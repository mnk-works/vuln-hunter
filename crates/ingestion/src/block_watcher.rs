//! Block watcher: polls for new blocks via HTTP, fetches full block
//! with transactions and receipts, extracts contract deployments

use vuln_common::{BlockHeader, ContractDeployment, Transaction, TransactionReceipt, HunterConfig, ChainConfig, Finding, RiskFactor, RiskKind, Severity, Address, U256, U64, B256, Bytes};
use alloy::{
    providers::{Provider, ProviderBuilder},
    network::TransactionResponse,
};
use anyhow::{Context, Result, anyhow};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::time::{interval, Duration};
use tracing::{debug, error, info, warn};

/// Maximum deployments to keep in memory
const MAX_DEPLOYMENTS: usize = 10_000;

/// Block watcher polls for new blocks via HTTP, extracts contract deployments
pub struct BlockWatcher {
    config: Arc<HunterConfig>,
    chain_config: ChainConfig,
    http_provider: alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
    deployments: Arc<DashMap<String, ContractDeployment>>,
    deployment_tx: mpsc::UnboundedSender<ContractDeployment>,
    processor_tx: mpsc::UnboundedSender<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)>,
    last_block: Arc<std::sync::atomic::AtomicU64>,
}

impl BlockWatcher {
    pub async fn new(config: Arc<HunterConfig>) -> Result<Self> {
        let chain_config = config.chains.first()
            .context("No chain configured")?
            .clone();

        let http_provider = ProviderBuilder::new()
            .on_http(chain_config.rpc_url.parse()?);

        let (deployment_tx, _) = mpsc::unbounded_channel();
        let (processor_tx, _) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            chain_config,
            http_provider,
            deployments: Arc::new(DashMap::new()),
            deployment_tx,
            processor_tx,
            last_block: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    /// Create a BlockWatcher for historical scanning (no background tasks)
    pub async fn new_for_scanning(
        http_provider: alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
        config: Arc<HunterConfig>,
    ) -> Result<Self> {
        let chain_config = config.chains.first()
            .context("No chain configured")?
            .clone();

        let (deployment_tx, _) = mpsc::unbounded_channel();
        let (processor_tx, _) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            chain_config,
            http_provider,
            deployments: Arc::new(DashMap::new()),
            deployment_tx,
            processor_tx,
            last_block: Arc::new(std::sync::atomic::AtomicU64::new(0)),
        })
    }

    pub fn subscribe_deployments(&self) -> mpsc::UnboundedReceiver<ContractDeployment> {
        let (tx, rx) = mpsc::unbounded_channel();
        rx
    }

    pub fn subscribe_blocks(&self) -> mpsc::UnboundedReceiver<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        rx
    }

    pub async fn start(&self) -> Result<tokio::task::JoinHandle<()>> {
        let http_provider = self.http_provider.clone();
        let deployments = self.deployments.clone();
        let deployment_tx = self.deployment_tx.clone();
        let processor_tx = self.processor_tx.clone();
        let chain_id = self.chain_config.chain_id;
        let last_block = self.last_block.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = Self::run_poller(http_provider, deployments, deployment_tx, processor_tx, chain_id, last_block, Duration::from_secs(3)).await {
                error!("Block watcher error: {}", e);
            }
        });

        Ok(handle)
    }

    async fn run_poller(
        provider: alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
        deployments: Arc<DashMap<String, ContractDeployment>>,
        deployment_tx: mpsc::UnboundedSender<ContractDeployment>,
        processor_tx: mpsc::UnboundedSender<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)>,
        chain_id: u64,
        last_block: Arc<std::sync::atomic::AtomicU64>,
        _poll_interval: Duration,
    ) -> Result<()> {
        info!("Starting HTTP block poller for chain {}", chain_id);

        let mut interval = interval(Duration::from_secs(3));
        
        let latest = provider.get_block_number().await?;
        last_block.store(latest, std::sync::atomic::Ordering::Relaxed);
        info!("Starting poll from block {}", latest);

        loop {
            interval.tick().await;
            
            if let Err(e) = Self::poll_once(
                &provider,
                &deployments,
                &deployment_tx,
                &processor_tx,
                chain_id,
                &last_block,
            ).await {
                warn!("Error polling block: {}", e);
            }
        }
    }

    async fn poll_once(
        provider: &alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
        deployments: &Arc<DashMap<String, ContractDeployment>>,
        deployment_tx: &mpsc::UnboundedSender<ContractDeployment>,
        processor_tx: &mpsc::UnboundedSender<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)>,
        chain_id: u64,
        last_block: &Arc<std::sync::atomic::AtomicU64>,
    ) -> Result<()> {
        let latest_block = provider.get_block_number().await?;
        let last_known = last_block.load(std::sync::atomic::Ordering::Relaxed);
        
        if latest_block <= last_known {
            return Ok(());
        }

        info!("New blocks detected: {} to {}", last_known + 1, latest_block);
        
        for block_num in (last_known + 1)..=latest_block {
            if let Err(e) = Self::process_block(
                provider,
                deployments,
                deployment_tx,
                processor_tx,
                block_num,
            ).await {
                warn!("Error processing block {}: {}", block_num, e);
            }
        }

        last_block.store(latest_block, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    async fn process_block(
        provider: &alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
        deployments: &Arc<DashMap<String, ContractDeployment>>,
        deployment_tx: &mpsc::UnboundedSender<ContractDeployment>,
        processor_tx: &mpsc::UnboundedSender<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)>,
        block_number: u64,
    ) -> Result<()> {
        debug!("Processing block {}", block_number);

        let block = provider
            .get_block_by_number(alloy::primitives::U64::from(block_number).into(), true)
            .await?;

        let block = match block {
            Some(b) => b,
            None => return Err(anyhow!("Block {} not found", block_number)),
        };

        let block_hash = block.header.hash;
        let timestamp = block.header.timestamp;

        let mut transactions = Vec::new();
        let mut receipts = Vec::new();

        if let Some(txs) = block.transactions.as_transactions() {
            for tx in txs {
                let tx_hash = tx.tx_hash();
                
                let our_tx = Transaction {
                    hash: tx_hash,
                    from: tx.from,
                    to: tx.to,
                    value: tx.value,
                    gas: alloy::primitives::U256::from(tx.gas as u64),
                    gas_price: tx.gas_price.map(|v| alloy::primitives::U256::from(v as u64)),
                    max_fee_per_gas: tx.max_fee_per_gas.map(|v| alloy::primitives::U256::from(v as u64)),
                    max_priority_fee_per_gas: tx.max_priority_fee_per_gas.map(|v| alloy::primitives::U256::from(v as u64)),
                    input: tx.input.clone(),
                    nonce: alloy::primitives::U64::from(tx.nonce),
                    block_number: Some(alloy::primitives::U64::from(block_number)),
                    block_hash: Some(block.header.hash),
                    transaction_index: tx.transaction_index.map(alloy::primitives::U64::from),
                };
                transactions.push(our_tx.clone());

                if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
                    let our_receipt = TransactionReceipt {
                        transaction_hash: tx_hash,
                        block_number: alloy::primitives::U64::from(block_number),
                        block_hash: block.header.hash,
                        transaction_index: alloy::primitives::U64::from(receipt.transaction_index.unwrap_or_default()),
                        from: tx.from,
                        to: tx.to,
                        contract_address: receipt.contract_address,
                        gas_used: alloy::primitives::U256::from(receipt.gas_used as u64),
                        effective_gas_price: alloy::primitives::U256::from(receipt.effective_gas_price as u64),
                        status: receipt.status(),
                        logs: receipt.inner.logs().iter().map(|log| vuln_common::Log {
                            address: log.address(),
                            topics: log.topics().to_vec(),
                            data: log.data().data.clone(),
                            block_number: alloy::primitives::U64::from(block_number),
                            transaction_hash: tx_hash,
                            log_index: alloy::primitives::U64::from(log.log_index.unwrap_or_default()),
                            removed: false,
                        }).collect(),
                    };
                    receipts.push(our_receipt.clone());

                    if let Some(contract_address) = receipt.contract_address {
                        Self::handle_deployment(
                            provider,
                            deployments,
                            deployment_tx,
                            contract_address,
                            &our_tx,
                            &our_receipt,
                            block.header.timestamp,
                        ).await?;
                    }
                }
            }
        }

        let header = BlockHeader {
            number: alloy::primitives::U64::from(block_number),
            hash: block.header.hash,
            parent_hash: block.header.parent_hash,
            timestamp: alloy::primitives::U64::from(block.header.timestamp),
            base_fee_per_gas: block.header.base_fee_per_gas.map(|v| alloy::primitives::U256::from(v as u64)),
            gas_used: alloy::primitives::U256::from(block.header.gas_used as u64),
            gas_limit: alloy::primitives::U256::from(block.header.gas_limit as u64),
        };

        let _ = processor_tx.send((header, transactions, receipts));
        Ok(())
    }

    async fn handle_deployment(
        provider: &alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
        deployments: &Arc<DashMap<String, ContractDeployment>>,
        deployment_tx: &mpsc::UnboundedSender<ContractDeployment>,
        contract_address: alloy::primitives::Address,
        tx: &Transaction,
        receipt: &TransactionReceipt,
        timestamp: u64,
    ) -> Result<()> {
        let addr_key = contract_address.to_string();
        
        if deployments.contains_key(&addr_key) {
            return Ok(());
        }

        let bytecode: Vec<u8> = provider.get_code_at(contract_address).await?.to_vec();

        let (is_proxy, implementation) = Self::detect_proxy(provider, contract_address).await?;

        let verified = false;

        let deployment = ContractDeployment {
            address: contract_address,
            deployer: tx.from,
            deployment_tx: tx.hash,
            block_number: alloy::primitives::U64::from(receipt.block_number),
            timestamp: alloy::primitives::U64::from(timestamp),
            bytecode: alloy::primitives::Bytes::from(bytecode),
            is_proxy,
            implementation,
            verified,
            abi: None,
        };

        deployments.insert(addr_key, deployment.clone());
        let _ = deployment_tx.send(deployment);

        info!("New contract deployment: {} at block {}", contract_address, receipt.block_number);
        Ok(())
    }

    async fn detect_proxy(
        provider: &alloy::providers::RootProvider<alloy::transports::http::Http<reqwest::Client>>,
        address: alloy::primitives::Address,
    ) -> Result<(bool, Option<alloy::primitives::Address>)> {
        let impl_slot = alloy::primitives::StorageKey::from(
            alloy::primitives::keccak256("eip1967.proxy.implementation")
        );
        
        if let Ok(storage) = provider.get_storage_at(address, impl_slot.into()).await {
            let bytes = storage.to_be_bytes::<32>();
            let impl_addr = alloy::primitives::Address::from_slice(&bytes[12..]);
            if impl_addr != alloy::primitives::Address::ZERO {
                return Ok((true, Some(impl_addr)));
            }
        }

        let proxiable_slot = alloy::primitives::StorageKey::from(
            alloy::primitives::keccak256("eip1967.proxy.proxiable")
        );
        
        if let Ok(storage) = provider.get_storage_at(address, proxiable_slot.into()).await {
            let bytes = storage.to_be_bytes::<32>();
            let impl_addr = alloy::primitives::Address::from_slice(&bytes[12..]);
            if impl_addr != alloy::primitives::Address::ZERO {
                return Ok((true, Some(impl_addr)));
            }
        }

        Ok((false, None))
    }

    // ========================================================================
    // HISTORICAL SCANNING METHODS
    // ========================================================================

    /// Scan a range of blocks for vulnerable contracts
    pub async fn scan_historical(
        &self,
        from_block: u64,
        to_block: u64,
        patterns: &[String],
        min_tvl_usd: f64,
    ) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();
        
        let end_block = if to_block == 0 {
            self.http_provider.get_block_number().await?
        } else {
            to_block
        };

        info!("Scanning blocks {} to {} for vulnerable contracts", from_block, end_block);

        for block_num in from_block..=end_block {
            if block_num % 1000 == 0 {
                info!("Scanning block {} / {}", block_num, end_block);
            }

            let block_findings = self.scan_block_for_vulnerabilities(block_num).await?;
            findings.extend(block_findings);
        }

        // Filter by TVL and patterns
        findings.retain(|f| f.estimated_tvl_at_risk.unwrap_or(0.0) >= min_tvl_usd);
        
        if !patterns.is_empty() {
            findings.retain(|f| {
                patterns.iter().any(|p| {
                    f.risk_factors.iter().any(|rf| rf.description.contains(p)) ||
                    f.vulnerability_type.contains(p)
                })
            });
        }

        Ok(findings)
    }

    /// Scan a single block for vulnerable contracts
    async fn scan_block_for_vulnerabilities(&self, block_num: u64) -> Result<Vec<Finding>> {
        let mut findings = Vec::new();

        let block = self.http_provider
            .get_block_by_number(alloy::primitives::U64::from(block_num).into(), true)
            .await?;

        let block = match block {
            Some(b) => b,
            None => return Ok(Vec::new()),
        };

        if let Some(txs) = block.transactions.as_transactions() {
            for tx in txs {
                if let Some(receipt) = self.http_provider.get_transaction_receipt(tx.tx_hash()).await? {
                    if let Some(contract_address) = receipt.contract_address {
                        let analysis = self.analyze_contract(contract_address, Some(block_num)).await?;
                        if let Some(severity) = analysis.get("overall_severity").and_then(|v| v.as_u64()) {
                            if severity >= 2 { // Medium or higher
                                let finding = Finding {
                                    id: format!("{}_{}", contract_address, block_num),
                                    contract: contract_address,
                                    vulnerability_type: analysis.get("vulnerability_type").and_then(|v| v.as_str()).unwrap_or("Unknown").to_string(),
                                    risk_factors: Vec::new(),
                                    overall_severity: match severity {
                                        0 => Severity::Info,
                                        1 => Severity::Low,
                                        2 => Severity::Medium,
                                        3 => Severity::High,
                                        _ => Severity::Critical,
                                    },
                                    exploitability_score: 0.5,
                                    estimated_tvl_at_risk: None,
                                    poc: None,
                                    timestamp: alloy::primitives::U64::from(block.header.timestamp),
                                };
                                findings.push(finding);
                            }
                        }
                    }
                }
            }
        }

        Ok(findings)
    }

    /// Analyze a specific contract for vulnerabilities
    pub async fn analyze_contract(
        &self,
        contract_address: Address,
        _at_block: Option<u64>,
    ) -> Result<serde_json::Value> {
        let bytecode: Vec<u8> = self.http_provider.get_code_at(contract_address).await?.to_vec();
        
        let is_contract = !bytecode.is_empty();
        
        let mut risk_factors = Vec::new();
        let mut vulnerability_type = "Unknown".to_string();
        let mut max_severity = 0u8;
        
        if is_contract {
            // Analyze bytecode for patterns
            let bytecode_str = alloy::hex::encode(&bytecode);
            
            // Check for known vulnerability patterns
            self.detect_vulnerability_patterns(&bytecode, &mut risk_factors, &mut vulnerability_type, &mut max_severity);
            
            // Check if proxy
            let (is_proxy, implementation) = self.detect_proxy_internal(&bytecode, contract_address).await?;
            
            // Get balance
            let balance = self.http_provider.get_balance(contract_address).await?;
            
            Ok(serde_json::json!({
                "address": format!("{:#x}", contract_address),
                "is_contract": is_contract,
                "is_proxy": is_proxy,
                "implementation": implementation.map(|a| format!("{:#x}", a)),
                "bytecode_size": bytecode.len(),
                "balance_wei": balance.to_string(),
                "risk_factors": risk_factors,
                "overall_severity": max_severity,
                "vulnerability_type": vulnerability_type,
            }))
        } else {
            Ok(serde_json::json!({
                "address": format!("{:#x}", contract_address),
                "is_contract": false,
                "error": "No bytecode at address (EOA or empty)"
            }))
        }
    }

    fn detect_vulnerability_patterns(&self, bytecode: &[u8], risk_factors: &mut Vec<RiskFactor>, vulnerability_type: &mut String, max_severity: &mut u8) {
        let bytecode_str = alloy::hex::encode(bytecode);
        let mut found_patterns = Vec::new();
        
        // Pattern: Admin-only via hash check (Fence-style)
        if bytecode_str.contains("ea7b0dec") || bytecode_str.contains("767081d1") {
            found_patterns.push(("AdminHashCheck", "High", "Fence-style tranche creation with admin hash check only".to_string(), serde_json::json!({"selectors": ["ea7b0dec", "767081d1"]})));
        }
        
        // Pattern: Aave V3 flashLoan
        if bytecode_str.contains("5cff2d4c") {
            found_patterns.push(("FlashLoanStateChange", "Medium", "Aave V3 flashLoan entry point detected".to_string(), serde_json::json!({"selector": "5cff2d4c"})));
        }
        
        // Pattern: Uniswap V2 flashLoan
        if bytecode_str.contains("6f7c3e5a") {
            found_patterns.push(("FlashLoanStateChange", "Medium", "Uniswap V2 flashLoan entry point detected".to_string(), serde_json::json!({"selector": "6f7c3e5a"})));
        }
        
        // Pattern: Balancer flashLoan
        if bytecode_str.contains("3f5c2e1a") {
            found_patterns.push(("FlashLoanStateChange", "Medium", "Balancer flashLoan entry point detected".to_string(), serde_json::json!({"selector": "3f5c2e1a"})));
        }
        
        // Pattern: dYdX flashLoan
        if bytecode_str.contains("4c1d5e2a") {
            found_patterns.push(("FlashLoanStateChange", "Medium", "dYdX flashLoan entry point detected".to_string(), serde_json::json!({"selector": "4c1d5e2a"})));
        }
        
        // Pattern: Admin-only via hash check (generic)
        if bytecode_str.contains("hash") && (bytecode_str.contains("admin") || bytecode_str.contains("owner")) {
            found_patterns.push(("AdminHashCheck", "Medium", "Admin/owner hash check pattern detected".to_string(), serde_json::json!({})));
        }
        
        // Pattern: Unvalidated hook/callback
        if bytecode_str.contains("hook") || bytecode_str.contains("callback") {
            found_patterns.push(("UnvalidatedHook", "Medium", "Hook/callback mechanism detected - validate input validation".to_string(), serde_json::json!({"bytecode_contains": ["hook", "callback"]})));
        }
        
        // Pattern: External calls (reentrancy risk)
        if bytecode_str.contains("f1") || bytecode_str.contains("f3") || bytecode_str.contains("fa") { // call, staticcall, delegatecall
            found_patterns.push(("Reentrancy", "Medium", "External calls detected - verify reentrancy protection".to_string(), serde_json::json!({"external_calls": true})));
        }
        
        // Pattern: CREATE/CREATE2 (factory patterns)
        if bytecode_str.contains("f0") || bytecode_str.contains("f5") { // CREATE, CREATE2
            found_patterns.push(("FactoryPattern", "Low", "Contract creation (CREATE/CREATE2) detected".to_string(), serde_json::json!({})));
        }
        
        // Pattern: Selfdestruct
        if bytecode_str.contains("ff") { // selfdestruct
            found_patterns.push(("SelfDestruct", "Medium", "SELFDESTRUCT opcode detected - verify access control".to_string(), serde_json::json!({})));
        }
        
        // Pattern: Delegatecall (proxy/upgradeable)
        if bytecode_str.contains("f4") { // delegatecall
            found_patterns.push(("UpgradeableProxy", "Medium", "DELEGATECALL detected - verify proxy/upgradeable pattern".to_string(), serde_json::json!({})));
        }
        
        // Determine overall vulnerability type and max severity
        for (pattern_type, severity_str, description, evidence) in &found_patterns {
            let severity = match *severity_str {
                "Critical" => 4,
                "High" => 3,
                "Medium" => 2,
                "Low" => 1,
                _ => 1,
            };
            
            if severity > *max_severity {
                *max_severity = severity;
                *vulnerability_type = pattern_type.to_string();
            }
            
            risk_factors.push(RiskFactor {
                kind: match *pattern_type {
                    "AdminHashCheck" => RiskKind::AdminHashCheck,
                    "FlashLoanStateChange" => RiskKind::FlashLoanStateChange,
                    "UnvalidatedHook" => RiskKind::UnvalidatedHook,
                    "Reentrancy" => RiskKind::Reentrancy,
                    "UpgradeableProxy" => RiskKind::UpgradeableProxy,
                    "SelfDestruct" => RiskKind::IntegerArithmetic, // fallback
                    "FactoryPattern" => RiskKind::MissingAccessControl, // fallback
                    _ => RiskKind::Custom(pattern_type.to_string()),
                },
                severity: match *severity_str {
                    "Critical" => Severity::Critical,
                    "High" => Severity::High,
                    "Medium" => Severity::Medium,
                    "Low" => Severity::Low,
                    _ => Severity::Low,
                },
                description: description.clone(),
                location: None,
                evidence: evidence.clone(),
            });
        }
        
        // Set default vulnerability type if none found
        if *vulnerability_type == "Unknown" && !found_patterns.is_empty() {
            *vulnerability_type = found_patterns[0].0.to_string();
        }
    }

    async fn detect_proxy_internal(
        &self,
        _bytecode: &[u8],
        address: Address,
    ) -> Result<(bool, Option<Address>)> {
        // Check for EIP-1967 implementation slot
        let impl_slot = alloy::primitives::StorageKey::from(
            alloy::primitives::keccak256("eip1967.proxy.implementation")
        );
        
        if let Ok(storage) = self.http_provider.get_storage_at(address, impl_slot.into()).await {
            let bytes = storage.to_be_bytes::<32>();
            let impl_addr = alloy::primitives::Address::from_slice(&bytes[12..]);
            if impl_addr != alloy::primitives::Address::ZERO {
                return Ok((true, Some(impl_addr)));
            }
        }

        // Check for EIP-1822 (UUPS) proxiable slot
        let proxiable_slot = alloy::primitives::StorageKey::from(
            alloy::primitives::keccak256("eip1967.proxy.proxiable")
        );
        
        if let Ok(storage) = self.http_provider.get_storage_at(address, proxiable_slot.into()).await {
            let bytes = storage.to_be_bytes::<32>();
            let impl_addr = alloy::primitives::Address::from_slice(&bytes[12..]);
            if impl_addr != alloy::primitives::Address::ZERO {
                return Ok((true, Some(impl_addr)));
            }
        }

        Ok((false, None))
    }

    pub async fn recent_deployments(&self, limit: usize) -> Vec<ContractDeployment> {
        self.deployments
            .iter()
            .take(limit)
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn get_deployment(&self, address: &alloy::primitives::Address) -> Option<ContractDeployment> {
        self.deployments.get(&address.to_string()).map(|v| v.clone())
    }
}
