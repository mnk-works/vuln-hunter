use alloy::network::TransactionResponse;
// Block watcher: polls for new blocks via HTTP, fetches full block
// with transactions and receipts, extracts contract deployments.

use vuln_common::{BlockHeader, ContractDeployment, Transaction, TransactionReceipt, HunterConfig, ChainConfig};
use alloy::{
    providers::{Provider, ProviderBuilder},
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
        let poll_interval = Duration::from_secs(3);

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
        poll_interval: Duration,
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

        let bytecode: Vec<u8> = provider.get_code_at(contract_address).await?.into();

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
