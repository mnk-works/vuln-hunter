//! Block watcher: subscribes to new blocks via WebSocket, fetches full block
//! with transactions and receipts, extracts contract deployments.

use alloy::providers::Provider;
use alloy::network::TransactionResponse;
use vuln_common::{BlockHeader, ContractDeployment, Transaction, TransactionReceipt, HunterConfig, ChainConfig};
use alloy::{
    providers::{ProviderBuilder, WsConnect},
    rpc::types::{Block},
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use futures::StreamExt;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

// Type alias for the provider with boxed transport
type BoxedProvider = alloy::providers::RootProvider<alloy::transports::BoxTransport>;

/// Maximum deployments to keep in memory
const MAX_DEPLOYMENTS: usize = 10_000;

/// Block watcher handles new block subscriptions and deployment extraction
pub struct BlockWatcher {
    config: Arc<HunterConfig>,
    chain_config: ChainConfig,
    provider: BoxedProvider,
    deployments: Arc<DashMap<String, ContractDeployment>>,
    deployment_tx: mpsc::UnboundedSender<ContractDeployment>,
    processor_tx: mpsc::UnboundedSender<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)>,
}

impl BlockWatcher {
    pub async fn new(config: Arc<HunterConfig>) -> Result<Self> {
        let chain_config = config.chains.first()
            .context("No chain configured")?
            .clone();

        // Build WebSocket provider
        let ws_connect = WsConnect::new(&chain_config.ws_url);
        let provider = ProviderBuilder::new()
            .on_ws(ws_connect)
            .await
            .context("Failed to connect to WebSocket")?
            .boxed();

        let (deployment_tx, _) = mpsc::unbounded_channel();
        let (processor_tx, _) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            chain_config,
            provider,
            deployments: Arc::new(DashMap::new()),
            deployment_tx,
            processor_tx,
        })
    }

    /// Subscribe to new deployments
    pub fn subscribe_deployments(&self) -> mpsc::UnboundedReceiver<ContractDeployment> {
        let (tx, rx) = mpsc::unbounded_channel();
        rx
    }

    /// Subscribe to full block data for processors
    pub fn subscribe_blocks(&self) -> mpsc::UnboundedReceiver<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        rx
    }

    /// Start watching for new blocks
    pub async fn start(&self) -> Result<tokio::task::JoinHandle<()>> {
        let provider = self.provider.clone();
        let deployments = self.deployments.clone();
        let deployment_tx = self.deployment_tx.clone();
        let processor_tx = self.processor_tx.clone();
        let chain_id = self.chain_config.chain_id;

        let handle = tokio::spawn(async move {
            if let Err(e) = Self::run_watcher(provider, deployments, deployment_tx, processor_tx, chain_id).await {
                error!("Block watcher error: {}", e);
            }
        });

        Ok(handle)
    }

    async fn run_watcher(
        provider: BoxedProvider,
        deployments: Arc<DashMap<String, ContractDeployment>>,
        deployment_tx: mpsc::UnboundedSender<ContractDeployment>,
        processor_tx: mpsc::UnboundedSender<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)>,
        chain_id: u64,
    ) -> Result<()> {
        info!("Starting block watcher for chain {}", chain_id);

        // Subscribe to new blocks
        let sub = provider.subscribe_blocks().await?;
        let mut stream = sub.into_stream();

        while let Some(block) = stream.next().await {
            if let Err(e) = Self::process_block(
                &provider,
                &deployments,
                &deployment_tx,
                &processor_tx,
                block,
                chain_id,
            ).await {
                warn!("Error processing block: {}", e);
            }
        }

        Ok(())
    }

    async fn process_block(
        provider: &BoxedProvider,
        deployments: &Arc<DashMap<String, ContractDeployment>>,
        deployment_tx: &mpsc::UnboundedSender<ContractDeployment>,
        processor_tx: &mpsc::UnboundedSender<(BlockHeader, Vec<Transaction>, Vec<TransactionReceipt>)>,
        block: Block,
        chain_id: u64,
    ) -> Result<()> {
        let block_number = block.header.number;
        let block_hash = block.header.hash;
        let timestamp = block.header.timestamp;

        debug!("Processing block {} ({})", block_number, block_hash);

        // Fetch full block with transactions
        let full_block = provider
            .get_block_by_number(block_number.into(), true)
            .await?
            .context("Block not found")?;

        // Fetch receipts for all transactions
        let mut transactions = Vec::new();
        let mut receipts = Vec::new();

        // Handle transactions - they come as full transactions when full_block is requested with true
        if let Some(txs) = full_block.transactions.as_transactions() {
            for tx in txs {
                let tx_hash = tx.tx_hash();
                
                // Convert to our Transaction type
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
                    block_hash: Some(block_hash),
                    transaction_index: tx.transaction_index.map(alloy::primitives::U64::from),
                };
                transactions.push(our_tx.clone());

                // Get receipt
                if let Ok(Some(receipt)) = provider.get_transaction_receipt(tx_hash).await {
                    let our_receipt = TransactionReceipt {
                        transaction_hash: tx_hash,
                        block_number: alloy::primitives::U64::from(block_number),
                        block_hash,
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

                    // Check for contract deployment
                    if let Some(contract_address) = receipt.contract_address {
                        Self::handle_deployment(
                            provider,
                            deployments,
                            deployment_tx,
                            contract_address,
                            &our_tx,
                            &our_receipt,
                            timestamp,
                        ).await?;
                    }
                }
            }
        }

        // Create block header
        let header = BlockHeader {
            number: alloy::primitives::U64::from(block_number),
            hash: block_hash,
            parent_hash: block.header.parent_hash,
            timestamp: alloy::primitives::U64::from(timestamp),
            base_fee_per_gas: block.header.base_fee_per_gas.map(|v| alloy::primitives::U256::from(v as u64)),
            gas_used: alloy::primitives::U256::from(block.header.gas_used as u64),
            gas_limit: alloy::primitives::U256::from(block.header.gas_limit as u64),
        };

        // Send to processors
        let _ = processor_tx.send((header, transactions, receipts));

        Ok(())
    }

    async fn handle_deployment(
        provider: &BoxedProvider,
        deployments: &Arc<DashMap<String, ContractDeployment>>,
        deployment_tx: &mpsc::UnboundedSender<ContractDeployment>,
        contract_address: alloy::primitives::Address,
        tx: &Transaction,
        receipt: &TransactionReceipt,
        timestamp: u64,
    ) -> Result<()> {
        let addr_key = contract_address.to_string();
        
        // Skip if already seen
        if deployments.contains_key(&addr_key) {
            return Ok(());
        }

        // Fetch runtime bytecode
        let bytecode = provider.get_code_at(contract_address).await?.to_vec();

        // Check if proxy
        let (is_proxy, implementation) = Self::detect_proxy(provider, contract_address).await?;

        // Check verification status (placeholder - would call Etherscan/Sourcify)
        let verified = false; // TODO: implement

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

        // Store
        deployments.insert(addr_key, deployment.clone());

        // Notify subscribers
        let _ = deployment_tx.send(deployment);

        info!("New contract deployment: {} at block {}", contract_address, receipt.block_number);

        Ok(())
    }

    async fn detect_proxy(
        provider: &BoxedProvider,
        address: alloy::primitives::Address,
    ) -> Result<(bool, Option<alloy::primitives::Address>)> {
        // Check EIP-1967 implementation slot
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

        // Check EIP-1822 (UUPS) proxiable slot
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

    /// Get recent deployments
    pub async fn recent_deployments(&self, limit: usize) -> Vec<ContractDeployment> {
        self.deployments
            .iter()
            .take(limit)
            .map(|entry| entry.value().clone())
            .collect()
    }

    /// Get deployment by address
    pub fn get_deployment(&self, address: &alloy::primitives::Address) -> Option<ContractDeployment> {
        self.deployments.get(&address.to_string()).map(|v| v.clone())
    }
}
