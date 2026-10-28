// Transaction pool watcher: monitors pending transactions for contract deployments,
// large value transfers, and suspicious patterns.

use futures::StreamExt;
use vuln_common::{Transaction, HunterConfig};
use alloy::{
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::Transaction as AlloyTx,
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

// Type alias for the provider with boxed transport
type BoxedProvider = alloy::providers::RootProvider<alloy::transports::BoxTransport>;

/// Maximum pending transactions to track
const MAX_PENDING_TXS: usize = 50_000;

pub struct TxPoolWatcher {
    config: Arc<HunterConfig>,
    provider: BoxedProvider,
    pending_txs: Arc<DashMap<String, Transaction>>,
    deployment_tx: mpsc::UnboundedSender<Transaction>,
}

impl TxPoolWatcher {
    pub async fn new(config: Arc<HunterConfig>) -> Result<Self> {
        let chain_config = config.chains.first()
            .context("No chain configured")?;

        let ws_connect = WsConnect::new(&chain_config.ws_url);
        let provider = ProviderBuilder::new()
            .on_ws(ws_connect)
            .await
            .context("Failed to connect to WebSocket for tx pool")?
            .boxed();

        let (deployment_tx, _) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            provider,
            pending_txs: Arc::new(DashMap::new()),
            deployment_tx,
        })
    }

    pub fn subscribe_pending_deployments(&self) -> mpsc::UnboundedReceiver<Transaction> {
        let (tx, rx) = mpsc::unbounded_channel();
        rx
    }

    pub async fn start(&self) -> Result<tokio::task::JoinHandle<()>> {
        let provider = self.provider.clone();
        let pending_txs = self.pending_txs.clone();
        let deployment_tx = self.deployment_tx.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = Self::run_watcher(provider, pending_txs, deployment_tx).await {
                warn!("Tx pool watcher error: {}", e);
            }
        });

        Ok(handle)
    }

    async fn run_watcher(
        provider: BoxedProvider,
        pending_txs: Arc<DashMap<String, Transaction>>,
        deployment_tx: mpsc::UnboundedSender<Transaction>,
    ) -> Result<()> {
        info!("Starting transaction pool watcher");

        // Subscribe to pending transactions
        let sub = provider.subscribe_pending_transactions().await?;
        let mut stream = sub.into_stream();

        while let Some(tx_hash) = stream.next().await {
            if let Err(e) = Self::process_pending_tx(&provider, &pending_txs, &deployment_tx, tx_hash).await {
                debug!("Error processing pending tx: {}", e);
            }
        }

        Ok(())
    }

    async fn process_pending_tx(
        provider: &BoxedProvider,
        pending_txs: &Arc<DashMap<String, Transaction>>,
        deployment_tx: &mpsc::UnboundedSender<Transaction>,
        tx_hash: alloy::primitives::B256,
    ) -> Result<()> {
        // Fetch full transaction
        let tx = match provider.get_transaction_by_hash(tx_hash).await? {
            Some(tx) => tx,
            None => return Ok(()), // Might be already mined
        };

        let hash_str = tx_hash.to_string();
        
        // Skip if already tracked
        if pending_txs.contains_key(&hash_str) {
            return Ok(());
        }

        // Convert to our type
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
            block_number: None,
            block_hash: None,
            transaction_index: None,
        };

        // Check if contract deployment (to == null)
        let is_deployment = tx.to.is_none();

        // Check for large value transfers
        let is_large_value = tx.value > alloy::primitives::U256::from(100_000_000_000_000_000_000u128); // > 100 ETH equivalent

        // Check for flash loan patterns (calls to known lending pools)
        let is_flash_loan = Self::detect_flash_loan_pattern(&tx.input);

        // Store
        if pending_txs.len() >= MAX_PENDING_TXS {
            // Remove oldest (simple cleanup)
            if let Some(oldest) = pending_txs.iter().next() {
                pending_txs.remove(oldest.key());
            }
        }
        pending_txs.insert(hash_str, our_tx.clone());

        // Notify if deployment
        if is_deployment || is_flash_loan || is_large_value {
            let _ = deployment_tx.send(our_tx.clone());
            if is_deployment {
                info!("Pending contract deployment detected: {}", tx_hash);
            }
        }

        Ok(())
    }

    fn detect_flash_loan_pattern(input: &alloy::primitives::Bytes) -> bool {
        if input.len() < 4 {
            return false;
        }
        
        let selector = &input[0..4];
        
        // Common flash loan selectors
        const FLASH_LOAN_SELECTORS: &[[u8; 4]] = &[
            // Aave V3 flashLoan(address,address[],uint256[],uint256[],address,bytes)
            [0x5c, 0xff, 0x2d, 0x4c],
            // dYdX flashLoan(uint256,address,uint256,bytes)
            [0x4c, 0x1d, 0x5e, 0x2a],
            // Uniswap V2 flashLoan(address,address,uint256,uint256,bytes)
            [0x6f, 0x7c, 0x3e, 0x5a],
            // Balancer flashLoan(address,address[],uint256[],bytes)
            [0x3f, 0x5c, 0x2e, 0x1a],
        ];

        FLASH_LOAN_SELECTORS.iter().any(|s| s.as_slice() == selector)
    }

    pub async fn pending_deployments(&self) -> Vec<Transaction> {
        self.pending_txs
            .iter()
            .filter(|entry| entry.value().to.is_none())
            .map(|entry| entry.value().clone())
            .collect()
    }

    pub fn pending_count(&self) -> usize {
        self.pending_txs.len()
    }
}
