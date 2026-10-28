//! Ingestion layer: real-time block watching, contract deployment detection,
//! transaction pool monitoring, and event indexing.

pub mod block_watcher;
pub mod tx_pool;
pub mod event_indexer;
pub mod tvl_tracker;
pub mod types;

use vuln_common::{BlockHeader, ContractDeployment, Transaction, TransactionReceipt, HunterConfig};
use anyhow::Result;
use std::sync::Arc;

/// Main ingestion service that coordinates all watchers
pub struct IngestionService {
    config: Arc<HunterConfig>,
    block_watcher: block_watcher::BlockWatcher,
    tx_pool_watcher: tx_pool::TxPoolWatcher,
    event_indexer: event_indexer::EventIndexer,
    tvl_tracker: tvl_tracker::TVLTracker,
}

impl IngestionService {
    pub async fn new(config: HunterConfig) -> Result<Self> {
        let config = Arc::new(config);
        
        let block_watcher = block_watcher::BlockWatcher::new(config.clone()).await?;
        let tx_pool_watcher = tx_pool::TxPoolWatcher::new(config.clone()).await?;
        let event_indexer = event_indexer::EventIndexer::new(config.clone()).await?;
        let tvl_tracker = tvl_tracker::TVLTracker::new(config.clone()).await?;

        Ok(Self {
            config,
            block_watcher,
            tx_pool_watcher,
            event_indexer,
            tvl_tracker,
        })
    }

    /// Start all watchers
    pub async fn start(&self) -> Result<()> {
        tracing::info!("Starting ingestion service");
        
        // Start block watcher (primary)
        let block_handle = self.block_watcher.start().await?;
        
        // Start tx pool watcher
        let pool_handle = self.tx_pool_watcher.start().await?;
        
        // Start event indexer
        let event_handle = self.event_indexer.start().await?;
        
        // Start TVL tracker
        let tvl_handle = self.tvl_tracker.start().await?;

        // Wait for all (they run forever unless error)
        tokio::try_join!(block_handle, pool_handle, event_handle, tvl_handle)?;
        
        Ok(())
    }

    /// Get recent contract deployments
    pub async fn recent_deployments(&self, limit: usize) -> Vec<ContractDeployment> {
        self.block_watcher.recent_deployments(limit).await
    }

    /// Get pending transactions that look like contract deployments
    pub async fn pending_deployments(&self) -> Vec<Transaction> {
        self.tx_pool_watcher.pending_deployments().await
    }
}

/// Trait for block processors
#[async_trait::async_trait]
pub trait BlockProcessor: Send + Sync {
    async fn process_block(&self, block: BlockHeader, txs: Vec<Transaction>, receipts: Vec<TransactionReceipt>) -> Result<()>;
    async fn process_transaction(&self, tx: &Transaction, receipt: &TransactionReceipt) -> Result<()>;
}

/// Trait for contract deployment handlers
#[async_trait::async_trait]
pub trait DeploymentHandler: Send + Sync {
    async fn on_deployment(&self, deployment: &ContractDeployment) -> Result<()>;
}
