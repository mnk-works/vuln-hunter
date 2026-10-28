//! TVL Tracker: tracks Total Value Locked in contracts by monitoring token balances
//! and known DeFi protocol patterns.

use vuln_common::{HunterConfig, Address, U256, ContractDeployment};
use alloy::{
    providers::{ProviderBuilder, WsConnect},
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::{sync::mpsc, time::{interval, Duration}};
use tracing::{debug, info, warn};

// Type alias for the provider with boxed transport
type BoxedProvider = alloy::providers::RootProvider<alloy::transports::BoxTransport>;

pub struct TVLTracker {
    config: Arc<HunterConfig>,
    provider: BoxedProvider,
    contract_tvl: Arc<DashMap<String, TVLInfo>>,
    token_prices: Arc<RwLock<HashMap<String, f64>>>,
    tvl_tx: mpsc::UnboundedSender<TVLUpdate>,
}

#[derive(Debug, Clone)]
pub struct TVLInfo {
    pub contract: Address,
    pub token_balances: HashMap<Address, U256>,
    pub total_usd: f64,
    pub last_updated: u64,
}

#[derive(Debug, Clone)]
pub struct TVLUpdate {
    pub contract: Address,
    pub tvl_usd: f64,
    pub token_balances: HashMap<Address, U256>,
    pub change: f64,
}

impl TVLTracker {
    pub async fn new(config: Arc<HunterConfig>) -> Result<Self> {
        let chain_config = config.chains.first()
            .context("No chain configured")?;

        let ws_connect = WsConnect::new(&chain_config.ws_url);
        let provider = ProviderBuilder::new()
            .on_ws(ws_connect)
            .await
            .context("Failed to connect to WebSocket for TVL")?
            .boxed();

        let (tvl_tx, _) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            provider,
            contract_tvl: Arc::new(DashMap::new()),
            token_prices: Arc::new(RwLock::new(HashMap::new())),
            tvl_tx,
        })
    }

    pub fn subscribe_tvl(&self) -> mpsc::UnboundedReceiver<TVLUpdate> {
        let (tx, rx) = mpsc::unbounded_channel();
        rx
    }

    pub async fn start(&self) -> Result<tokio::task::JoinHandle<()>> {
        let provider = self.provider.clone();
        let contract_tvl = self.contract_tvl.clone();
        let token_prices = self.token_prices.clone();
        let tvl_tx = self.tvl_tx.clone();
        let min_tvl = self.config.filters.min_tvl_usd;

        let handle = tokio::spawn(async move {
            // Start periodic TVL recalculation
            let mut ticker = interval(Duration::from_secs(60)); // Every minute
            
            loop {
                ticker.tick().await;
                
                if let Err(e) = Self::recalculate_all_tvl(
                    &provider,
                    &contract_tvl,
                    &token_prices,
                    &tvl_tx,
                    min_tvl,
                ).await {
                    warn!("TVL recalculation error: {}", e);
                }
            }
        });

        Ok(handle)
    }

    /// Register a contract for TVL tracking
    pub async fn track_contract(&self, deployment: &ContractDeployment) -> Result<()> {
        let addr_key = format!("{:#x}", deployment.address);
        
        // Fetch initial token balances
        let token_balances: HashMap<Address, U256> = Self::fetch_token_balances(&self.provider, deployment.address).await?;
        
        // Calculate USD value
        let prices = self.token_prices.read();
        let mut total_usd = 0.0;
        for (token, balance) in &token_balances {
            let token_key = format!("{:#x}", token);
            if let Some(price) = prices.get(&token_key) {
                let balance_f64 = balance.to_string().parse::<f64>().unwrap_or(0.0);
                // Assume 18 decimals for simplicity
                total_usd += balance_f64 * price / 1e18;
            }
        }

        let tvl_info = TVLInfo {
            contract: deployment.address,
            token_balances,
            total_usd,
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        self.contract_tvl.insert(addr_key, tvl_info);
        
        info!("Tracking TVL for contract: {}", deployment.address);
        Ok(())
    }

    async fn recalculate_all_tvl(
        provider: &BoxedProvider,
        contract_tvl: &Arc<DashMap<String, TVLInfo>>,
        token_prices: &Arc<RwLock<HashMap<String, f64>>>,
        tvl_tx: &mpsc::UnboundedSender<TVLUpdate>,
        min_tvl: f64,
    ) -> Result<()> {
        debug!("Recalculating TVL for {} contracts", contract_tvl.len());

        for mut entry in contract_tvl.iter_mut() {
            let contract = entry.contract;
            let old_usd = entry.total_usd;

            // Fetch current balances
            let token_balances: HashMap<Address, U256> = Self::fetch_token_balances(provider, contract).await?;
            
            // Calculate USD
            let prices = token_prices.read();
            let mut total_usd = 0.0;
            for (token, balance) in &token_balances {
                let token_key = format!("{:#x}", token);
                if let Some(price) = prices.get(&token_key) {
                    let balance_f64 = balance.to_string().parse::<f64>().unwrap_or(0.0);
                    total_usd += balance_f64 * price / 1e18;
                }
            }

            entry.token_balances = token_balances.clone();
            entry.total_usd = total_usd;
            entry.last_updated = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            // Notify if significant change or above threshold
            let change = total_usd - old_usd;
            if total_usd >= min_tvl || change.abs() > min_tvl * 0.1 {
                let _ = tvl_tx.send(TVLUpdate {
                    contract,
                    tvl_usd: total_usd,
                    token_balances,
                    change,
                });
            }
        }

        Ok(())
    }

    async fn fetch_token_balances(
        _provider: &BoxedProvider,
        _contract: Address,
    ) -> Result<HashMap<Address, U256>> {
        // This is a simplified version - in production you'd:
        // 1. Check if contract is a known protocol (Aave, Compound, Uniswap, etc.)
        // 2. Call protocol-specific view functions
        // 3. For generic ERC20, you'd need to know which tokens to check
        
        // For now, return empty - will be populated by event indexer
        Ok(HashMap::new())
    }

    /// Update token price (called from external price oracle)
    pub fn update_price(&self, token: &Address, price_usd: f64) {
        let token_key = format!("{:#x}", token);
        self.token_prices.write().insert(token_key, price_usd);
    }

    /// Get TVL for a contract
    pub fn get_tvl(&self, contract: &Address) -> Option<TVLInfo> {
        self.contract_tvl.get(&format!("{:#x}", contract)).map(|v| v.clone())
    }

    /// Get all contracts above TVL threshold
    pub fn get_high_tvl_contracts(&self, min_tvl: f64) -> Vec<TVLInfo> {
        self.contract_tvl
            .iter()
            .filter(|entry| entry.total_usd >= min_tvl)
            .map(|entry| entry.value().clone())
            .collect()
    }
}
