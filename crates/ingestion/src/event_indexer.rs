//! Event indexer: indexes Transfer, Deploy, Swap, and other relevant events
//! for TVL tracking and pattern detection.

use vuln_common::{Log, HunterConfig};
use alloy::{
    providers::{Provider, ProviderBuilder, WsConnect},
    rpc::types::{Filter, Topic},
    sol,
};
use anyhow::{Context, Result};
use dashmap::DashMap;
use futures::StreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use alloy::primitives::{Address, B256, U256};

// Type alias for the provider with boxed transport
type BoxedProvider = alloy::providers::RootProvider<alloy::transports::BoxTransport>;

sol! {
    /// ERC20 Transfer event
    event Transfer(address indexed from, address indexed to, uint256 value);
    
    /// ERC721 Transfer event
    event ERC721Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
    
    /// PairCreated (Uniswap V2)
    event PairCreated(address indexed token0, address indexed token1, address pair, uint256);
    
    /// PoolCreated (Uniswap V3)
    event PoolCreated(address indexed token0, address indexed token1, uint24 indexed fee, int24 tickSpacing, address pool);
}

pub struct EventIndexer {
    config: Arc<HunterConfig>,
    provider: BoxedProvider,
    token_balances: Arc<DashMap<String, HashMap<String, U256>>>,
    pair_cache: Arc<DashMap<String, (Address, Address)>>,
    event_tx: mpsc::UnboundedSender<IndexedEvent>,
}

#[derive(Debug, Clone)]
pub struct IndexedEvent {
    pub log: Log,
    pub event_type: EventType,
    pub decoded: Option<DecodedEvent>,
}

#[derive(Debug, Clone)]
pub enum EventType {
    Transfer,
    ERC721Transfer,
    PairCreated,
    PoolCreated,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct DecodedEvent {
    pub name: String,
    pub params: HashMap<String, String>,
}

impl EventIndexer {
    pub async fn new(config: Arc<HunterConfig>) -> Result<Self> {
        let chain_config = config.chains.first()
            .context("No chain configured")?;

        let ws_connect = WsConnect::new(&chain_config.ws_url);
        let provider = ProviderBuilder::new()
            .on_ws(ws_connect)
            .await
            .context("Failed to connect to WebSocket for events")?
            .boxed();

        let (event_tx, _) = mpsc::unbounded_channel();

        Ok(Self {
            config,
            provider,
            token_balances: Arc::new(DashMap::new()),
            pair_cache: Arc::new(DashMap::new()),
            event_tx,
        })
    }

    pub fn subscribe_events(&self) -> mpsc::UnboundedReceiver<IndexedEvent> {
        let (tx, rx) = mpsc::unbounded_channel();
        rx
    }

    pub async fn start(&self) -> Result<tokio::task::JoinHandle<()>> {
        let provider = self.provider.clone();
        let token_balances = self.token_balances.clone();
        let pair_cache = self.pair_cache.clone();
        let event_tx = self.event_tx.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = Self::run_indexer(provider, token_balances, pair_cache, event_tx).await {
                warn!("Event indexer error: {}", e);
            }
        });

        Ok(handle)
    }

    async fn run_indexer(
        provider: BoxedProvider,
        token_balances: Arc<DashMap<String, HashMap<String, U256>>>,
        pair_cache: Arc<DashMap<String, (Address, Address)>>,
        event_tx: mpsc::UnboundedSender<IndexedEvent>,
    ) -> Result<()> {
        info!("Starting event indexer");

        // Create filter for relevant events
        let filter = Filter::new()
            .event_signature(Topic::from("Transfer(address,address,uint256)".parse::<alloy::primitives::FixedBytes<32>>().unwrap()))
            .event_signature(Topic::from("PairCreated(address,address,address,uint256)".parse::<alloy::primitives::FixedBytes<32>>().unwrap()))
            .event_signature(Topic::from("PoolCreated(address,address,uint24,int24,address)".parse::<alloy::primitives::FixedBytes<32>>().unwrap()));

        let sub = provider.subscribe_logs(&filter).await?;
        
        // Convert subscription to stream
        let mut stream = sub.into_stream();
        
        while let Some(log) = stream.next().await {
            if let Err(e) = Self::process_log(&provider, &token_balances, &pair_cache, &event_tx, log).await {
                debug!("Error processing log: {}", e);
            }
        }

        Ok(())
    }

    async fn process_log(
        _provider: &BoxedProvider,
        token_balances: &Arc<DashMap<String, HashMap<String, U256>>>,
        pair_cache: &Arc<DashMap<String, (Address, Address)>>,
        event_tx: &mpsc::UnboundedSender<IndexedEvent>,
        log: alloy::rpc::types::Log,
    ) -> Result<()> {
        let our_log = vuln_common::Log {
            address: log.address(),
            topics: log.topics().to_vec(),
            data: log.data().data.clone(),
            block_number: alloy::primitives::U64::from(log.block_number.unwrap_or_default()),
            transaction_hash: log.transaction_hash.unwrap_or_default(),
            log_index: alloy::primitives::U64::from(log.log_index.unwrap_or_default()),
            removed: log.removed,
        };

        if log.removed {
            return Ok(());
        }

        let (event_type, decoded) = Self::decode_log(&our_log)?;

        // Update balances for Transfer events
        if matches!(event_type, EventType::Transfer) {
            if let Some(decoded) = &decoded {
                if let (Some(from), Some(to), Some(value)) = (
                    decoded.params.get("from"),
                    decoded.params.get("to"),
                    decoded.params.get("value"),
                ) {
                    Self::update_balance(token_balances, &our_log.address, from, to, value);
                }
            }
        }

        // Cache pairs
        if matches!(event_type, EventType::PairCreated | EventType::PoolCreated) {
            if let Some(decoded) = &decoded {
                if let (Some(token0), Some(token1), Some(pair)) = (
                    decoded.params.get("token0"),
                    decoded.params.get("token1"),
                    decoded.params.get("pair").or(decoded.params.get("pool")),
                ) {
                    let token0_addr = token0.parse().ok();
                    let token1_addr = token1.parse().ok();
                    let pair_addr: Option<Address> = pair.parse().ok();
                    if let (Some(t0), Some(t1), Some(p)) = (token0_addr, token1_addr, pair_addr) {
                        pair_cache.insert(format!("{:#x}", p), (t0, t1));
                    }
                }
            }
        }

        let indexed = IndexedEvent {
            log: our_log,
            event_type,
            decoded,
        };

        let _ = event_tx.send(indexed);

        Ok(())
    }

    fn decode_log(log: &vuln_common::Log) -> Result<(EventType, Option<DecodedEvent>)> {
        if log.topics.is_empty() {
            return Ok((EventType::Unknown, None));
        }

        let topic0 = log.topics[0];
        
        // Transfer: 0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef
        const TRANSFER_TOPIC: B256 = B256::new([
            0xdd, 0xf2, 0x52, 0xad, 0x1b, 0xe2, 0xc8, 0x9b,
            0x69, 0xc2, 0xb0, 0x68, 0xfc, 0x37, 0x8d, 0xaa,
            0x95, 0x2b, 0xa7, 0xf1, 0x63, 0xc4, 0xa1, 0x16,
            0x28, 0xf5, 0x5a, 0x4d, 0xf5, 0x23, 0xb3, 0xef,
        ]);

        // PairCreated: 0x0d3648bd0f6ba80134a33ba9275ac585d9d315f0ad835540de74e0b6d9b3c5b0
        const PAIR_CREATED_TOPIC: B256 = B256::new([
            0x0d, 0x36, 0x48, 0xbd, 0x0f, 0x6b, 0xa8, 0x01,
            0x34, 0xa3, 0x3b, 0xa9, 0x27, 0x5a, 0xc5, 0x85,
            0xd9, 0xd3, 0x15, 0xf0, 0xad, 0x83, 0x55, 0x40,
            0xde, 0x74, 0xe0, 0xb6, 0xd9, 0xb3, 0xc5, 0xb0,
        ]);

        if topic0 == TRANSFER_TOPIC {
            // ERC20: 3 topics (from, to) + data (value)
            // ERC721: 4 topics (from, to, tokenId) + empty data
            let event_type = if log.topics.len() == 4 {
                EventType::ERC721Transfer
            } else {
                EventType::Transfer
            };

            let mut params = HashMap::new();
            if log.topics.len() >= 3 {
                params.insert("from".to_string(), format!("{:#x}", Address::from_slice(&log.topics[1][12..])));
                params.insert("to".to_string(), format!("{:#x}", Address::from_slice(&log.topics[2][12..])));
            }
            if log.topics.len() == 4 {
                params.insert("tokenId".to_string(), format!("{:#x}", log.topics[3]));
            }
            // Value in data for ERC20
            if log.topics.len() == 3 && log.data.len() >= 32 {
                let value = U256::from_be_slice(&log.data[0..32]);
                params.insert("value".to_string(), value.to_string());
            }

            return Ok((event_type, Some(DecodedEvent { name: "Transfer".to_string(), params })));
        }

        if topic0 == PAIR_CREATED_TOPIC {
            let mut params = HashMap::new();
            if log.topics.len() >= 3 {
                params.insert("token0".to_string(), format!("{:#x}", Address::from_slice(&log.topics[1][12..])));
                params.insert("token1".to_string(), format!("{:#x}", Address::from_slice(&log.topics[2][12..])));
            }
            if log.data.len() >= 40 {
                let pair = Address::from_slice(&log.data[12..32]);
                params.insert("pair".to_string(), format!("{:#x}", pair));
            }

            return Ok((EventType::PairCreated, Some(DecodedEvent { name: "PairCreated".to_string(), params })));
        }

        Ok((EventType::Unknown, None))
    }

    fn update_balance(
        token_balances: &Arc<DashMap<String, HashMap<String, U256>>>,
        token: &Address,
        from: &str,
        to: &str,
        value_str: &str,
    ) {
        let token_key = format!("{:#x}", token);
        let value = match value_str.parse::<U256>() {
            Ok(v) => v,
            Err(_) => return,
        };

        token_balances
            .entry(token_key.clone())
            .or_default()
            .entry(from.to_string())
            .and_modify(|bal| *bal = bal.saturating_sub(value))
            .or_insert(U256::ZERO);

        token_balances
            .entry(token_key)
            .or_default()
            .entry(to.to_string())
            .and_modify(|bal| *bal = bal.saturating_add(value))
            .or_insert(value);
    }

    /// Get token balance for an address
    pub fn get_balance(&self, token: &Address, holder: &Address) -> U256 {
        let token_key = format!("{:#x}", token);
        self.token_balances
            .get(&token_key)
            .and_then(|balances| balances.get(&format!("{:#x}", holder)).copied())
            .unwrap_or(U256::ZERO)
    }

    /// Get all balances for a token
    pub fn get_token_balances(&self, token: &Address) -> HashMap<String, U256> {
        let token_key = format!("{:#x}", token);
        self.token_balances
            .get(&token_key)
            .map(|v| v.clone())
            .unwrap_or_default()
    }

    /// Get pair tokens
    pub fn get_pair_tokens(&self, pair: &Address) -> Option<(Address, Address)> {
        self.pair_cache.get(&format!("{:#x}", pair)).map(|v| *v)
    }
}
