//! Shared types and utilities for vuln-hunter

use alloy::primitives::{Address as PrimitiveAddress, Bytes, B256, U256 as PrimitiveU256, U64};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

pub type Address = PrimitiveAddress;
pub type U256 = PrimitiveU256;

/// Block header with minimal fields we care about
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub number: U64,
    pub hash: B256,
    pub parent_hash: B256,
    pub timestamp: U64,
    pub base_fee_per_gas: Option<U256>,
    pub gas_used: U256,
    pub gas_limit: U256,
}

/// Transaction with decoded fields
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    pub hash: B256,
    pub from: Address,
    pub to: Option<Address>,
    pub value: U256,
    pub gas: U256,
    pub gas_price: Option<U256>,
    pub max_fee_per_gas: Option<U256>,
    pub max_priority_fee_per_gas: Option<U256>,
    pub input: Bytes,
    pub nonce: U64,
    pub block_number: Option<U64>,
    pub block_hash: Option<B256>,
    pub transaction_index: Option<U64>,
}

/// Transaction receipt with logs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: B256,
    pub block_number: U64,
    pub block_hash: B256,
    pub transaction_index: U64,
    pub from: Address,
    pub to: Option<Address>,
    pub contract_address: Option<Address>,
    pub gas_used: U256,
    pub effective_gas_price: U256,
    pub status: bool,
    pub logs: Vec<Log>,
}

/// Event log
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Log {
    pub address: Address,
    pub topics: Vec<B256>,
    pub data: Bytes,
    pub block_number: U64,
    pub transaction_hash: B256,
    pub log_index: U64,
    pub removed: bool,
}

/// Contract deployment info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractDeployment {
    pub address: Address,
    pub deployer: Address,
    pub deployment_tx: B256,
    pub block_number: U64,
    pub timestamp: U64,
    pub bytecode: Bytes,
    pub is_proxy: bool,
    pub implementation: Option<Address>,
    pub verified: bool,
    pub abi: Option<serde_json::Value>,
}

/// Enriched contract with analysis results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedContract {
    pub deployment: ContractDeployment,
    pub tvl_usd: Option<f64>,
    pub token_balances: HashMap<Address, U256>,
    pub function_signatures: Vec<FunctionSignature>,
    pub proxy_chain: Vec<Address>,
    pub risk_factors: Vec<RiskFactor>,
}

/// Function signature from 4byte directory or heuristic
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    pub selector: [u8; 4],
    pub name: String,
    pub inputs: Vec<String>,
    pub source: SignatureSource,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SignatureSource {
    FourByteDirectory,
    Heuristic,
    VerifiedSource,
}

/// Risk factor detected during analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RiskFactor {
    pub kind: RiskKind,
    pub severity: Severity,
    pub description: String,
    pub location: Option<CodeLocation>,
    pub evidence: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum RiskKind {
    /// Admin-only check via hash comparison only
    AdminHashCheck,
    /// Shared balance across isolated pools/trances
    SharedBalance,
    /// Hook/callback with no validation
    UnvalidatedHook,
    /// Principal due but unpaid counted as repaid
    UnpaidPrincipalAsRepaid,
    /// Flash loan + state change in single transaction
    FlashLoanStateChange,
    /// Unverified contract with high TVL
    UnverifiedHighTVL,
    /// Upgradeable proxy with admin key
    UpgradeableProxy,
    /// Reentrancy vulnerability pattern
    Reentrancy,
    /// Integer overflow/underflow
    IntegerArithmetic,
    /// Access control missing
    MissingAccessControl,
    /// Oracle manipulation vector
    OracleManipulation,
    /// Custom pattern
    Custom(String),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}

/// Code location in bytecode or source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeLocation {
    pub pc: Option<u64>,
    pub function_selector: Option<[u8; 4]>,
    pub source_file: Option<String>,
    pub source_line: Option<u32>,
}

/// Analysis finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub contract: Address,
    pub risk_factors: Vec<RiskFactor>,
    pub overall_severity: Severity,
    pub exploitability_score: f64, // 0.0 - 1.0
    pub estimated_tvl_at_risk: Option<f64>,
    pub poc: Option<ProofOfConcept>,
    pub timestamp: U64,
}

/// Proof of concept exploit
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfConcept {
    pub description: String,
    pub steps: Vec<String>,
    pub exploit_contract: Option<String>, // Solidity source
    pub test_case: Option<String>,        // Foundry test
    pub required_capital: Option<U256>,
    pub expected_profit: Option<U256>,
    pub gas_estimate: Option<U256>,
}

/// Simulation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimulationResult {
    pub success: bool,
    pub profit: Option<U256>,
    pub gas_used: U256,
    pub state_changes: Vec<StateChange>,
    pub revert_reason: Option<String>,
    pub traces: Vec<CallTrace>,
}

/// State change during simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateChange {
    pub address: Address,
    pub storage_changes: HashMap<B256, B256>,
    pub balance_change: Option<i128>,
    pub code_change: Option<Bytes>,
}

/// Call trace from simulation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallTrace {
    pub from: Address,
    pub to: Address,
    pub value: U256,
    pub input: Bytes,
    pub output: Bytes,
    pub gas_used: U256,
    pub success: bool,
    pub calls: Vec<CallTrace>,
}

/// Configuration for the hunter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HunterConfig {
    pub rpc_url: String,
    pub ws_url: String,
    pub chains: Vec<ChainConfig>,
    pub filters: FilterConfig,
    pub alerting: AlertingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub name: String,
    pub rpc_url: String,
    pub ws_url: String,
    pub explorer_api_key: Option<String>,
    pub native_token: String,
    pub native_token_usd: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FilterConfig {
    pub min_tvl_usd: f64,
    pub max_contract_age_blocks: u64,
    pub watch_unverified_only: bool,
    pub watch_proxies: bool,
    pub interesting_selectors: Vec<[u8; 4]>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertingConfig {
    pub webhook_urls: Vec<String>,
    pub discord_webhook: Option<String>,
    pub telegram_bot_token: Option<String>,
    pub telegram_chat_id: Option<String>,
    pub min_severity: Severity,
}

impl Default for HunterConfig {
    fn default() -> Self {
        Self {
            rpc_url: "https://api.avax.network/ext/bc/C/rpc".to_string(),
            ws_url: "wss://api.avax.network/ext/bc/C/ws".to_string(),
            chains: vec![ChainConfig {
                chain_id: 43114,
                name: "Avalanche C-Chain".to_string(),
                rpc_url: "https://api.avax.network/ext/bc/C/rpc".to_string(),
                ws_url: "wss://api.avax.network/ext/bc/C/ws".to_string(),
                explorer_api_key: None,
                native_token: "AVAX".to_string(),
                native_token_usd: None,
            }],
            filters: FilterConfig {
                min_tvl_usd: 10_000.0,
                max_contract_age_blocks: 100_000,
                watch_unverified_only: true,
                watch_proxies: true,
                interesting_selectors: vec![],
            },
            alerting: AlertingConfig {
                webhook_urls: vec![],
                discord_webhook: None,
                telegram_bot_token: None,
                telegram_chat_id: None,
                min_severity: Severity::Medium,
            },
        }
    }
}
