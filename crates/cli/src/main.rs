//! vuln-hunter: Real-time DeFi vulnerability hunter
//! 
//! Monitors blockchain for new contract deployments, analyzes bytecode for
//! vulnerable patterns, and simulates exploits in forked environments.

use vuln_common::{HunterConfig, Finding};
use vuln_ingestion::{IngestionService, BlockWatcher};
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use figment::{Figment, providers::{Toml, Format}};
use serde_json;
use std::path::PathBuf;
use std::sync::Arc;
use tracing::{error, info, Level};
use tracing_subscriber::EnvFilter;

#[derive(Parser, Debug)]
#[command(name = "vuln-hunter", version, about = "Real-time DeFi vulnerability hunter")]
struct Args {
    /// Configuration file path
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Log level
    #[arg(short, long, default_value = "info")]
    log_level: String,

    /// Chain to monitor (overrides config)
    #[arg(short, long)]
    chain: Option<String>,

    /// Run in dry-run mode (no alerts)
    #[arg(long)]
    dry_run: bool,

    /// Print config and exit
    #[arg(long)]
    print_config: bool,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Watch for new deployments in real-time (default)
    Watch,
    
    /// Scan historical blocks for vulnerable contracts
    Scan {
        /// Start block number (inclusive)
        #[arg(long, default_value = "0")]
        from_block: u64,
        
        /// End block number (inclusive, 0 = latest)
        #[arg(long, default_value = "0")]
        to_block: u64,
        
        /// Only scan contracts matching these patterns
        #[arg(long)]
        patterns: Vec<String>,
        
        /// Minimum TVL in USD to consider
        #[arg(long, default_value = "10000")]
        min_tvl: f64,
        
        /// Output file for findings (JSON)
        #[arg(long)]
        output: Option<PathBuf>,
    },
    
    /// Analyze a specific contract address
    Analyze {
        /// Contract address to analyze
        address: String,
        
        /// Block number to analyze at (0 = latest)
        #[arg(long, default_value = "0")]
        block: u64,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Initialize logging
    let log_level = args.log_level.parse::<Level>().unwrap_or(Level::INFO);
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(log_level.into()))
        .with_target(false)
        .with_thread_ids(true)
        .with_file(true)
        .with_line_number(true)
        .init();

    info!("Starting vuln-hunter");

    // Load configuration
    let mut config: HunterConfig = Figment::new()
        .merge(Toml::file(&args.config))
        
        .extract()
        .context("Failed to load configuration")?;

    // Override chain if provided
    if let Some(chain_name) = args.chain {
        if let Some(chain) = config.chains.iter().find(|c| c.name == chain_name).cloned() {
            config.chains = vec![chain];
        }
    }

    if args.print_config {
        println!("{}", toml::to_string(&config)?);
        return Ok(());
    }

    let config_arc = Arc::new(config);
    let command = args.command.unwrap_or(Command::Watch);

    match command {
        Command::Watch => {
            if args.dry_run {
                info!("Running in DRY-RUN mode - no alerts will be sent");
            }

            // Create and start ingestion service
            let ingestion = IngestionService::new((*config_arc).clone()).await?;
            
            info!("Ingestion service started, watching for new blocks...");

            // Start ingestion
            let ingestion_handle = tokio::spawn(async move {
                if let Err(e) = ingestion.start().await {
                    error!("Ingestion service error: {}", e);
                }
            });

            // Wait for shutdown signal
            tokio::signal::ctrl_c().await?;
            info!("Shutdown signal received, stopping...");

            ingestion_handle.abort();

            info!("vuln-hunter stopped");
        }
        Command::Scan { from_block, to_block, patterns, min_tvl, output } => {
            info!("Starting historical scan from block {} to {}", from_block, if to_block == 0 { "latest".to_string() } else { to_block.to_string() });
            
            let chain_config = config_arc.chains.first().context("No chain configured")?.clone();
            let http_provider = alloy::providers::ProviderBuilder::new()
                .on_http(chain_config.rpc_url.parse()?);
            
            let watcher: BlockWatcher = BlockWatcher::new_for_scanning(http_provider, config_arc.clone()).await?;
            
            let findings: Vec<Finding> = watcher.scan_historical(from_block, to_block, &patterns, min_tvl).await?;
            
            info!("Found {} potentially vulnerable contracts", findings.len());
            
            for finding in &findings {
                info!("VULNERABLE: {} - {} - {:?}", finding.contract, finding.vulnerability_type, finding.risk_factors.first().map(|rf| &rf.description));
            }
            
            if let Some(output_path) = output {
                let json = serde_json::to_string_pretty(&findings)?;
                std::fs::write(&output_path, json)?;
                info!("Results written to {}", output_path.display());
            }
        }
        Command::Analyze { address, block } => {
            info!("Analyzing contract {} at block {}", address, if block == 0 { "latest".to_string() } else { block.to_string() });
            
            let chain_config = config_arc.chains.first().context("No chain configured")?.clone();
            let http_provider = alloy::providers::ProviderBuilder::new()
                .on_http(chain_config.rpc_url.parse()?);
            
            let watcher: BlockWatcher = BlockWatcher::new_for_scanning(http_provider, config_arc.clone()).await?;
            
            let contract_addr = address.parse().context("Invalid address")?;
            let analysis = watcher.analyze_contract(contract_addr, if block == 0 { None } else { Some(block) }).await?;
            
            println!("{}", serde_json::to_string_pretty(&analysis)?);
        }
    }

    Ok(())
}
