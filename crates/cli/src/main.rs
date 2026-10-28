//! vuln-hunter: Real-time DeFi vulnerability hunter
//!
//! Monitors blockchain for new contract deployments, analyzes bytecode for
//! vulnerable patterns, and simulates exploits in forked environments.

use vuln_common::{HunterConfig};
use vuln_ingestion::IngestionService;
use anyhow::{Context, Result};
use clap::Parser;
use figment::{Figment, providers::{Toml, Format}};
use std::path::PathBuf;
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

    if args.dry_run {
        info!("Running in DRY-RUN mode - no alerts will be sent");
    }

    // Create and start ingestion service
    let ingestion = IngestionService::new(config.clone()).await?;
    
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
    Ok(())
}
