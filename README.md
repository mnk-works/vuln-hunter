# vuln-hunter

Real-time DeFi vulnerability hunter for EVM chains. Monitors blockchain for new contract deployments, analyzes bytecode for vulnerable patterns, and simulates exploits in forked environments.

## Features

- **Real-time block watching** via WebSocket - detects new contracts within seconds of deployment
- **Transaction pool monitoring** - catches pending deployments and flash loan transactions
- **Event indexing** - tracks Transfer, PairCreated, PoolCreated events for TVL calculation
- **TVL tracking** - monitors value locked in contracts
- **Bytecode pattern matching** - detects vulnerable patterns in unverified contracts
- **Fork-based simulation** - validates exploits against forked state (coming soon)
- **Multi-chain support** - Avalanche, Ethereum, Arbitrum, and more

## Vulnerability Patterns Detected

| Pattern | Description | Example |
|---------|-------------|---------|
| `AdminHashCheck` | Admin-only check via hash comparison only | Fence Finance tranche creation |
| `SharedBalance` | Shared balance across isolated pools/trances | Fence Finance single pool for all tranches |
| `UnvalidatedHook` | Hook/callback with no validation | Malicious hook returning `true` |
| `UnpaidPrincipalAsRepaid` | Principal due but unpaid counted as repaid | Fence Finance draw after day rollover |
| `FlashLoanStateChange` | Flash loan + state change in single TX | Most flash loan exploits |
| `UnverifiedHighTVL` | Unverified contract with significant TVL | High-risk deployment |

## Quick Start

```bash
# Clone and build
git clone https://github.com/modemnakata/vuln-hunter
cd vuln-hunter
cargo build --release

# Configure (edit config.toml with your RPC endpoints)
cp config.toml.example config.toml

# Run
./target/release/vuln-hunter
```

## Configuration

Edit `config.toml` to customize:

- **RPC endpoints** - HTTP and WebSocket URLs for each chain
- **Filters** - Minimum TVL, contract age, unverified-only mode
- **Alerting** - Discord, Telegram, webhook integrations
- **Patterns** - Custom function selectors to flag

## Architecture

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Ingestion  │────▶│ Enrichment  │────▶│  Analysis   │
│  (Rust)     │     │  (Rust)     │     │  (Rust)     │
│  - Blocks   │     │  - Bytecode │     │  - Patterns │
│  - Tx Pool  │     │  - Decompile│     │  - Symbolic │
│  - Events   │     │  - ABI Guess│     │  - Fork Sim │
│  - TVL      │     │  - Proxy    │     │             │
└─────────────┘     └─────────────┘     └──────┬──────┘
                                               │
                    ┌─────────────┐            │
                    │  Alerting   │◀───────────┘
                    │  (Python)   │
                    │  - Score    │
                    │  - Notify   │
                    │  - PoC Gen  │
                    └─────────────┘
```

## Crates

| Crate | Purpose |
|-------|---------|
| `vuln-common` | Shared types, config, risk factors |
| `vuln-ingestion` | Block watcher, tx pool, event indexer, TVL tracker |
| `vun-enrichment` | Bytecode fetching, decompilation, ABI guessing (planned) |
| `vuln-analysis` | Pattern matching, symbolic execution, fork simulation (planned) |
| `vuln-alerting` | Scoring, notification, PoC generation (planned) |

## Development

```bash
# Run tests
cargo test

# Check formatting
cargo fmt --check

# Lint
cargo clippy --all-targets

# Build all
cargo build --workspace --release
```

## Roadmap

- [x] Ingestion layer (blocks, tx pool, events, TVL)
- [ ] Enrichment layer (bytecode fetch, decompilation, proxy resolution)
- [ ] Analysis layer (YARA-style pattern matcher, symbolic executor)
- [ ] Simulation layer (revm fork manager, exploit simulator, fuzzer)
- [ ] Alerting layer (scoring, notifications, PoC generator)
- [ ] Python orchestration layer (LLM analysis, dashboard, rule engine)

## License

MIT OR Apache-2.0
