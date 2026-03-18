mod common;
mod config;
mod crypto;
mod obfs;
mod protocol;
mod server;
mod state;
mod udp_relay;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;
use std::str::FromStr;
use tracing_subscriber::filter::LevelFilter;

#[derive(Parser, Debug)]
#[command(name = "ssrr-server")]
#[command(
    about = "Simplified ShadowsocksR server in Rust (tls1.2_ticket_auth + auth_chain/auth_akarin)"
)]
struct Args {
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = config::AppConfig::load(&args.config)?;
    let level = LevelFilter::from_str(config.logging.level.trim()).with_context(|| {
        format!(
            "invalid logging.level `{}` (expected: trace/debug/info/warn/error)",
            config.logging.level
        )
    })?;

    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_target(false)
        .compact()
        .init();

    server::run(config).await
}
