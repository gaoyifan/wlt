use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio_util::sync::CancellationToken;
use wlt::dns::{DnsConfig, DnsDaemon};

#[derive(Parser)]
#[command(version, about = "WLT split-forwarding DNS proxy")]
struct Args {
    /// Path to the standalone wlt-dns TOML configuration.
    #[arg(long)]
    config: PathBuf,

    /// Shared WLT config fragment directory. Only outlet_groups are imported;
    /// defaults to config.d next to the main DNS config.
    #[arg(long)]
    config_dir: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();
    let _ = rustls::crypto::ring::default_provider().install_default();

    let args = Args::parse();
    let config = DnsConfig::load(&args.config, args.config_dir.as_deref())?;
    let shutdown = CancellationToken::new();
    let daemon = DnsDaemon::run(config, shutdown.clone());
    tokio::pin!(daemon);

    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;
    tokio::select! {
        result = &mut daemon => return result,
        _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down"),
        _ = sigint.recv() => tracing::info!("received SIGINT, shutting down"),
    }
    shutdown.cancel();
    daemon.await
}
