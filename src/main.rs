mod app;
mod config;
mod nft;
mod persist;
mod ssh;
mod web;

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use tokio::signal::unix::{SignalKind, signal};
use tokio::task::JoinSet;
use tokio_util::sync::CancellationToken;

use crate::app::AppState;

/// 网络通: nftables-based network outlet manager.
///
/// Services (web portal, SSH TUI, snapshot persistence) are enabled by the
/// presence of their config sections.
#[derive(Parser)]
#[command(version)]
struct Args {
    /// Path to the main config file; fragments are read from the sibling
    /// config.d/ directory.
    #[arg(long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    let args = Args::parse();
    let cfg = Arc::new(config::load_config(&args.config)?);
    let nft = nft::Nft::new(&cfg.nftables);
    let state = AppState::new(cfg.clone(), nft.clone());

    let shutdown = CancellationToken::new();
    let mut services: JoinSet<Result<()>> = JoinSet::new();
    if let Some(web_cfg) = cfg.web.clone() {
        services.spawn(web::serve(state.clone(), web_cfg));
    }
    if let Some(ssh_cfg) = cfg.ssh.clone() {
        services.spawn(ssh::serve(state.clone(), ssh_cfg));
    }
    if let Some(persist_cfg) = cfg.persist.clone() {
        services.spawn(persist::run(
            cfg.clone(),
            nft,
            persist_cfg,
            shutdown.clone(),
        ));
    }
    anyhow::ensure!(
        !services.is_empty(),
        "no services enabled: add a [web], [ssh] or [persist] section to the config"
    );

    let mut sigterm =
        signal(SignalKind::terminate()).context("failed to install SIGTERM handler")?;
    let mut sigint = signal(SignalKind::interrupt()).context("failed to install SIGINT handler")?;

    tokio::select! {
        _ = sigterm.recv() => tracing::info!("received SIGTERM, shutting down"),
        _ = sigint.recv() => tracing::info!("received SIGINT, shutting down"),
        // No service exits on its own before shutdown; any completion is fatal.
        Some(result) = services.join_next() => {
            shutdown.cancel();
            result.context("service panicked")??;
            anyhow::bail!("service exited unexpectedly");
        }
    }

    // On cancel only persist exits (after a final snapshot); wait for it.
    shutdown.cancel();
    if cfg.persist.is_some()
        && tokio::time::timeout(Duration::from_secs(10), services.join_next())
            .await
            .is_err()
    {
        tracing::warn!("persist did not finish within 10s");
    }
    Ok(())
}
