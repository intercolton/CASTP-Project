//! `astp-probe-server` — diagnostic server (spec 4).

use anyhow::{Context, Result};
use clap::Parser;
use probe_common::config::ServerConfig;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "astp-probe-server",
    version,
    about = "ASTP network probe server"
)]
struct Cli {
    #[arg(long, default_value = "/etc/astp-probe/server.toml")]
    config: PathBuf,
    /// Only validate the configuration and certificates, then exit
    #[arg(long)]
    check: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = ServerConfig::load(&cli.config)
        .with_context(|| format!("load {}", cli.config.display()))?;
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.server.log_level)),
        )
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start async runtime")?;
    rt.block_on(async move {
        if cli.check {
            probe_server::check(&cfg)?;
            println!("configuration OK");
            return Ok(());
        }
        let handle = probe_server::start(cfg).await?;
        shutdown_signal().await;
        tracing::info!("stopping");
        handle.shutdown().await
    })
}

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(unix)]
async fn shutdown_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("install SIGTERM handler");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {}
        _ = term.recv() => {}
    }
}
