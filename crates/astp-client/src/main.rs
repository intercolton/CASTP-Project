//! `astp-client` — ASTP-M VPN client.

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "astp-client", version, about = "ASTP-M VPN client")]
struct Cli {
    #[arg(long, default_value = "/etc/astp/client.toml")]
    config: PathBuf,
    /// Check the configuration and secret, then exit
    #[arg(long)]
    check: bool,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let cfg = astp_client::config::Config::load(&cli.config)
        .with_context(|| format!("load {}", cli.config.display()))?;
    if cli.check {
        cfg.secret(|k| std::env::var(k).ok())?;
        println!("configuration OK");
        return Ok(());
    }
    tracing_subscriber::fmt()
        .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(&cfg.client.log_level)),
        )
        .init();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start async runtime")?;
    rt.block_on(async move {
        let (tx, rx) = tokio::sync::watch::channel(false);
        let mut client = tokio::spawn(astp_client::run(cfg, rx));
        tokio::select! {
            r = &mut client => return r.context("client task")?,
            _ = shutdown_signal() => {}
        }
        tracing::info!("stopping");
        let _ = tx.send(true);
        client.await.context("client task")?
    })
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

#[cfg(not(unix))]
async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
