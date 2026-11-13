//! `astp-server` — ASTP-M VPN server.

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "astp-server", version, about = "ASTP-M VPN server")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Serve until SIGTERM or Ctrl-C
    Run {
        #[arg(long, default_value = "/etc/astp/server.toml")]
        config: PathBuf,
    },
    /// Check the configuration, certificate and client secrets, then exit
    Check {
        #[arg(long, default_value = "/etc/astp/server.toml")]
        config: PathBuf,
    },
    /// Print a new client secret and a session path
    Keygen,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd {
        Cmd::Keygen => {
            let (secret, path) = astp_server::keygen()?;
            println!("secret       = \"{secret}\"");
            println!("session_path = \"{path}\"");
            Ok(())
        }
        Cmd::Check { config } => {
            let cfg = astp_server::config::Config::load(&config)?;
            let clients = astp_server::check(&cfg, |k| std::env::var(k).ok())?;
            println!("configuration OK, {} client(s)", clients.len());
            Ok(())
        }
        Cmd::Run { config } => {
            let cfg = astp_server::config::Config::load(&config)
                .with_context(|| format!("load {}", config.display()))?;
            tracing_subscriber::fmt()
                .with_ansi(std::io::IsTerminal::is_terminal(&std::io::stderr()))
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                        tracing_subscriber::EnvFilter::new(&cfg.server.log_level)
                    }),
                )
                .init();
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .context("start async runtime")?;
            rt.block_on(async move {
                let (tx, rx) = tokio::sync::watch::channel(false);
                let mut server = tokio::spawn(astp_server::run(cfg, rx));
                tokio::select! {
                    r = &mut server => return r.context("server task")?,
                    _ = shutdown_signal() => {}
                }
                tracing::info!("stopping");
                let _ = tx.send(true);
                // Sessions send DISCONNECT 4, listeners close, then run() returns.
                server.await.context("server task")?
            })
        }
    }
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
