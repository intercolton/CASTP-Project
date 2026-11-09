//! `astp-probe` — CLI client (spec 5.1).

use anyhow::{bail, Context, Result};
use clap::{Args, Parser, Subcommand};
use probe_client::stream::SessionPlan;
use probe_client::{run_long, run_quick, Selection};
use probe_common::config::{ClientConfig, ClientSection, TargetConfig};
use probe_common::jsonl::JsonlWriter;
use probe_common::ProbeEvent;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "astp-probe", version, about = "ASTP network probe client")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run short tests once (Quick Test)
    Test(Box<TestArgs>),
    /// Run tests on a schedule until stopped (Scheduled Test)
    Run {
        #[arg(long)]
        config: PathBuf,
    },
    /// Summarise stored results
    Report {
        #[arg(long, default_value = "24h")]
        last: String,
    },
    /// Show configuration and stored-result status
    Status {
        #[arg(long)]
        config: Option<PathBuf>,
    },
}

#[derive(Args)]
struct TestArgs {
    /// Client configuration file
    #[arg(long)]
    config: Option<PathBuf>,
    /// Only this target id from the configuration
    #[arg(long)]
    target: Option<String>,
    /// Ad-hoc target host (instead of --config)
    #[arg(long, conflicts_with = "config")]
    host: Option<String>,
    #[arg(long, default_value_t = 443)]
    port: u16,
    /// TLS server name for ad-hoc targets given as an IP
    #[arg(long)]
    sni: Option<String>,
    /// PEM CA file for ad-hoc targets with a private CA
    #[arg(long)]
    ca_file: Option<PathBuf>,
    /// Bind sockets to this interface (bypass a VPN), e.g. eno1
    #[arg(long)]
    interface: Option<String>,
    /// Network label written into events
    #[arg(long)]
    network: Option<String>,
    /// Do not write results to the data directory
    #[arg(long)]
    no_save: bool,
    #[arg(long)]
    all: bool,
    #[arg(long)]
    dns: bool,
    #[arg(long)]
    tcp: bool,
    #[arg(long)]
    tls: bool,
    #[arg(long)]
    https: bool,
    #[arg(long)]
    h2: bool,
    #[arg(long)]
    quic: bool,
    #[arg(long)]
    h3: bool,
    /// Bulk download over TLS + HTTP/2
    #[arg(long)]
    download: bool,
    /// Size of the download test in bytes
    #[arg(long, default_value_t = 1024 * 1024)]
    download_bytes: u64,
    #[arg(long)]
    controls: bool,
    /// Long session: the server sends a heartbeat every interval; catches
    /// connections that freeze or get cut after minutes or kilobytes
    #[arg(long)]
    long: bool,
    /// Long session length (default: schedule.long_duration_seconds)
    #[arg(long)]
    long_seconds: Option<u64>,
    #[arg(long, default_value_t = 1000)]
    long_interval_ms: u64,
    /// Heartbeat size in bytes
    #[arg(long, default_value_t = 1024)]
    long_size: usize,
    /// No data for this many seconds counts as a freeze
    #[arg(long, default_value_t = 15)]
    stall_seconds: u64,
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("start async runtime")?;
    match cli.cmd {
        Cmd::Test(a) => rt.block_on(cmd_test(*a)),
        Cmd::Status { config } => cmd_status(config),
        Cmd::Run { .. } => bail!("`run` (scheduled tests) is not implemented yet — stage C"),
        Cmd::Report { .. } => bail!("`report` is not implemented yet — stage D"),
    }
}

/// Short tests to run. `--long` alone runs only the long session.
fn selection(a: &TestArgs) -> Option<Selection> {
    let any =
        a.dns || a.tcp || a.tls || a.https || a.h2 || a.quic || a.h3 || a.download || a.controls;
    let sel = if a.all || !any {
        Selection::all()
    } else {
        Selection {
            dns: a.dns,
            tcp: a.tcp,
            tls: a.tls,
            https: a.https,
            h2: a.h2,
            quic: a.quic,
            h3: a.h3,
            download: a.download,
            controls: a.controls,
            download_bytes: 0,
        }
    };
    if a.long && !a.all && !any {
        return None;
    }
    Some(Selection {
        download_bytes: a.download_bytes,
        ..sel
    })
}

fn build_config(a: &TestArgs) -> Result<ClientConfig> {
    let mut cfg = if let Some(path) = &a.config {
        ClientConfig::load(path).with_context(|| format!("load {}", path.display()))?
    } else if let Some(host) = &a.host {
        let mut cfg = ClientConfig {
            client: ClientSection {
                id: hostname(),
                network_id: "adhoc".into(),
                log_level: "info".into(),
                data_dir: PathBuf::from("./data"),
                bind_interface: None,
            },
            schedule: Default::default(),
            limits: Default::default(),
            logs: Default::default(),
            delivery: None,
            targets: vec![TargetConfig {
                id: "adhoc".into(),
                host: host.clone(),
                port: a.port,
                tls_server_name: a.sni.clone(),
                ca_file: a.ca_file.clone(),
                enable_tcp: true,
                enable_tls: true,
                enable_h2: true,
                enable_quic: true,
                enable_h3: true,
                quic_port: a.port,
            }],
            controls: vec![],
        };
        cfg.apply_env(|k| std::env::var(k).ok());
        cfg.validate()?;
        cfg
    } else {
        bail!("give --config <file> or --host <name>");
    };
    if let Some(id) = &a.target {
        cfg.targets.retain(|t| &t.id == id);
        cfg.controls.clear();
        if cfg.targets.is_empty() {
            bail!("no target with id {id}");
        }
    }
    if let Some(i) = &a.interface {
        cfg.client.bind_interface = Some(i.clone());
    }
    if let Some(n) = &a.network {
        cfg.client.network_id = n.clone();
    }
    Ok(cfg)
}

async fn cmd_test(a: TestArgs) -> Result<()> {
    let cfg = build_config(&a)?;
    let sel = selection(&a);
    let mut writer = if a.no_save {
        None
    } else {
        let path = cfg.client.data_dir.join("events.jsonl");
        Some(
            JsonlWriter::open(&path, cfg.logs.max_file_bytes, cfg.logs.keep_files)
                .with_context(|| format!("open {}", path.display()))?,
        )
    };
    let mut failed = 0usize;
    let mut write_err = None;
    let mut record = |ev: ProbeEvent| {
        if !ev.success {
            failed += 1;
        }
        println!("{}", human(&ev));
        if let Some(w) = writer.as_mut() {
            if let Err(e) = w.write(&ev) {
                write_err.get_or_insert(e);
            }
        }
    };
    if let Some(sel) = sel {
        run_quick(&cfg, sel, &mut record).await;
    }
    if a.long {
        let plan = SessionPlan {
            seconds: a.long_seconds.unwrap_or(cfg.schedule.long_duration_seconds),
            interval_ms: a.long_interval_ms,
            size: a.long_size,
            stall_seconds: a.stall_seconds,
        };
        eprintln!(
            "long session: {} s, {} B every {} ms, freeze after {} s without data",
            plan.seconds, plan.size, plan.interval_ms, plan.stall_seconds
        );
        run_long(&cfg, plan, &mut record, |t, secs, bytes| {
            eprintln!("  {t}: {secs} s, {bytes} B received, still going");
        })
        .await;
    }
    if let Some(e) = write_err {
        bail!("could not save results: {e}");
    }
    if let Some(w) = &writer {
        eprintln!("results appended to {}", w.path().display());
    }
    if failed > 0 {
        std::process::exit(1);
    }
    Ok(())
}

fn human(ev: &ProbeEvent) -> String {
    let status = match (ev.success, ev.error_code) {
        (true, _) => "OK  ".to_string(),
        (false, Some(c)) => format!("FAIL {c}"),
        (false, None) => "FAIL".to_string(),
    };
    let mut s = format!(
        "{:<14} {:<15} {:<26} {:>6} ms",
        ev.target_id,
        ev.test_type.as_str(),
        status,
        ev.duration_ms
    );
    if let Some(p) = ev.phase {
        s.push_str(&format!(
            "  phase={}",
            serde_json::to_value(p).unwrap().as_str().unwrap_or("?")
        ));
    }
    if let Some(a) = &ev.alpn {
        s.push_str(&format!(" alpn={a}"));
    }
    if ev.bytes_sent + ev.bytes_received > 0 {
        s.push_str(&format!(" tx={} rx={}", ev.bytes_sent, ev.bytes_received));
    }
    if let Some(d) = &ev.detail {
        s.push_str(&format!("  — {d}"));
    }
    s
}

fn cmd_status(config: Option<PathBuf>) -> Result<()> {
    let Some(path) = config else {
        println!("no configuration given (use --config)");
        return Ok(());
    };
    let cfg = ClientConfig::load(&path)?;
    println!(
        "client:    {} (network {})",
        cfg.client.id, cfg.client.network_id
    );
    println!(
        "interface: {}",
        cfg.client
            .bind_interface
            .as_deref()
            .unwrap_or("default route")
    );
    println!(
        "targets:   {}",
        cfg.targets
            .iter()
            .map(|t| t.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    println!(
        "controls:  {}",
        cfg.controls
            .iter()
            .map(|c| c.id.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let log = cfg.client.data_dir.join("events.jsonl");
    match probe_common::jsonl::read_events(&log) {
        Ok((events, bad)) => {
            let ok = events.iter().filter(|e| e.success).count();
            println!(
                "results:   {} events ({} ok, {} failed), {} unreadable lines in {}",
                events.len(),
                ok,
                events.len() - ok,
                bad.len(),
                log.display()
            );
        }
        Err(_) => println!("results:   none yet ({})", log.display()),
    }
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "client".into())
}
