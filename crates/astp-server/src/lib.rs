//! ASTP-M v1 VPN server: TLS/HTTP/2 and QUIC/HTTP/3 listeners, client
//! sessions and packet routing to a TUN device (`docs/design/`).

#![forbid(unsafe_code)]

pub mod config;
pub mod core;

use crate::config::{Client, Config};
use crate::core::Core;
use anyhow::{Context, Result};
use astp_crypto::{AlpnMode, ClientId, Identity, KeyTable};
use astp_session::{Packet, SessionParams};
use astp_transport::{Decoy, ServerOptions};
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

/// The packet side of the server: channels to and from the TUN device
/// (or, in tests, whatever stands in for it).
pub struct TunSide {
    pub to_tun: mpsc::Sender<Packet>,
    pub from_tun: mpsc::Receiver<Packet>,
}

/// Where the listeners ended up (ports may be 0 in the config).
#[derive(Debug, Clone, Copy)]
pub struct Bound {
    pub tcp: SocketAddr,
    pub quic: Option<SocketAddr>,
}

fn decoy(cfg: &Config) -> Result<Decoy> {
    let mut d = Decoy::default();
    if let Some(p) = &cfg.decoy.index_file {
        d.index_html =
            Bytes::from(std::fs::read(p).with_context(|| format!("read {}", p.display()))?);
    }
    if let Some(p) = &cfg.decoy.not_found_file {
        d.not_found_html =
            Bytes::from(std::fs::read(p).with_context(|| format!("read {}", p.display()))?);
    }
    Ok(d)
}

fn tls(cfg: &Config, alpn: AlpnMode) -> Result<Arc<rustls::ServerConfig>> {
    astp_crypto::server_config(astp_crypto::ServerOptions {
        identity: Identity::Pem {
            certificate: cfg.tls.cert_file.clone(),
            private_key: cfg.tls.key_file.clone(),
        },
        client_auth: None,
        alpn,
    })
    .map_err(|e| anyhow::anyhow!("{e}"))
}

/// Checks the configuration, certificates and client secrets without
/// binding anything.
pub fn check(cfg: &Config, env: impl Fn(&str) -> Option<String>) -> Result<Vec<Client>> {
    tls(cfg, AlpnMode::Tcp)?;
    if cfg.server.listen_quic.is_some() {
        tls(cfg, AlpnMode::Quic)?;
    }
    decoy(cfg)?;
    let clients = cfg.clients(env)?;
    let mut table = KeyTable::new().map_err(|e| anyhow::anyhow!("{e}"))?;
    for c in &clients {
        table
            .insert(&c.secret, ClientId::new(c.name.as_bytes()))
            .with_context(|| format!("client {}", c.name))?;
    }
    Ok(clients)
}

/// Starts listeners and routing. Runs until `shutdown` turns true and
/// every session has said goodbye.
pub async fn serve(
    cfg: Config,
    clients: Vec<Client>,
    tun: TunSide,
    shutdown: watch::Receiver<bool>,
    bound: Option<tokio::sync::oneshot::Sender<Bound>>,
) -> Result<()> {
    let mut table = KeyTable::new().map_err(|e| anyhow::anyhow!("{e}"))?;
    for c in &clients {
        table.insert(&c.secret, ClientId::new(c.name.as_bytes()))?;
    }
    let auth: Arc<dyn astp_crypto::Authenticator> = Arc::new(table);
    let opts = ServerOptions {
        session_path: cfg.server.session_path.clone(),
        decoy: decoy(&cfg)?,
        handshake_timeout: Duration::from_secs(cfg.limits.handshake_timeout_seconds),
        max_connections: cfg.limits.max_connections,
    };
    let (_, prefix4) = cfg.tunnel4();
    let base = SessionParams {
        mtu: cfg.tunnel.mtu,
        dns4: cfg.tunnel.dns4.clone(),
        dns6: cfg.tunnel.dns6.clone(),
        routes: cfg.routes(),
        keepalive: cfg.keepalive(),
        idle_timeout: cfg.idle_timeout(),
        ..SessionParams::default()
    };
    let core = Arc::new(Core::new(
        clients,
        base,
        prefix4,
        cfg.tunnel6().map(|(_, p)| p),
        tun.to_tun,
        opts.handshake_timeout,
    ));

    let (acc_tx, mut acc_rx) = mpsc::channel(64);
    let listener = tokio::net::TcpListener::bind(cfg.server.listen_tcp)
        .await
        .with_context(|| format!("bind {}", cfg.server.listen_tcp))?;
    let mut addrs = Bound {
        tcp: listener.local_addr()?,
        quic: None,
    };
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(astp_transport::serve_tcp(
        listener,
        tls(&cfg, AlpnMode::Tcp)?,
        auth.clone(),
        opts.clone(),
        acc_tx.clone(),
        shutdown.clone(),
    ));
    if let Some(q) = cfg.server.listen_quic {
        let ep =
            astp_transport::quic_endpoint_server(q, tls(&cfg, AlpnMode::Quic)?, cfg.idle_timeout())
                .with_context(|| format!("bind UDP {q}"))?;
        addrs.quic = Some(ep.local_addr()?);
        tasks.spawn(astp_transport::serve_quic(
            ep,
            auth,
            opts,
            acc_tx,
            shutdown.clone(),
        ));
    } else {
        drop(acc_tx);
    }
    tracing::info!(tcp = %addrs.tcp, quic = ?addrs.quic, "listening");
    if let Some(b) = bound {
        let _ = b.send(addrs);
    }

    let mut from_tun = tun.from_tun;
    let dispatcher = {
        let core = core.clone();
        tokio::spawn(async move {
            while let Some(p) = from_tun.recv().await {
                core.dispatch(p);
            }
        })
    };
    let mut sessions = tokio::task::JoinSet::new();
    let mut sd = shutdown.clone();
    loop {
        tokio::select! {
            _ = sd.changed() => break,
            Some(_) = sessions.join_next(), if !sessions.is_empty() => {}
            acc = acc_rx.recv() => match acc {
                Some(acc) => {
                    sessions.spawn(core.clone().handle(acc, shutdown.clone()));
                }
                None => break,
            }
        }
    }
    // Sessions send DISCONNECT 4 on their own; give them a moment.
    let wait = async { while sessions.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(5), wait).await;
    sessions.shutdown().await;
    while tasks.join_next().await.is_some() {}
    dispatcher.abort();
    Ok(())
}

/// Production entry: creates and configures the TUN device, then serves.
pub async fn run(cfg: Config, shutdown: watch::Receiver<bool>) -> Result<()> {
    let clients = check(&cfg, |k| std::env::var(k).ok())?;
    let tun = astp_tun::Tun::create(&cfg.tunnel.device)
        .with_context(|| format!("create TUN {} (needs CAP_NET_ADMIN)", cfg.tunnel.device))?;
    let dev = tun.name().to_owned();
    let (a4, p4) = cfg.tunnel4();
    astp_tun::netcfg::add_addr(&dev, a4.into(), p4).await?;
    if let Some((a6, p6)) = cfg.tunnel6() {
        astp_tun::netcfg::add_addr(&dev, a6.into(), p6).await?;
    }
    astp_tun::netcfg::link_up(&dev, cfg.tunnel.mtu).await?;
    tracing::info!(device = %dev, address = %cfg.tunnel.address4, "tunnel device up");

    let (to_tun_tx, to_tun_rx) = mpsc::channel(4096);
    let (from_tun_tx, from_tun_rx) = mpsc::channel(4096);
    let pump = tokio::spawn(async move {
        if let Err(e) = astp_tun::pump(&tun, from_tun_tx, to_tun_rx).await {
            tracing::error!("TUN device failed: {e}");
        }
    });
    let r = serve(
        cfg,
        clients,
        TunSide {
            to_tun: to_tun_tx,
            from_tun: from_tun_rx,
        },
        shutdown,
        None,
    )
    .await;
    pump.abort();
    r
}

/// A new client secret and a session path, for `astp-server keygen`.
pub fn keygen() -> Result<(String, String)> {
    let secret = astp_crypto::ClientSecret::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let path = astp_crypto::ClientSecret::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
    Ok((secret.encode(), format!("/{}", &path.encode()[..22])))
}
