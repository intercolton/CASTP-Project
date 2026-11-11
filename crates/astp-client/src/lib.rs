//! ASTP-M v1 VPN client: connects, takes the server's CONFIG, brings up
//! a TUN device with its addresses and routes, and moves packets until
//! stopped, reconnecting when the session drops (`docs/design/`).

#![forbid(unsafe_code)]

pub mod config;
pub mod routes;

use crate::config::{Config, TransportChoice};
use crate::routes::{plan, Target};
use anyhow::{anyhow, bail, Context, Result};
use astp_crypto::{AlpnMode, ClientOptions, ClientSecret, TrustAnchors};
use astp_frame::FrameReader;
use astp_session::{
    client_handshake, run as run_session, EndReason, Link, Packet, Role, SessionParams, Stats,
};
use astp_transport::{AbortOnDrop, ByteReader, ByteWriter};
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, watch};

/// A connected, authenticated session that has not exchanged frames yet.
pub struct Connected {
    pub reader: ByteReader,
    pub writer: ByteWriter,
    pub guard: AbortOnDrop,
    /// `"h2"` or `"h3"`.
    pub transport: &'static str,
    pub server: SocketAddr,
}

fn trust(cfg: &Config) -> Result<TrustAnchors> {
    let Some(path) = &cfg.client.ca_file else {
        return Ok(TrustAnchors::Webpki);
    };
    use rustls_pki_types::pem::PemObject;
    let mut roots = rustls::RootCertStore::empty();
    for c in rustls_pki_types::CertificateDer::pem_file_iter(path)
        .with_context(|| format!("read {}", path.display()))?
    {
        roots.add(c.with_context(|| format!("parse {}", path.display()))?)?;
    }
    if roots.is_empty() {
        bail!("{} has no certificate", path.display());
    }
    Ok(TrustAnchors::Explicit(roots))
}

fn tls(cfg: &Config, alpn: AlpnMode) -> Result<astp_crypto::ClientTlsConfig> {
    astp_crypto::client_config(ClientOptions {
        trust: trust(cfg)?,
        alpn,
        host: cfg.host().to_owned(),
        tls_server_name: cfg.client.tls_server_name.clone(),
        client_identity: None,
    })
    .map_err(|e| anyhow!("{e}"))
}

/// Resolves the server, IPv4 first.
pub async fn resolve(cfg: &Config) -> Result<SocketAddr> {
    let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host(&cfg.client.server)
        .await
        .with_context(|| format!("resolve {}", cfg.client.server))?
        .collect();
    addrs.sort_by_key(|a| !a.is_ipv4());
    addrs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("{} resolves to nothing", cfg.client.server))
}

/// Opens a session over the configured transport.
pub async fn connect(cfg: &Config, secret: &ClientSecret) -> Result<Connected> {
    let server = resolve(cfg).await?;
    let path = &cfg.client.session_path;
    let timeout = cfg.connect_timeout();
    let h3 = || async {
        astp_transport::connect_quic(
            server,
            tls(cfg, AlpnMode::Quic)?,
            secret,
            path,
            timeout.min(Duration::from_secs(5)),
            Duration::from_secs(60),
        )
        .await
        .map_err(anyhow::Error::from)
    };
    let h2 = || async {
        astp_transport::connect_tcp(server, tls(cfg, AlpnMode::Tcp)?, secret, path, timeout)
            .await
            .map_err(anyhow::Error::from)
    };
    let (io, guard, transport) = match cfg.client.transport {
        TransportChoice::H3 => h3().await.map(|(io, g)| (io, g, "h3"))?,
        TransportChoice::H2 => h2().await.map(|(io, g)| (io, g, "h2"))?,
        TransportChoice::Auto => match h3().await {
            Ok((io, g)) => (io, g, "h3"),
            Err(e) => {
                tracing::info!("HTTP/3 failed ({e:#}), trying HTTP/2");
                h2().await.map(|(io, g)| (io, g, "h2"))?
            }
        },
    };
    Ok(Connected {
        reader: io.reader,
        writer: io.writer,
        guard,
        transport,
        server,
    })
}

/// Reads the server's CONFIG and acknowledges it. A CONFIG without an
/// IPv4 address is refused.
pub async fn handshake(c: &mut Connected) -> Result<(FrameReader<ByteReader>, SessionParams)> {
    let reader = std::mem::replace(&mut c.reader, empty_reader());
    let mut reader = FrameReader::new(reader);
    let params = client_handshake(&mut reader, &mut c.writer, Duration::from_secs(15), |p| {
        if p.addr4.is_none() {
            Err("no IPv4 address in CONFIG".into())
        } else {
            Ok(())
        }
    })
    .await?;
    Ok((reader, params))
}

fn empty_reader() -> ByteReader {
    astp_transport::ByteReader::closed()
}

/// The packet side, alive across reconnects: the session of the moment
/// gets packets from the device through `current`.
struct Device {
    to_tun: mpsc::Sender<Packet>,
    current: Arc<Mutex<Option<mpsc::Sender<Packet>>>>,
    name: String,
    routes: astp_tun::netcfg::Routes,
    applied: SessionParams,
    _tasks: Vec<AbortOnDropTask>,
}

struct AbortOnDropTask(tokio::task::JoinHandle<()>);
impl Drop for AbortOnDropTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn bring_up(cfg: &Config, p: &SessionParams, server: IpAddr) -> Result<Device> {
    use astp_tun::netcfg;
    let tun = astp_tun::Tun::create(&cfg.client.device)
        .with_context(|| format!("create TUN {} (needs CAP_NET_ADMIN)", cfg.client.device))?;
    let dev = tun.name().to_owned();
    if let Some((a, pre)) = p.addr4 {
        netcfg::add_addr(&dev, a.into(), pre).await?;
    }
    if let Some((a, pre)) = p.addr6 {
        netcfg::add_addr(&dev, a.into(), pre).await?;
    }
    netcfg::link_up(&dev, p.mtu).await?;

    let mut routes = netcfg::Routes::default();
    let planned = plan(&p.routes, server);
    // Look the original paths up before any tunnel route exists.
    let mut originals = Vec::new();
    for r in planned.iter().filter(|r| r.target == Target::Original) {
        originals.push(netcfg::route_get(r.dest).await?);
    }
    let mut orig = originals.into_iter();
    for r in &planned {
        let via = match r.target {
            Target::Original => orig.next().expect("one lookup per original route"),
            Target::Tunnel => netcfg::Via {
                gateway: None,
                dev: dev.clone(),
            },
        };
        if let Err(e) = routes.add(r.dest, r.prefix, via).await {
            routes.remove_all().await;
            return Err(e.into());
        }
    }
    if cfg.client.set_dns {
        let dns: Vec<IpAddr> = p
            .dns4
            .iter()
            .map(|a| IpAddr::V4(*a))
            .chain(p.dns6.iter().map(|a| IpAddr::V6(*a)))
            .collect();
        if !dns.is_empty() {
            if let Err(e) = netcfg::set_dns(&dev, &dns).await {
                tracing::warn!("DNS not set: {e}");
            }
        }
    } else if !p.dns4.is_empty() || !p.dns6.is_empty() {
        tracing::info!(dns4 = ?p.dns4, dns6 = ?p.dns6, "server suggests DNS (set_dns = false)");
    }

    let tun = Arc::new(tun);
    let (to_tun, mut to_tun_rx) = mpsc::channel::<Packet>(4096);
    let current: Arc<Mutex<Option<mpsc::Sender<Packet>>>> = Arc::new(Mutex::new(None));
    let writer = {
        let tun = tun.clone();
        AbortOnDropTask(tokio::spawn(async move {
            while let Some(p) = to_tun_rx.recv().await {
                if let Err(e) = tun.send(&p).await {
                    tracing::debug!("TUN write: {e}");
                }
            }
        }))
    };
    let reader = {
        let current = current.clone();
        AbortOnDropTask(tokio::spawn(async move {
            let mut buf = vec![0u8; astp_tun::MAX_PACKET];
            loop {
                let n = match tun.recv(&mut buf).await {
                    Ok(n) => n,
                    Err(e) => {
                        tracing::error!("TUN read: {e}");
                        return;
                    }
                };
                let tx = current.lock().expect("session slot").clone();
                if let Some(tx) = tx {
                    let _ = tx.try_send(buf[..n].to_vec());
                }
            }
        }))
    };
    tracing::info!(device = %dev, addr4 = ?p.addr4, addr6 = ?p.addr6, mtu = p.mtu, routes = routes.added().len(), "tunnel up");
    Ok(Device {
        to_tun,
        current,
        name: dev,
        routes,
        applied: p.clone(),
        _tasks: vec![writer, reader],
    })
}

/// Connects, brings the tunnel up and keeps it up until `shutdown`,
/// reconnecting with a growing pause (1 s to 60 s) when sessions drop.
pub async fn run(cfg: Config, mut shutdown: watch::Receiver<bool>) -> Result<()> {
    let secret = cfg.secret(|k| std::env::var(k).ok())?;
    let mut device: Option<Device> = None;
    let mut backoff = Duration::from_secs(1);
    let result = loop {
        if *shutdown.borrow() {
            break Ok(());
        }
        let attempt = async {
            let mut c = connect(&cfg, &secret).await?;
            let (reader, params) = handshake(&mut c).await?;
            Ok::<_, anyhow::Error>((c, reader, params))
        };
        let (c, reader, params) = tokio::select! {
            _ = shutdown.changed() => break Ok(()),
            r = attempt => match r {
                Ok(x) => x,
                Err(e) => {
                    tracing::warn!("cannot connect: {e:#}; retrying in {} s", backoff.as_secs());
                    tokio::select! {
                        _ = shutdown.changed() => break Ok(()),
                        _ = tokio::time::sleep(backoff) => {}
                    }
                    backoff = (backoff * 2).min(Duration::from_secs(60));
                    continue;
                }
            }
        };
        if device
            .as_ref()
            .is_some_and(|d| d.applied.addr4 != params.addr4 || d.applied.addr6 != params.addr6)
        {
            break Err(anyhow!(
                "the server changed this client's tunnel address; restart the client"
            ));
        }
        if device.is_none() {
            match bring_up(&cfg, &params, c.server.ip()).await {
                Ok(d) => device = Some(d),
                Err(e) => break Err(e),
            }
        }
        let d = device.as_ref().expect("brought up above");
        tracing::info!(server = %c.server, transport = c.transport, device = %d.name, "session up");
        let (from_tun_tx, from_tun_rx) = mpsc::channel(1024);
        *d.current.lock().expect("session slot") = Some(from_tun_tx);
        let started = Instant::now();
        let mut sd = shutdown.clone();
        let end = run_session(
            Role::Client,
            reader,
            c.writer,
            &params,
            Link {
                to_local: d.to_tun.clone(),
                from_local: from_tun_rx,
                events: None,
            },
            Arc::new(Stats::default()),
            async move {
                let _ = sd.changed().await;
                astp_session::code::NORMAL
            },
        )
        .await;
        *d.current.lock().expect("session slot") = None;
        drop(c.guard);
        tracing::info!("session ended: {end:?}");
        if matches!(end, EndReason::LocalStop(_)) || *shutdown.borrow() {
            break Ok(());
        }
        if started.elapsed() > Duration::from_secs(30) {
            backoff = Duration::from_secs(1);
        }
        tokio::select! {
            _ = shutdown.changed() => break Ok(()),
            _ = tokio::time::sleep(backoff) => {}
        }
        backoff = (backoff * 2).min(Duration::from_secs(60));
    };
    if let Some(mut d) = device {
        d.routes.remove_all().await;
        tracing::info!(device = %d.name, "tunnel down");
    }
    result
}
