//! QUIC + HTTP/3 listener (spec 4.2). Every incoming QUIC connection gets a
//! `quic_accept` event, including those whose handshake never completes;
//! `/probe` and `/echo` over HTTP/3 are logged with the client's test id.

use crate::handler::{request_event, ECHO_PATH, PROBE_PATH};
use crate::{tls, Shared};
use anyhow::{Context, Result};
use bytes::Bytes;
use http::{Response, StatusCode};
use probe_common::{ErrorCode, Phase, ProbeEvent, Side, TestType, Transport};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::watch;
use tokio::task::JoinSet;

pub fn endpoint(shared: &Shared, listen: &str) -> Result<quinn::Endpoint> {
    let cfg = &shared.cfg;
    let tls = tls::quic_server_config(&cfg.tls.cert_file, &cfg.tls.key_file)?;
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .context("TLS config is not usable for QUIC")?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    let idle = Duration::from_secs(cfg.limits.idle_timeout_seconds);
    transport.max_idle_timeout(Some(idle.try_into().context("idle timeout too large")?));
    sc.transport_config(Arc::new(transport));
    let addr: SocketAddr = listen.parse().context("quic.listen")?;
    quinn::Endpoint::server(sc, addr).with_context(|| format!("bind UDP {addr}"))
}

pub async fn accept_loop(
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
    mut shutdown: watch::Receiver<bool>,
) {
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let shared = shared.clone();
                conns.spawn(async move { handle_conn(shared, incoming).await });
            }
        }
    }
    endpoint.close(0u32.into(), b"server shutdown");
    conns.shutdown().await;
    let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
}

async fn handle_conn(shared: Arc<Shared>, incoming: quinn::Incoming) {
    let start = Instant::now();
    let cfg = &shared.cfg;
    let peer = incoming.remote_address();
    let mut ev = ProbeEvent::new(
        ProbeEvent::new_test_id(),
        &cfg.server.id,
        "server",
        &cfg.server.id,
        TestType::QuicAccept,
        Transport::Quic,
    );
    ev.side = Side::Server;
    ev.peer = Some(peer.to_string());
    // An Initial packet arrived: that is the first thing a QUIC server sees.
    ev.phase = Some(Phase::FirstBytesReceived);

    let Ok(_permit) = shared.limit.clone().try_acquire_owned() else {
        incoming.refuse();
        let _ = shared
            .tx
            .send(ev.fail(
                ErrorCode::Unknown,
                "server connection limit reached, refused",
            ))
            .await;
        return;
    };

    let hs_timeout = Duration::from_secs(cfg.limits.handshake_timeout_seconds);
    let conn = match tokio::time::timeout(hs_timeout, incoming).await {
        Ok(Ok(c)) => c,
        other => {
            let (code, detail) = match other {
                Err(_) => (
                    ErrorCode::QuicTimeout,
                    format!(
                        "no complete QUIC handshake within {}s",
                        hs_timeout.as_secs()
                    ),
                ),
                Ok(Err(quinn::ConnectionError::TimedOut)) => {
                    (ErrorCode::QuicTimeout, "handshake idle timeout".into())
                }
                Ok(Err(e)) => (ErrorCode::TlsHandshakeFailed, e.to_string()),
                Ok(Ok(_)) => unreachable!(),
            };
            ev.duration_ms = start.elapsed().as_millis() as u64;
            let _ = shared.tx.send(ev.fail(code, detail)).await;
            return;
        }
    };
    ev.handshake_ms = Some(start.elapsed().as_millis() as u64);
    ev.phase = Some(Phase::HandshakeDone);
    ev.tls_stack = Some(tls::TLS_STACK.into());
    ev.alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .map(|p| String::from_utf8_lossy(&p).into_owned());

    let requests = Arc::new(AtomicU64::new(0));
    let max = Duration::from_secs(cfg.limits.max_session_seconds + 30);
    let r = tokio::time::timeout(max, serve_h3(&shared, conn.clone(), peer, &requests)).await;

    let n = requests.load(Ordering::Relaxed);
    if n > 0 {
        ev.phase = Some(Phase::Completed);
    }
    let s = conn.stats();
    ev.duration_ms = start.elapsed().as_millis() as u64;
    ev.bytes_sent = s.udp_tx.bytes;
    ev.bytes_received = s.udp_rx.bytes;
    ev.detail = Some(format!("{n} request(s)"));
    let ev = match r {
        Err(_) => {
            conn.close(0u32.into(), b"session limit");
            ev.fail(
                ErrorCode::ApplicationTimeout,
                "connection exceeded the session limit",
            )
        }
        Ok(end) => {
            if let Some(e) = end {
                ev.detail = Some(format!("{n} request(s), closed: {e}"));
            }
            ev.succeed()
        }
    };
    let _ = shared.tx.send(ev).await;
}

/// Serves HTTP/3 until the client goes away. Returns why the connection
/// ended when that was not a clean close.
async fn serve_h3(
    shared: &Arc<Shared>,
    conn: quinn::Connection,
    peer: SocketAddr,
    requests: &AtomicU64,
) -> Option<String> {
    let mut h3 =
        match h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await {
            Ok(c) => c,
            // A QUIC-handshake-only test leaves before HTTP/3 starts.
            Err(e) if e.is_h3_no_error() => return None,
            Err(e) => return Some(e.to_string()),
        };
    let mut streams = JoinSet::new();
    let end = loop {
        match h3.accept().await {
            Ok(Some(resolver)) => {
                requests.fetch_add(1, Ordering::Relaxed);
                let shared = shared.clone();
                streams.spawn(async move {
                    let Ok((req, mut stream)) = resolver.resolve_request().await else {
                        return;
                    };
                    let started = Instant::now();
                    let (status, body, tt): (_, &'static [u8], _) =
                        match (req.method(), req.uri().path()) {
                            (&http::Method::GET, PROBE_PATH) => {
                                (StatusCode::OK, b"ok astp\n", Some(TestType::H3Request))
                            }
                            (&http::Method::GET, ECHO_PATH) => {
                                (StatusCode::OK, b"echo\n", Some(TestType::Echo))
                            }
                            (&http::Method::GET, _) => {
                                (StatusCode::NOT_FOUND, b"not found\n", None)
                            }
                            _ => (StatusCode::METHOD_NOT_ALLOWED, b"GET only\n", None),
                        };
                    let resp = Response::builder()
                        .status(status)
                        .header(http::header::CONTENT_TYPE, "text/plain")
                        .body(())
                        .expect("static response is valid");
                    let sent = async {
                        stream.send_response(resp).await?;
                        stream.send_data(Bytes::from_static(body)).await?;
                        stream.finish().await
                    }
                    .await;
                    if let Some(tt) = tt {
                        let mut ev = request_event(
                            &shared.cfg.server.id,
                            peer,
                            &req,
                            tt,
                            Transport::Quic,
                            "h3",
                        );
                        ev.duration_ms = started.elapsed().as_millis() as u64;
                        ev.bytes_sent = body.len() as u64;
                        ev.phase = Some(Phase::Completed);
                        let ev = match sent {
                            Ok(()) => ev.succeed(),
                            Err(e) => ev.fail(ErrorCode::RemoteClosed, e.to_string()),
                        };
                        if shared.tx.try_send(ev).is_err() {
                            tracing::warn!("event queue full, dropped a request event");
                        }
                    }
                });
            }
            Ok(None) => break None,
            Err(e) if e.is_h3_no_error() => break None,
            Err(e) => break Some(e.to_string()),
        }
    };
    while streams.join_next().await.is_some() {}
    end
}
