//! QUIC handshake and HTTP/3 request (spec 6.1) on quinn + h3.
//!
//! QUIC has no connect step of its own: the handshake is the first thing on
//! the wire, so a failure leaves the phase at `dns_resolved` and the detail
//! says how many UDP bytes came back, which tells "nothing arrives" apart
//! from "the server answered but the handshake broke".

use crate::netutil::{self, Failure};
use crate::probes::{Attempt, Ctx, PROBE_PATH, TEST_ID_HEADER};
use crate::tlsutil::{self, TLS_STACK};
use bytes::Buf;
use probe_common::config::TargetConfig;
use probe_common::{ErrorCode, Phase, ProbeEvent, TestType, Transport};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

pub const H3_ALPN: &[u8] = b"h3";

pub async fn quic_handshake(ctx: &Ctx, t: &TargetConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::QuicHandshake, Transport::Quic);
    a.ev.tls_stack = Some(TLS_STACK.into());
    let r = async {
        let q = open(&mut a, ctx, t).await?;
        // quinn only offers QUIC v1 (RFC 9000).
        let detail = format!("QUIC v1, path MTU {}", q.conn.stats().path.current_mtu);
        q.close(&mut a);
        Ok(Some(detail))
    }
    .await;
    a.finish(r)
}

pub async fn h3(ctx: &Ctx, t: &TargetConfig) -> ProbeEvent {
    let mut a = Attempt::new(ctx, &t.id, TestType::H3Request, Transport::Quic);
    a.ev.tls_stack = Some(TLS_STACK.into());
    let r = async {
        let q = open(&mut a, ctx, t).await?;
        let authority = if t.quic_port == 443 {
            t.server_name().to_owned()
        } else {
            format!("{}:{}", t.server_name(), t.quic_port)
        };
        let uri = format!("https://{authority}{PROBE_PATH}?test_id={}", a.ev.test_id);
        let r = tokio::time::timeout(
            ctx.request_timeout(),
            h3_get(&mut a, &q.conn, &uri, ctx.limits.max_test_bytes),
        )
        .await;
        q.close(&mut a);
        let (status, len) = match r {
            Err(_) => {
                return Err(Failure::new(
                    ErrorCode::ApplicationTimeout,
                    format!(
                        "no complete HTTP/3 response within {}s",
                        ctx.request_timeout().as_secs()
                    ),
                ))
            }
            Ok(r) => r?,
        };
        if !status.is_success() {
            return Err(Failure::new(
                ErrorCode::HttpProtocolError,
                format!("HTTP status {status}"),
            ));
        }
        a.reached(Phase::Completed);
        Ok(Some(format!("HTTP {} h3, body {len} B", status.as_u16())))
    }
    .await;
    a.finish(r)
}

struct Quic {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
}

impl Quic {
    /// Closes politely so the server sees a clean end, and records UDP bytes.
    fn close(self, a: &mut Attempt) {
        // H3_NO_ERROR: the code HTTP/3 uses for an orderly close (RFC 9114 8.1).
        self.conn.close(0x100u32.into(), b"done");
        let s = self.conn.stats();
        a.ev.bytes_sent = s.udp_tx.bytes;
        a.ev.bytes_received = s.udp_rx.bytes;
        // Draining takes a few PTOs; keep it out of the measured duration.
        let endpoint = self.endpoint;
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(1), endpoint.wait_idle()).await;
        });
    }
}

async fn open(a: &mut Attempt, ctx: &Ctx, t: &TargetConfig) -> Result<Quic, Failure> {
    let addrs = netutil::resolve(&t.host, t.quic_port, ctx.connect_timeout()).await?;
    a.reached(Phase::DnsResolved);
    let addr = addrs[0];
    let endpoint = endpoint(addr, ctx.iface.as_deref())?;

    let tls = tlsutil::client_config(t.ca_file.as_deref(), &[H3_ALPN], true)?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|e| Failure::new(ErrorCode::Unknown, format!("QUIC TLS config: {e}")))?;
    let mut cfg = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    let idle = quinn::IdleTimeout::try_from(ctx.request_timeout()).expect("timeout fits");
    transport.max_idle_timeout(Some(idle));
    cfg.transport_config(Arc::new(transport));

    let connecting = endpoint
        .connect_with(cfg, addr, t.server_name())
        .map_err(|e| Failure::new(ErrorCode::Unknown, format!("QUIC connect: {e}")))?;
    let ts = Instant::now();
    let conn = match tokio::time::timeout(ctx.tls_timeout(), connecting).await {
        Ok(Ok(c)) => c,
        Ok(Err(e)) => return Err(classify(&e)),
        Err(_) => {
            return Err(Failure::new(
                ErrorCode::QuicTimeout,
                format!(
                    "no QUIC handshake within {}s (UDP to {addr})",
                    ctx.tls_timeout().as_secs()
                ),
            ))
        }
    };
    a.ev.handshake_ms = Some(ts.elapsed().as_millis() as u64);
    a.ev.alpn = conn
        .handshake_data()
        .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|d| d.protocol)
        .map(|p| String::from_utf8_lossy(&p).into_owned());
    a.reached(Phase::HandshakeDone);
    Ok(Quic { endpoint, conn })
}

/// A client endpoint on an ephemeral UDP port, optionally bound to `iface`.
fn endpoint(peer: SocketAddr, iface: Option<&str>) -> Result<quinn::Endpoint, Failure> {
    let local: SocketAddr = if peer.is_ipv4() {
        "0.0.0.0:0".parse().unwrap()
    } else {
        "[::]:0".parse().unwrap()
    };
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(peer),
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )
    .map_err(|e| Failure::new(ErrorCode::LocalNetworkUnavailable, format!("socket: {e}")))?;
    if let Some(dev) = iface {
        netutil::bind_to_interface(&socket, dev)?;
    }
    socket
        .bind(&local.into())
        .map_err(|e| Failure::new(ErrorCode::LocalNetworkUnavailable, format!("bind: {e}")))?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| Failure::new(ErrorCode::Unknown, "no async runtime for QUIC"))?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        None,
        socket.into(),
        runtime,
    )
    .map_err(|e| {
        Failure::new(
            ErrorCode::LocalNetworkUnavailable,
            format!("UDP endpoint: {e}"),
        )
    })
}

async fn h3_get(
    a: &mut Attempt,
    conn: &quinn::Connection,
    uri: &str,
    max_bytes: u64,
) -> Result<(http::StatusCode, u64), Failure> {
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .map_err(|e| h3_failure(&e.to_string()))?;
    let drive = tokio::spawn(async move { driver.wait_idle().await });
    let r = async {
        let req = http::Request::get(uri)
            .header(TEST_ID_HEADER, &a.ev.test_id)
            .header(http::header::USER_AGENT, "astp-probe/0.1")
            .body(())
            .map_err(|e| Failure::new(ErrorCode::Unknown, e.to_string()))?;
        let mut stream = send
            .send_request(req)
            .await
            .map_err(|e| h3_failure(&e.to_string()))?;
        stream
            .finish()
            .await
            .map_err(|e| h3_failure(&e.to_string()))?;
        a.reached(Phase::AppDataSent);
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| h3_failure(&e.to_string()))?;
        a.reached(Phase::AppDataReceived);
        let mut len = 0u64;
        while let Some(chunk) = stream
            .recv_data()
            .await
            .map_err(|e| h3_failure(&e.to_string()))?
        {
            len += chunk.remaining() as u64;
            if len > max_bytes {
                return Err(Failure::new(
                    ErrorCode::HttpProtocolError,
                    format!("body exceeds {max_bytes} B"),
                ));
            }
        }
        Ok((resp.status(), len))
    }
    .await;
    drop(send);
    drive.abort();
    r
}

fn h3_failure(msg: &str) -> Failure {
    let code = if msg.contains("timeout") || msg.contains("timed out") {
        ErrorCode::QuicTimeout
    } else if msg.contains("closed") || msg.contains("reset") {
        ErrorCode::RemoteClosed
    } else {
        ErrorCode::HttpProtocolError
    };
    Failure::new(code, msg.to_owned())
}

fn classify(e: &quinn::ConnectionError) -> Failure {
    use quinn::ConnectionError as E;
    let msg = e.to_string();
    let code = match e {
        E::TimedOut => ErrorCode::QuicTimeout,
        E::TransportError(_) | E::ConnectionClosed(_) if msg.contains("certificate") => {
            ErrorCode::TlsCertificateError
        }
        E::TransportError(_) | E::ConnectionClosed(_) => ErrorCode::TlsHandshakeFailed,
        E::ApplicationClosed(_) | E::Reset => ErrorCode::RemoteClosed,
        _ => ErrorCode::Unknown,
    };
    Failure::new(code, msg)
}
