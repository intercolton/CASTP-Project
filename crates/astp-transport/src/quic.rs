//! Sessions over QUIC + HTTP/3.

use crate::io::{session_channels, SessionIo};
use crate::tcp::{Gate, ServerOptions};
use crate::{auth_header, AbortOnDrop, Accepted, TransportError};
use astp_crypto::{
    client_credential_header, Authenticator, ChannelBinding, ClientSecret, ClientTlsConfig,
    CHANNEL_BINDING_LABEL, CHANNEL_BINDING_LEN,
};
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

/// The ASTP-M channel binding of a QUIC connection: the TLS exporter
/// with the same label, length and empty context as over TCP.
fn binding(conn: &quinn::Connection) -> Option<ChannelBinding> {
    let mut b = [0u8; CHANNEL_BINDING_LEN];
    conn.export_keying_material(&mut b, CHANNEL_BINDING_LABEL.as_bytes(), &[])
        .ok()?;
    Some(ChannelBinding::from_exporter(b))
}

fn transport_config(idle: Duration) -> Result<Arc<quinn::TransportConfig>, TransportError> {
    let mut t = quinn::TransportConfig::default();
    t.max_idle_timeout(Some(
        idle.try_into()
            .map_err(|_| TransportError::Quic("idle timeout too large".into()))?,
    ));
    t.keep_alive_interval(Some(idle / 3));
    Ok(Arc::new(t))
}

/// A QUIC server endpoint. `tls` must be built for [`astp_crypto::AlpnMode::Quic`].
pub fn quic_endpoint_server(
    addr: SocketAddr,
    tls: Arc<rustls::ServerConfig>,
    idle: Duration,
) -> Result<quinn::Endpoint, TransportError> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|e| TransportError::Quic(e.to_string()))?;
    let mut sc = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    sc.transport_config(transport_config(idle)?);
    Ok(quinn::Endpoint::server(sc, addr)?)
}

/// Serves sessions on a QUIC endpoint until `shutdown` turns true.
pub async fn serve_quic(
    endpoint: quinn::Endpoint,
    auth: Arc<dyn Authenticator>,
    opts: ServerOptions,
    accepted: mpsc::Sender<Accepted>,
    mut shutdown: watch::Receiver<bool>,
) {
    let limit = Arc::new(Semaphore::new(opts.max_connections));
    let gate = Gate {
        opts: Arc::new(opts),
        auth,
        accepted,
    };
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    incoming.refuse();
                    continue;
                };
                let gate = gate.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    serve_conn(gate, incoming).await;
                });
            }
        }
    }
    let wait = async { while conns.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(3), wait).await;
    conns.shutdown().await;
    endpoint.close(0u32.into(), b"");
}

async fn serve_conn(gate: Gate, incoming: quinn::Incoming) {
    let peer = incoming.remote_address();
    let conn = match tokio::time::timeout(gate.opts.handshake_timeout, incoming).await {
        Ok(Ok(c)) => c,
        _ => return,
    };
    let Some(binding) = binding(&conn) else {
        return;
    };
    let Ok(mut h3) = h3::server::Connection::<_, Bytes>::new(h3_quinn::Connection::new(conn)).await
    else {
        return;
    };
    let mut streams = JoinSet::new();
    while let Ok(Some(resolver)) = h3.accept().await {
        while streams.try_join_next().is_some() {}
        let gate = gate.clone();
        streams.spawn(async move {
            let Ok((req, stream)) = resolver.resolve_request().await else {
                return;
            };
            serve_request(gate, req, stream, binding, peer).await;
        });
    }
    // Sessions keep their streams; they end when the connection does.
    while streams.join_next().await.is_some() {}
}

type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

async fn serve_request(
    gate: Gate,
    req: Request<()>,
    mut stream: ServerStream,
    binding: ChannelBinding,
    peer: SocketAddr,
) {
    if let Some(client) = gate.check(&req, &binding, None) {
        let ok = Response::builder()
            .status(StatusCode::OK)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(())
            .expect("static response is valid");
        if stream.send_response(ok).await.is_err() {
            return;
        }
        let (io, in_tx, out_rx) = session_channels();
        let (send, recv) = stream.split();
        let accepted = Accepted {
            client,
            peer,
            transport: "h3",
            io,
        };
        if gate.accepted.send(accepted).await.is_err() {
            return;
        }
        tokio::join!(pump_recv(recv, in_tx), pump_send(send, out_rx));
        return;
    }
    let resp = gate.decoy(&req);
    let (parts, body) = resp.into_parts();
    let head = Response::from_parts(parts, ());
    if stream.send_response(head).await.is_ok() {
        if !body.is_empty() {
            let _ = stream.send_data(body).await;
        }
        let _ = stream.finish().await;
    }
}

fn h3_err(e: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::ConnectionAborted, e.to_string())
}

/// Copies the received half of a request stream into the session's
/// input channel, and the session's output channel into the send half,
/// finishing the stream when the session closes its writer. Same code for
/// both ends; only the stream types differ.
macro_rules! pumps {
    ($recv_fn:ident, $send_fn:ident, $recv:ty, $send:ty) => {
        async fn $recv_fn(mut recv: $recv, tx: mpsc::Sender<io::Result<Bytes>>) {
            loop {
                let item = match recv.recv_data().await {
                    Ok(Some(mut b)) => Ok(b.copy_to_bytes(b.remaining())),
                    Ok(None) => return,
                    Err(e) => Err(h3_err(e)),
                };
                let stop = item.is_err();
                if tx.send(item).await.is_err() || stop {
                    return;
                }
            }
        }

        async fn $send_fn(mut send: $send, mut rx: mpsc::Receiver<Bytes>) {
            while let Some(b) = rx.recv().await {
                if send.send_data(b).await.is_err() {
                    return;
                }
            }
            let _ = send.finish().await;
        }
    };
}

pumps!(
    pump_recv,
    pump_send,
    h3::server::RequestStream<h3_quinn::RecvStream, Bytes>,
    h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>
);
pumps!(
    client_pump_recv,
    client_pump_send,
    h3::client::RequestStream<h3_quinn::RecvStream, Bytes>,
    h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>
);

/// Opens a session to `server` over QUIC + HTTP/3. `tls` must be built
/// for [`astp_crypto::AlpnMode::Quic`].
pub async fn connect_quic(
    server: SocketAddr,
    tls: ClientTlsConfig,
    secret: &ClientSecret,
    session_path: &str,
    timeout: Duration,
    idle: Duration,
) -> Result<(SessionIo, AbortOnDrop), TransportError> {
    let work = async {
        let (config, name) = tls.into_parts();
        let authority = crate::authority(&name, server.port());
        let sni = match &name {
            rustls::pki_types::ServerName::DnsName(d) => d.as_ref().to_owned(),
            rustls::pki_types::ServerName::IpAddress(ip) => std::net::IpAddr::from(*ip).to_string(),
            _ => return Err(TransportError::Protocol("unsupported server name".into())),
        };
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(config)
            .map_err(|e| TransportError::Quic(e.to_string()))?;
        let mut cc = quinn::ClientConfig::new(Arc::new(crypto));
        cc.transport_config(transport_config(idle)?);
        let local: SocketAddr = if server.is_ipv4() {
            (std::net::Ipv4Addr::UNSPECIFIED, 0).into()
        } else {
            (std::net::Ipv6Addr::UNSPECIFIED, 0).into()
        };
        let endpoint = quinn::Endpoint::client(local)?;
        let conn = endpoint
            .connect_with(cc, server, &sni)
            .map_err(|e| TransportError::Quic(e.to_string()))?
            .await
            .map_err(|e| TransportError::Quic(e.to_string()))?;
        let binding =
            binding(&conn).ok_or_else(|| TransportError::Protocol("no QUIC exporter".into()))?;
        let (mut driver, mut requests) = h3::client::new(h3_quinn::Connection::new(conn))
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let req = Request::post(format!("https://{authority}{session_path}"))
            .header(
                http::header::AUTHORIZATION,
                auth_header(&client_credential_header(secret, &binding)),
            )
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(())
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let stream = requests
            .send_request(req)
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let (send, mut recv) = stream.split();
        // The connection lives as long as the session holds the guard.
        let guard = AbortOnDrop(tokio::spawn(async move {
            let _keep = (endpoint, requests);
            let _ = driver.wait_idle().await;
        }));
        let resp = recv
            .recv_response()
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if resp.status() != StatusCode::OK {
            return Err(TransportError::Refused(resp.status().as_u16()));
        }
        let (io, in_tx, out_rx) = session_channels();
        tokio::spawn(client_pump_recv(recv, in_tx));
        tokio::spawn(client_pump_send(send, out_rx));
        Ok((io, guard))
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| TransportError::Timeout)?
}
