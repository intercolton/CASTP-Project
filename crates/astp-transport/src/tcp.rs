//! Sessions over TLS 1.3 + HTTP/2 on TCP.

use crate::decoy::Decoy;
use crate::io::{pump_body, session_channels, ChannelBody, SessionIo};
use crate::{auth_header, AbortOnDrop, Accepted, TransportError, AUTH_SCHEME};
use astp_crypto::{
    channel_binding, client_credential_header, Authenticator, ClientSecret, ClientTlsConfig,
};
use bytes::Bytes;
use http::{Method, Request, Response, StatusCode, Version};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo, TokioTimer};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch, Semaphore};
use tokio::task::JoinSet;

/// Settings of a listener.
#[derive(Debug, Clone)]
pub struct ServerOptions {
    /// Secret path of the session endpoint, e.g. `/a8Kx…`. Anything else is
    /// the decoy site.
    pub session_path: String,
    pub decoy: Decoy,
    /// TLS (or QUIC) handshake deadline.
    pub handshake_timeout: Duration,
    /// Connections served at once; more are closed at accept.
    pub max_connections: usize,
}

impl Default for ServerOptions {
    fn default() -> Self {
        ServerOptions {
            session_path: "/".into(),
            decoy: Decoy::default(),
            handshake_timeout: Duration::from_secs(10),
            max_connections: 1024,
        }
    }
}

type RespBody = BoxBody<Bytes, Infallible>;

/// What a listener needs to judge requests.
#[derive(Clone)]
pub(crate) struct Gate {
    pub(crate) opts: Arc<ServerOptions>,
    pub(crate) auth: Arc<dyn Authenticator>,
    pub(crate) accepted: mpsc::Sender<Accepted>,
}

impl Gate {
    /// The client, when `req` is an authenticated session request on a
    /// connection with `binding`. `version` is the HTTP version the session
    /// must use on this transport.
    pub(crate) fn check<B>(
        &self,
        req: &Request<B>,
        binding: &astp_crypto::ChannelBinding,
        version: Option<Version>,
    ) -> Option<astp_crypto::ClientId> {
        if req.method() != Method::POST
            || req.uri().path() != self.opts.session_path
            || version.is_some_and(|v| req.version() != v)
        {
            return None;
        }
        let header = req
            .headers()
            .get(http::header::AUTHORIZATION)?
            .to_str()
            .ok()?;
        let token = header.strip_prefix(AUTH_SCHEME)?;
        // Decode errors and bad credentials alike end in the decoy; the
        // HMAC runs for any well-formed credential.
        let credential = astp_crypto::decode_credential_header(token).ok()?;
        match self.auth.verify(binding, &credential) {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::debug!("session request refused: {e}");
                None
            }
        }
    }

    pub(crate) fn decoy<B>(&self, req: &Request<B>) -> Response<Bytes> {
        self.opts.decoy.respond(req.method(), req.uri().path())
    }
}

/// Serves sessions on `listener` until `shutdown` turns true. Each
/// authenticated session is handed over on `accepted`.
pub async fn serve_tcp(
    listener: TcpListener,
    tls: Arc<rustls::ServerConfig>,
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
    let acceptor = tokio_rustls::TlsAcceptor::from(tls);
    let mut conns = JoinSet::new();
    loop {
        tokio::select! {
            _ = shutdown.changed() => break,
            Some(_) = conns.join_next(), if !conns.is_empty() => {}
            r = listener.accept() => {
                let (tcp, peer) = match r {
                    Ok(x) => x,
                    Err(e) => {
                        tracing::warn!("accept: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let Ok(permit) = limit.clone().try_acquire_owned() else {
                    continue;
                };
                let gate = gate.clone();
                let acceptor = acceptor.clone();
                let sd = shutdown.clone();
                conns.spawn(async move {
                    let _permit = permit;
                    serve_conn(gate, acceptor, tcp, peer, sd).await;
                });
            }
        }
    }
    // Sessions are told to stop by their owner; connections get a moment.
    let wait = async { while conns.join_next().await.is_some() {} };
    let _ = tokio::time::timeout(Duration::from_secs(3), wait).await;
    conns.shutdown().await;
}

async fn serve_conn(
    gate: Gate,
    acceptor: tokio_rustls::TlsAcceptor,
    tcp: TcpStream,
    peer: SocketAddr,
    mut shutdown: watch::Receiver<bool>,
) {
    let _ = tcp.set_nodelay(true);
    let tls = match tokio::time::timeout(gate.opts.handshake_timeout, acceptor.accept(tcp)).await {
        Ok(Ok(t)) => t,
        Ok(Err(e)) => {
            tracing::debug!(%peer, "TLS handshake failed: {e}");
            return;
        }
        Err(_) => return,
    };
    let Ok(binding) = channel_binding(tls.get_ref().1) else {
        return;
    };
    let svc = hyper::service::service_fn(move |req: Request<Incoming>| {
        let gate = gate.clone();
        async move { Ok::<_, Infallible>(handle(gate, req, binding, peer).await) }
    });
    let mut builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
    builder
        .http1()
        .timer(TokioTimer::new())
        .header_read_timeout(Duration::from_secs(20));
    builder
        .http2()
        .timer(TokioTimer::new())
        .keep_alive_interval(Duration::from_secs(30))
        .keep_alive_timeout(Duration::from_secs(20));
    let conn = builder.serve_connection(TokioIo::new(tls), svc);
    tokio::pin!(conn);
    tokio::select! {
        _ = conn.as_mut() => {}
        _ = shutdown.changed() => {
            conn.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(Duration::from_secs(2), conn.as_mut()).await;
        }
    }
}

async fn handle(
    gate: Gate,
    req: Request<Incoming>,
    binding: astp_crypto::ChannelBinding,
    peer: SocketAddr,
) -> Response<RespBody> {
    if let Some(client) = gate.check(&req, &binding, Some(Version::HTTP_2)) {
        let (io, in_tx, out_rx) = session_channels();
        let accepted = Accepted {
            client,
            peer,
            transport: "h2",
            io,
        };
        if gate.accepted.send(accepted).await.is_ok() {
            tokio::spawn(pump_body(req.into_body(), in_tx));
            return Response::builder()
                .status(StatusCode::OK)
                .header(http::header::CONTENT_TYPE, "application/octet-stream")
                .body(ChannelBody(out_rx).boxed())
                .expect("static response is valid");
        }
    }
    gate.decoy(&req).map(|b| Full::new(b).boxed())
}

/// Opens a session to `server` over TLS + HTTP/2.
pub async fn connect_tcp(
    server: SocketAddr,
    tls: ClientTlsConfig,
    secret: &ClientSecret,
    session_path: &str,
    timeout: Duration,
) -> Result<(SessionIo, AbortOnDrop), TransportError> {
    let work = async {
        let tcp = TcpStream::connect(server).await?;
        let _ = tcp.set_nodelay(true);
        let (config, name) = tls.into_parts();
        let authority = crate::authority(&name, server.port());
        let stream = tokio_rustls::TlsConnector::from(config)
            .connect(name, tcp)
            .await?;
        let conn = stream.get_ref().1;
        if conn.alpn_protocol() != Some(astp_crypto::TCP_ALPN[0]) {
            return Err(TransportError::Protocol(
                "server did not negotiate h2".into(),
            ));
        }
        let binding = channel_binding(conn).map_err(|e| TransportError::Protocol(e.to_string()))?;
        let (mut sender, conn) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .map_err(|e| TransportError::Http(e.to_string()))?;
        let guard = AbortOnDrop(tokio::spawn(async move {
            let _ = conn.await;
        }));
        let (io, in_tx, out_rx) = session_channels();
        let req = Request::post(format!("https://{authority}{session_path}"))
            .header(
                http::header::AUTHORIZATION,
                auth_header(&client_credential_header(secret, &binding)),
            )
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(ChannelBody(out_rx))
            .map_err(|e| TransportError::Http(e.to_string()))?;
        let resp = sender
            .send_request(req)
            .await
            .map_err(|e| TransportError::Http(e.to_string()))?;
        if resp.status() != StatusCode::OK {
            return Err(TransportError::Refused(resp.status().as_u16()));
        }
        tokio::spawn(pump_body(resp.into_body(), in_tx));
        Ok((io, guard))
    };
    tokio::time::timeout(timeout, work)
        .await
        .map_err(|_| TransportError::Timeout)?
}
