//! QUIC listener and client.
//!
//! ALPN `h3` is handed to the HTTP/3 layer. Any other negotiated protocol,
//! including `h2`, is closed with application code 0 and an empty reason.
//! The brief names that close `H3_NO_ERROR / 0`. RFC 9114's `H3_NO_ERROR`
//! is `0x100`; the numeric code here is the `0` written in the brief, and
//! the reason is empty so the peer sees no banner.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use astp_crypto::{channel_binding, ClientTls};
use astp_types::ALPN_H3;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;

use crate::limits::QuicLimits;
use crate::TransportError;

/// A finished QUIC handshake whose ALPN is `h3`.
///
/// `binding` is the ASTP-M exporter, taken immediately after the handshake.
pub struct Accepted {
    /// Established QUIC connection.
    pub conn: quinn::Connection,
    /// Channel binding for this connection.
    pub binding: astp_crypto::ChannelBinding,
    /// UDP address of the peer.
    pub remote: SocketAddr,
}

/// QUIC server. [`QuicServer::accept`] yields connections that negotiated `h3`.
pub struct QuicServer {
    endpoint: quinn::Endpoint,
    incoming: mpsc::Receiver<Accepted>,
    pending: Arc<AtomicUsize>,
    shutdown: Option<oneshot::Sender<()>>,
    driver: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for QuicServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicServer")
            .field("pending", &self.pending_handshakes())
            .finish_non_exhaustive()
    }
}

impl Drop for QuicServer {
    fn drop(&mut self) {
        self.signal_stop();
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

impl QuicServer {
    /// Bind a QUIC listener.
    ///
    /// `config` must be TLS 1.3 with 0-RTT off (`max_early_data_size == 0`)
    /// and half-RTT off. [`quinn::crypto::rustls::QuicServerConfig::try_from`]
    /// does not rewrite those fields. A non-zero early-data limit is
    /// [`TransportError::ZeroRttEnabled`]. rustls does not expose the enabled
    /// protocol versions, so a config that is not TLS 1.3 is not rejected
    /// here; [`astp_crypto::server_config`] is the config this stack builds,
    /// and it enables TLS 1.3 only. Quinn panics later if that check would
    /// have failed, which is why callers use `server_config`.
    ///
    /// # Errors
    ///
    /// [`TransportError::ZeroRttEnabled`], [`TransportError::HalfRttEnabled`],
    /// [`TransportError::TlsConfig`], or [`TransportError::Endpoint`].
    pub fn bind(
        addr: SocketAddr,
        config: Arc<rustls::ServerConfig>,
        limits: QuicLimits,
    ) -> Result<Self, TransportError> {
        if config.max_early_data_size != 0 {
            return Err(TransportError::ZeroRttEnabled);
        }
        if config.send_half_rtt_data {
            return Err(TransportError::HalfRttEnabled);
        }
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(config).map_err(|err| {
            TransportError::TlsConfig {
                detail: err.to_string(),
            }
        })?;
        let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        let transport = Arc::new(limits.transport_config(false)?);
        server.transport_config(Arc::clone(&transport));
        let endpoint =
            quinn::Endpoint::server(server, addr).map_err(|err| TransportError::Endpoint {
                detail: err.to_string(),
            })?;
        let (tx, rx) = mpsc::channel(limits.max_connections.max(1));
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let pending = Arc::new(AtomicUsize::new(0));
        let established = Arc::new(AtomicUsize::new(0));
        let driver = tokio::spawn(accept_loop(
            endpoint.clone(),
            limits,
            tx,
            shutdown_rx,
            Arc::clone(&pending),
            established,
        ));
        Ok(Self {
            endpoint,
            incoming: rx,
            pending,
            shutdown: Some(shutdown_tx),
            driver: Some(driver),
        })
    }

    /// Local UDP address, after the kernel assigns an ephemeral port.
    ///
    /// # Errors
    ///
    /// [`TransportError::Endpoint`] if the socket has no local address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|err| TransportError::Endpoint {
                detail: err.to_string(),
            })
    }

    /// Handshakes that have been accepted and have not finished or timed out.
    #[must_use]
    pub fn pending_handshakes(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }

    /// Next connection that negotiated `h3`.
    ///
    /// Handshakes that time out, are refused, or negotiate another ALPN are
    /// not returned. `None` means the listener has stopped.
    ///
    /// # Errors
    ///
    /// [`TransportError::Closed`] when the driver has stopped.
    pub async fn accept(&mut self) -> Result<Accepted, TransportError> {
        self.incoming.recv().await.ok_or(TransportError::Closed)
    }

    /// Stop accepting. Connections already returned stay up.
    pub async fn close(mut self) {
        self.signal_stop();
        if let Some(driver) = self.driver.take() {
            let _ = driver.await;
        }
    }

    fn signal_stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
    }
}

/// Dial `addr`. The server name is taken from `tls` and is not a separate argument.
///
/// ```compile_fail
/// fn sneak_sni(
///     tls: astp_crypto::ClientTls,
///     addr: std::net::SocketAddr,
///     limits: astp_transport::QuicLimits,
/// ) {
///     let _ = astp_transport::quic::connect(tls, addr, limits, "evil.test");
/// }
/// ```
///
/// # Errors
///
/// [`TransportError::HandshakeTimeout`] if the handshake exceeds
/// `limits.handshake_timeout`, or another [`TransportError`] when the
/// endpoint, the TLS config, or the exporter fails.
pub async fn connect(
    tls: ClientTls,
    addr: SocketAddr,
    limits: QuicLimits,
) -> Result<QuicClient, TransportError> {
    let bind_to = if addr.is_ipv6() {
        SocketAddr::from(([0, 0, 0, 0, 0, 0, 0, 0], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let mut endpoint =
        quinn::Endpoint::client(bind_to).map_err(|err| TransportError::Endpoint {
            detail: err.to_string(),
        })?;
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::clone(tls.config()))
        .map_err(|err| TransportError::TlsConfig {
            detail: err.to_string(),
        })?;
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    client.transport_config(Arc::new(limits.transport_config(true)?));
    endpoint.set_default_client_config(client);
    let server_name = tls.server_name().to_str().into_owned();
    let connecting =
        endpoint
            .connect(addr, &server_name)
            .map_err(|err| TransportError::Connection {
                detail: err.to_string(),
            })?;
    let conn = match tokio::time::timeout(limits.handshake_timeout, connecting).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => {
            return Err(TransportError::Connection {
                detail: err.to_string(),
            })
        }
        Err(_) => return Err(TransportError::HandshakeTimeout),
    };
    let binding = channel_binding(&conn)?;
    Ok(QuicClient {
        endpoint,
        conn,
        binding,
        server_name,
    })
}

/// QUIC client. Dropping it closes the connection.
pub struct QuicClient {
    endpoint: quinn::Endpoint,
    conn: quinn::Connection,
    binding: astp_crypto::ChannelBinding,
    server_name: String,
}

impl std::fmt::Debug for QuicClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("QuicClient")
            .field("server_name", &self.server_name)
            .finish_non_exhaustive()
    }
}

impl Drop for QuicClient {
    fn drop(&mut self) {
        close_quietly(&self.conn);
        self.endpoint.close(quinn::VarInt::from_u32(0), b"");
    }
}

impl QuicClient {
    /// Established connection.
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Channel binding taken immediately after the handshake.
    #[must_use]
    pub fn binding(&self) -> &astp_crypto::ChannelBinding {
        &self.binding
    }

    /// Server name that was verified. This is the name from [`ClientTls`].
    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }
}

/// Close with application code 0 and no reason string.
pub(crate) fn close_quietly(conn: &quinn::Connection) {
    conn.close(quinn::VarInt::from_u32(0), b"");
}

struct PendingGuard(Arc<AtomicUsize>);

impl Drop for PendingGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

async fn accept_loop(
    endpoint: quinn::Endpoint,
    limits: QuicLimits,
    tx: mpsc::Sender<Accepted>,
    mut shutdown: oneshot::Receiver<()>,
    pending: Arc<AtomicUsize>,
    established: Arc<AtomicUsize>,
) {
    let mut tasks = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            Some(_) = tasks.join_next(), if !tasks.is_empty() => {}
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                admit(
                    incoming,
                    &limits,
                    &tx,
                    &pending,
                    &established,
                    &mut tasks,
                );
            }
        }
    }
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
}

fn admit(
    incoming: quinn::Incoming,
    limits: &QuicLimits,
    tx: &mpsc::Sender<Accepted>,
    pending: &Arc<AtomicUsize>,
    established: &Arc<AtomicUsize>,
    tasks: &mut tokio::task::JoinSet<()>,
) {
    if established.load(Ordering::Acquire) >= limits.max_connections {
        incoming.refuse();
        return;
    }
    let pending_now = pending.load(Ordering::Acquire);
    if pending_now >= limits.max_pending_handshakes {
        incoming.refuse();
        return;
    }
    if !incoming.remote_address_validated()
        && pending_now >= limits.retry_threshold
        && incoming.may_retry()
    {
        // A failed retry drops the packet, and `Incoming`'s Drop refuses it.
        let _ = incoming.retry();
        return;
    }
    let remote = incoming.remote_address();
    pending.fetch_add(1, Ordering::AcqRel);
    let timeout = limits.handshake_timeout;
    let max_connections = limits.max_connections;
    let tx = tx.clone();
    let pending = Arc::clone(pending);
    let established = Arc::clone(established);
    tasks.spawn(async move {
        let _slot = PendingGuard(pending);
        let Ok(connecting) = incoming.accept() else {
            return;
        };
        let conn = match tokio::time::timeout(timeout, connecting).await {
            Ok(Ok(conn)) => conn,
            _ => return,
        };
        if !negotiated_h3(&conn) {
            close_quietly(&conn);
            return;
        }
        let Ok(binding) = channel_binding(&conn) else {
            close_quietly(&conn);
            return;
        };
        if !reserve_connection(&established, max_connections) {
            close_quietly(&conn);
            return;
        }
        let accepted = Accepted {
            conn: conn.clone(),
            binding,
            remote,
        };
        if tx.send(accepted).await.is_err() {
            established.fetch_sub(1, Ordering::AcqRel);
            close_quietly(&conn);
            return;
        }
        conn.closed().await;
        established.fetch_sub(1, Ordering::AcqRel);
    });
}

fn reserve_connection(established: &AtomicUsize, max: usize) -> bool {
    loop {
        let current = established.load(Ordering::Acquire);
        if current >= max {
            return false;
        }
        if established
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return true;
        }
    }
}

fn negotiated_h3(conn: &quinn::Connection) -> bool {
    conn.handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.protocol)
        .is_some_and(|protocol| protocol.as_slice() == ALPN_H3)
}
