//! HTTP/3 on a QUIC connection that already negotiated ALPN `h3`.
//!
//! Every request other than `POST` on the configured tunnel path gets an
//! empty 404. The tunnel path defaults to `/t`. Its body is a sequence of
//! ASTP-M frames read with [`astp_frame::FrameReader`]. A frame error or a
//! frame-read timeout closes the QUIC connection. HTTP datagrams (RFC 9297)
//! are bound to that request stream through the quarter stream id in
//! `h3-datagram`.
//!
//! `h3-datagram` 0.0.2 encodes the quarter stream id into a stack buffer and
//! then discards that buffer, so only stream id 0 (a leading zero byte) is
//! on the wire correctly. The first client-initiated bidirectional stream is
//! id 0, and this task opens one tunnel request per connection. A second
//! request on the same connection would not be bound to the right stream
//! until that crate is fixed. Grease is off so the first request stays id 0.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::Duration;

use astp_frame::{encode, Frame, FrameReader};
use bytes::{Buf, Bytes};
use h3_datagram::datagram_handler::HandleDatagramsExt;
use http::{Method, Request, Response, StatusCode};
use tokio::io::{AsyncRead, ReadBuf};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

use crate::quic::close_quietly;
use crate::TransportError;

type QuinnConn = h3_quinn::Connection;
type SendHandler =
    <QuinnConn as h3_datagram::quic_traits::DatagramConnectionExt<Bytes>>::SendDatagramHandler;
type RecvHandler =
    <QuinnConn as h3_datagram::quic_traits::DatagramConnectionExt<Bytes>>::RecvDatagramHandler;
type DatagramTx = h3_datagram::datagram_handler::DatagramSender<SendHandler, Bytes>;
type DatagramRx = h3_datagram::datagram_handler::DatagramReader<RecvHandler>;

type ServerSend = h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ServerRecv = h3::server::RequestStream<h3_quinn::RecvStream, Bytes>;
type ClientSend = h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>;
type ClientRecv = h3::client::RequestStream<h3_quinn::RecvStream, Bytes>;

/// HTTP/3 settings for one connection.
#[derive(Debug, Clone)]
pub struct Http3Options {
    /// Path of `POST` that carries the tunnel. The default is `/t`.
    pub tunnel_path: String,
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`. The default is 16 KiB.
    pub max_field_section_size: u64,
    /// How long one ASTP-M frame may take to arrive. The default is 10 s.
    pub frame_read_timeout: Duration,
}

impl Default for Http3Options {
    fn default() -> Self {
        Self {
            tunnel_path: "/t".to_owned(),
            max_field_section_size: 16 * 1024,
            frame_read_timeout: Duration::from_secs(10),
        }
    }
}

impl Http3Options {
    /// Copy the HTTP/3 fields out of QUIC limits. The tunnel path stays `/t`.
    #[must_use]
    pub fn from_limits(limits: &crate::QuicLimits) -> Self {
        Self {
            tunnel_path: "/t".to_owned(),
            max_field_section_size: limits.max_field_section_size,
            frame_read_timeout: limits.frame_read_timeout,
        }
    }
}

/// Status and body of one HTTP/3 response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// HTTP status.
    pub status: StatusCode,
    /// Response body. Empty for the 404 stub.
    pub body: Vec<u8>,
}

/// Server HTTP/3 driver for one QUIC connection.
pub struct Http3Server {
    tunnels: mpsc::Receiver<ServerTunnel>,
    shutdown: Option<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
}

impl Drop for Http3Server {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Http3Server {
    /// Start HTTP/3 on `conn`.
    ///
    /// Datagrams and extended CONNECT are enabled. Grease is disabled.
    /// The field section size comes from `options`.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`] if the HTTP/3 handshake settings cannot be sent.
    pub async fn start(
        conn: quinn::Connection,
        options: Http3Options,
    ) -> Result<Self, TransportError> {
        let h3_conn = QuinnConn::new(conn.clone());
        let mut builder = h3::server::builder();
        builder
            .max_field_section_size(options.max_field_section_size)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .send_grease(false);
        let server = builder
            .build(h3_conn)
            .await
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })?;
        let hub = Arc::new(DatagramHub::default());
        let reader = server.get_datagram_reader();
        let (tunnel_tx, tunnel_rx) = mpsc::channel(16);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut tasks = JoinSet::new();
        let hub_read = Arc::clone(&hub);
        tasks.spawn(async move {
            read_datagrams(reader, hub_read).await;
        });
        tasks.spawn(async move {
            serve_requests(server, conn, options, hub, tunnel_tx, shutdown_rx).await;
        });
        Ok(Self {
            tunnels: tunnel_rx,
            shutdown: Some(shutdown_tx),
            tasks,
        })
    }

    /// Next `POST` on the tunnel path.
    ///
    /// Other requests are answered with an empty 404 inside the driver.
    /// `None` means the connection has stopped.
    ///
    /// # Errors
    ///
    /// [`TransportError::Closed`] when the driver has stopped.
    pub async fn accept_tunnel(&mut self) -> Result<ServerTunnel, TransportError> {
        self.tunnels.recv().await.ok_or(TransportError::Closed)
    }

    /// Stop the driver.
    pub async fn close(mut self) {
        self.stop();
        while self.tasks.join_next().await.is_some() {}
    }

    fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.tasks.abort_all();
    }
}

/// Client HTTP/3 driver for one QUIC connection.
pub struct Http3Client {
    send: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    hub: Arc<DatagramHub>,
    sender_tx: mpsc::UnboundedSender<SenderRequest>,
    options: Http3Options,
    conn: quinn::Connection,
    shutdown: Option<oneshot::Sender<()>>,
    tasks: JoinSet<()>,
}

impl Drop for Http3Client {
    fn drop(&mut self) {
        self.stop();
    }
}

impl Http3Client {
    /// Start HTTP/3 on `conn`.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`] if the settings cannot be sent.
    pub async fn start(
        conn: quinn::Connection,
        options: Http3Options,
    ) -> Result<Self, TransportError> {
        let h3_conn = QuinnConn::new(conn.clone());
        let mut builder = h3::client::builder();
        builder
            .max_field_section_size(options.max_field_section_size)
            .enable_datagram(true)
            .enable_extended_connect(true)
            .send_grease(false);
        let (driver, send) = builder
            .build(h3_conn)
            .await
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })?;
        let hub = Arc::new(DatagramHub::default());
        let reader = driver.get_datagram_reader();
        let (sender_tx, sender_rx) = mpsc::unbounded_channel();
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let mut tasks = JoinSet::new();
        let hub_read = Arc::clone(&hub);
        tasks.spawn(async move {
            read_datagrams(reader, hub_read).await;
        });
        tasks.spawn(async move {
            drive_client(driver, sender_rx, shutdown_rx).await;
        });
        Ok(Self {
            send,
            hub,
            sender_tx,
            options,
            conn,
            shutdown: Some(shutdown_tx),
            tasks,
        })
    }

    /// `GET` `path` and collect the body.
    ///
    /// `path` is an origin path such as `/`. The URI sent on the wire is
    /// `https://astp.test` plus that path. The server name of the QUIC
    /// handshake is not taken from this string.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`] or [`TransportError::Invalid`].
    pub async fn get(&mut self, path: &str) -> Result<HttpResponse, TransportError> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(https_uri(path)?)
            .body(())
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })?;
        let mut stream =
            self.send
                .send_request(request)
                .await
                .map_err(|err| TransportError::H3 {
                    detail: err.to_string(),
                })?;
        stream.finish().await.map_err(|err| TransportError::H3 {
            detail: err.to_string(),
        })?;
        let response = stream
            .recv_response()
            .await
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })?;
        let mut body = Vec::new();
        while let Some(mut chunk) = stream.recv_data().await.map_err(|err| TransportError::H3 {
            detail: err.to_string(),
        })? {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.copy_to_bytes(n));
        }
        Ok(HttpResponse {
            status: response.status(),
            body,
        })
    }

    /// Open `POST` on the tunnel path.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`] when the request cannot be opened, or when the
    /// stream id is not a client request (h3-datagram would panic on it).
    pub async fn open_tunnel(&mut self) -> Result<ClientTunnel, TransportError> {
        let request = Request::builder()
            .method(Method::POST)
            .uri(https_uri(&self.options.tunnel_path)?)
            .body(())
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })?;
        let stream = self
            .send
            .send_request(request)
            .await
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })?;
        let id = stream.id();
        if !id.is_request() {
            return Err(TransportError::H3 {
                detail: "tunnel stream id is not a client request".into(),
            });
        }
        let (reply_tx, reply_rx) = oneshot::channel();
        self.sender_tx
            .send(SenderRequest {
                id,
                reply: reply_tx,
            })
            .map_err(|_| TransportError::Closed)?;
        let datagrams = reply_rx.await.map_err(|_| TransportError::Closed)?;
        let incoming = self.hub.register(id.into_inner());
        let (send, recv) = stream.split();
        let (body, body_task) = spawn_client_body(recv);
        Ok(ClientTunnel {
            stream_id: id.into_inner(),
            send,
            frames: FrameReader::new(body),
            datagrams_in: incoming,
            datagrams,
            conn: self.conn.clone(),
            hub: Arc::clone(&self.hub),
            frame_read_timeout: self.options.frame_read_timeout,
            body_task,
        })
    }

    /// QUIC connection this client is driving.
    #[must_use]
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// Stop the driver.
    pub async fn close(mut self) {
        self.stop();
        while self.tasks.join_next().await.is_some() {}
    }

    fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.tasks.abort_all();
    }
}

/// One thing read from a tunnel: a frame on the body, or a datagram.
#[derive(Debug)]
pub enum TunnelInput {
    /// The next frame. `None` is the end of the body.
    Frame(Option<Frame>),
    /// Payload of one HTTP datagram bound to this stream.
    Datagram(Bytes),
}

/// Server side of one `POST` tunnel.
pub struct ServerTunnel {
    stream_id: u64,
    send: ServerSend,
    frames: FrameReader<BodyReader>,
    datagrams_in: mpsc::UnboundedReceiver<Bytes>,
    datagrams: DatagramTx,
    conn: quinn::Connection,
    hub: Arc<DatagramHub>,
    frame_read_timeout: Duration,
    body_task: JoinHandle<()>,
}

impl Drop for ServerTunnel {
    fn drop(&mut self) {
        self.hub.close_stream(self.stream_id);
        self.body_task.abort();
    }
}

impl ServerTunnel {
    /// QUIC stream id. Client request streams are divisible by 4.
    #[must_use]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Next frame or datagram, whichever arrives first.
    ///
    /// A clean end of the body is [`TunnelInput::Frame`]`(None)` and stops
    /// datagrams for this stream. A frame error still closes the connection.
    ///
    /// # Errors
    ///
    /// [`TransportError::Frame`], [`TransportError::FrameReadTimeout`], or
    /// [`TransportError::TunnelClosed`].
    pub async fn recv(&mut self) -> Result<TunnelInput, TransportError> {
        let timeout = self.frame_read_timeout;
        let stream_id = self.stream_id;
        tokio::select! {
            biased;
            frame = read_one_frame(
                &mut self.frames,
                timeout,
                &self.conn,
                &self.hub,
                stream_id,
            ) => frame.map(TunnelInput::Frame),
            datagram = self.datagrams_in.recv() => {
                datagram.map(TunnelInput::Datagram).ok_or(TransportError::TunnelClosed)
            }
        }
    }

    /// Next ASTP-M frame on the request body.
    ///
    /// `Ok(None)` is a clean end of the body. Any frame error closes the
    /// QUIC connection.
    ///
    /// # Errors
    ///
    /// [`TransportError::Frame`], [`TransportError::FrameReadTimeout`].
    pub async fn read_frame(&mut self) -> Result<Option<Frame>, TransportError> {
        read_one_frame(
            &mut self.frames,
            self.frame_read_timeout,
            &self.conn,
            &self.hub,
            self.stream_id,
        )
        .await
    }

    /// Write one frame on the response body.
    ///
    /// # Errors
    ///
    /// [`TransportError::Frame`] or [`TransportError::H3`].
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let bytes = Bytes::from(encode(frame, None).map_err(TransportError::Frame)?);
        self.send
            .send_data(bytes)
            .await
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })
    }

    /// Next HTTP datagram bound to this stream, payload only.
    ///
    /// # Errors
    ///
    /// [`TransportError::TunnelClosed`] when the driver stops delivering them.
    pub async fn recv_datagram(&mut self) -> Result<Bytes, TransportError> {
        self.datagrams_in
            .recv()
            .await
            .ok_or(TransportError::TunnelClosed)
    }

    /// Send one HTTP datagram bound to this stream.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`] when Quinn or h3-datagram rejects it.
    pub fn send_datagram(&mut self, payload: Bytes) -> Result<(), TransportError> {
        self.datagrams
            .send_datagram(payload)
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })
    }

    /// Stop accepting datagrams for this stream.
    pub fn close_datagrams(&self) {
        self.hub.close_stream(self.stream_id);
    }

    /// Finish the response body.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`] if the stream is already closed.
    pub async fn finish(&mut self) -> Result<(), TransportError> {
        self.send.finish().await.map_err(|err| TransportError::H3 {
            detail: err.to_string(),
        })
    }
}

/// Client side of one `POST` tunnel.
pub struct ClientTunnel {
    stream_id: u64,
    send: ClientSend,
    frames: FrameReader<BodyReader>,
    datagrams_in: mpsc::UnboundedReceiver<Bytes>,
    datagrams: DatagramTx,
    conn: quinn::Connection,
    hub: Arc<DatagramHub>,
    frame_read_timeout: Duration,
    body_task: JoinHandle<()>,
}

impl Drop for ClientTunnel {
    fn drop(&mut self) {
        self.hub.close_stream(self.stream_id);
        self.body_task.abort();
    }
}

impl ClientTunnel {
    /// QUIC stream id of the request.
    #[must_use]
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Next ASTP-M frame on the response body.
    ///
    /// # Errors
    ///
    /// [`TransportError::Frame`] or [`TransportError::FrameReadTimeout`].
    /// Either one closes the QUIC connection.
    pub async fn read_frame(&mut self) -> Result<Option<Frame>, TransportError> {
        read_one_frame(
            &mut self.frames,
            self.frame_read_timeout,
            &self.conn,
            &self.hub,
            self.stream_id,
        )
        .await
    }

    /// Write raw bytes on the request body.
    ///
    /// [`Self::write_frame`] is the framed path. This exists so a peer can
    /// send a frame the reader must reject.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`] if the stream is closed.
    pub async fn write_body(&mut self, bytes: Bytes) -> Result<(), TransportError> {
        self.send
            .send_data(bytes)
            .await
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })
    }

    /// Write one frame on the request body.
    ///
    /// # Errors
    ///
    /// [`TransportError::Frame`] or [`TransportError::H3`].
    pub async fn write_frame(&mut self, frame: &Frame) -> Result<(), TransportError> {
        let bytes = Bytes::from(encode(frame, None).map_err(TransportError::Frame)?);
        self.send
            .send_data(bytes)
            .await
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })
    }

    /// Next HTTP datagram bound to this stream.
    ///
    /// # Errors
    ///
    /// [`TransportError::TunnelClosed`].
    pub async fn recv_datagram(&mut self) -> Result<Bytes, TransportError> {
        self.datagrams_in
            .recv()
            .await
            .ok_or(TransportError::TunnelClosed)
    }

    /// Send one HTTP datagram bound to this stream.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`].
    pub fn send_datagram(&mut self, payload: Bytes) -> Result<(), TransportError> {
        self.datagrams
            .send_datagram(payload)
            .map_err(|err| TransportError::H3 {
                detail: err.to_string(),
            })
    }

    /// Stop accepting datagrams for this stream.
    pub fn close_datagrams(&self) {
        self.hub.close_stream(self.stream_id);
    }

    /// Finish the request body. Datagrams for this stream are no longer accepted locally.
    ///
    /// # Errors
    ///
    /// [`TransportError::H3`].
    pub async fn finish(&mut self) -> Result<(), TransportError> {
        self.send.finish().await.map_err(|err| TransportError::H3 {
            detail: err.to_string(),
        })
    }
}

struct SenderRequest {
    id: h3::quic::StreamId,
    reply: oneshot::Sender<DatagramTx>,
}

struct HubState {
    routes: HashMap<u64, mpsc::UnboundedSender<Bytes>>,
    closed: HashSet<u64>,
    pending: HashMap<u64, Vec<Bytes>>,
}

struct DatagramHub {
    state: Mutex<HubState>,
}

impl DatagramHub {
    fn register(&self, id: u64) -> mpsc::UnboundedReceiver<Bytes> {
        let (tx, rx) = mpsc::unbounded_channel();
        let mut state = lock_hub(&self.state);
        if state.closed.contains(&id) {
            return rx;
        }
        if let Some(queued) = state.pending.remove(&id) {
            for bytes in queued {
                let _ = tx.send(bytes);
            }
        }
        state.routes.insert(id, tx);
        rx
    }

    fn push(&self, id: u64, bytes: Bytes) {
        let mut state = lock_hub(&self.state);
        if state.closed.contains(&id) {
            return;
        }
        if let Some(tx) = state.routes.get(&id) {
            let _ = tx.send(bytes);
            return;
        }
        state.pending.entry(id).or_default().push(bytes);
    }

    fn close_stream(&self, id: u64) {
        let mut state = lock_hub(&self.state);
        state.closed.insert(id);
        state.routes.remove(&id);
        state.pending.remove(&id);
    }
}

impl Default for DatagramHub {
    fn default() -> Self {
        Self {
            state: Mutex::new(HubState {
                routes: HashMap::new(),
                closed: HashSet::new(),
                pending: HashMap::new(),
            }),
        }
    }
}

fn lock_hub(mutex: &Mutex<HubState>) -> MutexGuard<'_, HubState> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

async fn read_datagrams(mut reader: DatagramRx, hub: Arc<DatagramHub>) {
    while let Ok(datagram) = reader.read_datagram().await {
        let id = datagram.stream_id().into_inner();
        let mut payload = datagram.into_payload();
        let bytes = payload.copy_to_bytes(payload.remaining());
        hub.push(id, bytes);
    }
}

async fn serve_requests(
    mut server: h3::server::Connection<QuinnConn, Bytes>,
    conn: quinn::Connection,
    options: Http3Options,
    hub: Arc<DatagramHub>,
    tunnels: mpsc::Sender<ServerTunnel>,
    mut shutdown: oneshot::Receiver<()>,
) {
    loop {
        tokio::select! {
            biased;
            _ = &mut shutdown => break,
            accepted = server.accept() => {
                match accepted {
                    Ok(Some(resolver)) => {
                        let Ok((request, stream)) = resolver.resolve_request().await else {
                            continue;
                        };
                        if request.method() == Method::POST
                            && request.uri().path() == options.tunnel_path
                        {
                            if hand_tunnel(
                                stream,
                                &mut server,
                                &conn,
                                &options,
                                &hub,
                                &tunnels,
                            )
                            .await
                            .is_err()
                            {
                                break;
                            }
                        } else if respond_empty(stream, StatusCode::NOT_FOUND).await.is_err() {
                            continue;
                        }
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        }
    }
}

async fn hand_tunnel(
    stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    server: &mut h3::server::Connection<QuinnConn, Bytes>,
    conn: &quinn::Connection,
    options: &Http3Options,
    hub: &Arc<DatagramHub>,
    tunnels: &mpsc::Sender<ServerTunnel>,
) -> Result<(), ()> {
    let id = stream.id();
    if !id.is_request() {
        close_quietly(conn);
        return Err(());
    }
    let datagrams = server.get_datagram_sender(id);
    let (mut send, recv) = stream.split();
    let response = match empty_response(StatusCode::OK) {
        Ok(response) => response,
        Err(_) => return Err(()),
    };
    if send.send_response(response).await.is_err() {
        return Err(());
    }
    let incoming = hub.register(id.into_inner());
    let (body, body_task) = spawn_server_body(recv);
    let tunnel = ServerTunnel {
        stream_id: id.into_inner(),
        send,
        frames: FrameReader::new(body),
        datagrams_in: incoming,
        datagrams,
        conn: conn.clone(),
        hub: Arc::clone(hub),
        frame_read_timeout: options.frame_read_timeout,
        body_task,
    };
    tunnels.send(tunnel).await.map_err(|_| ())
}

async fn respond_empty(
    mut stream: h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>,
    status: StatusCode,
) -> Result<(), ()> {
    let response = empty_response(status).map_err(|_| ())?;
    stream.send_response(response).await.map_err(|_| ())?;
    stream.finish().await.map_err(|_| ())?;
    Ok(())
}

fn empty_response(status: StatusCode) -> Result<Response<()>, TransportError> {
    Response::builder()
        .status(status)
        .body(())
        .map_err(|err| TransportError::H3 {
            detail: err.to_string(),
        })
}

async fn drive_client(
    mut conn: h3::client::Connection<QuinnConn, Bytes>,
    mut requests: mpsc::UnboundedReceiver<SenderRequest>,
    mut shutdown: oneshot::Receiver<()>,
) {
    std::future::poll_fn(|cx| {
        if Pin::new(&mut shutdown).poll(cx).is_ready() {
            return Poll::Ready(());
        }
        while let Poll::Ready(Some(request)) = requests.poll_recv(cx) {
            let sender = conn.get_datagram_sender(request.id);
            let _ = request.reply.send(sender);
        }
        match conn.poll_close(cx) {
            Poll::Ready(_) => Poll::Ready(()),
            Poll::Pending => Poll::Pending,
        }
    })
    .await;
}

fn https_uri(path: &str) -> Result<http::Uri, TransportError> {
    if !path.starts_with('/') {
        return Err(TransportError::Invalid {
            detail: "HTTP path must start with /".into(),
        });
    }
    format!("https://astp.test{path}")
        .parse()
        .map_err(|err: http::uri::InvalidUri| TransportError::Invalid {
            detail: err.to_string(),
        })
}

async fn read_one_frame(
    frames: &mut FrameReader<BodyReader>,
    timeout: Duration,
    conn: &quinn::Connection,
    hub: &DatagramHub,
    stream_id: u64,
) -> Result<Option<Frame>, TransportError> {
    match tokio::time::timeout(timeout, frames.read_frame()).await {
        Ok(Ok(None)) => {
            hub.close_stream(stream_id);
            Ok(None)
        }
        Ok(Ok(frame)) => Ok(frame),
        Ok(Err(err)) => {
            hub.close_stream(stream_id);
            close_quietly(conn);
            Err(TransportError::Frame(err))
        }
        Err(_) => {
            hub.close_stream(stream_id);
            close_quietly(conn);
            Err(TransportError::FrameReadTimeout)
        }
    }
}

struct BodyReader {
    rx: mpsc::Receiver<Result<Option<Bytes>, String>>,
    buf: Bytes,
    failed: Option<String>,
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = &mut *self;
        if let Some(detail) = this.failed.clone() {
            return Poll::Ready(Err(io::Error::other(detail)));
        }
        while this.buf.is_empty() {
            match std::task::ready!(this.rx.poll_recv(cx)) {
                Some(Ok(Some(bytes))) if bytes.is_empty() => continue,
                Some(Ok(Some(bytes))) => this.buf = bytes,
                Some(Ok(None)) | None => return Poll::Ready(Ok(())),
                Some(Err(detail)) => {
                    this.failed = Some(detail.clone());
                    return Poll::Ready(Err(io::Error::other(detail)));
                }
            }
        }
        let n = buf.remaining().min(this.buf.len());
        buf.put_slice(&this.buf.split_to(n));
        Poll::Ready(Ok(()))
    }
}

fn spawn_server_body(stream: ServerRecv) -> (BodyReader, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(8);
    let body_task = tokio::spawn(async move {
        drain_server_body(stream, tx).await;
    });
    (
        BodyReader {
            rx,
            buf: Bytes::new(),
            failed: None,
        },
        body_task,
    )
}

fn spawn_client_body(stream: ClientRecv) -> (BodyReader, JoinHandle<()>) {
    let (tx, rx) = mpsc::channel(8);
    let body_task = tokio::spawn(async move {
        drain_client_body(stream, tx).await;
    });
    (
        BodyReader {
            rx,
            buf: Bytes::new(),
            failed: None,
        },
        body_task,
    )
}

async fn drain_server_body(
    mut stream: ServerRecv,
    tx: mpsc::Sender<Result<Option<Bytes>, String>>,
) {
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                if forward_chunk(chunk, &tx).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = tx.send(Ok(None)).await;
                break;
            }
            Err(err) => {
                let _ = tx.send(Err(err.to_string())).await;
                break;
            }
        }
    }
}

async fn drain_client_body(
    mut stream: ClientRecv,
    tx: mpsc::Sender<Result<Option<Bytes>, String>>,
) {
    if let Err(err) = stream.recv_response().await {
        let _ = tx.send(Err(err.to_string())).await;
        return;
    }
    loop {
        match stream.recv_data().await {
            Ok(Some(chunk)) => {
                if forward_chunk(chunk, &tx).await.is_err() {
                    break;
                }
            }
            Ok(None) => {
                let _ = tx.send(Ok(None)).await;
                break;
            }
            Err(err) => {
                let _ = tx.send(Err(err.to_string())).await;
                break;
            }
        }
    }
}

async fn forward_chunk(
    mut chunk: impl Buf,
    tx: &mpsc::Sender<Result<Option<Bytes>, String>>,
) -> Result<(), ()> {
    let n = chunk.remaining();
    let bytes = chunk.copy_to_bytes(n);
    tx.send(Ok(Some(bytes))).await.map_err(|_| ())
}
