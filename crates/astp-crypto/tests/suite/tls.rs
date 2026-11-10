//! Handshake, resumption, exporter, and authenticator checks.
//!
//! Compiled as a unit-test module of `astp-crypto` (`cfg(test)`), so
//! `StaticTokenAuthenticator` is available without enabling `test-util`.
//! Cargo does not treat `tests/suite/` as an integration-test crate.

use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName};
use rustls::RootCertStore;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};

use crate::{
    channel_binding, client_config, server_config, AlpnMode, AuthError, Authenticator,
    ChannelBinding, ClientAuth, ClientId, ClientOptions, CryptoError, Identity, ServerOptions,
    StaticTokenAuthenticator, TlsSession, TrustAnchors, CHANNEL_BINDING_LEN, SERVER_ALPN, TCP_ALPN,
};

const EXT_PRE_SHARED_KEY: u16 = 41;
const EXT_EARLY_DATA: u16 = 42;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

struct Issued {
    ca_der: CertificateDer<'static>,
    leaf_cert: CertificateDer<'static>,
    leaf_key: PrivateKeyDer<'static>,
    client_cert: CertificateDer<'static>,
    client_key: PrivateKeyDer<'static>,
    leaf_pem: String,
    leaf_key_pem: String,
}

#[derive(Debug)]
struct RecordWrite<S> {
    inner: S,
    written: Arc<Mutex<Vec<u8>>>,
}

type ClientTls = tokio_rustls::client::TlsStream<RecordWrite<TcpStream>>;
type ServerTls = tokio_rustls::server::TlsStream<TcpStream>;

fn issue(alg: &'static rcgen::SignatureAlgorithm) -> Issued {
    let ca_key = rcgen::KeyPair::generate_for(alg).expect("ca key");
    let mut ca_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca certificate parameters");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "astp test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca certificate");
    let ca_der = ca_cert.der().clone();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf_key = rcgen::KeyPair::generate_for(alg).expect("leaf key");
    let leaf = rcgen::CertificateParams::new(vec!["astp.test".to_string()])
        .expect("leaf parameters")
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    let leaf_pem = leaf.pem();
    let leaf_key_pem = leaf_key.serialize_pem();
    let leaf_cert = leaf.der().clone();
    let leaf_key = PrivateKeyDer::from(leaf_key);

    let client_key_pair = rcgen::KeyPair::generate_for(alg).expect("client key");
    let client = rcgen::CertificateParams::new(vec!["client.astp.test".to_string()])
        .expect("client parameters")
        .signed_by(&client_key_pair, &issuer)
        .expect("client certificate");

    Issued {
        ca_der,
        leaf_cert,
        leaf_key,
        client_cert: client.der().clone(),
        client_key: PrivateKeyDer::from(client_key_pair),
        leaf_pem,
        leaf_key_pem,
    }
}

fn other_ca() -> CertificateDer<'static> {
    let key = rcgen::KeyPair::generate().expect("other ca key");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("other ca parameters");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "other ca");
    params.self_signed(&key).expect("other ca").der().clone()
}

fn roots_of(cert: &CertificateDer<'static>) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add(cert.clone()).expect("add trust anchor");
    roots
}

fn server_identity(issued: &Issued) -> Identity {
    Identity::Der {
        certificates: vec![issued.leaf_cert.clone()],
        private_key: issued.leaf_key.clone_key(),
    }
}

fn mtls_identity(issued: &Issued) -> Identity {
    Identity::Der {
        certificates: vec![issued.client_cert.clone()],
        private_key: issued.client_key.clone_key(),
    }
}

fn client_options(
    roots: RootCertStore,
    host: &str,
    tls_server_name: Option<&str>,
    alpn: AlpnMode,
    client_identity: Option<Identity>,
) -> ClientOptions {
    ClientOptions {
        trust: TrustAnchors::Explicit(roots),
        alpn,
        host: host.to_string(),
        tls_server_name: tls_server_name.map(str::to_string),
        client_identity,
    }
}

fn configs(
    issued: &Issued,
    client_auth: Option<ClientAuth>,
    client_identity: Option<Identity>,
) -> (
    Arc<rustls::ServerConfig>,
    Arc<rustls::ClientConfig>,
    ServerName<'static>,
) {
    let server = server_config(ServerOptions {
        identity: server_identity(issued),
        client_auth,
    })
    .expect("server config");
    let options = client_options(
        roots_of(&issued.ca_der),
        "127.0.0.1",
        Some("astp.test"),
        AlpnMode::Tcp,
        client_identity,
    );
    let name = options.server_name().expect("server name");
    let client = client_config(options).expect("client config");
    (server, client, name)
}

fn protocol_vecs(protocols: &[&[u8]]) -> Vec<Vec<u8>> {
    protocols.iter().map(|protocol| protocol.to_vec()).collect()
}

fn tls12_client(roots: RootCertStore) -> Arc<rustls::ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS12])
        .expect("tls 1.2 client builder")
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = protocol_vecs(TCP_ALPN);
    Arc::new(config)
}

fn early_data_server(issued: &Issued) -> Arc<rustls::ServerConfig> {
    // Test-only peer. Our public server config refuses early data, so this
    // one exists to prove the client still omits 0-RTT when the peer allows it.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .expect("harness builder")
        .with_no_client_auth()
        .with_single_cert(vec![issued.leaf_cert.clone()], issued.leaf_key.clone_key())
        .expect("harness certificate");
    config.alpn_protocols = protocol_vecs(TCP_ALPN);
    config.max_early_data_size = 4096;
    config.send_half_rtt_data = false;
    config.send_tls13_tickets = 4;
    Arc::new(config)
}

impl<S: AsyncRead + Unpin> AsyncRead for RecordWrite<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for RecordWrite<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_write(cx, buf) {
            Poll::Ready(Ok(n)) => {
                this.written
                    .lock()
                    .expect("record client bytes")
                    .extend_from_slice(&buf[..n]);
                Poll::Ready(Ok(n))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

async fn drive(
    server_cfg: Arc<rustls::ServerConfig>,
    client_cfg: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
) -> io::Result<(ClientTls, ServerTls)> {
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let server_task = tokio::spawn(async move {
        let (tcp, _) = tokio::time::timeout(HANDSHAKE_TIMEOUT, listener.accept())
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "server accept timed out"))??;
        tcp.set_nodelay(true)?;
        let stream =
            tokio::time::timeout(HANDSHAKE_TIMEOUT, TlsAcceptor::from(server_cfg).accept(tcp))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "server handshake timed out")
                })??;
        Ok(stream)
    });

    let written = Arc::new(Mutex::new(Vec::new()));
    let client_result = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let tcp = TcpStream::connect(addr).await?;
        tcp.set_nodelay(true)?;
        let io = RecordWrite {
            inner: tcp,
            written: Arc::clone(&written),
        };
        TlsConnector::from(client_cfg).connect(name, io).await
    })
    .await;

    let server_result = server_task.await;
    match client_result {
        Ok(Ok(client)) => match server_result {
            Ok(Ok(server)) => Ok((client, server)),
            Ok(Err(err)) => Err(err),
            Err(err) => Err(io::Error::other(err.to_string())),
        },
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "client handshake timed out",
        )),
    }
}

async fn exchange_byte(client: &mut ClientTls, server: &mut ServerTls) {
    server.write_all(b"t").await.expect("server write");
    server.flush().await.expect("server flush");
    let mut buf = [0u8; 1];
    client.read_exact(&mut buf).await.expect("client read");
    assert_eq!(buf, [b't']);
}

fn assert_tls_refusal(err: &io::Error, what: &str) {
    let text = err.to_string();
    assert!(
        !text.contains("timed out") && err.kind() != io::ErrorKind::ConnectionRefused,
        "{what}: not a TLS refusal: {text}"
    );
    let has_rustls = err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some();
    let lower = text.to_ascii_lowercase();
    assert!(
        has_rustls
            || lower.contains("handshake")
            || lower.contains("certificate")
            || lower.contains("protocol")
            || lower.contains("tls"),
        "{what}: {text}"
    );
}

fn client_hello_extensions(bytes: &[u8]) -> Result<Vec<u16>, String> {
    let mut offset = 0;
    let mut extensions = Vec::new();
    let mut saw_hello = false;
    while offset + 5 <= bytes.len() {
        let content_type = byte(bytes, offset)?;
        let length =
            u16::from_be_bytes([byte(bytes, offset + 3)?, byte(bytes, offset + 4)?]) as usize;
        let start = offset + 5;
        let end = start + length;
        if end > bytes.len() {
            return Err(format!("truncated TLS record at {offset}"));
        }
        if content_type == 22 {
            parse_handshake(&bytes[start..end], &mut extensions, &mut saw_hello)?;
        }
        offset = end;
    }
    if !saw_hello {
        return Err(format!("no ClientHello in {} bytes", bytes.len()));
    }
    Ok(extensions)
}

fn parse_handshake(
    mut buf: &[u8],
    extensions: &mut Vec<u16>,
    saw_hello: &mut bool,
) -> Result<(), String> {
    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err("truncated handshake header".into());
        }
        let message_type = buf[0];
        let length = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]) as usize;
        if buf.len() < 4 + length {
            return Err("truncated handshake body".into());
        }
        let body = &buf[4..4 + length];
        buf = &buf[4 + length..];
        if message_type == 1 {
            *saw_hello = true;
            extensions.extend(parse_client_hello(body)?);
        }
    }
    Ok(())
}

fn parse_client_hello(body: &[u8]) -> Result<Vec<u16>, String> {
    let mut index = 2 + 32;
    let session_len = byte(body, index)? as usize;
    index += 1 + session_len;
    if index + 2 > body.len() {
        return Err("client hello cipher suites are truncated".into());
    }
    let cipher_len = u16::from_be_bytes([byte(body, index)?, byte(body, index + 1)?]) as usize;
    index += 2 + cipher_len;
    let compression_len = byte(body, index)? as usize;
    index += 1 + compression_len;
    if index + 2 > body.len() {
        return Err("client hello has no extensions".into());
    }
    let ext_len = u16::from_be_bytes([byte(body, index)?, byte(body, index + 1)?]) as usize;
    index += 2;
    if index + ext_len > body.len() {
        return Err("client hello extensions are truncated".into());
    }
    let mut rest = &body[index..index + ext_len];
    let mut types = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 4 {
            return Err("truncated extension header".into());
        }
        let ext_type = u16::from_be_bytes([rest[0], rest[1]]);
        let len = u16::from_be_bytes([rest[2], rest[3]]) as usize;
        if rest.len() < 4 + len {
            return Err("truncated extension".into());
        }
        types.push(ext_type);
        rest = &rest[4 + len..];
    }
    Ok(types)
}

fn byte(bytes: &[u8], index: usize) -> Result<u8, String> {
    bytes
        .get(index)
        .copied()
        .ok_or_else(|| format!("need byte at {index}, have {}", bytes.len()))
}

fn captured_client_bytes(client: &ClientTls) -> Vec<u8> {
    client
        .get_ref()
        .0
        .written
        .lock()
        .expect("client bytes")
        .clone()
}

async fn assert_resumption_omits_early_data(
    server: Arc<rustls::ServerConfig>,
    client: Arc<rustls::ClientConfig>,
    name: ServerName<'static>,
    min_tickets: u32,
) {
    let (mut first_client, mut first_server) =
        drive(Arc::clone(&server), Arc::clone(&client), name.clone())
            .await
            .expect("first handshake");
    exchange_byte(&mut first_client, &mut first_server).await;
    let tickets = first_client.get_ref().1.tls13_tickets_received();
    assert!(
        tickets >= min_tickets,
        "client stored {tickets} tickets, need {min_tickets}"
    );
    drop(first_client);
    drop(first_server);

    let (resumed, _) = drive(server, client, name)
        .await
        .expect("resumed handshake");
    let extensions = client_hello_extensions(&captured_client_bytes(&resumed))
        .unwrap_or_else(|err| panic!("parse resumed ClientHello: {err}"));
    assert!(
        extensions.contains(&EXT_PRE_SHARED_KEY),
        "resumption ClientHello lacked a PSK extension: {extensions:?}"
    );
    assert!(
        !extensions.contains(&EXT_EARLY_DATA),
        "client offered early_data: {extensions:?}"
    );
    assert_eq!(
        resumed.get_ref().1.handshake_kind(),
        Some(rustls::HandshakeKind::Resumed)
    );
    assert!(!resumed.get_ref().1.is_early_data_accepted());
}

async fn connection_bindings(issued: &Issued) -> (ChannelBinding, ChannelBinding) {
    let (server, client, name) = configs(issued, None, None);
    let (left, right) = drive(server, client, name).await.expect("handshake");
    let client_binding = channel_binding(left.get_ref().1).expect("client channel binding");
    let server_binding = channel_binding(right.get_ref().1).expect("server channel binding");
    (client_binding, server_binding)
}

async fn expect_handshake(issued: &Issued, mtls: bool, label: &str) {
    let client_auth = if mtls {
        Some(ClientAuth::Required(roots_of(&issued.ca_der)))
    } else {
        None
    };
    let identity = if mtls {
        Some(mtls_identity(issued))
    } else {
        None
    };
    let (server, client, name) = configs(issued, client_auth, identity);
    let (left, right) = drive(server, client, name).await.unwrap_or_else(|err| {
        panic!("{label} mtls={mtls} handshake failed: {err}");
    });
    assert_eq!(
        left.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3),
        "{label}"
    );
    assert_eq!(
        left.get_ref().1.alpn_protocol(),
        Some(astp_types::ALPN_H2),
        "{label}"
    );
    if mtls {
        assert!(
            right.get_ref().1.peer_certificates().is_some(),
            "{label} mTLS presented no client certificate"
        );
    } else {
        assert!(
            right.get_ref().1.peer_certificates().is_none(),
            "{label} default profile requested a client certificate"
        );
    }
}

#[tokio::test]
async fn tls13_handshake_negotiates_h2() {
    let issued = issue(&rcgen::PKCS_ECDSA_P256_SHA256);
    let dir = tempfile::tempdir().expect("temp dir");
    let certificate = dir.path().join("cert.pem");
    let private_key = dir.path().join("key.pem");
    std::fs::write(&certificate, &issued.leaf_pem).expect("write certificate");
    std::fs::write(&private_key, &issued.leaf_key_pem).expect("write key");
    let server = server_config(ServerOptions {
        identity: Identity::Pem {
            certificate,
            private_key,
        },
        client_auth: None,
    })
    .expect("server config");
    assert_eq!(server.alpn_protocols, protocol_vecs(SERVER_ALPN));
    assert!(server
        .alpn_protocols
        .iter()
        .all(|protocol| protocol.as_slice() != astp_types::ALPN_ASTP_M));
    assert_eq!(server.max_early_data_size, 0);
    assert!(!server.send_half_rtt_data);

    let roots = roots_of(&issued.ca_der);
    let tcp = client_options(
        roots.clone(),
        "127.0.0.1",
        Some("astp.test"),
        AlpnMode::Tcp,
        None,
    );
    let name = tcp.server_name().expect("server name");
    match &name {
        ServerName::DnsName(dns) => assert_eq!(AsRef::<str>::as_ref(dns), "astp.test"),
        other => panic!("expected a DNS server name, got {other:?}"),
    }
    let tcp_cfg = client_config(tcp).expect("tcp client");
    assert_eq!(tcp_cfg.alpn_protocols, protocol_vecs(TCP_ALPN));
    assert!(!tcp_cfg.enable_early_data);

    let quic = client_options(roots, "astp.test", None, AlpnMode::Quic, None);
    let quic_cfg = client_config(quic).expect("quic client");
    assert_eq!(quic_cfg.alpn_protocols, protocol_vecs(SERVER_ALPN));
    assert!(!quic_cfg.enable_early_data);

    let (client, server_io) = drive(server, tcp_cfg, name).await.expect("handshake");
    assert_eq!(
        client.get_ref().1.alpn_protocol(),
        Some(astp_types::ALPN_H2)
    );
    assert_eq!(
        server_io.get_ref().1.alpn_protocol(),
        Some(astp_types::ALPN_H2)
    );
    assert_eq!(
        client.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        server_io.get_ref().1.protocol_version(),
        Some(rustls::ProtocolVersion::TLSv1_3)
    );
    assert_eq!(
        client.get_ref().1.handshake_kind(),
        Some(rustls::HandshakeKind::Full)
    );
}

#[tokio::test]
async fn tls12_only_client_is_rejected() {
    let issued = issue(&rcgen::PKCS_ECDSA_P256_SHA256);
    let (server, _client, name) = configs(&issued, None, None);
    let err = drive(server, tls12_client(roots_of(&issued.ca_der)), name)
        .await
        .expect_err("TLS 1.2 client was accepted");
    assert_tls_refusal(&err, "tls 1.2");
}

#[tokio::test]
async fn rejects_untrusted_ca_wrong_name_and_ip_without_server_name() {
    let issued = issue(&rcgen::PKCS_ECDSA_P256_SHA256);
    let roots = roots_of(&issued.ca_der);

    for host in ["127.0.0.1", "::1", "[::1]", "[127.0.0.1]"] {
        let options = client_options(roots.clone(), host, None, AlpnMode::Tcp, None);
        let err = client_config(options).expect_err(host);
        assert_eq!(err, CryptoError::IpLiteralRequiresServerName, "{host}");
    }
    let blank_name = client_options(roots.clone(), "::1", Some("   "), AlpnMode::Tcp, None);
    assert_eq!(
        client_config(blank_name).expect_err("blank server name"),
        CryptoError::IpLiteralRequiresServerName
    );
    let empty_host = client_options(roots.clone(), "  ", None, AlpnMode::Tcp, None);
    assert!(matches!(
        client_config(empty_host).expect_err("empty host"),
        CryptoError::InvalidServerName { .. }
    ));
    assert_eq!(
        client_config(client_options(
            RootCertStore::empty(),
            "astp.test",
            None,
            AlpnMode::Tcp,
            None,
        ))
        .expect_err("empty trust"),
        CryptoError::EmptyTrustAnchors
    );
    assert_eq!(
        server_config(ServerOptions {
            identity: server_identity(&issued),
            client_auth: Some(ClientAuth::Required(RootCertStore::empty())),
        })
        .expect_err("empty mTLS roots"),
        CryptoError::EmptyTrustAnchors
    );

    let (server, _, _) = configs(&issued, None, None);
    let foreign = client_options(
        roots_of(&other_ca()),
        "astp.test",
        None,
        AlpnMode::Tcp,
        None,
    );
    let foreign_name = foreign.server_name().expect("foreign name");
    let foreign_cfg = client_config(foreign).expect("foreign client");
    let err = drive(server, foreign_cfg, foreign_name)
        .await
        .expect_err("foreign CA was accepted");
    assert_tls_refusal(&err, "foreign CA");

    let (server, _, _) = configs(&issued, None, None);
    let wrong = client_options(roots.clone(), "not-astp.test", None, AlpnMode::Tcp, None);
    let wrong_name = wrong.server_name().expect("wrong name");
    let wrong_cfg = client_config(wrong).expect("wrong-name client");
    let err = drive(server, wrong_cfg, wrong_name)
        .await
        .expect_err("wrong server name was accepted");
    assert_tls_refusal(&err, "wrong server name");

    let (server, _, _) = configs(&issued, None, None);
    let webpki = ClientOptions {
        trust: TrustAnchors::Webpki,
        alpn: AlpnMode::Tcp,
        host: "astp.test".to_string(),
        tls_server_name: None,
        client_identity: None,
    };
    let webpki_name = webpki.server_name().expect("webpki name");
    let webpki_cfg = client_config(webpki).expect("webpki client");
    let err = drive(server, webpki_cfg, webpki_name)
        .await
        .expect_err("webpki roots accepted a private CA");
    assert_tls_refusal(&err, "webpki roots");
}

#[tokio::test]
async fn early_data_is_not_offered_on_resumption() {
    let issued = issue(&rcgen::PKCS_ECDSA_P256_SHA256);
    let (server, client, name) = configs(&issued, None, None);
    assert_eq!(server.max_early_data_size, 0);
    assert!(!server.send_half_rtt_data);
    assert!(!client.enable_early_data);
    assert_resumption_omits_early_data(server, client, name, 1).await;

    let harness = early_data_server(&issued);
    let options = client_options(
        roots_of(&issued.ca_der),
        "127.0.0.1",
        Some("astp.test"),
        AlpnMode::Tcp,
        None,
    );
    let name = options.server_name().expect("server name");
    let client = client_config(options).expect("client config");
    assert!(!client.enable_early_data);
    assert_resumption_omits_early_data(Arc::clone(&harness), Arc::clone(&client), name.clone(), 2)
        .await;

    let mut eager = rustls::ClientConfig::clone(&client);
    eager.enable_early_data = true;
    let mut control = rustls::ClientConnection::new(Arc::new(eager), name).expect("control client");
    assert!(
        control.early_data().is_some(),
        "control client did not see a 0-RTT ticket; the refusal check would not show a difference"
    );
    let mut hello = Vec::new();
    while control.wants_write() {
        control
            .write_tls(&mut hello)
            .expect("write control ClientHello");
    }
    let extensions = client_hello_extensions(&hello)
        .unwrap_or_else(|err| panic!("parse control ClientHello: {err}"));
    assert!(
        extensions.contains(&EXT_PRE_SHARED_KEY),
        "control ClientHello was not a resumption: {extensions:?}"
    );
    assert!(
        extensions.contains(&EXT_EARLY_DATA),
        "control ClientHello lacked early_data, so the parser cannot see 0-RTT: {extensions:?}"
    );
}

#[tokio::test]
async fn mtls_is_opt_in_and_default_profile_has_no_client_auth() {
    let issued = issue(&rcgen::PKCS_ECDSA_P256_SHA256);

    let (server, client, name) = configs(&issued, None, None);
    let (_client_io, server_io) = drive(server, client, name)
        .await
        .expect("default handshake");
    assert!(server_io.get_ref().1.peer_certificates().is_none());

    let (server, client, name) = configs(
        &issued,
        Some(ClientAuth::Required(roots_of(&issued.ca_der))),
        None,
    );
    let err = drive(server, client, name)
        .await
        .expect_err("mTLS server accepted a client with no certificate");
    assert_tls_refusal(&err, "mTLS without client certificate");

    let (server, client, name) = configs(
        &issued,
        Some(ClientAuth::Required(roots_of(&issued.ca_der))),
        Some(mtls_identity(&issued)),
    );
    let (_client_io, server_io) = drive(server, client, name).await.expect("mTLS handshake");
    assert!(server_io.get_ref().1.peer_certificates().is_some());

    let (server, client, name) = configs(&issued, None, None);
    let (_client_io, server_io) = drive(server, client, name)
        .await
        .expect("default profile changed");
    assert!(server_io.get_ref().1.peer_certificates().is_none());
}

#[tokio::test]
async fn channel_binding_matches_within_connection_and_differs_across() {
    fn assert_session<T: TlsSession + ?Sized>() {}
    assert_session::<rustls::Connection>();
    assert_session::<rustls::ClientConnection>();
    assert_session::<rustls::ServerConnection>();

    let issued = issue(&rcgen::PKCS_ECDSA_P256_SHA256);
    let (client_a, server_a) = connection_bindings(&issued).await;
    let (client_b, server_b) = connection_bindings(&issued).await;
    assert_eq!(client_a, server_a);
    assert_eq!(client_b, server_b);
    assert_ne!(client_a, client_b);
    assert_eq!(client_a.as_bytes().len(), CHANNEL_BINDING_LEN);
    assert_eq!(format!("{client_a:?}"), "ChannelBinding([redacted])");
}

#[tokio::test]
async fn authenticator_rejects_credential_from_another_connection() {
    let issued = issue(&rcgen::PKCS_ECDSA_P256_SHA256);
    let (binding_a, same_a) = connection_bindings(&issued).await;
    let (binding_b, _) = connection_bindings(&issued).await;
    assert_eq!(binding_a, same_a);
    assert_ne!(binding_a, binding_b);

    let auth = StaticTokenAuthenticator::new(b"test-secret", ClientId::new(b"client-a"))
        .expect("authenticator");
    let credential_a = auth.credential(&binding_a).expect("credential a");
    let credential_b = auth.credential(&binding_b).expect("credential b");
    assert_eq!(credential_a.len(), CHANNEL_BINDING_LEN);

    let accepted = auth.verify(&binding_a, &credential_a).expect("accept");
    assert_eq!(accepted.as_bytes(), b"client-a");
    assert_eq!(
        auth.verify(&same_a, &credential_a)
            .expect("same binding")
            .as_bytes(),
        b"client-a"
    );
    assert_eq!(
        auth.verify(&binding_b, &credential_a).expect_err("replay"),
        AuthError::Rejected
    );
    assert_eq!(
        auth.verify(&binding_a, &credential_b)
            .expect_err("other credential"),
        AuthError::Rejected
    );
    let mut flipped = credential_a.clone();
    flipped[0] ^= 0xff;
    assert_eq!(
        auth.verify(&binding_a, &flipped).expect_err("flipped byte"),
        AuthError::Rejected
    );
    assert_eq!(
        auth.verify(&binding_a, b"short")
            .expect_err("short credential"),
        AuthError::Malformed
    );
    assert_eq!(
        StaticTokenAuthenticator::new(b"", ClientId::new(b"x")).expect_err("empty secret"),
        AuthError::Malformed
    );
    assert_eq!(AuthError::Rejected.to_string(), "authentication rejected");
    assert_eq!(
        AuthError::Malformed.to_string(),
        "authentication credential is malformed"
    );
    assert_eq!(
        AuthError::Internal.to_string(),
        "internal authentication error"
    );
    assert!(!format!("{auth:?}").contains("test-secret"));
    assert!(!AuthError::Rejected.to_string().contains("test-secret"));
}

#[tokio::test]
async fn ed25519_and_p256_certificates_are_accepted() {
    for (label, alg) in [
        ("ed25519", &rcgen::PKCS_ED25519),
        ("p256", &rcgen::PKCS_ECDSA_P256_SHA256),
    ] {
        let issued = issue(alg);
        expect_handshake(&issued, false, label).await;
        expect_handshake(&issued, true, label).await;
    }
}

#[test]
fn rsa_and_p384_own_keys_are_rejected() {
    let p384 = issue(&rcgen::PKCS_ECDSA_P384_SHA384);
    assert_own_key_rejected(&p384, "ecdsa-p384");

    // Throwaway RSA key generated for this test. It is not a credential.
    let cert =
        CertificateDer::from_pem_slice(include_bytes!("rsa-own-cert.fixture")).expect("rsa cert");
    let key =
        PrivateKeyDer::from_pem_slice(include_bytes!("rsa-own-key.fixture")).expect("rsa key");
    let rsa = Issued {
        ca_der: cert.clone(),
        leaf_cert: cert.clone(),
        leaf_key: key.clone_key(),
        client_cert: cert,
        client_key: key,
        leaf_pem: String::new(),
        leaf_key_pem: String::new(),
    };
    assert_own_key_rejected(&rsa, "rsa");

    let allowed = issue(&rcgen::PKCS_ECDSA_P256_SHA256);
    let client = client_config(client_options(
        roots_of(&allowed.ca_der),
        "astp.test",
        None,
        AlpnMode::Tcp,
        None,
    ))
    .expect("p256 client");
    let schemes = client
        .crypto_provider()
        .signature_verification_algorithms
        .mapping;
    assert!(schemes
        .iter()
        .any(|(scheme, _)| *scheme == rustls::SignatureScheme::ECDSA_NISTP384_SHA384));
    assert!(schemes
        .iter()
        .any(|(scheme, _)| *scheme == rustls::SignatureScheme::RSA_PKCS1_SHA256));
}

fn assert_own_key_rejected(issued: &Issued, algorithm: &'static str) {
    let server_err = server_config(ServerOptions {
        identity: server_identity(issued),
        client_auth: None,
    })
    .expect_err("server accepted a disallowed own key");
    assert_eq!(
        server_err,
        CryptoError::UnsupportedOwnKey { algorithm },
        "server"
    );

    let client_err = client_config(client_options(
        roots_of(&issued.ca_der),
        "astp.test",
        None,
        AlpnMode::Tcp,
        Some(mtls_identity(issued)),
    ))
    .expect_err("mTLS client accepted a disallowed own key");
    assert_eq!(
        client_err,
        CryptoError::UnsupportedOwnKey { algorithm },
        "mTLS client"
    );
}

#[test]
fn missing_pem_is_an_identity_error() {
    let err = server_config(ServerOptions {
        identity: Identity::Pem {
            certificate: "/no/such/astp-cert.pem".into(),
            private_key: "/no/such/astp-key.pem".into(),
        },
        client_auth: None,
    })
    .expect_err("missing PEM should fail");
    assert!(matches!(err, CryptoError::Identity { .. }), "{err}");
}

#[test]
fn library_sources_do_not_panic_or_disable_verification() {
    let root = env!("CARGO_MANIFEST_DIR");
    for name in ["src/lib.rs", "src/tls.rs", "src/auth.rs"] {
        let text = std::fs::read_to_string(format!("{root}/{name}")).expect("read source");
        assert!(!text.contains("unsafe "), "{name} uses unsafe");
        assert!(!text.contains(".unwrap("), "{name} uses unwrap");
        assert!(!text.contains(".expect("), "{name} uses expect");
        assert!(!text.contains("panic!("), "{name} uses panic");
        assert!(!text.contains(".dangerous("), "{name} calls dangerous");
        assert!(
            !text.contains("enable_sni = false"),
            "{name} disables server name indication"
        );
    }
}
