use super::*;
use astp_crypto::{
    client_config, server_config, AlpnMode, ClientId, ClientOptions, ClientSecret, Identity,
    KeyTable, TrustAnchors,
};
use astp_session::{
    client_handshake, run, server_handshake, EndReason, Link, Role, SessionParams, Stats,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, watch};

const PATH: &str = "/s3cr3t-path";
const T: Duration = Duration::from_secs(10);

struct Pki {
    ca: CertificateDer<'static>,
    leaf: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
}

fn pki() -> Pki {
    let ca_key = rcgen::KeyPair::generate().unwrap();
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca = ca_params.self_signed(&ca_key).unwrap();
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let key = rcgen::KeyPair::generate().unwrap();
    let leaf = rcgen::CertificateParams::new(vec!["astp.test".to_string()])
        .unwrap()
        .signed_by(&key, &issuer)
        .unwrap();
    Pki {
        ca: ca.der().clone(),
        leaf: leaf.der().clone(),
        key: PrivateKeyDer::from(key),
    }
}

fn server_tls(p: &Pki, alpn: AlpnMode) -> Arc<rustls::ServerConfig> {
    server_config(astp_crypto::ServerOptions {
        identity: Identity::Der {
            certificates: vec![p.leaf.clone()],
            private_key: p.key.clone_key(),
        },
        client_auth: None,
        alpn,
    })
    .unwrap()
}

fn client_tls(p: &Pki, alpn: AlpnMode) -> astp_crypto::ClientTlsConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(p.ca.clone()).unwrap();
    client_config(ClientOptions {
        trust: TrustAnchors::Explicit(roots),
        alpn,
        host: "127.0.0.1".into(),
        tls_server_name: Some("astp.test".into()),
        client_identity: None,
    })
    .unwrap()
}

fn opts() -> ServerOptions {
    ServerOptions {
        session_path: PATH.into(),
        ..ServerOptions::default()
    }
}

fn keys() -> (ClientSecret, Arc<dyn astp_crypto::Authenticator>) {
    let secret = ClientSecret::generate().unwrap();
    let mut table = KeyTable::new().unwrap();
    table.insert(&secret, ClientId::new("alice")).unwrap();
    (secret, Arc::new(table))
}

/// One packet each way through a real session on top of the transport.
async fn exercise(server_io: SessionIo, client_io: SessionIo) {
    let params = SessionParams {
        addr4: Some(("10.77.0.2".parse().unwrap(), 24)),
        ..SessionParams::default()
    };
    let mut sr = astp_frame::FrameReader::new(server_io.reader);
    let mut sw = server_io.writer;
    let mut cr = astp_frame::FrameReader::new(client_io.reader);
    let mut cw = client_io.writer;
    let (s, c) = tokio::join!(
        server_handshake(&mut sr, &mut sw, &params, T),
        client_handshake(&mut cr, &mut cw, T, |_| Ok(())),
    );
    s.unwrap();
    let cp = c.unwrap();

    let (s_to, mut s_to_rx) = mpsc::channel(8);
    let (s_from_tx, s_from) = mpsc::channel(8);
    let (c_to, mut c_to_rx) = mpsc::channel(8);
    let (c_from_tx, c_from) = mpsc::channel(8);
    let mut pkt = vec![0u8; 40];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&40u16.to_be_bytes());
    let traffic = async {
        c_from_tx.send(pkt.clone()).await.unwrap();
        assert_eq!(s_to_rx.recv().await.unwrap(), pkt);
        s_from_tx.send(pkt.clone()).await.unwrap();
        assert_eq!(c_to_rx.recv().await.unwrap(), pkt);
        drop(c_from_tx);
    };
    let (se, ce, ()) = tokio::join!(
        run(
            Role::Server,
            sr,
            sw,
            &params,
            Link {
                to_local: s_to,
                from_local: s_from,
                events: None
            },
            Arc::new(Stats::default()),
            std::future::pending()
        ),
        run(
            Role::Client,
            cr,
            cw,
            &cp,
            Link {
                to_local: c_to,
                from_local: c_from,
                events: None
            },
            Arc::new(Stats::default()),
            std::future::pending()
        ),
        traffic
    );
    assert!(matches!(ce, EndReason::LocalClosed), "{ce:?}");
    assert!(
        matches!(se, EndReason::PeerDisconnect { code: 0, .. }),
        "{se:?}"
    );
}

async fn tcp_server(
    p: &Pki,
    auth: Arc<dyn astp_crypto::Authenticator>,
) -> (SocketAddr, mpsc::Receiver<Accepted>, watch::Sender<bool>) {
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    let (tx, rx) = mpsc::channel(4);
    let (sd_tx, sd_rx) = watch::channel(false);
    tokio::spawn(serve_tcp(
        l,
        server_tls(p, AlpnMode::Tcp),
        auth,
        opts(),
        tx,
        sd_rx,
    ));
    (addr, rx, sd_tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_session_end_to_end() {
    let p = pki();
    let (secret, auth) = keys();
    let (addr, mut acc, _sd) = tcp_server(&p, auth).await;
    let (cio, _guard) = connect_tcp(addr, client_tls(&p, AlpnMode::Tcp), &secret, PATH, T)
        .await
        .unwrap();
    let a = acc.recv().await.unwrap();
    assert_eq!(a.client, ClientId::new("alice"));
    assert_eq!(a.transport, "h2");
    exercise(a.io, cio).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn tcp_refusals_look_like_the_decoy() {
    let p = pki();
    let (_secret, auth) = keys();
    let (addr, mut acc, _sd) = tcp_server(&p, auth).await;
    let stranger = ClientSecret::generate().unwrap();
    let e = connect_tcp(addr, client_tls(&p, AlpnMode::Tcp), &stranger, PATH, T)
        .await
        .unwrap_err();
    assert!(matches!(e, TransportError::Refused(404)), "{e:?}");
    let e = connect_tcp(addr, client_tls(&p, AlpnMode::Tcp), &stranger, "/other", T)
        .await
        .unwrap_err();
    assert!(matches!(e, TransportError::Refused(404)), "{e:?}");
    assert!(acc.try_recv().is_err(), "nothing was accepted");

    // Same bytes for a bad credential on the session path and a GET of a
    // random path, and the index page for a browser.
    let fetch = |method: http::Method, path: &'static str, auth: Option<&'static str>| {
        let tls = client_tls(&p, AlpnMode::Tcp);
        async move {
            let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
            let (cfg, name) = tls.into_parts();
            let s = tokio_rustls::TlsConnector::from(cfg)
                .connect(name, tcp)
                .await
                .unwrap();
            let (mut send, conn) = hyper::client::conn::http2::handshake(
                hyper_util::rt::TokioExecutor::new(),
                hyper_util::rt::TokioIo::new(s),
            )
            .await
            .unwrap();
            tokio::spawn(conn);
            let mut b = Request::builder()
                .method(method)
                .uri(format!("https://astp.test:{}{path}", addr.port()));
            if let Some(a) = auth {
                b = b.header("authorization", a);
            }
            let r = send
                .send_request(
                    b.body(http_body_util::Empty::<bytes::Bytes>::new())
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = r.status();
            let ct = r.headers().get("content-type").cloned();
            let body = http_body_util::BodyExt::collect(r.into_body())
                .await
                .unwrap()
                .to_bytes();
            (status, ct, body)
        }
    };
    use http::Request;
    let bad_auth = fetch(http::Method::POST, PATH, Some("Bearer AAAA")).await;
    let garbage = fetch(http::Method::POST, PATH, Some("Bearer !!!")).await;
    let no_auth = fetch(http::Method::POST, PATH, None).await;
    let random = fetch(http::Method::GET, "/favicon.ico", None).await;
    assert_eq!(bad_auth, random);
    assert_eq!(garbage, random);
    assert_eq!(no_auth, random);
    assert_eq!(random.0, 404);
    let index = fetch(http::Method::GET, "/", None).await;
    assert_eq!(index.0, 200);
    assert!(index.2.starts_with(b"<!doctype html>"));
}

async fn quic_server(
    p: &Pki,
    auth: Arc<dyn astp_crypto::Authenticator>,
) -> (SocketAddr, mpsc::Receiver<Accepted>, watch::Sender<bool>) {
    let ep = quic_endpoint_server(
        "127.0.0.1:0".parse().unwrap(),
        server_tls(p, AlpnMode::Quic),
        Duration::from_secs(30),
    )
    .unwrap();
    let addr = ep.local_addr().unwrap();
    let (tx, rx) = mpsc::channel(4);
    let (sd_tx, sd_rx) = watch::channel(false);
    tokio::spawn(serve_quic(ep, auth, opts(), tx, sd_rx));
    (addr, rx, sd_tx)
}

#[tokio::test(flavor = "multi_thread")]
async fn quic_session_end_to_end_and_refusal() {
    let p = pki();
    let (secret, auth) = keys();
    let (addr, mut acc, _sd) = quic_server(&p, auth).await;
    let idle = Duration::from_secs(30);
    let (cio, _guard) = connect_quic(addr, client_tls(&p, AlpnMode::Quic), &secret, PATH, T, idle)
        .await
        .unwrap();
    let a = acc.recv().await.unwrap();
    assert_eq!(a.transport, "h3");
    exercise(a.io, cio).await;

    let stranger = ClientSecret::generate().unwrap();
    let e = connect_quic(
        addr,
        client_tls(&p, AlpnMode::Quic),
        &stranger,
        PATH,
        T,
        idle,
    )
    .await
    .unwrap_err();
    assert!(matches!(e, TransportError::Refused(404)), "{e:?}");
}

#[test]
fn authority_forms() {
    use rustls::pki_types::ServerName;
    assert_eq!(
        authority(&ServerName::try_from("a.test").unwrap(), 443),
        "a.test"
    );
    assert_eq!(
        authority(&ServerName::try_from("a.test").unwrap(), 8443),
        "a.test:8443"
    );
    assert_eq!(
        authority(&ServerName::try_from("::1").unwrap(), 8443),
        "[::1]:8443"
    );
}
