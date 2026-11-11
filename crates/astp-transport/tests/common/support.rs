//! Shared localhost fixtures for the QUIC tests.
//!
//! Each integration test is its own crate and uses only some of these helpers.
#![allow(dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use astp_crypto::{
    client_tls, server_config, AlpnMode, ClientOptions, ClientTls, Identity, ServerOptions,
    TrustAnchors,
};
use astp_transport::{QuicLimits, QuicServer};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::RootCertStore;
use tokio::net::UdpSocket;
use tokio::task::JoinHandle;

pub struct Fixture {
    pub server_config: Arc<rustls::ServerConfig>,
    pub roots: RootCertStore,
}

pub fn fixture() -> Fixture {
    let alg = &rcgen::PKCS_ECDSA_P256_SHA256;
    let ca_key = rcgen::KeyPair::generate_for(alg).expect("ca key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("ca parameters");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "astp test CA");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca certificate");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);
    let leaf_key = rcgen::KeyPair::generate_for(alg).expect("leaf key");
    let leaf = rcgen::CertificateParams::new(vec!["astp.test".to_string()])
        .expect("leaf parameters")
        .signed_by(&leaf_key, &issuer)
        .expect("leaf certificate");
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(ca_cert))
        .expect("trust anchor");
    let server_config = server_config(ServerOptions {
        identity: Identity::Der {
            certificates: vec![CertificateDer::from(leaf)],
            private_key: PrivateKeyDer::from(leaf_key),
        },
        client_auth: None,
    })
    .expect("server config");
    Fixture {
        server_config,
        roots,
    }
}

pub fn tls_quic(fixture: &Fixture) -> ClientTls {
    client_tls(client_options(fixture, AlpnMode::Quic)).expect("quic client tls")
}

pub fn tls_h2(fixture: &Fixture) -> ClientTls {
    client_tls(client_options(fixture, AlpnMode::Tcp)).expect("h2 client tls")
}

fn client_options(fixture: &Fixture, alpn: AlpnMode) -> ClientOptions {
    ClientOptions {
        trust: TrustAnchors::Explicit(fixture.roots.clone()),
        alpn,
        host: "127.0.0.1".into(),
        tls_server_name: Some("astp.test".into()),
        client_identity: None,
    }
}

pub fn test_limits() -> QuicLimits {
    QuicLimits {
        handshake_timeout: Duration::from_secs(5),
        retry_threshold: usize::MAX,
        ..QuicLimits::default()
    }
}

pub async fn bind(limits: QuicLimits) -> (Fixture, QuicServer) {
    let fixture = fixture();
    let server = QuicServer::bind(
        "127.0.0.1:0".parse().expect("addr"),
        Arc::clone(&fixture.server_config),
        limits,
    )
    .expect("bind");
    (fixture, server)
}

/// A client that emits one Initial and then goes silent from the server's point of view.
pub struct HalfOpen {
    _endpoint: quinn::Endpoint,
    _connecting: quinn::Connecting,
    _forward: JoinHandle<()>,
}

pub async fn half_open(server: SocketAddr, tls: &ClientTls) -> HalfOpen {
    let proxy = UdpSocket::bind("127.0.0.1:0").await.expect("proxy");
    let proxy_addr = proxy.local_addr().expect("proxy addr");
    let mut endpoint =
        quinn::Endpoint::client("127.0.0.1:0".parse().expect("client")).expect("client endpoint");
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::clone(tls.config()))
        .expect("quic client config");
    let mut client = quinn::ClientConfig::new(Arc::new(crypto));
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("idle")));
    client.transport_config(Arc::new(transport));
    endpoint.set_default_client_config(client);
    let connecting = endpoint
        .connect(proxy_addr, tls.server_name().to_str().as_ref())
        .expect("start initial");
    let forward = tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut forwarded = false;
        loop {
            let Ok((n, from)) = proxy.recv_from(&mut buf).await else {
                break;
            };
            if from == server {
                continue;
            }
            if !forwarded {
                let _ = proxy.send_to(&buf[..n], server).await;
                forwarded = true;
            }
        }
    });
    HalfOpen {
        _endpoint: endpoint,
        _connecting: connecting,
        _forward: forward,
    }
}

pub async fn wait_pending(server: &QuicServer, want: usize) {
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while server.pending_handshakes() < want && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(server.pending_handshakes(), want, "pending handshakes");
}
