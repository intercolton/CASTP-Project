//! Server and client libraries end to end on localhost. Channels stand in
//! for both TUN devices, so no privileges are needed.

use astp_client::config::Config as ClientConfig;
use astp_server::config::Config as ServerConfig;
use astp_server::{Bound, TunSide};
use astp_session::{code, run, EndReason, Link, Packet, Role, Stats};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot, watch};

const PATH: &str = "/e2e-session-path-0123";

struct Env {
    dir: tempfile::TempDir,
    alice: String,
    bob: String,
}

fn env() -> Env {
    let dir = tempfile::tempdir().unwrap();
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
    std::fs::write(dir.path().join("ca.pem"), ca.pem()).unwrap();
    std::fs::write(dir.path().join("cert.pem"), leaf.pem()).unwrap();
    std::fs::write(dir.path().join("key.pem"), key.serialize_pem()).unwrap();
    let (alice, _) = astp_server::keygen().unwrap();
    let (bob, _) = astp_server::keygen().unwrap();
    Env { dir, alice, bob }
}

fn server_cfg(e: &Env) -> ServerConfig {
    let d = e.dir.path();
    ServerConfig::from_toml(&format!(
        r#"
[server]
listen_tcp = "127.0.0.1:0"
listen_quic = "127.0.0.1:0"
session_path = "{PATH}"
[tls]
cert_file = '{cert}'
key_file = '{key}'
[tunnel]
address4 = "10.77.0.1/24"
dns4 = ["10.77.0.1"]
routes = ["0.0.0.0/0", "!192.168.0.0/16"]
keepalive_seconds = 5
idle_timeout_seconds = 30
[[clients]]
name = "alice"
secret = "{alice}"
address4 = "10.77.0.2"
[[clients]]
name = "bob"
secret = "{bob}"
address4 = "10.77.0.3"
"#,
        cert = d.join("cert.pem").display(),
        key = d.join("key.pem").display(),
        alice = e.alice,
        bob = e.bob,
    ))
    .unwrap()
}

fn client_cfg(e: &Env, port: u16, transport: &str, secret: &str) -> ClientConfig {
    ClientConfig::from_toml(&format!(
        r#"
[client]
server = "127.0.0.1:{port}"
tls_server_name = "astp.test"
ca_file = '{ca}'
transport = "{transport}"
session_path = "{PATH}"
secret = "{secret}"
"#,
        ca = e.dir.path().join("ca.pem").display(),
    ))
    .unwrap()
}

struct Server {
    bound: Bound,
    to_tun: mpsc::Receiver<Packet>,
    from_tun: mpsc::Sender<Packet>,
    stop: watch::Sender<bool>,
    task: tokio::task::JoinHandle<anyhow::Result<()>>,
}

async fn start(e: &Env) -> Server {
    let cfg = server_cfg(e);
    let clients = astp_server::check(&cfg, |_| None).unwrap();
    let (to_tun_tx, to_tun) = mpsc::channel(64);
    let (from_tun, from_tun_rx) = mpsc::channel(64);
    let (stop, stop_rx) = watch::channel(false);
    let (btx, brx) = oneshot::channel();
    let task = tokio::spawn(astp_server::serve(
        cfg,
        clients,
        TunSide {
            to_tun: to_tun_tx,
            from_tun: from_tun_rx,
        },
        stop_rx,
        Some(btx),
    ));
    Server {
        bound: brx.await.unwrap(),
        to_tun,
        from_tun,
        stop,
        task,
    }
}

fn ipv4(src: [u8; 4], dst: [u8; 4], tag: u8) -> Packet {
    let mut p = vec![0u8; 28];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&28u16.to_be_bytes());
    p[9] = 17;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    p[27] = tag;
    p
}

/// A running client session with channels for its "device".
struct Client {
    to_dev: mpsc::Receiver<Packet>,
    from_dev: mpsc::Sender<Packet>,
    end: tokio::task::JoinHandle<EndReason>,
    params: astp_session::SessionParams,
}

async fn session(cfg: &ClientConfig) -> Client {
    let secret = cfg.secret(|_| None).unwrap();
    let mut c = astp_client::connect(cfg, &secret).await.unwrap();
    let (reader, params) = astp_client::handshake(&mut c).await.unwrap();
    let (to_dev_tx, to_dev) = mpsc::channel(64);
    let (from_dev, from_dev_rx) = mpsc::channel(64);
    let p = params.clone();
    let end = tokio::spawn(async move {
        let _guard = c.guard;
        run(
            Role::Client,
            reader,
            c.writer,
            &p,
            Link {
                to_local: to_dev_tx,
                from_local: from_dev_rx,
                events: None,
            },
            Arc::new(Stats::default()),
            std::future::pending(),
        )
        .await
    });
    Client {
        to_dev,
        from_dev,
        end,
        params,
    }
}

async fn within<T>(f: impl std::future::Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(10), f)
        .await
        .expect("timed out")
}

/// Sends `pkt` into the server's TUN side until the client gets it: the
/// server registers a client's address only once its CONFIG_ACK arrives,
/// slightly after the client considers the handshake done, and packets
/// for an unregistered address are dropped like on a real network.
async fn deliver(
    from_tun: &mpsc::Sender<Packet>,
    to_dev: &mut mpsc::Receiver<Packet>,
    pkt: Packet,
) {
    within(async {
        loop {
            from_tun.send(pkt.clone()).await.unwrap();
            if let Ok(Some(got)) =
                tokio::time::timeout(Duration::from_millis(100), to_dev.recv()).await
            {
                assert_eq!(got, pkt);
                // Drain duplicates of the retries.
                while let Ok(Some(dup)) =
                    tokio::time::timeout(Duration::from_millis(50), to_dev.recv()).await
                {
                    assert_eq!(dup, pkt);
                }
                return;
            }
        }
    })
    .await;
}

async fn routes_packets(transport: &str) {
    let e = env();
    let mut s = start(&e).await;
    let port = if transport == "h3" {
        s.bound.quic.unwrap().port()
    } else {
        s.bound.tcp.port()
    };
    let mut alice = session(&client_cfg(&e, port, transport, &e.alice)).await;
    assert_eq!(alice.params.addr4, Some(("10.77.0.2".parse().unwrap(), 24)));
    assert_eq!(alice.params.routes.len(), 2);
    assert_eq!(
        alice.params.dns4,
        vec!["10.77.0.1".parse::<std::net::Ipv4Addr>().unwrap()]
    );

    // Client → TUN, with its own source address.
    let up = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 1);
    alice.from_dev.send(up.clone()).await.unwrap();
    assert_eq!(within(s.to_tun.recv()).await.unwrap(), up);
    // A spoofed source never reaches the TUN; the next good one does.
    alice
        .from_dev
        .send(ipv4([10, 77, 0, 3], [1, 1, 1, 1], 2))
        .await
        .unwrap();
    let good = ipv4([10, 77, 0, 2], [1, 1, 1, 1], 3);
    alice.from_dev.send(good.clone()).await.unwrap();
    assert_eq!(within(s.to_tun.recv()).await.unwrap(), good);

    // TUN → the client that owns the destination; unknown ones are dropped.
    s.from_tun
        .send(ipv4([1, 1, 1, 1], [10, 77, 0, 9], 4))
        .await
        .unwrap();
    deliver(
        &s.from_tun,
        &mut alice.to_dev,
        ipv4([1, 1, 1, 1], [10, 77, 0, 2], 5),
    )
    .await;

    // A second session of the same client replaces the first.
    let mut again = session(&client_cfg(&e, port, transport, &e.alice)).await;
    let first = within(alice.end).await.unwrap();
    assert!(
        matches!(
            first,
            EndReason::PeerDisconnect {
                code: code::REPLACED,
                ..
            }
        ),
        "{first:?}"
    );
    deliver(
        &s.from_tun,
        &mut again.to_dev,
        ipv4([1, 1, 1, 1], [10, 77, 0, 2], 6),
    )
    .await;

    // Bob has his own address.
    let mut bob = session(&client_cfg(&e, port, transport, &e.bob)).await;
    assert_eq!(bob.params.addr4, Some(("10.77.0.3".parse().unwrap(), 24)));
    deliver(
        &s.from_tun,
        &mut bob.to_dev,
        ipv4([1, 1, 1, 1], [10, 77, 0, 3], 7),
    )
    .await;

    // Shutdown: every client hears DISCONNECT 4.
    s.stop.send(true).unwrap();
    for end in [again.end, bob.end] {
        let r = within(end).await.unwrap();
        assert!(
            matches!(
                r,
                EndReason::PeerDisconnect {
                    code: code::SERVER_SHUTDOWN,
                    ..
                }
            ),
            "{r:?}"
        );
    }
    within(s.task).await.unwrap().unwrap();
}

#[tokio::test(flavor = "multi_thread")]
async fn h2_end_to_end() {
    routes_packets("h2").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn h3_end_to_end() {
    routes_packets("h3").await;
}

#[tokio::test(flavor = "multi_thread")]
async fn auto_falls_back_to_h2_and_strangers_are_refused() {
    let e = env();
    let s = start(&e).await;
    // The TCP port has no QUIC listener: auto must fall back to h2.
    let cfg = client_cfg(&e, s.bound.tcp.port(), "auto", &e.alice);
    let secret = cfg.secret(|_| None).unwrap();
    let c = astp_client::connect(&cfg, &secret).await.unwrap();
    assert_eq!(c.transport, "h2");

    let (stranger, _) = astp_server::keygen().unwrap();
    let cfg = client_cfg(&e, s.bound.tcp.port(), "h2", &stranger);
    let secret = cfg.secret(|_| None).unwrap();
    let err = astp_client::connect(&cfg, &secret).await.err().unwrap();
    assert!(format!("{err:#}").contains("404"), "{err:#}");
    s.stop.send(true).unwrap();
}
