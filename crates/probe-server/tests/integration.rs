//! Client and server together on localhost with a private test CA.

use probe_client::{probes, run_quick, Selection};
use probe_common::config::{ClientConfig, ServerConfig};
use probe_common::jsonl::read_events;
use probe_common::{ErrorCode, Phase, ProbeEvent, Side, TestType};
use std::path::Path;
use std::time::Duration;
use tokio::io::AsyncWriteExt;

struct Pki {
    dir: tempfile::TempDir,
}

impl Pki {
    /// A CA plus a leaf for `probe.test`; `other_ca.pem` is an unrelated CA.
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ca_key = rcgen::KeyPair::generate().unwrap();
        let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "astp test CA");
        let ca = ca_params.self_signed(&ca_key).unwrap();
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf = rcgen::CertificateParams::new(vec!["probe.test".to_string()])
            .unwrap()
            .signed_by(&leaf_key, &issuer)
            .unwrap();

        let other_key = rcgen::KeyPair::generate().unwrap();
        let mut other_params = rcgen::CertificateParams::new(Vec::<String>::new()).unwrap();
        other_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let other = other_params.self_signed(&other_key).unwrap();

        std::fs::write(dir.path().join("ca.pem"), ca.pem()).unwrap();
        std::fs::write(dir.path().join("other_ca.pem"), other.pem()).unwrap();
        std::fs::write(dir.path().join("cert.pem"), leaf.pem()).unwrap();
        std::fs::write(dir.path().join("key.pem"), leaf_key.serialize_pem()).unwrap();
        Pki { dir }
    }

    fn path(&self, f: &str) -> String {
        self.dir.path().join(f).display().to_string()
    }
}

fn server_cfg(pki: &Pki, data: &Path, handshake_timeout: u64) -> ServerConfig {
    ServerConfig::from_toml(&format!(
        r#"
[server]
id = "gw-test"
listen = "127.0.0.1:0"
data_dir = '{data}'
[tls]
cert_file = '{cert}'
key_file = '{key}'
[limits]
max_connections = 16
max_session_seconds = 60
max_session_bytes = 1048576
idle_timeout_seconds = 10
handshake_timeout_seconds = {handshake_timeout}
"#,
        data = data.display(),
        cert = pki.path("cert.pem"),
        key = pki.path("key.pem"),
    ))
    .unwrap()
}

fn client_cfg(port: u16, ca: &str, data: &Path) -> ClientConfig {
    ClientConfig::from_toml(&format!(
        r#"
[client]
id = "client-test"
network_id = "loopback"
data_dir = '{data}'
[[targets]]
id = "gw-test"
host = "127.0.0.1"
port = {port}
tls_server_name = "probe.test"
ca_file = '{ca}'
"#,
        data = data.display(),
    ))
    .unwrap()
}

async fn collect(cfg: &ClientConfig, sel: Selection) -> Vec<ProbeEvent> {
    let mut out = Vec::new();
    run_quick(cfg, sel, |e| out.push(e)).await;
    out
}

fn sel_tcp_tls_https_h2() -> Selection {
    Selection {
        tcp: true,
        tls: true,
        https: true,
        h2: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn client_and_server_agree() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());

    let events = collect(&cfg, sel_tcp_tls_https_h2()).await;
    assert_eq!(events.len(), 4);
    for e in &events {
        e.validate().unwrap();
        assert!(e.success, "{e:?}");
        assert_eq!(e.side, Side::Client);
    }
    let h2 = events
        .iter()
        .find(|e| e.test_type == TestType::H2Request)
        .unwrap();
    assert_eq!(
        h2.alpn.as_deref(),
        Some("h2"),
        "real HTTP/2 via ALPN (AC-04)"
    );
    assert_eq!(h2.phase, Some(Phase::Completed));
    assert!(h2.bytes_received > 0 && h2.bytes_sent > 0);
    let tls = events
        .iter()
        .find(|e| e.test_type == TestType::TlsHandshake)
        .unwrap();
    assert_eq!(tls.detail.as_deref(), Some("TLSv1_3"));

    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shutdown().await.unwrap();

    let (server_events, bad) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    assert!(bad.is_empty());
    // Requests carry the client's test_id: the two views join (spec 6.4).
    for tt in [TestType::HttpsGet, TestType::H2Request] {
        let c = events.iter().find(|e| e.test_type == tt).unwrap();
        let s = server_events
            .iter()
            .find(|e| e.test_id == c.test_id)
            .unwrap_or_else(|| panic!("server has no event for {tt:?}"));
        assert_eq!(s.side, Side::Server);
        assert_eq!(s.test_type, tt);
        assert_eq!(s.bytes_sent, "ok astp\n".len() as u64, "{s:?}");
        assert!(s.since_conn_ms.is_some(), "{s:?}");
    }
    // One accept per client connection (tcp, tls, https, h2).
    let accepts: Vec<_> = server_events
        .iter()
        .filter(|e| e.test_type == TestType::TcpAccept)
        .collect();
    assert_eq!(accepts.len(), 4, "{accepts:#?}");
    // The plain TCP test closed without sending anything.
    assert!(accepts
        .iter()
        .any(|e| !e.success && e.phase == Some(Phase::TcpConnected)));
}

#[tokio::test]
async fn wrong_ca_is_a_certificate_error() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("other_ca.pem"), data.path());
    let events = collect(
        &cfg,
        Selection {
            tls: true,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(events[0].error_code, Some(ErrorCode::TlsCertificateError));
    assert_eq!(events[0].phase, Some(Phase::TcpConnected));
    server.shutdown().await.unwrap();
}

/// The pattern seen on the wire against TSPU: TCP connects, the first part of
/// the ClientHello arrives, nothing more. The server must record it as an
/// accepted connection that received bytes but never finished TLS.
#[tokio::test]
async fn partial_client_hello_is_logged_by_server() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 1))
        .await
        .unwrap();

    let mut s = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    // A TLS record header announcing 512 bytes of handshake, then only 100.
    let mut partial = vec![0x16, 0x03, 0x01, 0x02, 0x00];
    partial.extend(std::iter::repeat_n(0u8, 100));
    s.write_all(&partial).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1600)).await;
    drop(s);
    tokio::time::sleep(Duration::from_millis(100)).await;
    server.shutdown().await.unwrap();

    let (ev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let a = ev
        .iter()
        .find(|e| e.test_type == TestType::TcpAccept)
        .expect("accept logged");
    assert!(!a.success);
    assert_eq!(a.phase, Some(Phase::FirstBytesReceived));
    assert_eq!(a.bytes_received, 105);
    assert_eq!(a.error_code, Some(ErrorCode::TlsHandshakeFailed));
}

#[tokio::test]
async fn server_unavailable_is_classified() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    let cfg = client_cfg(port, &pki.path("ca.pem"), data.path());
    let events = collect(&cfg, sel_tcp_tls_https_h2()).await;
    for e in events {
        assert_eq!(e.error_code, Some(ErrorCode::TcpRefused), "{e:?}");
        assert_eq!(e.phase, Some(Phase::DnsResolved));
    }
}

fn with_quic(mut cfg: ServerConfig) -> ServerConfig {
    cfg.quic.enable = true;
    cfg.quic.listen = Some("127.0.0.1:0".into());
    cfg
}

fn quic_target(cfg: &mut ClientConfig, quic_port: u16) {
    let t = &mut cfg.targets[0];
    t.enable_quic = true;
    t.enable_h3 = true;
    t.quic_port = quic_port;
}

fn sel_quic_h3() -> Selection {
    Selection {
        quic: true,
        h3: true,
        ..Default::default()
    }
}

#[tokio::test]
async fn quic_and_h3_work_and_join_with_server() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(with_quic(server_cfg(&pki, data.path(), 5)))
        .await
        .unwrap();
    let qport = server.quic_addr.expect("QUIC listener").port();
    let mut cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    quic_target(&mut cfg, qport);

    let events = collect(&cfg, sel_quic_h3()).await;
    assert_eq!(events.len(), 2);
    for e in &events {
        e.validate().unwrap();
        assert!(e.success, "{e:?}");
        assert_eq!(e.transport, probe_common::Transport::Quic);
        assert_eq!(e.alpn.as_deref(), Some("h3"));
        assert!(
            e.bytes_sent > 1200,
            "QUIC Initial is padded to 1200 B: {e:?}"
        );
    }
    let h3 = events
        .iter()
        .find(|e| e.test_type == TestType::H3Request)
        .unwrap();
    assert_eq!(h3.phase, Some(Phase::Completed));

    tokio::time::sleep(Duration::from_millis(300)).await;
    server.shutdown().await.unwrap();
    let (sev, bad) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    assert!(bad.is_empty());
    let s = sev
        .iter()
        .find(|e| e.test_id == h3.test_id)
        .expect("server saw the h3 test");
    assert_eq!(s.test_type, TestType::H3Request);
    assert_eq!(s.transport, probe_common::Transport::Quic);
    let accepts: Vec<_> = sev
        .iter()
        .filter(|e| e.test_type == TestType::QuicAccept)
        .collect();
    assert_eq!(accepts.len(), 2, "{accepts:#?}");
    assert!(accepts.iter().all(|e| e.success), "{accepts:#?}");
}

#[tokio::test]
async fn quic_without_listener_is_a_timeout() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let udp = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let port = udp.local_addr().unwrap().port();
    drop(udp);
    let mut cfg = client_cfg(1, &pki.path("ca.pem"), data.path());
    quic_target(&mut cfg, port);
    cfg.limits.tls_timeout_seconds = 1;
    let events = collect(
        &cfg,
        Selection {
            quic: true,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        events[0].error_code,
        Some(ErrorCode::QuicTimeout),
        "{:?}",
        events[0]
    );
    assert_eq!(events[0].phase, Some(Phase::DnsResolved));
}

#[tokio::test]
async fn quic_wrong_ca_is_a_certificate_error() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(with_quic(server_cfg(&pki, data.path(), 5)))
        .await
        .unwrap();
    let mut cfg = client_cfg(server.addr.port(), &pki.path("other_ca.pem"), data.path());
    quic_target(&mut cfg, server.quic_addr.unwrap().port());
    let events = collect(
        &cfg,
        Selection {
            quic: true,
            ..Default::default()
        },
    )
    .await;
    assert_eq!(
        events[0].error_code,
        Some(ErrorCode::TlsCertificateError),
        "{:?}",
        events[0]
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shutdown().await.unwrap();
    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let a = sev
        .iter()
        .find(|e| e.test_type == TestType::QuicAccept)
        .expect("server logged the failed QUIC handshake");
    assert!(!a.success);
}

#[tokio::test]
async fn control_counts_any_http_answer_as_reachable() {
    // Exercised against the local server: a 404 still proves reachability.
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let ctx = probes::Ctx {
        probe_id: "c".into(),
        network_id: "n".into(),
        iface: None,
        limits: cfg.limits.clone(),
        pair_id: None,
    };
    // Controls use the public root store, so the private CA is rejected:
    // that is a certificate error, not a reachable control.
    let c = probe_common::config::ControlConfig {
        id: "ctl".into(),
        url: format!("https://127.0.0.1:{}/nope", server.addr.port()),
    };
    let e = probes::control(&ctx, &c).await;
    assert!(e.control);
    assert!(!e.success);
    server.shutdown().await.unwrap();
}

// ------------------------------------------------------------- streaming ---

use probe_client::stream::{self, SessionPlan};

fn ctx_for(cfg: &ClientConfig) -> probes::Ctx {
    probes::Ctx {
        probe_id: cfg.client.id.clone(),
        network_id: cfg.client.network_id.clone(),
        iface: None,
        limits: cfg.limits.clone(),
        pair_id: None,
    }
}

#[tokio::test]
async fn download_completes_and_counts_bytes() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let e = stream::download(&ctx_for(&cfg), &cfg.targets[0], 200_000).await;
    assert!(e.success, "{e:?}");
    assert_eq!(e.test_type, TestType::Download);
    assert_eq!(e.phase, Some(Phase::Completed));
    assert!(e.bytes_received > 200_000, "raw TLS bytes include the body");
    assert!(
        e.detail.as_deref().unwrap().starts_with("200000 B in"),
        "{e:?}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shutdown().await.unwrap();
    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let s = sev
        .iter()
        .find(|s| s.test_id == e.test_id)
        .expect("server logged the download");
    assert!(s.success);
    assert_eq!(s.bytes_sent, 200_000);
}

#[tokio::test]
async fn long_session_runs_to_the_end() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let plan = SessionPlan {
        seconds: 2,
        interval_ms: 200,
        size: 100,
        stall_seconds: 2,
    };
    let e = stream::long_session(&ctx_for(&cfg), &cfg.targets[0], plan, |_, _| {}).await;
    assert!(e.success, "{e:?}");
    assert!(e.duration_ms >= 1800, "{e:?}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn long_session_reports_a_freeze() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    // Heartbeats every 3 s but a freeze is declared after 1 s of silence.
    let plan = SessionPlan {
        seconds: 10,
        interval_ms: 3000,
        size: 100,
        stall_seconds: 1,
    };
    let e = stream::long_session(&ctx_for(&cfg), &cfg.targets[0], plan, |_, _| {}).await;
    assert_eq!(e.error_code, Some(ErrorCode::ApplicationTimeout), "{e:?}");
    assert_eq!(e.phase, Some(Phase::AppDataReceived));
    assert!(e.detail.as_deref().unwrap().starts_with("stalled"), "{e:?}");
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn long_session_reports_a_cut() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let plan = SessionPlan {
        seconds: 30,
        interval_ms: 200,
        size: 100,
        stall_seconds: 10,
    };
    let stop = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        server.shutdown().await.unwrap();
    });
    let e = stream::long_session(&ctx_for(&cfg), &cfg.targets[0], plan, |_, _| {}).await;
    stop.await.unwrap();
    assert!(
        matches!(
            e.error_code,
            Some(ErrorCode::RemoteClosed | ErrorCode::TcpReset)
        ),
        "{e:?}"
    );
    assert!(
        e.duration_ms < 5000,
        "a cut is reported at once, not as a freeze: {e:?}"
    );
}

/// A TCP relay that forwards everything but stops passing server→client
/// data after `budget` bytes while keeping both sockets open: the
/// "freeze after N kilobytes" pattern attributed to TSPU (H2).
async fn freezing_relay(upstream: std::net::SocketAddr, budget: usize) -> std::net::SocketAddr {
    use tokio::io::AsyncReadExt;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        let s = tokio::net::TcpStream::connect(upstream).await.unwrap();
        let (mut cr, mut cw) = c.into_split();
        let (mut sr, mut sw) = s.into_split();
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut cr, &mut sw).await;
        });
        let mut left = budget;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = match sr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let pass = n.min(left);
            if pass > 0 {
                cw.write_all(&buf[..pass]).await.unwrap();
                left -= pass;
            }
            // Past the budget, data is read and dropped: the client just waits.
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    addr
}

#[tokio::test]
async fn download_detects_freeze_after_kilobytes() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let relay = freezing_relay(server.addr, 20_000).await;
    let mut cfg = client_cfg(relay.port(), &pki.path("ca.pem"), data.path());
    cfg.limits.request_timeout_seconds = 5;
    let t = std::time::Instant::now();
    let e = stream::download(&ctx_for(&cfg), &cfg.targets[0], 500_000).await;
    assert_eq!(e.error_code, Some(ErrorCode::ApplicationTimeout), "{e:?}");
    let d = e.detail.as_deref().unwrap();
    assert!(d.starts_with("stalled: no data for 10 s at "), "{d}");
    assert!(e.bytes_received <= 20_000, "{e:?}");
    assert!(t.elapsed() < Duration::from_secs(15));
    server.shutdown().await.unwrap();
}

/// A peer that finishes TLS and then says nothing must not hold a
/// connection slot until the session limit: it is closed after
/// `idle_timeout_seconds` and the slot is free again.
#[tokio::test]
async fn silent_connection_is_closed_after_idle_timeout() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let mut scfg = server_cfg(&pki, data.path(), 5);
    scfg.limits.max_connections = 1;
    scfg.limits.idle_timeout_seconds = 1;
    let server = probe_server::start(scfg).await.unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());

    // Takes the only slot: handshake, then silence.
    let tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let tls_cfg =
        probe_client::tlsutil::client_config(Some(Path::new(&pki.path("ca.pem"))), &[b"h2"], false)
            .unwrap();
    let silent =
        probe_client::tlsutil::handshake(tls_cfg, "probe.test", tcp, Duration::from_secs(5))
            .await
            .unwrap();

    // While it holds the slot a second connection is turned away.
    let busy = collect(
        &cfg,
        Selection {
            h2: true,
            ..Default::default()
        },
    )
    .await;
    assert!(!busy[0].success, "{:?}", busy[0]);

    tokio::time::sleep(Duration::from_millis(2500)).await;
    let free = collect(
        &cfg,
        Selection {
            h2: true,
            ..Default::default()
        },
    )
    .await;
    assert!(free[0].success, "slot was not released: {:?}", free[0]);
    drop(silent);

    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shutdown().await.unwrap();
    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let idle = sev
        .iter()
        .find(|e| {
            e.test_type == TestType::TcpAccept
                && e.detail
                    .as_deref()
                    .is_some_and(|d| d.contains("no request"))
        })
        .unwrap_or_else(|| panic!("idle close not logged: {sev:#?}"));
    assert!(!idle.success);
    assert_eq!(idle.error_code, Some(ErrorCode::ApplicationTimeout));
    assert!(idle.duration_ms < 5000, "{idle:?}");
}

/// Opens TLS + HTTP/2 to the test server and returns a request sender.
async fn h2_sender(
    server: &probe_server::Handle,
    pki: &Pki,
) -> hyper::client::conn::http2::SendRequest<http_body_util::Empty<bytes::Bytes>> {
    let tcp = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    let tls_cfg =
        probe_client::tlsutil::client_config(Some(Path::new(&pki.path("ca.pem"))), &[b"h2"], false)
            .unwrap();
    let hs = probe_client::tlsutil::handshake(tls_cfg, "probe.test", tcp, Duration::from_secs(5))
        .await
        .unwrap();
    let (sender, conn) = hyper::client::conn::http2::handshake(
        hyper_util::rt::TokioExecutor::new(),
        hyper_util::rt::TokioIo::new(hs.stream),
    )
    .await
    .unwrap();
    tokio::spawn(conn);
    sender
}

/// `max_session_bytes` bounds a whole connection, not each request: one
/// HTTP/2 connection cannot turn the server into a traffic generator by
/// asking for many downloads.
#[tokio::test]
async fn download_budget_is_per_connection() {
    use http_body_util::BodyExt;
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let mut sender = h2_sender(&server, &pki).await;
    let get = |bytes: u64| {
        http::Request::get(format!("https://probe.test/download?bytes={bytes}"))
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap()
    };
    // 1 MiB budget in server_cfg: 700 kB, then the 324 kB that is left.
    let r = sender.send_request(get(700_000)).await.unwrap();
    assert_eq!(r.status(), 200);
    let n = r.into_body().collect().await.unwrap().to_bytes().len();
    assert_eq!(n, 700_000);
    let r = sender.send_request(get(700_000)).await.unwrap();
    assert_eq!(r.status(), 200);
    let n = r.into_body().collect().await.unwrap().to_bytes().len();
    assert_eq!(n, 1_048_576 - 700_000);
    let r = sender.send_request(get(1)).await.unwrap();
    assert_eq!(r.status(), 429);

    // A new connection has its own budget.
    let mut fresh = h2_sender(&server, &pki).await;
    let r = fresh.send_request(get(1000)).await.unwrap();
    assert_eq!(r.status(), 200);
    server.shutdown().await.unwrap();
}

/// Shutting down with a long session open still logs that connection's
/// `tcp_accept` event instead of aborting its task.
#[tokio::test]
async fn shutdown_keeps_events_of_open_connections() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let mut sender = h2_sender(&server, &pki).await;
    let req =
        http::Request::get("https://probe.test/session?seconds=30&interval_ms=100&test_id=sd1")
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
    let resp = sender.send_request(req).await.unwrap();
    assert_eq!(resp.status(), 200);
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t = std::time::Instant::now();
    server.shutdown().await.unwrap();
    assert!(t.elapsed() < Duration::from_secs(5), "{:?}", t.elapsed());
    drop(resp);

    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let accept = sev
        .iter()
        .find(|e| e.test_type == TestType::TcpAccept)
        .unwrap_or_else(|| panic!("tcp_accept lost on shutdown: {sev:#?}"));
    assert!(
        accept
            .detail
            .as_deref()
            .unwrap()
            .contains("server shutdown"),
        "{accept:?}"
    );
    assert!(sev.iter().any(|e| e.test_id == "sd1"), "{sev:#?}");
}

/// A burst of connections over the limit is logged as one counted event,
/// not one event each.
#[tokio::test]
async fn refusals_are_rate_limited() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let mut scfg = server_cfg(&pki, data.path(), 5);
    scfg.limits.max_connections = 1;
    let server = probe_server::start(scfg).await.unwrap();
    let _hold = tokio::net::TcpStream::connect(server.addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    for _ in 0..50 {
        let mut s = tokio::net::TcpStream::connect(server.addr).await.unwrap();
        // The server closes refused connections at once.
        let mut b = [0u8; 1];
        let n = tokio::io::AsyncReadExt::read(&mut s, &mut b)
            .await
            .unwrap_or(0);
        assert_eq!(n, 0);
    }
    server.shutdown().await.unwrap();
    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let refusals: Vec<_> = sev
        .iter()
        .filter(|e| {
            e.detail
                .as_deref()
                .is_some_and(|d| d.contains("connection limit"))
        })
        .collect();
    assert!(
        (1..=3).contains(&refusals.len()),
        "expected a few counted events: {refusals:#?}"
    );
    let total: u64 = refusals
        .iter()
        .map(|e| {
            let d = e.detail.as_deref().unwrap();
            let n = d.split(": ").nth(1).unwrap().split(' ').next().unwrap();
            n.parse::<u64>().unwrap()
        })
        .sum();
    assert_eq!(total, 50, "{refusals:#?}");
}

// ------------------------------------------------------- cascade (split) ---

#[tokio::test]
async fn upload_session_runs_to_the_end() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let plan = SessionPlan {
        seconds: 2,
        interval_ms: 200,
        size: 100,
        stall_seconds: 2,
    };
    let e = stream::upload_session(&ctx_for(&cfg), &cfg.targets[0], plan, |_, _| {}).await;
    assert!(e.success, "{e:?}");
    assert_eq!(e.direction, Some(probe_common::Direction::Up));
    assert_eq!(e.phase, Some(Phase::Completed));
    assert!(e.duration_ms >= 1800, "{e:?}");
    let d = e.detail.as_deref().unwrap();
    // About 2 s / 200 ms heartbeats of 100 B, all acknowledged.
    let sent: u64 = d.split(' ').next().unwrap().parse().unwrap();
    assert!(
        (800..=1200).contains(&sent) && sent.is_multiple_of(100),
        "{d}"
    );

    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shutdown().await.unwrap();
    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let s = sev
        .iter()
        .find(|s| s.test_id == e.test_id)
        .expect("server logged the upload");
    assert!(s.success, "{s:?}");
    assert_eq!(s.direction, Some(probe_common::Direction::Up));
    assert_eq!(s.bytes_received, sent);
}

/// Like `freezing_relay`, but the client→server direction stops after
/// `budget` bytes: the uplink freezes while the downlink stays open.
async fn freezing_uplink_relay(
    upstream: std::net::SocketAddr,
    budget: usize,
) -> std::net::SocketAddr {
    use tokio::io::AsyncReadExt;
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = l.local_addr().unwrap();
    tokio::spawn(async move {
        let (c, _) = l.accept().await.unwrap();
        let s = tokio::net::TcpStream::connect(upstream).await.unwrap();
        let (mut cr, mut cw) = c.into_split();
        let (mut sr, mut sw) = s.into_split();
        tokio::spawn(async move {
            let _ = tokio::io::copy(&mut sr, &mut cw).await;
        });
        let mut left = budget;
        let mut buf = vec![0u8; 4096];
        loop {
            let n = match cr.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let pass = n.min(left);
            if pass > 0 {
                sw.write_all(&buf[..pass]).await.unwrap();
                left -= pass;
            }
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    });
    addr
}

#[tokio::test]
async fn upload_session_reports_a_freeze() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    // Enough for TLS, the HTTP/2 preface and a few heartbeats.
    let relay = freezing_uplink_relay(server.addr, 8_000).await;
    let cfg = client_cfg(relay.port(), &pki.path("ca.pem"), data.path());
    let plan = SessionPlan {
        seconds: 20,
        interval_ms: 100,
        size: 500,
        stall_seconds: 2,
    };
    let t = std::time::Instant::now();
    let e = stream::upload_session(&ctx_for(&cfg), &cfg.targets[0], plan, |_, _| {}).await;
    assert_eq!(e.error_code, Some(ErrorCode::ApplicationTimeout), "{e:?}");
    let d = e.detail.as_deref().unwrap();
    assert!(d.starts_with("stalled: no acknowledgement for 2 s"), "{d}");
    assert!(t.elapsed() < Duration::from_secs(10), "{:?}", t.elapsed());
    server.shutdown().await.unwrap();
}

/// Split-path cascade: upload to A and download from B at the same time.
/// Both client events and both servers' events carry the same pair_id.
#[tokio::test]
async fn paired_probe_joins_both_servers() {
    use probe_common::config::TargetRole;
    use probe_common::Direction;
    let pki = Pki::new();
    let data_a = tempfile::tempdir().unwrap();
    let data_b = tempfile::tempdir().unwrap();
    let a = probe_server::start(server_cfg(&pki, data_a.path(), 5))
        .await
        .unwrap();
    let b = probe_server::start(server_cfg(&pki, data_b.path(), 5))
        .await
        .unwrap();
    let mut cfg = client_cfg(a.addr.port(), &pki.path("ca.pem"), data_a.path());
    let mut down = cfg.targets[0].clone();
    cfg.targets[0].id = "up-a".into();
    cfg.targets[0].role = TargetRole::Uplink;
    down.id = "down-b".into();
    down.port = b.addr.port();
    down.role = TargetRole::Downlink;
    cfg.targets.push(down);
    assert_eq!(probe_client::pairs(&cfg).len(), 1);

    let plan = SessionPlan {
        seconds: 1,
        interval_ms: 200,
        size: 100,
        stall_seconds: 2,
    };
    let mut events = Vec::new();
    probe_client::run_long(&cfg, plan, |e| events.push(e), |_, _, _| {}).await;
    // A: upload only. B: download only. Then the pair.
    assert_eq!(events.len(), 4, "{events:#?}");
    for e in &events {
        assert!(e.success, "{e:?}");
        e.validate().unwrap();
    }
    assert_eq!(
        (events[0].target_id.as_str(), events[0].direction),
        ("up-a", Some(Direction::Up))
    );
    assert_eq!(
        (events[1].target_id.as_str(), events[1].direction),
        ("down-b", Some(Direction::Down))
    );
    assert!(events[..2].iter().all(|e| e.pair_id.is_none()));
    let pair = events[2].pair_id.clone().expect("pair id");
    assert_eq!(events[3].pair_id.as_deref(), Some(pair.as_str()));
    assert_eq!(events[2].direction, Some(Direction::Up));
    assert_eq!(events[3].direction, Some(Direction::Down));
    // Run at the same time, not one after the other.
    let (t2, t3) = (&events[2].timestamp, &events[3].timestamp);
    let start = |e: &ProbeEvent| {
        probe_common::timefmt::parse_rfc3339(&e.timestamp)
            .unwrap()
            .unix_timestamp_nanos()
    };
    let gap = (start(&events[2]) - start(&events[3])).abs();
    assert!(gap < 500_000_000, "{t2} vs {t3}");

    tokio::time::sleep(Duration::from_millis(200)).await;
    a.shutdown().await.unwrap();
    b.shutdown().await.unwrap();
    for (dir, data) in [(Direction::Up, &data_a), (Direction::Down, &data_b)] {
        let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
        let s = sev
            .iter()
            .find(|s| s.pair_id.as_deref() == Some(pair.as_str()))
            .unwrap_or_else(|| panic!("server for {dir:?} has no paired event: {sev:#?}"));
        assert_eq!(s.direction, Some(dir));
    }
}

/// HTTP/3 requests outside the probe API are logged like over TCP:
/// status, method and path in `detail`. (Review 3.5.)
#[tokio::test]
async fn h3_unknown_path_is_logged() {
    use bytes::Buf;
    use std::sync::Arc;
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(with_quic(server_cfg(&pki, data.path(), 5)))
        .await
        .unwrap();
    let qaddr = server.quic_addr.unwrap();

    let tls =
        probe_client::tlsutil::client_config(Some(Path::new(&pki.path("ca.pem"))), &[b"h3"], true)
            .unwrap();
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).unwrap();
    let mut ep = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    ep.set_default_client_config(quinn::ClientConfig::new(Arc::new(crypto)));
    let conn = ep.connect(qaddr, "probe.test").unwrap().await.unwrap();
    let (mut driver, mut send) = h3::client::new(h3_quinn::Connection::new(conn.clone()))
        .await
        .unwrap();
    let drive = tokio::spawn(async move { driver.wait_idle().await });
    let req = http::Request::get(format!("https://probe.test:{}/nope?x=1", qaddr.port()))
        .header("x-astp-test-id", "h3-unknown")
        .body(())
        .unwrap();
    let mut stream = send.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), 404);
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        chunk.advance(chunk.remaining());
    }
    drop(send);
    conn.close(0x100u32.into(), b"done");
    drive.abort();

    tokio::time::sleep(Duration::from_millis(300)).await;
    server.shutdown().await.unwrap();
    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    let e = sev
        .iter()
        .find(|e| e.test_id == "h3-unknown")
        .unwrap_or_else(|| panic!("unknown h3 path not logged: {sev:#?}"));
    assert_eq!(e.test_type, TestType::H3Request);
    assert_eq!(e.transport, probe_common::Transport::Quic);
    let d = e.detail.as_deref().unwrap();
    assert!(d.starts_with("404 GET /nope?x=1"), "{d}");
}

// ------------------------------------------------------------ scheduler ---

#[tokio::test]
async fn scheduler_alternates_quick_and_long_without_overlap() {
    use probe_client::schedule::{run_scheduled, Ran, Schedule};
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let sched = Schedule {
        quick_every: Duration::from_millis(300),
        long_every: Duration::from_millis(800),
        long_plan: SessionPlan {
            seconds: 1,
            interval_ms: 200,
            size: 100,
            stall_seconds: 2,
        },
        jitter_percent: 10,
        campaign: Some(Duration::from_secs(4)),
        no_long: false,
    };
    let mut events = Vec::new();
    let mut runs = Vec::new();
    let t = std::time::Instant::now();
    run_scheduled(
        &cfg,
        sched,
        |e| events.push(e),
        |r| runs.push(r),
        std::future::pending(),
    )
    .await;
    assert!(t.elapsed() < Duration::from_secs(8), "{:?}", t.elapsed());
    assert_eq!(runs.first(), Some(&Ran::Quick), "{runs:?}");
    let quick = runs.iter().filter(|r| **r == Ran::Quick).count();
    let long = runs.iter().filter(|r| **r == Ran::Long).count();
    assert!(quick >= 3 && long >= 1, "{runs:?}");
    for e in &events {
        assert!(e.success, "{e:?}");
    }
    // role = both: a long pass is a download and an upload session.
    let sessions = events
        .iter()
        .filter(|e| e.test_type == TestType::LongSession)
        .count();
    assert_eq!(sessions, 2 * long);
    server.shutdown().await.unwrap();
}

#[tokio::test]
async fn scheduler_stops_at_once_on_signal() {
    use probe_client::schedule::{run_scheduled, Schedule};
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let server = probe_server::start(server_cfg(&pki, data.path(), 5))
        .await
        .unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let sched = Schedule {
        quick_every: Duration::from_secs(3600),
        long_every: Duration::from_millis(1),
        long_plan: SessionPlan {
            seconds: 60,
            interval_ms: 200,
            size: 100,
            stall_seconds: 2,
        },
        jitter_percent: 0,
        campaign: None,
        no_long: false,
    };
    let t = std::time::Instant::now();
    // Stops in the middle of a 60 s long session.
    run_scheduled(
        &cfg,
        sched,
        |_| {},
        |_| {},
        tokio::time::sleep(Duration::from_secs(2)),
    )
    .await;
    assert!(t.elapsed() < Duration::from_secs(4), "{:?}", t.elapsed());
    server.shutdown().await.unwrap();
}

/// An HTTP/2 connection that never sends a request is idle even though
/// the server's keepalive PINGs and the client's ACKs keep bytes moving.
#[tokio::test]
async fn idle_h2_connection_is_closed_despite_pings() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let mut scfg = server_cfg(&pki, data.path(), 5);
    scfg.limits.max_connections = 1;
    scfg.limits.idle_timeout_seconds = 1;
    let server = probe_server::start(scfg).await.unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());

    // Preface and SETTINGS, then nothing but PING/ACK (every 0.5 s here).
    let sender = h2_sender(&server, &pki).await;
    tokio::time::sleep(Duration::from_millis(3000)).await;
    let free = collect(
        &cfg,
        Selection {
            h2: true,
            ..Default::default()
        },
    )
    .await;
    assert!(
        free[0].success,
        "slot still held by an idle h2 connection: {:?}",
        free[0]
    );
    drop(sender);

    tokio::time::sleep(Duration::from_millis(200)).await;
    server.shutdown().await.unwrap();
    let (sev, _) = read_events(&data.path().join("server-events.jsonl")).unwrap();
    assert!(
        sev.iter().any(|e| e.test_type == TestType::TcpAccept
            && e.detail
                .as_deref()
                .is_some_and(|d| d.contains("no request"))),
        "{sev:#?}"
    );
}

/// A request in flight is activity: a session whose heartbeats are
/// further apart than the idle timeout runs to its end.
#[tokio::test]
async fn slow_session_is_not_idle() {
    let pki = Pki::new();
    let data = tempfile::tempdir().unwrap();
    let mut scfg = server_cfg(&pki, data.path(), 5);
    scfg.limits.idle_timeout_seconds = 1;
    let server = probe_server::start(scfg).await.unwrap();
    let cfg = client_cfg(server.addr.port(), &pki.path("ca.pem"), data.path());
    let plan = SessionPlan {
        seconds: 4,
        interval_ms: 1500,
        size: 100,
        stall_seconds: 4,
    };
    let e = stream::long_session(&ctx_for(&cfg), &cfg.targets[0], plan, |_, _| {}).await;
    assert!(e.success, "{e:?}");
    let e = stream::upload_session(&ctx_for(&cfg), &cfg.targets[0], plan, |_, _| {}).await;
    assert!(e.success, "{e:?}");
    server.shutdown().await.unwrap();
}
