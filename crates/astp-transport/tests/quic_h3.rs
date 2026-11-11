//! QUIC handshake, ALPN, timeouts, channel binding, and the HTTP/3 stub.

#[path = "common/support.rs"]
mod support;

use std::sync::Arc;
use std::time::Duration;

use astp_crypto::{AuthError, Authenticator, ClientId, StaticTokenAuthenticator};
use astp_transport::{connect, Http3Client, Http3Options, Http3Server, QuicServer, TransportError};
use bytes::Bytes;
use support::{bind, fixture, half_open, test_limits, tls_h2, tls_quic, wait_pending};

#[tokio::test]
async fn quic_h3_get_is_404() {
    let limits = test_limits();
    let (fixture, mut server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let options = Http3Options::from_limits(&limits);
    let accept = tokio::spawn(async move {
        let accepted = server.accept().await.expect("accept");
        assert_eq!(accepted.binding.as_bytes().len(), 32);
        Http3Server::start(accepted.conn, options)
            .await
            .expect("h3 server")
    });
    let quic = connect(tls_quic(&fixture), addr, limits.clone())
        .await
        .expect("connect");
    let http = accept.await.expect("server task");
    let mut client = Http3Client::start(
        quic.connection().clone(),
        Http3Options::from_limits(&limits),
    )
    .await
    .expect("h3 client");
    let response = client.get("/").await.expect("get");
    assert_eq!(response.status, http::StatusCode::NOT_FOUND);
    assert!(response.body.is_empty());
    client.close().await;
    http.close().await;
}

#[tokio::test]
async fn h2_over_quic_is_closed_without_a_banner() {
    let limits = test_limits();
    let (fixture, mut server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let driver = tokio::spawn(async move { while server.accept().await.is_ok() {} });
    let result = connect(tls_h2(&fixture), addr, limits).await;
    match result {
        Ok(quic) => {
            let closed = tokio::time::timeout(Duration::from_secs(2), quic.connection().closed())
                .await
                .expect("close timed out");
            assert_empty_reason(&closed);
        }
        Err(TransportError::Connection { detail }) => {
            assert!(
                !detail.contains("banner") && !detail.contains("ASTP"),
                "close text: {detail}"
            );
        }
        Err(err) => panic!("unexpected connect error: {err}"),
    }
    driver.abort();
}

#[tokio::test]
async fn handshake_timeout_frees_the_slot() {
    let mut limits = test_limits();
    limits.handshake_timeout = Duration::from_millis(500);
    limits.max_pending_handshakes = 1;
    let (fixture, server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let tls = tls_quic(&fixture);
    let _half = half_open(addr, &tls).await;
    wait_pending(&server, 1).await;

    let mut blocked = limits.clone();
    blocked.handshake_timeout = Duration::from_secs(2);
    let refused = tokio::time::timeout(
        Duration::from_millis(400),
        connect(tls_quic(&fixture), addr, blocked),
    )
    .await;
    assert!(
        refused.is_ok(),
        "a full slot did not refuse the next client"
    );
    assert!(
        refused.expect("timeout").is_err(),
        "client was accepted while the slot was held"
    );

    tokio::time::sleep(Duration::from_millis(700)).await;
    assert_eq!(server.pending_handshakes(), 0);
    let quic = connect(tls_quic(&fixture), addr, limits)
        .await
        .expect("server did not accept a client after the timeout");
    assert_eq!(quic.server_name(), "astp.test");
}

#[tokio::test]
async fn garbage_datagrams_do_not_kill_the_server() {
    let limits = test_limits();
    let (fixture, server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("udp");
    for len in [0usize, 1, 1200, 1500] {
        let buf = vec![0xA5u8; len];
        socket.send_to(&buf, addr).await.expect("send garbage");
    }
    let mut state = 0x1234_5678u64;
    for _ in 0..32 {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        let len = (state % 1400) as usize;
        let buf = vec![(state & 0xff) as u8; len];
        socket.send_to(&buf, addr).await.expect("send random");
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let quic = connect(tls_quic(&fixture), addr, limits)
        .await
        .expect("server died after garbage");
    assert_eq!(quic.binding().as_bytes().len(), 32);
    drop(server);
}

#[tokio::test]
async fn fifth_pending_handshake_is_refused_and_slots_return() {
    let mut limits = test_limits();
    limits.handshake_timeout = Duration::from_millis(500);
    limits.max_pending_handshakes = 4;
    let (fixture, server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let tls = tls_quic(&fixture);
    let _held = [
        half_open(addr, &tls).await,
        half_open(addr, &tls).await,
        half_open(addr, &tls).await,
        half_open(addr, &tls).await,
    ];
    wait_pending(&server, 4).await;

    let mut probe_limits = limits.clone();
    probe_limits.handshake_timeout = Duration::from_secs(2);
    let fifth = tokio::time::timeout(
        Duration::from_millis(400),
        connect(tls_quic(&fixture), addr, probe_limits),
    )
    .await;
    assert!(fifth.is_ok(), "fifth client hung instead of being refused");
    assert!(
        fifth.expect("elapsed").is_err(),
        "fifth client was accepted"
    );

    tokio::time::sleep(Duration::from_millis(800)).await;
    assert_eq!(server.pending_handshakes(), 0);
    connect(tls_quic(&fixture), addr, limits)
        .await
        .expect("slots did not return");
}

#[tokio::test]
async fn channel_binding_matches_and_rejects_a_replay() {
    let limits = test_limits();
    let (fixture, mut server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let collect = tokio::spawn(async move {
        let first = server.accept().await.expect("first");
        let second = server.accept().await.expect("second");
        (first.binding, second.binding)
    });
    let client_a = connect(tls_quic(&fixture), addr, limits.clone())
        .await
        .expect("client a");
    let client_b = connect(tls_quic(&fixture), addr, limits)
        .await
        .expect("client b");
    let (server_a, server_b) = collect.await.expect("server");
    assert_eq!(client_a.binding(), &server_a);
    assert_eq!(client_b.binding(), &server_b);
    assert_ne!(client_a.binding(), client_b.binding());

    let auth = StaticTokenAuthenticator::new(b"test-secret", ClientId::new(b"client-a"))
        .expect("authenticator");
    let credential = auth.credential(client_a.binding()).expect("credential");
    assert_eq!(
        auth.verify(&server_a, &credential)
            .expect("same connection")
            .as_bytes(),
        b"client-a"
    );
    assert_eq!(
        auth.verify(&server_b, &credential).expect_err("replay"),
        AuthError::Rejected
    );
}

#[tokio::test]
async fn bad_frame_on_post_closes_the_connection() {
    let mut limits = test_limits();
    limits.frame_read_timeout = Duration::from_millis(500);
    let (fixture, mut server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let options = Http3Options::from_limits(&limits);
    let reader = tokio::spawn(async move {
        let accepted = server.accept().await.expect("accept");
        let mut http = Http3Server::start(accepted.conn.clone(), options)
            .await
            .expect("h3");
        let mut tunnel = http.accept_tunnel().await.expect("tunnel");
        let err = tunnel
            .read_frame()
            .await
            .expect_err("bad frame was accepted");
        assert!(matches!(err, TransportError::Frame(_)));
        let closed = tokio::time::timeout(Duration::from_secs(2), accepted.conn.closed())
            .await
            .expect("connection stayed up");
        assert_empty_reason(&closed);
    });
    let quic = connect(tls_quic(&fixture), addr, limits.clone())
        .await
        .expect("connect");
    let mut client = Http3Client::start(
        quic.connection().clone(),
        Http3Options::from_limits(&limits),
    )
    .await
    .expect("h3 client");
    let mut tunnel = client.open_tunnel().await.expect("tunnel");
    // Version 0x99, length 0. Length is legal, so the reader reports the version.
    tunnel
        .write_body(Bytes::from_static(&[0x99, 0, 0, 0, 0, 0, 0, 0]))
        .await
        .expect("write");
    reader.await.expect("server task");
    let closed = tokio::time::timeout(Duration::from_secs(2), quic.connection().closed())
        .await
        .expect("client connection stayed up");
    assert_empty_reason(&closed);
}

#[tokio::test]
async fn stalled_frame_read_times_out_and_closes() {
    let mut limits = test_limits();
    limits.frame_read_timeout = Duration::from_millis(200);
    let (fixture, mut server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let options = Http3Options::from_limits(&limits);
    let reader = tokio::spawn(async move {
        let accepted = server.accept().await.expect("accept");
        let mut http = Http3Server::start(accepted.conn.clone(), options)
            .await
            .expect("h3");
        let mut tunnel = http.accept_tunnel().await.expect("tunnel");
        let err = tunnel.read_frame().await.expect_err("stall was accepted");
        assert!(matches!(err, TransportError::FrameReadTimeout));
        let closed = tokio::time::timeout(Duration::from_secs(2), accepted.conn.closed())
            .await
            .expect("connection stayed up");
        assert_empty_reason(&closed);
    });
    let quic = connect(tls_quic(&fixture), addr, limits.clone())
        .await
        .expect("connect");
    let mut client = Http3Client::start(
        quic.connection().clone(),
        Http3Options::from_limits(&limits),
    )
    .await
    .expect("h3 client");
    let mut tunnel = client.open_tunnel().await.expect("tunnel");
    tunnel
        .write_body(Bytes::from_static(&[0x01, 0, 0, 0]))
        .await
        .expect("partial header");
    reader.await.expect("server task");
}

#[tokio::test]
async fn zero_rtt_and_half_rtt_configs_are_rejected() {
    let early = fixture();
    let mut config = Arc::try_unwrap(early.server_config).expect("unique config");
    config.max_early_data_size = u32::MAX;
    let err = QuicServer::bind(
        "127.0.0.1:0".parse().expect("addr"),
        Arc::new(config),
        test_limits(),
    )
    .expect_err("0-rtt");
    assert!(matches!(err, TransportError::ZeroRttEnabled));

    let half = fixture();
    let mut config = Arc::try_unwrap(half.server_config).expect("unique config");
    config.send_half_rtt_data = true;
    let err = QuicServer::bind(
        "127.0.0.1:0".parse().expect("addr"),
        Arc::new(config),
        test_limits(),
    )
    .expect_err("half-rtt");
    assert!(matches!(err, TransportError::HalfRttEnabled));
}

fn assert_empty_reason(err: &quinn::ConnectionError) {
    match err {
        quinn::ConnectionError::ApplicationClosed(close) => {
            assert!(close.reason.is_empty(), "banner bytes: {:?}", close.reason);
        }
        quinn::ConnectionError::ConnectionClosed(close) => {
            assert!(close.reason.is_empty(), "banner bytes: {:?}", close.reason);
        }
        // The side that called `close` observes this. The reason it sent is empty.
        quinn::ConnectionError::LocallyClosed => {}
        other => panic!("expected an empty close, got {other}"),
    }
}
