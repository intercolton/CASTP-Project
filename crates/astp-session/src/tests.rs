use super::*;
use astp_frame::{encode_camouflage, Frame, FrameBody, FrameReader};
use std::net::Ipv4Addr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, DuplexStream, ReadHalf, WriteHalf};
use tokio::sync::mpsc;

type Rd = FrameReader<ReadHalf<DuplexStream>>;
type Wr = WriteHalf<DuplexStream>;

fn pipe(buf: usize) -> ((Rd, Wr), (Rd, Wr)) {
    let (a, b) = tokio::io::duplex(buf);
    let (ar, aw) = tokio::io::split(a);
    let (br, bw) = tokio::io::split(b);
    ((FrameReader::new(ar), aw), (FrameReader::new(br), bw))
}

/// A valid IPv4 packet of `len` bytes (header plus zero payload).
fn ipv4(len: usize, tag: u8) -> Packet {
    let mut p = vec![0u8; len];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[19] = tag;
    p
}

fn params() -> SessionParams {
    SessionParams {
        addr4: Some((Ipv4Addr::new(10, 77, 0, 2), 24)),
        keepalive: Duration::from_millis(100),
        idle_timeout: Duration::from_secs(5),
        session_id: [9; 16],
        routes: vec![Route::V4 {
            dest: Ipv4Addr::UNSPECIFIED,
            prefix: 0,
            include: true,
        }],
        ..SessionParams::default()
    }
}

struct Side {
    to_local: mpsc::Receiver<Packet>,
    from_local: mpsc::Sender<Packet>,
    link: Option<Link>,
}

fn side() -> Side {
    let (to_tx, to_rx) = mpsc::channel(64);
    let (from_tx, from_rx) = mpsc::channel(64);
    Side {
        to_local: to_rx,
        from_local: from_tx,
        link: Some(Link {
            to_local: to_tx,
            from_local: from_rx,
            events: None,
        }),
    }
}

#[test]
fn params_round_trip() {
    let p = params();
    assert_eq!(SessionParams::from_tlvs(&p.to_tlvs()).unwrap(), p);
    let mut bad = p.to_tlvs();
    bad.push(astp_frame::Tlv::Keepalive(0));
    assert!(SessionParams::from_tlvs(&bad).is_err());
}

#[tokio::test]
async fn handshake_then_packets_both_ways_then_close() {
    let ((mut sr, mut sw), (mut cr, mut cw)) = pipe(64 * 1024);
    let p = params();
    let server = async { server_handshake(&mut sr, &mut sw, &p, Duration::from_secs(2)).await };
    let client = async {
        client_handshake(&mut cr, &mut cw, Duration::from_secs(2), |got| {
            assert_eq!(got.addr4, Some((Ipv4Addr::new(10, 77, 0, 2), 24)));
            Ok(())
        })
        .await
    };
    let (s, c) = tokio::join!(server, client);
    s.unwrap();
    let cp = c.unwrap();
    assert_eq!(cp, p);

    let mut srv = side();
    let mut cli = side();
    let sstats = Arc::new(Stats::default());
    let cstats = Arc::new(Stats::default());
    let srun = run(
        Role::Server,
        sr,
        sw,
        &p,
        srv.link.take().unwrap(),
        sstats.clone(),
        std::future::pending(),
    );
    let crun = run(
        Role::Client,
        cr,
        cw,
        &cp,
        cli.link.take().unwrap(),
        cstats.clone(),
        std::future::pending(),
    );
    let traffic = async {
        for i in 0..10u8 {
            cli.from_local.send(ipv4(100, i)).await.unwrap();
            srv.from_local.send(ipv4(200, i)).await.unwrap();
        }
        for i in 0..10u8 {
            assert_eq!(srv.to_local.recv().await.unwrap(), ipv4(100, i));
            assert_eq!(cli.to_local.recv().await.unwrap(), ipv4(200, i));
        }
        // Not an IP packet: dropped, not sent.
        cli.from_local.send(vec![0x10, 1, 2]).await.unwrap();
        // Idle past several keepalive periods: PINGs keep both alive.
        tokio::time::sleep(Duration::from_millis(400)).await;
        drop(cli.from_local);
    };
    let (s, c, ()) = tokio::join!(srun, crun, traffic);
    assert!(matches!(c, EndReason::LocalClosed), "{c:?}");
    assert!(
        matches!(s, EndReason::PeerDisconnect { code: 0, .. }),
        "{s:?}"
    );
    assert_eq!(
        cstats
            .sent_packets
            .load(std::sync::atomic::Ordering::Relaxed),
        10
    );
    assert_eq!(
        cstats
            .dropped_invalid
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        sstats
            .received_bytes
            .load(std::sync::atomic::Ordering::Relaxed),
        1000
    );
}

#[tokio::test]
async fn client_can_refuse_the_config() {
    let ((mut sr, mut sw), (mut cr, mut cw)) = pipe(64 * 1024);
    let p = params();
    let (s, c) = tokio::join!(
        server_handshake(&mut sr, &mut sw, &p, Duration::from_secs(2)),
        client_handshake(&mut cr, &mut cw, Duration::from_secs(2), |_| Err(
            "no".into()
        )),
    );
    assert!(matches!(s, Err(SessionError::Rejected(_))), "{s:?}");
    assert!(matches!(c, Err(SessionError::Rejected(_))), "{c:?}");
}

#[tokio::test]
async fn silent_peer_hits_the_idle_timeout() {
    let ((sr, sw), (_cr, _cw)) = pipe(64 * 1024);
    let p = SessionParams {
        keepalive: Duration::from_secs(60),
        idle_timeout: Duration::from_millis(200),
        ..params()
    };
    let mut srv = side();
    let t = std::time::Instant::now();
    let end = run(
        Role::Server,
        sr,
        sw,
        &p,
        srv.link.take().unwrap(),
        Arc::new(Stats::default()),
        std::future::pending(),
    )
    .await;
    assert!(matches!(end, EndReason::IdleTimeout), "{end:?}");
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[tokio::test]
async fn stop_sends_disconnect_with_its_code() {
    let ((sr, sw), (mut cr, _cw)) = pipe(64 * 1024);
    let mut srv = side();
    let p = params();
    let srun = run(
        Role::Server,
        sr,
        sw,
        &p,
        srv.link.take().unwrap(),
        Arc::new(Stats::default()),
        async { code::SERVER_SHUTDOWN },
    );
    let end = srun.await;
    assert!(matches!(end, EndReason::LocalStop(4)), "{end:?}");
    let f = cr.read_frame().await.unwrap().unwrap();
    assert!(
        matches!(f.body, FrameBody::Disconnect { code: 4, .. }),
        "{f:?}"
    );
}

async fn raw(w: &mut Wr, body: FrameBody) {
    let b = encode_camouflage(&Frame {
        key_epoch: None,
        body,
    })
    .unwrap();
    w.write_all(&b).await.unwrap();
}

#[tokio::test]
async fn frames_of_the_wrong_side_are_protocol_errors() {
    for body in [
        FrameBody::Config(params().to_config(1)),
        FrameBody::RouteUpdate(astp_frame::RouteUpdate { tlvs: vec![] }),
    ] {
        let ((sr, sw), (_cr, mut cw)) = pipe(64 * 1024);
        let mut srv = side();
        raw(&mut cw, body).await;
        let end = run(
            Role::Server,
            sr,
            sw,
            &params(),
            srv.link.take().unwrap(),
            Arc::new(Stats::default()),
            std::future::pending(),
        )
        .await;
        assert!(
            matches!(end, EndReason::Failed(SessionError::Protocol(_))),
            "{end:?}"
        );
    }
}

/// A peer that keeps sending past the credit it was given is cut off.
/// The server's write side is stuck (the peer does not read), so its
/// second WINDOW cannot go out and the peer's credit is 2 MiB at most.
#[tokio::test]
async fn sending_past_the_credit_is_a_protocol_error() {
    let ((sr, sw), (_cr, mut cw)) = pipe(100);
    let mut srv = side();
    let p = SessionParams {
        keepalive: Duration::from_secs(60),
        ..params()
    };
    let srun = run(
        Role::Server,
        sr,
        sw,
        &p,
        srv.link.take().unwrap(),
        Arc::new(Stats::default()),
        std::future::pending(),
    );
    let flood = async {
        for i in 0..40u8 {
            let pkt = astp_frame::Ipv4Packet::new(ipv4(60_000, i)).unwrap();
            let b = encode_camouflage(&Frame {
                key_epoch: None,
                body: FrameBody::TunIpv4(pkt),
            })
            .unwrap();
            if cw.write_all(&b).await.is_err() {
                return;
            }
        }
    };
    let (end, ()) = tokio::join!(srun, flood);
    match end {
        EndReason::Failed(SessionError::Protocol(m)) => assert!(m.contains("WINDOW"), "{m}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn client_reports_later_config_and_routes() {
    let ((sr, sw), (cr, cw)) = pipe(64 * 1024);
    let _ = (sr,);
    let mut sw = sw;
    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel();
    let mut cli = side();
    let mut link = cli.link.take().unwrap();
    link.events = Some(ev_tx);
    let p = params();
    let crun = run(
        Role::Client,
        cr,
        cw,
        &p,
        link,
        Arc::new(Stats::default()),
        std::future::pending(),
    );
    let server = async {
        raw(&mut sw, FrameBody::Config(params().to_config(7))).await;
        raw(
            &mut sw,
            FrameBody::RouteUpdate(astp_frame::RouteUpdate {
                tlvs: route_tlvs(&[Route::V4 {
                    dest: Ipv4Addr::new(192, 0, 2, 0),
                    prefix: 24,
                    include: false,
                }]),
            }),
        )
        .await;
        assert!(matches!(ev_rx.recv().await, Some(Event::Config(_))));
        assert!(matches!(ev_rx.recv().await, Some(Event::Routes(r)) if r.len() == 1));
        raw(
            &mut sw,
            FrameBody::Disconnect {
                code: 0,
                reason: "bye".into(),
            },
        )
        .await;
    };
    let (end, ()) = tokio::join!(crun, server);
    assert!(
        matches!(end, EndReason::PeerDisconnect { code: 0, ref reason } if reason == "bye"),
        "{end:?}"
    );
}
