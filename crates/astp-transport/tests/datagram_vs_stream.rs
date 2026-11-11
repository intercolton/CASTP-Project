//! Datagram versus stream on one lossy loopback.
//!
//! The CI run is 1000 frames at 0% and 3% loss. The full stand (10 000 frames,
//! 0/1/3%, 2000 frames/s) is `datagram_vs_stream_full` and is `#[ignore]`.
//! Both write JSONL. Point `ASTP_DATAGRAM_JSONL` at the output file.

#[path = "common/support.rs"]
mod support;

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use astp_frame::{encode, Frame, FrameBody};
use astp_transport::{connect, Http3Client, Http3Options, Http3Server, QuicServer, TunnelInput};
use astp_types::{FRAME_HEADER_LEN, MAX_DATAGRAM_PAYLOAD};
use bytes::Bytes;
use serde_json::{json, Value};
use support::{bind, test_limits, tls_quic};
use tokio::net::UdpSocket;

const LOSS_SEED: u64 = 0x4153_5450_4d31_0004;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mode {
    Datagram,
    Stream,
}

impl Mode {
    fn label(self) -> &'static str {
        match self {
            Self::Datagram => "D",
            Self::Stream => "S",
        }
    }
}

#[tokio::test]
async fn datagram_vs_stream_ci() {
    let path = jsonl_path("datagram_vs_stream.jsonl");
    let mut lines = Vec::new();
    let stopped = stream_close_stops_datagrams().await;
    lines.push(json!({
        "event": "stream_close",
        "stopped": stopped,
    }));
    assert!(
        stopped,
        "closing the request stream did not stop its datagrams"
    );
    for loss in [0u8, 3] {
        for mode in [Mode::Datagram, Mode::Stream] {
            let row = run_scenario(mode, loss, 1_000, 2_000.0).await;
            lines.push(row);
        }
    }
    write_jsonl(&path, &lines);
    assert_delivery(&lines);
}

#[tokio::test]
#[ignore]
async fn datagram_vs_stream_full() {
    let path = jsonl_path("datagram_vs_stream-full.jsonl");
    let mut lines = Vec::new();
    let stopped = stream_close_stops_datagrams().await;
    lines.push(json!({
        "event": "stream_close",
        "stopped": stopped,
    }));
    for loss in [0u8, 1, 3] {
        for mode in [Mode::Datagram, Mode::Stream] {
            lines.push(run_scenario(mode, loss, 10_000, 2_000.0).await);
        }
    }
    write_jsonl(&path, &lines);
    assert_delivery(&lines);
}

fn assert_delivery(lines: &[Value]) {
    for row in lines {
        if row.get("event").and_then(|v| v.as_str()) == Some("stream_close") {
            continue;
        }
        let mode = row["mode"].as_str().unwrap_or("");
        let loss = row["loss_percent"].as_u64().unwrap_or(0);
        let frames = row["frames"].as_u64().unwrap_or(0);
        let delivered = row["delivered"].as_u64().unwrap_or(0);
        let duplicates = row["duplicates"].as_u64().unwrap_or(1);
        let mismatches = row["mismatches"].as_u64().unwrap_or(1);
        assert_eq!(duplicates, 0, "{mode} loss {loss}: duplicates");
        assert_eq!(mismatches, 0, "{mode} loss {loss}: mismatches");
        if loss == 0 {
            assert_eq!(delivered, frames, "{mode} at 0% loss");
        } else {
            // Two-way UDP loss lands below (100 - loss - 0.5)%. That is
            // recorded for the choice rule; CI only checks the path still moves frames.
            assert!(
                delivered * 2 >= frames,
                "{mode} loss {loss}: delivered {delivered} of {frames}"
            );
        }
    }
}

async fn run_scenario(mode: Mode, loss_percent: u8, frames: usize, rate: f64) -> Value {
    let mut limits = test_limits();
    limits.handshake_timeout = Duration::from_secs(8);
    limits.frame_read_timeout = Duration::from_secs(30);
    let (fixture, server) = bind(limits.clone()).await;
    let server_addr = server.local_addr().expect("addr");
    let proxy = LossProxy::start(server_addr, loss_percent).await;
    let options = Http3Options::from_limits(&limits);
    let _closed = echo(server, options.clone());
    let quic = connect(tls_quic(&fixture), proxy.client_addr, limits.clone())
        .await
        .unwrap_or_else(|err| panic!("{mode:?} loss {loss_percent}: connect: {err}"));
    let max_before = sample_datagram_size(quic.connection()).await;
    let mut http = Http3Client::start(quic.connection().clone(), options)
        .await
        .unwrap_or_else(|err| panic!("h3 client: {err}"));
    let mut tunnel = http
        .open_tunnel()
        .await
        .unwrap_or_else(|err| panic!("tunnel: {err}"));
    let overhead = FRAME_HEADER_LEN + 1;
    let fit = max_before.unwrap_or(0).saturating_sub(overhead);
    let large = fit.clamp(28, MAX_DATAGRAM_PAYLOAD);
    let payloads = [64usize, 512.min(large), large];
    let stats = transfer(&mut tunnel, mode, frames, rate, payloads).await;
    let max_after = sample_datagram_size(quic.connection()).await;
    let max_datagram_size = max_before.max(max_after);
    let payload_1200_fits =
        max_datagram_size.unwrap_or(0) >= FRAME_HEADER_LEN + 1 + MAX_DATAGRAM_PAYLOAD;
    drop(tunnel);
    http.close().await;
    json!({
        "mode": mode.label(),
        "loss_percent": loss_percent,
        "frames": frames,
        "rate_per_s": rate,
        "delivered": stats.delivered,
        "duplicates": stats.duplicates,
        "mismatches": stats.mismatches,
        "p50_us": stats.p50_us,
        "p99_us": stats.p99_us,
        "max_us": stats.max_us,
        "max_datagram_size": max_datagram_size,
        "max_single_datagram_payload": large,
        "payload_1200_fits": payload_1200_fits,
        "payload_1200_sent": stats.sent_1200,
        "payload_1200_delivered": stats.delivered_1200,
        "payloads": payloads,
        "stream_id": stats.stream_id,
    })
}

struct Stats {
    delivered: usize,
    duplicates: usize,
    mismatches: usize,
    p50_us: u128,
    p99_us: u128,
    max_us: u128,
    sent_1200: usize,
    delivered_1200: usize,
    stream_id: u64,
}

async fn transfer(
    tunnel: &mut astp_transport::ClientTunnel,
    mode: Mode,
    frames: usize,
    rate: f64,
    payloads: [usize; 3],
) -> Stats {
    let gap = Duration::from_secs_f64(1.0 / rate);
    let mut next = tokio::time::Instant::now();
    let mut sent = 0usize;
    let mut wire = HashMap::<u64, Vec<u8>>::new();
    let mut sent_at = HashMap::<u64, Instant>::new();
    let mut latency = Vec::new();
    let mut seen = HashMap::<u64, usize>::new();
    let mut mismatches = 0usize;
    let mut delivered_1200 = 0usize;
    let mut sent_1200 = 0usize;
    let idle = Duration::from_secs(20);
    loop {
        let sending = sent < frames;
        tokio::select! {
            biased;
            _ = tokio::time::sleep_until(next), if sending => {
                let seq = sent as u64;
                let len = payloads[sent % 3];
                if len == MAX_DATAGRAM_PAYLOAD {
                    sent_1200 += 1;
                }
                let frame = ipv4_frame(len, seq);
                let bytes = encode(&frame, None).expect("encode");
                wire.insert(seq, bytes.clone());
                sent_at.insert(seq, Instant::now());
                match mode {
                    Mode::Stream => tunnel.write_frame(&frame).await.expect("write frame"),
                    Mode::Datagram => tunnel
                        .send_datagram(Bytes::from(bytes))
                        .unwrap_or_else(|err| panic!("datagram {seq} ({len} bytes): {err}")),
                }
                sent += 1;
                next += gap;
                if sent == frames && mode == Mode::Stream {
                    tunnel.finish().await.expect("finish request");
                }
            }
            received = recv_payload(tunnel, mode) => {
                match received {
                    Some(bytes) => {
                        if note_echo(&bytes, &wire, &sent_at, &mut seen, &mut latency, &mut mismatches, &mut delivered_1200)
                            && seen.len() == frames
                            && mismatches == 0
                        {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(idle), if sent == frames => break,
        }
    }
    latency.sort_unstable();
    Stats {
        delivered: seen.len(),
        duplicates: seen.values().filter(|n| **n > 1).map(|n| *n - 1).sum(),
        mismatches,
        p50_us: percentile(&latency, 50.0),
        p99_us: percentile(&latency, 99.0),
        max_us: latency.last().copied().unwrap_or(0),
        sent_1200,
        delivered_1200,
        stream_id: tunnel.stream_id(),
    }
}

fn note_echo(
    bytes: &[u8],
    wire: &HashMap<u64, Vec<u8>>,
    sent_at: &HashMap<u64, Instant>,
    seen: &mut HashMap<u64, usize>,
    latency: &mut Vec<u128>,
    mismatches: &mut usize,
    delivered_1200: &mut usize,
) -> bool {
    let seq = match seq_of(bytes) {
        Some(seq) => seq,
        None => {
            *mismatches += 1;
            return false;
        }
    };
    let count = seen.entry(seq).or_insert(0);
    *count += 1;
    if *count > 1 {
        return false;
    }
    match wire.get(&seq) {
        Some(expected) if expected.as_slice() == bytes => {
            if let Some(start) = sent_at.get(&seq) {
                latency.push(start.elapsed().as_micros());
            }
            if expected.len() == FRAME_HEADER_LEN + MAX_DATAGRAM_PAYLOAD {
                *delivered_1200 += 1;
            }
            true
        }
        _ => {
            *mismatches += 1;
            false
        }
    }
}

async fn recv_payload(tunnel: &mut astp_transport::ClientTunnel, mode: Mode) -> Option<Vec<u8>> {
    match mode {
        Mode::Datagram => tunnel.recv_datagram().await.ok().map(|b| b.to_vec()),
        Mode::Stream => match tunnel.read_frame().await.ok()? {
            Some(frame) => encode(&frame, None).ok(),
            None => None,
        },
    }
}

fn seq_of(bytes: &[u8]) -> Option<u64> {
    let frame = astp_frame::decode(bytes).ok()?;
    let FrameBody::TunIpv4(packet) = frame.body else {
        return None;
    };
    let raw = packet.as_bytes();
    raw.get(20..28)
        .and_then(|slice| slice.try_into().ok())
        .map(u64::from_be_bytes)
}

fn ipv4_frame(len: usize, seq: u64) -> Frame {
    let mut packet = vec![0u8; len];
    packet[0] = 0x45;
    let total = u16::try_from(len).expect("payload fits u16");
    packet[2] = (total >> 8) as u8;
    packet[3] = (total & 0xff) as u8;
    packet[8] = 64;
    packet[9] = 17;
    packet[20..28].copy_from_slice(&seq.to_be_bytes());
    Frame {
        key_epoch: None,
        body: FrameBody::TunIpv4(astp_frame::Ipv4Packet::new(packet).expect("ipv4")),
    }
}

fn percentile(sorted: &[u128], percent: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let rank = ((percent / 100.0) * sorted.len() as f64).ceil() as usize;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

async fn sample_datagram_size(conn: &quinn::Connection) -> Option<usize> {
    let start = Instant::now();
    let mut best = conn.max_datagram_size();
    while start.elapsed() < Duration::from_millis(400) {
        tokio::time::sleep(Duration::from_millis(20)).await;
        if let Some(size) = conn.max_datagram_size() {
            best = Some(best.map_or(size, |prev| prev.max(size)));
        }
    }
    best
}

async fn stream_close_stops_datagrams() -> bool {
    let limits = test_limits();
    let (fixture, server) = bind(limits.clone()).await;
    let addr = server.local_addr().expect("addr");
    let options = Http3Options::from_limits(&limits);
    let closed = echo(server, options.clone());
    let quic = connect(tls_quic(&fixture), addr, limits)
        .await
        .expect("connect");
    let mut http = Http3Client::start(quic.connection().clone(), options)
        .await
        .expect("h3");
    let mut tunnel = http.open_tunnel().await.expect("tunnel");
    assert_eq!(
        tunnel.stream_id() % 4,
        0,
        "request stream is not divisible by 4"
    );
    let frame = ipv4_frame(64, 1);
    let bytes = encode(&frame, None).expect("encode");
    tunnel
        .send_datagram(Bytes::from(bytes.clone()))
        .expect("first datagram");
    let echoed = tokio::time::timeout(Duration::from_secs(2), tunnel.recv_datagram())
        .await
        .expect("echo timed out")
        .expect("echo failed");
    if echoed.as_ref() != bytes.as_slice() {
        return false;
    }
    tunnel.finish().await.expect("finish");
    if tokio::time::timeout(Duration::from_secs(2), closed)
        .await
        .is_err()
    {
        return false;
    }
    let late = ipv4_frame(64, 2);
    let late_bytes = encode(&late, None).expect("encode late");
    if tunnel.send_datagram(Bytes::from(late_bytes)).is_err() {
        return true;
    }
    tokio::time::timeout(Duration::from_millis(300), tunnel.recv_datagram())
        .await
        .is_err()
}

fn echo(mut server: QuicServer, options: Http3Options) -> tokio::sync::oneshot::Receiver<()> {
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let accepted = server.accept().await.expect("accept");
        let mut http = Http3Server::start(accepted.conn, options)
            .await
            .expect("h3 server");
        let mut tunnel = http.accept_tunnel().await.expect("tunnel");
        let mut tx = Some(tx);
        loop {
            match tunnel.recv().await {
                Ok(TunnelInput::Frame(Some(frame))) => {
                    if tunnel.write_frame(&frame).await.is_err() {
                        break;
                    }
                }
                Ok(TunnelInput::Frame(None)) => {
                    if let Some(tx) = tx.take() {
                        let _ = tx.send(());
                    }
                    break;
                }
                Ok(TunnelInput::Datagram(bytes)) => {
                    if tunnel.send_datagram(bytes).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
        let _ = tunnel.finish().await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        http.close().await;
        server.close().await;
    });
    rx
}

struct LossProxy {
    client_addr: std::net::SocketAddr,
    _task: tokio::task::JoinHandle<()>,
}

impl LossProxy {
    async fn start(server: std::net::SocketAddr, loss_percent: u8) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("proxy");
        let client_addr = socket.local_addr().expect("proxy addr");
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            let mut client = None;
            let mut to_server = 0u64;
            let mut to_client = 0u64;
            loop {
                let Ok((n, from)) = socket.recv_from(&mut buf).await else {
                    break;
                };
                if from == server {
                    let drop_it = drop_packet(to_client, loss_percent, LOSS_SEED);
                    to_client += 1;
                    if !drop_it {
                        if let Some(peer) = client {
                            let _ = socket.send_to(&buf[..n], peer).await;
                        }
                    }
                } else {
                    client = Some(from);
                    let drop_it = drop_packet(to_server, loss_percent, LOSS_SEED.wrapping_add(1));
                    to_server += 1;
                    if !drop_it {
                        let _ = socket.send_to(&buf[..n], server).await;
                    }
                }
            }
        });
        Self {
            client_addr,
            _task: task,
        }
    }
}

fn drop_packet(index: u64, loss_percent: u8, seed: u64) -> bool {
    if loss_percent == 0 {
        return false;
    }
    index.wrapping_add(seed) % 100 < u64::from(loss_percent)
}

fn jsonl_path(name: &str) -> PathBuf {
    if let Ok(dir) = std::env::var("ASTP_DATAGRAM_DIR") {
        return PathBuf::from(dir).join(name);
    }
    std::env::temp_dir().join(name)
}

fn write_jsonl(path: &PathBuf, lines: &[Value]) {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let mut out = String::new();
    for line in lines {
        out.push_str(&line.to_string());
        out.push('\n');
    }
    std::fs::write(path, out).unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    eprintln!("wrote {}", path.display());
    for line in lines {
        eprintln!("{line}");
    }
}
