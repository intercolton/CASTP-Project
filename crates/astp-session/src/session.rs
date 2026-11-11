//! The session driver: handshake frames, then packets both ways with
//! keepalive, idle timeout and `WINDOW` credit (`docs/design/session.md`).
//!
//! Reading and writing run as two halves of one task. Neither waits on
//! the other: a peer that stops reading cannot keep this side from
//! reading, which would otherwise deadlock two sessions that both write.

use crate::params::{routes_of, Route, SessionParams};
use astp_frame::{
    encode_camouflage, Frame, FrameBody, FrameError, FrameReader, Ipv4Packet, Ipv6Packet,
};
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt};
use tokio::sync::{mpsc, oneshot, Notify};
use tokio::time::Instant;

/// One raw IP packet.
pub type Packet = Vec<u8>;

/// Credit each side starts with, bytes of `TUN_*` bodies.
pub const INITIAL_WINDOW: u64 = 1 << 20;

/// `DISCONNECT` codes.
pub mod code {
    pub const NORMAL: u16 = 0;
    pub const PROTOCOL_ERROR: u16 = 1;
    pub const IDLE_TIMEOUT: u16 = 2;
    pub const CONFIG_REJECTED: u16 = 3;
    pub const SERVER_SHUTDOWN: u16 = 4;
    pub const REPLACED: u16 = 5;
}

/// Why a handshake or a session failed.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("bad frame: {0}")]
    Frame(#[from] FrameError),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("timed out waiting for {0}")]
    Timeout(&'static str),
    #[error("peer closed the stream")]
    Closed,
    #[error("peer disconnected: code {code}, {reason:?}")]
    Disconnected { code: u16, reason: String },
    #[error("configuration rejected: {0}")]
    Rejected(String),
}

/// Which end of the session this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Client,
    Server,
}

async fn write_frame<W: AsyncWrite + Unpin>(
    w: &mut W,
    body: FrameBody,
) -> Result<(), SessionError> {
    let bytes = encode_camouflage(&Frame {
        key_epoch: None,
        body,
    })?;
    w.write_all(&bytes).await?;
    w.flush().await?;
    Ok(())
}

async fn read_one<R: AsyncRead + Unpin>(
    r: &mut FrameReader<R>,
    until: Instant,
    what: &'static str,
) -> Result<FrameBody, SessionError> {
    match tokio::time::timeout_at(until, r.read_frame()).await {
        Err(_) => Err(SessionError::Timeout(what)),
        Ok(Err(e)) => Err(e.into()),
        Ok(Ok(None)) => Err(SessionError::Closed),
        Ok(Ok(Some(f))) if f.key_epoch.is_some() => {
            Err(SessionError::Protocol("KEY_EPOCH is not used in v1".into()))
        }
        Ok(Ok(Some(f))) => Ok(f.body),
    }
}

/// Server side of the handshake: sends `CONFIG` and waits for a matching
/// `CONFIG_ACK` with code 0.
pub async fn server_handshake<R, W>(
    reader: &mut FrameReader<R>,
    writer: &mut W,
    params: &SessionParams,
    timeout: Duration,
) -> Result<(), SessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let until = Instant::now() + timeout;
    let cfg_id: u32 = rand::random();
    write_frame(writer, FrameBody::Config(params.to_config(cfg_id))).await?;
    loop {
        match read_one(reader, until, "CONFIG_ACK").await? {
            FrameBody::ConfigAck { cfg_id: id, code } if id == cfg_id => {
                return if code == 0 {
                    Ok(())
                } else {
                    Err(SessionError::Rejected(format!(
                        "client answered code {code}"
                    )))
                };
            }
            FrameBody::Ping(b) => write_frame(writer, FrameBody::Pong(b)).await?,
            FrameBody::Padding | FrameBody::Pong(_) => {}
            FrameBody::Disconnect { code, reason } => {
                return Err(SessionError::Disconnected { code, reason })
            }
            other => {
                let e = format!("unexpected {:#04x} before CONFIG_ACK", other.type_code());
                let _ = write_frame(
                    writer,
                    FrameBody::Disconnect {
                        code: code::PROTOCOL_ERROR,
                        reason: String::new(),
                    },
                )
                .await;
                return Err(SessionError::Protocol(e));
            }
        }
    }
}

/// Client side of the handshake: waits for `CONFIG`, lets `accept` judge
/// it, and answers `CONFIG_ACK` (plus `DISCONNECT 3` on refusal).
pub async fn client_handshake<R, W>(
    reader: &mut FrameReader<R>,
    writer: &mut W,
    timeout: Duration,
    accept: impl FnOnce(&SessionParams) -> Result<(), String>,
) -> Result<SessionParams, SessionError>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let until = Instant::now() + timeout;
    loop {
        match read_one(reader, until, "CONFIG").await? {
            FrameBody::Config(cfg) => {
                let verdict =
                    SessionParams::from_tlvs(&cfg.tlvs).and_then(|p| accept(&p).map(|()| p));
                return match verdict {
                    Ok(p) => {
                        write_frame(
                            writer,
                            FrameBody::ConfigAck {
                                cfg_id: cfg.cfg_id,
                                code: 0,
                            },
                        )
                        .await?;
                        Ok(p)
                    }
                    Err(why) => {
                        let _ = write_frame(
                            writer,
                            FrameBody::ConfigAck {
                                cfg_id: cfg.cfg_id,
                                code: 1,
                            },
                        )
                        .await;
                        let _ = write_frame(
                            writer,
                            FrameBody::Disconnect {
                                code: code::CONFIG_REJECTED,
                                reason: String::new(),
                            },
                        )
                        .await;
                        Err(SessionError::Rejected(why))
                    }
                };
            }
            FrameBody::Ping(b) => write_frame(writer, FrameBody::Pong(b)).await?,
            FrameBody::Padding | FrameBody::Pong(_) => {}
            FrameBody::Disconnect { code, reason } => {
                return Err(SessionError::Disconnected { code, reason })
            }
            other => {
                return Err(SessionError::Protocol(format!(
                    "unexpected {:#04x} before CONFIG",
                    other.type_code()
                )))
            }
        }
    }
}

/// Packets between the session and the local side (TUN or router).
pub struct Link {
    /// Packets that arrived from the peer.
    pub to_local: mpsc::Sender<Packet>,
    /// Packets to send to the peer. Closing it ends the session normally.
    pub from_local: mpsc::Receiver<Packet>,
    /// Client: later `CONFIG` and `ROUTE_UPDATE` from the server.
    pub events: Option<mpsc::UnboundedSender<Event>>,
}

/// Something the server changed during the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Config(SessionParams),
    Routes(Vec<Route>),
}

/// Counters of one session.
#[derive(Debug, Default)]
pub struct Stats {
    pub sent_packets: AtomicU64,
    pub sent_bytes: AtomicU64,
    pub received_packets: AtomicU64,
    pub received_bytes: AtomicU64,
    /// Not sent: no credit left (the peer is behind).
    pub dropped_no_credit: AtomicU64,
    /// Received but the local side's queue was full.
    pub dropped_local_full: AtomicU64,
    /// Not sent: not a valid IPv4 or IPv6 packet.
    pub dropped_invalid: AtomicU64,
}

impl Stats {
    fn add(c: &AtomicU64, n: u64) {
        c.fetch_add(n, Ordering::Relaxed);
    }
}

/// How a session ended.
#[derive(Debug)]
pub enum EndReason {
    /// `stop` fired; we sent `DISCONNECT` with this code.
    LocalStop(u16),
    /// The local side closed `from_local`.
    LocalClosed,
    PeerDisconnect {
        code: u16,
        reason: String,
    },
    /// The stream ended without `DISCONNECT`.
    PeerClosed,
    IdleTimeout,
    Failed(SessionError),
}

enum Close {
    /// Send this `DISCONNECT` code, then end.
    Send(u16),
    /// Just end.
    Quiet,
}

/// Runs an established session until either side ends it.
///
/// `stop` resolves to a `DISCONNECT` code when the local side wants out
/// (e.g. [`code::SERVER_SHUTDOWN`]). `stats` can be read while it runs.
pub async fn run<R, W>(
    role: Role,
    mut reader: FrameReader<R>,
    mut writer: W,
    params: &SessionParams,
    link: Link,
    stats: Arc<Stats>,
    stop: impl Future<Output = u16>,
) -> EndReason
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let Link {
        to_local,
        mut from_local,
        events,
    } = link;
    let send_credit = AtomicU64::new(INITIAL_WINDOW);
    // Credit we have returned to the peer: counted before the WINDOW frame
    // is written, so a peer quick to use it is never seen as cheating.
    let granted = AtomicU64::new(0);
    let grant = AtomicU64::new(0);
    let grant_ready = Notify::new();
    let reader_stop = Notify::new();
    let (ctrl_tx, mut ctrl_rx) = mpsc::channel::<FrameBody>(64);
    let (close_tx, close_rx) = oneshot::channel::<Close>();
    let keepalive = params.keepalive;
    let idle = params.idle_timeout;

    let read_half = async {
        let mut received_total = 0u64;
        let mut consumed = 0u64;
        let mut close_tx = Some(close_tx);
        let mut close = |c: Close| {
            if let Some(tx) = close_tx.take() {
                let _ = tx.send(c);
            }
        };
        loop {
            let frame = tokio::select! {
                _ = reader_stop.notified() => return None,
                f = tokio::time::timeout(idle, reader.read_frame()) => f,
            };
            let body = match frame {
                Err(_) => {
                    close(Close::Send(code::IDLE_TIMEOUT));
                    return Some(EndReason::IdleTimeout);
                }
                Ok(Ok(None)) => {
                    close(Close::Quiet);
                    return Some(EndReason::PeerClosed);
                }
                Ok(Err(e)) => {
                    close(Close::Send(code::PROTOCOL_ERROR));
                    return Some(EndReason::Failed(e.into()));
                }
                Ok(Ok(Some(f))) if f.key_epoch.is_some() => {
                    close(Close::Send(code::PROTOCOL_ERROR));
                    return Some(EndReason::Failed(SessionError::Protocol(
                        "KEY_EPOCH is not used in v1".into(),
                    )));
                }
                Ok(Ok(Some(f))) => f.body,
            };
            let violation =
                |what: &str| Some(EndReason::Failed(SessionError::Protocol(what.to_owned())));
            match body {
                FrameBody::TunIpv4(_) | FrameBody::TunIpv6(_) => {
                    let pkt = match body {
                        FrameBody::TunIpv4(p) => p.into_bytes(),
                        FrameBody::TunIpv6(p) => p.into_bytes(),
                        _ => unreachable!("matched above"),
                    };
                    let n = pkt.len() as u64;
                    received_total += n;
                    if received_total > INITIAL_WINDOW + granted.load(Ordering::Relaxed) {
                        close(Close::Send(code::PROTOCOL_ERROR));
                        return violation("peer sent past its WINDOW credit");
                    }
                    Stats::add(&stats.received_packets, 1);
                    Stats::add(&stats.received_bytes, n);
                    match to_local.try_send(pkt) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            Stats::add(&stats.dropped_local_full, 1)
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            close(Close::Send(code::NORMAL));
                            return Some(EndReason::LocalClosed);
                        }
                    }
                    // Handled (delivered or dropped): the credit goes back.
                    consumed += n;
                    if consumed >= INITIAL_WINDOW / 2 {
                        grant.fetch_add(consumed, Ordering::Relaxed);
                        consumed = 0;
                        grant_ready.notify_one();
                    }
                }
                FrameBody::Ping(b) => {
                    // A peer flooding PINGs loses PONGs, nothing else.
                    let _ = ctrl_tx.try_send(FrameBody::Pong(b));
                }
                FrameBody::Pong(_) | FrameBody::Padding => {}
                FrameBody::Window { credit } => {
                    send_credit.fetch_add(u64::from(credit), Ordering::Relaxed);
                }
                FrameBody::Disconnect { code, reason } => {
                    close(Close::Quiet);
                    return Some(EndReason::PeerDisconnect { code, reason });
                }
                FrameBody::Config(cfg) if role == Role::Client => {
                    let ack = match SessionParams::from_tlvs(&cfg.tlvs) {
                        Ok(p) => {
                            if let Some(ev) = &events {
                                let _ = ev.send(Event::Config(p));
                            }
                            0
                        }
                        Err(_) => 1,
                    };
                    let _ = ctrl_tx
                        .send(FrameBody::ConfigAck {
                            cfg_id: cfg.cfg_id,
                            code: ack,
                        })
                        .await;
                }
                FrameBody::RouteUpdate(u) if role == Role::Client => {
                    if let Some(ev) = &events {
                        let _ = ev.send(Event::Routes(routes_of(&u.tlvs)));
                    }
                }
                // v1 servers send no CONFIG once the session runs.
                FrameBody::ConfigAck { .. } if role == Role::Server => {}
                other => {
                    close(Close::Send(code::PROTOCOL_ERROR));
                    return violation(&format!(
                        "frame {:#04x} not allowed from the {}",
                        other.type_code(),
                        if role == Role::Client {
                            "server"
                        } else {
                            "client"
                        }
                    ));
                }
            }
        }
    };

    let write_half = async {
        tokio::pin!(stop);
        let mut close_rx = close_rx;
        let mut last_sent = Instant::now();
        let end = loop {
            let ping_at = last_sent + keepalive;
            let result = tokio::select! {
                biased;
                c = &mut close_rx => {
                    if let Ok(Close::Send(code)) = c {
                        let _ = write_frame(&mut writer, FrameBody::Disconnect { code, reason: String::new() }).await;
                    }
                    break None;
                }
                code = &mut stop => {
                    let _ = write_frame(&mut writer, FrameBody::Disconnect { code, reason: String::new() }).await;
                    break Some(EndReason::LocalStop(code));
                }
                Some(f) = ctrl_rx.recv() => write_frame(&mut writer, f).await,
                _ = grant_ready.notified() => {
                    let mut n = grant.swap(0, Ordering::Relaxed);
                    let mut r = Ok(());
                    while n > 0 && r.is_ok() {
                        let part = n.min(u64::from(u32::MAX));
                        n -= part;
                        granted.fetch_add(part, Ordering::Relaxed);
                        r = write_frame(&mut writer, FrameBody::Window { credit: part as u32 }).await;
                    }
                    r
                }
                p = from_local.recv() => match p {
                    None => {
                        let _ = write_frame(&mut writer, FrameBody::Disconnect { code: code::NORMAL, reason: String::new() }).await;
                        break Some(EndReason::LocalClosed);
                    }
                    Some(pkt) => {
                        let n = pkt.len() as u64;
                        let body = match pkt.first().map(|b| b >> 4) {
                            Some(4) => Ipv4Packet::new(pkt).ok().map(FrameBody::TunIpv4),
                            Some(6) => Ipv6Packet::new(pkt).ok().map(FrameBody::TunIpv6),
                            _ => None,
                        };
                        match body {
                            None => { Stats::add(&stats.dropped_invalid, 1); Ok(()) }
                            Some(body) => {
                                let have = send_credit.load(Ordering::Relaxed);
                                if have < n {
                                    Stats::add(&stats.dropped_no_credit, 1);
                                    Ok(())
                                } else {
                                    send_credit.fetch_sub(n, Ordering::Relaxed);
                                    Stats::add(&stats.sent_packets, 1);
                                    Stats::add(&stats.sent_bytes, n);
                                    write_frame(&mut writer, body).await
                                }
                            }
                        }
                    }
                },
                _ = tokio::time::sleep_until(ping_at) => {
                    write_frame(&mut writer, FrameBody::Ping(rand::random())).await
                }
            };
            match result {
                Ok(()) => last_sent = Instant::now(),
                Err(e) => break Some(EndReason::Failed(e)),
            }
        };
        let _ = writer.shutdown().await;
        reader_stop.notify_one();
        end
    };

    tokio::pin!(read_half);
    tokio::pin!(write_half);
    tokio::select! {
        r = &mut read_half => {
            // The write side may be stuck on a peer that does not read: it
            // gets a moment to send DISCONNECT and is then abandoned.
            let w = tokio::time::timeout(CLOSE_GRACE, &mut write_half).await.ok().flatten();
            r.or(w).unwrap_or(EndReason::PeerClosed)
        }
        w = &mut write_half => {
            // The write side told the read side to stop.
            let r = read_half.await;
            w.or(r).unwrap_or(EndReason::PeerClosed)
        }
    }
}

/// How long the write side may take to send `DISCONNECT` once the read
/// side has ended the session.
pub const CLOSE_GRACE: Duration = Duration::from_secs(2);
