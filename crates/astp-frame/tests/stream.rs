//! TCP-style framing: chunked reads, cancellation, and poison.

use std::cell::Cell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use astp_frame::{
    decode, encode, encode_to, DecodeLimits, Frame, FrameBody, FrameError, FrameReader,
};
use tokio::io::{AsyncRead, ReadBuf};

/// Cursor and poll count. Cloned into the test so it can be read while
/// [`FrameReader`] holds `&mut Script`.
struct Counters {
    pos: Cell<usize>,
    polls: Cell<usize>,
}

/// Byte source whose `poll_read` calls are visible to the tests.
struct Script {
    data: Vec<u8>,
    counters: Rc<Counters>,
    chunk: usize,
    /// Return `Pending` once, the first time `pos` has reached this offset.
    pending_once_at: Option<usize>,
    pending_once_done: bool,
    /// Return `ConnectionReset` once `pos` has reached this offset.
    reset_at: Option<usize>,
}

impl Script {
    fn chunked(data: Vec<u8>, chunk: usize) -> Self {
        assert!(chunk > 0);
        Self {
            data,
            counters: Rc::new(Counters {
                pos: Cell::new(0),
                polls: Cell::new(0),
            }),
            chunk,
            pending_once_at: None,
            pending_once_done: false,
            reset_at: None,
        }
    }

    fn pending_once_at(mut self, pos: usize) -> Self {
        self.pending_once_at = Some(pos);
        self
    }

    fn reset_at(mut self, pos: usize) -> Self {
        self.reset_at = Some(pos);
        self
    }

    fn counters(&self) -> Rc<Counters> {
        Rc::clone(&self.counters)
    }
}

impl AsyncRead for Script {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.counters.polls.set(this.counters.polls.get() + 1);
        let pos = this.counters.pos.get();
        if this.reset_at.is_some_and(|at| pos >= at) {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "reset")));
        }
        if this.pending_once_at.is_some_and(|at| pos >= at) && !this.pending_once_done {
            this.pending_once_done = true;
            return Poll::Pending;
        }
        if pos >= this.data.len() || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let n = this.chunk.min(buf.remaining()).min(this.data.len() - pos);
        buf.put_slice(&this.data[pos..pos + n]);
        this.counters.pos.set(pos + n);
        Poll::Ready(Ok(()))
    }
}

fn ping(byte: u8) -> Frame {
    Frame {
        key_epoch: None,
        body: FrameBody::Ping([byte; 8]),
    }
}

fn header(version: u8, ty: u8, flags: u16, length: u32) -> [u8; 8] {
    let mut out = [0u8; 8];
    out[0] = version;
    out[1] = ty;
    out[2..4].copy_from_slice(&flags.to_be_bytes());
    out[4..8].copy_from_slice(&length.to_be_bytes());
    out
}

fn assert_poisoned<R>(frames: &FrameReader<R>, counters: &Rc<Counters>, polls_before: usize) {
    assert!(frames.is_poisoned());
    assert_eq!(
        counters.polls.get(),
        polls_before,
        "a poisoned reader must not poll the socket"
    );
}

fn drive_until_pending<F>(fut: Pin<&mut F>)
where
    F: Future + ?Sized,
{
    let waker = std::task::Waker::noop();
    let mut cx = Context::from_waker(waker);
    match fut.poll(&mut cx) {
        Poll::Pending => {}
        Poll::Ready(_) => panic!("future completed before Pending"),
    }
}

#[tokio::test]
async fn one_byte_chunks_and_two_frames_in_one_buffer() {
    let first = encode(&ping(1), None).unwrap();
    let second = encode(&ping(2), None).unwrap();
    let mut both = first.clone();
    both.extend_from_slice(&second);

    let mut split = Script::chunked(both.clone(), 1);
    let mut frames = FrameReader::new(&mut split);
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(1));
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(2));
    assert!(frames.read_frame().await.unwrap().is_none());
    assert!(frames.read_frame().await.unwrap().is_none());
    assert!(!frames.is_poisoned());

    let mut whole = Script::chunked(both, 64);
    let mut frames = FrameReader::new(&mut whole);
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(1));
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(2));
    assert!(frames.read_frame().await.unwrap().is_none());
}

#[tokio::test]
async fn header_and_payload_arrive_in_separate_chunks() {
    let bytes = encode(&ping(9), None).unwrap();
    assert_eq!(bytes.len(), 16);
    let mut reader = Script::chunked(bytes, 8);
    let seen = reader.counters();
    let mut frames = FrameReader::new(&mut reader);
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(9));
    assert_eq!(seen.pos.get(), 16);
}

#[tokio::test]
async fn incomplete_header_or_payload_is_not_a_clean_eof() {
    let mut header_only = Script::chunked(vec![0x01, 0x01, 0x00], 8);
    let seen = header_only.counters();
    let mut frames = FrameReader::new(&mut header_only);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Incomplete)
    ));
    assert_eq!(seen.pos.get(), 3);
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);

    let mut short_payload = encode(&ping(1), None).unwrap();
    short_payload.pop();
    let mut reader = Script::chunked(short_payload, 8);
    let seen = reader.counters();
    let mut frames = FrameReader::new(&mut reader);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Incomplete)
    ));
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);

    let mut empty = Script::chunked(Vec::new(), 1);
    let mut frames = FrameReader::new(&mut empty);
    assert!(frames.read_frame().await.unwrap().is_none());
    assert!(frames.read_frame().await.unwrap().is_none());
    assert!(!frames.is_poisoned());
}

#[tokio::test]
async fn overlong_length_does_not_read_the_payload() {
    let mut data = vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    data.extend_from_slice(&encode(&ping(1), None).unwrap());
    let mut reader = Script::chunked(data, 64);
    let seen = reader.counters();
    let mut frames = FrameReader::new(&mut reader);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::FrameTooLong {
            length: 65_536,
            max_frame: 65_535
        })
    ));
    assert_eq!(seen.pos.get(), 8, "payload must not be consumed");
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 8);

    let ping_bytes = encode(&ping(3), None).unwrap();
    let mut limited = Script::chunked(ping_bytes, 64);
    let seen = limited.counters();
    let mut frames = FrameReader::with_limits(&mut limited, DecodeLimits { max_frame: 7 });
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::FrameTooLong {
            length: 8,
            max_frame: 7
        })
    ));
    assert_eq!(seen.pos.get(), 8);
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_eq!(seen.polls.get(), polls);
    assert_eq!(seen.pos.get(), 8);
}

#[tokio::test]
async fn encode_to_appends_and_a_failed_encode_keeps_the_buffer() {
    let mut buf = Vec::new();
    encode_to(&ping(1), None, &mut buf).unwrap();
    encode_to(&ping(2), None, &mut buf).unwrap();
    let mut reader = Script::chunked(buf, 3);
    let mut frames = FrameReader::new(&mut reader);
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(1));
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(2));

    let mut kept = vec![0xAA];
    let bad = Frame {
        key_epoch: None,
        body: FrameBody::Config(astp_frame::Config {
            cfg_id: 1,
            tlvs: vec![astp_frame::Tlv::Addr4 {
                addr: std::net::Ipv4Addr::LOCALHOST,
                prefix: 33,
            }],
        }),
    };
    assert!(matches!(
        encode_to(&bad, None, &mut kept),
        Err(FrameError::BadPrefix {
            ty: 0x0001,
            prefix: 33
        })
    ));
    assert_eq!(kept, vec![0xAA]);
    let _ = decode(&encode(&ping(1), None).unwrap()).unwrap();
}

/// Version `0x02`, `Length = 16`, then a 16-byte PING and one extra byte.
///
/// Those bytes are the rejected frame's payload. They stay unread. The
/// reader is poisoned and does not parse them as the next frame.
#[tokio::test]
async fn unknown_version_does_not_read_its_payload_and_poisons() {
    let ping_bytes = encode(&ping(1), None).unwrap();
    assert_eq!(ping_bytes.len(), 16);
    let mut data = header(0x02, 0x01, 0, 16).to_vec();
    data.extend_from_slice(&ping_bytes);
    data.push(0xFF);
    let mut script = Script::chunked(data, 64);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);

    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::UnknownVersion { version: 0x02 })
    ));
    assert_eq!(seen.pos.get(), 8, "payload must not be consumed");
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 8);
}

/// F1: version and flags are not allowed to hide an overlong `Length`.
#[tokio::test]
async fn overlong_length_wins_over_version_and_reserved_flags() {
    let mut version = header(0x02, 0x01, 0, u32::MAX).to_vec();
    version.extend_from_slice(&[0xAB; 8]);
    let mut script = Script::chunked(version, 64);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::FrameTooLong {
            length: u32::MAX,
            max_frame: 65_535
        })
    ));
    assert_eq!(seen.pos.get(), 8);
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);

    let mut flags = header(0x01, 0x01, 0x0004, 65_536).to_vec();
    flags.extend_from_slice(&[0xAB; 8]);
    let mut script = Script::chunked(flags, 8);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::FrameTooLong {
            length: 65_536,
            max_frame: 65_535
        })
    ));
    assert_eq!(seen.pos.get(), 8);
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
}

#[tokio::test]
async fn reserved_flags_do_not_read_the_payload_and_poison() {
    let mut data = header(0x01, 0x01, 0x0004, 4).to_vec();
    data.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF, 0xFF]);
    let mut script = Script::chunked(data, 3);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::ReservedFlags { flags: 0x0004 })
    ));
    assert_eq!(seen.pos.get(), 8, "payload must not be consumed");
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 8);
}

#[tokio::test]
async fn unknown_version_wins_over_reserved_flags_when_length_is_legal() {
    let mut data = header(0x02, 0x01, 0x0004, 0).to_vec();
    data.extend_from_slice(&encode(&ping(4), None).unwrap());
    let mut script = Script::chunked(data, 64);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::UnknownVersion { version: 0x02 })
    ));
    assert_eq!(seen.pos.get(), 8, "the reader stops after the header");
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 8);
}

/// F2: one byte at a time, `Pending` after 4 bytes, drop the future.
///
/// The byte at offset 4 of a PING header is `0x00`. Losing the stored
/// prefix made the next read return `UnknownVersion { version: 0 }`.
#[tokio::test]
async fn dropped_pending_read_resumes_the_same_ping() {
    let bytes = encode(&ping(7), None).unwrap();
    assert_eq!(bytes.len(), 16);
    assert_eq!(bytes[0], 0x01);
    assert_eq!(bytes[4], 0x00);
    let mut script = Script::chunked(bytes, 1).pending_once_at(4);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);

    {
        let fut = frames.read_frame();
        let mut fut = std::pin::pin!(fut);
        drive_until_pending(fut.as_mut());
        assert_eq!(seen.pos.get(), 4);
    }
    assert_eq!(seen.pos.get(), 4, "dropping the future does not rewind");

    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(7));
    assert_eq!(seen.pos.get(), 16);
    assert!(!frames.is_poisoned());
    assert!(frames.read_frame().await.unwrap().is_none());
}

/// F2: the payload buffer has to survive cancellation the same way.
#[tokio::test]
async fn dropped_pending_read_mid_payload_resumes_the_same_ping() {
    let bytes = encode(&ping(8), None).unwrap();
    let mut script = Script::chunked(bytes, 1).pending_once_at(10);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);

    {
        let fut = frames.read_frame();
        let mut fut = std::pin::pin!(fut);
        drive_until_pending(fut.as_mut());
        assert_eq!(seen.pos.get(), 10);
    }
    assert_eq!(seen.pos.get(), 10, "dropping the future does not rewind");

    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(8));
    assert_eq!(seen.pos.get(), 16);
    assert!(!frames.is_poisoned());
}

/// F2: `ConnectionReset` after 3 bytes. The cursor stays at 3, and the
/// next read does not touch the socket.
#[tokio::test]
async fn connection_reset_after_three_bytes_poisons() {
    let bytes = encode(&ping(1), None).unwrap();
    let mut script = Script::chunked(bytes, 1).reset_at(3);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    match frames.read_frame().await {
        Err(FrameError::Io(err)) => {
            assert_eq!(err.kind(), io::ErrorKind::ConnectionReset);
        }
        other => panic!("expected connection reset, got {other:?}"),
    }
    assert_eq!(seen.pos.get(), 3);
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 3);
}

/// A reset parked inside the unread payload is not observed. The header
/// error poisons the reader after the 8-byte header.
#[tokio::test]
async fn unknown_version_does_not_reach_a_reset_in_the_payload() {
    let mut data = header(0x02, 0x01, 0, 16).to_vec();
    data.extend_from_slice(&[0x11; 16]);
    let mut script = Script::chunked(data, 1).reset_at(10);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::UnknownVersion { version: 0x02 })
    ));
    assert_eq!(seen.pos.get(), 8, "payload must not be consumed");
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 8);
}

/// EOF inside the declared payload is not read. The header error is
/// returned, the short tail stays in the socket, and the reader is poisoned.
#[tokio::test]
async fn unknown_version_does_not_read_a_truncated_payload() {
    let mut data = header(0x02, 0x01, 0, 16).to_vec();
    data.extend_from_slice(&[0x11; 4]);
    let mut script = Script::chunked(data, 8);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::UnknownVersion { version: 0x02 })
    ));
    assert_eq!(seen.pos.get(), 8, "payload must not be consumed");
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 8);
}

/// A fully consumed frame with a bad body is aligned, and still poisoned.
/// The following PING must not be parsed.
#[tokio::test]
async fn unknown_type_consumes_the_frame_then_poisons() {
    let mut data = header(0x01, 0x99, 0, 0).to_vec();
    data.extend_from_slice(&encode(&ping(1), None).unwrap());
    let mut script = Script::chunked(data, 64);
    let seen = script.counters();
    let mut frames = FrameReader::new(&mut script);
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::UnknownType { ty: 0x99 })
    ));
    assert_eq!(seen.pos.get(), 8);
    let polls = seen.polls.get();
    assert!(matches!(
        frames.read_frame().await,
        Err(FrameError::Poisoned)
    ));
    assert_poisoned(&frames, &seen, polls);
    assert_eq!(seen.pos.get(), 8);
}

/// F3: a CONFIG `MaxFrame` TLV does not become this reader's limit,
/// including for the frame that carried it.
#[tokio::test]
async fn config_max_frame_tlv_does_not_change_the_reader_limit() {
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Config(astp_frame::Config {
            cfg_id: 1,
            tlvs: vec![astp_frame::Tlv::MaxFrame(7)],
        }),
    };
    let config = encode(&frame, None).unwrap();
    assert!(
        config.len() > 8 + 7,
        "the frame itself is longer than the TLV"
    );
    let mut data = config;
    data.extend_from_slice(&encode(&ping(1), None).unwrap());
    let mut script = Script::chunked(data, 5);
    let mut frames = FrameReader::new(&mut script);
    assert_eq!(frames.limits(), DecodeLimits::DEFAULT);
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), frame);
    assert_eq!(frames.limits(), DecodeLimits::DEFAULT);
    assert_eq!(frames.read_frame().await.unwrap().unwrap(), ping(1));
    assert!(!frames.is_poisoned());
}
