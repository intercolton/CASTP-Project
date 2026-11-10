//! TCP-style framing: chunked reads, back-to-back frames, and a length cap.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use astp_frame::{
    decode, encode, encode_to, read_frame, read_frame_with, DecodeLimits, Frame, FrameBody,
    FrameError,
};
use tokio::io::{AsyncRead, ReadBuf};

struct Chunks {
    data: Vec<u8>,
    pos: usize,
    chunk: usize,
}

impl Chunks {
    fn new(data: Vec<u8>, chunk: usize) -> Self {
        assert!(chunk > 0);
        Self {
            data,
            pos: 0,
            chunk,
        }
    }
}

impl AsyncRead for Chunks {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos >= this.data.len() || buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        let n = this
            .chunk
            .min(buf.remaining())
            .min(this.data.len() - this.pos);
        buf.put_slice(&this.data[this.pos..this.pos + n]);
        this.pos += n;
        Poll::Ready(Ok(()))
    }
}

fn ping(byte: u8) -> Frame {
    Frame {
        key_epoch: None,
        body: FrameBody::Ping([byte; 8]),
    }
}

#[tokio::test]
async fn one_byte_chunks_and_two_frames_in_one_buffer() {
    let first = encode(&ping(1), None).unwrap();
    let second = encode(&ping(2), None).unwrap();
    let mut both = first.clone();
    both.extend_from_slice(&second);

    let mut split = Chunks::new(both.clone(), 1);
    assert_eq!(read_frame(&mut split).await.unwrap().unwrap(), ping(1));
    assert_eq!(read_frame(&mut split).await.unwrap().unwrap(), ping(2));
    assert!(read_frame(&mut split).await.unwrap().is_none());

    let mut whole = Chunks::new(both, 64);
    assert_eq!(read_frame(&mut whole).await.unwrap().unwrap(), ping(1));
    assert_eq!(read_frame(&mut whole).await.unwrap().unwrap(), ping(2));
    assert!(read_frame(&mut whole).await.unwrap().is_none());
}

#[tokio::test]
async fn header_and_payload_arrive_in_separate_chunks() {
    let bytes = encode(&ping(9), None).unwrap();
    assert_eq!(bytes.len(), 16);
    let mut reader = Chunks::new(bytes, 8);
    assert_eq!(read_frame(&mut reader).await.unwrap().unwrap(), ping(9));
    assert_eq!(reader.pos, 16);
}

#[tokio::test]
async fn incomplete_header_or_payload_is_not_a_clean_eof() {
    let mut header_only = Chunks::new(vec![0x01, 0x01, 0x00], 8);
    assert!(matches!(
        read_frame(&mut header_only).await,
        Err(FrameError::Incomplete)
    ));

    let mut short_payload = encode(&ping(1), None).unwrap();
    short_payload.pop();
    let mut reader = Chunks::new(short_payload, 8);
    assert!(matches!(
        read_frame(&mut reader).await,
        Err(FrameError::Incomplete)
    ));

    let mut empty = Chunks::new(Vec::new(), 1);
    assert!(read_frame(&mut empty).await.unwrap().is_none());
}

#[tokio::test]
async fn overlong_length_does_not_read_the_payload() {
    let mut data = vec![0x01, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00];
    data.extend_from_slice(&encode(&ping(1), None).unwrap());
    let mut reader = Chunks::new(data, 64);
    assert!(matches!(
        read_frame(&mut reader).await,
        Err(FrameError::FrameTooLong {
            length: 65_536,
            max_frame: 65_535
        })
    ));
    assert_eq!(reader.pos, 8, "payload must not be consumed");

    let ping_bytes = encode(&ping(3), None).unwrap();
    let mut limited = Chunks::new(ping_bytes, 64);
    assert!(matches!(
        read_frame_with(&mut limited, DecodeLimits { max_frame: 7 }).await,
        Err(FrameError::FrameTooLong {
            length: 8,
            max_frame: 7
        })
    ));
    assert_eq!(limited.pos, 8);
}

#[tokio::test]
async fn encode_to_appends_and_a_failed_encode_keeps_the_buffer() {
    let mut buf = Vec::new();
    encode_to(&ping(1), None, &mut buf).unwrap();
    encode_to(&ping(2), None, &mut buf).unwrap();
    let mut reader = Chunks::new(buf, 3);
    assert_eq!(read_frame(&mut reader).await.unwrap().unwrap(), ping(1));
    assert_eq!(read_frame(&mut reader).await.unwrap().unwrap(), ping(2));

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
