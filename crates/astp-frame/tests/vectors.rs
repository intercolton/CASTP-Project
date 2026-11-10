//! Fixed vectors V1–V12 and the mandatory rejections from the frame brief.

use std::net::Ipv4Addr;

use astp_frame::{
    camouflage_pad_len, decode, decode_with, encode, encode_camouflage_with, CamouflageProfile,
    Config, DecodeLimits, Frame, FrameBody, FrameError, Ipv4Packet, Ipv6Packet, Tlv,
};

fn hex(text: &str) -> Vec<u8> {
    let digits: String = text.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    assert!(digits.len().is_multiple_of(2), "odd hex length in {text}");
    (0..digits.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("hex"))
        .collect()
}

fn header(version: u8, ty: u8, flags: u16, length: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(8);
    out.push(version);
    out.push(ty);
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&length.to_be_bytes());
    out
}

fn frame_bytes(ty: u8, flags: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = header(0x01, ty, flags, u32::try_from(payload.len()).unwrap());
    out.extend_from_slice(payload);
    out
}

fn ping() -> Frame {
    Frame {
        key_epoch: None,
        body: FrameBody::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
    }
}

fn v3() -> Vec<u8> {
    let mut bytes = hex("01 01 00 01 00 00 00 38 01 02 03 04 05 06 07 08");
    bytes.extend_from_slice(&[0xAB; 46]);
    bytes.extend_from_slice(&0x002Eu16.to_be_bytes());
    assert_eq!(bytes.len(), 64);
    bytes
}

fn v9_packet() -> Vec<u8> {
    hex("45 00 00 14 00 00 00 00 40 01 00 00 0A 00 00 01 0A 00 00 02")
}

fn v12() -> Vec<u8> {
    let mut bytes = hex("01 10 00 01 00 00 00 38");
    bytes.extend_from_slice(&v9_packet());
    bytes.extend_from_slice(&[0xAB; 34]);
    bytes.extend_from_slice(&0x0022u16.to_be_bytes());
    assert_eq!(bytes.len(), 64);
    bytes
}

fn assert_err(bytes: &[u8], check: impl Fn(&FrameError) -> bool) {
    match decode(bytes) {
        Ok(frame) => panic!("expected error, decoded {frame:?}"),
        Err(err) => assert!(check(&err), "unexpected error: {err:?}"),
    }
}

#[test]
fn v1_ping_round_trip() {
    let bytes = hex("01 01 00 00 00 00 00 08 01 02 03 04 05 06 07 08");
    assert_eq!(decode(&bytes).unwrap(), ping());
    assert_eq!(encode(&ping(), None).unwrap(), bytes);
}

#[test]
fn v2_pong_round_trip() {
    let bytes = hex("01 02 00 00 00 00 00 08 01 02 03 04 05 06 07 08");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Pong([1, 2, 3, 4, 5, 6, 7, 8]),
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v3_padded_ping_explicit_and_camouflage() {
    let bytes = v3();
    assert_eq!(decode(&bytes).unwrap(), ping());
    assert_eq!(encode(&ping(), Some(&[0xAB; 46])).unwrap(), bytes);
    let filled = encode_camouflage_with(&ping(), &CamouflageProfile::V1, |buf| {
        buf.fill(0xAB);
        Ok(())
    })
    .unwrap();
    assert_eq!(filled, bytes);
    assert_eq!(camouflage_pad_len(8, 64, 64, 255), Some(46));
}

#[test]
fn v4_key_epoch_ping() {
    let bytes = hex("01 01 00 02 00 00 00 09 07 01 02 03 04 05 06 07 08");
    let frame = Frame {
        key_epoch: Some(7),
        body: FrameBody::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v5_empty_padding() {
    let bytes = hex("01 00 00 00 00 00 00 00");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Padding,
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v6_config_ack() {
    let bytes = hex("01 21 00 00 00 00 00 05 01 02 03 04 00");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::ConfigAck {
            cfg_id: 0x0102_0304,
            code: 0,
        },
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v7_window() {
    let bytes = hex("01 31 00 00 00 00 00 04 00 00 03 E8");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Window { credit: 1000 },
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v8_disconnect() {
    let bytes = hex("01 30 00 00 00 00 00 05 00 01 62 79 65");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Disconnect {
            code: 1,
            reason: "bye".to_owned(),
        },
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v9_tun_ipv4() {
    let bytes =
        hex("01 10 00 00 00 00 00 14 45 00 00 14 00 00 00 00 40 01 00 00 0A 00 00 01 0A 00 00 02");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::TunIpv4(Ipv4Packet::new(v9_packet()).unwrap()),
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v10_tun_ipv6() {
    let bytes = hex("01 11 00 00 00 00 00 28 \
         60 00 00 00 00 00 3B 40 \
         FD 00 00 17 05 30 00 00 00 00 00 00 00 00 00 01 \
         FD 00 00 17 05 30 00 00 00 00 00 00 00 00 00 02");
    let packet = hex("60 00 00 00 00 00 3B 40 \
         FD 00 00 17 05 30 00 00 00 00 00 00 00 00 00 01 \
         FD 00 00 17 05 30 00 00 00 00 00 00 00 00 00 02");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::TunIpv6(Ipv6Packet::new(packet).unwrap()),
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v11_config_addr4() {
    let bytes = hex("01 20 00 00 00 00 00 0D 00 00 00 01 00 01 00 05 0A 40 00 02 20");
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Config(astp_frame::Config {
            cfg_id: 1,
            tlvs: vec![astp_frame::Tlv::Addr4 {
                addr: Ipv4Addr::new(10, 64, 0, 2),
                prefix: 32,
            }],
        }),
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, None).unwrap(), bytes);
}

#[test]
fn v12_camouflaged_ipv4() {
    let bytes = v12();
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::TunIpv4(Ipv4Packet::new(v9_packet()).unwrap()),
    };
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert_eq!(encode(&frame, Some(&[0xAB; 34])).unwrap(), bytes);
    let filled = encode_camouflage_with(&frame, &CamouflageProfile::V1, |buf| {
        buf.fill(0xAB);
        Ok(())
    })
    .unwrap();
    assert_eq!(filled, bytes);
    assert_eq!(camouflage_pad_len(20, 64, 64, 255), Some(34));
    assert_eq!(camouflage_pad_len(56, 64, 64, 255), None);
    assert_eq!(camouflage_pad_len(8, 64, 64, 10), Some(10));
}

#[test]
fn rejects_unknown_version_type_flags_and_overlong_length() {
    let mut unknown_version = header(0x02, 0x01, 0, 8);
    unknown_version.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_err(&unknown_version, |err| {
        matches!(err, FrameError::UnknownVersion { version: 0x02 })
    });

    assert_err(&frame_bytes(0x99, 0, &[0; 8]), |err| {
        matches!(err, FrameError::UnknownType { ty: 0x99 })
    });
    assert_err(&frame_bytes(0x40, 0, &[]), |err| {
        matches!(err, FrameError::UnknownType { ty: 0x40 })
    });
    assert_err(&frame_bytes(0x4F, 0, &[]), |err| {
        matches!(err, FrameError::UnknownType { ty: 0x4F })
    });
    assert_err(&frame_bytes(0xE0, 0, &[]), |err| {
        matches!(err, FrameError::UnknownType { ty: 0xE0 })
    });
    assert_err(&frame_bytes(0xFF, 0, &[]), |err| {
        matches!(err, FrameError::UnknownType { ty: 0xFF })
    });

    assert_err(&frame_bytes(0x01, 0x0004, &[0; 8]), |err| {
        matches!(err, FrameError::ReservedFlags { flags: 0x0004 })
    });

    assert_err(&header(0x01, 0x01, 0, 65_536), |err| {
        matches!(
            err,
            FrameError::FrameTooLong {
                length: 65_536,
                max_frame: 65_535
            }
        )
    });
    assert_err(&header(0x01, 0x00, 0, 65_535), |err| {
        matches!(err, FrameError::Incomplete)
    });
}

#[test]
fn rejects_bad_padding_epoch_ip_disconnect_and_tlv() {
    assert_err(&frame_bytes(0x01, 0x0001, &[0x00]), |err| {
        matches!(err, FrameError::BadPadding)
    });
    assert_err(&frame_bytes(0x00, 0x0001, &hex("00 00 00 05")), |err| {
        matches!(err, FrameError::BadPadding)
    });
    assert_err(&header(0x01, 0x00, 0x0002, 0), |err| {
        matches!(err, FrameError::EmptyKeyEpoch)
    });

    let mut bad_version = frame_bytes(0x10, 0, &v9_packet());
    bad_version[8] = 0x55;
    assert_err(&bad_version, |err| matches!(err, FrameError::BadIpv4));

    let mut bad_total = v9_packet();
    bad_total[2] = 0x00;
    bad_total[3] = 0x15;
    assert_err(&frame_bytes(0x10, 0, &bad_total), |err| {
        matches!(err, FrameError::BadIpv4)
    });
    assert_err(&frame_bytes(0x10, 0, &v9_packet()[..19]), |err| {
        matches!(err, FrameError::BadIpv4)
    });
    let mut tail = v9_packet();
    tail.push(0);
    assert_err(&frame_bytes(0x10, 0, &tail), |err| {
        matches!(err, FrameError::BadIpv4)
    });
    assert_err(&frame_bytes(0x00, 0, &[0x01]), |err| {
        matches!(
            err,
            FrameError::BadBodyLength {
                kind: "PADDING",
                length: 1
            }
        )
    });
    assert_err(&frame_bytes(0x21, 0, &[0, 0, 0, 1]), |err| {
        matches!(
            err,
            FrameError::BadBodyLength {
                kind: "CONFIG_ACK",
                length: 4
            }
        )
    });
    assert_err(&frame_bytes(0x31, 0, &[0, 0, 0]), |err| {
        matches!(
            err,
            FrameError::BadBodyLength {
                kind: "WINDOW",
                length: 3
            }
        )
    });

    assert_err(&frame_bytes(0x30, 0, &hex("00 01 FF")), |err| {
        matches!(err, FrameError::InvalidUtf8)
    });
    assert_err(&frame_bytes(0x20, 0, &hex("00 00 00 01 00 01")), |err| {
        matches!(err, FrameError::TruncatedTlv)
    });
    assert_err(
        &frame_bytes(0x20, 0, &hex("00 00 00 01 00 01 00 04 0A 40 00 02")),
        |err| {
            matches!(
                err,
                FrameError::BadTlvLength {
                    ty: 0x0001,
                    length: 4
                }
            )
        },
    );
    assert_err(
        &frame_bytes(0x20, 0, &hex("00 00 00 01 00 01 00 05 0A 40 00 02 21")),
        |err| {
            matches!(
                err,
                FrameError::BadPrefix {
                    ty: 0x0001,
                    prefix: 33
                }
            )
        },
    );
}

#[test]
fn tightened_max_frame_rejects_from_the_header() {
    let ping_bytes = hex("01 01 00 00 00 00 00 08 01 02 03 04 05 06 07 08");
    let tight = DecodeLimits { max_frame: 7 };
    assert!(matches!(
        decode_with(&ping_bytes, tight),
        Err(FrameError::FrameTooLong {
            length: 8,
            max_frame: 7
        })
    ));
    assert!(decode_with(&ping_bytes, DecodeLimits { max_frame: 8 }).is_ok());
    assert!(decode_with(
        &ping_bytes,
        DecodeLimits {
            max_frame: u32::MAX
        }
    )
    .is_ok());
    assert!(matches!(
        decode_with(
            &header(0x01, 0x01, 0, 65_536),
            DecodeLimits {
                max_frame: u32::MAX
            }
        ),
        Err(FrameError::FrameTooLong {
            length: 65_536,
            max_frame: 65_535
        })
    ));
}

/// F3: a failing padding fill returns [`FrameError::Random`] and no buffer.
#[test]
fn injected_padding_rng_failure_returns_random_and_no_buffer() {
    let result = encode_camouflage_with(&ping(), &CamouflageProfile::V1, |_| {
        Err(FrameError::Random {
            detail: "injected".to_owned(),
        })
    });
    match result {
        Err(FrameError::Random { detail }) => assert_eq!(detail, "injected"),
        Ok(buf) => panic!("encoder returned a buffer after RNG failure: {buf:?}"),
        Err(other) => panic!("unexpected error: {other:?}"),
    }
}

/// F3: `content_len` 54 pads with `pad_len` 0. Wire size 64, flag `0x0001`,
/// trailer `00 00`. The fill closure is not asked for octets.
#[test]
fn pad_len_zero_is_on_the_wire() {
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Disconnect {
            code: 1,
            reason: "x".repeat(52),
        },
    };
    assert_eq!(camouflage_pad_len(54, 64, 64, 255), Some(0));
    let mut fill_calls = 0usize;
    let bytes = encode_camouflage_with(&frame, &CamouflageProfile::V1, |buf| {
        fill_calls += 1;
        buf.fill(0xAB);
        Ok(())
    })
    .unwrap();
    assert_eq!(fill_calls, 0);
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[2..4], &[0x00, 0x01]);
    assert_eq!(&bytes[4..8], &56u32.to_be_bytes());
    assert_eq!(&bytes[62..64], &[0x00, 0x00]);
    assert_eq!(decode(&bytes).unwrap(), frame);
}

/// F3: TLV `MaxFrame(7)` is stored and does not cap this same frame.
/// The body is longer than 7 bytes. A caller-supplied limit of 7 still
/// rejects it, which is the limit the TLV did not replace.
#[test]
fn config_max_frame_tlv_does_not_change_the_decode_limit() {
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Config(Config {
            cfg_id: 1,
            tlvs: vec![Tlv::MaxFrame(7)],
        }),
    };
    let bytes = encode(&frame, None).unwrap();
    assert!(bytes.len() > 8 + 7);
    assert_eq!(decode(&bytes).unwrap(), frame);
    assert!(decode_with(&bytes, DecodeLimits { max_frame: 12 }).is_ok());
    assert!(matches!(
        decode_with(&bytes, DecodeLimits { max_frame: 7 }),
        Err(FrameError::FrameTooLong { max_frame: 7, .. })
    ));
}
