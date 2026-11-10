//! Round-trips that are not pinned to vectors V1–V12.

use std::net::{Ipv4Addr, Ipv6Addr};

use astp_frame::{
    decode, encode, encode_camouflage, encode_camouflage_with, is_known_tlv, CamouflageProfile,
    Config, Frame, FrameBody, FrameError, Ipv4Packet, Ipv6Packet, RouteUpdate, Tlv,
};

fn round_trip(frame: &Frame, pad: Option<&[u8]>) {
    let bytes = encode(frame, pad).unwrap();
    assert_eq!(decode(&bytes).unwrap(), *frame);
}

fn ipv4(total: u16, src: [u8; 4]) -> Ipv4Packet {
    let mut bytes = vec![0u8; usize::from(total)];
    bytes[0] = 0x45;
    bytes[2..4].copy_from_slice(&total.to_be_bytes());
    bytes[8] = 64;
    bytes[12..16].copy_from_slice(&src);
    Ipv4Packet::new(bytes).unwrap()
}

fn ipv6(payload_len: u16) -> Ipv6Packet {
    let mut bytes = vec![0u8; 40 + usize::from(payload_len)];
    bytes[0] = 0x60;
    bytes[4..6].copy_from_slice(&payload_len.to_be_bytes());
    bytes[7] = 64;
    Ipv6Packet::new(bytes).unwrap()
}

#[test]
fn every_body_round_trips_with_both_flags_and_explicit_pad() {
    let frames = vec![
        Frame {
            key_epoch: None,
            body: FrameBody::Padding,
        },
        Frame {
            key_epoch: Some(7),
            body: FrameBody::Ping([9, 8, 7, 6, 5, 4, 3, 2]),
        },
        Frame {
            key_epoch: None,
            body: FrameBody::Pong([1, 1, 1, 1, 1, 1, 1, 2]),
        },
        Frame {
            key_epoch: Some(1),
            body: FrameBody::TunIpv4(ipv4(20, [224, 0, 0, 1])),
        },
        Frame {
            key_epoch: None,
            body: FrameBody::TunIpv6(ipv6(0)),
        },
        Frame {
            key_epoch: Some(3),
            body: FrameBody::TunIpv6(ipv6(8)),
        },
        Frame {
            key_epoch: None,
            body: FrameBody::Config(sample_config()),
        },
        Frame {
            key_epoch: None,
            body: FrameBody::ConfigAck {
                cfg_id: 99,
                code: 9,
            },
        },
        Frame {
            key_epoch: Some(4),
            body: FrameBody::RouteUpdate(RouteUpdate {
                tlvs: vec![
                    Tlv::Route4 {
                        dest: Ipv4Addr::UNSPECIFIED,
                        prefix: 0,
                        include: true,
                    },
                    Tlv::Raw {
                        ty: 0x000C,
                        value: vec![0xAA, 0xBB],
                    },
                ],
            }),
        },
        Frame {
            key_epoch: None,
            body: FrameBody::RouteUpdate(RouteUpdate { tlvs: Vec::new() }),
        },
        Frame {
            key_epoch: None,
            body: FrameBody::Disconnect {
                code: 7,
                reason: String::new(),
            },
        },
        Frame {
            key_epoch: Some(2),
            body: FrameBody::Disconnect {
                code: 1,
                reason: "byeé".to_owned(),
            },
        },
        Frame {
            key_epoch: None,
            body: FrameBody::Window { credit: u32::MAX },
        },
        Frame {
            key_epoch: Some(0),
            body: FrameBody::Window { credit: 0 },
        },
    ];
    for frame in &frames {
        round_trip(frame, None);
        round_trip(frame, Some(&[]));
        round_trip(frame, Some(&[0x11, 0x22]));
    }
}

#[test]
fn both_flags_use_the_documented_byte_order() {
    let frame = Frame {
        key_epoch: Some(0x09),
        body: FrameBody::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
    };
    let bytes = encode(&frame, Some(&[0x11, 0x22])).unwrap();
    assert_eq!(
        bytes,
        vec![
            0x01, 0x01, 0x00, 0x03, 0x00, 0x00, 0x00, 0x0D, 0x09, 0x01, 0x02, 0x03, 0x04, 0x05,
            0x06, 0x07, 0x08, 0x11, 0x22, 0x00, 0x02,
        ]
    );
    assert_eq!(decode(&bytes).unwrap(), frame);
}

#[test]
fn reserved_tlvs_stay_raw_and_are_not_known_types() {
    assert!(!is_known_tlv(0x000C));
    assert!(!is_known_tlv(0x000D));
    assert!(is_known_tlv(0x0001));
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Config(Config {
            cfg_id: 1,
            tlvs: vec![
                Tlv::Raw {
                    ty: 0x000C,
                    value: vec![1, 2, 3],
                },
                Tlv::Raw {
                    ty: 0x000D,
                    value: Vec::new(),
                },
                Tlv::Raw {
                    ty: 0x00FF,
                    value: vec![9],
                },
            ],
        }),
    };
    round_trip(&frame, None);
    assert!(matches!(
        encode(
            &Frame {
                key_epoch: None,
                body: FrameBody::Config(Config {
                    cfg_id: 1,
                    tlvs: vec![Tlv::Raw {
                        ty: 0x0001,
                        value: vec![0; 5],
                    }],
                }),
            },
            None
        ),
        Err(FrameError::KnownTlvAsRaw { ty: 0x0001 })
    ));
}

#[test]
fn ipv6_and_route_failures_and_a_legal_tail_free_ipv4() {
    let mut short = vec![0u8; 39];
    short[0] = 0x60;
    assert!(Ipv6Packet::new(short).is_err());

    let mut bad_version = vec![0u8; 40];
    bad_version[0] = 0x50;
    assert!(matches!(
        Ipv6Packet::new(bad_version),
        Err(FrameError::BadIpv6)
    ));

    let mut mismatch = vec![0u8; 41];
    mismatch[0] = 0x60;
    assert!(matches!(
        Ipv6Packet::new(mismatch),
        Err(FrameError::BadIpv6)
    ));

    let packet = ipv4(21, [10, 0, 0, 1]);
    assert_eq!(packet.as_bytes().len(), 21);
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::TunIpv4(packet),
    };
    round_trip(&frame, None);

    let bad_route = Frame {
        key_epoch: None,
        body: FrameBody::RouteUpdate(RouteUpdate {
            tlvs: vec![Tlv::Route6 {
                dest: Ipv6Addr::UNSPECIFIED,
                prefix: 129,
                include: false,
            }],
        }),
    };
    assert!(matches!(
        encode(&bad_route, None),
        Err(FrameError::BadPrefix {
            ty: 0x0007,
            prefix: 129
        })
    ));

    let mut flag = encode(
        &Frame {
            key_epoch: None,
            body: FrameBody::RouteUpdate(RouteUpdate {
                tlvs: vec![Tlv::Route4 {
                    dest: Ipv4Addr::new(10, 0, 0, 0),
                    prefix: 8,
                    include: true,
                }],
            }),
        },
        None,
    )
    .unwrap();
    *flag.last_mut().unwrap() = 2;
    assert!(matches!(
        decode(&flag),
        Err(FrameError::BadRouteFlag {
            ty: 0x0006,
            flag: 2
        })
    ));
}

#[test]
fn key_epoch_counts_toward_camouflage_content_len() {
    let frame = Frame {
        key_epoch: Some(7),
        body: FrameBody::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
    };
    assert_eq!(camouflage_content(&frame), 9);
    let bytes = encode_camouflage_with(&frame, &CamouflageProfile::V1, |buf| {
        assert_eq!(buf.len(), 45);
        buf.fill(0xAB);
        Ok(())
    })
    .unwrap();
    assert_eq!(bytes.len(), 64);
    assert_eq!(&bytes[2..4], &0x0003u16.to_be_bytes());
    assert_eq!(decode(&bytes).unwrap(), frame);
}

fn camouflage_content(frame: &Frame) -> usize {
    let body = match &frame.body {
        FrameBody::Ping(_) | FrameBody::Pong(_) => 8,
        _ => panic!("test helper"),
    };
    body + usize::from(frame.key_epoch.is_some())
}

#[test]
fn camouflage_rng_path_round_trips_without_a_fixed_pad() {
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Pong([4, 5, 6, 7, 8, 9, 10, 11]),
    };
    let bytes = encode_camouflage(&frame).unwrap();
    assert_eq!(bytes.len(), 64);
    assert_eq!(decode(&bytes).unwrap(), frame);
    let aligned = Frame {
        key_epoch: None,
        body: FrameBody::Disconnect {
            code: 1,
            reason: "x".repeat(54),
        },
    };
    // body is 2 + 54 = 56, wire 64, already aligned: no PAD flag.
    let plain = encode_camouflage(&aligned).unwrap();
    assert_eq!(plain.len(), 64);
    assert_eq!(&plain[2..4], &[0, 0]);
    assert_eq!(decode(&plain).unwrap(), aligned);
}

#[test]
fn padding_that_does_not_fit_in_the_length_field_is_rejected() {
    let frame = Frame {
        key_epoch: None,
        body: FrameBody::Padding,
    };
    let pad = vec![0xAB; 65_536];
    assert!(matches!(
        encode(&frame, Some(&pad)),
        Err(FrameError::BadPadding)
    ));
    let almost = vec![0x11; 65_534];
    assert!(matches!(
        encode(&frame, Some(&almost)),
        Err(FrameError::FrameTooLong { .. })
    ));
}

#[test]
fn trailing_byte_and_short_header_and_bad_body_lengths() {
    let mut ping = encode(
        &Frame {
            key_epoch: None,
            body: FrameBody::Ping([0; 8]),
        },
        None,
    )
    .unwrap();
    ping.push(0);
    assert!(matches!(
        decode(&ping),
        Err(FrameError::TrailingBytes { extra: 1 })
    ));
    assert!(matches!(decode(&[0x01, 0x01]), Err(FrameError::Incomplete)));
    let mut short_ping = encode(
        &Frame {
            key_epoch: None,
            body: FrameBody::Ping([0; 8]),
        },
        None,
    )
    .unwrap();
    short_ping.pop();
    short_ping[7] = 7;
    assert!(matches!(
        decode(&short_ping),
        Err(FrameError::BadBodyLength {
            kind: "PING",
            length: 7
        })
    ));
}

fn sample_config() -> Config {
    Config {
        cfg_id: 0x11,
        tlvs: vec![
            Tlv::Addr4 {
                addr: Ipv4Addr::new(10, 64, 0, 2),
                prefix: 32,
            },
            Tlv::Addr6 {
                addr: Ipv6Addr::new(0xfd00, 0x17, 0x0530, 0, 0, 0, 0, 1),
                prefix: 128,
            },
            Tlv::Mtu(1280),
            Tlv::Dns4(Ipv4Addr::new(1, 1, 1, 1)),
            Tlv::Dns6(Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111)),
            Tlv::Route4 {
                dest: Ipv4Addr::UNSPECIFIED,
                prefix: 0,
                include: true,
            },
            Tlv::Route6 {
                dest: Ipv6Addr::UNSPECIFIED,
                prefix: 0,
                include: false,
            },
            Tlv::Keepalive(15_000),
            Tlv::IdleTimeout(60_000),
            Tlv::SessionId([0xAB; 16]),
            Tlv::MaxFrame(65_535),
        ],
    }
}
