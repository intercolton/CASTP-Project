//! Real device test. Skipped (passes with a note) without root,
//! `/dev/net/tun` or `ip`: CI runners usually have none of them.

use astp_tun::{netcfg, Tun};
use std::time::Duration;

fn ipv4_header(src: [u8; 4], dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
    let len = 20 + payload.len();
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    p[2..4].copy_from_slice(&(len as u16).to_be_bytes());
    p[8] = 64;
    p[9] = proto;
    p[12..16].copy_from_slice(&src);
    p[16..20].copy_from_slice(&dst);
    let c = checksum(&p);
    p[10..12].copy_from_slice(&c.to_be_bytes());
    p.extend_from_slice(payload);
    p
}

fn checksum(b: &[u8]) -> u16 {
    let mut sum = 0u32;
    for c in b.chunks(2) {
        let w = u16::from_be_bytes([c[0], *c.get(1).unwrap_or(&0)]);
        sum += u32::from(w);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

#[tokio::test]
async fn tun_device_round_trip() {
    let tun = match Tun::create("astpt%d") {
        Ok(t) => t,
        Err(e) => {
            eprintln!("skipped: cannot create a TUN device here ({e})");
            return;
        }
    };
    let dev = tun.name().to_owned();
    if let Err(e) = netcfg::add_addr(&dev, "10.199.0.1".parse().unwrap(), 24).await {
        eprintln!("skipped: cannot configure {dev} ({e})");
        return;
    }
    netcfg::link_up(&dev, 1400).await.unwrap();

    // Kernel → device: a datagram to a peer on the tunnel subnet.
    let sock = tokio::net::UdpSocket::bind("10.199.0.1:0").await.unwrap();
    sock.send_to(b"hello", "10.199.0.2:9").await.unwrap();
    let mut buf = vec![0u8; 2000];
    let pkt = loop {
        let n = tokio::time::timeout(Duration::from_secs(5), tun.recv(&mut buf))
            .await
            .expect("packet from the kernel")
            .unwrap();
        let p = buf[..n].to_vec();
        // Skip router solicitations and the like.
        if astp_tun::packet::version(&p) == Some(4) && p[9] == 17 {
            break p;
        }
    };
    assert_eq!(
        astp_tun::packet::destination(&pkt),
        Some("10.199.0.2".parse().unwrap())
    );
    assert!(pkt.ends_with(b"hello"));

    // Device → kernel: an ICMP echo request to our address gets a reply.
    let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
    icmp.extend_from_slice(b"ping");
    let c = checksum(&icmp);
    icmp[2..4].copy_from_slice(&c.to_be_bytes());
    let req = ipv4_header([10, 199, 0, 2], [10, 199, 0, 1], 1, &icmp);
    tun.send(&req).await.unwrap();
    let reply = loop {
        let n = tokio::time::timeout(Duration::from_secs(5), tun.recv(&mut buf))
            .await
            .expect("echo reply")
            .unwrap();
        let p = buf[..n].to_vec();
        if astp_tun::packet::version(&p) == Some(4) && p[9] == 1 {
            break p;
        }
    };
    assert_eq!(reply[20], 0, "ICMP echo reply");
    assert_eq!(
        astp_tun::packet::destination(&reply),
        Some("10.199.0.2".parse().unwrap())
    );
}
