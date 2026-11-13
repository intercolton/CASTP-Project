//! Just enough of an IP header to route a packet.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 4, 6 or `None` for anything else (including an empty buffer).
pub fn version(pkt: &[u8]) -> Option<u8> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => Some(4),
        6 if pkt.len() >= 40 => Some(6),
        _ => None,
    }
}

/// Source address.
pub fn source(pkt: &[u8]) -> Option<IpAddr> {
    match version(pkt)? {
        4 => Some(IpAddr::V4(v4_at(pkt, 12))),
        _ => Some(IpAddr::V6(v6_at(pkt, 8))),
    }
}

/// Destination address.
pub fn destination(pkt: &[u8]) -> Option<IpAddr> {
    match version(pkt)? {
        4 => Some(IpAddr::V4(v4_at(pkt, 16))),
        _ => Some(IpAddr::V6(v6_at(pkt, 24))),
    }
}

fn v4_at(p: &[u8], at: usize) -> Ipv4Addr {
    Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3])
}

fn v6_at(p: &[u8], at: usize) -> Ipv6Addr {
    let mut b = [0u8; 16];
    b.copy_from_slice(&p[at..at + 16]);
    Ipv6Addr::from(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_addresses() {
        let mut v4 = vec![0u8; 20];
        v4[0] = 0x45;
        v4[12..16].copy_from_slice(&[10, 0, 0, 2]);
        v4[16..20].copy_from_slice(&[1, 1, 1, 1]);
        assert_eq!(version(&v4), Some(4));
        assert_eq!(source(&v4), Some("10.0.0.2".parse().unwrap()));
        assert_eq!(destination(&v4), Some("1.1.1.1".parse().unwrap()));

        let mut v6 = vec![0u8; 40];
        v6[0] = 0x60;
        v6[23] = 1;
        v6[39] = 2;
        assert_eq!(source(&v6), Some("::1".parse().unwrap()));
        assert_eq!(destination(&v6), Some("::2".parse().unwrap()));

        assert_eq!(version(&[]), None);
        assert_eq!(version(&[0x45; 10]), None);
        assert_eq!(version(&[0x20; 60]), None);
    }
}
