//! Which routes the client installs for a CONFIG (`docs/design/network.md`).

use astp_session::Route;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Where a planned route goes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// Through the tunnel device.
    Tunnel,
    /// Through whatever carried the traffic before the tunnel came up.
    Original,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Planned {
    pub dest: IpAddr,
    pub prefix: u8,
    pub target: Target,
}

fn contains(dest: IpAddr, prefix: u8, a: IpAddr) -> bool {
    match (dest, a) {
        (IpAddr::V4(n), IpAddr::V4(a)) => {
            let m = u32::MAX.checked_shl(32 - u32::from(prefix)).unwrap_or(0);
            u32::from(n) & m == u32::from(a) & m
        }
        (IpAddr::V6(n), IpAddr::V6(a)) => {
            let m = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
            u128::from(n) & m == u128::from(a) & m
        }
        _ => false,
    }
}

/// Routes to add, in order. `Original` routes come first so they are in
/// place before anything points at the tunnel:
///
/// - the server itself, when an included route covers it (otherwise the
///   tunnel's own packets would enter the tunnel);
/// - every excluded route;
/// - included routes through the tunnel, a default route split into two
///   halves (`0.0.0.0/1`, `128.0.0.0/1`) so the original default stays
///   untouched and comes back when the halves are removed.
pub fn plan(routes: &[Route], server: IpAddr) -> Vec<Planned> {
    let mut first = Vec::new();
    let mut tunnel = Vec::new();
    let mut covers_server = false;
    for r in routes {
        let (dest, prefix, include) = match *r {
            Route::V4 {
                dest,
                prefix,
                include,
            } => (IpAddr::V4(dest), prefix, include),
            Route::V6 {
                dest,
                prefix,
                include,
            } => (IpAddr::V6(dest), prefix, include),
        };
        if !include {
            first.push(Planned {
                dest,
                prefix,
                target: Target::Original,
            });
            continue;
        }
        covers_server |= contains(dest, prefix, server);
        if prefix == 0 {
            let (lo, hi): (IpAddr, IpAddr) = if dest.is_ipv4() {
                (
                    Ipv4Addr::new(0, 0, 0, 0).into(),
                    Ipv4Addr::new(128, 0, 0, 0).into(),
                )
            } else {
                (
                    Ipv6Addr::UNSPECIFIED.into(),
                    Ipv6Addr::from(1u128 << 127).into(),
                )
            };
            tunnel.push(Planned {
                dest: lo,
                prefix: 1,
                target: Target::Tunnel,
            });
            tunnel.push(Planned {
                dest: hi,
                prefix: 1,
                target: Target::Tunnel,
            });
        } else {
            tunnel.push(Planned {
                dest,
                prefix,
                target: Target::Tunnel,
            });
        }
    }
    let mut out = Vec::new();
    if covers_server {
        let host = if server.is_ipv4() { 32 } else { 128 };
        out.push(Planned {
            dest: server,
            prefix: host,
            target: Target::Original,
        });
    }
    out.extend(first);
    out.extend(tunnel);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str, prefix: u8, include: bool) -> Route {
        Route::V4 {
            dest: s.parse().unwrap(),
            prefix,
            include,
        }
    }

    #[test]
    fn default_route_is_split_and_the_server_bypasses_it() {
        let p = plan(
            &[v4("0.0.0.0", 0, true), v4("192.168.0.0", 16, false)],
            "203.0.113.5".parse().unwrap(),
        );
        let t: Vec<_> = p
            .iter()
            .map(|p| (p.dest.to_string(), p.prefix, p.target))
            .collect();
        assert_eq!(
            t,
            [
                ("203.0.113.5".to_string(), 32, Target::Original),
                ("192.168.0.0".to_string(), 16, Target::Original),
                ("0.0.0.0".to_string(), 1, Target::Tunnel),
                ("128.0.0.0".to_string(), 1, Target::Tunnel),
            ]
        );
    }

    #[test]
    fn split_tunnel_leaves_the_server_alone() {
        let p = plan(&[v4("10.0.0.0", 8, true)], "203.0.113.5".parse().unwrap());
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].target, Target::Tunnel);
        // ...unless the server is inside the routed range.
        let p = plan(
            &[v4("203.0.113.0", 24, true)],
            "203.0.113.5".parse().unwrap(),
        );
        assert_eq!(
            p[0],
            Planned {
                dest: "203.0.113.5".parse().unwrap(),
                prefix: 32,
                target: Target::Original
            }
        );
    }

    #[test]
    fn ipv6_default_is_split_too() {
        let p = plan(
            &[Route::V6 {
                dest: Ipv6Addr::UNSPECIFIED,
                prefix: 0,
                include: true,
            }],
            "2001:db8::1".parse().unwrap(),
        );
        assert_eq!(p.len(), 3);
        assert_eq!(p[2].dest, "8000::".parse::<IpAddr>().unwrap());
    }
}
