//! Session parameters carried in `CONFIG` (and `ROUTE_UPDATE`) TLVs.

use astp_frame::{Config, Tlv};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::Duration;

/// Default `keepalive`: a PING after this long without sending anything.
pub const DEFAULT_KEEPALIVE: Duration = Duration::from_secs(25);
/// Default `idle_timeout`: give up after this long without receiving anything.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(90);
/// Default tunnel MTU.
pub const DEFAULT_MTU: u16 = 1400;

/// A route pushed to the client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Route {
    V4 {
        dest: Ipv4Addr,
        prefix: u8,
        /// `true`: through the tunnel. `false`: around it.
        include: bool,
    },
    V6 {
        dest: Ipv6Addr,
        prefix: u8,
        include: bool,
    },
}

/// What the server tells the client in `CONFIG`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionParams {
    pub addr4: Option<(Ipv4Addr, u8)>,
    pub addr6: Option<(Ipv6Addr, u8)>,
    pub mtu: u16,
    pub dns4: Vec<Ipv4Addr>,
    pub dns6: Vec<Ipv6Addr>,
    pub routes: Vec<Route>,
    pub keepalive: Duration,
    pub idle_timeout: Duration,
    /// Not a secret; identifies the session in logs.
    pub session_id: [u8; 16],
}

impl Default for SessionParams {
    fn default() -> Self {
        SessionParams {
            addr4: None,
            addr6: None,
            mtu: DEFAULT_MTU,
            dns4: Vec::new(),
            dns6: Vec::new(),
            routes: Vec::new(),
            keepalive: DEFAULT_KEEPALIVE,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
            session_id: [0; 16],
        }
    }
}

fn ms(d: Duration) -> u32 {
    u32::try_from(d.as_millis()).unwrap_or(u32::MAX)
}

impl SessionParams {
    /// The TLV list for `CONFIG`.
    pub fn to_tlvs(&self) -> Vec<Tlv> {
        let mut t = Vec::new();
        if let Some((addr, prefix)) = self.addr4 {
            t.push(Tlv::Addr4 { addr, prefix });
        }
        if let Some((addr, prefix)) = self.addr6 {
            t.push(Tlv::Addr6 { addr, prefix });
        }
        t.push(Tlv::Mtu(self.mtu));
        t.extend(self.dns4.iter().map(|a| Tlv::Dns4(*a)));
        t.extend(self.dns6.iter().map(|a| Tlv::Dns6(*a)));
        t.extend(self.routes.iter().map(route_tlv));
        t.push(Tlv::Keepalive(ms(self.keepalive)));
        t.push(Tlv::IdleTimeout(ms(self.idle_timeout)));
        t.push(Tlv::SessionId(self.session_id));
        t
    }

    /// `CONFIG` with this proposal id.
    pub fn to_config(&self, cfg_id: u32) -> Config {
        Config {
            cfg_id,
            tlvs: self.to_tlvs(),
        }
    }

    /// Reads a `CONFIG`. Missing values keep their defaults; unknown TLVs
    /// are ignored; a zero keepalive or idle timeout is rejected.
    pub fn from_tlvs(tlvs: &[Tlv]) -> Result<Self, String> {
        let mut p = SessionParams::default();
        for t in tlvs {
            match t {
                Tlv::Addr4 { addr, prefix } => p.addr4 = Some((*addr, *prefix)),
                Tlv::Addr6 { addr, prefix } => p.addr6 = Some((*addr, *prefix)),
                Tlv::Mtu(m) => p.mtu = *m,
                Tlv::Dns4(a) => p.dns4.push(*a),
                Tlv::Dns6(a) => p.dns6.push(*a),
                Tlv::Route4 { .. } | Tlv::Route6 { .. } => p.routes.extend(tlv_route(t)),
                Tlv::Keepalive(v) => p.keepalive = Duration::from_millis(u64::from(*v)),
                Tlv::IdleTimeout(v) => p.idle_timeout = Duration::from_millis(u64::from(*v)),
                Tlv::SessionId(id) => p.session_id = *id,
                _ => {}
            }
        }
        if p.keepalive.is_zero() || p.idle_timeout.is_zero() {
            return Err("keepalive and idle_timeout must be > 0".into());
        }
        if p.mtu < 576 {
            return Err(format!("mtu {} is below 576", p.mtu));
        }
        Ok(p)
    }
}

fn route_tlv(r: &Route) -> Tlv {
    match *r {
        Route::V4 {
            dest,
            prefix,
            include,
        } => Tlv::Route4 {
            dest,
            prefix,
            include,
        },
        Route::V6 {
            dest,
            prefix,
            include,
        } => Tlv::Route6 {
            dest,
            prefix,
            include,
        },
    }
}

/// Routes in a `ROUTE_UPDATE` or `CONFIG` TLV list.
pub fn routes_of(tlvs: &[Tlv]) -> Vec<Route> {
    tlvs.iter().filter_map(tlv_route).collect()
}

fn tlv_route(t: &Tlv) -> Option<Route> {
    match *t {
        Tlv::Route4 {
            dest,
            prefix,
            include,
        } => Some(Route::V4 {
            dest,
            prefix,
            include,
        }),
        Tlv::Route6 {
            dest,
            prefix,
            include,
        } => Some(Route::V6 {
            dest,
            prefix,
            include,
        }),
        _ => None,
    }
}

/// Encodes routes for a `ROUTE_UPDATE`.
pub fn route_tlvs(routes: &[Route]) -> Vec<Tlv> {
    routes.iter().map(route_tlv).collect()
}
