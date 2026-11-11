//! Interface and route setup through `ip` (iproute2), which an
//! administrator can read and repeat by hand.

use std::io;
use std::net::IpAddr;
use tokio::process::Command;

/// Runs `ip <args>`; a non-zero exit is an error carrying its stderr.
pub async fn ip(args: &[String]) -> io::Result<String> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .await
        .map_err(|e| io::Error::new(e.kind(), format!("cannot run ip (iproute2): {e}")))?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "ip {}: {}",
            args.join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

fn family(a: IpAddr) -> &'static str {
    if a.is_ipv4() {
        "-4"
    } else {
        "-6"
    }
}

/// Sets the MTU and brings the interface up.
pub async fn link_up(dev: &str, mtu: u16) -> io::Result<()> {
    ip(&s(&[
        "link",
        "set",
        "dev",
        dev,
        "mtu",
        &mtu.to_string(),
        "up",
    ]))
    .await?;
    Ok(())
}

/// Adds `addr/prefix` to `dev`.
pub async fn add_addr(dev: &str, addr: IpAddr, prefix: u8) -> io::Result<()> {
    ip(&s(&[
        family(addr),
        "addr",
        "add",
        &format!("{addr}/{prefix}"),
        "dev",
        dev,
    ]))
    .await?;
    Ok(())
}

/// Where a route sends traffic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Via {
    pub gateway: Option<IpAddr>,
    pub dev: String,
}

/// One route this process added; [`Routes::remove_all`] takes them back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddedRoute {
    pub dest: IpAddr,
    pub prefix: u8,
    pub via: Via,
}

fn route_args(verb: &str, r: &AddedRoute) -> Vec<String> {
    let mut a = s(&[family(r.dest), "route", verb]);
    a.push(format!("{}/{}", r.dest, r.prefix));
    if let Some(g) = r.via.gateway {
        a.push("via".into());
        a.push(g.to_string());
    }
    a.push("dev".into());
    a.push(r.via.dev.clone());
    a
}

/// Routes added by this process, removed again on [`Routes::remove_all`].
#[derive(Debug, Default)]
pub struct Routes {
    added: Vec<AddedRoute>,
}

impl Routes {
    /// Adds a route (replacing an identical one) and remembers it.
    pub async fn add(&mut self, dest: IpAddr, prefix: u8, via: Via) -> io::Result<()> {
        let r = AddedRoute { dest, prefix, via };
        ip(&route_args("replace", &r)).await?;
        self.added.push(r);
        Ok(())
    }

    /// Removes every route added here, newest first; errors are logged.
    pub async fn remove_all(&mut self) {
        while let Some(r) = self.added.pop() {
            if let Err(e) = ip(&route_args("del", &r)).await {
                tracing::warn!("removing route {}/{}: {e}", r.dest, r.prefix);
            }
        }
    }

    pub fn added(&self) -> &[AddedRoute] {
        &self.added
    }
}

/// How the kernel would reach `dst` right now: `ip route get`.
pub async fn route_get(dst: IpAddr) -> io::Result<Via> {
    let out = ip(&s(&[family(dst), "-o", "route", "get", &dst.to_string()])).await?;
    parse_route_get(&out).ok_or_else(|| io::Error::other(format!("cannot parse: {out}")))
}

/// Parses one line of `ip -o route get` output.
pub fn parse_route_get(line: &str) -> Option<Via> {
    let words: Vec<&str> = line.split_whitespace().collect();
    let after = |key: &str| {
        words
            .iter()
            .position(|w| *w == key)
            .and_then(|i| words.get(i + 1))
            .copied()
    };
    Some(Via {
        gateway: after("via").and_then(|g| g.parse().ok()),
        dev: after("dev")?.to_owned(),
    })
}

/// Points DNS for `dev` at `servers` with `resolvectl` (systemd-resolved).
pub async fn set_dns(dev: &str, servers: &[IpAddr]) -> io::Result<()> {
    let mut args = vec!["dns".to_owned(), dev.to_owned()];
    args.extend(servers.iter().map(ToString::to_string));
    let out = Command::new("resolvectl").args(&args).output().await?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "resolvectl: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_route_get() {
        let v =
            parse_route_get("1.1.1.1 via 192.168.1.1 dev eno1 src 192.168.1.10 uid 0 \\    cache")
                .unwrap();
        assert_eq!(v.gateway, Some("192.168.1.1".parse().unwrap()));
        assert_eq!(v.dev, "eno1");
        let v = parse_route_get("10.0.0.5 dev eth0 src 10.0.0.2 uid 0").unwrap();
        assert_eq!(v.gateway, None);
        assert_eq!(v.dev, "eth0");
        assert!(parse_route_get("garbage").is_none());
    }

    #[test]
    fn route_arguments() {
        let r = AddedRoute {
            dest: "0.0.0.0".parse().unwrap(),
            prefix: 1,
            via: Via {
                gateway: None,
                dev: "astp0".into(),
            },
        };
        assert_eq!(
            route_args("replace", &r).join(" "),
            "-4 route replace 0.0.0.0/1 dev astp0"
        );
        let r = AddedRoute {
            dest: "203.0.113.5".parse().unwrap(),
            prefix: 32,
            via: Via {
                gateway: Some("192.168.1.1".parse().unwrap()),
                dev: "eno1".into(),
            },
        };
        assert_eq!(
            route_args("del", &r).join(" "),
            "-4 route del 203.0.113.5/32 via 192.168.1.1 dev eno1"
        );
    }
}
