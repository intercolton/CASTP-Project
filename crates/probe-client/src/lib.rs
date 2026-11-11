//! Library side of `astp-probe`: network tests that the CLI and the
//! integration tests both drive.

pub mod netutil;
pub mod probes;
pub mod quic;
pub mod stream;
pub mod tlsutil;

pub use probe_common::error_chain;

use probe_common::config::{ClientConfig, TargetConfig, TargetRole};
use probe_common::ProbeEvent;

/// Which short tests to run.
#[derive(Debug, Clone, Copy, Default)]
pub struct Selection {
    pub dns: bool,
    pub tcp: bool,
    pub tls: bool,
    pub https: bool,
    pub h2: bool,
    pub quic: bool,
    pub h3: bool,
    pub download: bool,
    pub controls: bool,
    /// Bytes for the download test; 0 means 1 MiB.
    pub download_bytes: u64,
}

impl Selection {
    pub fn all() -> Self {
        Selection {
            dns: true,
            tcp: true,
            tls: true,
            https: true,
            h2: true,
            quic: true,
            h3: true,
            download: true,
            controls: true,
            download_bytes: 0,
        }
    }
}

/// Runs the selected tests one after another (spec 6.2: tests must not
/// overlap when that would blur what the network did), calling `sink` with
/// each event as soon as it is ready.
pub async fn run_quick(cfg: &ClientConfig, sel: Selection, mut sink: impl FnMut(ProbeEvent)) {
    let ctx = ctx(cfg);
    for t in &cfg.targets {
        run_target(&ctx, t, sel, &mut sink).await;
    }
    if sel.controls {
        for c in &cfg.controls {
            sink(probes::control(&ctx, c).await);
        }
    }
}

fn ctx(cfg: &ClientConfig) -> probes::Ctx {
    probes::Ctx {
        probe_id: cfg.client.id.clone(),
        network_id: cfg.client.network_id.clone(),
        iface: cfg.client.bind_interface.clone(),
        limits: cfg.limits.clone(),
        pair_id: None,
    }
}

/// Long sessions, one after another: for each target with TLS, a download
/// session if its role takes downloads and an upload session if it takes
/// uploads. Then one paired probe per (uplink, downlink) pair of targets:
/// upload to the first and download from the second at the same time,
/// as split-path traffic would flow, with a shared `pair_id`.
/// `progress(target, seconds, bytes)` reports a running session.
pub async fn run_long(
    cfg: &ClientConfig,
    plan: stream::SessionPlan,
    mut sink: impl FnMut(ProbeEvent),
    progress: impl FnMut(&str, u64, u64),
) {
    let ctx = ctx(cfg);
    // Both halves of a pair report through the same callback.
    let progress = std::cell::RefCell::new(progress);
    let report = |id: &str, s, b| (progress.borrow_mut())(id, s, b);
    for t in cfg.targets.iter().filter(|t| t.enable_tls) {
        if t.role.down() {
            sink(stream::long_session(&ctx, t, plan, |s, b| report(&t.id, s, b)).await);
        }
        if t.role.up() {
            sink(stream::upload_session(&ctx, t, plan, |s, b| report(&t.id, s, b)).await);
        }
    }
    for (up, down) in pairs(cfg) {
        let mut pctx = ctx.clone();
        pctx.pair_id = Some(ProbeEvent::new_test_id());
        let (u, d) = tokio::join!(
            stream::upload_session(&pctx, up, plan, |s, b| report(&up.id, s, b)),
            stream::long_session(&pctx, down, plan, |s, b| report(&down.id, s, b)),
        );
        sink(u);
        sink(d);
    }
}

/// (uplink, downlink) target pairs for the paired cascade probe.
pub fn pairs(cfg: &ClientConfig) -> Vec<(&TargetConfig, &TargetConfig)> {
    let with = |r| {
        cfg.targets
            .iter()
            .filter(move |t: &&TargetConfig| t.enable_tls && t.role == r)
    };
    with(TargetRole::Uplink)
        .flat_map(|u| with(TargetRole::Downlink).map(move |d| (u, d)))
        .collect()
}

async fn run_target(
    ctx: &probes::Ctx,
    t: &TargetConfig,
    sel: Selection,
    sink: &mut impl FnMut(ProbeEvent),
) {
    if sel.dns && t.host.parse::<std::net::IpAddr>().is_err() {
        sink(probes::dns(ctx, t).await);
    }
    if sel.tcp && t.enable_tcp {
        sink(probes::tcp(ctx, t).await);
    }
    if sel.tls && t.enable_tls {
        sink(probes::tls(ctx, t).await);
    }
    if sel.https && t.enable_tls {
        sink(probes::https_get(ctx, t).await);
    }
    if sel.h2 && t.enable_h2 {
        sink(probes::h2(ctx, t).await);
    }
    if sel.quic && t.enable_quic {
        sink(quic::quic_handshake(ctx, t).await);
    }
    if sel.h3 && t.enable_h3 {
        sink(quic::h3(ctx, t).await);
    }
    if sel.download && t.enable_tls && t.role.down() {
        let bytes = if sel.download_bytes == 0 {
            1024 * 1024
        } else {
            sel.download_bytes
        };
        sink(stream::download(ctx, t, bytes).await);
    }
}
