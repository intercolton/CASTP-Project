//! Scheduled tests (`astp-probe run`): quick tests every
//! `quick_interval_seconds` and long sessions every `long_interval_seconds`,
//! each interval jittered by `jitter_percent`, until stopped or until the
//! campaign length runs out.
//!
//! Tests never overlap (spec 6.2): one loop runs whatever is due next and
//! waits for it to finish. A long session that is due while quick tests
//! run starts right after them, and the other way round.

use crate::stream::SessionPlan;
use crate::{run_long, run_quick, Selection};
use probe_common::config::ClientConfig;
use probe_common::ProbeEvent;
use rand::Rng;
use std::future::Future;
use std::time::Duration;
use tokio::time::Instant;

/// When and how to run, independent of the TOML so tests can use short
/// intervals.
#[derive(Debug, Clone, Copy)]
pub struct Schedule {
    pub quick_every: Duration,
    pub long_every: Duration,
    pub long_plan: SessionPlan,
    /// 0..=50: each wait is the interval ± this share of it.
    pub jitter_percent: u8,
    /// Stop after this long (a measurement campaign); `None` runs until stopped.
    pub campaign: Option<Duration>,
    /// Skip long sessions altogether.
    pub no_long: bool,
}

impl Schedule {
    pub fn from_config(cfg: &ClientConfig) -> Self {
        let s = &cfg.schedule;
        Schedule {
            quick_every: Duration::from_secs(s.quick_interval_seconds),
            long_every: Duration::from_secs(s.long_interval_seconds),
            long_plan: SessionPlan {
                seconds: s.long_duration_seconds,
                ..SessionPlan::default()
            },
            jitter_percent: s.jitter_percent,
            campaign: None,
            no_long: false,
        }
    }
}

/// `interval` ± `percent`% (uniform), never below 1 ms.
pub fn jittered(interval: Duration, percent: u8, rng: &mut impl Rng) -> Duration {
    let spread = interval.as_secs_f64() * f64::from(percent.min(50)) / 100.0;
    let offset = if spread > 0.0 {
        rng.random_range(-spread..=spread)
    } else {
        0.0
    };
    Duration::from_secs_f64((interval.as_secs_f64() + offset).max(0.001))
}

/// What one pass of the loop ran.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ran {
    Quick,
    Long,
}

/// Runs the schedule until `stop` resolves or the campaign ends. Quick
/// tests run first, at once; the first long session follows one jittered
/// long interval later. `sink` gets every event; `on_run` is told what ran
/// and when it finished. A test in progress when `stop` fires is
/// abandoned (its event is lost), so a stop is never held up by a long
/// session.
pub async fn run_scheduled(
    cfg: &ClientConfig,
    sched: Schedule,
    mut sink: impl FnMut(ProbeEvent),
    mut on_run: impl FnMut(Ran),
    stop: impl Future<Output = ()>,
) {
    let mut rng = rand::rng();
    let start = Instant::now();
    let end = sched.campaign.map(|c| start + c);
    let mut next_quick = start;
    let mut next_long = start + jittered(sched.long_every, sched.jitter_percent, &mut rng);
    tokio::pin!(stop);
    loop {
        let due = if sched.no_long {
            next_quick
        } else {
            next_quick.min(next_long)
        };
        if end.is_some_and(|e| due >= e) {
            tracing::info!("campaign finished");
            return;
        }
        tokio::select! {
            _ = &mut stop => return,
            _ = tokio::time::sleep_until(due) => {}
        }
        // Quick tests win a tie: they are short and the long session follows.
        let ran = if next_quick <= next_long || sched.no_long {
            let work = run_quick(cfg, Selection::all(), &mut sink);
            tokio::select! {
                _ = &mut stop => return,
                _ = work => {}
            }
            next_quick =
                Instant::now() + jittered(sched.quick_every, sched.jitter_percent, &mut rng);
            Ran::Quick
        } else {
            let work = run_long(cfg, sched.long_plan, &mut sink, |t, secs, bytes| {
                tracing::info!(target_id = t, secs, bytes, "long session running");
            });
            tokio::select! {
                _ = &mut stop => return,
                _ = work => {}
            }
            next_long = Instant::now() + jittered(sched.long_every, sched.jitter_percent, &mut rng);
            Ran::Long
        };
        on_run(ran);
    }
}

/// Parses `90s`, `30m`, `24h`, `14d` (a bare number is seconds).
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let s = s.trim();
    let split = s.find(|c: char| !c.is_ascii_digit()).unwrap_or(s.len());
    let (num, unit) = s.split_at(split);
    let n: u64 = num
        .parse()
        .map_err(|_| format!("{s:?} is not a duration like 30m, 24h or 14d"))?;
    let mult = match unit {
        "" | "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        _ => return Err(format!("unknown unit {unit:?} in {s:?}: use s, m, h or d")),
    };
    n.checked_mul(mult)
        .map(Duration::from_secs)
        .filter(|d| !d.is_zero())
        .ok_or_else(|| format!("{s:?} is zero or too long"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_bounds() {
        let mut rng = rand::rng();
        let base = Duration::from_secs(300);
        for _ in 0..1000 {
            let d = jittered(base, 10, &mut rng);
            assert!(
                d >= Duration::from_secs(270) && d <= Duration::from_secs(330),
                "{d:?}"
            );
        }
        assert_eq!(jittered(base, 0, &mut rng), base);
        // Capped at 50 %.
        for _ in 0..1000 {
            assert!(jittered(base, 200, &mut rng) >= Duration::from_secs(150));
        }
    }

    #[test]
    fn durations() {
        assert_eq!(parse_duration("90").unwrap(), Duration::from_secs(90));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
        assert_eq!(parse_duration("24h").unwrap(), Duration::from_secs(86_400));
        assert_eq!(
            parse_duration("14d").unwrap(),
            Duration::from_secs(14 * 86_400)
        );
        for bad in ["", "h", "0h", "5w", "-1h", "1.5h"] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }
}
