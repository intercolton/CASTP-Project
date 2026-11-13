//! Reads probe journals and turns them into numbers (spec 6.4, 9).
//!
//! - [`Journal::load`] reads a JSONL file and its rotated siblings.
//! - [`Journal::since`] keeps a time window.
//! - [`join`] pairs each client event with the server events that carry
//!   the same `test_id`, so a report can say whether the server saw what
//!   the client tried.
//! - [`summarize`] counts outcomes per target, test type and transport,
//!   with error codes, the phase a failure stopped at and durations.
//! - [`pairs`] groups the two halves of paired cascade probes.
//!
//! Nothing here interprets causes: a `tcp_timeout` stays a timeout.

#![forbid(unsafe_code)]

use probe_common::jsonl::{read_events, rotated_set};
use probe_common::timefmt::parse_rfc3339;
use probe_common::{Direction, ErrorCode, Phase, ProbeEvent, Side, TestType, Transport};
use serde::Serialize;
use std::collections::{BTreeMap, HashMap};
use std::io;
use std::path::{Path, PathBuf};
use time::OffsetDateTime;

/// Events read from one or more journals.
#[derive(Debug, Default, Clone)]
pub struct Journal {
    pub events: Vec<ProbeEvent>,
    /// Lines that were not valid events, as `file:line: error`.
    pub bad_lines: Vec<String>,
    /// Files that were read, oldest first.
    pub files: Vec<PathBuf>,
}

impl Journal {
    /// Reads `path` and up to `keep_files` rotated siblings
    /// (`path.1`, `path.2`, …), oldest first. A missing journal is empty,
    /// not an error.
    pub fn load(path: &Path, keep_files: usize) -> io::Result<Journal> {
        let mut j = Journal::default();
        for f in rotated_set(path, keep_files) {
            match read_events(&f) {
                Ok((events, bad)) => {
                    j.events.extend(events);
                    j.bad_lines.extend(
                        bad.into_iter()
                            .map(|b| format!("{}:{}: {}", f.display(), b.line_no, b.error)),
                    );
                    j.files.push(f);
                }
                // Rotated away between listing and reading.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
        Ok(j)
    }

    /// Adds another journal's events.
    pub fn merge(&mut self, other: Journal) {
        self.events.extend(other.events);
        self.bad_lines.extend(other.bad_lines);
        self.files.extend(other.files);
    }

    /// Keeps events at or after `cutoff`. Events whose timestamp does not
    /// parse cannot be here: [`ProbeEvent::validate`] rejected them.
    pub fn since(mut self, cutoff: OffsetDateTime) -> Journal {
        self.events
            .retain(|e| parse_rfc3339(&e.timestamp).is_some_and(|t| t >= cutoff));
        self
    }

    pub fn client(&self) -> impl Iterator<Item = &ProbeEvent> {
        self.events.iter().filter(|e| e.side == Side::Client)
    }

    pub fn server(&self) -> impl Iterator<Item = &ProbeEvent> {
        self.events.iter().filter(|e| e.side == Side::Server)
    }
}

/// A client event and what the server logged for the same test.
#[derive(Debug, Clone)]
pub struct Joined<'a> {
    pub client: &'a ProbeEvent,
    pub server: Vec<&'a ProbeEvent>,
}

/// Test types whose requests carry the client's `test_id` to the server.
/// The others (DNS, TCP connect, TLS and QUIC handshakes) never get that
/// far: the server logs them under an id of its own.
pub fn joinable(tt: TestType) -> bool {
    matches!(
        tt,
        TestType::HttpsGet
            | TestType::H2Request
            | TestType::H3Request
            | TestType::Echo
            | TestType::Download
            | TestType::LongSession
    )
}

/// Pairs each joinable, non-control client event with the server events
/// carrying its `test_id`.
pub fn join<'a>(
    client: impl IntoIterator<Item = &'a ProbeEvent>,
    server: impl IntoIterator<Item = &'a ProbeEvent>,
) -> Vec<Joined<'a>> {
    let mut by_id: HashMap<&str, Vec<&ProbeEvent>> = HashMap::new();
    for s in server {
        by_id.entry(s.test_id.as_str()).or_default().push(s);
    }
    client
        .into_iter()
        .filter(|c| joinable(c.test_type) && !c.control)
        .map(|c| Joined {
            client: c,
            server: by_id.get(c.test_id.as_str()).cloned().unwrap_or_default(),
        })
        .collect()
}

/// How a joined test looks from both ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinOutcome {
    /// Client succeeded.
    ClientOk,
    /// Client failed and the server logged the request: the path reached
    /// the server and broke afterwards (or on the way back).
    FailedServerSaw,
    /// Client failed and the server has no record of the request.
    FailedServerSilent,
}

impl Joined<'_> {
    pub fn outcome(&self) -> JoinOutcome {
        if self.client.success {
            JoinOutcome::ClientOk
        } else if self.server.is_empty() {
            JoinOutcome::FailedServerSilent
        } else {
            JoinOutcome::FailedServerSaw
        }
    }
}

/// Key of a statistics bucket.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BucketKey {
    pub target_id: String,
    pub test_type: TestType,
    pub transport: Transport,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<Direction>,
    pub control: bool,
}

/// Outcomes of one kind of test against one target.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Bucket {
    pub total: u64,
    pub ok: u64,
    pub errors: BTreeMap<ErrorCode, u64>,
    /// Phase reached by failed tests: where they stopped.
    pub failed_at: BTreeMap<Phase, u64>,
    /// Duration percentiles of successful tests, ms.
    pub ok_ms: Percentiles,
    /// Networks the events came from.
    pub networks: Vec<String>,
}

impl Bucket {
    /// Share of successes, 0..=1; `None` without events.
    pub fn success_rate(&self) -> Option<f64> {
        (self.total > 0).then(|| self.ok as f64 / self.total as f64)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Percentiles {
    pub p50: Option<u64>,
    pub p90: Option<u64>,
    pub max: Option<u64>,
}

impl Percentiles {
    /// Nearest-rank percentiles.
    pub fn of(mut values: Vec<u64>) -> Self {
        if values.is_empty() {
            return Self::default();
        }
        values.sort_unstable();
        let rank = |p: f64| {
            let i = ((p * values.len() as f64).ceil() as usize).clamp(1, values.len());
            values[i - 1]
        };
        Percentiles {
            p50: Some(rank(0.5)),
            p90: Some(rank(0.9)),
            max: values.last().copied(),
        }
    }
}

/// Everything a report shows.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Summary {
    pub client_events: u64,
    pub server_events: u64,
    pub first: Option<String>,
    pub last: Option<String>,
    pub buckets: BTreeMap<String, (BucketKey, Bucket)>,
    /// Joinable client events by outcome, when server journals were given.
    pub joined: BTreeMap<JoinOutcome, u64>,
    pub pairs: PairStats,
    pub bad_lines: usize,
}

/// Paired cascade probes by outcome.
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct PairStats {
    pub total: u64,
    pub both_ok: u64,
    pub only_up_failed: u64,
    pub only_down_failed: u64,
    pub both_failed: u64,
    /// One half is missing from the journal.
    pub incomplete: u64,
}

/// One paired cascade probe: its upload and download halves.
#[derive(Debug, Clone)]
pub struct Pair<'a> {
    pub pair_id: &'a str,
    pub up: Option<&'a ProbeEvent>,
    pub down: Option<&'a ProbeEvent>,
}

/// Groups client events by `pair_id`.
pub fn pairs<'a>(client: impl IntoIterator<Item = &'a ProbeEvent>) -> Vec<Pair<'a>> {
    let mut by: BTreeMap<&str, Pair<'a>> = BTreeMap::new();
    for e in client {
        let Some(id) = e.pair_id.as_deref() else {
            continue;
        };
        let p = by.entry(id).or_insert(Pair {
            pair_id: id,
            up: None,
            down: None,
        });
        match e.direction {
            Some(Direction::Up) => p.up = Some(e),
            Some(Direction::Down) => p.down = Some(e),
            None => {}
        }
    }
    by.into_values().collect()
}

/// Counts a journal. `with_server` says whether server journals were
/// loaded, so a missing server event means something.
pub fn summarize(j: &Journal, with_server: bool) -> Summary {
    let mut s = Summary {
        bad_lines: j.bad_lines.len(),
        ..Summary::default()
    };
    let mut durations: HashMap<String, Vec<u64>> = HashMap::new();
    let mut times: Vec<OffsetDateTime> = Vec::new();
    for e in j.client() {
        s.client_events += 1;
        if let Some(t) = parse_rfc3339(&e.timestamp) {
            times.push(t);
        }
        let key = BucketKey {
            target_id: e.target_id.clone(),
            test_type: e.test_type,
            transport: e.transport,
            direction: e.direction,
            control: e.control,
        };
        let name = format!(
            "{}{} {} {}{}",
            if e.control { "control " } else { "" },
            key.target_id,
            key.test_type.as_str(),
            transport_str(key.transport),
            key.direction
                .map(|d| format!(" {}", d.as_str()))
                .unwrap_or_default()
        );
        let (_, b) = s
            .buckets
            .entry(name.clone())
            .or_insert_with(|| (key, Bucket::default()));
        b.total += 1;
        if !b.networks.contains(&e.network_id) {
            b.networks.push(e.network_id.clone());
        }
        if e.success {
            b.ok += 1;
            durations.entry(name).or_default().push(e.duration_ms);
        } else {
            *b.errors
                .entry(e.error_code.unwrap_or(ErrorCode::Unknown))
                .or_default() += 1;
            *b.failed_at
                .entry(e.phase.unwrap_or(Phase::None))
                .or_default() += 1;
        }
    }
    for (name, d) in durations {
        if let Some((_, b)) = s.buckets.get_mut(&name) {
            b.ok_ms = Percentiles::of(d);
        }
    }
    s.server_events = j.server().count() as u64;
    times.sort();
    s.first = times
        .first()
        .map(|t| probe_common::timefmt::format_rfc3339(*t));
    s.last = times
        .last()
        .map(|t| probe_common::timefmt::format_rfc3339(*t));
    if with_server {
        for jn in join(j.client(), j.server()) {
            *s.joined.entry(jn.outcome()).or_default() += 1;
        }
    }
    for p in pairs(j.client()) {
        let st = &mut s.pairs;
        st.total += 1;
        match (p.up.map(|e| e.success), p.down.map(|e| e.success)) {
            (Some(true), Some(true)) => st.both_ok += 1,
            (Some(false), Some(true)) => st.only_up_failed += 1,
            (Some(true), Some(false)) => st.only_down_failed += 1,
            (Some(false), Some(false)) => st.both_failed += 1,
            _ => st.incomplete += 1,
        }
    }
    s
}

pub fn transport_str(t: Transport) -> &'static str {
    match t {
        Transport::Udp => "udp",
        Transport::Tcp => "tcp",
        Transport::Quic => "quic",
    }
}

/// Snake-case name of a phase, as in the journal.
pub fn phase_str(p: Phase) -> &'static str {
    match p {
        Phase::None => "none",
        Phase::DnsResolved => "dns_resolved",
        Phase::TcpConnected => "tcp_connected",
        Phase::FirstBytesReceived => "first_bytes_received",
        Phase::HandshakeDone => "handshake_done",
        Phase::AppDataSent => "app_data_sent",
        Phase::AppDataReceived => "app_data_received",
        Phase::Completed => "completed",
    }
}

#[cfg(test)]
mod tests;
