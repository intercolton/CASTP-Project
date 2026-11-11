use super::*;
use probe_common::jsonl::JsonlWriter;

fn ev(id: &str, tt: TestType, ok: bool) -> ProbeEvent {
    let e = ProbeEvent::new(id, "c1", "net-a", "gw", tt, Transport::Tcp);
    if ok {
        e.succeed()
    } else {
        let mut e = e.fail(ErrorCode::TlsHandshakeFailed, "x");
        e.phase = Some(Phase::TcpConnected);
        e
    }
}

fn server(id: &str, tt: TestType) -> ProbeEvent {
    let mut e = ProbeEvent::new(id, "srv", "server", "srv", tt, Transport::Tcp).succeed();
    e.side = Side::Server;
    e
}

#[test]
fn percentiles_nearest_rank() {
    let p = Percentiles::of((1..=10).collect());
    assert_eq!((p.p50, p.p90, p.max), (Some(5), Some(9), Some(10)));
    assert_eq!(Percentiles::of(vec![]), Percentiles::default());
    let one = Percentiles::of(vec![7]);
    assert_eq!((one.p50, one.p90), (Some(7), Some(7)));
}

#[test]
fn joins_by_test_id_and_classifies() {
    let c = [
        ev("a", TestType::H2Request, true),
        ev("b", TestType::H2Request, false),
        ev("c", TestType::H2Request, false),
        // Not joinable: the server cannot know a handshake's test id.
        ev("d", TestType::TlsHandshake, false),
    ];
    let s = [
        server("a", TestType::H2Request),
        server("b", TestType::H2Request),
    ];
    let j = join(&c, &s);
    assert_eq!(j.len(), 3);
    let out: Vec<_> = j.iter().map(Joined::outcome).collect();
    assert_eq!(
        out,
        [
            JoinOutcome::ClientOk,
            JoinOutcome::FailedServerSaw,
            JoinOutcome::FailedServerSilent
        ]
    );
}

#[test]
fn summary_counts_buckets_errors_and_pairs() {
    let mut events = vec![
        ev("1", TestType::TlsHandshake, true),
        ev("2", TestType::TlsHandshake, true),
        ev("3", TestType::TlsHandshake, false),
    ];
    events[0].duration_ms = 10;
    events[1].duration_ms = 30;
    for (id, dir, ok) in [
        ("u1", Direction::Up, true),
        ("d1", Direction::Down, false),
        ("u2", Direction::Up, true),
    ] {
        let mut e = ev(id, TestType::LongSession, ok);
        e.direction = Some(dir);
        e.pair_id = Some(if id.ends_with('1') { "p1" } else { "p2" }.into());
        events.push(e);
    }
    let j = Journal {
        events,
        ..Journal::default()
    };
    let s = summarize(&j, false);
    assert_eq!(s.client_events, 6);
    let (_, tls) = &s.buckets["gw tls_handshake tcp"];
    assert_eq!((tls.total, tls.ok), (3, 2));
    assert_eq!(tls.errors[&ErrorCode::TlsHandshakeFailed], 1);
    assert_eq!(tls.failed_at[&Phase::TcpConnected], 1);
    assert_eq!(tls.ok_ms.max, Some(30));
    assert!(s.buckets.contains_key("gw long_session tcp up"));
    assert_eq!(s.pairs.total, 2);
    assert_eq!(s.pairs.only_down_failed, 1);
    assert_eq!(s.pairs.incomplete, 1);
    assert!(s.joined.is_empty());
}

#[test]
fn loads_rotated_files_and_filters_by_time() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("events.jsonl");
    let mut old = ev("old", TestType::TcpConnect, true);
    old.timestamp = "2026-01-01T00:00:00Z".into(); // schema 1 style
    old.schema_version = 1;
    {
        let mut w = JsonlWriter::open(&path, 1024, 3).unwrap();
        // Enough lines to rotate at least once.
        for i in 0..20 {
            w.write(&ev(&format!("n{i}"), TestType::TcpConnect, true))
                .unwrap();
        }
        w.write(&old).unwrap();
    }
    std::fs::write(dir.path().join("events.jsonl.9"), "not json\n").unwrap();
    let j = Journal::load(&path, 3).unwrap();
    assert!(j.files.len() >= 2, "{:?}", j.files);
    assert!(j.events.iter().any(|e| e.test_id == "old"));
    // .9 is beyond keep_files and is not read.
    assert!(j.bad_lines.is_empty());
    let recent = j.since(OffsetDateTime::now_utc() - time::Duration::hours(1));
    assert!(recent.events.iter().all(|e| e.test_id != "old"));
    assert!(!recent.events.is_empty());

    let missing = Journal::load(&dir.path().join("none.jsonl"), 3).unwrap();
    assert!(missing.events.is_empty());
}
