use std::process::Command;

fn command() -> Command {
    // Cargo on the MSRV (Rust 1.89) exports the hyphenated target name.
    // Underscore is the documented fallback if a newer Cargo rewrites the key.
    let path = option_env!("CARGO_BIN_EXE_astp-probe")
        .or(option_env!("CARGO_BIN_EXE_astp_probe"))
        .expect("Cargo did not export the astp-probe executable path");
    Command::new(path)
}

/// A campaign with nothing to probe ends on time and exits 0.
#[test]
fn run_ends_with_the_campaign() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("client.toml");
    std::fs::write(
        &cfg,
        format!(
            "[client]\nid = \"c\"\ndata_dir = '{}'\n",
            dir.path().join("data").display()
        ),
    )
    .unwrap();
    let t = std::time::Instant::now();
    let output = command()
        .args(["run", "--campaign", "1s", "--no-long", "--config"])
        .arg(&cfg)
        .output()
        .expect("spawn astp-probe");
    assert!(output.status.success(), "{output:?}");
    assert!(t.elapsed() < std::time::Duration::from_secs(10));
    assert!(dir.path().join("data/events.jsonl").exists());
}

#[test]
fn run_rejects_a_bad_campaign() {
    let output = command()
        .args(["run", "--config", "/nonexistent.toml", "--campaign", "5w"])
        .output()
        .expect("spawn astp-probe");
    assert!(!output.status.success());
}

#[test]
fn adhoc_flags_conflict_with_config() {
    for flag in [
        ["--sni", "a.test"],
        ["--ca-file", "ca.pem"],
        ["--port", "8443"],
    ] {
        let output = command()
            .args(["test", "--config", "c.toml"])
            .args(flag)
            .output()
            .expect("spawn astp-probe");
        assert_eq!(output.status.code(), Some(2), "{flag:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("cannot be used with"), "{stderr}");
    }
}

#[test]
fn long_session_parameters_are_checked_before_running() {
    let output = command()
        .args([
            "test",
            "--host",
            "127.0.0.1",
            "--sni",
            "probe.test",
            "--no-save",
            "--long",
            "--long-seconds",
            "5",
            "--long-interval-ms",
            "3000",
            "--stall-seconds",
            "2",
        ])
        .output()
        .expect("spawn astp-probe");
    assert_eq!(output.status.code(), Some(1), "{:?}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("two heartbeat intervals"), "{stderr}");
}

#[test]
fn empty_ca_file_is_a_startup_error() {
    let dir = tempfile::tempdir().unwrap();
    let ca = dir.path().join("empty.pem");
    std::fs::write(&ca, "").unwrap();
    let output = command()
        .args([
            "test",
            "--host",
            "127.0.0.1",
            "--sni",
            "probe.test",
            "--no-save",
            "--tcp",
        ])
        .arg("--ca-file")
        .arg(&ca)
        .output()
        .expect("spawn astp-probe");
    assert_eq!(output.status.code(), Some(1), "{:?}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("has no certificate"), "{stderr}");
}

#[test]
fn status_counts_rotated_files() {
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let ev = |ok: bool| {
        let e = probe_common::ProbeEvent::new(
            "t",
            "c",
            "n",
            "g",
            probe_common::TestType::TcpConnect,
            probe_common::Transport::Tcp,
        );
        let e = if ok {
            e.succeed()
        } else {
            e.fail(probe_common::ErrorCode::TcpTimeout, "x")
        };
        format!("{}\n", serde_json::to_string(&e).unwrap())
    };
    std::fs::write(data.join("events.jsonl.1"), ev(true) + &ev(false)).unwrap();
    std::fs::write(data.join("events.jsonl"), ev(true)).unwrap();
    let cfg = dir.path().join("client.toml");
    std::fs::write(
        &cfg,
        format!("[client]\nid = \"c\"\ndata_dir = '{}'\n", data.display()),
    )
    .unwrap();
    let output = command()
        .args(["status", "--config"])
        .arg(&cfg)
        .output()
        .expect("spawn astp-probe");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("3 events (2 ok, 1 failed), 0 unreadable lines in 2 file(s)"),
        "{stdout}"
    );
}

#[test]
fn report_summarises_client_and_server_journals() {
    use probe_common::{ErrorCode, ProbeEvent, Side, TestType, Transport};
    let dir = tempfile::tempdir().unwrap();
    let data = dir.path().join("data");
    std::fs::create_dir(&data).unwrap();
    let line = |e: &ProbeEvent| format!("{}\n", serde_json::to_string(e).unwrap());
    let ok = ProbeEvent::new("t1", "c", "net", "gw", TestType::H2Request, Transport::Tcp).succeed();
    let bad = ProbeEvent::new("t2", "c", "net", "gw", TestType::H2Request, Transport::Tcp)
        .fail(ErrorCode::RemoteClosed, "x");
    std::fs::write(data.join("events.jsonl"), line(&ok) + &line(&bad)).unwrap();
    let mut srv = ProbeEvent::new(
        "t2",
        "s",
        "server",
        "s",
        TestType::H2Request,
        Transport::Tcp,
    )
    .succeed();
    srv.side = Side::Server;
    let server_log = dir.path().join("server-events.jsonl");
    std::fs::write(&server_log, line(&srv)).unwrap();
    let cfg = dir.path().join("client.toml");
    std::fs::write(
        &cfg,
        format!("[client]\nid = \"c\"\ndata_dir = '{}'\n", data.display()),
    )
    .unwrap();
    let html = dir.path().join("report.html");
    let output = command()
        .args(["report", "--last", "1h", "--config"])
        .arg(&cfg)
        .arg("--server-log")
        .arg(&server_log)
        .arg("--html")
        .arg(&html)
        .output()
        .expect("spawn astp-probe");
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("gw h2_request tcp"), "{stdout}");
    assert!(stdout.contains("50.0%"), "{stdout}");
    assert!(
        stdout.contains("client failed, server saw the request"),
        "{stdout}"
    );
    let page = std::fs::read_to_string(&html).unwrap();
    assert!(page.starts_with("<!doctype html>"));

    let output = command()
        .args(["report", "--json", "--last", "all", "--log"])
        .arg(data.join("events.jsonl"))
        .output()
        .expect("spawn astp-probe");
    assert!(output.status.success(), "{output:?}");
    let v: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["client_events"], 2);
}
