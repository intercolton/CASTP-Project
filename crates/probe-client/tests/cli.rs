use std::process::Command;

fn command() -> Command {
    // Cargo on the MSRV (Rust 1.89) exports the hyphenated target name.
    // Underscore is the documented fallback if a newer Cargo rewrites the key.
    let path = option_env!("CARGO_BIN_EXE_astp-probe")
        .or(option_env!("CARGO_BIN_EXE_astp_probe"))
        .expect("Cargo did not export the astp-probe executable path");
    Command::new(path)
}

/// `RestartPreventExitStatus=69` in deploy/systemd/astp-probe-client.service
/// depends on this code.
#[test]
fn run_exits_69_while_not_implemented() {
    let output = command()
        .args(["run", "--config", "/nonexistent.toml"])
        .output()
        .expect("spawn astp-probe");
    assert_eq!(output.status.code(), Some(69), "{:?}", output.status);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not implemented"), "stderr was {stderr:?}");
    let unit = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../deploy/systemd/astp-probe-client.service"),
    )
    .unwrap();
    assert!(unit.contains("RestartPreventExitStatus=69"));
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
