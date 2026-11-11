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
