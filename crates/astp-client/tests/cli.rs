use std::process::Command;

fn command() -> Command {
    // Cargo on the MSRV (Rust 1.89) exports the hyphenated target name.
    // Underscore is the documented fallback if a newer Cargo rewrites the key.
    let path = option_env!("CARGO_BIN_EXE_astp-client")
        .or(option_env!("CARGO_BIN_EXE_astp_client"))
        .expect("Cargo did not export the astp-client executable path");
    Command::new(path)
}

#[test]
fn missing_config_exits_1() {
    let output = command()
        .args(["--config", "/nonexistent/client.toml"])
        .output()
        .expect("spawn astp-client");
    assert_eq!(output.status.code(), Some(1), "{:?}", output.status);
    assert!(String::from_utf8_lossy(&output.stderr).contains("client.toml"));
}

#[test]
fn help_exits_0() {
    for flag in ["--help", "-h"] {
        let output = command().arg(flag).output().expect("spawn astp-client");
        assert_eq!(output.status.code(), Some(0), "{flag}");
    }
}

#[test]
fn check_validates_the_secret() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = dir.path().join("client.toml");
    let write = |secret: &str| {
        std::fs::write(
            &cfg,
            format!(
                "[client]\nserver = \"vpn.example.net:443\"\nsession_path = \"/abcdefghijklmnop\"\nsecret = \"{secret}\"\n"
            ),
        )
        .unwrap();
    };
    let (good, _) = astp_server::keygen().unwrap();
    write(&good);
    let ok = command()
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert!(ok.status.success(), "{ok:?}");
    write("not-a-secret");
    let bad = command()
        .arg("--check")
        .arg("--config")
        .arg(&cfg)
        .output()
        .unwrap();
    assert_eq!(bad.status.code(), Some(1));
}
