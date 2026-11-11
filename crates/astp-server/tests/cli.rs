use std::process::Command;

fn command() -> Command {
    // Cargo on the MSRV (Rust 1.89) exports the hyphenated target name.
    // Underscore is the documented fallback if a newer Cargo rewrites the key.
    let path = option_env!("CARGO_BIN_EXE_astp-server")
        .or(option_env!("CARGO_BIN_EXE_astp_server"))
        .expect("Cargo did not export the astp-server executable path");
    Command::new(path)
}

#[test]
fn no_args_is_a_usage_error() {
    let output = command().output().expect("spawn astp-server");
    assert_eq!(output.status.code(), Some(2), "{:?}", output.status);
}

#[test]
fn help_exits_0() {
    for flag in ["--help", "-h"] {
        let output = command().arg(flag).output().expect("spawn astp-server");
        assert_eq!(output.status.code(), Some(0), "{flag}");
    }
}

#[test]
fn keygen_prints_a_secret_and_a_path() {
    let output = command().arg("keygen").output().expect("spawn astp-server");
    assert!(output.status.success());
    let out = String::from_utf8_lossy(&output.stdout);
    let secret = out
        .lines()
        .find_map(|l| l.strip_prefix("secret       = \""))
        .and_then(|l| l.strip_suffix('"'))
        .expect("secret line");
    astp_crypto::ClientSecret::parse(secret).expect("a valid secret");
    assert!(out.contains("session_path = \"/"), "{out}");
}

#[test]
fn check_reports_a_missing_config() {
    let output = command()
        .args(["check", "--config", "/nonexistent/server.toml"])
        .output()
        .expect("spawn astp-server");
    assert_eq!(output.status.code(), Some(1));
}
