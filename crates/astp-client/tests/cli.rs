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
fn no_args_exits_1_with_not_implemented() {
    let output = command().output().expect("spawn astp-client");
    assert_eq!(
        output.status.code(),
        Some(1),
        "status was {:?}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not implemented"), "stderr was {stderr:?}");
}

#[test]
fn help_exits_0() {
    for flag in ["--help", "-h"] {
        let output = command().arg(flag).output().expect("spawn astp-client");
        assert_eq!(
            output.status.code(),
            Some(0),
            "{flag} status was {:?}",
            output.status
        );
    }
}
