//! `astp-client` — ASTP-M VPN client skeleton.

use anyhow::Result;
use astp_client::run;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "astp-client",
    version,
    about = "ASTP-M VPN client (not implemented)"
)]
struct Cli {}

fn main() -> Result<()> {
    let _cli = Cli::parse();
    run()
}
