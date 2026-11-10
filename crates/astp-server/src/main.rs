//! `astp-server` — ASTP-M VPN server skeleton.

use anyhow::Result;
use astp_server::run;
use clap::Parser;

#[derive(Parser)]
#[command(
    name = "astp-server",
    version,
    about = "ASTP-M VPN server (not implemented)"
)]
struct Cli {}

fn main() -> Result<()> {
    let _cli = Cli::parse();
    run()
}
