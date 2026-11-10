//! Skeleton of the ASTP-M VPN server.
//!
//! This is not the network probe. The tunnel is not implemented.

use anyhow::{bail, Result};

/// Refuse to run the VPN server.
///
/// Every real path ends here until the tunnel exists.
pub fn run() -> Result<()> {
    bail!("astp-server is not implemented")
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn run_refuses_with_not_implemented() {
        let err = run().expect_err("server must refuse");
        let message = format!("{err:#}");
        assert!(
            message.contains("not implemented"),
            "message was {message:?}"
        );
    }
}
