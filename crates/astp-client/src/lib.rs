//! Skeleton of the ASTP-M VPN client.
//!
//! This is not the network probe. The tunnel is not implemented.

use anyhow::{bail, Result};

/// Refuse to run the VPN client.
///
/// Every real path ends here until the tunnel exists.
pub fn run() -> Result<()> {
    bail!("astp-client is not implemented")
}

#[cfg(test)]
mod tests {
    use super::run;

    #[test]
    fn run_refuses_with_not_implemented() {
        let err = run().expect_err("client must refuse");
        let message = format!("{err:#}");
        assert!(
            message.contains("not implemented"),
            "message was {message:?}"
        );
    }
}
