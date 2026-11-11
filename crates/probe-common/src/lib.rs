//! Shared building blocks for ASTP Network Probe: the event schema written to
//! JSONL, error classification, configuration files and the rotating log
//! writer.

pub mod config;
pub mod counting;
pub mod error_code;
pub mod event;
pub mod jsonl;
pub mod timefmt;

pub use error_code::ErrorCode;
pub use event::{Phase, ProbeEvent, Side, TestType, Transport, READABLE_SCHEMA_VERSIONS, SCHEMA_VERSION};

/// `error: cause: cause…` — the top-level message alone ("connection
/// error") rarely says what happened.
pub fn error_chain(e: &(dyn std::error::Error + 'static)) -> String {
    let mut out = e.to_string();
    let mut src = e.source();
    while let Some(s) = src {
        let m = s.to_string();
        if !out.ends_with(&m) {
            out.push_str(": ");
            out.push_str(&m);
        }
        src = s.source();
    }
    out
}
