//! Wall-clock timestamps for events. Durations are measured separately with
//! `std::time::Instant` (monotonic); this module only formats the UTC moment
//! an event happened.

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

/// Current UTC time as RFC 3339 with second precision, e.g. `2026-11-02T12:00:00Z`.
pub fn now_rfc3339() -> String {
    format_rfc3339(OffsetDateTime::now_utc())
}

pub fn format_rfc3339(t: OffsetDateTime) -> String {
    let t = t
        .to_offset(time::UtcOffset::UTC)
        .replace_nanosecond(0)
        .expect("zero nanoseconds is always valid");
    t.format(&Rfc3339)
        .expect("RFC 3339 formatting of a UTC time cannot fail")
}

pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn formats_utc_without_fraction() {
        let t = datetime!(2026-11-02 12:00:00.123 UTC);
        assert_eq!(format_rfc3339(t), "2026-11-02T12:00:00Z");
    }

    #[test]
    fn converts_offsets_to_utc() {
        let t = datetime!(2026-11-02 15:00:00 +3);
        assert_eq!(format_rfc3339(t), "2026-11-02T12:00:00Z");
    }

    #[test]
    fn round_trips() {
        let s = now_rfc3339();
        assert_eq!(format_rfc3339(parse_rfc3339(&s).unwrap()), s);
    }
}
