//! Wall-clock timestamps for events. Durations are measured separately with
//! `std::time::Instant` (monotonic); this module only formats the UTC moment
//! an event happened.

use time::format_description::well_known::Rfc3339;
use time::macros::format_description;
use time::OffsetDateTime;

/// Current UTC time as RFC 3339 with millisecond precision, e.g.
/// `2026-11-02T12:00:00.123Z`. Milliseconds are what lets events of a
/// client and two cascade servers be put in order (schema 2; schema 1
/// wrote whole seconds and is still read).
pub fn now_rfc3339() -> String {
    format_rfc3339(OffsetDateTime::now_utc())
}

pub fn format_rfc3339(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    t.format(format_description!(
        "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:3]Z"
    ))
    .expect("formatting a UTC time cannot fail")
}

/// Parses any RFC 3339 time, with or without a fraction of a second.
pub fn parse_rfc3339(s: &str) -> Option<OffsetDateTime> {
    OffsetDateTime::parse(s, &Rfc3339).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn formats_utc_with_milliseconds() {
        let t = datetime!(2026-11-02 12:00:00.123456 UTC);
        assert_eq!(format_rfc3339(t), "2026-11-02T12:00:00.123Z");
        let t = datetime!(2026-11-02 12:00:00 UTC);
        assert_eq!(format_rfc3339(t), "2026-11-02T12:00:00.000Z");
    }

    #[test]
    fn converts_offsets_to_utc() {
        let t = datetime!(2026-11-02 15:00:00.5 +3);
        assert_eq!(format_rfc3339(t), "2026-11-02T12:00:00.500Z");
    }

    #[test]
    fn reads_schema_1_whole_seconds() {
        let t = parse_rfc3339("2026-11-02T12:00:00Z").unwrap();
        assert_eq!(t, datetime!(2026-11-02 12:00:00 UTC));
    }

    #[test]
    fn round_trips() {
        let s = now_rfc3339();
        assert_eq!(format_rfc3339(parse_rfc3339(&s).unwrap()), s);
    }
}
