//! Local and UTC times as text (jiff; chrono is unmaintained).

use jiff::{tz::TimeZone, Timestamp, Zoned};

/// `now` formatted in local time with an strftime pattern (`%Y-%m-%d`, `%H:%M`, …).
pub fn now_local(fmt: &str) -> String {
    Zoned::now().strftime(fmt).to_string()
}

/// RFC 3339 in local time with its offset, whole seconds: `2026-11-22T02:30:00+01:00`.
pub fn local_rfc3339(t: Timestamp) -> String {
    t.to_zoned(TimeZone::system())
        .strftime("%Y-%m-%dT%H:%M:%S%:z")
        .to_string()
}

/// RFC 3339 in UTC, whole seconds: `2026-11-22T01:30:00Z`.
pub fn utc_rfc3339(t: Timestamp) -> String {
    t.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// A `SystemTime` as a Timestamp (the epoch when out of range).
pub fn from_system(t: std::time::SystemTime) -> Timestamp {
    Timestamp::try_from(t).unwrap_or(Timestamp::UNIX_EPOCH)
}

/// A Unix time in milliseconds as a Timestamp.
pub fn from_ms(ms: u64) -> Option<Timestamp> {
    Timestamp::from_millisecond(i64::try_from(ms).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats() {
        let t = Timestamp::from_second(1_795_300_000).unwrap();
        assert_eq!(utc_rfc3339(t), "2026-11-21T22:26:40Z");
        let l = local_rfc3339(t);
        assert_eq!(l.len(), 25, "{l}");
        assert!(l[19..].starts_with('+') || l[19..].starts_with('-'), "{l}");
        assert_eq!(now_local("%Y").len(), 4);
    }
}
