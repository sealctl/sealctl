//! Timers and credit (SPEC 6.4): idle allowance, hard stop, minutes worked. Pure functions of
//! the clock so tests can drive them with any time.

use jiff::tz::TimeZone;
use serde::{Deserialize, Serialize};

/// What `session.json` keeps (no keys): survives locks and restarts until the hard stop.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Saved {
    /// First `open` granted today, Unix ms.
    pub first_open: Option<u64>,
    /// Minutes worked since the first open.
    pub worked: u64,
    /// Last work moment, Unix ms.
    pub last_work: u64,
    /// The minute (Unix ms / 60000) last counted as worked.
    pub last_minute: u64,
    /// Allowance cap, seconds.
    pub cap: u64,
    /// Allowance base, seconds.
    pub base: u64,
    /// Seconds added per minute worked.
    pub rate: u64,
    /// Place of the last open.
    pub place: Option<String>,
    /// Why the session last locked.
    pub lock_reason: Option<String>,
}

/// `min(cap, base + rate × minutes worked)`, in seconds.
pub fn idle_allowance(cap: u64, base: u64, rate: u64, worked: u64) -> u64 {
    cap.min(base.saturating_add(rate.saturating_mul(worked)))
}

/// The hard stop for a session first opened at `first_open` (Unix ms): 02:00 local time or 14
/// hours after the first open, whichever comes first.
pub fn hard_stop(first_open: u64) -> u64 {
    hard_stop_in(first_open, &TimeZone::system())
}

/// [`hard_stop`] in the time zone `tz`.
pub fn hard_stop_in(first_open: u64, tz: &TimeZone) -> u64 {
    let fourteen = first_open + 14 * 3600 * 1000;
    let Some(start) = crate::clock::from_ms(first_open) else {
        return fourteen;
    };
    let first_day = start.to_zoned(tz.clone()).date();
    let mut day = first_day;
    for _ in 0..3 {
        // 02:00 that day. In a DST gap it does not exist: the moment the clock jumps past it.
        // In a fold it comes twice: the first of the two after the first open.
        let two = tz.to_ambiguous_zoned(day.at(2, 0, 0, 0));
        let times = match two.offset() {
            jiff::tz::AmbiguousOffset::Fold { .. } => {
                vec![two.clone().earlier(), two.later()]
            }
            _ => vec![two.compatible()],
        };
        for t in times.into_iter().flatten() {
            let ms = t.timestamp().as_millisecond();
            if ms > first_open as i64 {
                return (ms as u64).min(fourteen);
            }
        }
        match day.tomorrow() {
            Ok(d) => day = d,
            Err(_) => break,
        }
    }
    fourteen
}

/// `HH:MM` of a Unix ms time, local.
pub fn hhmm(ms: u64) -> String {
    crate::clock::from_ms(ms)
        .map(|t| t.to_zoned(TimeZone::system()).strftime("%H:%M").to_string())
        .unwrap_or_default()
}

/// RFC 3339 with offset.
pub fn rfc3339(ms: u64) -> String {
    crate::clock::from_ms(ms)
        .map(crate::clock::local_rfc3339)
        .unwrap_or_default()
}

/// `3 h 12 min`, `30 min`, `45 s`.
pub fn duration(secs: u64) -> String {
    match secs {
        s if s < 60 => format!("{s} s"),
        s if s < 3600 => format!("{} min", s / 60),
        s => {
            let m = (s % 3600) / 60;
            if m == 0 {
                format!("{} h", s / 3600)
            } else {
                format!("{} h {m} min", s / 3600)
            }
        }
    }
}

impl Saved {
    /// Counts the minute of `now` as worked (once per minute).
    pub fn work(&mut self, now: u64) {
        let minute = now / 60_000;
        if minute != self.last_minute {
            self.last_minute = minute;
            self.worked += 1;
        }
        self.last_work = now;
    }

    /// Seconds of idle allowance left at `now`.
    pub fn left(&self, now: u64) -> u64 {
        let allowance = idle_allowance(self.cap, self.base, self.rate, self.worked);
        let idle = now.saturating_sub(self.last_work) / 1000;
        allowance.saturating_sub(idle)
    }

    /// Past the hard stop at `now`?
    pub fn past_hard_stop(&self, now: u64) -> bool {
        self.first_open.is_some_and(|f| now >= hard_stop(f))
    }

    /// Resets the credit (at the hard stop).
    pub fn reset_credit(&mut self) {
        self.first_open = None;
        self.worked = 0;
        self.last_minute = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allowance() {
        // trusted place: 30 min + 2 min per minute worked, cap 4 h
        assert_eq!(idle_allowance(14_400, 1_800, 120, 0), 1_800);
        assert_eq!(idle_allowance(14_400, 1_800, 120, 60), 9_000);
        assert_eq!(idle_allowance(14_400, 1_800, 120, 600), 14_400);
        // other place: 10 min flat
        assert_eq!(idle_allowance(600, 600, 0, 300), 600);
    }

    #[test]
    fn idle_and_credit_with_a_fake_clock() {
        let t0 = 1_800_000_000_000u64;
        let mut s = Saved {
            first_open: Some(t0),
            cap: 14_400,
            base: 1_800,
            rate: 120,
            ..Saved::default()
        };
        s.work(t0);
        assert_eq!(s.worked, 1);
        s.work(t0 + 1_000); // same minute
        assert_eq!(s.worked, 1);
        for m in 1..=59 {
            s.work(t0 + m * 60_000);
        }
        assert_eq!(s.worked, 60);
        let last = s.last_work;
        // allowance 1800 + 120*60 = 9000 s
        assert_eq!(s.left(last), 9_000);
        assert_eq!(s.left(last + 8_999_000), 1);
        assert_eq!(s.left(last + 9_000_000), 0);
        // a lock keeps the credit; the hard stop resets it
        s.reset_credit();
        assert_eq!(s.worked, 0);
        assert!(s.first_open.is_none());
    }

    #[test]
    fn hard_stop_is_at_most_fourteen_hours() {
        let t0 = 1_800_000_000_000u64;
        let h = hard_stop(t0);
        assert!(h > t0);
        assert!(h <= t0 + 14 * 3600 * 1000);
        let fourteen = h == t0 + 14 * 3600 * 1000;
        assert!(fourteen || hhmm(h) == "02:00");
        // in other zones too: 02:00 local, or fourteen hours
        for tz in [
            "Europe/Warsaw",
            "America/Los_Angeles",
            "Asia/Kolkata",
            "Pacific/Chatham",
        ] {
            // build sandboxes (nix) may have no time zone database
            let Ok(zone) = jiff::tz::TimeZone::get(tz) else {
                continue;
            };
            let start = crate::clock::from_ms(t0).unwrap().to_zoned(zone.clone());
            let two = start.date().at(2, 0, 0, 0).to_zoned(zone.clone()).unwrap();
            let two = if two.timestamp() > start.timestamp() {
                two
            } else {
                start
                    .date()
                    .tomorrow()
                    .unwrap()
                    .at(2, 0, 0, 0)
                    .to_zoned(zone)
                    .unwrap()
            };
            let want = (two.timestamp().as_millisecond() as u64).min(t0 + 14 * 3600 * 1000);
            assert!(want > t0 && want <= t0 + 14 * 3600 * 1000, "{tz}");
        }
    }

    #[test]
    fn hard_stop_across_daylight_saving_changes() {
        let Ok(warsaw) = jiff::tz::TimeZone::get("Europe/Warsaw") else {
            return;
        };
        let ms = |s: &str| s.parse::<jiff::Timestamp>().unwrap().as_millisecond() as u64;
        // autumn: 02:00 to 02:59 come twice (03:00 CEST back to 02:00 CET). Opened at 02:30
        // CEST, the next 02:00 is the second one, half an hour later.
        assert_eq!(
            hard_stop_in(ms("2026-10-25T00:30:00Z"), &warsaw),
            ms("2026-10-25T01:00:00Z")
        );
        // opened the evening before: the first 02:00 (CEST)
        assert_eq!(
            hard_stop_in(ms("2026-10-24T18:00:00Z"), &warsaw),
            ms("2026-10-25T00:00:00Z")
        );
        // spring: 02:00 does not exist; the stop is when the clock jumps to 03:00 CEST
        assert_eq!(
            hard_stop_in(ms("2026-03-28T20:00:00Z"), &warsaw),
            ms("2026-03-29T01:00:00Z")
        );
        // opened right after the jump: the next night, or 14 hours
        assert_eq!(
            hard_stop_in(ms("2026-03-29T01:00:00Z"), &warsaw),
            ms("2026-03-29T15:00:00Z")
        );
        if let Ok(la) = jiff::tz::TimeZone::get("America/Los_Angeles") {
            // 01:00 to 01:59 come twice there; 02:00 PST once
            assert_eq!(
                hard_stop_in(ms("2026-11-01T08:30:00Z"), &la),
                ms("2026-11-01T10:00:00Z")
            );
        }
        // opened exactly at 02:00: the next 02:00 is a day away, so 14 hours
        assert_eq!(
            hard_stop_in(ms("2027-01-15T01:00:00Z"), &warsaw),
            ms("2027-01-15T15:00:00Z")
        );
        // a minute before 02:00: one minute
        assert_eq!(
            hard_stop_in(ms("2027-01-15T00:59:00Z"), &warsaw),
            ms("2027-01-15T01:00:00Z")
        );
    }

    #[test]
    fn durations() {
        assert_eq!(duration(45), "45 s");
        assert_eq!(duration(1800), "30 min");
        assert_eq!(duration(11_520), "3 h 12 min");
        assert_eq!(duration(7200), "2 h");
    }
}
