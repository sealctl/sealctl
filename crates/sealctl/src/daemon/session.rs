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
    /// The session state the phone last heard (`open`, `waiting`, `locked`), so that a daemon
    /// started after one whose last status failed tells the phone the session is Locked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub told: Option<String>,
}

/// A status goes out while Open when the lock deadline moved this much later than the one the
/// last status told the phone (SPEC 6.6): work moves it on all the time, and the phone counts
/// down from the last `left` it heard.
pub const DEADLINE_LATER_MS: u64 = 2 * 60_000;

/// ... or this much earlier: a wall clock set back (less than the minute that locks), or a move
/// to another time zone bringing 02:00, and so the hard stop, closer. The allowance itself
/// never shrinks while Open.
pub const DEADLINE_EARLIER_MS: u64 = 60_000;

/// At most one status for a moved deadline in this time, sent or failed.
pub const DEADLINE_STATUS_EVERY_MS: u64 = 2 * 60_000;

/// Whether the lock deadline moved enough to tell the phone at `now`. `deadline` is the
/// session's lock deadline now (`None` unless Open), `told` the one the last status implied
/// (its time plus its `left`, capped by its `stop`; `None` when it said Locked), `last` when
/// the last status for a moved deadline was tried.
pub fn deadline_moved(now: u64, deadline: Option<u64>, told: Option<u64>, last: u64) -> bool {
    let (Some(deadline), Some(told)) = (deadline, told) else {
        return false;
    };
    let moved = deadline.saturating_sub(told) >= DEADLINE_LATER_MS
        || told.saturating_sub(deadline) >= DEADLINE_EARLIER_MS;
    moved && now.saturating_sub(last) >= DEADLINE_STATUS_EVERY_MS
}

/// `min(cap, base + rate × minutes worked)`, in seconds.
pub fn idle_allowance(cap: u64, base: u64, rate: u64, worked: u64) -> u64 {
    cap.min(base.saturating_add(rate.saturating_mul(worked)))
}

/// The longest a session lasts after the first `open` granted today (SPEC 6.4): the hard stop
/// is 02:00 local time or this long after the first open, whichever comes first.
pub const HARD_STOP_AFTER_MS: u64 = 24 * 3_600_000;

/// The hard stop for a session first opened at `first_open` (Unix ms): 02:00 local time or 24
/// hours after the first open ([`HARD_STOP_AFTER_MS`]), whichever comes first.
pub fn hard_stop(first_open: u64) -> u64 {
    hard_stop_in(first_open, &TimeZone::system())
}

/// [`hard_stop`] in the time zone `tz`.
pub fn hard_stop_in(first_open: u64, tz: &TimeZone) -> u64 {
    let latest = first_open.saturating_add(HARD_STOP_AFTER_MS);
    let Some(start) = crate::clock::from_ms(first_open) else {
        return latest;
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
                return (ms as u64).min(latest);
            }
        }
        match day.tomorrow() {
            Ok(d) => day = d,
            Err(_) => break,
        }
    }
    latest
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

    /// When the session locks unless more work comes, Unix ms: the last work moment plus the
    /// idle allowance, or the hard stop when that comes first.
    pub fn deadline(&self) -> u64 {
        let allowance = idle_allowance(self.cap, self.base, self.rate, self.worked);
        let idle = self.last_work.saturating_add(allowance.saturating_mul(1000));
        self.first_open.map_or(idle, |f| idle.min(hard_stop(f)))
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
    fn a_moved_deadline_is_told_by_two_minutes_later_or_one_earlier() {
        let now = 1_800_000_000_000u64;
        let told = now + 1_800_000;
        let last = now - 10 * 60_000;
        let moved = |d: u64, last: u64| deadline_moved(now, Some(d), Some(told), last);
        // later: 1:59 is not enough, 2:00 is
        assert!(!moved(told + 119_000, last));
        assert!(moved(told + 120_000, last));
        // not moved at all
        assert!(!moved(told, last));
        // at most once every 2 minutes for this reason
        assert!(!moved(told + 600_000, now - 119_000));
        assert!(moved(told + 600_000, now - 120_000));
        // earlier: 59 s is not enough, a minute is
        assert!(!moved(told - 59_000, last));
        assert!(moved(told - 60_000, last));
        assert!(!moved(told - 600_000, now - 60_000));
        // Locked: no deadline; the last status said Locked: nothing to compare
        assert!(!deadline_moved(now, None, Some(told), last));
        assert!(!deadline_moved(now, Some(told + 600_000), None, last));
        // the first status for a moved deadline after the daemon started
        assert!(deadline_moved(now, Some(told + 600_000), Some(told), 0));
    }

    #[test]
    fn the_deadline_is_the_last_work_plus_the_allowance_or_the_hard_stop() {
        let t0 = 1_800_000_000_000u64;
        let mut s = Saved {
            first_open: Some(t0),
            cap: 14_400,
            base: 1_800,
            rate: 120,
            ..Saved::default()
        };
        s.work(t0);
        // 1,800 s + 120 s for the minute of the open
        assert_eq!(s.deadline(), t0 + 1_920_000);
        // it agrees with `left` at any time before it
        for idle in [0, 15_000, 600_000] {
            assert_eq!(t0 + idle + s.left(t0 + idle) * 1000, s.deadline());
        }
        // close to the hard stop, the hard stop
        let stop = hard_stop(t0);
        s.last_work = stop - 60_000;
        assert_eq!(s.deadline(), stop);
    }

    #[test]
    fn hard_stop_is_at_most_a_day() {
        let t0 = 1_800_000_000_000u64;
        let h = hard_stop(t0);
        assert!(h > t0);
        assert!(h <= t0 + HARD_STOP_AFTER_MS);
        let a_day = h == t0 + HARD_STOP_AFTER_MS;
        assert!(a_day || hhmm(h) == "02:00");
        // in other zones too: the next 02:00 local, or 24 hours
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
                    .to_zoned(zone.clone())
                    .unwrap()
            };
            let want = (two.timestamp().as_millisecond() as u64).min(t0 + HARD_STOP_AFTER_MS);
            assert!(want > t0 && want <= t0 + HARD_STOP_AFTER_MS, "{tz}");
            assert_eq!(hard_stop_in(t0, &zone), want, "{tz}");
        }
    }

    /// Europe/Warsaw as a POSIX rule, so the tests run without a time zone database.
    fn warsaw() -> TimeZone {
        TimeZone::posix("CET-1CEST,M3.5.0,M10.5.0/3").unwrap()
    }

    fn ms(s: &str) -> u64 {
        s.parse::<jiff::Timestamp>().unwrap().as_millisecond() as u64
    }

    #[test]
    fn a_session_first_opened_at_07_15_is_open_at_23_59_and_stops_at_02_00() {
        let warsaw = warsaw();
        // 07:15 CET
        let first_open = ms("2027-01-15T06:15:00Z");
        let stop = hard_stop_in(first_open, &warsaw);
        // 23:59 the same day: still before the stop
        assert!(ms("2027-01-15T22:59:00Z") < stop);
        // 02:00 the next night, 18 h 45 min after the first open (before 24 hours)
        assert_eq!(stop, ms("2027-01-16T01:00:00Z"));
        assert_eq!(stop - first_open, (18 * 60 + 45) * 60_000);
        // the same through `Saved`, in this machine's zone
        let local = |day: i8, h: i8, m: i8| {
            jiff::civil::date(2027, 1, day)
                .at(h, m, 0, 0)
                .to_zoned(TimeZone::system())
                .unwrap()
                .timestamp()
                .as_millisecond() as u64
        };
        let s = Saved {
            first_open: Some(local(15, 7, 15)),
            ..Saved::default()
        };
        assert!(!s.past_hard_stop(local(15, 23, 59)));
        assert!(!s.past_hard_stop(local(16, 1, 59)));
        assert!(s.past_hard_stop(local(16, 2, 0)));
    }

    #[test]
    fn a_session_first_opened_at_03_00_runs_until_02_00_the_next_night() {
        // about 23 hours, the longest a session runs to 02:00
        assert_eq!(
            hard_stop_in(ms("2027-01-15T02:00:00Z"), &warsaw()),
            ms("2027-01-16T01:00:00Z")
        );
    }

    #[test]
    fn hard_stop_across_daylight_saving_changes() {
        // POSIX rules, so the test runs without a time zone database: Europe/Warsaw and
        // America/Los_Angeles as of 2026
        let warsaw = warsaw();
        let la = jiff::tz::TimeZone::posix("PST8PDT,M3.2.0,M11.1.0").unwrap();
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
        // opened at the second 02:00 (CET): the next 02:00 is 24 hours away, the same moment
        assert_eq!(
            hard_stop_in(ms("2026-10-25T01:00:00Z"), &warsaw),
            ms("2026-10-26T01:00:00Z")
        );
        // spring: 02:00 does not exist; the stop is when the clock jumps to 03:00 CEST
        assert_eq!(
            hard_stop_in(ms("2026-03-28T20:00:00Z"), &warsaw),
            ms("2026-03-29T01:00:00Z")
        );
        // opened right after the jump: 02:00 the next night, 23 hours later
        assert_eq!(
            hard_stop_in(ms("2026-03-29T01:00:00Z"), &warsaw),
            ms("2026-03-30T00:00:00Z")
        );
        // 01:00 to 01:59 come twice there; 02:00 PST once
        assert_eq!(
            hard_stop_in(ms("2026-11-01T08:30:00Z"), &la),
            ms("2026-11-01T10:00:00Z")
        );
        // there the day before has 25 hours from 02:00 PDT to 02:00 PST: opened at 02:30 PDT,
        // 24 hours comes first, at 01:30 PST
        assert_eq!(
            hard_stop_in(ms("2026-10-31T09:30:00Z"), &la),
            ms("2026-11-01T09:30:00Z")
        );
        // opened exactly at 02:00: the next 02:00 is 24 hours away, the same moment
        assert_eq!(
            hard_stop_in(ms("2027-01-15T01:00:00Z"), &warsaw),
            ms("2027-01-16T01:00:00Z")
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
