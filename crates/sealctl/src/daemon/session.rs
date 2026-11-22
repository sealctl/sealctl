//! Timers and credit (SPEC 6.4): idle allowance, hard stop, minutes worked. Pure functions of
//! the clock so tests can drive them with any time.

use chrono::{DateTime, Local, NaiveTime, TimeZone};
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
    let fourteen = first_open + 14 * 3600 * 1000;
    let Some(start) = Local.timestamp_millis_opt(first_open as i64).single() else {
        return fourteen;
    };
    let two = NaiveTime::from_hms_opt(2, 0, 0).expect("02:00");
    let mut day = start.date_naive();
    loop {
        if let Some(t) = Local.from_local_datetime(&day.and_time(two)).earliest() {
            let ms = t.timestamp_millis() as u64;
            if ms > first_open {
                return ms.min(fourteen);
            }
        }
        day = day.succ_opt().unwrap_or(day);
        if day > start.date_naive() + chrono::Days::new(2) {
            return fourteen;
        }
    }
}

/// `HH:MM` of a Unix ms time, local.
pub fn hhmm(ms: u64) -> String {
    Local
        .timestamp_millis_opt(ms as i64)
        .single()
        .map(|t| t.format("%H:%M").to_string())
        .unwrap_or_default()
}

/// RFC 3339 with offset.
pub fn rfc3339(ms: u64) -> String {
    Local
        .timestamp_millis_opt(ms as i64)
        .single()
        .map(|t: DateTime<Local>| t.to_rfc3339_opts(chrono::SecondsFormat::Secs, false))
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
        let at = Local.timestamp_millis_opt(h as i64).single().unwrap();
        let fourteen = h == t0 + 14 * 3600 * 1000;
        assert!(fourteen || at.format("%H:%M").to_string() == "02:00");
    }

    #[test]
    fn durations() {
        assert_eq!(duration(45), "45 s");
        assert_eq!(duration(1800), "30 min");
        assert_eq!(duration(11_520), "3 h 12 min");
        assert_eq!(duration(7200), "2 h");
    }
}
