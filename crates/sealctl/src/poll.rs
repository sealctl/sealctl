//! Polling the relay until an answer is final (SPEC 7): `pair` waiting for the phone, `buy`
//! waiting for the payment, `unseal` waiting for a delayed approval.
//!
//! Every pause gets ±20% jitter. "Not yet" answers are asked again after `every`, growing by
//! half each time up to `most`. Failed calls (the relay unreachable after its own retries, a
//! `5xx`, a short-term `429`) wait `every`, doubling up to 30 s, and at least a `429`'s
//! `retryAfter`. A final answer ends the poll at once: the daily limit (`429` scope `phone`),
//! `401` (`clock_skew` is asked once more), `403`, any other `4xx` the caller does not expect.

use std::future::Future;
use std::time::Duration;

use anyhow::Result;
use tokio::time::Instant;

use crate::relay::{error_for, Answer};

/// The longest pause after failed calls.
pub const ERROR_CAP: Duration = Duration::from_secs(30);

/// How often a poll asks.
#[derive(Debug, Clone, Copy)]
pub struct Pace {
    /// The first pause.
    pub every: Duration,
    /// The longest pause between "not yet" answers.
    pub most: Duration,
}

/// What the caller makes of an answer.
#[derive(Debug)]
pub enum Seen<T> {
    /// The answer it waited for.
    Done(T),
    /// Not yet: ask again at the poll's pace.
    NotYet,
    /// Not yet: ask again after this long, without jitter (a known release time).
    After(Duration),
    /// Not an answer the caller knows: the poll decides (wait, or end with its error).
    Other,
}

/// A number in `0..1` for jitter (0.5 means none).
pub fn jitter() -> f64 {
    let mut b = [0u8; 2];
    let _ = getrandom::fill(&mut b);
    f64::from(u16::from_le_bytes(b)) / f64::from(u16::MAX)
}

fn jittered(d: Duration, j: f64) -> Duration {
    d.mul_f64(0.8 + 0.4 * j.clamp(0.0, 1.0))
}

/// The pauses of one poll.
#[derive(Debug, Clone)]
pub struct Pauses {
    pace: Pace,
    not_yet: Duration,
    failed: u32,
    skewed: bool,
}

/// What to do after an answer the caller left to the poll.
#[derive(Debug, PartialEq, Eq)]
pub enum Then {
    /// Ask again after this long.
    Wait(Duration),
    /// The answer is final.
    Stop,
}

impl Pauses {
    /// Fresh pauses at `pace`.
    pub fn new(pace: Pace) -> Pauses {
        Pauses {
            pace,
            not_yet: pace.every,
            failed: 0,
            skewed: false,
        }
    }

    /// The pause after a "not yet" answer; `j` is the jitter in `0..1`.
    pub fn not_yet(&mut self, j: f64) -> Duration {
        self.failed = 0;
        let d = self.not_yet;
        self.not_yet = self.not_yet.mul_f64(1.5).min(self.pace.most.max(self.pace.every));
        jittered(d, j)
    }

    /// The pause after a call that reached no answer (the relay unreachable).
    pub fn failed(&mut self, j: f64) -> Duration {
        self.failed_at_least(0, j)
    }

    fn failed_at_least(&mut self, retry_after: u64, j: f64) -> Duration {
        let d = self
            .pace
            .every
            .saturating_mul(1 << self.failed.min(16))
            .min(ERROR_CAP.max(self.pace.every));
        self.failed = self.failed.saturating_add(1);
        jittered(d, j).max(Duration::from_secs(retry_after))
    }

    /// What to do after an answer the caller did not expect.
    pub fn answer(&mut self, a: &Answer, j: f64) -> Then {
        match a.status {
            429 if a.body["scope"].as_str().unwrap_or("phone") == "phone" => Then::Stop,
            429 => Then::Wait(self.failed_at_least(a.body["retryAfter"].as_u64().unwrap_or(10), j)),
            401 if a.error() == "clock_skew" && !self.skewed => {
                self.skewed = true;
                Then::Wait(self.failed(j))
            }
            s if s >= 500 => Then::Wait(self.failed(j)),
            _ => Then::Stop,
        }
    }
}

/// Calls `call` until `judge` says [`Seen::Done`] (its value), a final answer or error ends
/// the poll (that error), or `deadline` passes: `None`, or the last error when the last call
/// failed. The first call goes at once.
pub async fn until<T, F, Fut, J>(
    pace: Pace,
    deadline: Instant,
    mut call: F,
    mut judge: J,
) -> Result<Option<T>>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<Answer>>,
    J: FnMut(&Answer) -> Result<Seen<T>>,
{
    let mut p = Pauses::new(pace);
    loop {
        let (wait, last_err) = match call().await {
            Ok(a) => match judge(&a)? {
                Seen::Done(t) => return Ok(Some(t)),
                Seen::NotYet => (p.not_yet(jitter()), None),
                Seen::After(d) => (d, None),
                Seen::Other => match p.answer(&a, jitter()) {
                    Then::Wait(d) => (d, Some(error_for(&a))),
                    Then::Stop => return Err(error_for(&a)),
                },
            },
            Err(e) => (p.failed(jitter()), Some(e)),
        };
        let now = Instant::now();
        if now + wait > deadline {
            if let Some(e) = last_err {
                return Err(e);
            }
            // one last look at the deadline itself, if there is time left
            if now >= deadline {
                return Ok(None);
            }
            tokio::time::sleep_until(deadline).await;
            return match call().await {
                Ok(a) => match judge(&a)? {
                    Seen::Done(t) => Ok(Some(t)),
                    Seen::Other if p.answer(&a, 0.5) == Then::Stop => Err(error_for(&a)),
                    _ => Ok(None),
                },
                Err(_) => Ok(None),
            };
        }
        tokio::time::sleep(wait).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::exit;
    use serde_json::{json, Value};
    use std::sync::{Arc, Mutex};

    fn a(status: u16, body: Value) -> Answer {
        Answer { status, body }
    }

    const PACE: Pace = Pace {
        every: Duration::from_secs(2),
        most: Duration::from_secs(30),
    };

    #[test]
    fn not_yet_grows_by_half_up_to_most() {
        let mut p = Pauses::new(Pace {
            every: Duration::from_secs(2),
            most: Duration::from_secs(5),
        });
        let got: Vec<u128> = (0..5).map(|_| p.not_yet(0.5).as_millis()).collect();
        assert_eq!(got, vec![2000, 3000, 4500, 5000, 5000]);
    }

    #[test]
    fn failures_double_up_to_30_s_and_honour_retry_after() {
        let mut p = Pauses::new(PACE);
        let got: Vec<u64> = (0..6).map(|_| p.failed(0.5).as_secs()).collect();
        assert_eq!(got, vec![2, 4, 8, 16, 30, 30]);
        // an answer resets the doubling
        p.not_yet(0.5);
        assert_eq!(p.failed(0.5), Duration::from_secs(2));
        let mut p = Pauses::new(PACE);
        let limited = a(
            429,
            json!({"error": "rate_limited", "scope": "network", "retryAfter": 45}),
        );
        assert_eq!(p.answer(&limited, 0.5), Then::Wait(Duration::from_secs(45)));
    }

    #[test]
    fn jitter_stays_within_20_percent() {
        for j in [0.0, 0.25, 1.0, -3.0, 7.0] {
            let d = Pauses::new(PACE).not_yet(j);
            assert!(
                d >= Duration::from_millis(1600) && d <= Duration::from_millis(2400),
                "{d:?}"
            );
        }
        let spread: std::collections::BTreeSet<u128> = (0..50)
            .map(|_| Pauses::new(PACE).not_yet(jitter()).as_millis())
            .collect();
        assert!(spread.len() > 1, "the pauses vary");
    }

    #[test]
    fn final_answers_stop() {
        let mut p = Pauses::new(PACE);
        for (s, body) in [
            (
                429,
                json!({"error": "rate_limited", "scope": "phone", "retryAfter": 3600}),
            ),
            (429, json!({"error": "rate_limited"})),
            (401, json!({"error": "bad_signature"})),
            (403, json!({"error": "forbidden"})),
            (400, json!({"error": "bad_id"})),
            (404, json!({"error": "not_found"})),
        ] {
            assert_eq!(p.answer(&a(s, body.clone()), 0.5), Then::Stop, "{s} {body}");
        }
        // clock_skew is asked once more, then it is final
        let skew = a(401, json!({"error": "clock_skew", "time": 1}));
        assert!(matches!(p.answer(&skew, 0.5), Then::Wait(_)));
        assert_eq!(p.answer(&skew, 0.5), Then::Stop);
        assert!(matches!(p.answer(&a(503, json!({})), 0.5), Then::Wait(_)));
    }

    /// Runs a poll against scripted answers on a paused clock; returns its result and the
    /// seconds of every call from the start.
    async fn run(
        answers: Vec<Result<Answer, ()>>,
        deadline: Duration,
    ) -> (Result<Option<&'static str>>, Vec<f64>) {
        let start = Instant::now();
        let times = Arc::new(Mutex::new(Vec::new()));
        let left = Arc::new(Mutex::new(answers.into_iter()));
        let t2 = times.clone();
        let r = until(
            PACE,
            start + deadline,
            || {
                t2.lock().unwrap().push(start.elapsed().as_secs_f64());
                let next = left.lock().unwrap().next();
                async move {
                    match next {
                        Some(Ok(a)) => Ok(a),
                        Some(Err(())) | None => Err(anyhow::anyhow!("unreachable")),
                    }
                }
            },
            |a| {
                Ok(match a.status {
                    200 => Seen::Done("paid"),
                    404 => Seen::NotYet,
                    _ => Seen::Other,
                })
            },
        )
        .await;
        let t = times.lock().unwrap().clone();
        (r, t)
    }

    #[tokio::test(start_paused = true)]
    async fn the_daily_limit_ends_a_poll_at_once() {
        let limited = a(
            429,
            json!({"error": "rate_limited", "scope": "phone", "retryAfter": 3600}),
        );
        let (r, t) = run(vec![Ok(a(404, json!({}))), Ok(limited)], Duration::from_secs(900)).await;
        assert_eq!(exit::code_of(&r.unwrap_err()), exit::LIMIT);
        assert_eq!(t.len(), 2, "{t:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn failed_calls_back_off_and_an_answer_ends_it() {
        let answers = vec![
            Err(()),
            Ok(a(503, json!({}))),
            Err(()),
            Err(()),
            Ok(a(200, json!({}))),
        ];
        let (r, t) = run(answers, Duration::from_secs(900)).await;
        assert_eq!(r.unwrap(), Some("paid"));
        let gaps: Vec<f64> = t.windows(2).map(|w| w[1] - w[0]).collect();
        for (gap, want) in gaps.iter().zip([2.0, 4.0, 8.0, 16.0]) {
            assert!(*gap >= want * 0.8 - 0.01 && *gap <= want * 1.2 + 0.01, "{gaps:?}");
        }
    }

    #[tokio::test(start_paused = true)]
    async fn a_poll_ends_at_its_deadline() {
        let (r, t) = run(vec![Ok(a(404, json!({}))); 100], Duration::from_secs(60)).await;
        assert_eq!(r.unwrap(), None);
        // 2, 3, 4.5, 6.75, ... s apart (±20%): far fewer than one call every 2 s
        assert!(t.len() <= 12, "{t:?}");
        assert!(*t.last().unwrap() <= 60.0 + 0.01, "{t:?}");
        // the last failure is what a poll that runs out says
        let (r, _) = run(vec![Err(()); 100], Duration::from_secs(60)).await;
        assert!(r.unwrap_err().to_string().contains("unreachable"));
    }
}
