//! The machine channel (SPEC 6.6): while Open, the daemon keeps the machine socket open,
//! sends its status, and applies `lock`, `answers`, `ack` and `notice` messages, plus the
//! relay's own `delayed` and `cancelled` notes.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

use super::Daemon;
use crate::approve;
use crate::poll::jitter;
use crate::relay::{self, WaitEnd};

/// How long the machine socket waits before the next upgrade.
///
/// Every reconnect waits, whatever ended the last socket; the wait doubles from 2 s up to
/// 300 s and starts over only after a socket stayed open for a minute. A relay that accepts
/// and drops at once (two daemons sharing a machine key evict each other's socket; a relay
/// restart) therefore cannot make a reconnect every 2 s forever, each of which costs the
/// phone's daily limit. Waits get ±20% jitter so that daemons do not reconnect in step, and
/// a `429` is waited out for at least its `retryAfter` (staging incident 2026-11-22).
#[derive(Debug, Clone)]
pub struct Reconnect {
    next: u64,
}

impl Default for Reconnect {
    fn default() -> Self {
        Reconnect { next: Self::FIRST }
    }
}

impl Reconnect {
    const FIRST: u64 = 2;
    const MAX: u64 = 300;
    /// A socket open at least this long resets the wait.
    pub const STABLE: Duration = Duration::from_secs(60);

    /// The wait after an attempt that ended: a failed upgrade (`open` = `None`) or a socket
    /// that was open for `open`. `retry_after` is a `429`'s `retryAfter`. `jitter` is in
    /// `0..1` (0.5 means none).
    pub fn after(&mut self, open: Option<Duration>, retry_after: Option<u64>, jitter: f64) -> Duration {
        if open.is_some_and(|o| o >= Self::STABLE) {
            self.next = Self::FIRST;
        }
        let base = self.next.max(retry_after.unwrap_or(0).min(3600));
        self.next = (self.next * 2).min(Self::MAX);
        Duration::from_secs_f64(base as f64 * (0.8 + 0.4 * jitter.clamp(0.0, 1.0)))
    }
}

/// The relay answers every `ping` (sent each 30 s) with `pong`. A socket that has carried
/// nothing for this long is taken as dead (a half-open connection after sleep or a network
/// change) and replaced, so held messages such as `lock` are fetched again.
const SILENT: Duration = Duration::from_secs(75);

/// Runs until the session locks (the task is aborted) or the relay says it has no channel.
pub async fn run(d: Arc<Daemon>) {
    // the open sent one already, unless it failed
    let unsent = {
        let st = d.st();
        st.status_dirty || st.sent_state != "open"
    };
    if unsent {
        if let Err(e) = d.send_status().await {
            log::info!("status: {e:#}");
        }
    }
    let mut wait = Reconnect::default();
    loop {
        // the pairing is not held while connecting (up to 10 s): requests and statuses go on
        let (keys_path, keys) = {
            let paired = d.paired.lock().await;
            let path = format!(
                "/v1/phones/{}/machines/{}/socket",
                paired.phone_id(),
                paired.file.machine
            );
            (path, paired.keys_copy())
        };
        let keys = match keys {
            Ok(k) => k,
            Err(e) => {
                log::warn!("machine channel: {e:#}");
                return;
            }
        };
        let sock = d.relay.socket(&keys, &keys_path).await;
        drop(keys);
        let mut ws = match sock {
            Ok(ws) => ws,
            Err(e) => {
                if let Some(a) = relay::refused(&e) {
                    if a.status == 404 {
                        log::info!("this relay has no machine channel: report requests for 6 hours");
                        if !report_loop(&d, Duration::from_secs(6 * 3600)).await {
                            return;
                        }
                        continue;
                    }
                    if a.status == 403 {
                        let mut paired = d.paired.lock().await;
                        if !matches!(crate::approve::look_up(&d.relay, &mut paired).await, Ok(true)) {
                            drop(paired);
                            d.lock("unpaired", true, false).await;
                            return;
                        }
                        // Still paired, yet refused: wait like any failure, never at once.
                    }
                }
                let retry_after = relay::refused(&e)
                    .filter(|a| a.status == 429)
                    .and_then(|a| a.body["retryAfter"].as_u64());
                log::info!("machine socket {keys_path}: {e:#}");
                tokio::time::sleep(wait.after(None, retry_after, jitter())).await;
                continue;
            }
        };
        d.reset_answer_parts();
        let opened = tokio::time::Instant::now();
        let mut heard = opened;
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        ping.tick().await;
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    if heard.elapsed() >= SILENT {
                        log::info!("machine socket {keys_path}: no answer to ping; reconnecting");
                        break;
                    }
                    if ws.send(Message::text("ping")).await.is_err() {
                        break;
                    }
                }
                m = ws.next() => {
                    let Some(Ok(m)) = m else { break };
                    heard = tokio::time::Instant::now();
                    let Message::Text(t) = m else { continue };
                    if t.as_str() == "pong" {
                        continue;
                    }
                    let v: Value = serde_json::from_str(t.as_str()).unwrap_or(Value::Null);
                    match v["type"].as_str().unwrap_or("") {
                        "message" => {
                            if let Some(s) = v["sealed"].as_str() {
                                d.on_message(s).await;
                            }
                        }
                        "delayed" => d.on_delayed_note(
                            v["id"].as_str().unwrap_or(""),
                            v["machine"].as_str(),
                            v["releaseAt"].as_u64(),
                        ),
                        "cancelled" => d.on_cancelled_note(v["id"].as_str().unwrap_or("")),
                        "error" => {
                            let code = v["error"].as_str().unwrap_or("");
                            if code == "unpaired" || code == "moved" {
                                let mut paired = d.paired.lock().await;
                                if !matches!(crate::approve::look_up(&d.relay, &mut paired).await, Ok(true)) {
                                    drop(paired);
                                    d.lock("unpaired", true, false).await;
                                    return;
                                }
                            }
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }
        tokio::time::sleep(wait.after(Some(opened.elapsed()), None, jitter())).await;
    }
}

/// The fallback without a machine channel (protocol.md, Machine status and messages): one
/// `report` request waiting on the relay at a time, at most one every 60 seconds, carrying the
/// status fields; the phone's reply carries `ack` and the messages waiting for this machine.
/// Returns `false` when the machine was unpaired (the session is then locked).
pub async fn report_loop(d: &Arc<Daemon>, for_how_long: Duration) -> bool {
    d.reset_answer_parts();
    let until = tokio::time::Instant::now() + for_how_long;
    while tokio::time::Instant::now() < until {
        let started = tokio::time::Instant::now();
        let body = d.report_body().await;
        // seal under the lock, wait without it: other requests go on meanwhile
        let sealed = {
            let paired = d.paired.lock().await;
            let id = match sealctl_core::request::new_request_id() {
                Ok(i) => i,
                Err(_) => return true,
            };
            let Ok(keys) = paired.keys_copy() else {
                return true;
            };
            sealctl_core::request::seal_request(&paired.keys, &paired.phone, &id, body)
                .ok()
                .map(|r| {
                    (
                        r,
                        keys,
                        paired.phone_id().to_string(),
                        *paired.keys.public(),
                        paired.phone.identity,
                    )
                })
        };
        let Some((request, keys, phone_id, m, p)) = sealed else {
            return true;
        };
        let deadline = tokio::time::Instant::now() + approve::WAIT;
        let end = d
            .relay
            .wait(
                &keys,
                &phone_id,
                &request.id,
                &request.sealed,
                approve::WAIT.as_secs(),
                deadline,
            )
            .await;
        match end {
            Ok(WaitEnd::Reply(s)) => {
                if let Ok(reply) = request.open_reply(&m, &p, &s) {
                    if reply.ok {
                        if let Some(ack) = reply.ack {
                            d.ack(ack);
                        }
                        for msg in reply.msgs {
                            let take = super::take_message(&mut d.paired.lock().await.file, &msg);
                            if take {
                                d.apply_message(msg).await;
                            }
                        }
                    }
                }
            }
            Ok(WaitEnd::Error(code)) if code == "unpaired" || code == "moved" => {
                let mut paired = d.paired.lock().await;
                if !matches!(approve::look_up(&d.relay, &mut paired).await, Ok(true)) {
                    drop(paired);
                    d.lock("unpaired", true, false).await;
                    return false;
                }
            }
            Ok(_) => {}
            Err(e) => log::info!("report: {e:#}"),
        }
        if !d.st().open {
            return true;
        }
        tokio::time::sleep_until(started + Duration::from_secs(60)).await;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::Reconnect;
    use std::time::Duration;

    const NONE: f64 = 0.5;

    #[test]
    fn a_socket_dropped_at_once_backs_off() {
        // two daemons on one machine key evict each other: each socket lives a moment
        let mut w = Reconnect::default();
        let waits: Vec<u64> = (0..10)
            .map(|_| w.after(Some(Duration::from_millis(200)), None, NONE).as_secs())
            .collect();
        assert_eq!(waits, [2, 4, 8, 16, 32, 64, 128, 256, 300, 300]);
    }

    #[test]
    fn a_stable_socket_starts_over() {
        let mut w = Reconnect::default();
        for _ in 0..5 {
            w.after(None, None, NONE);
        }
        assert_eq!(
            w.after(Some(Reconnect::STABLE), None, NONE),
            Duration::from_secs(2)
        );
        assert_eq!(w.after(None, None, NONE), Duration::from_secs(4));
    }

    #[test]
    fn a_429_is_waited_out_and_jitter_stays_within_20_percent() {
        let mut w = Reconnect::default();
        assert_eq!(w.after(None, Some(60), NONE), Duration::from_secs(60));
        assert_eq!(w.after(None, Some(86_400), NONE), Duration::from_secs(3600));
        let mut w = Reconnect::default();
        assert_eq!(w.after(None, None, 0.0), Duration::from_secs_f64(1.6));
        let mut w = Reconnect::default();
        assert_eq!(w.after(None, None, 1.0), Duration::from_secs_f64(2.4));
    }
}
