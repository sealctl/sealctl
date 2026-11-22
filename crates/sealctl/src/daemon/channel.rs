//! The machine channel (SPEC 6.6): while Open, the daemon keeps the machine socket open,
//! sends its status, and applies `lock`, `answers`, `ack` and `notice` messages, plus the
//! relay's own `delayed` and `cancelled` notes.

use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::Value;
use tokio_tungstenite::tungstenite::Message;

use super::Daemon;
use crate::relay;

/// Runs until the session locks (the task is aborted) or the relay says it has no channel.
pub async fn run(d: Arc<Daemon>) {
    if let Err(e) = d.send_status(&[]).await {
        log::info!("status: {e:#}");
    }
    let mut backoff = 2u64;
    loop {
        let (keys_path, sock) = {
            let paired = d.paired.lock().await;
            let path = format!(
                "/v1/phones/{}/machines/{}/socket",
                paired.phone_id(),
                paired.file.machine
            );
            let s = d.relay.socket(&paired.keys, &path).await;
            (path, s)
        };
        let mut ws = match sock {
            Ok(ws) => ws,
            Err(e) => {
                if let Some(a) = relay::refused(&e) {
                    if a.status == 404 {
                        log::info!("this relay has no machine channel; trying again in 6 hours");
                        tokio::time::sleep(Duration::from_secs(6 * 3600)).await;
                        continue;
                    }
                    if a.status == 403 {
                        let mut paired = d.paired.lock().await;
                        if !matches!(crate::approve::look_up(&d.relay, &mut paired).await, Ok(true)) {
                            drop(paired);
                            d.lock("unpaired", true, false).await;
                            return;
                        }
                        continue;
                    }
                }
                log::info!("machine socket {keys_path}: {e:#}");
                tokio::time::sleep(Duration::from_secs(backoff)).await;
                backoff = (backoff * 2).min(300);
                continue;
            }
        };
        backoff = 2;
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        ping.tick().await;
        loop {
            tokio::select! {
                _ = ping.tick() => {
                    if ws.send(Message::text("ping")).await.is_err() {
                        break;
                    }
                }
                m = ws.next() => {
                    let Some(Ok(m)) = m else { break };
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
                            v["releaseAt"].as_u64().unwrap_or(0),
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
        tokio::time::sleep(Duration::from_secs(backoff)).await;
    }
}
