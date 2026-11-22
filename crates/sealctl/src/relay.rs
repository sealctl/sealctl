//! Relay client (SPEC 7): signed HTTP calls and WebSockets.
//!
//! Every call is signed with the pairing key (protocol.md, Relay API, Signing). TLS through
//! rustls with the platform verifier. Network errors and `5xx` are retried at 1, 2 and 4 s,
//! then the command fails with exit 6; `429` is not retried (exit 7); `401 clock_skew` is
//! exit 12. Only method, path, status and duration are logged, never headers or bodies.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use futures_util::{SinkExt, StreamExt};
use sealctl_core::MachineKeys;
use serde_json::{json, Value};
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::{self, client::IntoClientRequest, http::HeaderValue, Message};
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::config::host_of;
use crate::exit::{self, fail};

/// The status page every relay error points to.
pub const STATUS_PAGE: &str = "https://sealctl.com/status";

/// A WebSocket to the relay.
pub type Socket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// One relay origin.
#[derive(Clone)]
pub struct Relay {
    origin: String,
    http: reqwest::Client,
}

/// An HTTP answer.
#[derive(Debug, Clone)]
pub struct Answer {
    /// HTTP status.
    pub status: u16,
    /// The JSON body (`null` when empty or not JSON).
    pub body: Value,
}

impl Answer {
    /// The `error` code of a failed call.
    pub fn error(&self) -> &str {
        self.body["error"].as_str().unwrap_or("")
    }

    /// 2xx.
    pub fn ok(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// How a wait ended.
#[derive(Debug)]
pub enum WaitEnd {
    /// The phone's sealed reply.
    Reply(String),
    /// Approved with a delay; fetch the reply from `GET .../delayed/{id}` after `release_at` (ms).
    Delayed {
        /// The delayed id (the request id).
        id: String,
        /// When the reply is released, Unix ms.
        release_at: u64,
    },
    /// The request expired without an answer.
    Expired,
    /// The relay closed the wait with an error code (`unpaired`, `moved`, ...).
    Error(String),
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn tls_config() -> Result<Arc<rustls::ClientConfig>> {
    static CFG: OnceLock<Arc<rustls::ClientConfig>> = OnceLock::new();
    if let Some(c) = CFG.get() {
        return Ok(c.clone());
    }
    use rustls_platform_verifier::BuilderVerifierExt;
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let cfg = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .context("TLS setup")?
        .with_platform_verifier()
        .context("TLS setup")?
        .with_no_client_auth();
    Ok(CFG.get_or_init(|| Arc::new(cfg)).clone())
}

/// The error for a failed relay answer (SPEC 5.5).
pub fn error_for(answer: &Answer) -> anyhow::Error {
    let code = answer.error();
    match answer.status {
        401 if code == "clock_skew" => {
            let minutes = answer.body["time"]
                .as_u64()
                .map(|t| unix_now().abs_diff(t).div_ceil(60))
                .unwrap_or(5);
            fail(
                exit::CLOCK,
                format!("This computer's clock is {minutes} minutes off. Set the time automatically and try again."),
            )
        }
        429 => {
            let retry = answer.body["retryAfter"].as_u64().unwrap_or(60);
            if answer.body["scope"].as_str().unwrap_or("phone") == "phone" {
                fail(
                    exit::LIMIT,
                    "Your phone reached the relay's daily limit of 5,000 requests. It resets at 00:00 UTC.",
                )
            } else {
                fail(
                    exit::LIMIT,
                    format!("Too many requests from this network. Try again in {retry} s."),
                )
            }
        }
        s if s >= 500 => fail(
            exit::RELAY,
            format!("The relay failed ({s}). Status: {STATUS_PAGE}"),
        ),
        s => fail(
            exit::RELAY,
            format!("The relay refused the call ({s} {code}). Status: {STATUS_PAGE}"),
        ),
    }
}

impl Relay {
    /// A client for `origin` (already validated).
    pub fn new(origin: &str) -> Result<Relay> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("sealctl/", env!("CARGO_PKG_VERSION")))
            .build()
            .context("HTTP client")?;
        Ok(Relay {
            origin: origin.trim_end_matches('/').to_string(),
            http,
        })
    }

    /// The origin.
    pub fn origin(&self) -> &str {
        &self.origin
    }

    fn unreachable(&self, reason: impl std::fmt::Display) -> anyhow::Error {
        fail(
            exit::RELAY,
            format!(
                "Cannot reach the relay ({}): {reason}. Status: {STATUS_PAGE}",
                host_of(&self.origin)
            ),
        )
    }

    async fn once(
        &self,
        keys: Option<&MachineKeys>,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<Answer, String> {
        let url = format!("{}{path}", self.origin);
        let m = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| e.to_string())?;
        let mut rb = self.http.request(m, &url);
        if let Some(k) = keys {
            let h = sealctl_core::relay_auth::machine_relay_headers(k, method, path, unix_now(), body);
            rb = rb
                .header("Sealctl-Key", h.key)
                .header("Sealctl-Time", h.time)
                .header("Sealctl-Signature", h.signature);
        }
        if !body.is_empty() {
            rb = rb.header("Content-Type", "application/json").body(body.to_vec());
        }
        let started = Instant::now();
        let resp = rb.send().await.map_err(|e| {
            let mut s = e.to_string();
            if e.is_timeout() {
                s = "timed out".into();
            } else if e.is_connect() {
                s = "connection failed".into();
            }
            s
        })?;
        let status = resp.status().as_u16();
        let bytes = resp.bytes().await.map_err(|e| e.to_string())?;
        log::debug!("{method} {path} {status} {} ms", started.elapsed().as_millis());
        let body = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        Ok(Answer { status, body })
    }

    /// A call with retries (network errors and 5xx at 1, 2, 4 s). Returns any answer the relay
    /// gave, success or not; fails only when the relay cannot be reached or keeps failing.
    pub async fn request(
        &self,
        keys: Option<&MachineKeys>,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Answer> {
        let bytes = match body {
            Some(b) => serde_json::to_vec(b)?,
            None => Vec::new(),
        };
        let mut last_err = String::new();
        for (attempt, delay) in [0u64, 1, 2, 4].into_iter().enumerate() {
            if attempt > 0 {
                tokio::time::sleep(Duration::from_secs(delay)).await;
            }
            match self.once(keys, method, path, &bytes).await {
                Ok(a) if a.status >= 500 && attempt < 3 => {
                    last_err = format!("{}", a.status);
                    continue;
                }
                Ok(a) => return Ok(a),
                Err(e) => last_err = e,
            }
        }
        Err(self.unreachable(last_err))
    }

    /// A call that must succeed: any non-2xx answer becomes the error of SPEC 5.5.
    pub async fn call(
        &self,
        keys: &MachineKeys,
        method: &str,
        path: &str,
        body: Option<&Value>,
    ) -> Result<Value> {
        let a = self.request(Some(keys), method, path, body).await?;
        if a.ok() {
            Ok(a.body)
        } else {
            Err(error_for(&a))
        }
    }

    /// `GET /v1/health` with a short timeout.
    pub async fn health(&self) -> Result<Value> {
        let url = format!("{}/v1/health", self.origin);
        let resp = self
            .http
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|e| self.unreachable(e))?;
        let status = resp.status().as_u16();
        let body: Value = resp.json().await.unwrap_or(Value::Null);
        if status != 200 {
            return Err(error_for(&Answer { status, body }));
        }
        Ok(body)
    }

    fn ws_url(&self, path: &str) -> String {
        let o = if let Some(r) = self.origin.strip_prefix("https://") {
            format!("wss://{r}")
        } else if let Some(r) = self.origin.strip_prefix("http://") {
            format!("ws://{r}")
        } else {
            self.origin.clone()
        };
        format!("{o}{path}")
    }

    /// Opens a signed WebSocket (`wait` or the machine socket).
    pub async fn socket(&self, keys: &MachineKeys, path: &str) -> Result<Socket> {
        let mut req = self.ws_url(path).into_client_request().context("relay URL")?;
        let h = sealctl_core::relay_auth::machine_relay_headers(keys, "GET", path, unix_now(), b"");
        let hdrs = req.headers_mut();
        hdrs.insert("Sealctl-Key", HeaderValue::from_str(&h.key)?);
        hdrs.insert("Sealctl-Time", HeaderValue::from_str(&h.time)?);
        hdrs.insert("Sealctl-Signature", HeaderValue::from_str(&h.signature)?);
        let connector = if self.origin.starts_with("https://") {
            Some(tokio_tungstenite::Connector::Rustls(tls_config()?))
        } else {
            None
        };
        let started = Instant::now();
        let fut = tokio_tungstenite::connect_async_tls_with_config(req, None, false, connector);
        let res = tokio::time::timeout(Duration::from_secs(10), fut)
            .await
            .map_err(|_| self.unreachable("timed out"))?;
        match res {
            Ok((ws, _)) => {
                log::debug!("GET {path} 101 {} ms", started.elapsed().as_millis());
                Ok(ws)
            }
            Err(tungstenite::Error::Http(resp)) => {
                let status = resp.status().as_u16();
                log::debug!("GET {path} {status} {} ms", started.elapsed().as_millis());
                let body = resp
                    .body()
                    .as_ref()
                    .and_then(|b| serde_json::from_slice(b).ok())
                    .unwrap_or(Value::Null);
                Err(anyhow::Error::new(Refused(Answer { status, body })))
            }
            Err(e) => Err(self.unreachable(e)),
        }
    }

    /// Sends one sealed request on a new wait socket and waits for its end, at most until
    /// `deadline`. Pings every 30 seconds.
    pub async fn wait(
        &self,
        keys: &MachineKeys,
        phone: &str,
        id: &str,
        sealed: &str,
        ttl: u64,
        deadline: tokio::time::Instant,
    ) -> Result<WaitEnd> {
        let mut ws = self.socket(keys, &format!("/v1/phones/{phone}/wait")).await?;
        let msg = json!({"type": "request", "id": id, "sealed": sealed, "ttl": ttl});
        ws.send(Message::text(msg.to_string()))
            .await
            .map_err(|e| self.unreachable(e))?;
        let mut ping = tokio::time::interval(Duration::from_secs(30));
        ping.tick().await;
        loop {
            tokio::select! {
                _ = tokio::time::sleep_until(deadline) => {
                    let _ = ws.close(None).await;
                    return Ok(WaitEnd::Expired);
                }
                _ = ping.tick() => {
                    let _ = ws.send(Message::text("ping")).await;
                }
                m = ws.next() => {
                    let Some(m) = m else {
                        return Err(self.unreachable("the relay closed the connection"));
                    };
                    let m = m.map_err(|e| self.unreachable(e))?;
                    let text = match m {
                        Message::Text(t) => t.to_string(),
                        Message::Close(_) => return Err(self.unreachable("the relay closed the connection")),
                        _ => continue,
                    };
                    if text == "pong" {
                        continue;
                    }
                    let v: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
                    match v["type"].as_str().unwrap_or("") {
                        "queued" => continue,
                        "reply" if v["id"] == id => {
                            let s = v["sealed"].as_str().unwrap_or("").to_string();
                            return Ok(WaitEnd::Reply(s));
                        }
                        "delayed" => {
                            return Ok(WaitEnd::Delayed {
                                id: v["id"].as_str().unwrap_or(id).to_string(),
                                release_at: v["releaseAt"].as_u64().unwrap_or(0),
                            });
                        }
                        "expired" => return Ok(WaitEnd::Expired),
                        "error" => return Ok(WaitEnd::Error(v["error"].as_str().unwrap_or("error").to_string())),
                        _ => continue,
                    }
                }
            }
        }
    }
}

/// A WebSocket upgrade the relay refused with an HTTP answer.
#[derive(Debug)]
pub struct Refused(pub Answer);

impl std::fmt::Display for Refused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "relay refused ({} {})", self.0.status, self.0.error())
    }
}

impl std::error::Error for Refused {}

/// The refused answer inside an error, if any.
pub fn refused(e: &anyhow::Error) -> Option<&Answer> {
    e.downcast_ref::<Refused>().map(|r| &r.0)
}

/// A runtime for one command's relay calls.
pub fn runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("starting the async runtime")
}
