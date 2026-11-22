//! An in-process implementation of the Relay API (docs/protocol.md) for tests: real signature
//! checks, roles, pairing, approvals over WebSockets, delayed approvals, the machine channel,
//! licence, checkout and seat codes. State lives in memory.

use std::collections::{BTreeMap, HashMap};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequest, Request, State};
use axum::http::{Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Router;
use sealctl_core::relay_auth::{verify_relay_headers, RelayHeaders};
use serde_json::{json, Value};
use tokio::sync::mpsc::{unbounded_channel, UnboundedSender};

/// Something sent to a socket: a text frame, or a text frame then close.
#[derive(Debug, Clone)]
enum Out {
    Text(String),
    Close(String),
}

struct Pending {
    machine: String,
    sealed: String,
    created: u64,
    expires: u64,
    tx: UnboundedSender<Out>,
}

#[derive(Clone)]
struct DelayedRec {
    machine: Option<String>,
    sealed: Option<String>,
    created: u64,
    release_at: u64,
    expires: u64,
    cancelled: Option<(String, u64)>,
}

#[derive(Default)]
struct PhoneRec {
    machines: BTreeMap<String, Value>,
    pending: BTreeMap<String, Pending>,
    phone_sockets: Vec<UnboundedSender<Out>>,
    machine_sockets: HashMap<String, UnboundedSender<Out>>,
    held: HashMap<String, Vec<(String, u64)>>,
    status: HashMap<String, (String, u64)>,
    delayed: BTreeMap<String, DelayedRec>,
    paid: bool,
    source: Option<String>,
    days_used: u64,
    last_day: u64,
    codes: Vec<(String, u64, u64)>,
}

/// Switches for tests.
#[derive(Debug, Clone)]
pub struct Options {
    /// Checkout works (else `503 payments_not_configured`, as staging answers).
    pub payments: bool,
    /// The machine channel is offered (else the socket upgrade answers `404`).
    pub machine_channel: bool,
    /// `near` on requests.
    pub near: bool,
    /// `ask` threshold in days.
    pub ask_after_days: u64,
}

impl Default for Options {
    fn default() -> Self {
        Options {
            payments: true,
            machine_channel: true,
            near: false,
            ask_after_days: 30,
        }
    }
}

#[derive(Default)]
struct Inner {
    index: HashMap<String, (String, String)>,
    phones: HashMap<String, PhoneRec>,
    seats: HashMap<String, (u64, Vec<String>)>,
}

/// Shared state of a fake relay.
#[derive(Clone)]
pub struct App {
    inner: Arc<Mutex<Inner>>,
    opts: Arc<Mutex<Options>>,
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

fn err(status: u16, code: &str) -> Response {
    (
        StatusCode::from_u16(status).expect("status"),
        axum::Json(json!({"error": code})),
    )
        .into_response()
}

fn ok(status: u16, v: Value) -> Response {
    (StatusCode::from_u16(status).expect("status"), axum::Json(v)).into_response()
}

/// A running fake relay.
pub struct FakeRelay {
    /// `http://127.0.0.1:<port>`.
    pub origin: String,
    app: App,
    _rt: Option<std::thread::JoinHandle<()>>,
}

impl FakeRelay {
    /// Starts a relay on a free loopback port, on its own thread.
    pub fn start(opts: Options) -> FakeRelay {
        let app = App {
            inner: Arc::new(Mutex::new(Inner::default())),
            opts: Arc::new(Mutex::new(opts)),
        };
        let (tx, rx) = std::sync::mpsc::channel();
        let a2 = app.clone();
        let h = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .enable_all()
                .build()
                .expect("runtime");
            rt.block_on(async move {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.expect("bind");
                let addr: SocketAddr = listener.local_addr().expect("addr");
                tx.send(addr).expect("send addr");
                let router = Router::new().fallback(handle).with_state(a2);
                axum::serve(listener, router).await.expect("serve");
            });
        });
        let addr = rx.recv().expect("relay address");
        FakeRelay {
            origin: format!("http://127.0.0.1:{}", addr.port()),
            app,
            _rt: Some(h),
        }
    }

    /// Changes options while running.
    pub fn set(&self, f: impl FnOnce(&mut Options)) {
        f(&mut self.app.opts.lock().unwrap());
    }

    /// Marks a phone paid (as a Paddle webhook would).
    pub fn pay(&self, phone: &str, seats: u64) -> Option<String> {
        let mut g = self.app.inner.lock().unwrap();
        let mut code = None;
        if seats > 1 {
            let c = format!("TEST-{:04}", g.seats.len() + 1);
            g.seats.insert(c.clone(), (seats, vec![phone.to_string()]));
            code = Some(c);
        }
        let p = g.phones.entry(phone.to_string()).or_default();
        if !p.paid {
            p.paid = true;
            p.source = Some("purchase".into());
        }
        if let Some(c) = &code {
            p.codes.push((c.clone(), seats, 1));
        }
        code
    }

    /// Sets days used for a phone (for the ask).
    pub fn set_days_used(&self, phone: &str, days: u64) {
        self.app
            .inner
            .lock()
            .unwrap()
            .phones
            .entry(phone.to_string())
            .or_default()
            .days_used = days;
    }

    /// Pending request ids for a phone (for assertions).
    pub fn pending_count(&self, phone: &str) -> usize {
        self.app
            .inner
            .lock()
            .unwrap()
            .phones
            .get(phone)
            .map_or(0, |p| p.pending.len())
    }

    /// The latest sealed status of a machine.
    pub fn status_of(&self, phone: &str, machine: &str) -> Option<String> {
        self.app
            .inner
            .lock()
            .unwrap()
            .phones
            .get(phone)
            .and_then(|p| p.status.get(machine).map(|s| s.0.clone()))
    }

    /// Is the machine socket of `machine` open?
    pub fn machine_socket_open(&self, phone: &str, machine: &str) -> bool {
        self.app
            .inner
            .lock()
            .unwrap()
            .phones
            .get(phone)
            .is_some_and(|p| p.machine_sockets.get(machine).is_some_and(|t| !t.is_closed()))
    }
}

enum Role {
    Phone,
    Machine,
}

fn header(req: &axum::http::request::Parts, name: &str) -> Option<String> {
    req.headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

async fn handle(State(app): State<App>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let path = parts.uri.path().to_string();
    let pq = parts
        .uri
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or(path.clone());
    let segs: Vec<String> = path.trim_matches('/').split('/').map(str::to_owned).collect();
    let s: Vec<&str> = segs.iter().map(String::as_str).collect();
    let ws = parts.headers.get("upgrade").is_some();
    let bytes: Bytes = if ws {
        Bytes::new()
    } else {
        match axum::body::to_bytes(body, 2 << 20).await {
            Ok(b) => b,
            Err(_) => return err(413, "too_large"),
        }
    };
    if parts.method == Method::GET && s == ["v1", "health"] {
        return ok(
            200,
            json!({"ok": true, "env": "fake", "version": "test", "time": now_ms() / 1000}),
        );
    }
    // signature
    let (Some(key), Some(time), Some(sig)) = (
        header(&parts, "sealctl-key"),
        header(&parts, "sealctl-time"),
        header(&parts, "sealctl-signature"),
    ) else {
        return err(401, "unsigned");
    };
    let t: u64 = time.parse().unwrap_or(0);
    let now_s = now_ms() / 1000;
    if now_s.abs_diff(t) > 300 {
        return ok(401, json!({"error": "clock_skew", "time": now_s}));
    }
    let h = RelayHeaders {
        key: key.clone(),
        time,
        signature: sig,
    };
    if verify_relay_headers(&h, parts.method.as_str(), &pq, &bytes, now_s).is_err() {
        return err(401, "bad_signature");
    }
    let body: Value = if bytes.is_empty() {
        Value::Null
    } else {
        match serde_json::from_slice(&bytes) {
            Ok(v) => v,
            Err(_) => return err(400, "bad_json"),
        }
    };
    let m = parts.method.clone();

    // GET /v1/machines/{m}
    if m == Method::GET && s.len() == 3 && s[0] == "v1" && s[1] == "machines" {
        if key != s[2] {
            return err(403, "forbidden");
        }
        let g = app.inner.lock().unwrap();
        return match g.index.get(s[2]) {
            Some((phone, proof)) => ok(200, json!({"phone": phone, "proof": proof})),
            None => err(404, "not_paired"),
        };
    }
    if s.len() < 3 || s[0] != "v1" || s[1] != "phones" {
        return err(404, "not_found");
    }
    let phone = s[2].to_string();
    let rest: Vec<&str> = s[3..].to_vec();
    let role = {
        let g = app.inner.lock().unwrap();
        if key == phone {
            Some(Role::Phone)
        } else if g
            .phones
            .get(&phone)
            .is_some_and(|p| p.machines.contains_key(&key))
        {
            Some(Role::Machine)
        } else {
            None
        }
    };
    // registering needs no existing record
    let Some(role) = role else {
        return err(403, "forbidden");
    };
    let is_phone = matches!(role, Role::Phone);

    match (m.clone(), rest.as_slice()) {
        (Method::POST, ["machines"]) if is_phone => {
            let machine = body["machine"].as_str().unwrap_or("").to_string();
            if machine.len() != 43 || machine == phone {
                return err(400, "bad_machine");
            }
            let mut g = app.inner.lock().unwrap();
            let proof = body["proof"].as_str().unwrap_or("").to_string();
            let old = g.index.get(&machine).map(|(p, _)| p.clone());
            if let Some(old) = old.filter(|o| *o != phone) {
                if let Some(op) = g.phones.get_mut(&old) {
                    op.machines.remove(&machine);
                    close_machine(op, &machine, "moved");
                }
            }
            g.index.insert(machine.clone(), (phone.clone(), proof));
            let p = g.phones.entry(phone.clone()).or_default();
            let known = p.machines.contains_key(&machine);
            p.machines.insert(
                machine.clone(),
                json!({"machine": machine, "name": body["name"], "os": body["os"], "model": body["model"], "pairedAt": now_ms()}),
            );
            let n = p.machines.len();
            ok(
                if known { 200 } else { 201 },
                json!({"machine": machine, "machines": n}),
            )
        }
        (Method::GET, ["machines"]) if is_phone => {
            let g = app.inner.lock().unwrap();
            let list: Vec<Value> = g
                .phones
                .get(&phone)
                .map(|p| p.machines.values().cloned().collect())
                .unwrap_or_default();
            ok(200, json!({"machines": list}))
        }
        (Method::DELETE, ["machines", mid]) if is_phone || key == *mid => {
            let mut g = app.inner.lock().unwrap();
            let Some(p) = g.phones.get_mut(&phone) else {
                return err(404, "not_paired");
            };
            if p.machines.remove(*mid).is_none() {
                return err(404, "not_paired");
            }
            close_machine(p, mid, "unpaired");
            let n = p.machines.len();
            g.index.remove(*mid);
            ok(200, json!({"machines": n}))
        }
        (Method::GET, ["wait"]) if !is_phone && ws => {
            let req = Request::from_parts(parts, Body::empty());
            let Ok(up) = WebSocketUpgrade::from_request(req, &()).await else {
                return err(426, "websocket_required");
            };
            let app2 = app.clone();
            up.on_upgrade(move |sock| wait_socket(app2, phone, key, sock))
                .into_response()
        }
        (Method::GET, ["socket"]) if is_phone && ws => {
            let req = Request::from_parts(parts, Body::empty());
            let Ok(up) = WebSocketUpgrade::from_request(req, &()).await else {
                return err(426, "websocket_required");
            };
            let app2 = app.clone();
            up.on_upgrade(move |sock| phone_socket(app2, phone, sock))
                .into_response()
        }
        (Method::GET, ["requests"]) if is_phone => {
            let near = app.opts.lock().unwrap().near;
            let g = app.inner.lock().unwrap();
            let n = now_ms();
            let list: Vec<Value> = g
                .phones
                .get(&phone)
                .map(|p| {
                    p.pending
                        .iter()
                        .filter(|(_, r)| r.expires > n && !r.tx.is_closed())
                        .map(|(id, r)| json!({"id": id, "machine": r.machine, "sealed": r.sealed, "created": r.created, "expires": r.expires, "near": near}))
                        .collect()
                })
                .unwrap_or_default();
            ok(200, json!({"requests": list}))
        }
        (Method::POST, ["requests", id, "reply"]) if is_phone => {
            let sealed = body["sealed"].as_str().unwrap_or("").to_string();
            if sealed.is_empty() || sealed.len() > 4096 {
                return err(400, "bad_sealed");
            }
            let delay = body["delay"].as_u64();
            let mut g = app.inner.lock().unwrap();
            let Some(p) = g.phones.get_mut(&phone) else {
                return err(404, "gone");
            };
            let Some(pend) = p.pending.remove(*id) else {
                return err(404, "gone");
            };
            if pend.tx.is_closed() || pend.expires < now_ms() {
                return err(404, "gone");
            }
            let day = now_ms() / 86_400_000;
            if p.last_day != day {
                p.last_day = day;
                p.days_used += 1;
            }
            match delay {
                Some(d) if (1..=3600).contains(&d) => {
                    if p.delayed.len() >= 4 {
                        p.pending.insert(id.to_string(), pend);
                        return err(429, "too_many_delayed");
                    }
                    let created = now_ms();
                    let release_at = created + d * 1000;
                    p.delayed.insert(
                        id.to_string(),
                        DelayedRec {
                            machine: Some(pend.machine.clone()),
                            sealed: Some(sealed),
                            created,
                            release_at,
                            expires: release_at + 900_000,
                            cancelled: None,
                        },
                    );
                    let _ = pend.tx.send(Out::Close(
                        json!({"type": "delayed", "id": id, "releaseAt": release_at}).to_string(),
                    ));
                    let note = json!({"type": "delayed", "id": id, "machine": pend.machine, "releaseAt": release_at}).to_string();
                    for t in p.phone_sockets.iter().chain(p.machine_sockets.values()) {
                        let _ = t.send(Out::Text(note.clone()));
                    }
                    ok(200, json!({"delivered": true, "releaseAt": release_at}))
                }
                Some(_) => err(400, "bad_delay"),
                None => {
                    let _ = pend.tx.send(Out::Close(
                        json!({"type": "reply", "id": id, "sealed": sealed}).to_string(),
                    ));
                    ok(200, json!({"delivered": true}))
                }
            }
        }
        (Method::GET, ["licence"]) => {
            let ask_after = app.opts.lock().unwrap().ask_after_days;
            let g = app.inner.lock().unwrap();
            let p = g.phones.get(&phone);
            let paid = p.is_some_and(|p| p.paid);
            let days = p.map_or(0, |p| p.days_used);
            let codes: Vec<Value> = p
                .map(|p| {
                    p.codes
                        .iter()
                        .map(|(c, s, cl)| json!({"code": c, "seats": s, "claimed": cl}))
                        .collect()
                })
                .unwrap_or_default();
            ok(
                200,
                json!({
                    "licence": if paid { "paid" } else { "unpaid" },
                    "source": p.and_then(|p| p.source.clone()),
                    "since": Value::Null,
                    "movedTo": Value::Null,
                    "daysUsed": days,
                    "ask": !paid && days >= ask_after,
                    "machines": p.map_or(0, |p| p.machines.len()),
                    "machineGate": Value::Null,
                    "codes": codes,
                }),
            )
        }
        (Method::POST, ["checkout"]) => {
            let seats = body["seats"].as_u64().unwrap_or(1);
            if !(1..=1000).contains(&seats) {
                return err(400, "bad_seats");
            }
            if !app.opts.lock().unwrap().payments {
                return err(503, "payments_not_configured");
            }
            let g = app.inner.lock().unwrap();
            if seats == 1 && g.phones.get(&phone).is_some_and(|p| p.paid) {
                return err(409, "already_paid");
            }
            ok(
                200,
                json!({"url": format!("https://checkout.example.test/{phone}?seats={seats}"), "seats": seats}),
            )
        }
        (Method::POST, ["claim"]) => {
            let code = body["code"]
                .as_str()
                .unwrap_or("")
                .to_uppercase()
                .replace(' ', "");
            let mut g = app.inner.lock().unwrap();
            if g.phones.get(&phone).is_some_and(|p| p.paid) {
                return err(409, "already_paid");
            }
            let Some((seats, claimed)) = g.seats.get_mut(&code) else {
                return err(404, "unknown_code");
            };
            if claimed.len() as u64 >= *seats {
                return err(409, "no_seats_left");
            }
            claimed.push(phone.clone());
            let left = *seats - claimed.len() as u64;
            let p = g.phones.entry(phone.clone()).or_default();
            p.paid = true;
            p.source = Some("seat".into());
            ok(200, json!({"licence": "paid", "left": left}))
        }
        (Method::PUT, ["machines", mid, "status"]) if !is_phone && key == *mid => {
            let sealed = body["sealed"].as_str().unwrap_or("").to_string();
            if sealed.is_empty() || sealed.len() > 8192 {
                return err(400, "bad_sealed");
            }
            let mut g = app.inner.lock().unwrap();
            let p = g.phones.entry(phone.clone()).or_default();
            p.status.insert(mid.to_string(), (sealed, now_ms()));
            let note = json!({"type": "status", "machine": mid}).to_string();
            for t in &p.phone_sockets {
                let _ = t.send(Out::Text(note.clone()));
            }
            ok(200, json!({}))
        }
        (Method::GET, ["status"]) if is_phone => {
            let g = app.inner.lock().unwrap();
            let list: Vec<Value> = g
                .phones
                .get(&phone)
                .map(|p| {
                    p.status
                        .iter()
                        .map(|(m, (s, u))| json!({"machine": m, "sealed": s, "updated": u}))
                        .collect()
                })
                .unwrap_or_default();
            ok(200, json!({"status": list}))
        }
        (Method::POST, ["machines", mid, "messages"]) if is_phone => {
            let sealed = body["sealed"].as_str().unwrap_or("").to_string();
            let mut g = app.inner.lock().unwrap();
            let Some(p) = g.phones.get_mut(&phone) else {
                return err(404, "not_paired");
            };
            if !p.machines.contains_key(*mid) {
                return err(404, "not_paired");
            }
            let created = now_ms();
            let frame = json!({"type": "message", "sealed": sealed, "created": created}).to_string();
            if let Some(t) = p.machine_sockets.get(*mid).filter(|t| !t.is_closed()) {
                let _ = t.send(Out::Text(frame));
                return ok(200, json!({"delivered": true}));
            }
            let held = p.held.entry(mid.to_string()).or_default();
            held.push((sealed, created));
            if held.len() > 16 {
                held.remove(0);
            }
            ok(200, json!({"delivered": false}))
        }
        (Method::GET, ["machines", mid, "socket"]) if !is_phone && key == *mid && ws => {
            if !app.opts.lock().unwrap().machine_channel {
                return err(404, "not_found");
            }
            let req = Request::from_parts(parts, Body::empty());
            let Ok(up) = WebSocketUpgrade::from_request(req, &()).await else {
                return err(426, "websocket_required");
            };
            let app2 = app.clone();
            let mid = mid.to_string();
            up.on_upgrade(move |sock| machine_socket(app2, phone, mid, sock))
                .into_response()
        }
        (Method::POST, ["delayed"]) if is_phone => {
            let id = body["id"].as_str().unwrap_or("").to_string();
            let delay = body["delay"].as_u64().unwrap_or(0);
            if id.len() != 22 {
                return err(400, "bad_id");
            }
            if !(1..=3600).contains(&delay) {
                return err(400, "bad_delay");
            }
            let mut g = app.inner.lock().unwrap();
            let p = g.phones.entry(phone.clone()).or_default();
            if p.delayed.contains_key(&id) {
                return err(409, "duplicate_id");
            }
            let created = now_ms();
            let release_at = created + delay * 1000;
            p.delayed.insert(
                id.clone(),
                DelayedRec {
                    machine: None,
                    sealed: None,
                    created,
                    release_at,
                    expires: release_at + 900_000,
                    cancelled: None,
                },
            );
            let note = json!({"type": "delayed", "id": id, "machine": Value::Null, "releaseAt": release_at})
                .to_string();
            for t in p.phone_sockets.iter().chain(p.machine_sockets.values()) {
                let _ = t.send(Out::Text(note.clone()));
            }
            ok(
                201,
                json!({"id": id, "releaseAt": release_at, "expires": release_at + 900_000}),
            )
        }
        (Method::GET, ["delayed"]) => {
            let mut g = app.inner.lock().unwrap();
            let n = now_ms();
            let p = g.phones.entry(phone.clone()).or_default();
            p.delayed.retain(|_, d| d.expires > n);
            let list: Vec<Value> = p.delayed.iter().map(|(id, d)| delayed_json(id, d, n)).collect();
            ok(200, json!({"delayed": list}))
        }
        (Method::GET, ["delayed", id]) => {
            let mut g = app.inner.lock().unwrap();
            let n = now_ms();
            let p = g.phones.entry(phone.clone()).or_default();
            p.delayed.retain(|_, d| d.expires > n);
            let Some(d) = p.delayed.get(*id).cloned() else {
                return err(404, "gone");
            };
            let mut v = delayed_json(id, &d, n);
            if d.machine.as_deref() == Some(key.as_str()) && n >= d.release_at && d.cancelled.is_none() {
                if let Some(s) = &d.sealed {
                    v["sealed"] = json!(s);
                    p.delayed.remove(*id);
                }
            }
            ok(200, v)
        }
        (Method::POST, ["delayed", id, "cancel"]) => {
            let mut g = app.inner.lock().unwrap();
            let p = g.phones.entry(phone.clone()).or_default();
            let by = if is_phone {
                "phone".to_string()
            } else {
                key.clone()
            };
            let Some(d) = p.delayed.get_mut(*id) else {
                return err(404, "gone");
            };
            if d.cancelled.is_none() {
                d.cancelled = Some((by.clone(), now_ms()));
                d.sealed = None;
                let note = json!({"type": "cancelled", "id": id, "by": by}).to_string();
                for t in p.phone_sockets.iter().chain(p.machine_sockets.values()) {
                    let _ = t.send(Out::Text(note.clone()));
                }
            }
            ok(200, json!({"cancelled": true}))
        }
        (Method::POST, ["delayed", id, "finish"]) if is_phone => {
            let mut g = app.inner.lock().unwrap();
            let p = g.phones.entry(phone.clone()).or_default();
            let Some(d) = p.delayed.get(*id).cloned() else {
                return err(404, "gone");
            };
            if d.machine.is_some() {
                return err(400, "bad_id");
            }
            if let Some((by, _)) = d.cancelled {
                return ok(409, json!({"error": "cancelled", "by": by}));
            }
            if now_ms() < d.release_at {
                return ok(425, json!({"error": "too_early", "releaseAt": d.release_at}));
            }
            p.delayed.remove(*id);
            ok(200, json!({"finished": true}))
        }
        _ => err(403, "forbidden"),
    }
}

fn delayed_json(id: &str, d: &DelayedRec, n: u64) -> Value {
    let state = if d.cancelled.is_some() {
        "cancelled"
    } else if n >= d.release_at {
        "released"
    } else {
        "waiting"
    };
    let mut v = json!({"id": id, "machine": d.machine, "created": d.created, "releaseAt": d.release_at, "expires": d.expires, "state": state});
    if let Some((by, at)) = &d.cancelled {
        v["cancelled"] = json!({"by": by, "at": at});
        v["by"] = json!(by);
    }
    v
}

fn close_machine(p: &mut PhoneRec, machine: &str, why: &str) {
    let frame = json!({"type": "error", "error": why}).to_string();
    let ids: Vec<String> = p
        .pending
        .iter()
        .filter(|(_, r)| r.machine == machine)
        .map(|(i, _)| i.clone())
        .collect();
    for id in ids {
        if let Some(r) = p.pending.remove(&id) {
            let _ = r.tx.send(Out::Close(frame.clone()));
        }
    }
    if let Some(t) = p.machine_sockets.remove(machine) {
        let _ = t.send(Out::Close(frame));
    }
}

async fn pump(
    mut sock: WebSocket,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Out>,
    mut on_text: impl FnMut(&str) -> Option<String>,
) {
    loop {
        tokio::select! {
            o = rx.recv() => match o {
                Some(Out::Text(t)) => { if sock.send(Message::Text(t.into())).await.is_err() { return; } }
                Some(Out::Close(t)) => {
                    let _ = sock.send(Message::Text(t.into())).await;
                    let _ = sock.send(Message::Close(None)).await;
                    return;
                }
                None => return,
            },
            m = sock.recv() => match m {
                Some(Ok(Message::Text(t))) => {
                    if t.as_str() == "ping" {
                        let _ = sock.send(Message::Text("pong".into())).await;
                        continue;
                    }
                    if let Some(answer) = on_text(t.as_str()) {
                        let _ = sock.send(Message::Text(answer.into())).await;
                    }
                }
                Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return,
                _ => {}
            }
        }
    }
}

async fn wait_socket(app: App, phone: String, machine: String, sock: WebSocket) {
    let (tx, rx) = unbounded_channel::<Out>();
    let near = app.opts.lock().unwrap().near;
    let mut got = false;
    let tx2 = tx.clone();
    let on_text = move |t: &str| -> Option<String> {
        let v: Value = serde_json::from_str(t).ok()?;
        if got {
            let _ = tx2.send(Out::Close(
                json!({"type": "error", "error": "one_request_per_socket"}).to_string(),
            ));
            return None;
        }
        if v["type"] != "request" {
            let _ = tx2.send(Out::Close(
                json!({"type": "error", "error": "bad_request"}).to_string(),
            ));
            return None;
        }
        got = true;
        let id = v["id"].as_str().unwrap_or("").to_string();
        let sealed = v["sealed"].as_str().unwrap_or("").to_string();
        let ttl = v["ttl"].as_u64().unwrap_or(300).clamp(1, 300);
        let created = now_ms();
        let expires = created + ttl * 1000;
        let mut g = app.inner.lock().unwrap();
        let p = g.phones.entry(phone.clone()).or_default();
        if p.pending.contains_key(&id) {
            let _ = tx2.send(Out::Close(
                json!({"type": "error", "error": "duplicate_id"}).to_string(),
            ));
            return None;
        }
        p.pending.insert(
            id.clone(),
            Pending {
                machine: machine.clone(),
                sealed: sealed.clone(),
                created,
                expires,
                tx: tx2.clone(),
            },
        );
        let note = json!({"type": "request", "id": id, "machine": machine, "sealed": sealed, "created": created, "expires": expires, "near": near}).to_string();
        for t in &p.phone_sockets {
            let _ = t.send(Out::Text(note.clone()));
        }
        let tx3 = tx2.clone();
        let id2 = id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(ttl * 1000)).await;
            let _ = tx3.send(Out::Close(json!({"type": "expired", "id": id2}).to_string()));
        });
        Some(json!({"type": "queued", "id": id, "expires": expires}).to_string())
    };
    pump(sock, rx, on_text).await;
    drop(tx);
}

async fn phone_socket(app: App, phone: String, sock: WebSocket) {
    let (tx, rx) = unbounded_channel::<Out>();
    app.inner
        .lock()
        .unwrap()
        .phones
        .entry(phone)
        .or_default()
        .phone_sockets
        .push(tx);
    pump(sock, rx, |_| None).await;
}

async fn machine_socket(app: App, phone: String, machine: String, sock: WebSocket) {
    let (tx, rx) = unbounded_channel::<Out>();
    {
        let mut g = app.inner.lock().unwrap();
        let p = g.phones.entry(phone).or_default();
        if let Some(old) = p.machine_sockets.insert(machine.clone(), tx.clone()) {
            let _ = old.send(Out::Close(String::new()));
        }
        let n = now_ms();
        for (s, c) in p.held.remove(&machine).unwrap_or_default() {
            if n.saturating_sub(c) < 24 * 3600 * 1000 {
                let _ = tx.send(Out::Text(
                    json!({"type": "message", "sealed": s, "created": c}).to_string(),
                ));
            }
        }
        for (id, d) in &p.delayed {
            if d.cancelled.is_none() && n < d.release_at {
                let _ = tx.send(Out::Text(
                    json!({"type": "delayed", "id": id, "machine": d.machine, "releaseAt": d.release_at})
                        .to_string(),
                ));
            }
        }
    }
    pump(sock, rx, |_| None).await;
}
