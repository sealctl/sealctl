//! The session daemon (SPEC 6): one per user, holding the session keys, the timers, the relay
//! connections and the SSH agent socket. Every command that needs a key talks to it over
//! `daemon.sock` (JSON lines). With `SEALCTL_NO_DAEMON=1` the same code runs inside the
//! command, and keys live as long as that process.

pub mod channel;
pub mod client;
pub mod session;
#[cfg(test)]
pub(crate) mod testing;
#[cfg(test)]
mod timing_tests;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use sealctl_core::wire::{AgentUse, LogEntry, ReplyBody, RequestContext, RequestItem, Subject};
use sealctl_core::ObjectKey;
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use zeroize::Zeroizing;

use crate::approve::{self, Asked};
use crate::backup::Backup;
use crate::exit::{self, fail};
use crate::machine::{self, Paired};
use crate::relay::Relay;
use crate::store::Store;
use crate::volume::Volume;
use crate::{paths, util};

use session::Saved;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// How far the phone's clock may be behind the machine's for a `lock` message.
const LOCK_SKEW_MS: u64 = 60_000;

/// Set in the daemon process (the rewrap after a phone key change starts from there).
pub static IN_DAEMON: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The CLI version every socket request carries.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Where events about a request go (`waiting`).
pub type Events = Arc<dyn Fn(Value) + Send + Sync>;

/// A remembered agent answer.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Allowed {
    /// Agent name.
    pub agent: String,
    /// Repository id (or folder).
    pub repo: String,
    /// Secret name.
    pub name: String,
}

/// A delayed level 3 action this machine heard of.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Pending {
    /// Delayed id.
    pub id: String,
    /// What, as shown.
    pub what: String,
    /// The machine it concerns.
    pub machine: Option<String>,
    /// When it takes effect, Unix ms.
    pub at: u64,
}

/// The usage log (protocol.md, Machine status): uses wait here until a status that carried
/// them is acknowledged. Each status carries the oldest 50 waiting, and an `ack` removes only
/// what the acknowledged status carried.
#[derive(Default)]
struct UsageLog {
    /// Entries with their number, oldest first.
    entries: Vec<(u64, LogEntry)>,
    next: u64,
    /// `(status seq, number of the newest entry it carried)`, oldest first.
    carried: Vec<(u64, u64)>,
}

impl UsageLog {
    const KEEP: usize = 200;
    const PER_STATUS: usize = 50;

    fn push(&mut self, e: LogEntry) {
        self.next += 1;
        self.entries.push((self.next, e));
        if self.entries.len() > Self::KEEP {
            let drop = self.entries.len() - Self::KEEP;
            self.entries.drain(..drop);
        }
    }

    /// The entries the status `seq` carries, remembered for its `ack`.
    fn carry(&mut self, seq: u64) -> Vec<LogEntry> {
        let batch: Vec<&(u64, LogEntry)> = self.entries.iter().take(Self::PER_STATUS).collect();
        if let Some((last, _)) = batch.last() {
            self.carried.push((seq, *last));
            if self.carried.len() > 100 {
                self.carried.remove(0);
            }
        }
        batch.into_iter().map(|(_, e)| e.clone()).collect()
    }

    /// The phone stored status `seq`: its entries are done. Returns whether any are left.
    fn ack(&mut self, seq: u64) -> bool {
        let upto = self
            .carried
            .iter()
            .filter(|(s, _)| *s <= seq)
            .map(|(_, n)| *n)
            .max();
        self.carried.retain(|(s, _)| *s > seq);
        if let Some(upto) = upto {
            self.entries.retain(|(n, _)| *n > upto);
        }
        !self.entries.is_empty()
    }
}

impl State {
    /// The session state as a status tells it.
    fn state_word(&self) -> &'static str {
        if self.waiting_since.is_some() {
            "waiting"
        } else if self.open {
            "open"
        } else {
            "locked"
        }
    }
}

#[derive(Default)]
struct State {
    open: bool,
    /// When the session's `open` was sent, Unix ms: a `lock` message made more than a minute
    /// before it is old.
    opened_at: u64,
    saved: Saved,
    store_key: Option<ObjectKey>,
    keys: BTreeMap<String, ObjectKey>,
    allowed: BTreeSet<Allowed>,
    /// Parts of an `answers` list whose last part has not arrived yet.
    answers_parts: Vec<Allowed>,
    words: Option<String>,
    waiting_since: Option<u64>,
    log: UsageLog,
    pending: Vec<Pending>,
    clients: usize,
    last_client: u64,
    mounted: Vec<String>,
    channel: Option<tokio::task::JoinHandle<()>>,
    /// Machine channels of locks still running: each is closed at its lock's step 5, or at
    /// once when a new session starts its own (two sockets on one machine key evict each other).
    closing: Vec<tokio::task::JoinHandle<()>>,
    /// Counts the sessions opened; work started for one session never lands in a later one.
    generation: u64,
    /// Locks begun; each runs its slow steps after the one before it has finished.
    locks_begun: u64,
    status_dirty: bool,
    last_status: u64,
    /// The session state the last status told the phone (`open`, `waiting`, `locked`).
    sent_state: String,
    keys_used_month: u64,
}

/// The daemon.
pub struct Daemon {
    st: Mutex<State>,
    asking: tokio::sync::Mutex<()>,
    /// Held from the check that the session is Locked through the `open` it asks for, so that
    /// callers arriving meanwhile join that open instead of sending their own (SPEC 6.3).
    opening: tokio::sync::Mutex<()>,
    paired: tokio::sync::Mutex<Paired>,
    relay: Relay,
    inproc: bool,
    shutdown: tokio::sync::Notify,
    /// The number of locks whose slow steps have finished (see `State::locks_begun`).
    locks_done: tokio::sync::watch::Sender<u64>,
    /// Held while volumes are mounted or a lock runs its backups and unmounts.
    volumes: tokio::sync::Mutex<()>,
    #[cfg(test)]
    t: testing::Hooks,
}

/// What a lock took from the session at once (SPEC 6.5 step 1), for the slow steps.
struct Closing {
    /// Its place among the locks.
    turn: u64,
    was_open: bool,
    /// On-lock backups run (step 2); `jobs` are the ones configured.
    #[cfg_attr(not(test), allow(dead_code))]
    backups: bool,
    jobs: Vec<(Backup, ObjectKey, BTreeMap<String, Zeroizing<String>>)>,
    /// The machine channel it closes at step 5.
    channel: Option<tokio::task::Id>,
}

fn key_name(p: &str, i: &str) -> String {
    format!("{p}:{i}")
}

fn copy_key(k: &ObjectKey) -> ObjectKey {
    ObjectKey::from_bytes(k.as_bytes()).expect("16 bytes")
}

/// Keys handed to one command (`grant: once`) or held by the session.
pub struct KeySet(pub BTreeMap<String, ObjectKey>);

impl KeySet {
    fn get(&self, p: &str, i: &str) -> Option<ObjectKey> {
        self.0.get(&key_name(p, i)).map(copy_key)
    }
}

fn load_saved() -> Saved {
    paths::session_file()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_saved(s: &Saved) {
    if let (Ok(p), Ok(b)) = (paths::session_file(), serde_json::to_vec(s)) {
        let _ = paths::ensure_private_dir(p.parent().expect("state dir"));
        let _ = paths::write_private(&p, &b);
    }
}

/// Has the time of the session in `saved` run out at `n`? `Some(true)` past the hard stop, or
/// when the wall clock went back more than a minute behind the last work (neither idle time nor
/// the hard stop can be trusted then, so the credit goes too); `Some(false)` when the idle
/// allowance is used up.
fn expired(saved: &Saved, n: u64) -> Option<bool> {
    if saved.past_hard_stop(n) || saved.last_work > n + 60_000 {
        Some(true)
    } else if saved.left(n) == 0 {
        Some(false)
    } else {
        None
    }
}

/// Remembered answers from the phone (`answers.json`).
pub fn load_answers() -> Vec<Allowed> {
    paths::answers_file()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

fn save_answers(a: &[Allowed]) {
    if let (Ok(p), Ok(b)) = (paths::answers_file(), serde_json::to_vec_pretty(a)) {
        let _ = paths::write_private(&p, &b);
    }
}

fn now() -> u64 {
    machine::now_ms()
}

/// What a `values` call needs.
#[derive(Debug, Clone, Default, serde::Deserialize)]
pub struct ValuesReq {
    /// Secret names.
    pub names: Vec<String>,
    /// Agent name, if an agent asks.
    #[serde(default)]
    pub agent: Option<String>,
    /// Command (masked by the daemon before it goes anywhere).
    #[serde(default)]
    pub cmd: String,
    /// Working folder.
    #[serde(default)]
    pub cwd: String,
    /// Subject of the request.
    #[serde(default)]
    pub subject: Option<(String, String)>,
    /// Nobody watches a terminal: show a desktop notification while waiting.
    #[serde(default)]
    pub notify: bool,
}

impl Daemon {
    /// A daemon for this machine's pairing.
    pub fn new(inproc: bool) -> Result<Arc<Daemon>> {
        let paired = machine::load()?;
        let relay = Relay::new(&paired.file.relay)?;
        let saved = load_saved();
        let st = State {
            saved,
            last_client: now(),
            ..State::default()
        };
        Ok(Self::with(paired, relay, inproc, st))
    }

    fn with(paired: Paired, relay: Relay, inproc: bool, st: State) -> Arc<Daemon> {
        Arc::new(Daemon {
            st: Mutex::new(st),
            asking: tokio::sync::Mutex::new(()),
            opening: tokio::sync::Mutex::new(()),
            paired: tokio::sync::Mutex::new(paired),
            relay,
            inproc,
            shutdown: tokio::sync::Notify::new(),
            locks_done: tokio::sync::watch::channel(0).0,
            volumes: tokio::sync::Mutex::new(()),
            #[cfg(test)]
            t: testing::Hooks::default(),
        })
    }

    /// Wall clock, Unix ms (a test may set it).
    fn now(&self) -> u64 {
        #[cfg(test)]
        {
            let t = self.t.now.load(std::sync::atomic::Ordering::SeqCst);
            if t != 0 {
                return t;
            }
        }
        now()
    }

    /// Input idle time in seconds (a test may set it).
    fn idle_input(&self) -> Option<u64> {
        #[cfg(test)]
        if let Some(v) = *self.t.idle.lock().unwrap() {
            return v;
        }
        idle_input_secs()
    }

    fn st(&self) -> std::sync::MutexGuard<'_, State> {
        self.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// The turn to open the session (SPEC 6.3): a caller that finds an open pending waits for it
    /// and is told it is waiting for the phone, like the caller that asked. On an Open session the
    /// other holder usually needs the turn only for a moment, so the caller is told only when the
    /// phone is being asked or the turn has not come within half a second.
    async fn join_open(&self, ev: &Events) -> tokio::sync::MutexGuard<'_, ()> {
        if let Ok(g) = self.opening.try_lock() {
            return g;
        }
        let phone = {
            let st = self.st();
            !st.open || st.waiting_since.is_some()
        };
        if !phone {
            let soon = tokio::time::timeout(Duration::from_millis(500), self.opening.lock());
            if let Ok(g) = soon.await {
                return g;
            }
        }
        ev(json!({"event": "waiting"}));
        self.opening.lock().await
    }

    /// Asks the phone; one request at a time.
    async fn ask(
        self: &Arc<Self>,
        body: sealctl_core::wire::RequestBody,
        ev: &Events,
        notify: bool,
    ) -> Result<ReplyBody> {
        let _turn = self.asking.lock().await;
        self.st().waiting_since = Some(self.now());
        self.st().status_dirty = true;
        ev(json!({"event": "waiting"}));
        if notify && crate::guard::ai_agent().is_none() {
            util::notify("sealctl: waiting for your phone");
        }
        let r = self.send_ask(body).await;
        self.st().waiting_since = None;
        match r {
            Ok(Some(reply)) if reply.ok => {
                if let Some(w) = &reply.w {
                    self.st().words = Some(w.clone());
                }
                ev(json!({"event": "answered"}));
                Ok(reply)
            }
            Ok(Some(reply)) => {
                if reply.err.as_deref() == Some("declined") {
                    self.count_declined();
                }
                Err(approve::refusal(&reply, None, None))
            }
            Ok(None) => Err(fail(exit::ERROR, "The phone delayed a routine request.")),
            Err(e) => {
                if exit::code_of(&e) == exit::NOT_PAIRED {
                    self.lock("unpaired", true, false).await;
                }
                Err(e)
            }
        }
    }

    /// Sends one request and waits for the phone: its reply, or `None` when delayed.
    async fn send_ask(&self, body: sealctl_core::wire::RequestBody) -> Result<Option<ReplyBody>> {
        #[cfg(test)]
        if let Some(c) = self.t.canned() {
            self.t.event(format!("ask {}", body.why));
            if let Some(g) = c.gate {
                if let Ok(p) = g.acquire().await {
                    p.forget();
                }
            }
            return Ok(Some(c.reply));
        }
        match approve::send_shared(&self.relay, &self.paired, body).await? {
            Asked::Reply { reply, .. } => Ok(Some(reply)),
            Asked::Delayed { .. } => Ok(None),
        }
    }

    fn count_declined(&self) {
        let p = paths::month_file();
        if let Ok(p) = p {
            let mut v: Value = std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(json!({}));
            let month = crate::clock::now_local("%Y-%m");
            if v["month"] != month {
                v = json!({"month": month, "keysUsed": 0, "declined": 0});
            }
            v["declined"] = json!(v["declined"].as_u64().unwrap_or(0) + 1);
            let _ = paths::write_private(&p, v.to_string().as_bytes());
        }
    }

    fn count_used(&self, n: u64) {
        if let Ok(p) = paths::month_file() {
            let mut v: Value = std::fs::read(&p)
                .ok()
                .and_then(|b| serde_json::from_slice(&b).ok())
                .unwrap_or(json!({}));
            let month = crate::clock::now_local("%Y-%m");
            if v["month"] != month {
                v = json!({"month": month, "keysUsed": 0, "declined": 0});
            }
            v["keysUsed"] = json!(v["keysUsed"].as_u64().unwrap_or(0) + n);
            let _ = paths::write_private(&p, v.to_string().as_bytes());
        }
        self.st().keys_used_month += n;
    }

    async fn context(
        &self,
        agent: Option<&str>,
        cmd: &str,
        cwd: &str,
        subject: Option<(String, String)>,
    ) -> RequestContext {
        let paired = self.paired.lock().await;
        let cwd_path = if cwd.is_empty() {
            std::env::current_dir().unwrap_or_default()
        } else {
            std::path::PathBuf::from(cwd)
        };
        let mut ctx = approve::context(&paired, agent, cmd, &cwd_path);
        ctx.subject = subject.map(|(k, n)| Subject { kind: k, name: n });
        ctx
    }

    /// The items an `open` asks for: the store key, auto volumes, backups.
    fn open_items(store: &Store) -> Result<Vec<RequestItem>> {
        let mut items = vec![store.request_item()?];
        for v in Volume::list()? {
            if !v.manual {
                items.push(v.request_item());
            }
        }
        for b in Backup::list()? {
            items.push(b.request_item());
        }
        Ok(items)
    }

    /// Opens the session (or gets keys once). `extra` items are asked for too.
    async fn open_session(
        self: &Arc<Self>,
        extra: Vec<RequestItem>,
        uses: Vec<AgentUse>,
        ctx: RequestContext,
        ev: &Events,
        notify: bool,
    ) -> Result<(bool, KeySet)> {
        // unit tests have no store; they open with `open_with`
        #[cfg(test)]
        if self.t.offline() {
            return Err(fail(exit::NOT_FOUND, "no store in unit tests"));
        }
        let store = Store::configured()?;
        let new_store = store.id_file()?.is_none();
        let mut items = Self::open_items(&store)?;
        for e in extra {
            if !items.iter().any(|i| i.purpose == e.purpose && i.id == e.id) {
                items.push(e);
            }
        }
        let store_id = store.id.clone();
        self.open_with(items, &store_id, uses, ctx, ev, notify, |set, words| {
            if new_store {
                let k = set
                    .get(&key_name("secrets", &store.id))
                    .context("no store key in the reply")?;
                store.write_id(&store.new_id_file(words, k))?;
            }
            Ok(())
        })
        .await
    }

    /// The `open` request for `items` and what follows the answer; `first` runs before the
    /// session takes the keys (a new store writes its `.id` file).
    #[allow(clippy::too_many_arguments)]
    async fn open_with(
        self: &Arc<Self>,
        items: Vec<RequestItem>,
        store_id: &str,
        uses: Vec<AgentUse>,
        ctx: RequestContext,
        ev: &Events,
        notify: bool,
        first: impl FnOnce(&BTreeMap<String, ObjectKey>, &str) -> Result<()>,
    ) -> Result<(bool, KeySet)> {
        let mut body = approve::body("open");
        body.keys = items.clone();
        body.uses = uses;
        body.ctx = Some(ctx);
        body.work = Some(self.st().saved.worked);
        let asked_at = self.now();
        let reply = self.ask(body, ev, notify).await?;
        let keys = approve::keys_from(&reply, &items)?;
        let words = reply.w.clone().unwrap_or_default();
        let mut set = BTreeMap::new();
        for (item, key) in items.iter().zip(keys) {
            set.insert(key_name(&item.purpose, &item.id), key);
        }
        first(&set, &words)?;
        let session = reply.grant.as_deref() == Some("session");
        if session {
            let n = self.now();
            let generation = {
                let mut st = self.st();
                st.open = true;
                st.opened_at = asked_at;
                // past the hard stop, or saved while the clock was ahead: a new day of credit
                if expired(&st.saved, n) == Some(true)
                    || st.saved.first_open.is_some_and(|f| f > n)
                {
                    st.saved.reset_credit();
                }
                if st.saved.first_open.is_none() {
                    st.saved.first_open = Some(n);
                }
                st.saved.cap = u64::from(reply.cap.unwrap_or(600));
                st.saved.base = u64::from(reply.base.unwrap_or(600));
                st.saved.rate = u64::from(reply.rate.unwrap_or(0));
                st.saved.place = reply.place.clone();
                st.saved.lock_reason = None;
                st.saved.work(n);
                st.store_key = set.get(&key_name("secrets", store_id)).map(copy_key);
                for (k, v) in &set {
                    st.keys.insert(k.clone(), copy_key(v));
                }
                st.status_dirty = true;
                st.generation += 1;
                save_saved(&st.saved);
                st.generation
            };
            // The phone hears the session is Open before this caller (or one that joined the
            // open) sends its next request, not when the machine channel gets to it.
            if !self.inproc {
                if let Err(e) = self.send_status(&[]).await {
                    log::info!("status: {e:#}");
                    // tried again at the next tick
                    self.st().last_status = 0;
                }
            }
            self.mount_auto(generation).await;
            if !self.inproc {
                self.start_channel(generation);
            }
        }
        Ok((session, KeySet(set)))
    }

    /// Mounts the auto volumes of session `generation`, while it stays Open. A lock meanwhile
    /// unmounts after the mount in progress (both hold `volumes`).
    async fn mount_auto(&self, generation: u64) {
        let _volumes = self.volumes.lock().await;
        #[cfg(test)]
        self.t.mount.pass("mount", &self.t).await;
        let vols: Vec<Volume> = Volume::list()
            .unwrap_or_default()
            .into_iter()
            .filter(|v| !v.manual)
            .collect();
        for v in vols {
            let key = {
                let st = self.st();
                if !st.open || st.generation != generation {
                    return;
                }
                st.keys.get(&key_name("volume", &v.id)).map(copy_key)
            };
            let Some(key) = key else { continue };
            let name = v.name.clone();
            let r = tokio::task::spawn_blocking(move || {
                let was = v.is_open();
                crate::volume::open_with(&v, &key).map(|_| !was)
            })
            .await;
            match r {
                Ok(Ok(true)) => self.st().mounted.push(name),
                Ok(Ok(false)) => {}
                Ok(Err(e)) => log::warn!("mounting {name}: {e:#}"),
                Err(_) => {}
            }
        }
    }

    /// `open`.
    pub async fn op_open(self: &Arc<Self>, ctx: RequestContext, ev: &Events, notify: bool) -> Result<Value> {
        self.expire();
        let _opening = self.join_open(ev).await;
        if !self.st().open {
            let (session, _) = self.open_session(vec![], vec![], ctx, ev, notify).await?;
            if !session {
                return Ok(json!({"left": 0, "once": true}));
            }
        }
        let left = self.st().saved.left(self.now());
        Ok(json!({"left": left}))
    }

    /// `values`: secret values for names, with the caller's context.
    pub async fn op_values(
        self: &Arc<Self>,
        req: ValuesReq,
        ev: &Events,
    ) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
        self.expire();
        let store = Store::configured()?;
        let mut headers = Vec::new();
        for n in &req.names {
            headers.push((n.clone(), store.header(n)?));
        }
        let repo = {
            let cwd = if req.cwd.is_empty() {
                std::env::current_dir().unwrap_or_default()
            } else {
                req.cwd.clone().into()
            };
            approve::repo_of(&cwd)
                .map(|r| r.id)
                .unwrap_or_else(|| cwd.display().to_string())
        };
        let ctx = self
            .context(req.agent.as_deref(), &req.cmd, &req.cwd, req.subject.clone())
            .await;
        let mut ctx_n = ctx.clone();
        ctx_n.names = req.names.iter().take(10).cloned().collect();
        // what is not covered yet is judged after any pending open: a caller that joined it may
        // find its uses granted for the session already
        let opening = self.join_open(ev).await;
        let remembered = load_answers();
        // what the session covers and whether it is Open, read together: a lock in between
        // would leave uses counted as covered for the `open` that follows
        let (was_open, mut generation, uncovered) = {
            let st = self.st();
            let uncovered: Vec<String> = match &req.agent {
                Some(a) => req
                    .names
                    .iter()
                    .filter(|n| {
                        let al = Allowed {
                            agent: a.clone(),
                            repo: repo.clone(),
                            name: (*n).clone(),
                        };
                        !st.allowed.contains(&al) && !remembered.contains(&al)
                    })
                    .cloned()
                    .collect(),
                None => vec![],
            };
            (st.open, st.generation, uncovered)
        };
        let uses = match &req.agent {
            Some(a) if !uncovered.is_empty() => vec![AgentUse {
                agent: a.clone(),
                repository: repo.clone(),
                names: uncovered.clone(),
            }],
            _ => vec![],
        };
        let mut once_store_key: Option<ObjectKey> = None;
        // Agent uses are kept for the session only when the phone granted `session`; a `once`
        // answer covers this call and nothing after it.
        let mut session_uses = false;
        if !was_open {
            let (session, set) = self
                .open_session(vec![], uses.clone(), ctx_n.clone(), ev, req.notify)
                .await?;
            session_uses = session;
            generation = self.st().generation;
            if !session {
                once_store_key = set.get("secrets", &store.id);
            }
        }
        drop(opening);
        if was_open && !uses.is_empty() {
            let mut body = approve::body("agent");
            body.uses = uses.clone();
            body.ctx = Some(ctx_n.clone());
            let reply = self.ask(body, ev, req.notify).await?;
            session_uses = reply.grant.as_deref() == Some("session");
            if reply.remember == Some(true) {
                let mut a = load_answers();
                for u in &uses {
                    for n in &u.names {
                        a.push(Allowed {
                            agent: u.agent.clone(),
                            repo: u.repository.clone(),
                            name: n.clone(),
                        });
                    }
                }
                a.sort();
                a.dedup();
                save_answers(&a);
            }
        }
        if session_uses {
            let mut st = self.st();
            // kept only by the session that was asked: one that locked meanwhile does not hand
            // them to the next
            let same = st.open && st.generation == generation;
            for u in uses.iter().filter(|_| same) {
                for n in &u.names {
                    st.allowed.insert(Allowed {
                        agent: u.agent.clone(),
                        repo: u.repository.clone(),
                        name: n.clone(),
                    });
                }
            }
        }
        let store_key = match once_store_key {
            Some(k) => k,
            None => self
                .st()
                .store_key
                .as_ref()
                .map(copy_key)
                .ok_or_else(|| fail(exit::ERROR, "The session has no store key."))?,
        };
        // own-approval secrets: an `own` request every time
        let own: Vec<RequestItem> = headers
            .iter()
            .filter(|(_, h)| h.mode == sealctl_core::sealed::Mode::OwnApproval)
            .map(|(_, h)| crate::store::own_item(&store, h))
            .collect::<Result<_>>()?;
        let mut own_keys = BTreeMap::new();
        if !own.is_empty() {
            let mut body = approve::body("own");
            body.keys = own.clone();
            body.ctx = Some(ctx_n.clone());
            let reply = self.ask(body, ev, req.notify).await?;
            for (item, key) in own.iter().zip(approve::keys_from(&reply, &own)?) {
                own_keys.insert(item.id.clone(), key);
            }
        }
        let mut out = Vec::new();
        for (name, h) in &headers {
            let v = if h.mode == sealctl_core::sealed::Mode::OwnApproval {
                let k = own_keys.get(&h.file_id).context("own key")?;
                store.read(name, k)?
            } else {
                store.read(name, &store_key)?
            };
            out.push((name.clone(), v));
        }
        let n = self.now();
        {
            let mut st = self.st();
            if st.open {
                st.saved.work(n);
                save_saved(&st.saved);
            }
            st.log.push(LogEntry {
                time: n,
                agent: req.agent.clone(),
                repository: Some(repo),
                command: ctx.command.clone(),
                names: req.names.clone(),
                own: !own.is_empty(),
            });
            st.status_dirty = true;
        }
        self.count_used(out.len() as u64);
        Ok(out)
    }

    /// `keys`: object keys for volume and backup commands. Returns the keys and the words.
    pub async fn op_keys(
        self: &Arc<Self>,
        items: Vec<RequestItem>,
        subject: Option<(String, String)>,
        ev: &Events,
        notify: bool,
    ) -> Result<(Vec<ObjectKey>, String)> {
        self.expire();
        let held = || -> Option<(Vec<ObjectKey>, String)> {
            let st = self.st();
            if !st.open || items.iter().any(|i| i.words.is_none()) {
                return None;
            }
            let keys = items
                .iter()
                .map(|i| st.keys.get(&key_name(&i.purpose, &i.id)).map(copy_key))
                .collect::<Option<Vec<_>>>()?;
            Some((keys, st.words.clone().unwrap_or_default()))
        };
        if let Some(h) = held() {
            return Ok(h);
        }
        let ctx = self.context(None, "", "", subject).await;
        let opening = self.join_open(ev).await;
        if !self.st().open {
            let (_, set) = self.open_session(items.clone(), vec![], ctx, ev, notify).await?;
            let keys = items
                .iter()
                .map(|i| set.get(&i.purpose, &i.id).context("missing key"))
                .collect::<Result<Vec<_>>>()?;
            let w = self.st().words.clone().unwrap_or_default();
            return Ok((keys, w));
        }
        drop(opening);
        // the session was opened while this request waited for that open
        if let Some(h) = held() {
            return Ok(h);
        }
        let generation = self.st().generation;
        let mut body = approve::body("keys");
        body.keys = items.clone();
        body.ctx = Some(ctx);
        let reply = self.ask(body, ev, notify).await?;
        let keys = approve::keys_from(&reply, &items)?;
        // kept only by the session that asked: one that locked meanwhile does not hand them
        // to the next
        if reply.grant.as_deref() == Some("session") {
            let mut st = self.st();
            if !st.open || st.generation != generation {
                return Ok((keys, reply.w.unwrap_or_default()));
            }
            for (i, k) in items.iter().zip(keys.iter()) {
                st.keys.insert(key_name(&i.purpose, &i.id), copy_key(k));
            }
        }
        Ok((keys, reply.w.unwrap_or_default()))
    }

    /// `store`: write or rename a secret with the store key.
    pub async fn op_store(self: &Arc<Self>, req: &Value, ev: &Events) -> Result<Value> {
        self.expire();
        let store = Store::configured()?;
        let action = req["action"].as_str().unwrap_or("");
        let name = req["name"].as_str().unwrap_or("").to_string();
        crate::store::check_name(&name)?;
        // a `once` key serves this write only; it never goes into the session's state
        let mut once_key: Option<ObjectKey> = None;
        let opening = self.join_open(ev).await;
        if !self.st().open {
            let ctx = self
                .context(None, "", "", Some(("secret".into(), name.clone())))
                .await;
            let (session, set) = self
                .open_session(vec![], vec![], ctx, ev, req["notify"].as_bool().unwrap_or(false))
                .await?;
            if !session {
                once_key = set.get("secrets", &store.id);
            }
        }
        drop(opening);
        let key = match once_key {
            Some(k) => k,
            None => self
                .st()
                .store_key
                .as_ref()
                .map(copy_key)
                .ok_or_else(|| fail(exit::ERROR, "No store key."))?,
        };
        let words = store.id_file()?.map(|f| f.words).unwrap_or_default();
        match action {
            "set" => {
                let value = Zeroizing::new(
                    B64.decode(req["value"].as_str().unwrap_or(""))
                        .map_err(|_| fail(exit::USAGE, "bad value"))?,
                );
                let force = req["force"].as_bool().unwrap_or(false);
                if store.exists(&name) && !force {
                    return Err(fail(
                        exit::USAGE,
                        format!("{name} exists. Use --force to replace it."),
                    ));
                }
                if req["own"].as_bool().unwrap_or(false) {
                    let file_id = util::new_uuid()?;
                    let item = RequestItem {
                        purpose: "secret".into(),
                        id: file_id.clone(),
                        words: None,
                        check: None,
                        object: Some(sealctl_core::wire::ObjectFacts {
                            kind: "secret".into(),
                            path: paths::tilde(&store.dir),
                            size: value.len() as u64,
                        }),
                    };
                    let ctx = self
                        .context(None, "", "", Some(("secret".into(), name.clone())))
                        .await;
                    let mut body = approve::body("keys");
                    body.keys = vec![item.clone()];
                    body.ctx = Some(ctx);
                    let reply = self.ask(body, ev, false).await?;
                    let k = approve::keys_from(&reply, &[item])?.remove(0);
                    let w = reply.w.unwrap_or(words);
                    store.write(
                        &name,
                        sealctl_core::sealed::Mode::OwnApproval,
                        &k,
                        &w,
                        &value,
                        Some(&file_id),
                    )?;
                    store.add_own_check(&file_id, &k.check())?;
                } else {
                    store.write(
                        &name,
                        sealctl_core::sealed::Mode::StoreKey,
                        &key,
                        &words,
                        &value,
                        None,
                    )?;
                }
                Ok(json!({}))
            }
            "mv" => {
                let new = req["new"].as_str().unwrap_or("").to_string();
                crate::store::check_name(&new)?;
                if store.exists(&new) {
                    return Err(fail(exit::USAGE, format!("{new} exists already.")));
                }
                let h = store.header(&name)?;
                if h.mode == sealctl_core::sealed::Mode::OwnApproval {
                    let item = crate::store::own_item(&store, &h)?;
                    let mut body = approve::body("own");
                    body.keys = vec![item.clone()];
                    let reply = self.ask(body, ev, false).await?;
                    let k = approve::keys_from(&reply, &[item])?.remove(0);
                    let v = store.read(&name, &k)?;
                    store.write(&new, h.mode, &k, &h.words, &v, Some(&h.file_id))?;
                } else {
                    let v = store.read(&name, &key)?;
                    store.write(&new, h.mode, &key, &h.words, &v, None)?;
                }
                store.remove(&name)?;
                Ok(json!({}))
            }
            _ => Err(fail(exit::USAGE, "unknown store action")),
        }
    }

    /// Locks: wipes keys, runs on-lock backups, unmounts volumes, tells the phone (SPEC 6.5).
    /// Waits for the slow steps, and for those of any lock still running before them.
    pub async fn lock(self: &Arc<Self>, reason: &str, no_backup: bool, force: bool) -> Value {
        let c = self.close(reason, no_backup, |_| Some(false));
        match c {
            Some(c) => tokio::spawn(self.clone().finish(c, force))
                .await
                .unwrap_or_else(|_| json!({"lines": [], "busy": 0})),
            None => json!({"lines": [], "busy": 0}),
        }
    }

    /// Locks at once if `when` gives `Some` for the state (checked under the same lock), and
    /// runs the slow steps in the background. `Some(true)` also resets the credit (hard stop).
    /// Returns whether it locked.
    fn lock_soon(
        self: &Arc<Self>,
        reason: &str,
        no_backup: bool,
        when: impl FnOnce(&State) -> Option<bool>,
    ) -> bool {
        match self.close(reason, no_backup, when) {
            Some(c) => {
                tokio::spawn(self.clone().finish(c, false));
                true
            }
            None => false,
        }
    }

    /// SPEC 6.5 step 1: the session closes and its keys leave the shared state before anything
    /// slow runs, so nothing is handed out while backups and unmounts go on, and a second lock
    /// meanwhile finds the session Locked. The backups get their keys and credentials here;
    /// everything else taken is wiped when it drops. `when` gives `None` to leave the session
    /// as it is, or whether to reset the credit.
    fn close(
        &self,
        reason: &str,
        no_backup: bool,
        when: impl FnOnce(&State) -> Option<bool>,
    ) -> Option<Closing> {
        let (turn, was_open, store_key, keys, channel) = {
            let mut st = self.st();
            let reset_credit = when(&st)?;
            st.allowed.clear();
            st.answers_parts.clear();
            let was_open = std::mem::replace(&mut st.open, false);
            st.saved.lock_reason = match reason {
                "phone" => Some("Locked from your phone".into()),
                "place" => Some("Locked: your phone left the place".into()),
                _ => None,
            };
            // at the hard stop the credit goes with the session it ends, not with whatever
            // session the phone approves while this lock's backups run
            if reset_credit {
                st.saved.reset_credit();
            }
            save_saved(&st.saved);
            st.status_dirty = true;
            st.locks_begun += 1;
            let channel = st.channel.take().map(|h| {
                let id = h.id();
                st.closing.push(h);
                id
            });
            (
                st.locks_begun,
                was_open,
                st.store_key.take(),
                std::mem::take(&mut st.keys),
                channel,
            )
        };
        let backups = was_open && !no_backup && reason != "words" && reason != "unpaired";
        let mut jobs = Vec::new();
        if backups {
            for b in Backup::list().unwrap_or_default() {
                if !b.policy.on_lock {
                    continue;
                }
                let Some(key) = keys.get(&key_name("backup", &b.repo_id)).map(copy_key) else {
                    continue;
                };
                let env = Self::backup_env(&b, store_key.as_ref());
                jobs.push((b, key, env));
            }
        }
        Some(Closing {
            turn,
            was_open,
            backups,
            jobs,
            channel,
        })
    }

    /// SPEC 6.5 steps 2 to 5, after the locks before this one finished theirs: a second lock
    /// never unmounts under the first one's backups, and an exit waits for both.
    async fn finish(self: Arc<Self>, c: Closing, force: bool) -> Value {
        /// Marks this lock finished however its task ends.
        struct Done<'a>(&'a tokio::sync::watch::Sender<u64>, u64);
        impl Drop for Done<'_> {
            fn drop(&mut self) {
                let turn = self.1;
                self.0.send_modify(|d| *d = (*d).max(turn));
            }
        }
        let _done = Done(&self.locks_done, c.turn);
        let mut rx = self.locks_done.subscribe();
        let _ = rx.wait_for(|d| *d + 1 >= c.turn).await;
        // a mount in progress ends first: the backups read the volumes, step 3 closes them
        drop(self.volumes.lock().await);
        let mut lines = Vec::new();
        let mut busy = Vec::new();
        // step 2: on-lock backups, at most 15 minutes in total
        #[cfg(test)]
        if c.backups {
            self.t.backup.pass("backup", &self.t).await;
        }
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
        for (b, key, env) in c.jobs {
            let name = b.name.clone();
            let r = tokio::time::timeout_at(
                deadline,
                tokio::task::spawn_blocking(move || crate::backup::run_one(&b, &key, env, true)),
            )
            .await;
            match r {
                Ok(Ok(Ok(None))) => lines.push(format!("Backed up {name}.")),
                Ok(Ok(Ok(Some(warning)))) => lines.push(format!("Backed up {name} ({warning}).")),
                _ => lines.push(format!(
                    "Backup {name} failed; run sealctl backup run {name} later."
                )),
            }
        }
        // step 3: unmount, unless the phone approved a new session meanwhile: the volumes are
        // that session's now
        let volumes = self.volumes.lock().await;
        let reopened = self.st().open;
        #[cfg(test)]
        if !reopened {
            self.t.event(format!("unmount{}", if force { " force" } else { "" }));
        }
        let mounted: Vec<Volume> = if reopened {
            Vec::new()
        } else {
            Volume::list()
                .unwrap_or_default()
                .into_iter()
                .filter(|v| !v.manual || self.st().mounted.contains(&v.name))
                .collect()
        };
        for v in mounted {
            let name = v.name.clone();
            let mp = v.mountpoint.clone();
            let r = tokio::task::spawn_blocking(move || {
                if !v.is_open() {
                    return Ok(false);
                }
                crate::volume::close(&v, force).map(|_| true)
            })
            .await;
            match r {
                Ok(Ok(true)) => lines.push(format!("Volume {name} closed.")),
                Ok(Ok(false)) => {}
                Ok(Err(e)) => {
                    let holder = crate::volume::holder(&mp);
                    busy.push(sealctl_core::wire::BusyVolume {
                        name: name.clone(),
                        process: holder.as_ref().map(|h| h.0.clone()).unwrap_or_default(),
                        pid: holder.map(|h| h.1),
                    });
                    lines.push(exit::message_of(&e));
                }
                Err(_) => {}
            }
        }
        drop(volumes);
        // step 4
        let channel = {
            let mut st = self.st();
            // Unless the phone approved a new session meanwhile, wipe what came in during the
            // lock: a key or agent use approved by a request that started before it.
            if !st.open {
                st.store_key = None;
                st.keys.clear();
                st.allowed.clear();
                st.mounted.clear();
            }
            st.status_dirty = true;
            let i = c
                .channel
                .and_then(|id| st.closing.iter().position(|h| h.id() == id));
            i.map(|i| st.closing.remove(i))
        };
        // step 5
        if c.was_open && !self.inproc {
            let _ = self.send_status(&busy).await;
        }
        if let Some(h) = channel {
            h.abort();
        }
        json!({"lines": lines, "busy": busy.len()})
    }

    /// Storage credentials of a backup, read with the session's store key.
    fn backup_env(b: &Backup, key: Option<&ObjectKey>) -> BTreeMap<String, Zeroizing<String>> {
        let mut env = BTreeMap::new();
        let Ok(store) = Store::configured() else {
            return env;
        };
        let Some(key) = key else { return env };
        for var in &b.credentials {
            if let Ok(v) = store.read(&format!("backup/{}/{var}", b.name), key) {
                env.insert(
                    var.clone(),
                    Zeroizing::new(String::from_utf8_lossy(&v).into_owned()),
                );
            }
        }
        env
    }

    /// `status`.
    pub fn status(&self) -> Value {
        let st = self.st();
        let n = self.now();
        let state = if st.waiting_since.is_some() {
            "waiting"
        } else if st.open {
            "open"
        } else {
            "locked"
        };
        json!({
            "state": state,
            "open": st.open,
            "left": if st.open { Some(st.saved.left(n)) } else { None },
            "hardStop": st.saved.first_open.filter(|_| st.open).map(session::hard_stop),
            "lockReason": st.saved.lock_reason,
            "waitingSince": st.waiting_since,
            "place": st.saved.place,
            "words": st.words,
            "pending": st.pending,
            "keysHeld": st.keys.len() + usize::from(st.store_key.is_some()),
        })
    }

    /// The machine status for the phone (protocol.md, Machine status).
    /// The session state and the unacknowledged usage log, as the status or report `seq`
    /// carries them. Called under the `paired` lock that numbered `seq`, so the newest entry a
    /// status carries never goes back as `seq` grows.
    fn status_parts(
        &self,
        busy: &[sealctl_core::wire::BusyVolume],
        seq: u64,
    ) -> (sealctl_core::wire::SessionState, Vec<LogEntry>) {
        {
            let mut st = self.st();
            let n = self.now();
            let s = sealctl_core::wire::SessionState {
                session: st.state_word().into(),
                left: st.open.then(|| st.saved.left(n)),
                stop: st.saved.first_open.filter(|_| st.open).map(session::hard_stop),
                place: st.saved.place.clone(),
                busy: busy.to_vec(),
            };
            let log = st.log.carry(seq);
            (s, log)
        }
    }

    /// A `report` request body with the status fields (the fallback without a machine channel).
    async fn report_body(&self) -> sealctl_core::wire::RequestBody {
        let mut paired = self.paired.lock().await;
        paired.file.status_seq += 1;
        let seq = paired.file.status_seq;
        let _ = paired.file.save();
        let (state, log) = self.status_parts(&[], seq);
        drop(paired);
        let mut b = approve::body("report");
        b.seq = Some(seq);
        b.state = Some(state);
        b.log = log;
        b
    }

    /// The phone stored the status or report `seq`: drop the uses it carried, and send the
    /// rest with the next status.
    pub fn ack(&self, seq: u64) {
        let mut st = self.st();
        if st.log.ack(seq) {
            st.status_dirty = true;
        }
    }

    async fn send_status(&self, busy: &[sealctl_core::wire::BusyVolume]) -> Result<()> {
        let mut paired = self.paired.lock().await;
        paired.file.status_seq += 1;
        let seq = paired.file.status_seq;
        let _ = paired.file.save();
        let (state, log) = self.status_parts(busy, seq);
        let status = sealctl_core::wire::MachineStatus {
            version: 1,
            time: self.now(),
            seq,
            state: Some(state),
            log,
            inventory: Vec::new(),
            migrate: None,
        };
        #[cfg(test)]
        if self.t.offline() {
            let s = status.state.as_ref().map(|s| s.session.clone()).unwrap_or_default();
            self.t.event(format!("status {s}"));
            drop(paired);
            let mut st = self.st();
            st.status_dirty = false;
            st.last_status = self.now();
            st.sent_state = s;
            return Ok(());
        }
        let sealed = sealctl_core::channel::seal_status(&paired.keys, &paired.phone, &status)
            .map_err(|e| anyhow::anyhow!("sealing status: {e}"))?;
        let path = format!(
            "/v1/phones/{}/machines/{}/status",
            paired.phone_id(),
            paired.file.machine
        );
        self.relay
            .call(&paired.keys, "PUT", &path, Some(&json!({"sealed": sealed})))
            .await?;
        drop(paired);
        let mut st = self.st();
        st.status_dirty = false;
        st.last_status = self.now();
        st.sent_state = status.state.map(|s| s.session).unwrap_or_default();
        Ok(())
    }

    /// Starts the machine channel of session `generation`, if it is still Open. A channel left
    /// by a lock still running stops now: two sockets on one machine key evict each other.
    fn start_channel(self: &Arc<Self>, generation: u64) {
        let me = self.clone();
        let mut st = self.st();
        if !st.open || st.generation != generation {
            return;
        }
        #[cfg(test)]
        let h = if self.t.offline() {
            // the real channel sends a status first, then waits for messages
            tokio::spawn(async move {
                let _stopped = testing::Stopped(me.clone());
                let _ = me.send_status(&[]).await;
                std::future::pending::<()>().await;
            })
        } else {
            tokio::spawn(async move { channel::run(me).await })
        };
        #[cfg(not(test))]
        let h = tokio::spawn(async move { channel::run(me).await });
        for old in st.closing.drain(..) {
            old.abort();
        }
        if let Some(old) = st.channel.replace(h) {
            old.abort();
        }
    }

    /// Applies a machine message from the phone.
    pub async fn on_message(self: &Arc<Self>, sealed: &str) {
        let msg = {
            let mut paired = self.paired.lock().await;
            let m = sealctl_core::channel::open_message(&paired.keys, &paired.phone.identity, sealed);
            let Ok(m) = m else {
                log::warn!("dropped a machine message that did not check out");
                return;
            };
            if m.seq <= paired.file.msg_seq {
                return;
            }
            paired.file.msg_seq = m.seq;
            let _ = paired.file.save();
            m
        };
        self.apply_message(msg).await;
    }

    /// Applies a machine message whose `seq` is new (from the socket, or a report reply).
    pub async fn apply_message(self: &Arc<Self>, msg: sealctl_core::wire::MachineMessage) {
        use sealctl_core::wire::MessageKind;
        match msg.kind {
            MessageKind::Lock { reason } => {
                // A lock made before this session started is old (protocol.md); the phone's clock
                // may be behind the machine's, so "before" leaves a minute. The channel goes on
                // taking messages while the lock runs its slow steps.
                self.lock_soon(&reason, reason == "words", |st| {
                    (st.open && msg.time.saturating_add(LOCK_SKEW_MS) >= st.opened_at)
                        .then_some(false)
                });
            }
            MessageKind::Answers { answers, more } => {
                // a long list comes in parts; the list is replaced when the last part arrives
                let mut st = self.st();
                st.answers_parts.extend(answers.iter().flat_map(|x| {
                    x.names.iter().map(|n| Allowed {
                        agent: x.agent.clone(),
                        repo: x.repository.clone(),
                        name: n.clone(),
                    })
                }));
                if !more {
                    let a = std::mem::take(&mut st.answers_parts);
                    drop(st);
                    save_answers(&a);
                }
            }
            MessageKind::Ack { ack } => self.ack(ack),
            MessageKind::Notice { notice } => self.on_notice(&notice),
        }
    }

    /// Drops `answers` parts of a list that never finished (its last part lost or expired);
    /// called when a new machine socket or report session starts.
    pub fn reset_answer_parts(&self) {
        self.st().answers_parts.clear();
    }

    fn on_notice(&self, n: &sealctl_core::wire::Notice) {
        let what = match n.what.as_str() {
            "unseal_all" => "leaving sealctl",
            "leave" => "leaving sealctl",
            "words" => "showing the words",
            "delete" => "deleting the relay data",
            other => other,
        }
        .to_string();
        let on = n
            .machine
            .as_deref()
            .map(|m| format!(" on {m}"))
            .unwrap_or_default();
        match n.state.as_str() {
            "pending" => {
                let at = n.at.unwrap_or(0);
                util::notify(&format!(
                    "sealctl: your phone approved {what}{on} away from a trusted place. It takes effect at {}. Not you? Run: sealctl cancel",
                    session::hhmm(at)
                ));
                if let Some(id) = &n.delay {
                    let mut st = self.st();
                    st.pending.retain(|p| &p.id != id);
                    st.pending.push(Pending {
                        id: id.clone(),
                        what,
                        machine: n.machine.clone(),
                        at,
                    });
                }
            }
            "cancelled" => {
                util::notify(&format!("sealctl: cancelled from your phone: {what}{on}"));
                if let Some(id) = &n.delay {
                    self.st().pending.retain(|p| &p.id != id);
                }
            }
            "done" => {
                if let Some(r) = &n.report {
                    util::notify(&format!(
                        "sealctl: {} handed back {} objects ({}). {} failed.",
                        n.machine.clone().unwrap_or_default(),
                        r.done,
                        r.to.join(", "),
                        r.failed
                    ));
                }
            }
            _ => {}
        }
    }

    /// A relay `delayed` note.
    pub fn on_delayed_note(&self, id: &str, machine: Option<&str>, at: u64) {
        util::notify(&format!(
            "sealctl: a sensitive action was approved on your phone. It takes effect at {}. Not you? Run: sealctl cancel",
            session::hhmm(at)
        ));
        let mut st = self.st();
        if !st.pending.iter().any(|p| p.id == id) {
            st.pending.push(Pending {
                id: id.into(),
                what: "a sensitive action".into(),
                machine: machine.map(str::to_owned),
                at,
            });
        }
    }

    /// A relay `cancelled` note.
    pub fn on_cancelled_note(&self, id: &str) {
        self.st().pending.retain(|p| p.id != id);
    }

    /// One tick (every 15 s): idle input counts as work; idle allowance and hard stop lock.
    pub async fn tick(self: &Arc<Self>) {
        // The allowance is checked against the last work before this sample counts: after a
        // sleep, the key press that woke the machine must not turn the time asleep into work.
        // The tick goes on (status, the next session's timers) while the lock's backups run.
        if self.expire() {
            return;
        }
        // `ioreg` runs outside the state lock
        let idle = if self.st().open { self.idle_input() } else { None };
        let n = self.now();
        let (open, status_due) = {
            let mut st = self.st();
            if st.open && idle.is_some_and(|s| s < 60) {
                st.saved.work(n);
                save_saved(&st.saved);
            }
            // The phone takes the session as Open by its last status (keys and remembered
            // agent uses go without a tap): a status that went out while it was asked says
            // `waiting`, so the end of the wait is told at the next sample.
            let word = st.state_word();
            let changed = word != "waiting" && st.sent_state != word;
            let due = st.open
                && (n.saturating_sub(st.last_status) > 15 * 60 * 1000
                    || (st.status_dirty && n.saturating_sub(st.last_status) > 60 * 1000)
                    || (changed && n.saturating_sub(st.last_status) >= 10 * 1000));
            (st.open, due)
        };
        if open && status_due && !self.inproc {
            if let Err(e) = self.send_status(&[]).await {
                log::info!("status: {e:#}");
                // A failed status (refused, rate limited, relay down) is tried again in a
                // minute, not on every 15 s tick.
                let mut st = self.st();
                st.last_status = self.now();
                st.status_dirty = true;
            }
        }
    }

    /// Locks an Open session whose time is up (SPEC 6.4). The tick does this every 15 seconds,
    /// and every request for a key does it first, so a request right after a wake from sleep
    /// does not get a key, or count as work, before the tick has run. Returns whether it locked.
    fn expire(self: &Arc<Self>) -> bool {
        let n = self.now();
        self.lock_soon("idle", false, |st| {
            if st.open {
                expired(&st.saved, n)
            } else {
                None
            }
        })
    }

    /// A spawned daemon exits after 10 minutes Locked with no client (SPEC 6.1). A request
    /// on the phone is a client too: an SSH signature comes over the agent socket, not
    /// `daemon.sock`.
    fn idle_exit_due(&self) -> bool {
        let n = self.now();
        let st = self.st();
        !st.open
            && st.clients == 0
            && st.waiting_since.is_none()
            && n.saturating_sub(st.last_client) > 10 * 60 * 1000
    }

    /// The daemon is about to exit: it locks as any exit does (SPEC 6.3), and first lets any
    /// lock still running finish its backups and unmounts.
    async fn on_exit(self: &Arc<Self>) {
        if self.st().open {
            self.lock("cli", true, false).await;
        }
        let begun = self.st().locks_begun;
        let mut rx = self.locks_done.subscribe();
        let _ = rx.wait_for(|d| *d >= begun).await;
    }

    /// Handles one socket request.
    pub async fn handle(self: &Arc<Self>, req: Value, ev: Events) -> Result<Value> {
        let notify = req["notify"].as_bool().unwrap_or(false);
        match req["op"].as_str().unwrap_or("") {
            "status" => Ok(self.status()),
            "open" => {
                let ctx = self
                    .context(
                        None,
                        req["cmd"].as_str().unwrap_or(""),
                        req["cwd"].as_str().unwrap_or(""),
                        None,
                    )
                    .await;
                self.op_open(ctx, &ev, notify).await
            }
            "lock" => {
                let force = req["force"].as_bool().unwrap_or(false);
                let nb = req["noBackup"].as_bool().unwrap_or(false);
                Ok(self.lock("cli", nb, force).await)
            }
            "values" => {
                let r: ValuesReq = serde_json::from_value(req.clone())
                    .map_err(|_| fail(exit::USAGE, "bad values request"))?;
                let vals = self.op_values(r, &ev).await?;
                let out: Vec<Value> = vals
                    .iter()
                    .map(|(n, v)| json!({"name": n, "value": B64.encode(v.as_slice())}))
                    .collect();
                Ok(json!({"values": out}))
            }
            "keys" => {
                let items: Vec<RequestItem> = serde_json::from_value(req["items"].clone())
                    .map_err(|_| fail(exit::USAGE, "bad keys request"))?;
                let subject = req["subject"]["k"].as_str().map(|k| {
                    (
                        k.to_string(),
                        req["subject"]["n"].as_str().unwrap_or("").to_string(),
                    )
                });
                let (keys, words) = self.op_keys(items, subject, &ev, notify).await?;
                let out: Vec<String> = keys.iter().map(|k| k.b64u().to_string()).collect();
                Ok(json!({"keys": out, "words": words}))
            }
            "store" => self.op_store(&req, &ev).await,
            "exit" => {
                self.lock("cli", true, false).await;
                self.shutdown.notify_one();
                Ok(json!({}))
            }
            other => Err(fail(exit::USAGE, format!("unknown daemon op {other}"))),
        }
    }
}

/// Input idle time in seconds (macOS `HIDIdleTime`); `None` where unknown.
pub fn idle_input_secs() -> Option<u64> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let out = std::process::Command::new("/usr/sbin/ioreg")
        .args(["-c", "IOHIDSystem", "-d", "4", "-k", "HIDIdleTime"])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let ns: u64 = text
        .lines()
        .find_map(|l| l.split("\"HIDIdleTime\" = ").nth(1))?
        .trim()
        .parse()
        .ok()?;
    Some(ns / 1_000_000_000)
}

/// SPEC 6.7: no core dumps, and no other process of this user attaching a debugger or
/// reading the daemon's memory.
fn harden() {
    let _ = nix::sys::resource::setrlimit(nix::sys::resource::Resource::RLIMIT_CORE, 0, 0);
    #[cfg(target_os = "linux")]
    if let Err(e) = nix::sys::prctl::set_dumpable(false) {
        log::info!("PR_SET_DUMPABLE: {e}");
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: PT_DENY_ATTACH takes no address or data and only marks this process.
        let r = unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, std::ptr::null_mut(), 0) };
        if r != 0 {
            log::info!("PT_DENY_ATTACH: {}", std::io::Error::last_os_error());
        }
    }
}

/// One daemon per user: `daemon.lock` beside the socket, held while the daemon runs. A lock
/// held by a daemon that does not answer yet (starting) or any more (locking on its way out)
/// is waited for; one that answers means this daemon is not needed.
async fn instance_lock(sock: &std::path::Path) -> Result<nix::fcntl::Flock<std::fs::File>> {
    use nix::fcntl::{Flock, FlockArg};
    use std::os::unix::fs::OpenOptionsExt;
    let path = sock.with_file_name("daemon.lock");
    let until = tokio::time::Instant::now() + Duration::from_secs(30);
    loop {
        let f = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .context("opening daemon.lock")?;
        match Flock::lock(f, FlockArg::LockExclusiveNonblock) {
            Ok(l) => return Ok(l),
            Err((_, nix::errno::Errno::EWOULDBLOCK)) => {
                if tokio::net::UnixStream::connect(sock).await.is_ok() || tokio::time::Instant::now() >= until
                {
                    return Err(fail(exit::USAGE, "The daemon is running already."));
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err((_, e)) => return Err(anyhow::Error::from(e).context("locking daemon.lock")),
        }
    }
}

async fn serve_conn(d: Arc<Daemon>, stream: tokio::net::UnixStream) {
    if let Ok(cred) = stream.peer_cred() {
        if cred.uid() != nix::unistd::getuid().as_raw() {
            return;
        }
    } else {
        return;
    }
    {
        let mut st = d.st();
        st.clients += 1;
        st.last_client = now();
    }
    let (r, mut w) = stream.into_split();
    let mut lines = BufReader::new(r).lines();
    if let Ok(Some(line)) = lines.next_line().await {
        let req: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Value>();
        let ev: Events = Arc::new(move |v| {
            let _ = tx.send(v);
        });
        let version_ok = req["cli"].as_str() == Some(VERSION);
        let d2 = d.clone();
        let work = tokio::spawn(async move {
            if !version_ok {
                return Err(fail(
                    exit::ERROR,
                    "The sealctl daemon was another version; it restarts. Run the command again.",
                ));
            }
            d2.handle(req, ev).await
        });
        tokio::pin!(work);
        let result = loop {
            tokio::select! {
                Some(e) = rx.recv() => {
                    let _ = w.write_all(format!("{e}\n").as_bytes()).await;
                }
                r = &mut work => break r,
            }
        };
        while let Ok(e) = rx.try_recv() {
            let _ = w.write_all(format!("{e}\n").as_bytes()).await;
        }
        let answer = match result {
            Ok(Ok(mut v)) => {
                v["ok"] = json!(true);
                v
            }
            Ok(Err(e)) => json!({"ok": false, "code": exit::code_of(&e), "message": exit::message_of(&e)}),
            Err(_) => json!({"ok": false, "code": 1, "message": "the daemon failed"}),
        };
        let _ = w.write_all(format!("{answer}\n").as_bytes()).await;
        let _ = w.flush().await;
        if !version_ok {
            d.shutdown.notify_one();
        }
    }
    let mut st = d.st();
    st.clients = st.clients.saturating_sub(1);
    st.last_client = now();
}

/// `sealctl daemon [--spawned]`: serves the session until stopped.
pub fn run(spawned: bool) -> Result<()> {
    harden();
    IN_DAEMON.store(true, std::sync::atomic::Ordering::SeqCst);
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    rt.block_on(async move {
        let sock = paths::daemon_socket()?;
        paths::ensure_private_dir(sock.parent().context("state dir")?)?;
        // the state is read only once a daemon locking on its way out has written it
        let _instance = instance_lock(&sock).await?;
        let d = Daemon::new(false)?;
        let _ = std::fs::remove_file(&sock);
        let listener = tokio::net::UnixListener::bind(&sock).context("binding the daemon socket")?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
        crate::ssh::start_agent(d.clone());
        // the service manager stops the daemon with SIGTERM (logout, `launchctl bootout`,
        // `systemctl stop`): that is a daemon exit too, and locks
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .context("SIGTERM handler")?;
        let ticker = {
            let d = d.clone();
            tokio::spawn(async move {
                let mut t = tokio::time::interval(Duration::from_secs(15));
                loop {
                    t.tick().await;
                    d.tick().await;
                    if spawned && d.idle_exit_due() {
                        d.shutdown.notify_one();
                    }
                }
            })
        };
        loop {
            tokio::select! {
                a = listener.accept() => {
                    if let Ok((s, _)) = a {
                        tokio::spawn(serve_conn(d.clone(), s));
                    }
                }
                _ = d.shutdown.notified() => break,
                _ = tokio::signal::ctrl_c() => break,
                _ = term.recv() => break,
            }
        }
        ticker.abort();
        // Stop taking requests first, so the next CLI call starts the new daemon (which waits
        // for `daemon.lock`); then lock as any daemon exit does (SPEC 6.3), the version
        // mismatch included.
        drop(listener);
        let _ = std::fs::remove_file(&sock);
        d.on_exit().await;
        let _ = std::fs::remove_file(paths::ssh_agent_socket()?);
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(i: u64) -> LogEntry {
        LogEntry {
            time: i,
            ..LogEntry::default()
        }
    }

    fn times(v: &[LogEntry]) -> Vec<u64> {
        v.iter().map(|e| e.time).collect()
    }

    #[test]
    fn an_ack_drops_only_what_its_status_carried() {
        let mut log = UsageLog::default();
        for i in 1..=3 {
            log.push(entry(i));
        }
        assert_eq!(times(&log.carry(7)), [1, 2, 3]);
        // a use after status 7 was built, before its ack
        log.push(entry(4));
        assert!(log.ack(7));
        assert_eq!(times(&log.carry(8)), [4]);
        // an ack of an older status changes nothing more
        assert!(log.ack(7));
        assert!(!log.ack(8));
        assert!(log.carry(9).is_empty());
    }

    #[test]
    fn a_backlog_goes_out_oldest_first_fifty_at_a_time() {
        let mut log = UsageLog::default();
        for i in 1..=120 {
            log.push(entry(i));
        }
        let first = log.carry(1);
        assert_eq!(times(&first), (1..=50).collect::<Vec<_>>());
        assert!(log.ack(1));
        assert_eq!(times(&log.carry(2)), (51..=100).collect::<Vec<_>>());
        assert!(log.ack(2));
        assert_eq!(times(&log.carry(3)), (101..=120).collect::<Vec<_>>());
        assert!(!log.ack(3));
    }

    #[test]
    fn the_log_keeps_the_newest_two_hundred() {
        let mut log = UsageLog::default();
        for i in 1..=250 {
            log.push(entry(i));
        }
        assert_eq!(log.carry(1)[0].time, 51);
        // an ack for a status this daemon did not send drops nothing
        let mut fresh = UsageLog::default();
        fresh.push(entry(1));
        assert!(fresh.ack(99));
    }
}
