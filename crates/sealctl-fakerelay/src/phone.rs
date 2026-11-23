//! A scripted phone built on `sealctl-core`'s phone-side API: it pairs from a link, fetches
//! sealed requests from a relay (the fake one, or a live one), opens them, and answers them
//! the way a test says. It also sends machine messages and cancels delayed approvals.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use sealctl_core::wire::{MachineMessage, MessageKind};
use sealctl_core::{
    open_request, pairing_proof, plan_approval, relay_headers, seal_machine_message, seal_plan_keys_reply,
    seal_plan_part_reply, seal_reply, seal_report_reply, Decision, PairingOffer, PhoneKeys, PlanApproval,
    PlanAssembler, Request, RequestKind, Root, Words,
};
use serde_json::{json, Value};

/// A request as the relay lists it.
#[derive(Debug, Clone)]
pub struct Incoming {
    /// Request id.
    pub id: String,
    /// Machine key.
    pub machine: String,
    /// Sealed request.
    pub sealed: String,
    /// The relay's `near`.
    pub near: bool,
}

/// What a paired machine looks like to this phone.
#[derive(Debug, Clone)]
pub struct Machine {
    /// Machine key.
    pub key: String,
    /// Machine box key.
    pub box_key: String,
    /// Name.
    pub name: String,
}

/// The scripted phone.
pub struct Phone {
    /// Relay origin.
    pub relay: String,
    root: Arc<Root>,
    keys: PhoneKeys,
    http: reqwest::Client,
    assembler: PlanAssembler,
    approvals: std::sync::Mutex<Vec<PlanApproval>>,
    seq: std::sync::atomic::AtomicU64,
    /// Failed polls in a row; each one doubles the pause before the next poll.
    failures: std::sync::atomic::AtomicU32,
    /// Machines paired by this phone.
    pub machines: std::sync::Mutex<Vec<Machine>>,
    words: Vec<String>,
}

fn unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Phone {
    /// A phone with new random words.
    pub fn new(relay: &str) -> Phone {
        let words = Words::generate().expect("words");
        Phone::from_words(relay, &words)
    }

    /// A phone from given words.
    pub fn from_words(relay: &str, words: &Words) -> Phone {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let root = Root::from_words(words);
        let keys = PhoneKeys::from_root(&root);
        Phone {
            relay: relay.trim_end_matches('/').to_string(),
            root: Arc::new(root),
            keys,
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .expect("client"),
            assembler: PlanAssembler::new(),
            approvals: std::sync::Mutex::new(Vec::new()),
            seq: std::sync::atomic::AtomicU64::new(0),
            failures: std::sync::atomic::AtomicU32::new(0),
            machines: std::sync::Mutex::new(Vec::new()),
            words: words.list(),
        }
    }

    /// The 24 words (for tests that type them into `--words` or `recover`).
    pub fn words(&self) -> Vec<String> {
        self.words.clone()
    }

    /// The phone id.
    pub fn id(&self) -> String {
        self.keys.public_id()
    }

    /// The words fingerprint.
    pub fn fingerprint(&self) -> String {
        self.root.fingerprint()
    }

    /// The root (for deriving expected keys in tests).
    pub fn root(&self) -> Arc<Root> {
        self.root.clone()
    }

    /// The phone's clock moves on by `ms` (a fake clock for its plan window): every plan
    /// approval it keeps is that much older, so a continuation after it is judged as it would
    /// be `ms` later by the phone's clock, the machine's clock staying where it is.
    pub fn pass_time(&self, ms: u64) {
        for a in self.approvals.lock().unwrap().iter_mut() {
            a.not_before = a.not_before.saturating_sub(ms);
        }
    }

    /// One signed call.
    pub async fn call_once(&self, method: &str, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        let bytes = body
            .map(|b| serde_json::to_vec(&b).expect("json"))
            .unwrap_or_default();
        let h = relay_headers(&self.keys, method.into(), path.into(), unix(), bytes.clone());
        let mut rb = self
            .http
            .request(
                reqwest::Method::from_bytes(method.as_bytes())?,
                format!("{}{path}", self.relay),
            )
            .header("Sealctl-Key", h.key)
            .header("Sealctl-Time", h.time)
            .header("Sealctl-Signature", h.signature);
        if !bytes.is_empty() {
            rb = rb.header("Content-Type", "application/json").body(bytes);
        }
        let r = rb.send().await?;
        let status = r.status().as_u16();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        Ok((status, v))
    }

    /// A signed call that waits out the relay's short-term limits (`429` with `scope`
    /// `network` or `key`).
    pub async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<(u16, Value)> {
        for _ in 0..5 {
            let (s, v) = self.call_once(method, path, body.clone()).await?;
            if s == 429 && v["scope"].as_str().is_some_and(|x| x != "phone") {
                let wait = v["retryAfter"].as_u64().unwrap_or(10).clamp(1, 60);
                tokio::time::sleep(Duration::from_secs(wait)).await;
                continue;
            }
            return Ok((s, v));
        }
        self.call_once(method, path, body).await
    }

    /// Pairs from the link the CLI printed (or the part after `#`).
    pub async fn pair(&self, link: &str) -> Result<Machine> {
        let offer =
            PairingOffer::parse(link.trim().to_string()).map_err(|e| anyhow::anyhow!("pairing link: {e}"))?;
        let proof = pairing_proof(&self.keys, &offer);
        let body = json!({
            "machine": offer.machine_key(),
            "name": offer.name(),
            "os": offer.os(),
            "model": offer.model(),
            "hint": offer.hint(),
            "proof": proof,
        });
        let (s, v) = self
            .call("POST", &format!("/v1/phones/{}/machines", self.id()), Some(body))
            .await?;
        if s != 200 && s != 201 {
            bail!("pairing answered {s}: {v}");
        }
        let m = Machine {
            key: offer.machine_key(),
            box_key: offer.machine_box_key(),
            name: offer.name(),
        };
        self.machines.lock().unwrap().push(m.clone());
        Ok(m)
    }

    /// Registers a machine with a wrong proof (to test the machine refusing it).
    pub async fn pair_with_bad_proof(&self, link: &str) -> Result<()> {
        let offer = PairingOffer::parse(link.trim().to_string()).map_err(|e| anyhow::anyhow!("{e}"))?;
        let other = Phone::new(&self.relay);
        let proof = pairing_proof(&other.keys, &offer);
        let body = json!({"machine": offer.machine_key(), "name": offer.name(), "proof": proof});
        self.call("POST", &format!("/v1/phones/{}/machines", self.id()), Some(body))
            .await?;
        Ok(())
    }

    /// Pending requests.
    pub async fn requests(&self) -> Result<Vec<Incoming>> {
        let (s, v) = self
            .call("GET", &format!("/v1/phones/{}/requests", self.id()), None)
            .await?;
        if s != 200 {
            bail!("requests answered {s}: {v}");
        }
        Ok(v["requests"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .iter()
            .map(|r| Incoming {
                id: r["id"].as_str().unwrap_or("").into(),
                machine: r["machine"].as_str().unwrap_or("").into(),
                sealed: r["sealed"].as_str().unwrap_or("").into(),
                near: r["near"].as_bool().unwrap_or(false),
            })
            .collect())
    }

    /// How often to list pending requests: often on a loopback relay; on a live one slowly
    /// enough for its per-key limit (120 calls a minute) with several phones on one network.
    pub fn poll_interval(&self) -> Duration {
        if self.relay.starts_with("http://127.0.0.1") || self.relay.starts_with("http://localhost") {
            Duration::from_millis(150)
        } else {
            Duration::from_millis(1500)
        }
    }

    /// The pause after `failures` failed polls in a row: the poll interval doubled per
    /// failure, at most 30 s.
    pub fn failure_pause(&self, failures: u32) -> Duration {
        (self.poll_interval() * 2u32.pow(failures.min(8))).min(Duration::from_secs(30))
    }

    /// Waits for the next pending request not in `seen`.
    ///
    /// Every poll is followed by a pause, including one that failed (a `429`, a `5xx`, a
    /// dropped connection) and the last one before the timeout, so a caller that loops on
    /// this never lists requests faster than [`Phone::poll_interval`]; failures in a row
    /// back off up to 30 s (staging incident 2026-11-22: a loop that retried at once after
    /// `429` sent ~86,000 calls in 35 minutes).
    pub async fn next(&self, seen: &mut Vec<String>, timeout: Duration) -> Result<Incoming> {
        use std::sync::atomic::Ordering;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            match self.requests().await {
                Ok(list) => {
                    self.failures.store(0, Ordering::SeqCst);
                    for r in list {
                        if !seen.contains(&r.id) {
                            seen.push(r.id.clone());
                            return Ok(r);
                        }
                    }
                    tokio::time::sleep(self.poll_interval()).await;
                }
                Err(e) => {
                    let n = self.failures.fetch_add(1, Ordering::SeqCst);
                    tokio::time::sleep(self.failure_pause(n)).await;
                    if tokio::time::Instant::now() > deadline {
                        return Err(e);
                    }
                }
            }
            if tokio::time::Instant::now() > deadline {
                bail!("no request within {timeout:?}");
            }
        }
    }

    /// Opens a request.
    pub fn open(&self, r: &Incoming) -> Result<Arc<Request>> {
        open_request(&self.keys, r.machine.clone(), r.id.clone(), r.sealed.clone())
            .map_err(|e| anyhow::anyhow!("open_request: {e}"))
    }

    /// Posts a sealed reply, optionally delayed.
    pub async fn post_reply(&self, id: &str, sealed: String, delay: Option<u64>) -> Result<Value> {
        let mut body = json!({"sealed": sealed});
        if let Some(d) = delay {
            body["delay"] = json!(d);
        }
        let (s, v) = self
            .call(
                "POST",
                &format!("/v1/phones/{}/requests/{id}/reply", self.id()),
                Some(body),
            )
            .await?;
        if s != 200 {
            bail!("reply answered {s}: {v}");
        }
        Ok(v)
    }

    /// Answers with a decision (sealing with the root).
    pub async fn answer(&self, r: &Incoming, req: &Request, decision: Decision) -> Result<()> {
        let sealed = seal_reply(Some(self.root.clone()), &self.keys, req, decision)
            .map_err(|e| anyhow::anyhow!("seal_reply: {e}"))?;
        self.post_reply(&r.id, sealed, None).await.map(|_| ())
    }

    /// Answers an `unseal` request: plan parts are acknowledged, continuation requests get
    /// their keys, and the request that completes the plan is approved (after `pick`, when it
    /// carries the number match) with `delay` seconds. Returns `true` when a plan was approved.
    pub async fn answer_unseal(
        &self,
        r: &Incoming,
        req: &Arc<Request>,
        pick: Option<u32>,
        delay: Option<u64>,
    ) -> Result<bool> {
        let plan = req.plan().context("unseal without a plan")?;
        if plan.items.is_empty() && !plan.complete {
            // continuation: keys of an approved plan
            let approval = self
                .approvals
                .lock()
                .unwrap()
                .iter()
                .rev()
                .find(|a| a.hash == plan.hash && a.machine == r.machine)
                .cloned()
                .context("no approval for this plan")?;
            let sealed = seal_plan_keys_reply(&self.root, &self.keys, req, approval)
                .map_err(|e| anyhow::anyhow!("{e}"))?;
            self.post_reply(&r.id, sealed, None).await?;
            return Ok(false);
        }
        let complete = if plan.complete {
            true
        } else {
            self.assembler
                .add(req.clone())
                .map_err(|e| anyhow::anyhow!("plan: {e}"))?
                .is_some()
        };
        if !complete {
            let sealed = seal_plan_part_reply(&self.keys, req).map_err(|e| anyhow::anyhow!("{e}"))?;
            self.post_reply(&r.id, sealed, None).await?;
            return Ok(false);
        }
        if let Some(p) = pick {
            req.check_match(p);
        }
        let nb = now_ms() + delay.unwrap_or(0) * 1000;
        let sealed = seal_reply(
            Some(self.root.clone()),
            &self.keys,
            req,
            Decision::Plan {
                place: sealctl_core::Place::Trusted,
                not_before: nb,
            },
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
        if let Ok(a) = plan_approval(req, nb) {
            self.approvals.lock().unwrap().push(a);
        }
        self.post_reply(&r.id, sealed, delay).await?;
        Ok(true)
    }

    /// Answers a `report` request (acknowledged, no messages).
    pub async fn answer_report(&self, r: &Incoming, req: &Request) -> Result<()> {
        let sealed = seal_report_reply(&self.keys, req, req.status().map(|s| s.seq), vec![])
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.post_reply(&r.id, sealed, None).await.map(|_| ())
    }

    /// Answers a `report` request with messages for the machine (the fallback without a
    /// machine channel).
    pub async fn answer_report_with(
        &self,
        r: &Incoming,
        req: &Request,
        kinds: Vec<MessageKind>,
    ) -> Result<()> {
        let msgs = kinds
            .into_iter()
            .map(|kind| MachineMessage {
                version: 1,
                time: now_ms(),
                seq: self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1,
                kind,
            })
            .collect();
        let sealed = seal_report_reply(&self.keys, req, req.status().map(|s| s.seq), msgs)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.post_reply(&r.id, sealed, None).await.map(|_| ())
    }

    /// New words: registers `m` under this phone's key with a move proof signed by `old`
    /// (protocol.md, Phone key change); the relay drops the old pairing.
    pub async fn move_from(&self, old: &Phone, m: &Machine) -> Result<()> {
        let proof = sealctl_core::key_change_proof(&old.keys, &self.keys, m.key.clone())
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let body = json!({"machine": m.key, "name": m.name, "proof": proof});
        let (s, v) = self
            .call("POST", &format!("/v1/phones/{}/machines", self.id()), Some(body))
            .await?;
        if s != 200 && s != 201 {
            bail!("move answered {s}: {v}");
        }
        self.machines.lock().unwrap().push(m.clone());
        Ok(())
    }

    /// Answers `rewrap` with the old and new key of every item (`old`: the phone of the words
    /// before).
    pub async fn answer_rewrap(&self, r: &Incoming, req: &Request, old: &Phone) -> Result<()> {
        let sealed = sealctl_core::seal_rewrap_reply(&old.root, &self.root, &self.keys, req)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.post_reply(&r.id, sealed, None).await.map(|_| ())
    }

    /// Answers `old_words` as if the person typed the words of `old`.
    pub async fn answer_old_words(&self, r: &Incoming, req: &Request, old: &Phone) -> Result<()> {
        let sealed = sealctl_core::seal_old_words_reply(&old.root, &self.root, &self.keys, req)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        self.post_reply(&r.id, sealed, None).await.map(|_| ())
    }

    /// Sends a machine message (`lock`, `answers`, `notice`).
    pub async fn send_message(&self, m: &Machine, kind: MessageKind) -> Result<bool> {
        let seq = self.seq.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
        let msg = MachineMessage {
            version: 1,
            time: now_ms(),
            seq,
            kind,
        };
        let sealed = seal_machine_message(&self.keys, m.key.clone(), m.box_key.clone(), msg)
            .map_err(|e| anyhow::anyhow!("{e}"))?;
        let (s, v) = self
            .call(
                "POST",
                &format!("/v1/phones/{}/machines/{}/messages", self.id(), m.key),
                Some(json!({"sealed": sealed})),
            )
            .await?;
        if s != 200 {
            bail!("message answered {s}: {v}");
        }
        Ok(v["delivered"].as_bool().unwrap_or(false))
    }

    /// Cancels a delayed approval.
    pub async fn cancel(&self, id: &str) -> Result<()> {
        let (s, v) = self
            .call(
                "POST",
                &format!("/v1/phones/{}/delayed/{id}/cancel", self.id()),
                Some(json!({})),
            )
            .await?;
        if s != 200 {
            bail!("cancel answered {s}: {v}");
        }
        Ok(())
    }

    /// Delayed approvals.
    pub async fn delayed(&self) -> Result<Vec<Value>> {
        let (_, v) = self
            .call("GET", &format!("/v1/phones/{}/delayed", self.id()), None)
            .await?;
        Ok(v["delayed"].as_array().cloned().unwrap_or_default())
    }

    /// The latest machine status, opened.
    pub async fn status_of(&self, m: &Machine) -> Result<Option<sealctl_core::wire::MachineStatus>> {
        let (_, v) = self
            .call("GET", &format!("/v1/phones/{}/status", self.id()), None)
            .await?;
        for s in v["status"].as_array().cloned().unwrap_or_default() {
            if s["machine"] == m.key {
                let st = sealctl_core::open_machine_status(
                    &self.keys,
                    m.key.clone(),
                    s["sealed"].as_str().unwrap_or("").into(),
                )
                .map_err(|e| anyhow::anyhow!("{e}"))?;
                return Ok(Some(st));
            }
        }
        Ok(None)
    }

    /// Deletes the phone's data on the relay (staging clean-up).
    pub async fn delete(&self) -> Result<()> {
        let _ = self
            .call("DELETE", &format!("/v1/phones/{}", self.id()), None)
            .await?;
        Ok(())
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// How a scripted phone answers requests of each kind.
#[derive(Debug, Clone)]
pub enum Answer {
    /// Approve with `session` at a trusted place.
    Session,
    /// Approve once.
    Once,
    /// Approve and remember agent uses.
    Remember,
    /// Decline.
    Deny,
    /// Leave it unanswered.
    Ignore,
}

impl Phone {
    /// Answers one request by kind: `open`, `keys`, `agent`, `own` with `answer`; `report`
    /// acknowledged; `unseal` approved at once (no number, so only for level 2 with `near`
    /// or tests that pick through [`Phone::answer_unseal`]).
    pub async fn auto(&self, r: &Incoming, answer: &Answer) -> Result<RequestKind> {
        let req = self.open(r)?;
        let kind = req.kind();
        match kind {
            RequestKind::Report => self.answer_report(r, &req).await?,
            RequestKind::Unseal => {
                self.answer_unseal(r, &req, None, None).await?;
            }
            _ => {
                let place = sealctl_core::Place::Trusted;
                let d = match answer {
                    Answer::Session => Decision::Session { place },
                    Answer::Once => Decision::Once { place },
                    Answer::Remember => Decision::Remember { place },
                    Answer::Deny => Decision::Deny,
                    Answer::Ignore => return Ok(kind),
                };
                let d = if req.level() >= 2 && !matches!(d, Decision::Deny) {
                    // level 2: the number is checked by the test through `answer_with_pick`
                    d
                } else {
                    d
                };
                self.answer(r, &req, d).await?;
            }
        }
        Ok(kind)
    }
}

/// Runs a phone in the background on its own thread, answering every request with `answer`
/// until dropped. Returns a handle that stops it.
pub struct Background {
    stop: Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    /// Kinds answered, in order.
    pub log: Arc<std::sync::Mutex<Vec<String>>>,
}

impl Drop for Background {
    fn drop(&mut self) {
        self.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(h) = self.handle.take() {
            let _ = h.join();
        }
    }
}

impl Background {
    /// Starts answering.
    pub fn start(phone: Arc<Phone>, answer: Answer) -> Background {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let log = Arc::new(std::sync::Mutex::new(Vec::new()));
        let (s2, l2) = (stop.clone(), log.clone());
        let handle = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("rt");
            rt.block_on(async move {
                let mut seen = Vec::new();
                while !s2.load(std::sync::atomic::Ordering::SeqCst) {
                    match phone.next(&mut seen, Duration::from_millis(300)).await {
                        Ok(r) => match phone.auto(&r, &answer).await {
                            Ok(k) => l2.lock().unwrap().push(format!("{k:?}")),
                            Err(e) => l2.lock().unwrap().push(format!("error: {e:#}")),
                        },
                        Err(_) => continue,
                    }
                }
            });
        });
        Background {
            stop,
            handle: Some(handle),
            log,
        }
    }

    /// What was answered so far.
    pub fn answered(&self) -> Vec<String> {
        self.log.lock().unwrap().clone()
    }
}
