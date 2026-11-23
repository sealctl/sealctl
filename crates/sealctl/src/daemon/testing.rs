//! Unit-test seams for the daemon (compiled only for `cargo test`): a fake wall clock, a fake
//! input idle time, gates that hold the slow steps (on-lock backups, mounting) until a test
//! lets them go, canned phone answers, and a log of the steps taken in order. Production code
//! never builds a [`Hooks`] with anything switched on.
#![allow(dead_code)]

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine;
use sealctl_core::wire::ReplyBody;
use sealctl_core::{MachineKeys, PhoneKeys, PhonePublic};

use super::{Daemon, State};
use crate::machine::{MachineFile, Paired};
use crate::relay::Relay;

/// A slow step that waits for the test while switched on.
pub struct Gate {
    on: AtomicBool,
    sem: tokio::sync::Semaphore,
}

impl Default for Gate {
    fn default() -> Self {
        Gate {
            on: AtomicBool::new(false),
            sem: tokio::sync::Semaphore::new(0),
        }
    }
}

impl Gate {
    /// Holds the step until [`Gate::release`].
    pub fn hold(&self) {
        self.on.store(true, Ordering::SeqCst);
    }

    /// Lets one waiting (or future) step through.
    pub fn release(&self) {
        self.sem.add_permits(1);
    }

    pub(super) async fn pass(&self, name: &str, h: &Hooks) {
        h.event(format!("{name} start"));
        if self.on.load(Ordering::SeqCst) {
            if let Ok(p) = self.sem.acquire().await {
                p.forget();
            }
        }
        h.event(format!("{name} end"));
    }
}

/// A canned phone answer: waits for its gate (if any), then answers.
pub struct Canned {
    pub gate: Option<Arc<tokio::sync::Semaphore>>,
    pub reply: ReplyBody,
}

/// What a test switched on.
#[derive(Default)]
pub struct Hooks {
    /// Wall clock, Unix ms (0: the real clock).
    pub now: AtomicU64,
    /// Input idle time in seconds; `None` inside: unknown. Unset: the real one.
    pub idle: Mutex<Option<Option<u64>>>,
    /// The steps taken, in order.
    pub events: Mutex<Vec<String>>,
    /// One simulated on-lock backup per lock that runs backups.
    pub backup: Gate,
    /// One simulated auto volume mounted per open.
    pub mount: Gate,
    /// Answers for `ask`, in order; empty: the real relay.
    pub answers: Mutex<VecDeque<Canned>>,
    /// Results of closing one simulated volume (`true`: busy); empty: the real volumes.
    pub vol_busy: Mutex<VecDeque<bool>>,
    /// Statuses that fail before the rest go out.
    pub status_failures: Mutex<u32>,
    /// Statuses are recorded, not sent; the machine channel is a stand-in that sends one
    /// status when it starts, as the real one does.
    pub offline: AtomicBool,
}

impl Hooks {
    pub fn event(&self, e: impl Into<String>) {
        self.events.lock().unwrap().push(e.into());
    }

    pub fn events(&self) -> Vec<String> {
        self.events.lock().unwrap().clone()
    }

    pub fn set_now(&self, ms: u64) {
        self.now.store(ms, Ordering::SeqCst);
    }

    pub fn advance(&self, ms: u64) {
        self.now.fetch_add(ms, Ordering::SeqCst);
    }

    pub fn set_idle(&self, secs: Option<u64>) {
        *self.idle.lock().unwrap() = Some(secs);
    }

    pub fn answer(&self, reply: ReplyBody, gate: Option<Arc<tokio::sync::Semaphore>>) {
        self.answers.lock().unwrap().push_back(Canned { gate, reply });
    }

    pub(super) fn canned(&self) -> Option<Canned> {
        self.answers.lock().unwrap().pop_front()
    }

    pub(super) fn fail_status(&self) -> bool {
        let mut n = self.status_failures.lock().unwrap();
        match n.checked_sub(1) {
            Some(m) => {
                *n = m;
                true
            }
            None => false,
        }
    }

    pub(super) fn offline(&self) -> bool {
        self.offline.load(Ordering::SeqCst)
    }
}

/// Notes when the stand-in machine channel stops.
pub struct Stopped(pub Arc<Daemon>);

impl Drop for Stopped {
    fn drop(&mut self) {
        self.0.t.event("channel stopped");
    }
}

/// Test time: about 2027-01-15, moved to an hour whose hard stop (in this machine's zone) is the
/// full 14 hours away, so idle tests do not run into it.
pub fn t0() -> u64 {
    let base = 1_800_000_000_000u64;
    (0..48)
        .map(|h| base + h * 3_600_000)
        .find(|&t| super::session::hard_stop(t) == t + 14 * 3_600_000)
        .unwrap_or(base)
}

/// A daemon paired with a made-up phone through `relay` (nothing is called unless a test
/// lets it), statuses recorded, and the clock at [`t0`]. Returns the phone's keys too.
pub fn daemon(relay: &str) -> (Arc<Daemon>, PhoneKeys) {
    // as `main` does
    let _ = rustls::crypto::ring::default_provider().install_default();
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let keys = MachineKeys::generate().unwrap();
    let mut raw = [0u8; 64];
    getrandom::fill(&mut raw).unwrap();
    let phone_keys = PhoneKeys::from_bytes(raw.to_vec()).unwrap();
    let phone = PhonePublic {
        identity: *phone_keys.identity_public(),
        box_key: *phone_keys.box_public(),
    };
    let file = MachineFile::new(
        &keys,
        "tester@test",
        relay,
        &b64.encode(phone.identity),
        &b64.encode(phone.box_key),
    )
    .unwrap();
    let d = Daemon::with(
        Paired { keys, phone, file },
        Relay::new(relay).unwrap(),
        false,
        State::default(),
    );
    d.t.set_now(t0());
    d.t.set_idle(None);
    d.t.offline.store(true, Ordering::SeqCst);
    (d, phone_keys)
}

/// A `session` grant from a trusted place with keys for `items` (random keys).
pub fn session_reply(items: &[sealctl_core::wire::RequestItem]) -> ReplyBody {
    grant("session", items)
}

/// A reply granting `grant` with random keys for `items`.
pub fn grant(grant: &str, items: &[sealctl_core::wire::RequestItem]) -> ReplyBody {
    ReplyBody {
        v: 1,
        ok: true,
        grant: Some(grant.into()),
        place: Some("trusted".into()),
        cap: Some(14_400),
        base: Some(1_800),
        rate: Some(120),
        w: Some("qHWf".into()),
        keys: items
            .iter()
            .map(|i| {
                let mut k = [0u8; 16];
                getrandom::fill(&mut k).unwrap();
                sealctl_core::wire::ReplyKey {
                    p: i.purpose.clone(),
                    i: i.id.clone(),
                    k: Some(zeroize::Zeroizing::new(B64U.encode(k))),
                    ..Default::default()
                }
            })
            .collect(),
        ..Default::default()
    }
}

const B64U: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// A request item `purpose:id`.
pub fn item(purpose: &str, id: &str) -> sealctl_core::wire::RequestItem {
    sealctl_core::wire::RequestItem {
        purpose: purpose.into(),
        id: id.into(),
        words: Some("qHWf".into()),
        ..Default::default()
    }
}
