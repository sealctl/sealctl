//! Sealed requests (machine to phone) and the machine's side of replies.
//!
//! A machine seals a request to the phone box key with HPKE and signs it with its pairing key;
//! the phone opens it into a [`Request`]. The phone's replies are in [`crate::reply`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

use rand_core::CryptoRng;
use serde::Deserialize;
use zeroize::Zeroizing;

use crate::crypto::{self, ENC_LEN, SIG_LEN, TAG_LEN};
use crate::error::{CoreError, Result};
use crate::machine::MachineKeys;
use crate::pairing::PROTOCOL_VERSION;
use crate::phone::{PhoneKeys, PhonePublic};
use crate::plan::{self, RequestPlan};
use crate::time;
use crate::wire::{AgentUse, Handback, MachineStatus, ReplyBody, RequestBody, RequestContext, RequestItem};

/// Longest sealed request or reply, in base64url characters.
pub const MAX_SEALED: usize = 4096;
/// Longest request or reply body: 3,072 bytes less `enc`, tag and signature.
pub const MAX_BODY: usize = MAX_SEALED / 4 * 3 - ENC_LEN - TAG_LEN - SIG_LEN;
/// How far a request's `t` may be from the phone's clock, in ms.
pub const TIME_WINDOW_MS: u64 = 10 * 60 * 1000;

pub(crate) const REQUEST_INFO: &[u8] = b"sealctl/v1/request";
pub(crate) const REPLY_INFO: &[u8] = b"sealctl/v1/reply";

/// The request kinds (`why`).
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RequestKind {
    /// The session is Locked and needs a key.
    Open,
    /// The session is Open and needs a key it does not hold.
    Keys,
    /// An agent's first use of a secret in a repository.
    Agent,
    /// An `--own-approval` secret.
    Own,
    /// Old and new keys after new words.
    Rewrap,
    /// An object sealed with retired words.
    OldWords,
    /// `sealctl unseal`: hand objects back under the user's own passwords.
    Unseal,
    /// Status, migration estimates or a hand-back report; never shown.
    Report,
    /// A kind this core does not know: shown with Deny only, level 3.
    Unknown,
}

impl RequestKind {
    /// From `why`.
    pub fn parse(why: &str) -> Self {
        match why {
            "open" => Self::Open,
            "keys" => Self::Keys,
            "agent" => Self::Agent,
            "own" => Self::Own,
            "rewrap" => Self::Rewrap,
            "old_words" => Self::OldWords,
            "unseal" => Self::Unseal,
            "report" => Self::Report,
            _ => Self::Unknown,
        }
    }
}

#[derive(Default)]
struct MatchState {
    choices: Option<[u8; 3]>,
    verdict: Option<bool>,
}

/// An opened, verified request. The number match stays inside it.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Request {
    pub(crate) id: String,
    pub(crate) machine: [u8; 32],
    pub(crate) body: RequestBody,
    rq: String,
    number: Option<u8>,
    matching: Mutex<MatchState>,
    whole_plan: Mutex<Option<RequestPlan>>,
    answered: AtomicBool,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Request {
    /// The relay request id.
    pub fn id(&self) -> String {
        self.id.clone()
    }

    /// The machine id (`M`) it came from, 43 characters.
    pub fn machine(&self) -> String {
        crypto::b64u(&self.machine)
    }

    /// The kind.
    pub fn kind(&self) -> RequestKind {
        RequestKind::parse(&self.body.why)
    }

    /// `why` as sent, for an unknown kind.
    pub fn kind_name(&self) -> String {
        self.body.why.clone()
    }

    /// Protocol version of the body.
    pub fn version(&self) -> u32 {
        self.body.v
    }

    /// When the machine made it, Unix ms.
    pub fn time(&self) -> u64 {
        self.body.t
    }

    /// Who asks and why.
    pub fn ctx(&self) -> Option<RequestContext> {
        self.body.ctx.clone()
    }

    /// The keys asked for.
    pub fn items(&self) -> Vec<RequestItem> {
        self.body.keys.clone()
    }

    /// Agent uses to decide.
    pub fn uses(&self) -> Vec<AgentUse> {
        self.body.uses.clone()
    }

    /// `old_words`: the retired words fingerprint.
    pub fn old(&self) -> Option<String> {
        self.body.old.clone()
    }

    /// Minutes worked today on the machine.
    pub fn work(&self) -> Option<u64> {
        self.body.work
    }

    /// `report`: the status fields, when it carries any.
    pub fn status(&self) -> Option<MachineStatus> {
        let b = &self.body;
        let any = b.seq.is_some()
            || b.state.is_some()
            || !b.log.is_empty()
            || !b.inv.is_empty()
            || b.migrate.is_some();
        (self.kind() == RequestKind::Report && any).then(|| MachineStatus {
            version: b.v,
            time: b.t,
            seq: b.seq.unwrap_or(0),
            state: b.state.clone(),
            log: b.log.clone(),
            inventory: b.inv.clone(),
            migrate: b.migrate.clone(),
        })
    }

    /// `report`: what a finished `unseal` handed back.
    pub fn handback(&self) -> Option<Handback> {
        self.body.handback.clone()
    }

    /// `unseal`: the plan; the whole plan once complete (one part, or assembled).
    pub fn plan(&self) -> Option<RequestPlan> {
        if let Ok(guard) = self.whole_plan.lock() {
            if let Some(p) = guard.as_ref() {
                return Some(p.clone());
            }
        }
        let p = self.body.plan.as_ref()?;
        Some(RequestPlan {
            all: p.all,
            hash: p.h.clone(),
            items: p.items.clone(),
            part: p.i,
            parts: p.n,
            complete: false,
        })
    }

    /// The confirmation level the phone applies: the kind's level or `lvl`, whichever is higher.
    pub fn level(&self) -> u8 {
        let kind_level = match self.kind() {
            RequestKind::Open | RequestKind::Agent | RequestKind::Own | RequestKind::Report => 1,
            RequestKind::Keys => {
                let seal = self
                    .body
                    .ctx
                    .as_ref()
                    .and_then(|c| c.subject.as_ref())
                    .is_some_and(|s| s.kind == "machine" && s.name == "seal");
                if seal {
                    2
                } else {
                    1
                }
            }
            RequestKind::Rewrap | RequestKind::OldWords => 2,
            RequestKind::Unseal => self.plan().map_or(2, |p| p.level()),
            RequestKind::Unknown => 3,
        };
        kind_level.max(self.requested_level())
    }

    /// `lvl` as the machine sent it, 1 to 3.
    pub fn requested_level(&self) -> u8 {
        self.body.lvl.unwrap_or(1).clamp(1, 3) as u8
    }

    /// A person at the machine's terminal is shown the number match.
    pub fn has_match(&self) -> bool {
        self.number.is_some()
    }

    /// `b64u(SHA256(request body))`.
    pub fn rq(&self) -> String {
        self.rq.clone()
    }

    /// The three numbers to offer, in display order: the right one and two others, distinct,
    /// from 10 to 99. Empty when the request has no number match. Stable for this request.
    pub fn match_choices(&self) -> Vec<u32> {
        let Some(n) = self.number else { return Vec::new() };
        let Ok(mut st) = self.matching.lock() else {
            return Vec::new();
        };
        if st.choices.is_none() {
            st.choices = draw_choices(n).ok();
        }
        st.choices
            .map(|c| c.iter().map(|&n| u32::from(n)).collect())
            .unwrap_or_default()
    }

    /// Checks the pick. Only a pick among [`Request::match_choices`] can be right, and a wrong
    /// pick is final for this request.
    pub fn check_match(&self, pick: u32) -> bool {
        let Some(n) = self.number else { return false };
        let Ok(mut st) = self.matching.lock() else {
            return false;
        };
        let ok = st.verdict != Some(false)
            && st
                .choices
                .is_some_and(|c| c.iter().any(|&c| u32::from(c) == pick))
            && pick == u32::from(n);
        st.verdict = Some(ok);
        ok
    }
}

impl Request {
    pub(crate) fn match_passed(&self) -> bool {
        self.matching
            .lock()
            .map(|st| st.verdict == Some(true))
            .unwrap_or(false)
    }

    pub(crate) fn attach_plan(&self, plan: RequestPlan) -> Result<()> {
        *self.whole_plan.lock().map_err(|_| CoreError::Internal)? = Some(plan);
        Ok(())
    }

    pub(crate) fn ensure_unanswered(&self) -> Result<()> {
        if self.answered.load(Ordering::SeqCst) {
            Err(CoreError::Replay)
        } else {
            Ok(())
        }
    }

    pub(crate) fn mark_answered(&self) {
        self.answered.store(true, Ordering::SeqCst);
    }

    /// The one-time public key the reply is sealed to.
    pub(crate) fn one_time_public(&self) -> Result<[u8; 32]> {
        let ot = self.body.ot.as_deref().ok_or(CoreError::BadSealed)?;
        crypto::decode_key32(ot).map_err(|_| CoreError::BadSealed)
    }

    /// The request body as parsed.
    pub fn body(&self) -> &RequestBody {
        &self.body
    }
}

fn draw_choices(n: u8) -> Result<[u8; 3]> {
    let mut others = Vec::with_capacity(2);
    while others.len() < 2 {
        let c = 10 + crypto::random_below(90)? as u8;
        if c != n && !others.contains(&c) {
            others.push(c);
        }
    }
    let at = crypto::random_below(3)? as usize;
    let mut out = [n, others[0], others[1]];
    out.swap(0, at);
    Ok(out)
}

pub(crate) fn aad(id: &str, machine: &[u8; 32]) -> Vec<u8> {
    crypto::cat(&[id.as_bytes(), &[0], machine])
}

pub(crate) fn request_message(id: &str, phone: &[u8; 32], body: &[u8]) -> Vec<u8> {
    crypto::cat(&[REQUEST_INFO, &[0], id.as_bytes(), &[0], phone, body])
}

pub(crate) fn reply_message(id: &str, machine: &[u8; 32], body: &[u8]) -> Vec<u8> {
    crypto::cat(&[REPLY_INFO, &[0], id.as_bytes(), &[0], machine, body])
}

/// Reads `v` before anything else, so a newer body is refused as newer, not as malformed.
pub(crate) fn check_version(body: &[u8]) -> Result<()> {
    #[derive(Deserialize)]
    struct V {
        #[serde(default)]
        v: u64,
    }
    let v: V = serde_json::from_slice(body).map_err(|_| CoreError::BadSealed)?;
    if v.v > u64::from(PROTOCOL_VERSION) {
        return Err(CoreError::NewerVersion);
    }
    if v.v != u64::from(PROTOCOL_VERSION) {
        return Err(CoreError::BadSealed);
    }
    Ok(())
}

/// Opens a request from the relay: HPKE with the phone box key, the machine's signature, the
/// version, the 10-minute time window and the plan rules. `relay_machine_key` is the relay's
/// `machine`; the HPKE `aad` and the signature both bind it, so a relay that names another
/// machine gets nothing that opens.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn open_request(
    keys: &PhoneKeys,
    relay_machine_key: String,
    id: String,
    sealed: String,
) -> Result<std::sync::Arc<Request>> {
    open_request_at(keys, &relay_machine_key, &id, &sealed, time::now_unix_ms()).map(std::sync::Arc::new)
}

/// [`open_request`] against a given clock (Unix ms).
pub fn open_request_at(
    keys: &PhoneKeys,
    relay_machine_key: &str,
    id: &str,
    sealed: &str,
    now_ms: u64,
) -> Result<Request> {
    if sealed.len() > MAX_SEALED {
        return Err(CoreError::BadSealed);
    }
    let machine = crypto::decode_key32(relay_machine_key)?;
    crypto::b64u_decode_fixed::<16>(id).ok_or(CoreError::BadSealed)?;
    let raw = crypto::b64u_decode(sealed).ok_or(CoreError::BadSealed)?;
    if raw.len() < ENC_LEN + TAG_LEN + SIG_LEN {
        return Err(CoreError::BadSealed);
    }
    let (pt, export) = crypto::hpke_open(keys.box_secret(), REQUEST_INFO, &aad(id, &machine), &raw)?;
    if pt.len() < SIG_LEN {
        return Err(CoreError::BadSealed);
    }
    let (sig, body_bytes) = pt.split_at(SIG_LEN);
    crypto::ed25519_verify(
        &machine,
        &request_message(id, keys.identity_public(), body_bytes),
        sig,
    )?;
    check_version(body_bytes)?;
    let body: RequestBody = serde_json::from_slice(body_bytes).map_err(|_| CoreError::BadSealed)?;
    if body.t.abs_diff(now_ms) > TIME_WINDOW_MS {
        return Err(CoreError::Expired);
    }
    let machine_id = crypto::b64u(&machine);
    let mut whole = None;
    if let Some(p) = body.plan.as_ref() {
        for item in &p.items {
            plan::check_item(item)?;
        }
        if crypto::b64u_decode_fixed::<32>(&p.h).is_none() {
            return Err(CoreError::BadPlan);
        }
        let (parts, part) = (p.n.unwrap_or(1), p.i.unwrap_or(1));
        if parts == 0 || parts > plan::MAX_PARTS || part == 0 || part > parts {
            return Err(CoreError::BadPlan);
        }
        if parts == 1 && !p.items.is_empty() {
            if crypto::b64u(&plan::plan_hash(&machine_id, &p.items)) != p.h {
                return Err(CoreError::BadPlan);
            }
            whole = Some(RequestPlan {
                all: p.all,
                hash: p.h.clone(),
                items: p.items.clone(),
                part: p.i,
                parts: p.n,
                complete: true,
            });
        }
    }
    let number = body.has_match.then(|| crypto::match_number(&export));
    Ok(Request {
        id: id.to_owned(),
        machine,
        rq: crypto::b64u(&crypto::sha256(body_bytes)),
        body,
        number,
        matching: Mutex::new(MatchState::default()),
        whole_plan: Mutex::new(whole),
        answered: AtomicBool::new(false),
    })
}

// ---------- machine side ----------

/// The one-time X25519 key a reply is sealed to; lives in memory until the reply arrives.
pub struct OneTimeKey {
    secret: Zeroizing<[u8; 32]>,
    public: [u8; 32],
}

impl OneTimeKey {
    /// `ot_pk`.
    pub fn public(&self) -> &[u8; 32] {
        &self.public
    }
}

/// A sealed request and what the machine keeps to read its reply.
pub struct SealedRequest {
    /// The relay request id.
    pub id: String,
    /// `b64u(enc ‖ ct)`, at most 4,096 characters.
    pub sealed: String,
    /// The exact body bytes that were signed (for `rq`).
    pub body: Vec<u8>,
    /// The number match to print at the terminal, when the body has `match`.
    pub number: Option<u8>,
    one_time: OneTimeKey,
}

/// A new relay request id: 16 random bytes, 22 characters.
pub fn new_request_id() -> Result<String> {
    Ok(crypto::b64u(&crypto::random_array::<16>()?))
}

/// Seals a request to the phone. Makes the one-time key and puts it in `ot`.
pub fn seal_request(
    machine: &MachineKeys,
    phone: &PhonePublic,
    id: &str,
    body: RequestBody,
) -> Result<SealedRequest> {
    seal_request_with_rng(machine, phone, id, body, &mut crypto::os_rng())
}

/// [`seal_request`] with a given random source (the one-time key, then the HPKE ephemeral key).
pub fn seal_request_with_rng(
    machine: &MachineKeys,
    phone: &PhonePublic,
    id: &str,
    mut body: RequestBody,
    rng: &mut impl CryptoRng,
) -> Result<SealedRequest> {
    if crypto::b64u_decode_fixed::<16>(id).is_none() {
        return Err(CoreError::BadLabel);
    }
    let (secret, public) = crypto::x25519_generate(rng);
    body.ot = Some(crypto::b64u(&public));
    let bytes = serde_json::to_vec(&body).map_err(|_| CoreError::Internal)?;
    let (sealed, export) = seal_request_bytes(machine, phone, id, &bytes, rng)?;
    Ok(SealedRequest {
        id: id.to_owned(),
        sealed,
        body: bytes,
        number: body.has_match.then(|| crypto::match_number(&export)),
        one_time: OneTimeKey { secret, public },
    })
}

/// Seals exact body bytes (which must already hold `ot`).
pub(crate) fn seal_request_bytes(
    machine: &MachineKeys,
    phone: &PhonePublic,
    id: &str,
    body: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(String, [u8; 4])> {
    if body.len() > MAX_BODY {
        return Err(CoreError::TooLarge);
    }
    let sig = machine.sign(&request_message(id, &phone.identity, body));
    let pt = Zeroizing::new(crypto::cat(&[&sig, body]));
    let s = crypto::hpke_seal(&phone.box_key, REQUEST_INFO, &aad(id, machine.public()), &pt, rng)?;
    let sealed = crypto::b64u(&s.bytes);
    if sealed.len() > MAX_SEALED {
        return Err(CoreError::TooLarge);
    }
    Ok((sealed, s.match_export))
}

impl SealedRequest {
    #[cfg(test)]
    pub(crate) fn one_time_for_tests(&self) -> (&[u8; 32], &[u8; 32]) {
        (&self.one_time.public, &self.one_time.secret)
    }

    /// Opens the phone's reply: HPKE with the one-time key, the phone's signature, the
    /// version, and `rq`. Any failure means the reply is dropped (`bad_reply`).
    pub fn open_reply(&self, machine: &[u8; 32], phone: &[u8; 32], sealed: &str) -> Result<ReplyBody> {
        if sealed.len() > MAX_SEALED {
            return Err(CoreError::BadSealed);
        }
        let raw = crypto::b64u_decode(sealed).ok_or(CoreError::BadSealed)?;
        if raw.len() < ENC_LEN + TAG_LEN + SIG_LEN {
            return Err(CoreError::BadSealed);
        }
        let (pt, _) = crypto::hpke_open(&self.one_time.secret, REPLY_INFO, &aad(&self.id, machine), &raw)?;
        if pt.len() < SIG_LEN {
            return Err(CoreError::BadSealed);
        }
        let (sig, body) = pt.split_at(SIG_LEN);
        crypto::ed25519_verify(phone, &reply_message(&self.id, machine, body), sig)?;
        check_version(body)?;
        let reply: ReplyBody = serde_json::from_slice(body).map_err(|_| CoreError::BadSealed)?;
        if reply.rq != crypto::b64u(&crypto::sha256(&self.body)) {
            return Err(CoreError::BadSealed);
        }
        Ok(reply)
    }
}
