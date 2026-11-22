//! The phone's replies: every answer to a [`Request`] is signed with the phone identity and
//! sealed to the request's one-time key. Object keys are derived here and never leave Rust
//! except inside a sealed reply.

use std::sync::Arc;

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::keys::{is_valid_object_id, ObjectKey, Purpose};
use crate::pairing::PROTOCOL_VERSION;
use crate::phone::{PhoneKeys, Place};
use crate::plan::{self, KeyRef, PlanApproval, PLAN_WINDOW_MS};
use crate::request::{self, Request, RequestKind, MAX_BODY, MAX_SEALED, REPLY_INFO};
use crate::root::Root;
use crate::time;
use crate::wire::{MachineMessage, PlanSignature, ReplyBody, ReplyKey, RequestItem};

/// Why the phone refuses, beyond a plain Deny (`declined`).
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RefuseReason {
    /// A key purpose or id the phone does not hand out.
    BadLabel,
    /// The key would not match the object.
    WrongKey,
    /// The object is sealed with retired words.
    RetiredWords,
    /// The app does not support this request.
    Unsupported,
    /// The phone is locked (the root cannot be read).
    PhoneLocked,
    /// The wrong number was picked.
    NoMatch,
    /// No proximity.
    NotNear,
    /// Biometrics unavailable or locked out.
    NoBiometrics,
    /// This machine picked a wrong number within the last hour.
    Held,
    /// A key not in the approved plan.
    OutsidePlan,
    /// The plan approval expired.
    PlanExpired,
}

impl RefuseReason {
    /// The wire code (`err`).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::BadLabel => "bad_label",
            Self::WrongKey => "wrong_key",
            Self::RetiredWords => "retired_words",
            Self::Unsupported => "unsupported",
            Self::PhoneLocked => "phone_locked",
            Self::NoMatch => "no_match",
            Self::NotNear => "not_near",
            Self::NoBiometrics => "no_biometrics",
            Self::Held => "held",
            Self::OutsidePlan => "outside_plan",
            Self::PlanExpired => "plan_expired",
        }
    }
}

/// What the person (or the levels of asking) decided.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Declined (`declined`).
    Deny,
    /// Refused for a reason.
    Refuse {
        /// The reason.
        err: RefuseReason,
    },
    /// Keys and uses for the command that asked, then wiped (`grant: once`).
    Once {
        /// Where the phone is.
        place: Place,
    },
    /// Kept until the session locks (`grant: session`).
    Session {
        /// Where the phone is.
        place: Place,
    },
    /// `Session`, and the agent uses are remembered (`remember: true`).
    Remember {
        /// Where the phone is.
        place: Place,
    },
    /// `unseal`: sign the plan and hand out keys named by it (`grant: plan`).
    Plan {
        /// Where the phone is.
        place: Place,
        /// Approval time, or one hour later away from a trusted place; Unix ms.
        not_before: u64,
    },
}

/// Words the phone retired, so items sealed with them are answered `retired_words`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetiredWords {
    /// Their fingerprint.
    pub fingerprint: String,
    /// When they were retired, `YYYY-MM-DD`.
    pub retired: String,
}

fn base(request: &Request, ok: bool) -> ReplyBody {
    ReplyBody {
        v: PROTOCOL_VERSION,
        rq: request.rq(),
        ok,
        ..ReplyBody::default()
    }
}

fn level_field(request: &Request) -> Option<u32> {
    let l = request.level();
    (l >= 2).then_some(u32::from(l))
}

fn refusal(request: &Request, root: Option<&Root>, err: &str) -> ReplyBody {
    ReplyBody {
        err: Some(err.to_owned()),
        lvl: level_field(request),
        w: root.map(Root::fingerprint),
        ..base(request, false)
    }
}

/// Answers the key items, or names the error that refuses the whole reply.
fn answer_keys(
    root: &Root,
    items: &[RequestItem],
    retired: &[RetiredWords],
) -> std::result::Result<Vec<ReplyKey>, RefuseReason> {
    let fp = root.fingerprint();
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let purpose = Purpose::parse(&item.purpose).ok_or(RefuseReason::BadLabel)?;
        if !is_valid_object_id(&item.id) {
            return Err(RefuseReason::BadLabel);
        }
        let mut key = ReplyKey {
            p: item.purpose.clone(),
            i: item.id.clone(),
            ..ReplyKey::default()
        };
        match item.words.as_deref() {
            Some(w) if w != fp => {
                if let Some(r) = retired.iter().find(|r| r.fingerprint == w) {
                    key.err = Some(RefuseReason::RetiredWords.as_str().to_owned());
                    key.retired = Some(r.retired.clone());
                } else {
                    key.err = Some(RefuseReason::WrongKey.as_str().to_owned());
                }
                out.push(key);
                continue;
            }
            _ => {}
        }
        let k = ObjectKey::derive(root, purpose, &item.id).map_err(|_| RefuseReason::BadLabel)?;
        if item.check.as_deref().is_some_and(|c| c != k.check()) {
            key.err = Some(RefuseReason::WrongKey.as_str().to_owned());
        } else {
            key.k = Some(k.b64u());
        }
        out.push(key);
    }
    Ok(out)
}

fn body_len(body: &ReplyBody) -> Result<usize> {
    Ok(Zeroizing::new(serde_json::to_vec(body).map_err(|_| CoreError::Internal)?).len())
}

/// Puts as many keys in as fit in one reply; sets `more` when some did not.
fn fit_keys(body: &mut ReplyBody, keys: Vec<ReplyKey>) -> Result<()> {
    let total = keys.len();
    for key in keys {
        body.keys.push(key);
        if body_len(body)? > MAX_BODY - r#"","more":true"#.len() {
            body.keys.pop();
            break;
        }
    }
    if body.keys.len() < total {
        if body.keys.is_empty() {
            return Err(CoreError::TooLarge);
        }
        body.more = Some(true);
    }
    Ok(())
}

/// Signs and seals a reply body to the request's one-time key.
fn seal_body(
    keys: &PhoneKeys,
    request: &Request,
    body: &ReplyBody,
    rng: &mut impl CryptoRng,
) -> Result<String> {
    request.claim_answer()?;
    let sealed = seal_claimed(keys, request, body, rng);
    if sealed.is_err() {
        request.release_answer();
    }
    sealed
}

fn seal_claimed(
    keys: &PhoneKeys,
    request: &Request,
    body: &ReplyBody,
    rng: &mut impl CryptoRng,
) -> Result<String> {
    let bytes = Zeroizing::new(serde_json::to_vec(body).map_err(|_| CoreError::Internal)?);
    if bytes.len() > MAX_BODY {
        return Err(CoreError::TooLarge);
    }
    let ot = request.one_time_public()?;
    let sig = keys.sign(&request::reply_message(&request.id, &request.machine, &bytes));
    let pt = Zeroizing::new(crypto::cat(&[&sig, &bytes]));
    let sealed = crypto::b64u(
        &crypto::hpke_seal(
            &ot,
            REPLY_INFO,
            &request::aad(&request.id, &request.machine),
            &pt,
            rng,
        )?
        .bytes,
    );
    if sealed.len() > MAX_SEALED {
        return Err(CoreError::TooLarge);
    }
    Ok(sealed)
}

fn in_plan(plan_keys: &[KeyRef], items: &[RequestItem]) -> bool {
    items
        .iter()
        .all(|it| plan_keys.iter().any(|k| k.purpose == it.purpose && k.id == it.id))
}

/// Answers a request. `root` is needed only when the request asks for keys; without it such an
/// approval is answered `phone_locked`. A level 3 approval without a right number pick is
/// answered `no_match`. A request can be answered once (`CoreError::Replay` after).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_reply(
    root: Option<Arc<Root>>,
    keys: &PhoneKeys,
    request: &Request,
    decision: Decision,
) -> Result<String> {
    seal_reply_with_retired(root, keys, request, decision, Vec::new())
}

/// [`seal_reply`], answering items sealed with retired words `retired_words` with their date.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_reply_with_retired(
    root: Option<Arc<Root>>,
    keys: &PhoneKeys,
    request: &Request,
    decision: Decision,
    retired: Vec<RetiredWords>,
) -> Result<String> {
    let body = reply_body(root.as_deref(), keys, request, decision, &retired)?;
    seal_body(keys, request, &body, &mut crypto::os_rng())
}

/// Builds the reply body for a decision (exposed for tests and the vectors).
pub(crate) fn reply_body(
    root: Option<&Root>,
    keys: &PhoneKeys,
    request: &Request,
    decision: Decision,
    retired: &[RetiredWords],
) -> Result<ReplyBody> {
    let kind = request.kind();
    let place = match decision {
        Decision::Deny => return Ok(refusal(request, root, "declined")),
        Decision::Refuse { err } => return Ok(refusal(request, root, err.as_str())),
        Decision::Once { place } | Decision::Session { place } | Decision::Remember { place } => {
            if !matches!(
                kind,
                RequestKind::Open | RequestKind::Keys | RequestKind::Agent | RequestKind::Own
            ) {
                return Err(CoreError::WrongDecision);
            }
            place
        }
        Decision::Plan { place, .. } => {
            if kind != RequestKind::Unseal {
                return Err(CoreError::WrongDecision);
            }
            place
        }
    };
    if request.level() >= 3 && !request.match_passed() {
        return Ok(refusal(request, root, RefuseReason::NoMatch.as_str()));
    }
    let items = &request.body.keys;
    if !items.is_empty() && root.is_none() {
        return Ok(refusal(request, None, RefuseReason::PhoneLocked.as_str()));
    }
    let mut body = grant_body(request, root, decision, place);
    if let Decision::Plan { not_before, .. } = decision {
        let plan = request.plan().filter(|p| p.complete).ok_or(CoreError::BadPlan)?;
        if !in_plan(&plan.keys(), items) {
            return Ok(refusal(request, root, RefuseReason::OutsidePlan.as_str()));
        }
        let ph = crypto::b64u_decode_fixed::<32>(&plan.hash).ok_or(CoreError::BadPlan)?;
        let sig = keys.sign(&plan::plan_message(
            &request.id,
            &request.machine,
            &ph,
            not_before,
        ));
        body.plan = Some(PlanSignature {
            h: plan.hash,
            nb: not_before,
            sig: crypto::b64u(&sig),
        });
    }
    if let Some(root) = root.filter(|_| !items.is_empty()) {
        match answer_keys(root, items, retired) {
            // A plan may hand out its keys over several requests (`more`); other grants
            // must fit in one reply.
            Ok(k) if matches!(decision, Decision::Plan { .. }) => fit_keys(&mut body, k)?,
            Ok(k) => body.keys = k,
            Err(e) => return Ok(refusal(request, Some(root), e.as_str())),
        }
    }
    Ok(body)
}

fn grant_body(request: &Request, root: Option<&Root>, decision: Decision, place: Place) -> ReplyBody {
    let mut body = ReplyBody {
        lvl: level_field(request),
        w: root.map(Root::fingerprint),
        ..base(request, true)
    };
    match decision {
        Decision::Plan { .. } => {
            body.grant = Some("plan".into());
            body.place = Some(place.as_str().into());
        }
        _ => {
            body.grant = Some(
                if matches!(decision, Decision::Once { .. }) {
                    "once"
                } else {
                    "session"
                }
                .into(),
            );
            if matches!(decision, Decision::Remember { .. }) {
                body.remember = Some(true);
            }
            body.place = Some(place.as_str().into());
            let a = place.allowance();
            (body.cap, body.base, body.rate) = (Some(a.cap), Some(a.base), Some(a.rate));
        }
    }
    body
}

/// Acknowledges a plan part other than the last: `{"ok": true, "part": i}`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_plan_part_reply(keys: &PhoneKeys, request: &Request) -> Result<String> {
    let plan = request.plan().ok_or(CoreError::BadPlan)?;
    if request.kind() != RequestKind::Unseal {
        return Err(CoreError::WrongDecision);
    }
    let part = match (plan.part, plan.parts) {
        (Some(i), Some(n)) if i < n => i,
        _ => return Err(CoreError::BadPlan),
    };
    let body = ReplyBody {
        part: Some(part),
        ..base(request, true)
    };
    seal_body(keys, request, &body, &mut crypto::os_rng())
}

/// Answers a later `unseal` request of an approved plan without showing anything: same
/// machine and plan hash, keys the plan names only (`outside_plan`), inside the 30 minutes
/// after `not_before` (`plan_expired`).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_plan_keys_reply(
    root: &Root,
    keys: &PhoneKeys,
    request: &Request,
    approval: PlanApproval,
) -> Result<String> {
    let body = plan_keys_body(root, request, &approval, time::now_unix_ms())?;
    seal_body(keys, request, &body, &mut crypto::os_rng())
}

pub(crate) fn plan_keys_body(
    root: &Root,
    request: &Request,
    approval: &PlanApproval,
    now_ms: u64,
) -> Result<ReplyBody> {
    if request.kind() != RequestKind::Unseal {
        return Err(CoreError::WrongDecision);
    }
    let plan = request.plan().ok_or(CoreError::BadPlan)?;
    if plan.hash != approval.hash || request.machine() != approval.machine {
        return Err(CoreError::BadPlan);
    }
    if now_ms < approval.not_before || now_ms > approval.not_before.saturating_add(PLAN_WINDOW_MS) {
        return Ok(refusal(request, Some(root), RefuseReason::PlanExpired.as_str()));
    }
    if !in_plan(&approval.keys, &request.body.keys) {
        return Ok(refusal(request, Some(root), RefuseReason::OutsidePlan.as_str()));
    }
    let mut body = ReplyBody {
        lvl: level_field(request),
        w: Some(root.fingerprint()),
        grant: Some("plan".into()),
        ..base(request, true)
    };
    match answer_keys(root, &request.body.keys, &[]) {
        Ok(k) => fit_keys(&mut body, k)?,
        Err(e) => return Ok(refusal(request, Some(root), e.as_str())),
    }
    Ok(body)
}

/// Answers `rewrap`: the new key and the old key of every item. A level 3 request without a
/// right number pick is answered `no_match`, as in [`seal_reply`].
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_rewrap_reply(
    old_root: &Root,
    new_root: &Root,
    keys: &PhoneKeys,
    request: &Request,
) -> Result<String> {
    if request.kind() != RequestKind::Rewrap {
        return Err(CoreError::WrongDecision);
    }
    let body = old_new_body(old_root, new_root, request, false)?;
    seal_body(keys, request, &body, &mut crypto::os_rng())
}

/// Answers `old_words`: derives only the listed objects' keys under the retired words
/// (`old`) and the current ones (`k`). Level 3 needs the number pick, as for `rewrap`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_old_words_reply(
    old_root: &Root,
    root: &Root,
    keys: &PhoneKeys,
    request: &Request,
) -> Result<String> {
    if request.kind() != RequestKind::OldWords {
        return Err(CoreError::WrongDecision);
    }
    let body = old_new_body(old_root, root, request, true)?;
    seal_body(keys, request, &body, &mut crypto::os_rng())
}

fn old_new_body(old_root: &Root, new_root: &Root, request: &Request, only_old: bool) -> Result<ReplyBody> {
    if request.level() >= 3 && !request.match_passed() {
        return Ok(refusal(request, Some(new_root), RefuseReason::NoMatch.as_str()));
    }
    let (fp_old, fp_new) = (old_root.fingerprint(), new_root.fingerprint());
    if only_old && request.body.old.as_deref().is_some_and(|o| o != fp_old) {
        return Ok(refusal(request, Some(new_root), RefuseReason::WrongKey.as_str()));
    }
    let mut out = Vec::new();
    for item in &request.body.keys {
        let Some(purpose) = Purpose::parse(&item.purpose).filter(|_| is_valid_object_id(&item.id)) else {
            return Ok(refusal(request, Some(new_root), RefuseReason::BadLabel.as_str()));
        };
        let old = ObjectKey::derive(old_root, purpose, &item.id)?;
        let new = ObjectKey::derive(new_root, purpose, &item.id)?;
        let check_against = match item.words.as_deref() {
            Some(w) if w == fp_old => Some(&old),
            Some(w) if w == fp_new && !only_old => Some(&new),
            None if !only_old => None,
            _ => {
                out.push(ReplyKey {
                    p: item.purpose.clone(),
                    i: item.id.clone(),
                    err: Some(RefuseReason::WrongKey.as_str().into()),
                    ..ReplyKey::default()
                });
                continue;
            }
        };
        let mut key = ReplyKey {
            p: item.purpose.clone(),
            i: item.id.clone(),
            ..ReplyKey::default()
        };
        if check_against.is_some_and(|k| item.check.as_deref().is_some_and(|c| c != k.check())) {
            key.err = Some(RefuseReason::WrongKey.as_str().into());
        } else {
            key.k = Some(new.b64u());
            key.old = Some(old.b64u());
        }
        out.push(key);
    }
    Ok(ReplyBody {
        lvl: level_field(request),
        w: Some(fp_new),
        grant: Some("once".into()),
        keys: out,
        ..base(request, true)
    })
}

/// Answers a `report`: the status `seq` stored and the machine messages waiting for it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_report_reply(
    keys: &PhoneKeys,
    request: &Request,
    ack: Option<u64>,
    messages: Vec<MachineMessage>,
) -> Result<String> {
    if request.kind() != RequestKind::Report {
        return Err(CoreError::WrongDecision);
    }
    let msgs = messages
        .into_iter()
        .map(|m| MachineMessage {
            version: PROTOCOL_VERSION,
            ..m
        })
        .collect();
    let body = ReplyBody {
        ack,
        msgs,
        ..base(request, true)
    };
    seal_body(keys, request, &body, &mut crypto::os_rng())
}

#[cfg(test)]
pub(crate) fn seal_body_with_rng(
    keys: &PhoneKeys,
    request: &Request,
    body: &ReplyBody,
    rng: &mut impl CryptoRng,
) -> Result<String> {
    seal_body(keys, request, body, rng)
}
