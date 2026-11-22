//! `unseal` plans: plan text and hash, the plan signature, plans sent in parts, and the
//! approval that later key requests of the same plan are checked against.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::keys::{is_valid_object_id, Purpose};
use crate::request::{Request, RequestKind};
use crate::wire::PlanItem;

/// Longest plan field.
pub const MAX_FIELD: usize = 200;
/// Most parts a plan may be sent in.
pub const MAX_PARTS: u32 = 64;
/// How long after `not_before` later keys of a plan are handed out, in ms.
pub const PLAN_WINDOW_MS: u64 = 30 * 60 * 1000;

const KINDS: &[&str] = &[
    "secrets", "secret", "volume", "backup", "ssh", "git", "ai", "services", "local", "pairing",
];

/// The plan as the phone shows it.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPlan {
    /// `unseal --all`.
    pub all: bool,
    /// `h`: `b64u(SHA256(plan text))`.
    pub hash: String,
    /// The items: the whole plan when `complete`, else only this part's.
    pub items: Vec<PlanItem>,
    /// This part, from 1, when sent in parts.
    pub part: Option<u32>,
    /// Number of parts, when sent in parts.
    pub parts: Option<u32>,
    /// `items` is the whole plan and its hash checked out.
    pub complete: bool,
}

impl RequestPlan {
    /// The confirmation level the plan itself needs: 3 for `--all` or a `pairing` step, else 2.
    pub fn level(&self) -> u8 {
        if self.all || self.items.iter().any(|i| i.kind == "pairing") {
            3
        } else {
            2
        }
    }

    /// The distinct keys the plan names, in plan order.
    pub fn keys(&self) -> Vec<KeyRef> {
        let mut out: Vec<KeyRef> = Vec::new();
        for item in &self.items {
            if let (Some(p), Some(i)) = (&item.purpose, &item.id) {
                let k = KeyRef {
                    purpose: p.clone(),
                    id: i.clone(),
                };
                if !out.contains(&k) {
                    out.push(k);
                }
            }
        }
        out
    }
}

/// A key named by purpose and object id.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct KeyRef {
    /// Purpose (`p`).
    pub purpose: String,
    /// Object id (`i`).
    pub id: String,
}

/// An approved plan, kept by the app for the 30 minutes after `not_before`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanApproval {
    /// The machine id it was approved for.
    pub machine: String,
    /// The plan hash `h`.
    pub hash: String,
    /// Not-before time, Unix ms.
    pub not_before: u64,
    /// Every key the plan names.
    pub keys: Vec<KeyRef>,
}

/// The approval to keep after answering `request` with a `Plan` decision at `not_before`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn plan_approval(request: &Request, not_before: u64) -> Result<PlanApproval> {
    let plan = request.plan().filter(|p| p.complete).ok_or(CoreError::BadPlan)?;
    Ok(PlanApproval {
        machine: request.machine(),
        hash: plan.hash.clone(),
        not_before,
        keys: plan.keys(),
    })
}

/// Checks the field rules of one plan item: known kind, at most 200 characters, no control
/// characters, and a purpose and id the phone can derive (or neither).
pub(crate) fn check_item(item: &PlanItem) -> Result<()> {
    let field_ok = |s: &str| s.chars().count() <= MAX_FIELD && !s.chars().any(char::is_control);
    if !KINDS.contains(&item.kind.as_str()) || !field_ok(&item.name) {
        return Err(CoreError::BadPlan);
    }
    match (&item.purpose, &item.id) {
        (None, None) => Ok(()),
        (Some(p), Some(i)) if Purpose::parse(p).is_some() && is_valid_object_id(i) => Ok(()),
        _ => Err(CoreError::BadPlan),
    }
}

/// `"sealctl-plan-v1\n" ‖ b64u(M) ‖ "\n" ‖ k \t n \t p \t i \n …`.
pub fn plan_text(machine_id: &str, items: &[PlanItem]) -> String {
    let mut text = format!("sealctl-plan-v1\n{machine_id}\n");
    for item in items {
        text.push_str(&format!(
            "{}\t{}\t{}\t{}\n",
            item.kind,
            item.name,
            item.purpose.as_deref().unwrap_or(""),
            item.id.as_deref().unwrap_or("")
        ));
    }
    text
}

/// `ph = SHA256(plan text)`.
pub fn plan_hash(machine_id: &str, items: &[PlanItem]) -> [u8; 32] {
    crypto::sha256(plan_text(machine_id, items).as_bytes())
}

/// The signed plan message `"sealctl/v1/plan" ‖ 0x00 ‖ id ‖ 0x00 ‖ M ‖ ph ‖ nb`.
pub fn plan_message(id: &str, machine: &[u8; 32], ph: &[u8; 32], not_before: u64) -> Vec<u8> {
    crypto::cat(&[
        b"sealctl/v1/plan",
        &[0],
        id.as_bytes(),
        &[0],
        machine,
        ph,
        &not_before.to_be_bytes(),
    ])
}

/// The machine's check of a plan signature with its paired phone key `P`.
pub fn verify_plan_signature(
    phone: &[u8; 32],
    id: &str,
    machine: &[u8; 32],
    ph: &[u8; 32],
    not_before: u64,
    sig_b64u: &str,
) -> Result<()> {
    let sig = crypto::b64u_decode_fixed::<64>(sig_b64u).ok_or(CoreError::BadSignature)?;
    crypto::ed25519_verify(phone, &plan_message(id, machine, ph, not_before), &sig)
}

struct Partial {
    machine: String,
    hash: String,
    all: bool,
    parts: u32,
    got: BTreeMap<u32, Vec<PlanItem>>,
}

/// Collects a plan sent in several `unseal` requests and checks its hash.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PlanAssembler {
    partial: Mutex<Option<Partial>>,
}

impl Default for PlanAssembler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PlanAssembler {
    /// An empty assembler.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn new() -> Self {
        Self {
            partial: Mutex::new(None),
        }
    }

    /// Adds one part. Returns the whole plan once every part is in and the hash checks out;
    /// the plan is then also attached to `request`, which the final answer is sealed for.
    /// A part for another machine or plan hash starts over. A later key request of an
    /// approved plan (`plan: {h}` only, no part) is not a part: it returns `None` and leaves
    /// the parts collected so far as they are.
    pub fn add(&self, request: Arc<Request>) -> Result<Option<RequestPlan>> {
        if request.kind() != RequestKind::Unseal {
            return Err(CoreError::BadPlan);
        }
        let plan = request.plan().ok_or(CoreError::BadPlan)?;
        if plan.complete {
            return Ok(Some(plan));
        }
        if plan.part.is_none() && plan.parts.is_none() && plan.items.is_empty() {
            return Ok(None);
        }
        let (part, parts) = (
            plan.part.ok_or(CoreError::BadPlan)?,
            plan.parts.ok_or(CoreError::BadPlan)?,
        );
        let mut guard = self.partial.lock().map_err(|_| CoreError::Internal)?;
        let machine = request.machine();
        let fresh = guard
            .as_ref()
            .is_none_or(|p| p.machine != machine || p.hash != plan.hash || p.parts != parts);
        if fresh {
            *guard = Some(Partial {
                machine: machine.clone(),
                hash: plan.hash.clone(),
                all: false,
                parts,
                got: BTreeMap::new(),
            });
        }
        let partial = guard.as_mut().expect("set above");
        partial.all |= plan.all;
        partial.got.insert(part, plan.items);
        if partial.got.len() as u32 != parts {
            return Ok(None);
        }
        let done = guard.take().expect("set above");
        let items: Vec<PlanItem> = done.got.into_values().flatten().collect();
        let whole = RequestPlan {
            all: done.all,
            hash: done.hash,
            items,
            part: Some(part),
            parts: Some(parts),
            complete: true,
        };
        if crypto::b64u(&plan_hash(&machine, &whole.items)) != whole.hash {
            return Err(CoreError::BadPlan);
        }
        request.attach_plan(whole.clone())?;
        Ok(Some(whole))
    }
}
