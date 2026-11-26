//! JSON bodies of requests, replies, machine status and machine messages.
//!
//! Field order in the structs is the order on the wire (signatures cover exact bytes, and the
//! vectors fix them). Readable Rust names map to the short wire names with `serde(rename)`;
//! the same types are UniFFI records for the apps. Readers ignore unknown fields.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

fn is_false(b: &bool) -> bool {
    !*b
}

// ---------- request ----------

/// A request body (`why` says the kind). Built by machines, read by the phone.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestBody {
    /// Protocol major version.
    pub v: u32,
    /// When the request was made, Unix ms.
    pub t: u64,
    /// The request kind.
    pub why: String,
    /// The confirmation level the machine asks for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lvl: Option<u32>,
    /// `b64u(ot_pk)`, set by [`crate::request::seal_request`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ot: Option<String>,
    /// A person at the terminal is shown the number match.
    #[serde(default, rename = "match", skip_serializing_if = "is_false")]
    pub has_match: bool,
    /// Who asks and why.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ctx: Option<RequestContext>,
    /// `unseal` only: the plan.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanBody>,
    /// Keys asked for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<RequestItem>,
    /// Agent uses to decide.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub uses: Vec<AgentUse>,
    /// Minutes worked today on this machine.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub work: Option<u64>,
    /// `old_words` only: the retired words fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<String>,
    /// `report` only: status `seq`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
    /// `report` only: session state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<SessionState>,
    /// `report` only: usage log.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<LogEntry>,
    /// `report` only: inventory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inv: Vec<RequestItem>,
    /// `report` only: re-encryption progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrate: Option<Migration>,
    /// `report` only: what a finished `unseal` handed back.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handback: Option<Handback>,
}

/// `ctx`: who asks and why.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestContext {
    /// Agent name; `None` for a person.
    #[serde(default)]
    pub agent: Option<String>,
    /// The repository, or `None`.
    #[serde(default)]
    pub repo: Option<Repository>,
    /// The command, key-like parts masked.
    #[serde(default, rename = "cmd")]
    pub command: String,
    /// Working directory.
    #[serde(default)]
    pub cwd: String,
    /// `user@full-hostname`.
    #[serde(default)]
    pub user: String,
    /// What triggered the request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<Subject>,
    /// Secret names involved.
    #[serde(default, rename = "n", skip_serializing_if = "Vec::is_empty")]
    pub names: Vec<String>,
}

/// `ctx.repo`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Repository {
    /// Stable id for answers (`host/owner/name` or a path).
    #[serde(default)]
    pub id: String,
    /// For display.
    #[serde(default)]
    pub name: String,
}

/// `ctx.subject`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Subject {
    /// `secret`, `volume`, `backup`, `ssh` or `machine`.
    #[serde(default, rename = "k")]
    pub kind: String,
    /// Its name.
    #[serde(default, rename = "n")]
    pub name: String,
}

/// An item of `keys` (and of `inv`).
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RequestItem {
    /// `secrets`, `secret`, `volume` or `backup`.
    #[serde(default, rename = "p")]
    pub purpose: String,
    /// Object id.
    #[serde(default, rename = "i")]
    pub id: String,
    /// Words fingerprint from the `.id` file; absent for a new object.
    #[serde(default, rename = "w", skip_serializing_if = "Option::is_none")]
    pub words: Option<String>,
    /// Key check from the `.id` file; absent for a new object.
    #[serde(default, rename = "c", skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// Inventory facts.
    #[serde(default, rename = "o", skip_serializing_if = "Option::is_none")]
    pub object: Option<ObjectFacts>,
}

/// `o`: inventory facts of an object.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObjectFacts {
    /// `store`, `secret`, `volume` or `backup`.
    #[serde(default, rename = "k")]
    pub kind: String,
    /// Path or URL.
    #[serde(default, rename = "p")]
    pub path: String,
    /// Size in bytes.
    #[serde(default, rename = "s")]
    pub size: u64,
}

/// An item of `uses`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AgentUse {
    /// Agent name.
    #[serde(default, rename = "a")]
    pub agent: String,
    /// Repository id.
    #[serde(default, rename = "r")]
    pub repository: String,
    /// Secret names.
    #[serde(default, rename = "n")]
    pub names: Vec<String>,
}

/// `plan` in an `unseal` request.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PlanBody {
    /// `unseal --all`.
    #[serde(default, skip_serializing_if = "is_false")]
    pub all: bool,
    /// `b64u(ph)` over the whole plan.
    #[serde(default)]
    pub h: String,
    /// The items of this part.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub items: Vec<PlanItem>,
    /// Number of parts.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub n: Option<u32>,
    /// This part, from 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub i: Option<u32>,
}

/// One step of an `unseal` plan.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanItem {
    /// `secrets`, `secret`, `volume`, `backup`, `ssh`, `git`, `ai`, `services`, `local`, `pairing`.
    #[serde(default, rename = "k")]
    pub kind: String,
    /// Name as the terminal shows it.
    #[serde(default, rename = "n")]
    pub name: String,
    /// Purpose of the key this step needs.
    #[serde(default, rename = "p", skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    /// Id of the key this step needs.
    #[serde(default, rename = "i", skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
}

/// `handback` in a `report`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Handback {
    /// The plan hash it ran.
    #[serde(default, rename = "h")]
    pub hash: String,
    /// What each item became.
    #[serde(default)]
    pub items: Vec<HandbackItem>,
    /// The run folder.
    #[serde(default)]
    pub run: String,
}

/// One item of a hand-back report.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HandbackItem {
    /// Plan item kind.
    #[serde(default, rename = "k")]
    pub kind: String,
    /// Plan item name.
    #[serde(default, rename = "n")]
    pub name: String,
    /// Where its password or value went.
    #[serde(default)]
    pub to: String,
    /// `done`, `failed` or `skipped`.
    #[serde(default, rename = "s")]
    pub state: String,
}

// ---------- status ----------

/// A machine status body (and the status fields of a `report`).
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MachineStatus {
    /// Protocol major version.
    #[serde(default = "one", rename = "v")]
    pub version: u32,
    /// When it was made, Unix ms.
    #[serde(default, rename = "t")]
    pub time: u64,
    /// Increases by one with every status.
    #[serde(default)]
    pub seq: u64,
    /// Session state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<SessionState>,
    /// Uses since the last acknowledged status.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub log: Vec<LogEntry>,
    /// Objects on the machine, when changed.
    #[serde(default, rename = "inv", skip_serializing_if = "Vec::is_empty")]
    pub inventory: Vec<RequestItem>,
    /// Re-encryption progress.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub migrate: Option<Migration>,
}

fn one() -> u32 {
    1
}

/// `state` of a status.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SessionState {
    /// `locked`, `open` or `waiting`.
    #[serde(default, rename = "s")]
    pub session: String,
    /// Idle seconds left.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub left: Option<u64>,
    /// Seconds since the last work moment, at the status's time. Absent from older machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle: Option<u64>,
    /// The idle allowance now, seconds. Absent from older machines.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<u64>,
    /// Hard stop time, Unix ms.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stop: Option<u64>,
    /// Place from the last open.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// Volumes still mounted after a lock.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub busy: Vec<BusyVolume>,
}

/// A volume still mounted after a lock, with the process holding it.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BusyVolume {
    /// Volume name.
    #[serde(default, rename = "n")]
    pub name: String,
    /// Process name.
    #[serde(default, rename = "p")]
    pub process: String,
    /// Process id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pid: Option<u64>,
}

/// One use in the usage log.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct LogEntry {
    /// When, Unix ms.
    #[serde(default, rename = "t")]
    pub time: u64,
    /// Agent, or `None` for a person.
    #[serde(default, rename = "a")]
    pub agent: Option<String>,
    /// Repository id, or `None`.
    #[serde(default, rename = "r")]
    pub repository: Option<String>,
    /// The command.
    #[serde(default, rename = "c")]
    pub command: String,
    /// Secret names used.
    #[serde(default, rename = "n")]
    pub names: Vec<String>,
    /// An `--own-approval` secret.
    #[serde(default)]
    pub own: bool,
}

/// `migrate` of a status.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Migration {
    /// One entry per object.
    #[serde(default)]
    pub items: Vec<MigrationItem>,
}

/// Re-encryption progress of one object.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MigrationItem {
    /// Purpose.
    #[serde(default, rename = "p")]
    pub purpose: String,
    /// Object id.
    #[serde(default, rename = "i")]
    pub id: String,
    /// Path or URL.
    #[serde(default)]
    pub path: String,
    /// Its state.
    #[serde(default, rename = "s")]
    pub state: String,
    /// Rewrap estimate, seconds.
    #[serde(default, rename = "rw", skip_serializing_if = "Option::is_none")]
    pub rewrap_secs: Option<u64>,
    /// Re-encryption estimate `[min, max]`, seconds.
    #[serde(default, rename = "re", skip_serializing_if = "Option::is_none")]
    pub reencrypt_secs: Option<Vec<u64>>,
    /// Free bytes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub free: Option<u64>,
    /// Progress from 0 to 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub done: Option<f64>,
    /// Why it is paused, or `None`.
    #[serde(default)]
    pub paused: Option<String>,
}

// ---------- machine message ----------

/// A message from the phone to a machine.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MachineMessage {
    /// Protocol major version.
    #[serde(default = "one", rename = "v")]
    pub version: u32,
    /// When it was made, Unix ms.
    #[serde(rename = "t")]
    pub time: u64,
    /// Increases by one with every message to this machine.
    pub seq: u64,
    /// What it says.
    #[serde(flatten)]
    pub kind: MessageKind,
}

/// The kinds of machine message (`type`).
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum MessageKind {
    /// Lock the session.
    Lock {
        /// `phone`, `place` or `words`.
        reason: String,
    },
    /// This machine's remembered answers.
    Answers {
        /// At most 40 per message.
        answers: Vec<Answer>,
        /// Another `answers` message follows.
        #[serde(default, skip_serializing_if = "is_false")]
        more: bool,
    },
    /// The status `seq` the phone stored.
    Ack {
        /// The `seq`.
        ack: u64,
    },
    /// A level 3 action, for the machine to show.
    Notice {
        /// What happened.
        notice: Notice,
    },
}

/// A remembered answer.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Answer {
    /// Agent.
    #[serde(default, rename = "a")]
    pub agent: String,
    /// Repository id.
    #[serde(default, rename = "r")]
    pub repository: String,
    /// Secret names.
    #[serde(default, rename = "n")]
    pub names: Vec<String>,
    /// Last used, Unix ms.
    #[serde(default)]
    pub last: u64,
}

/// `notice` of a machine message.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Notice {
    /// `unseal_all`, `leave`, `words` or `delete`.
    #[serde(default)]
    pub what: String,
    /// `pending`, `cancelled` or `done`.
    #[serde(default)]
    pub state: String,
    /// Name of the machine it concerns.
    #[serde(default)]
    pub machine: Option<String>,
    /// Delayed approval id.
    #[serde(default)]
    pub delay: Option<String>,
    /// `releaseAt`, Unix ms.
    #[serde(default)]
    pub at: Option<u64>,
    /// Counts of a finished hand-back.
    #[serde(default)]
    pub report: Option<NoticeReport>,
}

/// `notice.report`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NoticeReport {
    /// Items done.
    #[serde(default)]
    pub done: u64,
    /// Items failed.
    #[serde(default)]
    pub failed: u64,
    /// Items skipped.
    #[serde(default)]
    pub skipped: u64,
    /// Stores the values went to.
    #[serde(default)]
    pub to: Vec<String>,
}

// ---------- reply ----------

/// A reply body. Holds keys, so it has no `Debug` or `Clone`.
#[derive(Default, Serialize, Deserialize)]
pub struct ReplyBody {
    /// Protocol major version.
    pub v: u32,
    /// `b64u(SHA256(request body))`.
    pub rq: String,
    /// `false` when denied or failed.
    pub ok: bool,
    /// Why not.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    /// The confirmation level applied, when above 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lvl: Option<u32>,
    /// The phone's current words fingerprint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub w: Option<String>,
    /// `once`, `session` or `plan`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grant: Option<String>,
    /// The phone stored the answer for the agent uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remember: Option<bool>,
    /// `trusted`, `other` or `none`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub place: Option<String>,
    /// The plan signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<PlanSignature>,
    /// The plan part acknowledged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub part: Option<u32>,
    /// Keys of the plan remain to be asked for.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub more: Option<bool>,
    /// Allowance cap, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cap: Option<u32>,
    /// Allowance base, seconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<u32>,
    /// Seconds added per minute worked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate: Option<u32>,
    /// Keys.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub keys: Vec<ReplyKey>,
    /// `report`: the `seq` stored.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<u64>,
    /// `report`: machine message bodies.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub msgs: Vec<MachineMessage>,
}

/// `plan` in a reply.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanSignature {
    /// `b64u(ph)`.
    pub h: String,
    /// Not-before time, Unix ms.
    pub nb: u64,
    /// `b64u(psig)`.
    pub sig: String,
}

/// A key in a reply. Holds a key, so it has no `Debug` or `Clone`.
#[derive(Default, Serialize, Deserialize)]
pub struct ReplyKey {
    /// Purpose.
    pub p: String,
    /// Object id.
    pub i: String,
    /// `b64u(key)`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k: Option<Zeroizing<String>>,
    /// `b64u(previous key)`, `rewrap` and `old_words` only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub old: Option<Zeroizing<String>>,
    /// `retired_words` or `wrong_key` instead of `k`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,
    /// With `retired_words`: when those words were retired, `YYYY-MM-DD`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retired: Option<String>,
}
