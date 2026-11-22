//! `sealctl unseal` (SPEC 18): hand objects back in plain, standard form, into one new folder
//! `~/sealctl-unsealed-<date>` (the `folder` store). Keys come from the phone with `unseal`
//! requests bound to the confirmed plan (level 2 for one object, level 3 for `--all`: number
//! match, plan signature, delay away from a trusted place), or from the 24 words (`--words`).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use sealctl_core::plan::{plan_hash, verify_plan_signature};
use sealctl_core::request::MAX_BODY;
use sealctl_core::wire::{Handback, HandbackItem, PlanBody, PlanItem, ReplyBody, RequestItem};
use sealctl_core::{ObjectKey, Purpose, Root};
use serde::{Deserialize, Serialize};
use serde_json::json;
use zeroize::Zeroizing;

use super::handback::{self as hb, Credential};
use super::journal::Run;
use super::store::{self, Item, Location, StoreKind, Stores};
use crate::approve::{self, Asked};
use crate::backup::{Backup, Repo};
use crate::daemon::session;
use crate::exit::{self, fail};
use crate::machine::{self, Paired};
use crate::relay::{self, Relay};
use crate::store::Store;
use crate::volume::{self, Kind, Volume};
use crate::{paths, term, util};

/// What to hand back.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Target {
    /// `--all`.
    All,
    /// `secrets`.
    Secrets,
    /// `secret <name>`.
    Secret(String),
    /// `volume <name>`.
    Volume(String),
    /// `backup <name>`.
    Backup(String),
    /// `ssh <name>`.
    Ssh(String),
    /// `git`.
    Git,
    /// `ai [TOOL...]`.
    Ai(Vec<String>),
}

/// Options of `sealctl unseal`.
pub struct Opts {
    /// The target (`None` with `--resume`).
    pub target: Option<Target>,
    /// `--resume`.
    pub resume: bool,
    /// `--words`.
    pub words: bool,
    /// `--dry-run`.
    pub dry_run: bool,
    /// `--json`.
    pub json: bool,
    /// `--keep-store`.
    pub keep_store: bool,
    /// `--skip <kind>/<name>`.
    pub skip: Vec<String>,
    /// `--to`: new passwords.
    pub to: Option<StoreKind>,
    /// `--secrets-to`: secrets and storage credentials.
    pub secrets_to: Option<StoreKind>,
    /// `--env-file`.
    pub env_file: Option<PathBuf>,
    /// `--op-vault`.
    pub op_vault: Option<String>,
    /// `--bw-folder`.
    pub bw_folder: Option<String>,
    /// `--type-passwords`.
    pub type_passwords: bool,
    /// `--no-ssh-passphrase`.
    pub no_ssh_passphrase: bool,
    /// `--relay`.
    pub relay: Option<String>,
}

/// One step of the plan.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Step {
    /// `<kind>:<name>`.
    pub id: String,
    /// Plan item kind.
    pub kind: String,
    /// Name as shown.
    pub name: String,
    /// The key it needs.
    pub purpose: Option<String>,
    /// Object id of that key.
    pub key_id: Option<String>,
    /// The plan line.
    pub text: String,
    /// Words fingerprint and check of the key (from the object), for the request.
    #[serde(default)]
    pub words: Option<String>,
    /// Key check.
    #[serde(default)]
    pub check: Option<String>,
}

impl Step {
    fn item(&self) -> PlanItem {
        PlanItem {
            kind: self.kind.clone(),
            name: self.name.clone(),
            purpose: self.purpose.clone(),
            id: self.key_id.clone(),
        }
    }
}

/// `plan.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PlanFile {
    /// What was asked for.
    pub target: Target,
    /// `--all`.
    pub all: bool,
    /// The steps.
    pub steps: Vec<Step>,
    /// `--keep-store`.
    #[serde(default)]
    pub keep_store: bool,
    /// The plan hash `h`.
    #[serde(default)]
    pub h: Option<String>,
    /// Not-before, Unix ms.
    #[serde(default)]
    pub nb: Option<u64>,
    /// The phone's plan signature.
    #[serde(default)]
    pub sig: Option<String>,
    /// Keys came from the words.
    #[serde(default)]
    pub words: bool,
    /// Where passwords and secrets go.
    pub stores: store::Config,
    /// SSH keys end without a passphrase.
    #[serde(default)]
    pub no_ssh_passphrase: bool,
}

fn line(n: usize, kind: &str, name: &str, what: &str) -> String {
    format!("{n:>2}  {kind:<12} {name:<24} {what}")
}

fn store_item(store: &Store) -> Option<(String, Option<String>, Option<String>)> {
    let f = store.id_file().ok()??;
    Some((store.id.clone(), Some(f.words), Some(f.check)))
}

/// Builds the plan for a target.
pub fn build(target: &Target, keep_store: bool, skip: &[String]) -> Result<Vec<Step>> {
    let store = Store::configured().ok();
    let sitem = store.as_ref().and_then(store_item);
    let secrets = store
        .as_ref()
        .map(|s| s.list().unwrap_or_default())
        .unwrap_or_default();
    let mut steps: Vec<Step> = Vec::new();
    let skipped = |k: &str, n: &str| skip.iter().any(|s| s == &format!("{k}/{n}"));
    let all = *target == Target::All;
    let mut push = |kind: &str,
                    name: &str,
                    key: Option<(&str, String, Option<String>, Option<String>)>,
                    what: String| {
        let n = steps.len() + 1;
        let shown = match kind {
            "secrets" => "secrets",
            "secret" => "secret",
            "ssh" => "ssh key",
            "ai" => "AI tools",
            "local" => "local files",
            other => other,
        };
        steps.push(Step {
            id: format!("{kind}:{name}"),
            kind: kind.into(),
            name: name.into(),
            purpose: key.as_ref().map(|k| k.0.to_string()),
            key_id: key.as_ref().map(|k| k.1.clone()),
            text: line(n, shown, name, &what),
            words: key.as_ref().and_then(|k| k.2.clone()),
            check: key.as_ref().and_then(|k| k.3.clone()),
        });
    };
    let store_key = |s: &Option<(String, Option<String>, Option<String>)>| {
        s.clone().map(|(i, w, c)| ("secrets", i, w, c))
    };
    let own_checks = store
        .as_ref()
        .map(|s| s.own_checks().unwrap_or_default())
        .unwrap_or_default();
    let own_key = |name: &str| -> Option<(&'static str, String, Option<String>, Option<String>)> {
        let h = store.as_ref()?.header(name).ok()?;
        (h.mode == sealctl_core::sealed::Mode::OwnApproval).then(|| {
            (
                "secret",
                h.file_id.clone(),
                Some(h.words.clone()),
                own_checks.get(&h.file_id).cloned(),
            )
        })
    };
    let mut want_secrets = matches!(target, Target::All | Target::Secrets);
    if want_secrets && secrets.is_empty() {
        want_secrets = false;
    }
    if want_secrets && !skipped("secrets", "store") {
        push(
            "secrets",
            &format!("{} secrets", secrets.len()),
            store_key(&sitem),
            "→ secrets.env in the folder, plain".into(),
        );
        for s in secrets.iter().filter(|s| s.own) {
            push(
                "secret",
                &s.name,
                own_key(&s.name),
                "→ secrets.env in the folder, plain (own approval)".into(),
            );
        }
    }
    if let Target::Secret(name) = target {
        let s = store
            .as_ref()
            .ok_or_else(|| fail(exit::NOT_FOUND, "No secret store."))?;
        if !s.exists(name) {
            return Err(fail(exit::NOT_FOUND, format!("No secret {name}.")));
        }
        let key = own_key(name).or_else(|| store_key(&sitem));
        push("secret", name, key, "→ secrets.env in the folder, plain".into());
    }
    let backups = Backup::list()?;
    let volumes = Volume::list()?;
    let wanted_backups: Vec<&Backup> = backups
        .iter()
        .filter(|b| all || *target == Target::Backup(b.name.clone()))
        .filter(|b| !skipped("backup", &b.name))
        .collect();
    if let Target::Backup(n) = target {
        if wanted_backups.is_empty() {
            return Err(fail(exit::NOT_FOUND, format!("No backup {n}.")));
        }
    }
    let wanted_volumes: Vec<&Volume> = volumes
        .iter()
        .filter(|v| all || *target == Target::Volume(v.name.clone()))
        .filter(|v| !skipped("volume", &v.name))
        .collect();
    if let Target::Volume(n) = target {
        if wanted_volumes.is_empty() {
            return Err(fail(exit::NOT_FOUND, format!("No volume {n}.")));
        }
    }
    // each backup before the volume that holds its source
    for b in &wanted_backups {
        push(
            "backup",
            &b.name,
            Some((
                "backup",
                b.repo_id.clone(),
                Some(b.words.clone()),
                Some(b.check.clone()),
            )),
            "stays encrypted; it will open with a new password (passwords.txt). sealctl's key is removed."
                .into(),
        );
        if !b.credentials.is_empty() && !all {
            push(
                "backup",
                &format!("{} credentials", b.name),
                store_key(&sitem),
                "storage credentials → backup env file in the folder".into(),
            );
        }
    }
    for v in &wanted_volumes {
        push(
            "volume",
            &v.name,
            Some((
                "volume",
                v.id.clone(),
                Some(v.words.clone()),
                Some(v.check.clone()),
            )),
            format!(
                "{} stays encrypted; it will open with a new passphrase (passwords.txt).",
                v.name
            ),
        );
    }
    let keys = crate::ssh::names();
    for k in keys
        .iter()
        .filter(|k| all || *target == Target::Ssh((*k).clone()))
    {
        if skipped("ssh", k) {
            continue;
        }
        push(
            "ssh",
            k,
            store_key(&sitem),
            format!("→ ~/.ssh/{k} with no passphrase"),
        );
    }
    if let Target::Ssh(n) = target {
        if !keys.contains(n) {
            return Err(fail(exit::NOT_FOUND, format!("No SSH key {n}.")));
        }
    }
    let git_ours = git_signing_ours();
    if (all && git_ours) || *target == Target::Git {
        push(
            "git",
            "signing",
            None,
            "keeps signing with your key through ssh-keygen.".into(),
        );
    }
    let installed: Vec<String> = crate::ai::status(&[])
        .unwrap_or_default()
        .into_iter()
        .filter(|r| r.detected && r.lines.iter().any(|l| l.ends_with(" yes")))
        .map(|r| r.tool.to_string())
        .collect();
    match target {
        Target::Ai(tools) => push(
            "ai",
            &if tools.is_empty() {
                installed.join(", ")
            } else {
                tools.join(", ")
            },
            None,
            "hooks, skill and session text removed.".into(),
        ),
        Target::All if !installed.is_empty() => push(
            "ai",
            &installed.join(", "),
            None,
            "hooks, skill and session text removed.".into(),
        ),
        _ => {}
    }
    if all {
        push(
            "services",
            "daemon, backup schedule",
            None,
            "stopped and removed.".into(),
        );
        if let Ok(p) = machine::load() {
            push("pairing", &p.label(), None, "is unpaired from your phone.".into());
        }
        push(
            "local",
            "settings",
            None,
            if keep_store {
                "~/.config/sealctl and ~/.local/state/sealctl removed; the store stays.".into()
            } else {
                "~/.config/sealctl and ~/.local/state/sealctl removed; the store is kept in the folder."
                    .into()
            },
        );
    }
    Ok(steps)
}

fn git_signing_ours() -> bool {
    std::process::Command::new("git")
        .args(["config", "--global", "--get", "gpg.ssh.program"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("sealctl"))
        .unwrap_or(false)
}

/// The program's own uninstall command, for the last line.
fn uninstall_hint() -> String {
    let exe = std::env::current_exe()
        .map(|e| e.display().to_string())
        .unwrap_or_default();
    if exe.contains("/Cellar/") || exe.contains("homebrew") {
        "brew uninstall sealctl/tap/sealctl".into()
    } else if exe.starts_with("/usr/bin/") {
        "sudo apt remove sealctl (or dnf, pacman)".into()
    } else if exe.contains("/nix/store/") {
        "nix profile remove sealctl".into()
    } else {
        format!("rm {exe}")
    }
}

fn key_name(p: &str, i: &str) -> String {
    format!("{p}:{i}")
}

/// Keys the plan needs, in plan order, as request items.
fn key_items(steps: &[Step]) -> Vec<RequestItem> {
    let mut out: Vec<RequestItem> = Vec::new();
    for s in steps {
        if let (Some(p), Some(i)) = (&s.purpose, &s.key_id) {
            if !out.iter().any(|x| &x.purpose == p && &x.id == i) {
                out.push(RequestItem {
                    purpose: p.clone(),
                    id: i.clone(),
                    words: s.words.clone(),
                    check: s.check.clone(),
                    object: None,
                });
            }
        }
    }
    out
}

/// Keys from the 24 words, checked against each object's words and check.
fn keys_from_words(steps: &[Step]) -> Result<BTreeMap<String, ObjectKey>> {
    let items = key_items(steps);
    let mut out = BTreeMap::new();
    if items.is_empty() {
        return Ok(out);
    }
    let root: Root = crate::recover::read_root()?;
    for it in &items {
        if let Some(w) = &it.words {
            crate::recover::check_fingerprint(&root, w)?;
        }
        let p = Purpose::parse(&it.purpose).context("purpose")?;
        let k = crate::recover::derive_checked(&root, p, &it.id, it.check.as_deref())?;
        out.insert(key_name(&it.purpose, &it.id), k);
    }
    Ok(out)
}

fn body_len(b: &sealctl_core::wire::RequestBody) -> usize {
    // `ot` is added when sealing: 43 characters and its key
    serde_json::to_vec(b).map(|v| v.len()).unwrap_or(usize::MAX) + 56
}

/// The request bodies of a plan: parts that fit, the last with `match` and as many keys as fit.
fn plan_bodies(
    paired: &Paired,
    steps: &[Step],
    all: bool,
    h: &str,
    level: u32,
) -> Result<(Vec<sealctl_core::wire::RequestBody>, Vec<RequestItem>)> {
    let items: Vec<PlanItem> = steps.iter().map(Step::item).collect();
    let keys = key_items(steps);
    let cwd = std::env::current_dir().unwrap_or_default();
    let ctx = approve::context(paired, None, "sealctl unseal", &cwd);
    let make = |part: &[PlanItem], n: Option<u32>, i: Option<u32>, last: bool, keys: Vec<RequestItem>| {
        let mut b = approve::body("unseal");
        b.lvl = Some(level);
        b.has_match = last;
        b.ctx = Some(ctx.clone());
        b.plan = Some(PlanBody {
            all,
            h: h.into(),
            items: part.to_vec(),
            n,
            i,
        });
        b.keys = keys;
        b
    };
    // one body when everything fits
    let whole = make(&items, None, None, true, keys.clone());
    if body_len(&whole) <= MAX_BODY {
        return Ok((vec![whole], vec![]));
    }
    // split the items into parts; the last part carries the keys that fit
    let mut parts: Vec<Vec<PlanItem>> = vec![Vec::new()];
    for it in &items {
        let mut trial = parts.last().cloned().unwrap_or_default();
        trial.push(it.clone());
        if body_len(&make(&trial, Some(99), Some(99), true, vec![])) > MAX_BODY - 200
            && !parts.last().is_some_and(Vec::is_empty)
        {
            parts.push(vec![it.clone()]);
        } else {
            *parts.last_mut().expect("part") = trial;
        }
    }
    let n = parts.len() as u32;
    let mut bodies = Vec::new();
    for (idx, p) in parts.iter().enumerate() {
        let i = idx as u32 + 1;
        bodies.push(make(p, Some(n), Some(i), i == n, vec![]));
    }
    let mut rest = keys.clone();
    let last = bodies.last_mut().expect("last");
    let mut taken = Vec::new();
    while let Some(k) = rest.first().cloned() {
        last.keys.push(k.clone());
        if body_len(last) > MAX_BODY {
            last.keys.pop();
            break;
        }
        taken.push(k);
        rest.remove(0);
    }
    Ok((bodies, rest))
}

fn by_name(paired: &Paired, key: &str) -> String {
    if key == "phone" {
        "your phone".into()
    } else if key == paired.file.machine {
        paired.file.name.clone()
    } else {
        "another paired machine".into()
    }
}

/// Waits out a delayed approval, showing the time left; returns the released sealed reply.
fn wait_delayed(
    rt: &tokio::runtime::Runtime,
    relay: &Relay,
    paired: &Paired,
    id: &str,
    release_at: u64,
    all: bool,
) -> Result<String> {
    eprintln!(
        "Approved on your phone, away from a trusted place: it starts at {}.",
        session::hhmm(release_at)
    );
    eprintln!("Your phone and every paired machine can cancel it until then.");
    let tty = term::stderr_tty();
    let started = machine::now_ms();
    let mut last_line = 0u64;
    loop {
        let now = machine::now_ms();
        let left = release_at.saturating_sub(now);
        let mins = left.div_ceil(60_000);
        if tty {
            eprint!(
                "\r\x1b[2KStarts in {mins} min. Ctrl-C stops waiting; running it again needs a new approval."
            );
        } else if now.saturating_sub(last_line) >= 10 * 60_000 || last_line == 0 {
            eprintln!("Starts in {mins} min. Ctrl-C stops waiting; running it again needs a new approval.");
            last_line = now.max(1);
        }
        if last_line == 0 || now == started {
            let cmd = if all {
                "sealctl unseal --all --words"
            } else {
                "sealctl unseal <object> --words"
            };
            if !tty {
                eprintln!("Or use your card now: {cmd}");
            }
        }
        // read the record every 60 s, and at releaseAt
        let wait = if left == 0 { 2_000 } else { left.min(60_000) };
        std::thread::sleep(Duration::from_millis(wait.max(500)));
        let rec = rt.block_on(approve::delayed_get(relay, paired, id))?;
        let Some(rec) = rec else {
            if tty {
                eprintln!();
            }
            return Err(fail(
                exit::DECLINED,
                "The approval is gone from the relay. Nothing was changed.",
            ));
        };
        if rec.state == "cancelled" || rec.by.is_some() {
            if tty {
                eprintln!();
            }
            let by = rec.by.as_deref().unwrap_or("phone");
            return Err(fail(
                exit::DECLINED,
                format!("Cancelled from {}.", by_name(paired, by)),
            ));
        }
        if let Some(s) = rec.sealed {
            if tty {
                eprintln!();
            }
            return Ok(s);
        }
        if last_line == 0 {
            last_line = 1;
        }
    }
}

/// The plan signature, checked against our own hash, the request id and `nb`.
fn check_signature(
    paired: &Paired,
    reply: &ReplyBody,
    request_id: &str,
    ph: &[u8; 32],
    h: &str,
) -> Result<(u64, String)> {
    let sig = reply.plan.as_ref().ok_or_else(|| {
        fail(
            exit::ERROR,
            "The phone's approval has no plan signature. Nothing was changed.",
        )
    })?;
    if sig.h != h {
        return Err(fail(
            exit::ERROR,
            "The phone signed another plan. Nothing was changed.",
        ));
    }
    verify_plan_signature(
        &paired.phone.identity,
        request_id,
        paired.keys.public(),
        ph,
        sig.nb,
        &sig.sig,
    )
    .map_err(|_| {
        fail(
            exit::ERROR,
            "The plan signature did not check out. Nothing was changed.",
        )
    })?;
    if reply.grant.as_deref() != Some("plan") {
        return Err(fail(
            exit::ERROR,
            "The phone did not grant this plan. Nothing was changed.",
        ));
    }
    Ok((sig.nb, sig.sig.clone()))
}

fn take_keys(reply: &ReplyBody, items: &[RequestItem], into: &mut BTreeMap<String, ObjectKey>) -> Result<()> {
    let got: Vec<RequestItem> = items
        .iter()
        .filter(|i| reply.keys.iter().any(|k| k.p == i.purpose && k.i == i.id))
        .cloned()
        .collect();
    for (it, k) in got.iter().zip(approve::keys_from(reply, &got)?) {
        into.insert(key_name(&it.purpose, &it.id), k);
    }
    Ok(())
}

/// Gets the plan's keys from the phone: plan parts, the number match, the plan signature,
/// the delay, then continuation requests for keys that did not fit.
fn keys_from_phone(
    plan: &mut PlanFile,
    pending: &[Step],
    run: Option<&Run>,
) -> Result<BTreeMap<String, ObjectKey>> {
    let mut paired = machine::load()?;
    let relay = Relay::new(&paired.file.relay)?;
    let rt = relay::runtime()?;
    let items: Vec<PlanItem> = plan.steps.iter().map(Step::item).collect();
    let ph = plan_hash(&paired.file.machine, &items);
    let h = machine::b64u(&ph);
    let level = if plan.all || plan.steps.iter().any(|s| s.kind == "pairing") {
        3
    } else {
        2
    };
    let all_keys = key_items(pending);
    let mut keys = BTreeMap::new();
    let still_valid = plan.h.as_deref() == Some(h.as_str())
        && plan
            .nb
            .is_some_and(|nb| machine::now_ms() < nb + sealctl_core::plan::PLAN_WINDOW_MS);
    let mut remaining = if still_valid {
        all_keys.clone()
    } else {
        let (bodies, rest) = plan_bodies(&paired, &plan.steps, plan.all, &h, level)?;
        let count = bodies.len();
        let mut final_reply = None;
        for (idx, body) in bodies.into_iter().enumerate() {
            let last = idx + 1 == count;
            let sent_keys = body.keys.clone();
            let mut number = None;
            let asked = rt.block_on(approve::send(&relay, &mut paired, body, &mut |n| {
                if last {
                    number = n;
                    eprintln!("{}", term::waiting_line(n, level == 3));
                }
            }))?;
            match asked {
                Asked::Reply { reply, .. } if !last => {
                    if !reply.ok {
                        return Err(approve::refusal(&reply, None, Some("sealctl unseal")));
                    }
                }
                Asked::Reply { reply, id, .. } => {
                    if !reply.ok {
                        return Err(approve::refusal(
                            &reply,
                            number,
                            Some(if plan.all {
                                "sealctl unseal --all"
                            } else {
                                "sealctl unseal"
                            }),
                        ));
                    }
                    final_reply = Some((reply, id, sent_keys));
                }
                Asked::Delayed { request, release_at } => {
                    let sealed = wait_delayed(&rt, &relay, &paired, &request.id, release_at, plan.all)?;
                    let reply = request
                        .open_reply(paired.keys.public(), &paired.phone.identity, &sealed)
                        .map_err(|_| {
                            fail(
                                exit::ERROR,
                                "The phone's reply did not check out (bad_reply). Nothing was changed.",
                            )
                        })?;
                    if !reply.ok {
                        return Err(approve::refusal(&reply, number, Some("sealctl unseal --all")));
                    }
                    final_reply = Some((reply, request.id.clone(), sent_keys));
                }
            }
        }
        let (reply, id, sent) = final_reply.context("no reply")?;
        let (nb, sig) = check_signature(&paired, &reply, &id, &ph, &h)?;
        // never before nb by this machine's clock
        let now = machine::now_ms();
        if nb > now {
            if nb - now > 130 * 60_000 {
                return Err(fail(
                    exit::ERROR,
                    "The approval starts more than two hours from now. Nothing was changed.",
                ));
            }
            std::thread::sleep(Duration::from_millis(nb - now));
        }
        plan.h = Some(h.clone());
        plan.nb = Some(nb);
        plan.sig = Some(sig);
        if let Some(r) = run {
            r.write("plan.json", &serde_json::to_vec_pretty(plan)?)?;
        }
        take_keys(&reply, &sent, &mut keys)?;
        let mut left: Vec<RequestItem> = all_keys
            .iter()
            .filter(|k| !keys.contains_key(&key_name(&k.purpose, &k.id)))
            .cloned()
            .collect();
        if left.is_empty() {
            left = rest;
        }
        left
    };
    // continuation requests: plan {h} and keys, no match; answered without asking
    let mut guard = 0;
    while !remaining.is_empty() {
        guard += 1;
        if guard > 64 {
            return Err(fail(exit::ERROR, "The phone kept back keys of the plan."));
        }
        let mut batch = Vec::new();
        let mut b = approve::body("unseal");
        b.lvl = Some(level);
        b.plan = Some(PlanBody {
            h: h.clone(),
            ..PlanBody::default()
        });
        while let Some(k) = remaining.first().cloned() {
            b.keys.push(k.clone());
            if body_len(&b) > MAX_BODY {
                b.keys.pop();
                break;
            }
            batch.push(k);
            remaining.remove(0);
        }
        let asked = rt.block_on(approve::send(&relay, &mut paired, b, &mut |_| {}))?;
        let Asked::Reply { reply, .. } = asked else {
            return Err(fail(exit::ERROR, "The phone delayed a key of an approved plan."));
        };
        if !reply.ok {
            return Err(approve::refusal(&reply, None, Some("sealctl unseal")));
        }
        take_keys(&reply, &batch, &mut keys)?;
        for k in &batch {
            if !keys.contains_key(&key_name(&k.purpose, &k.id)) {
                remaining.push(k.clone());
            }
        }
    }
    Ok(keys)
}

// ---------- steps ----------

struct Ctx<'a> {
    run: &'a mut Run,
    keys: &'a BTreeMap<String, ObjectKey>,
    plan: &'a PlanFile,
    handback: Vec<HandbackItem>,
    objects: Vec<hb::Object>,
    paired: Option<Paired>,
    stores: Stores,
}

impl Ctx<'_> {
    fn key(&self, p: &str, i: &str) -> Result<&ObjectKey> {
        self.keys.get(&key_name(p, i)).ok_or_else(|| {
            fail(
                exit::ERROR,
                format!("No key of the plan for {p}:{i}. The run stops."),
            )
        })
    }

    /// Puts a value into a store, reads it back, and returns where it went.
    fn put(&mut self, kind: StoreKind, item: &Item, value: &[u8]) -> Result<Location> {
        let run = &*self.run;
        self.stores.put_checked(kind, item, value, &|f| run.keep_copy(f))
    }

    /// A new password: generated, or typed with `--type-passwords`.
    fn new_password(&self, what: &str) -> Result<Zeroizing<String>> {
        if self.plan.stores.type_passwords {
            store::type_password(what)
        } else {
            store::generate_password()
        }
    }

    /// The new password of an object's step, stored and journalled before the object changes.
    /// A resumed step takes the one an earlier attempt stored instead of making another: that
    /// attempt may have got as far as making it the only password that opens the object.
    fn step_password(
        &mut self,
        step: &str,
        what: &str,
        item: &Item,
    ) -> Result<(Zeroizing<String>, Location)> {
        if let Some(note) = self.run.last_note(step, "password") {
            let loc: Location = serde_json::from_str(&note).context("the journal's password line")?;
            let v = self.stores.read(&loc).with_context(|| {
                format!(
                    "reading the new password of {what} that an earlier attempt stored in {}",
                    loc.describe()
                )
            })?;
            let pw = Zeroizing::new(String::from_utf8(v.to_vec()).context("passwords are text")?);
            return Ok((pw, loc));
        }
        let pw = self.new_password(what)?;
        let loc = self.put(self.plan.stores.to, item, pw.as_bytes())?;
        self.run.log(step, "password", &serde_json::to_string(&loc)?)?;
        Ok((pw, loc))
    }

    fn done(&mut self, kind: &str, name: &str, to: String, obj: hb::Object) -> Result<()> {
        self.handback.push(HandbackItem {
            kind: kind.into(),
            name: name.into(),
            to,
            state: "done".into(),
        });
        self.objects.push(obj);
        save_handback(self.run, &self.objects)
    }
}

fn save_handback(run: &Run, objects: &[hb::Object]) -> Result<()> {
    let mut h = hb::Handback::new(&machine::default_name());
    h.objects = objects.to_vec();
    run.write("handback.json", &serde_json::to_vec_pretty(&h)?)
}

fn load_handback(run: &Run) -> Vec<hb::Object> {
    std::fs::read(run.dir.join("handback.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<hb::Handback>(&b).ok())
        .map(|h| h.objects)
        .unwrap_or_default()
}

fn store_key_of(c: &Ctx<'_>, store: &Store) -> Result<ObjectKey> {
    let k = c.key("secrets", &store.id)?;
    Ok(ObjectKey::from_bytes(k.as_bytes()).expect("16"))
}

fn read_secret(c: &Ctx<'_>, store: &Store, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let h = store.header(name)?;
    if h.mode == sealctl_core::sealed::Mode::OwnApproval {
        store.read(name, c.key("secret", &h.file_id)?)
    } else {
        store.read(name, &store_key_of(c, store)?)
    }
}

/// Every named secret to the secrets store, each read back.
fn hand_back_secrets(c: &mut Ctx<'_>, store: &Store, names: &[String]) -> Result<usize> {
    let vars = store::env_vars(names);
    let kind = c.plan.stores.secrets_to;
    for n in names {
        let v = read_secret(c, store, n)?;
        let item = Item {
            kind: "secret",
            name: n,
            notes: format!("sealctl secret {n}"),
            credential: true,
            var: vars.get(n).cloned(),
        };
        let loc = c.put(kind, &item, &v)?;
        let to = loc.describe();
        c.done(
            "secret",
            n,
            to,
            hb::Object {
                kind: "secret".into(),
                name: n.clone(),
                value: Some(loc),
                ..Default::default()
            },
        )?;
    }
    Ok(names.len())
}

fn hostname() -> String {
    crate::machine::default_name()
        .split('@')
        .nth(1)
        .unwrap_or("localhost")
        .to_string()
}

fn step_backup(c: &mut Ctx<'_>, name: &str) -> Result<String> {
    if let Some(base) = name.strip_suffix(" credentials") {
        let _ = base;
        return Ok("credentials go with the backup.".into());
    }
    let b = Backup::load(name)?;
    let key = c.key("backup", &b.repo_id)?;
    let mut env = BTreeMap::new();
    if !b.credentials.is_empty() {
        let store = Store::configured()?;
        for var in &b.credentials {
            let v = read_secret(c, &store, &format!("backup/{}/{var}", b.name))?;
            env.insert(
                var.clone(),
                Zeroizing::new(String::from_utf8_lossy(&v).into_owned()),
            );
        }
    }
    let derived = Repo::new(&b.repo, key, env.clone());
    // the new password and the credentials are saved before anything changes
    let step = format!("backup:{}", b.name);
    let pw_name = format!("{}/password", b.name);
    let (pw, loc) = c.step_password(
        &step,
        &format!("backup {}", b.name),
        &Item {
            kind: "backup",
            name: &pw_name,
            notes: format!("restic repository {}", b.repo),
            credential: false,
            var: None,
        },
    )?;
    let mut creds = Vec::new();
    for (var, v) in &env {
        let n = format!("{}/{var}", b.name);
        let l = c.put(
            c.plan.stores.secrets_to,
            &Item {
                kind: "backup",
                name: &n,
                notes: format!("storage credential of restic repository {}", b.repo),
                credential: true,
                var: Some(var.clone()),
            },
            v.as_bytes(),
        )?;
        creds.push(Credential {
            var: var.clone(),
            location: l,
        });
    }
    if c.plan.stores.to == StoreKind::Folder {
        // restic settings in one file people can source
        for (var, v) in [
            ("RESTIC_REPOSITORY", b.repo.as_bytes()),
            ("RESTIC_PASSWORD", pw.as_bytes()),
        ] {
            let n = format!("{}/{var}", b.name);
            c.put(
                StoreKind::Folder,
                &Item {
                    kind: "backup",
                    name: &n,
                    notes: String::new(),
                    credential: false,
                    var: Some(var.into()),
                },
                v,
            )?;
        }
    }
    let own = Repo::with_password(&b.repo, pw.clone(), env.clone());
    let opens_already = own.opens().unwrap_or(false);
    // a resumed step whose earlier attempt removed sealctl's key already has nothing to change
    if !(opens_already && !derived.opens()?) {
        let ours = derived
            .keys()?
            .into_iter()
            .find(|k| k.3)
            .map(|k| k.0)
            .context("sealctl's restic key")?;
        let new_id = if opens_already {
            own.keys()?
                .into_iter()
                .find(|k| k.3)
                .map(|k| k.0)
                .context("key")?
        } else {
            let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
            derived.key_add(pw.as_bytes(), &user, &hostname())?
        };
        if !own.opens()? {
            return Err(fail(
                exit::ERROR,
                format!(
                    "The new password does not open backup {}. sealctl's key still does.",
                    b.name
                ),
            ));
        }
        own.key_remove(&ours, &new_id)?;
        c.run.log(&step, "changed", "")?;
        if derived.opens()? {
            return Err(fail(
                exit::ERROR,
                format!("sealctl's key still opens backup {}.", b.name),
            ));
        }
    }
    b.forget()?;
    if Backup::list()?.is_empty() {
        let _ = crate::backup::schedule_uninstall();
    }
    let to = loc.describe();
    c.done(
        "backup",
        &b.name,
        to,
        hb::Object {
            kind: "backup".into(),
            name: b.name.clone(),
            url: Some(b.repo.clone()),
            password: Some(loc),
            credentials: creds,
            ..Default::default()
        },
    )?;
    Ok("your password works; sealctl's key is removed.".into())
}

fn step_volume(c: &mut Ctx<'_>, name: &str) -> Result<String> {
    let v = Volume::load(name)?;
    let key = c.key("volume", &v.id)?;
    let derived = key.hex();
    let was_open = v.is_open();
    if v.kind == Kind::Sparsebundle && was_open {
        volume::close(&v, false)?;
    }
    let path = v.path.clone();
    let opens = |pass: &[u8]| -> Result<bool> {
        match v.kind {
            Kind::Sparsebundle => volume::sparsebundle::verify(path.as_ref().context("path")?, pass),
            Kind::Apfs => volume::apfs::verify(&v.id, pass),
            Kind::Luks => volume::luks::verify(path.as_ref().context("path")?, pass),
        }
    };
    let notes = match v.kind {
        Kind::Apfs => format!(
            "APFS volume {} (UUID {}). Open with: diskutil apfs unlockVolume {}",
            v.name, v.id, v.id
        ),
        Kind::Sparsebundle => format!(
            "Sparse bundle {}. Open with: hdiutil attach {}",
            v.name,
            v.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default()
        ),
        Kind::Luks => format!(
            "LUKS volume {}. Open with: sudo cryptsetup open {} {}",
            v.name,
            v.path
                .as_ref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            v.name
        ),
    };
    let step = format!("volume:{}", v.name);
    let (pw, loc) = c.step_password(
        &step,
        &format!("volume {}", v.name),
        &Item {
            kind: "volume",
            name: &v.name,
            notes,
            credential: false,
            var: None,
        },
    )?;
    if !opens(pw.as_bytes())? {
        match v.kind {
            Kind::Sparsebundle => volume::sparsebundle::change_passphrase(
                path.as_ref().context("path")?,
                derived.as_bytes(),
                pw.as_bytes(),
            )?,
            Kind::Apfs => volume::apfs::change_passphrase(&v.id, derived.as_bytes(), pw.as_bytes())?,
            Kind::Luks => {
                let out = util::run_with_fds(
                    util::system_cmd("cryptsetup")
                        .args(["luksAddKey", "--key-file", "/dev/fd/3"])
                        .arg(path.as_ref().context("path")?)
                        .arg("/dev/fd/4"),
                    &[(3, derived.as_bytes()), (4, pw.as_bytes())],
                    None,
                )?;
                util::check(out, "cryptsetup luksAddKey")?;
            }
        }
    }
    if !opens(pw.as_bytes())? {
        if v.kind != Kind::Luks {
            let _ = match v.kind {
                Kind::Sparsebundle => volume::sparsebundle::change_passphrase(
                    path.as_ref().context("path")?,
                    pw.as_bytes(),
                    derived.as_bytes(),
                ),
                _ => volume::apfs::change_passphrase(&v.id, pw.as_bytes(), derived.as_bytes()),
            };
        }
        return Err(fail(
            exit::ERROR,
            format!(
                "The new passphrase did not open volume {}; sealctl's key still does.",
                v.name
            ),
        ));
    }
    // LUKS has slots: sealctl's goes only once the new passphrase is known to open it
    if v.kind == Kind::Luks && opens(derived.as_bytes())? {
        let out = util::run_with_stdin(
            util::system_cmd("cryptsetup")
                .args(["luksRemoveKey", "--key-file=-"])
                .arg(path.as_ref().context("path")?),
            derived.as_bytes(),
        )?;
        util::check(out, "cryptsetup luksRemoveKey")?;
        // the words marker goes with sealctl's key slot (SPEC 18.2)
        volume::luks::remove_tokens(path.as_ref().context("path")?);
    }
    c.run.log(&step, "changed", "")?;
    if opens(derived.as_bytes())? {
        return Err(fail(
            exit::ERROR,
            format!("sealctl's key still opens volume {}.", v.name),
        ));
    }
    match v.kind {
        Kind::Sparsebundle => {
            if let Some(p) = volume::sparsebundle::id_path(&v) {
                let _ = std::fs::remove_file(p);
            }
        }
        Kind::Apfs => {
            let _ = volume::apfs::set_hint(&v, "");
        }
        Kind::Luks => {}
    }
    let _ = std::fs::remove_dir_all(v.mountpoint.join(".sealctl"));
    let cfg = paths::volumes_dir()?.join(format!("{}.toml", v.name));
    let _ = std::fs::remove_file(cfg);
    let to = loc.describe();
    c.done(
        "volume",
        &v.name,
        to,
        hb::Object {
            kind: "volume".into(),
            name: v.name.clone(),
            volume: Some(v.kind.as_str().into()),
            uuid: Some(v.id.clone()),
            path: v.path.as_ref().map(|p| paths::tilde(p)),
            password: Some(loc),
            ..Default::default()
        },
    )?;
    Ok("your passphrase works; sealctl's is removed.".into())
}

fn step_ssh(c: &mut Ctx<'_>, name: &str) -> Result<String> {
    let store = Store::configured()?;
    let v = read_secret(c, &store, &format!("ssh/{name}"))?;
    let key = ssh_key::PrivateKey::from_openssh(std::str::from_utf8(&v).unwrap_or(""))
        .map_err(|_| fail(exit::ERROR, format!("ssh/{name} is not an OpenSSH key.")))?;
    let dir = paths::ssh_dir()?;
    std::fs::create_dir_all(&dir)?;
    let mut dest = dir.join(name);
    let mut i = 1;
    while dest.exists() {
        // resumed: the same key is already there
        if std::fs::read_to_string(&dest)
            .ok()
            .and_then(|t| ssh_key::PrivateKey::from_openssh(t).ok())
            .is_some_and(|k| k.public_key().key_data() == key.public_key().key_data())
        {
            break;
        }
        dest = dir.join(format!("{name}-{i}"));
        i += 1;
    }
    let (text, loc, pass) = if c.plan.no_ssh_passphrase {
        (
            Zeroizing::new(key.to_openssh(ssh_key::LineEnding::LF)?.to_string()),
            None,
            None,
        )
    } else {
        let pass = c.new_password(&format!("ssh key {name}"))?;
        let loc = c.put(
            c.plan.stores.to,
            &Item {
                kind: "ssh",
                name,
                notes: format!("passphrase of the SSH key {}", paths::tilde(&dest)),
                credential: false,
                var: None,
            },
            pass.as_bytes(),
        )?;
        let enc = key.encrypt(&mut ssh_key::rand_core::OsRng, pass.as_bytes())?;
        (
            Zeroizing::new(enc.to_openssh(ssh_key::LineEnding::LF)?.to_string()),
            Some(loc),
            Some(pass),
        )
    };
    paths::write_private(&dest, text.as_bytes())?;
    paths::write_mode(
        &dest.with_extension("pub"),
        format!("{}\n", key.public_key().to_openssh()?).as_bytes(),
        0o644,
    )?;
    let mut back = ssh_key::PrivateKey::from_openssh(std::fs::read_to_string(&dest)?)?;
    if let (Some(l), Some(_)) = (&loc, &pass) {
        // the passphrase read back from its store opens the file
        let p = c.stores.read(l)?;
        back = back.decrypt(&p).map_err(|_| {
            fail(
                exit::ERROR,
                format!("{} does not open with its stored passphrase.", dest.display()),
            )
        })?;
    }
    if back.public_key().key_data() != key.public_key().key_data() {
        return Err(fail(
            exit::ERROR,
            format!("{} did not read back the same key.", dest.display()),
        ));
    }
    // ~/.ssh/config: sealctl's IdentityAgent lines go
    let cfg = dir.join("config");
    if let Ok(text) = std::fs::read_to_string(&cfg) {
        let sock = paths::ssh_agent_socket()?.display().to_string();
        if text.contains(&sock) || text.contains("sealctl/ssh-agent.sock") {
            c.run.keep_copy(&cfg)?;
            let kept: String = text
                .lines()
                .filter(|l| {
                    !(l.trim_start().starts_with("IdentityAgent")
                        && l.contains("ssh-agent.sock")
                        && l.contains("sealctl"))
                })
                .map(|l| format!("{l}\n"))
                .collect();
            paths::write_mode(&cfg, kept.as_bytes(), 0o600)?;
        }
    }
    if let Ok(p) = crate::ssh::pub_path(name) {
        c.run.keep(&p, &format!("ssh/sealctl_{name}.pub"))?;
    }
    let to = match &loc {
        Some(l) => format!("{}, passphrase: {}", paths::tilde(&dest), l.describe()),
        None => paths::tilde(&dest),
    };
    c.done(
        "ssh",
        name,
        to,
        hb::Object {
            kind: "ssh".into(),
            name: name.into(),
            path: Some(paths::tilde(&dest)),
            password: loc.clone(),
            ..Default::default()
        },
    )?;
    if loc.is_some() {
        return Ok(format!("{} with a passphrase of your own.", paths::tilde(&dest)));
    }
    Ok(format!("{} with no passphrase.", paths::tilde(&dest)))
}

fn step_git() -> Result<String> {
    let g = |args: &[&str]| std::process::Command::new("git").args(args).output();
    let line = g(&["config", "--global", "--get", "user.signingkey"])
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let _ = g(&["config", "--global", "--unset", "gpg.ssh.program"]);
    if let Some(key_line) = line.strip_prefix("key::") {
        let dir = paths::ssh_dir()?;
        if let Ok(rd) = std::fs::read_dir(&dir) {
            for e in rd.flatten() {
                let p = e.path();
                let ours = p
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("sealctl_"));
                let same = std::fs::read_to_string(&p).is_ok_and(|t| {
                    t.split_whitespace()
                        .take(2)
                        .eq(key_line.split_whitespace().take(2))
                });
                if p.extension().is_some_and(|x| x == "pub") && !ours && same {
                    let _ = g(&["config", "--global", "user.signingkey", &p.to_string_lossy()]);
                }
            }
        }
        let allowed = dir.join("allowed_signers");
        let ours = paths::config_dir()?.join("allowed_signers");
        if let Ok(t) = std::fs::read_to_string(&ours) {
            let mut cur = std::fs::read_to_string(&allowed).unwrap_or_default();
            if !cur.contains(t.trim()) {
                cur.push_str(&t);
                paths::write_mode(&allowed, cur.as_bytes(), 0o644)?;
            }
            let _ = g(&[
                "config",
                "--global",
                "gpg.ssh.allowedSignersFile",
                &allowed.to_string_lossy(),
            ]);
        }
    }
    Ok("signing goes through ssh-keygen.".into())
}

fn send_report(c: &mut Ctx<'_>) -> bool {
    let Some(paired) = c.paired.as_mut() else {
        return false;
    };
    let Ok(relay) = Relay::new(&paired.file.relay) else {
        return false;
    };
    let Ok(rt) = relay::runtime() else { return false };
    let mut body = approve::body("report");
    body.handback = Some(Handback {
        hash: c.plan.h.clone().unwrap_or_default(),
        items: c.handback.clone(),
        run: paths::tilde(&c.run.dir),
    });
    let r = rt.block_on(approve::send_for(
        &relay,
        paired,
        body,
        &mut |_| {},
        Duration::from_secs(60),
    ));
    matches!(r, Ok(Asked::Reply { reply, .. }) if reply.ok)
}

fn run_step(c: &mut Ctx<'_>, s: &Step) -> Result<String> {
    match s.kind.as_str() {
        "secrets" => {
            let store = Store::configured()?;
            let names: Vec<String> = store.list()?.into_iter().map(|l| l.name).collect();
            let n = hand_back_secrets(c, &store, &names)?;
            if c.plan.target == Target::Secrets && !c.plan.keep_store {
                c.run.keep(&store.dir, "store")?;
                let mut cfg = crate::config::Config::load()?;
                cfg.store = None;
                cfg.save()?;
            }
            Ok(format!(
                "{n} values to {}, read back.",
                c.plan.stores.secrets_to.describe()
            ))
        }
        "secret" => {
            if c.plan.target == Target::All || c.plan.target == Target::Secrets {
                // own-approval secrets went with the store step (their key is in this item)
                return Ok("handed back with the store.".into());
            }
            let store = Store::configured()?;
            hand_back_secrets(c, &store, std::slice::from_ref(&s.name))?;
            Ok(format!(
                "value to {}, read back.",
                c.plan.stores.secrets_to.describe()
            ))
        }
        "backup" => step_backup(c, &s.name),
        "volume" => step_volume(c, &s.name),
        "ssh" => step_ssh(c, &s.name),
        "git" => step_git(),
        "ai" => {
            let only: Vec<String> = match &c.plan.target {
                Target::Ai(t) => t.clone(),
                _ => vec![],
            };
            for f in [
                ".claude/settings.json",
                ".codex/config.toml",
                ".gemini/settings.json",
            ] {
                if let Ok(h) = paths::home() {
                    c.run.keep_copy(&h.join(f))?;
                }
            }
            crate::ai::uninstall(&only)?;
            Ok("removed.".into())
        }
        "services" => {
            crate::daemon::client::stop_running();
            let _ = crate::service::uninstall(crate::service::DAEMON_LABEL);
            let _ = crate::service::uninstall(crate::service::BACKUP_LABEL);
            Ok("stopped and removed.".into())
        }
        "local" => {
            crate::daemon::client::stop_running();
            if !c.plan.keep_store {
                if let Ok(d) = paths::data_dir() {
                    c.run.keep(&d, "local-share-sealctl")?;
                }
            }
            for d in [paths::config_dir()?, paths::state_dir()?] {
                if d.exists() {
                    std::fs::remove_dir_all(&d).with_context(|| format!("removing {}", d.display()))?;
                }
            }
            for n in crate::ssh::names() {
                if let Ok(p) = crate::ssh::pub_path(&n) {
                    c.run.keep(&p, &format!("ssh/sealctl_{n}.pub"))?;
                }
            }
            Ok("removed.".into())
        }
        "pairing" => {
            let Some(p) = c.paired.as_ref() else {
                return Ok("not paired.".into());
            };
            let relay = Relay::new(&p.file.relay)?;
            let rt = relay::runtime()?;
            let path = format!("/v1/phones/{}/machines/{}", p.phone_id(), p.file.machine);
            match rt.block_on(relay.request(Some(&p.keys), "DELETE", &path, None)) {
                Ok(a) if a.ok() || a.status == 404 => Ok("unpaired.".into()),
                _ => Ok(format!("Unpair {} on your phone.", p.file.name)),
            }
        }
        other => Err(fail(exit::ERROR, format!("Unknown step {other}."))),
    }
}

/// `sealctl unseal`.
pub fn unseal(o: Opts) -> Result<()> {
    term::require_person("sealctl unseal", None)?;
    if machine::is_paired() {
        machine::load_for(o.relay.as_deref())?;
    }
    let (mut run, mut plan) = if o.resume {
        let run = Run::resume()?;
        let plan: PlanFile = serde_json::from_slice(&std::fs::read(run.dir.join("plan.json"))?)?;
        eprintln!("Resuming the run in {}.", paths::tilde(&run.dir));
        (run, plan)
    } else {
        let target = o
            .target
            .clone()
            .ok_or_else(|| fail(exit::USAGE, "Say what to unseal, or --all."))?;
        let all = target == Target::All;
        let steps = build(&target, o.keep_store, &o.skip)?;
        if steps.is_empty() {
            return Err(fail(exit::NOT_FOUND, "Nothing to hand back."));
        }
        let to = o.to.unwrap_or(StoreKind::Folder);
        // secrets follow the password store, except that `show` can't take them
        let secrets_to = o.secrets_to.unwrap_or(match to {
            StoreKind::Show => StoreKind::Folder,
            t => t,
        });
        let uses_to = steps
            .iter()
            .any(|s| s.kind == "volume" || (s.kind == "backup" && !s.name.ends_with(" credentials")))
            || (steps.iter().any(|s| s.kind == "ssh") && !o.no_ssh_passphrase && to != StoreKind::Folder);
        let uses_secrets = steps
            .iter()
            .any(|s| matches!(s.kind.as_str(), "secrets" | "secret" | "backup"));
        if uses_to {
            store::usable(to, false)
                .map_err(|e| fail(exit::USAGE, format!("--to {}: {e:#}", to.as_str())))?;
        }
        if uses_secrets {
            store::usable(secrets_to, true).map_err(|e| {
                fail(
                    exit::USAGE,
                    format!("--secrets-to {}: {e:#}", secrets_to.as_str()),
                )
            })?;
        }
        let plan = PlanFile {
            target,
            all,
            steps,
            keep_store: o.keep_store,
            h: None,
            nb: None,
            sig: None,
            words: o.words,
            stores: store::Config {
                to,
                secrets_to,
                env_file: o.env_file.clone(),
                op_vault: o.op_vault.clone(),
                bw_folder: o.bw_folder.clone(),
                type_passwords: o.type_passwords,
            },
            no_ssh_passphrase: o.no_ssh_passphrase || to == StoreKind::Folder,
        };
        let mut plan = plan;
        retext(&mut plan);
        show_plan(&plan);
        if o.dry_run {
            if o.json {
                println!(
                    "{}",
                    json!({"plan": plan.steps.iter().map(|s| json!({"kind": s.kind, "name": s.name})).collect::<Vec<_>>()})
                );
            }
            return Ok(());
        }
        if all {
            let typed = term::ask_line("Type unseal to start: ")?;
            if typed != "unseal" {
                return Err(fail(exit::USAGE, "Not started. Nothing was changed."));
            }
        } else if !term::confirm("Start?", false)? {
            return Err(fail(exit::USAGE, "Not started. Nothing was changed."));
        }
        let run = Run::create()?;
        run.write(
            "README.txt",
            format!(
                "This folder holds what sealctl handed back on {}: new passwords and secrets in plain form.\n\
                 passwords.txt    passwords of volumes and backups\n\
                 secrets.env      secrets, NAME=\"value\"\n\
                 backup-*.env     restic settings: source one with  set -a; . ./backup-NAME.env  then run restic\n\
                 handback.json    what went where (no passwords in it)\n\
                 Passwords and secrets that went to a password manager or the keychain are not here.\n\
                 Delete this folder (rm -rf) once the new passwords and keys work. sealctl never deletes it.\n",
                machine::default_name()
            )
            .as_bytes(),
        )?;
        if cfg!(target_os = "macos") {
            let _ = util::system_cmd("tmutil")
                .arg("addexclusion")
                .arg(&run.dir)
                .output();
        }
        run.write("plan.json", &serde_json::to_vec_pretty(&plan)?)?;
        (run, plan)
    };

    let done = run.done_steps();
    let pending: Vec<Step> = plan
        .steps
        .iter()
        .filter(|s| !done.contains(&s.id))
        .cloned()
        .collect();
    let keys = if key_items(&pending).is_empty() && (o.resume || !plan.all) {
        BTreeMap::new()
    } else if plan.words || o.words {
        keys_from_words(&pending)?
    } else {
        keys_from_phone(&mut plan, &pending, Some(&run))?
    };
    let total = plan.steps.len();
    let paired = machine::load().ok();
    let plan_c = plan.clone();
    let mut stores = Stores::new(plan.stores.clone());
    stores.folder = Some(run.dir.clone());
    let objects = load_handback(&run);
    let mut c = Ctx {
        run: &mut run,
        keys: &keys,
        plan: &plan_c,
        handback: Vec::new(),
        objects,
        paired,
        stores,
    };
    // Ctrl-C (or a TERM) from here on lets the current step finish, then stops with the
    // journal resumable
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    for sig in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        let _ = signal_hook::flag::register(sig, stop.clone());
    }
    let stopped = |c: &mut Ctx<'_>, step: &str| -> Result<()> {
        if stop.load(std::sync::atomic::Ordering::SeqCst) {
            let _ = c.run.log(step, "skipped", "stopped by Ctrl-C");
            return Err(fail(
                exit::PARTWAY,
                format!(
                    "Stopped before {step}. Steps before it are done. Run sealctl unseal --resume to go on.\nThe run folder is {}.",
                    paths::tilde(&c.run.dir)
                ),
            ));
        }
        Ok(())
    };
    let mut report_note = None;
    for (i, s) in plan.steps.iter().enumerate() {
        if done.contains(&s.id) {
            continue;
        }
        stopped(&mut c, &s.id)?;
        if s.kind == "pairing" && !plan.words {
            // the hand-back report goes before the pairing step
            if !send_report(&mut c) {
                report_note = Some("Your phone did not get the report.");
            }
            stopped(&mut c, &s.id)?;
        }
        c.run.log(&s.id, "start", "")?;
        match run_step(&mut c, s) {
            Ok(note) => {
                c.run.log(&s.id, "done", &note)?;
                eprintln!("[{}/{total}] {} {}: {note}", i + 1, s.kind, s.name);
            }
            Err(e) => {
                let _ = c.run.log(&s.id, "failed", &exit::message_of(&e));
                eprintln!("[{}/{total}] {} {}: failed.", i + 1, s.kind, s.name);
                let code = exit::code_of(&e);
                return Err(fail(
                    if code == exit::BUSY {
                        exit::BUSY
                    } else {
                        exit::PARTWAY
                    },
                    format!(
                        "{}\nRun sealctl unseal --resume after fixing this.",
                        exit::message_of(&e)
                    ),
                ));
            }
        }
    }
    save_handback(c.run, &c.objects)?;
    c.run.finish()?;
    let dir = paths::tilde(&c.run.dir);
    if plan.all {
        eprintln!("Done. sealctl holds nothing on this machine.");
    } else {
        eprintln!("Done.");
    }
    let files: Vec<String> = ["passwords.txt", "secrets.env"]
        .iter()
        .filter(|f| c.run.dir.join(f).exists())
        .map(|f| f.to_string())
        .chain(
            std::fs::read_dir(&c.run.dir)
                .map(|rd| {
                    rd.flatten()
                        .map(|e| e.file_name().to_string_lossy().into_owned())
                        .filter(|n| n.starts_with("backup-"))
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
        )
        .collect();
    eprintln!(
        "Everything is in {dir}: {}README.txt, handback.json (no passwords in it).",
        files.iter().map(|f| format!("{f}, ")).collect::<String>()
    );
    for kind in [plan.stores.to, plan.stores.secrets_to] {
        if !matches!(kind, StoreKind::Folder | StoreKind::Show) {
            eprintln!(
                "Some went to {} (labels start with \"sealctl: \").",
                kind.describe()
            );
        }
    }
    if plan.all {
        eprintln!("Remove the program: {}", uninstall_hint());
    }
    eprintln!("Once the new passwords and keys work, delete the folder:\n  rm -rf {dir}");
    if let Some(n) = report_note {
        eprintln!("{n}");
    }
    if plan.all {
        eprintln!("Keep your paper card until no old copies of these backups or volumes remain.");
    }
    if o.json {
        println!("{}", json!({"run": dir, "done": total}));
    }
    Ok(())
}

/// Where a secret goes, for its plan row: the chosen store, not always the folder.
fn secrets_destination(stores: &store::Config) -> String {
    match stores.secrets_to {
        StoreKind::Folder => "secrets.env in the folder, plain".into(),
        StoreKind::Env => format!(
            "{} (a .env file), plain",
            stores
                .env_file
                .as_ref()
                .map(|f| paths::tilde(f))
                .unwrap_or_else(|| "~/sealctl-secrets.env".into())
        ),
        StoreKind::Keychain => format!(
            "{}, labels \"sealctl: secret <name>\"",
            StoreKind::Keychain.describe()
        ),
        StoreKind::Op => "1Password, titles \"sealctl: secret <name>\"".into(),
        StoreKind::Bw => "Bitwarden, names \"sealctl: secret <name>\"".into(),
        StoreKind::Show => StoreKind::Show.describe().into(),
    }
}

/// Plan rows that depend on the chosen stores: secrets, own-approval secrets, backup
/// passwords and credentials, volume passphrases, SSH keys.
pub fn retext(plan: &mut PlanFile) {
    let to = plan.stores.to;
    let dest = secrets_destination(&plan.stores);
    let pw_in = match to {
        StoreKind::Folder => "passwords.txt".to_string(),
        k => k.describe().to_string(),
    };
    let ssh_plain = plan.no_ssh_passphrase;
    for s in plan.steps.iter_mut() {
        let n = s
            .text
            .find(&s.name)
            .map(|i| i + s.name.len())
            .unwrap_or(s.text.len());
        let head = s.text[..n].to_string();
        let pad = |head: &str| format!("{head:<41} ");
        let new = match s.kind.as_str() {
            "secrets" => Some(format!("→ {dest}")),
            "secret" => Some(format!(
                "→ {dest}{}",
                if s.text.contains("own approval") {
                    " (own approval)"
                } else {
                    ""
                }
            )),
            "backup" if s.name.ends_with(" credentials") => Some(format!("storage credentials → {dest}")),
            "backup" => Some(format!(
                "stays encrypted; it will open with a new password ({pw_in}). sealctl's key is removed."
            )),
            "volume" => Some(format!(
                "{} stays encrypted; it will open with a new passphrase ({pw_in}).",
                s.name
            )),
            "ssh" if ssh_plain => Some(format!("→ ~/.ssh/{} with no passphrase", s.name)),
            "ssh" => Some(format!(
                "→ ~/.ssh/{} with a passphrase in {}",
                s.name,
                to.describe()
            )),
            _ => None,
        };
        if let Some(what) = new {
            s.text = format!("{}{what}", pad(&head));
        }
    }
}

fn show_plan(plan: &PlanFile) {
    let who = machine::load()
        .map(|p| p.file.name)
        .unwrap_or_else(|_| machine::default_name());
    if plan.all {
        eprintln!("This hands everything sealctl holds on {who} back to you, in plain, standard form.");
    } else {
        eprintln!("This hands back to you, in plain, standard form:");
    }
    eprintln!();
    eprintln!(
        "Everything goes into one new folder: ~/sealctl-unsealed-{}",
        crate::clock::now_local("%Y-%m-%d")
    );
    eprintln!("  Only you can read the folder. Delete it yourself once the new passwords and keys work.");
    eprintln!();
    eprintln!(
        "New passwords go to: {}   (change with --to folder|keychain|op|bw|show)",
        plan.stores.to.describe()
    );
    eprintln!(
        "Secrets go to:       {}   (change with --secrets-to folder|keychain|op|bw|env)",
        plan.stores.secrets_to.describe()
    );
    if plan.stores.secrets_to == StoreKind::Env {
        eprintln!("  This file holds your keys in plain text, where AI agents can read them. Move them to a password manager, then delete it.");
    }
    eprintln!();
    for s in &plan.steps {
        eprintln!("{}", s.text);
    }
    if plan.all {
        eprintln!("    last, by you {}", uninstall_hint());
    }
    eprintln!();
    eprintln!("If anything stops, run: sealctl unseal --resume");
}

/// For tests and resume: whether a folder is a finished run.
pub fn is_done(dir: &Path) -> bool {
    dir.join("done").exists()
}

/// The newest run folder, if any.
pub fn newest_run() -> Option<PathBuf> {
    let home = paths::home().ok()?;
    let mut runs: Vec<PathBuf> = std::fs::read_dir(home)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("sealctl-unsealed-"))
        })
        .collect();
    runs.sort();
    runs.pop()
}
