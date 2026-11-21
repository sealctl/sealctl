//! `sealctl unseal`: hand everything sealctl holds back to the user, under passwords of their
//! own, so they can leave the Ledger version (0.6.0) — and install 0.7 and `seal` each object,
//! or stop using sealctl.
//!
//! Rules (SPEC.md section 18, 24.1):
//! * plan first: nothing changes before the plan is shown and confirmed (`y` for one object,
//!   the typed word `unseal` for `--all`); `--dry-run` only shows it;
//! * every object is opened with the new password, read back from where it was stored, before
//!   sealctl's key or slot is removed;
//! * every step goes to a journal in the run folder, so a stopped run resumes (`--resume`);
//! * every edited file is copied into the run folder first; nothing is deleted that could be
//!   needed (replaced files and the old store move to `kept/`);
//! * values are never printed; a person at a terminal runs it, never an AI agent.

pub mod handback;
pub mod journal;
pub mod objects;
pub mod sshconfig;
pub mod store;

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::derive::Oracle;
use crate::volume::{Kind, Volume};
use store::StoreKind;

// ---------------------------------------------------------------- exit codes ----

/// An error with the exit code of SPEC.md 18.7.
#[derive(Debug)]
pub struct Exit {
    pub code: i32,
    pub msg: String,
}

impl std::fmt::Display for Exit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.msg)
    }
}

impl std::error::Error for Exit {}

/// 2 usage or another run active; 8 inside an agent or without a terminal; 9 no such object;
/// 10 sealctl's key does not open the object; 11 a volume busy; 13 stopped part way or with
/// skipped objects.
pub fn exit(code: i32, msg: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Exit {
        code,
        msg: msg.into(),
    })
}

/// The exit code carried by an error, if any.
pub fn exit_code(e: &anyhow::Error) -> Option<i32> {
    e.chain().find_map(|c| c.downcast_ref::<Exit>()).map(|x| x.code)
}

// ---------------------------------------------------------------- options ----

/// What one `sealctl unseal <object>` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    Secrets,
    Secret(String),
    Volume(String),
    Backup(String),
    Ssh(String),
    Git,
    Ai(Vec<String>),
}

const TARGETS: &str =
    "secrets | secret <name> | volume <name> | backup <volume> | ssh <name> | git | ai [TOOL...]";

pub fn parse_target(words: &[String]) -> Result<Target> {
    let usage = || exit(2, format!("name what to unseal: {TARGETS}, or --all"));
    let (first, rest) = words.split_first().ok_or_else(usage)?;
    let one = |what: &str| -> Result<String> {
        match rest {
            [n] => Ok(n.clone()),
            _ => Err(exit(2, format!("usage: sealctl unseal {what} <name>"))),
        }
    };
    Ok(match first.as_str() {
        "secrets" if rest.is_empty() => Target::Secrets,
        "secret" => Target::Secret(one("secret")?),
        "volume" => Target::Volume(one("volume")?),
        "backup" => Target::Backup(one("backup")?),
        "ssh" => Target::Ssh(one("ssh")?),
        "git" if rest.is_empty() => Target::Git,
        "ai" => Target::Ai(rest.to_vec()),
        _ => return Err(usage()),
    })
}

#[derive(Debug, Clone, Default)]
pub struct Options {
    pub all: bool,
    pub target: Option<Target>,
    pub resume: bool,
    pub to: Option<StoreKind>,
    pub secrets_to: Option<StoreKind>,
    pub env_file: Option<PathBuf>,
    pub op_vault: Option<String>,
    pub bw_folder: Option<String>,
    pub type_passwords: bool,
    pub no_ssh_passphrase: bool,
    /// `--keep-env-rules` (true) / `--drop-env-rules` (false); asked when `None`.
    pub env_rules: Option<bool>,
    pub skip: Vec<String>,
    pub words: bool,
    pub dry_run: bool,
    pub json: bool,
    pub keep_store: bool,
}

// ---------------------------------------------------------------- the plan ----

/// A key file `~/.ssh/sealctl_<name>` and where it goes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshKey {
    pub name: String,
    pub path: PathBuf,
    pub dest: PathBuf,
    /// `ssh-ed25519 AAAA…` (public).
    pub public: String,
}

/// One object of the plan, in run order.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "object", rename_all = "kebab-case")]
pub enum Object {
    /// The secret store (`whole`), or some of its secrets.
    Secrets {
        names: Vec<String>,
        whole: bool,
    },
    /// The restic backup configured for a volume.
    Backup {
        volume: Volume,
    },
    Volume {
        volume: Volume,
    },
    Ssh {
        keys: Vec<SshKey>,
    },
    Git {
        configs: Vec<crate::git::SigningConfig>,
    },
    Ai {
        tools: Vec<String>,
    },
    Services {
        labels: Vec<String>,
        agent: bool,
    },
    LocalState,
}

impl Object {
    /// The id used by `--skip` and in step ids.
    pub fn id(&self) -> String {
        match self {
            Object::Secrets { .. } => "secrets".into(),
            Object::Backup { volume } => format!("backup/{}", volume.name),
            Object::Volume { volume } => format!("volume/{}", volume.name),
            Object::Ssh { .. } => "ssh".into(),
            Object::Git { .. } => "git".into(),
            Object::Ai { .. } => "ai".into(),
            Object::Services { .. } => "services".into(),
            Object::LocalState => "local".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Plan {
    pub sealctl: u32,
    pub kind: String,
    pub created: String,
    pub machine: String,
    pub from: String,
    pub all: bool,
    pub stores: store::Config,
    pub no_ssh_passphrase: bool,
    pub keep_store: bool,
    pub env_rules: Option<bool>,
    pub objects: Vec<Object>,
    /// `kind/name` left out with `--skip`, and what was kept for them.
    pub skipped: Vec<String>,
    /// Problems that stop a real run (shown by `--dry-run`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub problems: Vec<String>,
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME is not set")
}

/// `~/x` for display.
pub fn tilde(p: &Path) -> String {
    handback::tilde(p)
}

/// Where a key file `sealctl_<name>` goes: `~/.ssh/<name>`, or `<name>-1`, … when taken.
fn ssh_dest(dir: &Path, name: &str, taken: &[PathBuf]) -> PathBuf {
    let free = |p: &Path| !p.exists() && !ssh_public(p).exists() && !taken.iter().any(|t| t == p);
    let first = dir.join(name);
    if free(&first) {
        return first;
    }
    (1..)
        .map(|i| dir.join(format!("{name}-{i}")))
        .find(|p| free(p))
        .expect("a free name")
}

fn ssh_public(p: &Path) -> PathBuf {
    crate::ssh::public_path(p)
}

fn ssh_keys(only: Option<&str>) -> Result<Vec<SshKey>> {
    let dir = crate::paths::ssh_dir()?;
    let mut keys: Vec<SshKey> = vec![];
    for path in crate::ssh::key_files() {
        let fname = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        let name = fname.trim_start_matches("sealctl_").to_string();
        if only.is_some_and(|o| o != name) {
            continue;
        }
        let public = crate::ssh::read_public(&path)
            .and_then(|k| Ok(k.to_openssh()?))
            .with_context(|| format!("reading {}", path.display()))?;
        let taken: Vec<PathBuf> = keys.iter().map(|k| k.dest.clone()).collect();
        let dest = ssh_dest(&dir, &name, &taken);
        keys.push(SshKey {
            name,
            path,
            dest,
            public: public.split_whitespace().take(2).collect::<Vec<_>>().join(" "),
        });
    }
    Ok(keys)
}

fn local_state_present() -> bool {
    [
        crate::paths::config_dir(),
        crate::paths::data_dir(),
        crate::paths::state_dir(),
    ]
    .into_iter()
    .any(|d| d.is_ok_and(|d| d.exists()))
}

/// Find what sealctl holds on this machine, in run order. Changes nothing.
pub fn discover(opts: &Options) -> Result<(Vec<Object>, Vec<String>)> {
    let mut objects = vec![];
    let skip = |id: &str| opts.skip.iter().any(|s| s == id);
    let mut skipped: Vec<String> = vec![];
    match &opts.target {
        None => {
            let mut names = crate::secrets::list()?;
            names.retain(|n| {
                let s = skip(&format!("secret/{n}"));
                if s {
                    skipped.push(format!("secret/{n}"));
                }
                !s
            });
            if !names.is_empty() {
                if skip("secrets") {
                    skipped.push("secrets".into());
                } else {
                    let whole = !skipped.iter().any(|s| s.starts_with("secret/"));
                    objects.push(Object::Secrets { names, whole });
                }
            }
            for v in Volume::list()? {
                if v.backup.as_ref().is_some_and(|b| !b.repository.is_empty()) {
                    let id = format!("backup/{}", v.name);
                    if skip(&id) {
                        skipped.push(id);
                    } else {
                        objects.push(Object::Backup { volume: v.clone() });
                    }
                }
                let id = format!("volume/{}", v.name);
                if skip(&id) {
                    skipped.push(id);
                } else {
                    objects.push(Object::Volume { volume: v });
                }
            }
            let mut keys = ssh_keys(None)?;
            keys.retain(|k| {
                let id = format!("ssh/{}", k.name);
                let s = skip(&id);
                if s {
                    skipped.push(id);
                }
                !s
            });
            if !keys.is_empty() {
                if skip("ssh") {
                    skipped.push("ssh".into());
                } else {
                    objects.push(Object::Ssh { keys });
                }
            }
            let configs = crate::git::find_configs()?;
            if !configs.is_empty() {
                if skip("git") {
                    skipped.push("git".into());
                } else {
                    objects.push(Object::Git { configs });
                }
            }
            let mut tools: Vec<String> = crate::ai::installed()
                .into_iter()
                .map(|(id, _)| id.to_string())
                .collect();
            tools.retain(|t| {
                let id = format!("ai/{t}");
                let s = skip(&id);
                if s {
                    skipped.push(id);
                }
                !s
            });
            if !tools.is_empty() {
                if skip("ai") {
                    skipped.push("ai".into());
                } else {
                    objects.push(Object::Ai { tools });
                }
            }
            // With anything skipped, sealctl must keep working for it: no services or local
            // state are removed.
            let labels = crate::service::installed_labels()?;
            // the session agent: running now, or started by this run to get keys
            let agent = crate::agent::session_alive()
                || objects.iter().any(|o| {
                    matches!(
                        o,
                        Object::Secrets { .. }
                            | Object::Backup { .. }
                            | Object::Volume { .. }
                            | Object::Ssh { .. }
                    )
                });
            if skipped.is_empty() {
                if !labels.is_empty() || agent {
                    objects.push(Object::Services { labels, agent });
                }
                if local_state_present() {
                    objects.push(Object::LocalState);
                }
            }
        }
        Some(Target::Secrets) => {
            let names = crate::secrets::list()?;
            if names.is_empty() {
                return Err(exit(9, "the secret store is empty"));
            }
            objects.push(Object::Secrets { names, whole: true });
        }
        Some(Target::Secret(n)) => {
            if !crate::secrets::list()?.contains(n) {
                return Err(exit(9, format!("no secret named {n}")));
            }
            objects.push(Object::Secrets {
                names: vec![n.clone()],
                whole: false,
            });
        }
        Some(Target::Volume(n)) => {
            let v = Volume::load(n).map_err(|_| exit(9, format!("no volume named {n}")))?;
            if v.backup.as_ref().is_some_and(|b| !b.repository.is_empty()) {
                return Err(exit(
                    2,
                    format!(
                        "volume {n} has a backup sealed by sealctl, whose settings live inside the volume.\n\
                         Hand the backup back first: sealctl unseal backup {n}"
                    ),
                ));
            }
            objects.push(Object::Volume { volume: v });
        }
        Some(Target::Backup(n)) => {
            let v = Volume::load(n).map_err(|_| exit(9, format!("no volume named {n}")))?;
            if !v.backup.as_ref().is_some_and(|b| !b.repository.is_empty()) {
                return Err(exit(9, format!("volume {n} has no backup")));
            }
            objects.push(Object::Backup { volume: v });
        }
        Some(Target::Ssh(n)) => {
            let keys = ssh_keys(Some(n))?;
            if keys.is_empty() {
                return Err(exit(9, format!("no SSH key ~/.ssh/sealctl_{n}")));
            }
            objects.push(Object::Ssh { keys });
        }
        Some(Target::Git) => {
            let configs = crate::git::find_configs()?;
            if configs.is_empty() {
                return Err(exit(9, "no git config signs through sealctl"));
            }
            objects.push(Object::Git { configs });
        }
        Some(Target::Ai(only)) => {
            let installed: Vec<String> = crate::ai::installed()
                .into_iter()
                .map(|(id, _)| id.to_string())
                .collect();
            for o in only {
                if !crate::ai::tool_ids().contains(&o.as_str()) {
                    return Err(exit(
                        2,
                        format!("unknown tool {o:?}; known: {}", crate::ai::tool_ids().join(", ")),
                    ));
                }
            }
            let tools: Vec<String> = installed
                .into_iter()
                .filter(|t| only.is_empty() || only.contains(t))
                .collect();
            if tools.is_empty() {
                return Err(exit(9, "sealctl is not installed in any of these AI tools"));
            }
            objects.push(Object::Ai { tools });
        }
    }
    Ok((objects, skipped))
}

/// Problems that would stop the run, found without changing anything.
fn problems(objects: &[Object], cfg: &store::Config) -> Vec<String> {
    let mut p = vec![];
    let needs_passwords = objects.iter().any(|o| {
        matches!(
            o,
            Object::Backup { .. } | Object::Volume { .. } | Object::Ssh { .. }
        )
    });
    let needs_secrets = objects
        .iter()
        .any(|o| matches!(o, Object::Secrets { .. } | Object::Backup { .. }));
    if needs_passwords {
        if let Err(e) = store::usable(cfg.to, false) {
            p.push(format!("--to {}: {e}", cfg.to.as_str()));
        }
    }
    if needs_secrets {
        if let Err(e) = store::usable(cfg.secrets_to, true) {
            p.push(format!("--secrets-to {}: {e}", cfg.secrets_to.as_str()));
        }
    }
    let keys: Vec<SshKey> = objects
        .iter()
        .filter_map(|o| match o {
            Object::Ssh { keys } => Some(keys.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    for o in objects {
        match o {
            Object::Git { configs } => {
                for c in configs {
                    let line = c.signingkey.as_deref().and_then(crate::git::signingkey_line);
                    let found = line
                        .as_deref()
                        .map(|l| objects::find_pub(l, &keys).ok().flatten().is_some())
                        .unwrap_or(false);
                    if !found {
                        p.push(format!(
                            "{} signs with a key that is not one of sealctl's key files (the Ledger's own key?); \
                             point it at a key file first (sealctl git setup --key <name>), or --skip git",
                            tilde(&c.file)
                        ));
                    }
                }
            }
            Object::Secrets { names, .. } if cfg.secrets_to == StoreKind::Env => {
                let mut seen = std::collections::BTreeMap::new();
                for n in names {
                    if let Some(other) = seen.insert(store::env_var_name(n), n.clone()) {
                        p.push(format!(
                            "secrets {other} and {n} would both be {} in the .env file; use another --secrets-to",
                            store::env_var_name(n)
                        ));
                    }
                }
            }
            Object::Backup { volume } => {
                if !crate::util::which(&crate::backup::restic_bin())
                    && std::env::var_os("SEALCTL_RESTIC").is_none()
                {
                    p.push(format!(
                        "backup of {}: restic is not installed (brew install restic / apt install restic)",
                        volume.name
                    ));
                }
            }
            Object::Volume { volume } => {
                if volume.is_legacy() {
                    p.push(format!(
                        "volume {} uses a key file from an older sealctl; run `sealctl volume rekey {}` first, or --skip volume/{}",
                        volume.name, volume.name, volume.name
                    ));
                } else if let Err(e) = crate::volume::backend(volume.kind).read_id(volume) {
                    p.push(format!(
                        "volume {} not found ({e:#}); connect its disk, or --skip volume/{}",
                        volume.name, volume.name
                    ));
                }
            }
            _ => {}
        }
    }
    p
}

fn kind_label(k: Kind) -> &'static str {
    match k {
        Kind::ApfsVolume => "APFS",
        Kind::Sparsebundle => "sparse bundle",
        Kind::Luks => "LUKS",
    }
}

fn machine_word() -> &'static str {
    if cfg!(target_os = "macos") {
        "this Mac"
    } else {
        "this machine"
    }
}

/// The command that removes the program, for how it was installed. Never run by sealctl.
pub fn uninstall_hint() -> String {
    let exe = std::env::current_exe().unwrap_or_default();
    let real = std::fs::canonicalize(&exe).unwrap_or(exe.clone());
    let s = real.to_string_lossy();
    if s.contains("/Cellar/") || s.contains("/homebrew/") || s.contains("/linuxbrew/") {
        "brew uninstall sealctl/tap/sealctl".into()
    } else if s.starts_with("/nix/store/") {
        "nix profile remove sealctl".into()
    } else if s.contains("/.cargo/bin/") {
        "cargo uninstall sealctl".into()
    } else if s == "/usr/bin/sealctl" && Path::new("/etc/debian_version").exists() {
        "sudo apt remove sealctl".into()
    } else if s == "/usr/bin/sealctl" && Path::new("/etc/arch-release").exists() {
        "sudo pacman -R sealctl".into()
    } else if s == "/usr/bin/sealctl" {
        "sudo dnf remove sealctl".into()
    } else {
        format!("rm {}", exe.display())
    }
}

const COL: usize = 44;

fn line(out: &mut String, n: usize, kind: &str, name: &str, desc: &[String]) {
    let mut first = true;
    for d in desc {
        if first {
            out.push_str(&format!("{n:>2}  {kind:<12} {name:<24} {d}\n"));
            first = false;
        } else {
            out.push_str(&format!("{:COL$}{d}\n", ""));
        }
    }
}

/// The plan as people read it (stderr).
pub fn plan_text(plan: &Plan, words: bool) -> String {
    let mut s = String::new();
    if plan.all {
        s.push_str(&format!(
            "This hands everything sealctl 0.5 holds on {} back to you, under passwords of your own.\n",
            machine_word()
        ));
    } else {
        s.push_str("This hands the object below back to you, under a password of your own.\n");
    }
    s.push_str("Your files stay encrypted. ");
    if words {
        s.push_str("Keys come from your 24 words.\n\n");
    } else {
        s.push_str("Keys come from your Ledger: keep it connected with the OpenPGP app open.\n\n");
    }
    let needs_to = plan.objects.iter().any(|o| {
        matches!(o, Object::Volume { .. } | Object::Backup { .. })
            || matches!(o, Object::Ssh { .. } if !plan.no_ssh_passphrase)
    });
    let needs_secrets = plan
        .objects
        .iter()
        .any(|o| matches!(o, Object::Secrets { .. } | Object::Backup { .. }));
    if needs_to {
        s.push_str(&format!(
            "New passwords go to: {:<18} (change with --to keychain|op|bw|show)\n",
            plan.stores.to.describe()
        ));
    }
    if needs_secrets {
        s.push_str(&format!(
            "Secrets go to:       {:<18} (change with --secrets-to keychain|op|bw|env)\n",
            plan.stores.secrets_to.describe()
        ));
    }
    if plan.stores.secrets_to == StoreKind::Env && needs_secrets {
        let f = plan
            .stores
            .env_file
            .clone()
            .or_else(|| store::default_env_file().ok())
            .unwrap_or_default();
        s.push_str(&format!(
            "  {}: This file holds your keys in plain text, where AI agents can read them.\n  \
             Move them to a password manager, then delete it.\n",
            tilde(&f)
        ));
    }
    s.push('\n');
    let mut n = 0;
    for o in &plan.objects {
        n += 1;
        match o {
            Object::Secrets { names, whole } => {
                let what = if names.len() == 1 {
                    "1 secret".to_string()
                } else {
                    format!("{} secrets", names.len())
                };
                let mut d = vec![format!("\u{2192} {}", where_secrets(&plan.stores))];
                if *whole {
                    d.push("the store folder is kept, still encrypted, in the run folder.".into());
                }
                line(&mut s, n, "secrets", &what, &d);
            }
            Object::Backup { volume } => {
                let url = volume
                    .backup
                    .as_ref()
                    .map(|b| b.repository.clone())
                    .unwrap_or_default();
                line(
                    &mut s,
                    n,
                    "backup",
                    &format!("of volume {} (restic)", volume.name),
                    &[
                        "stays encrypted; it will open with your own password.".into(),
                        "sealctl's key and the backup schedule are removed.".into(),
                        "Backups no longer run by themselves.".into(),
                        format!("repository: {url}"),
                    ],
                );
            }
            Object::Volume { volume } => line(
                &mut s,
                n,
                "volume",
                &format!("{} ({})", volume.name, kind_label(volume.kind)),
                &[format!(
                    "{} stays encrypted; it will open with your own passphrase.",
                    volume.name
                )],
            ),
            Object::Ssh { keys } => {
                let what = if keys.len() == 1 {
                    keys[0].name.clone()
                } else {
                    format!("{} keys", keys.len())
                };
                let dests: Vec<String> = keys.iter().map(|k| tilde(&k.dest)).collect();
                let pass = if plan.no_ssh_passphrase {
                    "without a passphrase".to_string()
                } else {
                    "with your own passphrase".to_string()
                };
                let mut d = vec![format!("\u{2192} {} {pass}", dests.join(", "))];
                if cfg!(target_os = "macos") && !plan.no_ssh_passphrase {
                    d.push("added to the macOS keychain and ssh-agent.".into());
                }
                d.push("sealctl's IdentityAgent lines in ~/.ssh/config are removed.".into());
                line(&mut s, n, "ssh keys", &what, &d);
            }
            Object::Git { configs } => {
                let what = match (configs.iter().filter(|c| c.global).count(), configs.len()) {
                    (1, 1) => "global signing".to_string(),
                    (g, t) if g > 0 && t - g == 1 => "global + 1 repository".to_string(),
                    (g, t) if g > 0 => format!("global + {} repositories", t - g),
                    (_, 1) => "1 repository".to_string(),
                    (_, t) => format!("{t} repositories"),
                };
                line(
                    &mut s,
                    n,
                    "git",
                    &what,
                    &["keeps signing with your key through ssh-keygen.".into()],
                );
            }
            Object::Ai { tools } => {
                let names = ai_names(tools);
                let mut d = vec!["hooks, skill and deny rules removed.".to_string()];
                match plan.env_rules {
                    Some(true) => d.push("rules that keep agents away from .env files are kept.".into()),
                    Some(false) => d.push("no .env rules are left behind.".into()),
                    None => {}
                }
                line(&mut s, n, "AI tools", &names.join(", "), &d);
            }
            Object::Services { labels, agent } => {
                let mut names: Vec<String> = labels
                    .iter()
                    .map(|l| l.trim_start_matches(crate::service::LABEL_PREFIX).to_string())
                    .collect();
                if *agent {
                    names.push("session agent".into());
                }
                line(
                    &mut s,
                    n,
                    "services",
                    &names.join(", "),
                    &["stopped and removed.".into()],
                );
            }
            Object::LocalState => line(
                &mut s,
                n,
                "local files",
                "",
                &[
                    "~/.config/sealctl, ~/.local/share/sealctl, ~/.local/state/sealctl removed;".into(),
                    "the store and certificate are kept in the run folder.".into(),
                ],
            ),
        }
    }
    if plan.all {
        s.push_str(&format!("{:4}{:<12} {}\n", "", "last, by you", uninstall_hint()));
    }
    if !plan.skipped.is_empty() {
        s.push_str(&format!(
            "\nLeft out: {}. sealctl's services and settings stay so that these keep working.\n",
            plan.skipped.join(", ")
        ));
    }
    if !plan.problems.is_empty() {
        s.push_str("\nTo fix before it can start:\n");
        for p in &plan.problems {
            s.push_str(&format!("  - {p}\n"));
        }
    }
    s
}

fn where_secrets(cfg: &store::Config) -> String {
    match cfg.secrets_to {
        StoreKind::Keychain => format!("{}, service {}", StoreKind::Keychain.describe(), store::SERVICE),
        StoreKind::Env => tilde(
            &cfg.env_file
                .clone()
                .or_else(|| store::default_env_file().ok())
                .unwrap_or_default(),
        ),
        k => k.describe().to_string(),
    }
}

fn ai_names(ids: &[String]) -> Vec<String> {
    let names: std::collections::BTreeMap<&str, &str> = crate::ai::tool_names().into_iter().collect();
    ids.iter()
        .map(|i| {
            names
                .get(i.as_str())
                .map(|n| n.to_string())
                .unwrap_or_else(|| i.clone())
        })
        .collect()
}

// ---------------------------------------------------------------- terminal ----

/// Read one line from stdin (the confirmations).
fn ask(prompt: &str) -> Result<String> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn choose_store(question: &str, offered: &[StoreKind]) -> Result<StoreKind> {
    eprintln!("{question}");
    for (i, k) in offered.iter().enumerate() {
        eprintln!("  {}  {:<9} {}", i + 1, k.as_str(), k.describe());
    }
    for _ in 0..3 {
        let a = ask("Choose a number: ")?;
        if let Some(k) = a
            .parse::<usize>()
            .ok()
            .and_then(|i| i.checked_sub(1))
            .and_then(|i| offered.get(i))
        {
            return Ok(*k);
        }
        if let Some(k) = offered.iter().find(|k| k.as_str() == a) {
            return Ok(*k);
        }
    }
    Err(exit(2, "no store chosen"))
}

/// Pick the stores: the flags, else the keychain when there is one, else a question listing the
/// stores present.
fn stores_config(opts: &Options, interactive: bool) -> Result<store::Config> {
    let present = store::available();
    let to = match opts.to {
        Some(k) => k,
        None if present.contains(&StoreKind::Keychain) => StoreKind::Keychain,
        None if interactive => choose_store("Where should new passwords go?", &present)?,
        None => *present.first().unwrap_or(&StoreKind::Show),
    };
    let secrets_to = match opts.secrets_to {
        Some(k) => k,
        None if to != StoreKind::Show => to,
        None if present.contains(&StoreKind::Keychain) => StoreKind::Keychain,
        None => {
            let mut offered: Vec<StoreKind> = present.into_iter().filter(|k| *k != StoreKind::Show).collect();
            offered.push(StoreKind::Env);
            if interactive {
                choose_store("Where should secrets go?", &offered)?
            } else {
                offered[0]
            }
        }
    };
    Ok(store::Config {
        to,
        secrets_to,
        env_file: opts.env_file.clone(),
        op_vault: opts.op_vault.clone(),
        bw_folder: opts.bw_folder.clone(),
        type_passwords: opts.type_passwords,
    })
}

/// Build the plan (no changes).
pub fn build_plan(opts: &Options, interactive: bool) -> Result<Plan> {
    let (objects, skipped) = discover(opts)?;
    let stores = stores_config(opts, interactive && !opts.dry_run)?;
    let problems = problems(&objects, &stores);
    Ok(Plan {
        sealctl: 1,
        kind: "unseal-plan".into(),
        created: crate::util::local_time().1,
        machine: crate::util::machine_name(),
        from: env!("CARGO_PKG_VERSION").into(),
        all: opts.all,
        stores,
        no_ssh_passphrase: opts.no_ssh_passphrase,
        keep_store: opts.keep_store,
        env_rules: opts.env_rules,
        objects,
        skipped,
        problems,
    })
}

// ---------------------------------------------------------------- Ctrl-C ----

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

/// Ctrl-C lets the current step finish; the run stops before the next one.
fn catch_ctrl_c() {
    // SAFETY: the handler only stores to an atomic.
    unsafe {
        libc::signal(libc::SIGINT, on_sigint as *const () as libc::sighandler_t);
    }
}

pub fn interrupted() -> bool {
    INTERRUPTED.load(Ordering::SeqCst)
}

// ---------------------------------------------------------------- the run ----

/// Where keys come from.
pub enum Keys {
    /// The Ledger, through the session agent (PIN asked once).
    Ledger(crate::Ctx),
    /// The Ledger's 24 words, checked against the certificate (as `recover` does).
    Words,
}

/// State of one run while it executes.
pub struct Runner {
    pub run: journal::Run,
    pub plan: Plan,
    pub stores: store::Stores,
    keys: Keys,
    oracle: Option<Box<dyn Oracle>>,
    /// Problems reported at the end with exit 11 (a busy or unmountable volume).
    pub busy: Vec<String>,
    /// Lines for the end text.
    pub notes: Vec<String>,
}

impl Runner {
    /// The key source, opened on first use.
    pub fn oracle(&mut self) -> Result<&mut dyn Oracle> {
        if self.oracle.is_none() {
            let o: Box<dyn Oracle> = match &self.keys {
                Keys::Ledger(ctx) => crate::agent::oracle(ctx)?,
                Keys::Words => words_oracle(&self.run.dir)?,
            };
            self.oracle = Some(o);
        }
        Ok(self.oracle.as_mut().expect("set").as_mut())
    }

    /// Run one journaled step: skipped when the journal says it is done; otherwise `start`,
    /// the step (which first checks whether it already took effect), then `done` with a note
    /// and data, or `failed`.
    pub fn step(
        &mut self,
        id: &str,
        f: impl FnOnce(&mut Runner) -> Result<(String, Option<Value>)>,
    ) -> Result<Option<Value>> {
        if self.run.is_done(id) {
            return Ok(self.run.data(id).cloned());
        }
        if interrupted() {
            return Err(exit(13, "stopped (Ctrl-C)"));
        }
        self.run.start(id)?;
        match f(self) {
            Ok((note, data)) => {
                self.run.done(id, &note, data.clone())?;
                Ok(data)
            }
            Err(e) => {
                let first = format!("{e:#}");
                let first = first.lines().next().unwrap_or("").to_string();
                let _ = self.run.failed(id, &first);
                Err(e.context(format!("step {id}")))
            }
        }
    }

    /// Copy a file into the run folder before its first edit.
    pub fn before_edit(&self, file: &Path) -> Result<()> {
        self.run.backup_file(file)
    }

    /// Store a value with `put_checked`, copying a `.env` store file first.
    pub fn store(&mut self, kind: StoreKind, item: &store::Item, value: &[u8]) -> Result<store::Location> {
        let run = &self.run;
        let before = |f: &Path| run.backup_file(f);
        self.stores.put_checked(kind, item, value, &before)
    }
}

fn words_oracle(run_dir: &Path) -> Result<Box<dyn Oracle>> {
    eprintln!(
        "These words also guard anything else on your Ledger. Type them only if the Ledger is lost or broken."
    );
    let expected = match crate::recover::expected_public() {
        Ok(k) => k,
        Err(e) => {
            // after the local files step, the certificate is in the run folder
            let kept = run_dir.join("kept").join("keys");
            let cert = std::fs::read_dir(&kept)
                .ok()
                .and_then(|rd| {
                    rd.flatten()
                        .map(|e| e.path())
                        .find(|p| p.extension().is_some_and(|x| x == "asc"))
                })
                .and_then(|p| crate::cert::read(&p).ok());
            match cert.as_ref().and_then(crate::recover::cert_decryption_key) {
                Some(k) => k,
                None => return Err(e),
            }
        }
    };
    let words = crate::util::read_hidden("Recovery phrase (24 words, separated by spaces): ")?;
    if words.split_whitespace().count() < 12 {
        bail!("expected 12 to 24 words");
    }
    let key =
        crate::recover::recover_key(&words, "", 0, &expected).map_err(|e| exit(10, format!("{e:#}")))?;
    Ok(Box::new(crate::recover::SeedOracle(key)))
}

/// `sealctl unseal`: plan, confirm, run (or resume). `interactive` is false only in tests.
pub fn run(opts: Options, dev: crate::Ctx) -> Result<()> {
    if opts.all && opts.target.is_some() {
        return Err(exit(2, "name one object, or --all, not both"));
    }
    if !opts.all && opts.target.is_none() && !opts.resume {
        return Err(exit(2, format!("name what to unseal: {TARGETS}, or --all")));
    }
    if opts.env_file.is_some() && opts.secrets_to.is_some_and(|k| k != StoreKind::Env) {
        return Err(exit(2, "--env-file goes with --secrets-to env"));
    }
    let keys = if opts.words {
        Keys::Words
    } else {
        Keys::Ledger(dev)
    };

    // an unfinished run comes first
    let unfinished = journal::Run::unfinished()?;
    if opts.resume || (unfinished.is_some() && !opts.dry_run) {
        let Some(dir) = unfinished else {
            return Err(exit(2, "there is no unfinished sealctl unseal run"));
        };
        if !opts.resume {
            let started = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            let hhmm = started
                .split('T')
                .nth(1)
                .map(|t| t.split('-').take(2).collect::<Vec<_>>().join(":"))
                .unwrap_or(started.clone());
            let a = ask(&format!("Resume the run from {hhmm}? [Y/n] "))?;
            if a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no") {
                return Err(exit(
                    2,
                    format!(
                        "an unfinished run is in {}. Finish it first: sealctl unseal --resume",
                        tilde(&dir)
                    ),
                ));
            }
        }
        let run = journal::Run::open(&dir)?;
        let plan: Plan = run.read_json("plan.json")?;
        eprintln!("Resuming the run in {}.", tilde(&dir));
        return execute(run, plan, keys);
    }

    let mut plan = build_plan(&opts, true)?;
    if let Some(dir) = unfinished.as_ref().filter(|_| opts.dry_run) {
        eprintln!(
            "Note: a run stopped part way in {}; sealctl unseal --resume continues it.\n",
            tilde(dir)
        );
    }
    if plan.objects.is_empty() {
        eprintln!(
            "sealctl holds nothing on {} that unseal hands back.",
            machine_word()
        );
        if opts.json {
            println!("{}", serde_json::to_string(&plan)?);
        }
        return Ok(());
    }
    eprint!("{}", plan_text(&plan, opts.words));
    if opts.dry_run {
        if opts.json {
            println!("{}", serde_json::to_string_pretty(&plan)?);
        }
        eprintln!("\nDry run: nothing was changed.");
        return Ok(());
    }
    if !plan.problems.is_empty() {
        return Err(exit(
            9,
            "fix the problems above first (or leave the object out with --skip)",
        ));
    }
    eprintln!();
    if plan.objects.iter().any(|o| matches!(o, Object::Ai { .. })) && plan.env_rules.is_none() {
        let a = ask("Keep the rules that stop AI agents reading .env files? [Y/n] ")?;
        plan.env_rules = Some(!(a.eq_ignore_ascii_case("n") || a.eq_ignore_ascii_case("no")));
    }
    let run = journal::Run::create()?;
    eprintln!(
        "Run folder: {}. If anything stops, run: sealctl unseal --resume",
        tilde(&run.dir)
    );
    let go = if plan.all {
        ask("Type unseal to start: ")? == "unseal"
    } else {
        matches!(ask("Start? [y/N] ")?.as_str(), "y" | "Y" | "yes")
    };
    if !go {
        // nothing changed: the run folder goes again
        let dir = run.dir.clone();
        drop(run);
        let _ = std::fs::remove_dir_all(&dir);
        eprintln!("Nothing was changed.");
        return Ok(());
    }
    run.write_json("plan.json", &plan)?;
    execute(run, plan, keys)
}

fn execute(run: journal::Run, plan: Plan, keys: Keys) -> Result<()> {
    catch_ctrl_c();
    let mut r = Runner {
        stores: store::Stores::new(plan.stores.clone()),
        run,
        plan,
        keys,
        oracle: None,
        busy: vec![],
        notes: vec![],
    };
    let total = r.plan.objects.len();
    let objects = r.plan.objects.clone();
    for (i, o) in objects.iter().enumerate() {
        let res = objects::run(&mut r, o);
        // the hand-back list is current after every object
        let _ = r.run.write_json("handback.json", &objects::handback(&r));
        match res {
            Ok(summary) => eprintln!("[{}/{total}] {summary}", i + 1),
            Err(e) => return Err(stopped(&r, o, e)),
        }
    }
    r.run.write_json("handback.json", &objects::handback(&r))?;
    r.run.finish()?;
    end_text(&r);
    if !r.plan.skipped.is_empty() {
        return Err(exit(
            13,
            format!(
                "Left out: {}. sealctl stays installed and set up for them; hand them back later with sealctl unseal.",
                r.plan.skipped.join(", ")
            ),
        ));
    }
    if !r.busy.is_empty() {
        return Err(exit(11, r.busy.join("\n")));
    }
    Ok(())
}

/// The message when a step fails: which key opens the object now, and how to go on.
fn stopped(r: &Runner, o: &Object, e: anyhow::Error) -> anyhow::Error {
    let code = exit_code(&e).filter(|c| [2, 9, 10, 11].contains(c)).unwrap_or(13);
    let now = objects::opens_now(r, o);
    exit(
        code,
        format!(
            "{e:#}\n{now}\nRun folder: {}\nRun sealctl unseal --resume after fixing this.",
            tilde(&r.run.dir)
        ),
    )
}

fn end_text(r: &Runner) {
    let h = objects::handback(r);
    let mut stores: Vec<String> = vec![];
    for o in &h.objects {
        for l in o.password.iter().chain(o.value.iter()) {
            let d = match l.store {
                StoreKind::Keychain => format!(
                    "{}, service {}",
                    StoreKind::Keychain.describe(),
                    l.service.as_deref().unwrap_or(store::SERVICE)
                ),
                StoreKind::Env => l.file.as_deref().map(tilde).unwrap_or_else(|| ".env file".into()),
                k => k.describe().to_string(),
            };
            if !stores.contains(&d) {
                stores.push(d);
            }
        }
    }
    let run_dir = tilde(&r.run.dir);
    if r.plan.all {
        eprintln!("\nDone. sealctl 0.5 holds nothing on {}.", machine_word());
    } else {
        eprintln!("\nDone.");
    }
    if !stores.is_empty() {
        eprintln!("Your passwords: {}.", stores.join("; "));
    }
    for n in &r.notes {
        eprintln!("{n}");
    }
    eprintln!("Hand-back list: {run_dir}/handback.json (no passwords in it).");
    eprintln!("The run folder {run_dir} can be deleted once everything opens with your new passwords.");
    if r.plan.all {
        eprintln!("Next: install sealctl 0.7 and run sealctl seal --from that file. Or remove sealctl:");
        eprintln!("  {}", uninstall_hint());
        eprintln!("Keep your Ledger and paper card until no old copies of these backups or volumes remain.");
    }
}

/// The newest unfinished run folder, for `doctor` and `status`.
pub fn unfinished_run() -> Option<PathBuf> {
    journal::Run::unfinished().ok().flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn targets_parse() {
        let w = |s: &str| s.split_whitespace().map(String::from).collect::<Vec<_>>();
        assert_eq!(parse_target(&w("secrets")).unwrap(), Target::Secrets);
        assert_eq!(
            parse_target(&w("secret shop/key")).unwrap(),
            Target::Secret("shop/key".into())
        );
        assert_eq!(
            parse_target(&w("volume safe")).unwrap(),
            Target::Volume("safe".into())
        );
        assert_eq!(
            parse_target(&w("backup safe")).unwrap(),
            Target::Backup("safe".into())
        );
        assert_eq!(
            parse_target(&w("ssh ed25519")).unwrap(),
            Target::Ssh("ed25519".into())
        );
        assert_eq!(parse_target(&w("git")).unwrap(), Target::Git);
        assert_eq!(
            parse_target(&w("ai claude codex")).unwrap(),
            Target::Ai(vec!["claude".into(), "codex".into()])
        );
        for bad in ["", "volume", "volume a b", "git x", "nonsense"] {
            let e = parse_target(&w(bad)).unwrap_err();
            assert_eq!(exit_code(&e), Some(2), "{bad}");
        }
    }

    #[test]
    fn ssh_destinations_avoid_taken_names() {
        let t = tempfile::tempdir().unwrap();
        let d = t.path();
        assert_eq!(ssh_dest(d, "ed25519", &[]), d.join("ed25519"));
        std::fs::write(d.join("ed25519"), "x").unwrap();
        assert_eq!(ssh_dest(d, "ed25519", &[]), d.join("ed25519-1"));
        std::fs::write(d.join("ed25519-1.pub"), "x").unwrap();
        assert_eq!(
            ssh_dest(d, "ed25519", &[d.join("ed25519-2")]),
            d.join("ed25519-3")
        );
    }
}
