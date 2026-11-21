//! `sealctl unseal`: the inverse of sealing. Everything sealctl holds comes back to the user in
//! plain, standard form, so they can leave the Ledger version (0.6.0) — and install 0.7 and
//! `seal` each object, or stop using sealctl.
//!
//! By default everything goes into one visible folder, `~/sealctl-unsealed-<date>` (0700):
//! volumes and backups stay encrypted under a new random password written to `passwords.txt`
//! first; SSH keys become plain key files without a passphrase; secrets go to `secrets.env`;
//! restic settings to `backup-<volume>.env`. Nothing goes to Keychain, 1Password or Bitwarden
//! unless asked (`--to`, `--secrets-to`). The person deletes the folder; sealctl never does.
//!
//! Rules (SPEC.md section 18, 24.1):
//! * plan first: nothing changes before the plan is shown and confirmed (`y` for one object,
//!   the typed word `unseal` for `--all`); `--dry-run` only shows it;
//! * write-ahead: a new password is durable where it was stored (file and directory `fsync`ed)
//!   and read back before anything depends on it; every object is opened with it before
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
    /// The run folder: `~/sealctl-unsealed-<date>` (the next free name when the run starts).
    #[serde(default)]
    pub folder: PathBuf,
    /// AI tools on this machine that get rules keeping their agents out of the folder.
    #[serde(default)]
    pub ai_rules: Vec<String>,
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
    let cfg = &plan.stores;
    if plan.all {
        s.push_str(&format!(
            "This hands everything sealctl 0.5 holds on {} back to you, in plain, standard form.\n",
            machine_word()
        ));
    } else {
        s.push_str("This hands the object below back to you, in plain, standard form.\n");
    }
    if words {
        s.push_str("Keys come from your 24 words.\n\n");
    } else {
        s.push_str("Keys come from your Ledger: keep it connected with the OpenPGP app open.\n\n");
    }
    let has = |f: fn(&Object) -> bool| plan.objects.iter().any(f);
    let vols = has(|o| matches!(o, Object::Volume { .. }));
    let backups = has(|o| matches!(o, Object::Backup { .. }));
    let ssh = has(|o| matches!(o, Object::Ssh { .. }));
    let secrets = has(|o| matches!(o, Object::Secrets { .. }));
    let folder = tilde(&plan.folder);
    s.push_str(&format!("Everything goes into one new folder: {folder}\n"));
    let mut points: Vec<String> = vec![];
    if vols || backups {
        let what = match (vols, backups) {
            (true, true) => "volumes and backups stay",
            (true, false) => "volumes stay",
            _ => "backups stay",
        };
        points.push(if cfg.to == StoreKind::Folder {
            format!(
                "{what} encrypted; each gets a new random password, saved in passwords.txt in the folder before it is set"
            )
        } else {
            format!("{what} encrypted; each gets a new password, kept in {}", cfg.to.describe())
        });
    }
    if backups && cfg.secrets_to == StoreKind::Folder {
        points.push(
            "restic settings (repository, password, storage credentials) go into backup-<volume>.env".into(),
        );
    }
    if ssh {
        points.push(if plan.no_ssh_passphrase {
            "SSH keys end with no passphrase: plain key files in ~/.ssh".into()
        } else {
            format!("SSH keys get a new passphrase, kept in {}", cfg.to.describe())
        });
    }
    if secrets {
        points.push(match cfg.secrets_to {
            StoreKind::Folder => "secrets are written in plain form into secrets.env in the folder".into(),
            StoreKind::Env => format!("secrets are written in plain form into {}", where_secrets(cfg)),
            k => format!("secrets go to {}", k.describe()),
        });
    }
    let n = points.len();
    for (i, p) in points.iter().enumerate() {
        let end = if i + 1 == n { "." } else { ";" };
        s.push_str(&wrap(&format!("- {p}{end}"), "  ", "    "));
    }
    let external = |k: StoreKind| !matches!(k, StoreKind::Folder | StoreKind::Env);
    let uses_to = vols || backups || (ssh && !plan.no_ssh_passphrase);
    let uses_secrets = secrets || backups;
    if !(uses_to && external(cfg.to)) && !(uses_secrets && external(cfg.secrets_to)) {
        s.push_str(
            "  Nothing is written to Keychain, 1Password or Bitwarden (--to keychain|op|bw|show for that).\n",
        );
    }
    if cfg.secrets_to == StoreKind::Env && uses_secrets {
        s.push_str(&format!(
            "  {}: This file holds your keys in plain text, where AI agents can read them.\n  \
             Move them to a password manager, then delete it.\n",
            where_secrets(cfg)
        ));
    }
    let mut guard = String::from("  Only you can read the folder");
    if !plan.ai_rules.is_empty() {
        guard.push_str(&format!(
            "; {} {} told not to read it",
            ai_names(&plan.ai_rules).join(", "),
            if plan.ai_rules.len() == 1 { "is" } else { "are" }
        ));
    }
    if cfg!(target_os = "macos") {
        guard.push_str("; Time Machine skips it");
    }
    guard.push_str(".\n");
    s.push_str(&guard);
    s.push_str("  Delete it yourself once the new passwords and keys work. sealctl never deletes it.\n");
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
                let mut d = vec![format!("\u{2192} {}", where_secrets(cfg))];
                if *whole {
                    d.push("the store folder is kept, still encrypted, in the folder.".into());
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
                        format!(
                            "stays encrypted; it will open with a new password ({}).",
                            where_password(cfg)
                        ),
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
                    "{} stays encrypted; it will open with a new passphrase ({}).",
                    volume.name,
                    where_password(cfg)
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
                    "with no passphrase".to_string()
                } else {
                    "with your own passphrase".to_string()
                };
                let mut d = vec![format!("\u{2192} {} {pass}", dests.join(", "))];
                if cfg!(target_os = "macos") && cfg.to != StoreKind::Folder && !plan.no_ssh_passphrase {
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
                    "the store and certificate are kept, encrypted, in the folder.".into(),
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

/// `text` wrapped at 92 columns: `first` before the first line, `rest` before the others.
fn wrap(text: &str, first: &str, rest: &str) -> String {
    let mut out = String::new();
    let mut cur = first.to_string();
    let mut empty = true;
    for w in text.split(' ') {
        if !empty && cur.len() + 1 + w.len() > 92 {
            out.push_str(&cur);
            out.push('\n');
            cur = rest.to_string();
            empty = true;
        }
        if !empty {
            cur.push(' ');
        }
        cur.push_str(w);
        empty = false;
    }
    out.push_str(&cur);
    out.push('\n');
    out
}

/// Where new passwords go, short (the plan's object lines).
fn where_password(cfg: &store::Config) -> String {
    match cfg.to {
        StoreKind::Folder => "passwords.txt".into(),
        StoreKind::Keychain => format!("{}, service {}", StoreKind::Keychain.describe(), store::SERVICE),
        k => k.describe().to_string(),
    }
}

fn where_secrets(cfg: &store::Config) -> String {
    match cfg.secrets_to {
        StoreKind::Folder => "secrets.env in the folder, plain".into(),
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

/// Pick the stores: the flags, else the run folder (`--to` alone sends secrets to the same
/// store, as before; `--to show` sends them to the folder).
fn stores_config(opts: &Options) -> store::Config {
    let to = opts.to.unwrap_or(StoreKind::Folder);
    let secrets_to = match opts.secrets_to {
        Some(k) => k,
        None if to == StoreKind::Show => StoreKind::Folder,
        None => to,
    };
    store::Config {
        to,
        secrets_to,
        env_file: opts.env_file.clone(),
        op_vault: opts.op_vault.clone(),
        bw_folder: opts.bw_folder.clone(),
        type_passwords: opts.type_passwords,
    }
}

/// Build the plan (no changes).
pub fn build_plan(opts: &Options) -> Result<Plan> {
    let (objects, skipped) = discover(opts)?;
    let stores = stores_config(opts);
    let problems = problems(&objects, &stores);
    // with the folder, SSH keys end without a passphrase (the owner's decision: plain, standard
    // key files; a passphrase can be added with ssh-keygen -p)
    let no_ssh_passphrase = opts.no_ssh_passphrase || stores.to == StoreKind::Folder;
    Ok(Plan {
        sealctl: 1,
        kind: "unseal-plan".into(),
        created: crate::util::local_time().1,
        machine: crate::util::machine_name(),
        from: env!("CARGO_PKG_VERSION").into(),
        all: opts.all,
        stores,
        folder: journal::next_dir()?,
        ai_rules: crate::ai::unsealed_rule_tools()
            .into_iter()
            .map(String::from)
            .collect(),
        no_ssh_passphrase,
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
            let a = ask(&format!("Resume the run in {}? [Y/n] ", tilde(&dir)))?;
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

    let mut plan = build_plan(&opts)?;
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
    eprintln!("If anything stops, run: sealctl unseal --resume");
    let go = if plan.all {
        ask("Type unseal to start: ")? == "unseal"
    } else {
        matches!(ask("Start? [y/N] ")?.as_str(), "y" | "Y" | "yes")
    };
    if !go {
        eprintln!("Nothing was changed.");
        return Ok(());
    }
    // the folder is made only now, under the next free name
    let run = journal::Run::create(&plan.folder)?;
    plan.folder = run.dir.clone();
    run.write_json("plan.json", &plan)?;
    execute(run, plan, keys)
}

fn execute(run: journal::Run, plan: Plan, keys: Keys) -> Result<()> {
    catch_ctrl_c();
    let mut stores = store::Stores::new(plan.stores.clone());
    stores.folder = Some(run.dir.clone());
    let mut r = Runner {
        stores,
        run,
        plan,
        keys,
        oracle: None,
        busy: vec![],
        notes: vec![],
    };
    if let Err(e) = prepare(&mut r) {
        return Err(exit(
            exit_code(&e).unwrap_or(13),
            format!(
                "{e:#}\nNothing was handed back yet.\nRun folder: {}\nRun sealctl unseal --resume after fixing this.",
                tilde(&r.run.dir)
            ),
        ));
    }
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

/// The first steps of every run, before anything is written in plain form: README.txt, the
/// Time Machine exclusion (macOS) and the AI rules that keep agents out of the folder.
fn prepare(r: &mut Runner) -> Result<()> {
    r.step("folder:readme", |r| {
        let text = readme_text(&r.plan, &r.run.dir);
        r.run.write_file("README.txt", text.as_bytes())?;
        Ok(("README.txt written".into(), None))
    })?;
    if cfg!(target_os = "macos") {
        r.step("folder:tmutil", |r| {
            let out = crate::util::system_cmd("tmutil")
                .arg("addexclusion")
                .arg(&r.run.dir)
                .stdin(std::process::Stdio::null())
                .output();
            let note = match out {
                Ok(o) if o.status.success() => {
                    "Time Machine skips the folder (tmutil addexclusion)".to_string()
                }
                Ok(o) => format!(
                    "tmutil addexclusion failed ({}); Time Machine may back the folder up",
                    String::from_utf8_lossy(&o.stderr)
                        .lines()
                        .next()
                        .unwrap_or("")
                        .trim()
                ),
                Err(e) => format!("tmutil not run ({e}); Time Machine may back the folder up"),
            };
            Ok((note, None))
        })?;
    }
    let tools = r.plan.ai_rules.clone();
    if !tools.is_empty() {
        r.step("folder:ai-rules", |r| {
            for t in &tools {
                let Some(f) = crate::ai::unsealed_rules_file(t) else {
                    continue;
                };
                r.before_edit(&f)?;
                crate::ai::write_unsealed_rules(t)?;
                crate::ai::still_parses(&f)?;
            }
            Ok((
                format!(
                    "rules that keep agents out of ~/sealctl-unsealed-*: {}",
                    tools.join(", ")
                ),
                None,
            ))
        })?;
    }
    Ok(())
}

/// README.txt of the run folder: what is in it, how to check each item by hand, and to delete
/// it. No values.
pub fn readme_text(plan: &Plan, dir: &Path) -> String {
    let d = tilde(dir);
    let cfg = &plan.stores;
    let mut s = String::new();
    s.push_str(&format!(
        "sealctl unseal on {}, {}\n\n\
         This folder holds what sealctl handed back to you, in plain, standard form. Only you can\n\
         read it (mode 0700). It may hold passwords, secrets and SSH keys in plain text: keep it\n\
         off shared drives and synced folders. {}\n\n\
         Check that everything below opens, keep the passwords where you keep passwords, then\n\
         delete this folder:\n\n    rm -rf {d}\n\n\
         sealctl never deletes it.\n\n",
        plan.machine,
        plan.created,
        if plan.ai_rules.is_empty() {
            "Keep AI agents away from it."
        } else {
            "AI agents are told not to read it."
        }
    ));
    s.push_str("What is here\n------------\n");
    let mut rows: Vec<(String, String)> = vec![];
    let backups: Vec<&Volume> = plan
        .objects
        .iter()
        .filter_map(|o| match o {
            Object::Backup { volume } => Some(volume),
            _ => None,
        })
        .collect();
    let has_vols = plan.objects.iter().any(|o| matches!(o, Object::Volume { .. }));
    if cfg.to == StoreKind::Folder && (has_vols || !backups.is_empty()) {
        rows.push((
            store::folder::PASSWORDS.into(),
            "new volume passphrases and restic passwords, one per line".into(),
        ));
    }
    if cfg.secrets_to == StoreKind::Folder {
        if plan.objects.iter().any(|o| matches!(o, Object::Secrets { .. })) {
            rows.push((
                store::folder::SECRETS.into(),
                "the secrets of sealctl's store, plain (a shell can source it)".into(),
            ));
        }
        for v in &backups {
            rows.push((
                store::folder::backup_env(&v.name),
                "restic: repository, password, storage credentials".into(),
            ));
        }
    }
    rows.push((
        "handback.json".into(),
        "what was handed back, where each password went (no passwords)".into(),
    ));
    rows.push((
        "files/".into(),
        "every file sealctl edited, as it was before".into(),
    ));
    rows.push((
        "kept/".into(),
        "sealctl's originals, still encrypted to the Ledger".into(),
    ));
    rows.push((
        "plan.json, journal.jsonl".into(),
        "the run (sealctl unseal --resume reads them)".into(),
    ));
    for (f, what) in rows {
        s.push_str(&format!("  {f:<26} {what}\n"));
    }
    let pw = |label: &str| -> String {
        match cfg.to {
            StoreKind::Folder => format!("the line \"{label}\" in {d}/passwords.txt"),
            k => format!("in {} (\"sealctl: {label}\")", k.describe()),
        }
    };
    s.push_str("\nCheck each item by hand\n-----------------------\n");
    for o in &plan.objects {
        match o {
            Object::Volume { volume: v } => {
                let label = format!("volume {}", v.name);
                let path = v
                    .path
                    .as_deref()
                    .map(|p| p.display().to_string())
                    .unwrap_or_default();
                let (open, change) = match v.kind {
                    Kind::ApfsVolume => (
                        format!("diskutil apfs unlockVolume {}", v.id),
                        format!("diskutil apfs changePassphrase {} -user disk", v.id),
                    ),
                    Kind::Sparsebundle => (
                        format!("hdiutil attach \"{path}\""),
                        format!("hdiutil chpass \"{path}\""),
                    ),
                    Kind::Luks => (
                        format!("sudo cryptsetup open --test-passphrase \"{path}\""),
                        format!("sudo cryptsetup luksChangeKey \"{path}\""),
                    ),
                };
                s.push_str(&format!(
                    "\nVolume {} ({}), still encrypted. Its passphrase: {}.\n    {open}\n\
                     \x20 To choose your own passphrase: {change}{}\n",
                    v.name,
                    kind_label(v.kind),
                    pw(&label),
                    if v.kind == Kind::Luks {
                        ""
                    } else {
                        " (or Disk Utility)"
                    }
                ));
            }
            Object::Backup { volume: v } => {
                let repo = v.backup.as_ref().map(|b| b.repository.as_str()).unwrap_or("");
                s.push_str(&format!(
                    "\nBackup of volume {} (restic, {repo}), still encrypted. Its password: {}.\n",
                    v.name,
                    pw(&format!("backup {}", v.name))
                ));
                if cfg.secrets_to == StoreKind::Folder {
                    s.push_str(&format!(
                        "    set -a; . {d}/{}; set +a\n    restic snapshots\n",
                        store::folder::backup_env(&v.name)
                    ));
                } else {
                    s.push_str(&format!("    restic -r {repo} snapshots\n"));
                }
                s.push_str(
                    "  Backups no longer run by themselves: run restic backup yourself, or schedule it.\n\
                     \x20 Your own password: restic key passwd (with the same settings).\n",
                );
            }
            Object::Ssh { keys } => {
                s.push_str("\nSSH keys, standard OpenSSH files:\n");
                for k in keys {
                    let f = tilde(&k.dest);
                    if plan.no_ssh_passphrase {
                        s.push_str(&format!(
                            "    ssh-keygen -y -f {f}     prints the line in {f}.pub, asking nothing\n"
                        ));
                    } else {
                        s.push_str(&format!(
                            "    ssh-keygen -y -f {f}     asks for the passphrase ({}), prints the line in {f}.pub\n",
                            pw(&format!("ssh {}", k.name))
                        ));
                    }
                }
                if plan.no_ssh_passphrase {
                    s.push_str("  They have no passphrase. To add one: ssh-keygen -p -f <key>\n");
                }
                s.push_str("  Then log in where you use them, e.g. ssh -T git@github.com\n");
            }
            Object::Git { .. } => {
                s.push_str(
                    "\nGit signing goes through standard ssh-keygen. In a repository:\n    \
                     git commit --allow-empty -m \"signing check\" && git log --show-signature -1\n",
                );
            }
            Object::Secrets { names, .. } => {
                match cfg.secrets_to {
                    StoreKind::Folder => {
                        s.push_str(&format!(
                            "\nSecrets: {d}/secrets.env (variable, then the secret's name in sealctl):\n"
                        ));
                        for (n, v) in store::env_vars(names) {
                            s.push_str(&format!("    {v:<32} {n}\n"));
                        }
                    }
                    k => s.push_str(&format!(
                        "\nSecrets: in {}.\n",
                        where_secrets(&store::Config {
                            secrets_to: k,
                            ..cfg.clone()
                        })
                    )),
                }
                s.push_str("  Programs that used `sealctl run` need another way to get them now.\n");
            }
            _ => {}
        }
    }
    s.push_str(
        "\nKeep your Ledger and its paper card until no old copies of these backups or volumes\n\
         remain (old snapshots of a disk, an old copy of a repository): those open only with the\n\
         Ledger. The originals in kept/ do too.\n",
    );
    s
}

fn end_text(r: &Runner) {
    let h = objects::handback(r);
    let mut stores: Vec<String> = vec![];
    for o in &h.objects {
        for l in o.password.iter().chain(o.value.iter()) {
            let d = match l.store {
                StoreKind::Folder => continue,
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
    let dir = &r.run.dir;
    let d = tilde(dir);
    if r.plan.all {
        eprintln!("\nDone. sealctl 0.5 holds nothing on {}.", machine_word());
    } else {
        eprintln!("\nDone.");
    }
    let mut rows: Vec<(String, String)> = vec![];
    let mut plain = false;
    if dir.join(store::folder::PASSWORDS).exists() {
        rows.push((
            store::folder::PASSWORDS.into(),
            "the new passwords of your volumes and backups".into(),
        ));
        plain = true;
    }
    if dir.join(store::folder::SECRETS).exists() {
        rows.push((
            store::folder::SECRETS.into(),
            "your secrets, in plain text".into(),
        ));
        plain = true;
    }
    if dir.join(store::folder::BINARY).exists() {
        rows.push((
            format!("{}/", store::folder::BINARY),
            "secrets that are not text, one file each".into(),
        ));
    }
    for o in &r.plan.objects {
        if let Object::Backup { volume } = o {
            let f = store::folder::backup_env(&volume.name);
            if dir.join(&f).exists() {
                rows.push((f, "restic settings (README.txt shows how to use them)".into()));
                plain = true;
            }
        }
    }
    rows.push(("README.txt".into(), "how to check each item by hand".into()));
    rows.push((
        "handback.json".into(),
        "the hand-back list (no passwords in it)".into(),
    ));
    eprintln!("Everything is in {d}:");
    for (f, what) in rows {
        eprintln!("  {f:<22} {what}");
    }
    if !stores.is_empty() {
        eprintln!("Your passwords: {}.", stores.join("; "));
    }
    let keys: Vec<String> = r
        .plan
        .objects
        .iter()
        .filter_map(|o| match o {
            Object::Ssh { keys } => Some(keys.iter().map(|k| tilde(&k.dest)).collect::<Vec<_>>()),
            _ => None,
        })
        .flatten()
        .collect();
    if !keys.is_empty() && r.plan.no_ssh_passphrase {
        eprintln!(
            "SSH keys: {}, with no passphrase (add one with ssh-keygen -p -f <key>).",
            keys.join(", ")
        );
    }
    for n in &r.notes {
        eprintln!("{n}");
    }
    if r.plan.all {
        eprintln!(
            "To move to sealctl 0.7: install it and run sealctl seal --from {d}/handback.json. Or remove sealctl:"
        );
        eprintln!("  {}", uninstall_hint());
        eprintln!("Keep your Ledger and paper card until no old copies of these backups or volumes remain.");
    }
    eprintln!("Once the new passwords and keys work, delete the folder:");
    eprintln!("  rm -rf {d}");
    if plain {
        eprintln!("It holds your passwords and secrets in plain text. sealctl never deletes it.");
    } else {
        eprintln!("sealctl never deletes it.");
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
