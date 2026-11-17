//! Encrypted, versioned backups of volumes with restic.
//!
//! How it works without a daemon:
//! * the restic password is **derived from the Ledger seed and the repository URL**
//!   (`crate::derive`, purpose "restic") — nothing to back up; with the 24 words and the
//!   repository URL you can always open the repository again;
//! * a cached copy of the password and the storage credentials live **inside the encrypted
//!   volume** (`<mount>/.sealctl/`), readable exactly while the volume is unlocked;
//! * a scheduled job runs `sealctl backup run --all --if-unlocked` (no Ledger needed), and
//!   `sealctl lock` runs a final backup before unmounting.

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::derive::{self, Oracle, Purpose};
use crate::volume::{BackupPolicy, Volume};
use crate::{paths, util};

/// Everything restic needs. Secret: stored only inside the encrypted volume.
#[derive(Serialize, Deserialize)]
pub struct RepoSecrets {
    pub repository: String,
    pub password: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

impl Drop for RepoSecrets {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        for v in self.env.values_mut() {
            v.zeroize();
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BackupState {
    pub last_success: Option<u64>,
    pub last_attempt: Option<u64>,
    pub last_error: Option<String>,
    pub last_prune: Option<u64>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn state_file(vol: &str) -> Result<PathBuf> {
    Ok(paths::state_dir()?.join("backup").join(format!("{vol}.toml")))
}

pub fn load_state(vol: &str) -> BackupState {
    state_file(vol)
        .ok()
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|t| toml::from_str(&t).ok())
        .unwrap_or_default()
}

fn save_state(vol: &str, s: &BackupState) -> Result<()> {
    let p = state_file(vol)?;
    fs::create_dir_all(p.parent().context("dir")?)?;
    fs::write(p, toml::to_string(s)?)?;
    Ok(())
}

pub fn restic_bin() -> String {
    std::env::var("SEALCTL_RESTIC").unwrap_or_else(|_| "restic".into())
}

fn inner_secrets_file(vol: &Volume) -> PathBuf {
    vol.inner_dir().join("backup.toml")
}

fn inner_password_file(vol: &Volume) -> PathBuf {
    vol.inner_dir().join("restic-password")
}

fn write_inner(vol: &Volume, s: &RepoSecrets) -> Result<()> {
    if let Err(e) = paths::ensure_private_dir(&vol.inner_dir()) {
        let denied = e
            .chain()
            .filter_map(|c| c.downcast_ref::<std::io::Error>())
            .any(|io| io.kind() == std::io::ErrorKind::PermissionDenied);
        if denied {
            // New APFS volumes have a root-owned top directory.
            anyhow::bail!(
                "{e:#}\n   The top folder of the volume is not yours. Fix it once (it stays on the volume):\n   \
                 sudo chown \"$USER\" {}",
                vol.mountpoint.display()
            );
        }
        return Err(e);
    }
    paths::write_private(&inner_secrets_file(vol), toml::to_string(s)?.as_bytes())?;
    paths::write_private(&inner_password_file(vol), s.password.as_bytes())?;
    Ok(())
}

fn read_inner(vol: &Volume) -> Result<RepoSecrets> {
    let text = Zeroizing::new(fs::read_to_string(inner_secrets_file(vol)).with_context(|| {
        format!(
            "backup settings missing in '{}' — run `sealctl backup init`",
            vol.name
        )
    })?);
    Ok(toml::from_str(&text)?)
}

enum Probe {
    Exists,
    Missing,
    WrongPassword,
}

/// How restic gets its password: a file inside the unlocked volume, or our stdin pipe.
enum Password {
    File(PathBuf),
    Pipe(Zeroizing<String>),
}

struct Repo {
    secrets: RepoSecrets,
    password: Password,
}

impl Repo {
    fn from_unlocked(vol: &Volume) -> Result<Repo> {
        Ok(Repo {
            secrets: read_inner(vol)?,
            password: Password::File(inner_password_file(vol)),
        })
    }

    /// Works while locked or lost too: the password is derived on the Ledger from the
    /// repository's key id; storage credentials come from the environment or a prompt.
    fn open(oracle: &mut dyn Oracle, vol: &Volume) -> Result<Repo> {
        if vol.is_unlocked().unwrap_or(false) && inner_secrets_file(vol).exists() {
            return Self::from_unlocked(vol);
        }
        let policy = vol
            .backup
            .as_ref()
            .filter(|b| !b.repository.is_empty())
            .context("no backup configured for this volume")?;
        Self::derived(oracle, &policy.repository, policy.password_id())
    }

    fn derived(oracle: &mut dyn Oracle, repository: &str, key_id: &str) -> Result<Repo> {
        let password = derive::passphrase(oracle, Purpose::Restic, key_id)?;
        let env = collect_env(repository, &[])?;
        Ok(Repo {
            secrets: RepoSecrets {
                repository: repository.to_string(),
                password: password.to_string(),
                env,
            },
            password: Password::Pipe(password),
        })
    }

    /// Does a repository exist at the URL, and does our password open it? (No output.)
    fn probe(&self) -> Result<Probe> {
        let mut c = self.command();
        c.args(["cat", "config"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        let out = c.output().context("starting restic")?;
        if out.status.success() {
            return Ok(Probe::Exists);
        }
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("does not exist") || err.contains("unable to open config file") {
            Ok(Probe::Missing)
        } else if err.contains("wrong password") || err.contains("no key found") {
            Ok(Probe::WrongPassword)
        } else {
            bail!("restic could not open the repository:\n{}", err.trim())
        }
    }

    /// The id of the restic key our password opens.
    fn current_key(&self) -> Result<String> {
        #[derive(serde::Deserialize)]
        struct Key {
            current: bool,
            id: String,
        }
        let out = self
            .command()
            .args(["key", "list", "--json"])
            .stdin(Stdio::null())
            .output()
            .context("starting restic")?;
        if !out.status.success() {
            bail!(
                "restic key list failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let keys: Vec<Key> = serde_json::from_slice(&out.stdout).context("parsing restic key list")?;
        keys.into_iter()
            .find(|k| k.current)
            .map(|k| k.id)
            .context("restic did not mark a current key")
    }

    fn command(&self) -> Command {
        let mut c = Command::new(restic_bin());
        c.env("RESTIC_REPOSITORY", &self.secrets.repository);
        for (k, v) in &self.secrets.env {
            c.env(k, v);
        }
        match &self.password {
            Password::File(p) => {
                c.env("RESTIC_PASSWORD_FILE", p);
            }
            Password::Pipe(_) => {
                c.env("RESTIC_PASSWORD_FILE", "/dev/stdin");
            }
        }
        c
    }

    /// Run restic with inherited stdout/stderr.
    fn run(&self, args: &[&str], quiet: bool) -> Result<()> {
        let mut c = self.command();
        c.args(args);
        if quiet {
            c.stdout(Stdio::null());
        }
        let status = match &self.password {
            Password::File(_) => c.stdin(Stdio::null()).status(),
            Password::Pipe(pw) => {
                c.stdin(Stdio::piped());
                let mut child = c.spawn().context("starting restic (is it installed?)")?;
                {
                    use std::io::Write;
                    let mut i = child.stdin.take().context("stdin")?;
                    i.write_all(pw.as_bytes())?;
                }
                child.wait()
            }
        }
        .context("starting restic (is it installed? brew install restic / apt install restic)")?;
        if !status.success() {
            bail!("restic {} failed ({status})", args.first().unwrap_or(&""));
        }
        Ok(())
    }
}

/// Credentials restic needs for common backends, asked for when not given.
fn needed_env(repo: &str) -> Vec<&'static str> {
    if repo.starts_with("s3:") {
        vec!["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    } else if repo.starts_with("b2:") {
        vec!["B2_ACCOUNT_ID", "B2_ACCOUNT_KEY"]
    } else if repo.starts_with("azure:") {
        vec!["AZURE_ACCOUNT_NAME", "AZURE_ACCOUNT_KEY"]
    } else {
        vec![]
    }
}

/// Storage credentials: `--env` pairs, then the process environment, then a hidden prompt.
fn collect_env(repository: &str, env_pairs: &[String]) -> Result<BTreeMap<String, String>> {
    let mut env = BTreeMap::new();
    for p in env_pairs {
        let (k, v) = p
            .split_once('=')
            .with_context(|| format!("expected KEY=VALUE, got {p:?}"))?;
        env.insert(k.to_string(), v.to_string());
    }
    for key in needed_env(repository) {
        if env.contains_key(key) {
            continue;
        }
        let v = match std::env::var(key) {
            Ok(v) if !v.is_empty() => Zeroizing::new(v),
            _ => util::read_hidden(&format!("{key}: "))?,
        };
        env.insert(key.to_string(), v.to_string());
    }
    if repository.contains(".r2.cloudflarestorage.com") {
        env.entry("AWS_DEFAULT_REGION".into())
            .or_insert_with(|| "auto".into());
    }
    Ok(env)
}

/// Configure backups for an unlocked volume. The repository password is derived from the
/// Ledger seed and the repository URL; re-running `init` with the same URL reconnects to an
/// existing repository.
pub fn init(
    oracle: &mut dyn Oracle,
    vol_name: &str,
    repository: &str,
    key_id: Option<&str>,
    env_pairs: &[String],
) -> Result<()> {
    let mut vol = Volume::load(vol_name)?;
    if !vol.is_unlocked()? {
        bail!("unlock '{vol_name}' first (`sealctl unlock {vol_name}`)");
    }
    if !util::which(&restic_bin()) && std::env::var_os("SEALCTL_RESTIC").is_none() {
        bail!("restic not found — install it (brew install restic / apt install restic)");
    }
    let key_id = key_id.unwrap_or(vol_name);
    let env = collect_env(repository, env_pairs)?;
    let password = derive::passphrase(oracle, Purpose::Restic, key_id)?;
    let secrets = RepoSecrets {
        repository: repository.to_string(),
        password: password.to_string(),
        env,
    };
    write_inner(&vol, &secrets)?;
    let repo = Repo::from_unlocked(&vol)?;
    match repo.probe()? {
        Probe::Exists => {
            println!("existing repository found — reconnected (same seed, same key id ⇒ same password)")
        }
        Probe::Missing => repo.run(&["init"], false)?,
        Probe::WrongPassword => bail!(
            "a repository exists at {repository}, but not for key id '{key_id}'.\n   \
             Repositories created by sealctl 0.2.0 use the URL as key id: add --key-id '{repository}'"
        ),
    }
    vol.backup = Some(BackupPolicy::new(repository, key_id));
    vol.save()?;
    println!("✅ backups configured for '{vol_name}' → {repository}");
    println!("   password derived from your seed and key id '{key_id}'");
    println!("   first backup:      sealctl backup run {vol_name}");
    println!("   hourly schedule:   sealctl backup schedule install");
    Ok(())
}

/// Filesystem bookkeeping, never user data (macOS metadata, ext4 lost+found).
const SYSTEM_EXCLUDES: &[&str] = &[
    ".Spotlight-V100",
    ".fseventsd",
    ".Trashes",
    ".TemporaryItems",
    ".DocumentRevisions-V100",
    "lost+found",
];

pub fn run_one(vol: &Volume, quiet: bool) -> Result<()> {
    if !vol.is_unlocked()? {
        bail!("'{}' is locked", vol.name);
    }
    let policy = vol
        .backup
        .clone()
        .context("no backup configured — run `sealctl backup init`")?;
    let repo = Repo::from_unlocked(vol)?;
    let mut state = load_state(&vol.name);
    state.last_attempt = Some(now());
    let mp = vol.mountpoint.to_string_lossy().into_owned();
    let tag = format!("vol:{}", vol.name);
    let mut args: Vec<String> = vec![
        "backup".into(),
        mp.clone(),
        "--tag".into(),
        "sealctl".into(),
        "--tag".into(),
        tag.clone(),
    ];
    for ex in std::iter::once(".sealctl").chain(SYSTEM_EXCLUDES.iter().copied()) {
        args.push("--exclude".into());
        args.push(format!("{mp}/{ex}"));
    }
    if quiet {
        args.push("--quiet".into());
    }
    let refs: Vec<&str> = args.iter().map(String::as_str).collect();
    let res = repo.run(&refs, quiet);
    match &res {
        Ok(()) => {
            state.last_success = Some(now());
            state.last_error = None;
        }
        Err(e) => state.last_error = Some(format!("{e:#}")),
    }
    save_state(&vol.name, &state)?;
    res?;

    // Weekly retention + prune.
    if state
        .last_prune
        .is_none_or(|t| now().saturating_sub(t) > 7 * 86_400)
    {
        let (d, w, m) = (
            policy.keep_daily.to_string(),
            policy.keep_weekly.to_string(),
            policy.keep_monthly.to_string(),
        );
        let r = repo.run(
            &[
                "forget",
                "--tag",
                &tag,
                "--keep-daily",
                &d,
                "--keep-weekly",
                &w,
                "--keep-monthly",
                &m,
                "--prune",
                "--quiet",
            ],
            true,
        );
        match r {
            Ok(()) => {
                state.last_prune = Some(now());
                save_state(&vol.name, &state)?;
            }
            Err(e) if !quiet => eprintln!("⚠️  pruning old snapshots failed (backups are fine): {e:#}"),
            Err(_) => {}
        }
    }
    Ok(())
}

/// `sealctl backup run`: explicit volumes, or all scheduled ones.
pub fn run(names: &[String], all: bool, if_unlocked: bool, quiet: bool) -> Result<()> {
    let vols: Vec<Volume> = if all || names.is_empty() {
        Volume::list()?
            .into_iter()
            .filter(|v| v.backup.as_ref().is_some_and(|b| b.scheduled))
            .collect()
    } else {
        names.iter().map(|n| Volume::load(n)).collect::<Result<_>>()?
    };
    let mut failed = 0;
    for v in vols {
        if !v.is_unlocked().unwrap_or(false) {
            if if_unlocked {
                continue;
            }
            eprintln!("skipping '{}': locked", v.name);
            failed += 1;
            continue;
        }
        if !quiet {
            println!("backing up '{}'…", v.name);
        }
        if let Err(e) = run_one(&v, quiet) {
            eprintln!("❌ '{}': {e:#}", v.name);
            failed += 1;
        } else if !quiet {
            println!("✅ '{}' backed up", v.name);
        }
    }
    if failed > 0 {
        bail!("{failed} volume(s) not backed up");
    }
    Ok(())
}

pub fn snapshots(oracle: &mut dyn Oracle, vol: &str) -> Result<()> {
    let v = Volume::load(vol)?;
    Repo::open(oracle, &v)?.run(&["snapshots", "--tag", &format!("vol:{vol}")], false)
}

pub fn restore(
    oracle: &mut dyn Oracle,
    vol: &str,
    snapshot: &str,
    target: &std::path::Path,
    include: &[String],
) -> Result<()> {
    let v = Volume::load(vol)?;
    let target = target.to_string_lossy().into_owned();
    let mut args = vec!["restore", snapshot, "--target", &target, "--tag", "sealctl"];
    let tagf = format!("vol:{vol}");
    args.extend(["--tag", &tagf]);
    let incl: Vec<String> = include
        .iter()
        .map(|p| {
            if p.starts_with('/') {
                p.clone()
            } else {
                format!("{}/{p}", v.mountpoint.display())
            }
        })
        .collect();
    for p in &incl {
        args.extend(["--include", p]);
    }
    Repo::open(oracle, &v)?.run(&args, false)?;
    println!("✅ restored into {target}{}", v.mountpoint.display());
    Ok(())
}

pub fn check(oracle: &mut dyn Oracle, vol: &str, read_data_percent: Option<u8>) -> Result<()> {
    let v = Volume::load(vol)?;
    let subset = read_data_percent.map(|p| format!("--read-data-subset={p}%"));
    let mut args = vec!["check"];
    if let Some(s) = &subset {
        args.push(s);
    }
    Repo::open(oracle, &v)?.run(&args, false)
}

pub fn set_policy(vol: &str, f: impl FnOnce(&mut BackupPolicy)) -> Result<()> {
    let mut v = Volume::load(vol)?;
    let p = v.backup.as_mut().context("no backup configured")?;
    f(p);
    v.save()
}

// ---- scheduling ----

pub const SCHEDULE_LABEL: &str = "io.github.oleksiyp.sealctl.backup";

/// Switch an existing repository to the password derived from `key_id` (default: the volume
/// name), using restic's own key management: the new key is added, then the old one removed.
/// The data and the repository's master key stay the same.
pub fn rekey(oracle: &mut dyn Oracle, vol_name: &str, key_id: Option<&str>) -> Result<()> {
    let mut vol = Volume::load(vol_name)?;
    if !vol.is_unlocked()? {
        bail!("unlock '{vol_name}' first (`sealctl unlock {vol_name}`)");
    }
    let mut policy = vol
        .backup
        .clone()
        .context("no backup configured for this volume")?;
    let new_id = key_id.unwrap_or(vol_name);
    if policy.key_id.as_deref() == Some(new_id) {
        println!("'{vol_name}' backups already use key id '{new_id}'");
        return Ok(());
    }
    let repo = Repo::from_unlocked(&vol)?;
    let old_key = repo.current_key()?;
    let new_password = derive::passphrase(oracle, Purpose::Restic, new_id)?;
    let staged = vol.inner_dir().join("restic-password.new");
    paths::write_private(&staged, new_password.as_bytes())?;
    let added = repo.run(
        &["key", "add", "--new-password-file", &staged.to_string_lossy()],
        true,
    );
    let _ = fs::remove_file(&staged);
    added?;
    let mut secrets = repo.secrets;
    secrets.password = new_password.to_string();
    write_inner(&vol, &secrets)?;
    Repo::from_unlocked(&vol)?.run(&["key", "remove", &old_key], true)?;
    policy.key_id = Some(new_id.to_string());
    vol.backup = Some(policy);
    vol.save()?;
    println!("✅ '{vol_name}' backups now use a password derived from key id '{new_id}'");
    Ok(())
}

pub fn schedule_install(every_minutes: u64) -> Result<()> {
    let exe = std::env::current_exe()?;
    let args = vec![
        exe.to_string_lossy().into_owned(),
        "backup".into(),
        "run".into(),
        "--all".into(),
        "--if-unlocked".into(),
        "--quiet".into(),
    ];
    crate::service::install(&crate::service::Service {
        label: SCHEDULE_LABEL,
        args,
        every_secs: Some(every_minutes * 60),
        description: "sealctl: back up unlocked volumes",
    })?;
    println!("✅ unlocked volumes will be backed up every {every_minutes} min (and before `sealctl lock`)");
    Ok(())
}

pub fn schedule_uninstall() -> Result<()> {
    crate::service::uninstall(SCHEDULE_LABEL)
}

pub fn age(secs: u64) -> String {
    let d = now().saturating_sub(secs);
    match d {
        0..=59 => "just now".into(),
        60..=3599 => format!("{} min ago", d / 60),
        3600..=86_399 => format!("{} h ago", d / 3600),
        _ => format!("{} days ago", d / 86_400),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_requirements() {
        assert_eq!(
            needed_env("s3:https://x.r2.cloudflarestorage.com/b"),
            vec!["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
        );
        assert!(needed_env("/mnt/usb/repo").is_empty());
        assert_eq!(needed_env("b2:bucket:path").len(), 2);
    }

    #[test]
    fn secrets_roundtrip() {
        let s = RepoSecrets {
            repository: "r".into(),
            password: "p".into(),
            env: [("A".into(), "1".into())].into(),
        };
        let t: RepoSecrets = toml::from_str(&toml::to_string(&s).unwrap()).unwrap();
        assert_eq!(t.repository, "r");
        assert_eq!(t.env["A"], "1");
    }
}
