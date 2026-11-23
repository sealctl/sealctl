//! Backups with restic on derived keys (SPEC 14). The repository password is
//! `hex(derive(root, "backup:<repository-id>", 16))`, handed to restic on a pipe; storage
//! credentials are secrets `backup/<name>/<VAR>` in the store. Nothing secret is written to
//! disk: the daemon holds the key and the credentials while the session is Open.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use sealctl_core::wire::{ObjectFacts, RequestItem};
use sealctl_core::ObjectKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::exit::{self, fail};
use crate::paths;

/// Retention and when backups run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Policy {
    /// Back up before the session locks.
    #[serde(default = "yes")]
    pub on_lock: bool,
    /// Include in scheduled backups.
    #[serde(default = "yes")]
    pub scheduled: bool,
    /// `--keep-daily`.
    #[serde(default = "d7")]
    pub keep_daily: u32,
    /// `--keep-weekly`.
    #[serde(default = "d4")]
    pub keep_weekly: u32,
    /// `--keep-monthly`.
    #[serde(default = "d12")]
    pub keep_monthly: u32,
}

fn yes() -> bool {
    true
}
fn d7() -> u32 {
    7
}
fn d4() -> u32 {
    4
}
fn d12() -> u32 {
    12
}

impl Default for Policy {
    fn default() -> Self {
        Policy {
            on_lock: true,
            scheduled: true,
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 12,
        }
    }
}

/// `~/.config/sealctl/backups/<name>.toml`. No secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Backup {
    /// Name.
    pub name: String,
    /// What is backed up: a folder, or a volume's mount point.
    pub source: PathBuf,
    /// The volume it backs up, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    /// The restic repository URL.
    pub repo: String,
    /// The repository id (its last path segment).
    pub repo_id: String,
    /// Words fingerprint.
    pub words: String,
    /// `check(backup key)`.
    pub check: String,
    /// Names of the storage credential variables (secrets `backup/<name>/<VAR>`).
    #[serde(default)]
    pub credentials: Vec<String>,
    /// Policy.
    #[serde(default)]
    pub policy: Policy,
}

/// Last backup times.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BackupState {
    /// Last successful backup, Unix seconds.
    pub last_success: Option<u64>,
    /// Last error.
    pub last_error: Option<String>,
    /// Last `forget --prune`, Unix seconds.
    pub last_prune: Option<u64>,
}

/// The restic binary (`SEALCTL_RESTIC` or `restic`).
pub fn restic_bin() -> String {
    std::env::var("SEALCTL_RESTIC").unwrap_or_else(|_| "restic".into())
}

/// Credentials restic needs for common backends.
pub fn needed_env(repo: &str) -> Vec<&'static str> {
    if repo.starts_with("s3:") {
        vec!["AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"]
    } else if repo.starts_with("b2:") {
        vec!["B2_ACCOUNT_ID", "B2_ACCOUNT_KEY"]
    } else if repo.starts_with("azure:") {
        vec!["AZURE_ACCOUNT_NAME", "AZURE_ACCOUNT_KEY"]
    } else if repo.starts_with("gs:") {
        vec!["GOOGLE_PROJECT_ID", "GOOGLE_APPLICATION_CREDENTIALS"]
    } else {
        vec![]
    }
}

fn now_secs() -> u64 {
    crate::machine::now_ms() / 1000
}

impl Backup {
    fn file(name: &str) -> Result<PathBuf> {
        Ok(paths::backups_dir()?.join(format!("{name}.toml")))
    }

    /// Loads a definition (exit 9).
    pub fn load(name: &str) -> Result<Backup> {
        crate::volume::validate_name(name)?;
        let text = std::fs::read_to_string(Self::file(name)?)
            .map_err(|_| fail(exit::NOT_FOUND, format!("No backup {name}.")))?;
        Ok(toml::from_str(&text)?)
    }

    /// Saves it.
    pub fn save(&self) -> Result<()> {
        paths::ensure_private_dir(&paths::backups_dir()?)?;
        paths::write_private(&Self::file(&self.name)?, toml::to_string_pretty(self)?.as_bytes())
    }

    /// Every definition.
    pub fn list() -> Result<Vec<Backup>> {
        let Ok(rd) = std::fs::read_dir(paths::backups_dir()?) else {
            return Ok(vec![]);
        };
        let mut v: Vec<Backup> = rd
            .flatten()
            .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
            .filter_map(|e| std::fs::read_to_string(e.path()).ok())
            .filter_map(|t| toml::from_str(&t).ok())
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    /// Removes the definition.
    pub fn forget(&self) -> Result<()> {
        let _ = std::fs::remove_file(Self::file(&self.name)?);
        Ok(())
    }

    /// The `keys` item for its key.
    pub fn request_item(&self) -> RequestItem {
        RequestItem {
            purpose: "backup".into(),
            id: self.repo_id.clone(),
            words: Some(self.words.clone()),
            check: Some(self.check.clone()),
            object: Some(ObjectFacts {
                kind: "backup".into(),
                path: self.repo.clone(),
                size: 0,
            }),
        }
    }

    /// Secret names of its credentials.
    pub fn credential_names(&self) -> Vec<String> {
        self.credentials
            .iter()
            .map(|v| format!("backup/{}/{v}", self.name))
            .collect()
    }

    /// Last backup times.
    pub fn state(&self) -> BackupState {
        paths::backup_state_dir()
            .ok()
            .and_then(|d| std::fs::read_to_string(d.join(format!("{}.toml", self.name))).ok())
            .and_then(|t| toml::from_str(&t).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, st: &BackupState) -> Result<()> {
        let d = paths::backup_state_dir()?;
        paths::ensure_private_dir(&d)?;
        paths::write_private(
            &d.join(format!("{}.toml", self.name)),
            toml::to_string(st)?.as_bytes(),
        )
    }
}

/// A repository opened with its password and credentials.
pub struct Repo {
    /// Repository URL.
    pub url: String,
    password: Zeroizing<String>,
    env: BTreeMap<String, Zeroizing<String>>,
}

impl Repo {
    /// From a backup key.
    pub fn new(url: &str, key: &ObjectKey, env: BTreeMap<String, Zeroizing<String>>) -> Repo {
        Repo {
            url: url.into(),
            password: key.hex(),
            env,
        }
    }

    /// From a plain password (for `unseal`, `seal` and `recover`).
    pub fn with_password(
        url: &str,
        password: Zeroizing<String>,
        env: BTreeMap<String, Zeroizing<String>>,
    ) -> Repo {
        Repo {
            url: url.into(),
            password,
            env,
        }
    }

    /// restic with the repository, credentials, and the password on stdin.
    pub fn command(&self) -> Command {
        let mut c = Command::new(restic_bin());
        c.env("RESTIC_REPOSITORY", &self.url);
        c.env("RESTIC_PASSWORD_FILE", "/dev/stdin");
        c.env_remove("RESTIC_PASSWORD");
        c.env_remove("RESTIC_PASSWORD_COMMAND");
        for (k, v) in &self.env {
            c.env(k, v.as_str());
        }
        if self.url.contains(".r2.cloudflarestorage.com") && !self.env.contains_key("AWS_DEFAULT_REGION") {
            c.env("AWS_DEFAULT_REGION", "auto");
        }
        c
    }

    /// Runs restic with output captured.
    pub fn output(&self, args: &[&str]) -> Result<std::process::Output> {
        let mut c = self.command();
        c.args(args);
        crate::util::run_with_stdin(&mut c, self.password.as_bytes())
            .context("starting restic (is it installed? brew install restic / apt install restic)")
    }

    /// Runs restic with output shown (stdout optional).
    pub fn run(&self, args: &[&str], quiet: bool) -> Result<()> {
        self.run_until(args, quiet, None)
    }

    /// [`Repo::run`], stopping restic at `limit` (the on-lock time limit, or the daemon's exit):
    /// it holds the backup key and the storage credentials, so it does not run on after it.
    pub fn run_until(&self, args: &[&str], quiet: bool, limit: Option<&Limit>) -> Result<()> {
        let status = self.run_status(args, quiet, limit)?;
        if !status.success() {
            bail!("restic {} failed ({status})", args.first().unwrap_or(&""));
        }
        Ok(())
    }

    /// [`Repo::run_until`], returning how restic exited.
    pub fn run_status(
        &self,
        args: &[&str],
        quiet: bool,
        limit: Option<&Limit>,
    ) -> Result<std::process::ExitStatus> {
        let mut c = self.command();
        c.args(args).stdin(Stdio::piped());
        if quiet {
            c.stdout(Stdio::null());
        }
        let mut child = c
            .spawn()
            .context("starting restic (is it installed? brew install restic / apt install restic)")?;
        {
            use std::io::Write;
            let mut i = child.stdin.take().context("stdin")?;
            i.write_all(self.password.as_bytes())?;
        }
        wait_until(&mut child, limit, STOP_GRACE)
    }

    /// Does the password open the repository?
    pub fn opens(&self) -> Result<bool> {
        let out = self.output(&["cat", "config"])?;
        if out.status.success() {
            return Ok(true);
        }
        let err = String::from_utf8_lossy(&out.stderr);
        if err.contains("wrong password") || err.contains("no key found") {
            return Ok(false);
        }
        bail!(
            "restic could not open the repository: {}",
            err.trim().lines().last().unwrap_or("")
        )
    }

    /// The keys of the repository: `(id, user, host, current)`.
    pub fn keys(&self) -> Result<Vec<(String, String, String, bool)>> {
        #[derive(Deserialize)]
        struct K {
            id: String,
            #[serde(default, rename = "userName")]
            user: String,
            #[serde(default, rename = "hostName")]
            host: String,
            #[serde(default)]
            current: bool,
        }
        let out = self.output(&["key", "list", "--json"])?;
        if !out.status.success() {
            bail!(
                "restic key list failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let keys: Vec<K> = serde_json::from_slice(&out.stdout).context("parsing restic key list")?;
        Ok(keys
            .into_iter()
            .map(|k| (k.id, k.user, k.host, k.current))
            .collect())
    }

    /// `restic key add --user U --host H` with the new password on fd 3. Returns the new key id.
    pub fn key_add(&self, new: &[u8], user: &str, host: &str) -> Result<String> {
        let before: Vec<String> = self.keys()?.into_iter().map(|k| k.0).collect();
        let mut c = self.command();
        c.args([
            "key",
            "add",
            "--new-password-file",
            "/dev/fd/3",
            "--user",
            user,
            "--host",
            host,
        ]);
        let out = crate::util::run_with_fds(&mut c, &[(3, new)], Some(self.password.as_bytes()))?;
        if !out.status.success() {
            bail!(
                "restic key add failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let after = self.keys()?;
        after
            .into_iter()
            .map(|k| k.0)
            .find(|id| !before.contains(id))
            .context("restic did not list the new key")
    }

    /// `restic key remove <id>`, opening with the key `hint`.
    pub fn key_remove(&self, id: &str, hint: &str) -> Result<()> {
        let out = self.output(&["--key-hint", hint, "key", "remove", id])?;
        if !out.status.success() {
            bail!(
                "restic key remove failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

/// Collects credentials: `-e VAR=value`, then the environment, then a hidden prompt.
pub fn collect_env(repo: &str, pairs: &[String]) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let mut env = BTreeMap::new();
    for p in pairs {
        let (k, v) = p.split_once('=').ok_or_else(|| {
            fail(
                exit::USAGE,
                format!("Expected VAR=value, got {}.", p.split('=').next().unwrap_or("")),
            )
        })?;
        env.insert(k.to_string(), Zeroizing::new(v.to_string()));
    }
    for key in needed_env(repo) {
        if env.contains_key(key) {
            continue;
        }
        let v = match std::env::var(key) {
            Ok(v) if !v.is_empty() => Zeroizing::new(v),
            _ => {
                if !crate::term::is_person() {
                    return Err(fail(
                        exit::REFUSED,
                        format!("{key} is needed. Give it with -e {key}=…"),
                    ));
                }
                crate::util::read_hidden(&format!("{key}: "))?
            }
        };
        env.insert(key.to_string(), v);
    }
    Ok(env)
}

/// What `backup init` needs.
pub struct InitOpts<'a> {
    /// Name.
    pub name: &'a str,
    /// Volume name or folder.
    pub from: &'a str,
    /// Base URL; the repository is `<base>/<repo-id>`.
    pub repo_base: &'a str,
    /// Credentials.
    pub env: BTreeMap<String, Zeroizing<String>>,
}

/// Makes a repository with a new id and key, and records the definition.
pub fn init(opts: InitOpts<'_>, new_key: &mut crate::volume::NewKey<'_>) -> Result<(Backup, ObjectKey)> {
    crate::volume::validate_name(opts.name)?;
    let _name = lock_name(opts.name)?;
    if Backup::load(opts.name).is_ok() {
        return Err(fail(exit::USAGE, format!("Backup {} exists already.", opts.name)));
    }
    let (source, volume) = match crate::volume::Volume::load(opts.from) {
        Ok(v) => (v.mountpoint.clone(), Some(v.name)),
        Err(_) => {
            let p = std::fs::canonicalize(opts.from)
                .map_err(|_| fail(exit::NOT_FOUND, format!("No volume or folder {}.", opts.from)))?;
            (p, None)
        }
    };
    let repo_id = crate::util::new_uuid()?;
    let url = format!("{}/{repo_id}", opts.repo_base.trim_end_matches('/'));
    let item = RequestItem {
        purpose: "backup".into(),
        id: repo_id.clone(),
        words: None,
        check: None,
        object: Some(ObjectFacts {
            kind: "backup".into(),
            path: url.clone(),
            size: 0,
        }),
    };
    let (key, words) = new_key(&item)?;
    let repo = Repo::new(&url, &key, opts.env.clone());
    let out = repo.output(&["init"])?;
    if !out.status.success() {
        bail!(
            "restic init failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("")
        );
    }
    // A key that names the words, then the one `init` made removed.
    let init_key = repo
        .keys()?
        .into_iter()
        .map(|k| k.0)
        .next()
        .context("restic key list")?;
    let new_id = repo.key_add(key.hex().as_bytes(), "sealctl", &format!("sealctl-{words}"))?;
    repo.key_remove(&init_key, &new_id)?;
    let b = Backup {
        name: opts.name.into(),
        source,
        volume,
        repo: url,
        repo_id,
        words,
        check: key.check(),
        credentials: opts.env.keys().cloned().collect(),
        policy: Policy::default(),
    };
    b.save()?;
    Ok((b, key))
}

/// The [`crate::util::object_lock`] of a restic repository: held by `backup run`, `seal backup`,
/// `unseal`, rewrap and re-encryption while they use or change it.
pub fn lock_repo(url: &str) -> Result<crate::util::ObjectLock> {
    let key = if url.contains(':') {
        format!("restic:{url}")
    } else {
        crate::util::path_key(std::path::Path::new(url))
    };
    crate::util::object_lock(&key, &format!("The restic repository {url}"))
}

/// The [`crate::util::object_lock`] of a backup name, held from the check that it is free to the
/// saved definition (`backup init`, `seal backup`).
pub fn lock_name(name: &str) -> Result<crate::util::ObjectLock> {
    crate::util::object_lock(&format!("backup-name:{name}"), &format!("Backup {name}"))
}

/// When restic has to stop: at `deadline`, or as soon as `stop` is set (the daemon exits).
#[derive(Clone)]
pub struct Limit {
    /// The time limit.
    pub deadline: std::time::Instant,
    /// Set to stop now.
    pub stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Limit {
    fn reached(&self) -> bool {
        self.stop.load(std::sync::atomic::Ordering::SeqCst) || std::time::Instant::now() >= self.deadline
    }
}

/// How long restic has after SIGINT to remove its repository lock before it is killed.
const STOP_GRACE: std::time::Duration = std::time::Duration::from_secs(10);

/// Waits for `child`, stopping it at `limit`: SIGINT first, so restic removes its lock from the
/// repository (other machines would see it held for up to 30 minutes), then SIGKILL once
/// `grace` has passed.
fn wait_until(
    child: &mut std::process::Child,
    limit: Option<&Limit>,
    grace: std::time::Duration,
) -> Result<std::process::ExitStatus> {
    let Some(limit) = limit else {
        return Ok(child.wait()?);
    };
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(status);
        }
        if limit.reached() {
            let pid = nix::unistd::Pid::from_raw(child.id() as i32);
            let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGINT);
            let until = std::time::Instant::now() + grace;
            while std::time::Instant::now() < until {
                if child.try_wait()?.is_some() {
                    bail!("stopped at the time limit");
                }
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
            let _ = child.kill();
            let _ = child.wait();
            bail!("stopped at the time limit");
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    }
}

/// Runs one backup now, then `forget` with the policy (`--prune` at most weekly). `Some` is a
/// warning: the snapshot was made but is missing something.
pub fn run_one(
    b: &Backup,
    key: &ObjectKey,
    env: BTreeMap<String, Zeroizing<String>>,
    quiet: bool,
) -> Result<Option<String>> {
    run_one_until(b, key, env, quiet, None)
}

/// [`run_one`], with restic stopped at `limit`.
pub fn run_one_until(
    b: &Backup,
    key: &ObjectKey,
    env: BTreeMap<String, Zeroizing<String>>,
    quiet: bool,
    limit: Option<&Limit>,
) -> Result<Option<String>> {
    if key.check() != b.check {
        return Err(fail(
            exit::WRONG_KEY,
            format!("The key does not open backup {} (check mismatch).", b.name),
        ));
    }
    // a closed volume can leave its empty mount point folder behind: backing that up would
    // make an empty snapshot that `forget` then keeps in place of the real ones
    let there = match &b.volume {
        Some(v) => crate::volume::Volume::load(v).is_ok_and(|v| v.is_open()),
        None => b.source.is_dir(),
    };
    if !there {
        return Err(fail(
            exit::NOT_FOUND,
            match &b.volume {
                Some(v) => format!("Volume {v} is not open."),
                None => format!("{} is not there.", b.source.display()),
            },
        ));
    }
    // never beside a re-encryption, rewrap or unseal of this repository, and only into the
    // repository the definition names now: one that moved (re-encrypted) or went (unsealed)
    // since `b` was read would take a snapshot that is then lost
    let _lock = lock_repo(&b.repo)?;
    match Backup::load(&b.name) {
        Ok(cur) if cur.repo == b.repo && cur.check == b.check => {}
        _ => {
            return Err(fail(
                exit::BUSY,
                format!(
                    "Backup {} changed while it was starting (re-encrypted or handed back). Run it again.",
                    b.name
                ),
            ))
        }
    }
    let repo = Repo::new(&b.repo, key, env);
    let mut st = b.state();
    let src = b.source.to_string_lossy().into_owned();
    // volume roots hold OS folders nobody can read or needs back
    let mut args = vec![
        "backup",
        src.as_str(),
        "--exclude",
        ".sealctl",
        "--exclude",
        ".fseventsd",
        "--exclude",
        ".Spotlight-V100",
        "--exclude",
        ".Trashes",
        "--exclude",
        ".TemporaryItems",
        "--exclude",
        "lost+found",
    ];
    if quiet {
        args.push("--quiet");
    }
    // restic exits 3 when it made the snapshot but could not read some files (it lists them)
    let r = match repo.run_status(&args, quiet, limit) {
        Ok(s) if s.success() => Ok(None),
        Ok(s) if s.code() == Some(3) => Ok(Some("some files could not be read".to_string())),
        Ok(s) => Err(anyhow::anyhow!("restic backup failed ({s})")),
        Err(e) => Err(e),
    };
    match &r {
        Ok(warning) => {
            st.last_success = Some(now_secs());
            st.last_error = warning.clone();
            let prune = prune_due(st.last_prune, now_secs());
            let (d, w, m) = (
                b.policy.keep_daily.to_string(),
                b.policy.keep_weekly.to_string(),
                b.policy.keep_monthly.to_string(),
            );
            let mut fargs = vec![
                "forget",
                "--keep-daily",
                &d,
                "--keep-weekly",
                &w,
                "--keep-monthly",
                &m,
            ];
            if prune {
                fargs.push("--prune");
            }
            if repo.run_until(&fargs, true, limit).is_ok() && prune {
                st.last_prune = Some(now_secs());
            }
        }
        Err(e) => st.last_error = Some(format!("{e:#}")),
    }
    b.save_state(&st)?;
    r
}

/// Whether `forget` prunes this time: at most weekly. A last prune later than `now` (Unix
/// seconds) means the clock was set back since; it counts as long ago, or no prune would come
/// until the clock caught up with it.
fn prune_due(last: Option<u64>, now: u64) -> bool {
    last.is_none_or(|t| t > now || now - t > 7 * 86_400)
}

/// `1 h 5 min ago`.
pub fn age(secs: u64) -> String {
    match secs {
        s if s < 90 => "just now".into(),
        s if s < 3600 => format!("{} min ago", s / 60),
        s if s < 172_800 => format!("{} h ago", s / 3600),
        s => format!("{} days ago", s / 86_400),
    }
}

/// Installs the schedule: `sealctl backup run --all --if-open --quiet` every N minutes.
pub fn schedule_install(every_minutes: u64) -> Result<()> {
    let exe = crate::util::stable_exe()?;
    crate::service::install(&crate::service::Service {
        label: crate::service::BACKUP_LABEL,
        args: vec![
            exe.to_string_lossy().into_owned(),
            "backup".into(),
            "run".into(),
            "--all".into(),
            "--if-open".into(),
            "--quiet".into(),
        ],
        every_secs: Some(every_minutes * 60),
        description: "sealctl scheduled backups",
    })
}

/// Removes the schedule.
pub fn schedule_uninstall() -> Result<()> {
    crate::service::uninstall(crate::service::BACKUP_LABEL)
}

#[cfg(test)]
mod deadline_tests {
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use super::Limit;

    fn limit(after: Duration) -> Limit {
        Limit {
            deadline: Instant::now() + after,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }

    #[test]
    fn a_process_past_its_deadline_is_stopped() {
        let mut child = std::process::Command::new("sleep").arg("30").spawn().unwrap();
        let started = Instant::now();
        let r = super::wait_until(
            &mut child,
            Some(&limit(Duration::from_millis(300))),
            super::STOP_GRACE,
        );
        assert!(r.is_err());
        assert!(started.elapsed() < Duration::from_secs(5));
        assert!(child.try_wait().unwrap().is_some(), "killed and reaped");
        // without a limit it is waited for
        let mut child = std::process::Command::new("true").spawn().unwrap();
        assert!(super::wait_until(&mut child, None, super::STOP_GRACE)
            .unwrap()
            .success());
    }

    /// A process that notes SIGINT in `mark` and exits, or ignores it.
    fn interruptible(mark: &std::path::Path, ignore: bool) -> std::process::Child {
        let handler = if ignore {
            "trap '' INT".to_string()
        } else {
            format!("trap 'echo stopped > \"{}\"; exit 3' INT", mark.display())
        };
        std::process::Command::new("sh")
            .arg("-c")
            .arg(format!(
                "{handler}; echo ready > \"{}.ready\"; while :; do sleep 0.05; done",
                mark.display()
            ))
            .spawn()
            .unwrap()
    }

    fn wait_ready(mark: &std::path::Path) {
        let ready = mark.with_extension("ready");
        let until = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < until {
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    #[test]
    fn a_stopped_process_gets_sigint_first_and_sigkill_after_the_grace() {
        let dir = crate::paths::unit_test_root().join("deadline");
        std::fs::create_dir_all(&dir).unwrap();
        // restic removes its repository lock on SIGINT
        let mark = dir.join(format!("int-{}", std::process::id()));
        let mut child = interruptible(&mark, false);
        wait_ready(&mark);
        let l = limit(Duration::from_secs(60));
        l.stop.store(true, std::sync::atomic::Ordering::SeqCst);
        let started = Instant::now();
        assert!(super::wait_until(&mut child, Some(&l), Duration::from_secs(5)).is_err());
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(mark.exists(), "the process had its SIGINT");
        // one that does not stop on SIGINT is killed after the grace
        let mark = dir.join(format!("ign-{}", std::process::id()));
        let mut child = interruptible(&mark, true);
        wait_ready(&mark);
        let started = Instant::now();
        let r = super::wait_until(&mut child, Some(&l), Duration::from_millis(300));
        assert!(r.is_err());
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert!(started.elapsed() < Duration::from_secs(4));
        assert!(child.try_wait().unwrap().is_some(), "killed and reaped");
    }
}

#[cfg(test)]
mod prune_tests {
    use super::prune_due;

    const NOW: u64 = 1_795_300_000;
    const DAY: u64 = 86_400;

    #[test]
    fn prune_at_most_weekly_by_the_clock_as_it_is() {
        assert!(prune_due(None, NOW));
        assert!(!prune_due(Some(NOW - DAY), NOW));
        assert!(!prune_due(Some(NOW - 7 * DAY), NOW));
        assert!(prune_due(Some(NOW - 7 * DAY - 1), NOW));
        // the clock set back after a prune (a year ahead, then corrected)
        assert!(prune_due(Some(NOW + 365 * DAY), NOW));
        assert!(prune_due(Some(NOW + 1), NOW));
    }
}
