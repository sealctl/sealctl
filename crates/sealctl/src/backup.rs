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
        let status = self.run_status(args, quiet)?;
        if !status.success() {
            bail!("restic {} failed ({status})", args.first().unwrap_or(&""));
        }
        Ok(())
    }

    /// The same, returning how restic exited.
    pub fn run_status(&self, args: &[&str], quiet: bool) -> Result<std::process::ExitStatus> {
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
        Ok(child.wait()?)
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

/// Runs one backup now, then `forget` with the policy (`--prune` at most weekly). `Some` is a
/// warning: the snapshot was made but is missing something.
pub fn run_one(
    b: &Backup,
    key: &ObjectKey,
    env: BTreeMap<String, Zeroizing<String>>,
    quiet: bool,
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
    let r = match repo.run_status(&args, quiet) {
        Ok(s) if s.success() => Ok(None),
        Ok(s) if s.code() == Some(3) => Ok(Some("some files could not be read".to_string())),
        Ok(s) => Err(anyhow::anyhow!("restic backup failed ({s})")),
        Err(e) => Err(e),
    };
    match &r {
        Ok(warning) => {
            st.last_success = Some(now_secs());
            st.last_error = warning.clone();
            let prune = st
                .last_prune
                .is_none_or(|t| now_secs().saturating_sub(t) > 7 * 86_400);
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
            if repo.run(&fargs, true).is_ok() && prune {
                st.last_prune = Some(now_secs());
            }
        }
        Err(e) => st.last_error = Some(format!("{e:#}")),
    }
    b.save_state(&st)?;
    r
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
