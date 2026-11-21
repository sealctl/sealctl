//! The steps of each object. Every step is journaled and first checks the object itself
//! (does the new password already open it? is sealctl's key already gone?), so a run stopped
//! anywhere resumes without repeating or skipping anything.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::{json, Value};
use ssh_key::{HashAlg, PublicKey};
use zeroize::Zeroizing;

use super::handback::{self, Credential, Handback};
use super::store::{self, Item, Location, StoreKind};
use super::{exit, tilde, Object, Runner, SshKey};
use crate::derive::{self, Purpose};
use crate::volume::{self, Kind, Volume};

pub fn run(r: &mut Runner, o: &Object) -> Result<String> {
    match o {
        Object::Secrets { names, whole } => secrets(r, names, *whole),
        Object::Backup { volume } => backup(r, volume),
        Object::Volume { volume } => volume_obj(r, volume),
        Object::Ssh { keys } => ssh(r, keys),
        Object::Git { configs } => git(r, configs),
        Object::Ai { tools } => ai(r, tools),
        Object::Services { labels, agent } => services(r, labels, *agent),
        Object::LocalState => local_state(r),
    }
}

// ---------------------------------------------------------------- helpers ----

fn loc_of(r: &Runner, step: &str) -> Option<Location> {
    r.run
        .data(step)
        .and_then(|d| serde_json::from_value(d.clone()).ok())
}

/// Read back the value a done `…:password` step stored.
fn read_back(r: &mut Runner, step: &str) -> Result<Zeroizing<Vec<u8>>> {
    let loc = loc_of(r, step).with_context(|| format!("the journal has no location for {step}"))?;
    r.stores.read(&loc)
}

fn new_password(r: &Runner, what: &str) -> Result<Zeroizing<String>> {
    if r.plan.stores.type_passwords {
        store::type_password(what)
    } else {
        store::generate_password()
    }
}

/// Generate (or ask for) a new password and put it in the `--to` store, read back.
fn password_step(r: &mut Runner, step: &str, item: Item) -> Result<()> {
    let to = r.plan.stores.to;
    r.step(step, |r| {
        let pw = new_password(r, &format!("{} {}", item.kind, item.name))?;
        let loc = r.store(to, &item, pw.as_bytes())?;
        Ok((
            format!("new password stored in {} and read back", to.as_str()),
            Some(serde_json::to_value(&loc)?),
        ))
    })?;
    Ok(())
}

/// Test hook (feature `test-hooks`): `SEALCTL_TEST_BREAK_CHECK=<step>` makes the check after
/// that step's change fail, as a wrong read-back or a broken tool would.
fn test_break(step: &str) -> bool {
    #[cfg(feature = "test-hooks")]
    if std::env::var("SEALCTL_TEST_BREAK_CHECK").ok().as_deref() == Some(step) {
        return true;
    }
    let _ = step;
    false
}

fn as_text(v: &[u8]) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(
        String::from_utf8(v.to_vec()).context("passwords are text")?,
    ))
}

fn write_keeping_mode(path: &Path, text: &str) -> Result<()> {
    // follows symlinks (dotfiles setups), keeps the file's permissions, and is durable: a power
    // cut leaves the old file or the new one, never a part
    crate::durable::replace_keeping_mode(path, text.as_bytes())
        .with_context(|| format!("writing {}", path.display()))
}

fn user_and_host() -> (String, String) {
    let user = std::env::var("USER").unwrap_or_else(|_| "user".into());
    let m = crate::util::machine_name();
    let host = m.split_once('@').map(|(_, h)| h.to_string()).unwrap_or(m);
    (user, host)
}

// ---------------------------------------------------------------- secrets ----

fn secrets(r: &mut Runner, names: &[String], whole: bool) -> Result<String> {
    let kind = r.plan.stores.secrets_to;
    let pending: Vec<String> = names
        .iter()
        .filter(|n| !r.run.is_done(&format!("secret:{n}:store")))
        .cloned()
        .collect();
    // the variable of each secret in a dotenv file, the same on every resume
    let vars = store::env_vars(names);
    let mut values: BTreeMap<String, Zeroizing<Vec<u8>>> = BTreeMap::new();
    if !pending.is_empty() {
        let oracle = r.oracle()?;
        values = crate::secrets::open_all(oracle, Some(&pending))?
            .into_iter()
            .collect();
    }
    for n in names {
        r.step(&format!("secret:{n}:store"), |r| {
            let v = values.remove(n).context("the value was not opened")?;
            let item = Item {
                kind: "secret",
                name: n,
                notes: format!("Secret {n}, handed back by sealctl unseal."),
                credential: true,
                var: vars.get(n).cloned(),
            };
            let loc = r.store(kind, &item, &v)?;
            Ok((
                "stored and read back; SHA-256 matches".into(),
                Some(serde_json::to_value(&loc)?),
            ))
        })?;
    }
    let mut kept = "";
    if whole && !r.plan.keep_store {
        r.step("secrets:store:keep", |r| {
            let dir = crate::paths::secrets_dir()?;
            if !dir.exists() {
                return Ok(("store folder already moved".into(), None));
            }
            r.run.keep(&dir, "secrets")?;
            Ok((
                "store folder moved to kept/secrets (still encrypted to the Ledger)".into(),
                None,
            ))
        })?;
        kept = " The encrypted store is in the folder's kept/secrets.";
    }
    let n = names.len();
    let to = match kind {
        StoreKind::Folder => store::folder::SECRETS.to_string(),
        k => k.describe().to_string(),
    };
    Ok(format!(
        "secrets: {n} {} in {to}, each read back.{kept}",
        if n == 1 { "secret" } else { "secrets" },
    ))
}

// ---------------------------------------------------------------- backup ----

fn backup(r: &mut Runner, vol: &Volume) -> Result<String> {
    let name = vol.name.clone();
    let policy = vol.backup.clone().context("no backup configured")?;
    let be = volume::backend(vol.kind);
    let st = |s: &str| format!("backup:{name}:{s}");
    let need_repo = !r.run.is_done(&st("key-add")) || !r.run.is_done(&st("key-remove"));
    let need_creds = !r.run.is_done(&st("credentials"));
    let need_inner = !r.run.is_done(&st("inner"));

    // The password and credentials sealctl cached inside the volume are read while it is
    // mounted; it is mounted with its derived key for this if needed, and locked again after.
    let mut mounted_here = false;
    if (need_repo || need_creds || need_inner) && !be.is_unlocked(vol)? {
        let id = derive::canonical_id(&be.read_id(vol).unwrap_or_else(|_| vol.id.clone()));
        let pass = derive::passphrase(r.oracle()?, Purpose::Volume, &id)?;
        match be.unlock(vol, pass.as_bytes()) {
            Ok(()) => mounted_here = true,
            Err(e) => r.busy.push(format!(
                "volume {name} could not be mounted ({e:#}); its .sealctl/ folder was left in place"
            )),
        }
    }
    let res = backup_steps(r, vol, &policy, need_repo, need_creds);
    if mounted_here {
        if let Err(e) = be.lock(vol, false) {
            r.busy.push(format!(
                "volume {name} was mounted for this and could not be locked again: {e:#}"
            ));
        }
    }
    res?;
    Ok(format!(
        "backup of {name}: your password works; sealctl's key is removed. Backups no longer run by themselves."
    ))
}

fn backup_steps(
    r: &mut Runner,
    vol: &Volume,
    policy: &crate::volume::BackupPolicy,
    need_repo: bool,
    need_creds: bool,
) -> Result<()> {
    let name = vol.name.clone();
    let st = |s: &str| format!("backup:{name}:{s}");
    let mounted = vol.is_unlocked().unwrap_or(false);
    let inner = if mounted && crate::backup::has_inner(vol) {
        Some(crate::backup::Repo::from_unlocked(vol)?)
    } else {
        None
    };
    // storage credentials: from the volume, else from the store they went to, else asked
    let env: BTreeMap<String, String> = if let Some(i) = &inner {
        i.env().clone()
    } else if let Some(d) = r.run.data(&st("credentials")).cloned() {
        let mut env = BTreeMap::new();
        for (var, l) in d.as_object().into_iter().flatten() {
            let loc: Location = serde_json::from_value(l.clone())?;
            let v = r.stores.read(&loc)?;
            env.insert(var.clone(), as_text(&v)?.to_string());
        }
        env
    } else if need_repo || need_creds {
        crate::backup::collect_env(&policy.repository, &[])?
    } else {
        BTreeMap::new()
    };
    let old = if need_repo {
        let pw = match &inner {
            Some(i) => Zeroizing::new(i.password().to_string()),
            None => derive::passphrase(r.oracle()?, Purpose::Restic, policy.password_id())?,
        };
        Some(crate::backup::Repo::from_parts(
            &policy.repository,
            pw.as_bytes(),
            env.clone(),
        )?)
    } else {
        None
    };

    password_step(
        r,
        &st("password"),
        Item {
            kind: "backup",
            name: &format!("{name}/password"),
            notes: format!(
                "Password of the restic repository {} (backups of volume {name}). Open with: restic -r {} snapshots",
                policy.repository, policy.repository
            ),
            credential: false,
            var: None,
        },
    )?;

    let secrets_to = r.plan.stores.secrets_to;
    let to = r.plan.stores.to;
    r.step(&st("credentials"), |r| {
        // the folder: backup-<volume>.env holds everything restic needs, ready to source
        if secrets_to == StoreKind::Folder {
            let mut first: Vec<(&str, Zeroizing<Vec<u8>>)> = vec![(
                "RESTIC_REPOSITORY",
                Zeroizing::new(policy.repository.as_bytes().to_vec()),
            )];
            if to == StoreKind::Folder {
                first.push(("RESTIC_PASSWORD", read_back(r, &st("password"))?));
            }
            for (var, val) in first {
                let item = Item {
                    kind: "backup",
                    name: &format!("{name}/{var}"),
                    notes: String::new(),
                    credential: true,
                    var: None,
                };
                r.store(StoreKind::Folder, &item, &val)?;
            }
        }
        let mut data = serde_json::Map::new();
        for (var, val) in &env {
            let item = Item {
                kind: "backup",
                name: &format!("{name}/{var}"),
                notes: format!("{var} for the restic repository {}", policy.repository),
                credential: true,
                var: None,
            };
            let loc = r.store(secrets_to, &item, val.as_bytes())?;
            data.insert(var.clone(), serde_json::to_value(&loc)?);
        }
        let note = if data.is_empty() {
            "no storage credentials".to_string()
        } else {
            format!("{} storage credentials stored and read back", data.len())
        };
        Ok((note, Some(Value::Object(data))))
    })?;

    r.step(&st("key-add"), |r| {
        let old = old.as_ref().context("repository")?;
        let new = read_back(r, &st("password"))?;
        let new_repo = old.with_password(&new)?;
        if new_repo.opens()? {
            let new_key = new_repo.current_key()?;
            let old_key = if old.opens()? {
                Some(old.current_key()?)
            } else {
                None
            };
            return Ok((
                "your password already opens the repository".into(),
                Some(json!({"old_key": old_key, "new_key": new_key})),
            ));
        }
        if !old.opens()? {
            return Err(exit(
                10,
                format!(
                    "sealctl's key does not open the repository {} (other Ledger words?)",
                    policy.repository
                ),
            ));
        }
        let old_key = old.current_key()?;
        let (user, host) = user_and_host();
        let new_key = old.key_add(&new, Some(&user), Some(&host))?;
        // check: the new password opens it and is the current key
        if test_break(&st("key-add")) || !new_repo.opens()? || new_repo.current_key()? != new_key {
            bail!("the new password does not open the repository after restic key add");
        }
        Ok((
            "your password added (restic key add) and checked with restic cat config".into(),
            Some(json!({"old_key": old_key, "new_key": new_key})),
        ))
    })?;

    r.step(&st("key-remove"), |r| {
        let d = r.run.data(&st("key-add")).cloned().unwrap_or_default();
        let new = read_back(r, &st("password"))?;
        let old = old.as_ref().context("repository")?;
        let new_repo = old.with_password(&new)?;
        if !new_repo.opens()? {
            bail!("your new password does not open the repository; sealctl's key stays");
        }
        if let Some(old_key) = d["old_key"].as_str() {
            let keys = new_repo.keys()?;
            if keys.iter().any(|(id, _)| id == old_key) {
                new_repo.key_remove(old_key)?;
            }
        }
        if old.opens()? {
            bail!("sealctl's key still opens the repository");
        }
        Ok((
            "sealctl's key removed; the derived password now gives \"wrong password\"".into(),
            None,
        ))
    })?;

    r.step(&st("inner"), |_r| {
        if !vol.is_unlocked().unwrap_or(false) {
            return Ok((
                "volume not mounted; .sealctl/ left in place".into(),
                Some(json!({"left": true})),
            ));
        }
        crate::backup::forget_inner(vol)?;
        if vol.inner_dir().exists() {
            bail!("{} is still there", vol.inner_dir().display());
        }
        Ok((
            "cached password and credentials removed from the volume".into(),
            None,
        ))
    })?;
    if r.run.data(&st("inner")).is_some_and(|d| d["left"] == true)
        && !r.busy.iter().any(|b| b.contains(&name))
    {
        r.busy.push(format!(
            "volume {name}: its .sealctl/ folder (old restic password and credentials) is still inside; mount it and delete .sealctl/ by hand"
        ));
    }

    r.step(&st("config"), |r| {
        let f = Volume::config_file_for(&name)?;
        if !f.exists() {
            return Ok(("volume settings already gone".into(), None));
        }
        r.before_edit(&f)?;
        let mut v = Volume::load(&name)?;
        v.backup = None;
        v.save()?;
        Ok((
            "backup settings removed from sealctl's volume settings".into(),
            None,
        ))
    })?;

    r.step(&st("schedule"), |r| {
        let label = crate::backup::SCHEDULE_LABEL;
        let others = Volume::list()?.iter().any(|v| v.backup.is_some());
        if others {
            return Ok(("other volumes still back up; schedule kept".into(), None));
        }
        if !crate::service::files_present(label) {
            return Ok(("no backup schedule installed".into(), None));
        }
        for f in crate::service::files_of(label) {
            r.before_edit(&f)?;
        }
        crate::service::remove(label)?;
        if crate::service::files_present(label) {
            bail!("the backup schedule is still installed");
        }
        Ok(("backup schedule removed".into(), None))
    })?;
    Ok(())
}

// ---------------------------------------------------------------- volume ----

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::ApfsVolume => "apfs",
        Kind::Sparsebundle => "sparsebundle",
        Kind::Luks => "luks",
    }
}

fn volume_notes(vol: &Volume) -> String {
    match vol.kind {
        Kind::ApfsVolume => format!(
            "APFS volume {} (UUID {}). Open with: diskutil apfs unlockVolume {}",
            vol.name, vol.id, vol.id
        ),
        Kind::Sparsebundle => format!(
            "Encrypted sparse bundle {}. Open with: hdiutil attach {}",
            vol.name,
            vol.path.as_deref().map(tilde).unwrap_or_default()
        ),
        Kind::Luks => format!(
            "LUKS volume {} (UUID {}). Open with: sudo cryptsetup open {} {}",
            vol.name,
            vol.id,
            vol.path
                .as_deref()
                .map(|p| p.display().to_string())
                .unwrap_or_default(),
            vol.name
        ),
    }
}

fn volume_obj(r: &mut Runner, vol: &Volume) -> Result<String> {
    let name = vol.name.clone();
    let st = |s: &str| format!("volume:{name}:{s}");
    password_step(
        r,
        &st("password"),
        Item {
            kind: "volume",
            name: &name,
            notes: volume_notes(vol),
            credential: false,
            var: None,
        },
    )?;

    r.step(&st("change"), |r| {
        let be = volume::backend(vol.kind);
        let new = read_back(r, &st("password"))?;
        // an attached sparse bundle accepts any passphrase and refuses chpass: eject it first
        let mut remount = false;
        if vol.kind == Kind::Sparsebundle && volume::sparsebundle::is_attached(vol)? {
            remount = be.is_unlocked(vol)?;
            if let Err(e) = be.lock(vol, false) {
                return Err(exit(
                    11,
                    format!("volume {name} is busy and can't be ejected for the change: {e:#}"),
                ));
            }
        }
        let res = (|| -> Result<String> {
            let id = derive::canonical_id(&be.read_id(vol).unwrap_or_else(|_| vol.id.clone()));
            if be.verify(vol, &new)? {
                // done before a stop; a LUKS file may still have sealctl's slot as well
                let derived = derive::passphrase(r.oracle()?, Purpose::Volume, &id)?;
                if be.verify(vol, derived.as_bytes())? {
                    if vol.kind != Kind::Luks {
                        bail!("both passphrases open volume {name}");
                    }
                    let path = vol.path.as_deref().context("luks needs a path")?;
                    let slot =
                        volume::luks::slot_of(path, derived.as_bytes())?.context("sealctl's key slot")?;
                    volume::luks::kill_slot(path, slot, &new)?;
                    if be.verify(vol, derived.as_bytes())? {
                        bail!("sealctl's key still opens volume {name}");
                    }
                    return Ok("your passphrase opens it; sealctl's key slot removed".into());
                }
                return Ok("your passphrase already opens it".into());
            }
            let derived = derive::passphrase(r.oracle()?, Purpose::Volume, &id)?;
            if !be.verify(vol, derived.as_bytes())? {
                return Err(exit(
                    10,
                    format!("sealctl's key does not open volume {name} (other Ledger words?)"),
                ));
            }
            be.change_passphrase(vol, derived.as_bytes(), &new)?;
            // check with the passphrase as read back from the store
            if test_break(&st("change")) || !be.verify(vol, &new)? {
                if vol.kind != Kind::Luks {
                    // a one-step swap: swap back, the old one still works in this case
                    be.change_passphrase(vol, &new, derived.as_bytes())
                        .context("swapping the passphrase back")?;
                }
                bail!("your new passphrase does not open volume {name}; the change was reversed");
            }
            if be.verify(vol, derived.as_bytes())? {
                bail!("sealctl's key still opens volume {name}");
            }
            Ok("passphrase changed; yours opens it, sealctl's no longer does".into())
        })();
        if remount {
            // mounted again as it was found: with the new passphrase, or sealctl's after a
            // reversed change
            let again = be.unlock(vol, &new).or_else(|e| {
                let id = derive::canonical_id(&be.read_id(vol).unwrap_or_else(|_| vol.id.clone()));
                let derived = derive::passphrase(r.oracle()?, Purpose::Volume, &id)?;
                be.unlock(vol, derived.as_bytes()).map_err(|_| e)
            });
            if let Err(e) = again {
                r.busy
                    .push(format!("volume {name} could not be mounted again: {e:#}"));
            }
        }
        Ok((res?, None))
    })?;

    if vol.kind == Kind::Sparsebundle {
        r.step(&st("id"), |_r| {
            volume::sparsebundle::remove_id(vol)?;
            Ok(("sealctl.id removed from the bundle".into(), None))
        })?;
    }

    r.step(&st("config"), |r| {
        let f = Volume::config_file_for(&name)?;
        if !f.exists() {
            return Ok(("volume settings already gone".into(), None));
        }
        r.before_edit(&f)?;
        std::fs::remove_file(&f)?;
        Ok(("sealctl's settings for the volume removed".into(), None))
    })?;
    Ok(format!(
        "volume {name}: your passphrase works; sealctl's is removed. It stays encrypted."
    ))
}

// ---------------------------------------------------------------- SSH ----

/// The ssh-agent the user's logins use (not sealctl's): `$SSH_AUTH_SOCK` unless it is
/// sealctl's socket, else (macOS) launchd's.
fn system_agent() -> Option<PathBuf> {
    let ours = crate::ssh::socket_path().ok();
    if let Some(s) = std::env::var_os("SSH_AUTH_SOCK").map(PathBuf::from) {
        let is_ours =
            ours.as_ref().is_some_and(|o| *o == s) || s.to_string_lossy().contains("sealctl/ssh-agent.sock");
        if !is_ours && s.exists() {
            return Some(s);
        }
    }
    if cfg!(target_os = "macos") {
        let out = crate::util::system_cmd("launchctl")
            .args(["getenv", "SSH_AUTH_SOCK"])
            .output()
            .ok()?;
        let s = PathBuf::from(String::from_utf8_lossy(&out.stdout).trim());
        if s.exists() {
            return Some(s);
        }
    }
    None
}

fn apple_keychain() -> bool {
    #[cfg(feature = "test-hooks")]
    if std::env::var_os("SEALCTL_TEST_NO_APPLE_KEYCHAIN").is_some() {
        return false;
    }
    cfg!(target_os = "macos")
}

/// `ssh-keygen -y -P "" -f <key>` must print the key's public key: OpenSSH itself opens the
/// file without a passphrase. Skipped (the file was already read back) without ssh-keygen.
fn ssh_keygen_check(path: &Path, public: &str) -> Result<()> {
    if !crate::util::which("ssh-keygen") {
        return Ok(());
    }
    let out = std::process::Command::new("ssh-keygen")
        .args(["-y", "-P", "", "-f"])
        .arg(path)
        .stdin(std::process::Stdio::null())
        .output()
        .context("running ssh-keygen -y")?;
    let got: Vec<String> = String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .take(2)
        .map(str::to_string)
        .collect();
    if !out.status.success() || got.join(" ") != public {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!(
            "ssh-keygen -y -P \"\" -f {} does not give the key's public key{}",
            tilde(path),
            err.lines().next().map(|l| format!(": {l}")).unwrap_or_default()
        );
    }
    Ok(())
}

fn ssh(r: &mut Runner, keys: &[SshKey]) -> Result<String> {
    let no_pass = r.plan.no_ssh_passphrase;
    for k in keys {
        let name = k.name.clone();
        let st = |s: &str| format!("ssh:{name}:{s}");
        let public = PublicKey::from_openssh(&k.public).context("public key")?;
        if !no_pass {
            password_step(
                r,
                &st("password"),
                Item {
                    kind: "ssh",
                    name: &name,
                    notes: format!(
                        "Passphrase of the SSH key {} ({})",
                        tilde(&k.dest),
                        public.fingerprint(HashAlg::Sha256)
                    ),
                    credential: false,
                    var: None,
                },
            )?;
        }
        r.step(&st("export"), |r| {
            let pass = if no_pass {
                None
            } else {
                Some(read_back(r, &st("password"))?)
            };
            if k.dest.exists() {
                if crate::ssh::opens_with(&k.dest, pass.as_deref().map(|p| &p[..]), &public)? {
                    if pass.is_none() {
                        ssh_keygen_check(&k.dest, &k.public)?;
                    }
                    return Ok(("already written".into(), None));
                }
                bail!(
                    "{} exists and is not this key; move it away and resume",
                    k.dest.display()
                );
            }
            if !k.path.exists() {
                bail!("{} is gone", k.path.display());
            }
            let oracle = r.oracle()?;
            // written to a temporary file, fsynced, renamed, directory fsynced; the encrypted
            // original stays where it is until the keep step moves it to kept/ssh
            crate::ssh::export(oracle, &k.path, &k.dest, pass.as_deref().map(|p| &p[..]))?;
            if pass.is_none() {
                ssh_keygen_check(&k.dest, &k.public)?;
            }
            Ok((
                if pass.is_none() {
                    format!(
                        "written as {} without a passphrase; ssh-keygen -y gives its public key",
                        tilde(&k.dest)
                    )
                } else {
                    format!(
                        "written as {} and read back with the new passphrase",
                        tilde(&k.dest)
                    )
                },
                Some(json!({"dest": k.dest})),
            ))
        })?;
        // only for a password store: with the folder, keys are plain files and nothing goes
        // to an agent or the keychain
        if cfg!(target_os = "macos") && r.plan.stores.to != StoreKind::Folder {
            r.step(&st("agent"), |r| {
                let Some(sock) = system_agent() else {
                    r.notes.push(format!(
                        "Add {} to your agent yourself: ssh-add --apple-use-keychain {}",
                        tilde(&k.dest),
                        tilde(&k.dest)
                    ));
                    return Ok(("no system ssh-agent found; not added".into(), None));
                };
                let fp = public.fingerprint(HashAlg::Sha256).to_string();
                if crate::ssh::agent_fingerprints(&sock).contains(&fp) {
                    return Ok(("already in the agent".into(), None));
                }
                let pass = if no_pass {
                    None
                } else {
                    Some(read_back(r, &st("password"))?)
                };
                let keychain = apple_keychain();
                crate::ssh::ssh_add_keychain(
                    &k.dest,
                    pass.as_deref().map(|p| &p[..]),
                    &sock,
                    &r.run.dir,
                    keychain,
                )?;
                if !crate::ssh::agent_fingerprints(&sock).contains(&fp) {
                    bail!("ssh-add -l does not list {}", tilde(&k.dest));
                }
                Ok((
                    if keychain {
                        "added with ssh-add --apple-use-keychain; ssh-add -l lists it"
                    } else {
                        "added with ssh-add; ssh-add -l lists it"
                    }
                    .into(),
                    None,
                ))
            })?;
        }
        r.step(&st("keep"), |r| {
            let fname = k
                .path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if k.path.exists() {
                r.run.keep(&k.path, &format!("ssh/{fname}"))?;
            }
            let pubf = crate::ssh::public_path(&k.path);
            if pubf.exists() {
                r.run.keep(&pubf, &format!("ssh/{fname}.pub"))?;
            }
            Ok(("sealctl's key files moved to kept/ssh".into(), None))
        })?;
    }

    r.step("ssh:config", |r| {
        let ssh_dir = crate::paths::ssh_dir()?;
        let socket = crate::ssh::socket_path()?;
        let remove_agent = crate::ssh::key_files().is_empty();
        let edit = super::sshconfig::Edit {
            remove_agent,
            renames: keys
                .iter()
                .map(|k| (format!("sealctl_{}", k.name), tilde(&k.dest)))
                .collect(),
            keychain: cfg!(target_os = "macos") && !no_pass,
        };
        let main = ssh_dir.join("config");
        let mut files = super::sshconfig::config_files(&ssh_dir);
        if files.is_empty() && edit.keychain {
            files.push(main.clone());
        }
        let mut changed = vec![];
        for f in &files {
            let text = std::fs::read_to_string(f).unwrap_or_default();
            let (new, ch) = super::sshconfig::rewrite(&text, &edit, &socket, *f == main);
            if ch {
                r.before_edit(f)?;
                if !f.exists() {
                    crate::paths::write_private(f, new.as_bytes())?;
                } else {
                    write_keeping_mode(f, &new)?;
                }
                changed.push(tilde(f));
            }
        }
        if remove_agent {
            let home = super::home()?;
            for f in super::sshconfig::rc_files(&home) {
                let text = std::fs::read_to_string(&f)?;
                let (new, ch) = super::sshconfig::rewrite_rc(&text, &socket);
                if ch {
                    r.before_edit(&f)?;
                    write_keeping_mode(&f, &new)?;
                    changed.push(tilde(&f));
                }
            }
        }
        // check: a second pass finds nothing left to change
        for f in super::sshconfig::config_files(&ssh_dir) {
            let text = std::fs::read_to_string(&f).unwrap_or_default();
            if super::sshconfig::rewrite(&text, &edit, &socket, f == main).1 {
                bail!("{} still names sealctl", f.display());
            }
        }
        let note = if changed.is_empty() {
            "nothing to change".to_string()
        } else {
            format!("edited {}", changed.join(", "))
        };
        Ok((note, None))
    })?;
    let dests: Vec<String> = keys.iter().map(|k| tilde(&k.dest)).collect();
    Ok(format!(
        "ssh keys: {} {}.",
        dests.join(", "),
        if no_pass {
            "are standard key files (no passphrase)"
        } else {
            "are standard key files with your own passphrase"
        }
    ))
}

// ---------------------------------------------------------------- git ----

fn git_step_id(cfg: &crate::git::SigningConfig) -> String {
    let home = super::home().unwrap_or_default();
    let rel = cfg
        .file
        .strip_prefix(&home)
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| cfg.file.display().to_string());
    format!("git:{rel}")
}

/// The handed-back `.pub` whose key is `line` (`ssh-ed25519 AAAA…`).
pub(super) fn find_pub(line: &str, keys: &[SshKey]) -> Result<Option<PathBuf>> {
    for k in keys {
        if k.public == line {
            return Ok(Some(crate::ssh::public_path(&k.dest)));
        }
    }
    let dir = crate::paths::ssh_dir()?;
    let Ok(rd) = std::fs::read_dir(&dir) else {
        return Ok(None);
    };
    let mut pubs: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension().is_some_and(|x| x == "pub")
                && !p
                    .file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with("sealctl_"))
        })
        .collect();
    pubs.sort();
    for p in pubs {
        let text = std::fs::read_to_string(&p).unwrap_or_default();
        let l: Vec<&str> = text.split_whitespace().take(2).collect();
        if l.join(" ") == line {
            return Ok(Some(p));
        }
    }
    Ok(None)
}

fn git(r: &mut Runner, configs: &[crate::git::SigningConfig]) -> Result<String> {
    let keys: Vec<SshKey> = r
        .plan
        .objects
        .iter()
        .filter_map(|o| match o {
            Object::Ssh { keys } => Some(keys.clone()),
            _ => None,
        })
        .flatten()
        .collect();
    let mut used = vec![];
    for cfg in configs {
        let id = git_step_id(cfg);
        let pub_path = r.step(&id, |r| {
            if crate::git::handed_back(&cfg.file) {
                return Ok(("already handed back".into(), None));
            }
            let line = cfg
                .signingkey
                .as_deref()
                .and_then(crate::git::signingkey_line)
                .with_context(|| {
                    format!("{}: user.signingkey is not a key sealctl set", cfg.file.display())
                })?;
            let new_pub = find_pub(&line, &keys)?.ok_or_else(|| {
                exit(
                    2,
                    format!(
                        "{} signs with a key that is not handed back yet; run sealctl unseal ssh <name> first",
                        cfg.file.display()
                    ),
                )
            })?;
            let allowed = crate::paths::ssh_dir()?.join("allowed_signers");
            let public = PublicKey::from_openssh(&std::fs::read_to_string(&new_pub)?)?;

            // the passphrase of the key file, for the check
            let private = new_pub.with_extension("");
            let ssh_key = keys.iter().find(|k| k.dest == private).cloned();
            let pass = match &ssh_key {
                Some(k) if !r.plan.no_ssh_passphrase => {
                    Some(read_back(r, &format!("ssh:{}:password", k.name))?)
                }
                Some(_) => None,
                None => {
                    // handed back by an earlier run: the person knows the passphrase
                    let text = std::fs::read_to_string(&private).unwrap_or_default();
                    let enc = ssh_key::PrivateKey::from_openssh(&text)
                        .map(|k| k.is_encrypted())
                        .unwrap_or(false);
                    if enc {
                        let p = crate::util::read_hidden(&format!(
                            "Passphrase of {} (for a signing check): ",
                            tilde(&private)
                        ))?;
                        Some(Zeroizing::new(p.as_bytes().to_vec()))
                    } else {
                        None
                    }
                }
            };
            // a key without a passphrase: git signs with the key file itself, no agent needed;
            // with a passphrase: with the .pub, through the agent that holds it
            let signing = if pass.is_none() { private.clone() } else { new_pub.clone() };
            r.before_edit(&cfg.file)?;
            r.before_edit(&allowed)?;
            crate::git::merge_allowed_signers(&allowed, &[])?;
            let principal = match crate::git::principal_for(&allowed, &public) {
                Some(p) => p,
                None => {
                    let email = crate::git::config_get(&cfg.file, "user.email")
                        .unwrap_or_else(|| "git".into());
                    crate::git::merge_allowed_signers(
                        &allowed,
                        &[format!("{email} namespaces=\"git\" {line}")],
                    )?;
                    email
                }
            };
            crate::git::hand_back(cfg, &signing, &allowed)?;

            // check: sign as git does, verify with ssh-keygen against the allowed signers
            let key = crate::ssh::open_file(&private, pass.as_deref().map(|p| &p[..]))?;
            crate::git::test_sign(&key, &allowed, &principal)?;
            Ok((
                format!(
                    "signs with {} through ssh-keygen; test signature verified",
                    tilde(&signing)
                ),
                Some(json!({"pub": new_pub, "key": signing})),
            ))
        })?;
        if let Some(p) =
            pub_path.and_then(|d| d["key"].as_str().or_else(|| d["pub"].as_str()).map(PathBuf::from))
        {
            if !used.contains(&p) {
                used.push(p);
            }
        }
    }
    r.step("git:shim", |_r| {
        crate::git::remove_shim()?;
        Ok(("sealctl's gpg.ssh.program wrapper removed".into(), None))
    })?;
    let keys: Vec<String> = used.iter().map(|p| tilde(p)).collect();
    Ok(if keys.is_empty() {
        "git: signing goes through ssh-keygen.".to_string()
    } else {
        format!("git: signing goes through ssh-keygen with {}.", keys.join(", "))
    })
}

// ---------------------------------------------------------------- AI ----

fn ai(r: &mut Runner, tools: &[String]) -> Result<String> {
    for t in tools {
        r.step(&format!("ai:{t}:uninstall"), |r| {
            let installed = crate::ai::installed().iter().any(|(id, _)| id == t);
            if !installed {
                return Ok(("nothing installed".into(), None));
            }
            let files = crate::ai::files_of(std::slice::from_ref(t));
            for f in &files {
                r.before_edit(f)?;
            }
            let reports = crate::ai::uninstall(std::slice::from_ref(t))?;
            if let Some(err) = reports
                .iter()
                .flat_map(|rep| rep.lines.iter())
                .find(|l| l.starts_with('\u{274c}'))
            {
                bail!(
                    "removing from {t} failed: {}",
                    err.trim_start_matches('\u{274c}').trim()
                );
            }
            if crate::ai::installed().iter().any(|(id, _)| id == t) {
                bail!("sealctl is still installed in {t}");
            }
            for f in &files {
                crate::ai::still_parses(f)?;
            }
            Ok(("hooks, skill and rules removed; edited files parse".into(), None))
        })?;
    }
    let mut with_rules = vec![];
    let mut without = vec![];
    if r.plan.env_rules == Some(true) {
        let extra: Vec<String> = if r.plan.stores.secrets_to == StoreKind::Env {
            vec![r
                .plan
                .stores
                .env_file
                .clone()
                .or_else(|| store::default_env_file().ok())
                .unwrap_or_default()
                .display()
                .to_string()]
        } else {
            vec![]
        };
        for t in tools {
            if crate::ai::env_rules_file(t).is_some() {
                with_rules.push(t.clone());
            } else {
                without.push(t.clone());
            }
        }
        r.step("ai:env-rules", |r| {
            for t in &with_rules {
                let f = crate::ai::env_rules_file(t).context("rules file")?;
                r.before_edit(&f)?;
                crate::ai::write_env_rules(t, &extra)?;
                crate::ai::still_parses(&f)?;
            }
            Ok((
                format!(
                    "rules that keep agents away from .env files: {}",
                    with_rules.join(", ")
                ),
                None,
            ))
        })?;
    }
    let names = super::ai_names(tools);
    let mut s = format!("AI tools: {}: hooks and skill removed.", names.join(", "));
    if !with_rules.is_empty() {
        s.push_str(&format!(
            " .env rules kept in {}.",
            super::ai_names(&with_rules).join(", ")
        ));
    }
    if !without.is_empty() {
        s.push_str(&format!(
            " {} {} no such setting.",
            super::ai_names(&without).join(", "),
            if without.len() == 1 { "has" } else { "have" }
        ));
    }
    Ok(s)
}

// ---------------------------------------------------------------- services ----

fn services(r: &mut Runner, labels: &[String], agent: bool) -> Result<String> {
    for label in labels {
        let short = label.trim_start_matches(crate::service::LABEL_PREFIX).to_string();
        r.step(&format!("services:{short}"), |r| {
            if !crate::service::files_present(label) {
                return Ok(("already removed".into(), None));
            }
            for f in crate::service::files_of(label) {
                r.before_edit(&f)?;
            }
            crate::service::remove(label)?;
            if crate::service::files_present(label) {
                bail!("{label} is still installed");
            }
            Ok(("stopped and removed".into(), None))
        })?;
    }
    if agent {
        r.step("services:agent", |_r| {
            crate::agent::stop()?;
            for _ in 0..30 {
                if !crate::agent::session_alive() {
                    return Ok(("session agent stopped".into(), None));
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            bail!("the session agent is still running")
        })?;
    }
    let mut names: Vec<String> = labels
        .iter()
        .map(|l| l.trim_start_matches(crate::service::LABEL_PREFIX).to_string())
        .collect();
    if agent {
        names.push("session agent".into());
    }
    Ok(format!("services: {} stopped and removed.", names.join(", ")))
}

// ---------------------------------------------------------------- local state ----

fn local_state(r: &mut Runner) -> Result<String> {
    r.step("local:keys", |r| {
        let d = crate::paths::keys_dir()?;
        if d.exists() {
            r.run.keep(&d, "keys")?;
        }
        Ok(("certificate moved to kept/keys".into(), None))
    })?;
    let keep_store = r.plan.keep_store;
    r.step("local:data", |r| {
        let d = crate::paths::data_dir()?;
        if keep_store {
            return Ok(("kept in place (--keep-store)".into(), None));
        }
        if d.exists() {
            r.run.keep(&d, "data")?;
        }
        Ok(("~/.local/share/sealctl moved to kept/data".into(), None))
    })?;
    r.step("local:config", |r| {
        let d = crate::paths::config_dir()?;
        if d.exists() {
            r.run.keep(&d, "config")?;
        }
        Ok(("~/.config/sealctl moved to kept/config".into(), None))
    })?;
    r.step("local:state", |_r| {
        let d = crate::paths::state_dir()?;
        if d.exists() {
            std::fs::remove_dir_all(&d).with_context(|| format!("removing {}", d.display()))?;
        }
        Ok(("~/.local/state/sealctl removed".into(), None))
    })?;
    r.step("local:check", |_r| {
        let mut left = vec![];
        for d in [crate::paths::config_dir()?, crate::paths::state_dir()?] {
            if d.exists() {
                left.push(tilde(&d));
            }
        }
        if !keep_store && crate::paths::data_dir()?.exists() {
            left.push(tilde(&crate::paths::data_dir()?));
        }
        if !left.is_empty() {
            bail!("still there: {}", left.join(", "));
        }
        Ok(("sealctl's folders are gone".into(), None))
    })?;
    Ok("local files: sealctl's folders removed; the store and certificate are in the folder's kept/.".into())
}

// ---------------------------------------------------------------- reports ----

/// Which key opens an object now, from the journal (for the failure message).
pub fn opens_now(r: &Runner, o: &Object) -> String {
    match o {
        Object::Volume { volume } => {
            let n = &volume.name;
            if r.run.is_done(&format!("volume:{n}:change")) {
                format!(
                    "Volume {n} now opens with your new passphrase ({}).",
                    where_is(r, &format!("volume:{n}:password"))
                )
            } else {
                format!("Volume {n} still opens with sealctl's key (your Ledger).")
            }
        }
        Object::Backup { volume } => {
            let n = &volume.name;
            if r.run.is_done(&format!("backup:{n}:key-remove")) {
                format!(
                    "The backup of {n} opens with your new password ({}).",
                    where_is(r, &format!("backup:{n}:password"))
                )
            } else if r.run.is_done(&format!("backup:{n}:key-add")) {
                format!(
                    "The backup of {n} opens with sealctl's key and with your new password ({}).",
                    where_is(r, &format!("backup:{n}:password"))
                )
            } else {
                format!("The backup of {n} still opens with sealctl's key (your Ledger).")
            }
        }
        Object::Secrets { .. } => "The secret store is untouched and still opens with your Ledger.".into(),
        Object::Ssh { .. } => {
            "sealctl's SSH key files still open with your Ledger until they move to kept/ssh.".into()
        }
        _ => String::new(),
    }
}

fn where_is(r: &Runner, step: &str) -> String {
    loc_of(r, step)
        .map(|l| l.describe())
        .unwrap_or_else(|| "see the journal".into())
}

/// The hand-back list from the plan and the journal.
pub fn handback(r: &Runner) -> Handback {
    let mut h = Handback::new(&r.plan.machine);
    for o in &r.plan.objects {
        match o {
            Object::Secrets { names, .. } => {
                for n in names {
                    if let Some(l) = loc_of(r, &format!("secret:{n}:store")) {
                        h.objects.push(handback::Object {
                            kind: "secret".into(),
                            name: n.clone(),
                            value: Some(l),
                            ..Default::default()
                        });
                    }
                }
            }
            Object::Backup { volume } => {
                let n = &volume.name;
                let Some(pw) = loc_of(r, &format!("backup:{n}:password")) else {
                    continue;
                };
                let credentials = r
                    .run
                    .data(&format!("backup:{n}:credentials"))
                    .and_then(|d| d.as_object().cloned())
                    .map(|m| {
                        m.into_iter()
                            .filter_map(|(var, l)| {
                                serde_json::from_value(l)
                                    .ok()
                                    .map(|location| Credential { var, location })
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                h.objects.push(handback::Object {
                    kind: "backup".into(),
                    name: n.clone(),
                    url: volume.backup.as_ref().map(|b| b.repository.clone()),
                    password: Some(pw),
                    credentials,
                    ..Default::default()
                });
            }
            Object::Volume { volume } => {
                let n = &volume.name;
                if let Some(l) = loc_of(r, &format!("volume:{n}:password")) {
                    h.objects.push(handback::Object {
                        kind: "volume".into(),
                        name: n.clone(),
                        volume: Some(kind_name(volume.kind).into()),
                        uuid: Some(volume.id.clone()),
                        path: volume.path.as_deref().map(tilde),
                        password: Some(l),
                        ..Default::default()
                    });
                }
            }
            Object::Ssh { keys } => {
                for k in keys {
                    if !r.run.is_done(&format!("ssh:{}:export", k.name)) {
                        continue;
                    }
                    h.objects.push(handback::Object {
                        kind: "ssh".into(),
                        name: k.name.clone(),
                        path: Some(tilde(&k.dest)),
                        password: loc_of(r, &format!("ssh:{}:password", k.name)),
                        ..Default::default()
                    });
                }
            }
            _ => {}
        }
    }
    h
}
