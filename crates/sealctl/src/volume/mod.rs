//! Encrypted volumes whose passphrase is **derived from the Ledger seed and the volume's UUID**
//! (see `crate::derive`). No key file exists anywhere: with only the 24 words, any sealctl volume
//! can be opened again — the UUID is read from the (locked) disk itself.
//!
//! The passphrase goes to the OS tool through stdin only and is zeroized afterwards.

pub mod apfs;
pub mod luks;
pub mod sparsebundle;

use std::fs;
use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::derive::{self, Oracle, Purpose};
use crate::paths;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// macOS: encrypted APFS disk image in a file.
    Sparsebundle,
    /// macOS: encrypted APFS volume in an APFS container, e.g. the internal disk (default).
    ApfsVolume,
    /// Linux: LUKS2 container in a file, ext4 inside (default on Linux).
    Luks,
}

impl Kind {
    pub fn default_for_os() -> Kind {
        if cfg!(target_os = "macos") {
            Kind::ApfsVolume
        } else {
            Kind::Luks
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupPolicy {
    /// restic repository URL.
    #[serde(default)]
    pub repository: String,
    /// Id the repository password is derived from (with the Ledger seed). New repositories use
    /// the volume name, so the repository can move to another URL/provider and is recovered
    /// with only the seed and the name. Absent (repositories from 0.2.0): the URL is the id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// Back up before `sealctl lock`.
    #[serde(default = "yes")]
    pub on_lock: bool,
    /// Include in scheduled backups (`sealctl backup run --all`).
    #[serde(default = "yes")]
    pub scheduled: bool,
    #[serde(default = "d7")]
    pub keep_daily: u32,
    #[serde(default = "d4")]
    pub keep_weekly: u32,
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

impl BackupPolicy {
    pub fn new(repository: &str, key_id: &str) -> Self {
        Self {
            repository: repository.to_string(),
            key_id: Some(key_id.to_string()),
            on_lock: true,
            scheduled: true,
            keep_daily: 7,
            keep_weekly: 4,
            keep_monthly: 12,
        }
    }

    /// The id the repository password is derived from.
    pub fn password_id(&self) -> &str {
        self.key_id.as_deref().unwrap_or(&self.repository)
    }
}

/// A volume definition, stored in `~/.config/sealctl/volumes/<name>.toml`. Contains no secrets
/// and is only a convenience: `sealctl volume import` recreates it from the disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    pub name: String,
    pub kind: Kind,
    /// Image / container file (sparsebundle, luks).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// The volume UUID — input of the key derivation. Empty for legacy volumes (see `rekey`).
    #[serde(default, alias = "uuid")]
    pub id: String,
    /// Where the volume is mounted when unlocked.
    pub mountpoint: PathBuf,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backup: Option<BackupPolicy>,
}

/// Per-kind operations. Passphrases arrive as bytes and must only be written to a tool's stdin.
pub trait Backend {
    /// Create the volume. `key_for(id)` derives the passphrase for a volume id; the backend
    /// decides the id (generated, or assigned by the OS) and stores it in `v.id`.
    fn create(
        &self,
        v: &mut Volume,
        size: &str,
        key_for: &mut dyn FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Zeroizing<String>>;
    /// Read the volume id from the (possibly locked) disk.
    fn read_id(&self, v: &Volume) -> Result<String>;
    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()>;
    fn lock(&self, v: &Volume, force: bool) -> Result<()>;
    fn is_unlocked(&self, v: &Volume) -> Result<bool>;
    fn change_passphrase(&self, v: &Volume, old: &[u8], new: &[u8]) -> Result<()>;
    /// Does `passphrase` open the volume? Changes nothing: the volume stays mounted or locked
    /// as it is. `Ok(false)` means "wrong passphrase"; errors mean the check could not run.
    fn verify(&self, v: &Volume, passphrase: &[u8]) -> Result<bool>;
    /// Permanently delete the encrypted data.
    fn destroy(&self, v: &Volume) -> Result<()>;
}

pub fn backend(kind: Kind) -> Box<dyn Backend> {
    match kind {
        Kind::Sparsebundle => Box::new(sparsebundle::Sparsebundle),
        Kind::ApfsVolume => Box::new(apfs::ApfsVolume),
        Kind::Luks => Box::new(luks::Luks),
    }
}

pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("volume names may contain letters, digits, - and _ (max 40)");
    }
    Ok(())
}

impl Volume {
    pub fn config_file_for(name: &str) -> Result<PathBuf> {
        Ok(paths::volumes_dir()?.join(format!("{name}.toml")))
    }

    /// Key file of volumes created before derived keys (removed by `rekey`).
    pub fn legacy_key_file(&self) -> Result<PathBuf> {
        Ok(paths::volumes_dir()?.join(format!("{}.key.asc", self.name)))
    }

    /// Directory inside the unlocked volume holding its backup settings.
    pub fn inner_dir(&self) -> PathBuf {
        self.mountpoint.join(".sealctl")
    }

    pub fn load(name: &str) -> Result<Volume> {
        validate_name(name)?;
        let p = Self::config_file_for(name)?;
        let text =
            fs::read_to_string(&p).with_context(|| format!("unknown volume '{name}' ({})", p.display()))?;
        Ok(toml::from_str(&text)?)
    }

    pub fn save(&self) -> Result<()> {
        let dir = paths::volumes_dir()?;
        paths::ensure_private_dir(&dir)?;
        paths::write_private(
            &Self::config_file_for(&self.name)?,
            toml::to_string_pretty(self)?.as_bytes(),
        )
    }

    pub fn list() -> Result<Vec<Volume>> {
        let Ok(rd) = fs::read_dir(paths::volumes_dir()?) else {
            return Ok(vec![]);
        };
        let mut v: Vec<Volume> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .filter_map(|p| fs::read_to_string(&p).ok().and_then(|t| toml::from_str(&t).ok()))
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    pub fn is_unlocked(&self) -> Result<bool> {
        backend(self.kind).is_unlocked(self)
    }

    pub fn is_legacy(&self) -> bool {
        self.id.is_empty()
    }
}

pub struct CreateOpts {
    pub name: String,
    pub kind: Kind,
    pub size: String,
    pub path: Option<PathBuf>,
    pub container: Option<String>,
    pub mountpoint: Option<PathBuf>,
}

fn default_vault_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(std::env::var_os("HOME").context("$HOME")?).join("Vaults"))
}

fn default_mountpoint(kind: Kind, name: &str) -> Result<PathBuf> {
    Ok(match kind {
        Kind::Luks => default_vault_dir()?.join(name),
        _ => PathBuf::from("/Volumes").join(name),
    })
}

/// Create a volume whose passphrase is derived on the Ledger, then mount it with the derived
/// passphrase — which proves the Ledger-derived key opens it.
pub fn create(oracle: &mut dyn Oracle, opts: CreateOpts) -> Result<Volume> {
    validate_name(&opts.name)?;
    if Volume::config_file_for(&opts.name)?.exists() {
        bail!("volume '{}' already exists", opts.name);
    }
    let path = match opts.kind {
        Kind::Sparsebundle => Some(
            opts.path
                .clone()
                .unwrap_or(default_vault_dir()?.join(format!("{}.sparsebundle", opts.name))),
        ),
        Kind::Luks => Some(
            opts.path
                .clone()
                .unwrap_or(default_vault_dir()?.join(format!("{}.luks", opts.name))),
        ),
        Kind::ApfsVolume => None,
    };
    if let Some(p) = &path {
        if p.exists() {
            bail!("{} already exists", p.display());
        }
        if let Some(d) = p.parent() {
            fs::create_dir_all(d)?;
        }
    }
    let mountpoint = match opts.mountpoint {
        Some(m) => m,
        None => default_mountpoint(opts.kind, &opts.name)?,
    };
    let mut vol = Volume {
        name: opts.name.clone(),
        kind: opts.kind,
        path,
        // apfs-volume: carries the target container until the OS assigns the volume UUID
        id: opts.container.clone().unwrap_or_default(),
        mountpoint,
        backup: None,
    };
    let be = backend(vol.kind);
    let mut key_for = |id: &str| derive::passphrase(oracle, Purpose::Volume, &derive::canonical_id(id));
    let pass = be.create(&mut vol, &opts.size, &mut key_for)?;
    vol.id = derive::canonical_id(&vol.id);
    vol.save()?;
    be.unlock(&vol, pass.as_bytes())
        .context("mounting the new volume with its derived key")?;
    Ok(vol)
}

/// Unlock: read the UUID from the disk, derive the passphrase on the Ledger, unlock.
pub fn unlock(oracle: &mut dyn Oracle, name: &str) -> Result<Volume> {
    let mut vol = Volume::load(name)?;
    let be = backend(vol.kind);
    if be.is_unlocked(&vol)? {
        println!(
            "'{}' is already unlocked at {}",
            vol.name,
            vol.mountpoint.display()
        );
        return Ok(vol);
    }
    if vol.is_legacy() {
        bail!("'{name}' uses a stored key file (older sealctl) — convert it once with `sealctl volume rekey {name}`");
    }
    // The disk is the source of truth for the id — but the config is only updated once the
    // disk's id has actually unlocked it (a damaged id file must not overwrite a good id).
    let disk_id = derive::canonical_id(&be.read_id(&vol)?);
    if disk_id != vol.id {
        eprintln!(
            "note: volume id on disk ({disk_id}) differs from config ({}); trying the disk's",
            vol.id
        );
        let config_id = std::mem::replace(&mut vol.id, disk_id);
        let pass = derive::passphrase(oracle, Purpose::Volume, &vol.id)?;
        match be.unlock(&vol, pass.as_bytes()) {
            Ok(()) => vol.save()?,
            Err(e) => {
                eprintln!("   that failed ({e:#}); trying the id from the config");
                vol.id = config_id;
                let pass = derive::passphrase(oracle, Purpose::Volume, &vol.id)?;
                be.unlock(&vol, pass.as_bytes())?;
            }
        }
        println!("🔓 '{}' unlocked at {}", vol.name, vol.mountpoint.display());
        return Ok(vol);
    }
    let pass = derive::passphrase(oracle, Purpose::Volume, &vol.id)?;
    be.unlock(&vol, pass.as_bytes())?;
    println!("🔓 '{}' unlocked at {}", vol.name, vol.mountpoint.display());
    Ok(vol)
}

pub fn lock(name: &str, no_backup: bool, force: bool) -> Result<()> {
    let vol = Volume::load(name)?;
    let be = backend(vol.kind);
    if !be.is_unlocked(&vol)? {
        println!("'{}' is already locked", vol.name);
        return Ok(());
    }
    if let Some(policy) = &vol.backup {
        if policy.on_lock && !no_backup {
            println!("backing up '{}' before locking…", vol.name);
            if let Err(e) = crate::backup::run_one(&vol, false) {
                // Locking protects the data; never keep it exposed because a backup failed.
                eprintln!(
                    "⚠️  backup failed: {e:#}\n   locking anyway — run `sealctl backup run {}` later",
                    vol.name
                );
            }
        }
    }
    be.lock(&vol, force)?;
    println!("🔒 '{}' locked", vol.name);
    Ok(())
}

/// Lock every unlocked volume (e.g. before leaving the computer).
/// Lock every unlocked volume; one that refuses doesn't stop the others.
pub fn lock_all(no_backup: bool, force: bool) -> Result<()> {
    let mut failed = vec![];
    for v in Volume::list()? {
        if v.is_unlocked().unwrap_or(false) {
            if let Err(e) = lock(&v.name, no_backup, force) {
                eprintln!("❌ '{}': {e:#}", v.name);
                failed.push(v.name);
            }
        }
    }
    if !failed.is_empty() {
        bail!(
            "could not lock {} — close programs using it, or add --force",
            failed.join(", ")
        );
    }
    Ok(())
}

/// Forget a volume definition; with `delete_data` also destroy the encrypted data.
pub fn remove(name: &str, delete_data: bool) -> Result<()> {
    let vol = Volume::load(name)?;
    if vol.is_unlocked()? {
        bail!("lock '{name}' first");
    }
    if delete_data {
        backend(vol.kind).destroy(&vol)?;
    }
    let _ = fs::remove_file(Volume::config_file_for(name)?);
    let _ = fs::remove_file(vol.legacy_key_file()?);
    Ok(())
}

/// Register an existing sealctl volume on this machine (e.g. after recovery from the seed):
/// a sparsebundle or LUKS file by path, or an APFS volume by UUID.
pub fn import(name: &str, kind: Kind, target: &str, mountpoint: Option<PathBuf>) -> Result<Volume> {
    validate_name(name)?;
    if Volume::config_file_for(name)?.exists() {
        bail!("volume '{name}' already exists");
    }
    let mut vol = Volume {
        name: name.to_string(),
        kind,
        path: None,
        id: String::new(),
        mountpoint: match mountpoint {
            Some(m) => m,
            None => default_mountpoint(kind, name)?,
        },
        backup: None,
    };
    match kind {
        Kind::ApfsVolume => vol.id = target.to_string(),
        _ => vol.path = Some(fs::canonicalize(target).with_context(|| format!("{target} not found"))?),
    }
    vol.id = derive::canonical_id(&backend(kind).read_id(&vol)?);
    vol.save()?;
    println!(
        "✅ imported '{name}' (id {}) — unlock with `sealctl unlock {name}`",
        vol.id
    );
    Ok(vol)
}

/// Convert a volume from an older sealctl (passphrase in an OpenPGP key file) to a derived key,
/// then delete the key file.
pub fn rekey(ctx: &crate::Ctx, oracle: &mut dyn Oracle, name: &str) -> Result<()> {
    let mut vol = Volume::load(name)?;
    if !vol.is_legacy() {
        println!("'{name}' already uses a derived key");
        return Ok(());
    }
    let be = backend(vol.kind);
    let key_file = vol.legacy_key_file()?;
    let old = crate::crypto::decrypt(ctx, &fs::read(&key_file).context("legacy key file missing")?)?;
    match vol.kind {
        Kind::Sparsebundle => {
            let id = derive::new_uuid()?;
            sparsebundle::write_id(&vol, &id)?;
            vol.id = id;
        }
        _ => vol.id = derive::canonical_id(&be.read_id(&vol)?),
    }
    let new = derive::passphrase(oracle, Purpose::Volume, &vol.id)?;
    be.change_passphrase(&vol, &old, new.as_bytes())?;
    vol.save()?;
    fs::remove_file(&key_file)?;
    println!(
        "✅ '{name}' now uses a key derived from your Ledger seed; {} removed",
        key_file.display()
    );
    Ok(())
}

/// Compare paths after resolving symlinks (macOS reports `/private/var/…` for `/var/…`).
pub(crate) fn same_path(a: &std::path::Path, b: &std::path::Path) -> bool {
    let canon = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    !a.as_os_str().is_empty() && (a == b || canon(a) == canon(b))
}
