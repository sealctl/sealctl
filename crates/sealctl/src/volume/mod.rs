//! Encrypted volumes (SPEC 13) on derived keys: the passphrase is `hex(volume key)`, where the
//! volume key is `derive(root, "volume:<volume-id>", 16)` handed out by the phone. Passphrases
//! reach the OS tools through stdin only.

pub mod apfs;
pub mod luks;
pub mod sparsebundle;

use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use sealctl_core::ids::IdFile;
use sealctl_core::wire::{ObjectFacts, RequestItem};
use sealctl_core::ObjectKey;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::exit::{self, fail};
use crate::paths;

/// Volume kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, clap::ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum Kind {
    /// macOS: encrypted APFS volume in an APFS container (default on macOS).
    #[serde(alias = "apfs-volume")]
    #[value(alias = "apfs-volume")]
    Apfs,
    /// macOS: encrypted APFS disk image in a sparse bundle folder (portable).
    Sparsebundle,
    /// Linux: LUKS2 container in a file, ext4 inside (default on Linux).
    Luks,
}

impl Kind {
    /// The default kind here.
    pub fn default_for_os() -> Kind {
        if cfg!(target_os = "macos") {
            Kind::Apfs
        } else {
            Kind::Luks
        }
    }

    /// `apfs`, `sparsebundle`, `luks`.
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Apfs => "apfs",
            Kind::Sparsebundle => "sparsebundle",
            Kind::Luks => "luks",
        }
    }

    /// `APFS`, `sparse bundle`, `LUKS`.
    pub fn label(self) -> &'static str {
        match self {
            Kind::Apfs => "APFS",
            Kind::Sparsebundle => "sparse bundle",
            Kind::Luks => "LUKS",
        }
    }
}

/// A volume definition in `~/.config/sealctl/volumes/<name>.toml`. No secrets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Volume {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: Kind,
    /// Image or container file (sparse bundle, LUKS).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<PathBuf>,
    /// Volume id (UUID): input of the key derivation.
    #[serde(default)]
    pub id: String,
    /// Words fingerprint of the words that sealed it.
    #[serde(default)]
    pub words: String,
    /// `check(volume key)`.
    #[serde(default)]
    pub check: String,
    /// Where it is mounted.
    pub mountpoint: PathBuf,
    /// Not mounted when the session opens.
    #[serde(default)]
    pub manual: bool,
}

/// Per-kind operations. Passphrases arrive as bytes and are only written to a tool's stdin.
pub trait Backend {
    /// Creates the volume. `key_for(id)` gives the passphrase for a volume id; the backend
    /// decides the id (generated, or assigned by the OS) and stores it in `v.id`.
    fn create(
        &self,
        v: &mut Volume,
        size: &str,
        key_for: &mut dyn FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Zeroizing<String>>;
    /// Reads the volume id from the (possibly locked) disk.
    fn read_id(&self, v: &Volume) -> Result<String>;
    /// Mounts with the passphrase.
    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()>;
    /// Unmounts.
    fn lock(&self, v: &Volume, force: bool) -> Result<()>;
    /// Mounted?
    fn is_unlocked(&self, v: &Volume) -> Result<bool>;
    /// Replaces the passphrase.
    fn change_passphrase(&self, v: &Volume, old: &[u8], new: &[u8]) -> Result<()>;
    /// Destroys the encrypted data.
    fn destroy(&self, v: &Volume) -> Result<()>;
}

/// The backend of a kind.
pub fn backend(kind: Kind) -> Box<dyn Backend> {
    match kind {
        Kind::Sparsebundle => Box::new(sparsebundle::Sparsebundle),
        Kind::Apfs => Box::new(apfs::ApfsVolume),
        Kind::Luks => Box::new(luks::Luks),
    }
}

/// Letters, digits, `-` and `_`, at most 40.
pub fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(fail(
            exit::USAGE,
            "Volume names may contain letters, digits, - and _ (at most 40).",
        ));
    }
    Ok(())
}

impl Volume {
    fn config_file_for(name: &str) -> Result<PathBuf> {
        Ok(paths::volumes_dir()?.join(format!("{name}.toml")))
    }

    /// Loads a definition (exit 9 when unknown).
    pub fn load(name: &str) -> Result<Volume> {
        validate_name(name)?;
        let p = Self::config_file_for(name)?;
        let text = fs::read_to_string(&p).map_err(|_| fail(exit::NOT_FOUND, format!("No volume {name}.")))?;
        let v: Volume = toml::from_str(&text).with_context(|| format!("reading {}", p.display()))?;
        if v.words.is_empty() {
            return Err(fail(
                exit::WRONG_KEY,
                format!("{} names no words: not a sealctl volume.", p.display()),
            ));
        }
        Ok(v)
    }

    /// Saves the definition.
    pub fn save(&self) -> Result<()> {
        paths::ensure_private_dir(&paths::volumes_dir()?)?;
        paths::write_private(
            &Self::config_file_for(&self.name)?,
            toml::to_string_pretty(self)?.as_bytes(),
        )
    }

    /// Every 0.7 definition, by name.
    pub fn list() -> Result<Vec<Volume>> {
        let Ok(rd) = fs::read_dir(paths::volumes_dir()?) else {
            return Ok(vec![]);
        };
        let mut v: Vec<Volume> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "toml"))
            .filter_map(|p| {
                fs::read_to_string(&p)
                    .ok()
                    .and_then(|t| toml::from_str::<Volume>(&t).ok())
            })
            .filter(|v| !v.words.is_empty())
            .collect();
        v.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(v)
    }

    /// Mounted?
    pub fn is_open(&self) -> bool {
        backend(self.kind).is_unlocked(self).unwrap_or(false)
    }

    /// The `keys` item for its key.
    pub fn request_item(&self) -> RequestItem {
        RequestItem {
            purpose: "volume".into(),
            id: self.id.clone(),
            words: Some(self.words.clone()),
            check: Some(self.check.clone()),
            object: Some(self.facts()),
        }
    }

    fn facts(&self) -> ObjectFacts {
        let path = match &self.path {
            Some(p) => paths::tilde(p),
            None => self.id.clone(),
        };
        let size = self.path.as_ref().map(|p| dir_size(p)).unwrap_or(0);
        ObjectFacts {
            kind: "volume".into(),
            path,
            size,
        }
    }

    /// Checks a key against the definition (exit 10).
    pub fn check_key(&self, key: &ObjectKey) -> Result<()> {
        if key.check() != self.check {
            return Err(fail(
                exit::WRONG_KEY,
                format!("The key does not open volume {} (check mismatch).", self.name),
            ));
        }
        Ok(())
    }

    /// The `.id` object for this volume.
    pub fn id_file(&self) -> IdFile {
        IdFile {
            sealctl: 1,
            kind: "volume".into(),
            id: self.id.clone(),
            words: self.words.clone(),
            check: self.check.clone(),
            created: crate::clock::utc_rfc3339(jiff::Timestamp::now()),
            format: None,
            own: None,
            volume: Some(self.kind.as_str().into()),
        }
    }
}

fn dir_size(p: &Path) -> u64 {
    let Ok(m) = fs::metadata(p) else { return 0 };
    if !m.is_dir() {
        return m.len();
    }
    fs::read_dir(p)
        .map(|rd| rd.flatten().map(|e| dir_size(&e.path())).sum())
        .unwrap_or(0)
}

/// What `volume create` needs.
pub struct CreateOpts {
    /// Name.
    pub name: String,
    /// Kind.
    pub kind: Kind,
    /// Size, e.g. `50g`.
    pub size: String,
    /// Image path.
    pub path: Option<PathBuf>,
    /// APFS container.
    pub container: Option<String>,
    /// Mount point.
    pub mountpoint: Option<PathBuf>,
    /// `--manual`.
    pub manual: bool,
}

fn default_vault_dir() -> Result<PathBuf> {
    Ok(paths::home()?.join("Vaults"))
}

/// The default mount point of a kind.
pub fn default_mountpoint(kind: Kind, name: &str) -> Result<PathBuf> {
    Ok(match kind {
        Kind::Luks => default_vault_dir()?.join(name),
        _ => PathBuf::from("/Volumes").join(name),
    })
}

/// A key handed out for a new object: the key and the words fingerprint that made it.
pub type NewKey<'a> = dyn FnMut(&RequestItem) -> Result<(ObjectKey, String)> + 'a;

/// Creates a volume with a key from `new_key`, then mounts it with that key.
pub fn create(opts: CreateOpts, new_key: &mut NewKey<'_>) -> Result<Volume> {
    validate_name(&opts.name)?;
    if Volume::config_file_for(&opts.name)?.exists() {
        return Err(fail(exit::USAGE, format!("Volume {} exists already.", opts.name)));
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
        Kind::Apfs => None,
    };
    if let Some(p) = &path {
        if p.exists() {
            return Err(fail(exit::USAGE, format!("{} exists already.", p.display())));
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
        id: opts.container.clone().unwrap_or_default(),
        words: String::new(),
        check: String::new(),
        mountpoint,
        manual: opts.manual,
    };
    let be = backend(vol.kind);
    let mut got: Option<(String, String)> = None;
    let facts_path = vol.path.as_ref().map(|p| paths::tilde(p)).unwrap_or_default();
    let mut key_for = |id: &str| -> Result<Zeroizing<String>> {
        let id = id.to_lowercase();
        let item = RequestItem {
            purpose: "volume".into(),
            id: id.clone(),
            words: None,
            check: None,
            object: Some(ObjectFacts {
                kind: "volume".into(),
                path: if facts_path.is_empty() {
                    id.clone()
                } else {
                    facts_path.clone()
                },
                size: 0,
            }),
        };
        let (key, words) = new_key(&item)?;
        got = Some((words, key.check()));
        Ok(key.hex())
    };
    let pass = be.create(&mut vol, &opts.size, &mut key_for)?;
    let (words, check) = got.context("no key was asked for")?;
    vol.id = vol.id.to_lowercase();
    vol.words = words;
    vol.check = check;
    write_marker(&vol)?;
    vol.save()?;
    be.unlock(&vol, pass.as_bytes())
        .context("mounting the new volume with its key")?;
    write_inner_id(&vol);
    Ok(vol)
}

/// The words marker readable while locked: `sealctl.id` in a sparse bundle, the APFS hint, the
/// LUKS2 token.
pub fn write_marker(vol: &Volume) -> Result<()> {
    match vol.kind {
        Kind::Sparsebundle => sparsebundle::write_id(vol, &vol.id_file().to_json()),
        Kind::Apfs => apfs::set_hint(vol, &format!("sealctl {}", vol.words)),
        Kind::Luks => luks::import_token(vol, &vol.id_file()),
    }
}

/// `<mount>/.sealctl/volume.id`, once mounted (best effort: the top folder may be root's).
pub fn write_inner_id(vol: &Volume) {
    let dir = vol.mountpoint.join(".sealctl");
    if fs::create_dir_all(&dir).is_ok() {
        let _ = paths::write_mode(&dir.join("volume.id"), vol.id_file().to_json().as_bytes(), 0o644);
    }
}

/// Mounts a volume with its key (checked against the definition first).
pub fn open_with(vol: &Volume, key: &ObjectKey) -> Result<()> {
    vol.check_key(key)?;
    let be = backend(vol.kind);
    if be.is_unlocked(vol)? {
        return Ok(());
    }
    be.unlock(vol, key.hex().as_bytes())?;
    write_inner_id(vol);
    Ok(())
}

/// The process holding files open under a mount point: `(name, pid)`.
pub fn holder(mountpoint: &Path) -> Option<(String, u64)> {
    if cfg!(target_os = "macos") {
        let out = crate::util::system_cmd("lsof")
            .args(["-F", "pcn"])
            .arg(mountpoint)
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        let pid = text.lines().find_map(|l| l.strip_prefix('p'))?.parse().ok()?;
        let cmd = text.lines().find_map(|l| l.strip_prefix('c'))?.to_string();
        Some((cmd, pid))
    } else {
        let out = crate::util::system_cmd("fuser")
            .arg("-vm")
            .arg(mountpoint)
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&out.stderr);
        text.lines().skip(1).find_map(|l| {
            let f: Vec<&str> = l.split_whitespace().collect();
            let pid = f.iter().find_map(|x| x.parse::<u64>().ok())?;
            Some((f.last()?.to_string(), pid))
        })
    }
}

/// Unmounts; a busy volume names the process holding it (exit 11).
pub fn close(vol: &Volume, force: bool) -> Result<()> {
    let be = backend(vol.kind);
    if !be.is_unlocked(vol)? {
        return Ok(());
    }
    if let Err(e) = be.lock(vol, force) {
        if let Some((p, pid)) = holder(&vol.mountpoint) {
            return Err(fail(
                exit::BUSY,
                format!("Volume {} is busy: {p} (pid {pid}) has files open.", vol.name),
            ));
        }
        if be.is_unlocked(vol).unwrap_or(true) {
            return Err(fail(exit::BUSY, format!("Volume {} is busy: {e:#}", vol.name)));
        }
    }
    Ok(())
}

/// Forgets a definition; with `delete_data` also destroys the data.
pub fn remove(name: &str, delete_data: bool) -> Result<()> {
    let vol = Volume::load(name)?;
    if vol.is_open() {
        bail!("close {name} first: sealctl volume close {name}");
    }
    if delete_data {
        backend(vol.kind).destroy(&vol)?;
    }
    let _ = fs::remove_file(Volume::config_file_for(name)?);
    Ok(())
}

/// Reads the words marker and id of an existing sealctl volume (for `volume import`).
pub fn read_marker(kind: Kind, target: &str) -> Result<Option<IdFile>> {
    match kind {
        Kind::Sparsebundle => {
            let p = Path::new(target).join("sealctl.id");
            match fs::read_to_string(&p) {
                Ok(t) => match sealctl_core::ids::IdFile::parse(&t) {
                    Ok(f) => Ok(Some(f)),
                    Err(_) => Ok(None),
                },
                Err(_) => Ok(None),
            }
        }
        _ => Ok(None),
    }
}

/// Compares paths after resolving symlinks (macOS reports `/private/var/…` for `/var/…`).
pub fn same_path(a: &Path, b: &Path) -> bool {
    let canon = |p: &Path| fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    !a.as_os_str().is_empty() && (a == b || canon(a) == canon(b))
}
