//! macOS encrypted APFS sparse bundle (`hdiutil`). No admin rights needed; the image is a
//! folder of 8 MB bands. sealctl stores the volume id in `<bundle>/sealctl.id` (plaintext,
//! not secret) so the derived key can be recomputed from the bundle alone.

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Backend, Volume};
use crate::derive;
use crate::util::{check, run_with_stdin};

pub struct Sparsebundle;

const ID_FILE: &str = "sealctl.id";

pub fn write_id(v: &Volume, id: &str) -> Result<()> {
    let path = v.path.as_ref().context("sparsebundle needs a path")?;
    std::fs::write(path.join(ID_FILE), format!("{id}\n")).context("writing the volume id into the bundle")
}

/// Mount points of attached images whose image-path equals `path` (from `hdiutil info`).
pub fn attached_mounts(path: &std::path::Path) -> Result<Vec<String>> {
    let out = check(
        crate::util::system_cmd("hdiutil").arg("info").output()?,
        "hdiutil info",
    )?;
    let text = String::from_utf8_lossy(&out.stdout);
    let want = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mut mounts = Vec::new();
    for block in text.split("================================================") {
        let image = block.lines().find_map(|l| {
            l.strip_prefix("image-path")
                .map(|r| r.trim_start_matches([' ', ':', '\t']).trim())
        });
        let Some(image) = image else { continue };
        let image = std::fs::canonicalize(image).unwrap_or_else(|_| image.into());
        if image != want {
            continue;
        }
        for l in block.lines().filter(|l| l.starts_with("/dev/")) {
            if let Some(mp) = l.split('\t').map(str::trim).filter(|s| s.starts_with('/')).nth(1) {
                mounts.push(mp.to_string());
            }
        }
        if mounts.is_empty() {
            mounts.push(String::new()); // attached but not mounted
        }
    }
    Ok(mounts)
}

/// Remove `<bundle>/sealctl.id` (when the bundle leaves sealctl).
pub fn remove_id(v: &Volume) -> Result<()> {
    let path = v.path.as_ref().context("sparsebundle needs a path")?;
    match std::fs::remove_file(path.join(ID_FILE)) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Is the image attached at all (mounted or not)? `hdiutil chpass` refuses an attached image,
/// and `hdiutil attach` of an attached image succeeds with any passphrase.
pub fn is_attached(v: &Volume) -> Result<bool> {
    let path = v.path.as_ref().context("sparsebundle needs a path")?;
    Ok(!attached_mounts(path)?.is_empty())
}

/// Devices of the image's `hdiutil attach` output (`/dev/diskN` first).
fn attached_devices(stdout: &str) -> Vec<String> {
    stdout
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|d| d.starts_with("/dev/"))
        .map(str::to_string)
        .collect()
}

impl Backend for Sparsebundle {
    fn create(
        &self,
        v: &mut Volume,
        size: &str,
        key_for: &mut dyn FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Zeroizing<String>> {
        let path = v.path.clone().context("sparsebundle needs a path")?;
        let id = derive::new_uuid()?;
        let pass = key_for(&id)?;
        let out = run_with_stdin(
            crate::util::system_cmd("hdiutil")
                .args([
                    "create",
                    "-quiet",
                    "-size",
                    size,
                    "-type",
                    "SPARSEBUNDLE",
                    "-fs",
                    "APFS",
                ])
                .args(["-encryption", "AES-256", "-stdinpass", "-volname", &v.name])
                .arg(&path),
            pass.as_bytes(),
        )?;
        check(out, "hdiutil create")?;
        v.id = id.clone();
        write_id(v, &id)?;
        Ok(pass)
    }

    fn read_id(&self, v: &Volume) -> Result<String> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        let id = std::fs::read_to_string(path.join(ID_FILE))
            .with_context(|| format!("{} has no {ID_FILE} — not a sealctl volume?", path.display()))?;
        Ok(id.trim().to_string())
    }

    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        let mut cmd = crate::util::system_cmd("hdiutil");
        cmd.args(["attach", "-quiet", "-stdinpass", "-owners", "on"]);
        let default_mp = std::path::Path::new("/Volumes").join(&v.name);
        if v.mountpoint != default_mp {
            std::fs::create_dir_all(&v.mountpoint)?;
            cmd.arg("-mountpoint").arg(&v.mountpoint);
        }
        cmd.arg(path);
        check(
            run_with_stdin(&mut cmd, passphrase)?,
            "hdiutil attach (wrong key?)",
        )?;
        if !self.is_unlocked(v)? {
            bail!("image attached but not mounted at {}", v.mountpoint.display());
        }
        Ok(())
    }

    fn lock(&self, v: &Volume, force: bool) -> Result<()> {
        let mut cmd = crate::util::system_cmd("hdiutil");
        cmd.args(["detach", "-quiet"]);
        if force {
            cmd.arg("-force");
        }
        cmd.arg(&v.mountpoint);
        check(cmd.output()?, "hdiutil detach (files still open? use --force)")?;
        Ok(())
    }

    fn is_unlocked(&self, v: &Volume) -> Result<bool> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        Ok(attached_mounts(path)?
            .iter()
            .any(|m| super::same_path(std::path::Path::new(m), &v.mountpoint)))
    }

    fn change_passphrase(&self, v: &Volume, old: &[u8], new: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        let mut input = Zeroizing::new(Vec::with_capacity(old.len() + new.len() + 2));
        input.extend_from_slice(old);
        input.push(0);
        input.extend_from_slice(new);
        input.push(0);
        check(
            run_with_stdin(
                crate::util::system_cmd("hdiutil")
                    .args(["chpass", "-oldstdinpass", "-newstdinpass"])
                    .arg(path),
                &input,
            )?,
            "hdiutil chpass",
        )?;
        Ok(())
    }

    /// `hdiutil attach -nomount -stdinpass`, then `hdiutil detach`. The image must be detached
    /// (an attached image accepts any passphrase), so an attached one is an error.
    fn verify(&self, v: &Volume, passphrase: &[u8]) -> Result<bool> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        if is_attached(v)? {
            bail!("{} is attached; eject it first (hdiutil detach)", path.display());
        }
        let out = run_with_stdin(
            crate::util::system_cmd("hdiutil")
                .args(["attach", "-nomount", "-noverify", "-noautofsck", "-stdinpass"])
                .arg(path),
            passphrase,
        )?;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            if err.contains("Authentication error") || err.contains("authentication") {
                return Ok(false);
            }
            bail!(
                "hdiutil attach failed: {}",
                err.trim().lines().last().unwrap_or("")
            );
        }
        let devs = attached_devices(&String::from_utf8_lossy(&out.stdout));
        if let Some(first) = devs.first() {
            check(
                crate::util::system_cmd("hdiutil")
                    .args(["detach", "-quiet", first])
                    .output()?,
                "hdiutil detach",
            )?;
        }
        Ok(true)
    }

    fn destroy(&self, v: &Volume) -> Result<()> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        if path.exists() {
            std::fs::remove_dir_all(path)?;
        }
        Ok(())
    }
}
