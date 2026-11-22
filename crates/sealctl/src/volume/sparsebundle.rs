//! macOS encrypted APFS sparse bundle (`hdiutil`). No admin rights needed; the image is a
//! folder of 8 MB bands. sealctl stores the volume id in `<bundle>/sealctl.id` (plaintext,
//! not secret) so the derived key can be recomputed from the bundle alone.

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Backend, Volume};

use crate::util::{check, run_with_stdin};

pub struct Sparsebundle;

const ID_FILE: &str = "sealctl.id";

/// Writes `<bundle>/sealctl.id`: the volume's `.id` file (public).
pub fn write_id(v: &Volume, text: &str) -> Result<()> {
    let path = v.path.as_ref().context("sparsebundle needs a path")?;
    crate::paths::write_mode(&path.join(ID_FILE), text.as_bytes(), 0o644)
        .context("writing the volume id into the bundle")
}

/// `<bundle>/sealctl.id`.
pub fn id_path(v: &Volume) -> Option<std::path::PathBuf> {
    v.path.as_ref().map(|p| p.join(ID_FILE))
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

impl Backend for Sparsebundle {
    fn create(
        &self,
        v: &mut Volume,
        size: &str,
        key_for: &mut dyn FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Zeroizing<String>> {
        let path = v.path.clone().context("sparsebundle needs a path")?;
        let id = crate::util::new_uuid()?;
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
        Ok(pass)
    }

    fn read_id(&self, v: &Volume) -> Result<String> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        let text = std::fs::read_to_string(path.join(ID_FILE))
            .with_context(|| format!("{} has no {ID_FILE}: not a sealctl volume?", path.display()))?;
        match sealctl_core::ids::IdFile::parse(&text) {
            Ok(f) => Ok(f.id),
            Err(_) => anyhow::bail!("{} is damaged", path.join(ID_FILE).display()),
        }
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

    fn destroy(&self, v: &Volume) -> Result<()> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        if path.exists() {
            std::fs::remove_dir_all(path)?;
        }
        Ok(())
    }
}

/// Does `passphrase` open the bundle? Attaches without mounting, then detaches.
pub fn verify(path: &std::path::Path, passphrase: &[u8]) -> Result<bool> {
    let out = run_with_stdin(
        crate::util::system_cmd("hdiutil")
            .args(["attach", "-nomount", "-plist", "-stdinpass"])
            .arg(path),
        passphrase,
    )?;
    if !out.status.success() {
        return Ok(false);
    }
    let text = String::from_utf8_lossy(&out.stdout);
    // the first /dev/diskN entity is the whole image
    if let Some(dev) = text
        .split("<string>")
        .filter_map(|s| s.split("</string>").next())
        .find(|s| s.starts_with("/dev/disk"))
    {
        let base: String = dev.trim_start_matches("/dev/").to_string();
        let whole = base
            .char_indices()
            .skip(4)
            .find(|(_, c)| *c == 's')
            .map_or(base.clone(), |(i, _)| base[..i].to_string());
        let _ = crate::util::system_cmd("hdiutil")
            .args(["detach", "-quiet", &format!("/dev/{whole}")])
            .output();
    }
    Ok(true)
}

/// Replaces the passphrase (`hdiutil chpass`).
pub fn change_passphrase(path: &std::path::Path, old: &[u8], new: &[u8]) -> Result<()> {
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
