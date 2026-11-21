//! macOS encrypted APFS volume inside an APFS container (`diskutil apfs`) — what Disk Utility's
//! "Add APFS volume → APFS (Encrypted)" creates. The volume UUID (readable while locked) is the
//! input of the key derivation.

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Backend, Volume};
use crate::util::{check, random_secret, run_with_stdin};

pub struct ApfsVolume;

fn info_value(target: &str, key: &str) -> Result<Option<String>> {
    let out = crate::util::system_cmd("diskutil")
        .args(["info", target])
        .output()?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.trim()
            .strip_prefix(key)
            .map(|r| r.trim_start_matches(':').trim().to_string())
    }))
}

fn change(uuid: &str, old: &[u8], new: &[u8]) -> Result<()> {
    // diskutil reads the old and the new passphrase as two lines from stdin
    let mut input = Zeroizing::new(Vec::with_capacity(old.len() + new.len() + 2));
    input.extend_from_slice(old);
    input.push(b'\n');
    input.extend_from_slice(new);
    input.push(b'\n');
    check(
        run_with_stdin(
            crate::util::system_cmd("diskutil").args([
                "apfs",
                "changePassphrase",
                uuid,
                "-user",
                "disk",
                "-oldStdinpassphrase",
                "-newStdinpassphrase",
            ]),
            &input,
        )?,
        "diskutil apfs changePassphrase",
    )?;
    Ok(())
}

/// The UUID of the volume's "Disk User" (the passphrase user diskutil creates), which
/// `unlockVolume -verify` needs; the volume UUID when it can't be listed.
fn disk_user(uuid: &str) -> String {
    let out = crate::util::system_cmd("diskutil")
        .args(["apfs", "listCryptoUsers", uuid])
        .output();
    let Ok(out) = out else {
        return uuid.to_string();
    };
    let text = String::from_utf8_lossy(&out.stdout);
    let mut last_uuid: Option<String> = None;
    for l in text.lines() {
        let t = l.trim().trim_start_matches(['+', '-', ' ', '|']);
        if t.len() == 36 && t.chars().filter(|c| *c == '-').count() == 4 {
            last_uuid = Some(t.to_string());
        } else if t.starts_with("Type:") && t.contains("Disk User") {
            if let Some(u) = last_uuid.take() {
                return u;
            }
        }
    }
    uuid.to_string()
}

/// `diskutil apfs unlockVolume <uuid> -user <disk user> -verify -stdinpassphrase`: checks the
/// passphrase without mounting; works on a locked and on a mounted volume.
pub fn verify(uuid: &str, passphrase: &[u8]) -> Result<bool> {
    let user = disk_user(uuid);
    let out = run_with_stdin(
        crate::util::system_cmd("diskutil").args([
            "apfs",
            "unlockVolume",
            uuid,
            "-user",
            &user,
            "-verify",
            "-stdinpassphrase",
        ]),
        passphrase,
    )?;
    if out.status.success() {
        return Ok(true);
    }
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if text.contains("not valid") || text.contains("incorrect") || text.contains("-69749") {
        return Ok(false);
    }
    bail!(
        "diskutil apfs unlockVolume -verify failed: {}",
        text.trim().lines().last().unwrap_or("")
    )
}

/// Switch the passphrase of an APFS volume (one step; locked or mounted).
pub fn change_passphrase(uuid: &str, old: &[u8], new: &[u8]) -> Result<()> {
    change(uuid, old, new)
}

impl Backend for ApfsVolume {
    fn create(
        &self,
        v: &mut Volume,
        _size: &str,
        key_for: &mut dyn FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Zeroizing<String>> {
        if v.mountpoint != std::path::Path::new("/Volumes").join(&v.name) {
            bail!("apfs-volume always mounts at /Volumes/<name>");
        }
        let container = std::mem::take(&mut v.id);
        if container.is_empty() {
            bail!("--container is required for apfs-volume (e.g. disk3 — see `diskutil list internal`)");
        }
        // The OS assigns the UUID, so create with a throwaway passphrase, then switch to the
        // derived one. The throwaway never leaves this process.
        let temp = random_secret(32)?;
        let out = run_with_stdin(
            crate::util::system_cmd("diskutil").args([
                "apfs",
                "addVolume",
                &container,
                "APFS",
                &v.name,
                "-stdinpassphrase",
                "-nomount",
            ]),
            temp.as_bytes(),
        )?;
        let out = check(out, "diskutil apfs addVolume")?;
        let text = String::from_utf8_lossy(&out.stdout);
        let dev = text
            .lines()
            .find_map(|l| l.trim().strip_prefix("Created new APFS Volume "))
            .map(|d| d.trim().to_string())
            .context("could not find the new volume in diskutil output")?;
        let uuid = info_value(&dev, "Volume UUID")?.context("reading the new volume's UUID")?;
        let res = (|| {
            let pass = key_for(&uuid)?;
            change(&uuid, temp.as_bytes(), pass.as_bytes())?;
            Ok(pass)
        })();
        match res {
            Ok(pass) => {
                v.id = uuid;
                Ok(pass)
            }
            Err(e) => {
                // don't leave a volume behind that nobody can open
                let _ = crate::util::system_cmd("diskutil")
                    .args(["apfs", "deleteVolume", &uuid])
                    .output();
                Err(e)
            }
        }
    }

    fn read_id(&self, v: &Volume) -> Result<String> {
        info_value(&v.id, "Volume UUID")?
            .with_context(|| format!("APFS volume {} not found — is the disk connected?", v.id))
    }

    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()> {
        let out = run_with_stdin(
            crate::util::system_cmd("diskutil").args(["apfs", "unlockVolume", &v.id, "-stdinpassphrase"]),
            passphrase,
        )?;
        check(out, "diskutil apfs unlockVolume (wrong key?)")?;
        Ok(())
    }

    fn lock(&self, v: &Volume, force: bool) -> Result<()> {
        if force {
            let _ = crate::util::system_cmd("diskutil")
                .args(["unmount", "force", &v.id])
                .output();
        }
        check(
            crate::util::system_cmd("diskutil")
                .args(["apfs", "lockVolume", &v.id])
                .output()?,
            "diskutil apfs lockVolume (files still open? use --force)",
        )?;
        Ok(())
    }

    fn is_unlocked(&self, v: &Volume) -> Result<bool> {
        Ok(info_value(&v.id, "Mounted")?.is_some_and(|m| m.starts_with("Yes")))
    }

    fn change_passphrase(&self, v: &Volume, old: &[u8], new: &[u8]) -> Result<()> {
        change(&v.id, old, new)
    }

    fn verify(&self, v: &Volume, passphrase: &[u8]) -> Result<bool> {
        verify(&v.id, passphrase)
    }

    fn destroy(&self, v: &Volume) -> Result<()> {
        check(
            crate::util::system_cmd("diskutil")
                .args(["apfs", "deleteVolume", &v.id])
                .output()?,
            "diskutil apfs deleteVolume",
        )?;
        Ok(())
    }
}
