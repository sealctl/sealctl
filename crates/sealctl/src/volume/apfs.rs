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

/// The words marker while locked: the passphrase hint `sealctl <fp>`.
pub fn set_hint(v: &Volume, hint: &str) -> Result<()> {
    check(
        crate::util::system_cmd("diskutil")
            .args(["apfs", "setPassphraseHint", &v.id, "-user", "disk", "-hint", hint])
            .output()?,
        "diskutil apfs setPassphraseHint",
    )?;
    Ok(())
}

/// Does `passphrase` open the volume (a UUID or disk identifier)? (`diskutil apfs unlockVolume
/// -verify`.) `-verify` needs the cryptographic user named by UUID on recent macOS: the disk
/// user's is the volume UUID.
pub fn verify(target: &str, passphrase: &[u8]) -> Result<bool> {
    let uuid = match sealctl_core::ids::parse_uuid(&target.to_lowercase()) {
        Some(_) => target.to_string(),
        None => match info_value(target, "Volume UUID")? {
            Some(u) => u,
            None => return Ok(false),
        },
    };
    let out = run_with_stdin(
        crate::util::system_cmd("diskutil").args([
            "apfs",
            "unlockVolume",
            &uuid,
            "-user",
            &uuid,
            "-verify",
            "-stdinpassphrase",
        ]),
        passphrase,
    )?;
    Ok(out.status.success())
}

/// An APFS volume found by its UUID or disk identifier: its UUID in lower case, whether it is
/// mounted, and where. `None` when diskutil knows no APFS volume by that name.
pub fn find(target: &str) -> Result<Option<(String, Option<String>)>> {
    if info_value(target, "Type (Bundle)")?.as_deref() != Some("apfs") {
        return Ok(None);
    }
    let Some(uuid) = info_value(target, "Volume UUID")? else {
        return Ok(None);
    };
    let mounted = info_value(target, "Mounted")?.is_some_and(|m| m.starts_with("Yes"));
    let mp = info_value(target, "Mount Point")?.filter(|m| mounted && !m.is_empty());
    Ok(Some((uuid.to_lowercase(), mp)))
}

/// The words fingerprint in the passphrase hint `sealctl <fp>`, readable while locked
/// (`diskutil apfs listUsers`).
pub fn hint_words(uuid: &str) -> Result<Option<String>> {
    let out = crate::util::system_cmd("diskutil")
        .args(["apfs", "listUsers", uuid])
        .output()?;
    if !out.status.success() {
        return Ok(None);
    }
    Ok(hint_in(&String::from_utf8_lossy(&out.stdout)))
}

/// `Hint: sealctl <fp>` in `diskutil apfs listUsers` output.
fn hint_in(text: &str) -> Option<String> {
    text.lines().find_map(|l| {
        l.trim()
            .strip_prefix("Hint:")
            .and_then(|h| h.trim().strip_prefix("sealctl "))
            .map(|fp| fp.trim().to_string())
            .filter(|fp| !fp.is_empty())
    })
}

/// Unlocks and mounts the volume at its default mount point; returns the mount point.
pub fn unlock_uuid(uuid: &str, passphrase: &[u8]) -> Result<String> {
    check(
        run_with_stdin(
            crate::util::system_cmd("diskutil").args(["apfs", "unlockVolume", uuid, "-stdinpassphrase"]),
            passphrase,
        )?,
        "diskutil apfs unlockVolume",
    )?;
    Ok(info_value(uuid, "Mount Point")?.unwrap_or_default())
}

/// Replaces the passphrase.
pub fn change_passphrase(uuid: &str, old: &[u8], new: &[u8]) -> Result<()> {
    change(uuid, old, new)
}

#[cfg(test)]
mod tests {
    #[test]
    fn the_hint_gives_the_words() {
        let out = "Cryptographic user for disk7s2 (1 found)\n|\n+-- 00C167BE-32EB-4BD7-936B-A4ACA1BF5A67\n    Type: Disk User\n    Hint: sealctl AbCd\n \n";
        assert_eq!(super::hint_in(out).as_deref(), Some("AbCd"));
        assert_eq!(super::hint_in("    Hint: my own words\n"), None);
        assert_eq!(super::hint_in("    Type: Disk User\n"), None);
    }
}
