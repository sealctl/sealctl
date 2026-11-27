//! macOS encrypted APFS volume inside an APFS container (`diskutil apfs`) — what Disk Utility's
//! "Add APFS volume → APFS (Encrypted)" creates. The volume UUID (readable while locked) is the
//! input of the key derivation.

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Backend, Volume};
use crate::exit::{self, fail};
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

/// Removes the passphrase hint of the disk user.
pub fn clear_hint(v: &Volume) -> Result<()> {
    check(
        crate::util::system_cmd("diskutil")
            .args(["apfs", "setPassphraseHint", &v.id, "-user", "disk", "-clear"])
            .output()?,
        "diskutil apfs setPassphraseHint -clear",
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

/// A volume UUID (any case) or a disk identifier (`disk3s5`, `/dev/disk3s5`).
pub fn looks_like_id(target: &str) -> bool {
    let t = target.strip_prefix("/dev/").unwrap_or(target);
    sealctl_core::ids::parse_uuid(&t.to_lowercase()).is_some()
        || t.strip_prefix("disk").is_some_and(|r| {
            r.split_once('s').is_some_and(|(d, s)| {
                !d.is_empty()
                    && !s.is_empty()
                    && d.bytes().all(|b| b.is_ascii_digit())
                    && s.bytes().all(|b| b.is_ascii_digit())
            })
        })
}

/// One volume in `diskutil apfs list`.
#[derive(Debug, PartialEq)]
struct Listed {
    name: String,
    /// In lower case.
    uuid: String,
    dev: String,
}

/// Every APFS volume macOS knows, locked ones too (`diskutil apfs list -plist`, read through
/// `plutil` as JSON).
fn listed() -> Result<Vec<Listed>> {
    let out = crate::util::system_cmd("diskutil")
        .args(["apfs", "list", "-plist"])
        .output()?;
    if !out.status.success() {
        return Ok(Vec::new());
    }
    let json = check(
        run_with_stdin(
            crate::util::system_cmd("plutil").args(["-convert", "json", "-o", "-", "-"]),
            &out.stdout,
        )?,
        "plutil -convert json",
    )?;
    Ok(parse_list(&json.stdout))
}

fn parse_list(json: &[u8]) -> Vec<Listed> {
    let v: serde_json::Value = serde_json::from_slice(json).unwrap_or_default();
    v["Containers"]
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|c| c["Volumes"].as_array().into_iter().flatten())
        .filter_map(|v| {
            Some(Listed {
                name: v["Name"].as_str()?.to_string(),
                uuid: v["APFSVolumeUUID"].as_str()?.to_lowercase(),
                dev: v["DeviceIdentifier"].as_str()?.to_string(),
            })
        })
        .collect()
}

/// The UUID of the one volume named `name`: an exact match, or when there is none, a match
/// ignoring case. Several with that name: an error that lists them.
fn pick(vols: &[Listed], name: &str) -> Result<Option<String>> {
    let mut found: Vec<&Listed> = vols.iter().filter(|v| v.name == name).collect();
    if found.is_empty() {
        let lower = name.to_lowercase();
        found = vols.iter().filter(|v| v.name.to_lowercase() == lower).collect();
    }
    match found.as_slice() {
        [] => Ok(None),
        [one] => Ok(Some(one.uuid.clone())),
        many => Err(fail(
            exit::USAGE,
            format!(
                "{} APFS volumes are named {name}: {}. Give its disk identifier or UUID instead.",
                many.len(),
                many.iter()
                    .map(|v| format!("{} (UUID {})", v.dev, v.uuid))
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )),
    }
}

/// The UUID of the APFS volume named `name` (as Finder and Disk Utility show it), in lower case.
/// `None` when no APFS volume has that name.
pub fn uuid_by_name(name: &str) -> Result<Option<String>> {
    pick(&listed()?, name)
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

/// `diskutil apfs listUsers` of a volume; `None` when diskutil refuses.
fn list_users(uuid: &str) -> Result<Option<String>> {
    let out = crate::util::system_cmd("diskutil")
        .args(["apfs", "listUsers", uuid])
        .output()?;
    Ok(out
        .status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).into_owned()))
}

/// The words fingerprint in the passphrase hint `sealctl <fp>`, readable while locked
/// (`diskutil apfs listUsers`).
pub fn hint_words(uuid: &str) -> Result<Option<String>> {
    Ok(list_users(uuid)?.as_deref().and_then(hint_in))
}

/// The disk user's passphrase hint as it is, whoever set it (`diskutil apfs listUsers`).
pub fn disk_user_hint(uuid: &str) -> Result<Option<String>> {
    Ok(list_users(uuid)?.as_deref().and_then(disk_user_hint_in))
}

/// The `Hint:` of the `Type: Disk User` entry in `diskutil apfs listUsers` output.
fn disk_user_hint_in(text: &str) -> Option<String> {
    // one entry per user, each starting with `+-- <uuid>`
    text.split("+--").find_map(|user| {
        let mut lines = user.lines().map(str::trim);
        if !lines.clone().any(|l| l == "Type: Disk User") {
            return None;
        }
        lines
            .find_map(|l| l.strip_prefix("Hint:"))
            .map(|h| h.trim().to_string())
            .filter(|h| !h.is_empty())
    })
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

    #[test]
    fn the_disk_user_hint_is_read_as_it_is() {
        let out = "Cryptographic users for disk7s2 (2 found)\n|\n\
            +-- 11C167BE-32EB-4BD7-936B-A4ACA1BF5A67\n    Type: Personal Recovery User\n    Hint: not this one\n|\n\
            +-- 00C167BE-32EB-4BD7-936B-A4ACA1BF5A67\n    Type: Disk User\n    Hint: my own words\n \n";
        assert_eq!(super::disk_user_hint_in(out).as_deref(), Some("my own words"));
        let none = "+-- 00C167BE-32EB-4BD7-936B-A4ACA1BF5A67\n    Type: Disk User\n \n";
        assert_eq!(super::disk_user_hint_in(none), None);
        assert_eq!(
            super::disk_user_hint_in("+-- X\n    Type: Disk User\n    Hint:   \n"),
            None
        );
    }

    fn vol(name: &str, uuid: &str, dev: &str) -> super::Listed {
        super::Listed {
            name: name.into(),
            uuid: uuid.into(),
            dev: dev.into(),
        }
    }

    #[test]
    fn the_list_gives_names_uuids_and_disks() {
        let json = br#"{"Containers":[{"Volumes":[
            {"Name":"Work","APFSVolumeUUID":"00C167BE-32EB-4BD7-936B-A4ACA1BF5A67","DeviceIdentifier":"disk7s2","Locked":true},
            {"APFSVolumeUUID":"11C167BE-32EB-4BD7-936B-A4ACA1BF5A67","DeviceIdentifier":"disk7s3"}
        ]},{"Volumes":[
            {"Name":"Recovery","APFSVolumeUUID":"22C167BE-32EB-4BD7-936B-A4ACA1BF5A67","DeviceIdentifier":"disk3s3"}
        ]}]}"#;
        assert_eq!(
            super::parse_list(json),
            vec![
                vol("Work", "00c167be-32eb-4bd7-936b-a4aca1bf5a67", "disk7s2"),
                vol("Recovery", "22c167be-32eb-4bd7-936b-a4aca1bf5a67", "disk3s3"),
            ]
        );
        assert!(super::parse_list(b"not json").is_empty());
    }

    #[test]
    fn a_name_finds_one_volume() {
        let vols = vec![
            vol("Work", "a", "disk7s2"),
            vol("work", "b", "disk8s2"),
            vol("Recovery", "c", "disk1s4"),
            vol("Recovery", "d", "disk3s3"),
            vol("Photos", "e", "disk9s1"),
        ];
        // exact first, then ignoring case
        assert_eq!(super::pick(&vols, "Work").unwrap().as_deref(), Some("a"));
        assert_eq!(super::pick(&vols, "work").unwrap().as_deref(), Some("b"));
        assert_eq!(super::pick(&vols, "photos").unwrap().as_deref(), Some("e"));
        // no exact match and two ignoring case: which one is meant is unclear
        let e = super::pick(&vols, "WORK").unwrap_err().to_string();
        assert!(e.contains("2 APFS volumes are named WORK"), "{e}");
        assert_eq!(super::pick(&vols, "Nope").unwrap(), None);
        let e = super::pick(&vols, "Recovery").unwrap_err().to_string();
        assert!(e.contains("2 APFS volumes are named Recovery"), "{e}");
        assert!(
            e.contains("disk1s4 (UUID c)") && e.contains("disk3s3 (UUID d)"),
            "{e}"
        );
    }

    #[test]
    fn ids_are_told_from_names() {
        assert!(super::looks_like_id("00C167BE-32EB-4BD7-936B-A4ACA1BF5A67"));
        assert!(super::looks_like_id("disk3s5"));
        assert!(super::looks_like_id("/dev/disk3s5"));
        assert!(!super::looks_like_id("disk3"));
        assert!(!super::looks_like_id("Work"));
        assert!(!super::looks_like_id("disk3s"));
    }
}
