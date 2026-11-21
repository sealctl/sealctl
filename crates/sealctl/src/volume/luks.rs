//! Linux LUKS2 container in a file (`cryptsetup`), ext4 inside. Opening needs root, so the
//! device-mapper steps run through `sudo` (which asks for the password on the terminal);
//! the LUKS passphrase itself only ever goes to cryptsetup's stdin.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Backend, Volume};
use crate::derive;
use crate::util::{check, run_with_stdin};

pub struct Luks;

fn mapper_name(v: &Volume) -> String {
    format!("sealctl-{}", v.name)
}

fn sudo() -> Command {
    let mut c = Command::new("sudo");
    if std::env::var_os("SEALCTL_SUDO_NONINTERACTIVE").is_some() {
        c.arg("-n");
    }
    c
}

/// /proc/mounts escapes space, tab, newline and backslash as \040 \011 \012 \134.
fn unescape_mount(field: &str) -> String {
    let b = field.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' && i + 3 < b.len() && b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
            let v = (b[i + 1] - b'0') * 64 + (b[i + 2] - b'0') * 8 + (b[i + 3] - b'0');
            out.push(v);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn is_mounted(mp: &Path) -> Result<bool> {
    let mounts = std::fs::read_to_string("/proc/self/mounts").unwrap_or_default();
    // the kernel lists the resolved path (e.g. /var/home/… for a symlinked /home)
    let want = std::fs::canonicalize(mp).unwrap_or_else(|_| mp.to_path_buf());
    Ok(mounts.lines().any(|l| {
        l.split_whitespace()
            .nth(1)
            .is_some_and(|f| Path::new(&unescape_mount(f)) == want || Path::new(&unescape_mount(f)) == mp)
    }))
}

fn mapper_open(v: &Volume) -> bool {
    Path::new("/dev/mapper").join(mapper_name(v)).exists()
}

impl Backend for Luks {
    fn create(
        &self,
        v: &mut Volume,
        size: &str,
        key_for: &mut dyn FnMut(&str) -> Result<Zeroizing<String>>,
    ) -> Result<Zeroizing<String>> {
        let path = v.path.clone().context("luks needs a path")?;
        let path = &path;
        // We choose the LUKS UUID, so the key can be derived before formatting.
        let id = derive::new_uuid()?;
        let pass = key_for(&id)?;
        let passphrase = pass.as_bytes();
        check(
            Command::new("truncate").args(["-s", size]).arg(path).output()?,
            "truncate",
        )?;
        check(
            run_with_stdin(
                crate::util::system_cmd("cryptsetup")
                    .args([
                        "luksFormat",
                        "--type",
                        "luks2",
                        "--batch-mode",
                        "--key-file=-",
                        "--uuid",
                        &id,
                    ])
                    .arg(path),
                passphrase,
            )?,
            "cryptsetup luksFormat",
        )?;
        let mapper = mapper_name(v);
        check(
            run_with_stdin(
                sudo()
                    .args(["cryptsetup", "open", "--type", "luks2", "--key-file=-"])
                    .arg(path)
                    .arg(&mapper),
                passphrase,
            )?,
            "cryptsetup open",
        )?;
        let dev = format!("/dev/mapper/{mapper}");
        let res = check(
            sudo().args(["mkfs.ext4", "-q", "-L", &v.name, &dev]).output()?,
            "mkfs.ext4",
        );
        // Make the new filesystem's root owned by the user.
        let res = res.and_then(|_| {
            std::fs::create_dir_all(&v.mountpoint)?;
            check(
                sudo().arg("mount").arg(&dev).arg(&v.mountpoint).output()?,
                "mount",
            )?;
            let owner = format!("{}:{}", users_uid(), users_gid());
            check(
                sudo().args(["chown", &owner]).arg(&v.mountpoint).output()?,
                "chown",
            )?;
            check(sudo().arg("umount").arg(&v.mountpoint).output()?, "umount")?;
            Ok(())
        });
        let _ = sudo().args(["cryptsetup", "close", &mapper]).output();
        res?;
        v.id = id;
        Ok(pass)
    }

    fn read_id(&self, v: &Volume) -> Result<String> {
        let path = v.path.as_ref().context("luks needs a path")?;
        let out = check(
            crate::util::system_cmd("cryptsetup")
                .arg("luksUUID")
                .arg(path)
                .output()?,
            "cryptsetup luksUUID",
        )?;
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    }

    /// Add `new` in a free key slot, then remove the slot `old` opens.
    fn change_passphrase(&self, v: &Volume, old: &[u8], new: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("luks needs a path")?;
        let old_slot = slot_of(path, old)?.context("the old passphrase opens no key slot")?;
        add_key(path, old, new)?;
        match slot_of(path, new)? {
            Some(n) if n != old_slot => kill_slot(path, old_slot, new),
            _ => bail!("the new passphrase does not open its own key slot; nothing removed"),
        }
    }

    fn verify(&self, v: &Volume, passphrase: &[u8]) -> Result<bool> {
        let path = v.path.as_ref().context("luks needs a path")?;
        Ok(slot_of(path, passphrase)?.is_some())
    }

    fn destroy(&self, v: &Volume) -> Result<()> {
        if let Some(p) = &v.path {
            if p.exists() {
                std::fs::remove_file(p)?;
            }
        }
        Ok(())
    }

    fn unlock(&self, v: &Volume, passphrase: &[u8]) -> Result<()> {
        let path = v.path.as_ref().context("luks needs a path")?;
        let mapper = mapper_name(v);
        let opened_now = !Path::new("/dev/mapper").join(&mapper).exists();
        if opened_now {
            check(
                run_with_stdin(
                    sudo()
                        .args(["cryptsetup", "open", "--type", "luks2", "--key-file=-"])
                        .arg(path)
                        .arg(&mapper),
                    passphrase,
                )?,
                "cryptsetup open (wrong key?)",
            )?;
        }
        let mounted = std::fs::create_dir_all(&v.mountpoint)
            .map_err(anyhow::Error::from)
            .and_then(|_| {
                check(
                    sudo()
                        .arg("mount")
                        .arg(format!("/dev/mapper/{mapper}"))
                        .arg(&v.mountpoint)
                        .output()?,
                    "mount",
                )
            });
        if let Err(e) = mounted {
            // don't leave the decrypted device open behind a failed mount
            if opened_now {
                let _ = sudo().args(["cryptsetup", "close", &mapper]).output();
            }
            return Err(e);
        }
        Ok(())
    }

    fn lock(&self, v: &Volume, force: bool) -> Result<()> {
        if is_mounted(&v.mountpoint)? {
            let mut c = sudo();
            c.arg("umount");
            if force {
                c.arg("-l");
            }
            check(
                c.arg(&v.mountpoint).output()?,
                "umount (files still open? use --force)",
            )?;
        }
        if mapper_open(v) {
            check(
                sudo().args(["cryptsetup", "close", &mapper_name(v)]).output()?,
                "cryptsetup close",
            )?;
        }
        Ok(())
    }

    /// Unlocked = mounted, or decrypted but not mounted (still open: must be locked too).
    fn is_unlocked(&self, v: &Volume) -> Result<bool> {
        Ok(is_mounted(&v.mountpoint)? || mapper_open(v))
    }
}

/// `cryptsetup luksAddKey --key-file /dev/fd/3 <file> /dev/fd/4`: `existing` opens a slot,
/// `new` goes into a free one. Both passphrases travel on pipes.
pub fn add_key(file: &Path, existing: &[u8], new: &[u8]) -> Result<()> {
    check(
        crate::util::run_with_fds(
            crate::util::system_cmd("cryptsetup")
                .args(["luksAddKey", "--batch-mode", "--key-file", "/dev/fd/3"])
                .arg(file)
                .arg("/dev/fd/4"),
            b"",
            &[(3, existing), (4, new)],
        )?,
        "cryptsetup luksAddKey",
    )?;
    Ok(())
}

/// The key slot `passphrase` opens (`cryptsetup open --test-passphrase -v`: "Key slot N
/// unlocked."), or `None` when it opens none.
pub fn slot_of(file: &Path, passphrase: &[u8]) -> Result<Option<u32>> {
    let out = run_with_stdin(
        crate::util::system_cmd("cryptsetup")
            .args(["open", "--test-passphrase", "-v", "--key-file=-"])
            .arg(file),
        passphrase,
    )?;
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    if out.status.success() {
        let slot = text.lines().find_map(|l| {
            l.trim()
                .strip_prefix("Key slot ")
                .and_then(|r| r.split_whitespace().next())
                .and_then(|n| n.parse::<u32>().ok())
        });
        return slot
            .map(Some)
            .context("cryptsetup did not say which key slot opened");
    }
    // exit 2: no key available with this passphrase
    if out.status.code() == Some(2) || text.contains("No key available") {
        return Ok(None);
    }
    bail!(
        "cryptsetup open --test-passphrase failed: {}",
        text.trim().lines().last().unwrap_or("")
    )
}

/// `cryptsetup luksKillSlot <file> N`, authorised by a passphrase of another slot on stdin.
pub fn kill_slot(file: &Path, slot: u32, remaining: &[u8]) -> Result<()> {
    if slot_of(file, remaining)? == Some(slot) {
        bail!("refusing to remove key slot {slot}: it is the one that would remain");
    }
    check(
        run_with_stdin(
            crate::util::system_cmd("cryptsetup")
                .args(["luksKillSlot", "--key-file=-"])
                .arg(file)
                .arg(slot.to_string()),
            remaining,
        )?,
        "cryptsetup luksKillSlot",
    )?;
    Ok(())
}

fn users_uid() -> String {
    String::from_utf8_lossy(
        &Command::new("id")
            .arg("-u")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string()
}

fn users_gid() -> String {
    String::from_utf8_lossy(
        &Command::new("id")
            .arg("-g")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string()
}

#[cfg(test)]
mod tests {
    #[test]
    fn mount_paths_are_unescaped() {
        assert_eq!(super::unescape_mount("/home/u/My\\040Vault"), "/home/u/My Vault");
        assert_eq!(super::unescape_mount("/plain"), "/plain");
    }
}
