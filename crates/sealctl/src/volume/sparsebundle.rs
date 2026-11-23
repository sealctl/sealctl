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

/// One attachment of an image: its whole-disk device (`/dev/disk4`) and the mount points of its
/// volumes (none when attached without mounting).
#[derive(Debug, PartialEq, Eq)]
struct Attachment {
    disk: String,
    mounts: Vec<String>,
}

/// The attachments of the image at `path`, from `hdiutil info`.
fn attachments(path: &std::path::Path) -> Result<Vec<Attachment>> {
    let out = check(
        crate::util::system_cmd("hdiutil").arg("info").output()?,
        "hdiutil info",
    )?;
    let want = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    Ok(parse_info(&String::from_utf8_lossy(&out.stdout), |image| {
        std::fs::canonicalize(image).unwrap_or_else(|_| image.into()) == want
    }))
}

/// The attachments in `hdiutil info` text whose image-path passes `is_ours`.
fn parse_info(text: &str, is_ours: impl Fn(&str) -> bool) -> Vec<Attachment> {
    let mut found = Vec::new();
    for block in text.split("================================================") {
        let image = block.lines().find_map(|l| {
            l.strip_prefix("image-path")
                .map(|r| r.trim_start_matches([' ', ':', '\t']).trim())
        });
        let Some(image) = image else { continue };
        if !is_ours(image) {
            continue;
        }
        let devs: Vec<&str> = block.lines().filter(|l| l.starts_with("/dev/")).collect();
        // the first entity is the whole image
        let Some(disk) = devs.first().and_then(|l| l.split('\t').next()) else {
            continue;
        };
        let mounts = devs
            .iter()
            .filter_map(|l| l.split('\t').map(str::trim).filter(|s| s.starts_with('/')).nth(1))
            .map(str::to_string)
            .collect();
        found.push(Attachment {
            disk: disk.trim().to_string(),
            mounts,
        });
    }
    found
}

/// Mount points of attached images whose image-path equals `path` (from `hdiutil info`); an
/// empty string for an image attached but not mounted.
pub fn attached_mounts(path: &std::path::Path) -> Result<Vec<String>> {
    let mut mounts = Vec::new();
    for a in attachments(path)? {
        if a.mounts.is_empty() {
            mounts.push(String::new()); // attached but not mounted
        }
        mounts.extend(a.mounts);
    }
    Ok(mounts)
}

/// Detaches every attachment of the image at `path`, wherever it is mounted. Just after a
/// mount or a write, macOS services (Spotlight, fseventsd) can hold the volume for a moment,
/// so a detach without `force` is tried three times, a second apart, before the volume is
/// reported busy. Callers in the daemon run this off its async threads.
fn detach_all(path: &std::path::Path, force: bool) -> Result<()> {
    const TRIES: u32 = 3;
    for a in attachments(path)? {
        for attempt in 1..=TRIES {
            let mut cmd = crate::util::system_cmd("hdiutil");
            cmd.args(["detach", "-quiet"]);
            if force {
                cmd.arg("-force");
            }
            cmd.arg(&a.disk);
            let out = cmd.output()?;
            if out.status.success() || force || attempt == TRIES {
                check(out, "hdiutil detach (files still open? use --force)")?;
                break;
            }
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
    Ok(())
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
        let mounted_here = attached_mounts(path)?
            .iter()
            .any(|m| super::same_path(std::path::Path::new(m), &v.mountpoint));
        if !mounted_here {
            // macOS mounted it elsewhere (`/Volumes/<name> 1` when the name is taken), or not at
            // all: don't leave it attached and decrypted
            let _ = detach_all(path, true);
            bail!("image attached but not mounted at {}", v.mountpoint.display());
        }
        Ok(())
    }

    /// Detaches the image wherever it is attached, not only at its mount point.
    fn lock(&self, v: &Volume, force: bool) -> Result<()> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        detach_all(path, force)
    }

    /// Attached anywhere (decrypted), mounted at its mount point or not.
    fn is_unlocked(&self, v: &Volume) -> Result<bool> {
        let path = v.path.as_ref().context("sparsebundle needs a path")?;
        Ok(!attachments(path)?.is_empty())
    }

    fn is_mounted(&self, v: &Volume) -> Result<bool> {
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

/// Does `passphrase` open the bundle? Attaches without mounting, then detaches. An image that
/// is attached already is refused: attaching it again only reports the existing attachment
/// (which says nothing about the passphrase), and detaching that would close the user's volume.
pub fn verify(path: &std::path::Path, passphrase: &[u8]) -> Result<bool> {
    if !attachments(path)?.is_empty() {
        bail!("{} is attached: close it first", path.display());
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const INFO: &str = "framework       : 671.100.2
driver          : 671.100.2
================================================
image-path      : /Users/u/Vaults/v.sparsebundle
image-alias     : /Users/u/Vaults/v.sparsebundle
shadow-path     : <none>
image-type      : sparse bundle disk image
image-encrypted : true
/dev/disk4\tGUID_partition_scheme\t
/dev/disk4s1\tApple_APFS\t
/dev/disk5\tEF57347C-0000-11AA-AA11-0030654\t
/dev/disk5s1\t41504653-0000-11AA-AA11-0030654\t/Volumes/v 1
================================================
image-path      : /Users/u/Downloads/other.dmg
/dev/disk6\tGUID_partition_scheme\t
/dev/disk6s1\tApple_HFS\t/Volumes/other
================================================
image-path      : /Users/u/Vaults/v.sparsebundle
/dev/disk7\tGUID_partition_scheme\t
/dev/disk7s1\tApple_APFS\t
";

    /// Every attachment of the image is found, with its whole disk, wherever it is mounted.
    #[test]
    fn attachments_of_an_image_wherever_mounted() {
        let got = parse_info(INFO, |p| p == "/Users/u/Vaults/v.sparsebundle");
        assert_eq!(
            got,
            vec![
                Attachment {
                    disk: "/dev/disk4".into(),
                    mounts: vec!["/Volumes/v 1".into()],
                },
                Attachment {
                    disk: "/dev/disk7".into(),
                    mounts: vec![],
                },
            ]
        );
        assert!(parse_info(INFO, |p| p == "/nowhere").is_empty());
    }
}
