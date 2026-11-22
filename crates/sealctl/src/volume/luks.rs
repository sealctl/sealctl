//! Linux LUKS2 container in a file (`cryptsetup`), ext4 inside. Opening needs root, so the
//! device-mapper steps run through `sudo` (which asks for the password on the terminal);
//! the LUKS passphrase itself only ever goes to cryptsetup's stdin.

use std::path::Path;
use std::process::Command;

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use super::{Backend, Volume};

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
        let id = crate::util::new_uuid()?;
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

    fn change_passphrase(&self, _v: &Volume, _old: &[u8], _new: &[u8]) -> Result<()> {
        bail!("changing a LUKS passphrase in place is not supported yet")
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

/// The words marker while locked: a LUKS2 token of type `sealctl` (best effort: needs sudo).
/// `cryptsetup token import` alone adds a token, so the existing `sealctl` token is replaced in
/// place (`--token-id N --token-replace`) and any others of that type are removed: after a
/// rewrap the header holds the new words and check only, and repeated rewraps use no more of
/// the header's token slots.
pub fn import_token(v: &Volume, id: &sealctl_core::ids::IdFile) -> Result<()> {
    let Some(path) = v.path.as_ref() else {
        return Ok(());
    };
    let mut token = serde_json::to_value(id)?;
    token["type"] = TOKEN_TYPE.into();
    token["keyslots"] = serde_json::json!([]);
    let json = token.to_string();
    let existing = match sealctl_tokens(path) {
        Ok(ids) => ids,
        Err(e) => {
            // without knowing the tokens an import could add a second one: leave the header
            log::info!("could not read the LUKS tokens of {}: {e:#}", path.display());
            return Ok(());
        }
    };
    let import = |extra: &[&str]| {
        run_with_stdin(
            sudo()
                .args(["cryptsetup", "token", "import", "--json-file=-"])
                .args(extra)
                .arg(path),
            json.as_bytes(),
        )
        .is_ok_and(|o| o.status.success())
    };
    let done = match existing.first() {
        None => import(&[]),
        Some(id) => {
            let id = id.to_string();
            // cryptsetup 2.4 and later replace in place; before that, remove and import
            import(&["--token-id", &id, "--token-replace"])
                || (remove_token(path, &id) && import(&["--token-id", &id]))
        }
    };
    if !done {
        log::info!("could not import the sealctl LUKS token into {}", path.display());
    }
    for id in existing.iter().skip(1) {
        remove_token(path, &id.to_string());
    }
    Ok(())
}

/// Removes every `sealctl` token from the LUKS header (`unseal`; best effort).
pub fn remove_tokens(path: &Path) {
    match sealctl_tokens(path) {
        Ok(ids) => {
            for id in ids {
                remove_token(path, &id.to_string());
            }
        }
        Err(e) => log::info!("could not read the LUKS tokens of {}: {e:#}", path.display()),
    }
}

const TOKEN_TYPE: &str = "sealctl";

fn remove_token(path: &Path, id: &str) -> bool {
    sudo()
        .args(["cryptsetup", "token", "remove", "--token-id", id])
        .arg(path)
        .output()
        .is_ok_and(|o| o.status.success())
}

/// The ids of the LUKS2 tokens of type `sealctl`, lowest first.
fn sealctl_tokens(path: &Path) -> Result<Vec<u32>> {
    let out = sudo()
        .args(["cryptsetup", "luksDump", "--dump-json-metadata"])
        .arg(path)
        .output()
        .context("running cryptsetup")?;
    if out.status.success() {
        if let Some(ids) = tokens_in_json(&out.stdout) {
            return Ok(ids);
        }
    }
    // before cryptsetup 2.4: the text dump
    let out = sudo()
        .args(["cryptsetup", "luksDump"])
        .arg(path)
        .output()
        .context("running cryptsetup")?;
    if !out.status.success() {
        bail!(
            "cryptsetup luksDump: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(tokens_in_text(&String::from_utf8_lossy(&out.stdout)))
}

/// `luksDump --dump-json-metadata`: `{"tokens": {"0": {"type": "sealctl", …}}, …}`.
fn tokens_in_json(out: &[u8]) -> Option<Vec<u32>> {
    let v: serde_json::Value = serde_json::from_slice(out).ok()?;
    let mut ids: Vec<u32> = v
        .get("tokens")?
        .as_object()?
        .iter()
        .filter(|(_, t)| t["type"] == TOKEN_TYPE)
        .filter_map(|(id, _)| id.parse().ok())
        .collect();
    ids.sort_unstable();
    Some(ids)
}

/// `luksDump` text: a `Tokens:` section with lines `  <id>: <type>`.
fn tokens_in_text(out: &str) -> Vec<u32> {
    let mut ids = Vec::new();
    let mut in_tokens = false;
    for line in out.lines() {
        if !line.starts_with(char::is_whitespace) {
            in_tokens = line.trim_end() == "Tokens:";
            continue;
        }
        if !in_tokens {
            continue;
        }
        if let Some((id, kind)) = line.trim().split_once(':') {
            if kind.trim() == TOKEN_TYPE {
                if let Ok(id) = id.trim().parse() {
                    ids.push(id);
                }
            }
        }
    }
    ids.sort_unstable();
    ids
}

/// Does `passphrase` open the LUKS file? (`cryptsetup open --test-passphrase`.)
pub fn verify(path: &Path, passphrase: &[u8]) -> Result<bool> {
    let out = run_with_stdin(
        crate::util::system_cmd("cryptsetup")
            .args(["open", "--test-passphrase", "--key-file=-"])
            .arg(path),
        passphrase,
    )?;
    Ok(out.status.success())
}

#[cfg(test)]
mod tests {
    #[test]
    fn sealctl_tokens_are_found_in_either_dump() {
        let json = br#"{"keyslots":{},"tokens":{"0":{"type":"systemd-tpm2","keyslots":["0"]},"1":{"type":"sealctl","keyslots":[]},"3":{"type":"sealctl","keyslots":[]}},"segments":{}}"#;
        assert_eq!(super::tokens_in_json(json), Some(vec![1, 3]));
        assert_eq!(super::tokens_in_json(br#"{"tokens":{}}"#), Some(vec![]));
        assert_eq!(super::tokens_in_json(b"not json"), None);
        let text = "LUKS header information\nVersion:       \t2\n\nKeyslots:\n  0: luks2\n\tKey:        512 bits\nTokens:\n  0: systemd-tpm2\n\tKeyslot:    0\n  2: sealctl\n  5: sealctl\nDigests:\n  0: pbkdf2\n";
        assert_eq!(super::tokens_in_text(text), vec![2, 5]);
        assert_eq!(
            super::tokens_in_text("Tokens:\nDigests:\n  0: pbkdf2\n"),
            Vec::<u32>::new()
        );
    }

    /// Linux with cryptsetup and password-less sudo (CI): a rewrap writes the token again and
    /// the header still holds one `sealctl` token, with the new words.
    #[cfg(target_os = "linux")]
    #[test]
    fn rewrap_replaces_the_token() {
        use std::process::Command;
        let have = |c: &str, a: &[&str]| Command::new(c).args(a).output().is_ok_and(|o| o.status.success());
        if !have("cryptsetup", &["--version"]) || !have("sudo", &["-n", "true"]) {
            eprintln!("skipped: needs cryptsetup and password-less sudo");
            return;
        }
        std::env::set_var("SEALCTL_SUDO_NONINTERACTIVE", "1");
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("t.luks");
        std::fs::File::create(&file).unwrap().set_len(32 << 20).unwrap();
        let out = crate::util::run_with_stdin(
            Command::new("cryptsetup")
                .args(["luksFormat", "--type", "luks2", "--batch-mode", "--key-file=-"])
                .args(["--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000"])
                .arg(&file),
            b"pass",
        )
        .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let mut v = super::Volume {
            name: "t".into(),
            kind: super::super::Kind::Luks,
            path: Some(file.clone()),
            id: "00000000-0000-4000-8000-000000000000".into(),
            words: "old-words".into(),
            check: "old-check".into(),
            mountpoint: dir.path().join("mnt"),
            manual: true,
        };
        super::import_token(&v, &v.id_file()).unwrap();
        for round in 0..3 {
            v.words = format!("new-words-{round}");
            v.check = format!("new-check-{round}");
            super::import_token(&v, &v.id_file()).unwrap();
            let ids = super::sealctl_tokens(&file).unwrap();
            assert_eq!(ids.len(), 1, "round {round}: {ids:?}");
            let dump = Command::new("sudo")
                .args(["-n", "cryptsetup", "token", "export", "--token-id"])
                .arg(ids[0].to_string())
                .arg(&file)
                .output()
                .unwrap();
            let t: serde_json::Value = serde_json::from_slice(&dump.stdout).unwrap();
            assert_eq!(t["words"], v.words.as_str());
            assert_eq!(t["check"], v.check.as_str());
        }
        super::remove_tokens(&file);
        assert!(super::sealctl_tokens(&file).unwrap().is_empty());
    }

    #[test]
    fn mount_paths_are_unescaped() {
        assert_eq!(super::unescape_mount("/home/u/My\\040Vault"), "/home/u/My Vault");
        assert_eq!(super::unescape_mount("/plain"), "/plain");
    }
}
