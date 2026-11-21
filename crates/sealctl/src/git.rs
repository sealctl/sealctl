//! Git commit/tag signing with an SSH key file unlocked by the Ledger (SSH signatures).
//!
//! Git calls `gpg.ssh.program` (normally `ssh-keygen -Y sign`). We point it at
//! `sealctl git ssh-keygen`, which runs the real `ssh-keygen` with `SSH_AUTH_SOCK` set to the
//! sealctl agent — so signing works regardless of the shell's SSH_AUTH_SOCK.

use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::{cert, paths, ssh};

fn git_config(scope: &str, key: &str, value: &str) -> Result<()> {
    let out = Command::new("git")
        .args(["config", scope, key, value])
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git config {key} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

const SETTINGS: &[&str] = &[
    "gpg.format",
    "user.signingkey",
    "gpg.ssh.program",
    "gpg.ssh.allowedSignersFile",
    "commit.gpgsign",
    "tag.gpgsign",
];

fn shim_path() -> Result<std::path::PathBuf> {
    Ok(paths::config_dir()?.join("git-ssh-keygen"))
}

/// `~/.config/sealctl/git-ssh-keygen`: runs `sealctl git ssh-keygen "$@"`.
fn write_shim(exe: &std::path::Path) -> Result<std::path::PathBuf> {
    use std::os::unix::fs::PermissionsExt;
    let path = shim_path()?;
    std::fs::create_dir_all(path.parent().context("config dir")?)?;
    let quoted = format!("'{}'", exe.to_string_lossy().replace('\'', r"'\''"));
    std::fs::write(
        &path,
        format!("#!/bin/sh\n# git's gpg.ssh.program, written by `sealctl git setup`\nexec {quoted} git ssh-keygen \"$@\"\n"),
    )?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
    Ok(path)
}

/// Remove the settings `setup` made.
pub fn undo(local: bool) -> Result<()> {
    let scope = if local { "--local" } else { "--global" };
    for key in SETTINGS {
        // exit code 5 = not set; fine
        let _ = Command::new("git")
            .args(["config", scope, "--unset", key])
            .status();
    }
    if !local {
        let _ = std::fs::remove_file(shim_path()?);
    }
    println!(
        "✅ git ({}) no longer signs with sealctl",
        scope.trim_start_matches("--")
    );
    Ok(())
}

pub fn setup(local: bool, key: Option<&str>) -> Result<()> {
    let cert = cert::own()?;
    let name = key.unwrap_or("ed25519");
    let path = ssh::key_path(name)?;
    if !path.exists() {
        bail!(
            "no SSH key {} — create it first: `sealctl ssh keygen {name}`",
            path.display()
        );
    }
    let line = ssh::read_public(&path)?.to_openssh()?;
    let uid = cert::primary_user_id(&cert);
    let email = uid
        .split_once('<')
        .and_then(|(_, r)| r.split_once('>'))
        .map(|(e, _)| e.to_string())
        .unwrap_or_else(|| uid.clone());

    // allowed_signers lets `git log --show-signature` verify our own signatures.
    let allowed = paths::config_dir()?.join("allowed_signers");
    std::fs::create_dir_all(paths::config_dir()?)?;
    std::fs::write(&allowed, format!("{email} namespaces=\"git\" {line}\n"))?;

    let exe = crate::util::stable_exe()?;
    let scope = if local { "--local" } else { "--global" };
    git_config(scope, "gpg.format", "ssh")?;
    git_config(scope, "user.signingkey", &format!("key::{line}"))?;
    // gpg.ssh.program must be ONE executable (git doesn't split arguments): a small wrapper
    git_config(scope, "gpg.ssh.program", &write_shim(&exe)?.to_string_lossy())?;
    git_config(scope, "gpg.ssh.allowedSignersFile", &allowed.to_string_lossy())?;
    git_config(scope, "commit.gpgsign", "true")?;
    git_config(scope, "tag.gpgsign", "true")?;
    println!(
        "✅ git ({}) signs commits and tags with ~/.ssh/sealctl_{name}",
        scope.trim_start_matches("--")
    );
    println!("   Requires the agent: `sealctl ssh install` (once).");
    println!("   Add this key on GitHub → Settings → SSH and GPG keys → New SSH key → type *Signing Key*:");
    println!("   {line}");
    Ok(())
}

/// `gpg.ssh.program` shim: exec `ssh-keygen` with our agent socket.
pub fn ssh_keygen_shim(args: &[String]) -> Result<()> {
    let sock = ssh::socket_path()?;
    if !sock.exists() {
        bail!(
            "sealctl ssh-agent is not running — start it with `sealctl ssh install` (or `sealctl ssh agent`)"
        );
    }
    let mut cmd = Command::new("ssh-keygen");
    cmd.args(args).env("SSH_AUTH_SOCK", &sock);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        bail!("running ssh-keygen: {err}");
    }
    #[cfg(not(unix))]
    {
        let st = cmd.status()?;
        std::process::exit(st.code().unwrap_or(1));
    }
}

// ---- handing signing back (`sealctl unseal`) ----

/// A git config file that signs through sealctl's `gpg.ssh.program` shim.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SigningConfig {
    pub file: std::path::PathBuf,
    pub global: bool,
    /// `user.signingkey` as set (`key::ssh-ed25519 AAAA… comment` when sealctl set it).
    pub signingkey: Option<String>,
}

fn home() -> Result<std::path::PathBuf> {
    std::env::var_os("HOME")
        .map(std::path::PathBuf::from)
        .context("$HOME is not set")
}

/// `git config --file <file> --get <key>`.
pub fn config_get(file: &std::path::Path, key: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--file"])
        .arg(file)
        .args(["--get", key])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim_end().to_string())
}

fn config_set(file: &std::path::Path, key: &str, value: &str) -> Result<()> {
    let out = Command::new("git")
        .args(["config", "--file"])
        .arg(file)
        .args([key, value])
        .output()
        .context("running git")?;
    if !out.status.success() {
        bail!(
            "git config {key} in {} failed: {}",
            file.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

fn config_unset(file: &std::path::Path, key: &str) -> Result<()> {
    let out = Command::new("git")
        .args(["config", "--file"])
        .arg(file)
        .args(["--unset-all", key])
        .output()
        .context("running git")?;
    // exit 5: not set
    if !out.status.success() && out.status.code() != Some(5) {
        bail!(
            "git config --unset {key} in {} failed: {}",
            file.display(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Is this `gpg.ssh.program` value sealctl's shim?
pub fn is_shim(value: &str) -> bool {
    let v = value.trim();
    v.ends_with("sealctl/git-ssh-keygen") || shim_path().is_ok_and(|p| std::path::Path::new(v) == p)
}

/// The user's global git config files: `~/.gitconfig` and `$XDG_CONFIG_HOME/git/config`.
pub fn global_config_files() -> Result<Vec<std::path::PathBuf>> {
    let xdg = match std::env::var_os("XDG_CONFIG_HOME") {
        Some(d) if !d.is_empty() => std::path::PathBuf::from(d),
        _ => home()?.join(".config"),
    };
    Ok(vec![home()?.join(".gitconfig"), xdg.join("git").join("config")])
}

/// Folders never searched for repositories.
const SKIP_DIRS: &[&str] = &[
    "Library",
    "node_modules",
    ".cache",
    "target",
    ".Trash",
    ".sealctl-unseal",
];

/// Every git config that signs through sealctl: the global ones, and `.git/config` of
/// repositories under `$HOME` (6 levels deep, skipping Library, node_modules, .cache, target).
pub fn find_configs() -> Result<Vec<SigningConfig>> {
    let mut out = vec![];
    let mut push = |file: std::path::PathBuf, global: bool| {
        if config_get(&file, "gpg.ssh.program").is_some_and(|v| is_shim(&v)) {
            let signingkey = config_get(&file, "user.signingkey");
            out.push(SigningConfig {
                file,
                global,
                signingkey,
            });
        }
    };
    for f in global_config_files()? {
        if f.is_file() {
            push(f, true);
        }
    }
    fn walk(dir: &std::path::Path, depth: usize, found: &mut Vec<std::path::PathBuf>) {
        if depth > 6 {
            return;
        }
        let Ok(rd) = std::fs::read_dir(dir) else { return };
        for e in rd.flatten() {
            let Ok(ft) = e.file_type() else { continue };
            if !ft.is_dir() {
                continue; // symlinks are not followed
            }
            let name = e.file_name();
            let name = name.to_string_lossy();
            if name == ".git" {
                let cfg = e.path().join("config");
                if cfg.is_file() {
                    found.push(cfg);
                }
                continue;
            }
            if SKIP_DIRS.contains(&name.as_ref()) {
                continue;
            }
            walk(&e.path(), depth + 1, found);
        }
    }
    let mut locals = vec![];
    walk(&home()?, 1, &mut locals);
    locals.sort();
    for f in locals {
        push(f, false);
    }
    Ok(out)
}

/// The public key line in a `key::…` signing key (`ssh-ed25519 AAAA…`, without comment).
pub fn signingkey_line(value: &str) -> Option<String> {
    let rest = value.trim().strip_prefix("key::")?;
    let mut it = rest.split_whitespace();
    Some(format!("{} {}", it.next()?, it.next()?))
}

/// Append the lines of sealctl's `allowed_signers` that `dest` doesn't have yet (and `extra`).
/// Returns whether the file changed.
pub fn merge_allowed_signers(dest: &std::path::Path, extra: &[String]) -> Result<bool> {
    let ours = std::fs::read_to_string(paths::config_dir()?.join("allowed_signers")).unwrap_or_default();
    let mut have = std::fs::read_to_string(dest).unwrap_or_default();
    let before = have.clone();
    for line in ours.lines().map(str::to_string).chain(extra.iter().cloned()) {
        let line = line.trim();
        if line.is_empty() || have.lines().any(|l| l.trim() == line) {
            continue;
        }
        if !have.is_empty() && !have.ends_with('\n') {
            have.push('\n');
        }
        have.push_str(line);
        have.push('\n');
    }
    if have == before {
        return Ok(false);
    }
    if let Some(d) = dest.parent() {
        std::fs::create_dir_all(d)?;
    }
    std::fs::write(dest, have)?;
    Ok(true)
}

/// Point one config at standard `ssh-keygen` signing with `new_pub`: `gpg.ssh.program` unset,
/// `user.signingkey` = the `.pub` path, `gpg.ssh.allowedSignersFile` = `allowed`.
/// `gpg.format`, `commit.gpgsign` and `tag.gpgsign` stay as they are.
pub fn hand_back(cfg: &SigningConfig, new_pub: &std::path::Path, allowed: &std::path::Path) -> Result<()> {
    config_set(&cfg.file, "user.signingkey", &new_pub.to_string_lossy())?;
    config_set(
        &cfg.file,
        "gpg.ssh.allowedSignersFile",
        &allowed.to_string_lossy(),
    )?;
    config_unset(&cfg.file, "gpg.ssh.program")?;
    Ok(())
}

/// Is `cfg` already handed back (no sealctl shim)?
pub fn handed_back(file: &std::path::Path) -> bool {
    !config_get(file, "gpg.ssh.program").is_some_and(|v| is_shim(&v))
}

/// Delete `~/.config/sealctl/git-ssh-keygen`.
pub fn remove_shim() -> Result<()> {
    match std::fs::remove_file(shim_path()?) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

/// Sign a test buffer the way git does (`-n git`) with `key`, then verify it with the real
/// `ssh-keygen -Y verify` against `allowed` as `principal`.
pub fn test_sign(key: &ssh_key::PrivateKey, allowed: &std::path::Path, principal: &str) -> Result<()> {
    let msg = b"sealctl unseal: git signing check\n";
    let sig = key
        .sign("git", ssh_key::HashAlg::Sha512, msg)
        .context("signing the test buffer")?;
    let dir = tempfile_dir()?;
    let sig_path = dir.join("check.sig");
    std::fs::write(&sig_path, sig.to_pem(ssh_key::LineEnding::LF)?)?;
    let mut child = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-n", "git", "-I", principal, "-f"])
        .arg(allowed)
        .arg("-s")
        .arg(&sig_path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("running ssh-keygen -Y verify")?;
    {
        use std::io::Write;
        child.stdin.take().context("stdin")?.write_all(msg)?;
    }
    let out = child.wait_with_output()?;
    let _ = std::fs::remove_dir_all(&dir);
    if !out.status.success() {
        bail!(
            "ssh-keygen -Y verify rejected the test signature: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// The principal of the `allowed_signers` line for `public` (first field), if any.
pub fn principal_for(allowed: &std::path::Path, public: &ssh_key::PublicKey) -> Option<String> {
    let want = public.to_openssh().ok()?;
    let want: Vec<&str> = want.split_whitespace().take(2).collect();
    std::fs::read_to_string(allowed).ok()?.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        let i = f
            .iter()
            .position(|x| x.starts_with("ssh-") || x.starts_with("ecdsa-"))?;
        (f.get(i..i + 2)? == want.as_slice()).then(|| f[0].to_string())
    })
}

fn tempfile_dir() -> Result<std::path::PathBuf> {
    let mut rnd = [0u8; 8];
    getrandom::fill(&mut rnd).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
    let d = std::env::temp_dir().join(format!("sealctl-sign-{}", hex::encode(rnd)));
    paths::ensure_private_dir(&d)?;
    Ok(d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signingkey_lines() {
        assert_eq!(
            signingkey_line("key::ssh-ed25519 AAAAC3Nz me@x").as_deref(),
            Some("ssh-ed25519 AAAAC3Nz")
        );
        assert!(signingkey_line("/home/u/.ssh/id.pub").is_none());
        assert!(is_shim("/Users/u/.config/sealctl/git-ssh-keygen"));
        assert!(!is_shim("/usr/bin/ssh-keygen"));
    }
}
