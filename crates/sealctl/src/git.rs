//! Git commit/tag signing with the Ledger authentication key via SSH signatures.
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
    let line = match key {
        Some(name) => ssh::read_public(&ssh::key_path(name)?)?.to_openssh()?,
        None => ssh::public_key_line(&cert)?,
    };
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
        "✅ git ({}) signs commits and tags with your Ledger key",
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
