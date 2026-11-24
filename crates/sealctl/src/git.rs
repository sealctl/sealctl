//! Git commit and tag signing with an SSH key from the store (SSH signatures), and the git
//! credential helper for tokens stored as `git/<host>`.
//!
//! Git calls `gpg.ssh.program` (normally `ssh-keygen -Y sign`). We point it at
//! `sealctl git ssh-keygen`, which runs the real `ssh-keygen` with `SSH_AUTH_SOCK` set to the
//! daemon's agent, so signing works regardless of the shell's SSH_AUTH_SOCK.

use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::exit::{self, fail};
use crate::{paths, ssh};

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

/// Does git sign through sealctl here (`sealctl git setup` wrote the `gpg.ssh.program` shim)?
pub fn signs_through_sealctl() -> bool {
    shim_path().is_ok_and(|p| p.is_file())
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
    eprintln!(
        "git ({}) no longer signs with sealctl.",
        scope.trim_start_matches("--")
    );
    Ok(())
}

pub fn setup(local: bool, key: Option<&str>) -> Result<()> {
    let name = key.unwrap_or("ed25519");
    let public = ssh::read_public(name).map_err(|_| {
        fail(
            exit::NOT_FOUND,
            format!("No SSH key {name}. Create it first: sealctl ssh keygen {name}"),
        )
    })?;
    let line = public.to_openssh()?;
    let email = Command::new("git")
        .args(["config", "--get", "user.email"])
        .output()
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|e| !e.is_empty())
        .unwrap_or_else(|| "*".into());

    // allowed_signers lets `git log --show-signature` verify our own signatures.
    let allowed = paths::config_dir()?.join("allowed_signers");
    paths::ensure_private_dir(&paths::config_dir()?)?;
    paths::write_mode(
        &allowed,
        format!("{email} namespaces=\"git\" {line}\n").as_bytes(),
        0o644,
    )?;

    let exe = crate::util::stable_exe()?;
    let scope = if local { "--local" } else { "--global" };
    git_config(scope, "gpg.format", "ssh")?;
    git_config(scope, "user.signingkey", &format!("key::{line}"))?;
    // gpg.ssh.program must be ONE executable (git doesn't split arguments): a small wrapper
    git_config(scope, "gpg.ssh.program", &write_shim(&exe)?.to_string_lossy())?;
    git_config(scope, "gpg.ssh.allowedSignersFile", &allowed.to_string_lossy())?;
    git_config(scope, "commit.gpgsign", "true")?;
    git_config(scope, "tag.gpgsign", "true")?;
    eprintln!(
        "git ({}) signs commits and tags with ssh/{name}.",
        scope.trim_start_matches("--")
    );
    eprintln!("Add this key on GitHub as a Signing Key: Settings, SSH and GPG keys, New SSH key:");
    println!("{line}");
    Ok(())
}

/// `sealctl git credentials <host>`: git asks `sealctl git credential` for `https://<host>`.
pub fn credentials(host: &str, undo: bool) -> Result<()> {
    if host.is_empty() || host.contains('/') || host.contains(char::is_whitespace) {
        return Err(fail(exit::USAGE, "Give a host name, e.g. github.com."));
    }
    let key = format!("credential.https://{host}.helper");
    if undo {
        let _ = Command::new("git")
            .args(["config", "--global", "--unset", &key])
            .status();
        eprintln!("git no longer asks sealctl for {host}.");
        return Ok(());
    }
    let exe = crate::util::stable_exe()?;
    git_config(
        "--global",
        &key,
        &format!(
            "!'{}' git credential",
            exe.to_string_lossy().replace('\'', r"'\''")
        ),
    )?;
    eprintln!("git asks sealctl for {host} (token: secret git/{host}).");
    Ok(())
}

/// `host=` of the git credential helper protocol input (empty when missing or unusable).
pub fn credential_host(input: &str) -> String {
    let h = input
        .lines()
        .find_map(|l| l.strip_prefix("host="))
        .map(str::trim)
        .unwrap_or("");
    // a host name, with an optional port: never a path into the store
    if h.is_empty()
        || h.len() > 253
        || !h
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | ':'))
    {
        return String::new();
    }
    h.to_string()
}

/// The git credential helper protocol: `get` prints `username=` and `password=` for
/// `host=` from the secret `git/<host>` (a token, or `user` and token on two lines).
pub fn credential(action: &str) -> Result<()> {
    if action != "get" {
        return Ok(());
    }
    // inside an agent only git itself may ask (SPEC 10.6): not the agent's shell, not
    // `git credential fill` run by the agent
    crate::caller::check_helper(crate::caller::Tool::Git, "sealctl git credential")?;
    if crate::guard::ai_agent().is_some() && std::io::IsTerminal::is_terminal(&std::io::stdout()) {
        return Err(exit::agent_refusal("sealctl git credential"));
    }
    let mut input = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut input)?;
    let host = credential_host(&input);
    if host.is_empty() {
        return Ok(());
    }
    let name = format!("git/{host}");
    let store = crate::store::Store::configured()?;
    if !store.exists(&name) {
        return Ok(());
    }
    let vals = crate::daemon::client::values(std::slice::from_ref(&name), Some(("secret", &name)))?;
    let text = zeroize::Zeroizing::new(String::from_utf8_lossy(&vals[0].1).into_owned());
    let (user, token) = match text.split_once('\n') {
        Some((u, t)) => (u.trim(), t.trim()),
        None => ("x-access-token", text.trim()),
    };
    let out = zeroize::Zeroizing::new(format!("username={user}\npassword={token}\n"));
    std::io::Write::write_all(&mut std::io::stdout(), out.as_bytes())?;
    Ok(())
}

/// `gpg.ssh.program` shim: exec `ssh-keygen` with our agent socket.
pub fn ssh_keygen_shim(args: &[String]) -> Result<()> {
    let sock = ssh::socket_path()?;
    // a socket file left by a daemon that did not exit cleanly answers nothing
    let answers = || std::os::unix::net::UnixStream::connect(&sock).is_ok();
    if !answers() {
        // the daemon serves the agent; start it
        let _ = crate::daemon::client::call(serde_json::json!({"op": "status"}));
    }
    if !answers() {
        bail!("The sealctl SSH agent is not running. Run: sealctl status");
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
