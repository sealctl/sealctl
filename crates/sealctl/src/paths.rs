//! Where sealctl keeps its files. Everything is per-user; nothing secret is stored unencrypted.
//!
//! * config  (`~/.config/sealctl`): public certificate, volume definitions (no secrets)
//! * data    (`~/.local/share/sealctl`): the secret store
//! * state   (`~/.local/state/sealctl`): sockets, logs

use std::path::PathBuf;

use anyhow::{Context, Result};

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .context("$HOME is not set")
}

fn xdg(var: &str, fallback: &str) -> Result<PathBuf> {
    match std::env::var_os(var) {
        Some(p) if !p.is_empty() => Ok(PathBuf::from(p).join("sealctl")),
        _ => Ok(home()?.join(fallback).join("sealctl")),
    }
}

pub fn config_dir() -> Result<PathBuf> {
    xdg("XDG_CONFIG_HOME", ".config")
}

pub fn data_dir() -> Result<PathBuf> {
    xdg("XDG_DATA_HOME", ".local/share")
}

pub fn state_dir() -> Result<PathBuf> {
    xdg("XDG_STATE_HOME", ".local/state")
}

pub fn keys_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("keys"))
}

pub fn volumes_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("volumes"))
}

pub fn secrets_dir() -> Result<PathBuf> {
    Ok(data_dir()?.join("secrets"))
}

pub fn ssh_agent_socket() -> Result<PathBuf> {
    Ok(state_dir()?.join("ssh-agent.sock"))
}

/// Create a directory (and parents) readable only by the user.
pub fn ensure_private_dir(p: &std::path::Path) -> Result<()> {
    std::fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write a file readable only by the user: atomic replace, durable (data and directory entry
/// `fsync`ed), see [`crate::durable`].
pub fn write_private(p: &std::path::Path, data: &[u8]) -> Result<()> {
    crate::durable::write_atomic(p, data, 0o600)
}

/// `~/.ssh` (or `$SEALCTL_SSH_DIR`): where `sealctl ssh keygen` puts encrypted key files.
pub fn ssh_dir() -> Result<PathBuf> {
    match std::env::var_os("SEALCTL_SSH_DIR") {
        Some(p) if !p.is_empty() => Ok(PathBuf::from(p)),
        _ => Ok(home()?.join(".ssh")),
    }
}
