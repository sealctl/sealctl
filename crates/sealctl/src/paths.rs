//! Where sealctl keeps its files (SPEC section 3). XDG variables when set, else these
//! defaults, on macOS and Linux alike. Directories 0700, files 0600, written atomically.
//!
//! * config (`~/.config/sealctl`): `config.toml`, `machine.json`, volume and backup definitions
//! * data   (`~/.local/share/sealctl`): the secret store
//! * state  (`~/.local/state/sealctl`): sockets, session, licence cache, inventory, logs

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// `$HOME`.
pub fn home() -> Result<PathBuf> {
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .context("$HOME is not set")
}

fn xdg(var: &str, fallback: &str) -> Result<PathBuf> {
    // unit tests run with the developer's HOME: they never touch the real session, volumes or
    // configuration
    #[cfg(test)]
    {
        let _ = var;
        Ok(unit_test_root().join(fallback).join("sealctl"))
    }
    #[cfg(not(test))]
    match std::env::var_os(var) {
        Some(p) if !p.is_empty() => Ok(PathBuf::from(p).join("sealctl")),
        _ => Ok(home()?.join(fallback).join("sealctl")),
    }
}

/// Where the unit tests (`cargo test`, with any HOME) keep sealctl's folders: a temporary
/// folder of their own per test process.
#[cfg(test)]
pub fn unit_test_root() -> PathBuf {
    static ROOT: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    ROOT.get_or_init(|| std::env::temp_dir().join(format!("sealctl-unit-{}", std::process::id())))
        .clone()
}

/// `~/.config/sealctl`.
pub fn config_dir() -> Result<PathBuf> {
    xdg("XDG_CONFIG_HOME", ".config")
}

/// `~/.local/share/sealctl`.
pub fn data_dir() -> Result<PathBuf> {
    xdg("XDG_DATA_HOME", ".local/share")
}

/// `~/.local/state/sealctl`.
pub fn state_dir() -> Result<PathBuf> {
    xdg("XDG_STATE_HOME", ".local/state")
}

/// `config.toml`.
pub fn config_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.toml"))
}

/// `machine.json`: the pairing.
pub fn machine_file() -> Result<PathBuf> {
    Ok(config_dir()?.join("machine.json"))
}

/// Volume definitions.
pub fn volumes_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("volumes"))
}

/// Backup definitions.
pub fn backups_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("backups"))
}

/// Default parent of store folders.
pub fn store_root() -> Result<PathBuf> {
    Ok(data_dir()?.join("store"))
}

/// The daemon socket.
pub fn daemon_socket() -> Result<PathBuf> {
    Ok(state_dir()?.join("daemon.sock"))
}

/// The SSH agent socket.
pub fn ssh_agent_socket() -> Result<PathBuf> {
    Ok(state_dir()?.join("ssh-agent.sock"))
}

/// Session state (no keys).
pub fn session_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("session.json"))
}

/// Licence cache.
pub fn licence_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("licence.json"))
}

/// Objects this machine knows.
pub fn inventory_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("inventory.json"))
}

/// Remembered agent answers from the phone.
pub fn answers_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("answers.json"))
}

/// Monthly counters.
pub fn month_file() -> Result<PathBuf> {
    Ok(state_dir()?.join("month.json"))
}

/// Daemon log.
pub fn daemon_log() -> Result<PathBuf> {
    Ok(state_dir()?.join("daemon.log"))
}

/// Last backup times per backup.
pub fn backup_state_dir() -> Result<PathBuf> {
    Ok(state_dir()?.join("backup"))
}

/// Create a directory (and parents) readable only by the user.
pub fn ensure_private_dir(p: &Path) -> Result<()> {
    std::fs::create_dir_all(p).with_context(|| format!("creating {}", p.display()))?;
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(p, std::fs::Permissions::from_mode(0o700))?;
    Ok(())
}

/// Write a file readable only by the user: temporary name in the same folder, `fsync`, rename.
pub fn write_private(p: &Path, data: &[u8]) -> Result<()> {
    write_mode(p, data, 0o600)
}

/// Write a file with `mode`: temporary name in the same folder, `fsync`, rename.
pub fn write_mode(p: &Path, data: &[u8], mode: u32) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = p.parent().context("file without a folder")?;
    std::fs::create_dir_all(dir)?;
    let mut rnd = [0u8; 6];
    getrandom::fill(&mut rnd).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
    let name = p.file_name().context("file name")?.to_string_lossy();
    let tmp = dir.join(format!(".{name}.tmp-{}", hex::encode(rnd)));
    {
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(data)?;
        f.sync_all()?;
    }
    if let Err(e) = std::fs::rename(&tmp, p) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("writing {}", p.display()));
    }
    if let Ok(d) = std::fs::File::open(dir) {
        let _ = d.sync_all();
    }
    Ok(())
}

/// `~/.ssh` (or `$SEALCTL_SSH_DIR`).
pub fn ssh_dir() -> Result<PathBuf> {
    match std::env::var_os("SEALCTL_SSH_DIR") {
        Some(p) if !p.is_empty() => Ok(PathBuf::from(p)),
        _ => Ok(home()?.join(".ssh")),
    }
}

/// `~` for the home folder in paths shown to people and phones.
pub fn tilde(p: &Path) -> String {
    if let Ok(h) = home() {
        if let Ok(rest) = p.strip_prefix(&h) {
            return if rest.as_os_str().is_empty() {
                "~".into()
            } else {
                format!("~/{}", rest.display())
            };
        }
    }
    p.display().to_string()
}

/// Expands a leading `~/`.
pub fn expand(p: &str) -> Result<PathBuf> {
    match p.strip_prefix("~/") {
        Some(rest) => Ok(home()?.join(rest)),
        None if p == "~" => home(),
        None => Ok(PathBuf::from(p)),
    }
}
