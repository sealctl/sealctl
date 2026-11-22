//! `config.toml` and the relay origin (SPEC 3, 4, 7).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::exit::{self, fail};
use crate::paths;

/// The production relay.
pub const DEFAULT_RELAY: &str = sealctl_core::pairing::DEFAULT_RELAY;

/// `~/.config/sealctl/config.toml`.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Config {
    /// Relay origin; `SEALCTL_RELAY` and `--relay` override it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// The store folder (`~/.local/share/sealctl/store/<store-id>`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub store: Option<String>,
}

impl Config {
    /// Loads the file; missing means defaults.
    pub fn load() -> Result<Config> {
        let p = paths::config_file()?;
        match std::fs::read_to_string(&p) {
            Ok(t) => toml::from_str(&t).with_context(|| format!("reading {}", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(e).with_context(|| format!("reading {}", p.display())),
        }
    }

    /// Saves the file (0600).
    pub fn save(&self) -> Result<()> {
        let dir = paths::config_dir()?;
        paths::ensure_private_dir(&dir)?;
        paths::write_private(&paths::config_file()?, toml::to_string_pretty(self)?.as_bytes())
    }

    /// The store folder, if one is set.
    pub fn store_path(&self) -> Result<Option<PathBuf>> {
        self.store.as_deref().map(paths::expand).transpose()
    }
}

/// Checks a relay origin: `https://` only, except `http://127.0.0.1:<port>` and
/// `http://localhost:<port>` for tests. Returns it without a trailing slash.
pub fn validate_origin(text: &str) -> Result<String> {
    let t = text.trim().trim_end_matches('/');
    let ok = if let Some(rest) = t.strip_prefix("https://") {
        !rest.is_empty() && !rest.contains('/') && !rest.contains('@')
    } else if let Some(rest) = t.strip_prefix("http://") {
        let host = rest.rsplit_once(':').map_or(rest, |(h, _)| h);
        matches!(host, "127.0.0.1" | "localhost" | "[::1]") && !rest.contains('/')
    } else {
        false
    };
    if !ok {
        return Err(fail(
            exit::USAGE,
            format!("{t} is not a relay origin: https:// only (http:// only to localhost)."),
        ));
    }
    Ok(t.to_string())
}

/// The relay asked for on the command line or in the environment, if any.
pub fn requested_relay(flag: Option<&str>) -> Result<Option<String>> {
    let env = std::env::var("SEALCTL_RELAY").ok().filter(|s| !s.is_empty());
    flag.map(str::to_owned)
        .or(env)
        .map(|s| validate_origin(&s))
        .transpose()
}

/// The relay for a machine that is not paired yet: flag, environment, config, default.
pub fn relay_for_pairing(flag: Option<&str>) -> Result<String> {
    if let Some(r) = requested_relay(flag)? {
        return Ok(r);
    }
    match Config::load()?.relay {
        Some(r) => validate_origin(&r),
        None => Ok(DEFAULT_RELAY.to_string()),
    }
}

/// The host of an origin, for messages.
pub fn host_of(origin: &str) -> &str {
    origin
        .split_once("://")
        .map_or(origin, |(_, r)| r)
        .trim_end_matches('/')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn origins() {
        assert_eq!(
            validate_origin("https://relay.sealctl.com/").unwrap(),
            "https://relay.sealctl.com"
        );
        assert!(validate_origin("http://127.0.0.1:8787").is_ok());
        assert!(validate_origin("http://localhost:1").is_ok());
        assert!(validate_origin("http://relay.example.com").is_err());
        assert!(validate_origin("https://relay.example.com/path").is_err());
        assert!(validate_origin("ftp://x").is_err());
        assert_eq!(host_of("https://relay.sealctl.com"), "relay.sealctl.com");
    }
}
