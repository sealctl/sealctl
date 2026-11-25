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
    /// Desktop notifications while a request waits for the phone and for level 3 notices
    /// (SPEC 5.2); `false` turns them off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notifications: Option<bool>,
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

/// Checks a relay origin: `https://host[:port]` only, except `http://127.0.0.1:<port>`,
/// `http://localhost:<port>` and `http://[::1]:<port>` for tests. No user name or password,
/// no path other than one trailing `/`, no query and no fragment: API paths are appended to the
/// origin, and any of these would change where signed requests go. Returns the origin as the
/// URL parser normalizes it (lower-case host, default port left out), without a trailing slash.
pub fn validate_origin(text: &str) -> Result<String> {
    let t = text.trim();
    let refuse = |why: &str| {
        fail(
            exit::USAGE,
            format!("{t} is not a relay origin: {why}. Use https://host (http:// only to localhost)."),
        )
    };
    // the URL parser drops tabs and line breaks inside a URL; refuse them instead
    if t.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(refuse("it contains spaces or control characters"));
    }
    let url = reqwest::Url::parse(t).map_err(|_| refuse("not a URL"))?;
    let host = url.host_str().unwrap_or_default();
    match url.scheme() {
        "https" if !host.is_empty() => {}
        "http" if matches!(host, "127.0.0.1" | "localhost" | "[::1]") => {}
        "http" => return Err(refuse("http:// is only for localhost")),
        _ => return Err(refuse("https:// only")),
    }
    if !url.username().is_empty() || url.password().is_some() {
        return Err(refuse("it has a user name or password"));
    }
    if url.path() != "/" || t.ends_with("//") {
        return Err(refuse("it has a path"));
    }
    if url.query().is_some() {
        return Err(refuse("it has a query string"));
    }
    if url.fragment().is_some() {
        return Err(refuse("it has a fragment"));
    }
    Ok(url.origin().ascii_serialization())
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
        // normalized: one trailing slash, case, default port
        for (given, want) in [
            ("https://relay.example.test", "https://relay.example.test"),
            ("  https://relay.example.test/  ", "https://relay.example.test"),
            ("https://Relay.Example.TEST:443/", "https://relay.example.test"),
            (
                "https://relay.example.test:8443",
                "https://relay.example.test:8443",
            ),
            ("http://[::1]:8787/", "http://[::1]:8787"),
            ("http://localhost:8787", "http://localhost:8787"),
        ] {
            assert_eq!(validate_origin(given).unwrap(), want, "{given}");
        }
        // not origins: a path, query, fragment, user info, or anything the parser would rewrite
        for bad in [
            "https://relay.example.test/v1",
            "https://relay.example.test/v1/",
            "https://relay.example.test//",
            "https://relay.example.test?x=1",
            "https://relay.example.test/?x=1",
            "https://relay.example.test?",
            "https://relay.example.test#fragment",
            "https://relay.example.test/#",
            "https://user@relay.example.test",
            "https://user:pw@relay.example.test",
            "https://:pw@relay.example.test",
            "http://localhost:8787/api",
            "http://127.0.0.1:8787?x",
            "http://localhost.example.test:8787",
            "https://relay.exa\tmple.test",
            "https://relay.exa\nmple.test",
            "https://relay.example.test\\path",
            "https://",
            "relay.example.test",
            "",
        ] {
            assert!(validate_origin(bad).is_err(), "{bad:?}");
        }
        assert_eq!(host_of("https://relay.sealctl.com"), "relay.sealctl.com");
    }
}
