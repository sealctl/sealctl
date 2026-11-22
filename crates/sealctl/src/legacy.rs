//! Objects and services left by sealctl 0.5 (the Ledger version). 0.7 never changes or
//! removes them; it points to `sealctl unseal --all` of release 0.6 (SPEC 6.1).

use std::path::Path;

use crate::paths;

/// The line printed when 0.5 objects are found.
pub const MESSAGE: &str = "Found objects from sealctl 0.5 (Ledger). Hand them back first with sealctl 0.6: sealctl unseal --all. See https://sealctl.com/docs/from-ledger";

fn has_gpg(dir: &Path, depth: usize) -> bool {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return false;
    };
    rd.flatten().any(|e| {
        let p = e.path();
        if p.is_dir() {
            depth > 0 && has_gpg(&p, depth - 1)
        } else {
            p.extension().is_some_and(|x| x == "gpg")
        }
    })
}

/// What was found, for `doctor`.
pub fn found() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(c) = paths::config_dir() {
        if c.join("keys").is_dir() {
            out.push(format!("{}", c.join("keys").display()));
        }
        if let Ok(rd) = std::fs::read_dir(c.join("volumes")) {
            for e in rd.flatten() {
                let p = e.path();
                if p.extension().is_some_and(|x| x == "toml") {
                    let text = std::fs::read_to_string(&p).unwrap_or_default();
                    if !text.lines().any(|l| l.trim_start().starts_with("words")) {
                        out.push(format!("{}", p.display()));
                    }
                }
            }
        }
    }
    if let Ok(d) = paths::data_dir() {
        if has_gpg(&d.join("secrets"), 8) {
            out.push(format!("{}", d.join("secrets").display()));
        }
    }
    if let Ok(ssh) = paths::ssh_dir() {
        if let Ok(rd) = std::fs::read_dir(&ssh) {
            for e in rd.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("sealctl_") && !n.ends_with(".pub") {
                    out.push(format!("{}", e.path().display()));
                }
            }
        }
    }
    if let Ok(h) = paths::home() {
        for l in [
            "io.github.oleksiyp.sealctl.ssh-agent",
            "io.github.oleksiyp.sealctl.backup",
        ] {
            let plist = h.join("Library/LaunchAgents").join(format!("{l}.plist"));
            if plist.exists() {
                out.push(plist.display().to_string());
            }
        }
        for u in ["sealctl-ssh-agent.service", "sealctl-backup.service"] {
            let unit = h.join(".config/systemd/user").join(u);
            if unit.exists() && std::fs::read_to_string(&unit).is_ok_and(|t| !t.contains("--if-open")) {
                out.push(unit.display().to_string());
            }
        }
    }
    out
}

/// Prints the 0.5 line on stderr when anything was found; returns whether it did.
pub fn warn() -> bool {
    let f = found();
    if !f.is_empty() {
        eprintln!("sealctl: {MESSAGE}");
    }
    !f.is_empty()
}
