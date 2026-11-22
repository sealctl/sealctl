//! The run folder and journal of a `seal` or `unseal` run (SPEC 18.4):
//! `~/sealctl-unsealed-<date>/` with `plan.json`, `journal.jsonl`, `files/`, `kept/`,
//! `handback.json`, the `folder` store files, and `done` written last.

use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde_json::{json, Value};

use crate::exit::{self, fail};
use crate::paths;

/// One run.
pub struct Run {
    /// The folder.
    pub dir: PathBuf,
    n: u64,
    _lock: std::fs::File,
}

fn fsync_dir(d: &Path) {
    if let Ok(f) = std::fs::File::open(d) {
        let _ = f.sync_all();
    }
}

fn lock_file(dir: &Path) -> Result<std::fs::File> {
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("run.lock"))?;
    nix::fcntl::Flock::lock(f.try_clone()?, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|_| {
            fail(
                exit::USAGE,
                format!("Another run is using {}.", paths::tilde(dir)),
            )
        })
        .map(std::mem::forget)?;
    Ok(f)
}

impl Run {
    /// A new folder `~/sealctl-unsealed-<date>` (`-2`, `-3`, … when taken), 0700.
    pub fn create() -> Result<Run> {
        let home = paths::home()?;
        let date = chrono::Local::now().format("%Y-%m-%d").to_string();
        let mut dir = home.join(format!("sealctl-unsealed-{date}"));
        let mut i = 2;
        while dir.exists() {
            dir = home.join(format!("sealctl-unsealed-{date}-{i}"));
            i += 1;
        }
        paths::ensure_private_dir(&dir)?;
        fsync_dir(&home);
        let lock = lock_file(&dir)?;
        Ok(Run {
            dir,
            n: 0,
            _lock: lock,
        })
    }

    /// The newest run without `done`.
    pub fn resume() -> Result<Run> {
        let home = paths::home()?;
        let mut runs: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&home)?
            .flatten()
            .filter(|e| e.file_name().to_string_lossy().starts_with("sealctl-unsealed-"))
            .filter(|e| e.path().join("plan.json").exists() && !e.path().join("done").exists())
            .filter_map(|e| Some((e.metadata().ok()?.modified().ok()?, e.path())))
            .collect();
        runs.sort();
        let (_, dir) = runs
            .pop()
            .ok_or_else(|| fail(exit::NOT_FOUND, "No unfinished run to resume."))?;
        let lock = lock_file(&dir)?;
        let n = std::fs::read_to_string(dir.join("journal.jsonl"))
            .map(|t| t.lines().count() as u64)
            .unwrap_or(0);
        Ok(Run { dir, n, _lock: lock })
    }

    /// Writes a file in the run folder (0600), durably.
    pub fn write(&self, name: &str, data: &[u8]) -> Result<()> {
        paths::write_private(&self.dir.join(name), data)?;
        fsync_dir(&self.dir);
        Ok(())
    }

    /// Appends one journal line and `fsync`s it.
    pub fn log(&mut self, step: &str, state: &str, note: &str) -> Result<()> {
        self.n += 1;
        let line = json!({
            "v": 1,
            "t": chrono::Local::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, false),
            "n": self.n,
            "step": step,
            "state": state,
            "note": note,
        });
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(self.dir.join("journal.jsonl"))
            .context("journal")?;
        f.write_all(format!("{line}\n").as_bytes())?;
        f.sync_all()?;
        Ok(())
    }

    /// Steps recorded `done` (lines cut short by a power cut are skipped).
    pub fn done_steps(&self) -> Vec<String> {
        std::fs::read_to_string(self.dir.join("journal.jsonl"))
            .unwrap_or_default()
            .lines()
            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
            .filter(|v| v["state"] == "done" || v["state"] == "skipped")
            .filter_map(|v| v["step"].as_str().map(str::to_owned))
            .collect()
    }

    /// Copies a file into `files/<path under $HOME>` before its first edit.
    pub fn keep_copy(&self, file: &Path) -> Result<()> {
        if !file.exists() {
            return Ok(());
        }
        let home = paths::home()?;
        let rel = file.strip_prefix(&home).unwrap_or(file);
        let dest = self.dir.join("files").join(rel.strip_prefix("/").unwrap_or(rel));
        if dest.exists() {
            return Ok(());
        }
        if let Some(d) = dest.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::copy(file, &dest)?;
        fsync_dir(dest.parent().unwrap_or(&self.dir));
        Ok(())
    }

    /// Moves a file or folder into `kept/<name>` instead of deleting it.
    pub fn keep(&self, from: &Path, name: &str) -> Result<()> {
        if !from.exists() {
            return Ok(());
        }
        let dest = self.dir.join("kept").join(name);
        if let Some(d) = dest.parent() {
            std::fs::create_dir_all(d)?;
        }
        if std::fs::rename(from, &dest).is_err() {
            copy_tree(from, &dest)?;
            if from.is_dir() {
                std::fs::remove_dir_all(from)?;
            } else {
                std::fs::remove_file(from)?;
            }
        }
        fsync_dir(dest.parent().unwrap_or(&self.dir));
        Ok(())
    }

    /// Marks the run finished.
    pub fn finish(&self) -> Result<()> {
        self.write("done", b"")
    }
}

fn copy_tree(from: &Path, to: &Path) -> Result<()> {
    if from.is_dir() {
        std::fs::create_dir_all(to)?;
        for e in std::fs::read_dir(from)?.flatten() {
            copy_tree(&e.path(), &to.join(e.file_name()))?;
        }
    } else {
        std::fs::copy(from, to)?;
    }
    Ok(())
}

/// A double-quoted dotenv value that a POSIX shell (`set -a; . file`) and the dotenv parser
/// read back as the same bytes.
pub fn quote_env(v: &str) -> String {
    let mut out = String::from("\"");
    for c in v.chars() {
        match c {
            '\\' | '"' | '$' | '`' => {
                out.push('\\');
                out.push(c);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// `NAME` for a secret name: upper case, `/ - . @ +` as `_`.
pub fn env_name(secret: &str) -> String {
    secret
        .chars()
        .map(|c| match c {
            '/' | '-' | '.' | '@' | '+' => '_',
            c => c.to_ascii_uppercase(),
        })
        .collect()
}

/// A new password: 32 characters of `a-z0-9` in groups of four joined by `-`.
pub fn new_password() -> Result<zeroize::Zeroizing<String>> {
    const ALPHA: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
    let mut out = zeroize::Zeroizing::new(String::with_capacity(39));
    let mut n = 0;
    while n < 32 {
        let mut b = [0u8; 1];
        getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
        // 252 = 7 × 36: no modulo bias
        if b[0] >= 252 {
            continue;
        }
        if n > 0 && n % 4 == 0 {
            out.push('-');
        }
        out.push(ALPHA[(b[0] % 36) as usize] as char);
        n += 1;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwords() {
        let p = new_password().unwrap();
        assert_eq!(p.len(), 39);
        assert_eq!(p.split('-').count(), 8);
        assert!(p
            .chars()
            .all(|c| c == '-' || c.is_ascii_lowercase() || c.is_ascii_digit()));
    }

    #[test]
    fn env_quoting_reads_back() {
        let v = "a \"b\" $c `d` \\e\nline2";
        let text = format!("X={}\n", quote_env(v));
        let back = crate::dotenv::parse_dotenv(&text).unwrap();
        assert_eq!(back["X"].as_str(), v);
        assert_eq!(env_name("shop/openai-api.key"), "SHOP_OPENAI_API_KEY");
    }
}
