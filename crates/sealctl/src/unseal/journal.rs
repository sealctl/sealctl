//! The run folder of one `sealctl unseal` run: `~/.sealctl-unseal/<local start time>/`.
//!
//! | File | Content |
//! | --- | --- |
//! | `plan.json` | the plan as confirmed |
//! | `journal.jsonl` | one line per step event, appended and `fsync`ed |
//! | `files/<path under $HOME>` | the copy of every file before its first edit, with its mode |
//! | `kept/` | objects moved instead of deleted (still encrypted) |
//! | `handback.json` | where every new password went (no passwords in it) |
//! | `run.lock` | locked while the run is active |
//! | `done` | written last |
//!
//! The folder sits outside sealctl's own folders, so `unseal --all` can remove those and still
//! finish. Journal notes never hold a value, a password or a path inside the secret store.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::paths;

/// `~/.sealctl-unseal`.
pub fn base_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(std::env::var_os("HOME").context("$HOME is not set")?).join(".sealctl-unseal"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Start,
    Done,
    Failed,
    Skipped,
}

/// One journal line.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Entry {
    pub v: u32,
    pub t: String,
    pub n: u64,
    pub step: String,
    pub state: State,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Non-secret facts later steps and `--resume` need (where a password went, restic key ids).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

/// An open run folder with its lock held.
pub struct Run {
    pub dir: PathBuf,
    entries: Vec<Entry>,
    journal: File,
    _lock: File,
}

fn lock(dir: &Path) -> Result<File> {
    let f = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join("run.lock"))
        .context("opening run.lock")?;
    match f.try_lock() {
        Ok(()) => Ok(f),
        Err(std::fs::TryLockError::WouldBlock) => Err(super::exit(
            2,
            format!("another sealctl unseal run is active ({})", dir.display()),
        )),
        Err(std::fs::TryLockError::Error(e)) => Err(e).context("locking run.lock"),
    }
}

impl Run {
    /// Make a new run folder named after the local start time.
    pub fn create() -> Result<Run> {
        let base = base_dir()?;
        paths::ensure_private_dir(&base)?;
        let (stamp, _) = crate::util::local_time();
        let mut dir = base.join(&stamp);
        let mut i = 1;
        while dir.exists() {
            dir = base.join(format!("{stamp}-{i}"));
            i += 1;
        }
        paths::ensure_private_dir(&dir)?;
        paths::ensure_private_dir(&dir.join("files"))?;
        paths::ensure_private_dir(&dir.join("kept"))?;
        Self::open(&dir)
    }

    /// Open an existing run folder (for `--resume`) and take its lock.
    pub fn open(dir: &Path) -> Result<Run> {
        let lock = lock(dir)?;
        let path = dir.join("journal.jsonl");
        let entries = match fs::read_to_string(&path) {
            Ok(t) => t
                .lines()
                .filter(|l| !l.trim().is_empty())
                // a line cut short by a kill is ignored; its step simply runs (and checks) again
                .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
                .collect(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e.into()),
        };
        let journal = {
            let mut o = OpenOptions::new();
            o.create(true).append(true);
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
            o.open(&path).context("opening journal.jsonl")?
        };
        Ok(Run {
            dir: dir.to_path_buf(),
            entries,
            journal,
            _lock: lock,
        })
    }

    /// The newest run folder without `done`, if any.
    pub fn unfinished() -> Result<Option<PathBuf>> {
        let Ok(rd) = fs::read_dir(base_dir()?) else {
            return Ok(None);
        };
        let mut dirs: Vec<PathBuf> = rd
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.is_dir() && p.join("plan.json").is_file() && !p.join("done").exists())
            .collect();
        dirs.sort();
        Ok(dirs.pop())
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    /// The last state recorded for a step.
    pub fn state(&self, step: &str) -> Option<State> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.step == step)
            .map(|e| e.state)
    }

    pub fn is_done(&self, step: &str) -> bool {
        self.state(step) == Some(State::Done)
    }

    /// The data of the step's last `done` line.
    pub fn data(&self, step: &str) -> Option<&Value> {
        self.entries
            .iter()
            .rev()
            .find(|e| e.step == step && e.state == State::Done)
            .and_then(|e| e.data.as_ref())
    }

    fn append(&mut self, step: &str, state: State, note: Option<String>, data: Option<Value>) -> Result<()> {
        let e = Entry {
            v: 1,
            t: crate::util::local_time().1,
            n: self.entries.len() as u64 + 1,
            step: step.to_string(),
            state,
            note,
            data,
        };
        let mut line = serde_json::to_string(&e)?;
        line.push('\n');
        self.journal.write_all(line.as_bytes())?;
        self.journal.sync_all()?;
        self.entries.push(e);
        Ok(())
    }

    pub fn start(&mut self, step: &str) -> Result<()> {
        self.append(step, State::Start, None, None)?;
        test_kill(step, "start");
        Ok(())
    }

    pub fn done(&mut self, step: &str, note: &str, data: Option<Value>) -> Result<()> {
        test_kill(step, "before-done");
        self.append(step, State::Done, Some(note.to_string()), data)
    }

    pub fn failed(&mut self, step: &str, note: &str) -> Result<()> {
        self.append(step, State::Failed, Some(note.to_string()), None)
    }

    pub fn skipped(&mut self, step: &str, note: &str) -> Result<()> {
        self.append(step, State::Skipped, Some(note.to_string()), None)
    }

    /// Write a JSON file into the run folder (0600).
    pub fn write_json(&self, name: &str, v: &impl Serialize) -> Result<PathBuf> {
        let p = self.dir.join(name);
        let mut text = serde_json::to_string_pretty(v)?;
        text.push('\n');
        paths::write_private(&p, text.as_bytes())?;
        Ok(p)
    }

    pub fn read_json<T: for<'de> Deserialize<'de>>(&self, name: &str) -> Result<T> {
        let p = self.dir.join(name);
        let text = fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))?;
        serde_json::from_str(&text).with_context(|| format!("parsing {}", p.display()))
    }

    /// Where the copy of `file` goes: `files/<path under $HOME>` (`files/_root/<path>` outside).
    fn copy_path(&self, file: &Path) -> PathBuf {
        let home = std::env::var_os("HOME").map(PathBuf::from).unwrap_or_default();
        match file.strip_prefix(&home) {
            Ok(rel) if !home.as_os_str().is_empty() => self.dir.join("files").join(rel),
            _ => self
                .dir
                .join("files")
                .join("_root")
                .join(file.strip_prefix("/").unwrap_or(file)),
        }
    }

    /// Copy `file` into `files/` before its first edit in this run, with its mode. A file that
    /// did not exist yet is recorded as `<name>.absent`.
    pub fn backup_file(&self, file: &Path) -> Result<()> {
        let dest = self.copy_path(file);
        let absent = {
            let mut s = dest.as_os_str().to_owned();
            s.push(".absent");
            PathBuf::from(s)
        };
        if dest.exists() || absent.exists() {
            return Ok(());
        }
        if let Some(d) = dest.parent() {
            fs::create_dir_all(d)?;
        }
        if !file.exists() {
            fs::write(&absent, b"")?;
            return Ok(());
        }
        let real = fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
        if real.is_dir() {
            copy_tree(&real, &dest)?;
        } else {
            fs::copy(&real, &dest).with_context(|| format!("copying {}", file.display()))?;
        }
        Ok(())
    }

    /// Move `src` to `kept/<rel>` (a rename, or copy and remove across file systems).
    pub fn keep(&self, src: &Path, rel: &str) -> Result<PathBuf> {
        let dest = self.dir.join("kept").join(rel);
        if let Some(d) = dest.parent() {
            paths::ensure_private_dir(d)?;
        }
        if dest.exists() {
            bail!("{} already exists", dest.display());
        }
        move_path(src, &dest)?;
        Ok(dest)
    }

    /// Mark the run finished.
    pub fn finish(&self) -> Result<()> {
        paths::write_private(&self.dir.join("done"), crate::util::local_time().1.as_bytes())
    }
}

/// Copy a folder tree with file modes (symlinks copied as links).
pub fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(src)?;
        std::os::unix::fs::symlink(target, dest)?;
    } else if meta.is_dir() {
        fs::create_dir_all(dest)?;
        fs::set_permissions(dest, meta.permissions())?;
        for e in fs::read_dir(src)?.flatten() {
            copy_tree(&e.path(), &dest.join(e.file_name()))?;
        }
    } else {
        fs::copy(src, dest)?;
    }
    Ok(())
}

/// Rename, or copy and remove when `src` and `dest` are on different file systems.
pub fn move_path(src: &Path, dest: &Path) -> Result<()> {
    match fs::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.raw_os_error() == Some(libc::EXDEV) => {
            copy_tree(src, dest)?;
            if fs::symlink_metadata(src)?.is_dir() {
                fs::remove_dir_all(src)?;
            } else {
                fs::remove_file(src)?;
            }
            Ok(())
        }
        Err(e) => Err(e).with_context(|| format!("moving {} to {}", src.display(), dest.display())),
    }
}

/// Test hook (feature `test-hooks`): `SEALCTL_TEST_KILL=<step>:<start|before-done>` makes the
/// process kill itself with SIGKILL at that point, as a power cut would.
#[allow(unused_variables)]
fn test_kill(step: &str, at: &str) {
    #[cfg(feature = "test-hooks")]
    if std::env::var("SEALCTL_TEST_KILL").ok().as_deref() == Some(&format!("{step}:{at}")) {
        // SAFETY: plain syscalls on our own pid.
        unsafe {
            libc::kill(libc::getpid(), libc::SIGKILL);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn journal_lines_roundtrip_and_resume_decisions() {
        let t = tempfile::tempdir().unwrap();
        let dir = t.path().join("run");
        std::fs::create_dir_all(&dir).unwrap();
        {
            let mut r = Run::open(&dir).unwrap();
            r.start("volume:safe:password").unwrap();
            r.done(
                "volume:safe:password",
                "stored and read back",
                Some(serde_json::json!({"store": "keychain"})),
            )
            .unwrap();
            r.start("volume:safe:change").unwrap();
        }
        // a torn last line (killed while writing) is ignored
        let mut f = OpenOptions::new()
            .append(true)
            .open(dir.join("journal.jsonl"))
            .unwrap();
        f.write_all(b"{\"v\":1,\"t\":\"x\",\"n\":4,\"st").unwrap();
        let r = Run::open(&dir).unwrap();
        assert!(r.is_done("volume:safe:password"));
        assert_eq!(r.state("volume:safe:change"), Some(State::Start));
        assert!(!r.is_done("volume:safe:change"));
        assert_eq!(r.data("volume:safe:password").unwrap()["store"], "keychain");
        // the lock is held: a second opener is refused with exit 2
        let err = Run::open(&dir).err().expect("locked");
        assert_eq!(super::super::exit_code(&err), Some(2));
    }

    #[test]
    fn copies_before_edit_once() {
        let t = tempfile::tempdir().unwrap();
        let home = t.path().join("home");
        std::fs::create_dir_all(home.join(".ssh")).unwrap();
        let cfg = home.join(".ssh/config");
        std::fs::write(&cfg, "Host *\n").unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&cfg, std::fs::Permissions::from_mode(0o640)).unwrap();
        }
        let dir = t.path().join("run");
        std::fs::create_dir_all(&dir).unwrap();
        let r = Run::open(&dir).unwrap();
        // copy_path uses $HOME; test it through a path that is not under HOME
        r.backup_file(&cfg).unwrap();
        std::fs::write(&cfg, "changed\n").unwrap();
        r.backup_file(&cfg).unwrap();
        let copy = r.copy_path(&cfg);
        assert_eq!(std::fs::read_to_string(&copy).unwrap(), "Host *\n");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&copy).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let missing = home.join(".zshrc");
        r.backup_file(&missing).unwrap();
        std::fs::write(&missing, "x").unwrap();
        r.backup_file(&missing).unwrap();
        assert!(!r.copy_path(&missing).exists(), "created by the run: no copy");
    }
}
