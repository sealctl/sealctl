//! The run folder of one `sealctl unseal` run: `~/sealctl-unsealed-<YYYY-MM-DD>` (`-2`, `-3`, …
//! when taken), mode 0700, files 0600. It is visible on purpose: everything sealctl hands back
//! in plain form is in it, and the person deletes it once everything works. sealctl never does.
//!
//! | File | Content |
//! | --- | --- |
//! | `README.txt` | what is in the folder and how to check each item by hand |
//! | `passwords.txt` | new volume passphrases and restic passwords (default store) |
//! | `backup-<volume>.env` | restic settings: repository, password, storage credentials |
//! | `secrets.env` | the secrets of the store, plain (default `--secrets-to`) |
//! | `plan.json` | the plan as confirmed |
//! | `journal.jsonl` | one line per step event, appended and `fsync`ed |
//! | `files/<path under $HOME>` | the copy of every file before its first edit, with its mode |
//! | `kept/` | objects moved instead of deleted (still encrypted) |
//! | `handback.json` | where every new password went (no passwords in it) |
//! | `run.lock` | locked while the run is active |
//! | `done` | written last |
//!
//! Write-ahead: every file here is written durably (see [`crate::durable`]) before the step
//! that depends on it runs, and every journal line is `fsync`ed. The folder sits outside
//! sealctl's own folders, so `unseal --all` can remove those and still finish. Journal notes
//! never hold a value, a password or a path inside the secret store.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::durable;

/// Run folders are `$HOME/<PREFIX><date>[-n]`.
pub const PREFIX: &str = "sealctl-unsealed-";

fn home() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME").context("$HOME is not set")?,
    ))
}

/// `(date, n)` of a run folder name `sealctl-unsealed-2026-11-21[-n]` (n = 1 without suffix).
fn run_name_key(name: &str) -> Option<(String, u32)> {
    let rest = name.strip_prefix(PREFIX)?;
    let date = rest.get(..10)?;
    let ok = date.len() == 10
        && date.chars().enumerate().all(|(i, c)| {
            if i == 4 || i == 7 {
                c == '-'
            } else {
                c.is_ascii_digit()
            }
        });
    if !ok {
        return None;
    }
    let n = match &rest[10..] {
        "" => 1,
        s => s.strip_prefix('-')?.parse().ok()?,
    };
    Some((date.to_string(), n))
}

/// The folder a run started now would get: `~/sealctl-unsealed-<today>`, or `-2`, `-3`, …
pub fn next_dir() -> Result<PathBuf> {
    let home = home()?;
    let (stamp, _) = crate::util::local_time();
    let date = &stamp[..10];
    let mut dir = home.join(format!("{PREFIX}{date}"));
    let mut i = 2;
    while fs::symlink_metadata(&dir).is_ok() {
        dir = home.join(format!("{PREFIX}{date}-{i}"));
        i += 1;
    }
    Ok(dir)
}

/// Every run folder in `$HOME`, oldest first.
pub fn run_dirs() -> Result<Vec<PathBuf>> {
    let Ok(rd) = fs::read_dir(home()?) else {
        return Ok(vec![]);
    };
    let mut dirs: Vec<((String, u32), PathBuf)> = rd
        .flatten()
        .filter_map(|e| {
            let key = run_name_key(&e.file_name().to_string_lossy())?;
            let p = e.path();
            (p.is_dir() && !p.is_symlink()).then_some((key, p))
        })
        .collect();
    dirs.sort();
    Ok(dirs.into_iter().map(|(_, p)| p).collect())
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
    let path = dir.join("run.lock");
    let new = !path.exists();
    if new {
        durable::tracker::touch(&path);
    }
    let f = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .context("opening run.lock")?
    };
    if new {
        durable::sync_file(&f, &path)?;
        durable::fsync_dir(dir)?;
    }
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
    /// Make the run folder `dir` (from [`next_dir`]; the next free name if it was taken since)
    /// and open it. Only after the plan is confirmed: nothing is created otherwise.
    pub fn create(dir: &Path) -> Result<Run> {
        let mut dir = dir.to_path_buf();
        if fs::symlink_metadata(&dir).is_ok() {
            dir = next_dir()?;
        }
        durable::create_dir_all(&dir, 0o700)?;
        durable::create_dir_all(&dir.join("files"), 0o700)?;
        durable::create_dir_all(&dir.join("kept"), 0o700)?;
        Self::open(&dir)
    }

    /// Open an existing run folder (for `--resume`) and take its lock.
    pub fn open(dir: &Path) -> Result<Run> {
        durable::tracker::existing(dir);
        let lock = lock(dir)?;
        let path = dir.join("journal.jsonl");
        let text = match fs::read(&path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => vec![],
            Err(e) => return Err(e.into()),
        };
        // a line cut short by a kill or a power cut is dropped from the file, so the next line
        // starts on a line of its own; its step simply runs (and checks) again
        let keep = match text.iter().rposition(|b| *b == b'\n') {
            Some(i) => i + 1,
            None => 0,
        };
        let entries = String::from_utf8_lossy(&text[..keep])
            .lines()
            .filter(|l| !l.trim().is_empty())
            .filter_map(|l| serde_json::from_str::<Entry>(l).ok())
            .collect();
        let created = text.is_empty() && !path.exists();
        if created {
            durable::tracker::touch(&path);
        }
        let journal = {
            let mut o = OpenOptions::new();
            o.create(true).append(true);
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
            o.open(&path).context("opening journal.jsonl")?
        };
        if keep < text.len() {
            journal
                .set_len(keep as u64)
                .context("dropping a torn journal line")?;
            durable::sync_file(&journal, &path)?;
        }
        if created {
            durable::sync_file(&journal, &path)?;
            durable::fsync_dir(dir)?;
        }
        Ok(Run {
            dir: dir.to_path_buf(),
            entries,
            journal,
            _lock: lock,
        })
    }

    /// The newest run folder without `done`, if any.
    pub fn unfinished() -> Result<Option<PathBuf>> {
        Ok(run_dirs()?
            .into_iter()
            .rfind(|p| p.join("plan.json").is_file() && !p.join("done").exists()))
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
        durable::sync_file(&self.journal, &self.dir.join("journal.jsonl"))?;
        self.entries.push(e);
        Ok(())
    }

    pub fn start(&mut self, step: &str) -> Result<()> {
        self.append(step, State::Start, None, None)?;
        self.test_kill(step, "start");
        Ok(())
    }

    pub fn done(&mut self, step: &str, note: &str, data: Option<Value>) -> Result<()> {
        self.test_kill(step, "before-done");
        self.append(step, State::Done, Some(note.to_string()), data)
    }

    pub fn failed(&mut self, step: &str, note: &str) -> Result<()> {
        self.append(step, State::Failed, Some(note.to_string()), None)
    }

    pub fn skipped(&mut self, step: &str, note: &str) -> Result<()> {
        self.append(step, State::Skipped, Some(note.to_string()), None)
    }

    /// Write a file into the run folder (0600), durably.
    pub fn write_file(&self, name: &str, data: &[u8]) -> Result<PathBuf> {
        let p = self.dir.join(name);
        durable::write_atomic(&p, data, 0o600)?;
        Ok(p)
    }

    /// Write a JSON file into the run folder (0600).
    pub fn write_json(&self, name: &str, v: &impl Serialize) -> Result<PathBuf> {
        let p = self.dir.join(name);
        let mut text = serde_json::to_string_pretty(v)?;
        text.push('\n');
        durable::write_atomic(&p, text.as_bytes(), 0o600)?;
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

    /// Copy `file` into `files/` before its first edit in this run, with its mode, durably. A
    /// file that did not exist yet is recorded as `<name>.absent`.
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
            durable::create_dir_all(d, 0o700)?;
        }
        if !file.exists() {
            durable::write_atomic(&absent, b"", 0o600)?;
            return Ok(());
        }
        let real = fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
        if real.is_dir() {
            copy_tree(&real, &dest)?;
        } else {
            durable::copy_file(&real, &dest)?;
        }
        Ok(())
    }

    /// Move `src` to `kept/<rel>` (a rename, or copy and remove across file systems).
    pub fn keep(&self, src: &Path, rel: &str) -> Result<PathBuf> {
        let dest = self.dir.join("kept").join(rel);
        if let Some(d) = dest.parent() {
            durable::create_dir_all(d, 0o700)?;
        }
        if dest.exists() {
            bail!("{} already exists", dest.display());
        }
        move_path(src, &dest)?;
        Ok(dest)
    }

    /// Mark the run finished.
    pub fn finish(&self) -> Result<()> {
        self.write_file("done", crate::util::local_time().1.as_bytes())
            .map(|_| ())
    }

    /// Test hook (feature `test-hooks`): `SEALCTL_TEST_KILL=<step>:<start|before-done>` makes
    /// the process kill itself with SIGKILL at that point; `SEALCTL_TEST_POWERCUT=<same>` first
    /// throws away everything not made durable (see [`durable::tracker`]) and writes what it
    /// lost to `$SEALCTL_TEST_POWERCUT_REPORT`.
    #[allow(unused_variables)]
    fn test_kill(&self, step: &str, at: &str) {
        #[cfg(feature = "test-hooks")]
        {
            let point = format!("{step}:{at}");
            let kill = std::env::var("SEALCTL_TEST_KILL").ok().as_deref() == Some(&point);
            let cut = std::env::var("SEALCTL_TEST_POWERCUT").ok().as_deref() == Some(&point);
            if cut {
                let lost = durable::tracker::cut(&self.dir, &self.dir.join("journal.jsonl"));
                if let Some(r) = std::env::var_os("SEALCTL_TEST_POWERCUT_REPORT") {
                    let _ = fs::write(r, lost.join("\n"));
                }
            }
            if kill || cut {
                // SAFETY: plain syscalls on our own pid.
                unsafe {
                    libc::kill(libc::getpid(), libc::SIGKILL);
                }
            }
        }
    }
}

/// Copy a folder tree with file modes (symlinks copied as links), durably.
pub fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(src)?;
    if meta.file_type().is_symlink() {
        let target = fs::read_link(src)?;
        durable::tracker::touch(dest);
        std::os::unix::fs::symlink(target, dest)?;
        durable::fsync_parent(dest)?;
    } else if meta.is_dir() {
        durable::create_dir_all(dest, 0o700)?;
        fs::set_permissions(dest, meta.permissions())?;
        for e in fs::read_dir(src)?.flatten() {
            copy_tree(&e.path(), &dest.join(e.file_name()))?;
        }
    } else {
        durable::copy_file(src, dest)?;
    }
    Ok(())
}

/// Rename (with both directories `fsync`ed), or copy durably and remove when `src` and `dest`
/// are on different file systems.
pub fn move_path(src: &Path, dest: &Path) -> Result<()> {
    match durable::rename(src, dest) {
        Ok(()) => Ok(()),
        Err(e) if e.downcast_ref::<std::io::Error>().and_then(|e| e.raw_os_error()) == Some(libc::EXDEV) => {
            copy_tree(src, dest)?;
            if fs::symlink_metadata(src)?.is_dir() {
                fs::remove_dir_all(src)?;
                durable::fsync_parent(src)?;
            } else {
                durable::remove_file(src)?;
            }
            Ok(())
        }
        Err(e) => Err(e),
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
        drop(r);
        // the torn line is gone from the file, so the next line is whole and read back
        let mut r = Run::open(&dir).unwrap();
        assert!(std::fs::read_to_string(dir.join("journal.jsonl"))
            .unwrap()
            .ends_with('\n'));
        r.done("volume:safe:change", "changed", None).unwrap();
        drop(r);
        let r = Run::open(&dir).unwrap();
        assert!(r.is_done("volume:safe:change"));
        assert_eq!(r.entries().len(), 4);
    }

    #[test]
    fn run_folder_names() {
        assert_eq!(
            run_name_key("sealctl-unsealed-2026-11-21"),
            Some(("2026-11-21".into(), 1))
        );
        assert_eq!(
            run_name_key("sealctl-unsealed-2026-11-21-12"),
            Some(("2026-11-21".into(), 12))
        );
        for bad in [
            "sealctl-unsealed-2026-11",
            "sealctl-unsealed-2026-11-21x",
            "sealctl-unsealed-2026-11-21-",
            "sealctl-unsealed-notadate!",
            ".sealctl-unseal",
        ] {
            assert_eq!(run_name_key(bad), None, "{bad}");
        }
        // -10 sorts after -9
        let mut v = [
            run_name_key("sealctl-unsealed-2026-11-21-10").unwrap(),
            run_name_key("sealctl-unsealed-2026-11-21-9").unwrap(),
            run_name_key("sealctl-unsealed-2026-11-20").unwrap(),
        ];
        v.sort();
        assert_eq!(v.last().unwrap().1, 10);
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
