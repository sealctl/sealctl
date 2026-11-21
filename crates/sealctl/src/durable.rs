//! Writes that survive a power cut: data `fsync`ed (F_FULLFSYNC on Apple), files replaced by
//! a temporary file and a rename, and the directory `fsync`ed after every entry it gains, loses
//! or renames. Every durable write of sealctl goes through here.
//!
//! With the `test-hooks` feature and `SEALCTL_TEST_POWERCUT` set, a [`tracker`] records what
//! each call made durable, so a test can throw away everything else at a step boundary (see
//! [`tracker::cut`]) — the state a power cut could leave.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// `fsync` a directory, so the entries created, removed or renamed in it are on disk.
pub fn fsync_dir(dir: &Path) -> Result<()> {
    let d = File::open(dir).with_context(|| format!("opening {} to sync it", dir.display()))?;
    // std's sync_all is F_FULLFSYNC on Apple platforms, which directories accept as well
    if d.sync_all().is_err() {
        // SAFETY: fsync on a file descriptor we own.
        if unsafe { libc::fsync(std::os::unix::io::AsRawFd::as_raw_fd(&d)) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("syncing {}", dir.display()));
        }
    }
    tracker::dir_synced(dir);
    Ok(())
}

/// `fsync` the parent directory of `path`.
pub fn fsync_parent(path: &Path) -> Result<()> {
    match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => fsync_dir(d),
        _ => fsync_dir(Path::new(".")),
    }
}

/// `fsync` a file's data.
pub fn sync_file(f: &File, path: &Path) -> Result<()> {
    f.sync_all()
        .with_context(|| format!("syncing {}", path.display()))?;
    tracker::file_synced(path);
    Ok(())
}

/// The temporary file next to `p` used to replace it.
fn tmp_path(p: &Path) -> PathBuf {
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    p.with_file_name(format!(".{name}.tmp~"))
}

/// Replace `p` with `data` (mode `mode`) so that after a power cut it holds either the old or
/// the new content, never a part: write a temporary file next to it, `fsync` it, rename it
/// over `p`, `fsync` the directory.
pub fn write_atomic(p: &Path, data: &[u8], mode: u32) -> Result<()> {
    let dir = p.parent().filter(|d| !d.as_os_str().is_empty());
    if let Some(dir) = dir {
        if !dir.exists() {
            create_dir_all(dir, 0o700)?;
        }
    }
    let tmp = tmp_path(p);
    tracker::touch(&tmp);
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        // an older temporary file keeps its mode: set it
        {
            use std::os::unix::fs::PermissionsExt;
            f.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        f.write_all(data)
            .with_context(|| format!("writing {}", tmp.display()))?;
        sync_file(&f, &tmp)?;
    }
    rename(&tmp, p)?;
    Ok(())
}

/// Replace the file `path` points to (following symlinks, as dotfile setups use) with `data`,
/// keeping its mode; durable like [`write_atomic`]. A missing file is created 0600.
pub fn replace_keeping_mode(path: &Path, data: &[u8]) -> Result<()> {
    let real = fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mode = fs::metadata(&real)
        .ok()
        .map(|m| {
            use std::os::unix::fs::PermissionsExt;
            m.permissions().mode() & 0o7777
        })
        .unwrap_or(0o600);
    write_atomic(&real, data, mode)
}

/// Rename `from` to `to` and `fsync` both directories.
pub fn rename(from: &Path, to: &Path) -> Result<()> {
    tracker::touch(from);
    tracker::touch(to);
    fs::rename(from, to).with_context(|| format!("moving {} to {}", from.display(), to.display()))?;
    tracker::renamed(from, to);
    fsync_parent(to)?;
    if from.parent() != to.parent() {
        fsync_parent(from)?;
    }
    Ok(())
}

/// Create a directory and its missing parents with `mode`, `fsync`ing each parent that gained
/// an entry.
pub fn create_dir_all(dir: &Path, mode: u32) -> Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    if let Some(parent) = dir.parent().filter(|d| !d.as_os_str().is_empty()) {
        create_dir_all(parent, mode)?;
    }
    tracker::touch(dir);
    match fs::create_dir(dir) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => return Ok(()),
        Err(e) => return Err(e).with_context(|| format!("creating {}", dir.display())),
    }
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir, fs::Permissions::from_mode(mode))?;
    }
    fsync_parent(dir)
}

/// Copy a file (keeping its mode) and make the copy durable.
pub fn copy_file(src: &Path, dest: &Path) -> Result<()> {
    tracker::touch(dest);
    fs::copy(src, dest).with_context(|| format!("copying {}", src.display()))?;
    let f = File::open(dest)?;
    sync_file(&f, dest)?;
    fsync_parent(dest)
}

/// Remove a file and `fsync` its directory.
pub fn remove_file(p: &Path) -> Result<()> {
    tracker::touch(p);
    fs::remove_file(p).with_context(|| format!("removing {}", p.display()))?;
    fsync_parent(p)
}

/// Test hooks: a model of what a power cut keeps.
///
/// Every path a function of this module touches is recorded with the state it had before
/// (its *durable* state). A file's content becomes durable when it is `fsync`ed and its
/// directory entry is durable; an entry (created, renamed, removed) becomes durable when its
/// directory is `fsync`ed. [`cut`] puts every recorded path back to its durable state and
/// removes files in the run folder that no function here ever made durable, then appends half a
/// journal line (a write in flight). That is the worst a power cut may leave on a POSIX file
/// system; with sealctl's writes all made durable at once, nothing is lost at a step boundary,
/// and the report says so.
pub mod tracker {
    use std::path::Path;

    #[cfg(feature = "test-hooks")]
    pub use imp::{St, T};

    #[cfg(feature = "test-hooks")]
    mod imp {
        use std::collections::{BTreeMap, BTreeSet};
        use std::path::{Path, PathBuf};
        use std::sync::Mutex;

        #[derive(Clone, Debug, PartialEq)]
        pub enum St {
            Absent,
            File(Vec<u8>),
            Dir,
        }

        /// The model: what survives a power cut now.
        #[derive(Default)]
        pub struct T {
            /// What each touched path holds after a power cut now.
            pub durable: BTreeMap<PathBuf, St>,
            /// Content made durable by an fsync of the file (whatever its entry).
            pub synced: BTreeMap<PathBuf, Vec<u8>>,
            /// Paths whose entry changed since their directory's last fsync.
            pub pending: BTreeSet<PathBuf>,
            /// Directory renames, to undo when their entries are not durable.
            pub dir_moves: Vec<(PathBuf, PathBuf)>,
        }

        pub static GLOBAL: Mutex<Option<T>> = Mutex::new(None);

        pub fn on() -> bool {
            std::env::var_os("SEALCTL_TEST_POWERCUT").is_some_and(|v| !v.is_empty())
        }

        pub fn state(p: &Path) -> St {
            match std::fs::symlink_metadata(p) {
                Err(_) => St::Absent,
                Ok(m) if m.is_dir() => St::Dir,
                Ok(_) => St::File(std::fs::read(p).unwrap_or_default()),
            }
        }

        pub fn with(f: impl FnOnce(&mut T)) {
            if !on() {
                return;
            }
            let mut g = GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
            f(g.get_or_insert_with(T::default));
        }

        impl T {
            pub fn touch(&mut self, p: &Path) {
                if !self.durable.contains_key(p) {
                    self.durable.insert(p.to_path_buf(), state(p));
                }
                self.pending.insert(p.to_path_buf());
            }

            pub fn file_synced(&mut self, p: &Path) {
                let content = std::fs::read(p).unwrap_or_default();
                // a file not touched before was there before: its entry is durable
                if !self.durable.contains_key(p) || !self.pending.contains(p) {
                    self.durable.insert(p.to_path_buf(), St::File(content.clone()));
                }
                self.synced.insert(p.to_path_buf(), content);
            }

            pub fn renamed(&mut self, from: &Path, to: &Path) {
                // the data moves with the entry: what was synced, or what was durable before
                let c = self.synced.remove(from).or_else(|| match self.durable.get(from) {
                    Some(St::File(c)) => Some(c.clone()),
                    _ => None,
                });
                if let Some(c) = c {
                    self.synced.insert(to.to_path_buf(), c);
                }
                if to.is_dir() {
                    self.dir_moves.push((from.to_path_buf(), to.to_path_buf()));
                    // what the directory holds moved with it: as durable as its entry
                    fn walk(p: &Path, t: &mut T) {
                        let Ok(rd) = std::fs::read_dir(p) else { return };
                        for e in rd.flatten() {
                            let path = e.path();
                            if !t.durable.contains_key(&path) {
                                t.durable.insert(path.clone(), state(&path));
                            }
                            if path.is_dir() && !path.is_symlink() {
                                walk(&path, t);
                            }
                        }
                    }
                    walk(to, self);
                }
            }

            pub fn dir_synced(&mut self, dir: &Path) {
                let done: Vec<_> = self
                    .pending
                    .iter()
                    .filter(|p| p.parent() == Some(dir))
                    .cloned()
                    .collect();
                for p in done {
                    let st = match state(&p) {
                        St::Absent => St::Absent,
                        St::Dir => St::Dir,
                        St::File(_) => St::File(self.synced.get(&p).cloned().unwrap_or_default()),
                    };
                    self.durable.insert(p.clone(), st);
                    self.pending.remove(&p);
                    self.dir_moves.retain(|(f, to)| *f != p && *to != p);
                }
            }

            pub fn existing(&mut self, root: &Path) {
                let Ok(rd) = std::fs::read_dir(root) else { return };
                for e in rd.flatten() {
                    let path = e.path();
                    if !self.durable.contains_key(&path) {
                        self.durable.insert(path.clone(), state(&path));
                    }
                    if path.is_dir() && !path.is_symlink() {
                        self.existing(&path);
                    }
                }
            }

            /// Put every path back to its durable state; remove files below `run_dir` never
            /// made durable. Returns what was lost.
            pub fn cut(&mut self, run_dir: &Path) -> Vec<String> {
                let mut lost = vec![];
                let mut undone: Vec<PathBuf> = vec![];
                for (from, to) in self.dir_moves.iter().rev() {
                    if to.exists() && !from.exists() {
                        let _ = std::fs::rename(to, from);
                        lost.push(format!("moved directory {} (not synced)", to.display()));
                        undone.push(to.clone());
                    }
                }
                for (p, st) in &self.durable {
                    if *st == St::Dir || undone.iter().any(|u| p.starts_with(u)) {
                        continue;
                    }
                    if state(p) == *st {
                        continue;
                    }
                    lost.push(format!("{} (not synced)", p.display()));
                    match st {
                        St::Absent if p.is_dir() => {
                            let _ = std::fs::remove_dir_all(p);
                        }
                        St::Absent => {
                            let _ = std::fs::remove_file(p);
                        }
                        St::File(c) => {
                            let _ = std::fs::write(p, c);
                        }
                        St::Dir => {}
                    }
                }
                fn walk(p: &Path, t: &T, lost: &mut Vec<String>) {
                    let Ok(rd) = std::fs::read_dir(p) else { return };
                    for e in rd.flatten() {
                        let path = e.path();
                        if path.is_dir() && !path.is_symlink() {
                            walk(&path, t, lost);
                        } else if !t.durable.contains_key(&path) {
                            lost.push(format!("{} (never synced)", path.display()));
                            let _ = std::fs::remove_file(&path);
                        }
                    }
                }
                walk(run_dir, self, &mut lost);
                lost
            }
        }
    }

    /// Before an entry of `p` changes (created, written, renamed, removed).
    pub fn touch(p: &Path) {
        #[cfg(feature = "test-hooks")]
        imp::with(|t| t.touch(p));
        let _ = p;
    }

    /// After `p`'s data was fsynced.
    pub fn file_synced(p: &Path) {
        #[cfg(feature = "test-hooks")]
        imp::with(|t| t.file_synced(p));
        let _ = p;
    }

    /// After `from` was renamed to `to` (both touched before).
    pub fn renamed(from: &Path, to: &Path) {
        #[cfg(feature = "test-hooks")]
        imp::with(|t| t.renamed(from, to));
        let _ = (from, to);
    }

    /// After `dir` was fsynced: its changed entries are durable now.
    pub fn dir_synced(dir: &Path) {
        #[cfg(feature = "test-hooks")]
        imp::with(|t| t.dir_synced(dir));
        let _ = dir;
    }

    /// Paths below `run_dir` when the process opened it: they survived whatever came before.
    pub fn existing(run_dir: &Path) {
        #[cfg(feature = "test-hooks")]
        imp::with(|t| t.existing(run_dir));
        let _ = run_dir;
    }

    /// Throw away everything not durable (see the module text) and append half a journal line
    /// (a write in flight). Returns what was lost, one line per path (empty when everything
    /// was durable).
    pub fn cut(run_dir: &Path, journal: &Path) -> Vec<String> {
        #[allow(unused_mut)]
        let mut lost = vec![];
        #[cfg(feature = "test-hooks")]
        {
            let mut g = imp::GLOBAL.lock().unwrap_or_else(|e| e.into_inner());
            lost = g.get_or_insert_with(imp::T::default).cut(run_dir);
            if let Ok(mut f) = std::fs::OpenOptions::new().append(true).open(journal) {
                use std::io::Write;
                let _ = f.write_all(b"{\"v\":1,\"t\":\"2026-");
            }
        }
        let _ = (run_dir, journal);
        lost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_writes_keep_mode_and_leave_no_temporary_file() {
        let t = tempfile::tempdir().unwrap();
        let p = t.path().join("a/b/f.txt");
        write_atomic(&p, b"one", 0o600).unwrap();
        write_atomic(&p, b"two", 0o644).unwrap();
        assert_eq!(fs::read(&p).unwrap(), b"two");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o644);
        assert!(!tmp_path(&p).exists());
        assert_eq!(
            fs::metadata(t.path().join("a")).unwrap().permissions().mode() & 0o777,
            0o700
        );
        // through a symlink: the target is replaced, the link stays
        let target = t.path().join("real");
        fs::write(&target, "x").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o640)).unwrap();
        let link = t.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        replace_keeping_mode(&link, b"y").unwrap();
        assert!(fs::symlink_metadata(&link).unwrap().file_type().is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"y");
        assert_eq!(fs::metadata(&target).unwrap().permissions().mode() & 0o777, 0o640);
    }

    /// The power-cut model: what was not synced is lost, what was is kept.
    #[cfg(feature = "test-hooks")]
    #[test]
    fn the_power_cut_model_keeps_only_what_was_synced() {
        use tracker::T;
        let t = tempfile::tempdir().unwrap();
        let run = t.path().join("run");
        fs::create_dir(&run).unwrap();
        fs::write(run.join("old"), "old").unwrap();
        let d1 = run.join("d1");
        fs::create_dir(&d1).unwrap();
        fs::write(d1.join("f"), "f").unwrap();
        let mut m = T::default();
        m.existing(&run);
        // 1. written, synced, directory synced: kept
        let a = run.join("a");
        m.touch(&a);
        fs::write(&a, "a1").unwrap();
        m.file_synced(&a);
        m.dir_synced(&run);
        // ... then changed in place without a sync: back to a1
        fs::write(&a, "a2").unwrap();
        // 2. written and synced, directory not synced: gone
        let b = run.join("b");
        m.touch(&b);
        fs::write(&b, "b").unwrap();
        m.file_synced(&b);
        // 3. written by something that never synced: gone
        fs::write(run.join("c"), "c").unwrap();
        // 4. a replace by rename whose directory was not synced: the old content is back
        let tmp = run.join(".old.tmp~");
        m.touch(&tmp);
        fs::write(&tmp, "new").unwrap();
        m.file_synced(&tmp);
        m.touch(&run.join("old"));
        fs::rename(&tmp, run.join("old")).unwrap();
        m.renamed(&tmp, &run.join("old"));
        // 5. a directory moved without syncing: moved back
        let d2 = run.join("d2");
        m.touch(&d1);
        m.touch(&d2);
        fs::rename(&d1, &d2).unwrap();
        m.renamed(&d1, &d2);
        let lost = m.cut(&run);
        assert_eq!(fs::read_to_string(&a).unwrap(), "a1");
        assert!(!b.exists() && !run.join("c").exists() && !tmp.exists());
        assert_eq!(fs::read_to_string(run.join("old")).unwrap(), "old");
        assert!(d1.join("f").exists() && !d2.exists());
        assert!(lost.len() >= 5, "{lost:?}");
        // with every write synced and the directory synced, nothing is lost
        let mut m = T::default();
        m.existing(&run);
        m.touch(&b);
        fs::write(&b, "b").unwrap();
        m.file_synced(&b);
        m.dir_synced(&run);
        assert!(m.cut(&run).is_empty());
        assert!(b.exists());
    }
}
