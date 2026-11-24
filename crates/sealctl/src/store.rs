//! The secret store (protocol.md, Store format): a folder named by its store id with one
//! public `.id` file and one `.sealed` file per secret. Listing needs no key.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sealctl_core::ids::IdFile;
use sealctl_core::sealed::{self, Header, Mode};
use sealctl_core::wire::{ObjectFacts, RequestItem};
use sealctl_core::ObjectKey;
use zeroize::Zeroizing;

use crate::config::Config;
use crate::exit::{self, fail};
use crate::paths;

/// One store folder.
#[derive(Debug, Clone)]
pub struct Store {
    /// The folder.
    pub dir: PathBuf,
    /// The store id (the folder name).
    pub id: String,
}

/// A secret as listed.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Listed {
    /// Its name.
    pub name: String,
    /// Own approval (mode 2).
    pub own: bool,
    /// Words fingerprint in its header.
    pub words: String,
    /// Last modified, RFC 3339.
    pub modified: String,
}

/// Validates a secret name (exit 2).
pub fn check_name(name: &str) -> Result<()> {
    if !sealed::is_valid_name(name) {
        return Err(fail(
            exit::USAGE,
            format!("{name:?} is not a secret name: segments of A-Z a-z 0-9 - _ . @ + separated by /, not starting with a dot."),
        ));
    }
    Ok(())
}

fn rfc3339(t: std::time::SystemTime) -> String {
    crate::clock::local_rfc3339(crate::clock::from_system(t))
}

impl Store {
    /// The store this machine uses (`config.toml` `store`).
    pub fn configured() -> Result<Store> {
        let mut cfg = Config::load()?;
        let dir = match cfg.store_path()? {
            Some(d) => d,
            // a paired machine without a store (handed back with `unseal secrets`): a new one,
            // whose key the next `open` asks for
            None if crate::machine::is_paired() => {
                let id = crate::util::new_uuid()?;
                let root = paths::store_root()?;
                paths::ensure_private_dir(&root)?;
                let d = root.join(id);
                paths::ensure_private_dir(&d)?;
                cfg.store = Some(paths::tilde(&d));
                cfg.save()?;
                d
            }
            None => return Err(fail(exit::NOT_FOUND, "No secret store yet. Run: sealctl pair")),
        };
        Store::at(&dir)
    }

    /// The store in `dir` (named by its id).
    pub fn at(dir: &Path) -> Result<Store> {
        let id = dir
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if sealctl_core::ids::parse_uuid(&id).is_none() {
            return Err(fail(
                exit::NOT_FOUND,
                format!(
                    "{} is not a store folder (its name must be the store id).",
                    dir.display()
                ),
            ));
        }
        Ok(Store {
            dir: dir.to_path_buf(),
            id,
        })
    }

    /// `<store-id>.id`.
    pub fn id_path(&self) -> PathBuf {
        self.dir.join(format!("{}.id", self.id))
    }

    /// The `.id` file, if written yet.
    pub fn id_file(&self) -> Result<Option<IdFile>> {
        match std::fs::read_to_string(self.id_path()) {
            Ok(t) => {
                match IdFile::parse(&t).map_err(|e| anyhow::anyhow!("{}: {e}", self.id_path().display()))? {
                    f if f.kind == "store" && f.id == self.id => Ok(Some(f)),
                    _ => Err(fail(
                        exit::WRONG_KEY,
                        format!("{} does not describe this store.", self.id_path().display()),
                    )),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Writes the `.id` file (last, when a store is made).
    pub fn write_id(&self, file: &IdFile) -> Result<()> {
        paths::ensure_private_dir(&self.dir)?;
        paths::write_private(&self.id_path(), file.to_json().as_bytes())
    }

    /// A new `.id` file for this store.
    pub fn new_id_file(&self, words: &str, key: &ObjectKey) -> IdFile {
        IdFile {
            sealctl: 1,
            kind: "store".into(),
            id: self.id.clone(),
            words: words.into(),
            check: key.check(),
            created: crate::clock::utc_rfc3339(jiff::Timestamp::now()),
            format: Some("sealed-v1".into()),
            own: None,
            volume: None,
        }
    }

    /// The `keys` item for the store key: with `w` and `c` once the `.id` file exists.
    pub fn request_item(&self) -> Result<RequestItem> {
        let id = self.id_file()?;
        Ok(RequestItem {
            purpose: "secrets".into(),
            id: self.id.clone(),
            words: id.as_ref().map(|f| f.words.clone()),
            check: id.as_ref().map(|f| f.check.clone()),
            object: Some(ObjectFacts {
                kind: "store".into(),
                path: paths::tilde(&self.dir),
                size: self.size(),
            }),
        })
    }

    fn size(&self) -> u64 {
        self.walk()
            .iter()
            .filter_map(|p| p.metadata().ok())
            .map(|m| m.len())
            .sum()
    }

    fn walk(&self) -> Vec<PathBuf> {
        const MAX_DEPTH: usize = 64;
        fn go(dir: &Path, depth: usize, out: &mut Vec<PathBuf>) {
            let Ok(rd) = std::fs::read_dir(dir) else { return };
            for e in rd.flatten() {
                let p = e.path();
                let n = e.file_name();
                if n.to_string_lossy().starts_with('.') {
                    continue;
                }
                // a symlink is never followed into a folder, so a symlink loop cannot make the
                // walk grow; a symlink to a sealed file still counts
                let Ok(ft) = e.file_type() else { continue };
                if ft.is_dir() {
                    if depth > 0 {
                        go(&p, depth - 1, out);
                    }
                } else if ft.is_symlink() && p.is_dir() {
                    continue;
                } else if p.extension().is_some_and(|x| x == "sealed") {
                    out.push(p);
                }
            }
        }
        // as deep as a valid name goes (`a/b/…`: 64 segments in 128 bytes), and no deeper
        let mut out = Vec::new();
        go(&self.dir, MAX_DEPTH, &mut out);
        out
    }

    /// The file of a secret.
    pub fn path_of(&self, name: &str) -> PathBuf {
        self.dir.join(format!("{name}.sealed"))
    }

    /// Does the secret exist?
    pub fn exists(&self, name: &str) -> bool {
        self.path_of(name).is_file()
    }

    /// Every secret, sorted by name. Needs no key.
    pub fn list(&self) -> Result<Vec<Listed>> {
        let mut out = Vec::new();
        for p in self.walk() {
            let Ok(rel) = p.strip_prefix(&self.dir) else {
                continue;
            };
            let rel = rel.to_string_lossy();
            let Some(name) = rel.strip_suffix(".sealed") else {
                continue;
            };
            let name = name.to_string();
            if !sealed::is_valid_name(&name) {
                continue;
            }
            let bytes = match std::fs::read(&p) {
                Ok(b) => b,
                Err(_) => continue,
            };
            let Ok(h) = Header::parse(&bytes) else { continue };
            let modified = p
                .metadata()
                .and_then(|m| m.modified())
                .map(rfc3339)
                .unwrap_or_default();
            out.push(Listed {
                name,
                own: h.mode == Mode::OwnApproval,
                words: h.words,
                modified,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    /// The header of a secret (exit 9 when missing).
    pub fn header(&self, name: &str) -> Result<Header> {
        let bytes = self.read_file(name)?;
        Header::parse(&bytes).map_err(|_| fail(exit::ERROR, format!("{name} is damaged.")))
    }

    fn read_file(&self, name: &str) -> Result<Vec<u8>> {
        check_name(name)?;
        std::fs::read(self.path_of(name)).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => fail(exit::NOT_FOUND, format!("No secret {name}.")),
            _ => anyhow::Error::new(e).context(format!("reading {name}")),
        })
    }

    /// Opens a secret with the store key (mode 1) or its own-approval key (mode 2).
    pub fn read(&self, name: &str, key: &ObjectKey) -> Result<Zeroizing<Vec<u8>>> {
        let bytes = self.read_file(name)?;
        sealed::open(&bytes, key, &self.id, name)
            .map_err(|_| fail(exit::WRONG_KEY, format!("{name} does not open with this key.")))
    }

    /// The lock between writers and a move to new words: `<state>/locks/store-<id>.lock`, on
    /// this machine (the store folder may be synced, or on a file system without locks; the
    /// writers and the rewrap are both on this machine). Writers through the daemon hold it
    /// shared around the write itself, after any phone answer, and never wait; `migrate`'s
    /// rewrap holds it exclusive from the listing of the files to the new `.id`.
    fn lock_file(&self) -> String {
        format!("store-{}.lock", self.id)
    }

    /// The writers' side of the store lock: shared, refused while a rewrap runs (exit 11).
    pub fn lock_writes(&self) -> Result<StoreLock> {
        crate::util::lock_named(
            &self.lock_file(),
            crate::util::LockHow::Shared,
            &|| "The secret store is moving to a new seed (sealctl migrate). Try again once it ends.".into(),
            &mut || {},
        )
    }

    /// The rewrap's side of the store lock: exclusive, waiting up to a minute for the writes
    /// under way (each one is a single file).
    pub fn lock_rewrap(&self) -> Result<StoreLock> {
        crate::util::lock_named(
            &self.lock_file(),
            crate::util::LockHow::ExclusiveWait(std::time::Duration::from_secs(60)),
            &|| "The secret store is still being written to after a minute. Run it again.".into(),
            &mut || eprintln!("Waiting for a secret write to finish..."),
        )
    }

    /// Writes a secret. A replaced value keeps its file id; a new one gets a new id. A value
    /// under the store key is written only with the key the `.id` file names: a session that
    /// opened before the store moved to new words holds the old key, and a value sealed with it
    /// would open with neither the store's key nor the words the file says.
    pub fn write(
        &self,
        name: &str,
        mode: Mode,
        key: &ObjectKey,
        words: &str,
        value: &[u8],
        file_id: Option<&str>,
    ) -> Result<()> {
        if mode == Mode::StoreKey {
            if let Some(f) = self.id_file()? {
                if f.check != key.check() {
                    return Err(fail(
                        exit::WRONG_KEY,
                        "The secret store moved to a new seed since this session opened. Lock \
                         (sealctl lock) and try again.",
                    ));
                }
            }
        }
        self.write_moved(name, mode, key, words, value, file_id)
    }

    /// [`Store::write`] without the `.id` check: the rewrap, writing the new key's files before
    /// the `.id` names it.
    pub fn write_moved(
        &self,
        name: &str,
        mode: Mode,
        key: &ObjectKey,
        words: &str,
        value: &[u8],
        file_id: Option<&str>,
    ) -> Result<()> {
        check_name(name)?;
        let file_id = match file_id {
            Some(f) => f.to_string(),
            None => match self.header(name) {
                Ok(h) if h.mode == mode => h.file_id,
                _ => sealctl_core::ids::new_uuid().map_err(|e| anyhow::anyhow!("{e}"))?,
            },
        };
        // `seal` draws a new nonce for every write; the file id (and so the file key) is kept
        let label = sealed::Label {
            mode,
            words: words.to_owned(),
            file_id,
        };
        let bytes = sealed::seal(&label, key, &self.id, name, value).map_err(|e| match e {
            sealctl_core::CoreError::TooLarge => fail(exit::USAGE, "A secret is 1 to 65,536 bytes."),
            e => anyhow::anyhow!("sealing {name}: {e}"),
        })?;
        let path = self.path_of(name);
        let mut dir = path.parent().context("folder")?.to_path_buf();
        // folders 0700 down from the store folder
        let mut made = Vec::new();
        while !dir.exists() && dir.starts_with(&self.dir) {
            made.push(dir.clone());
            dir = dir.parent().context("folder")?.to_path_buf();
        }
        for d in made.iter().rev() {
            paths::ensure_private_dir(d)?;
        }
        paths::write_private(&path, &bytes)
    }

    /// Removes a secret and folders that became empty.
    pub fn remove(&self, name: &str) -> Result<()> {
        check_name(name)?;
        let p = self.path_of(name);
        std::fs::remove_file(&p).map_err(|e| match e.kind() {
            std::io::ErrorKind::NotFound => fail(exit::NOT_FOUND, format!("No secret {name}.")),
            _ => e.into(),
        })?;
        let mut d = p.parent().map(Path::to_path_buf);
        while let Some(dir) = d {
            if dir == self.dir || std::fs::remove_dir(&dir).is_err() {
                break;
            }
            d = dir.parent().map(Path::to_path_buf);
        }
        Ok(())
    }

    /// Own-approval checks from the `.id` file.
    pub fn own_checks(&self) -> Result<BTreeMap<String, String>> {
        Ok(self.id_file()?.and_then(|f| f.own).unwrap_or_default())
    }

    /// Adds an own-approval check to the `.id` file.
    pub fn add_own_check(&self, file_id: &str, check: &str) -> Result<()> {
        let Some(mut f) = self.id_file()? else {
            return Err(fail(exit::ERROR, "The store has no .id file yet."));
        };
        f.own
            .get_or_insert_with(BTreeMap::new)
            .insert(file_id.into(), check.into());
        self.write_id(&f)
    }
}

/// A held [`Store::lock_writes`] or [`Store::lock_rewrap`]; released when dropped.
pub type StoreLock = crate::util::ObjectLock;

/// The `keys` item of an own-approval secret.
pub fn own_item(store: &Store, header: &Header) -> Result<RequestItem> {
    let checks = store.own_checks()?;
    Ok(RequestItem {
        purpose: "secret".into(),
        id: header.file_id.clone(),
        words: Some(header.words.clone()),
        check: checks.get(&header.file_id).cloned(),
        object: Some(ObjectFacts {
            kind: "secret".into(),
            path: paths::tilde(&store.dir),
            size: 0,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn store(dir: &Path) -> Store {
        // an id of its own: the store lock is per id, and the tests run side by side
        let d = dir.join(crate::util::new_uuid().unwrap());
        std::fs::create_dir_all(&d).unwrap();
        Store::at(&d).unwrap()
    }

    /// A session opened before `migrate` moved the store to new words still holds the old store
    /// key: a write with it after the move is refused instead of sealing a value that neither
    /// the store's key nor the words named in the file open.
    #[test]
    fn a_write_with_the_key_from_before_a_rewrap_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let old = ObjectKey::from_bytes(&[1; 16]).unwrap();
        let new = ObjectKey::from_bytes(&[2; 16]).unwrap();
        s.write_id(&s.new_id_file("aaaa", &old)).unwrap();
        s.write("a/one", Mode::StoreKey, &old, "aaaa", b"one", None)
            .unwrap();
        crate::migrate::rewrap_one(&crate::migrate::Obj::Store(s.clone()), &old, &new, "bbbb", None).unwrap();
        assert_eq!(s.read("a/one", &new).unwrap().as_slice(), b"one");
        // the daemon's session key from before the move
        let e = s
            .write("a/two", Mode::StoreKey, &old, "bbbb", b"two", None)
            .expect_err("refused");
        assert_eq!(crate::exit::code_of(&e), exit::WRONG_KEY);
        assert!(!s.exists("a/two"));
        s.write("a/two", Mode::StoreKey, &new, "bbbb", b"two", None)
            .unwrap();
        assert_eq!(s.read("a/two", &new).unwrap().as_slice(), b"two");
    }

    /// While a rewrap holds the store, a write through the daemon is refused at once (it would
    /// carry the old key, or land after the rewrap listed the files); a rewrap waits for a write
    /// under way; after it, writes go on.
    #[test]
    fn writes_wait_out_a_rewrap() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let held = s.lock_rewrap().unwrap();
        let e = s.lock_writes().err().expect("busy");
        assert_eq!(crate::exit::code_of(&e), exit::BUSY);
        drop(held);
        let w1 = s.lock_writes().unwrap();
        let w2 = s.lock_writes().unwrap();
        let s2 = s.clone();
        let rewrap = std::thread::spawn(move || s2.lock_rewrap().map(drop));
        std::thread::sleep(std::time::Duration::from_millis(300));
        assert!(!rewrap.is_finished(), "the rewrap waits for the writes under way");
        drop(w1);
        drop(w2);
        rewrap.join().unwrap().unwrap();
        // the lock lives with this machine's state, never in the (maybe synced) store folder
        assert!(!s.dir.join(".sealctl-write.lock").exists());
        assert!(std::fs::read_dir(&s.dir).unwrap().next().is_none());
    }

    fn names(s: &Store) -> Vec<String> {
        s.list().unwrap().into_iter().map(|l| l.name).collect()
    }

    /// Every valid name is listed: deep ones, and ones that end in `.sealed` themselves.
    #[test]
    fn list_shows_every_valid_name() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let key = ObjectKey::from_bytes(&[7; 16]).unwrap();
        let deep = (0..64)
            .map(|i| format!("{}", (b'a' + (i % 26) as u8) as char))
            .collect::<Vec<_>>()
            .join("/");
        assert!(sealed::is_valid_name(&deep));
        let wanted = [
            "a/b/c/d/e/f/g/h/i/j",
            deep.as_str(),
            "cfg/app.sealed",
            "cfg/app",
            "x.sealed.sealed",
        ];
        for n in wanted {
            s.write(n, Mode::StoreKey, &key, "4kPz", b"v", None).unwrap();
        }
        let mut want: Vec<String> = wanted.iter().map(|n| n.to_string()).collect();
        want.sort();
        assert_eq!(names(&s), want);
        for n in wanted {
            s.header(n).unwrap();
        }
    }

    /// Folder symlinks are not followed, so symlinks back into the store end the walk at once.
    #[test]
    fn list_does_not_follow_folder_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let s = store(tmp.path());
        let key = ObjectKey::from_bytes(&[7; 16]).unwrap();
        s.write("a/b", Mode::StoreKey, &key, "4kPz", b"v", None).unwrap();
        let a = s.dir.join("a");
        for l in ["l1", "l2", "l3"] {
            std::os::unix::fs::symlink(&s.dir, a.join(l)).unwrap();
        }
        assert_eq!(names(&s), ["a/b"]);
    }
}
