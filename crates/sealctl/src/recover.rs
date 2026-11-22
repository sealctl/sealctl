//! `sealctl recover` (SPEC 17) and the `--words` path of `seal` and `unseal`: keys from the
//! 24 words alone, with no phone, relay, pairing or config. The words are typed by a person,
//! without echo, one at a time; never accepted as an argument, from a pipe or the environment.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sealctl_core::ids::IdFile;
use sealctl_core::{complete_word, ObjectKey, Purpose, Root, Words};
use zeroize::Zeroizing;

use crate::exit::{self, fail};
use crate::{paths, term};

fn read_word(i: usize) -> Result<Zeroizing<String>> {
    let w = crate::util::read_hidden(&format!("Word {i} of 24: "))?;
    Ok(Zeroizing::new(w.trim().to_lowercase()))
}

/// Asks for the 24 words (three tries) and returns the root.
pub fn read_root() -> Result<Root> {
    term::require_person("typing the 24 words", None)?;
    for attempt in 0..3 {
        if attempt > 0 {
            eprintln!("These words do not add up (checksum). Start again from word 1.");
        }
        let mut list: Vec<String> = Vec::with_capacity(24);
        let mut i = 1;
        while i <= 24 {
            let w = read_word(i)?;
            let matches = complete_word(w.chars().take(4).collect());
            let exact = matches.iter().find(|m| **m == *w).cloned();
            let pick = match (exact, matches.len()) {
                (Some(e), _) => Some(e),
                (None, 1) if w.len() >= 4 => Some(matches[0].clone()),
                (None, 1) if w.len() >= 3 && matches[0].starts_with(w.as_str()) => Some(matches[0].clone()),
                _ => None,
            };
            match pick {
                Some(p) if p.starts_with(w.as_str()) => {
                    list.push(p);
                    i += 1;
                }
                _ => eprintln!("Not a word from the list. Type it again (the first 4 letters are enough)."),
            }
        }
        let words = Words::parse(list);
        if let Ok(w) = words {
            return Ok(Root::from_words(&w));
        }
    }
    Err(fail(
        exit::WRONG_KEY,
        "These words do not add up. Nothing was opened.",
    ))
}

/// Checks the root's fingerprint against the object's (exit 10).
pub fn check_fingerprint(root: &Root, words: &str) -> Result<()> {
    let fp = root.fingerprint();
    if fp != words {
        return Err(fail(
            exit::WRONG_KEY,
            format!("These words have fingerprint {fp}; this object was sealed with words {words}."),
        ));
    }
    Ok(())
}

/// Derives an object key and checks it against `check` (exit 10).
pub fn derive_checked(root: &Root, purpose: Purpose, id: &str, check: Option<&str>) -> Result<ObjectKey> {
    let k = ObjectKey::derive(root, purpose, id)
        .map_err(|_| fail(exit::USAGE, format!("{id} is not an object id.")))?;
    if let Some(c) = check {
        if k.check() != c {
            return Err(fail(
                exit::WRONG_KEY,
                "The key from these words does not match the object's check.",
            ));
        }
    }
    Ok(k)
}

enum Target {
    Store(PathBuf),
    Sealed(PathBuf, String),
    Bundle(PathBuf),
    Restic(String),
}

fn find_store_of(file: &Path) -> Option<(PathBuf, String)> {
    let mut d = file.parent();
    while let Some(dir) = d {
        let id = dir.file_name()?.to_string_lossy().into_owned();
        if sealctl_core::ids::parse_uuid(&id).is_some() && dir.join(format!("{id}.id")).exists() {
            let rel = file
                .strip_prefix(dir)
                .ok()?
                .to_string_lossy()
                .trim_end_matches(".sealed")
                .to_string();
            return Some((dir.to_path_buf(), rel));
        }
        d = dir.parent();
    }
    None
}

fn classify(target: &str) -> Result<Target> {
    let p = Path::new(target);
    if p.is_dir() {
        if p.join("sealctl.id").is_file() {
            return Ok(Target::Bundle(p.to_path_buf()));
        }
        let id = p
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        if p.join(format!("{id}.id")).is_file() {
            return Ok(Target::Store(p.to_path_buf()));
        }
        if p.join("config").is_file() && p.join("keys").is_dir() {
            return Ok(Target::Restic(target.to_string()));
        }
    }
    if p.is_file() && target.ends_with(".sealed") {
        let abs = std::fs::canonicalize(p)?;
        let (store, name) = find_store_of(&abs)
            .ok_or_else(|| fail(exit::NOT_FOUND, "This .sealed file is not inside a store folder."))?;
        return Ok(Target::Sealed(store, name));
    }
    if target.contains(':') && !p.exists() {
        return Ok(Target::Restic(target.to_string()));
    }
    Err(fail(
        exit::NOT_FOUND,
        format!("{target} is not a store, .sealed file, sparse bundle or restic repository."),
    ))
}

fn read_id_file(p: &Path) -> Result<IdFile> {
    let t = std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?;
    match IdFile::parse(&t) {
        Ok(f) => Ok(f),
        Err(_) => Err(fail(exit::ERROR, format!("{} is damaged.", p.display()))),
    }
}

/// The words fingerprint of a local restic repository, from its key's host `sealctl-<fp>`.
pub fn restic_words(repo: &str) -> Option<String> {
    let dir = Path::new(repo).join("keys");
    for e in std::fs::read_dir(dir).ok()?.flatten() {
        let v: serde_json::Value = serde_json::from_slice(&std::fs::read(e.path()).ok()?).ok()?;
        if let Some(h) = v["hostname"].as_str().and_then(|h| h.strip_prefix("sealctl-")) {
            return Some(h.to_string());
        }
    }
    None
}

fn write_out(dir: &Path, name: &str, value: &[u8]) -> Result<()> {
    let p = dir.join(name);
    let mut d = p.parent().map(Path::to_path_buf);
    while let Some(x) = d {
        if x.starts_with(dir) && !x.exists() {
            paths::ensure_private_dir(&x)?;
        }
        if x == dir {
            break;
        }
        d = x.parent().map(Path::to_path_buf);
    }
    paths::write_private(&p, value)
}

fn give_value(value: &[u8], show: bool) -> Result<()> {
    use std::io::Write;
    crate::guard::may_print_secret(show).map_err(|m| fail(exit::REFUSED, m))?;
    std::io::stdout().write_all(value)?;
    Ok(())
}

/// `sealctl recover <target> [--out DIR | --name N [--show]] [-- restic args]`.
pub fn recover(
    target: &str,
    out: Option<PathBuf>,
    name: Option<String>,
    show: bool,
    restic_args: Vec<String>,
) -> Result<()> {
    term::require_person("sealctl recover", None)?;
    let t = classify(target)?;
    match t {
        Target::Store(ref dir) | Target::Sealed(ref dir, _)
            if out.is_some() || name.is_some() || matches!(t, Target::Sealed(..)) =>
        {
            let store = crate::store::Store::at(dir)?;
            let idf = read_id_file(&store.id_path())?;
            let root = read_root()?;
            check_fingerprint(&root, &idf.words)?;
            let key = derive_checked(&root, Purpose::Secrets, &store.id, Some(&idf.check))?;
            let one = match &t {
                Target::Sealed(_, n) => Some(n.clone()),
                _ => name,
            };
            let open = |n: &str| -> Result<Zeroizing<Vec<u8>>> {
                let h = store.header(n)?;
                if h.mode == sealctl_core::sealed::Mode::OwnApproval {
                    let own = derive_checked(
                        &root,
                        Purpose::Secret,
                        &h.file_id,
                        idf.own
                            .as_ref()
                            .and_then(|o| o.get(&h.file_id))
                            .map(String::as_str),
                    )?;
                    store.read(n, &own)
                } else {
                    store.read(n, &key)
                }
            };
            if let Some(n) = one {
                let v = open(&n)?;
                return give_value(&v, show);
            }
            let dir_out = out.expect("checked");
            paths::ensure_private_dir(&dir_out)?;
            let list = store.list()?;
            for s in &list {
                let v = open(&s.name)?;
                write_out(&dir_out, &s.name, &v)?;
            }
            eprintln!(
                "Wrote {} secrets to {} (0600 files). Delete them when done.",
                list.len(),
                dir_out.display()
            );
            Ok(())
        }
        Target::Store(_) | Target::Sealed(..) => Err(fail(
            exit::USAGE,
            "Give --out <dir> for every secret, or --name <secret> for one.",
        )),
        Target::Bundle(b) => {
            let idf = read_id_file(&b.join("sealctl.id"))?;
            let root = read_root()?;
            check_fingerprint(&root, &idf.words)?;
            let key = derive_checked(&root, Purpose::Volume, &idf.id, Some(&idf.check))?;
            let out = crate::util::run_with_stdin(
                crate::util::system_cmd("hdiutil")
                    .args(["attach", "-stdinpass", "-owners", "on"])
                    .arg(&b),
                key.hex().as_bytes(),
            )?;
            crate::util::check(out, "hdiutil attach")?;
            let mounts = crate::volume::sparsebundle::attached_mounts(&b)?;
            let mp = mounts.into_iter().find(|m| !m.is_empty()).unwrap_or_default();
            println!("{mp}");
            eprintln!("Mounted. Eject with: diskutil eject {mp}");
            Ok(())
        }
        Target::Restic(url) => {
            let id = url
                .trim_end_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or("")
                .to_string();
            let words = restic_words(&url);
            let root = read_root()?;
            if let Some(w) = &words {
                check_fingerprint(&root, w)?;
            }
            let key = derive_checked(&root, Purpose::Backup, &id, None)?;
            let env = crate::backup::collect_env(&url, &[])?;
            let repo = crate::backup::Repo::new(&url, &key, env);
            if !repo.opens()? {
                return Err(fail(
                    exit::WRONG_KEY,
                    "The key from these words does not open this repository.",
                ));
            }
            let args: Vec<String> = if restic_args.is_empty() {
                vec!["snapshots".into()]
            } else {
                restic_args
            };
            let a: Vec<&str> = args.iter().map(String::as_str).collect();
            repo.run(&a, false)
        }
    }
}
