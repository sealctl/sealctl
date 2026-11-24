//! `sealctl seal` (SPEC 18): take over a volume, a restic backup, an SSH key, a secret or a
//! `.env` file the user already has. The new key comes from the phone at confirmation level 2
//! (`keys` with `ctx.subject` `{"k": "machine", "n": "seal"}`, `lvl` 2 and the number match),
//! or from the 24 words with `--words`. Each object is opened with the new key before the old
//! way in is removed.

pub mod handback;
pub mod journal;
pub mod store;
pub mod unseal;

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use sealctl_core::wire::{ObjectFacts, RequestItem, Subject};
use sealctl_core::{ObjectKey, Purpose};
use zeroize::Zeroizing;

use crate::approve::{self, Asked};
use crate::backup::{self, Backup, Repo};
use crate::daemon::client;
use crate::exit::{self, fail};
use crate::machine::{self, Paired};
use crate::relay::{self, Relay};
use crate::volume::{self, Kind, Volume};
use crate::{paths, term, util};

/// Sends a request from this terminal and prints the waiting line with the number.
pub fn ask_here(
    paired: &mut Paired,
    body: sealctl_core::wire::RequestBody,
    level3: bool,
) -> Result<(Asked, Option<u8>)> {
    let relay = Relay::new(&paired.file.relay)?;
    let rt = relay::runtime()?;
    let mut shown = None;
    let asked = rt.block_on(approve::send(&relay, paired, body, &mut |n| {
        shown = n;
        eprintln!("{}", term::waiting_line(n, level3));
    }))?;
    Ok((asked, shown))
}

/// A key for an object being taken over: from the phone at level 2, or from the words.
pub fn takeover_key(item: &RequestItem, words: bool) -> Result<(ObjectKey, String)> {
    if words {
        // typed once per command, wiped when it exits
        static ROOT: std::sync::Mutex<Option<sealctl_core::Root>> = std::sync::Mutex::new(None);
        let mut cached = ROOT.lock().unwrap_or_else(|e| e.into_inner());
        if cached.is_none() {
            *cached = Some(crate::recover::read_root()?);
        }
        let root = cached.as_ref().expect("root");
        let p = Purpose::parse(&item.purpose).context("purpose")?;
        let k = crate::recover::derive_checked(root, p, &item.id, None)?;
        return Ok((k, root.fingerprint()));
    }
    let mut paired = machine::load()?;
    let mut body = approve::body("keys");
    body.lvl = Some(2);
    body.has_match = true;
    body.keys = vec![item.clone()];
    let cwd = std::env::current_dir().unwrap_or_default();
    let mut ctx = approve::context(
        &paired,
        None,
        &std::env::args().skip(1).collect::<Vec<_>>().join(" "),
        &cwd,
    );
    ctx.subject = Some(Subject {
        kind: "machine".into(),
        name: "seal".into(),
    });
    body.ctx = Some(ctx);
    let (asked, number) = ask_here(&mut paired, body, false)?;
    let Asked::Reply { reply, .. } = asked else {
        return Err(fail(exit::ERROR, "The phone delayed a level 2 request."));
    };
    if !reply.ok {
        return Err(approve::refusal(&reply, number, Some("sealctl seal")));
    }
    let k = approve::keys_from(&reply, std::slice::from_ref(item))?.remove(0);
    Ok((k, reply.w.unwrap_or_default()))
}

fn old_passphrase(what: &str) -> Result<Zeroizing<String>> {
    util::read_hidden(&format!("Passphrase of {what}: "))
}

/// The UUID of an APFS volume given by UUID, disk identifier or name, in lower case.
fn uuid_of_apfs(target: &str) -> Result<String> {
    let missing = || {
        fail(
            exit::NOT_FOUND,
            format!("No APFS volume, file or folder {target}. See diskutil apfs list."),
        )
    };
    let id = if volume::apfs::looks_like_id(target) {
        target.to_string()
    } else {
        volume::apfs::uuid_by_name(target)?.ok_or_else(missing)?
    };
    let out = util::system_cmd("diskutil").args(["info", &id]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Volume UUID:")
                .map(|r| r.trim().to_lowercase())
        })
        .ok_or_else(missing)
}

/// `sealctl seal volume <name> <target>`.
pub fn seal_volume(
    name: &str,
    target: &str,
    mountpoint: Option<PathBuf>,
    manual: bool,
    words: bool,
) -> Result<()> {
    seal_volume_given(name, target, mountpoint, manual, words, None)
}

/// [`seal_volume`] with the current passphrase given (from a hand-back list).
pub fn seal_volume_given(
    name: &str,
    target: &str,
    mountpoint: Option<PathBuf>,
    manual: bool,
    words: bool,
    given: Option<Zeroizing<String>>,
) -> Result<()> {
    term::require_person("sealctl seal", None)?;
    volume::validate_name(name)?;
    let _name = volume::lock_name(name)?;
    if Volume::load(name).is_ok() {
        return Err(fail(exit::USAGE, format!("Volume {name} exists already.")));
    }
    let p = Path::new(target);
    let kind = if p.is_dir() {
        Kind::Sparsebundle
    } else if p.is_file() {
        Kind::Luks
    } else {
        Kind::Apfs
    };
    let path = (kind != Kind::Apfs)
        .then(|| std::fs::canonicalize(p))
        .transpose()?;
    // one seal (or other change) of this target at a time, from the marker read to the saved
    // definition: a second seal whose phone answers late would write its own id over the marker
    // of the first, leaving the bundle under a key its marker does not lead to
    // (an APFS volume by its UUID, as every other command locks it, whatever name it was given)
    let apfs_uuid = (kind == Kind::Apfs).then(|| uuid_of_apfs(target)).transpose()?;
    let _lock = volume::lock_target(
        kind,
        path.as_deref(),
        apfs_uuid.as_deref().unwrap_or(target),
        target,
    )?;
    // a marker with no volume of this machine on the bundle: left by a seal that stopped
    // before it finished; its id is used again if the passphrase still opens the bundle
    let mut leftover = None;
    if kind == Kind::Sparsebundle {
        if let Some(f) = volume::read_marker(kind, target)? {
            let ours = Volume::list()?.iter().any(|v| {
                v.path
                    .as_deref()
                    .zip(path.as_deref())
                    .is_some_and(|(a, b)| volume::same_path(a, b))
            });
            if ours {
                return Err(fail(
                    exit::USAGE,
                    format!("{target} is sealed already (words {}).", f.words),
                ));
            }
            leftover = Some(f);
        }
    }
    let old = match given {
        Some(p) => p,
        None => old_passphrase(target)?,
    };
    let opens = |pass: &[u8]| -> Result<bool> {
        match kind {
            Kind::Sparsebundle => volume::sparsebundle::verify(path.as_ref().expect("path"), pass),
            Kind::Apfs => volume::apfs::verify(apfs_uuid.as_deref().expect("uuid"), pass),
            Kind::Luks => volume::luks::verify(path.as_ref().expect("path"), pass),
        }
    };
    if !opens(old.as_bytes())? {
        if let Some(f) = &leftover {
            return Err(fail(
                exit::WRONG_KEY,
                format!(
                    "That passphrase does not open {target}. Check it and try again. The bundle has \
                     the marker of a seal that did not finish (words {}): if your passphrase is right, \
                     that seal changed it already, and sealctl recover opens it with those words.",
                    f.words
                ),
            ));
        }
        return Err(fail(
            exit::WRONG_KEY,
            format!("That passphrase does not open {target}."),
        ));
    }
    let id = match kind {
        Kind::Sparsebundle => match &leftover {
            Some(f) => f.id.clone(),
            None => util::new_uuid()?,
        },
        Kind::Apfs => apfs_uuid.clone().context("APFS volume UUID")?,
        Kind::Luks => {
            let out = util::system_cmd("cryptsetup")
                .arg("luksUUID")
                .arg(path.as_ref().expect("path"))
                .output()?;
            String::from_utf8_lossy(&out.stdout).trim().to_lowercase()
        }
    };
    let item = RequestItem {
        purpose: "volume".into(),
        id: id.clone(),
        words: None,
        check: None,
        object: Some(ObjectFacts {
            kind: "volume".into(),
            path: path
                .as_ref()
                .map(|p| paths::tilde(p))
                .unwrap_or_else(|| id.clone()),
            size: 0,
        }),
    };
    let (key, fp) = takeover_key(&item, words)?;
    let new = key.hex();
    let vol = Volume {
        name: name.into(),
        kind,
        path: path.clone(),
        id: id.clone(),
        words: fp.clone(),
        check: key.check(),
        mountpoint: match mountpoint {
            Some(m) => m,
            None => volume::default_mountpoint(kind, name)?,
        },
        manual,
    };
    // a sparse bundle's id is random: it is on disk before the passphrase changes, since the
    // key (from the words or the phone) cannot be found again without it
    let unmark = || {
        if let Some(p) = volume::sparsebundle::id_path(&vol) {
            let _ = std::fs::remove_file(p);
        }
    };
    if kind == Kind::Sparsebundle {
        volume::write_marker(&vol)?;
        journal::test_kill("seal-volume", "marked");
    }
    match kind {
        Kind::Sparsebundle => volume::sparsebundle::change_passphrase(
            path.as_ref().expect("path"),
            old.as_bytes(),
            new.as_bytes(),
        )
        .inspect_err(|_| {
            if opens(old.as_bytes()).unwrap_or(false) {
                unmark();
            }
        })?,
        Kind::Apfs => volume::apfs::change_passphrase(&id, old.as_bytes(), new.as_bytes())?,
        Kind::Luks => {
            let out = util::run_with_fds(
                util::system_cmd("cryptsetup")
                    .args(["luksAddKey", "--key-file", "/dev/fd/3"])
                    .arg(path.as_ref().expect("path"))
                    .arg("/dev/fd/4"),
                &[(3, old.as_bytes()), (4, new.as_bytes())],
                None,
            )?;
            util::check(out, "cryptsetup luksAddKey")?;
        }
    }
    // LUKS has slots: the user's goes only once the new key is known to open it, and once the
    // definition and marker are saved, so a stop right after never leaves a container that only
    // sealctl's key opens without sealctl knowing it
    if kind == Kind::Luks && opens(new.as_bytes())? {
        volume::write_marker(&vol)?;
        vol.save()?;
        let out = util::run_with_stdin(
            util::system_cmd("cryptsetup")
                .args(["luksRemoveKey", "--key-file=-"])
                .arg(path.as_ref().expect("path")),
            old.as_bytes(),
        )?;
        util::check(out, "cryptsetup luksRemoveKey").map_err(|e| {
            fail(
                exit::ERROR,
                format!(
                    "Volume {name} is sealed, but removing your old passphrase failed ({}); your \
                     passphrase still opens it too. Remove it with: cryptsetup luksRemoveKey {}",
                    exit::message_of(&e),
                    target
                ),
            )
        })?;
    }
    // check before the old way in is gone: the new key opens it
    if !opens(new.as_bytes())? {
        if kind != Kind::Luks {
            let back = match kind {
                Kind::Sparsebundle => volume::sparsebundle::change_passphrase(
                    path.as_ref().expect("path"),
                    new.as_bytes(),
                    old.as_bytes(),
                ),
                _ => volume::apfs::change_passphrase(&id, new.as_bytes(), old.as_bytes()),
            };
            if back.is_ok() && kind == Kind::Sparsebundle {
                unmark();
            }
        }
        return Err(fail(
            exit::ERROR,
            "The new key did not open the volume; your passphrase still does.",
        ));
    }
    volume::write_marker(&vol)?;
    vol.save()?;
    eprintln!(
        "Sealed volume {name} ({}) with words {fp}. Your old passphrase no longer opens it.",
        kind.label()
    );
    Ok(())
}

/// Validates a restic repository id taken from a URL.
pub fn repo_id_of(url: &str) -> Result<String> {
    let id = repo_id_in(url)?;
    if Backup::list()?.iter().any(|b| b.repo_id == id) {
        return Err(fail(
            exit::USAGE,
            format!("Another backup uses the repository id {id}."),
        ));
    }
    Ok(id)
}

/// The id of a restic repository, its key's derivation id: the last segment of its URL after
/// `/` or `:`. `seal backup` and `recover` both take it from here.
pub fn repo_id_in(url: &str) -> Result<String> {
    let id = url
        .trim_end_matches('/')
        .rsplit(['/', ':'])
        .next()
        .unwrap_or("")
        .to_string();
    let ok = (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'));
    if !ok {
        return Err(fail(
            exit::USAGE,
            "The repository's last path segment must be 1 to 64 of A-Z a-z 0-9 . _ -",
        ));
    }
    Ok(id)
}

/// `sealctl seal backup <name> --repo <URL>`.
pub fn seal_backup(
    name: &str,
    repo: &str,
    from: Option<&str>,
    env_pairs: &[String],
    keep_old: bool,
    words: bool,
) -> Result<()> {
    seal_backup_given(name, repo, from, env_pairs, keep_old, words, None, None)
}

/// [`seal_backup`] with the password and credentials given (from a hand-back list).
#[allow(clippy::too_many_arguments)]
pub fn seal_backup_given(
    name: &str,
    repo: &str,
    from: Option<&str>,
    env_pairs: &[String],
    keep_old: bool,
    words: bool,
    given_pw: Option<Zeroizing<String>>,
    given_env: Option<BTreeMap<String, Zeroizing<String>>>,
) -> Result<()> {
    term::require_person("sealctl seal", None)?;
    volume::validate_name(name)?;
    let _name = backup::lock_name(name)?;
    if Backup::load(name).is_ok() {
        return Err(fail(exit::USAGE, format!("Backup {name} exists already.")));
    }
    let _lock = backup::lock_repo(repo)?;
    let repo_id = repo_id_of(repo)?;
    let (source, vol) = match from {
        Some(f) => match Volume::load(f) {
            Ok(v) => (v.mountpoint.clone(), Some(v.name)),
            Err(_) => (
                std::fs::canonicalize(f)
                    .map_err(|_| fail(exit::NOT_FOUND, format!("No volume or folder {f}.")))?,
                None,
            ),
        },
        None => (PathBuf::new(), None),
    };
    let env = match given_env {
        Some(e) => e,
        None => backup::collect_env(repo, env_pairs)?,
    };
    let pw = match given_pw {
        Some(p) => p,
        None => util::read_hidden("Password of the restic repository: ")?,
    };
    let old = Repo::with_password(repo, pw.clone(), env.clone());
    if !old.opens()? {
        return Err(fail(
            exit::WRONG_KEY,
            "That password does not open the repository.",
        ));
    }
    let old_key = old
        .keys()?
        .into_iter()
        .find(|k| k.3)
        .map(|k| k.0)
        .context("restic did not mark the current key")?;
    let item = RequestItem {
        purpose: "backup".into(),
        id: repo_id.clone(),
        words: None,
        check: None,
        object: Some(ObjectFacts {
            kind: "backup".into(),
            path: repo.into(),
            size: 0,
        }),
    };
    let (key, fp) = takeover_key(&item, words)?;
    let new_id = old.key_add(key.hex().as_bytes(), "sealctl", &format!("sealctl-{fp}"))?;
    let new = Repo::new(repo, &key, env.clone());
    if !new.opens()? {
        return Err(fail(
            exit::ERROR,
            "The new key did not open the repository; your password still does.",
        ));
    }
    // credentials into the store
    for (var, v) in &env {
        client::store_set(&format!("backup/{name}/{var}"), v.as_bytes(), false, true)?;
    }
    let b = Backup {
        name: name.into(),
        source,
        volume: vol,
        repo: repo.into(),
        repo_id,
        words: fp.clone(),
        check: key.check(),
        credentials: env.keys().cloned().collect(),
        policy: Default::default(),
    };
    // the definition before the user's key goes: a stop in between leaves a repository both
    // open, never one only sealctl's key opens that sealctl does not know
    b.save()?;
    if !keep_old {
        new.key_remove(&old_key, &new_id).map_err(|e| {
            fail(
                exit::ERROR,
                format!(
                    "Backup {name} is sealed, but removing your old key failed ({}); your password \
                     still opens it too.",
                    exit::message_of(&e)
                ),
            )
        })?;
    }
    eprintln!(
        "Sealed backup {name} with words {fp}.{}",
        if keep_old {
            " Your password still opens it too."
        } else {
            " Your old password no longer opens it."
        }
    );
    Ok(())
}

/// `sealctl seal ssh <file>`.
pub fn seal_ssh(file: &Path, name: Option<String>) -> Result<()> {
    term::refuse_agent("sealctl seal")?;
    let name = name.unwrap_or_else(|| {
        file.file_name()
            .map(|n| n.to_string_lossy().trim_start_matches("id_").to_string())
            .unwrap_or_else(|| "ed25519".into())
    });
    let line = crate::ssh::import(file, &name)?;
    println!("{line}");
    eprintln!(
        "Stored as ssh/{name}. Once logins work, delete the original: rm {}",
        file.display()
    );
    Ok(())
}

/// `sealctl seal env [FILE] --prefix <p>` (also `secret import-env`).
pub fn seal_env(file: &Path, prefix: &str, delete: bool, force: bool) -> Result<()> {
    term::refuse_agent("sealctl seal")?;
    let text = Zeroizing::new(
        std::fs::read_to_string(file)
            .map_err(|_| fail(exit::NOT_FOUND, format!("Cannot read {}.", file.display())))?,
    );
    let vars = crate::dotenv::parse_dotenv(&text).map_err(|e| {
        fail(
            exit::USAGE,
            format!("{}: {e}. Nothing was stored.", file.display()),
        )
    })?;
    if vars.is_empty() {
        return Err(fail(exit::USAGE, format!("No variables in {}.", file.display())));
    }
    let store = crate::store::Store::configured()?;
    let named: Vec<(String, String)> = vars
        .keys()
        .map(|k| {
            (
                k.clone(),
                format!("{prefix}/{}", k.to_lowercase().replace('_', "-")),
            )
        })
        .collect();
    for (_, n) in &named {
        crate::store::check_name(n)?;
    }
    let existing: Vec<&str> = named
        .iter()
        .filter(|(_, n)| store.exists(n))
        .map(|(_, n)| n.as_str())
        .collect();
    if !existing.is_empty() && !force {
        return Err(fail(
            exit::USAGE,
            format!(
                "These secrets exist already: {}. Use another --prefix, or --force.",
                existing.join(", ")
            ),
        ));
    }
    for (k, n) in &named {
        if vars[k].is_empty() {
            continue;
        }
        client::store_set(n, vars[k].as_bytes(), false, true)?;
        eprintln!("  {k:<28} → {n}");
    }
    let names: Vec<String> = named
        .iter()
        .filter(|(k, _)| !vars[k].is_empty())
        .map(|(_, n)| n.clone())
        .collect();
    let back = client::values(&names, None)?;
    let by: BTreeMap<&str, &[u8]> = back.iter().map(|(n, v)| (n.as_str(), v.as_slice())).collect();
    for (k, n) in &named {
        if vars[k].is_empty() {
            continue;
        }
        if util::sha256_hex(by.get(n.as_str()).copied().unwrap_or_default())
            != util::sha256_hex(vars[k].as_bytes())
        {
            return Err(fail(
                exit::ERROR,
                format!("{k} did not read back the same. {} is kept.", file.display()),
            ));
        }
    }
    let dir = file
        .parent()
        .map(Path::to_path_buf)
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| PathBuf::from("."));
    let pfile = dir.join(crate::project::FILE);
    crate::project::update(&pfile, |project| {
        for (k, n) in &named {
            if !vars[k].is_empty() {
                project.env.insert(k.clone(), n.clone());
            }
        }
    })?;
    eprintln!(
        "{} variables stored; mapping written to {}.",
        names.len(),
        pfile.display()
    );
    // `--delete` only when every variable in the file is stored and read back, and the file
    // is still what was read: an empty value is not stored, so its line would be lost
    let empty: Vec<&str> = vars
        .iter()
        .filter(|(_, v)| v.is_empty())
        .map(|(k, _)| k.as_str())
        .collect();
    let unchanged = || {
        std::fs::read(file)
            .map(|now| util::sha256_hex(&now) == util::sha256_hex(text.as_bytes()))
            .unwrap_or(false)
    };
    if delete && !empty.is_empty() {
        eprintln!(
            "{} is kept: {} empty and not stored.",
            file.display(),
            empty.join(", ")
        );
    } else if delete && !unchanged() {
        eprintln!("{} changed while it was read; it is kept.", file.display());
    } else if delete {
        std::fs::remove_file(file)?;
        eprintln!("Removed {}.", file.display());
    } else {
        eprintln!(
            "{} still holds the values; delete it once programs work with sealctl run.",
            file.display()
        );
    }
    Ok(())
}

/// `sealctl seal --from <hand-back list>`: takes over every object of a `handback.json` written
/// by `unseal`, each with its password read from where `unseal` put it. Volumes go first, so a
/// backup can follow the volume of the same name.
pub fn seal_from(file: &Path, skip: &[String], words: bool) -> Result<()> {
    term::require_person("sealctl seal --from", None)?;
    let text = std::fs::read_to_string(file)
        .map_err(|_| fail(exit::NOT_FOUND, format!("Cannot read {}.", file.display())))?;
    let list: handback::Handback = serde_json::from_str(&text).map_err(|_| {
        fail(
            exit::USAGE,
            format!("{} is not a hand-back list.", file.display()),
        )
    })?;
    if list.sealctl != 1 || list.kind != "handback" {
        return Err(fail(
            exit::USAGE,
            format!("{} is not a hand-back list.", file.display()),
        ));
    }
    let mut objects: Vec<&handback::Object> = list
        .objects
        .iter()
        .filter(|o| !skip.iter().any(|s| s == &format!("{}/{}", o.kind, o.name)))
        .filter(|o| matches!(o.kind.as_str(), "volume" | "backup" | "ssh" | "secret"))
        .collect();
    let rank = |k: &str| match k {
        "volume" => 0,
        "backup" => 1,
        "ssh" => 2,
        _ => 3,
    };
    objects.sort_by_key(|o| rank(&o.kind));
    if objects.is_empty() {
        return Err(fail(exit::NOT_FOUND, "Nothing to take over in that list."));
    }
    eprintln!(
        "This takes over {} objects handed back by sealctl {} on {}:",
        objects.len(),
        list.from,
        list.machine
    );
    for (i, o) in objects.iter().enumerate() {
        let from = o
            .password
            .as_ref()
            .or(o.value.as_ref())
            .map(|l| l.describe())
            .unwrap_or_else(|| "no password".into());
        eprintln!("{:>2}  {:<8} {:<28} password from {from}", i + 1, o.kind, o.name);
    }
    eprintln!("Each one asks your phone (or uses your words with --words).");
    if term::ask_line("Type seal to start: ")? != "seal" {
        return Err(fail(exit::USAGE, "Not started. Nothing was changed."));
    }
    let mut stores = store::Stores::new(store::Config {
        to: store::StoreKind::Folder,
        secrets_to: store::StoreKind::Folder,
        env_file: None,
        op_vault: None,
        bw_folder: None,
        type_passwords: false,
    });
    stores.folder = file.parent().map(Path::to_path_buf);
    let mut failed = Vec::new();
    let total = objects.len();
    for (i, o) in objects.iter().enumerate() {
        let r = seal_one(&mut stores, o, words);
        match r {
            Ok(note) => eprintln!("[{}/{total}] {} {}: {note}", i + 1, o.kind, o.name),
            Err(e) => {
                eprintln!(
                    "[{}/{total}] {} {}: {}",
                    i + 1,
                    o.kind,
                    o.name,
                    exit::message_of(&e)
                );
                failed.push(format!("{}/{}", o.kind, o.name));
            }
        }
    }
    if !failed.is_empty() {
        return Err(fail(
            exit::PARTWAY,
            format!(
                "Not taken over: {}. Fix them and run again with --skip for the ones done, or seal them one by one.",
                failed.join(", ")
            ),
        ));
    }
    eprintln!("Done. sealctl holds these objects now; the passwords in the list no longer open them.");
    Ok(())
}

fn text_of(v: Zeroizing<Vec<u8>>) -> Zeroizing<String> {
    Zeroizing::new(String::from_utf8_lossy(&v).into_owned())
}

fn seal_one(stores: &mut store::Stores, o: &handback::Object, words: bool) -> Result<String> {
    let password = |stores: &mut store::Stores| -> Result<Zeroizing<String>> {
        let loc = o
            .password
            .as_ref()
            .ok_or_else(|| fail(exit::NOT_FOUND, "The list says nothing about its password."))?;
        Ok(text_of(stores.read(loc)?))
    };
    match o.kind.as_str() {
        "volume" => {
            let target = match o.volume.as_deref() {
                Some("apfs") | Some("apfs-volume") => o.uuid.clone(),
                _ => o
                    .path
                    .as_deref()
                    .map(|p| paths::expand(p).map(|x| x.display().to_string()))
                    .transpose()?,
            }
            .ok_or_else(|| fail(exit::NOT_FOUND, "The list has no path or UUID for it."))?;
            let pw = password(stores)?;
            seal_volume_given(&o.name, &target, None, false, words, Some(pw))?;
            Ok("sealed.".into())
        }
        "backup" => {
            let url = o
                .url
                .clone()
                .ok_or_else(|| fail(exit::NOT_FOUND, "The list has no repository URL."))?;
            let pw = password(stores)?;
            let mut env = BTreeMap::new();
            for c in &o.credentials {
                env.insert(c.var.clone(), text_of(stores.read(&c.location)?));
            }
            // a backup named like a volume backs up that volume again
            let from = Volume::load(&o.name).ok().map(|v| v.name);
            let name = if Backup::load(&o.name).is_ok() {
                format!("{}-backup", o.name)
            } else {
                o.name.clone()
            };
            seal_backup_given(
                &name,
                &url,
                from.as_deref(),
                &[],
                false,
                words,
                Some(pw),
                Some(env),
            )?;
            Ok(format!("sealed as backup {name}."))
        }
        "ssh" => {
            let path = paths::expand(
                o.path
                    .as_deref()
                    .ok_or_else(|| fail(exit::NOT_FOUND, "The list has no key file."))?,
            )?;
            let pass = match &o.password {
                Some(l) => Some(stores.read(l)?),
                None => None,
            };
            crate::ssh::import_given(&path, &o.name, pass.as_deref().map(|v| v.as_slice()))?;
            Ok(format!(
                "stored as ssh/{}. Once logins work, delete the original: rm {}",
                o.name,
                path.display()
            ))
        }
        "secret" => {
            let loc = o
                .value
                .as_ref()
                .ok_or_else(|| fail(exit::NOT_FOUND, "The list says nothing about its value."))?;
            let v = stores.read(loc)?;
            crate::store::check_name(&o.name)?;
            client::store_set(&o.name, &v, false, true)?;
            let back = client::values(std::slice::from_ref(&o.name), Some(("secret", &o.name)))?;
            if util::sha256_hex(&back[0].1) != util::sha256_hex(&v) {
                return Err(fail(exit::ERROR, "It did not read back the same."));
            }
            Ok("stored, read back.".into())
        }
        other => Err(fail(exit::USAGE, format!("Unknown kind {other}."))),
    }
}

#[cfg(test)]
mod tests {
    use super::repo_id_in;

    #[test]
    fn repository_ids_from_every_url_form() {
        for (url, id) in [
            ("/srv/restic/safe-backup/", "safe-backup"),
            ("rclone:gdrive:backups", "backups"),
            ("sftp:user@nas:docs", "docs"),
            ("sftp:user@nas:/srv/docs", "docs"),
            ("s3:s3.amazonaws.com/bucket/repo", "repo"),
            ("b2:bucket:repo.1", "repo.1"),
        ] {
            assert_eq!(repo_id_in(url).unwrap(), id, "{url}");
        }
        assert!(repo_id_in("rclone:remote:").is_err());
    }
}
