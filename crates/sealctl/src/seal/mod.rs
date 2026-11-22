//! `sealctl seal` (SPEC 18): take over a volume, a restic backup, an SSH key, a secret or a
//! `.env` file the user already has. The new key comes from the phone at confirmation level 2
//! (`keys` with `ctx.subject` `{"k": "machine", "n": "seal"}`, `lvl` 2 and the number match),
//! or from the 24 words with `--words`. Each object is opened with the new key before the old
//! way in is removed.

pub mod journal;
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
        let root = crate::recover::read_root()?;
        let p = Purpose::parse(&item.purpose).context("purpose")?;
        let k = crate::recover::derive_checked(&root, p, &item.id, None)?;
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

fn uuid_of_apfs(target: &str) -> Result<String> {
    let out = util::system_cmd("diskutil").args(["info", target]).output()?;
    let text = String::from_utf8_lossy(&out.stdout);
    text.lines()
        .find_map(|l| {
            l.trim()
                .strip_prefix("Volume UUID:")
                .map(|r| r.trim().to_lowercase())
        })
        .ok_or_else(|| fail(exit::NOT_FOUND, format!("No APFS volume {target}.")))
}

/// `sealctl seal volume <name> <target>`.
pub fn seal_volume(
    name: &str,
    target: &str,
    mountpoint: Option<PathBuf>,
    manual: bool,
    words: bool,
) -> Result<()> {
    term::require_person("sealctl seal", None)?;
    volume::validate_name(name)?;
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
    if kind == Kind::Sparsebundle {
        if let Some(f) = volume::read_marker(kind, target)? {
            return Err(fail(
                exit::USAGE,
                format!("{target} is sealed already (words {}).", f.words),
            ));
        }
    }
    let old = old_passphrase(target)?;
    let opens = |pass: &[u8]| -> Result<bool> {
        match kind {
            Kind::Sparsebundle => volume::sparsebundle::verify(path.as_ref().expect("path"), pass),
            Kind::Apfs => volume::apfs::verify(target, pass),
            Kind::Luks => volume::luks::verify(path.as_ref().expect("path"), pass),
        }
    };
    if !opens(old.as_bytes())? {
        return Err(fail(
            exit::WRONG_KEY,
            format!("That passphrase does not open {target}."),
        ));
    }
    let id = match kind {
        Kind::Sparsebundle => util::new_uuid()?,
        Kind::Apfs => uuid_of_apfs(target)?,
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
    match kind {
        Kind::Sparsebundle => volume::sparsebundle::change_passphrase(
            path.as_ref().expect("path"),
            old.as_bytes(),
            new.as_bytes(),
        )?,
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
    // LUKS has slots: the user's goes only once the new key is known to open it
    if kind == Kind::Luks && opens(new.as_bytes())? {
        let out = util::run_with_stdin(
            util::system_cmd("cryptsetup")
                .args(["luksRemoveKey", "--key-file=-"])
                .arg(path.as_ref().expect("path")),
            old.as_bytes(),
        )?;
        util::check(out, "cryptsetup luksRemoveKey")?;
    }
    // check before the old way in is gone: the new key opens it
    if !opens(new.as_bytes())? {
        if kind != Kind::Luks {
            let _ = match kind {
                Kind::Sparsebundle => volume::sparsebundle::change_passphrase(
                    path.as_ref().expect("path"),
                    new.as_bytes(),
                    old.as_bytes(),
                ),
                _ => volume::apfs::change_passphrase(&id, new.as_bytes(), old.as_bytes()),
            };
        }
        return Err(fail(
            exit::ERROR,
            "The new key did not open the volume; your passphrase still does.",
        ));
    }
    let vol = Volume {
        name: name.into(),
        kind,
        path,
        id,
        words: fp.clone(),
        check: key.check(),
        mountpoint: match mountpoint {
            Some(m) => m,
            None => volume::default_mountpoint(kind, name)?,
        },
        manual,
    };
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
    if Backup::list()?.iter().any(|b| b.repo_id == id) {
        return Err(fail(
            exit::USAGE,
            format!("Another backup uses the repository id {id}."),
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
    term::require_person("sealctl seal", None)?;
    volume::validate_name(name)?;
    if Backup::load(name).is_ok() {
        return Err(fail(exit::USAGE, format!("Backup {name} exists already.")));
    }
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
    let env = backup::collect_env(repo, env_pairs)?;
    let pw = util::read_hidden("Password of the restic repository: ")?;
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
    if !keep_old {
        new.key_remove(&old_key, &new_id)?;
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
    b.save()?;
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
    let mut project = if pfile.exists() {
        crate::project::load(&pfile)?
    } else {
        crate::project::ProjectFile::default()
    };
    for (k, n) in &named {
        if !vars[k].is_empty() {
            project.env.insert(k.clone(), n.clone());
        }
    }
    std::fs::write(&pfile, toml::to_string_pretty(&project)?)?;
    eprintln!(
        "{} variables stored; mapping written to {}.",
        names.len(),
        pfile.display()
    );
    if delete {
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
