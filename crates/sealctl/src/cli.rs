//! Command bodies that are mostly glue: session, secrets, volumes, backups, AWS (SPEC 10).

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::path::PathBuf;

use anyhow::Result;
use serde_json::json;
use zeroize::Zeroizing;

use crate::backup::{self, Backup};
use crate::daemon::{client, session};
use crate::exit::{self, fail};
use crate::store::Store;
use crate::volume::{self, Kind, Volume};
use crate::{licence, paths, status, term, util};

// ---------- session ----------

/// `sealctl open`.
pub fn open() -> Result<()> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let a = client::call(json!({"op": "open", "cwd": cwd.display().to_string(), "cmd": "sealctl open"}))?;
    if a["once"] == json!(true) {
        println!("Approved once; the session stays Locked.");
    } else {
        println!(
            "Open · {} left",
            session::duration(a["left"].as_u64().unwrap_or(0))
        );
    }
    Ok(())
}

/// `sealctl lock`.
pub fn lock(force: bool, no_backup: bool) -> Result<i32> {
    let running = client::status_if_running().is_some() || client::no_daemon();
    let mut code = 0;
    if running {
        let a = client::call(json!({"op": "lock", "force": force, "noBackup": no_backup}))?;
        println!("Locked.");
        for l in a["lines"].as_array().cloned().unwrap_or_default() {
            println!("{}", l.as_str().unwrap_or(""));
        }
        if a["busy"].as_u64().unwrap_or(0) > 0 {
            code = exit::BUSY;
        }
    } else {
        // no daemon: close what is open anyway
        for v in Volume::list()? {
            if !v.manual && v.is_open() {
                match volume::close(&v, force) {
                    Ok(()) => println!("Volume {} closed.", v.name),
                    Err(e) => {
                        eprintln!("sealctl: {}", exit::message_of(&e));
                        code = exit::BUSY;
                    }
                }
            }
        }
        println!("Locked.");
    }
    Ok(code)
}

// ---------- secrets ----------

fn read_value(from_clipboard: bool, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::IsTerminal;
    if from_clipboard {
        return util::take_clipboard();
    }
    if !std::io::stdin().is_terminal() {
        let mut v = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut v)?;
        if v.last() == Some(&b'\n') {
            v.pop();
            if v.last() == Some(&b'\r') {
                v.pop();
            }
        }
        return Ok(v);
    }
    if crate::guard::ai_agent().is_some() || !std::io::stderr().is_terminal() {
        return Err(fail(
            exit::REFUSED,
            "No value: use --from-clipboard, or pipe it in.",
        ));
    }
    let v = util::read_hidden(&format!("Value of {name} (hidden): "))?;
    Ok(Zeroizing::new(v.as_bytes().to_vec()))
}

/// `sealctl secret set`.
pub fn secret_set(name: &str, force: bool, from_clipboard: bool, own: bool) -> Result<()> {
    crate::store::check_name(name)?;
    let store = Store::configured()?;
    if store.exists(name) && !force {
        return Err(fail(
            exit::USAGE,
            format!("{name} exists. Use --force to replace it."),
        ));
    }
    let v = read_value(from_clipboard, name)?;
    if v.is_empty() {
        return Err(fail(exit::USAGE, "The value is empty."));
    }
    client::store_set(name, &v, own, force)?;
    if own {
        eprintln!("Stored {name} (asks your phone on every use)");
    } else {
        eprintln!("Stored {name}");
    }
    Ok(())
}

/// `sealctl secret get`.
pub fn secret_get(name: &str, clip: bool, show: bool) -> Result<()> {
    term::refuse_agent("sealctl secret get")?;
    crate::store::check_name(name)?;
    if !clip {
        crate::guard::may_print_secret(show).map_err(|m| fail(exit::REFUSED, m))?;
    }
    let vals = client::values(&[name.to_string()], Some(("secret", name)))?;
    let v = &vals[0].1;
    if clip {
        let text = Zeroizing::new(String::from_utf8_lossy(v).into_owned());
        util::copy_to_clipboard_with_clear(&text, 30)?;
        eprintln!("Copied {name}; the clipboard is cleared in 30 s.");
        return Ok(());
    }
    use std::io::IsTerminal;
    let mut out = std::io::stdout().lock();
    out.write_all(v)?;
    if std::io::stdout().is_terminal() {
        out.write_all(b"\n")?;
    } else {
        status::count_given_out();
    }
    Ok(())
}

/// `sealctl secret ls`.
pub fn secret_ls(json_out: bool) -> Result<()> {
    let store = Store::configured()?;
    let list = store.list()?;
    if json_out {
        println!("{}", json!({"store": store.id, "secrets": list}));
        return Ok(());
    }
    for s in &list {
        if s.own {
            println!("{}  own approval", s.name);
        } else {
            println!("{}", s.name);
        }
    }
    if let Ok(p) = crate::machine::load() {
        let _ = licence::refreshed(&p, std::time::Duration::from_secs(2));
    }
    licence::maybe_ask();
    Ok(())
}

/// `sealctl secret rm`.
pub fn secret_rm(name: &str, yes: bool) -> Result<()> {
    let store = Store::configured()?;
    if !store.exists(name) {
        return Err(fail(exit::NOT_FOUND, format!("No secret {name}.")));
    }
    if !yes {
        if !term::is_person() {
            return Err(fail(exit::REFUSED, "Removing needs a terminal. Use --yes."));
        }
        if !term::confirm(&format!("Remove {name}?"), false)? {
            return Ok(());
        }
    }
    store.remove(name)?;
    eprintln!("Removed {name}");
    Ok(())
}

/// `sealctl secret store [--use <folder>]`.
pub fn secret_store(use_dir: Option<PathBuf>, json_out: bool) -> Result<()> {
    if let Some(d) = use_dir {
        let d = std::fs::canonicalize(&d)
            .map_err(|_| fail(exit::NOT_FOUND, format!("No folder {}.", d.display())))?;
        let s = Store::at(&d)?;
        if s.id_file()?.is_none() {
            return Err(fail(
                exit::NOT_FOUND,
                format!("{} has no {}.id file.", d.display(), s.id),
            ));
        }
        let mut cfg = crate::config::Config::load()?;
        cfg.store = Some(paths::tilde(&d));
        cfg.save()?;
        client::stop_running();
        eprintln!("This machine now uses the store in {}.", paths::tilde(&d));
    }
    let s = Store::configured()?;
    let f = s.id_file()?;
    if json_out {
        println!(
            "{}",
            json!({"id": s.id, "path": s.dir, "words": f.as_ref().map(|f| f.words.clone())})
        );
    } else {
        println!("{}", paths::tilde(&s.dir));
        println!("{}", s.id);
    }
    Ok(())
}

// ---------- volumes ----------

/// `sealctl volume create`.
pub fn volume_create(opts: volume::CreateOpts) -> Result<()> {
    let name = opts.name.clone();
    let vol = volume::create(opts, &mut |item| client::new_key(item, ("volume", &name)))?;
    eprintln!("Volume {} ({}) created and mounted.", vol.name, vol.kind.label());
    println!("{}", vol.mountpoint.display());
    Ok(())
}

/// `sealctl volume ls`.
pub fn volume_ls(json_out: bool) -> Result<()> {
    let vols = Volume::list()?;
    if json_out {
        let v: Vec<_> = vols
            .iter()
            .map(|v| json!({"name": v.name, "kind": v.kind.as_str(), "open": v.is_open(), "mountpoint": v.mountpoint, "words": v.words, "manual": v.manual}))
            .collect();
        println!("{}", json!({"volumes": v}));
        return Ok(());
    }
    for v in vols {
        println!(
            "{:<16} {:<14} {:<7} {}  words {}",
            v.name,
            v.kind.label(),
            if v.is_open() { "Open" } else { "closed" },
            v.mountpoint.display(),
            v.words
        );
    }
    Ok(())
}

/// `sealctl volume open`.
pub fn volume_open(name: &str) -> Result<()> {
    let vol = Volume::load(name)?;
    if vol.is_open() {
        println!("{}", vol.mountpoint.display());
        return Ok(());
    }
    let (keys, _) = client::keys(&[vol.request_item()], Some(("volume", name)))?;
    volume::open_with(&vol, &keys[0], Some(std::time::Duration::from_secs(60)))?;
    println!("{}", vol.mountpoint.display());
    Ok(())
}

/// `sealctl volume close`.
pub fn volume_close(name: &str, force: bool) -> Result<()> {
    let vol = Volume::load(name)?;
    volume::close(&vol, force)?;
    eprintln!("Volume {name} closed.");
    Ok(())
}

/// `sealctl volume import`: registers a volume sealed with these words, or seals one.
pub fn volume_import(
    name: &str,
    target: &str,
    kind: Option<Kind>,
    mountpoint: Option<PathBuf>,
) -> Result<()> {
    let k = kind.unwrap_or(if std::path::Path::new(target).is_dir() {
        Kind::Sparsebundle
    } else {
        Kind::default_for_os()
    });
    if let Some(f) = volume::read_marker(k, target)? {
        volume::validate_name(name)?;
        let path = std::fs::canonicalize(target)?;
        let vol = Volume {
            name: name.into(),
            kind: k,
            path: Some(path),
            id: f.id,
            words: f.words,
            check: f.check,
            mountpoint: match mountpoint {
                Some(m) => m,
                None => volume::default_mountpoint(k, name)?,
            },
            manual: false,
        };
        vol.save()?;
        eprintln!(
            "Registered volume {name} (words {}). Open it with: sealctl volume open {name}",
            vol.words
        );
        return Ok(());
    }
    crate::seal::seal_volume(name, target, mountpoint, false, false)
}

/// `sealctl volume rm`.
pub fn volume_rm(name: &str, delete_data: bool) -> Result<()> {
    if delete_data {
        term::require_person("deleting a volume", None)?;
        let typed = term::ask_line(&format!(
            "This destroys the data of {name}. Type its name to go on: "
        ))?;
        if typed != name {
            return Err(fail(exit::USAGE, "Not deleted."));
        }
    }
    volume::remove(name, delete_data)?;
    eprintln!("Forgot volume {name}.");
    Ok(())
}

// ---------- backups ----------

/// `sealctl backup init`.
pub fn backup_init(name: &str, from: &str, repo: &str, env_pairs: &[String]) -> Result<()> {
    let env = backup::collect_env(repo, env_pairs)?;
    for (var, v) in &env {
        crate::store::check_name(&format!("backup/{name}/{var}"))?;
        let _ = v;
    }
    let (b, _) = backup::init(
        backup::InitOpts {
            name,
            from,
            repo_base: repo,
            env: env.clone(),
        },
        &mut |item| client::new_key(item, ("backup", name)),
    )?;
    for (var, v) in &env {
        client::store_set(&format!("backup/{name}/{var}"), v.as_bytes(), false, true)?;
    }
    eprintln!("Backup {name}: {} → {}", b.source.display(), b.repo);
    Ok(())
}

fn backup_material(b: &Backup) -> Result<(sealctl_core::ObjectKey, BTreeMap<String, Zeroizing<String>>)> {
    let (mut keys, _) = client::keys(&[b.request_item()], Some(("backup", &b.name)))?;
    let mut env = BTreeMap::new();
    let names = b.credential_names();
    if !names.is_empty() {
        for ((_, v), var) in client::values(&names, Some(("backup", &b.name)))?
            .into_iter()
            .zip(&b.credentials)
        {
            env.insert(
                var.clone(),
                Zeroizing::new(String::from_utf8_lossy(&v).into_owned()),
            );
        }
    }
    Ok((keys.remove(0), env))
}

/// `sealctl backup run`.
pub fn backup_run(names: &[String], all: bool, if_open: bool, quiet: bool) -> Result<()> {
    if if_open {
        let open = client::status_if_running().is_some_and(|s| s["open"] == json!(true));
        if !open {
            return Ok(());
        }
    }
    let list: Vec<Backup> = if all || names.is_empty() {
        Backup::list()?
            .into_iter()
            .filter(|b| !all || b.policy.scheduled)
            .collect()
    } else {
        names.iter().map(|n| Backup::load(n)).collect::<Result<_>>()?
    };
    let mut failed = Vec::new();
    let mut all_busy = true;
    for b in list {
        let (key, env) = backup_material(&b)?;
        match backup::run_one(&b, &key, env, quiet) {
            Err(e) => {
                eprintln!("sealctl: backup {} failed: {}", b.name, exit::message_of(&e));
                all_busy &= exit::code_of(&e) == exit::BUSY;
                failed.push(b.name.clone());
            }
            Ok(Some(warning)) => eprintln!("Backed up {} ({warning}).", b.name),
            Ok(None) if !quiet => eprintln!("Backed up {}.", b.name),
            Ok(None) => {}
        }
    }
    if !failed.is_empty() {
        // busy (another sealctl command has the repository) when that is the only reason
        return Err(fail(
            if all_busy { exit::BUSY } else { exit::ERROR },
            format!("Backups failed: {}", failed.join(", ")),
        ));
    }
    Ok(())
}

/// `sealctl backup snapshots|restore|check`.
pub fn backup_restic(name: &str, args: &[&str]) -> Result<()> {
    let b = Backup::load(name)?;
    let (key, env) = backup_material(&b)?;
    let repo = backup::Repo::new(&b.repo, &key, env);
    repo.run(args, false)
}

/// `sealctl backup policy`.
pub fn backup_policy(
    name: &str,
    on_lock: Option<bool>,
    scheduled: Option<bool>,
    d: Option<u32>,
    w: Option<u32>,
    m: Option<u32>,
) -> Result<()> {
    let mut b = Backup::load(name)?;
    if let Some(x) = on_lock {
        b.policy.on_lock = x;
    }
    if let Some(x) = scheduled {
        b.policy.scheduled = x;
    }
    if let Some(x) = d {
        b.policy.keep_daily = x;
    }
    if let Some(x) = w {
        b.policy.keep_weekly = x;
    }
    if let Some(x) = m {
        b.policy.keep_monthly = x;
    }
    b.save()?;
    eprintln!(
        "{name}: on lock {}, scheduled {}, keep {} daily, {} weekly, {} monthly",
        b.policy.on_lock,
        b.policy.scheduled,
        b.policy.keep_daily,
        b.policy.keep_weekly,
        b.policy.keep_monthly
    );
    Ok(())
}

// ---------- AWS ----------

/// `sealctl aws credentials --profile <p>`: `credential_process` output from `aws/<p>`.
pub fn aws_credentials(profile: &str) -> Result<()> {
    use std::io::IsTerminal;
    if std::io::stdout().is_terminal() {
        return Err(fail(
            exit::REFUSED,
            "This prints keys for the AWS CLI, not for a terminal.",
        ));
    }
    // inside an agent only the AWS CLI itself may ask (SPEC 10.6)
    crate::caller::check_helper(crate::caller::Tool::Aws, "sealctl aws credentials")?;
    let name = format!("aws/{profile}");
    let vals = client::values(std::slice::from_ref(&name), Some(("secret", &name)))?;
    let v: serde_json::Value = serde_json::from_slice(&vals[0].1)
        .map_err(|_| fail(exit::ERROR, format!("{name} is not AWS credentials JSON.")))?;
    let mut out = json!({
        "Version": 1,
        "AccessKeyId": v["aws_access_key_id"].as_str().or(v["AccessKeyId"].as_str()).unwrap_or(""),
        "SecretAccessKey": v["aws_secret_access_key"].as_str().or(v["SecretAccessKey"].as_str()).unwrap_or(""),
    });
    if let Some(t) = v["aws_session_token"].as_str().or(v["SessionToken"].as_str()) {
        out["SessionToken"] = json!(t);
    }
    let text = Zeroizing::new(out.to_string());
    std::io::stdout().write_all(text.as_bytes())?;
    Ok(())
}
