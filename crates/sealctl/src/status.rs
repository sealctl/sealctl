//! `sealctl status`, `doctor`, `cancel`, `inventory` and `rules` (SPEC 10.1, 10.5, 15).

use std::time::Duration;

use anyhow::Result;
use serde_json::{json, Value};

use crate::approve;
use crate::backup::Backup;
use crate::daemon::{client, session};
use crate::exit::{self, fail};
use crate::machine::{self, Paired};
use crate::relay::{self, Relay};
use crate::store::Store;
use crate::volume::Volume;
use crate::{licence, paths, ssh, term};

fn month() -> Value {
    let v: Value = paths::month_file()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or(json!({}));
    let m = crate::clock::now_local("%Y-%m");
    if v["month"] != m {
        return json!({"keysUsed": 0, "declined": 0, "valuesGivenOut": 0});
    }
    json!({
        "keysUsed": v["keysUsed"].as_u64().unwrap_or(0),
        "declined": v["declined"].as_u64().unwrap_or(0),
        "valuesGivenOut": v["valuesGivenOut"].as_u64().unwrap_or(0),
    })
}

/// Counts a value given out to a pipe (`secret get`).
pub fn count_given_out() {
    if let Ok(p) = paths::month_file() {
        let mut v: Value = std::fs::read(&p)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(json!({}));
        let m = crate::clock::now_local("%Y-%m");
        if v["month"] != m {
            v = json!({"month": m, "keysUsed": 0, "declined": 0});
        }
        v["valuesGivenOut"] = json!(v["valuesGivenOut"].as_u64().unwrap_or(0) + 1);
        let _ = paths::write_private(&p, v.to_string().as_bytes());
    }
}

/// Delayed actions from the relay (2-second timeout), named as well as this machine can.
fn pending(paired: &Paired) -> Vec<Value> {
    let Ok(relay) = Relay::new(&paired.file.relay) else {
        return vec![];
    };
    let Ok(rt) = relay::runtime() else { return vec![] };
    let list = rt.block_on(async {
        tokio::time::timeout(Duration::from_secs(2), approve::delayed_list(&relay, paired)).await
    });
    let Ok(Ok(list)) = list else { return vec![] };
    list.into_iter()
        .filter(|d| d.state == "waiting")
        .map(|d| {
            let (what, machine) = describe(paired, &d);
            json!({"id": d.id, "what": what, "machine": machine, "at": session::rfc3339(d.release_at), "atMs": d.release_at})
        })
        .collect()
}

fn describe(paired: &Paired, d: &approve::Delayed) -> (String, Option<String>) {
    match d.machine.as_deref() {
        Some(m) if m == paired.file.machine => ("leaving sealctl".into(), Some(paired.file.name.clone())),
        Some(_) => ("leaving sealctl".into(), Some("another paired machine".into())),
        None => ("an action on your phone".into(), None),
    }
}

/// `sealctl status [--json]`.
pub fn status(json_out: bool) -> Result<i32> {
    crate::legacy::warn();
    let paired = machine::load().ok();
    let daemon = client::status_if_running();
    let cfg = crate::config::Config::load()?;
    let store = Store::configured().ok();
    let secrets = store
        .as_ref()
        .and_then(|s| s.list().ok())
        .map(|l| l.len())
        .unwrap_or(0);
    let words = store
        .as_ref()
        .and_then(|s| s.id_file().ok().flatten())
        .map(|f| f.words)
        .or_else(|| {
            daemon
                .as_ref()
                .and_then(|d| d["words"].as_str().map(str::to_owned))
        });
    let volumes = Volume::list().unwrap_or_default();
    let backups = Backup::list().unwrap_or_default();
    let keys = ssh::names();
    let lic = paired
        .as_ref()
        .map(|p| licence::refreshed(p, Duration::from_secs(2)));
    let pend = paired.as_ref().map(pending).unwrap_or_default();
    let state = daemon
        .as_ref()
        .and_then(|d| d["state"].as_str().map(str::to_owned))
        .unwrap_or_else(|| "locked".into());
    let m = month();

    if json_out {
        let vols: Vec<Value> = volumes
            .iter()
            .map(|v| {
                let last = backups
                    .iter()
                    .find(|b| b.volume.as_deref() == Some(&v.name))
                    .and_then(|b| b.state().last_success)
                    .map(|s| session::rfc3339(s * 1000));
                json!({"name": v.name, "kind": v.kind.as_str(), "mounted": v.is_open(), "mountpoint": v.mountpoint, "lastBackup": last})
            })
            .collect();
        let out = json!({
            "version": env!("CARGO_PKG_VERSION"),
            "state": if paired.is_some() { state.clone() } else { "unpaired".into() },
            "left": daemon.as_ref().and_then(|d| d["left"].as_u64()),
            "hardStop": daemon.as_ref().and_then(|d| d["hardStop"].as_u64()).map(session::rfc3339),
            "lockReason": daemon.as_ref().and_then(|d| d["lockReason"].as_str().map(str::to_owned)),
            "machine": paired.as_ref().map(|p| json!({"name": p.file.name, "tag": p.file.tag, "paired": true, "relay": p.file.relay}))
                .unwrap_or(json!({"paired": false})),
            "words": words,
            "store": store.as_ref().map(|s| json!({"id": s.id, "path": s.dir, "secrets": secrets})),
            "volumes": vols,
            "backups": backups.iter().map(|b| json!({"name": b.name, "repo": b.repo, "lastBackup": b.state().last_success.map(|s| session::rfc3339(s * 1000))})).collect::<Vec<_>>(),
            "ssh": {"keys": keys},
            "pending": pend.iter().map(|p| json!({"id": p["id"], "what": p["what"], "machine": p["machine"], "at": p["at"]})).collect::<Vec<_>>(),
            "migrate": Value::Null,
            "month": m,
            "licence": lic.as_ref().map(|c| c.licence()).unwrap_or("unknown"),
            "daemon": if daemon.is_some() { "running" } else { "stopped" },
        });
        println!("{out}");
        let _ = cfg;
        return Ok(if paired.is_some() { 0 } else { exit::NOT_PAIRED });
    }

    let Some(p) = paired.as_ref() else {
        println!("Not paired · sealctl pair");
        return Ok(exit::NOT_PAIRED);
    };
    let first = match state.as_str() {
        "open" => {
            let left = daemon.as_ref().and_then(|d| d["left"].as_u64()).unwrap_or(0);
            let stop = daemon
                .as_ref()
                .and_then(|d| d["hardStop"].as_u64())
                .map(|h| format!(" · hard stop {}", session::hhmm(h)))
                .unwrap_or_default();
            format!("Open · {} left{stop}", session::duration(left))
        }
        "waiting" => {
            let since = daemon
                .as_ref()
                .and_then(|d| d["waitingSince"].as_u64())
                .unwrap_or(machine::now_ms());
            let s = machine::now_ms().saturating_sub(since) / 1000;
            format!("Waiting for your phone (asked {}:{:02} ago)", s / 60, s % 60)
        }
        _ => daemon
            .as_ref()
            .and_then(|d| d["lockReason"].as_str().map(str::to_owned))
            .unwrap_or_else(|| "Locked".into()),
    };
    println!("{first}");
    println!(
        "{} #{}{}",
        p.file.name,
        p.file.tag,
        words
            .as_ref()
            .map(|w| format!(" · words {w}"))
            .unwrap_or_default()
    );
    if let Some(s) = &store {
        let short: String = s.id.chars().take(8).collect();
        println!(
            "Store     {secrets} secrets · {}/{short}…",
            paths::tilde(s.dir.parent().unwrap_or(&s.dir))
        );
    }
    for (i, v) in volumes.iter().enumerate() {
        let head = if i == 0 { "Volumes   " } else { "          " };
        let last = backups
            .iter()
            .find(|b| b.volume.as_deref() == Some(&v.name))
            .and_then(|b| b.state().last_success)
            .map(|s| {
                format!(
                    " · backup {}",
                    crate::backup::age((machine::now_ms() / 1000).saturating_sub(s))
                )
            })
            .unwrap_or_default();
        if v.is_open() {
            println!(
                "{head}{} ({}) mounted at {}{last}",
                v.name,
                v.kind.label(),
                v.mountpoint.display()
            );
        } else {
            println!("{head}{} ({}) closed{last}", v.name, v.kind.label());
        }
    }
    for b in backups.iter().filter(|b| b.volume.is_none()) {
        let last = b
            .state()
            .last_success
            .map(|s| crate::backup::age((machine::now_ms() / 1000).saturating_sub(s)))
            .unwrap_or_else(|| "never".into());
        println!("Backup    {} of {} · {last}", b.name, b.source.display());
    }
    if !keys.is_empty() {
        println!(
            "SSH       {} key{}: {}",
            keys.len(),
            if keys.len() == 1 { "" } else { "s" },
            keys.join(", ")
        );
    }
    for pd in &pend {
        let at = pd["atMs"].as_u64().map(session::hhmm).unwrap_or_default();
        println!(
            "Pending   {}, approved on your phone · takes effect {at} · sealctl cancel",
            pd["what"].as_str().unwrap_or("")
        );
    }
    let given = m["valuesGivenOut"].as_u64().unwrap_or(0);
    println!(
        "This month: {} keys used, {} requests declined, {}.",
        m["keysUsed"].as_u64().unwrap_or(0),
        m["declined"].as_u64().unwrap_or(0),
        if given == 0 {
            "nothing written to disk".to_string()
        } else {
            format!("values given out: {given}")
        }
    );
    match lic.as_ref().map(|c| c.licence()) {
        Some("paid") => println!("Paid"),
        Some("unpaid") => println!("Unpaid · sealctl buy"),
        _ => {}
    }
    licence::maybe_ask();
    Ok(0)
}

/// `sealctl cancel [<id>] [--yes]`.
pub fn cancel(id: Option<String>, yes: bool, relay_flag: Option<&str>) -> Result<()> {
    term::refuse_agent("sealctl cancel")?;
    let paired = machine::load_for(relay_flag)?;
    let relay = Relay::new(&paired.file.relay)?;
    let rt = relay::runtime()?;
    let list = rt.block_on(approve::delayed_list(&relay, &paired))?;
    let waiting: Vec<&approve::Delayed> = list.iter().filter(|d| d.state == "waiting").collect();
    let target = match id {
        Some(i) => *waiting
            .iter()
            .find(|d| d.id == i)
            .ok_or_else(|| fail(exit::NOT_FOUND, format!("Nothing pending with id {i}.")))?,
        None => match waiting.as_slice() {
            [] => return Err(fail(exit::NOT_FOUND, "Nothing pending.")),
            [one] => *one,
            many => {
                for d in many {
                    let (what, m) = describe(&paired, d);
                    eprintln!(
                        "{}  {what}{}  due {}",
                        d.id,
                        m.map(|m| format!(" on {m}")).unwrap_or_default(),
                        session::hhmm(d.release_at)
                    );
                }
                return Err(fail(exit::USAGE, "Several are pending. Run: sealctl cancel <id>"));
            }
        },
    };
    let (what, m) = describe(&paired, target);
    if !yes {
        if !term::is_person() {
            return Err(fail(exit::REFUSED, "Cancelling needs a terminal. Use --yes."));
        }
        let q = format!(
            "Cancel {what}{}, due at {}?",
            m.map(|m| format!(" on {m}")).unwrap_or_default(),
            session::hhmm(target.release_at)
        );
        if !term::confirm(&q, false)? {
            return Ok(());
        }
    }
    if !rt.block_on(approve::delayed_cancel(&relay, &paired, &target.id))? {
        return Err(fail(exit::NOT_FOUND, "It already ended."));
    }
    println!("Cancelled.");
    println!("{LOST_PHONE}");
    Ok(())
}

/// After a cancel: the approval came from the phone, so if it wasn't the user, the phone is in
/// someone else's hands.
const LOST_PHONE: &str = "\
If you didn't approve this on your phone, someone else may have it:
  - Find, lock or erase it: Google Find My Device (google.com/android/find)
    or Apple Find My (icloud.com/find).
  - Then restore sealctl on another phone from your card, and change your words there.";

/// `sealctl inventory [--json]`.
pub fn inventory(json_out: bool) -> Result<()> {
    let mut objects = Vec::new();
    if let Ok(s) = Store::configured() {
        if let Some(f) = s.id_file()? {
            objects.push(json!({"kind": "store", "id": s.id, "words": f.words, "check": f.check, "path": paths::tilde(&s.dir)}));
        }
    }
    for v in Volume::list()? {
        objects.push(json!({"kind": "volume", "name": v.name, "volume": v.kind.as_str(), "id": v.id, "words": v.words, "check": v.check,
            "path": v.path.as_ref().map(|p| paths::tilde(p)).unwrap_or_else(|| v.id.clone())}));
    }
    for b in Backup::list()? {
        objects.push(json!({"kind": "backup", "name": b.name, "id": b.repo_id, "words": b.words, "check": b.check, "path": b.repo}));
    }
    if json_out {
        println!("{}", json!({"objects": objects}));
        return Ok(());
    }
    for o in &objects {
        let id: String = o["id"].as_str().unwrap_or("").chars().take(8).collect();
        println!(
            "{:<7} {id}…  {}  {}",
            o["kind"].as_str().unwrap_or(""),
            o["words"].as_str().unwrap_or(""),
            o["path"].as_str().unwrap_or("")
        );
    }
    Ok(())
}

/// `sealctl rules [--json]`.
pub fn rules(json_out: bool) -> Result<()> {
    let a = crate::daemon::load_answers();
    if json_out {
        println!("{}", json!({"answers": a}));
        return Ok(());
    }
    for r in &a {
        println!("{} · {} · {}", r.agent, r.repo, r.name);
    }
    eprintln!("Remove answers on your phone: Answers.");
    Ok(())
}

/// `sealctl doctor`.
pub fn doctor(json_out: bool) -> Result<i32> {
    let mut checks: Vec<(String, Option<String>)> = Vec::new();
    let paired = machine::load();
    match &paired {
        Ok(p) => checks.push((format!("paired as {}", p.label()), None)),
        Err(e) => checks.push(("paired".into(), Some(exit::message_of(e)))),
    }
    if let Ok(p) = &paired {
        let relay = Relay::new(&p.file.relay)?;
        let rt = relay::runtime()?;
        match rt.block_on(relay.health()) {
            Ok(v) => {
                checks.push((format!("relay {}", p.file.relay), None));
                if let Some(t) = v["time"].as_u64() {
                    let off = (machine::now_ms() / 1000).abs_diff(t);
                    checks.push((
                        "clock".into(),
                        (off > 300).then(|| format!("{} minutes off", off / 60)),
                    ));
                }
            }
            Err(e) => checks.push((format!("relay {}", p.file.relay), Some(exit::message_of(&e)))),
        }
        let d = client::status_if_running();
        checks.push((
            "daemon running".into(),
            d.is_none()
                .then(|| "not running; it starts on the next command".into()),
        ));
        if crate::service::allowed() {
            let installed = crate::service::is_installed(crate::service::DAEMON_LABEL);
            checks.push((
                "login service".into(),
                (!installed).then(|| "not installed: sealctl pair installs it".into()),
            ));
        }
    }
    if let Ok(mf) = paths::machine_file() {
        if let Ok(m) = std::fs::metadata(&mf) {
            use std::os::unix::fs::PermissionsExt;
            checks.push((
                "machine.json mode 0600".into(),
                (m.permissions().mode() & 0o077 != 0).then(|| format!("chmod 600 {}", mf.display())),
            ));
        }
    }
    checks.push((
        "restic installed".into(),
        (!crate::util::which("restic")).then(|| "install restic for backups".into()),
    ));
    match Store::configured().and_then(|s| s.list().map(|l| l.len())) {
        Ok(n) => checks.push((format!("store readable ({n} secrets)"), None)),
        Err(e) => checks.push(("store".into(), Some(exit::message_of(&e)))),
    }
    let legacy = crate::legacy::found();
    checks.push((
        "no sealctl 0.5 objects".into(),
        (!legacy.is_empty()).then(|| crate::legacy::MESSAGE.to_string()),
    ));
    let problems = checks.iter().filter(|c| c.1.is_some()).count();
    if json_out {
        let v: Vec<Value> = checks
            .iter()
            .map(|(n, p)| json!({"check": n, "problem": p}))
            .collect();
        println!("{}", json!({"checks": v, "problems": problems}));
    } else {
        for (n, p) in &checks {
            match p {
                None => println!("ok: {n}"),
                Some(p) => println!("problem: {n}: {p}"),
            }
        }
    }
    Ok(if problems > 0 { 1 } else { 0 })
}
