//! Changing words (SPEC 16): the phone moves the machine to a new key, `sealctl migrate
//! --depth rewrap` moves every object to the new words, objects on retired words go through
//! `old_words`, the re-encryption job copies sparse bundles and restic repositories under new
//! keys, and `--scan` finds objects by their markers.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{canary, have, Env, Pty};
use sealctl_core::RequestKind;
use sealctl_fakerelay::{Answer, Phone};

/// A phone thread for words changes: `rewrap` answered with `old`'s root, `old_words` with
/// `retired`'s, anything else approved for the session.
fn words_phone(
    phone: Arc<Phone>,
    old: Arc<Phone>,
    retired: Option<Arc<Phone>>,
) -> (
    Arc<std::sync::atomic::AtomicBool>,
    std::thread::JoinHandle<Vec<String>>,
) {
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let s2 = stop.clone();
    let h = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut seen = Vec::new();
            let mut kinds = Vec::new();
            while !s2.load(std::sync::atomic::Ordering::SeqCst) {
                let Ok(r) = phone.next(&mut seen, Duration::from_millis(300)).await else {
                    continue;
                };
                let req = phone.open(&r).unwrap();
                kinds.push(format!("{:?}", req.kind()));
                // a request can be gone by the time it is answered (its command ended, or the
                // daemon stopped after a rewrap): note it, go on
                let r2 = match req.kind() {
                    RequestKind::Rewrap => phone.answer_rewrap(&r, &req, &old).await,
                    RequestKind::OldWords => {
                        phone.answer_old_words(&r, &req, retired.as_ref().unwrap()).await
                    }
                    _ => phone.auto(&r, &Answer::Session).await.map(|_| ()),
                };
                if let Err(e) = r2 {
                    kinds.push(format!("error: {e:#}"));
                }
            }
            kinds
        })
    });
    (stop, h)
}

fn migrate(
    env: &Env,
    args: &[&str],
    phone: Arc<Phone>,
    old: Arc<Phone>,
    retired: Option<Arc<Phone>>,
) -> (i32, String, Vec<String>) {
    let mut c = env.cmd();
    c.arg("migrate").args(args);
    let (stop, h) = words_phone(phone, old, retired);
    let pty = Pty::spawn(c);
    let (code, _, screen) = pty.wait(Duration::from_secs(180));
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let kinds = h.join().unwrap();
    (code, screen, kinds)
}

#[test]
fn new_words_rewrap_every_object() {
    let mut env = Env::new();
    let m = env.pair();
    let (value, own) = (canary(), canary());
    let bundle = env.h().join("v.sparsebundle");
    let mnt = env.h().join("mnt/v");
    let repos = env.h().join("repos");
    let macos = cfg!(target_os = "macos");
    let restic = have("restic");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let mut r = env.run_in(&["secret", "set", "shop/key"], value.as_bytes());
        if r.0 == 0 {
            r = env.run_in(&["secret", "set", "shop/own", "--own-approval"], own.as_bytes());
        }
        if r.0 == 0 && macos {
            r = env.run(&[
                "volume",
                "create",
                "v",
                "--kind",
                "sparsebundle",
                "--size",
                "32m",
                "--path",
                bundle.to_str().unwrap(),
                "--mountpoint",
                mnt.to_str().unwrap(),
            ]);
        }
        if r.0 == 0 && macos && restic {
            std::fs::write(mnt.join("f.txt"), "data").unwrap();
            r = env.run(&[
                "backup",
                "init",
                "b",
                "--from",
                "v",
                "--repo",
                repos.to_str().unwrap(),
            ]);
        }
        r
    });
    assert_eq!(code, 0, "{err}");
    env.run(&["lock"]);
    let a = env.phone.clone();

    // new words on the phone: it moves this machine to its new key
    let b = Arc::new(Phone::new(&env.origin));
    env.block(b.move_from(&a, &m)).unwrap();
    let (code, screen, kinds) = migrate(&env, &["--depth", "rewrap"], b.clone(), a.clone(), None);
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains(&format!("to seed {}.", b.fingerprint())),
        "{screen}"
    );
    assert!(kinds.contains(&"Rewrap".to_string()), "{kinds:?}");
    env.phone = b.clone();
    let mf: serde_json::Value =
        serde_json::from_slice(&std::fs::read(env.h().join(".config/sealctl/machine.json")).unwrap())
            .unwrap();
    assert_eq!(mf["phone"], b.id());

    // everything opens with the new words, through the new phone
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["secret", "get", "shop/key"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, value);
    let ((code, out, err), _) = env.with_phone(Answer::Once, || env.run(&["secret", "get", "shop/own"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, own);
    let (_, inv, _) = env.run(&["inventory", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&inv).unwrap();
    for o in v["objects"].as_array().unwrap() {
        assert_eq!(o["words"], b.fingerprint(), "{o}");
    }
    if macos {
        let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "v"]));
        assert_eq!(code, 0, "{err}");
        if restic {
            let (code, _, err) = env.run(&["backup", "run", "b", "--quiet"]);
            assert_eq!(code, 0, "{err}");
        }
        env.run(&["lock"]);
    }
    // running it again finds nothing to do
    let (code, screen, _) = migrate(&env, &["--depth", "rewrap"], b.clone(), a.clone(), None);
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains("on seed") && screen.contains("already"),
        "{screen}"
    );
}

#[test]
fn a_store_on_retired_words_goes_through_old_words() {
    let mut env = Env::new();
    env.pair();
    // a store sealed with other words (made here with sealctl-core), taken into use
    let x = Phone::new(&env.origin);
    let id = sealctl_core::ids::new_uuid().unwrap();
    let dir = env.h().join("synced").join(&id);
    std::fs::create_dir_all(&dir).unwrap();
    let key = sealctl_core::ObjectKey::derive(&x.root(), sealctl_core::Purpose::Secrets, &id).unwrap();
    let value = canary();
    let header = sealctl_core::sealed::Label {
        mode: sealctl_core::sealed::Mode::StoreKey,
        words: x.fingerprint(),
        file_id: sealctl_core::ids::new_uuid().unwrap(),
    };
    std::fs::create_dir_all(dir.join("shop")).unwrap();
    std::fs::write(
        dir.join("shop/old.sealed"),
        sealctl_core::sealed::seal(&header, &key, &id, "shop/old", value.as_bytes()).unwrap(),
    )
    .unwrap();
    let idf = sealctl_core::ids::IdFile {
        sealctl: 1,
        kind: "store".into(),
        id: id.clone(),
        words: x.fingerprint(),
        check: key.check(),
        created: "2026-01-01T00:00:00Z".into(),
        format: Some("sealed-v1".into()),
        own: None,
        volume: None,
    };
    std::fs::write(dir.join(format!("{id}.id")), idf.to_json()).unwrap();
    let (code, _, err) = env.run(&["secret", "store", "--use", dir.to_str().unwrap()]);
    assert_eq!(code, 0, "{err}");
    // using it: the phone cannot open words it does not have
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["secret", "get", "shop/old"]));
    assert_eq!(code, 10, "{err}");
    assert!(
        err.contains(&format!(
            "Sealed with seed {}; your phone has seed {}.",
            x.fingerprint(),
            env.phone.fingerprint()
        )),
        "{err}"
    );
    // migrate: rewrap says retired, then old_words with those words typed on the phone
    let x = Arc::new(x);
    let (code, screen, kinds) = migrate(
        &env,
        &["--depth", "rewrap"],
        env.phone.clone(),
        env.phone.clone(),
        Some(x.clone()),
    );
    assert_eq!(code, 0, "{screen}");
    assert!(kinds.contains(&"OldWords".to_string()), "{kinds:?}");
    assert!(
        screen.contains(&format!(
            "Type the 24 words of seed {} on your phone.",
            x.fingerprint()
        )),
        "{screen}"
    );
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["secret", "get", "shop/old"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, value);
}

#[cfg(target_os = "macos")]
#[test]
fn re_encryption_copies_under_new_keys() {
    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    let bundle = env.h().join("w.sparsebundle");
    let mnt = env.h().join("mnt/w");
    let repos = env.h().join("repos");
    let marker = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let r = env.run(&[
            "volume",
            "create",
            "w",
            "--kind",
            "sparsebundle",
            "--size",
            "32m",
            "--path",
            bundle.to_str().unwrap(),
            "--mountpoint",
            mnt.to_str().unwrap(),
        ]);
        if r.0 != 0 {
            return r;
        }
        std::fs::write(mnt.join("keep.txt"), &marker).unwrap();
        let r = env.run(&[
            "backup",
            "init",
            "wb",
            "--from",
            "w",
            "--repo",
            repos.to_str().unwrap(),
        ]);
        if r.0 != 0 {
            return r;
        }
        env.run(&["backup", "run", "wb", "--quiet"])
    });
    assert_eq!(code, 0, "{err}");
    let before: serde_json::Value = serde_json::from_str(&env.run(&["inventory", "--json"]).1).unwrap();
    // the table, then the job in the foreground
    let ((code, out, err), _) =
        env.with_phone(Answer::Session, || env.run(&["migrate", "--yes", "--foreground"]));
    assert_eq!(code, 0, "{err}");
    assert!(
        out.contains("volume w (sparse bundle)") && out.contains("re-encrypt"),
        "{out}"
    );
    let (_, status, _) = env.run(&["migrate", "--status", "--json"]);
    let st: serde_json::Value = serde_json::from_str(&status).unwrap();
    assert!(
        st["items"]
            .as_array()
            .unwrap()
            .iter()
            .all(|i| i["state"] == "done"),
        "{status}"
    );
    let after: serde_json::Value = serde_json::from_str(&env.run(&["inventory", "--json"]).1).unwrap();
    // volumes and backups get new ids; the store is rewrapped, not re-encrypted
    let ids = |v: &serde_json::Value| {
        v["objects"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|o| o["kind"] != "store")
            .map(|o| o["id"].as_str().unwrap().to_string())
            .collect::<Vec<_>>()
    };
    for id in ids(&before) {
        assert!(!ids(&after).contains(&id), "new ids after re-encryption");
    }
    // the data is there under the new keys, and the old repository is gone
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "w"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read_to_string(mnt.join("keep.txt")).unwrap(), marker);
    // the old bundle, set aside during the swap, is gone with the copy's name
    assert!(!env.h().join(".w.old.sparsebundle").exists());
    assert!(!env.h().join(".w.migrating.sparsebundle").exists());
    let (code, out, err) = env.run(&["backup", "snapshots", "wb", "--json"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&out)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1,
        "snapshots copied"
    );
    assert_eq!(
        std::fs::read_dir(&repos).unwrap().count(),
        1,
        "one repository left"
    );
    env.run(&["lock"]);
    // --scan finds both by their markers
    let (code, out, _) = env.run(&["migrate", "--scan", env.h().to_str().unwrap(), "--json"]);
    assert_eq!(code, 0);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    let kinds: Vec<&str> = v["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["kind"].as_str().unwrap())
        .collect();
    assert!(
        kinds.contains(&"volume") && kinds.contains(&"backup") && kinds.contains(&"store"),
        "{out}"
    );
}

#[test]
fn the_daemon_rewraps_by_itself_after_a_move() {
    let mut env = Env::new();
    let m = env.pair();
    let value = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(&["secret", "set", "a/b"], value.as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    env.run(&["lock"]);
    let a = env.phone.clone();
    let b = Arc::new(Phone::new(&env.origin));
    env.block(b.move_from(&a, &m)).unwrap();
    let (stop, h) = words_phone(b.clone(), a.clone(), None);
    // the next use meets the move; the daemon starts the rewrap without a terminal
    let _ = env.run(&["secret", "get", "a/b"]);
    let mut moved = false;
    for _ in 0..100 {
        let (_, inv, _) = env.run(&["inventory", "--json"]);
        let v: serde_json::Value = serde_json::from_str(&inv).unwrap();
        if v["objects"][0]["words"] == b.fingerprint() {
            moved = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    let kinds = h.join().unwrap();
    assert!(moved, "rewrapped by the daemon: {kinds:?}");
    env.phone = b;
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["secret", "get", "a/b"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, value);
}
