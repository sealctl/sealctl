//! `unseal --to` and `--secrets-to` (SPEC 18.3) with fake `op` and `bw` CLIs on PATH that
//! record their argv; `--secrets-to env`; a corrupted read-back stops the run; Ctrl-C between
//! steps exits 13 with the journal resumable.

mod common;

use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{canary, Env, PhoneThread, Pick, Pty};
use sealctl_fakerelay::Answer;

fn fixtures() -> String {
    format!("{}/tests/fixtures/bin", env!("CARGO_MANIFEST_DIR"))
}

/// A paired machine with two secrets and one SSH key.
fn setup() -> (Env, String, String) {
    let mut env = Env::new();
    env.pair();
    let (a, b) = (canary(), canary());
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let r = env.run_in(&["secret", "set", "shop/api-key"], a.as_bytes());
        if r.0 != 0 {
            return r;
        }
        let r = env.run_in(&["secret", "set", "shop/db.url"], b.as_bytes());
        if r.0 != 0 {
            return r;
        }
        env.run(&["ssh", "keygen", "deploy"])
    });
    assert_eq!(code, 0, "{err}");
    env.run(&["lock"]);
    (env, a, b)
}

fn unseal(env: &Env, args: &[&str], extra_env: &[(&str, String)]) -> (i32, String) {
    let mut c = env.cmd();
    c.env(
        "PATH",
        format!("{}:{}", fixtures(), std::env::var("PATH").unwrap()),
    );
    for (k, v) in extra_env {
        c.env(k, v);
    }
    c.arg("unseal").args(args);
    let pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    (code, screen)
}

#[test]
fn secrets_to_1password_and_ssh_passphrase_to_bitwarden() {
    let (env, a, b) = setup();
    let fake = env.h().join("fake-store");
    let (code, screen) = unseal(
        &env,
        &[
            "secrets",
            "--keep-store",
            "--secrets-to",
            "op",
            "--op-vault",
            "Work",
        ],
        &[("FAKE_STORE", fake.display().to_string())],
    );
    assert_eq!(code, 0, "{screen}");
    assert!(screen.contains("Secrets go to:       1Password"), "{screen}");
    let argv = std::fs::read_to_string(fake.join("argv.log")).unwrap();
    assert!(!argv.contains(&a) && !argv.contains(&b), "no value in any argv");
    assert!(
        argv.contains("op item create --format json --vault Work"),
        "{argv}"
    );
    let titles: Vec<String> = std::fs::read_dir(fake.join("op"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".title"))
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
        .collect();
    assert!(
        titles.contains(&"sealctl: secret shop/api-key".to_string()),
        "{titles:?}"
    );
    let hb = std::fs::read_to_string(unseal_dir(&env).join("handback.json")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&hb).unwrap();
    let obj = v["objects"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["name"] == "shop/api-key")
        .unwrap()
        .clone();
    assert_eq!(obj["value"]["store"], "op");
    assert_eq!(obj["value"]["vault"], "Work");
    assert!(!hb.contains(&a));

    // an SSH key back with a passphrase kept in Bitwarden
    let (code, screen) = unseal(
        &env,
        &["ssh", "deploy", "--to", "bw", "--bw-folder", "keys"],
        &[("FAKE_STORE", fake.display().to_string())],
    );
    assert_eq!(code, 0, "{screen}");
    let key = std::fs::read_to_string(env.h().join(".ssh/deploy")).unwrap();
    let k = ssh_key::PrivateKey::from_openssh(&key).unwrap();
    assert!(k.is_encrypted(), "a passphrase of your own");
    let pass = std::fs::read_to_string(fake.join("bw/id1")).unwrap();
    assert!(k.decrypt(pass.as_bytes()).is_ok());
    let argv = std::fs::read_to_string(fake.join("argv.log")).unwrap();
    assert!(!argv.contains(&pass), "the passphrase never in argv");
}

#[test]
fn a_changed_read_back_stops_the_run() {
    let (env, _, _) = setup();
    let fake = env.h().join("fake-store");
    let (code, screen) = unseal(
        &env,
        &["secrets", "--secrets-to", "op"],
        &[
            ("FAKE_STORE", fake.display().to_string()),
            ("FAKE_OP_CORRUPT", "1".into()),
        ],
    );
    assert_eq!(code, 13, "{screen}");
    assert!(screen.contains("differs from what was written"), "{screen}");
    // the store is still in place
    let (code, out, _) = env.run(&["secret", "ls"]);
    assert_eq!(code, 0);
    assert!(out.contains("shop/api-key"));
}

#[test]
fn secrets_to_an_env_file() {
    let (env, a, b) = setup();
    let file = env.h().join("mine.env");
    let (code, screen) = unseal(
        &env,
        &[
            "secrets",
            "--secrets-to",
            "env",
            "--env-file",
            file.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains("This file holds your keys in plain text"),
        "{screen}"
    );
    let text = std::fs::read_to_string(&file).unwrap();
    assert!(text.contains(&format!("SHOP_API_KEY=\"{a}\"")), "{text}");
    assert!(text.contains(&format!("SHOP_DB_URL=\"{b}\"")), "{text}");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&file).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn the_show_store_refuses_secrets() {
    let (env, _, _) = setup();
    let mut c = env.cmd();
    c.args(["unseal", "secrets", "--secrets-to", "show"]);
    let (code, _, screen) = Pty::spawn(c).wait(Duration::from_secs(30));
    assert_eq!(code, 2, "{screen}");
    assert!(screen.contains("secrets can't be shown"), "{screen}");
}

fn unseal_dir(env: &Env) -> std::path::PathBuf {
    std::fs::read_dir(env.h())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sealctl-unsealed-")
        })
        .min()
        .expect("run folder")
}

#[test]
fn ctrl_c_stops_between_steps_and_resume_finishes() {
    let (env, a, _) = setup();
    let mut c = env.cmd();
    c.args(["unseal", "--all"]);
    let pty = Pty::spawn(c);
    pty.expect("Type unseal to start:", Duration::from_secs(30));
    let phone = PhoneThread::start_gated(env.phone.clone(), pty.screen.clone(), Pick::Right, None, false);
    pty.line("unseal");
    // the run is at the report, just before the pairing step: Ctrl-C now
    let start = std::time::Instant::now();
    while !phone.report_seen.load(Ordering::SeqCst) {
        assert!(start.elapsed() < Duration::from_secs(90), "no report");
        std::thread::sleep(Duration::from_millis(50));
    }
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(pty.child.id() as i32),
        nix::sys::signal::Signal::SIGINT,
    )
    .unwrap();
    phone.report_release.store(true, Ordering::SeqCst);
    let (code, _, screen) = pty.wait(Duration::from_secs(90));
    assert_eq!(code, 13, "{screen}");
    assert!(
        screen.contains("Run sealctl unseal --resume to go on."),
        "{screen}"
    );
    let run = unseal_dir(&env);
    assert!(!run.join("done").exists());
    assert!(std::fs::read_to_string(run.join("journal.jsonl"))
        .unwrap()
        .contains("stopped by Ctrl-C"));
    let machines = env
        .block(
            env.phone
                .call("GET", &format!("/v1/phones/{}/machines", env.phone.id()), None),
        )
        .unwrap();
    assert_eq!(
        machines.1["machines"].as_array().unwrap().len(),
        1,
        "still paired: the pairing step did not run"
    );
    drop(phone);

    let mut c = env.cmd();
    c.args(["unseal", "--resume"]);
    let pty = Pty::spawn(c);
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(run.join("done").exists());
    let hb = std::fs::read_to_string(run.join("handback.json")).unwrap();
    assert!(
        hb.contains("shop/api-key"),
        "objects of the first part are kept: {hb}"
    );
    assert!(std::fs::read_to_string(run.join("secrets.env"))
        .unwrap()
        .contains(&a));
}

/// The real keychain, under a test service name: CI only (`--features test-hooks` and
/// `SEALCTL_TEST_KEYCHAIN=1` on the macOS runner); items are removed afterwards.
#[cfg(all(feature = "test-hooks", target_os = "macos"))]
#[test]
fn secrets_to_the_keychain_with_readable_labels() {
    use std::process::Command;
    if std::env::var_os("SEALCTL_TEST_KEYCHAIN").is_none() {
        return;
    }
    let (env, _, _) = setup();
    let service = format!("sealctl-test-{}", &canary()[6..14]);
    let (code, screen) = unseal(
        &env,
        &["secrets", "--keep-store", "--secrets-to", "keychain"],
        &[("SEALCTL_TEST_KEYCHAIN_SERVICE", service.clone())],
    );
    assert_eq!(code, 0, "{screen}");
    for account in ["secret/shop/api-key", "secret/shop/db.url"] {
        let o = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", &service, "-a", account])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&o.stdout);
        let name = account.strip_prefix("secret/").unwrap();
        assert!(
            text.contains(&format!("\"labl\"<blob>=\"sealctl: secret {name}\"")),
            "{text}"
        );
        let _ = Command::new("/usr/bin/security")
            .args(["delete-generic-password", "-s", &service, "-a", account])
            .output();
    }
}
