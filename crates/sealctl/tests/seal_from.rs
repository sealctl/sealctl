//! `sealctl seal --from <hand-back list>` (SPEC 18.2): a list written by 0.6.0 (Ledger) and
//! one written by 0.7's own `unseal`, each object taken over with its password read from
//! where `unseal` put it.

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{canary, have, Env, PhoneThread, Pick, Pty};
use sealctl_fakerelay::Answer;
use serde_json::json;

fn restic(repo: &std::path::Path, password: &str, args: &[&str]) -> std::process::Output {
    let mut c = Command::new("restic")
        .env("RESTIC_REPOSITORY", repo)
        .env("RESTIC_PASSWORD_FILE", "/dev/stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(password.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

fn seal_from(env: &Env, list: &std::path::Path) -> (i32, String) {
    let mut c = env.cmd();
    c.args(["seal", "--from", list.to_str().unwrap()]);
    let pty = Pty::spawn(c);
    pty.expect("Type seal to start:", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("seal");
    let (code, _, screen) = pty.wait(Duration::from_secs(240));
    (code, screen)
}

#[test]
fn a_list_written_by_0_6_0() {
    let mut env = Env::new();
    env.pair();
    let dir = env.h().join("sealctl-unsealed-2026-11-21");
    std::fs::create_dir_all(&dir).unwrap();
    let secret = canary();
    // the folder store as 0.6.0 writes it
    std::fs::write(
        dir.join("secrets.env"),
        format!("# The secrets of sealctl's store\nSHOP_API_KEY=\"{secret}\"\n"),
    )
    .unwrap();
    let mut passwords =
        String::from("# New passwords from `sealctl unseal`, one per line: `<what>: <password>`.\n");
    let mut objects = vec![json!({"kind": "secret", "name": "shop/api-key",
        "value": {"store": "folder", "file": dir.join("secrets.env"), "var": "SHOP_API_KEY"}})];
    // an SSH key handed back without a passphrase
    let key =
        ssh_key::PrivateKey::random(&mut ssh_key::rand_core::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    std::fs::create_dir_all(env.h().join(".ssh")).unwrap();
    let keyfile = env.h().join(".ssh/old-key");
    std::fs::write(
        &keyfile,
        key.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    objects.push(json!({"kind": "ssh", "name": "old-key", "path": "~/.ssh/old-key"}));
    // a restic repository under a password of the user's
    let have_restic = have("restic");
    let repo = env.h().join("repos/5f3c");
    let rpw = canary();
    if have_restic {
        assert!(restic(&repo, &rpw, &["init"]).status.success());
        passwords.push_str(&format!("backup safe: {rpw}\n"));
        objects.push(json!({"kind": "backup", "name": "safe", "url": repo,
            "password": {"store": "folder", "file": dir.join("passwords.txt"), "var": "backup safe"}}));
    }
    // a sparse bundle (macOS) under a passphrase of the user's
    let bundle = env.h().join("mine.sparsebundle");
    let vpw = canary();
    if cfg!(target_os = "macos") {
        let mut c = Command::new("/usr/bin/hdiutil")
            .args([
                "create",
                "-quiet",
                "-size",
                "32m",
                "-type",
                "SPARSEBUNDLE",
                "-fs",
                "APFS",
                "-encryption",
                "AES-256",
                "-stdinpass",
                "-volname",
                "mine",
            ])
            .arg(&bundle)
            .stdin(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(vpw.as_bytes()).unwrap();
        assert!(c.wait().unwrap().success());
        passwords.push_str(&format!("volume mine: {vpw}\n"));
        objects.push(json!({"kind": "volume", "name": "mine", "volume": "sparsebundle",
            "uuid": "8c8e2a3e-5d27-4b8c-9c51-2f0d1a4b7e10", "path": "~/mine.sparsebundle",
            "password": {"store": "folder", "file": dir.join("passwords.txt"), "var": "volume mine"}}));
    }
    std::fs::write(dir.join("passwords.txt"), passwords).unwrap();
    let list = json!({"sealctl": 1, "kind": "handback", "created": "2026-11-21T10:31:07+01:00",
        "machine": "dev@mbp.example.com", "from": "0.6.0", "objects": objects});
    std::fs::write(
        dir.join("handback.json"),
        serde_json::to_vec_pretty(&list).unwrap(),
    )
    .unwrap();

    let (code, screen) = seal_from(&env, &dir.join("handback.json"));
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains("handed back by sealctl 0.6.0 on dev@mbp.example.com"),
        "{screen}"
    );
    let ((code, out, err), _) =
        env.with_phone(Answer::Session, || env.run(&["secret", "get", "shop/api-key"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, secret);
    let (_, out, _) = env.run(&["ssh", "pubkey", "old-key"]);
    assert_eq!(out.trim(), key.public_key().to_openssh().unwrap());
    if cfg!(target_os = "macos") {
        let (code, out, err) = env.run(&["volume", "ls", "--json"]);
        assert_eq!(code, 0, "{err}");
        assert!(out.contains("\"mine\""), "{out}");
        assert!(bundle.join("sealctl.id").exists());
    }
    if have_restic {
        assert!(
            !restic(&repo, &rpw, &["cat", "config"]).status.success(),
            "the old password is removed"
        );
        let (_, out, _) = env.run(&["inventory", "--json"]);
        assert!(out.contains("\"5f3c\""), "repository id from the URL: {out}");
    }
}

#[test]
fn a_list_written_by_unseal_round_trips() {
    let mut env = Env::new();
    env.pair();
    let value = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let r = env.run_in(&["secret", "set", "shop/token"], value.as_bytes());
        if r.0 != 0 {
            return r;
        }
        env.run(&["ssh", "keygen", "work"])
    });
    assert_eq!(code, 0, "{err}");
    let pubkey = env.run(&["ssh", "pubkey", "work"]).1;
    // hand both back (the folder store), keeping the machine paired
    let mut c = env.cmd();
    c.args(["unseal", "secrets"]);
    let pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    drop(phone);
    let run = std::fs::read_dir(env.h())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sealctl-unsealed-")
        })
        .unwrap();
    // the store went to kept/; a new one is made by the first secret stored
    let cfg = std::fs::read_to_string(env.h().join(".config/sealctl/config.toml")).unwrap();
    assert!(!cfg.contains("store ="), "{cfg}");
    env.stop_daemon();
    let (code, screen) = seal_from(&env, &run.join("handback.json"));
    assert_eq!(code, 0, "{screen}");
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["secret", "get", "shop/token"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, value);
    // the SSH key's secret came back as a secret too (ssh/work)
    let (_, out, _) = env.run(&["secret", "ls"]);
    assert!(out.contains("ssh/work"), "{out}");
    assert!(!pubkey.is_empty());
}
