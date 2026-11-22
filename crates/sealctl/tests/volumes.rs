//! Volumes and backups on derived keys with the real OS tools (SPEC 13, 14, 18): sparse bundles
//! with `hdiutil` on macOS, restic folder repositories. Disk images live in temporary folders.
//! Against the fake relay or the live one (`SEALCTL_TEST_RELAY`).
#![cfg(target_os = "macos")]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{canary, have, Env, PhoneThread, Pick, Pty};
use sealctl_fakerelay::Answer;

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

/// `name: value` from passwords.txt.
fn password_in(run: &std::path::Path, name: &str) -> String {
    std::fs::read_to_string(run.join("passwords.txt"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")).map(str::to_owned))
        .expect("password line")
}

fn run_dir(env: &Env) -> std::path::PathBuf {
    std::fs::read_dir(env.h())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sealctl-unsealed-")
        })
        .expect("run folder")
}

#[cfg(target_os = "macos")]
fn hdiutil_opens(bundle: &std::path::Path, pass: &str) -> bool {
    let mut c = Command::new("/usr/bin/hdiutil")
        .args(["attach", "-nomount", "-plist", "-stdinpass"])
        .arg(bundle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(pass.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    if !o.status.success() {
        return false;
    }
    let t = String::from_utf8_lossy(&o.stdout);
    let devs: Vec<&str> = t
        .split("<string>")
        .filter_map(|s| s.split("</string>").next())
        .filter(|s| s.starts_with("/dev/disk"))
        .collect();
    if let Some(d) = devs.iter().min_by_key(|d| d.len()) {
        let _ = Command::new("/usr/bin/hdiutil")
            .args(["detach", "-quiet", d])
            .status();
    }
    true
}

#[cfg(target_os = "macos")]
#[test]
fn sparse_bundle_volume_with_backup_lock_and_unseal() {
    let mut env = Env::new();
    env.pair();
    let bundle = env.h().join("v1.sparsebundle");
    let mnt = env.h().join("mnt/v1");
    let repos = env.h().join("repos");
    let marker = canary();
    let ((code, out, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "volume",
            "create",
            "v1",
            "--kind",
            "sparsebundle",
            "--size",
            "64m",
            "--path",
            bundle.to_str().unwrap(),
            "--mountpoint",
            mnt.to_str().unwrap(),
        ])
    });
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), mnt.to_str().unwrap());
    std::fs::write(mnt.join("hello.txt"), &marker).unwrap();
    let id: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(bundle.join("sealctl.id")).unwrap()).unwrap();
    assert_eq!(id["kind"], "volume");
    assert_eq!(id["words"], env.phone.fingerprint());
    assert!(mnt.join(".sealctl/volume.id").exists());

    let restic_ok = have("restic");
    if restic_ok {
        let ((code, _, err), _) = env.with_phone(Answer::Session, || {
            env.run(&[
                "backup",
                "init",
                "b1",
                "--from",
                "v1",
                "--repo",
                repos.to_str().unwrap(),
            ])
        });
        assert_eq!(code, 0, "{err}");
        let (code, _, err) = env.run(&["backup", "run", "b1", "--quiet"]);
        assert_eq!(code, 0, "{err}");
        // restic's key names the words
        let repo = std::fs::read_dir(&repos).unwrap().next().unwrap().unwrap().path();
        let keys: Vec<_> = std::fs::read_dir(repo.join("keys")).unwrap().flatten().collect();
        assert_eq!(keys.len(), 1);
        let k: serde_json::Value = serde_json::from_slice(&std::fs::read(keys[0].path()).unwrap()).unwrap();
        assert_eq!(k["hostname"], format!("sealctl-{}", env.phone.fingerprint()));
    }

    // lock: on-lock backup, then the volume closes
    let (code, out, err) = env.run(&["lock"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Volume v1 closed."), "{out}");
    if restic_ok {
        assert!(out.contains("Backed up b1."), "{out}");
    }
    assert!(!mnt.join("hello.txt").exists());

    // open asks the phone again (Locked)
    let ((code, _, err), log) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "v1"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Open"]);
    assert_eq!(std::fs::read_to_string(mnt.join("hello.txt")).unwrap(), marker);
    let (_, out, _) = env.run(&["status", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["volumes"][0]["mounted"], true, "{out}");
    let (code, _, err) = env.run(&["volume", "close", "v1"]);
    assert_eq!(code, 0, "{err}");

    // unseal the volume (and the backup): new passwords in the folder, sealctl's gone
    let mut c = env.cmd();
    c.args(["unseal", "volume", "v1"]);
    let pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    let run = run_dir(&env);
    let pw = password_in(&run, "volume v1");
    assert!(hdiutil_opens(&bundle, &pw), "the new passphrase opens it");
    assert!(!bundle.join("sealctl.id").exists());
    assert!(!env.h().join(".config/sealctl/volumes/v1.toml").exists());

    if restic_ok {
        let mut c = env.cmd();
        c.args(["unseal", "backup", "b1"]);
        let pty = Pty::spawn(c);
        pty.expect("Start?", Duration::from_secs(30));
        let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
        pty.line("y");
        let (code, _, screen) = pty.wait(Duration::from_secs(180));
        assert_eq!(code, 0, "{screen}");
        let run2 = std::fs::read_dir(env.h())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("sealctl-unsealed-")
            })
            .max()
            .unwrap();
        let pw = password_in(&run2, "backup b1");
        let repo = std::fs::read_dir(&repos).unwrap().next().unwrap().unwrap().path();
        let o = restic(&repo, &pw, &["snapshots", "--json"]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let keys = restic(&repo, &pw, &["key", "list", "--json"]);
        let ks: serde_json::Value = serde_json::from_slice(&keys.stdout).unwrap();
        assert_eq!(ks.as_array().unwrap().len(), 1, "only the user's key is left");
        let envfile = std::fs::read_to_string(run2.join("backup-b1.env")).unwrap();
        assert!(envfile.contains("RESTIC_REPOSITORY="));
    }
}

#[cfg(target_os = "macos")]
#[test]
fn seal_an_existing_sparse_bundle_and_restic_repository() {
    let mut env = Env::new();
    env.pair();
    let own = canary();
    let bundle = env.h().join("mine.sparsebundle");
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
    c.stdin.take().unwrap().write_all(own.as_bytes()).unwrap();
    assert!(c.wait().unwrap().success());

    let mut c = env.cmd();
    c.args([
        "seal",
        "volume",
        "mine",
        bundle.to_str().unwrap(),
        "--mountpoint",
        env.h().join("mnt/mine").to_str().unwrap(),
    ]);
    let pty = Pty::spawn(c);
    pty.expect("Passphrase of", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&own);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(screen.contains("pick "), "level 2 with the number: {screen}");
    assert!(phone.kinds().contains(&"Keys".to_string()));
    drop(phone);
    assert!(
        !hdiutil_opens(&bundle, &own),
        "the old passphrase no longer opens it"
    );
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "mine"]));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("mnt/mine"));
    env.run(&["volume", "close", "mine"]);

    if !have("restic") {
        return;
    }
    let repo = env.h().join("myrepo");
    let rpw = canary();
    assert!(restic(&repo, &rpw, &["init"]).status.success());
    let src = env.h().join("data");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), "x").unwrap();
    let mut c = env.cmd();
    c.args([
        "seal",
        "backup",
        "mine-b",
        "--repo",
        repo.to_str().unwrap(),
        "--from",
        src.to_str().unwrap(),
    ]);
    let pty = Pty::spawn(c);
    pty.expect("Password of the restic repository:", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&rpw);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(
        !restic(&repo, &rpw, &["cat", "config"]).status.success(),
        "old password removed"
    );
    let (code, _, err) = env.run(&["backup", "run", "mine-b", "--quiet"]);
    assert_eq!(code, 0, "{err}");
}

/// `unseal backup` killed (SIGKILL) right after sealctl's restic key is removed, so that only
/// the new password opens the repository: `--resume` reads that password back from the folder
/// store instead of making another, and finishes with it.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn unseal_backup_resumed_after_the_key_change_keeps_the_new_password() {
    use std::os::unix::process::ExitStatusExt;

    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    let repo = env.h().join("myrepo");
    let rpw = canary();
    assert!(restic(&repo, &rpw, &["init"]).status.success());
    let src = env.h().join("data");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), "x").unwrap();
    let mut c = env.cmd();
    c.args([
        "seal",
        "backup",
        "rb",
        "--repo",
        repo.to_str().unwrap(),
        "--from",
        src.to_str().unwrap(),
    ]);
    let pty = Pty::spawn(c);
    pty.expect("Password of the restic repository:", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&rpw);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    drop(phone);

    let mut c = env.cmd();
    c.env("SEALCTL_TEST_KILL", "changed:backup")
        .args(["unseal", "backup", "rb"]);
    let mut pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = pty.child.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() > Duration::from_secs(180) {
            let _ = pty.child.kill();
            panic!("not killed; screen:\n{}", pty.screen.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let screen = pty.screen.lock().unwrap().clone();
    assert_eq!(status.signal(), Some(9), "killed at the hook: {screen}");
    drop(phone);
    let run = run_dir(&env);
    let first = password_in(&run, "backup rb");
    let keys = restic(&repo, &first, &["key", "list", "--json"]);
    assert!(keys.status.success(), "the new password opens it");
    let ks: serde_json::Value = serde_json::from_slice(&keys.stdout).unwrap();
    assert_eq!(ks.as_array().unwrap().len(), 1, "sealctl's key is gone already");

    let mut c = env.cmd();
    c.args(["unseal", "--resume"]);
    let pty = Pty::spawn(c);
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    let (code, _, screen) = pty.wait(Duration::from_secs(180));
    assert_eq!(code, 0, "{screen}");
    assert!(run.join("done").exists());
    assert_eq!(password_in(&run, "backup rb"), first, "the same password");
    let envfile = std::fs::read_to_string(run.join("backup-rb.env")).unwrap();
    assert!(envfile.contains(&first), "backup-rb.env has the same password");
    let o = restic(&repo, &first, &["snapshots", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}
