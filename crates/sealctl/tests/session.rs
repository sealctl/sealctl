//! The session around the keys: SSH agent and git signing, lock messages over the machine
//! channel, licence and `buy`, the soft ask, `recover` with the words (SPEC 6, 10, 17, 19).

mod common;

use std::time::Duration;

use common::{canary, have, Env, Pty};
use sealctl_core::wire::MessageKind;
use sealctl_fakerelay::{Answer, Options};
use serde_json::Value;

fn status(env: &Env) -> Value {
    let (_, out, _) = env.run(&["status", "--json"]);
    serde_json::from_str(&out).unwrap()
}

#[test]
fn ssh_agent_and_git_signing() {
    if !have("ssh-keygen") || !have("git") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    let ((code, out, err), _) = env.with_phone(Answer::Session, || {
        env.run(&["ssh", "keygen", "ed25519", "--comment", "t@test"])
    });
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("ssh-ed25519 "), "{out}");
    let pubf = env.h().join(".ssh/sealctl_ed25519.pub");
    assert!(pubf.exists());
    let sock = env.h().join("s/sealctl/ssh-agent.sock");
    let data = env.h().join("data.txt");
    std::fs::write(&data, "hello").unwrap();
    let sign = |env: &Env| {
        std::process::Command::new("ssh-keygen")
            .env("SSH_AUTH_SOCK", &sock)
            .args(["-Y", "sign", "-n", "git", "-f"])
            .arg(&pubf)
            .arg(&data)
            .current_dir(env.h())
            .output()
            .unwrap()
    };
    // Open: signs without asking
    let o = sign(&env);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(env.h().join("data.txt.sig").exists());
    std::fs::remove_file(env.h().join("data.txt.sig")).unwrap();
    // Locked: the first signature opens the session through the phone
    env.run(&["lock"]);
    let (o, log) = env.with_phone(Answer::Session, || sign(&env));
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(log, vec!["Open"]);

    // git commit signing through the daemon's agent
    let (code, out, err) = env.run(&["git", "setup"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("ssh-ed25519 "));
    let repo = env.h().join("repo");
    std::fs::create_dir_all(&repo).unwrap();
    let git = |args: &[&str]| {
        std::process::Command::new("git")
            .env_clear()
            .env("HOME", env.h())
            .env("PATH", std::env::var("PATH").unwrap())
            .env("XDG_STATE_HOME", env.h().join("s"))
            .env("SEALCTL_NO_SERVICE", "1")
            .env("SEALCTL_RELAY", &env.origin)
            .env("GIT_AUTHOR_NAME", "t")
            .env("GIT_AUTHOR_EMAIL", "t@test")
            .env("GIT_COMMITTER_NAME", "t")
            .env("GIT_COMMITTER_EMAIL", "t@test")
            .args(args)
            .current_dir(&repo)
            .output()
            .unwrap()
    };
    assert!(git(&["init", "-q"]).status.success());
    let o = git(&["commit", "-q", "--allow-empty", "-m", "signed"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = git(&["cat-file", "commit", "HEAD"]);
    assert!(String::from_utf8_lossy(&o.stdout).contains("BEGIN SSH SIGNATURE"));
}

#[test]
fn lock_from_the_phone_over_the_machine_channel() {
    let mut env = Env::new();
    let m = env.pair();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(status(&env)["state"], "open");
    // the phone sees the machine's status
    let mut seen = None;
    for _ in 0..50 {
        if let Ok(Some(s)) = env.block(env.phone.status_of(&m)) {
            seen = Some(s);
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let s = seen.expect("a status from the machine");
    assert_eq!(s.state.unwrap().session, "open");
    // lock from the phone
    std::thread::sleep(Duration::from_millis(500));
    env.block(env.phone.send_message(
        &m,
        MessageKind::Lock {
            reason: "phone".into(),
        },
    ))
    .unwrap();
    let mut locked = false;
    for _ in 0..50 {
        let v = status(&env);
        if v["state"] == "locked" {
            assert_eq!(v["lockReason"], "Locked from your phone");
            locked = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(locked, "locked by the phone");
    let (_, out, _) = env.run(&["status"]);
    assert!(out.starts_with("Locked from your phone"), "{out}");
}

#[test]
fn buy_when_payments_are_not_configured() {
    // staging answers 503 payments_not_configured; the fake relay does when told to
    let mut env = Env::with_options(Options {
        payments: false,
        ..Options::default()
    });
    env.pair();
    let (code, _, err) = env.run(&["buy", "--seats", "2"]);
    assert_eq!(code, 6, "{err}");
    assert!(
        err.contains(
            "Payments are not available on this relay right now. Status: https://sealctl.com/status"
        ),
        "{err}"
    );
    // without a terminal and without --seats/--code: exit 8
    let (code, _, _) = env.run(&["buy"]);
    assert_eq!(code, 8);
    // never inside an agent
    let mut c = env.cmd();
    c.env("SEALCTL_AGENT", "1").args(["buy", "--seats", "2"]);
    assert_eq!(c.output().unwrap().status.code(), Some(8));
}

#[test]
fn buy_seats_and_claim_a_code() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let fake_phone = env.phone.id();
    let relay_pay = std::sync::Arc::new(std::sync::Mutex::new(None::<String>));
    let child = env
        .cmd()
        .args(["buy", "--seats", "3"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    *relay_pay.lock().unwrap() = env.fake.as_ref().unwrap().pay(&fake_phone, 3);
    let o = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(o.status.code(), Some(0), "{err}");
    assert!(String::from_utf8_lossy(&o.stdout).contains("https://checkout.example.test/"));
    let code = relay_pay.lock().unwrap().clone().unwrap();
    assert!(
        err.contains(&format!(
            "Seat code {code} (3 seats, 1 used by you). Each developer runs: sealctl buy --code {code}"
        )),
        "{err}"
    );
    // paid now
    assert_eq!(status(&env)["licence"], "paid");
    // a colleague on another phone claims a seat
    let mut other = Env::fake(Options::default());
    other.origin = env.origin.clone();
    other.phone = std::sync::Arc::new(sealctl_fakerelay::Phone::new(&env.origin));
    other.pair();
    let (c, _, err) = other.run(&["buy", "--code", &code]);
    assert_eq!(c, 0, "{err}");
    assert!(
        err.contains(&format!("Paid with a seat from {code}. 1 seats left.")),
        "{err}"
    );
    let (c, _, err) = other.run(&["buy", "--code", "NOPE-0000"]);
    assert_eq!(c, 0, "already paid: {err}");
    let (c, _, err) = env.run(&["buy", "--seats", "1"]);
    assert_eq!(c, 2, "--seats is 2 to 1,000: {err}");
}

#[test]
fn the_ask_shows_only_to_a_person_and_weekly() {
    let mut env = Env::fake(Options::default());
    env.pair();
    env.fake.as_ref().unwrap().set_days_used(&env.phone.id(), 41);
    let ask = "You've used sealctl on 41 days. It's $5.99 once: sealctl buy";
    // a pipe: never
    let (_, _, err) = env.run(&["status"]);
    assert!(!err.contains(ask), "{err}");
    // an agent: never
    let mut c = env.cmd();
    c.env("SEALCTL_AGENT", "1").args(["secret", "ls"]);
    assert!(!String::from_utf8_lossy(&c.output().unwrap().stderr).contains(ask));
    // a person: once, then not for 7 days
    let mut c = env.cmd();
    c.args(["status"]);
    let (code, out, screen) = Pty::spawn(c).wait(Duration::from_secs(30));
    assert_eq!(code, 0, "{screen}");
    assert!(screen.contains(ask), "{screen}");
    assert!(out.contains("Unpaid · sealctl buy"), "{out}");
    let mut c = env.cmd();
    c.args(["secret", "ls"]);
    let (_, _, screen) = Pty::spawn(c).wait(Duration::from_secs(30));
    assert!(!screen.contains(ask), "weekly at most: {screen}");
    // never in sealctl run
    let mut c = env.cmd();
    c.args(["run", "--", "true"]);
    let (_, _, screen) = Pty::spawn(c).wait(Duration::from_secs(30));
    assert!(!screen.contains("$5.99"), "{screen}");
}

#[test]
fn recover_a_store_with_the_words() {
    let mut env = Env::new();
    env.pair();
    let value = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(&["secret", "set", "shop/key"], value.as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    let root = env.h().join(".local/share/sealctl/store");
    let store = std::fs::read_dir(&root).unwrap().next().unwrap().unwrap().path();
    env.stop_daemon();
    // no pairing, no relay needed: another HOME with only the folder
    let other = tempfile::Builder::new().prefix("sc").tempdir_in("/tmp").unwrap();
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_sealctl"));
    c.env_clear()
        .env("HOME", other.path())
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SEALCTL_AGENT", "0")
        .env("SEALCTL_RELAY", "http://127.0.0.1:9")
        .args(["recover", store.to_str().unwrap(), "--name", "shop/key"]);
    let pty = Pty::spawn(c);
    for (i, w) in env.phone.words().iter().enumerate() {
        pty.expect(&format!("Word {} of 24:", i + 1), Duration::from_secs(30));
        pty.line(w);
    }
    let (code, out, screen) = pty.wait(Duration::from_secs(60));
    assert_eq!(code, 0, "{screen}");
    assert_eq!(out, value);
    // other words: the fingerprint names both
    let other_phone = sealctl_fakerelay::Phone::new("http://127.0.0.1:9");
    let mut c = std::process::Command::new(env!("CARGO_BIN_EXE_sealctl"));
    c.env_clear()
        .env("HOME", other.path())
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SEALCTL_AGENT", "0")
        .args(["recover", store.to_str().unwrap(), "--name", "shop/key"]);
    let pty = Pty::spawn(c);
    for (i, w) in other_phone.words().iter().enumerate() {
        pty.expect(&format!("Word {} of 24:", i + 1), Duration::from_secs(30));
        pty.line(w);
    }
    let (code, out, screen) = pty.wait(Duration::from_secs(60));
    assert_eq!(code, 10, "{screen}");
    assert!(out.is_empty());
    assert!(
        screen.contains(&format!(
            "These words have fingerprint {}; this object was sealed with words {}.",
            other_phone.fingerprint(),
            env.phone.fingerprint()
        )),
        "{screen}"
    );
}
