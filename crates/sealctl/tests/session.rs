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

/// While `buy` waits for the payment, a final answer from the relay (the phone's daily limit)
/// ends the wait at once with that error, instead of asking again for 15 minutes.
#[test]
fn buy_stops_waiting_on_a_final_answer() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let fake = env.fake.as_ref().unwrap();
    let limited = serde_json::json!({"error": "rate_limited", "retryAfter": 3600, "scope": "phone"});
    fake.watch("GET", "/licence", Some((429, limited)));
    let mut child = env
        .cmd()
        .args(["buy", "--seats", "3"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut done = false;
    for _ in 0..300 {
        if child.try_wait().unwrap().is_some() {
            done = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    if !done {
        let _ = child.kill();
    }
    let o = child.wait_with_output().unwrap();
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(done, "buy still waits after 30 s: {err}");
    assert_eq!(o.status.code(), Some(7), "{err}");
    assert!(err.contains("daily limit"), "{err}");
    assert!(
        err.contains("sealctl status shows the payment when it arrives."),
        "{err}"
    );
    // the seat codes before the checkout, then one look while waiting
    let calls = fake.calls("GET", "/licence");
    assert!(calls <= 2, "{calls}");
}

/// `26 Nov 2027` from the date part of `2027-11-26T...`.
fn long_date(rfc3339: &str) -> String {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let p: Vec<usize> = rfc3339[..10].split('-').map(|x| x.parse().unwrap()).collect();
    format!("{} {} {}", p[2], MONTHS[p[1] - 1], p[0])
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// The questionnaire, typed with some wrong answers first (each is asked again).
fn answer_the_questionnaire(pty: &Pty) {
    let t = Duration::from_secs(30);
    pty.expect("What do you use sealctl for?", t);
    pty.expect("Choose: ", t);
    pty.line("1,9");
    pty.expect("Type numbers from 1 to 5, like 1,3 or 1 3.", t);
    pty.line("1, 3");
    pty.expect("Would $5.99 once be fair?", t);
    pty.line("5");
    pty.expect("Type a number from 1 to 4.", t);
    pty.line("2");
    pty.expect("What's missing?", t);
    pty.line("5 1");
    pty.expect("Nothing goes on its own.", t);
    pty.line("1 3");
    pty.expect("Anything else?", t);
    pty.line(&"x".repeat(281));
    pty.expect("One line of at most 280 characters, please.", t);
    pty.line("  works well  ");
}

#[test]
fn buy_while_payments_are_closed_records_the_intent() {
    let mut env = Env::fake(Options {
        payments: false,
        ..Options::default()
    });
    env.pair();
    let fake = env.fake.as_ref().unwrap();
    let mut c = env.cmd();
    c.args(["buy"]);
    let pty = Pty::spawn(c);
    let t = Duration::from_secs(30);
    let screen = pty.expect("Choose 1, 2 or 3: ", t);
    assert!(
        screen.contains("sealctl is $5.99 once. Card payments open soon."),
        "{screen}"
    );
    assert!(
        screen.contains("  1  I'd buy it      sealctl tells you here when you can (nothing is charged)"),
        "{screen}"
    );
    assert!(
        screen.contains("  2  Give feedback   2 minutes; you get a year free"),
        "{screen}"
    );
    assert!(screen.contains("  3  Not now"), "{screen}");
    pty.line("yes");
    pty.expect("Type a number from 1 to 3.", t);
    pty.line("1");
    let (code, _, screen) = pty.wait(t);
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains("Noted. Thank you: sealctl will tell you here when you can buy."),
        "{screen}"
    );
    let intent = fake.intent_of(&env.phone.id()).expect("intent recorded");
    assert_eq!(intent.as_object().unwrap().len(), 1, "only the time: {intent}");
    // nothing else changes: still unpaid, and "Not now" sends nothing
    assert_eq!(status(&env)["licence"], "unpaid");
    let mut c = env.cmd();
    c.args(["buy"]);
    let pty = Pty::spawn(c);
    pty.expect("Choose 1, 2 or 3: ", t);
    pty.line("3");
    let (code, _, screen) = pty.wait(t);
    assert_eq!(code, 0, "{screen}");
    assert!(fake.feedback_of(&env.phone.id()).is_none());
}

#[test]
fn feedback_gives_a_year_once_and_status_shows_it() {
    let mut env = Env::fake(Options {
        payments: false,
        ..Options::default()
    });
    env.pair();
    let fake = env.fake.as_ref().unwrap();
    fake.set_days_used(&env.phone.id(), 41);
    let t = Duration::from_secs(30);
    let mut c = env.cmd();
    c.args(["buy"]);
    let pty = Pty::spawn(c);
    pty.expect("Choose 1, 2 or 3: ", t);
    pty.line("2");
    answer_the_questionnaire(&pty);
    let (code, _, screen) = pty.wait(t);
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains("Sent with this phone's id; no name or email."),
        "{screen}"
    );
    let got = fake.feedback_of(&env.phone.id()).expect("feedback stored");
    assert_eq!(got["use"], serde_json::json!(["agents", "volumes"]));
    assert_eq!(got["price"], "more");
    assert_eq!(got["missing"], serde_json::json!(["windows", "teams"]));
    assert_eq!(got["text"], "works well");
    let keys: Vec<&String> = got.as_object().unwrap().keys().collect();
    assert_eq!(
        keys.len(),
        6,
        "v, use, price, missing, text, at; no name or email: {got}"
    );

    // status: the line and the JSON, from the cache `buy` refreshed
    let v = status(&env);
    assert_eq!(v["licence"], "feedback");
    let until = v["until"].as_str().expect("until").to_string();
    assert!(
        screen.contains(&format!("Sent. Licensed until {}. Thank you.", long_date(&until))),
        "{screen}"
    );
    let (_, out, _) = env.run(&["status"]);
    assert!(
        out.contains(&format!("Licensed until {} (feedback)", &until[..10])),
        "{out}"
    );
    assert!(!out.contains("Unpaid"), "{out}");
    // no ask while it lasts
    let mut c = env.cmd();
    c.args(["status"]);
    let (_, _, screen) = Pty::spawn(c).wait(t);
    assert!(!screen.contains("$5.99"), "{screen}");

    // a second feedback is kept but gives nothing new
    let mut c = env.cmd();
    c.args(["buy"]);
    let pty = Pty::spawn(c);
    pty.expect("Choose 1, 2 or 3: ", t);
    pty.line("2");
    answer_the_questionnaire(&pty);
    let (code, _, screen) = pty.wait(t);
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains(&format!(
            "Sent. Thank you. This phone has its free year already: licensed until {}.",
            long_date(&until)
        )),
        "{screen}"
    );
    assert_eq!(status(&env)["until"], until.as_str(), "the end does not move");

    // the year ends: unpaid at once, without waiting for the hour-long cache
    fake.set_feedback_until(&env.phone.id(), now_ms() - 1);
    let file = env.h().join("s/sealctl/licence.json");
    let mut cache: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(cache["answer"]["kind"], "feedback");
    cache["answer"]["until"] = serde_json::json!(now_ms() - 1);
    std::fs::write(&file, serde_json::to_vec(&cache).unwrap()).unwrap();
    let v = status(&env);
    assert_eq!(v["licence"], "unpaid");
    assert!(v["until"].is_null(), "{v}");
    let (_, out, _) = env.run(&["status"]);
    assert!(out.contains("Unpaid · sealctl buy"), "{out}");
    // and the usual ask resumes
    let mut c = env.cmd();
    c.args(["status"]);
    let (_, _, screen) = Pty::spawn(c).wait(t);
    assert!(
        screen.contains("You've used sealctl on 41 days. It's $5.99 once: sealctl buy"),
        "{screen}"
    );
}

#[test]
fn with_payments_open_feedback_is_offered_until_given() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let fake = env.fake.as_ref().unwrap();
    let t = Duration::from_secs(30);
    let mut c = env.cmd();
    c.args(["buy"]);
    let pty = Pty::spawn(c);
    let screen = pty.expect("Choose 1, 2, 3 or 4: ", t);
    assert!(screen.contains("Who pays?"), "{screen}");
    assert!(screen.contains("  4  Give feedback instead"), "{screen}");
    pty.line("4");
    answer_the_questionnaire(&pty);
    let (code, _, screen) = pty.wait(t);
    assert_eq!(code, 0, "{screen}");
    assert!(screen.contains("Sent. Licensed until "), "{screen}");
    assert!(fake.feedback_of(&env.phone.id()).is_some());
    // given once: the menu no longer offers it; the end of input leaves without a checkout
    let mut c = env.cmd();
    c.args(["buy"]);
    let pty = Pty::spawn(c);
    let screen = pty.expect("Choose 1, 2 or 3: ", t);
    assert!(!screen.contains("Give feedback"), "{screen}");
    pty.line("\u{4}");
    let (code, out, screen) = pty.wait(t);
    assert_eq!(code, 0, "{screen}");
    assert!(!out.contains("https://"), "{out}");
}

#[test]
fn buy_menus_are_for_a_person_only() {
    let mut env = Env::fake(Options {
        payments: false,
        ..Options::default()
    });
    env.pair();
    let fake = env.fake.as_ref().unwrap();
    // inside an AI agent, even on a terminal: exit 8
    let mut c = env.cmd();
    c.env("SEALCTL_AGENT", "1").args(["buy"]);
    let (code, _, screen) = Pty::spawn(c).wait(Duration::from_secs(30));
    assert_eq!(code, 8, "{screen}");
    assert!(!screen.contains("Card payments"), "{screen}");
    // CI, even on a terminal: exit 8
    let mut c = env.cmd();
    c.env("CI", "true").args(["buy"]);
    let (code, _, screen) = Pty::spawn(c).wait(Duration::from_secs(30));
    assert_eq!(code, 8, "{screen}");
    assert!(screen.contains("This needs a terminal: sealctl buy."), "{screen}");
    // a pipe with scripted answers: exit 8, nothing sent
    let (code, _, err) = env.run_in(&["buy"], b"2\n1\n1\n5\n\n");
    assert_eq!(code, 8, "{err}");
    assert!(fake.feedback_of(&env.phone.id()).is_none());
    assert!(fake.intent_of(&env.phone.id()).is_none());
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
            "These words are seed {}; this object was sealed with seed {}.",
            other_phone.fingerprint(),
            env.phone.fingerprint()
        )),
        "{screen}"
    );
}

#[test]
fn the_cli_waits_out_the_relays_short_term_limit() {
    let mut env = Env::fake(Options::default());
    env.pair();
    // the wait socket upgrade and the licence call meet a 429 (scope network), then go through
    env.fake.as_ref().unwrap().rate_limit(2);
    // in-process, so that the note is on this command's stderr (a daemon logs it)
    let ((code, out, err), log) = env.with_phone(Answer::Session, || {
        let o = env
            .cmd()
            .env("SEALCTL_NO_DAEMON", "1")
            .args(["open"])
            .output()
            .unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    });
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("Open · "), "{out}");
    assert!(
        err.contains("sealctl: The relay asks to slow down; trying again in 1 s."),
        "{err}"
    );
    assert_eq!(log, vec!["Open"]);
}

#[test]
fn without_a_machine_channel_reports_carry_status_and_the_lock() {
    let mut env = Env::fake(Options {
        machine_channel: false,
        ..Options::default()
    });
    env.pair();
    let phone = env.phone.clone();
    let h = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(async move {
            let mut seen = Vec::new();
            let r = phone.next(&mut seen, Duration::from_secs(30)).await.unwrap();
            let req = phone.open(&r).unwrap();
            assert_eq!(req.kind(), sealctl_core::RequestKind::Open);
            phone
                .answer(
                    &r,
                    &req,
                    sealctl_core::Decision::Session {
                        place: sealctl_core::Place::Trusted,
                    },
                )
                .await
                .unwrap();
            // the daemon falls back to a report request carrying its status
            let r = phone.next(&mut seen, Duration::from_secs(30)).await.unwrap();
            let req = phone.open(&r).unwrap();
            assert_eq!(req.kind(), sealctl_core::RequestKind::Report);
            let st = req.status().expect("status fields in the report");
            assert_eq!(st.state.unwrap().session, "open");
            phone
                .answer_report_with(
                    &r,
                    &req,
                    vec![MessageKind::Lock {
                        reason: "place".into(),
                    }],
                )
                .await
                .unwrap();
        });
    });
    let (code, _, err) = env.run(&["open"]);
    assert_eq!(code, 0, "{err}");
    h.join().unwrap();
    let mut locked = false;
    for _ in 0..50 {
        let v = status(&env);
        if v["state"] == "locked" {
            assert_eq!(v["lockReason"], "Locked: your phone left the place");
            locked = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert!(locked, "locked through the report reply");
}
