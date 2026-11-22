//! `sealctl unseal` with the phone (SPEC 18.9): plan, number match, plan signature, delayed
//! approvals, cancel from another machine, the hand-back report, and `--words`. Against the
//! fake relay or the live one (`SEALCTL_TEST_RELAY`). Commands run on a pseudo-terminal.

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{canary, number_on, Env, Pty};
use sealctl_core::RequestKind;
use sealctl_fakerelay::{Answer, Phone};

#[derive(Clone, Copy)]
enum Pick {
    Right,
    Wrong,
}

/// A phone that answers everything: `unseal` with the number read from the terminal (or a
/// wrong one) and `delay`; reports acknowledged; anything else approved for the session.
struct PhoneThread {
    stop: Arc<AtomicBool>,
    h: Option<std::thread::JoinHandle<()>>,
    kinds: Arc<Mutex<Vec<String>>>,
}

impl PhoneThread {
    fn start(phone: Arc<Phone>, screen: Arc<Mutex<String>>, pick: Pick, delay: Option<u64>) -> PhoneThread {
        let stop = Arc::new(AtomicBool::new(false));
        let kinds = Arc::new(Mutex::new(Vec::new()));
        let (s2, k2) = (stop.clone(), kinds.clone());
        let h = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut seen = Vec::new();
                while !s2.load(Ordering::SeqCst) {
                    let Ok(r) = phone.next(&mut seen, Duration::from_millis(300)).await else {
                        continue;
                    };
                    let req = phone.open(&r).unwrap();
                    k2.lock().unwrap().push(format!("{:?}", req.kind()));
                    match req.kind() {
                        RequestKind::Unseal => {
                            let p = if req.has_match() {
                                let shown = loop {
                                    if let Some(n) = number_on(&screen.lock().unwrap()) {
                                        break n;
                                    }
                                    tokio::time::sleep(Duration::from_millis(50)).await;
                                };
                                let choices = req.match_choices();
                                assert!(choices.contains(&shown), "the shown number is offered");
                                Some(match pick {
                                    Pick::Right => shown,
                                    Pick::Wrong => *choices.iter().find(|c| **c != shown).unwrap(),
                                })
                            } else {
                                None
                            };
                            phone.answer_unseal(&r, &req, p, delay).await.unwrap();
                        }
                        RequestKind::Report => phone.answer_report(&r, &req).await.unwrap(),
                        _ => {
                            phone.auto(&r, &Answer::Session).await.unwrap();
                        }
                    }
                }
            });
        });
        PhoneThread {
            stop,
            h: Some(h),
            kinds,
        }
    }

    fn kinds(&self) -> Vec<String> {
        self.kinds.lock().unwrap().clone()
    }
}

impl Drop for PhoneThread {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.h.take() {
            let _ = h.join();
        }
    }
}

/// A paired machine with one secret and one SSH key in its store.
fn setup() -> (Env, String) {
    let mut env = Env::new();
    env.pair();
    let value = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let a = env.run_in(&["secret", "set", "shop/api-key"], value.as_bytes());
        if a.0 != 0 {
            return a;
        }
        env.run(&["ssh", "keygen", "ed25519"])
    });
    assert_eq!(code, 0, "{err}");
    env.run(&["lock"]);
    (env, value)
}

fn unseal_run_dir(env: &Env) -> std::path::PathBuf {
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

#[test]
fn unseal_all_with_number_match_and_report() {
    let (env, value) = setup();
    let mut c = env.cmd();
    c.args(["unseal", "--all"]);
    let pty = Pty::spawn(c);
    let screen = pty.expect("Type unseal to start:", Duration::from_secs(30));
    assert!(screen.contains("secrets"), "{screen}");
    assert!(screen.contains("ssh key"), "{screen}");
    assert!(screen.contains("pairing"), "{screen}");
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("unseal");
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(
        screen.contains("Waiting for your phone. On your phone, pick "),
        "{screen}"
    );
    assert!(
        screen.contains("Done. sealctl holds nothing on this machine."),
        "{screen}"
    );
    let kinds = phone.kinds();
    assert!(kinds.contains(&"Unseal".to_string()), "{kinds:?}");
    assert!(
        kinds.contains(&"Report".to_string()),
        "report before the pairing step: {kinds:?}"
    );

    let run = unseal_run_dir(&env);
    let env_file = std::fs::read_to_string(run.join("secrets.env")).unwrap();
    assert!(
        env_file.contains(&format!("SHOP_API_KEY=\"{value}\"")),
        "secret handed back"
    );
    assert!(run.join("handback.json").exists() && run.join("done").exists());
    let hb = std::fs::read_to_string(run.join("handback.json")).unwrap();
    assert!(!hb.contains(&value), "no value in the hand-back list");
    let journal = std::fs::read_to_string(run.join("journal.jsonl")).unwrap();
    assert!(!journal.contains(&value));
    // the SSH key is a plain key file now
    let key = std::fs::read_to_string(env.h().join(".ssh/ed25519")).unwrap();
    assert!(!ssh_key::PrivateKey::from_openssh(key).unwrap().is_encrypted());
    // sealctl's own folders are gone; the pairing too
    assert!(!env.h().join(".config/sealctl").exists());
    assert!(!env.h().join("s/sealctl").exists());
    let (code, _, _) = env.run(&["status"]);
    assert_eq!(code, 3);
    let machines = env
        .block(
            env.phone
                .call("GET", &format!("/v1/phones/{}/machines", env.phone.id()), None),
        )
        .unwrap();
    assert_eq!(
        machines.1["machines"].as_array().unwrap().len(),
        0,
        "unpaired on the relay"
    );
}

#[test]
fn a_wrong_number_changes_nothing() {
    let (env, _) = setup();
    let mut c = env.cmd();
    c.args(["unseal", "--all"]);
    let pty = Pty::spawn(c);
    pty.expect("Type unseal to start:", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Wrong, None);
    pty.line("unseal");
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 4, "{screen}");
    let n = number_on(&screen).unwrap();
    assert!(
        screen.contains(&format!(
            "sealctl: The number picked on your phone was not {n}. Nothing was changed."
        )),
        "{screen}"
    );
    assert!(
        env.h().join(".config/sealctl/machine.json").exists(),
        "still paired"
    );
    let run = unseal_run_dir(&env);
    assert!(!run.join("secrets.env").exists(), "nothing handed back");
}

#[test]
fn delayed_approval_runs_after_the_delay() {
    let (env, value) = setup();
    let mut c = env.cmd();
    c.args(["unseal", "secrets"]);
    let pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, Some(3));
    pty.line("y");
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(screen.contains("pick "), "level 2 with the number: {screen}");
    assert!(
        screen.contains("Approved on your phone, away from a trusted place: it starts at"),
        "{screen}"
    );
    assert!(
        screen.contains("Your phone and every paired machine can cancel it until then."),
        "{screen}"
    );
    let run = unseal_run_dir(&env);
    assert!(std::fs::read_to_string(run.join("secrets.env"))
        .unwrap()
        .contains(&value));
    // the store went to kept/, still sealed
    assert!(run.join("kept/store").is_dir());
}

#[test]
fn cancel_from_another_machine() {
    let (env, _) = setup();
    let mut second = env.second();
    second.pair();
    let mut c = env.cmd();
    c.args(["unseal", "--all"]);
    let pty = Pty::spawn(c);
    pty.expect("Type unseal to start:", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, Some(60));
    pty.line("unseal");
    pty.expect("Starts in", Duration::from_secs(60));
    // the other machine sees it pending, and cancels it
    let (code, out, err) = second.run(&["status", "--json"]);
    assert_eq!(code, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["pending"].as_array().unwrap().len(), 1, "{out}");
    let (code, out, err) = second.run(&["cancel", "--yes"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Cancelled."));
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 4, "{screen}");
    assert!(
        screen.contains("sealctl: Cancelled from another paired machine."),
        "{screen}"
    );
    assert!(
        env.h().join(".config/sealctl/machine.json").exists(),
        "nothing changed"
    );
    let (code, _, _) = second.run(&["cancel", "--yes"]);
    assert_eq!(code, 9, "nothing pending any more");
}

#[test]
fn unseal_one_secret_with_the_words_sends_no_request() {
    let (env, value) = setup();
    let mut c = env.cmd();
    c.args(["unseal", "secret", "shop/api-key", "--words"]);
    let pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    pty.line("y");
    for (i, w) in env.phone.words().iter().enumerate() {
        pty.expect(&format!("Word {} of 24:", i + 1), Duration::from_secs(30));
        // the first four letters are enough
        pty.line(&w.chars().take(4).collect::<String>());
    }
    let (code, _, screen) = pty.wait(Duration::from_secs(60));
    assert_eq!(code, 0, "{screen}");
    let run = unseal_run_dir(&env);
    assert!(std::fs::read_to_string(run.join("secrets.env"))
        .unwrap()
        .contains(&value));
    if let Some(f) = &env.fake {
        assert_eq!(f.pending_count(&env.phone.id()), 0);
    }
    for w in env.phone.words() {
        assert!(!screen.contains(&format!("{w} ")), "words are not echoed");
    }
}

#[test]
fn unseal_is_refused_inside_an_agent_and_without_a_terminal() {
    let (env, _) = setup();
    let (code, _, err) = env.run(&["unseal", "--all"]);
    assert_eq!(code, 8, "{err}");
    let mut c = env.cmd();
    c.env("SEALCTL_AGENT", "")
        .env("CLAUDECODE", "1")
        .args(["unseal", "--all"]);
    let o = c.output().unwrap();
    assert_eq!(o.status.code(), Some(8));
    assert!(String::from_utf8_lossy(&o.stderr).contains("Not inside an AI agent"));
}
