//! `sealctl unseal` with the phone (SPEC 18.9): plan, number match, plan signature, delayed
//! approvals, cancel from another machine, the hand-back report, and `--words`. Against the
//! fake relay or the live one (`SEALCTL_TEST_RELAY`). Commands run on a pseudo-terminal.

mod common;

#[cfg(feature = "test-hooks")]
use std::sync::atomic::Ordering;
use std::time::Duration;

use common::{canary, number_on, Env, PhoneThread, Pick, Pty};
use sealctl_fakerelay::Answer;

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
    assert!(
        out.contains("Google Find My Device") && out.contains("Apple Find My"),
        "{out}"
    );
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
    // nothing follows a word prompt on its line: the words are not echoed
    for l in screen.lines().filter(|l| l.contains(" of 24:")) {
        let after = l.rsplit(" of 24:").next().unwrap_or("");
        assert!(after.trim().is_empty(), "echoed: {l:?}");
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

/// Journal lines of a run, as JSON.
#[cfg(feature = "test-hooks")]
fn journal(run: &std::path::Path) -> Vec<serde_json::Value> {
    std::fs::read_to_string(run.join("journal.jsonl"))
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// A run killed (SIGKILL) right after its first step is journalled done, while steps that need
/// keys of the plan are still to come, resumes under the same phone approval: no new number,
/// the keys left come without asking, and the first step is not repeated. The kill point is the
/// `test-hooks` hook `SEALCTL_TEST_KILL`, not a timed kill from here, which raced the run to its
/// end on slow machines.
#[cfg(feature = "test-hooks")]
#[test]
fn resume_after_a_kill_uses_the_same_approval() {
    use std::os::unix::process::ExitStatusExt;

    let (env, value) = setup();
    let mut c = env.cmd();
    // the first step is the secrets store
    c.env("SEALCTL_TEST_KILL", "done:secrets")
        .args(["unseal", "--all"]);
    let mut pty = Pty::spawn(c);
    pty.expect("Type unseal to start:", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("unseal");
    // power cut after the first step: the run kills itself there
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = pty.child.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let _ = pty.child.kill();
            panic!("not killed; screen:\n{}", pty.screen.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let screen = pty.screen.lock().unwrap().clone();
    assert_eq!(status.signal(), Some(9), "killed at the hook: {screen}");
    assert_eq!(phone.numbers.load(Ordering::SeqCst), 1, "{screen}");
    let unseal_requests = |p: &PhoneThread| p.kinds().iter().filter(|k| *k == "Unseal").count();
    let before = unseal_requests(&phone);

    let run = unseal_run_dir(&env);
    assert!(!run.join("done").exists());
    let lines = journal(&run);
    let last = lines.last().expect("journal");
    let first = last["step"].as_str().unwrap().to_owned();
    assert!(
        first.starts_with("secrets:") && last["state"] == "done",
        "nothing ran after the first step: {lines:?}"
    );
    // steps left that need a key of the plan: the resume has to get it from the phone
    let plan: serde_json::Value =
        serde_json::from_slice(&std::fs::read(run.join("plan.json")).unwrap()).unwrap();
    let keyed_left: Vec<&str> = plan["steps"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|s| s["id"] != first.as_str() && !s["purpose"].is_null())
        .filter_map(|s| s["id"].as_str())
        .collect();
    assert!(!keyed_left.is_empty(), "a keyed step is left: {plan}");

    let mut c = env.cmd();
    c.args(["unseal", "--resume"]);
    let pty = Pty::spawn(c);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(screen.contains("Resuming the run in"), "{screen}");
    assert!(
        !screen.contains("pick "),
        "no new number within 30 minutes of the approval: {screen}"
    );
    assert!(run.join("done").exists());
    let env_file = std::fs::read_to_string(run.join("secrets.env")).unwrap();
    assert_eq!(
        env_file.matches(&value).count(),
        1,
        "the secret step was not repeated"
    );
    let starts = journal(&run)
        .iter()
        .filter(|l| l["step"] == first.as_str() && l["state"] == "start")
        .count();
    assert_eq!(starts, 1, "the secrets step ran once");
    // the keys left came with the same approval: asked for again, one number in all
    assert!(
        unseal_requests(&phone) > before,
        "the resume asked for the keys left ({keyed_left:?}): {:?}",
        phone.kinds()
    );
    assert_eq!(phone.numbers.load(Ordering::SeqCst), 1, "one number in all");
    assert!(!env.h().join(".config/sealctl").exists());
}
