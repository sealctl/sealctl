//! The daemon's session state (SPEC 6): what a `once` grant leaves behind, multi-part
//! `answers`, and the lock on a version change. Always against the fake relay.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::time::Duration;

use common::{canary, Env};
use sealctl_core::wire::{Answer as Remembered, MessageKind};
use sealctl_fakerelay::{Answer, Options};
use serde_json::{json, Value};

/// One request on the daemon socket, answered by its last line.
fn daemon(env: &Env, mut op: Value) -> Value {
    op["v"] = json!(1);
    if op.get("cli").is_none() {
        op["cli"] = json!(env!("CARGO_PKG_VERSION"));
    }
    let mut s = UnixStream::connect(env.h().join("s/sealctl/daemon.sock")).unwrap();
    s.write_all(format!("{op}\n").as_bytes()).unwrap();
    let mut last = Value::Null;
    for line in BufReader::new(s).lines() {
        let Ok(line) = line else { break };
        last = serde_json::from_str(&line).unwrap_or(Value::Null);
        if last.get("event").is_none() {
            break;
        }
    }
    last
}

fn agent_run(env: &Env) -> (i32, String) {
    let mut c = env.cmd();
    c.env("SEALCTL_AGENT", "").env("CLAUDECODE", "1").args([
        "run",
        "-e",
        "K=shop/key",
        "--",
        "sh",
        "-c",
        "echo ran=$K",
    ]);
    let o = c.output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

#[test]
fn a_once_grant_leaves_nothing_in_the_daemon() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let ((code, _, err), log) = env.with_phone(Answer::Once, || {
        env.run_in(&["secret", "set", "shop/key"], canary().as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Open"]);
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "locked", "{st}");
    assert_eq!(st["keysHeld"], 0, "the store key went with the command: {st}");

    // an agent use approved once is not kept: the next session asks for it again
    let ((code, err), log) = env.with_phone(Answer::Once, || agent_run(&env));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Open"]);
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    let ((code, err), log) = env.with_phone(Answer::Once, || agent_run(&env));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Agent"], "a once answer covers one command");
    // and within the session, a `once` agent answer covers that command only
    let ((code, err), log) = env.with_phone(Answer::Once, || agent_run(&env));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Agent"]);
    let ((code, err), log) = env.with_phone(Answer::Session, || agent_run(&env));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Agent"]);
    let ((code, err), log) = env.with_phone(Answer::Session, || agent_run(&env));
    assert_eq!(code, 0, "{err}");
    assert!(log.is_empty(), "a session answer is kept: {log:?}");
}

#[test]
fn answers_in_parts_replace_the_list_once_all_arrived() {
    let mut env = Env::fake(Options::default());
    let m = env.pair();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    // the machine channel is up once the phone has its status
    for _ in 0..50 {
        if matches!(env.block(env.phone.status_of(&m)), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let part = |names: &[&str]| {
        vec![Remembered {
            agent: "claude".into(),
            repository: "github.com/o/r".into(),
            names: names.iter().map(|n| n.to_string()).collect(),
            last: 0,
        }]
    };
    let file = env.h().join("s/sealctl/answers.json");
    let read = || -> Vec<String> {
        let v: Value = std::fs::read(&file)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or(json!([]));
        v.as_array()
            .unwrap()
            .iter()
            .map(|a| a["name"].as_str().unwrap().to_string())
            .collect()
    };
    env.block(env.phone.send_message(
        &m,
        MessageKind::Answers {
            answers: part(&["a", "b"]),
            more: true,
        },
    ))
    .unwrap();
    env.block(env.phone.send_message(
        &m,
        MessageKind::Answers {
            answers: part(&["c"]),
            more: false,
        },
    ))
    .unwrap();
    let mut names = Vec::new();
    for _ in 0..50 {
        names = read();
        if !names.is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(names, ["a", "b", "c"]);

    // a list that never finished is dropped when the session locks, not merged into the next
    env.block(env.phone.send_message(
        &m,
        MessageKind::Answers {
            answers: part(&["x"]),
            more: true,
        },
    ))
    .unwrap();
    std::thread::sleep(Duration::from_secs(1));
    let (code, _, err) = env.run(&["lock"]);
    assert_eq!(code, 0, "{err}");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    std::thread::sleep(Duration::from_secs(1));
    env.block(env.phone.send_message(
        &m,
        MessageKind::Answers {
            answers: part(&["y"]),
            more: false,
        },
    ))
    .unwrap();
    for _ in 0..50 {
        names = read();
        if names != ["a", "b", "c"] {
            break;
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    assert_eq!(names, ["y"]);
}

#[test]
fn a_daemon_of_another_version_locks_before_it_exits() {
    let mut env = Env::fake(Options::default());
    let m = env.pair();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    let session = |want: &str| {
        for _ in 0..50 {
            if let Ok(Some(s)) = env.block(env.phone.status_of(&m)) {
                if s.state.is_some_and(|st| st.session == want) {
                    return true;
                }
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        false
    };
    assert!(session("open"));
    let a = daemon(&env, json!({"op": "status", "cli": "0.0.0-other"}));
    assert_eq!(a["ok"], false, "{a}");
    assert!(session("locked"), "the phone hears the session lock");
}
