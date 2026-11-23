//! The daemon's session state (SPEC 6): what a `once` grant leaves behind, multi-part
//! `answers`, the lock on a version change and on SIGTERM, and requests on the phone against
//! locks, Ctrl-C, other requests and the wall clock. Always against the fake relay.

mod common;

use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Mutex};
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

fn agent_cmd(env: &Env) -> std::process::Command {
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
    c
}

fn agent_run(env: &Env) -> (i32, String) {
    let o = agent_cmd(env).output().unwrap();
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
    let (code, _, err) = run_within(&env, &["lock"], 10);
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

/// The running daemon's pid. On Linux the daemon is not dumpable, so its open files are hidden
/// from `lsof`: the daemon socket's peer credentials name it instead.
#[cfg(target_os = "linux")]
fn daemon_pid(env: &Env) -> String {
    use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
    let s = UnixStream::connect(env.h().join("s/sealctl/daemon.sock")).unwrap();
    getsockopt(&s, PeerCredentials).unwrap().pid().to_string()
}

/// The running daemon's pid: the process holding `daemon.lock`.
#[cfg(not(target_os = "linux"))]
fn daemon_pid(env: &Env) -> String {
    let o = std::process::Command::new("lsof")
        .arg("-t")
        .arg(env.h().join("s/sealctl/daemon.lock"))
        .output()
        .unwrap();
    String::from_utf8_lossy(&o.stdout).trim().to_string()
}

/// Polls `f` every 100 ms for up to `secs` seconds.
fn until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..secs * 10 {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

/// Waits up to `secs` seconds for a started command; kills it and fails when it takes longer.
fn within(mut child: std::process::Child, secs: u64, what: &str) -> (i32, String, String) {
    for _ in 0..secs * 10 {
        if child.try_wait().unwrap().is_some() {
            let o = child.wait_with_output().unwrap();
            return (
                o.status.code().unwrap_or(-1),
                String::from_utf8_lossy(&o.stdout).into_owned(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("{what} did not finish within {secs} s");
}

/// Runs `sealctl args` (no terminal), which must finish within `secs` seconds.
fn run_within(env: &Env, args: &[&str], secs: u64) -> (i32, String, String) {
    let child = env
        .cmd()
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    within(child, secs, &format!("sealctl {}", args.join(" ")))
}

/// The next request the phone sees (unanswered).
fn next_request(env: &Env, seen: &mut Vec<String>) -> sealctl_fakerelay::Incoming {
    env.block(env.phone.next(seen, Duration::from_secs(20)))
        .expect("a request on the phone")
}

/// Is request `id` still waiting on the relay?
fn listed(env: &Env, id: &str) -> bool {
    env.block(env.phone.requests())
        .unwrap()
        .iter()
        .any(|r| r.id == id)
}

/// Opens the session and stores `shop/key`.
fn open_with_secret(env: &Env) {
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(&["secret", "set", "shop/key"], canary().as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    assert_eq!(daemon(env, json!({"op": "status"}))["state"], "open");
}

/// A started command whose output is read while it runs.
struct Started {
    child: std::process::Child,
    out: Arc<Mutex<String>>,
    err: Arc<Mutex<String>>,
    readers: Vec<std::thread::JoinHandle<()>>,
}

fn read_into(mut pipe: impl Read + Send + 'static, to: Arc<Mutex<String>>) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut b = [0u8; 512];
        while let Ok(n) = pipe.read(&mut b) {
            if n == 0 {
                break;
            }
            to.lock().unwrap().push_str(&String::from_utf8_lossy(&b[..n]));
        }
    })
}

/// Starts `c` without a terminal, reading what it prints.
fn start(mut c: std::process::Command) -> Started {
    let mut child = c
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (out, err) = (Arc::default(), Arc::default());
    let readers = vec![
        read_into(child.stdout.take().unwrap(), Arc::clone(&out)),
        read_into(child.stderr.take().unwrap(), Arc::clone(&err)),
    ];
    Started {
        child,
        out,
        err,
        readers,
    }
}

impl Started {
    /// Waits up to `secs` seconds for `text` on its stderr.
    fn says(&self, text: &str, secs: u64) -> bool {
        until(secs, || self.err.lock().unwrap().contains(text))
    }

    /// Is it waiting for the phone (or for the request it joined)? The daemon says so once the
    /// command waits for a pending request or its turn.
    fn waits(&self) {
        assert!(
            self.says("Waiting for your phone", 10),
            "the command waits: {:?}",
            self.err.lock().unwrap()
        );
    }

    fn kill(&mut self) {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
    }

    /// Its exit code, stdout and stderr; fails when it takes more than `secs` seconds.
    fn finish(mut self, secs: u64, what: &str) -> (i32, String, String) {
        let mut code = None;
        for _ in 0..secs * 10 {
            if let Some(s) = self.child.try_wait().unwrap() {
                code = Some(s.code().unwrap_or(-1));
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        let Some(code) = code else {
            let _ = self.child.kill();
            let _ = self.child.wait();
            panic!(
                "{what} did not finish within {secs} s: {:?}",
                self.err.lock().unwrap()
            );
        };
        for r in self.readers.drain(..) {
            r.join().unwrap();
        }
        let out = self.out.lock().unwrap().clone();
        let err = self.err.lock().unwrap().clone();
        (code, out, err)
    }
}

/// `sealctl open` started.
fn start_open(env: &Env) -> Started {
    let mut c = env.cmd();
    c.arg("open");
    start(c)
}

/// One request on the daemon socket from another thread: everything it got back. Gives up
/// after 20 seconds.
fn daemon_in_thread(env: &Env, op: Value) -> std::thread::JoinHandle<String> {
    let sock = env.h().join("s/sealctl/daemon.sock");
    let mut op = op;
    op["v"] = json!(1);
    op["cli"] = json!(env!("CARGO_PKG_VERSION"));
    std::thread::spawn(move || {
        let mut s = UnixStream::connect(sock).unwrap();
        s.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
        s.write_all(format!("{op}\n").as_bytes()).unwrap();
        let mut all = String::new();
        let _ = s.read_to_string(&mut all);
        all
    })
}

/// The last line a [`daemon_in_thread`] request got: its answer.
fn answer_of(all: &str) -> Value {
    serde_json::from_str(all.lines().last().unwrap_or("null")).unwrap_or(Value::Null)
}

#[test]
fn an_agent_answer_that_arrives_after_a_lock_grants_nothing() {
    let mut env = Env::fake(Options::default());
    env.pair();
    open_with_secret(&env);
    // an agent asks while the session is Open; the phone has not answered when it locks
    let agent = start(agent_cmd(&env));
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    let (code, _, err) = run_within(&env, &["lock"], 10);
    assert_eq!(code, 0, "{err}");
    // the session the use was asked for is gone: the answer adds it to no session, and the
    // store key went with the lock
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    let (code, out, _) = agent.finish(10, "the agent");
    assert_ne!(code, 0, "the agent got nothing");
    assert!(!out.contains("ran="));
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "locked", "{st}");
    assert_eq!(st["keysHeld"], 0, "{st}");

    // the next session does not inherit that agent use
    let ((code, _, err), log) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Open"]);
    let ((code, err), log) = env.with_phone(Answer::Session, || agent_run(&env));
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        log,
        vec!["Agent"],
        "the agent is asked for again in the new session"
    );
}

/// A `keys` request for a volume the session does not hold yet.
fn keys_op(env: &Env) -> Value {
    json!({"op": "keys", "items": [{"p": "volume", "i": "vol-late", "w": env.phone.fingerprint()}]})
}

/// A `keys` request is on the phone when the session locks, and the phone grants it for the
/// session after: the command that asked gets the keys (SPEC 6.3), the session that is gone
/// keeps nothing.
#[test]
fn a_keys_answer_that_arrives_after_a_lock_is_not_kept() {
    let mut env = Env::fake(Options::default());
    env.pair();
    open_with_secret(&env);
    let held = daemon(&env, json!({"op": "status"}))["keysHeld"].clone();
    let asker = daemon_in_thread(&env, keys_op(&env));
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    let (code, _, err) = run_within(&env, &["lock"], 10);
    assert_eq!(code, 0, "{err}");
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    let all = asker.join().unwrap();
    assert_eq!(answer_of(&all)["ok"], true, "the command that asked: {all}");
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "locked", "{st}");
    assert_eq!(st["keysHeld"], 0, "nothing held while Locked (was {held}): {st}");
}

/// Test hold points of the daemon (`test-hooks`): the daemon stops at `point` until
/// [`release`] removes the file. A `test-held-<point>` marker of an earlier hold is removed
/// first, so [`held`] waits for this one.
#[cfg(feature = "test-hooks")]
fn hold(env: &Env, point: &str) {
    let dir = env.h().join("s/sealctl");
    std::fs::create_dir_all(&dir).unwrap();
    let _ = std::fs::remove_file(dir.join(format!("test-held-{point}")));
    std::fs::write(dir.join(format!("test-hold-{point}")), b"").unwrap();
}

/// Waits until the daemon stopped at `point`.
#[cfg(feature = "test-hooks")]
fn held(env: &Env, point: &str) -> bool {
    until(20, || {
        env.h().join(format!("s/sealctl/test-held-{point}")).exists()
    })
}

/// Lets the daemon go on from `point`; it removes its `test-held-<point>` marker as it goes.
#[cfg(feature = "test-hooks")]
fn release(env: &Env, point: &str) {
    std::fs::remove_file(env.h().join(format!("s/sealctl/test-hold-{point}"))).unwrap();
    assert!(
        until(20, || !env
            .h()
            .join(format!("s/sealctl/test-held-{point}"))
            .exists()),
        "the daemon went on from {point}"
    );
}

/// The phone's answer is in the daemon's hands when the session locks (the hold point makes
/// the race certain). A `session` grant answered for a session that locked meanwhile serves
/// the command that asked only: nothing stays in the daemon, and no session opens.
#[cfg(feature = "test-hooks")]
#[test]
fn a_session_answer_that_crosses_a_lock_serves_only_its_command() {
    let mut env = Env::fake(Options::default());
    env.pair();
    open_with_secret(&env);
    hold(&env, "reply");
    let asker = daemon_in_thread(&env, keys_op(&env));
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    assert!(held(&env, "reply"), "the daemon has the answer");
    let (code, _, err) = run_within(&env, &["lock"], 10);
    assert_eq!(code, 0, "{err}");
    release(&env, "reply");
    let all = asker.join().unwrap();
    assert_eq!(answer_of(&all)["ok"], true, "the command that asked: {all}");
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "locked", "{st}");
    assert_eq!(st["keysHeld"], 0, "the key is not kept: {st}");

    // the same for a person's secret, asked while Locked: the `open` granted for the session
    // after a lock serves this command once
    hold(&env, "reply");
    let mut c = env.cmd();
    c.args(["run", "-e", "K=shop/key", "--", "sh", "-c", "echo ran=$K"]);
    let run = start(c);
    let r = next_request(&env, &mut seen);
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    assert!(held(&env, "reply"), "the daemon has the second answer");
    let (code, _, err) = run_within(&env, &["lock"], 10);
    assert_eq!(code, 0, "{err}");
    release(&env, "reply");
    let (code, out, err) = run.finish(10, "sealctl run");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ran="), "{out}");
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "locked", "no session opened: {st}");
    assert_eq!(st["keysHeld"], 0, "{st}");
}

/// `sealctl lock` while an open waits on the phone: the approval serves the command that
/// asked, once, and the session stays Locked (SPEC 6.3). The command that joined the open
/// finds no session and asks for itself.
#[test]
fn a_lock_while_an_open_waits_leaves_the_approval_with_its_command() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let opener = start_open(&env);
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    // another command joins the pending open
    let joiner = start_open(&env);
    joiner.waits();
    let (code, _, err) = run_within(&env, &["lock"], 10);
    assert_eq!(code, 0, "{err}");
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    let (code, out, err) = opener.finish(10, "the waiting open");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("Approved once"), "{out}");
    let r2 = next_request(&env, &mut seen);
    assert_ne!(r2.id, r.id, "the command that joined asks for itself");
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "waiting", "{st}");
    assert_eq!(st["keysHeld"], 0, "{st}");
    env.block(env.phone.auto(&r2, &Answer::Deny)).unwrap();
    let (code, _, err) = joiner.finish(10, "the command that joined");
    assert_eq!(code, 4, "{err}");
    assert_eq!(daemon(&env, json!({"op": "status"}))["state"], "locked");
}

#[test]
fn a_declined_open_ends_the_commands_that_joined_it() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let opener = start_open(&env);
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    let joiner = start_open(&env);
    joiner.waits();
    env.block(env.phone.auto(&r, &Answer::Deny)).unwrap();
    let (code, _, err) = opener.finish(10, "the declined open");
    assert_eq!(code, 4, "{err}");
    // the person said no once: the command that joined is told the same, not asked again
    let (code, _, err) = joiner.finish(10, "the command that joined");
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("Declined on your phone"), "{err}");
    assert!(env.block(env.phone.requests()).unwrap().is_empty());

    // a later command asks again
    let ((code, _, err), log) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Open"]);
}

/// A command that found the session Open waits only for another command's turn: a lock
/// meanwhile does not fail it with a wait for the phone it never had. It asks, or joins
/// the open that follows.
#[cfg(feature = "test-hooks")]
#[test]
fn a_command_that_found_the_session_open_goes_on_after_a_lock() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    hold(&env, "open-turn");
    let first = start_open(&env);
    assert!(held(&env, "open-turn"));
    // the second finds the turn taken on an Open session, and waits for it
    let second = start_open(&env);
    second.waits();
    let (code, _, err) = run_within(&env, &["lock"], 10);
    assert_eq!(code, 0, "{err}");
    release(&env, "open-turn");
    // the first finds the session Locked and asks; the second joins that open
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    let (code, _, err) = first.finish(10, "the first open");
    assert_eq!(code, 0, "{err}");
    let (code, _, err) = second.finish(10, "the second open");
    assert_eq!(code, 0, "{err}");
    assert!(env.block(env.phone.requests()).unwrap().is_empty());
    assert_eq!(daemon(&env, json!({"op": "status"}))["state"], "open");
}

#[test]
fn ctrl_c_of_the_asker_withdraws_its_request() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let mut opener = start_open(&env);
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    // a second command joins the pending open
    let joiner = start_open(&env);
    joiner.waits();
    opener.kill();
    assert!(
        until(5, || !listed(&env, &r.id)),
        "the request of a command that stopped is withdrawn"
    );
    // a late answer to it opens nothing
    let _ = env.block(env.phone.auto(&r, &Answer::Session));
    // the command that joined asks for itself
    let r2 = next_request(&env, &mut seen);
    assert_ne!(r2.id, r.id);
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "waiting", "{st}");
    assert_eq!(st["keysHeld"], 0, "{st}");
    env.block(env.phone.auto(&r2, &Answer::Session)).unwrap();
    let (code, _, err) = joiner.finish(10, "the command that joined");
    assert_eq!(code, 0, "{err}");
    assert_eq!(daemon(&env, json!({"op": "status"}))["state"], "open");
}

/// Waits until the phone holds a status from the machine (its channel is up).
fn channel_up(env: &Env, m: &sealctl_fakerelay::Machine) {
    assert!(until(10, || matches!(
        env.block(env.phone.status_of(m)),
        Ok(Some(_))
    )));
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[test]
fn a_lock_from_a_phone_whose_clock_is_behind_still_locks() {
    let mut env = Env::fake(Options::default());
    let m = env.pair();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    channel_up(&env, &m);
    let file = env.h().join("s/sealctl/answers.json");
    let answers = |name: &str| Remembered {
        agent: "claude".into(),
        repository: "github.com/o/r".into(),
        names: vec![name.into()],
        last: 0,
    };
    // a lock made half an hour before this session (held for the machine) is ignored; the
    // `answers` after it shows it was read
    let lock = || MessageKind::Lock {
        reason: "phone".into(),
    };
    env.block(env.phone.send_message_at(&m, lock(), now_ms() - 30 * 60_000))
        .unwrap();
    env.block(env.phone.send_message(
        &m,
        MessageKind::Answers {
            answers: vec![answers("marker")],
            more: false,
        },
    ))
    .unwrap();
    assert!(until(10, || std::fs::read_to_string(&file)
        .is_ok_and(|s| s.contains("marker"))));
    assert_eq!(daemon(&env, json!({"op": "status"}))["state"], "open");
    // a phone clock half a minute behind this machine's: Lock tapped now
    env.block(env.phone.send_message_at(&m, lock(), now_ms() - 30_000))
        .unwrap();
    assert!(
        until(10, || daemon(&env, json!({"op": "status"}))["state"] == "locked"),
        "the lock is applied"
    );
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["lockReason"], "Locked from your phone", "{st}");
}

#[test]
fn a_finished_delayed_action_leaves_the_pending_list() {
    use sealctl_core::wire::{Notice, NoticeReport};
    let mut env = Env::fake(Options::default());
    let m = env.pair();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    channel_up(&env, &m);
    let notice = |state: &str| MessageKind::Notice {
        notice: Notice {
            what: "unseal_all".into(),
            state: state.into(),
            machine: Some("tester@box.test".into()),
            delay: Some("-dLy1d".into()),
            at: Some(now_ms() + 3_600_000),
            report: (state == "done").then(|| NoticeReport {
                done: 1,
                to: vec!["keychain".into()],
                ..NoticeReport::default()
            }),
        },
    };
    let pending = || {
        daemon(&env, json!({"op": "status"}))["pending"]
            .as_array()
            .map_or(0, Vec::len)
    };
    env.block(env.phone.send_message(&m, notice("pending"))).unwrap();
    assert!(until(10, || pending() == 1));
    env.block(env.phone.send_message(&m, notice("done"))).unwrap();
    assert!(
        until(10, || pending() == 0),
        "a finished action is no longer pending"
    );

    // one whose relay record expired (15 minutes after `releaseAt`) while its `done` never
    // came is not pending either
    let stale = MessageKind::Notice {
        notice: Notice {
            what: "leave".into(),
            state: "pending".into(),
            machine: None,
            delay: Some("old".into()),
            at: Some(now_ms() - 16 * 60_000),
            report: None,
        },
    };
    env.block(env.phone.send_message(&m, stale)).unwrap();
    // one announced without its time (`at` null) is pending until it can have taken effect
    let untimed = MessageKind::Notice {
        notice: Notice {
            what: "words".into(),
            state: "pending".into(),
            machine: None,
            delay: Some("untimed".into()),
            at: None,
            report: None,
        },
    };
    env.block(env.phone.send_message(&m, untimed)).unwrap();
    env.block(env.phone.send_message(&m, notice("pending"))).unwrap();
    let ids = || -> Vec<String> {
        let st = daemon(&env, json!({"op": "status"}));
        let mut ids: Vec<String> = st["pending"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["id"].as_str().unwrap().to_string())
            .collect();
        ids.sort();
        ids
    };
    assert!(until(10, || ids().contains(&"-dLy1d".to_string())));
    assert_eq!(ids(), ["-dLy1d", "untimed"]);
}

/// The relay is slow to answer the machine socket's upgrade (up to the 10 s timeout): the
/// pairing is not held meanwhile, so a lock and its status to the phone go on at once.
#[test]
fn a_slow_machine_socket_does_not_hold_up_a_lock() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let relay = env.fake.as_ref().unwrap();
    relay.stall_machine_sockets(true);
    let tries = relay.machine_socket_tries();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["open"]));
    assert_eq!(code, 0, "{err}");
    assert!(
        until(10, || env.fake.as_ref().unwrap().machine_socket_tries() > tries),
        "the channel is connecting"
    );
    let (code, _, err) = run_within(&env, &["lock"], 5);
    env.fake.as_ref().unwrap().stall_machine_sockets(false);
    assert_eq!(code, 0, "{err}");
    assert_eq!(daemon(&env, json!({"op": "status"}))["state"], "locked");
}

#[test]
fn a_request_queued_behind_another_says_it_waits_for_the_phone() {
    let mut env = Env::fake(Options::default());
    env.pair();
    open_with_secret(&env);
    let first = start(agent_cmd(&env));
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    // the same agent again: its use is not covered yet, so it asks after the first request
    let second = start(agent_cmd(&env));
    assert!(
        second.says("Waiting for your phone", 5),
        "the second command shows that it waits"
    );
    // a session answer to the first covers the second
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    let (code, out, e) = first.finish(10, "the first agent");
    assert_eq!(code, 0, "{e}");
    assert!(out.contains("ran="));
    let (code, out, e) = second.finish(10, "the second agent");
    assert_eq!(code, 0, "{e}");
    assert!(out.contains("ran="));
    assert!(env.block(env.phone.requests()).unwrap().is_empty());
}

/// An agent's request waits for its turn behind another when the session locks. At its turn
/// the session it found Open is gone: it ends there, and the phone is never asked for uses of
/// a Locked session.
#[test]
fn a_request_queued_when_the_session_locks_does_not_reach_the_phone() {
    let mut env = Env::fake(Options::default());
    env.pair();
    open_with_secret(&env);
    let first = start(agent_cmd(&env));
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    let second = start(agent_cmd(&env));
    second.waits();
    let (code, _, err) = run_within(&env, &["lock"], 10);
    assert_eq!(code, 0, "{err}");
    env.block(env.phone.auto(&r, &Answer::Session)).unwrap();
    let (code, out, _) = first.finish(10, "the first agent");
    assert_ne!(code, 0, "the answer came after the lock");
    assert!(!out.contains("ran="));
    let (code, out, err) = second.finish(10, "the queued agent");
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("The session locked while this command waited"),
        "{err}"
    );
    assert!(!out.contains("ran="));
    assert!(
        env.block(env.phone.requests()).unwrap().is_empty(),
        "no request for a Locked session"
    );
    assert_eq!(daemon(&env, json!({"op": "status"}))["state"], "locked");
}

#[test]
fn a_person_is_not_held_up_by_an_agent_request_on_the_phone() {
    let mut env = Env::fake(Options::default());
    env.pair();
    open_with_secret(&env);
    let agent = agent_cmd(&env)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    // the session is Open: a person's use needs no phone, and does not wait for the agent's
    let person = env
        .cmd()
        .args(["run", "-e", "K=shop/key", "--", "sh", "-c", "echo ran=$K"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let (code, out, err) = within(person, 10, "a person's sealctl run");
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ran="), "{out}");
    assert!(daemon(&env, json!({"op": "status"}))["state"] == "waiting");
    env.block(env.phone.auto(&r, &Answer::Deny)).unwrap();
    let (code, _, _) = within(agent, 10, "the declined agent");
    assert_eq!(code, 4);
}

#[test]
fn a_lock_message_while_a_request_waits_locks_at_once() {
    let mut env = Env::fake(Options::default());
    let m = env.pair();
    open_with_secret(&env);
    channel_up(&env, &m);
    let agent = agent_cmd(&env)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    env.block(env.phone.send_message(
        &m,
        MessageKind::Lock {
            reason: "place".into(),
        },
    ))
    .unwrap();
    assert!(
        until(10, || daemon(&env, json!({"op": "status"}))["keysHeld"] == 0),
        "the lock message is applied while the agent's request waits"
    );
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["lockReason"], "Locked: your phone left the place", "{st}");
    let _ = env.block(env.phone.auto(&r, &Answer::Deny));
    let (code, out, _) = within(agent, 10, "the agent");
    assert_ne!(code, 0);
    assert!(!out.contains("ran="));
}

#[test]
fn a_daemon_that_restarts_while_an_open_waits_withdraws_it() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let opener = env
        .cmd()
        .arg("open")
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    // a command of another version makes the daemon exit
    let a = daemon(&env, json!({"op": "status", "cli": "0.0.0-other"}));
    assert_eq!(a["ok"], false, "{a}");
    assert!(until(10, || !listed(&env, &r.id)), "the open is withdrawn");
    let _ = env.block(env.phone.auto(&r, &Answer::Session));
    let (code, _, _) = within(opener, 10, "the waiting open");
    assert_ne!(code, 0);
    // the next command starts a new daemon, Locked, which asks again
    let ((code, _, err), log) = env.with_phone(Answer::Deny, || env.run(&["open"]));
    assert_eq!(code, 4, "{err}");
    assert_eq!(log, vec!["Open"]);
}

/// The machine sleeps past a request's 5 minutes (fake clock: the wall clock moves on, the
/// monotonic one stands still, as in a suspend). The request expired on the relay meanwhile, so
/// the wait ends soon after waking instead of waiting out 5 more awake minutes.
#[cfg(feature = "test-hooks")]
#[test]
fn a_wait_ends_after_the_machine_slept_past_it() {
    let mut env = Env::fake(Options::default());
    env.pair();
    let opener = start_open(&env);
    let mut seen = Vec::new();
    let r = next_request(&env, &mut seen);
    // a short sleep changes nothing
    let ahead = env.h().join("s/sealctl/test-clock-ahead-ms");
    std::fs::write(&ahead, (4 * 60_000).to_string()).unwrap();
    std::thread::sleep(Duration::from_millis(1500));
    assert!(listed(&env, &r.id), "still waiting");
    // past the 5 minutes
    std::fs::write(&ahead, (6 * 60_000).to_string()).unwrap();
    let (code, _, err) = opener.finish(10, "the open asked before the sleep");
    assert_eq!(code, 5, "{err}");
    assert!(until(5, || !listed(&env, &r.id)));
    std::fs::remove_file(&ahead).unwrap();
    let st = daemon(&env, json!({"op": "status"}));
    assert_eq!(st["state"], "locked", "{st}");
}

#[test]
fn a_daemon_stopped_by_its_service_manager_locks_first() {
    // the service manager stops the daemon with SIGTERM (logout, `systemctl stop`)
    if cfg!(not(target_os = "linux")) && !common::have("lsof") {
        return;
    }
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
    let pid = daemon_pid(&env);
    assert!(!pid.is_empty(), "the daemon's pid");
    let killed = std::process::Command::new("kill")
        .args(["-TERM", &pid])
        .status()
        .unwrap();
    assert!(killed.success());
    let mut gone = false;
    for _ in 0..100 {
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid])
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        if !alive {
            gone = true;
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    assert!(gone, "the daemon exits");
    assert!(session("locked"), "the phone hears the session lock");
}
