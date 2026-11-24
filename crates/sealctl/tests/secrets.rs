//! Secrets, `sealctl run` and agents (SPEC 9, 10.2, 10.3, 11) through the daemon, against the
//! fake relay or the live one (`SEALCTL_TEST_RELAY`).

mod common;

use common::{canary, Env};
use sealctl_fakerelay::Answer;

#[test]
fn secrets_run_and_agents() {
    let mut env = Env::new();
    env.pair();
    let value = canary();

    // storing opens the session: one tap (the phone grants `session`)
    let ((code, _, err), log) = env.with_phone(Answer::Session, || {
        env.run_in(
            &["secret", "set", "shop/api-key"],
            format!("{value}\n").as_bytes(),
        )
    });
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("Waiting for your phone"), "{err}");
    assert!(err.contains("Stored shop/api-key"), "{err}");
    assert_eq!(log, vec!["Open"], "{log:?}");
    // the store: .id file and one .sealed file, nothing in plain text
    let store_root = env.h().join(".local/share/sealctl/store");
    let store = std::fs::read_dir(&store_root)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    let id = store.file_name().unwrap().to_string_lossy().into_owned();
    let idf: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(store.join(format!("{id}.id"))).unwrap()).unwrap();
    assert_eq!(idf["words"], env.phone.fingerprint());
    let sealed = std::fs::read(store.join("shop/api-key.sealed")).unwrap();
    assert_eq!(&sealed[..4], b"SCS1");
    assert!(!String::from_utf8_lossy(&sealed).contains(&value));

    // listing needs no key and no phone
    let (code, out, _) = env.run(&["secret", "ls"]);
    assert_eq!(code, 0);
    assert_eq!(out.trim(), "shop/api-key");

    // Open: a person's run asks nothing; output to a pipe is masked
    let (code, out, err) = env.run(&[
        "run",
        "-e",
        "K=shop/api-key",
        "--",
        "sh",
        "-c",
        "echo got=$K; test \"$K\" = \"$WANT\"",
    ]);
    let _ = err;
    assert_eq!(
        code, 1,
        "WANT is unset in the child, so test fails but the value was there"
    );
    assert!(out.contains("got=****"), "{out}");
    assert!(!out.contains(&value));
    let mut c = env.cmd();
    c.env("WANT", &value).args([
        "run",
        "-e",
        "K=shop/api-key",
        "--",
        "sh",
        "-c",
        "test \"$K\" = \"$WANT\"",
    ]);
    let o = c.output().unwrap();
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert!(String::from_utf8_lossy(&o.stderr).contains("sealctl: K ← shop/api-key"));

    // .sealctl.toml mappings, once the file is trusted (tests/project.rs)
    std::fs::write(env.h().join(".sealctl.toml"), "[env]\nK = \"shop/api-key\"\n").unwrap();
    let (code, _, err) = env.run(&["project", "trust"]);
    assert_eq!(code, 0, "{err}");
    let mut c = env.cmd();
    c.env("WANT", &value)
        .args(["run", "--", "sh", "-c", "test \"$K\" = \"$WANT\""]);
    assert!(c.output().unwrap().status.success());

    // an agent's first use in this folder asks the phone (`agent`), then not again
    let ((code, out, err), log) = env.with_phone(Answer::Session, || {
        let mut c = env.cmd();
        c.env("SEALCTL_AGENT", "")
            .env("CLAUDECODE", "1")
            .args(["run", "--", "sh", "-c", "echo agent=$K"]);
        let o = c.output().unwrap();
        (
            o.status.code().unwrap(),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    });
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("agent=****"), "{out}");
    assert!(err.contains("Waiting for your phone"), "{err}");
    assert_eq!(log, vec!["Agent"]);
    let mut c = env.cmd();
    c.env("SEALCTL_AGENT", "")
        .env("CLAUDECODE", "1")
        .args(["run", "--", "sh", "-c", "echo again=$K"]);
    let o = c.output().unwrap();
    assert!(String::from_utf8_lossy(&o.stdout).contains("again=****"));
    assert!(
        !String::from_utf8_lossy(&o.stderr).contains("Waiting"),
        "allowed for the session"
    );

    // agents never get values
    let mut c = env.cmd();
    c.env("SEALCTL_AGENT", "")
        .env("CLAUDECODE", "1")
        .args(["secret", "get", "shop/api-key"]);
    let o = c.output().unwrap();
    assert_eq!(o.status.code(), Some(8));
    assert!(!String::from_utf8_lossy(&o.stdout).contains(&value));
    // a script (pipe) gets the exact bytes
    let (code, out, _) = env.run(&["secret", "get", "shop/api-key"]);
    assert_eq!(code, 0);
    assert_eq!(out, value);

    // rename and remove
    let (code, _, err) = env.run(&["secret", "mv", "shop/api-key", "shop/key2"]);
    assert_eq!(code, 0, "{err}");
    let (_, out, _) = env.run(&["secret", "get", "shop/key2"]);
    assert_eq!(out, value);
    let (code, _, _) = env.run(&["secret", "get", "shop/api-key"]);
    assert_eq!(code, 9);
    let (code, _, _) = env.run(&["secret", "rm", "shop/key2", "--yes"]);
    assert_eq!(code, 0);

    // lock: then the next use asks again; a decline is exit 4
    let (code, out, _) = env.run(&["lock"]);
    assert_eq!(code, 0);
    assert!(out.contains("Locked."));
    let ((code, _, err), _) =
        env.with_phone(Answer::Deny, || env.run_in(&["secret", "set", "shop/x"], b"y\n"));
    assert_eq!(code, 4, "{err}");
    assert!(err.contains("sealctl: Declined on your phone."), "{err}");

    // no value in any file under the state and config folders
    for dir in [env.h().join("s"), env.h().join(".config")] {
        for e in walk(&dir) {
            let t = std::fs::read(&e).unwrap_or_default();
            assert!(
                !String::from_utf8_lossy(&t).contains(&value),
                "value in {}",
                e.display()
            );
        }
    }
}

#[test]
fn own_approval_asks_every_time() {
    let mut env = Env::new();
    env.pair();
    let value = canary();
    let ((code, _, err), log) = env.with_phone(Answer::Session, || {
        env.run_in(
            &["secret", "set", "deploy/token", "--own-approval"],
            value.as_bytes(),
        )
    });
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("(asks your phone on every use)"), "{err}");
    assert_eq!(log, vec!["Open", "Keys"], "{log:?}");
    let (_, out, _) = env.run(&["secret", "ls"]);
    assert!(out.contains("deploy/token  own approval"), "{out}");
    for _ in 0..2 {
        let ((code, out, err), log) =
            env.with_phone(Answer::Once, || env.run(&["secret", "get", "deploy/token"]));
        assert_eq!(code, 0, "{err}");
        assert_eq!(out, value);
        assert_eq!(log, vec!["Own"]);
    }
}

#[test]
fn no_daemon_mode() {
    let mut env = Env::new();
    env.pair();
    let value = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let mut c = env.cmd();
        c.env("SEALCTL_NO_DAEMON", "1")
            .args(["secret", "set", "ci/token"])
            .stdin(std::process::Stdio::piped());
        let mut ch = c
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        ch.stdin.take().unwrap().write_all(value.as_bytes()).unwrap();
        let o = ch.wait_with_output().unwrap();
        (
            o.status.code().unwrap(),
            String::new(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    });
    assert_eq!(code, 0, "{err}");
    assert!(
        !env.h().join("s/sealctl/daemon.sock").exists(),
        "no daemon was started"
    );
}

fn walk(d: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

/// `seal env --delete` removes the file only when every variable in it is stored: CR-only and
/// mixed line endings are read in full, and an unreadable or partly stored file is kept.
#[test]
fn seal_env_delete_never_drops_a_variable() {
    let mut env = Env::new();
    env.pair();
    let a = canary();
    let b = canary();
    let c = canary();
    let cases = [
        ("cr", format!("A_KEY={a}\rB_KEY=\"{b}\"\r# note\rC_KEY={c}\r")),
        ("mixed", format!("A_KEY={a}\r\nB_KEY='{b}'\rC_KEY={c}\n")),
    ];
    for (prefix, text) in &cases {
        let file = env.h().join(format!("{prefix}.env"));
        std::fs::write(&file, text).unwrap();
        let ((code, _, err), _) = env.with_phone(Answer::Session, || {
            env.run(&[
                "seal",
                "env",
                file.to_str().unwrap(),
                "--prefix",
                prefix,
                "--delete",
            ])
        });
        assert_eq!(code, 0, "{prefix}: {err}");
        assert!(!file.exists(), "{prefix}: the file is removed once all is stored");
        for (k, v) in [("a-key", &a), ("b-key", &b), ("c-key", &c)] {
            let (code, out, err) = env.run(&["secret", "get", &format!("{prefix}/{k}")]);
            assert_eq!(code, 0, "{prefix}/{k}: {err}");
            assert_eq!(&out, v, "{prefix}/{k}");
        }
    }

    // an unreadable line: nothing stored, the file kept
    let file = env.h().join("bad.env");
    let text = format!("X_KEY={a}\rnot an assignment\rY_KEY={b}\r");
    std::fs::write(&file, &text).unwrap();
    let (code, _, err) = env.run(&[
        "seal",
        "env",
        file.to_str().unwrap(),
        "--prefix",
        "bad",
        "--delete",
    ]);
    assert_ne!(code, 0);
    assert!(err.contains("Nothing was stored"), "{err}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
    let (_, out, _) = env.run(&["secret", "ls"]);
    assert!(!out.contains("bad/"), "{out}");

    // an empty value is not stored, so its line would be lost: the file is kept
    let file = env.h().join("empty.env");
    let text = format!("Z_KEY={a}\rEMPTY_KEY=\r");
    std::fs::write(&file, &text).unwrap();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "seal",
            "env",
            file.to_str().unwrap(),
            "--prefix",
            "empty",
            "--delete",
        ])
    });
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("is kept: EMPTY_KEY empty and not stored"), "{err}");
    assert_eq!(std::fs::read_to_string(&file).unwrap(), text);
}

/// The credential helpers inside an agent (SPEC 10.6, 11): git and the AWS CLI get the
/// credential; the agent calling the helper itself, from its shell or through `sh -c`, is refused
/// with exit 8 and no value, whether stdout is a pipe or not.
#[test]
fn credential_helpers_answer_only_git_and_aws_inside_agents() {
    let mut env = Env::new();
    env.pair();
    let token = canary();
    let aws_secret = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(&["secret", "set", "git/example.test"], token.as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    let aws_json = format!(r#"{{"aws_access_key_id":"AKIDEXAMPLE","aws_secret_access_key":"{aws_secret}"}}"#);
    let (code, _, err) = env.run_in(&["secret", "set", "aws/default"], aws_json.as_bytes());
    assert_eq!(code, 0, "{err}");

    let sealctl = env!("CARGO_BIN_EXE_sealctl");
    // `prog args` with this HOME's environment (as `env.cmd()` sets it), inside an agent
    let in_agent = |prog: &str, args: &[&str]| {
        let mut c2 = std::process::Command::new(prog);
        c2.env_clear();
        for (k, v) in env.cmd().get_envs() {
            if let Some(v) = v {
                c2.env(k, v);
            }
        }
        c2.env("SEALCTL_AGENT", "")
            .env("CLAUDECODE", "1")
            .env("SEALCTL_BIN", sealctl);
        c2.current_dir(env.h()).args(args);
        let mut ch = c2
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        use std::io::Write;
        let _ = ch
            .stdin
            .take()
            .unwrap()
            .write_all(b"protocol=https\nhost=example.test\n\n");
        let o = ch.wait_with_output().unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };

    // directly, as an agent's tool call would (stdout a pipe)
    for args in [
        &[sealctl, "git", "credential", "get"][..],
        &[sealctl, "aws", "credentials", "--profile", "default"][..],
    ] {
        let (code, out, err) = in_agent(args[0], &args[1..]);
        assert_eq!(code, 8, "{args:?}: {out} {err}");
        assert!(out.is_empty(), "{args:?}: {out}");
        assert!(err.contains("Not inside an AI agent"), "{err}");
    }
    // through a shell
    let (code, out, err) = in_agent("/bin/sh", &["-c", "\"$SEALCTL_BIN\" git credential get; echo"]);
    assert!(!out.contains(&token), "{code} {out} {err}");
    assert!(err.contains("Not inside an AI agent"), "{err}");

    // git and the AWS CLI themselves: stand-ins whose executables are named git-remote-https
    // and aws (copies of this test binary, see `stand_in_spawner`) start the helper from a
    // script, as git does. One named plain `git` is refused: that program only relays.
    let bin = env.h().join("toolbin");
    std::fs::create_dir_all(&bin).unwrap();
    let me = std::env::current_exe().unwrap();
    for name in ["git-remote-https", "aws", "git"] {
        std::fs::copy(&me, bin.join(name)).unwrap();
    }
    for (tool, line, want) in [
        (
            "git-remote-https",
            "printf 'protocol=https\\nhost=example.test\\n\\n' | \"$SEALCTL_BIN\" git credential get",
            format!("username=x-access-token\npassword={token}\n"),
        ),
        (
            "aws",
            "\"$SEALCTL_BIN\" aws credentials --profile default",
            aws_secret.clone(),
        ),
        (
            "git",
            "printf 'protocol=https\\nhost=example.test\\n\\n' | \"$SEALCTL_BIN\" git credential get",
            String::new(),
        ),
    ] {
        let script = env.h().join(format!("{tool}.sh"));
        std::fs::write(&script, format!("{line}\nexit $?\n")).unwrap();
        let out_file = env.h().join(format!("{tool}.out"));
        let ((code, _, err), _) = env.with_phone(Answer::Session, || {
            let mut c = std::process::Command::new(bin.join(tool));
            c.env_clear();
            for (k, v) in env.cmd().get_envs() {
                if let Some(v) = v {
                    c.env(k, v);
                }
            }
            let o = c
                .env("SEALCTL_AGENT", "")
                .env("CLAUDECODE", "1")
                .env("SEALCTL_BIN", sealctl)
                .env("SEALCTL_TEST_SPAWN", &script)
                .env("SEALCTL_TEST_SPAWN_OUT", &out_file)
                .args(["stand_in_spawner", "--exact", "--test-threads=1", "-q"])
                .stdin(std::process::Stdio::null())
                .output()
                .unwrap();
            (
                o.status.code().unwrap_or(-1),
                String::new(),
                String::from_utf8_lossy(&o.stderr).into_owned(),
            )
        });
        let out = std::fs::read_to_string(&out_file).unwrap();
        if tool == "git" {
            // the `git` program itself only relays (an alias, a pager, a hook): refused
            assert_eq!(code, 8, "{tool}: {err}");
            assert!(!out.contains(&token), "{tool}: {out}");
            continue;
        }
        assert_eq!(code, 0, "{tool}: {err}");
        assert!(out.contains(&want), "{tool}: {out}");
    }

    // outside an agent nothing changes: a script gets the credential from a pipe
    let (code, out, err) = env.run(&["aws", "credentials", "--profile", "default"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains(&aws_secret));
}

/// Not a test on its own: with `SEALCTL_TEST_SPAWN` set, this process (a copy of the test binary
/// named like git or the AWS CLI) runs that script as its child, its stdout to
/// `SEALCTL_TEST_SPAWN_OUT`, and exits with the child's code.
#[test]
fn stand_in_spawner() {
    let Some(script) = std::env::var_os("SEALCTL_TEST_SPAWN") else {
        return;
    };
    let out = std::fs::File::create(std::env::var_os("SEALCTL_TEST_SPAWN_OUT").unwrap()).unwrap();
    let st = std::process::Command::new("/bin/sh")
        .arg(script)
        .stdin(std::process::Stdio::null())
        .stdout(out)
        .status()
        .unwrap();
    std::process::exit(st.code().unwrap_or(1));
}

/// `SEALCTL_AGENT=0` turns agent detection off; when an agent's own variable is set as well,
/// stderr says so, once per process.
#[test]
fn agent_detection_off_is_said_when_an_agent_runs() {
    let env = Env::fake(Default::default());
    let notice = "sealctl: agent detection is off (SEALCTL_AGENT=0) although Claude Code is running";
    let run = |vars: &[(&str, &str)], args: &[&str]| {
        let mut c = env.cmd();
        c.env_remove("SEALCTL_AGENT");
        for (k, v) in vars {
            c.env(k, v);
        }
        let o = c.args(args).stdin(std::process::Stdio::null()).output().unwrap();
        String::from_utf8_lossy(&o.stderr).into_owned()
    };
    // every command says it, once also when it asks who is reading several times
    for args in [
        &["status"][..],
        &["run", "--", "true"][..],
        &["secret", "get", "x/y"][..],
        &["git", "credential", "get"][..],
    ] {
        let err = run(&[("SEALCTL_AGENT", "0"), ("CLAUDECODE", "1")], args);
        assert_eq!(err.matches(notice).count(), 1, "{args:?}: {err}");
        // detection stays off: not refused as an agent
        assert!(!err.contains("inside Claude Code"), "{args:?}: {err}");
        // no agent variable: nothing to say
        let err = run(&[("SEALCTL_AGENT", "0")], args);
        assert!(!err.contains("agent detection is off"), "{args:?}: {err}");
        // detection on: nothing to say either
        let err = run(&[("CLAUDECODE", "1")], args);
        assert!(!err.contains("agent detection is off"), "{args:?}: {err}");
    }
}
