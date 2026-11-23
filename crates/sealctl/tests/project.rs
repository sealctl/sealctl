//! Project files trusted on first use (SPEC 10.3): `sealctl run` asks at a terminal the first
//! time it uses a `.sealctl.toml` and again after every change, refuses without a terminal until
//! `sealctl project trust`; files sealctl writes itself are trusted; an agent never trusts one.

mod common;

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use common::{canary, Env, Pty};
use sealctl_fakerelay::Answer;

/// A paired machine with an Open session and the secret `shop/api-key`.
fn open_env() -> Env {
    let mut env = Env::new();
    env.pair();
    let value = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(
            &["secret", "set", "shop/api-key"],
            format!("{value}\n").as_bytes(),
        )
    });
    assert_eq!(code, 0, "{err}");
    env
}

/// A folder `name` under HOME holding a `.sealctl.toml` with `text`.
fn repo(env: &Env, name: &str, text: &str) -> PathBuf {
    let dir = env.h().join(name);
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".sealctl.toml"), text).unwrap();
    dir
}

/// `sealctl args` in `dir` without a terminal, with `vars` set.
fn run_in(env: &Env, dir: &Path, vars: &[(&str, &str)], args: &[&str]) -> (i32, String, String) {
    let mut c = env.cmd();
    c.current_dir(dir).args(args).stdin(Stdio::null());
    for (k, v) in vars {
        c.env(k, v);
    }
    let o = c.output().unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// `sealctl run` of a program that prints `ran` when it gets `K`, on a terminal in `dir`.
fn run_on_terminal(env: &Env, dir: &Path) -> Pty {
    let mut c = env.cmd();
    c.current_dir(dir)
        .args(["run", "--", "sh", "-c", "test -n \"$K\" && echo ran"]);
    Pty::spawn(c)
}

fn trust_list(env: &Env) -> String {
    std::fs::read_to_string(env.h().join("s/sealctl/projects.json")).unwrap_or_default()
}

const AGENT: &[(&str, &str)] = &[("SEALCTL_AGENT", ""), ("CLAUDECODE", "1")];

#[test]
fn first_use_asks_and_a_change_asks_again() {
    let env = open_env();
    let dir = repo(
        &env,
        "shop",
        "[env]\nK = \"shop/api-key\"\n\n[command.\"make deploy\"]\nT = \"shop/api-key\"\n",
    );

    // first use: the names it maps, then the question; yes runs the program
    let pty = run_on_terminal(&env, &dir);
    let screen = pty.expect("Trust this file? [y/N]", Duration::from_secs(30));
    assert!(
        screen.contains("shop/.sealctl.toml is new on this machine"),
        "{screen}"
    );
    assert!(screen.contains("K ← shop/api-key"), "{screen}");
    assert!(screen.contains("T ← shop/api-key  (for make deploy)"), "{screen}");
    pty.line("y");
    let (code, out, screen) = pty.wait(Duration::from_secs(60));
    assert_eq!(code, 0, "{screen}");
    assert!(out.contains("ran"), "{out}");

    // recorded in the state folder: path, hash and time, no names
    let list: serde_json::Value = serde_json::from_str(&trust_list(&env)).unwrap();
    let t = &list["projects"][0];
    let canon = std::fs::canonicalize(dir.join(".sealctl.toml")).unwrap();
    assert_eq!(t["path"], canon.display().to_string());
    assert_eq!(t["sha256"].as_str().unwrap().len(), 64);
    assert!(t["trusted"].is_string());
    assert!(!trust_list(&env).contains("shop/api-key"));

    // trusted as it is: no question, and no terminal needed
    let (code, out, err) = run_in(
        &env,
        &dir,
        &[],
        &["run", "--", "sh", "-c", "test -n \"$K\" && echo ran"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ran"), "{out}");

    // a change asks again; without a terminal it is refused
    std::fs::write(
        dir.join(".sealctl.toml"),
        "[env]\nK = \"shop/api-key\"\nL = \"shop/other\"\n",
    )
    .unwrap();
    let (code, out, err) = run_in(&env, &dir, &[], &["run", "--", "sh", "-c", "echo ran"]);
    assert_eq!(code, 8, "{err}");
    assert!(
        err.contains("changed since it was trusted on this machine"),
        "{err}"
    );
    assert!(err.contains("trust it once: sealctl project trust "), "{err}");
    assert!(!out.contains("ran"), "{out}");
    let pty = run_on_terminal(&env, &dir);
    let screen = pty.expect("Trust this file? [y/N]", Duration::from_secs(30));
    assert!(screen.contains("changed since it was trusted"), "{screen}");
    assert!(screen.contains("L ← shop/other"), "{screen}");
    pty.line("n");
    let (code, out, screen) = pty.wait(Duration::from_secs(30));
    assert_eq!(code, 1, "{screen}");
    assert!(screen.contains("Not trusted; nothing was run."), "{screen}");
    assert!(!out.contains("ran"), "{out}");
}

#[test]
fn without_a_terminal_it_is_refused_until_trusted() {
    let env = open_env();
    let dir = repo(&env, "cloned", "[env]\nK = \"shop/api-key\"\n");
    let (code, out, err) = run_in(&env, &dir, &[], &["run", "--", "sh", "-c", "echo ran"]);
    assert_eq!(code, 8, "{err}");
    assert!(
        err.contains("cloned/.sealctl.toml is new on this machine; nothing was run."),
        "{err}"
    );
    assert!(err.contains("sealctl project trust"), "{err}");
    assert!(!out.contains("ran"));
    // -e alone, or --no-project, needs no trust
    let (code, out, err) = run_in(
        &env,
        &dir,
        &[],
        &[
            "run",
            "--no-project",
            "-e",
            "K=shop/api-key",
            "--",
            "sh",
            "-c",
            "test -n \"$K\" && echo ran",
        ],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ran"));

    // the one-time way: sealctl project trust (no terminal needed), from a folder below
    let below = dir.join("src");
    std::fs::create_dir_all(&below).unwrap();
    let (code, _, err) = run_in(&env, &below, &[], &["project", "trust"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("K ← shop/api-key"), "{err}");
    assert!(err.contains("cloned/.sealctl.toml."), "{err}");
    let (code, out, err) = run_in(
        &env,
        &below,
        &[],
        &["run", "--", "sh", "-c", "test -n \"$K\" && echo ran"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ran"));
    // a path that has no project file
    let (code, _, _) = run_in(&env, env.h(), &[], &["project", "trust", "/nonexistent/x"]);
    assert_eq!(code, 9);
}

#[test]
fn files_sealctl_writes_are_trusted() {
    let env = open_env();
    let value = canary();
    let dir = env.h().join("app");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join(".env"), format!("A_KEY={value}\n")).unwrap();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        run_in(
            &env,
            &dir,
            &[],
            &["seal", "env", ".env", "--prefix", "app", "--delete"],
        )
    });
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = run_in(
        &env,
        &dir,
        &[("WANT", &value)],
        &["run", "--", "sh", "-c", "test \"$A_KEY\" = \"$WANT\" && echo ran"],
    );
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("ran"), "{out}");

    // seal env into a project file that was there and not trusted (a cloned repository's):
    // the mappings it had are not trusted by the write
    let other = repo(&env, "cloned", "[env]\nX = \"shop/api-key\"\n");
    std::fs::write(other.join(".env"), format!("B_KEY={value}\n")).unwrap();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        run_in(&env, &other, &[], &["seal", "env", ".env", "--prefix", "cloned"])
    });
    assert_eq!(code, 0, "{err}");
    let toml = std::fs::read_to_string(other.join(".sealctl.toml")).unwrap();
    assert!(toml.contains("B_KEY") && toml.contains("X = "), "{toml}");
    let (code, _, err) = run_in(&env, &other, &[], &["run", "--", "true"]);
    assert_eq!(code, 8, "{err}");
    assert!(err.contains("is new on this machine"), "{err}");
}

#[test]
fn an_agent_cannot_trust_a_file() {
    let env = open_env();
    let dir = repo(&env, "shop", "[env]\nK = \"shop/api-key\"\n");
    for vars in [AGENT, &[("SEALCTL_AGENT", "1")]] {
        let (code, _, err) = run_in(&env, &dir, vars, &["project", "trust"]);
        assert_eq!(code, 8, "{err}");
        assert!(err.contains("Not inside an AI agent"), "{err}");
    }
    assert_eq!(trust_list(&env), "", "nothing recorded");

    // an agent's run goes to the phone as before (`agent`), and records nothing
    let ((code, out, err), log) = env.with_phone(Answer::Session, || {
        run_in(&env, &dir, AGENT, &["run", "--", "sh", "-c", "echo agent=$K"])
    });
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("agent=****"), "{out}");
    assert_eq!(log, vec!["Agent"]);
    assert_eq!(trust_list(&env), "", "nothing recorded");
    let (code, _, err) = run_in(&env, &dir, &[], &["run", "--", "true"]);
    assert_eq!(code, 8, "{err}");
}
