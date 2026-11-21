//! `sealctl unseal`: the plan on a fixture home made with the 0.5.0 code, `--dry-run` changing
//! nothing, and the refusals (AI agent, no terminal, usage). The real binary; a software key in
//! the session agent stands in for the Ledger.

mod common;

use common::{new_home, serial, text, FixtureOpts};

#[test]
fn dry_run_shows_the_plan_and_changes_nothing() {
    let _g = serial();
    let h = new_home();
    common::fixture(&h, &FixtureOpts::default());
    common::start_agent();
    let before = common::tree(&h.home);

    let out = h.unseal(
        &["--all", "--dry-run", "--to", "op", "--secrets-to", "env"],
        "",
        &[],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", text(&out));
    if std::env::var_os("SHOW_PLAN").is_some() {
        eprintln!("{err}");
    }
    for want in [
        "This hands everything sealctl 0.5 holds on",
        "Your files stay encrypted. Keys come from your Ledger",
        "New passwords go to: 1Password",
        "Secrets go to:       a .env file",
        "This file holds your keys in plain text, where AI agents can read them.",
        " 1  secrets      7 secrets",
        "ssh keys     2 keys                   \u{2192} ~/.ssh/ed25519, ~/.ssh/github with your own passphrase",
        "git          global + 1 repository    keeps signing with your key through ssh-keygen.",
        "AI tools     Claude Code, Codex",
        "local files",
        "last, by you",
        "Dry run: nothing was changed.",
    ] {
        assert!(err.contains(want), "missing {want:?} in:\n{err}");
    }
    // order: secrets, ssh, git, AI, (services,) local files
    let pos = |s: &str| err.find(s).unwrap_or_else(|| panic!("{s} in {err}"));
    assert!(pos("secrets      7") < pos("ssh keys"));
    assert!(pos("ssh keys") < pos("git    "));
    assert!(pos("git    ") < pos("AI tools"));
    assert!(pos("AI tools") < pos("local files"));
    assert!(!err.contains("Type unseal"), "a dry run asks nothing");
    assert_eq!(common::tree(&h.home), before, "--dry-run changed files");
    assert!(!h.home.join(".sealctl-unseal").exists());
    for (_, v) in common::fixture_secrets() {
        assert!(!err.contains(&v) && !String::from_utf8_lossy(&out.stdout).contains(&v));
    }

    // --json: the plan as one object on stdout
    let out = h.unseal(&["--all", "--dry-run", "--json", "--to", "op"], "", &[]);
    assert!(out.status.success(), "{}", text(&out));
    let plan: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(plan["kind"], "unseal-plan");
    let kinds: Vec<&str> = plan["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["object"].as_str().unwrap())
        .collect();
    // services: the session agent is running (and with SEALCTL_TEST_SERVICES the launchd /
    // systemd services of the fixture)
    let want = vec!["secrets", "ssh", "git", "ai", "services", "local-state"];
    assert_eq!(kinds, want);
    assert_eq!(common::tree(&h.home), before);

    // a single object, and --skip
    let out = h.unseal(&["ssh", "github", "--dry-run", "--to", "op"], "", &[]);
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "{}", text(&out));
    assert!(err.contains("ssh keys     github"), "{err}");
    assert!(!err.contains("secrets"), "{err}");
    let out = h.unseal(
        &[
            "--all",
            "--dry-run",
            "--to",
            "op",
            "--skip",
            "ai",
            "--skip",
            "secret/mail",
        ],
        "",
        &[],
    );
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains(" 1  secrets      6 secrets"), "{err}");
    assert!(err.contains("Left out: secret/mail, ai."), "{err}");
    assert!(
        !err.contains("local files"),
        "local state stays while objects are left out: {err}"
    );
    assert_eq!(common::tree(&h.home), before);

    // nothing confirmed: nothing changes
    let out = h.unseal(&["--all", "--to", "op", "--keep-env-rules"], "no\n", &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(String::from_utf8_lossy(&out.stderr).contains("Nothing was changed."));
    let mut after = common::tree(&h.home);
    after.remove(".sealctl-unseal");
    assert_eq!(after, before, "an unconfirmed run changed files");
    assert!(
        std::fs::read_dir(h.home.join(".sealctl-unseal"))
            .unwrap()
            .next()
            .is_none(),
        "no run folder is left"
    );
}

#[test]
fn refused_inside_ai_agents_and_without_a_terminal() {
    let _g = serial();
    let h = new_home();
    common::fixture(
        &h,
        &FixtureOpts {
            ai: false,
            services: false,
            ..Default::default()
        },
    );
    let before = common::tree(&h.home);
    for (var, val) in [
        ("CLAUDECODE", "1"),
        ("CODEX_SANDBOX", "seatbelt"),
        ("GEMINI_CLI", "1"),
        ("SEALCTL_AGENT", "1"),
    ] {
        let mut env = vec![(var, val)];
        if var != "SEALCTL_AGENT" {
            env.push(("SEALCTL_AGENT", ""));
        }
        let out = h.unseal(&["--all", "--dry-run"], "", &env);
        assert_eq!(out.status.code(), Some(8), "{var}: {}", text(&out));
        assert!(String::from_utf8_lossy(&out.stderr).contains("refusing"));
    }
    // no terminal: stdin is a pipe and the test hook is off
    let out = h.unseal(&["--all", "--dry-run"], "", &[("SEALCTL_TEST_ASSUME_TTY", "")]);
    let mut c = h.sealctl();
    c.env_remove("SEALCTL_TEST_ASSUME_TTY")
        .args(["unseal", "--all", "--dry-run"]);
    let no_tty = c.output().unwrap();
    assert_eq!(no_tty.status.code(), Some(8), "{}", text(&no_tty));
    assert!(String::from_utf8_lossy(&no_tty.stderr).contains("terminal"));
    let _ = out;

    // usage
    for args in [
        &["volume"][..],
        &[],
        &["--all", "secrets"],
        &["--all", "--resume"],
        &["nonsense"],
    ] {
        let out = h.unseal(args, "", &[]);
        assert_eq!(out.status.code(), Some(2), "{args:?}: {}", text(&out));
    }
    // no such object
    for args in [
        &["volume", "nope"][..],
        &["ssh", "nope"],
        &["secret", "nope"],
        &["backup", "nope"],
    ] {
        let out = h.unseal(&[args, &["--dry-run"]].concat(), "", &[]);
        assert_eq!(out.status.code(), Some(9), "{args:?}: {}", text(&out));
    }
    // --resume without an unfinished run
    let out = h.unseal(&["--resume"], "", &[]);
    assert_eq!(out.status.code(), Some(2), "{}", text(&out));
    assert_eq!(common::tree(&h.home), before);
}
