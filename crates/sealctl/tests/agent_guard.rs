//! What an AI agent can and cannot get out of sealctl, using the real binary. A software key
//! stands in for the Ledger (served by the agent, as in `sealctl recover`).

mod common;

use std::process::Command;
use std::time::Duration;

use sealctl::agent::{self, AgentClient, Limits};
use sealctl::Ctx;
use sealctl_ledger::Select;

const VALUE: &str = "sk-test-0123456789abcdefghijklmnopqrstuv";

fn sealctl(tmp: &std::path::Path, agent_env: Option<(&str, &str)>) -> Command {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sealctl"));
    c.env("XDG_CONFIG_HOME", tmp.join("c"))
        .env("XDG_DATA_HOME", tmp.join("d"))
        .env("XDG_STATE_HOME", tmp.join("s"))
        .env("SEALCTL_NO_NOTIFY", "1")
        // these tests may themselves run inside an AI agent
        .env_remove("CLAUDECODE")
        .env_remove("CLAUDE_CODE_CHILD_SESSION")
        .env("SEALCTL_AGENT", "0");
    if let Some((k, v)) = agent_env {
        c.env("SEALCTL_AGENT", "").env(k, v);
    }
    c
}

#[test]
fn agents_use_secrets_without_seeing_them() {
    let tmp = tempfile::Builder::new().prefix("ag").tempdir_in("/tmp").unwrap();
    let t = tmp.path();
    std::env::set_var("XDG_CONFIG_HOME", t.join("c"));
    std::env::set_var("XDG_DATA_HOME", t.join("d"));
    std::env::set_var("XDG_STATE_HOME", t.join("s"));
    std::thread::spawn(|| {
        agent::run_with(
            Ctx {
                select: Select::Usb,
                scan: Duration::from_secs(1),
            },
            Limits::default(),
            Some(Box::new(common::SoftOracle::fixed())),
        )
    });
    let mut client = None;
    for _ in 0..100 {
        if let Ok(c) = AgentClient::connect() {
            client = Some(c);
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut client = client.expect("agent started");
    sealctl::secrets::set(&mut client, "t/openai", VALUE.as_bytes(), false).unwrap();

    // `sealctl run` inside an agent: the program gets the value, the output shows ****
    let out = sealctl(t, Some(("CLAUDECODE", "1")))
        .args(["run", "--no-project", "--env", "KEY=t/openai", "--", "sh", "-c"])
        .arg(r#"echo "out=$KEY"; echo "err=$KEY" >&2; test "$KEY" = "$EXPECTED""#)
        .env("EXPECTED", VALUE)
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(out.status.success(), "program saw the real value: {stderr}");
    assert!(stdout.contains("out=****"), "{stdout}");
    assert!(stderr.contains("err=****"), "{stderr}");
    assert!(!stdout.contains(VALUE) && !stderr.contains(VALUE), "value leaked");

    // exit codes pass through
    let out = sealctl(t, Some(("CLAUDECODE", "1")))
        .args([
            "run",
            "--no-project",
            "--env",
            "KEY=t/openai",
            "--",
            "sh",
            "-c",
            "exit 7",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(7));

    // `secret get` refuses inside an agent, with or without --clip
    for args in [
        &["secret", "get", "t/openai"][..],
        &["secret", "get", "--clip", "t/openai"],
    ] {
        for agent_var in ["CLAUDECODE", "CODEX_SANDBOX", "GEMINI_CLI"] {
            let out = sealctl(t, Some((agent_var, "1"))).args(args).output().unwrap();
            assert!(!out.status.success(), "{args:?} under {agent_var}");
            assert!(!String::from_utf8_lossy(&out.stdout).contains(VALUE));
            assert!(String::from_utf8_lossy(&out.stderr).contains("refusing"));
        }
    }

    // a script (pipe, no agent) still gets the value
    let out = sealctl(t, None)
        .args(["secret", "get", "t/openai"])
        .output()
        .unwrap();
    assert_eq!(String::from_utf8_lossy(&out.stdout).trim(), VALUE);

    // storing from stdin works without the value ever being an argument
    let mut child = sealctl(t, Some(("CLAUDECODE", "1")))
        .args(["secret", "set", "t/other"])
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"another-secret-value-123\n")
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(
        *sealctl::secrets::get(&mut client, "t/other").unwrap(),
        "another-secret-value-123"
    );
    agent::stop().unwrap();
}
