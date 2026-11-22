//! Pairing, status, unpair (SPEC 8, 10.1) against the fake relay, or the live one when
//! `SEALCTL_TEST_RELAY` is set.

mod common;

use common::Env;
use serde_json::Value;

#[test]
fn pair_status_unpair() {
    let mut env = Env::new();
    // not paired
    let (code, out, _) = env.run(&["status"]);
    assert_eq!(code, 3);
    assert!(out.contains("Not paired · sealctl pair"), "{out}");
    let (code, out, _) = env.run(&["status", "--json"]);
    assert_eq!(code, 3);
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["machine"]["paired"], false);

    let m = env.pair();
    let mf = env.h().join(".config/sealctl/machine.json");
    use std::os::unix::fs::PermissionsExt;
    assert_eq!(
        std::fs::metadata(&mf).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let (code, out, err) = env.run(&["status", "--json"]);
    assert_eq!(code, 0, "{err}");
    let v: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["machine"]["paired"], true);
    assert_eq!(v["machine"]["name"], "tester@box.test");
    assert_eq!(v["machine"]["relay"], env.origin.as_str());
    assert_eq!(v["licence"], "unpaid");
    assert_eq!(v["state"], "locked");
    assert!(m.key.len() == 43);

    // a paired machine refuses another relay (exit 2)
    let (code, _, err) = {
        let mut c = env.cmd();
        c.env("SEALCTL_RELAY", "https://relay.example.test");
        let o = c.args(["unpair", "--yes"]).output().unwrap();
        (
            o.status.code().unwrap(),
            String::new(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    };
    assert_eq!(code, 2, "{err}");

    // terminal text
    let (code, out, _) = env.run(&["status"]);
    assert_eq!(code, 0);
    assert!(out.starts_with("Locked\n"), "{out}");
    assert!(out.contains("tester@box.test #"), "{out}");
    assert!(out.contains("Unpaid · sealctl buy"), "{out}");

    // unpair: the relay forgets the machine
    let (code, _, err) = env.run(&["unpair", "--yes"]);
    assert_eq!(code, 0, "{err}");
    assert!(!mf.exists());
    let (code, _, _) = env.run(&["status"]);
    assert_eq!(code, 3);
}

#[test]
fn a_wrong_proof_is_refused() {
    let env = Env::fake(Default::default());
    let mut child = env
        .cmd()
        .args(["pair"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Read;
    let mut out = child.stdout.take().unwrap();
    let mut link = String::new();
    let mut b = [0u8; 1];
    while out.read(&mut b).unwrap() == 1 && b[0] != b'\n' {
        link.push(b[0] as char);
    }
    env.block(env.phone.pair_with_bad_proof(&link)).unwrap();
    let o = child.wait_with_output().unwrap();
    assert_eq!(o.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&o.stderr)
        .contains("This pairing did not come from your phone. Run sealctl pair again."));
    assert!(!env.h().join(".config/sealctl/machine.json").exists());
}

#[test]
fn not_paired_commands_exit_3() {
    let env = Env::fake(Default::default());
    let (code, _, err) = env.run(&["open"]);
    assert_eq!(code, 3, "{err}");
    assert!(
        err.contains("sealctl: This machine is not paired. Run: sealctl pair"),
        "{err}"
    );
    let (code, _, _) = env.run(&["unlock", "x"]);
    assert_eq!(code, 2);
}

#[test]
fn pairing_at_a_terminal_shows_the_qr_code() {
    let env = Env::fake(Default::default());
    let mut c = env.cmd();
    c.args(["pair", "--name", "tty@box.test"]);
    let pty = common::Pty::spawn(c);
    let screen = pty.expect(
        "Waiting for your phone (10 min)",
        std::time::Duration::from_secs(30),
    );
    assert!(
        screen.contains("Scan with the sealctl app on your phone. Or open this link on the phone:"),
        "{screen}"
    );
    assert!(
        screen.contains('█') || screen.contains('▀'),
        "QR code drawn with half blocks"
    );
    let link = screen
        .lines()
        .find(|l| l.trim_start().starts_with("https://sealctl.com/p#"))
        .unwrap()
        .trim()
        .to_string();
    assert!(
        link.contains("&r=http%3A%2F%2F127.0.0.1%3A"),
        "a test relay is named in the link: {link}"
    );
    env.block(env.phone.pair(&link)).unwrap();
    let (code, out, screen) = pty.wait(std::time::Duration::from_secs(30));
    assert_eq!(code, 0, "{screen}");
    assert!(out.starts_with("Paired: tty@box.test #"), "{out}");
    assert!(
        screen
            .contains("Free to use. If it earns its place, $5.99 once keeps the relay running: sealctl buy"),
        "{screen}"
    );
}
