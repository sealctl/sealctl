//! Encrypted SSH key files: generated with a seed-derived passphrase, unlocked by the SSH agent
//! on first use, cached, forgotten by `ssh-add -D`. A software key stands in for the Ledger
//! (served by the agent exactly like `sealctl recover`); real `ssh-add` / `ssh-keygen` are used.

mod common;

use std::process::Command;
use std::time::Duration;

use sealctl::agent::{self, AgentClient, Limits};
use sealctl::derive::Oracle;
use sealctl::Ctx;
use sealctl_ledger::Select;

fn ctx() -> Ctx {
    Ctx {
        select: Select::Usb,
        scan: Duration::from_secs(1),
    }
}

/// Counts derivations, so the test can tell whether the "Ledger" was asked.
struct Counting(common::SoftOracle, std::sync::Arc<std::sync::atomic::AtomicUsize>);

impl Oracle for Counting {
    fn x25519(&mut self, u: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
        self.1.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        self.0.x25519(u)
    }
}

fn wait_for(path: &std::path::Path) {
    for _ in 0..100 {
        if path.exists() {
            return;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("{} did not appear", path.display());
}

fn ssh(sock: &std::path::Path, prog: &str, args: &[&str]) -> std::process::Output {
    Command::new(prog)
        .args(args)
        .env("SSH_AUTH_SOCK", sock)
        .output()
        .unwrap()
}

#[test]
fn encrypted_key_files_are_cached_by_the_agent() {
    if !common::have("ssh-keygen") || !common::have("ssh-add") {
        eprintln!("OpenSSH tools missing — skipping");
        return;
    }
    let tmp = tempfile::Builder::new().prefix("sk").tempdir_in("/tmp").unwrap();
    std::env::set_var("XDG_CONFIG_HOME", tmp.path().join("c"));
    std::env::set_var("XDG_DATA_HOME", tmp.path().join("d"));
    std::env::set_var("XDG_STATE_HOME", tmp.path().join("s"));
    std::env::set_var("SEALCTL_SSH_DIR", tmp.path().join("ssh"));
    std::env::set_var("SEALCTL_NO_NOTIFY", "1");

    // the "Ledger": a software key behind the sealctl agent
    let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let soft = Counting(common::SoftOracle::fixed(), calls.clone());
    std::thread::spawn(move || {
        agent::run_with(
            ctx(),
            Limits {
                idle: Duration::from_secs(600),
                max_life: Duration::from_secs(3600),
            },
            Some(Box::new(soft)),
        )
    });
    wait_for(&agent::socket_path().unwrap());

    // keygen: standard encrypted OpenSSH file + .pub
    let mut oracle = AgentClient::connect().unwrap();
    let path = sealctl::ssh::keygen(&mut oracle, "test", "test@sealctl").unwrap();
    let text = std::fs::read_to_string(&path).unwrap();
    assert!(text.starts_with("-----BEGIN OPENSSH PRIVATE KEY-----"));
    let public = sealctl::ssh::read_public(&path).unwrap();
    assert!(ssh_key::PrivateKey::from_openssh(&text).unwrap().is_encrypted());
    // OpenSSH itself opens it with the derived passphrase
    let pass = sealctl::ssh::passphrase_for(&mut oracle, &public).unwrap();
    let out = Command::new("ssh-keygen")
        .args(["-y", "-P", &pass, "-f"])
        .arg(&path)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).starts_with("ssh-ed25519 "));
    // a different seed cannot
    let mut other = common::SoftOracle(x25519_dalek::StaticSecret::from([9u8; 32]));
    assert!(sealctl::ssh::unlock_file(&mut other, &path).is_err());

    // importing an existing unencrypted key keeps the key pair and encrypts it
    let plain = ssh_key::PrivateKey::random(&mut rand::rngs::OsRng, ssh_key::Algorithm::Ed25519).unwrap();
    let src = tmp.path().join("id_plain");
    std::fs::write(
        &src,
        plain.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes(),
    )
    .unwrap();
    let imported = sealctl::ssh::import(&mut oracle, &src, "plain").unwrap();
    assert_eq!(
        sealctl::ssh::read_public(&imported).unwrap().key_data(),
        plain.public_key().key_data()
    );
    assert!(
        ssh_key::PrivateKey::from_openssh(std::fs::read_to_string(&imported).unwrap())
            .unwrap()
            .is_encrypted()
    );
    assert!(src.exists(), "original left in place");

    // the SSH agent lists it and signs with it
    let sock = tmp.path().join("ssh-agent.sock");
    let s2 = sock.clone();
    std::thread::spawn(move || sealctl::ssh::run_agent(ctx(), Some(s2)));
    wait_for(&sock);
    let list = ssh(&sock, "ssh-add", &["-L"]);
    let listed = String::from_utf8_lossy(&list.stdout).to_string();
    assert!(listed.contains(&public.to_openssh().unwrap()), "{listed}");

    let msg = tmp.path().join("msg");
    std::fs::write(&msg, b"hello").unwrap();
    let pubfile = path.with_extension("pub");
    let sign = |label: &str| {
        let _ = std::fs::remove_file(msg.with_extension("sig"));
        let out = ssh(
            &sock,
            "ssh-keygen",
            &[
                "-Y",
                "sign",
                "-n",
                "file",
                "-f",
                pubfile.to_str().unwrap(),
                msg.to_str().unwrap(),
            ],
        );
        assert!(
            out.status.success(),
            "{label}: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };
    let before = calls.load(std::sync::atomic::Ordering::SeqCst);
    sign("first signature");
    let after_first = calls.load(std::sync::atomic::Ordering::SeqCst);
    sign("second signature");
    let after_second = calls.load(std::sync::atomic::Ordering::SeqCst);
    // (the recovery agent passes every derivation to the oracle, so these count device calls)
    assert_eq!(after_first, before + 1, "first signature unlocks the key once");
    assert_eq!(after_second, after_first, "second signature needs no device");

    // the signature verifies with the public key
    let allowed = tmp.path().join("allowed");
    std::fs::write(
        &allowed,
        format!("test@sealctl {}\n", public.to_openssh().unwrap()),
    )
    .unwrap();
    let verify = Command::new("ssh-keygen")
        .args(["-Y", "verify", "-n", "file", "-I", "test@sealctl", "-f"])
        .arg(&allowed)
        .arg("-s")
        .arg(msg.with_extension("sig"))
        .stdin(std::fs::File::open(&msg).unwrap())
        .output()
        .unwrap();
    assert!(
        verify.status.success(),
        "{}",
        String::from_utf8_lossy(&verify.stderr)
    );

    // ssh-add -D forgets the decrypted key; the next signature has to unlock it again
    assert!(ssh(&sock, "ssh-add", &["-D"]).status.success());
    sign("after ssh-add -D");
    assert_eq!(
        calls.load(std::sync::atomic::Ordering::SeqCst),
        after_second + 1,
        "key was forgotten and unlocked again"
    );
    agent::stop().unwrap();
}
