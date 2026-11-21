//! `sealctl unseal` against the real Linux tools: a LUKS2 file made by the 0.5.0 code (through
//! `sudo cryptsetup`, so only with SEALCTL_TEST_SUDO=1, as in CI) with a restic backup in a
//! folder repository; key slots checked with `cryptsetup luksDump`. systemd user unit files of
//! sealctl's services are removed.
#![cfg(target_os = "linux")]

mod common;

use std::path::Path;
use std::process::Command;

use common::{new_home, serial, text, FixtureOpts};
use sealctl::derive::{passphrase, Purpose};
use sealctl::volume::{self, Kind, Volume};

fn none() -> FixtureOpts {
    FixtureOpts {
        secrets: false,
        ssh: false,
        git: false,
        ai: false,
        shell: false,
        services: false,
    }
}

fn derived(p: Purpose, id: &str) -> String {
    passphrase(&mut common::SoftOracle::fixed(), p, id)
        .unwrap()
        .to_string()
}

fn keyslots(file: &Path) -> usize {
    let out = Command::new("cryptsetup")
        .arg("luksDump")
        .arg(file)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let mut in_slots = false;
    let mut n = 0;
    for l in text.lines() {
        if l.starts_with("Keyslots:") {
            in_slots = true;
            continue;
        }
        if in_slots && !l.starts_with(' ') && !l.starts_with('\t') {
            break;
        }
        if in_slots
            && l.trim_start()
                .split(':')
                .next()
                .is_some_and(|k| k.trim().parse::<u32>().is_ok())
            && l.contains("luks2")
        {
            n += 1;
        }
    }
    n
}

fn restic(repo: &Path, password: &str, args: &[&str]) -> std::process::Output {
    let mut c = Command::new("restic");
    c.env("RESTIC_REPOSITORY", repo)
        .env("RESTIC_PASSWORD_FILE", "/dev/stdin")
        .args(args);
    sealctl::util::run_with_stdin(&mut c, password.as_bytes()).unwrap()
}

#[test]
fn luks_volume_and_backup_are_handed_back() {
    if !common::flag("SEALCTL_TEST_SUDO") {
        eprintln!("set SEALCTL_TEST_SUDO=1 (passwordless sudo) to run the LUKS test");
        return;
    }
    let _g = serial();
    std::env::set_var("SEALCTL_SUDO_NONINTERACTIVE", "1");
    let h = new_home();
    common::fixture(&h, &none());
    let mut ledger = common::SoftOracle::fixed();
    let tmp = h.tmp.path();
    let name = format!("sctl{}", std::process::id());
    let file = tmp.join("v.luks");
    let vol = volume::create(
        &mut ledger,
        volume::CreateOpts {
            name: name.clone(),
            kind: Kind::Luks,
            size: "64m".into(),
            path: Some(file.clone()),
            container: None,
            mountpoint: Some(tmp.join("mnt")),
        },
    )
    .expect("LUKS volume");
    std::fs::write(vol.mountpoint.join("hello.txt"), b"hello").unwrap();
    let have_restic = common::have("restic");
    let repo = tmp.join("repo");
    if have_restic {
        sealctl::backup::init(&mut ledger, &name, &repo.to_string_lossy(), None, &[]).unwrap();
        sealctl::backup::run(std::slice::from_ref(&name), false, false, true).unwrap();
    }
    // systemd unit files as sealctl 0.5.0 writes them (systemctl may have no user bus here)
    for label in [sealctl::ssh::AGENT_LABEL, sealctl::backup::SCHEDULE_LABEL] {
        let _ = sealctl::service::install(&sealctl::service::Service {
            label,
            args: vec!["/bin/sleep".into(), "86400".into()],
            every_secs: None,
            description: "sealctl unseal test",
        });
    }
    let units = h.home.join(".config/systemd/user");
    assert!(units.join("sealctl-ssh-agent.service").exists());
    common::start_agent();
    assert_eq!(keyslots(&file), 1);

    let out = h.unseal(
        &["--all", "--to", "op", "--secrets-to", "env", "--keep-env-rules"],
        "unseal\n",
        &[("SEALCTL_SUDO_NONINTERACTIVE", "1")],
    );
    assert!(out.status.success(), "{}", text(&out));

    let new = h.fake_value(&format!("sealctl: volume {name}")).unwrap();
    let be = volume::backend(Kind::Luks);
    let v = Volume { ..vol.clone() };
    assert!(
        be.verify(&v, new.as_bytes()).unwrap(),
        "the new passphrase opens it"
    );
    assert!(
        !be.verify(&v, derived(Purpose::Volume, &vol.id).as_bytes())
            .unwrap(),
        "sealctl's slot is gone"
    );
    assert_eq!(keyslots(&file), 1, "one key slot left");
    assert!(be.is_unlocked(&v).unwrap(), "left mounted as found");
    assert_eq!(std::fs::read(v.mountpoint.join("hello.txt")).unwrap(), b"hello");
    if have_restic {
        let pw = h.fake_value(&format!("sealctl: backup {name}/password")).unwrap();
        assert!(restic(&repo, &pw, &["snapshots"]).status.success());
        assert!(
            !restic(&repo, &derived(Purpose::Restic, &name), &["cat", "config"])
                .status
                .success()
        );
        assert!(!v.inner_dir().exists());
    }
    for u in [
        "sealctl-ssh-agent.service",
        "sealctl-backup.service",
        "sealctl-backup.timer",
    ] {
        assert!(!units.join(u).exists(), "{u} removed");
    }
    let _ = be.lock(&v, true);
}
