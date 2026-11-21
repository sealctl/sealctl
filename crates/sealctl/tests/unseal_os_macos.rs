//! `sealctl unseal` against the real macOS tools: an encrypted APFS volume in an APFS container
//! inside a throw-away disk image (locked), and an encrypted sparse bundle (mounted) with a
//! restic backup in a folder repository and its in-volume settings. Checked with
//! `diskutil apfs unlockVolume -verify`, `hdiutil attach` and `restic`. Never touches real disks.
#![cfg(target_os = "macos")]

mod common;

use std::path::{Path, PathBuf};
use std::process::Command;

use common::{new_home, serial, text, FixtureOpts, Home};
use sealctl::derive::{canonical_id, passphrase, Purpose};
use sealctl::volume::{self, Kind, Volume};

/// The default: new passwords and restic settings in the folder.
const ARGS: &[&str] = &["--all", "--keep-env-rules"];

struct Disks {
    /// The disk image holding the APFS container, to detach at the end.
    whole: String,
    apfs: Volume,
    bundle: Volume,
    repo: PathBuf,
}

impl Drop for Disks {
    fn drop(&mut self) {
        let _ = volume::backend(Kind::Sparsebundle).lock(&self.bundle, true);
        let _ = Command::new("hdiutil")
            .args(["detach", "-force", &format!("/dev/{}", self.whole)])
            .output();
    }
}

fn container_image(tmp: &Path) -> (String, String) {
    let img = tmp.join("container.sparseimage");
    assert!(Command::new("hdiutil")
        .args(["create", "-quiet", "-size", "1g", "-type", "SPARSE", "-fs", "APFS", "-volname", "sctbase"])
        .arg(&img)
        .status()
        .unwrap()
        .success());
    let out = Command::new("hdiutil")
        .args(["attach", "-nomount", "-plist"])
        .arg(&img)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    let entry = |d: &str, key: &str| -> Option<String> {
        let i = d.find(&format!("<key>{key}</key>"))?;
        let rest = &d[i..];
        let a = rest.find("<string>")? + "<string>".len();
        let b = rest[a..].find("</string>")?;
        Some(rest[a..a + b].to_string())
    };
    let (mut whole, mut container) = (None, None);
    for d in text.split("<dict>") {
        let (Some(hint), Some(dev)) = (entry(d, "content-hint"), entry(d, "dev-entry")) else {
            continue;
        };
        let dev = dev.trim_start_matches("/dev/").to_string();
        if hint == "GUID_partition_scheme" {
            whole = Some(dev.clone());
        }
        if hint.starts_with("EF57347C") {
            container = Some(dev);
        }
    }
    (whole.expect("whole disk"), container.expect("APFS container"))
}

/// Volumes made with the 0.5.0 code and the software key: a locked APFS volume and a mounted
/// sparse bundle with a restic backup (one snapshot) in a folder repository.
fn volumes(h: &Home) -> Disks {
    let tmp = h.tmp.path();
    let mut ledger = common::SoftOracle::fixed();
    let (whole, container) = container_image(tmp);
    let apfs_name = format!("sctu{}", std::process::id());
    let mut apfs = Volume {
        name: apfs_name.clone(),
        kind: Kind::ApfsVolume,
        path: None,
        id: container,
        mountpoint: Path::new("/Volumes").join(&apfs_name),
        backup: None,
    };
    let be = volume::backend(Kind::ApfsVolume);
    let mut key_for = |id: &str| passphrase(&mut ledger, Purpose::Volume, &canonical_id(id));
    be.create(&mut apfs, "", &mut key_for).expect("APFS volume");
    apfs.id = canonical_id(&apfs.id);
    apfs.save().unwrap();
    assert!(!be.is_unlocked(&apfs).unwrap(), "created locked");

    let bundle = volume::create(
        &mut ledger,
        volume::CreateOpts {
            name: format!("sctb{}", std::process::id()),
            kind: Kind::Sparsebundle,
            size: "64m".into(),
            path: Some(tmp.join("v.sparsebundle")),
            container: None,
            mountpoint: Some(tmp.join("mnt")),
        },
    )
    .expect("sparse bundle");
    std::fs::write(bundle.mountpoint.join("hello.txt"), b"hello").unwrap();
    let repo = tmp.join("repo");
    sealctl::backup::init(&mut ledger, &bundle.name, &repo.to_string_lossy(), None, &[])
        .expect("backup init");
    sealctl::backup::run(std::slice::from_ref(&bundle.name), false, false, true).expect("backup");
    let bundle = Volume::load(&bundle.name).unwrap();
    Disks {
        whole,
        apfs,
        bundle,
        repo,
    }
}

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

fn restic(repo: &Path, password: &str, args: &[&str]) -> std::process::Output {
    let mut c = Command::new("restic");
    c.env("RESTIC_REPOSITORY", repo)
        .env("RESTIC_PASSWORD_FILE", "/dev/stdin")
        .args(args);
    sealctl::util::run_with_stdin(&mut c, password.as_bytes()).unwrap()
}

fn derived(p: Purpose, id: &str) -> String {
    passphrase(&mut common::SoftOracle::fixed(), p, id)
        .unwrap()
        .to_string()
}

#[test]
fn apfs_volume_sparse_bundle_and_backup_are_handed_back() {
    if !common::have("restic") {
        eprintln!("restic not installed — skipping");
        return;
    }
    let _g = serial();
    let mut h = new_home();
    common::fixture(&h, &none());
    let d = volumes(&h);
    common::start_agent();
    h.start_ssh_agent();
    let snapshots_before = restic(
        &d.repo,
        &derived(Purpose::Restic, &d.bundle.name),
        &["snapshots", "--json"],
    );
    assert!(snapshots_before.status.success());

    let out = h.unseal(ARGS, "unseal\n", &[]);
    assert!(out.status.success(), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("stays encrypted; it will open with a new passphrase (passwords.txt)."),
        "{err}"
    );
    assert!(
        err.contains("- volumes and backups stay encrypted; each gets a new random password, saved in"),
        "{err}"
    );
    // backup before its volume
    assert!(err.find("backup of").unwrap() < err.find(&format!("volume {}:", d.bundle.name)).unwrap());

    // APFS: the new passphrase from the store opens it; sealctl's no longer does; still locked
    let new = h.folder_password(&format!("volume {}", d.apfs.name)).unwrap();
    assert!(volume::apfs::verify(&d.apfs.id, new.as_bytes()).unwrap());
    assert!(!volume::apfs::verify(&d.apfs.id, derived(Purpose::Volume, &d.apfs.id).as_bytes()).unwrap());
    assert!(
        !volume::backend(Kind::ApfsVolume).is_unlocked(&d.apfs).unwrap(),
        "left locked"
    );
    let info = Command::new("diskutil")
        .args(["info", &d.apfs.id])
        .output()
        .unwrap();
    let info = String::from_utf8_lossy(&info.stdout);
    assert!(
        info.contains("FileVault:                 Yes") || info.contains("Encrypted:                 Yes"),
        "{info}"
    );

    // sparse bundle: mounted again as it was found, sealctl.id gone; opens only with the new one
    let sb = volume::backend(Kind::Sparsebundle);
    assert!(sb.is_unlocked(&d.bundle).unwrap(), "mounted as found");
    assert!(
        !d.bundle.inner_dir().exists(),
        ".sealctl/ removed from the volume"
    );
    assert_eq!(
        std::fs::read(d.bundle.mountpoint.join("hello.txt")).unwrap(),
        b"hello"
    );
    let path = d.bundle.path.clone().unwrap();
    assert!(!path.join("sealctl.id").exists());
    sb.lock(&d.bundle, false).unwrap();
    let new_b = h.folder_password(&format!("volume {}", d.bundle.name)).unwrap();
    assert!(sb.verify(&d.bundle, new_b.as_bytes()).unwrap());
    assert!(!sb
        .verify(&d.bundle, derived(Purpose::Volume, &d.bundle.id).as_bytes())
        .unwrap());

    // restic: same snapshots under the new password, one key, sealctl's password refused
    let pw = h.folder_password(&format!("backup {}", d.bundle.name)).unwrap();
    // backup-<volume>.env: everything restic needs, and a shell can source it
    let envf = format!("backup-{}.env", d.bundle.name);
    let env = h.folder_env(&envf);
    assert_eq!(env["RESTIC_REPOSITORY"], d.repo.to_string_lossy());
    assert_eq!(env["RESTIC_PASSWORD"], pw);
    let sourced = Command::new("/bin/sh")
        .arg("-c")
        .arg("set -a; . \"$1\"; set +a; restic snapshots --json")
        .arg("sh")
        .arg(h.run_dir().join(&envf))
        .output()
        .unwrap();
    assert!(sourced.status.success(), "{}", text(&sourced));
    let after = restic(&d.repo, &pw, &["snapshots", "--json"]);
    assert!(after.status.success(), "{}", text(&after));
    let ids = |o: &std::process::Output| -> Vec<String> {
        serde_json::from_slice::<serde_json::Value>(&o.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap().to_string())
            .collect()
    };
    assert_eq!(ids(&after), ids(&snapshots_before));
    assert_eq!(ids(&sourced), ids(&snapshots_before));
    let keys = restic(&d.repo, &pw, &["key", "list", "--json"]);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&keys.stdout)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    let old = restic(
        &d.repo,
        &derived(Purpose::Restic, &d.bundle.name),
        &["cat", "config"],
    );
    assert!(!old.status.success());
    assert!(String::from_utf8_lossy(&old.stderr).contains("wrong password"));
    assert!(restic(&d.repo, &pw, &["check"]).status.success());

    // the hand-back list names both volumes and the backup with its URL
    let hb: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(h.run_dir().join("handback.json")).unwrap()).unwrap();
    let kinds: Vec<&str> = hb["objects"]
        .as_array()
        .unwrap()
        .iter()
        .map(|o| o["kind"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["backup", "volume", "volume"]);
    assert_eq!(hb["objects"][0]["url"], d.repo.to_string_lossy().as_ref());
    assert!(h.fake_values().is_empty(), "nothing in a password store");
    for v in [new, new_b, pw] {
        assert!(!err.contains(&v) && !common::all_text_but_plain(&h.run_dir()).contains(&v));
    }
}

#[test]
fn a_failed_check_removes_nothing_and_a_kill_resumes() {
    if !common::have("restic") {
        eprintln!("restic not installed — skipping");
        return;
    }
    let _g = serial();
    let h = new_home();
    common::fixture(&h, &none());
    let d = volumes(&h);
    common::start_agent();
    let n = d.bundle.name.clone();
    let sb = volume::backend(Kind::Sparsebundle);

    // the check after restic key add fails: sealctl's key stays, the run stops
    let out = h.unseal(
        &["backup", &n, "--to", "op", "--secrets-to", "env"],
        "y\n",
        &[("SEALCTL_TEST_BREAK_CHECK", &format!("backup:{n}:key-add"))],
    );
    assert_eq!(out.status.code(), Some(13), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains("Run sealctl unseal --resume after fixing this."),
        "{err}"
    );
    assert!(
        restic(&d.repo, &derived(Purpose::Restic, &n), &["cat", "config"])
            .status
            .success(),
        "sealctl's key kept"
    );
    assert!(d.bundle.inner_dir().exists() || !sb.is_unlocked(&d.bundle).unwrap());
    let out = h.unseal(&["--resume"], "", &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(
        !restic(&d.repo, &derived(Purpose::Restic, &n), &["cat", "config"])
            .status
            .success()
    );

    // the check after the passphrase change fails: the change is reversed
    let out = h.unseal(
        &["volume", &n, "--to", "op"],
        "y\n",
        &[("SEALCTL_TEST_BREAK_CHECK", &format!("volume:{n}:change"))],
    );
    assert_eq!(out.status.code(), Some(13), "{}", text(&out));
    assert!(
        String::from_utf8_lossy(&out.stderr).contains("still opens with sealctl's key"),
        "{}",
        text(&out)
    );
    sb.lock(&d.bundle, false).unwrap();
    assert!(
        sb.verify(&d.bundle, derived(Purpose::Volume, &d.bundle.id).as_bytes())
            .unwrap(),
        "sealctl's key still opens it"
    );
    assert!(d.bundle.path.as_ref().unwrap().join("sealctl.id").exists());
    // ... and finished with --resume
    let out = h.unseal(&["--resume"], "", &[]);
    assert!(out.status.success(), "{}", text(&out));
    assert!(!sb
        .verify(&d.bundle, derived(Purpose::Volume, &d.bundle.id).as_bytes())
        .unwrap());

    // APFS (the folder): a power cut right after the change took effect, before the journal
    // says so; the passphrase was durable in passwords.txt before the change
    let a = d.apfs.name.clone();
    let report = h.tmp.path().join("powercut.txt");
    let out = h.unseal(
        &["volume", &a],
        "y\n",
        &[
            ("SEALCTL_TEST_POWERCUT", &format!("volume:{a}:change:before-done")),
            ("SEALCTL_TEST_POWERCUT_REPORT", &report.display().to_string()),
        ],
    );
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(out.status.signal(), Some(9), "{}", text(&out));
    }
    assert_eq!(std::fs::read_to_string(&report).unwrap(), "", "all durable");
    let new = h.folder_password(&format!("volume {a}")).unwrap();
    assert!(
        volume::apfs::verify(&d.apfs.id, new.as_bytes()).unwrap(),
        "the change took effect"
    );
    let out = h.unseal(&["--resume"], "", &[]);
    assert!(out.status.success(), "{}", text(&out));
    let journal = std::fs::read_to_string(h.run_dir().join("journal.jsonl")).unwrap();
    assert!(journal.contains("your passphrase already opens it"), "{journal}");
    assert!(!volume::apfs::verify(&d.apfs.id, derived(Purpose::Volume, &d.apfs.id).as_bytes()).unwrap());
    assert!(!Volume::config_file_for(&a).unwrap().exists());
}
