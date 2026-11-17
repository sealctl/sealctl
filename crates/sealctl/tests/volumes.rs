//! End-to-end volume + backup tests against the real OS tools (no Ledger needed).
//!
//! * macOS: hdiutil sparse bundles and diskutil APFS volumes (no root required)
//! * Linux: LUKS2 — only with `SEALCTL_TEST_SUDO=1` (needs passwordless sudo, e.g. CI)
//!
//! Everything runs in one test function per OS because the tests change process-wide
//! environment variables (XDG directories).

mod common;

use std::fs;

use sealctl::volume::{self, Kind, Volume};

fn unique(prefix: &str) -> String {
    format!("{prefix}{}", std::process::id())
}

#[allow(dead_code)]
fn lifecycle(kind: Kind, mount_in_tmp: bool) {
    let (_sk, pk) = common::software_key();
    let tmp = tempfile::tempdir().unwrap();
    common::isolated_home(tmp.path(), &pk);
    let mut ledger = common::SoftOracle::fixed();
    let name = unique("sct");

    // create: passphrase derived from the "seed" + a fresh volume id, then mounted with it
    let mountpoint = mount_in_tmp.then(|| tmp.path().join("mnt").join(&name));
    let image = tmp.path().join(if kind == Kind::Luks {
        "v.luks"
    } else {
        "v.sparsebundle"
    });
    let vol = volume::create(
        &mut ledger,
        volume::CreateOpts {
            name: name.clone(),
            kind,
            size: "64m".into(),
            path: Some(image.clone()),
            container: None,
            mountpoint: mountpoint.clone(),
        },
    )
    .expect("create volume");
    assert!(vol.is_unlocked().unwrap(), "mounted after create");
    assert_eq!(vol.id.len(), 36, "volume id is a UUID");
    // nothing secret was written next to the config
    let leftovers: Vec<_> = fs::read_dir(sealctl::paths::volumes_dir().unwrap())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".toml"))
        .collect();
    assert!(leftovers.is_empty(), "no key files: {leftovers:?}");
    fs::write(vol.mountpoint.join("hello.txt"), b"hello from sealctl").unwrap();

    // backups: a repository as sealctl 0.2.0 made it (password derived from the URL) ...
    let have_restic = common::have("restic");
    let repo = tmp.path().join("repo").to_string_lossy().into_owned();
    if have_restic {
        sealctl::backup::init(&mut ledger, &name, &repo, Some(&repo), &[]).expect("backup init");
        sealctl::backup::run(std::slice::from_ref(&name), false, false, true).expect("backup run");
        // ... moved to the portable key id (the volume name) by restic key add/remove
        sealctl::backup::rekey(&mut ledger, &name, None).expect("backup rekey");
        let policy = Volume::load(&name).unwrap().backup.unwrap();
        assert_eq!(policy.password_id(), name, "key id is the volume name");
        sealctl::backup::run(std::slice::from_ref(&name), false, false, true).expect("backup after rekey");
        let st = sealctl::backup::load_state(&name);
        assert!(st.last_success.is_some() && st.last_error.is_none());
    } else {
        eprintln!("restic not installed — skipping backup part");
    }

    // lock (runs the on-lock backup)
    volume::lock(&name, false, false).expect("lock");
    assert!(!Volume::load(&name).unwrap().is_unlocked().unwrap(), "locked");

    // a different seed cannot open it
    let mut other = common::SoftOracle(x25519_dalek::StaticSecret::from([9u8; 32]));
    assert!(volume::unlock(&mut other, &name).is_err(), "other seed rejected");

    // forget everything on this machine except the disk, then recover from "seed" + disk
    volume::remove(&name, false).unwrap();
    let target = image.to_string_lossy().into_owned();
    volume::import(&name, kind, &target, mountpoint).expect("import from disk");
    let vol = volume::unlock(&mut ledger, &name).expect("unlock with the seed-derived key");
    assert_eq!(
        fs::read(vol.mountpoint.join("hello.txt")).unwrap(),
        b"hello from sealctl"
    );

    // re-init with only the seed and the volume name reconnects to the same repository; the old
    // URL-derived password no longer opens it
    if have_restic {
        fs::remove_dir_all(vol.inner_dir()).unwrap();
        let err = sealctl::backup::init(&mut ledger, &name, &repo, Some(&repo), &[])
            .expect_err("URL key was removed by rekey");
        assert!(format!("{err:#}").contains("not for key id"), "{err:#}");
        assert!(!vol.inner_dir().exists(), "a failed init writes no credentials");
        sealctl::backup::init(&mut ledger, &name, &repo, None, &[]).expect("reconnect to existing repo");
        sealctl::backup::run(std::slice::from_ref(&name), false, false, true)
            .expect("backup after reconnect");
    }

    volume::lock(&name, true, true).expect("final lock");
    volume::remove(&name, true).unwrap();
    assert!(!image.exists(), "data deleted");
}

#[cfg(target_os = "macos")]
#[test]
fn macos_sparsebundle_lifecycle() {
    lifecycle(Kind::Sparsebundle, true);
}

#[cfg(target_os = "linux")]
#[test]
fn linux_luks_lifecycle() {
    if std::env::var_os("SEALCTL_TEST_SUDO").is_none() {
        eprintln!("set SEALCTL_TEST_SUDO=1 (passwordless sudo) to run the LUKS test");
        return;
    }
    std::env::set_var("SEALCTL_SUDO_NONINTERACTIVE", "1");
    lifecycle(Kind::Luks, true);
}

/// APFS volume inside a throwaway (unencrypted) APFS disk image — never touches real disks.
#[cfg(target_os = "macos")]
#[test]
fn macos_apfs_volume_backend() {
    use std::process::Command;
    let tmp = tempfile::tempdir().unwrap();
    let img = tmp.path().join("container.sparseimage");
    let ok = Command::new("hdiutil")
        .args([
            "create", "-quiet", "-size", "2g", "-type", "SPARSE", "-fs", "APFS", "-volname", "sctbase",
        ])
        .arg(&img)
        .status()
        .unwrap();
    assert!(ok.success());
    let out = Command::new("hdiutil")
        .args(["attach", "-nomount", "-plist"])
        .arg(&img)
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout);
    // Each <dict> of system-entities has a content-hint and a dev-entry; the synthesized APFS
    // container has content-hint EF57347C-0000-11AA-AA11-00306543ECAC.
    let entry = |d: &str, key: &str| -> Option<String> {
        let i = d.find(&format!("<key>{key}</key>"))?;
        let rest = &d[i..];
        let a = rest.find("<string>")? + "<string>".len();
        let b = rest[a..].find("</string>")?;
        Some(rest[a..a + b].to_string())
    };
    let mut whole = None;
    let mut container = None;
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
    let whole = whole.expect("whole disk");
    let container = container.expect("APFS container");
    let name = unique("sctapfs");
    let mut v = Volume {
        name: name.clone(),
        kind: Kind::ApfsVolume,
        path: None,
        id: container.clone(),
        mountpoint: std::path::Path::new("/Volumes").join(&name),
        backup: None,
    };
    let be = volume::backend(Kind::ApfsVolume);
    let mut ledger = common::SoftOracle::fixed();
    let res = (|| -> anyhow::Result<()> {
        use sealctl::derive::{canonical_id, passphrase, Purpose};
        // created with a temporary passphrase, then switched to the one derived from its UUID
        let mut key_for = |id: &str| passphrase(&mut ledger, Purpose::Volume, &canonical_id(id));
        let pass = be.create(&mut v, "", &mut key_for)?;
        assert_eq!(v.id.len(), 36, "volume UUID recorded");
        assert_eq!(
            be.read_id(&v)?.to_lowercase(),
            v.id.to_lowercase(),
            "UUID readable while locked"
        );
        be.unlock(&v, pass.as_bytes())?;
        assert!(be.is_unlocked(&v)?);
        be.lock(&v, false)?;
        assert!(!be.is_unlocked(&v)?);
        assert!(be.unlock(&v, b"nope").is_err());
        // re-derived from the UUID alone
        let again = passphrase(&mut ledger, Purpose::Volume, &canonical_id(&v.id))?;
        be.unlock(&v, again.as_bytes())?;
        be.lock(&v, false)?;
        Ok(())
    })();
    let _ = Command::new("hdiutil")
        .args(["detach", "-force", &format!("/dev/{whole}")])
        .status();
    res.expect("apfs volume lifecycle");
}
