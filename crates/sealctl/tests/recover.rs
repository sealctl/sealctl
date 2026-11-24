//! `sealctl recover` of volumes with the 24 words alone (SPEC 17), on real OS tools: an APFS
//! volume in an APFS container in a disk image on macOS, a LUKS2 file with `sudo cryptsetup` on
//! Linux. The volume is made by `sealctl volume create` on a paired machine, closed, then opened
//! from another HOME with no pairing, relay or configuration.
#![cfg(any(target_os = "macos", target_os = "linux"))]

mod common;

use std::path::Path;
use std::process::Command;
use std::time::Duration;

use common::{Env, Pty};
use sealctl_fakerelay::{Answer, Phone};

/// `sealctl recover <target>` from an empty HOME, typing `words` on a terminal.
fn recover(home: &Path, target: &str, words: Option<&[String]>) -> (i32, String, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sealctl"));
    c.env_clear()
        .env("HOME", home)
        .env("PATH", std::env::var("PATH").unwrap())
        .env("SEALCTL_AGENT", "0")
        .env("SEALCTL_RELAY", "http://127.0.0.1:9")
        .env("SEALCTL_SUDO_NONINTERACTIVE", "1")
        .args(["recover", target]);
    let pty = Pty::spawn(c);
    for (i, w) in words.unwrap_or_default().iter().enumerate() {
        pty.expect(&format!("Word {} of 24:", i + 1), Duration::from_secs(30));
        pty.line(w);
    }
    pty.wait(Duration::from_secs(120))
}

/// A name for a test volume or container (the APFS tests only: LUKS files are named by path).
#[cfg(target_os = "macos")]
fn random_name(prefix: &str) -> String {
    let mut b = [0u8; 3];
    getrandom::fill(&mut b).unwrap();
    format!(
        "{prefix}{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

/// An APFS disk image of the test, attached; detached (forced) when dropped.
#[cfg(target_os = "macos")]
struct Image {
    /// The whole disk of the image, e.g. `disk5`.
    disk: String,
    /// Its APFS container, e.g. `disk7`.
    container: String,
}

#[cfg(target_os = "macos")]
impl Image {
    fn attach(dir: &Path) -> Image {
        let base = dir.join("container");
        let out = Command::new("/usr/bin/hdiutil")
            .args([
                "create", "-size", "1g", "-type", "SPARSE", "-fs", "APFS", "-volname",
            ])
            .arg(random_name("rcc"))
            .arg(&base)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        let out = Command::new("/usr/bin/hdiutil")
            .args(["attach", "-nomount", "-plist"])
            .arg(base.with_extension("sparseimage"))
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
        // whole disks: the image's own (its partition scheme), then the APFS container
        // synthesized from its APFS partition
        let text = String::from_utf8_lossy(&out.stdout);
        let whole: Vec<String> = text
            .lines()
            .filter_map(|l| {
                l.trim()
                    .strip_prefix("<string>/dev/disk")?
                    .strip_suffix("</string>")
            })
            .filter(|n| !n.contains('s'))
            .map(|n| format!("disk{n}"))
            .collect();
        assert_eq!(whole.len(), 2, "{text}");
        let (disk, container) = (whole[0].clone(), whole[1].clone());
        Image { disk, container }
    }
}

#[cfg(target_os = "macos")]
impl Drop for Image {
    fn drop(&mut self) {
        let _ = Command::new("/usr/bin/hdiutil")
            .args(["detach", "-force", &format!("/dev/{}", self.disk)])
            .output();
    }
}

#[cfg(target_os = "macos")]
fn diskutil_info(target: &str, key: &str) -> Option<String> {
    let out = Command::new("diskutil").args(["info", target]).output().ok()?;
    String::from_utf8_lossy(&out.stdout).lines().find_map(|l| {
        l.trim()
            .strip_prefix(key)
            .map(|r| r.trim_start_matches(':').trim().to_string())
    })
}

#[cfg(target_os = "macos")]
#[test]
fn recover_an_apfs_volume_with_the_words() {
    let mut env = Env::new();
    env.pair();
    let image = Image::attach(env.h());
    let name = random_name("rcv");
    let ((code, out, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "volume",
            "create",
            &name,
            "--kind",
            "apfs",
            "--container",
            &image.container,
        ])
    });
    assert_eq!(code, 0, "{err}");
    let mnt = out.trim().to_string();
    assert_eq!(mnt, format!("/Volumes/{name}"));
    std::fs::write(Path::new(&mnt).join("hello.txt"), "kept").unwrap();
    let def = std::fs::read_to_string(env.h().join(format!(".config/sealctl/volumes/{name}.toml"))).unwrap();
    let uuid = def
        .lines()
        .find_map(|l| l.strip_prefix("id = \"")?.strip_suffix('"'))
        .unwrap()
        .to_string();
    let (code, _, err) = env.run(&["volume", "close", &name]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(diskutil_info(&uuid, "Mounted").as_deref(), Some("No"));
    env.stop_daemon();

    let other = tempfile::Builder::new().prefix("sc").tempdir_in("/tmp").unwrap();
    // other words: the hint names both, nothing is unlocked
    let other_phone = Phone::new("http://127.0.0.1:9");
    let (code, out, screen) = recover(other.path(), &uuid, Some(&other_phone.words()[..]));
    assert_eq!(code, 10, "{screen}");
    assert!(out.is_empty());
    assert!(
        screen.contains(&format!(
            "These words have fingerprint {}; this object was sealed with words {}.",
            other_phone.fingerprint(),
            env.phone.fingerprint()
        )),
        "{screen}"
    );
    assert_eq!(diskutil_info(&uuid, "Mounted").as_deref(), Some("No"));

    // the words: unlocked and mounted, by UUID in either case
    let (code, out, screen) = recover(other.path(), &uuid.to_uppercase(), Some(&env.phone.words()[..]));
    assert_eq!(code, 0, "{screen}");
    assert_eq!(out.trim(), mnt);
    assert!(
        screen.contains(&format!("Lock with: diskutil apfs lockVolume {uuid}")),
        "{screen}"
    );
    assert_eq!(
        std::fs::read_to_string(Path::new(&mnt).join("hello.txt")).unwrap(),
        "kept"
    );
    assert!(Path::new(&mnt).join(".sealctl/volume.id").exists());
    // mounted already: said so, no words asked
    let (code, out, screen) = recover(other.path(), &uuid, None);
    assert_eq!(code, 0, "{screen}");
    assert_eq!(out.trim(), mnt);
    assert!(screen.contains("Mounted already"), "{screen}");
    assert!(
        !other.path().join(".config").exists(),
        "recover writes no configuration"
    );
    let _ = Command::new("diskutil")
        .args(["apfs", "lockVolume", &uuid])
        .output();
    assert_eq!(diskutil_info(&uuid, "Mounted").as_deref(), Some("No"));

    // by the name Finder shows, in another case too
    let (code, out, screen) = recover(other.path(), &name.to_uppercase(), Some(&env.phone.words()[..]));
    assert_eq!(code, 0, "{screen}");
    assert_eq!(out.trim(), mnt);
    assert_eq!(
        std::fs::read_to_string(Path::new(&mnt).join("hello.txt")).unwrap(),
        "kept"
    );
    let _ = Command::new("diskutil")
        .args(["apfs", "lockVolume", &uuid])
        .output();

    // a disk identifier that is no APFS volume, nor a name
    let (code, _, screen) = recover(other.path(), "disk999s9", None);
    assert_eq!(code, 9, "{screen}");
    let (code, _, screen) = recover(other.path(), &format!("{name}-none"), None);
    assert_eq!(code, 9, "{screen}");
    drop(image);
}

#[cfg(target_os = "linux")]
fn can_sudo_cryptsetup() -> bool {
    let ok = |c: &str, a: &[&str]| Command::new(c).args(a).output().is_ok_and(|o| o.status.success());
    ok("cryptsetup", &["--version"]) && ok("sudo", &["-n", "true"]) && ok("mkfs.ext4", &["-V"])
}

/// Unmounts and closes what a recover opened (on every way out of the test).
#[cfg(target_os = "linux")]
struct Opened(std::path::PathBuf, String);

#[cfg(target_os = "linux")]
impl Drop for Opened {
    fn drop(&mut self) {
        let _ = Command::new("sudo").arg("-n").arg("umount").arg(&self.0).output();
        let _ = Command::new("sudo")
            .args(["-n", "cryptsetup", "close", &self.1])
            .output();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn recover_a_luks_file_with_the_words() {
    if !can_sudo_cryptsetup() {
        eprintln!("skipped: needs cryptsetup, mkfs.ext4 and password-less sudo");
        return;
    }
    let mut env = Env::new();
    env.pair();
    let file = env.h().join("vaults/safe.luks");
    let mnt = env.h().join("mnt/safe");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let o = env
            .cmd()
            .env("SEALCTL_SUDO_NONINTERACTIVE", "1")
            .args([
                "volume", "create", "safe", "--kind", "luks", "--size", "64m", "--path",
            ])
            .arg(&file)
            .arg("--mountpoint")
            .arg(&mnt)
            .output()
            .unwrap();
        (
            o.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&o.stdout).into_owned(),
            String::from_utf8_lossy(&o.stderr).into_owned(),
        )
    });
    assert_eq!(code, 0, "{err}");
    std::fs::write(mnt.join("hello.txt"), "kept").unwrap();
    let (code, _, err) = env.run(&["volume", "close", "safe"]);
    assert_eq!(code, 0, "{err}");
    env.stop_daemon();
    let uuid = String::from_utf8_lossy(
        &Command::new("cryptsetup")
            .arg("luksUUID")
            .arg(&file)
            .output()
            .unwrap()
            .stdout,
    )
    .trim()
    .to_string();
    let mapper = format!("sealctl-recover-{}", &uuid[..8]);

    let other = tempfile::Builder::new().prefix("sc").tempdir_in("/tmp").unwrap();
    let target = file.to_str().unwrap();
    // other words: the token names both, nothing is opened
    let other_phone = Phone::new("http://127.0.0.1:9");
    let (code, out, screen) = recover(other.path(), target, Some(&other_phone.words()[..]));
    assert_eq!(code, 10, "{screen}");
    assert!(out.is_empty());
    assert!(
        screen.contains(&format!(
            "this object was sealed with words {}.",
            env.phone.fingerprint()
        )),
        "{screen}"
    );
    assert!(!Path::new("/dev/mapper").join(&mapper).exists());

    // the words: opened and mounted at ~/Vaults/<file name>
    let want = other.path().join("Vaults/safe");
    let opened = Opened(want.clone(), mapper.clone());
    let (code, out, screen) = recover(other.path(), target, Some(&env.phone.words()[..]));
    assert_eq!(code, 0, "{screen}");
    assert_eq!(out.trim(), want.to_str().unwrap());
    assert!(
        screen.contains(&format!("sudo cryptsetup close {mapper}")),
        "{screen}"
    );
    assert_eq!(std::fs::read_to_string(want.join("hello.txt")).unwrap(), "kept");
    assert!(want.join(".sealctl/volume.id").exists());
    // open already: busy, nothing asked
    let (code, _, screen) = recover(other.path(), target, None);
    assert_eq!(code, 11, "{screen}");
    drop(opened);

    // without the token (its import is best effort): the LUKS UUID and the words still open it,
    // and other words do not
    let out = Command::new("sudo")
        .args(["-n", "cryptsetup", "token", "remove", "--token-id", "0"])
        .arg(&file)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let (code, _, screen) = recover(other.path(), target, Some(&other_phone.words()[..]));
    assert_eq!(code, 10, "{screen}");
    assert!(
        screen.contains("The key from these words does not open this volume."),
        "{screen}"
    );
    let opened = Opened(want.clone(), mapper.clone());
    let (code, out, screen) = recover(other.path(), target, Some(&env.phone.words()[..]));
    assert_eq!(code, 0, "{screen}");
    assert_eq!(out.trim(), want.to_str().unwrap());
    assert_eq!(std::fs::read_to_string(want.join("hello.txt")).unwrap(), "kept");
    drop(opened);
    assert!(
        !other.path().join(".config").exists(),
        "recover writes no configuration"
    );
}
