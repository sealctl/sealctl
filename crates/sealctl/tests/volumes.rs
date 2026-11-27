//! Volumes and backups on derived keys with the real OS tools (SPEC 13, 14, 18): sparse bundles
//! with `hdiutil` on macOS, restic folder repositories. Disk images live in temporary folders.
//! Against the fake relay or the live one (`SEALCTL_TEST_RELAY`).
#![cfg(target_os = "macos")]

mod common;

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use common::{canary, have, Env, PhoneThread, Pick, Pty};
use sealctl_fakerelay::Answer;

fn restic(repo: &std::path::Path, password: &str, args: &[&str]) -> std::process::Output {
    let mut c = Command::new("restic")
        .env("RESTIC_REPOSITORY", repo)
        .env("RESTIC_PASSWORD_FILE", "/dev/stdin")
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(password.as_bytes()).unwrap();
    c.wait_with_output().unwrap()
}

/// `name: value` from passwords.txt.
fn password_in(run: &std::path::Path, name: &str) -> String {
    std::fs::read_to_string(run.join("passwords.txt"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")).map(str::to_owned))
        .expect("password line")
}

fn run_dir(env: &Env) -> std::path::PathBuf {
    std::fs::read_dir(env.h())
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .find(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("sealctl-unsealed-")
        })
        .expect("run folder")
}

#[cfg(target_os = "macos")]
fn hdiutil_opens(bundle: &std::path::Path, pass: &str) -> bool {
    let mut c = Command::new("/usr/bin/hdiutil")
        .args(["attach", "-nomount", "-plist", "-stdinpass"])
        .arg(bundle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(pass.as_bytes()).unwrap();
    let o = c.wait_with_output().unwrap();
    if !o.status.success() {
        return false;
    }
    let t = String::from_utf8_lossy(&o.stdout);
    let devs: Vec<&str> = t
        .split("<string>")
        .filter_map(|s| s.split("</string>").next())
        .filter(|s| s.starts_with("/dev/disk"))
        .collect();
    if let Some(d) = devs.iter().min_by_key(|d| d.len()) {
        // never left attached: a detach refused right after the attach is tried again, then forced
        let detached = (0..3).any(|i| {
            if i > 0 {
                std::thread::sleep(Duration::from_secs(1));
            }
            Command::new("/usr/bin/hdiutil")
                .args(["detach", "-quiet", d])
                .status()
                .is_ok_and(|s| s.success())
        }) || Command::new("/usr/bin/hdiutil")
            .args(["detach", "-quiet", "-force", d])
            .status()
            .is_ok_and(|s| s.success());
        assert!(detached, "{d} is still attached");
    }
    true
}

#[cfg(target_os = "macos")]
#[test]
fn sparse_bundle_volume_with_backup_lock_and_unseal() {
    let mut env = Env::new();
    env.pair();
    let bundle = env.h().join("v1.sparsebundle");
    let mnt = env.h().join("mnt/v1");
    let repos = env.h().join("repos");
    let marker = canary();
    let ((code, out, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "volume",
            "create",
            "v1",
            "--kind",
            "sparsebundle",
            "--size",
            "64m",
            "--path",
            bundle.to_str().unwrap(),
            "--mountpoint",
            mnt.to_str().unwrap(),
        ])
    });
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), mnt.to_str().unwrap());
    std::fs::write(mnt.join("hello.txt"), &marker).unwrap();
    let id: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(bundle.join("sealctl.id")).unwrap()).unwrap();
    assert_eq!(id["kind"], "volume");
    assert_eq!(id["words"], env.phone.fingerprint());
    assert!(mnt.join(".sealctl/volume.id").exists());

    let restic_ok = have("restic");
    if restic_ok {
        let ((code, _, err), _) = env.with_phone(Answer::Session, || {
            env.run(&[
                "backup",
                "init",
                "b1",
                "--from",
                "v1",
                "--repo",
                repos.to_str().unwrap(),
            ])
        });
        assert_eq!(code, 0, "{err}");
        let (code, _, err) = env.run(&["backup", "run", "b1", "--quiet"]);
        assert_eq!(code, 0, "{err}");
        // restic's key names the words
        let repo = std::fs::read_dir(&repos).unwrap().next().unwrap().unwrap().path();
        let keys: Vec<_> = std::fs::read_dir(repo.join("keys")).unwrap().flatten().collect();
        assert_eq!(keys.len(), 1);
        let k: serde_json::Value = serde_json::from_slice(&std::fs::read(keys[0].path()).unwrap()).unwrap();
        assert_eq!(k["hostname"], format!("sealctl-{}", env.phone.fingerprint()));
    }

    // lock: on-lock backup, then the volume closes
    let lock = env.run(&["lock"]);
    assert_eq!(lock.0, 0, "{}", report(&env, "lock", &lock));
    let (_, out, _) = lock;
    assert!(out.contains("Volume v1 closed."), "{out}");
    if restic_ok {
        assert!(out.contains("Backed up b1."), "{out}");
    }
    assert!(!mnt.join("hello.txt").exists());

    // open asks the phone again (Locked)
    let ((code, _, err), log) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "v1"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(log, vec!["Open"]);
    assert_eq!(std::fs::read_to_string(mnt.join("hello.txt")).unwrap(), marker);
    let (_, out, _) = env.run(&["status", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["volumes"][0]["mounted"], true, "{out}");
    let (code, _, err) = env.run(&["volume", "close", "v1"]);
    assert_eq!(code, 0, "{err}");
    if restic_ok {
        // a mount point folder left behind is not the volume: no empty snapshot of it
        std::fs::create_dir_all(&mnt).unwrap();
        let (code, _, err) = env.run(&["backup", "run", "b1", "--quiet"]);
        assert_ne!(code, 0, "backed up a closed volume");
        assert!(err.contains("Volume v1 is not open."), "{err}");
    }

    // unseal the volume (and the backup): new passwords in the folder, sealctl's gone
    let mut c = env.cmd();
    c.args(["unseal", "volume", "v1"]);
    let pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    let run = run_dir(&env);
    let pw = password_in(&run, "volume v1");
    assert!(hdiutil_opens(&bundle, &pw), "the new passphrase opens it");
    assert!(!bundle.join("sealctl.id").exists());
    assert!(!env.h().join(".config/sealctl/volumes/v1.toml").exists());

    if restic_ok {
        let mut c = env.cmd();
        c.args(["unseal", "backup", "b1"]);
        let pty = Pty::spawn(c);
        pty.expect("Start?", Duration::from_secs(30));
        let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
        pty.line("y");
        let (code, _, screen) = pty.wait(Duration::from_secs(180));
        assert_eq!(code, 0, "{screen}");
        let run2 = std::fs::read_dir(env.h())
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .unwrap()
                    .to_string_lossy()
                    .starts_with("sealctl-unsealed-")
            })
            .max()
            .unwrap();
        let pw = password_in(&run2, "backup b1");
        let repo = std::fs::read_dir(&repos).unwrap().next().unwrap().unwrap().path();
        let o = restic(&repo, &pw, &["snapshots", "--json"]);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let keys = restic(&repo, &pw, &["key", "list", "--json"]);
        let ks: serde_json::Value = serde_json::from_slice(&keys.stdout).unwrap();
        assert_eq!(ks.as_array().unwrap().len(), 1, "only the user's key is left");
        let envfile = std::fs::read_to_string(run2.join("backup-b1.env")).unwrap();
        assert!(envfile.contains("RESTIC_REPOSITORY="));
    }
}

/// A sparse bundle volume `u` with a file in it, created and mounted at `mnt/u`.
#[cfg(target_os = "macos")]
fn bundle_with_a_file(env: &Env) -> (std::path::PathBuf, String) {
    let bundle = env.h().join("u.sparsebundle");
    let mnt = env.h().join("mnt/u");
    let marker = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "volume",
            "create",
            "u",
            "--kind",
            "sparsebundle",
            "--size",
            "32m",
            "--path",
            bundle.to_str().unwrap(),
            "--mountpoint",
            mnt.to_str().unwrap(),
        ])
    });
    assert_eq!(code, 0, "{err}");
    std::fs::write(mnt.join("keep.txt"), &marker).unwrap();
    (mnt, marker)
}

/// `diskutil unmount`: the file system unmounted, the image still attached.
#[cfg(target_os = "macos")]
fn unmount(mnt: &std::path::Path) {
    let out = Command::new("diskutil").arg("unmount").arg(mnt).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(!mnt.join("keep.txt").exists());
}

/// Polls `f` every 100 ms for up to `secs` seconds.
#[cfg(feature = "test-hooks")]
fn until(secs: u64, mut f: impl FnMut() -> bool) -> bool {
    for _ in 0..secs * 10 {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    f()
}

/// Whether `hdiutil info` lists an image at `bundle`.
fn attached(bundle: &std::path::Path) -> bool {
    let real = std::fs::canonicalize(bundle).unwrap_or_else(|_| bundle.to_path_buf());
    let info = Command::new("hdiutil").arg("info").output().unwrap();
    let info = String::from_utf8_lossy(&info.stdout);
    info.lines().any(|l| {
        l.strip_prefix("image-path")
            .and_then(|r| r.split_once(':'))
            .is_some_and(|(_, p)| {
                let p = std::path::Path::new(p.trim());
                p == bundle || p == real
            })
    })
}

/// What a failed check needs: a command's output, the daemon's log, and the `hdiutil info`
/// blocks of this HOME's images (not the machine's other images).
fn report(env: &Env, what: &str, (code, out, err): &(i32, String, String)) -> String {
    let log = std::fs::read_to_string(env.h().join("s/sealctl/daemon.log")).unwrap_or_default();
    let info = Command::new("hdiutil").arg("info").output().unwrap();
    let home = std::fs::canonicalize(env.h()).unwrap();
    let blocks: Vec<String> = String::from_utf8_lossy(&info.stdout)
        .split("================================================")
        .filter(|b| b.contains(env.h().to_str().unwrap()) || b.contains(home.to_str().unwrap()))
        .map(str::to_owned)
        .collect();
    format!(
        "{what}: exit {code}\n--- stdout\n{out}\n--- stderr\n{err}\n--- daemon.log\n{log}\n\
         --- hdiutil info (exit {}, stderr {:?})\n{}",
        info.status,
        String::from_utf8_lossy(&info.stderr).trim(),
        blocks.join("====\n")
    )
}

/// Detaches the test's bundle however the test ends, so nothing stays attached.
struct Detach<'a>(&'a Env, std::path::PathBuf, std::path::PathBuf);

impl Drop for Detach<'_> {
    fn drop(&mut self) {
        if attached(&self.1) {
            let _ = self.0.run(&["volume", "close", "r", "--force"]);
        }
        if attached(&self.1) {
            let _ = Command::new("hdiutil")
                .args(["detach", "-force"])
                .arg(&self.2)
                .output();
        }
    }
}

/// `lock` (its exit code and output) closed volume `r`: it says so, and the image at `bundle`
/// is no longer attached. On failure: the lock's output, daemon.log and `hdiutil info`.
#[cfg(feature = "test-hooks")]
fn closed_by(env: &Env, lock: &(i32, String, String), bundle: &std::path::Path) {
    assert_eq!(lock.0, 0, "{}", report(env, "lock", lock));
    assert!(
        lock.1.contains("Volume r closed."),
        "the lock closed the volume\n{}",
        report(env, "lock", lock)
    );
    assert!(
        !attached(bundle),
        "the image is detached after the lock\n{}",
        report(env, "lock", lock)
    );
}

/// A stand-in `hdiutil` first on PATH: `body` (sh), then the real `/usr/bin/hdiutil`. Like
/// the real one, a stand-in failure says nothing under `-quiet`. Returns the PATH to run with.
fn stand_in_hdiutil(env: &Env, body: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let bin = env.h().join("bin");
    std::fs::create_dir_all(&bin).unwrap();
    std::fs::write(
        bin.join("hdiutil"),
        format!(
            "#!/bin/sh\nquiet() {{ case \" $* \" in *' -quiet '*) return 0;; esac; return 1; }}\n\
             {body}\nexec /usr/bin/hdiutil \"$@\"\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(bin.join("hdiutil"), std::fs::Permissions::from_mode(0o755)).unwrap();
    format!("{}:{}", bin.display(), std::env::var("PATH").unwrap())
}

/// `sealctl args` with `path` as PATH (the daemon it starts gets it too).
fn run_with_path(env: &Env, path: &str, args: &[&str]) -> (i32, String, String) {
    let o = env
        .cmd()
        .env("PATH", path)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap();
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

/// `volume create r` (a 32 MB sparse bundle in the test HOME) with `path` as PATH.
fn create_r(env: &Env, path: &str) -> (i32, String, String) {
    let bundle = env.h().join("r.sparsebundle");
    let mnt = env.h().join("mnt/r");
    let (r, _) = env.with_phone(Answer::Session, || {
        run_with_path(
            env,
            path,
            &[
                "volume",
                "create",
                "r",
                "--kind",
                "sparsebundle",
                "--size",
                "32m",
                "--path",
                bundle.to_str().unwrap(),
                "--mountpoint",
                mnt.to_str().unwrap(),
            ],
        )
    });
    r
}

/// `hdiutil create` refused as `Resource busy` (the disk images service busy with other
/// images, as on a CI runner) once: `volume create` tries again and the volume is made.
#[test]
fn volume_create_tries_again_after_hdiutil_create_was_busy() {
    let mut env = Env::new();
    env.pair();
    let once = env.h().join("create-was-busy");
    let path = stand_in_hdiutil(
        &env,
        &format!(
            "if [ \"$1\" = create ] && [ ! -e '{0}' ]; then\n  : > '{0}'\n  \
             quiet \"$@\" || echo 'hdiutil: create failed - Resource busy' >&2\n  exit 1\nfi",
            once.display()
        ),
    );
    let bundle = env.h().join("r.sparsebundle");
    let _detach = Detach(&env, bundle.clone(), env.h().join("mnt/r"));
    let (code, _, err) = create_r(&env, &path);
    assert!(once.exists(), "the stand-in was asked");
    assert_eq!(code, 0, "{err}");
    assert!(attached(&bundle));
}

/// Any other `hdiutil create` failure is reported at once, with hdiutil's reason (not an
/// empty `hdiutil create failed:`), and not tried again.
#[test]
fn volume_create_reports_why_hdiutil_create_failed() {
    let mut env = Env::new();
    env.pair();
    let calls = env.h().join("create-calls");
    let path = stand_in_hdiutil(
        &env,
        &format!(
            "if [ \"$1\" = create ]; then\n  echo x >> '{}'\n  \
             quiet \"$@\" || echo 'hdiutil: create failed - No space left on device' >&2\n  \
             exit 1\nfi",
            calls.display()
        ),
    );
    let (code, _, err) = create_r(&env, &path);
    assert_eq!(code, 1, "{err}");
    assert!(
        err.contains("hdiutil create failed: hdiutil: create failed - No space left on device"),
        "{err}"
    );
    assert_eq!(
        std::fs::read_to_string(&calls).unwrap().lines().count(),
        1,
        "not tried again"
    );
}

/// A lock that cannot tell whether a volume is open (`hdiutil info` fails) does not pass over
/// it as closed: it tries to close it, and when that fails too, reports it busy (exit 11, tried
/// again every minute, SPEC 6.5) rather than "Locked." with the volume still mounted. A
/// stand-in `hdiutil` on PATH, for the daemon too, fails `info` while `hdiutil-info-fails`
/// exists and runs the real one otherwise.
#[test]
fn a_lock_that_cannot_list_the_images_reports_the_volume_busy() {
    let mut env = Env::new();
    env.pair();
    // the daemon started for the pairing has the plain PATH; the next command starts another
    env.stop_daemon();
    let fails = env.h().join("hdiutil-info-fails");
    let path = stand_in_hdiutil(
        &env,
        &format!(
            "if [ \"$1\" = info ] && [ -e '{}' ]; then\n  \
             echo 'hdiutil: info failed - stand-in' >&2\n  exit 1\nfi",
            fails.display()
        ),
    );
    let bundle = env.h().join("r.sparsebundle");
    let (code, _, err) = create_r(&env, &path);
    assert_eq!(code, 0, "{err}");
    let _detach = Detach(&env, bundle.clone(), env.h().join("mnt/r"));
    std::fs::write(&fails, b"").unwrap();
    let lock = run_with_path(&env, &path, &["lock"]);
    std::fs::remove_file(&fails).unwrap();
    // the image is still attached: finding its device for the detach needs `hdiutil info` too
    assert!(attached(&bundle));
    assert_eq!(
        lock.0,
        11,
        "busy, not Locked with the volume mounted\n{}",
        report(&env, "lock", &lock)
    );
    assert!(
        lock.1.contains("Volume r could not be checked"),
        "the lock names the volume\n{}",
        report(&env, "lock", &lock)
    );
}

/// A lock just after a volume was mounted, written or backed up, while a macOS service still
/// holds it (SPEC 6.5 step 3): `hdiutil detach` is refused as `Resource busy` for longer than
/// its three quick tries, and no process of the user's has files open. The lock tries again
/// and closes the volume, instead of exit 11 with it left mounted until the next minute. A
/// stand-in `hdiutil` on PATH, for the daemon too, refuses the lock's first five plain detaches.
#[test]
fn a_lock_closes_a_volume_a_service_holds_for_a_few_seconds() {
    let mut env = Env::new();
    env.pair();
    // the daemon started for the pairing has the plain PATH; the next command starts another
    env.stop_daemon();
    let refused = env.h().join("detach-refused");
    let path = stand_in_hdiutil(
        &env,
        &format!(
            "if [ \"$1\" = detach ] && [ \"$2\" != -force ] && [ -e '{0}' ] && \
             [ $(wc -l < '{0}') -lt 5 ]; then\n  \
             echo x >> '{0}'\n  \
             echo 'hdiutil: detach failed - Resource busy' >&2\n  exit 16\nfi",
            refused.display()
        ),
    );
    let bundle = env.h().join("r.sparsebundle");
    let (code, _, err) = create_r(&env, &path);
    assert_eq!(code, 0, "{err}");
    let _detach = Detach(&env, bundle.clone(), env.h().join("mnt/r"));
    // from now on, the first five plain detaches are refused
    std::fs::write(&refused, b"").unwrap();
    let lock = run_with_path(&env, &path, &["lock"]);
    assert_eq!(lock.0, 0, "{}", report(&env, "lock", &lock));
    assert!(
        lock.1.contains("Volume r closed."),
        "the lock closed the volume\n{}",
        report(&env, "lock", &lock)
    );
    assert!(!attached(&bundle), "{}", report(&env, "lock", &lock));
    let refusals = std::fs::read_to_string(&refused).unwrap_or_default();
    assert_eq!(refusals.lines().count(), 5, "every refusal was tried again");
}

/// A lock while an `open` is mounting an auto volume (SPEC 6.5): the lock's unmount waits for
/// that mount, so the volume is closed and detached once the lock is done. The `mount` hold
/// point (`test-hooks`) stops the daemon just before it mounts, the session checked Open.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn a_lock_while_an_open_mounts_a_volume_leaves_it_closed() {
    let mut env = Env::new();
    env.pair();
    let bundle = env.h().join("r.sparsebundle");
    let mnt = env.h().join("mnt/r");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "volume",
            "create",
            "r",
            "--kind",
            "sparsebundle",
            "--size",
            "32m",
            "--path",
            bundle.to_str().unwrap(),
            "--mountpoint",
            mnt.to_str().unwrap(),
        ])
    });
    assert_eq!(code, 0, "{err}");
    let _detach = Detach(&env, bundle.clone(), mnt.clone());
    std::fs::write(mnt.join("keep.txt"), canary()).unwrap();
    let lock = env.run(&["lock"]);
    closed_by(&env, &lock, &bundle);

    let state = env.h().join("s/sealctl");
    let hold = state.join("test-hold-mount");
    let held = state.join("test-held-mount");
    let _ = std::fs::remove_file(&held);
    std::fs::write(&hold, b"").unwrap();
    let spawn = |args: &[&str]| {
        let mut c = env.cmd();
        c.args(args).stdin(Stdio::null());
        std::thread::spawn(move || c.output().unwrap())
    };
    let (lock, _) = env.with_phone(Answer::Session, || {
        let open = spawn(&["open"]);
        assert!(until(60, || held.exists()), "the daemon stopped before the mount");
        let lock = spawn(&["lock"]);
        let locked = until(20, || {
            let (_, out, _) = env.run(&["status", "--json"]);
            serde_json::from_str::<serde_json::Value>(&out).is_ok_and(|v| v["state"] == "locked")
        });
        assert!(locked, "the session locked while the mount waited");
        // the mount goes on after the lock began
        std::fs::remove_file(&hold).unwrap();
        let lock = lock.join().unwrap();
        open.join().unwrap();
        lock
    });
    let lock = (
        lock.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&lock.stdout).into_owned(),
        String::from_utf8_lossy(&lock.stderr).into_owned(),
    );
    closed_by(&env, &lock, &bundle);
    assert!(
        !mnt.join("keep.txt").exists(),
        "the volume is not mounted after the lock"
    );
    let (_, out, _) = env.run(&["status", "--json"]);
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["state"], "locked", "{out}");
    assert_eq!(v["volumes"][0]["mounted"], false, "{out}");
}

/// A bundle attached with nothing mounted from it (a key check that could not detach, a mount
/// that did not finish) is not taken for an open volume with an empty mount point: `volume open`
/// detaches it and opens the volume, and its files are there.
#[cfg(target_os = "macos")]
#[test]
fn volume_open_of_a_bundle_attached_with_nothing_mounted_opens_it() {
    let mut env = Env::new();
    env.pair();
    let (mnt, marker) = bundle_with_a_file(&env);
    unmount(&mnt);
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "u"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(out.trim(), mnt.to_str().unwrap());
    assert_eq!(std::fs::read_to_string(mnt.join("keep.txt")).unwrap(), marker);
    let (code, _, err) = env.run(&["volume", "close", "u"]);
    assert_eq!(code, 0, "{err}");
}

/// A bundle mounted somewhere other than its mount point may be in use there: `volume open`
/// says so and leaves it, instead of reporting an empty mount point as open.
#[cfg(target_os = "macos")]
#[test]
fn volume_open_of_a_bundle_mounted_elsewhere_says_so() {
    let mut env = Env::new();
    env.pair();
    let (mnt, marker) = bundle_with_a_file(&env);
    unmount(&mnt);
    // the image's file system device: the last /dev entry of its `hdiutil info` block
    let info = Command::new("hdiutil").arg("info").output().unwrap();
    let info = String::from_utf8_lossy(&info.stdout);
    let block = info
        .split("================================================")
        .find(|b| b.contains("u.sparsebundle"))
        .expect("the bundle is attached");
    let dev = block
        .lines()
        .rfind(|l| l.starts_with("/dev/"))
        .and_then(|l| l.split('\t').next())
        .unwrap()
        .trim()
        .to_string();
    let other = env.h().join("elsewhere");
    std::fs::create_dir_all(&other).unwrap();
    let out = Command::new("diskutil")
        .args(["mount", "-mountPoint"])
        .arg(&other)
        .arg(&dev)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(std::fs::read_to_string(other.join("keep.txt")).unwrap(), marker);
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "u"]));
    assert_ne!(code, 0, "an empty mount point is not an open volume: {out}");
    assert!(err.contains("not mounted at"), "{err}");
    assert_eq!(
        std::fs::read_to_string(other.join("keep.txt")).unwrap(),
        marker,
        "left as it was"
    );
    let (code, _, err) = env.run(&["volume", "close", "u"]);
    assert_eq!(code, 0, "{err}");
}

#[cfg(target_os = "macos")]
#[test]
fn seal_an_existing_sparse_bundle_and_restic_repository() {
    let mut env = Env::new();
    env.pair();
    let own = canary();
    let bundle = env.h().join("mine.sparsebundle");
    // the product's create: hdiutil's reason on a failure, and a create refused as
    // `Resource busy` (other tests' images) tried again
    sealctl::volume::sparsebundle::create_image(&bundle, "32m", "mine", own.as_bytes()).unwrap();

    let mut c = env.cmd();
    c.args([
        "seal",
        "volume",
        "mine",
        bundle.to_str().unwrap(),
        "--mountpoint",
        env.h().join("mnt/mine").to_str().unwrap(),
    ]);
    let pty = Pty::spawn(c);
    pty.expect("Passphrase of", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&own);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(screen.contains("pick "), "level 2 with the number: {screen}");
    assert!(phone.kinds().contains(&"Keys".to_string()));
    drop(phone);
    assert!(
        !hdiutil_opens(&bundle, &own),
        "the old passphrase no longer opens it"
    );
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "mine"]));
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("mnt/mine"));
    env.run(&["volume", "close", "mine"]);

    if !have("restic") {
        return;
    }
    let repo = env.h().join("myrepo");
    let rpw = canary();
    assert!(restic(&repo, &rpw, &["init"]).status.success());
    let src = env.h().join("data");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), "x").unwrap();
    let mut c = env.cmd();
    c.args([
        "seal",
        "backup",
        "mine-b",
        "--repo",
        repo.to_str().unwrap(),
        "--from",
        src.to_str().unwrap(),
    ]);
    let pty = Pty::spawn(c);
    pty.expect("Password of the restic repository:", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&rpw);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(
        !restic(&repo, &rpw, &["cat", "config"]).status.success(),
        "old password removed"
    );
    let (code, _, err) = env.run(&["backup", "run", "mine-b", "--quiet"]);
    assert_eq!(code, 0, "{err}");
}

/// `unseal backup` killed (SIGKILL) right after sealctl's restic key is removed, so that only
/// the new password opens the repository: `--resume` reads that password back from the folder
/// store instead of making another, and finishes with it.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn unseal_backup_resumed_after_the_key_change_keeps_the_new_password() {
    use std::os::unix::process::ExitStatusExt;

    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    let repo = env.h().join("myrepo");
    let rpw = canary();
    assert!(restic(&repo, &rpw, &["init"]).status.success());
    let src = env.h().join("data");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("f"), "x").unwrap();
    let mut c = env.cmd();
    c.args([
        "seal",
        "backup",
        "rb",
        "--repo",
        repo.to_str().unwrap(),
        "--from",
        src.to_str().unwrap(),
    ]);
    let pty = Pty::spawn(c);
    pty.expect("Password of the restic repository:", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&rpw);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    drop(phone);

    let mut c = env.cmd();
    c.env("SEALCTL_TEST_KILL", "changed:backup")
        .args(["unseal", "backup", "rb"]);
    let mut pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = pty.child.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() > Duration::from_secs(180) {
            let _ = pty.child.kill();
            panic!("not killed; screen:\n{}", pty.screen.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let screen = pty.screen.lock().unwrap().clone();
    assert_eq!(status.signal(), Some(9), "killed at the hook: {screen}");
    drop(phone);
    let run = run_dir(&env);
    let first = password_in(&run, "backup rb");
    let keys = restic(&repo, &first, &["key", "list", "--json"]);
    assert!(keys.status.success(), "the new password opens it");
    let ks: serde_json::Value = serde_json::from_slice(&keys.stdout).unwrap();
    assert_eq!(ks.as_array().unwrap().len(), 1, "sealctl's key is gone already");

    let mut c = env.cmd();
    c.args(["unseal", "--resume"]);
    let pty = Pty::spawn(c);
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    let (code, _, screen) = pty.wait(Duration::from_secs(180));
    assert_eq!(code, 0, "{screen}");
    assert!(run.join("done").exists());
    assert_eq!(password_in(&run, "backup rb"), first, "the same password");
    let envfile = std::fs::read_to_string(run.join("backup-rb.env")).unwrap();
    assert!(envfile.contains(&first), "backup-rb.env has the same password");
    let o = restic(&repo, &first, &["snapshots", "--json"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
}

/// The passphrase shown by `unseal volume --to show` on the terminal (no controlling terminal
/// for the run, so the `show` store writes to the pseudo-terminal it reads from).
#[cfg(feature = "test-hooks")]
fn shown_passphrase(screen: &str, name: &str) -> String {
    let head = format!("New passphrase for volume {name}: ");
    let at = screen.rfind(&head).expect("a shown passphrase") + head.len();
    screen[at..].split(['\r', '\n']).next().unwrap().to_string()
}

#[cfg(feature = "test-hooks")]
fn last4(s: &str) -> String {
    let c: Vec<char> = s.chars().collect();
    c[c.len() - 4..].iter().collect()
}

/// `unseal volume --to show` killed (SIGKILL) right after its new passphrase is shown and
/// journalled, before the bundle changes. sealctl's key still opens the bundle, so `--resume`
/// never asks for that passphrase back (a mistyped one would become the bundle's): it shows a
/// new one, and only that one opens the bundle at the end.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn unseal_volume_to_show_resumed_before_the_change_shows_a_new_passphrase() {
    use std::os::unix::process::{CommandExt, ExitStatusExt};

    let mut env = Env::new();
    env.pair();
    let bundle = env.h().join("sv.sparsebundle");
    let mnt = env.h().join("mnt/sv");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "volume",
            "create",
            "sv",
            "--kind",
            "sparsebundle",
            "--size",
            "32m",
            "--path",
            bundle.to_str().unwrap(),
            "--mountpoint",
            mnt.to_str().unwrap(),
        ])
    });
    assert_eq!(code, 0, "{err}");
    let no_tty = |c: &mut Command| unsafe {
        c.pre_exec(|| {
            nix::unistd::setsid().map_err(std::io::Error::from)?;
            Ok(())
        });
    };

    let mut c = env.cmd();
    c.env("SEALCTL_TEST_KILL", "password:volume")
        .args(["unseal", "volume", "sv", "--to", "show"]);
    no_tty(&mut c);
    let pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let screen = pty.expect("Type its last 4 characters", Duration::from_secs(120));
    let first = shown_passphrase(&screen, "sv");
    pty.line(&last4(&first));
    let mut pty = pty;
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = pty.child.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() > Duration::from_secs(60) {
            let _ = pty.child.kill();
            panic!("not killed; screen:\n{}", pty.screen.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let screen = pty.screen.lock().unwrap().clone();
    assert_eq!(
        status.signal(),
        Some(9),
        "killed at the hook; exit {:?}, screen:\n{screen}",
        status.code()
    );
    drop(phone);
    assert!(!hdiutil_opens(&bundle, &first), "the bundle has not changed yet");

    let mut c = env.cmd();
    c.args(["unseal", "--resume"]);
    no_tty(&mut c);
    let pty = Pty::spawn(c);
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    let screen = pty.expect("Type its last 4 characters", Duration::from_secs(120));
    assert!(!screen.contains("Type the passphrase you wrote down"), "{screen}");
    assert!(screen.contains("A new one replaces it."), "{screen}");
    let second = shown_passphrase(&screen, "sv");
    assert_ne!(second, first);
    pty.line(&last4(&second));
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(
        hdiutil_opens(&bundle, &second),
        "the passphrase shown last opens it"
    );
    assert!(!hdiutil_opens(&bundle, &first), "the first one does not");
}

/// A sparse bundle's id is on disk before its passphrase changes. `seal volume` killed
/// (SIGKILL) right after writing that marker leaves it on a bundle the user's passphrase still
/// opens: sealing it again uses the same id instead of refusing it as sealed.
#[cfg(all(target_os = "macos", feature = "test-hooks"))]
#[test]
fn sealing_a_bundle_resumed_after_a_kill_at_its_marker_uses_its_id() {
    use std::os::unix::process::ExitStatusExt;

    let mut env = Env::new();
    env.pair();
    let own = canary();
    let bundle = env.h().join("left.sparsebundle");
    // the product's create: hdiutil's reason on a failure, and a create refused as
    // `Resource busy` (other tests' images) tried again
    sealctl::volume::sparsebundle::create_image(&bundle, "32m", "left", own.as_bytes()).unwrap();

    let mut c = env.cmd();
    c.env("SEALCTL_TEST_KILL", "marked:seal-volume").args([
        "seal",
        "volume",
        "left",
        bundle.to_str().unwrap(),
        "--mountpoint",
        env.h().join("mnt/left").to_str().unwrap(),
    ]);
    let mut pty = Pty::spawn(c);
    pty.expect("Passphrase of", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&own);
    let start = std::time::Instant::now();
    let status = loop {
        if let Some(st) = pty.child.try_wait().unwrap() {
            break st;
        }
        if start.elapsed() > Duration::from_secs(120) {
            let _ = pty.child.kill();
            panic!("not killed; screen:\n{}", pty.screen.lock().unwrap());
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let screen = pty.screen.lock().unwrap().clone();
    assert_eq!(
        status.signal(),
        Some(9),
        "killed at the hook; exit {:?}, screen:\n{screen}",
        status.code()
    );
    drop(phone);
    let marker: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(bundle.join("sealctl.id")).unwrap()).unwrap();
    let id = marker["id"].as_str().unwrap().to_string();
    assert!(hdiutil_opens(&bundle, &own), "the passphrase has not changed yet");
    assert!(!env.h().join(".config/sealctl/volumes/left.toml").exists());

    let mut c = env.cmd();
    c.args([
        "seal",
        "volume",
        "left",
        bundle.to_str().unwrap(),
        "--mountpoint",
        env.h().join("mnt/left").to_str().unwrap(),
    ]);
    let pty = Pty::spawn(c);
    pty.expect("Passphrase of", Duration::from_secs(30));
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line(&own);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    let marker: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(bundle.join("sealctl.id")).unwrap()).unwrap();
    assert_eq!(marker["id"], id, "the leftover id is used again");
    assert!(!hdiutil_opens(&bundle, &own));
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "left"]));
    assert_eq!(code, 0, "{err}");
    env.run(&["volume", "close", "left"]);
}

#[test]
fn unreadable_files_still_make_a_backup_and_retention_runs() {
    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    let src = env.h().join("docs");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("a.txt"), canary()).unwrap();
    let locked = src.join("locked.txt");
    std::fs::write(&locked, "x").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o000)).unwrap();
    if std::fs::read(&locked).is_ok() {
        return; // root reads it anyway
    }
    let repos = env.h().join("repos");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "backup",
            "init",
            "docs",
            "--from",
            src.to_str().unwrap(),
            "--repo",
            repos.to_str().unwrap(),
        ])
    });
    assert_eq!(code, 0, "{err}");
    // restic exits 3: the snapshot is made, one file is missing from it
    let (code, _, err) = env.run(&["backup", "run", "docs", "--quiet"]);
    assert_eq!(code, 0, "{err}");
    assert!(
        err.contains("Backed up docs (some files could not be read)."),
        "{err}"
    );
    let state = std::fs::read_to_string(env.h().join("s/sealctl/backup/docs.toml")).unwrap();
    assert!(state.contains("last_success"), "{state}");
    assert!(state.contains("last_prune"), "forget ran: {state}");
    assert!(state.contains("could not be read"), "{state}");
    std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o600)).unwrap();
}
