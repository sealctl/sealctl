//! Long operations against each other and against the daemon: a re-encryption resumed after
//! its definition moved, a backup run during a re-encryption, `seal backup` and `unseal`
//! stopped at every step that matters, a secret written while the store moves to new words,
//! two `seal volume` runs on one bundle with the phone answering late, and `scan` while a
//! history file grows. Each interleaving is made explicit: a stand-in `restic` that stops at a
//! named point (`SEALCTL_RESTIC`), a phone that holds a request until the test lets it go, or
//! the journal kill points of `test-hooks`.

mod common;

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use common::{canary, have, Env, PhoneThread, Pick, Pty};
use sealctl_core::request::Request;
use sealctl_core::RequestKind;
use sealctl_fakerelay::{Answer, Background, Phone};

fn restic(repo: &Path, password: &str, args: &[&str]) -> std::process::Output {
    use std::io::Write;
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

/// A stand-in `restic`: a shell script in the test HOME that runs `body` around the real one.
fn wrapper(env: &Env, name: &str, body: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let real = std::env::split_paths(&std::env::var_os("PATH").unwrap())
        .map(|d| d.join("restic"))
        .find(|p| p.is_file())
        .expect("restic on PATH");
    let dir = env.h().join("bin");
    std::fs::create_dir_all(&dir).unwrap();
    let p = dir.join(name);
    std::fs::write(&p, format!("#!/bin/sh\nREAL='{}'\n{body}\n", real.display())).unwrap();
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

fn wait_for(p: &Path, what: &str, secs: u64) {
    let start = Instant::now();
    while !p.exists() {
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "timed out waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn snapshots(env: &Env, name: &str) -> (i32, usize, String) {
    let (code, out, err) = env.run(&["backup", "snapshots", name, "--json"]);
    let n = serde_json::from_str::<serde_json::Value>(&out)
        .ok()
        .and_then(|v| v.as_array().map(Vec::len))
        .unwrap_or(0);
    (code, n, err)
}

/// A backup `b` of a folder, in a repository under `<home>/repos`, with one snapshot.
fn backup_with_snapshot(env: &Env) -> PathBuf {
    let src = env.h().join("data");
    std::fs::create_dir_all(&src).unwrap();
    std::fs::write(src.join("keep.txt"), canary()).unwrap();
    let repos = env.h().join("repos");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let r = env.run(&[
            "backup",
            "init",
            "b",
            "--from",
            src.to_str().unwrap(),
            "--repo",
            repos.to_str().unwrap(),
        ]);
        if r.0 != 0 {
            return r;
        }
        env.run(&["backup", "run", "b", "--quiet"])
    });
    assert_eq!(code, 0, "{err}");
    repos
}

fn job_file(env: &Env) -> PathBuf {
    env.h().join("s/sealctl/migrate.json")
}

/// The re-encryption job stopped (power cut) after the backup's definition named the new
/// repository but before the job wrote that the item was done: the resumed job finds the work
/// done and keeps the new repository, the only one left.
#[test]
fn re_encryption_resumed_after_the_definition_moved_keeps_the_only_repository() {
    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    let repos = backup_with_snapshot(&env);
    let ((code, _, err), _) =
        env.with_phone(Answer::Session, || env.run(&["migrate", "--yes", "--foreground"]));
    assert_eq!(code, 0, "{err}");
    let mut job: serde_json::Value = serde_json::from_slice(&std::fs::read(job_file(&env)).unwrap()).unwrap();
    assert_eq!(job["items"][0]["state"], "done", "{job}");
    // what a power cut between the definition's save and the job's own save leaves
    job["items"][0]["state"] = "running".into();
    std::fs::write(job_file(&env), serde_json::to_vec(&job).unwrap()).unwrap();

    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["migrate", "--run-job"]));
    assert_eq!(code, 0, "{err}");
    let (code, n, err) = snapshots(&env, "b");
    assert_eq!(code, 0, "the backup's repository still opens: {err}");
    assert_eq!(n, 1, "the snapshot is there");
    assert_eq!(std::fs::read_dir(&repos).unwrap().count(), 1, "one repository");
}

/// A backup run while the re-encryption job copies that backup's repository: either the run
/// is refused, or its snapshot is in the repository the backup ends up with. Never a run that
/// reports success into a repository that is then removed.
#[test]
fn a_backup_run_during_its_re_encryption_is_never_lost() {
    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    backup_with_snapshot(&env);
    std::fs::write(env.h().join("data/later.txt"), canary()).unwrap();
    let barrier = env.h().join("barrier");
    std::fs::create_dir_all(&barrier).unwrap();
    // `restic check` comes right after the copy: it waits there for the test
    let w = wrapper(
        &env,
        "restic-check-waits",
        &format!(
            "case \" $* \" in *\" check \"*) touch '{b}/copied'; while [ ! -e '{b}/go' ]; do sleep 0.1; done;; esac\nexec \"$REAL\" \"$@\"",
            b = barrier.display()
        ),
    );
    let bg = Background::start(env.phone.clone(), Answer::Session);
    let job = env
        .cmd()
        .env("SEALCTL_RESTIC", &w)
        .args(["migrate", "--yes", "--foreground"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    wait_for(&barrier.join("copied"), "the copy", 180);
    let (run_code, _, run_err) = env.run(&["backup", "run", "b", "--quiet"]);
    std::fs::write(barrier.join("go"), "").unwrap();
    let out = job.wait_with_output().unwrap();
    let job_err = String::from_utf8_lossy(&out.stderr).into_owned();
    let (code, n, err) = snapshots(&env, "b");
    drop(bg);
    assert_eq!(code, 0, "{err}\njob: {job_err}");
    if run_code == 0 {
        assert_eq!(
            n, 2,
            "the run said it backed up: its snapshot is kept\njob: {job_err}"
        );
    } else {
        assert!(
            run_err.contains("busy") || run_err.contains("re-encrypt"),
            "{run_err}"
        );
        assert_eq!(n, 1, "{job_err}");
    }
}

/// `seal backup` stopped (power cut) right after the user's own restic key was removed: the
/// repository opens with sealctl's key only, so sealctl has its definition by then.
#[test]
fn seal_backup_stopped_after_the_old_key_went_keeps_its_definition() {
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
    let w = wrapper(
        &env,
        "restic-dies-after-key-remove",
        "\"$REAL\" \"$@\"; rc=$?\ncase \" $* \" in *\" key remove \"*) [ $rc -eq 0 ] && kill -9 $PPID;; esac\nexit $rc",
    );
    let mut c = env.cmd();
    c.env("SEALCTL_RESTIC", &w).args([
        "seal",
        "backup",
        "kb",
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
    drop(phone);
    assert_ne!(code, 0, "stopped at the key removal: {screen}");
    let user_opens = restic(&repo, &rpw, &["cat", "config"]).status.success();
    let defined = env.h().join(".config/sealctl/backups/kb.toml").exists();
    assert!(
        user_opens || defined,
        "neither the user's password opens it nor does sealctl know it: {screen}"
    );
    if defined {
        let ((code, _, err), _) =
            env.with_phone(Answer::Session, || env.run(&["backup", "run", "kb", "--quiet"]));
        assert_eq!(code, 0, "{err}");
    }
}

#[cfg(feature = "test-hooks")]
fn run_dir(env: &Env) -> PathBuf {
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

#[cfg(feature = "test-hooks")]
fn password_in(run: &Path, name: &str) -> String {
    std::fs::read_to_string(run.join("passwords.txt"))
        .unwrap()
        .lines()
        .find_map(|l| l.strip_prefix(&format!("{name}: ")).map(str::to_owned))
        .expect("password line")
}

/// `unseal backup` stopped (power cut) after the backup's definition is forgotten but before
/// the step is journalled done: `--resume` finishes the run, and the hand-back list names it.
#[cfg(feature = "test-hooks")]
#[test]
fn unseal_resumed_after_the_definition_went_finishes() {
    use std::os::unix::process::ExitStatusExt;

    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    backup_with_snapshot(&env);
    let mut c = env.cmd();
    c.env("SEALCTL_TEST_KILL", "changed:backup")
        .args(["unseal", "backup", "b"]);
    let mut pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let start = Instant::now();
    let status = loop {
        if let Some(st) = pty.child.try_wait().unwrap() {
            break st;
        }
        assert!(start.elapsed() < Duration::from_secs(180), "not killed");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.signal(), Some(9));
    drop(phone);
    // the rest of the step up to its journal line: the definition is forgotten
    std::fs::remove_file(env.h().join(".config/sealctl/backups/b.toml")).unwrap();

    let mut c = env.cmd();
    c.args(["unseal", "--resume"]);
    let pty = Pty::spawn(c);
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    let (code, _, screen) = pty.wait(Duration::from_secs(180));
    assert_eq!(code, 0, "{screen}");
    let run = run_dir(&env);
    assert!(run.join("done").exists());
    let pw = password_in(&run, "backup b");
    let list: serde_json::Value =
        serde_json::from_slice(&std::fs::read(run.join("handback.json")).unwrap()).unwrap();
    let named: Vec<&serde_json::Value> = list["objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|o| o["kind"] == "backup" && o["name"] == "b")
        .collect();
    assert_eq!(named.len(), 1, "the hand-back list names the backup once: {list}");
    assert!(
        restic(&env.h().join("repos"), &pw, &["cat", "config"])
            .status
            .success()
            || std::fs::read_dir(env.h().join("repos"))
                .unwrap()
                .flatten()
                .any(|r| restic(&r.path(), &pw, &["cat", "config"]).status.success()),
        "the new password opens it"
    );
}

/// What a scripted phone does with a request.
enum Act {
    /// Answer it now.
    Answer(Answer),
    /// Answer a `rewrap` with this phone as the old words.
    Rewrap(Arc<Phone>),
    /// Leave it pending; asked again on the next turn.
    Later,
}

/// A phone that decides per request, holding some until the test lets them go.
struct Scripted {
    stop: Arc<AtomicBool>,
    h: Option<std::thread::JoinHandle<()>>,
}

impl Scripted {
    fn start(phone: Arc<Phone>, decide: impl Fn(&Request) -> Act + Send + 'static) -> Scripted {
        let stop = Arc::new(AtomicBool::new(false));
        let s2 = stop.clone();
        let h = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async move {
                let mut seen = Vec::new();
                let mut held: Vec<sealctl_fakerelay::Incoming> = Vec::new();
                while !s2.load(Ordering::SeqCst) {
                    let mut todo = std::mem::take(&mut held);
                    if let Ok(r) = phone.next(&mut seen, Duration::from_millis(200)).await {
                        todo.push(r);
                    }
                    for r in todo {
                        let Ok(req) = phone.open(&r) else { continue };
                        let res = match decide(&req) {
                            Act::Later => {
                                held.push(r);
                                continue;
                            }
                            Act::Answer(a) => phone.auto(&r, &a).await.map(|_| ()),
                            Act::Rewrap(old) => phone.answer_rewrap(&r, &req, &old).await,
                        };
                        if let Err(e) = res {
                            eprintln!("phone: {:?}: {e:#}", req.kind());
                        }
                    }
                }
            });
        });
        Scripted { stop, h: Some(h) }
    }
}

impl Drop for Scripted {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(h) = self.h.take() {
            let _ = h.join();
        }
    }
}

/// A secret written through the daemon's open session while `migrate --depth rewrap` moves the
/// store to new words (after the store's files, before the run ends: here while the phone is
/// asked about an object on other words) is never left on the old key: the write is refused,
/// or the value reads back with the new words.
#[test]
fn a_secret_written_while_the_store_moves_to_new_words_stays_readable() {
    let mut env = Env::new();
    let m = env.pair();
    let first = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(&["secret", "set", "a/one"], first.as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    // an object on words the phone does not have: the rewrap asks `old_words` for it last
    let other = Phone::new(&env.origin);
    let bdir = env.h().join(".config/sealctl/backups");
    std::fs::create_dir_all(&bdir).unwrap();
    std::fs::write(
        bdir.join("x.toml"),
        format!(
            "name = \"x\"\nsource = \"\"\nrepo = \"{}\"\nrepo_id = \"xrepo\"\nwords = \"{}\"\ncheck = \"AAAAAAAAAAA\"\n",
            env.h().join("nowhere/xrepo").display(),
            other.fingerprint()
        ),
    )
    .unwrap();
    // new words on the phone
    let a = env.phone.clone();
    let b = Arc::new(Phone::new(&env.origin));
    env.block(b.move_from(&a, &m)).unwrap();
    let asked = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let (asked2, release2, a2) = (asked.clone(), release.clone(), a.clone());
    let phone = Scripted::start(b.clone(), move |req| match req.kind() {
        RequestKind::Rewrap => Act::Rewrap(a2.clone()),
        RequestKind::OldWords => {
            asked2.store(true, Ordering::SeqCst);
            if release2.load(Ordering::SeqCst) {
                Act::Answer(Answer::Deny)
            } else {
                Act::Later
            }
        }
        _ => Act::Answer(Answer::Session),
    });
    let mut c = env.cmd();
    c.args(["migrate", "--depth", "rewrap"]);
    let pty = Pty::spawn(c);
    let start = Instant::now();
    while !asked.load(Ordering::SeqCst) {
        assert!(
            start.elapsed() < Duration::from_secs(120),
            "no old_words request: {}",
            pty.screen.lock().unwrap()
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    // the store is on the new words by now; the daemon's session still has the old key
    let second = canary();
    let (set_code, _, set_err) = env.run_in(&["secret", "set", "a/two"], second.as_bytes());
    release.store(true, Ordering::SeqCst);
    let (_, _, screen) = pty.wait(Duration::from_secs(120));
    drop(phone);
    env.phone = b;
    std::fs::remove_file(bdir.join("x.toml")).unwrap();
    let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["secret", "get", "a/one"]));
    assert_eq!(code, 0, "{err}\n{screen}");
    assert_eq!(out, first);
    if set_code == 0 {
        let ((code, out, err), _) = env.with_phone(Answer::Session, || env.run(&["secret", "get", "a/two"]));
        assert_eq!(
            code, 0,
            "a/two was stored, so it opens with the new words: {err}\n{screen}"
        );
        assert_eq!(out, second);
    } else {
        eprintln!("the write was refused: {set_err}");
    }
}

/// `scan` reads the files, stores the values (the phone may take a while), then rewrites the
/// files: lines added to a history file meanwhile (another shell) are kept.
#[test]
fn scan_keeps_history_lines_written_while_the_phone_answers() {
    let mut env = Env::new();
    env.pair();
    let h = env.h().to_path_buf();
    let repo = h.join("code/shop");
    std::fs::create_dir_all(&repo).unwrap();
    let key = format!("Ab1{}", canary());
    std::fs::write(repo.join(".env"), format!("API_KEY={key}\n")).unwrap();
    let token = ["gh", "p_", "aB3dE6gH9jK2mN5pQ8sT1vW4yZ7bC0eF3hJ6"].concat();
    std::fs::write(
        h.join(".zsh_history"),
        format!(": 1:0;ls\n: 2:0;curl -H 'Authorization: Bearer {token}' x\n"),
    )
    .unwrap();
    let asked = Arc::new(AtomicBool::new(false));
    let release = Arc::new(AtomicBool::new(false));
    let (asked2, release2) = (asked.clone(), release.clone());
    let phone = Scripted::start(env.phone.clone(), move |_| {
        asked2.store(true, Ordering::SeqCst);
        if release2.load(Ordering::SeqCst) {
            Act::Answer(Answer::Session)
        } else {
            Act::Later
        }
    });
    let scan = env
        .cmd()
        .args(["scan", "--home", "--yes"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let start = Instant::now();
    while !asked.load(Ordering::SeqCst) {
        assert!(start.elapsed() < Duration::from_secs(60), "no request");
        std::thread::sleep(Duration::from_millis(50));
    }
    // another shell writes its history while the phone is asked
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(h.join(".zsh_history"))
        .unwrap();
    std::io::Write::write_all(&mut f, b": 3:0;echo written-meanwhile\n").unwrap();
    drop(f);
    release.store(true, Ordering::SeqCst);
    let out = scan.wait_with_output().unwrap();
    drop(phone);
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(out.status.code(), Some(0), "{err}");
    let hist = std::fs::read_to_string(h.join(".zsh_history")).unwrap();
    assert!(hist.contains("echo written-meanwhile"), "{hist}");
    assert!(!hist.contains(&token), "the token is masked: {hist}");
}

/// Two `seal volume` runs on one sparse bundle, the first one's phone answer coming late (after
/// the second has sealed it): the bundle's marker always names the id its key comes from, so
/// the words alone still open it.
#[cfg(target_os = "macos")]
#[test]
fn two_seals_of_one_bundle_leave_a_marker_that_opens_it() {
    use std::io::Write;
    let mut env = Env::new();
    env.pair();
    let own = canary();
    let bundle = env.h().join("mine.sparsebundle");
    let mut c = Command::new("/usr/bin/hdiutil")
        .args([
            "create",
            "-quiet",
            "-size",
            "32m",
            "-type",
            "SPARSEBUNDLE",
            "-fs",
            "APFS",
            "-encryption",
            "AES-256",
            "-stdinpass",
            "-volname",
            "mine",
        ])
        .arg(&bundle)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(own.as_bytes()).unwrap();
    assert!(c.wait().unwrap().success());
    let release_first = Arc::new(AtomicBool::new(false));
    let r2 = release_first.clone();
    let phone = Scripted::start(env.phone.clone(), move |req| {
        let cmd = req.ctx().map(|c| c.command).unwrap_or_default();
        if cmd.contains("volume first") && !r2.load(Ordering::SeqCst) {
            Act::Later
        } else {
            Act::Answer(Answer::Session)
        }
    });
    let seal = |name: &str| {
        let mut c = env.cmd();
        c.args([
            "seal",
            "volume",
            name,
            bundle.to_str().unwrap(),
            "--mountpoint",
            env.h().join(format!("mnt/{name}")).to_str().unwrap(),
        ]);
        let pty = Pty::spawn(c);
        // a seal of a bundle another seal is changing may be refused before it asks
        let start = Instant::now();
        loop {
            let screen = pty.screen.lock().unwrap().clone();
            if screen.contains("Passphrase of") {
                pty.line(&own);
                break;
            }
            if screen.contains("busy") {
                break;
            }
            assert!(start.elapsed() < Duration::from_secs(30), "{screen}");
            std::thread::sleep(Duration::from_millis(50));
        }
        pty
    };
    let first = seal("first");
    first.expect("pick ", Duration::from_secs(60));
    let second = seal("second");
    let (code2, _, screen2) = second.wait(Duration::from_secs(120));
    release_first.store(true, Ordering::SeqCst);
    let (code1, _, screen1) = first.wait(Duration::from_secs(120));
    drop(phone);
    assert!(
        code1 == 0 || code2 == 0,
        "one of them sealed it:\n{screen1}\n{screen2}"
    );
    let marker: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(bundle.join("sealctl.id")).unwrap()).unwrap();
    let defs: Vec<toml::Value> = std::fs::read_dir(env.h().join(".config/sealctl/volumes"))
        .unwrap()
        .flatten()
        .filter(|e| e.path().extension().is_some_and(|x| x == "toml"))
        .map(|e| toml::from_str(&std::fs::read_to_string(e.path()).unwrap()).unwrap())
        .collect();
    assert_eq!(defs.len(), 1, "one definition of the bundle: {defs:?}");
    assert_eq!(
        marker["id"].as_str(),
        defs[0]["id"].as_str(),
        "the marker names the id of the key that opens it:\n{screen1}\n{screen2}"
    );
}

/// `sealctl migrate` asked to start again while the job's runner is at work: refused, and the
/// job on file (with the new ids the runner is using) stays as it is.
#[test]
fn a_new_re_encryption_never_replaces_a_running_job() {
    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    env.pair();
    backup_with_snapshot(&env);
    let state = env.h().join("s/sealctl");
    std::fs::create_dir_all(&state).unwrap();
    let job = serde_json::json!({"items": [{"kind": "backup", "name": "b", "state": "running", "new_id": "in-use", "note": ""}]});
    std::fs::write(state.join("migrate.json"), job.to_string()).unwrap();
    // the runner's lock, held as a running job holds it
    let f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(state.join("migrate.lock"))
        .unwrap();
    let held = nix::fcntl::Flock::lock(f, nix::fcntl::FlockArg::LockExclusiveNonblock).unwrap();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["migrate", "--yes"]));
    drop(held);
    assert_ne!(code, 0, "refused while the job runs: {err}");
    let on_file: serde_json::Value =
        serde_json::from_slice(&std::fs::read(state.join("migrate.json")).unwrap()).unwrap();
    assert_eq!(on_file["items"][0]["new_id"], "in-use", "{on_file}");
}

/// A sparse bundle copy left beside the original by a job that was started over (under
/// another new id): the job makes the copy again instead of stopping on a copy its key does
/// not open.
#[cfg(target_os = "macos")]
#[test]
fn re_encryption_makes_a_stale_copy_again() {
    use std::io::Write;
    let mut env = Env::new();
    env.pair();
    let bundle = env.h().join("w.sparsebundle");
    let mnt = env.h().join("mnt/w");
    let marker = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&[
            "volume",
            "create",
            "w",
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
    env.run(&["lock"]);
    // the copy an earlier job made under its own new id
    let stale = env.h().join(".w.migrating.sparsebundle");
    let mut c = Command::new("/usr/bin/hdiutil")
        .args([
            "create",
            "-quiet",
            "-size",
            "32m",
            "-type",
            "SPARSEBUNDLE",
            "-fs",
            "APFS",
            "-encryption",
            "AES-256",
            "-stdinpass",
            "-volname",
            "w",
        ])
        .arg(&stale)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(canary().as_bytes()).unwrap();
    assert!(c.wait().unwrap().success());
    let ((code, _, err), _) =
        env.with_phone(Answer::Session, || env.run(&["migrate", "--yes", "--foreground"]));
    assert_eq!(code, 0, "{err}");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || env.run(&["volume", "open", "w"]));
    assert_eq!(code, 0, "{err}");
    assert_eq!(std::fs::read_to_string(mnt.join("keep.txt")).unwrap(), marker);
    env.run(&["lock"]);
}

/// A rewrap of a restic repository stopped (power cut) right after the key of the new words
/// was added: the next rewrap removes the old words' key too, so the old words no longer open
/// the repository.
#[test]
fn a_rewrap_stopped_after_the_new_key_was_added_still_removes_the_old_one() {
    if !have("restic") {
        return;
    }
    let mut env = Env::new();
    let m = env.pair();
    let repos = backup_with_snapshot(&env);
    env.run(&["lock"]);
    let def: toml::Value =
        toml::from_str(&std::fs::read_to_string(env.h().join(".config/sealctl/backups/b.toml")).unwrap())
            .unwrap();
    let repo_id = def["repo_id"].as_str().unwrap().to_string();
    let repo = repos.join(&repo_id);
    let a = env.phone.clone();
    let old_pw = sealctl_core::ObjectKey::derive(&a.root(), sealctl_core::Purpose::Backup, &repo_id)
        .unwrap()
        .hex()
        .to_string();
    assert!(restic(&repo, &old_pw, &["cat", "config"]).status.success());
    let b = Arc::new(Phone::new(&env.origin));
    env.block(b.move_from(&a, &m)).unwrap();
    let rewrap = |w: Option<&Path>| {
        let a2 = a.clone();
        let phone = Scripted::start(b.clone(), move |req| match req.kind() {
            RequestKind::Rewrap => Act::Rewrap(a2.clone()),
            _ => Act::Answer(Answer::Session),
        });
        let mut c = env.cmd();
        if let Some(w) = w {
            c.env("SEALCTL_RESTIC", w);
        }
        c.args(["migrate", "--depth", "rewrap"]);
        let pty = Pty::spawn(c);
        let r = pty.wait(Duration::from_secs(180));
        drop(phone);
        r
    };
    let w = wrapper(
        &env,
        "restic-dies-after-key-add",
        "\"$REAL\" \"$@\"; rc=$?\ncase \" $* \" in *\" key add \"*) [ $rc -eq 0 ] && kill -9 $PPID;; esac\nexit $rc",
    );
    let (code, _, screen) = rewrap(Some(&w));
    assert_ne!(code, 0, "stopped after the key was added: {screen}");
    let (code, _, screen) = rewrap(None);
    assert_eq!(code, 0, "{screen}");
    assert!(
        !restic(&repo, &old_pw, &["cat", "config"]).status.success(),
        "the old words no longer open the repository: {screen}"
    );
    let new_pw = sealctl_core::ObjectKey::derive(&b.root(), sealctl_core::Purpose::Backup, &repo_id)
        .unwrap()
        .hex()
        .to_string();
    assert!(restic(&repo, &new_pw, &["cat", "config"]).status.success());
}

/// `unseal secrets` stopped (power cut) after every value was handed back and the store folder
/// moved into the run folder, before the store setting was cleared: `--resume` finishes.
#[cfg(feature = "test-hooks")]
#[test]
fn unseal_secrets_resumed_after_the_store_moved_finishes() {
    use std::os::unix::process::ExitStatusExt;

    let mut env = Env::new();
    env.pair();
    let value = canary();
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(&["secret", "set", "shop/key"], value.as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    env.run(&["lock"]);
    let cfg_file = env.h().join(".config/sealctl/config.toml");
    let cfg_before = std::fs::read_to_string(&cfg_file).unwrap();
    let mut c = env.cmd();
    c.env("SEALCTL_TEST_KILL", "done:secrets")
        .args(["unseal", "secrets"]);
    let mut pty = Pty::spawn(c);
    pty.expect("Start?", Duration::from_secs(30));
    let phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    pty.line("y");
    let start = Instant::now();
    let status = loop {
        if let Some(st) = pty.child.try_wait().unwrap() {
            break st;
        }
        assert!(start.elapsed() < Duration::from_secs(120), "not killed");
        std::thread::sleep(Duration::from_millis(50));
    };
    assert_eq!(status.signal(), Some(9));
    drop(phone);
    let run = run_dir(&env);
    assert!(run.join("kept/store").exists());
    // the state just before the setting was cleared: the store setting as it was, and no
    // `done` line for the step
    std::fs::write(&cfg_file, &cfg_before).unwrap();
    let journal = std::fs::read_to_string(run.join("journal.jsonl")).unwrap();
    let kept: String = journal
        .lines()
        .filter(|l| !(l.contains("\"state\":\"done\"") && l.contains("\"step\":\"secrets:")))
        .map(|l| format!("{l}\n"))
        .collect();
    std::fs::write(run.join("journal.jsonl"), kept).unwrap();

    let mut c = env.cmd();
    c.args(["unseal", "--resume"]);
    let pty = Pty::spawn(c);
    let _phone = PhoneThread::start(env.phone.clone(), pty.screen.clone(), Pick::Right, None);
    let (code, _, screen) = pty.wait(Duration::from_secs(120));
    assert_eq!(code, 0, "{screen}");
    assert!(run.join("done").exists());
    let env_file = std::fs::read_to_string(run.join("secrets.env")).unwrap();
    assert!(env_file.contains(&value));
}
