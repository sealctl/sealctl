//! Small helpers: random secrets, clipboard, process plumbing.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// A new UUID v4 (lower case).
pub fn new_uuid() -> Result<String> {
    sealctl_core::ids::new_uuid().map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))
}

/// Runs `cmd` with each `(fd, bytes)` written to a pipe that the child sees as that file
/// descriptor (`/dev/fd/3`, `/dev/fd/4`). Values never go through argv or the environment.
///
/// The copies of the values live in `Zeroizing` buffers from the start, so an early return
/// (pipe, mapping or spawn failure) wipes them too. Once the child runs, `cmd` is replaced by an
/// empty command: that drops the parent's read ends held by the fd mappings, so a writer blocked
/// on a full pipe gets `BrokenPipe` when the child exits without reading, instead of hanging.
/// `cmd` must not be used again by the caller.
pub fn run_with_fds(
    cmd: &mut Command,
    fds: &[(i32, &[u8])],
    stdin_data: Option<&[u8]>,
) -> Result<std::process::Output> {
    use command_fds::{CommandFdExt, FdMapping};
    use std::os::fd::OwnedFd;
    let mut mappings = Vec::new();
    let mut writers = Vec::new();
    for (fd, data) in fds {
        let (r, w) = std::io::pipe().context("pipe")?;
        mappings.push(FdMapping {
            parent_fd: OwnedFd::from(r),
            child_fd: *fd,
        });
        writers.push((w, Zeroizing::new(data.to_vec())));
    }
    cmd.fd_mappings(mappings)
        .map_err(|e| anyhow::anyhow!("fd mapping: {e:?}"))?;
    cmd.stdin(if stdin_data.is_some() {
        Stdio::piped()
    } else {
        Stdio::null()
    })
    .stdout(Stdio::piped())
    .stderr(Stdio::piped());
    let name = format!("{:?}", cmd.get_program());
    let mut child = cmd.spawn().with_context(|| format!("starting {name}"))?;
    // the parent's read ends were moved into the mappings: drop them with the command
    drop(std::mem::replace(cmd, Command::new("/nonexistent")));
    // write and close each pipe
    let mut threads = Vec::new();
    for (mut w, data) in writers {
        threads.push(std::thread::spawn(move || {
            let _ = w.write_all(&data);
        }));
    }
    if let Some(d) = stdin_data {
        let stdin = child.stdin.take().context("stdin")?;
        write_stdin(stdin, d)?;
    }
    let out = child.wait_with_output()?;
    for t in threads {
        let _ = t.join();
    }
    Ok(out)
}

/// A random secret of `n` bytes, hex-encoded (`2n` characters, no newline).
pub fn random_secret(n: usize) -> Result<Zeroizing<String>> {
    let mut buf = Zeroizing::new(vec![0u8; n]);
    getrandom::fill(&mut buf).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
    let mut s = Zeroizing::new(String::with_capacity(n * 2));
    for b in buf.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    Ok(s)
}

/// Run `cmd`, writing `stdin_data` to its stdin. Secrets never go through argv or env.
pub fn run_with_stdin(cmd: &mut Command, stdin_data: &[u8]) -> Result<std::process::Output> {
    let name = format!("{:?}", cmd.get_program());
    let mut child = cmd
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {name}"))?;
    let stdin = child.stdin.take().context("stdin")?;
    write_stdin(stdin, stdin_data)?;
    let out = child.wait_with_output()?;
    Ok(out)
}

/// Writes a child's stdin and closes it. A child that exits without reading it all (a refused
/// `sudo -n`, a tool that fails early) is not an error here: the caller then sees its exit status
/// and stderr from `wait_with_output` instead of a broken pipe.
fn write_stdin(mut stdin: std::process::ChildStdin, data: &[u8]) -> Result<()> {
    match stdin.write_all(data) {
        Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e.into()),
        _ => Ok(()),
    }
}

/// Run `cmd` and fail with its stderr when it exits non-zero.
pub fn check(out: std::process::Output, what: &str) -> Result<std::process::Output> {
    if !out.status.success() {
        bail!(
            "{what} failed: {}",
            String::from_utf8_lossy(&out.stderr)
                .trim()
                .lines()
                .last()
                .unwrap_or("")
        );
    }
    Ok(out)
}

pub fn which(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
}

/// Directories that hold OS tools (diskutil, hdiutil, launchctl, cryptsetup, systemctl) but are
/// often missing from a user's PATH — notably `/usr/sbin` on macOS.
const SYSTEM_DIRS: &[&str] = &["/usr/sbin", "/sbin", "/usr/bin", "/bin"];

/// A `Command` for an OS tool: found on PATH, else in the standard system directories.
pub fn system_cmd(bin: &str) -> Command {
    if which(bin) {
        return Command::new(bin);
    }
    match SYSTEM_DIRS
        .iter()
        .map(|d| std::path::Path::new(d).join(bin))
        .find(|p| p.is_file())
    {
        Some(p) => Command::new(p),
        None => Command::new(bin),
    }
}

/// Copy to the clipboard and clear it again after `secs` seconds (only if unchanged).
pub fn copy_to_clipboard_with_clear(text: &str, secs: u64) -> Result<()> {
    let (copy, paste): (Vec<&str>, Vec<&str>) = if cfg!(target_os = "macos") {
        (vec!["pbcopy"], vec!["pbpaste"])
    } else if std::env::var_os("WAYLAND_DISPLAY").is_some() && which("wl-copy") {
        (vec!["wl-copy"], vec!["wl-paste", "-n"])
    } else if which("xclip") {
        (
            vec!["xclip", "-selection", "clipboard"],
            vec!["xclip", "-selection", "clipboard", "-o"],
        )
    } else {
        bail!("no clipboard tool found (install wl-clipboard or xclip)");
    };
    // checked before copying: without a hash tool the clear below could never match
    let hash = clipboard_hash_tool()?;
    check(
        run_with_stdin(Command::new(copy[0]).args(&copy[1..]), text.as_bytes())?,
        "clipboard",
    )?;

    // Detached shell clears the clipboard later if it still holds our value. It compares
    // hashes, and reads ours from its stdin, so neither the value nor its hash is on any
    // command line.
    let digest = sha256_hex(text.as_bytes());
    let script = clear_script(secs, &paste.join(" "), hash, &copy.join(" "));
    let mut child = Command::new("sh")
        .args(["-c", &script])
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("scheduling clipboard clear")?;
    let stdin = child.stdin.take().context("stdin")?;
    write_stdin(stdin, format!("{digest}\n").as_bytes()).context("scheduling clipboard clear")?;
    Ok(())
}

/// The SHA-256 tool for the delayed clipboard clear: `sha256sum` (coreutils), else
/// `shasum -a 256` (Perl; always on macOS).
fn clipboard_hash_tool() -> Result<&'static str> {
    if which("sha256sum") {
        Ok("sha256sum")
    } else if which("shasum") {
        Ok("shasum -a 256")
    } else {
        bail!("cannot clear the clipboard later: neither sha256sum nor shasum is installed")
    }
}

/// The shell script that clears the clipboard after `secs` seconds if it still holds the value
/// whose SHA-256 (hex) arrives as the first line on stdin.
fn clear_script(secs: u64, paste: &str, hash: &str, copy: &str) -> String {
    format!(
        "read -r want; sleep {secs}; cur=$({paste} | {hash} | cut -d' ' -f1); \
         [ -n \"$want\" ] && [ \"$cur\" = \"$want\" ] && printf '' | {copy}"
    )
}

/// A lock on one object (a volume, a restic repository) among sealctl's long operations on
/// this machine: `seal`, `unseal`, `migrate` (rewrap and re-encryption) and `backup run` each
/// hold it while they change or write the object, so two of them never interleave on it. An
/// exclusive `flock` on `<state>/locks/<hash of key>.lock`, released when the value drops (or
/// the process ends). A second command is told the object is busy (exit 11).
pub struct ObjectLock {
    _f: nix::fcntl::Flock<std::fs::File>,
}

/// How [`lock_named`] takes its lock.
#[derive(Clone, Copy, Debug)]
pub enum LockHow {
    /// Exclusive, never waits.
    Exclusive,
    /// Shared, never waits.
    Shared,
    /// Exclusive, waiting up to the given time for the holders to finish.
    ExclusiveWait(std::time::Duration),
}

/// The folder of the lock files: `<state>/locks` (local to this machine, never synced with a
/// store folder). Unit tests use a folder of their own.
fn locks_dir() -> Result<std::path::PathBuf> {
    #[cfg(test)]
    {
        Ok(std::env::temp_dir().join(format!("sealctl-test-locks-{}", std::process::id())))
    }
    #[cfg(not(test))]
    {
        Ok(crate::paths::state_dir()?.join("locks"))
    }
}

/// Takes the lock file `<state>/locks/<file>`. Only a lock held by another process makes it
/// busy (exit 11, `busy` names it); a file system that cannot lock is reported as it is.
/// `waiting` is called once if an [`LockHow::ExclusiveWait`] has to wait.
pub fn lock_named(
    file: &str,
    how: LockHow,
    busy: &dyn Fn() -> String,
    waiting: &mut dyn FnMut(),
) -> Result<ObjectLock> {
    use nix::fcntl::{Flock, FlockArg};
    let dir = locks_dir()?;
    crate::paths::ensure_private_dir(&dir)?;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(dir.join(file))?;
    let (arg, until) = match how {
        LockHow::Exclusive => (FlockArg::LockExclusiveNonblock, None),
        LockHow::Shared => (FlockArg::LockSharedNonblock, None),
        LockHow::ExclusiveWait(d) => (
            FlockArg::LockExclusiveNonblock,
            Some(std::time::Instant::now() + d),
        ),
    };
    let mut waited = false;
    loop {
        match Flock::lock(f, arg) {
            Ok(l) => return Ok(ObjectLock { _f: l }),
            Err((back, nix::errno::Errno::EWOULDBLOCK)) => match until {
                Some(t) if std::time::Instant::now() < t => {
                    if !waited {
                        waited = true;
                        waiting();
                    }
                    f = back;
                    std::thread::sleep(std::time::Duration::from_millis(200));
                }
                _ => return Err(crate::exit::fail(crate::exit::BUSY, busy())),
            },
            Err((_, e)) => {
                return Err(anyhow::anyhow!(
                    "locking {}: {e}",
                    crate::paths::tilde(&dir.join(file))
                ))
            }
        }
    }
}

fn object_busy(what: &str) -> String {
    format!("{what} is busy: another sealctl command is changing it. Try again once it ends.")
}

fn object_file(key: &str) -> String {
    format!("{}.lock", &sha256_hex(key.as_bytes())[..24])
}

/// Takes the [`ObjectLock`] of `key` (a canonical path, or `<kind>:<id>`); `what` names the
/// object in the message. Never waits.
pub fn object_lock(key: &str, what: &str) -> Result<ObjectLock> {
    lock_named(
        &object_file(key),
        LockHow::Exclusive,
        &|| object_busy(what),
        &mut || {},
    )
}

/// [`object_lock`], waiting up to `max` for the command holding it; `waiting` is called once
/// when it has to wait.
pub fn object_lock_wait(
    key: &str,
    what: &str,
    max: std::time::Duration,
    waiting: &mut dyn FnMut(),
) -> Result<ObjectLock> {
    lock_named(
        &object_file(key),
        LockHow::ExclusiveWait(max),
        &|| object_busy(what),
        waiting,
    )
}

/// The [`object_lock`] key of a file or folder: its canonical path.
pub fn path_key(p: &std::path::Path) -> String {
    std::fs::canonicalize(p)
        .unwrap_or_else(|_| p.to_path_buf())
        .display()
        .to_string()
}

pub fn sha256_hex(data: &[u8]) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Ask a yes/no question on the terminal.
pub fn confirm(question: &str) -> Result<bool> {
    eprint!("{question} [y/N] ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// Reads one line from the terminal on stdin without echo (prompt on stderr).
pub fn read_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    use nix::sys::termios::{tcgetattr, tcsetattr, LocalFlags, SetArg};
    use std::io::BufRead;
    use std::os::fd::AsFd;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let stdin = std::io::stdin();
    // Not a terminal (piped input): nothing to hide. Any other failure to turn echo off stops
    // here, before anything is read, so a hidden prompt never reads with echo on.
    let orig = match tcgetattr(stdin.as_fd()) {
        Ok(o) => Some(o),
        Err(nix::errno::Errno::ENOTTY) => None,
        Err(e) => anyhow::bail!("cannot turn off echo on this terminal: {e}"),
    };
    if let Some(o) = &orig {
        let mut t = o.clone();
        t.local_flags.remove(LocalFlags::ECHO);
        t.local_flags.insert(LocalFlags::ECHONL);
        tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &t)
            .map_err(|e| anyhow::anyhow!("cannot turn off echo on this terminal: {e}"))?;
    }
    let mut line = Zeroizing::new(String::new());
    let r = stdin.lock().read_line(&mut line);
    if let Some(o) = &orig {
        let _ = tcsetattr(stdin.as_fd(), SetArg::TCSANOW, o);
    }
    r?;
    while line.ends_with('\n') || line.ends_with('\r') {
        line.pop();
    }
    Ok(line)
}

/// A desktop notice (SPEC 6.6): [`crate::desktop::notice`].
pub fn notify(msg: &str) {
    crate::desktop::notice(msg);
}

/// Read the clipboard as text, then clear it (used to store a copied key without it ever being
/// typed, printed or passed through an AI agent).
pub fn take_clipboard() -> Result<Zeroizing<Vec<u8>>> {
    let (paste, copy): (Vec<&str>, Vec<&str>) = if cfg!(target_os = "macos") {
        (vec!["pbpaste"], vec!["pbcopy"])
    } else if std::env::var_os("WAYLAND_DISPLAY").is_some() && which("wl-paste") {
        (vec!["wl-paste", "-n"], vec!["wl-copy", "--clear"])
    } else if which("xclip") {
        (
            vec!["xclip", "-selection", "clipboard", "-o"],
            vec!["xclip", "-selection", "clipboard"],
        )
    } else {
        bail!("no clipboard tool found (install wl-clipboard or xclip)");
    };
    let out = check(
        Command::new(paste[0])
            .args(&paste[1..])
            .stdin(Stdio::null())
            .output()?,
        "reading the clipboard",
    )?;
    let mut v = Zeroizing::new(out.stdout);
    while v.last().is_some_and(|b| *b == b'\n' || *b == b'\r') {
        v.pop();
    }
    if v.is_empty() {
        bail!("the clipboard is empty — copy the key first");
    }
    // clear it so the key doesn't linger
    let _ = run_with_stdin(Command::new(copy[0]).args(&copy[1..]), b"");
    Ok(v)
}

/// Path to this program that survives upgrades: the `sealctl` on PATH (e.g. Homebrew's
/// `/opt/homebrew/bin/sealctl` symlink) if it is this binary, else the binary itself. Used in
/// services, hooks and git config, which would break when a versioned install folder goes away.
pub fn stable_exe() -> Result<std::path::PathBuf> {
    let exe = std::env::current_exe()?;
    let real = std::fs::canonicalize(&exe).unwrap_or_else(|_| exe.clone());
    if let Some(path) = std::env::var_os("PATH") {
        // only absolute entries: a relative one (".") would make hooks run ./sealctl of
        // whatever directory the agent is in
        for dir in std::env::split_paths(&path).filter(|d| d.is_absolute()) {
            let cand = dir.join("sealctl");
            if cand.is_file() && std::fs::canonicalize(&cand).ok().as_ref() == Some(&real) {
                return Ok(cand);
            }
        }
    }
    // Homebrew without PATH (e.g. launchd): prefer the stable prefix symlink
    for prefix in [
        "/opt/homebrew/bin/sealctl",
        "/usr/local/bin/sealctl",
        "/home/linuxbrew/.linuxbrew/bin/sealctl",
    ] {
        let cand = std::path::Path::new(prefix);
        if std::fs::canonicalize(cand).ok().as_ref() == Some(&real) {
            return Ok(cand.to_path_buf());
        }
    }
    Ok(exe)
}

/// A start time whose `elapsed()` also counts system sleep. `Instant` stops while a laptop is
/// suspended, so "1 h idle" would mean 1 h *awake*; wall-clock time keeps counting. The larger of
/// the two is used (a wall clock set backwards can't extend a session).
#[derive(Debug, Clone, Copy)]
pub struct Since {
    mono: std::time::Instant,
    wall: std::time::SystemTime,
}

impl Since {
    pub fn now() -> Self {
        Since {
            mono: std::time::Instant::now(),
            wall: std::time::SystemTime::now(),
        }
    }

    pub fn elapsed(&self) -> std::time::Duration {
        let wall = self.wall.elapsed().unwrap_or_default();
        self.mono.elapsed().max(wall)
    }
}

#[cfg(test)]
mod fd_tests {
    use super::*;

    /// A child that exits without reading a value larger than a pipe holds: the call returns.
    #[test]
    fn a_child_that_does_not_read_does_not_hang() {
        let big = vec![b'x'; 4 << 20];
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut c = Command::new("/bin/sh");
            c.args(["-c", "exit 3"]);
            let out = run_with_fds(&mut c, &[(3, &big)], None).map(|o| o.status.code());
            let _ = tx.send(out.ok().flatten());
        });
        let code = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("run_with_fds hung on an unread pipe");
        assert_eq!(code, Some(3));
    }

    /// A child that exits before reading its stdin: its own status and stderr come back.
    #[test]
    fn a_child_that_does_not_read_stdin_reports_its_own_error() {
        let big = vec![b'x'; 4 << 20];
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "echo refused >&2; exit 4"]);
        let out = run_with_stdin(&mut c, &big).unwrap();
        assert_eq!(out.status.code(), Some(4));
        assert_eq!(out.stderr, b"refused\n");
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "echo refused >&2; exit 4"]);
        let out = run_with_fds(&mut c, &[], Some(&big)).unwrap();
        assert_eq!(out.status.code(), Some(4));
    }

    /// The clear script takes the hash on stdin and clears only on a match.
    #[test]
    fn clear_script_compares_the_hash_from_stdin() {
        let hash = clipboard_hash_tool().unwrap();
        let tmp = tempfile::tempdir().unwrap();
        let clip = tmp.path().join("clip");
        let cleared = tmp.path().join("cleared");
        std::fs::write(&clip, b"s3cret").unwrap();
        let run = |want: &str| {
            let _ = std::fs::remove_file(&cleared);
            let script = clear_script(
                0,
                &format!("cat '{}'", clip.display()),
                hash,
                &format!("cat > '{}'", cleared.display()),
            );
            assert!(!script.contains(want) || want.is_empty());
            let mut c = Command::new("/bin/sh");
            c.args(["-c", &script]);
            run_with_stdin(&mut c, format!("{want}\n").as_bytes()).unwrap();
            cleared.exists()
        };
        assert!(run(&sha256_hex(b"s3cret")), "same value: cleared");
        assert!(!run(&sha256_hex(b"other")), "changed clipboard: kept");
        assert!(!run(""), "no hash: kept");
    }

    #[test]
    fn values_reach_the_child() {
        let mut c = Command::new("/bin/sh");
        c.args(["-c", "cat /dev/fd/3; cat /dev/fd/4"]);
        let out = run_with_fds(&mut c, &[(3, b"one"), (4, b"two")], None).unwrap();
        assert_eq!(out.stdout, b"onetwo");
    }
}
