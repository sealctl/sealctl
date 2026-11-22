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
        writers.push((w, data.to_vec()));
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
    // the parent's read ends were moved into the mappings; write and close each pipe
    let mut threads = Vec::new();
    for (mut w, data) in writers {
        let data = Zeroizing::new(data);
        threads.push(std::thread::spawn(move || {
            let _ = w.write_all(&data);
        }));
    }
    if let Some(d) = stdin_data {
        let mut stdin = child.stdin.take().context("stdin")?;
        stdin.write_all(d)?;
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
    {
        let mut stdin = child.stdin.take().context("stdin")?;
        stdin.write_all(stdin_data)?;
    }
    let out = child.wait_with_output()?;
    Ok(out)
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
    check(
        run_with_stdin(Command::new(copy[0]).args(&copy[1..]), text.as_bytes())?,
        "clipboard",
    )?;

    // Detached shell clears the clipboard later if it still holds our value.
    // The comparison uses a hash so the secret itself is not on any command line.
    let digest = sha256_hex(text.as_bytes());
    let script = format!(
        "sleep {secs}; cur=$({paste} | shasum -a 256 | cut -d' ' -f1); \
         [ \"$cur\" = \"{digest}\" ] && printf '' | {copy}",
        paste = paste.join(" "),
        copy = copy.join(" "),
    );
    Command::new("sh")
        .args(["-c", &script])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("scheduling clipboard clear")?;
    Ok(())
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
    let orig = tcgetattr(stdin.as_fd()).ok();
    if let Some(o) = &orig {
        let mut t = o.clone();
        t.local_flags.remove(LocalFlags::ECHO);
        t.local_flags.insert(LocalFlags::ECHONL);
        let _ = tcsetattr(stdin.as_fd(), SetArg::TCSANOW, &t);
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

/// A desktop notification (SPEC 5.2: when nobody watches a terminal): `osascript` on macOS,
/// `notify-send` on Linux, silently skipped if missing. The same message at most once a minute.
pub fn notify(msg: &str) {
    use std::sync::Mutex;
    use std::time::{Duration, Instant};
    static SHOWN: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());
    {
        let mut shown = SHOWN.lock().unwrap_or_else(|e| e.into_inner());
        shown.retain(|(_, t)| t.elapsed() < Duration::from_secs(60));
        if shown.iter().any(|(m, _)| m == msg) {
            return;
        }
        shown.push((msg.to_string(), Instant::now()));
    }
    if std::env::var_os("SEALCTL_NO_NOTIFY").is_some() {
        return;
    }
    let quoted = msg.replace('\\', "\\\\").replace('"', "\\\"");
    let _ = if cfg!(target_os = "macos") {
        Command::new("/usr/bin/osascript")
            .args([
                "-e",
                &format!("display notification \"{quoted}\" with title \"sealctl\" sound name \"Ping\""),
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    } else if which("notify-send") {
        Command::new("notify-send")
            .args(["sealctl", msg])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    } else {
        return;
    };
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
