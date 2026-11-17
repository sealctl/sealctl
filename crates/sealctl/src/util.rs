//! Small helpers: random secrets, clipboard, process plumbing.

use std::io::Write;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

/// A random secret of `n` bytes, hex-encoded (`2n` characters, no newline).
/// Used for volume passphrases and restic passwords.
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

/// Read a value from the terminal without echo (for API keys typed by the user).
pub fn read_hidden(prompt: &str) -> Result<Zeroizing<String>> {
    Ok(Zeroizing::new(rpassword::prompt_password(prompt)?))
}

/// Tell the user what to do on the Ledger: on stderr, and as a desktop notification (useful when
/// sealctl runs in the background — SSH agent, git signing, scheduled backups). The same
/// message is repeated at most once a minute.
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
    eprintln!("👉 {msg}");
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
