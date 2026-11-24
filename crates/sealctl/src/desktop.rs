//! Desktop notifications (SPEC 5.2): what a request waiting for the phone is about, shown where
//! nobody watches a terminal, and the answer shown in its place.
//!
//! - macOS: `sealctl Notifier.app` (packaging/macos/notifier), a small app that posts through
//!   UNUserNotificationCenter under the name "sealctl" with the sealctl icon, found next to the
//!   `sealctl` binary or in Homebrew's `libexec`. Without it, or when macOS does not let it
//!   notify, `osascript` (shown as Script Editor).
//! - Linux: `org.freedesktop.Notifications` over D-Bus (zbus) with app name and icon `sealctl`
//!   and the `desktop-entry` hint; `notify-send` when that fails.
//!
//! Only names ever go into a notification (of secrets, volumes, backups, keys, repositories,
//! agents, hosts), never values. `notifications = false` in `config.toml` (or
//! `SEALCTL_NO_NOTIFY`) turns them off.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use sealctl_core::wire::RequestBody;

/// The title while a request waits for the phone.
pub const WAITING_TITLE: &str = "Approve on your phone";
/// The same text is not shown again within this time.
const AGAIN_AFTER: Duration = Duration::from_secs(60);
/// An approval stays on screen this long, then goes.
const APPROVED_FOR: Duration = Duration::from_secs(5);
/// Longest name or detail shown.
const MAX_PART: usize = 60;

/// What the request does, for the words of its answer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verb {
    /// A signature (git commit or tag): "Signed", "nothing was signed".
    Sign,
    /// An SSH login: "Approved", "nothing was signed".
    Login,
    /// Opening a volume or the session: "nothing was opened".
    Open,
    /// A backup: "nothing was backed up".
    BackUp,
    /// Using secrets and anything else: "nothing was used".
    #[default]
    Use,
}

/// What a request is about: "Sign a git commit", with the repository and the agent.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct About {
    pub what: String,
    pub verb: Verb,
    pub repo: Option<String>,
    pub agent: Option<String>,
}

impl About {
    /// The notification text: "Sign a git commit · sealctl/app · Claude Code".
    pub fn line(&self) -> String {
        let mut parts = vec![clean(&self.what, 2 * MAX_PART)];
        for p in [&self.repo, &self.agent].into_iter().flatten() {
            let p = clean(p, MAX_PART);
            if !p.is_empty() && !parts.contains(&p) {
                parts.push(p);
            }
        }
        parts.join(" · ")
    }
}

/// How a request ended, as far as the notification tells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    Approved,
    Declined,
    Expired,
}

/// The title that replaces [`WAITING_TITLE`] when the answer comes.
pub fn outcome_title(verb: Verb, outcome: Outcome) -> &'static str {
    match (outcome, verb) {
        (Outcome::Approved, Verb::Sign) => "Signed",
        (Outcome::Approved, _) => "Approved",
        (Outcome::Declined, _) => "Declined",
        (Outcome::Expired, Verb::Sign | Verb::Login) => "Expired: nothing was signed",
        (Outcome::Expired, Verb::Open) => "Expired: nothing was opened",
        (Outcome::Expired, Verb::BackUp) => "Expired: nothing was backed up",
        (Outcome::Expired, Verb::Use) => "Expired: nothing was used",
    }
}

/// Whether a request shows a desktop notification while it waits, and what it is about when the
/// asker knows better than the request (the SSH agent knows the program that asked).
#[derive(Debug, Clone, Default)]
pub struct Desktop {
    pub show: bool,
    pub about: Option<About>,
}

impl Desktop {
    /// No notification: someone watches a terminal that says `Waiting for your phone`.
    pub const OFF: Desktop = Desktop {
        show: false,
        about: None,
    };

    /// A notification, with the text made from the request.
    pub fn on() -> Desktop {
        Desktop {
            show: true,
            about: None,
        }
    }
}

/// What `body` asks for, in the words of the phone's Activity rows.
pub fn about(body: &RequestBody) -> About {
    let ctx = body.ctx.clone().unwrap_or_default();
    let subject = ctx
        .subject
        .as_ref()
        .map(|s| (s.kind.as_str(), clean(&s.name, MAX_PART)));
    let mut names: Vec<String> = ctx.names.clone();
    for u in &body.uses {
        for n in &u.names {
            if !names.contains(n) {
                names.push(n.clone());
            }
        }
    }
    let uses = |names: &[String]| -> String {
        let what = match names {
            [one] => format!("Use {}", clean(one, MAX_PART)),
            many => format!("Use {} secrets", many.len()),
        };
        match program(&ctx.command) {
            Some(p) => format!("{what} for {p}"),
            None => what,
        }
    };
    let (what, verb) = match (body.why.as_str(), subject) {
        (_, Some(("volume", n))) => (format!("Open volume {n}"), Verb::Open),
        (_, Some(("backup", n))) => (format!("Back up {n}"), Verb::BackUp),
        (_, Some(("ssh", n))) => (format!("Use SSH key {n}"), Verb::Use),
        ("open" | "agent" | "own", _) if !names.is_empty() => (uses(&names), Verb::Use),
        (_, Some(("secret", n))) => (uses(&[n]), Verb::Use),
        (_, Some(("machine", n))) => (format!("sealctl {n}"), Verb::Use),
        ("open", _) => ("Open sealctl".to_string(), Verb::Open),
        ("unseal", _) => ("Hand back from sealctl".to_string(), Verb::Use),
        ("rewrap", _) => ("Move to new words".to_string(), Verb::Use),
        _ => ("A request from sealctl".to_string(), Verb::Use),
    };
    About {
        what,
        verb,
        repo: ctx.repo.map(|r| r.name).filter(|r| !r.is_empty()),
        agent: ctx.agent.filter(|a| !a.is_empty()),
    }
}

/// The program a `sealctl run -- <command>` runs, with its first word when that is a plain one:
/// `npm test`, `cargo build`, `make`. Nothing else of the command line, which may hold values.
fn program(cmd: &str) -> Option<String> {
    let (_, rest) = cmd
        .split_once(" -- ")
        .or_else(|| cmd.strip_prefix("-- ").map(|r| ("", r)))?;
    let mut words = rest.split_whitespace();
    let first = words.next()?;
    let first = first.rsplit('/').next().unwrap_or(first);
    let plain = |w: &str| {
        !w.is_empty() && w.len() <= 24 && w.chars().all(|c| c.is_ascii_alphanumeric() || "-_.:".contains(c))
    };
    if !plain(first) {
        return None;
    }
    match words.next().filter(|w| plain(w) && !w.starts_with('-')) {
        Some(w) => Some(format!("{first} {w}")),
        None => Some(first.to_string()),
    }
}

/// What an SSH agent signature is for, from the process that asked (`chain[0]`, then its
/// parents): `ssh-keygen -Y sign -n git` run by `git commit` signs a commit, `ssh host` logs in.
/// Programs are matched by the executable the kernel ran; their arguments are what they say.
/// Unverified: a hint for the user to look at the phone, whose card is what is approved
/// (SPEC 5.2, docs/threat-model.md).
pub fn ssh_about(
    key: &str,
    chain: &[crate::caller::Proc],
    repo: Option<String>,
    agent: Option<String>,
) -> About {
    let key = clean(key, MAX_PART);
    let (what, verb) = match chain.first() {
        Some(p) if p.name() == "ssh-keygen" && has_pair(&p.argv, "-Y", "sign") => {
            match value_of(&p.argv, "-n") {
                Some("git") => {
                    let what = match chain.iter().skip(1).take(4).find_map(git_command) {
                        Some("tag") => "Sign a git tag",
                        Some("push") => "Sign a git push",
                        _ => "Sign a git commit",
                    };
                    (what.to_string(), Verb::Sign)
                }
                _ => (format!("Sign with SSH key {key}"), Verb::Sign),
            }
        }
        Some(p) if p.name() == "ssh" => match ssh_host(&p.argv) {
            Some(h) => (format!("SSH login to {h}"), Verb::Login),
            None => (format!("SSH login with key {key}"), Verb::Login),
        },
        _ => (format!("Use SSH key {key}"), Verb::Login),
    };
    About {
        what,
        verb,
        repo,
        agent,
    }
}

fn has_pair(argv: &[String], a: &str, b: &str) -> bool {
    argv.windows(2).any(|w| w[0] == a && w[1] == b)
}

fn value_of<'a>(argv: &'a [String], flag: &str) -> Option<&'a str> {
    argv.windows(2).find(|w| w[0] == flag).map(|w| w[1].as_str())
}

/// The git command a `git` process runs (`commit`, `tag`, `push`), skipping git's own options.
fn git_command(p: &crate::caller::Proc) -> Option<&str> {
    if p.name() != "git" {
        return None;
    }
    let mut args = p.argv.iter().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "-c" | "-C" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env" | "--exec-path" => {
                args.next();
            }
            a if a.starts_with('-') => {}
            a => return Some(a),
        }
    }
    None
}

/// The host an `ssh` command line logs in to: its first argument that is not an option, as
/// `user@host`, `host` or `ssh://user@host:port`; the user and port left out.
fn ssh_host(argv: &[String]) -> Option<String> {
    // ssh's options that take a value (ssh(1))
    const WITH_VALUE: &str = "BbcDEeFIiJLlmOoPpQRSWw";
    let mut args = argv.iter().skip(1);
    while let Some(a) = args.next() {
        if a == "--" {
            return args.next().and_then(|d| host_of(d));
        }
        if let Some(opts) = a.strip_prefix('-') {
            // `-p22`, `-vT`, `-o Option=x`: an option with a value takes the rest or the next word
            if let Some(i) = opts.find(|c| WITH_VALUE.contains(c)) {
                if i + 1 == opts.len() {
                    args.next();
                }
            }
            continue;
        }
        return host_of(a);
    }
    None
}

fn host_of(dest: &str) -> Option<String> {
    let d = dest.strip_prefix("ssh://").unwrap_or(dest);
    let d = d.rsplit_once('@').map_or(d, |(_, h)| h);
    let d = if let Some(rest) = d.strip_prefix('[') {
        rest.split_once(']').map_or(rest, |(h, _)| h)
    } else if dest.starts_with("ssh://") {
        d.split(['/', ':']).next().unwrap_or(d)
    } else {
        d.split('/').next().unwrap_or(d)
    };
    let ok =
        !d.is_empty() && d.len() <= 253 && d.chars().all(|c| c.is_ascii_alphanumeric() || "-.:_".contains(c));
    ok.then(|| d.to_string())
}

/// A name as shown: control and direction-changing characters dropped, at most `max` characters.
pub fn clean(s: &str, max: usize) -> String {
    let bidi =
        |c: char| matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
    let s: String = s
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .filter(|c| !bidi(*c))
        .collect();
    let s = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if s.chars().count() > max {
        let mut t: String = s.chars().take(max - 1).collect();
        t.push('…');
        t
    } else {
        s
    }
}

/// A notification shown for a waiting request; [`Shown::answered`] replaces it.
pub struct Shown {
    id: String,
    about: About,
}

impl Shown {
    /// Shows how the request ended in place of the waiting notification: an approval for a few
    /// seconds, a decline or expiry until dismissed. `None` (the asker left, the relay failed)
    /// takes it away.
    pub fn answered(self, outcome: Option<Outcome>) {
        // after an approval the next request with the same text is a new one: it shows at once.
        // A decline or expiry keeps the minute, so a command retried in a loop stays quiet.
        if outcome == Some(Outcome::Approved) {
            shown_lately(&self.about.line(), Instant::now(), Seen::Forget);
        }
        match outcome {
            Some(o) => post(Post {
                id: self.id,
                title: outcome_title(self.about.verb, o).to_string(),
                body: self.about.line(),
                update: true,
                close_after: (o == Outcome::Approved).then_some(APPROVED_FOR),
            }),
            None => remove(self.id),
        }
    }
}

/// Shows that a request about `about` waits for the phone, unless notifications are off or the
/// same text was shown within the last minute.
pub fn waiting(about: &About) -> Option<Shown> {
    let line = about.line();
    if !enabled() || !first_in_a_while(&line, Instant::now()) {
        return None;
    }
    let id = next_id();
    post(Post {
        id: id.clone(),
        title: WAITING_TITLE.into(),
        body: line,
        update: false,
        close_after: None,
    });
    Some(Shown {
        id,
        about: about.clone(),
    })
}

/// A notice (SPEC 6.6, level 3 actions): `msg` as the text, under the title "sealctl". The same
/// message at most once a minute.
pub fn notice(msg: &str) {
    let body = clean(msg, 4 * MAX_PART);
    if !enabled() || !first_in_a_while(&body, Instant::now()) {
        return;
    }
    post(Post {
        id: next_id(),
        title: "sealctl".into(),
        body,
        update: false,
        close_after: None,
    });
}

fn enabled() -> bool {
    std::env::var_os("SEALCTL_NO_NOTIFY").is_none()
        && crate::config::Config::load().map_or(true, |c| c.notifications != Some(false))
}

/// The rate limit: `key` was not shown within [`AGAIN_AFTER`] of `now` (and is now).
fn first_in_a_while(key: &str, now: Instant) -> bool {
    shown_lately(key, now, Seen::Show)
}

enum Seen {
    Show,
    Forget,
}

fn shown_lately(key: &str, now: Instant, seen: Seen) -> bool {
    static SHOWN: Mutex<Vec<(String, Instant)>> = Mutex::new(Vec::new());
    let mut shown = SHOWN.lock().unwrap_or_else(|e| e.into_inner());
    shown.retain(|(_, t)| now.saturating_duration_since(*t) < AGAIN_AFTER);
    match seen {
        Seen::Forget => {
            shown.retain(|(k, _)| k != key);
            false
        }
        Seen::Show if shown.iter().any(|(k, _)| k == key) => false,
        Seen::Show => {
            shown.push((key.to_string(), now));
            true
        }
    }
}

fn next_id() -> String {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    // the process id keeps one daemon's notifications apart from an earlier daemon's
    format!("sealctl-{}-{n}", std::process::id())
}

/// One notification to show, or to show in place of the one with the same id.
#[derive(Debug, Clone)]
struct Post {
    id: String,
    title: String,
    body: String,
    /// Replaces the notification with this id, without a sound.
    update: bool,
    /// Taken away after this long.
    close_after: Option<Duration>,
}

enum Cmd {
    Post(Post),
    Remove(String),
}

fn post(p: Post) {
    send(Cmd::Post(p));
}

fn remove(id: String) {
    send(Cmd::Remove(id));
}

/// Hands `cmd` to the worker, which shows notifications one after another so that an answer
/// never overtakes its waiting notification. Outside a tokio runtime, a new notification is shown
/// the simple way and updates are dropped.
fn send(cmd: Cmd) {
    #[cfg(test)]
    {
        let _ = cmd;
    }
    #[cfg(not(test))]
    {
        #[cfg(feature = "test-hooks")]
        if let Some(log) = std::env::var_os("SEALCTL_TEST_NOTIFY_LOG") {
            test_log(&log, &cmd);
            return;
        }
        use tokio::sync::mpsc::UnboundedSender;
        static TX: Mutex<Option<UnboundedSender<Cmd>>> = Mutex::new(None);
        let mut tx = TX.lock().unwrap_or_else(|e| e.into_inner());
        let cmd = match tx.as_ref() {
            Some(t) => match t.send(cmd) {
                Ok(()) => return,
                // the runtime that ran the worker is gone
                Err(e) => e.0,
            },
            None => cmd,
        };
        match tokio::runtime::Handle::try_current() {
            Ok(rt) => {
                let (t, rx) = tokio::sync::mpsc::unbounded_channel();
                rt.spawn(worker(rx, t.clone()));
                let _ = t.send(cmd);
                *tx = Some(t);
            }
            Err(_) => {
                if let Cmd::Post(p) = cmd {
                    if !p.update {
                        fallback(&p);
                    }
                }
            }
        }
    }
}

/// `SEALCTL_TEST_NOTIFY_LOG` (test-hooks builds): notifications are written to this file, one
/// line each, instead of being shown.
#[cfg(all(feature = "test-hooks", not(test)))]
fn test_log(path: &std::ffi::OsStr, cmd: &Cmd) {
    use std::io::Write;
    let line = match cmd {
        Cmd::Post(p) if p.update => format!("update {}: {} | {}\n", p.id, p.title, p.body),
        Cmd::Post(p) => format!("show {}: {} | {}\n", p.id, p.title, p.body),
        Cmd::Remove(id) => format!("remove {id}\n"),
    };
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = f.write_all(line.as_bytes());
    }
}

#[cfg_attr(test, allow(dead_code))]
async fn worker(
    mut rx: tokio::sync::mpsc::UnboundedReceiver<Cmd>,
    tx: tokio::sync::mpsc::UnboundedSender<Cmd>,
) {
    let mut shown = backend::Backend::default();
    while let Some(cmd) = rx.recv().await {
        match cmd {
            Cmd::Post(p) => {
                let closed = p.close_after.map(|d| (d, p.id.clone()));
                shown.post(&p).await;
                if let Some((after, id)) = closed {
                    let tx = tx.clone();
                    tokio::spawn(async move {
                        tokio::time::sleep(after).await;
                        let _ = tx.send(Cmd::Remove(id));
                    });
                }
            }
            Cmd::Remove(id) => shown.remove(&id).await,
        }
    }
}

/// The simple way, without updates: `osascript` on macOS, `notify-send` on Linux, nothing when
/// neither is there.
fn fallback(p: &Post) {
    use std::process::{Command, Stdio};
    let quote = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let _ = if cfg!(target_os = "macos") {
        let sound = if p.update { "" } else { " sound name \"Ping\"" };
        Command::new("/usr/bin/osascript")
            .args([
                "-e",
                &format!(
                    "display notification \"{}\" with title \"{}\"{sound}",
                    quote(&p.body),
                    quote(&p.title)
                ),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    } else if crate::util::which("notify-send") {
        Command::new("notify-send")
            .args(["--app-name=sealctl", "--icon=sealctl", "--", &p.title, &p.body])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
    } else {
        return;
    };
}

#[cfg(target_os = "macos")]
mod backend {
    //! `sealctl Notifier.app`, then `osascript`.

    use std::collections::HashSet;
    use std::path::{Path, PathBuf};
    use std::process::{Command, Stdio};
    use std::time::{Duration, Instant};

    use super::Post;

    /// The app's folder name and its program inside.
    pub const APP: &str = "sealctl Notifier.app";
    const PROGRAM: &str = "Contents/MacOS/sealctl-notifier";
    /// How long a post may take before the notification is shown the other way.
    const WAIT: Duration = Duration::from_secs(3);

    #[derive(Default)]
    pub struct Backend {
        /// Notifications shown with osascript, which can neither update nor remove them.
        simple: HashSet<String>,
    }

    impl Backend {
        pub async fn post(&mut self, p: &Post) {
            if p.update && self.simple.contains(&p.id) {
                return;
            }
            let mut args = vec!["--id", &p.id, "--title", &p.title, "--body", &p.body];
            if p.update {
                args.push("--replace");
            }
            let args: Vec<String> = args.into_iter().map(str::to_owned).collect();
            let shown = tokio::task::spawn_blocking(move || run_helper(&args))
                .await
                .unwrap_or(false);
            if !shown && !p.update {
                self.simple.insert(p.id.clone());
                super::fallback(p);
            }
        }

        pub async fn remove(&mut self, id: &str) {
            if self.simple.remove(id) {
                return;
            }
            let args = vec!["--id".to_string(), id.to_string(), "--remove".to_string()];
            let _ = tokio::task::spawn_blocking(move || run_helper(&args)).await;
        }
    }

    /// Runs the helper; `true` when it exits 0 within [`WAIT`]. A helper still running then (macOS
    /// asks the user whether to allow notifications, the first time) goes on by itself.
    fn run_helper(args: &[String]) -> bool {
        let Some(exe) = std::env::current_exe().ok().and_then(|e| helper(&e)) else {
            return false;
        };
        let Ok(mut child) = Command::new(exe)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
        else {
            return false;
        };
        let start = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(st)) => return st.success(),
                Ok(None) if start.elapsed() < WAIT => std::thread::sleep(Duration::from_millis(25)),
                Ok(None) => {
                    std::thread::spawn(move || child.wait());
                    return false;
                }
                Err(_) => return false,
            }
        }
    }

    /// The helper's program for the `sealctl` at `exe`: in the same folder (the release
    /// tarball), in `../libexec` (Homebrew's formula), or in Homebrew's `opt` folder (a daemon
    /// whose versioned folder an upgrade removed).
    pub fn helper(exe: &Path) -> Option<PathBuf> {
        candidates(exe).into_iter().find(|p| p.is_file())
    }

    pub fn candidates(exe: &Path) -> Vec<PathBuf> {
        let mut dirs: Vec<PathBuf> = Vec::new();
        let real = std::fs::canonicalize(exe).ok();
        for e in [Some(exe.to_path_buf()), real].into_iter().flatten() {
            if let Some(d) = e.parent() {
                for c in [d.to_path_buf(), d.join("../libexec")] {
                    if !dirs.contains(&c) {
                        dirs.push(c);
                    }
                }
            }
        }
        for prefix in [
            "/opt/homebrew/opt/sealctl/libexec",
            "/usr/local/opt/sealctl/libexec",
        ] {
            dirs.push(PathBuf::from(prefix));
        }
        dirs.into_iter().map(|d| d.join(APP).join(PROGRAM)).collect()
    }
}

#[cfg(target_os = "linux")]
mod backend {
    //! `org.freedesktop.Notifications` over D-Bus, then `notify-send`.

    use std::collections::{HashMap, HashSet};

    use zbus::zvariant::Value;

    use super::Post;

    const DEST: &str = "org.freedesktop.Notifications";
    const PATH: &str = "/org/freedesktop/Notifications";

    #[derive(Default)]
    pub struct Backend {
        bus: Option<zbus::Connection>,
        /// Whether the server reads markup in the text (its `body-markup` capability).
        markup: Option<bool>,
        /// The server's id of each notification shown, for updates and removal.
        ids: HashMap<String, u32>,
        /// Notifications shown with notify-send.
        simple: HashSet<String>,
    }

    /// The arguments of `Notify` (Desktop Notifications Specification 1.2).
    #[derive(Debug, Clone, PartialEq)]
    pub struct Message {
        pub app_name: &'static str,
        pub replaces_id: u32,
        pub app_icon: &'static str,
        pub summary: String,
        pub body: String,
        pub desktop_entry: &'static str,
        /// 0 low, 1 normal, 2 critical.
        pub urgency: u8,
        /// Milliseconds; -1: the server decides.
        pub expire_timeout: i32,
    }

    /// The `Notify` call for `p`: app name, icon and desktop entry `sealctl`, the text escaped
    /// when the server reads markup, and the server's id of the notification it replaces.
    pub fn message(p: &Post, markup: bool, replaces_id: u32) -> Message {
        let esc = |s: &str| {
            if markup {
                s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
            } else {
                s.to_string()
            }
        };
        Message {
            app_name: "sealctl",
            replaces_id,
            app_icon: "sealctl",
            summary: p.title.clone(),
            body: esc(&p.body),
            desktop_entry: "sealctl",
            urgency: 1,
            expire_timeout: p
                .close_after
                .map_or(-1, |d| i32::try_from(d.as_millis()).unwrap_or(i32::MAX)),
        }
    }

    impl Backend {
        pub async fn post(&mut self, p: &Post) {
            if p.update && self.simple.contains(&p.id) {
                return;
            }
            let replaces = if p.update {
                match self.ids.get(&p.id) {
                    Some(n) => *n,
                    None => return,
                }
            } else {
                0
            };
            match self.notify(p, replaces).await {
                Ok(n) => {
                    self.ids.insert(p.id.clone(), n);
                }
                Err(e) => {
                    log::info!("desktop notification over D-Bus: {e}");
                    self.bus = None;
                    if !p.update {
                        self.simple.insert(p.id.clone());
                        super::fallback(p);
                    }
                }
            }
        }

        pub async fn remove(&mut self, id: &str) {
            self.simple.remove(id);
            let Some(n) = self.ids.remove(id) else { return };
            if let Ok(bus) = self.bus().await {
                let _ = bus
                    .call_method(Some(DEST), PATH, Some(DEST), "CloseNotification", &(n,))
                    .await;
            }
        }

        async fn bus(&mut self) -> zbus::Result<zbus::Connection> {
            if let Some(b) = &self.bus {
                return Ok(b.clone());
            }
            let b = zbus::Connection::session().await?;
            self.bus = Some(b.clone());
            Ok(b)
        }

        async fn notify(&mut self, p: &Post, replaces: u32) -> zbus::Result<u32> {
            let bus = self.bus().await?;
            let markup = match self.markup {
                Some(m) => m,
                None => {
                    let caps: Vec<String> = bus
                        .call_method(Some(DEST), PATH, Some(DEST), "GetCapabilities", &())
                        .await?
                        .body()
                        .deserialize()?;
                    let m = caps.iter().any(|c| c == "body-markup");
                    self.markup = Some(m);
                    m
                }
            };
            let m = message(p, markup, replaces);
            let mut hints: HashMap<&str, Value<'_>> = HashMap::new();
            hints.insert("desktop-entry", Value::from(m.desktop_entry));
            hints.insert("urgency", Value::U8(m.urgency));
            let actions: Vec<&str> = Vec::new();
            bus.call_method(
                Some(DEST),
                PATH,
                Some(DEST),
                "Notify",
                &(
                    m.app_name,
                    m.replaces_id,
                    m.app_icon,
                    m.summary.as_str(),
                    m.body.as_str(),
                    actions,
                    hints,
                    m.expire_timeout,
                ),
            )
            .await?
            .body()
            .deserialize::<u32>()
        }
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
mod backend {
    use super::Post;

    #[derive(Default)]
    pub struct Backend;

    impl Backend {
        pub async fn post(&mut self, p: &Post) {
            if !p.update {
                super::fallback(p);
            }
        }
        pub async fn remove(&mut self, _id: &str) {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::caller::Proc;
    use sealctl_core::wire::{AgentUse, Repository, RequestContext, Subject};

    fn body(why: &str, subject: Option<(&str, &str)>, names: &[&str], cmd: &str) -> RequestBody {
        let mut b = crate::approve::body(why);
        b.ctx = Some(RequestContext {
            agent: None,
            repo: None,
            command: cmd.into(),
            subject: subject.map(|(k, n)| Subject {
                kind: k.into(),
                name: n.into(),
            }),
            names: names.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        });
        b
    }

    fn p(exe: &str, argv: &[&str]) -> Proc {
        Proc {
            exe: Some(exe.into()),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            ..Proc::default()
        }
    }

    #[test]
    fn requests_are_named_like_the_phone_names_them() {
        let line = |b: &RequestBody| about(b).line();
        assert_eq!(
            line(&body("open", Some(("volume", "safe")), &[], "volume open safe")),
            "Open volume safe"
        );
        assert_eq!(
            line(&body("keys", Some(("volume", "safe")), &[], "")),
            "Open volume safe"
        );
        assert_eq!(
            line(&body("keys", Some(("backup", "safe")), &[], "")),
            "Back up safe"
        );
        assert_eq!(
            line(&body(
                "open",
                None,
                &["shop/a", "shop/b"],
                "run -e A=shop/a -e B=shop/b -- npm test"
            )),
            "Use 2 secrets for npm test"
        );
        assert_eq!(
            line(&body(
                "open",
                Some(("secret", "git/github.com")),
                &["git/github.com"],
                "git credential get"
            )),
            "Use git/github.com"
        );
        assert_eq!(line(&body("open", None, &[], "sealctl open")), "Open sealctl");
        assert_eq!(
            line(&body("open", Some(("ssh", "work")), &[], "")),
            "Use SSH key work"
        );

        // an agent's first use: the agent and the repository follow
        let mut b = crate::approve::body("agent");
        b.uses = vec![AgentUse {
            agent: "Claude Code".into(),
            repository: "github.com/sealctl/app".into(),
            names: vec!["shop/key".into()],
        }];
        b.ctx = Some(RequestContext {
            agent: Some("Claude Code".into()),
            repo: Some(Repository {
                id: "github.com/sealctl/app".into(),
                name: "sealctl/app".into(),
            }),
            command: "run -e K=shop/key -- ./deploy.sh --token=abc".into(),
            ..Default::default()
        });
        assert_eq!(
            about(&b).line(),
            "Use shop/key for deploy.sh · sealctl/app · Claude Code"
        );
    }

    #[test]
    fn only_the_program_of_a_command_is_shown() {
        assert_eq!(program("run -e K=x -- npm test").as_deref(), Some("npm test"));
        assert_eq!(program("run -- /usr/bin/make").as_deref(), Some("make"));
        assert_eq!(
            program("run -- curl -H Authorization:x https://x").as_deref(),
            Some("curl")
        );
        assert_eq!(program("run -- sh -c 'echo $K'").as_deref(), Some("sh"));
        assert_eq!(
            program("run -- psql postgres://u:p@h/db").as_deref(),
            Some("psql")
        );
        assert_eq!(program("git credential get"), None);
    }

    #[test]
    fn ssh_signatures_say_what_they_sign() {
        let keygen = p(
            "/usr/bin/ssh-keygen",
            &[
                "ssh-keygen",
                "-Y",
                "sign",
                "-n",
                "git",
                "-f",
                "/k.pub",
                "/tmp/.git_signing_buffer_tmpX",
            ],
        );
        let commit = p("/usr/bin/git", &["git", "-c", "x=y", "commit", "-m", "tag"]);
        let shim = p("/bin/sh", &["sh", "-c", "sealctl git ssh-keygen"]);
        let a = ssh_about(
            "work",
            &[keygen.clone(), commit],
            Some("sealctl/app".into()),
            Some("Claude Code".into()),
        );
        assert_eq!(a.line(), "Sign a git commit · sealctl/app · Claude Code");
        assert_eq!(a.verb, Verb::Sign);
        let tag = p("/usr/bin/git", &["git", "tag", "-s", "v1"]);
        assert_eq!(
            ssh_about("work", &[keygen.clone(), shim, tag], None, None).what,
            "Sign a git tag"
        );
        let file = p(
            "/usr/bin/ssh-keygen",
            &["ssh-keygen", "-Y", "sign", "-n", "file", "-f", "k", "f"],
        );
        assert_eq!(
            ssh_about("work", &[file], None, None).what,
            "Sign with SSH key work"
        );

        let login = |argv: &[&str]| ssh_about("work", &[p("/usr/bin/ssh", argv)], None, None).what;
        assert_eq!(
            login(&[
                "ssh",
                "-o",
                "SendEnv=GIT_PROTOCOL",
                "git@github.com",
                "git-upload-pack 'a/b.git'"
            ]),
            "SSH login to github.com"
        );
        assert_eq!(
            login(&["ssh", "-p", "2222", "-vT", "dev@mbp.example.com"]),
            "SSH login to mbp.example.com"
        );
        assert_eq!(
            login(&["ssh", "-p2222", "ssh://u@host.example.com:22/x"]),
            "SSH login to host.example.com"
        );
        assert_eq!(login(&["ssh", "-i", "k", "--", "[::1]"]), "SSH login to ::1");
        assert_eq!(login(&["ssh", "-G"]), "SSH login with key work");
        // a name that is not a host name is not shown
        assert_eq!(login(&["ssh", "h\u{202e}ost"]), "SSH login with key work");
        assert_eq!(ssh_about("work", &[], None, None).what, "Use SSH key work");
        // programs are known by the executable the kernel ran, not by the name they give
        let posing = p(
            "/tmp/x/helper",
            &["ssh-keygen", "-Y", "sign", "-n", "git", "-f", "k", "f"],
        );
        let posing_git = p("/tmp/x/other", &["git", "commit"]);
        assert_eq!(
            ssh_about("work", &[posing, posing_git.clone()], None, None).what,
            "Use SSH key work"
        );
        let posing_ssh = p("/tmp/x/helper", &["ssh", "github.com"]);
        assert_eq!(
            ssh_about("work", &[posing_ssh], None, None).what,
            "Use SSH key work"
        );
        // a real ssh-keygen under a program that only says it is git: a commit is the default
        let keygen = p(
            "/usr/bin/ssh-keygen",
            &["ssh-keygen", "-Y", "sign", "-n", "git", "-f", "k", "f"],
        );
        let tag_claim = p("/tmp/x/other", &["git", "tag"]);
        assert_eq!(
            ssh_about("work", &[keygen, tag_claim], None, None).what,
            "Sign a git commit"
        );
    }

    #[test]
    fn answers_replace_the_title() {
        assert_eq!(outcome_title(Verb::Sign, Outcome::Approved), "Signed");
        assert_eq!(outcome_title(Verb::Login, Outcome::Approved), "Approved");
        assert_eq!(outcome_title(Verb::Use, Outcome::Declined), "Declined");
        assert_eq!(
            outcome_title(Verb::Sign, Outcome::Expired),
            "Expired: nothing was signed"
        );
        assert_eq!(
            outcome_title(Verb::Login, Outcome::Expired),
            "Expired: nothing was signed"
        );
        assert_eq!(
            outcome_title(Verb::Open, Outcome::Expired),
            "Expired: nothing was opened"
        );
        assert_eq!(
            outcome_title(Verb::BackUp, Outcome::Expired),
            "Expired: nothing was backed up"
        );
        assert_eq!(
            outcome_title(Verb::Use, Outcome::Expired),
            "Expired: nothing was used"
        );
    }

    #[test]
    fn names_are_cleaned_and_cut() {
        assert_eq!(clean("a\nb\u{202e}c\td", 60), "a bc d");
        let long = "x".repeat(80);
        assert_eq!(clean(&long, 60).chars().count(), 60);
        assert!(clean(&long, 60).ends_with('…'));
        let a = About {
            what: "Open volume safe".into(),
            verb: Verb::Open,
            repo: Some(String::new()),
            agent: Some("Codex".into()),
        };
        assert_eq!(a.line(), "Open volume safe · Codex");
    }

    #[test]
    fn the_same_text_waits_a_minute() {
        let t = Instant::now();
        let key = format!("rate {}", next_id());
        assert!(first_in_a_while(&key, t));
        assert!(!first_in_a_while(&key, t + Duration::from_secs(30)));
        assert!(first_in_a_while(
            &format!("{key} other"),
            t + Duration::from_secs(30)
        ));
        assert!(first_in_a_while(&key, t + Duration::from_secs(61)));
        // an approval ends the minute
        let other = format!("{key} approved");
        assert!(first_in_a_while(&other, t));
        shown_lately(&other, t, Seen::Forget);
        assert!(first_in_a_while(&other, t + Duration::from_secs(1)));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn the_helper_is_found_next_to_the_binary_or_in_libexec() {
        let root = crate::paths::unit_test_root().join(format!("notifier-{}", next_id()));
        let bin = root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        let exe = bin.join("sealctl");
        std::fs::write(&exe, "").unwrap();
        let c = backend::candidates(&exe);
        assert!(
            c[0].ends_with("bin/sealctl Notifier.app/Contents/MacOS/sealctl-notifier"),
            "{c:?}"
        );
        assert!(
            c[1].ends_with("bin/../libexec/sealctl Notifier.app/Contents/MacOS/sealctl-notifier"),
            "{c:?}"
        );
        assert!(c
            .iter()
            .any(|p| p.starts_with("/opt/homebrew/opt/sealctl/libexec")));
        let app = root.join("libexec").join(backend::APP).join("Contents/MacOS");
        std::fs::create_dir_all(&app).unwrap();
        std::fs::write(app.join("sealctl-notifier"), "").unwrap();
        assert_eq!(
            backend::helper(&exe).map(|p| std::fs::canonicalize(p).unwrap()),
            Some(std::fs::canonicalize(app.join("sealctl-notifier")).unwrap())
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn the_dbus_message_names_sealctl() {
        let p = Post {
            id: "x".into(),
            title: WAITING_TITLE.into(),
            body: "Use a<b & c".into(),
            update: false,
            close_after: None,
        };
        let m = backend::message(&p, true, 0);
        assert_eq!(
            (m.app_name, m.app_icon, m.desktop_entry),
            ("sealctl", "sealctl", "sealctl")
        );
        assert_eq!(m.summary, "Approve on your phone");
        assert_eq!(m.body, "Use a&lt;b &amp; c");
        assert_eq!((m.replaces_id, m.expire_timeout, m.urgency), (0, -1, 1));
        let done = Post {
            title: "Approved".into(),
            update: true,
            close_after: Some(APPROVED_FOR),
            ..p
        };
        let m = backend::message(&done, false, 7);
        assert_eq!((m.replaces_id, m.expire_timeout), (7, 5000));
        assert_eq!(m.body, "Use a<b & c");
    }

    /// Against the session bus's notification server, where there is one (a desktop session);
    /// skipped elsewhere (CI, containers, SSH sessions).
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn a_notification_server_takes_the_message() {
        let Ok(bus) = zbus::Connection::session().await else {
            return;
        };
        let has_server = bus
            .call_method(
                Some("org.freedesktop.DBus"),
                "/org/freedesktop/DBus",
                Some("org.freedesktop.DBus"),
                "NameHasOwner",
                &("org.freedesktop.Notifications",),
            )
            .await
            .ok()
            .and_then(|m| m.body().deserialize::<bool>().ok())
            .unwrap_or(false);
        if !has_server {
            return;
        }
        let mut b = backend::Backend::default();
        let p = Post {
            id: "test".into(),
            title: WAITING_TITLE.into(),
            body: "sealctl unit test".into(),
            update: false,
            close_after: None,
        };
        b.post(&p).await;
        b.post(&Post {
            title: "Approved".into(),
            update: true,
            ..p
        })
        .await;
        b.remove("test").await;
    }
}
