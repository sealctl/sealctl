//! Test harness: a temporary HOME, a relay (the in-process fake, or a live one named by
//! `SEALCTL_TEST_RELAY`), a scripted phone, and the real `sealctl` binary. Commands that need
//! a terminal run on a pseudo-terminal.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use sealctl_fakerelay::{FakeRelay, Machine, Options, Phone};

/// A test environment.
pub struct Env {
    pub home: tempfile::TempDir,
    pub origin: String,
    pub fake: Option<FakeRelay>,
    pub phone: Arc<Phone>,
    pub rt: tokio::runtime::Runtime,
    pub machine: Option<Machine>,
}

/// The live relay to test against, if any.
pub fn live_relay() -> Option<String> {
    std::env::var("SEALCTL_TEST_RELAY").ok().filter(|s| !s.is_empty())
}

/// A random marker value (built at run time; never a credential-shaped literal).
pub fn canary() -> String {
    let mut b = [0u8; 12];
    getrandom::fill(&mut b).unwrap();
    format!(
        "canary{}",
        b.iter().map(|x| format!("{x:02x}")).collect::<String>()
    )
}

impl Env {
    /// Against the live relay when `SEALCTL_TEST_RELAY` is set, else a fake one.
    pub fn new() -> Env {
        Self::with(Options::default(), true)
    }

    /// Always the fake relay (for tests that need its switches).
    pub fn fake(opts: Options) -> Env {
        Self::with(opts, false)
    }

    fn with(opts: Options, allow_live: bool) -> Env {
        let (origin, fake) = match live_relay().filter(|_| allow_live) {
            Some(o) => (o, None),
            None => {
                let f = FakeRelay::start(opts);
                (f.origin.clone(), Some(f))
            }
        };
        let home = tempfile::Builder::new().prefix("sc").tempdir_in("/tmp").unwrap();
        let phone = Arc::new(Phone::new(&origin));
        let rt = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        Env {
            home,
            origin,
            fake,
            phone,
            rt,
            machine: None,
        }
    }

    /// The HOME folder.
    pub fn h(&self) -> &Path {
        self.home.path()
    }

    /// `sealctl` with this environment.
    pub fn cmd(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sealctl"));
        let h = self.h();
        c.env_clear()
            .env("HOME", h)
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("USER", "tester")
            .env("TMPDIR", std::env::temp_dir())
            .env("XDG_STATE_HOME", h.join("s"))
            .env("SEALCTL_RELAY", &self.origin)
            .env("SEALCTL_NO_SERVICE", "1")
            .env("SEALCTL_NO_NOTIFY", "1")
            .env("SEALCTL_AGENT", "0")
            .env("NO_COLOR", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .current_dir(h);
        c
    }

    /// Runs `sealctl args` without a terminal; returns (code, stdout, stderr).
    pub fn run(&self, args: &[&str]) -> (i32, String, String) {
        let out = self.cmd().args(args).stdin(Stdio::null()).output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Runs with stdin data.
    pub fn run_in(&self, args: &[&str], input: &[u8]) -> (i32, String, String) {
        let mut c = self
            .cmd()
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        c.stdin.take().unwrap().write_all(input).unwrap();
        let out = c.wait_with_output().unwrap();
        (
            out.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&out.stdout).into_owned(),
            String::from_utf8_lossy(&out.stderr).into_owned(),
        )
    }

    /// Pairs: `sealctl pair` prints the link (no terminal), the phone scans it.
    pub fn pair(&mut self) -> Machine {
        let mut child = self
            .cmd()
            .args(["pair", "--name", "tester@box.test"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let mut out = child.stdout.take().unwrap();
        let mut link = String::new();
        let mut buf = [0u8; 1];
        while out.read(&mut buf).unwrap() == 1 {
            if buf[0] == b'\n' {
                break;
            }
            link.push(buf[0] as char);
        }
        assert!(link.starts_with("https://sealctl.com/p#"), "pairing link: {link}");
        let m = self.block(self.phone.pair(&link)).unwrap();
        let mut rest = String::new();
        out.read_to_string(&mut rest).unwrap();
        let st = child.wait().unwrap();
        let mut err = String::new();
        child.stderr.take().unwrap().read_to_string(&mut err).unwrap();
        assert!(st.success(), "pair failed: {err}");
        assert!(rest.contains("Paired: tester@box.test #"), "{rest}");
        self.machine = Some(m.clone());
        m
    }

    /// Runs a future on the test runtime.
    pub fn block<F: std::future::Future>(&self, f: F) -> F::Output {
        self.rt.block_on(f)
    }

    /// Answers the next request with a closure, on a thread, while `body` runs.
    pub fn with_phone<T>(
        &self,
        answer: sealctl_fakerelay::Answer,
        body: impl FnOnce() -> T,
    ) -> (T, Vec<String>) {
        let bg = sealctl_fakerelay::Background::start(self.phone.clone(), answer);
        let r = body();
        std::thread::sleep(Duration::from_millis(50));
        let log = bg.answered();
        drop(bg);
        (r, log)
    }

    /// Stops this HOME's daemon.
    pub fn stop_daemon(&self) {
        let _ = self
            .cmd()
            .args(["daemon", "--stop"])
            .stdin(Stdio::null())
            .output();
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        self.stop_daemon();
        if self.fake.is_none() {
            // live relay: remove what this test made there
            let _ = self.rt.block_on(self.phone.delete());
        }
    }
}

/// A command on a pseudo-terminal: stdin and stderr are the terminal, stdout is a pipe.
pub struct Pty {
    pub child: Child,
    master: Arc<Mutex<std::fs::File>>,
    pub screen: Arc<Mutex<String>>,
    pub stdout: Arc<Mutex<String>>,
}

impl Pty {
    /// Starts `cmd` on a new pseudo-terminal.
    pub fn spawn(mut cmd: Command) -> Pty {
        let pty = nix::pty::openpty(None, None).unwrap();
        let slave: OwnedFd = pty.slave;
        let master = std::fs::File::from(pty.master);
        let s_in = slave.try_clone().unwrap();
        let s_err = slave.try_clone().unwrap();
        cmd.stdin(Stdio::from(s_in))
            .stderr(Stdio::from(s_err))
            .stdout(Stdio::piped());
        let mut child = cmd.spawn().unwrap();
        drop(slave);
        let screen = Arc::new(Mutex::new(String::new()));
        let stdout = Arc::new(Mutex::new(String::new()));
        let mut rd = master.try_clone().unwrap();
        let s2 = screen.clone();
        std::thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match rd.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => s2.lock().unwrap().push_str(&String::from_utf8_lossy(&buf[..n])),
                }
            }
        });
        let mut out = child.stdout.take().unwrap();
        let o2 = stdout.clone();
        std::thread::spawn(move || {
            let mut s = String::new();
            let _ = out.read_to_string(&mut s);
            o2.lock().unwrap().push_str(&s);
        });
        let _ = master.as_raw_fd();
        Pty {
            child,
            master: Arc::new(Mutex::new(master)),
            screen,
            stdout,
        }
    }

    /// Waits until the terminal shows `text`; returns the screen.
    pub fn expect(&self, text: &str, timeout: Duration) -> String {
        let start = Instant::now();
        loop {
            let s = self.screen.lock().unwrap().clone();
            if s.contains(text) {
                return s;
            }
            if start.elapsed() > timeout {
                panic!("timed out waiting for {text:?}; screen:\n{s}");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// Types a line.
    pub fn line(&self, text: &str) {
        let mut m = self.master.lock().unwrap();
        m.write_all(text.as_bytes()).unwrap();
        m.write_all(b"\r").unwrap();
        m.flush().unwrap();
    }

    /// Waits for the exit code.
    pub fn wait(mut self, timeout: Duration) -> (i32, String, String) {
        let start = Instant::now();
        loop {
            if let Some(st) = self.child.try_wait().unwrap() {
                std::thread::sleep(Duration::from_millis(200));
                let screen = self.screen.lock().unwrap().clone();
                let out = self.stdout.lock().unwrap().clone();
                return (st.code().unwrap_or(-1), out, screen);
            }
            if start.elapsed() > timeout {
                let _ = self.child.kill();
                panic!("timed out; screen:\n{}", self.screen.lock().unwrap());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }
}

/// The number shown after `pick ` on the terminal.
pub fn number_on(screen: &str) -> Option<u32> {
    let i = screen.rfind("pick ")?;
    screen[i + 5..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .ok()
}

/// Is a tool on PATH?
pub fn have(bin: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

/// A path for display in assertions.
pub fn p(p: &Path) -> PathBuf {
    p.to_path_buf()
}
