//! `sealctl agent`: a session that accumulates Ledger results for continuous work.
//!
//! The first command that needs the Ledger starts the agent in the background. You enter the
//! PIN once; the agent caches every `X25519(k, u)` it computed — the raw input of all derived
//! keys (secret store, volumes, restic) — in memory and answers repeats without the device.
//!
//! It wipes the cache and exits after `idle` without requests (default 1 h) and, however busy,
//! `max_life` after it started (default 24 h), so the PIN is required again at least daily.
//! `sealctl agent stop` and `sealctl lock` end it at once.
//!
//! Protocol (one request per line over a 0600 Unix socket in a 0700 directory):
//!   `X25519 <hex u>` → `OK <hex S>` | `ERR <message>`
//!   `STATUS`         → `OK <cached> <idle seconds left> <lifetime seconds left>`
//!   `STOP`           → `OK`

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use crate::derive::{CardOracle, Oracle};
use crate::device::Ctx;
use crate::paths;

pub fn socket_path() -> Result<PathBuf> {
    Ok(paths::state_dir()?.join("agent.sock"))
}

/// Limits of one agent session.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub idle: Duration,
    pub max_life: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            idle: Duration::from_secs(3600),
            max_life: Duration::from_secs(24 * 3600),
        }
    }
}

impl Limits {
    /// Defaults, overridable with SEALCTL_AGENT_IDLE_MIN / SEALCTL_AGENT_MAX_HOURS.
    pub fn from_env() -> Self {
        let mut l = Limits::default();
        if let Some(m) = std::env::var("SEALCTL_AGENT_IDLE_MIN")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            l.idle = Duration::from_secs(m.max(1) * 60);
        }
        if let Some(h) = std::env::var("SEALCTL_AGENT_MAX_HOURS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
        {
            l.max_life = Duration::from_secs(h.max(1) * 3600);
        }
        l
    }
}

// ---------------------------------------------------------------- server ----

struct Server {
    ctx: Ctx,
    card: Option<CardOracle>,
    /// A key recovered from the seed phrase (`sealctl recover`), used instead of a device.
    soft: Option<Box<dyn Oracle + Send>>,
    cache: HashMap<[u8; 32], Zeroizing<[u8; 32]>>,
}

impl Server {
    fn x25519(&mut self, u: [u8; 32]) -> Result<[u8; 32]> {
        if let Some(s) = self.cache.get(&u) {
            return Ok(**s);
        }
        if let Some(soft) = self.soft.as_mut() {
            return soft.x25519(&u);
        }
        let attempt = |card: &mut Option<CardOracle>| -> Result<[u8; 32]> {
            if card.is_none() {
                *card = Some(CardOracle::open(&self.ctx)?);
            }
            card.as_mut().expect("connected").x25519(&u)
        };
        let s = match attempt(&mut self.card) {
            Ok(s) => s,
            Err(e) if crate::device::is_user_refusal(&e) => return Err(e),
            Err(e) => {
                log::info!("retrying with a fresh device connection after: {e:#}");
                self.card = None;
                attempt(&mut self.card)?
            }
        };
        self.cache.insert(u, Zeroizing::new(s));
        Ok(s)
    }
}

/// Run the agent in the foreground until idle, too old, or told to stop.
pub fn run(ctx: Ctx, limits: Limits) -> Result<()> {
    run_with(ctx, limits, None)
}

/// Like [`run`], answering from a recovered key instead of a device.
pub fn run_with(ctx: Ctx, limits: Limits, soft: Option<Box<dyn Oracle + Send>>) -> Result<()> {
    let sock = socket_path()?;
    paths::ensure_private_dir(sock.parent().context("socket dir")?)?;
    if UnixStream::connect(&sock).is_ok() {
        bail!("an agent is already running ({})", sock.display());
    }
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock).with_context(|| format!("binding {}", sock.display()))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600))?;
    }
    listener.set_nonblocking(true)?;
    log::info!(
        "agent listening on {} (idle {:?}, max life {:?})",
        sock.display(),
        limits.idle,
        limits.max_life
    );

    let shared = Arc::new(Shared {
        server: Mutex::new(Server {
            ctx,
            card: None,
            soft,
            cache: HashMap::new(),
        }),
        last: Mutex::new(crate::util::Since::now()),
        stop: AtomicBool::new(false),
        started: crate::util::Since::now(),
        limits,
    });
    let result = loop {
        if shared.stop.load(Ordering::SeqCst) {
            log::info!("stop requested — exiting");
            break Ok(());
        }
        if let Some(why) = shared.expired() {
            log::info!("{why} — exiting");
            break Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                // (only derivations count as activity — a status poller must not keep the
                // session alive)
                let sh = Arc::clone(&shared);
                // one thread per client: a slow or silent client never blocks others
                std::thread::spawn(move || {
                    if let Err(e) = serve(&sh, stream) {
                        log::info!("client error: {e:#}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => break Err(e.into()),
        }
    };
    shared.stop.store(true, Ordering::SeqCst);
    {
        let mut srv = shared.server.lock().unwrap_or_else(|e| e.into_inner());
        srv.cache.clear(); // entries are Zeroizing: wiped on drop
        srv.card = None;
    }
    let _ = std::fs::remove_file(&sock);
    result
}

struct Shared {
    server: Mutex<Server>,
    last: Mutex<crate::util::Since>,
    stop: AtomicBool,
    started: crate::util::Since,
    limits: Limits,
}

impl Shared {
    fn touch(&self) {
        if let Ok(mut l) = self.last.lock() {
            *l = crate::util::Since::now();
        }
    }

    fn idle_for(&self) -> Duration {
        self.last.lock().map(|l| l.elapsed()).unwrap_or_default()
    }

    fn expired(&self) -> Option<&'static str> {
        if self.started.elapsed() >= self.limits.max_life {
            Some("session reached its maximum lifetime (PIN needed again)")
        } else if self.idle_for() >= self.limits.idle {
            Some("idle timeout")
        } else {
            None
        }
    }
}

/// A client that keeps its connection open without sending anything is dropped after this.
const CLIENT_SILENCE: Duration = Duration::from_secs(30);

/// Handle one client connection (on its own thread).
fn serve(sh: &Shared, stream: UnixStream) -> Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(Duration::from_millis(250)))?;
    let mut reader = BufReader::new(stream.try_clone()?);
    let mut out = stream;
    let mut line = String::new();
    let mut heard = Instant::now();
    loop {
        match reader.read_line(&mut line) {
            Ok(0) => return Ok(()),
            Ok(_) if !line.ends_with('\n') => continue,
            Ok(_) => {}
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) =>
            {
                if sh.stop.load(Ordering::SeqCst)
                    || sh.expired().is_some()
                    || heard.elapsed() > CLIENT_SILENCE
                {
                    return Ok(());
                }
                continue;
            }
            Err(e) => return Err(e.into()),
        }
        heard = Instant::now();
        let req = line.trim().to_string();
        line.clear();
        if sh.stop.load(Ordering::SeqCst) || sh.expired().is_some() {
            out.write_all(b"ERR agent session ended - run the command again\n")?;
            return Ok(());
        }
        let reply = if let Some(hex_u) = req.strip_prefix("X25519 ") {
            sh.touch();
            let res = parse32(hex_u).and_then(|u| {
                // A panic while talking to the device (malformed reply) must not poison the
                // agent for the rest of the session: drop the connection and carry on.
                let mut srv = sh.server.lock().unwrap_or_else(|e| {
                    let mut g = e.into_inner();
                    g.card = None;
                    g
                });
                std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| srv.x25519(u))).unwrap_or_else(
                    |_| {
                        srv.card = None;
                        Err(anyhow::anyhow!("the device sent a malformed reply"))
                    },
                )
            });
            match res {
                Ok(s) => {
                    let s = Zeroizing::new(hex::encode(s));
                    format!("OK {}\n", s.as_str())
                }
                Err(e) => format!("ERR {}\n", format!("{e:#}").replace('\n', " ")),
            }
        } else if req == "TOUCH" {
            // activity that uses this session without a derivation (SSH signing with a key
            // unlocked in it)
            sh.touch();
            "OK\n".to_string()
        } else if req == "STATUS" {
            let idle_left = sh.limits.idle.saturating_sub(sh.idle_for()).as_secs();
            let life_left = sh.limits.max_life.saturating_sub(sh.started.elapsed()).as_secs();
            let cached = sh.server.lock().map(|s| s.cache.len()).unwrap_or(0);
            format!("OK {cached} {idle_left} {life_left}\n")
        } else if req == "STOP" {
            sh.stop.store(true, Ordering::SeqCst);
            out.write_all(b"OK\n")?;
            return Ok(());
        } else {
            "ERR unknown request\n".to_string()
        };
        let reply = Zeroizing::new(reply); // same buffer, wiped on drop
        out.write_all(reply.as_bytes())?;
    }
}

fn parse32(h: &str) -> Result<[u8; 32]> {
    let v = hex::decode(h.trim()).context("bad hex")?;
    v.as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("expected 32 bytes"))
}

// ---------------------------------------------------------------- client ----

pub struct AgentClient {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
}

impl AgentClient {
    pub fn connect() -> Result<Self> {
        let s = UnixStream::connect(socket_path()?).context("agent not running")?;
        Ok(Self {
            reader: BufReader::new(s.try_clone()?),
            writer: s,
        })
    }

    fn request(&mut self, line: &str) -> Result<Zeroizing<String>> {
        self.writer.write_all(format!("{line}\n").as_bytes())?;
        // replies carry derived values: keep them in buffers that are wiped on drop
        let mut resp = Zeroizing::new(String::new());
        if self.reader.read_line(&mut resp)? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "the agent closed the connection",
            )
            .into());
        }
        let resp = resp.trim_end();
        match resp.strip_prefix("OK") {
            Some(rest) => Ok(Zeroizing::new(rest.trim().to_string())),
            None => bail!("{}", resp.strip_prefix("ERR ").unwrap_or(resp)),
        }
    }

    /// (cached results, idle seconds left, lifetime seconds left)
    pub fn status(&mut self) -> Result<(usize, u64, u64)> {
        let r = self.request("STATUS")?;
        let mut it = r.split_whitespace();
        let mut n = || it.next().and_then(|x| x.parse::<u64>().ok()).unwrap_or(0);
        Ok((n() as usize, n(), n()))
    }

    pub fn stop(&mut self) -> Result<()> {
        self.request("STOP").map(|_| ())
    }

    /// Count as activity: keeps the session from expiring while it is being used.
    pub fn touch(&mut self) -> Result<()> {
        self.request("TOUCH").map(|_| ())
    }
}

/// Is an agent session running? (Doesn't start one.)
pub fn session_alive() -> bool {
    AgentClient::connect().is_ok()
}

impl Oracle for AgentClient {
    fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]> {
        // If the agent has to go to the device, tell the user what to do.
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        let hint = std::thread::spawn(move || {
            if rx.recv_timeout(Duration::from_millis(1500)).is_err() {
                eprintln!(
                    "👉 Using the Ledger — confirm opening OpenPGP / enter your PIN on the device if asked"
                );
            }
        });
        let res = self.request(&format!("X25519 {}", hex::encode(u)));
        let _ = tx.send(());
        let _ = hint.join();
        let hex_s = Zeroizing::new(res?);
        parse32(&hex_s)
    }
}

/// Connect to the running agent, or start one in the background (inheriting the transport
/// settings) and connect to it.
pub fn connect_or_spawn(ctx: &Ctx, limits: Limits) -> Result<AgentClient> {
    if let Ok(c) = AgentClient::connect() {
        return Ok(c);
    }
    let exe = crate::util::stable_exe()?;
    let log = paths::state_dir()?.join("agent.log");
    std::fs::create_dir_all(paths::state_dir()?)?;
    let logf = std::fs::OpenOptions::new().create(true).append(true).open(&log)?;
    let mut cmd = std::process::Command::new(exe);
    // never keep a volume busy: a working directory inside it would block `sealctl lock`
    cmd.current_dir("/");
    cmd.args(["--transport", ctx.transport_name()])
        .args(["--ble-scan", &ctx.scan.as_secs().to_string()])
        .args(["agent", "run"])
        .args(["--idle", &(limits.idle.as_secs() / 60).max(1).to_string()])
        .args([
            "--max-hours",
            &(limits.max_life.as_secs() / 3600).max(1).to_string(),
        ])
        .env(
            "RUST_LOG",
            std::env::var("RUST_LOG").unwrap_or_else(|_| "info,btleplug=off".into()),
        )
        .stdin(std::process::Stdio::null())
        .stdout(logf.try_clone()?)
        .stderr(logf);
    {
        use std::os::unix::process::CommandExt;
        cmd.process_group(0); // keep running when the terminal closes
    }
    cmd.spawn().context("starting the sealctl agent")?;
    for _ in 0..50 {
        std::thread::sleep(Duration::from_millis(100));
        if let Ok(c) = AgentClient::connect() {
            return Ok(c);
        }
    }
    bail!("the agent did not start — see {}", log.display())
}

/// The oracle commands use: the agent (default), or the device directly with
/// `SEALCTL_NO_AGENT=1`.
pub fn oracle(ctx: &Ctx) -> Result<Box<dyn Oracle>> {
    if std::env::var_os("SEALCTL_NO_AGENT").is_some() {
        return Ok(Box::new(LazyCard {
            ctx: *ctx,
            card: None,
        }));
    }
    Ok(Box::new(AgentSession::open(ctx, Limits::from_env())?))
}

/// A connection to the agent that survives the agent dropping it. The agent closes a client
/// that stays silent for [`CLIENT_SILENCE`], and a session can end between two requests;
/// a long command (unseal waiting on restic or diskutil) then connects again (starting an
/// agent if needed) and repeats the request once. Requests are idempotent.
pub struct AgentSession {
    ctx: Ctx,
    limits: Limits,
    client: AgentClient,
}

impl AgentSession {
    pub fn open(ctx: &Ctx, limits: Limits) -> Result<Self> {
        Ok(Self {
            ctx: *ctx,
            limits,
            client: connect_or_spawn(ctx, limits)?,
        })
    }

    fn with_retry<T>(&mut self, f: impl Fn(&mut AgentClient) -> Result<T>) -> Result<T> {
        match f(&mut self.client) {
            Err(e) if disconnected(&e) => {
                log::info!("agent connection lost ({e:#}); connecting again");
                self.client = connect_or_spawn(&self.ctx, self.limits)?;
                f(&mut self.client)
            }
            r => r,
        }
    }

    /// (cached results, idle seconds left, lifetime seconds left)
    pub fn status(&mut self) -> Result<(usize, u64, u64)> {
        self.with_retry(|c| c.status())
    }
}

impl Oracle for AgentSession {
    fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]> {
        self.with_retry(|c| c.x25519(u))
    }
}

/// Did the request fail because the connection is gone (rather than an answer from the agent)?
fn disconnected(e: &anyhow::Error) -> bool {
    use std::io::ErrorKind::*;
    if e.to_string().starts_with("agent session ended") {
        return true;
    }
    e.chain().any(|c| {
        c.downcast_ref::<std::io::Error>().is_some_and(|io| {
            matches!(
                io.kind(),
                BrokenPipe | ConnectionReset | ConnectionAborted | NotConnected | UnexpectedEof
            )
        })
    })
}

/// Direct device access, connecting on first use.
struct LazyCard {
    ctx: Ctx,
    card: Option<CardOracle>,
}

impl Oracle for LazyCard {
    fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]> {
        if self.card.is_none() {
            self.card = Some(CardOracle::open(&self.ctx)?);
        }
        self.card.as_mut().expect("connected").x25519(u)
    }
}

/// Stop a running agent (no-op if none).
pub fn stop() -> Result<bool> {
    match AgentClient::connect() {
        Ok(mut c) => {
            c.stop()?;
            Ok(true)
        }
        Err(_) => Ok(false),
    }
}
