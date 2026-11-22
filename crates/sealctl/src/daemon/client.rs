//! Talking to the daemon: connect (or start it), send one JSON line, print `Waiting for your
//! phone` once when it says so, return the answer. With `SEALCTL_NO_DAEMON=1` the daemon code
//! runs inside this process instead.

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use base64::Engine;
use sealctl_core::wire::RequestItem;
use sealctl_core::ObjectKey;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use super::{Daemon, Events, VERSION};
use crate::exit::{self, fail};
use crate::{paths, term};

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

/// No daemon: the command asks the phone itself.
pub fn no_daemon() -> bool {
    std::env::var_os("SEALCTL_NO_DAEMON").is_some_and(|v| !v.is_empty() && v != "0")
}

fn connect() -> Option<UnixStream> {
    let sock = paths::daemon_socket().ok()?;
    UnixStream::connect(sock).ok()
}

fn spawn() -> Result<UnixStream> {
    let exe = std::env::current_exe().context("finding sealctl")?;
    use std::os::unix::process::CommandExt;
    let log = paths::daemon_log()?;
    paths::ensure_private_dir(log.parent().context("state dir")?)?;
    let err = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&log)
        .ok();
    let mut cmd = std::process::Command::new(exe);
    cmd.args(["daemon", "--spawned"])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .process_group(0);
    match err {
        Some(f) => cmd.stderr(f),
        None => cmd.stderr(std::process::Stdio::null()),
    };
    cmd.spawn().context("starting the sealctl daemon")?;
    for _ in 0..100 {
        if let Some(s) = connect() {
            return Ok(s);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    Err(fail(
        exit::ERROR,
        "The sealctl daemon did not start. See ~/.local/state/sealctl/daemon.log",
    ))
}

fn printer() -> impl FnMut(&Value) {
    let mut shown = false;
    move |e: &Value| {
        if e["event"] == "waiting" && !shown {
            shown = true;
            eprintln!("{}", term::waiting_line(None, false));
        }
    }
}

fn inproc() -> Result<Arc<Daemon>> {
    static D: OnceLock<Arc<Daemon>> = OnceLock::new();
    if let Some(d) = D.get() {
        return Ok(d.clone());
    }
    let d = Daemon::new(true)?;
    Ok(D.get_or_init(|| d).clone())
}

fn rt() -> &'static tokio::runtime::Runtime {
    static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("runtime")
    })
}

/// Sends `op` and returns the answer; errors keep their exit codes.
pub fn call(mut op: Value) -> Result<Value> {
    op["v"] = json!(1);
    op["cli"] = json!(VERSION);
    if op.get("notify").is_none() {
        op["notify"] = json!(term::reader() == term::Reader::Pipe && !term::stderr_tty());
    }
    if no_daemon() {
        crate::machine::load()?;
        let d = inproc()?;
        let shown = std::sync::Mutex::new(printer());
        let ev: Events = Arc::new(move |v| (shown.lock().unwrap_or_else(|e| e.into_inner()))(&v));
        return rt().block_on(d.handle(op, ev));
    }
    crate::machine::load()?;
    let mut tries = 0;
    loop {
        let stream = match connect() {
            Some(s) => s,
            None => spawn()?,
        };
        let answer = exchange(stream, &op)?;
        if answer["ok"] == json!(false)
            && answer["message"]
                .as_str()
                .is_some_and(|m| m.contains("another version"))
            && tries == 0
        {
            tries += 1;
            std::thread::sleep(Duration::from_millis(300));
            continue;
        }
        if answer["ok"] == json!(true) {
            return Ok(answer);
        }
        let code = answer["code"].as_i64().unwrap_or(1) as i32;
        return Err(fail(
            code,
            answer["message"]
                .as_str()
                .unwrap_or("the daemon failed")
                .to_string(),
        ));
    }
}

fn exchange(mut stream: UnixStream, op: &Value) -> Result<Value> {
    stream.write_all(format!("{op}\n").as_bytes())?;
    let mut print = printer();
    let mut r = BufReader::new(stream);
    loop {
        let mut line = String::new();
        if r.read_line(&mut line)? == 0 {
            return Err(fail(exit::ERROR, "The sealctl daemon closed the connection."));
        }
        let v: Value = serde_json::from_str(&line).unwrap_or(Value::Null);
        if v.get("event").is_some() {
            print(&v);
            continue;
        }
        return Ok(v);
    }
}

/// The daemon's status, if one is running (never starts one).
pub fn status_if_running() -> Option<Value> {
    if no_daemon() {
        return None;
    }
    let s = connect()?;
    s.set_read_timeout(Some(Duration::from_secs(3))).ok()?;
    exchange(s, &json!({"v": 1, "cli": VERSION, "op": "status"})).ok()
}

/// Tells a running daemon to lock and exit (pairing changed, unpair).
pub fn stop_running() {
    if let Some(s) = connect() {
        let _ = s.set_read_timeout(Some(Duration::from_secs(20)));
        let _ = exchange(s, &json!({"v": 1, "cli": VERSION, "op": "exit"}));
    }
}

/// Locks and stops the daemon.
pub fn lock_and_stop() {
    stop_running();
}

/// Secret values for names, with this process's context.
pub fn values(names: &[String], subject: Option<(&str, &str)>) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    let cwd = std::env::current_dir().unwrap_or_default();
    let cmd: Vec<String> = std::env::args().skip(1).collect();
    let mut op = json!({
        "op": "values",
        "names": names,
        "agent": crate::guard::ai_agent(),
        "cmd": cmd.join(" "),
        "cwd": cwd.display().to_string(),
    });
    if let Some((k, n)) = subject {
        op["subject"] = json!([k, n]);
    }
    let a = call(op)?;
    let mut out = Vec::new();
    for v in a["values"].as_array().cloned().unwrap_or_default() {
        let name = v["name"].as_str().unwrap_or("").to_string();
        let bytes = Zeroizing::new(
            B64.decode(v["value"].as_str().unwrap_or(""))
                .context("daemon value")?,
        );
        out.push((name, bytes));
    }
    Ok(out)
}

/// Keys for objects (volumes, backups), and the words fingerprint of the phone.
pub fn keys(items: &[RequestItem], subject: Option<(&str, &str)>) -> Result<(Vec<ObjectKey>, String)> {
    let mut op = json!({"op": "keys", "items": items});
    if let Some((k, n)) = subject {
        op["subject"] = json!({"k": k, "n": n});
    }
    let a = call(op)?;
    let keys = a["keys"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .map(|k| {
            ObjectKey::from_b64u(k.as_str().unwrap_or(""))
                .map_err(|_| fail(exit::ERROR, "bad key from the daemon"))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok((keys, a["words"].as_str().unwrap_or("").to_string()))
}

/// One key for a new object.
pub fn new_key(item: &RequestItem, subject: (&str, &str)) -> Result<(ObjectKey, String)> {
    let (mut k, w) = keys(std::slice::from_ref(item), Some(subject))?;
    Ok((k.remove(0), w))
}

/// Writes a secret through the daemon.
pub fn store_set(name: &str, value: &[u8], own: bool, force: bool) -> Result<()> {
    call(
        json!({"op": "store", "action": "set", "name": name, "value": B64.encode(value), "own": own, "force": force}),
    )?;
    Ok(())
}

/// Renames a secret through the daemon.
pub fn store_mv(old: &str, new: &str) -> Result<()> {
    call(json!({"op": "store", "action": "mv", "name": old, "new": new}))?;
    Ok(())
}
