//! Per-project environment: `.sealctl.toml` maps environment variables to secrets, and
//! `sealctl run -- cmd` starts `cmd` with those variables set — a replacement for `.env` files
//! that keeps secrets off disk.
//!
//! ```toml
//! [env]
//! OPENAI_API_KEY = "openai"
//! DATABASE_URL   = "myapp/database-url"
//! ```
//!
//! A project file can come with a cloned repository, so it is trusted on first use: the first
//! time `sealctl run` uses one, and again whenever its content changes, a person at a terminal
//! is asked; without a terminal the run is refused until `sealctl project trust`. The trust list
//! (`projects.json` in the state folder) keeps each file's canonical path, the SHA-256 of its
//! content and when it was trusted. Agents never trust a file: their uses go to the phone.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::exit::{self, fail};

/// The project file name.
pub const FILE: &str = ".sealctl.toml";

/// `.sealctl.toml`.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectFile {
    /// Variables for every command.
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    /// Variables for commands starting with these words.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub command: BTreeMap<String, BTreeMap<String, String>>,
}

/// Finds `.sealctl.toml` in `start` or any parent folder.
pub fn find(start: &Path) -> Option<PathBuf> {
    start.ancestors().map(|d| d.join(FILE)).find(|p| p.is_file())
}

/// Reads a project file.
pub fn load(path: &Path) -> Result<ProjectFile> {
    let text = std::fs::read_to_string(path)?;
    toml::from_str(&text).with_context(|| format!("reading {}", path.display()))
}

fn parse(path: &Path, bytes: &[u8]) -> Result<ProjectFile> {
    let text = std::str::from_utf8(bytes).with_context(|| format!("reading {}", path.display()))?;
    toml::from_str(text).with_context(|| format!("reading {}", path.display()))
}

impl ProjectFile {
    /// Every mapping as (variable, secret name, the command words of its section, if any).
    fn mappings(&self) -> Vec<(&str, &str, Option<&str>)> {
        let mut v: Vec<(&str, &str, Option<&str>)> = self
            .env
            .iter()
            .map(|(k, n)| (k.as_str(), n.as_str(), None))
            .collect();
        for (words, vars) in &self.command {
            v.extend(
                vars.iter()
                    .map(|(k, n)| (k.as_str(), n.as_str(), Some(words.as_str()))),
            );
        }
        v
    }
}

/// One trusted project file: no secret names, no values.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Trusted {
    /// Canonical path of the file.
    path: String,
    /// SHA-256 of its content, hex.
    sha256: String,
    /// When it was trusted (RFC 3339).
    trusted: String,
}

/// `projects.json`: the project files trusted on this machine.
#[derive(Debug, Default, Serialize, Deserialize)]
struct TrustList {
    #[serde(default)]
    projects: Vec<Trusted>,
}

fn trust_file() -> Result<PathBuf> {
    Ok(crate::paths::state_dir()?.join("projects.json"))
}

fn canonical(path: &Path) -> Result<String> {
    Ok(std::fs::canonicalize(path)
        .with_context(|| format!("reading {}", path.display()))?
        .display()
        .to_string())
}

fn trust_list() -> Result<TrustList> {
    match std::fs::read(trust_file()?) {
        Ok(b) => Ok(serde_json::from_slice(&b).unwrap_or_default()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TrustList::default()),
        Err(e) => Err(e).context("reading the list of trusted project files"),
    }
}

/// What the trust list says about a project file with this content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Trust {
    /// Trusted with this content.
    Yes,
    /// Never trusted.
    New,
    /// Trusted with other content.
    Changed,
}

fn trust_of(path: &Path, bytes: &[u8]) -> Result<Trust> {
    let canon = canonical(path)?;
    let hash = crate::util::sha256_hex(bytes);
    Ok(match trust_list()?.projects.iter().find(|t| t.path == canon) {
        Some(t) if t.sha256 == hash => Trust::Yes,
        Some(_) => Trust::Changed,
        None => Trust::New,
    })
}

/// Records the project file at `path`, with this content, as trusted. Never inside an AI agent.
fn record_trust(path: &Path, bytes: &[u8]) -> Result<()> {
    crate::term::refuse_agent("sealctl project trust")?;
    let canon = canonical(path)?;
    let mut list = trust_list()?;
    list.projects.retain(|t| t.path != canon);
    list.projects.push(Trusted {
        path: canon,
        sha256: crate::util::sha256_hex(bytes),
        trusted: crate::clock::local_rfc3339(jiff::Timestamp::now()),
    });
    let dir = crate::paths::state_dir()?;
    crate::paths::ensure_private_dir(&dir)?;
    crate::paths::write_private(&trust_file()?, &serde_json::to_vec_pretty(&list)?)
}

fn print_mappings(f: &ProjectFile) {
    for (var, name, words) in f.mappings() {
        match words {
            Some(w) => eprintln!("  {var} ← {name}  (for {w})"),
            None => eprintln!("  {var} ← {name}"),
        }
    }
}

/// Checks that a person trusts the project file at `path` with content `bytes` before its
/// mappings are used: asks at a terminal the first time and after every change, refuses
/// without one (exit 8). Inside an AI agent nothing is asked or recorded: an agent's uses go
/// to the phone (SPEC 9).
fn check_trust(path: &Path, bytes: &[u8], f: &ProjectFile) -> Result<()> {
    if f.mappings().is_empty() {
        return Ok(());
    }
    let state = trust_of(path, bytes)?;
    if state == Trust::Yes {
        return Ok(());
    }
    let shown = crate::paths::tilde(path);
    let what = match state {
        Trust::Changed => format!("{shown} changed since it was trusted on this machine"),
        _ => format!("{shown} is new on this machine"),
    };
    match crate::term::reader() {
        crate::term::Reader::Agent(_) => Ok(()),
        crate::term::Reader::Pipe => Err(fail(
            exit::REFUSED,
            format!(
                "{what}; nothing was run.\nCheck the secrets it names, then trust it once: \
                 sealctl project trust {shown}"
            ),
        )),
        crate::term::Reader::Person => {
            eprintln!("sealctl: {what}. It gives commands run here these secrets:");
            print_mappings(f);
            if !crate::term::confirm("Trust this file?", false)? {
                return Err(fail(
                    exit::ERROR,
                    "Not trusted; nothing was run. Without it: sealctl run --no-project -- <command>",
                ));
            }
            record_trust(path, bytes)
        }
    }
}

/// `sealctl project trust [PATH]`: trusts the project file at PATH (a `.sealctl.toml`, or a
/// folder searched upwards as `sealctl run` does; default the working directory) as it is now.
/// Refused inside an AI agent; needs no terminal, so scripts and CI can trust a file once.
pub fn trust(path: Option<&Path>) -> Result<()> {
    crate::term::refuse_agent("sealctl project trust")?;
    let start = match path {
        Some(p) => p.to_path_buf(),
        None => std::env::current_dir()?,
    };
    let file = if start.is_dir() {
        find(&start)
    } else if start.is_file() {
        Some(start.clone())
    } else {
        None
    }
    .ok_or_else(|| fail(exit::NOT_FOUND, format!("No {FILE} at {}.", start.display())))?;
    let bytes = std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?;
    let f = parse(&file, &bytes)?;
    eprintln!(
        "{} gives commands run here these secrets:",
        crate::paths::tilde(&file)
    );
    print_mappings(&f);
    record_trust(&file, &bytes)?;
    eprintln!("Trusted {}.", crate::paths::tilde(&file));
    Ok(())
}

/// Changes (or creates) the project file at `path` for sealctl itself (`seal env`, `scan`),
/// then records the result as trusted, since sealctl wrote it. Not when a file was there
/// already and not trusted (its mappings came from elsewhere, a cloned repository perhaps: the
/// next `sealctl run` asks about all of them), and never inside an AI agent.
pub fn update(path: &Path, change: impl FnOnce(&mut ProjectFile)) -> Result<()> {
    let before = match std::fs::read(path) {
        Ok(b) => Some(b),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => None,
        Err(e) => return Err(e).with_context(|| format!("reading {}", path.display())),
    };
    let mut f = match &before {
        Some(b) => parse(path, b)?,
        None => ProjectFile::default(),
    };
    let ours = match &before {
        None => true,
        Some(b) => f.mappings().is_empty() || trust_of(path, b)? == Trust::Yes,
    };
    change(&mut f);
    let text = toml::to_string_pretty(&f)?;
    std::fs::write(path, &text).with_context(|| format!("writing {}", path.display()))?;
    if ours && crate::guard::ai_agent().is_none() {
        record_trust(path, text.as_bytes())?;
    }
    Ok(())
}

/// Parses `NAME=secret` pairs given on the command line.
pub fn parse_pairs(pairs: &[String]) -> Result<BTreeMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            let (k, v) = p
                .split_once('=')
                .ok_or_else(|| fail(exit::USAGE, format!("Expected NAME=secret, got {p:?}.")))?;
            if k.is_empty() || v.is_empty() {
                return Err(fail(exit::USAGE, format!("Expected NAME=secret, got {p:?}.")));
            }
            Ok((k.to_string(), v.to_string()))
        })
        .collect()
}

/// The mappings for `argv`: `[env]`, then `[command."<words>"]` sections whose words are a prefix
/// of the command line (the longest prefix wins per variable), then `-e`.
pub fn mappings_for(
    project: Option<&ProjectFile>,
    argv: &[String],
    extra: &[String],
) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    if let Some(p) = project {
        map.extend(p.env.clone());
        let mut sections: Vec<(&String, &BTreeMap<String, String>)> = p
            .command
            .iter()
            .filter(|(words, _)| {
                let w: Vec<&str> = words.split_whitespace().collect();
                !w.is_empty() && w.len() <= argv.len() && w.iter().zip(argv).all(|(a, b)| a == b)
            })
            .collect();
        sections.sort_by_key(|(w, _)| w.split_whitespace().count());
        for (_, vars) in sections {
            map.extend(vars.clone());
        }
    }
    map.extend(parse_pairs(extra)?);
    Ok(map)
}

/// `sealctl run`: starts `argv` with the mapped secrets in its environment only.
pub fn run(extra: &[String], use_project: bool, argv: &[String]) -> Result<()> {
    let Some((prog, args)) = argv.split_first() else {
        return Err(fail(
            exit::USAGE,
            "No command given. Usage: sealctl run [-e NAME=secret] -- <command>",
        ));
    };
    let project = if use_project {
        match find(&std::env::current_dir()?) {
            Some(p) => {
                // read once: the bytes trusted are the bytes used
                let bytes = std::fs::read(&p).with_context(|| format!("reading {}", p.display()))?;
                let f = parse(&p, &bytes)?;
                check_trust(&p, &bytes, &f)?;
                Some(f)
            }
            None => None,
        }
    } else {
        None
    };
    let map = mappings_for(project.as_ref(), argv, extra)?;
    // say which secrets go to the program: a .sealctl.toml can come from a cloned repository
    for (var, name) in &map {
        eprintln!("sealctl: {var} ← {name}");
    }
    let names: Vec<String> = map
        .values()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    let values = if names.is_empty() {
        vec![]
    } else {
        crate::daemon::client::values(&names, None)?
    };
    let by_name: BTreeMap<&str, &[u8]> = values.iter().map(|(n, v)| (n.as_str(), v.as_slice())).collect();

    let mut cmd = Command::new(prog);
    cmd.args(args);
    let mut secrets = Vec::new();
    for (var, name) in &map {
        let v = by_name.get(name.as_str()).copied().unwrap_or_default();
        let text = zeroize::Zeroizing::new(String::from_utf8_lossy(v).into_owned());
        cmd.env(var, text.as_str());
        secrets.push(v.to_vec());
    }

    // Inside an AI agent, or whenever output isn't a terminal (logs, CI, pipes), whatever the
    // program prints passes through a filter that replaces the secret values with ****.
    use std::io::IsTerminal;
    let agent = crate::guard::ai_agent().is_some();
    let mask = agent || !std::io::stdout().is_terminal() || !std::io::stderr().is_terminal();
    // SEALCTL_NO_MASK is for humans debugging; an agent can't switch masking off
    let opt_out = std::env::var_os("SEALCTL_NO_MASK").is_some() && !agent;
    if mask && !secrets.is_empty() && !opt_out {
        return run_masked(cmd, prog, secrets);
    }
    use std::os::unix::process::CommandExt;
    let err = cmd.exec(); // replaces this process; secrets live only in the child
    Err(fail(127, format!("Cannot start {prog}: {err}")))
}

fn run_masked(mut cmd: Command, prog: &str, secrets: Vec<Vec<u8>>) -> Result<()> {
    use std::process::Stdio;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| fail(127, format!("Cannot start {prog}: {e}")))?;
    // sealctl stays until the program exits, so its last output still passes the filter.
    // Ctrl-C, Ctrl-\ and a terminal hangup reach the whole foreground group, the program too, so
    // they are not sent again (a second interrupt makes some programs quit without cleaning up);
    // one sent to sealctl's pid alone does not reach the program. SIGTERM is passed on, as it is
    // usually sent to sealctl alone; one sent to the whole group or tree (timeout(1), kill of a
    // process group) then reaches the program twice.
    use signal_hook::consts::{SIGHUP, SIGINT, SIGQUIT, SIGTERM};
    if let Ok(mut signals) = signal_hook::iterator::Signals::new([SIGINT, SIGQUIT, SIGTERM, SIGHUP]) {
        let pid = nix::unistd::Pid::from_raw(child.id() as i32);
        std::thread::spawn(move || {
            for sig in signals.forever() {
                if sig == SIGTERM {
                    let _ = nix::sys::signal::kill(pid, nix::sys::signal::Signal::SIGTERM);
                }
            }
        });
    }
    let out = child.stdout.take().context("stdout")?;
    let err = child.stderr.take().context("stderr")?;
    let s2 = secrets.clone();
    let t1 = std::thread::spawn(move || crate::guard::mask_stream(out, std::io::stdout(), secrets));
    let t2 = std::thread::spawn(move || crate::guard::mask_stream(err, std::io::stderr(), s2));
    let status = child.wait().with_context(|| format!("waiting for {prog}"))?;
    let _ = t1.join();
    let _ = t2.join();
    use std::os::unix::process::ExitStatusExt;
    if let Some(sig) = status.signal() {
        std::process::exit(128 + sig);
    }
    std::process::exit(status.code().unwrap_or(1));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pairs() {
        let m = parse_pairs(&["A=x".into(), "B=work/y".into()]).unwrap();
        assert_eq!(m["A"], "x");
        assert_eq!(m["B"], "work/y");
        assert!(parse_pairs(&["nope".into()]).is_err());
        assert!(parse_pairs(&["=x".into()]).is_err());
    }

    #[test]
    fn project_file_roundtrip() {
        let f: ProjectFile = toml::from_str("[env]\nOPENAI_API_KEY = \"openai\"\n").unwrap();
        assert_eq!(f.env["OPENAI_API_KEY"], "openai");
    }

    #[test]
    fn command_sections() {
        let f: ProjectFile = toml::from_str(
            "[env]\nA = \"shop/a\"\nT = \"shop/t\"\n[command.\"npm run\"]\nT = \"shop/run\"\n[command.\"npm run deploy\"]\nT = \"shop/deploy\"\n",
        )
        .unwrap();
        let argv = |s: &str| s.split(' ').map(String::from).collect::<Vec<_>>();
        let m = mappings_for(Some(&f), &argv("npm run deploy --prod"), &[]).unwrap();
        assert_eq!(m["T"], "shop/deploy");
        assert_eq!(m["A"], "shop/a");
        let m = mappings_for(Some(&f), &argv("npm run test"), &[]).unwrap();
        assert_eq!(m["T"], "shop/run");
        let m = mappings_for(Some(&f), &argv("npm test"), &["T=x/y".into()]).unwrap();
        assert_eq!(m["T"], "x/y");
    }
}
