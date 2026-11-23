//! Per-project environment: `.sealctl.toml` maps environment variables to secrets, and
//! `sealctl run -- cmd` starts `cmd` with those variables set — a replacement for `.env` files
//! that keeps secrets off disk.
//!
//! ```toml
//! [env]
//! OPENAI_API_KEY = "openai"
//! DATABASE_URL   = "myapp/database-url"
//! ```

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
            Some(p) => Some(load(&p)?),
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
