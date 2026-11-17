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

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::derive::Oracle;
use crate::secrets;

pub const FILE: &str = ".sealctl.toml";

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ProjectFile {
    #[serde(default)]
    pub env: BTreeMap<String, String>,
}

/// Find `.sealctl.toml` in `start` or any parent directory.
pub fn find(start: &Path) -> Option<PathBuf> {
    start.ancestors().map(|d| d.join(FILE)).find(|p| p.is_file())
}

pub fn load(path: &Path) -> Result<ProjectFile> {
    let text = std::fs::read_to_string(path)?;
    toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))
}

/// Parse `NAME=secret` pairs given on the command line.
pub fn parse_pairs(pairs: &[String]) -> Result<BTreeMap<String, String>> {
    pairs
        .iter()
        .map(|p| {
            let (k, v) = p
                .split_once('=')
                .with_context(|| format!("expected NAME=secret, got {p:?}"))?;
            if k.is_empty() || v.is_empty() {
                bail!("expected NAME=secret, got {p:?}");
            }
            Ok((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Resolve env mappings (project file + command line, command line wins).
pub fn mappings(extra: &[String], use_project: bool) -> Result<BTreeMap<String, String>> {
    let mut map = BTreeMap::new();
    if use_project {
        if let Some(p) = find(&std::env::current_dir()?) {
            eprintln!("sealctl: secrets mapped in {}", p.display());
            map.extend(load(&p)?.env);
        }
    }
    map.extend(parse_pairs(extra)?);
    Ok(map)
}

/// Run `argv` with secrets injected into its environment only.
pub fn run(oracle: &mut dyn Oracle, extra: &[String], use_project: bool, argv: &[String]) -> Result<()> {
    let Some((prog, args)) = argv.split_first() else {
        bail!("no command given — usage: sealctl run [--env NAME=secret] -- <command>");
    };
    let map = mappings(extra, use_project)?;
    if map.is_empty() {
        eprintln!("note: no secrets mapped (no {FILE} found and no --env given)");
    }
    let names: Vec<&str> = map.values().map(|s| s.as_str()).collect();
    // say which secrets go to the program — a .sealctl.toml can come from a cloned repository
    for (var, name) in &map {
        eprintln!("sealctl: {var} ← {name}");
    }
    let values = if names.is_empty() {
        vec![]
    } else {
        secrets::get_many(oracle, &names)?
    };

    let mut cmd = Command::new(prog);
    cmd.args(args);
    for (k, v) in map.keys().zip(values.iter()) {
        cmd.env(k, v.as_str());
    }

    // Inside an AI agent, or whenever output isn't a terminal (logs, CI, pipes), whatever the
    // program prints passes through a filter that replaces the secret values with ****.
    use std::io::IsTerminal;
    let mask = crate::guard::ai_agent().is_some()
        || !std::io::stdout().is_terminal()
        || !std::io::stderr().is_terminal();
    // SEALCTL_NO_MASK is for humans debugging; an agent can't switch masking off
    let opt_out = std::env::var_os("SEALCTL_NO_MASK").is_some() && crate::guard::ai_agent().is_none();
    if mask && !values.is_empty() && !opt_out {
        return run_masked(cmd, prog, values.iter().map(|v| v.as_bytes().to_vec()).collect());
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec(); // replaces this process; secrets live only in the child
        bail!("starting {prog}: {err}");
    }
    #[cfg(not(unix))]
    {
        let status = cmd.status().with_context(|| format!("starting {prog}"))?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn run_masked(mut cmd: Command, prog: &str, secrets: Vec<Vec<u8>>) -> Result<()> {
    use std::process::Stdio;
    let mut child = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {prog}"))?;
    let out = child.stdout.take().context("stdout")?;
    let err = child.stderr.take().context("stderr")?;
    let s2 = secrets.clone();
    let t1 = std::thread::spawn(move || crate::guard::mask_stream(out, std::io::stdout(), secrets));
    let t2 = std::thread::spawn(move || crate::guard::mask_stream(err, std::io::stderr(), s2));
    let status = child.wait().with_context(|| format!("waiting for {prog}"))?;
    let _ = t1.join();
    let _ = t2.join();
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(sig) = status.signal() {
            std::process::exit(128 + sig);
        }
    }
    std::process::exit(status.code().unwrap_or(1));
}

/// Move a `.env` file into the secret store and write `.sealctl.toml`.
pub fn import_dotenv(
    oracle: &mut dyn Oracle,
    dotenv: &Path,
    prefix: &str,
    delete: bool,
    force: bool,
) -> Result<()> {
    let text = zeroize::Zeroizing::new(
        std::fs::read_to_string(dotenv).with_context(|| format!("reading {}", dotenv.display()))?,
    );
    let vars = secrets::parse_dotenv(&text)
        .with_context(|| format!("{} — nothing was imported", dotenv.display()))?;
    if vars.is_empty() {
        bail!("no variables found in {}", dotenv.display());
    }
    let dir = dotenv
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."));
    let pfile = dir.join(FILE);
    let mut project = if pfile.exists() {
        load(&pfile)?
    } else {
        ProjectFile::default()
    };
    let named: Vec<(String, String)> = vars
        .keys()
        .map(|k| {
            (
                k.clone(),
                format!("{prefix}/{}", k.to_lowercase().replace('_', "-")),
            )
        })
        .collect();
    // never silently replace secrets that exist already (e.g. a second .env with the same prefix)
    let existing: Vec<&str> = named
        .iter()
        .filter(|(_, n)| secrets::exists(n).unwrap_or(false))
        .map(|(_, n)| n.as_str())
        .collect();
    if !existing.is_empty() && !force {
        bail!(
            "these secrets exist already: {} — use another --prefix, or --force to replace them",
            existing.join(", ")
        );
    }
    for (k, name) in &named {
        secrets::set(oracle, name, vars[k].as_bytes(), true)?;
        project.env.insert(k.clone(), name.clone());
        println!("  {k:<28} → {name}");
    }
    // read everything back before the plaintext file may be deleted
    let names: Vec<&str> = named.iter().map(|(_, n)| n.as_str()).collect();
    let back = secrets::get_many(oracle, &names)?;
    for ((k, _), v) in named.iter().zip(back.iter()) {
        if v.as_str() != vars[k].as_str() {
            bail!("{k} did not read back identically — keeping {}", dotenv.display());
        }
    }
    std::fs::write(&pfile, toml::to_string_pretty(&project)?)?;
    println!(
        "✅ {} variables stored; mapping written to {}",
        vars.len(),
        pfile.display()
    );
    if delete {
        std::fs::remove_file(dotenv)?;
        println!("   removed {}", dotenv.display());
    } else {
        println!(
            "   You can now delete {} (it still contains the plaintext values).",
            dotenv.display()
        );
    }
    println!("   Run your app with: sealctl run -- <command>");
    Ok(())
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
}
