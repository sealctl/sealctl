//! `sealctl scan` (SPEC 10.4): finds keys in files and moves them into the store, leaving
//! references behind. Sources: `.env` files, shell rc files, shell histories, `~/.aws/credentials`.
//! The list shows file, line, kind and the first 4 characters only; values never leave memory
//! except into the store.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::Serialize;
use serde_json::json;
use zeroize::Zeroizing;

use crate::daemon::client;
use crate::exit::{self, fail};
use crate::{paths, project, term, util};

/// One key found.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    /// The file.
    pub file: PathBuf,
    /// Line number, from 1.
    pub line: usize,
    /// `env file`, `shell rc`, `history`, `aws credentials`.
    pub kind: &'static str,
    /// The variable or profile.
    pub source: String,
    /// The secret it becomes (`None` for history copies, which are only masked).
    pub name: Option<String>,
    #[serde(skip)]
    value: Zeroizing<String>,
}

impl Finding {
    fn preview(&self) -> String {
        let head: String = self.value.chars().take(4).collect();
        format!("{head}…")
    }
}

const SKIP_DIRS: &[&str] = &["node_modules", ".git", "Library", "target", "vendor"];
const SAFE_ENV: &[&str] = &[
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
];

/// `UPPER_SNAKE` → `upper-snake`.
pub fn dashed(var: &str) -> String {
    var.to_lowercase().replace('_', "-")
}

/// A value worth sealing: a known key format, or a long random value in a variable whose name
/// says key, token, secret or password.
pub fn key_like(var: &str, value: &str) -> bool {
    if value.len() < 8 {
        return false;
    }
    if !crate::guard::find_secrets(value).is_empty() {
        return true;
    }
    let v = var.to_uppercase();
    let named = ["KEY", "TOKEN", "SECRET", "PASSW", "CREDENTIAL", "AUTH"]
        .iter()
        .any(|w| v.contains(w));
    let random = value.len() >= 16
        && value.chars().any(|c| c.is_ascii_digit())
        && value.chars().any(|c| c.is_ascii_alphabetic())
        && !value.contains(' ')
        && !value.starts_with('/')
        && !value.starts_with('$');
    named && random
}

fn env_files(root: &Path, depth: usize, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else { return };
    for e in rd.flatten() {
        let p = e.path();
        let n = e.file_name().to_string_lossy().into_owned();
        let Ok(ft) = e.file_type() else { continue };
        if ft.is_symlink() {
            continue;
        }
        if ft.is_dir() {
            if depth > 0 && !SKIP_DIRS.contains(&n.as_str()) {
                env_files(&p, depth - 1, out);
            }
        } else if (n == ".env" || n.starts_with(".env.")) && !SAFE_ENV.contains(&n.as_str()) {
            out.push(p);
        }
    }
}

/// The repository name of a folder (for secret names), else the folder name.
fn project_name(dir: &Path) -> String {
    crate::approve::repo_of(dir)
        .map(|r| r.name.rsplit('/').next().unwrap_or(&r.name).to_string())
        .unwrap_or_else(|| {
            dir.file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "project".into())
        })
        .to_lowercase()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn scan_env_file(file: &Path, out: &mut Vec<Finding>) {
    let Ok(text) = std::fs::read_to_string(file) else {
        return;
    };
    let text = Zeroizing::new(text);
    let Ok(entries) = crate::dotenv::entries(&text) else {
        return;
    };
    let dir = file.parent().unwrap_or(Path::new("."));
    let prefix = project_name(dir);
    // the last assignment of a name is the one in effect
    let last: BTreeMap<&str, &crate::dotenv::Entry> = entries.iter().map(|e| (e.key.as_str(), e)).collect();
    for (var, e) in last {
        if e.value.is_empty() {
            continue;
        }
        out.push(Finding {
            file: file.to_path_buf(),
            line: e.line,
            kind: "env file",
            source: var.to_string(),
            name: Some(format!("{prefix}/{}", dashed(var))),
            value: e.value.clone(),
        });
    }
}

/// `export VAR=value` / `set -x VAR value`: `(var, value)`.
fn rc_assignment(line: &str) -> Option<(String, String)> {
    let t = line.trim();
    if t.starts_with('#') {
        return None;
    }
    let (var, raw) = if let Some(r) = t.strip_prefix("export ") {
        let (k, v) = r.trim().split_once('=')?;
        (k.trim().to_string(), v.trim().to_string())
    } else {
        let r = t.strip_prefix("set -x ").or_else(|| t.strip_prefix("set -gx "))?;
        let (k, v) = r.trim().split_once(char::is_whitespace)?;
        (k.trim().to_string(), v.trim().to_string())
    };
    if var.is_empty() || !var.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return None;
    }
    let v = raw
        .strip_prefix('"')
        .and_then(|x| x.strip_suffix('"'))
        .or_else(|| raw.strip_prefix('\'').and_then(|x| x.strip_suffix('\'')))
        .unwrap_or(&raw)
        .to_string();
    Some((var, v))
}

fn scan_rc(file: &Path, out: &mut Vec<Finding>) {
    let Ok(text) = std::fs::read_to_string(file) else {
        return;
    };
    for (i, l) in text.lines().enumerate() {
        if let Some((var, value)) = rc_assignment(l) {
            if key_like(&var, &value) {
                out.push(Finding {
                    file: file.to_path_buf(),
                    line: i + 1,
                    kind: "shell rc",
                    source: var.clone(),
                    name: Some(format!("env/{}", dashed(&var))),
                    value: Zeroizing::new(value),
                });
            }
        }
    }
}

fn scan_history(file: &Path, out: &mut Vec<Finding>) {
    let Ok(bytes) = std::fs::read(file) else { return };
    let text = Zeroizing::new(String::from_utf8_lossy(&bytes).into_owned());
    for (i, l) in text.lines().enumerate() {
        for f in crate::guard::find_secret_values(l) {
            out.push(Finding {
                file: file.to_path_buf(),
                line: i + 1,
                kind: "history",
                source: f.0.to_string(),
                name: None,
                value: Zeroizing::new(f.1),
            });
        }
    }
}

fn scan_aws(file: &Path, out: &mut Vec<Finding>) {
    let Ok(text) = std::fs::read_to_string(file) else {
        return;
    };
    for (profile, vals, line) in ini_sections(&text) {
        let Some(secret) = vals.get("aws_secret_access_key") else {
            continue;
        };
        let mut j = json!({"aws_access_key_id": vals.get("aws_access_key_id").cloned().unwrap_or_default(), "aws_secret_access_key": secret});
        if let Some(t) = vals.get("aws_session_token") {
            j["aws_session_token"] = json!(t);
        }
        out.push(Finding {
            file: file.to_path_buf(),
            line,
            kind: "aws credentials",
            source: profile.clone(),
            name: Some(format!("aws/{profile}")),
            value: Zeroizing::new(j.to_string()),
        });
    }
}

/// `[profile]` sections of an ini file: name, keys, first line.
fn ini_sections(text: &str) -> Vec<(String, BTreeMap<String, String>, usize)> {
    let mut out: Vec<(String, BTreeMap<String, String>, usize)> = Vec::new();
    for (i, l) in text.lines().enumerate() {
        let t = l.trim();
        if let Some(n) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
            out.push((n.trim().to_string(), BTreeMap::new(), i + 1));
        } else if let (Some(sec), Some((k, v))) = (out.last_mut(), t.split_once('=')) {
            sec.1.insert(k.trim().to_string(), v.trim().to_string());
        }
    }
    out
}

/// Everything found under `paths` (default: the repository root or the working folder), and
/// with `home` the home folder, its shell files, histories and AWS credentials.
pub fn find(roots: &[PathBuf], home: bool) -> Result<Vec<Finding>> {
    let mut files = Vec::new();
    let roots: Vec<PathBuf> = if roots.is_empty() {
        let cwd = std::env::current_dir()?;
        let top = std::process::Command::new("git")
            .args(["rev-parse", "--show-toplevel"])
            .current_dir(&cwd)
            .stderr(std::process::Stdio::null())
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| PathBuf::from(String::from_utf8_lossy(&o.stdout).trim()));
        vec![top.unwrap_or(cwd)]
    } else {
        roots.to_vec()
    };
    for r in &roots {
        if r.is_file() {
            files.push(r.clone());
        } else {
            env_files(r, 6, &mut files);
        }
    }
    let h = paths::home()?;
    if home {
        env_files(&h, 6, &mut files);
    }
    // the same file reached through /tmp and /private/tmp is one file
    let mut files: Vec<PathBuf> = files
        .into_iter()
        .map(|f| std::fs::canonicalize(&f).unwrap_or(f))
        .collect();
    files.sort();
    files.dedup();
    let mut out = Vec::new();
    for f in &files {
        scan_env_file(f, &mut out);
    }
    if home {
        for rc in [
            ".zshrc",
            ".bashrc",
            ".bash_profile",
            ".profile",
            ".zprofile",
            ".config/fish/config.fish",
        ] {
            scan_rc(&h.join(rc), &mut out);
        }
        for hist in [".zsh_history", ".bash_history", ".local/share/fish/fish_history"] {
            scan_history(&h.join(hist), &mut out);
        }
        scan_aws(&h.join(".aws/credentials"), &mut out);
    }
    Ok(out)
}

/// Rewrites a file in place keeping its mode (temporary name, fsync, rename). A symlink
/// (a dotfiles repository's `~/.zshrc`) stays: the file it points to is the one rewritten.
fn rewrite(file: &Path, text: &[u8]) -> Result<()> {
    use anyhow::Context;
    use std::os::unix::fs::PermissionsExt;
    let target = std::fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
    let mode = std::fs::metadata(&target)
        .map(|m| m.permissions().mode() & 0o7777)
        .unwrap_or(0o600);
    paths::write_mode(&target, text, mode).with_context(|| format!("rewriting {}", file.display()))
}

/// `hay` with every `needle` replaced by `****`, byte for byte (a zsh history is not UTF-8).
fn mask_bytes(hay: &[u8], needle: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut out = Zeroizing::new(Vec::with_capacity(hay.len()));
    if needle.is_empty() {
        out.extend_from_slice(hay);
        return out;
    }
    let mut i = 0;
    while i < hay.len() {
        if hay[i..].starts_with(needle) {
            out.extend_from_slice(b"****");
            i += needle.len();
        } else {
            out.push(hay[i]);
            i += 1;
        }
    }
    out
}

/// The secret a value goes to: its name, or `<name>-2`, `-3`, … when the store or this run
/// has that name with another value; and whether the store still has to be written.
fn place(
    store: &crate::store::Store,
    base: &str,
    sum: &str,
    taken: &std::collections::BTreeSet<String>,
) -> Result<(String, bool)> {
    let mut name = base.to_string();
    let mut i = 2;
    loop {
        crate::store::check_name(&name)?;
        if !taken.contains(&name) {
            if !store.exists(&name) {
                return Ok((name, true));
            }
            // already in the store: the same value is used as it is, another one is kept
            let back = client::values(std::slice::from_ref(&name), None)?;
            if back.first().is_some_and(|(_, v)| util::sha256_hex(v) == sum) {
                return Ok((name, false));
            }
        }
        name = format!("{base}-{i}");
        i += 1;
    }
}

/// Seals the findings: values into the store (one secret per distinct value), each read back,
/// then the references written and the files changed.
pub fn seal(findings: &[Finding]) -> Result<usize> {
    // every file is read before anything is stored or changed
    let mut texts: BTreeMap<PathBuf, Zeroizing<Vec<u8>>> = BTreeMap::new();
    for f in findings {
        if !texts.contains_key(&f.file) {
            let bytes = std::fs::read(&f.file).map_err(|e| {
                fail(
                    exit::ERROR,
                    format!(
                        "Cannot read {}: {e}. Nothing was stored and no file was changed.",
                        f.file.display()
                    ),
                )
            })?;
            texts.insert(f.file.clone(), Zeroizing::new(bytes));
        }
    }
    // a folder's .sealctl.toml maps a variable to one secret: .env files of one folder that
    // give it different values stop the scan here, before anything is stored
    let mut per_var: BTreeMap<(PathBuf, &str), Vec<(&Path, String)>> = BTreeMap::new();
    for f in findings.iter().filter(|f| f.kind == "env file") {
        let dir = f.file.parent().unwrap_or(Path::new(".")).to_path_buf();
        per_var
            .entry((dir, f.source.as_str()))
            .or_default()
            .push((&f.file, util::sha256_hex(f.value.as_bytes())));
    }
    for ((dir, var), seen) in &per_var {
        if seen.iter().any(|(_, s)| *s != seen[0].1) {
            let files: Vec<String> = seen
                .iter()
                .map(|(f, _)| f.file_name().unwrap_or_default().to_string_lossy().into_owned())
                .collect();
            return Err(fail(
                exit::ERROR,
                format!(
                    "{var} has different values in {} in {}, and the folder's {} maps it to one \
                     secret. Nothing was stored and no file was changed. Keep one value of {var} \
                     in that folder, then scan again.",
                    files.join(" and "),
                    paths::tilde(dir),
                    project::FILE
                ),
            ));
        }
    }
    // one secret per value: the first name it was found under, never another value's
    let store = crate::store::Store::configured()?;
    let mut by_value: BTreeMap<String, String> = BTreeMap::new();
    let mut taken = std::collections::BTreeSet::new();
    let mut stored = 0;
    for f in findings {
        let Some(base) = &f.name else { continue };
        let sum = util::sha256_hex(f.value.as_bytes());
        if by_value.contains_key(&sum) {
            continue;
        }
        let (name, write) = place(&store, base, &sum, &taken)?;
        if write {
            client::store_set(&name, f.value.as_bytes(), false, false)?;
        }
        taken.insert(name.clone());
        by_value.insert(sum, name);
        stored += 1;
    }
    let names: Vec<String> = by_value.values().cloned().collect();
    if !names.is_empty() {
        let back = client::values(&names, None)?;
        let got: BTreeMap<String, String> = back
            .iter()
            .map(|(n, v)| (n.clone(), util::sha256_hex(v)))
            .collect();
        for (sum, name) in &by_value {
            if got.get(name) != Some(sum) {
                return Err(fail(
                    exit::ERROR,
                    format!("{name} did not read back the same. No file was changed."),
                ));
            }
        }
    }
    let name_of = |f: &Finding| by_value.get(&util::sha256_hex(f.value.as_bytes())).cloned();
    // .env files: mappings next to them, lines removed (the file deleted when empty)
    let mut by_file: BTreeMap<PathBuf, Vec<&Finding>> = BTreeMap::new();
    for f in findings {
        by_file.entry(f.file.clone()).or_default().push(f);
    }
    // the files were read before the store was written, which can wait on the phone: one that
    // changed meanwhile (a shell appending to its history, an edit) is never rewritten from the
    // old text. A history is masked as it is now; any other file is left as it is
    let mut changed = Vec::new();
    for (file, fs) in by_file {
        let bytes = &texts[&file];
        let Ok(now) = std::fs::read(&file).map(Zeroizing::new) else {
            changed.push(paths::tilde(&file));
            continue;
        };
        if fs[0].kind == "history" {
            let mut t = now;
            for f in &fs {
                t = mask_bytes(&t, f.value.as_bytes());
            }
            rewrite(&file, &t)?;
            continue;
        }
        if *now != **bytes {
            changed.push(paths::tilde(&file));
            continue;
        }
        let text = Zeroizing::new(String::from_utf8(bytes.to_vec()).map_err(|_| {
            fail(
                exit::ERROR,
                format!("{} is not text. It was left as it is.", file.display()),
            )
        })?);
        match fs[0].kind {
            "env file" => {
                let dir = file.parent().unwrap_or(Path::new(".")).to_path_buf();
                let pfile = dir.join(project::FILE);
                let mut p = if pfile.exists() {
                    project::load(&pfile)?
                } else {
                    project::ProjectFile::default()
                };
                for f in &fs {
                    if let Some(n) = name_of(f) {
                        p.env.insert(f.source.clone(), n);
                    }
                }
                std::fs::write(&pfile, toml::to_string_pretty(&p)?)?;
                // the assignments of the sealed names, found by the parser (any line ending,
                // quoted values over several lines), removed byte for byte. A name goes only if
                // the value in effect (its last assignment) is still the one stored; then its
                // earlier assignments go too, so none of them takes effect instead
                let entries = crate::dotenv::entries(&text).map_err(|e| {
                    fail(
                        exit::ERROR,
                        format!("{}: {e}. It was left as it is.", file.display()),
                    )
                })?;
                let last: BTreeMap<&str, &crate::dotenv::Entry> =
                    entries.iter().map(|e| (e.key.as_str(), e)).collect();
                let gone: Vec<&str> = fs
                    .iter()
                    .filter(|f| last.get(f.source.as_str()).is_some_and(|e| *e.value == *f.value))
                    .map(|f| f.source.as_str())
                    .collect();
                let remove: Vec<&crate::dotenv::Entry> = entries
                    .iter()
                    .filter(|e| gone.contains(&e.key.as_str()))
                    .collect();
                let kept = crate::dotenv::without(&text, &remove);
                if crate::dotenv::entries(&kept).is_ok_and(|e| e.is_empty())
                    && kept
                        .split(['\n', '\r'])
                        .all(|l| l.trim().is_empty() || l.trim_start().starts_with('#'))
                {
                    std::fs::remove_file(&file)
                        .map_err(|e| anyhow::anyhow!("removing {}: {e}", file.display()))?;
                } else {
                    rewrite(&file, kept.as_bytes())?;
                }
            }
            "shell rc" => {
                let mut lines: Vec<String> = text.lines().map(str::to_owned).collect();
                for f in &fs {
                    if let (Some(l), Some(n)) = (lines.get_mut(f.line - 1), name_of(f)) {
                        *l = format!(
                            "# {} moved to sealctl: sealctl run -e {}={n} -- <command>",
                            f.source, f.source
                        );
                    }
                }
                rewrite(&file, (lines.join("\n") + "\n").as_bytes())?;
            }
            "aws credentials" => {
                let profiles: Vec<&str> = fs.iter().map(|f| f.source.as_str()).collect();
                let mut keep = String::new();
                let mut skipping = false;
                for l in text.lines() {
                    let t = l.trim();
                    if let Some(n) = t.strip_prefix('[').and_then(|x| x.strip_suffix(']')) {
                        skipping = profiles.contains(&n.trim());
                    }
                    if !skipping {
                        keep.push_str(l);
                        keep.push('\n');
                    }
                }
                rewrite(&file, keep.as_bytes())?;
                let cfg = file.with_file_name("config");
                let mut c = std::fs::read_to_string(&cfg).unwrap_or_default();
                let exe = util::stable_exe()?.display().to_string();
                for p in profiles {
                    let header = if p == "default" {
                        "[default]".to_string()
                    } else {
                        format!("[profile {p}]")
                    };
                    let line = format!("credential_process = {exe} aws credentials --profile {p}");
                    if !c.contains(&line) {
                        if let Some(i) = c.find(&header) {
                            let at = i + header.len();
                            c.insert_str(at, &format!("\n{line}"));
                        } else {
                            c.push_str(&format!("\n{header}\n{line}\n"));
                        }
                    }
                }
                std::fs::create_dir_all(cfg.parent().unwrap_or(Path::new(".")))?;
                rewrite_or_create(&cfg, &c)?;
            }
            _ => {}
        }
    }
    if !changed.is_empty() {
        return Err(fail(
            exit::PARTWAY,
            format!(
                "{} changed while sealctl scanned; left as it is (the values are stored). Run sealctl scan again.",
                changed.join(", ")
            ),
        ));
    }
    Ok(stored)
}

fn rewrite_or_create(file: &Path, text: &str) -> Result<()> {
    if file.exists() {
        rewrite(file, text.as_bytes())
    } else {
        paths::write_mode(file, text.as_bytes(), 0o600)
    }
}

/// `sealctl scan [PATH...] [--home] [--dry-run] [--yes] [--json]`.
pub fn run(roots: Vec<PathBuf>, home: bool, dry_run: bool, yes: bool, json_out: bool) -> Result<()> {
    term::refuse_agent("sealctl scan")?;
    let findings = find(&roots, home)?;
    if json_out && (dry_run || findings.is_empty()) {
        println!("{}", json!({"findings": findings, "sealed": 0}));
        return Ok(());
    }
    if !json_out {
        for f in &findings {
            println!(
                "{}:{}  {:<15} {:<24} {}  → {}",
                paths::tilde(&f.file),
                f.line,
                f.kind,
                f.source,
                f.preview(),
                f.name.as_deref().unwrap_or("masked in place")
            );
        }
    }
    if findings.is_empty() {
        eprintln!("No keys found.");
        return Ok(());
    }
    if dry_run {
        return Ok(());
    }
    if !yes {
        if !term::is_person() {
            return Err(fail(
                exit::REFUSED,
                "Sealing needs a terminal to confirm. Use --yes.",
            ));
        }
        if !term::confirm(&format!("Seal {} keys?", findings.len()), false)? {
            return Ok(());
        }
    }
    let n = seal(&findings)?;
    if json_out {
        println!("{}", json!({"findings": findings, "sealed": n}));
    } else {
        eprintln!("Sealed {n} keys; references left behind. Programs get them with sealctl run.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rc_lines() {
        assert_eq!(
            rc_assignment("export A_TOKEN=\"x y\"").unwrap(),
            ("A_TOKEN".into(), "x y".into())
        );
        assert_eq!(
            rc_assignment("set -x API_KEY abc").unwrap(),
            ("API_KEY".into(), "abc".into())
        );
        assert!(rc_assignment("# export A=1").is_none());
        assert!(rc_assignment("alias x=y").is_none());
    }

    #[test]
    fn key_like_values() {
        let v = format!("{}{}", "zq9", "Xb81Lm2Pq7Rt4Vw6Yz3");
        assert!(key_like("MY_API_KEY", &v));
        assert!(!key_like("PATH", "/usr/bin:/bin"));
        assert!(!key_like("EDITOR_TOKEN", "vim"));
        assert!(!key_like("HOME_SECRET", "$HOME/x"));
    }

    #[test]
    fn ini() {
        let s =
            ini_sections("[default]\naws_access_key_id = A\naws_secret_access_key = B\n[other]\nregion=x\n");
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].1["aws_secret_access_key"], "B");
        assert_eq!(s[1].2, 4);
    }
}
