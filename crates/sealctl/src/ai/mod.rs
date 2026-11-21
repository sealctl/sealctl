//! Integration with AI coding agents: a skill (how to use sealctl), hooks (checks that run
//! every time) and permission rules, installed per tool by `sealctl ai install`.

pub mod adapters;
pub mod claude;
pub mod nested;
pub mod policy;
pub mod tools;

/// The Agent Skill (open SKILL.md format), shared by all tools.
pub const SKILL_MD: &str = include_str!("SKILL.md");
pub const SKILL_NAME: &str = "sealctl-secrets";

use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde_json::Value;

/// Write `SKILL.md` into `<skills_dir>/sealctl-secrets/`.
pub fn write_skill(skills_dir: &Path) -> Result<PathBuf> {
    let dir = skills_dir.join(SKILL_NAME);
    std::fs::create_dir_all(&dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = dir.join("SKILL.md");
    std::fs::write(&path, SKILL_MD)?;
    Ok(path)
}

pub fn remove_skill(skills_dir: &Path) -> bool {
    std::fs::remove_dir_all(skills_dir.join(SKILL_NAME)).is_ok()
}

pub fn skill_installed(skills_dir: &Path) -> bool {
    skills_dir.join(SKILL_NAME).join("SKILL.md").is_file()
}

/// Read a JSON settings file (missing → `{}`), refusing to touch one we can't parse.
pub fn read_json(path: &Path) -> Result<Value> {
    match std::fs::read_to_string(path) {
        Ok(t) if t.trim().is_empty() => Ok(serde_json::json!({})),
        Ok(t) => serde_json::from_str(&t)
            .with_context(|| format!("{} is not valid JSON — not changing it", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(serde_json::json!({})),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// Write JSON (install), keeping a one-time backup of the original (`<file>.before-sealctl`).
pub fn write_json(path: &Path, v: &Value) -> Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let backup = backup_path(&real);
    if real.exists() && !backup.exists() {
        std::fs::copy(&real, &backup)?;
    }
    write_raw(path, v)
}

fn backup_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.before-sealctl",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("settings")
    ))
}

/// Atomic write that follows symlinks (dotfiles setups keep the link and update the real file)
/// and keeps the file's permissions (new files: 0600 — settings may hold tokens).
pub(crate) fn write_raw(path: &Path, v: &Value) -> Result<()> {
    let real = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let mode = std::fs::metadata(&real).ok().map(|m| {
        use std::os::unix::fs::PermissionsExt;
        m.permissions().mode() & 0o7777
    });
    let tmp = real.with_file_name(format!(
        ".{}.sealctl-tmp",
        real.file_name().and_then(|n| n.to_str()).unwrap_or("settings")
    ));
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(mode.unwrap_or(0o600))
            .open(&tmp)
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.write_all(format!("{}\n", serde_json::to_string_pretty(v)?).as_bytes())?;
        f.sync_all()?;
    }
    if let Some(m) = mode {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(m))?;
    }
    std::fs::rename(&tmp, &real)?;
    Ok(())
}

/// Write JSON after removing our entries (uninstall). If nothing else is left in a file that
/// didn't exist before sealctl (no backup), the file is deleted; the backup is removed too.
pub fn write_json_after_strip(path: &Path, v: &Value) -> Result<()> {
    let backup = backup_path(&std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf()));
    fn hollow(v: &Value) -> bool {
        match v {
            Value::Object(o) => o.values().all(hollow),
            Value::Array(a) => a.is_empty(),
            _ => false,
        }
    }
    let empty = v
        .as_object()
        .is_none_or(|o| o.iter().all(|(k, val)| k == "version" || hollow(val)));
    if empty && !backup.exists() && !path.is_symlink() {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    write_raw(path, v)?;
    let _ = std::fs::remove_file(&backup);
    Ok(())
}

/// `sealctl hook <tool>`: read the hook JSON from stdin, print the tool's answer.
/// Never fails loudly: a broken hook must not break the user's tool (the deny rules and
/// sealctl's own refusals still apply).
pub fn run_hook(tool: &str) -> Result<()> {
    use std::io::Read;
    let mut input = String::new();
    std::io::stdin().read_to_string(&mut input)?;
    let v: Value = serde_json::from_str(&input).unwrap_or(Value::Null);
    if let Some(out) = adapters::handle(tool, &v) {
        println!("{out}");
    }
    Ok(())
}

/// What `ai install` set up for one tool.
pub struct Report {
    pub tool: &'static str,
    pub detected: bool,
    pub lines: Vec<String>,
}

fn exe_string() -> Result<String> {
    Ok(crate::util::stable_exe()?.to_string_lossy().into_owned())
}

fn on_path(bin: &str) -> bool {
    crate::util::which(bin)
}

// ---- Claude Code ----

fn claude_detected() -> bool {
    on_path("claude") || claude::home().is_ok_and(|h| h.exists())
}

fn claude_install() -> Result<Vec<String>> {
    let home = claude::home()?;
    let skill = write_skill(&home.join("skills"))?;
    let settings = home.join("settings.json");
    let mut v = read_json(&settings)?;
    claude::merge(&mut v, &exe_string()?);
    write_json(&settings, &v)?;
    Ok(vec![
        format!("skill     {}", skill.display()),
        format!(
            "hooks     {} (prompt check, Bash/Write/Edit/Read check, session context)",
            settings.display()
        ),
        format!("deny      {}", claude::DENY.join(", ")),
    ])
}

fn claude_uninstall() -> Result<Vec<String>> {
    let home = claude::home()?;
    let mut lines = vec![];
    if remove_skill(&home.join("skills")) {
        lines.push("skill removed".into());
    }
    let settings = home.join("settings.json");
    if settings.exists() {
        let mut v = read_json(&settings)?;
        claude::strip(&mut v);
        write_json_after_strip(&settings, &v)?;
        lines.push(format!(
            "hooks and deny rules removed from {}",
            settings.display()
        ));
    }
    Ok(lines)
}

fn claude_status() -> Result<Vec<String>> {
    let home = claude::home()?;
    let settings = read_json(&home.join("settings.json")).unwrap_or(Value::Null);
    let hooked = settings.to_string().contains(" hook claude");
    Ok(vec![
        format!(
            "skill {}",
            if skill_installed(&home.join("skills")) {
                "✅"
            } else {
                "—"
            }
        ),
        format!("hooks {}", if hooked { "✅" } else { "—" }),
    ])
}

fn claude_installed() -> bool {
    let Ok(home) = claude::home() else {
        return false;
    };
    let settings = read_json(&home.join("settings.json")).unwrap_or(Value::Null);
    let text = settings.to_string();
    skill_installed(&home.join("skills"))
        || text.contains(" hook claude")
        || claude::DENY.iter().any(|d| {
            settings["permissions"]["deny"]
                .as_array()
                .is_some_and(|a| a.iter().any(|x| x.as_str() == Some(*d)))
        })
}

fn claude_files() -> Vec<PathBuf> {
    claude::home()
        .map(|h| {
            vec![
                h.join("settings.json"),
                h.join("skills").join(SKILL_NAME).join("SKILL.md"),
            ]
        })
        .unwrap_or_default()
}

fn skill_files(dir: fn() -> Result<PathBuf>) -> Vec<PathBuf> {
    dir()
        .map(|d| vec![d.join(SKILL_NAME).join("SKILL.md")])
        .unwrap_or_default()
}

type Action = fn() -> Result<Vec<String>>;

struct Tool {
    name: &'static str,
    id: &'static str,
    detected: fn() -> bool,
    install: Action,
    uninstall: Action,
    status: Action,
    /// Something of ours is in place (skill, hooks, rules).
    installed: fn() -> bool,
    /// Files `uninstall` edits or removes.
    files: fn() -> Vec<PathBuf>,
}

fn skill_only_install(dir: fn() -> Result<PathBuf>) -> Result<Vec<String>> {
    Ok(vec![format!("skill     {}", write_skill(&dir()?)?.display())])
}

fn skill_only_uninstall(dir: fn() -> Result<PathBuf>) -> Result<Vec<String>> {
    Ok(if remove_skill(&dir()?) {
        vec!["skill removed".into()]
    } else {
        vec![]
    })
}

fn skill_only_status(dir: fn() -> Result<PathBuf>) -> Result<Vec<String>> {
    Ok(vec![format!(
        "skill {}",
        if skill_installed(&dir()?) { "✅" } else { "—" }
    )])
}

fn tools() -> Vec<Tool> {
    use tools as t;
    vec![
        Tool {
            name: "Claude Code",
            id: "claude",
            detected: claude_detected,
            install: claude_install,
            uninstall: claude_uninstall,
            status: claude_status,
            installed: claude_installed,
            files: claude_files,
        },
        Tool {
            name: "Shared skills folder ~/.agents/skills",
            id: "agents",
            detected: t::agents_detected,
            install: t::agents_install,
            uninstall: t::agents_uninstall,
            status: t::agents_status,
            installed: || t::agents_skills().is_ok_and(|d| skill_installed(&d)),
            files: || skill_files(t::agents_skills),
        },
        Tool {
            name: "Codex",
            id: "codex",
            detected: t::codex_detected,
            install: t::codex_install,
            uninstall: t::codex_uninstall,
            status: t::codex_status,
            installed: t::codex_installed,
            files: t::codex_files,
        },
        Tool {
            name: "Gemini CLI",
            id: "gemini",
            detected: t::gemini_detected,
            install: t::gemini_install,
            uninstall: t::gemini_uninstall,
            status: t::gemini_status,
            installed: t::gemini_installed,
            files: t::gemini_files,
        },
        Tool {
            name: "Qwen Code",
            id: "qwen",
            detected: t::qwen_detected,
            install: t::qwen_install,
            uninstall: t::qwen_uninstall,
            status: t::qwen_status,
            installed: t::qwen_installed,
            files: || t::qwen_settings().map(|p| vec![p]).unwrap_or_default(),
        },
        Tool {
            name: "GitHub Copilot CLI",
            id: "copilot",
            detected: t::copilot_detected,
            install: t::copilot_install,
            uninstall: t::copilot_uninstall,
            status: t::copilot_status,
            installed: t::copilot_installed,
            files: t::copilot_files,
        },
        Tool {
            name: "Cursor",
            id: "cursor",
            detected: t::cursor_detected,
            install: t::cursor_install,
            uninstall: t::cursor_uninstall,
            status: t::cursor_status,
            installed: t::cursor_installed,
            files: t::cursor_files,
        },
        Tool {
            name: "Antigravity CLI",
            id: "antigravity",
            detected: || crate::util::which("agy"),
            install: || skill_only_install(t::antigravity_skills),
            uninstall: || skill_only_uninstall(t::antigravity_skills),
            status: || skill_only_status(t::antigravity_skills),
            installed: || t::antigravity_skills().is_ok_and(|d| skill_installed(&d)),
            files: || skill_files(t::antigravity_skills),
        },
        Tool {
            name: "Kiro",
            id: "kiro",
            detected: || {
                crate::util::which("kiro-cli")
                    || t::kiro_skills().is_ok_and(|p| p.parent().is_some_and(|d| d.exists()))
            },
            install: || skill_only_install(t::kiro_skills),
            uninstall: || skill_only_uninstall(t::kiro_skills),
            status: || skill_only_status(t::kiro_skills),
            installed: || t::kiro_skills().is_ok_and(|d| skill_installed(&d)),
            files: || skill_files(t::kiro_skills),
        },
    ]
}

/// Tools with something of sealctl's installed: `(id, name)`.
pub fn installed() -> Vec<(&'static str, &'static str)> {
    tools()
        .into_iter()
        .filter(|t| (t.installed)())
        .map(|t| (t.id, t.name))
        .collect()
}

/// The files `uninstall` edits or removes for these tools (existing ones only).
pub fn files_of(ids: &[String]) -> Vec<PathBuf> {
    tools()
        .into_iter()
        .filter(|t| ids.iter().any(|i| i == t.id))
        .flat_map(|t| (t.files)())
        .filter(|p| p.exists())
        .collect()
}

/// Deny rules that keep `.env` and credential files away from an agent, without sealctl.
pub const ENV_DENY: &[&str] = &[
    "Read(**/.env)",
    "Read(**/.env.*)",
    "Read(~/.aws/credentials)",
    "Read(~/.netrc)",
    "Read(~/.git-credentials)",
    "Read(~/.npmrc)",
];

/// The file `write_env_rules` edits for a tool, or `None` when the tool has no such setting.
pub fn env_rules_file(id: &str) -> Option<PathBuf> {
    match id {
        "claude" => claude::home().ok().map(|h| h.join("settings.json")),
        "qwen" => tools::qwen_settings().ok(),
        "gemini" => tools::gemini_env_policy().ok(),
        _ => None,
    }
}

/// Add the `.env` deny rules for one tool (`extra`: more files to deny, e.g. the `--env-file`
/// of `sealctl unseal`). Returns the file written, or `None` when the tool has no such setting.
pub fn write_env_rules(id: &str, extra: &[String]) -> Result<Option<PathBuf>> {
    let rules: Vec<String> = ENV_DENY
        .iter()
        .map(|s| s.to_string())
        .chain(extra.iter().map(|e| format!("Read({e})")))
        .collect();
    let refs: Vec<&str> = rules.iter().map(String::as_str).collect();
    match id {
        "claude" | "qwen" => {
            let path = env_rules_file(id).context("settings path")?;
            let mut v = read_json(&path)?;
            nested::strip_list(&mut v, &["permissions", "deny"], &refs);
            nested::add_list(&mut v, &["permissions", "deny"], &refs);
            if let Some(dir) = path.parent() {
                std::fs::create_dir_all(dir)?;
            }
            write_raw(&path, &v)?;
            Ok(Some(path))
        }
        "gemini" => Ok(Some(tools::write_gemini_env_policy(extra)?)),
        _ => Ok(None),
    }
}

/// Does an edited settings file still parse (JSON; TOML for `.toml`)?
pub fn still_parses(path: &Path) -> Result<()> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    };
    if path.extension().is_some_and(|e| e == "toml") {
        toml::from_str::<toml::Value>(&text)
            .with_context(|| format!("{} no longer parses", path.display()))?;
    } else if path.extension().is_some_and(|e| e == "json") && !text.trim().is_empty() {
        serde_json::from_str::<Value>(&text)
            .with_context(|| format!("{} no longer parses", path.display()))?;
    }
    Ok(())
}

/// `(id, name)` of every tool sealctl knows.
pub fn tool_names() -> Vec<(&'static str, &'static str)> {
    tools().iter().map(|t| (t.id, t.name)).collect()
}

pub fn tool_ids() -> Vec<&'static str> {
    tools().iter().map(|t| t.id).collect()
}

fn selected(only: &[String]) -> Result<Vec<Tool>> {
    let all = tools();
    for o in only {
        if !all.iter().any(|t| t.id == o) {
            bail!("unknown tool {o:?} — known: {}", tool_ids().join(", "));
        }
    }
    Ok(all
        .into_iter()
        .filter(|t| only.is_empty() || only.iter().any(|o| o == t.id))
        .collect())
}

fn apply(only: &[String], pick: fn(&Tool) -> Action, require_detected: bool) -> Result<Vec<Report>> {
    let mut out = vec![];
    for t in selected(only)? {
        let detected = (t.detected)();
        let lines = if detected || !only.is_empty() || !require_detected {
            match (pick(&t))() {
                Ok(l) => l,
                Err(e) => vec![format!("❌ {e:#}")],
            }
        } else {
            vec!["not found — skipped".into()]
        };
        out.push(Report {
            tool: t.name,
            detected,
            lines,
        });
    }
    Ok(out)
}

/// Install for every detected tool (or only the named ones).
pub fn install(only: &[String]) -> Result<Vec<Report>> {
    apply(only, |t| t.install, true)
}

pub fn uninstall(only: &[String]) -> Result<Vec<Report>> {
    apply(only, |t| t.uninstall, false)
}

pub fn status(only: &[String]) -> Result<Vec<Report>> {
    apply(only, |t| t.status, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_writes_keep_symlinks_and_permissions() {
        use std::os::unix::fs::PermissionsExt;
        let t = tempfile::tempdir().unwrap();
        let real = t.path().join("dotfiles-settings.json");
        std::fs::write(&real, r#"{"env":{"TOKEN":"x"}}"#).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o600)).unwrap();
        let link = t.path().join("settings.json");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let mut v = read_json(&link).unwrap();
        v["added"] = serde_json::json!(true);
        write_json(&link, &v).unwrap();

        assert!(link.is_symlink(), "symlink kept");
        assert!(
            std::fs::read_to_string(&real).unwrap().contains("added"),
            "real file updated"
        );
        let mode = std::fs::metadata(&real).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "permissions kept");
        let fresh = t.path().join("new.json");
        write_json(&fresh, &serde_json::json!({})).unwrap();
        assert_eq!(
            std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}
