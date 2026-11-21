//! Where each AI tool keeps skills, hooks and rules (user level), and how to install ours.
//! Paths and formats from each tool's official documentation (see docs/ai-agents.md).

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use super::{
    nested, read_json, remove_skill, skill_installed, write_json, write_json_after_strip, write_skill,
};

fn home() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME").context("$HOME is not set")?,
    ))
}

fn env_dir(var: &str, default: &str) -> Result<PathBuf> {
    match std::env::var_os(var) {
        Some(d) if !d.is_empty() => Ok(PathBuf::from(d)),
        _ => Ok(home()?.join(default)),
    }
}

fn exe() -> Result<String> {
    Ok(crate::util::stable_exe()?.to_string_lossy().into_owned())
}

fn has(bin: &str) -> bool {
    crate::util::which(bin)
}

fn exists(p: Result<PathBuf>) -> bool {
    p.is_ok_and(|p| p.exists())
}

fn yes(b: bool) -> &'static str {
    if b {
        "✅"
    } else {
        "—"
    }
}

fn contains(path: &std::path::Path, marker: &str) -> bool {
    std::fs::read_to_string(path).is_ok_and(|t| t.contains(marker))
}

const WHY: &str = "secret values must not enter the conversation; use `sealctl run -- <command>`";

// ---- shared skills folder: ~/.agents/skills (Codex, Gemini CLI, Copilot, Cursor, Qwen Code,
// OpenCode, Amp, Goose) ----

pub fn agents_skills() -> Result<PathBuf> {
    Ok(home()?.join(".agents").join("skills"))
}

pub fn agents_detected() -> bool {
    [
        "codex",
        "gemini",
        "copilot",
        "cursor-agent",
        "qwen",
        "opencode",
        "amp",
        "goose",
    ]
    .iter()
    .any(|b| has(b))
        || exists(agents_skills())
}

pub fn agents_install() -> Result<Vec<String>> {
    Ok(vec![format!(
        "skill     {}",
        write_skill(&agents_skills()?)?.display()
    )])
}

pub fn agents_uninstall() -> Result<Vec<String>> {
    Ok(if remove_skill(&agents_skills()?) {
        vec!["skill removed".into()]
    } else {
        vec![]
    })
}

pub fn agents_status() -> Result<Vec<String>> {
    Ok(vec![format!(
        "skill {}  (read by Codex, Gemini CLI, Copilot, Cursor, Qwen Code, OpenCode, Amp, Goose)",
        yes(skill_installed(&agents_skills()?))
    )])
}

// ---- Codex: ~/.codex/hooks.json + ~/.codex/rules/sealctl.rules ----

fn codex_home() -> Result<PathBuf> {
    env_dir("CODEX_HOME", ".codex")
}

pub fn codex_detected() -> bool {
    has("codex") || exists(codex_home())
}

const CODEX_RULES: &str = "# Added by sealctl — `sealctl ai uninstall codex` removes this file.\n";

pub fn codex_install() -> Result<Vec<String>> {
    let dir = codex_home()?;
    let hooks = dir.join("hooks.json");
    let mut v = read_json(&hooks)?;
    nested::strip(&mut v, " hook codex");
    nested::add(
        &mut v,
        &[
            ("UserPromptSubmit", None),
            ("PreToolUse", Some("Bash|apply_patch|Edit|Write")),
            ("SessionStart", None),
        ],
        json!({ "type": "command", "command": nested::command(&exe()?, "codex"), "timeout": 15 }),
    );
    write_json(&hooks, &v)?;
    let rules = dir.join("rules").join("sealctl.rules");
    std::fs::create_dir_all(rules.parent().context("rules dir")?)?;
    let mut text = CODEX_RULES.to_string();
    for p in [
        r#"["sealctl", "secret", "get"]"#,
        r#"["sealctl", "ssh", "passphrase"]"#,
        r#"["sealctl", "recover"]"#,
        r#"["sealctl", "unseal"]"#,
    ] {
        text.push_str(&format!(
            "prefix_rule(pattern={p}, decision=\"forbidden\", justification=\"sealctl: {WHY}\")\n"
        ));
    }
    std::fs::write(&rules, text)?;
    Ok(vec![
        format!(
            "hooks     {} — run /hooks in Codex once to trust them",
            hooks.display()
        ),
        format!("rules     {}", rules.display()),
    ])
}

pub fn codex_uninstall() -> Result<Vec<String>> {
    let dir = codex_home()?;
    let hooks = dir.join("hooks.json");
    let mut out = vec![];
    if hooks.exists() {
        let mut v = read_json(&hooks)?;
        nested::strip(&mut v, " hook codex");
        write_json_after_strip(&hooks, &v)?;
        out.push(format!("hooks removed from {}", hooks.display()));
    }
    if std::fs::remove_file(dir.join("rules").join("sealctl.rules")).is_ok() {
        out.push("rules removed".into());
    }
    Ok(out)
}

pub fn codex_status() -> Result<Vec<String>> {
    let dir = codex_home()?;
    Ok(vec![
        format!("hooks {}", yes(contains(&dir.join("hooks.json"), " hook codex"))),
        format!("rules {}", yes(dir.join("rules").join("sealctl.rules").exists())),
    ])
}

// ---- Gemini CLI: ~/.gemini/settings.json hooks + ~/.gemini/policies/sealctl.toml ----

fn gemini_home() -> Result<PathBuf> {
    match std::env::var_os("GEMINI_CLI_HOME") {
        Some(d) if !d.is_empty() => Ok(PathBuf::from(d).join(".gemini")),
        _ => Ok(home()?.join(".gemini")),
    }
}

pub fn gemini_detected() -> bool {
    has("gemini") || exists(gemini_home().map(|h| h.join("settings.json")))
}

pub fn gemini_install() -> Result<Vec<String>> {
    let dir = gemini_home()?;
    let settings = dir.join("settings.json");
    let mut v = read_json(&settings)?;
    nested::strip(&mut v, " hook gemini");
    nested::add(
        &mut v,
        &[
            ("BeforeAgent", None),
            (
                "BeforeTool",
                Some("run_shell_command|write_file|replace|read_file"),
            ),
            ("SessionStart", None),
        ],
        json!({
            "name": "sealctl",
            "type": "command",
            "command": nested::command(&exe()?, "gemini"),
            "timeout": 15000
        }),
    );
    write_json(&settings, &v)?;
    let policy = dir.join("policies").join("sealctl.toml");
    std::fs::create_dir_all(policy.parent().context("policies dir")?)?;
    std::fs::write(
        &policy,
        format!(
            "# Added by sealctl — `sealctl ai uninstall gemini` removes this file.\n\
             [[rule]]\n\
             toolName = \"run_shell_command\"\n\
             commandRegex = \"sealctl\\\\b.*\\\\b(secret\\\\s+get|ssh\\\\s+passphrase|recover|unseal)\\\\b\"\n\
             decision = \"deny\"\n\
             priority = 900\n\
             denyMessage = \"sealctl: {WHY}\"\n"
        ),
    )?;
    Ok(vec![
        format!("hooks     {}", settings.display()),
        format!("policy    {}", policy.display()),
    ])
}

pub fn gemini_uninstall() -> Result<Vec<String>> {
    let dir = gemini_home()?;
    let settings = dir.join("settings.json");
    let mut out = vec![];
    if settings.exists() {
        let mut v = read_json(&settings)?;
        nested::strip(&mut v, " hook gemini");
        write_json_after_strip(&settings, &v)?;
        out.push(format!("hooks removed from {}", settings.display()));
    }
    if std::fs::remove_file(dir.join("policies").join("sealctl.toml")).is_ok() {
        out.push("policy removed".into());
    }
    Ok(out)
}

pub fn gemini_status() -> Result<Vec<String>> {
    let dir = gemini_home()?;
    Ok(vec![
        format!(
            "hooks  {}",
            yes(contains(&dir.join("settings.json"), " hook gemini"))
        ),
        format!(
            "policy {}",
            yes(dir.join("policies").join("sealctl.toml").exists())
        ),
    ])
}

// ---- Qwen Code: ~/.qwen/settings.json (Claude-compatible hooks and deny rules) ----

fn qwen_home() -> Result<PathBuf> {
    env_dir("QWEN_HOME", ".qwen")
}

pub fn qwen_detected() -> bool {
    has("qwen") || exists(qwen_home())
}

pub fn qwen_install() -> Result<Vec<String>> {
    let settings = qwen_home()?.join("settings.json");
    let mut v = read_json(&settings)?;
    nested::strip(&mut v, " hook qwen");
    nested::strip_list(&mut v, &["permissions", "deny"], super::claude::DENY);
    nested::add(
        &mut v,
        &[
            ("UserPromptSubmit", None),
            ("PreToolUse", Some("Bash|Write|Edit|Read")),
            ("SessionStart", None),
        ],
        json!({ "type": "command", "command": nested::command(&exe()?, "qwen"), "timeout": 15 }),
    );
    nested::add_list(&mut v, &["permissions", "deny"], super::claude::DENY);
    write_json(&settings, &v)?;
    Ok(vec![format!("hooks + deny rules {}", settings.display())])
}

pub fn qwen_uninstall() -> Result<Vec<String>> {
    let settings = qwen_home()?.join("settings.json");
    if !settings.exists() {
        return Ok(vec![]);
    }
    let mut v = read_json(&settings)?;
    nested::strip(&mut v, " hook qwen");
    nested::strip_list(&mut v, &["permissions", "deny"], super::claude::DENY);
    write_json_after_strip(&settings, &v)?;
    Ok(vec![format!(
        "hooks and deny rules removed from {}",
        settings.display()
    )])
}

pub fn qwen_status() -> Result<Vec<String>> {
    Ok(vec![format!(
        "hooks {}",
        yes(contains(&qwen_home()?.join("settings.json"), " hook qwen"))
    )])
}

// ---- Copilot CLI: our own ~/.copilot/hooks/sealctl.json ----

fn copilot_home() -> Result<PathBuf> {
    env_dir("COPILOT_HOME", ".copilot")
}

pub fn copilot_detected() -> bool {
    has("copilot") || exists(copilot_home())
}

fn copilot_file() -> Result<PathBuf> {
    Ok(copilot_home()?.join("hooks").join("sealctl.json"))
}

pub fn copilot_install() -> Result<Vec<String>> {
    let path = copilot_file()?;
    let cmd = nested::command(&exe()?, "copilot");
    let entry = |matcher: Option<&str>| {
        let mut e = json!({ "type": "command", "bash": cmd, "timeoutSec": 15 });
        if let Some(m) = matcher {
            e["matcher"] = json!(m);
        }
        e
    };
    // PascalCase event names select Copilot's Claude-compatible payloads
    let v = json!({
        "version": 1,
        "hooks": {
            "UserPromptSubmit": [entry(None)],
            "PreToolUse": [entry(Some("Bash|Write|Edit|Read|bash|create|edit|view"))],
            "SessionStart": [entry(None)]
        }
    });
    write_json(&path, &v)?;
    Ok(vec![format!(
        "hooks     {} (prompt blocking depends on your Copilot CLI version)",
        path.display()
    )])
}

pub fn copilot_uninstall() -> Result<Vec<String>> {
    let path = copilot_file()?;
    Ok(if std::fs::remove_file(&path).is_ok() {
        vec![format!("removed {}", path.display())]
    } else {
        vec![]
    })
}

pub fn copilot_status() -> Result<Vec<String>> {
    Ok(vec![format!("hooks {}", yes(copilot_file()?.exists()))])
}

// ---- Cursor: ~/.cursor/hooks.json (flat lists per event) ----

fn cursor_hooks() -> Result<PathBuf> {
    Ok(home()?.join(".cursor").join("hooks.json"))
}

pub fn cursor_detected() -> bool {
    has("cursor-agent") || exists(home().map(|h| h.join(".cursor")))
}

const CURSOR_EVENTS: &[&str] = &[
    "beforeSubmitPrompt",
    "beforeShellExecution",
    "beforeReadFile",
    "sessionStart",
];

fn cursor_strip(v: &mut Value) {
    if let Some(hooks) = v.get_mut("hooks").and_then(Value::as_object_mut) {
        for list in hooks.values_mut() {
            if let Some(a) = list.as_array_mut() {
                a.retain(|e| {
                    !e["command"]
                        .as_str()
                        .is_some_and(|c| c.contains("sealctl") && c.contains(" hook cursor"))
                });
            }
        }
        hooks.retain(|_, l| l.as_array().is_none_or(|a| !a.is_empty()));
    }
}

pub fn cursor_install() -> Result<Vec<String>> {
    let path = cursor_hooks()?;
    let mut v = read_json(&path)?;
    cursor_strip(&mut v);
    if !v.is_object() {
        v = json!({});
    }
    let o = v.as_object_mut().expect("object");
    o.entry("version").or_insert(json!(1));
    let hooks = o.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    let cmd = nested::command(&exe()?, "cursor");
    for ev in CURSOR_EVENTS {
        let list = hooks
            .as_object_mut()
            .expect("hooks object")
            .entry(*ev)
            .or_insert_with(|| json!([]));
        if !list.is_array() {
            *list = json!([]);
        }
        list.as_array_mut()
            .expect("array")
            .push(json!({ "command": cmd }));
    }
    write_json(&path, &v)?;
    Ok(vec![format!(
        "hooks     {} (the Cursor CLI may not fire every hook yet)",
        path.display()
    )])
}

pub fn cursor_uninstall() -> Result<Vec<String>> {
    let path = cursor_hooks()?;
    if !path.exists() {
        return Ok(vec![]);
    }
    let mut v = read_json(&path)?;
    cursor_strip(&mut v);
    write_json_after_strip(&path, &v)?;
    Ok(vec![format!("hooks removed from {}", path.display())])
}

pub fn cursor_status() -> Result<Vec<String>> {
    Ok(vec![format!(
        "hooks {}",
        yes(contains(&cursor_hooks()?, " hook cursor"))
    )])
}

// ---- what `sealctl unseal` needs: installed?, files touched, .env rules ----

pub fn codex_installed() -> bool {
    codex_home().is_ok_and(|d| {
        contains(&d.join("hooks.json"), " hook codex") || d.join("rules").join("sealctl.rules").exists()
    })
}

pub fn codex_files() -> Vec<PathBuf> {
    codex_home()
        .map(|d| vec![d.join("hooks.json"), d.join("rules").join("sealctl.rules")])
        .unwrap_or_default()
}

pub fn gemini_installed() -> bool {
    gemini_home().is_ok_and(|d| {
        contains(&d.join("settings.json"), " hook gemini") || d.join("policies").join("sealctl.toml").exists()
    })
}

pub fn gemini_files() -> Vec<PathBuf> {
    gemini_home()
        .map(|d| vec![d.join("settings.json"), d.join("policies").join("sealctl.toml")])
        .unwrap_or_default()
}

pub fn qwen_settings() -> Result<PathBuf> {
    Ok(qwen_home()?.join("settings.json"))
}

pub fn qwen_installed() -> bool {
    qwen_settings().is_ok_and(|p| contains(&p, " hook qwen"))
}

pub fn copilot_installed() -> bool {
    copilot_file().is_ok_and(|p| p.exists())
}

pub fn copilot_files() -> Vec<PathBuf> {
    copilot_file().map(|p| vec![p]).unwrap_or_default()
}

pub fn cursor_installed() -> bool {
    cursor_hooks().is_ok_and(|p| contains(&p, " hook cursor"))
}

pub fn cursor_files() -> Vec<PathBuf> {
    cursor_hooks().map(|p| vec![p]).unwrap_or_default()
}

/// Gemini CLI: a policy file of its own that keeps `.env` and credential files out of reach.
/// Written by `sealctl unseal`; it does not need sealctl.
pub fn gemini_env_policy() -> Result<PathBuf> {
    Ok(gemini_home()?.join("policies").join("deny-env-files.toml"))
}

/// Write [`gemini_env_policy`]; `extra` are more file paths to deny (the `--env-file`).
pub fn write_gemini_env_policy(extra: &[String]) -> Result<PathBuf> {
    let path = gemini_env_policy()?;
    // argsPattern is a regular expression over the tool call's JSON arguments
    let mut alts: Vec<String> = vec![
        r#"\.env(\.[A-Za-z0-9_-]+)?""#.into(),
        r"\.aws/credentials".into(),
        r"\.netrc".into(),
        r"\.git-credentials".into(),
        r"\.npmrc".into(),
    ];
    alts.extend(extra.iter().map(|e| regex::escape(e)));
    write_gemini_policy(
        &path,
        "# Written by `sealctl unseal` when sealctl was removed: keeps Gemini CLI from reading\n\
         # .env files and credential files. It does not need sealctl; delete it if you don't want it.\n",
        &["read_file", "read_many_files"],
        &format!("({})", alts.join("|")),
        "This file holds credentials; it must not be read into the conversation.",
    )?;
    Ok(path)
}

/// Gemini CLI's policy that keeps it out of `~/sealctl-unsealed-*`.
pub fn gemini_unsealed_policy() -> Result<PathBuf> {
    Ok(gemini_home()?.join("policies").join("deny-sealctl-unsealed.toml"))
}

/// Write [`gemini_unsealed_policy`].
pub fn write_gemini_unsealed_policy() -> Result<PathBuf> {
    let path = gemini_unsealed_policy()?;
    write_gemini_policy(
        &path,
        "# Written by `sealctl unseal`: ~/sealctl-unsealed-* holds passwords, secrets and keys in\n\
         # plain text, which must not enter a conversation. Delete this file with that folder.\n",
        &[
            "read_file",
            "read_many_files",
            "glob",
            "search_file_content",
            "run_shell_command",
        ],
        "sealctl-unsealed-",
        "This folder holds passwords and keys in plain text; it must not be read into the conversation.",
    )?;
    Ok(path)
}

/// A policy file of deny rules: each tool's calls whose JSON arguments match `pattern`.
fn write_gemini_policy(
    path: &std::path::Path,
    header: &str,
    tools: &[&str],
    pattern: &str,
    message: &str,
) -> Result<()> {
    std::fs::create_dir_all(path.parent().context("policies dir")?)?;
    let toml_str = |s: &str| serde_json::to_string(s).expect("string");
    let mut text = String::from(header);
    for tool in tools {
        text.push_str(&format!(
            "\n[[rule]]\ntoolName = \"{tool}\"\nargsPattern = {}\ndecision = \"deny\"\npriority = 900\n\
             denyMessage = {}\n",
            toml_str(pattern),
            toml_str(message)
        ));
    }
    std::fs::write(path, text)?;
    Ok(())
}

// ---- skill-only tools with their own folders ----

pub fn antigravity_skills() -> Result<PathBuf> {
    Ok(home()?.join(".gemini").join("config").join("skills"))
}

pub fn kiro_skills() -> Result<PathBuf> {
    Ok(home()?.join(".kiro").join("skills"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursor_merge_keeps_others_and_is_idempotent() {
        let mut v = json!({"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}]}});
        cursor_strip(&mut v);
        assert_eq!(v["hooks"]["beforeShellExecution"].as_array().unwrap().len(), 1);
        let mut w = json!({"version": 1, "hooks": {"beforeShellExecution": [
            {"command": "./audit.sh"}, {"command": "'/opt/homebrew/bin/sealctl' hook cursor"}
        ]}});
        cursor_strip(&mut w);
        assert_eq!(
            w,
            json!({"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}]}})
        );
    }
}
