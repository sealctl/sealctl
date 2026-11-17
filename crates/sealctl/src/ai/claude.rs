//! Claude Code: skill in `~/.claude/skills/`, hooks and deny rules in `~/.claude/settings.json`.
//! Hook contract: https://code.claude.com/docs/en/hooks

use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::{json, Value};

use super::nested;

pub fn home() -> Result<PathBuf> {
    match std::env::var_os("CLAUDE_CONFIG_DIR") {
        Some(d) if !d.is_empty() => Ok(PathBuf::from(d)),
        _ => Ok(PathBuf::from(std::env::var_os("HOME").context("$HOME")?).join(".claude")),
    }
}

/// Handle one hook call: `input` is the JSON Claude Code sends on stdin; returns what to print.
pub fn hook(input: &Value) -> Option<Value> {
    super::adapters::claude_style(input, super::adapters::Flavor::Claude)
}

/// Deny rules: a second line of defence when a hook can't run (hooks fail open).
pub const DENY: &[&str] = &[
    "Bash(sealctl secret get *)",
    "Bash(sealctl ssh passphrase *)",
    "Bash(sealctl recover *)",
];

const MARKER: &str = " hook claude";

/// Remove our entries from a settings object (idempotent install / uninstall).
pub fn strip(settings: &mut Value) {
    nested::strip(settings, MARKER);
    nested::strip_list(settings, &["permissions", "deny"], DENY);
}

/// Add our hooks and deny rules.
pub fn merge(settings: &mut Value, exe: &str) {
    strip(settings);
    let cmd = nested::command(exe, "claude");
    nested::add(
        settings,
        &[
            ("UserPromptSubmit", None),
            (
                "PreToolUse",
                Some("Bash|Write|Edit|MultiEdit|Read|Grep|NotebookEdit"),
            ),
            ("SessionStart", Some("startup|resume|clear|compact")),
        ],
        json!({ "type": "command", "command": cmd, "timeout": 15 }),
    );
    nested::add_list(settings, &["permissions", "deny"], DENY);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hook_outputs() {
        let blocked = hook(&json!({
            "hook_event_name": "UserPromptSubmit",
            "prompt": "key: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123"
        }))
        .unwrap();
        assert_eq!(blocked["decision"], "block");
        assert!(
            !blocked.to_string().contains("abcdefghijklmnopqrstuvwxyz0123"),
            "reason must not repeat the key"
        );
        assert!(hook(&json!({"hook_event_name": "UserPromptSubmit", "prompt": "hello"})).is_none());

        let denied = hook(&json!({
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": "sealctl secret get myapp/openai"}
        }))
        .unwrap();
        assert_eq!(denied["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(hook(&json!({
            "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": "sealctl run -- npm test"}
        }))
        .is_none());
        assert!(hook(&json!({
            "hook_event_name": "PreToolUse", "tool_name": "Read",
            "tool_input": {"file_path": "/p/.env"}
        }))
        .is_some());
    }

    #[test]
    fn merge_is_idempotent_and_keeps_other_settings() {
        let mut s = json!({
            "model": "opus",
            "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "other-tool" } ] } ] },
            "permissions": { "deny": ["Bash(rm -rf *)"] }
        });
        merge(&mut s, "/opt/homebrew/bin/sealctl");
        merge(&mut s, "/opt/homebrew/bin/sealctl");
        assert_eq!(s["model"], "opus");
        assert_eq!(s["hooks"]["PreToolUse"].as_array().unwrap().len(), 2, "{s:#}");
        assert_eq!(s["hooks"]["UserPromptSubmit"].as_array().unwrap().len(), 1);
        assert_eq!(s["permissions"]["deny"].as_array().unwrap().len(), 1 + DENY.len());
        strip(&mut s);
        assert_eq!(
            s,
            json!({
                "model": "opus",
                "hooks": { "PreToolUse": [ { "matcher": "Bash", "hooks": [ { "type": "command", "command": "other-tool" } ] } ] },
                "permissions": { "deny": ["Bash(rm -rf *)"] }
            })
        );
    }
}
