//! Hook input/output for each AI tool. All of them call the same rules in `policy.rs`.
//!
//! * Claude-style (Claude Code, Codex, Qwen Code, Copilot CLI with PascalCase events):
//!   `hook_event_name` = UserPromptSubmit / PreToolUse / SessionStart.
//! * Gemini CLI: BeforeAgent / BeforeTool / SessionStart.
//! * Cursor: beforeSubmitPrompt / beforeShellExecution / sessionStart.
//!
//! A hook must never fail: some tools block every action when a hook crashes (Copilot), so
//! unknown input yields no output (= no decision).

use serde_json::{json, Value};

use super::policy;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Claude,
    Codex,
    Qwen,
    Copilot,
}

fn first_str<'a>(v: &'a Value, keys: &[&str]) -> &'a str {
    keys.iter()
        .filter_map(|k| v[*k].as_str())
        .find(|s| !s.is_empty())
        .unwrap_or("")
}

/// A command given as a string, or as an argv array (Codex `["bash", "-lc", "…"]`).
fn command_of(v: &Value) -> String {
    for k in ["command", "cmd"] {
        match &v[k] {
            Value::String(s) if !s.is_empty() => return s.clone(),
            Value::Array(a) if !a.is_empty() => {
                return a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(" ")
            }
            _ => {}
        }
    }
    String::new()
}

/// All new text of an edit, including MultiEdit's `edits[].new_string`.
fn content_of(v: &Value) -> String {
    let mut parts: Vec<String> = [
        "content",
        "new_string",
        "newString",
        "file_text",
        "input",
        "patch",
    ]
    .iter()
    .filter_map(|k| v[*k].as_str().map(str::to_string))
    .collect();
    if let Some(s) = v["command"].as_str() {
        parts.push(s.to_string()); // Codex apply_patch
    }
    if let Some(edits) = v["edits"].as_array() {
        for e in edits {
            for k in ["new_string", "newString", "content"] {
                if let Some(s) = e[k].as_str() {
                    parts.push(s.to_string());
                }
            }
        }
    }
    parts.join("\n")
}

/// Classify a tool call and run the matching rule.
fn tool_verdict(tool: &str, input: &Value, cwd: Option<&str>) -> Option<String> {
    let t = tool.to_ascii_lowercase();
    let path = first_str(
        input,
        &["file_path", "path", "absolute_path", "filePath", "notebook_path"],
    );
    match t.as_str() {
        "bash" | "shell" | "exec_command" | "run_shell_command" | "powershell" | "run_command" => {
            policy::bash_in(&command_of(input), cwd)
        }
        "read" | "read_file" | "view" | "glob" | "notebookread" => policy::read(path),
        "grep" => policy::search(path, first_str(input, &["glob", "include"])),
        "write"
        | "edit"
        | "create"
        | "write_file"
        | "replace"
        | "multiedit"
        | "apply_patch"
        | "write_to_file"
        | "replace_file_content"
        | "multi_replace_file_content"
        | "notebookedit" => policy::write(if path.is_empty() { "a file" } else { path }, &content_of(input)),
        _ => None,
    }
}

/// Claude Code and tools that copied its hook contract.
pub fn claude_style(input: &Value, flavor: Flavor) -> Option<Value> {
    match input["hook_event_name"].as_str().unwrap_or("") {
        "UserPromptSubmit" => {
            let why = policy::prompt(first_str(input, &["prompt", "user_prompt"]))?;
            let mut out = json!({ "decision": "block", "reason": why });
            if flavor == Flavor::Claude {
                out["hookSpecificOutput"] = json!({
                    "hookEventName": "UserPromptSubmit",
                    "suppressOriginalPrompt": true
                });
            }
            Some(out)
        }
        "PreToolUse" => {
            let why = tool_verdict(
                input["tool_name"].as_str().unwrap_or(""),
                &input["tool_input"],
                input["cwd"].as_str(),
            )?;
            let mut out = json!({
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                    "permissionDecisionReason": why
                }
            });
            if flavor == Flavor::Copilot {
                // Copilot's own config-file contract reads these at the top level
                out["permissionDecision"] = json!("deny");
                out["permissionDecisionReason"] = json!(why);
            }
            Some(out)
        }
        "SessionStart" => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": policy::session_context()
            }
        })),
        _ => None,
    }
}

/// Gemini CLI (https://geminicli.com/docs/hooks/reference/).
pub fn gemini(input: &Value) -> Option<Value> {
    match input["hook_event_name"].as_str().unwrap_or("") {
        "BeforeAgent" => {
            let why = policy::prompt(first_str(input, &["prompt"]))?;
            Some(json!({ "decision": "deny", "reason": why }))
        }
        "BeforeTool" => {
            let why = tool_verdict(
                input["tool_name"].as_str().unwrap_or(""),
                &input["tool_input"],
                input["cwd"].as_str(),
            )?;
            Some(json!({ "decision": "deny", "reason": why }))
        }
        "SessionStart" => Some(json!({
            "hookSpecificOutput": {
                "hookEventName": "SessionStart",
                "additionalContext": policy::session_context()
            }
        })),
        _ => None,
    }
}

/// Cursor (https://cursor.com/docs/agent/hooks).
pub fn cursor(input: &Value) -> Option<Value> {
    match input["hook_event_name"].as_str().unwrap_or("") {
        "beforeSubmitPrompt" => {
            let why = policy::prompt(first_str(input, &["prompt"]))?;
            Some(json!({ "continue": false, "user_message": why }))
        }
        "beforeShellExecution" => {
            let why = policy::bash_in(first_str(input, &["command"]), input["cwd"].as_str())?;
            Some(json!({ "permission": "deny", "user_message": why, "agent_message": why }))
        }
        "beforeReadFile" | "preToolUse" => {
            let why = match input["tool_name"].as_str() {
                Some(t) => tool_verdict(t, &input["tool_input"], input["cwd"].as_str()),
                None => policy::read(first_str(input, &["file_path", "path"])),
            }?;
            Some(json!({ "permission": "deny", "user_message": why, "agent_message": why }))
        }
        "sessionStart" => Some(json!({ "additional_context": policy::session_context() })),
        _ => None,
    }
}

/// Dispatch by the tool name used in `sealctl hook <tool>`.
pub fn handle(tool: &str, input: &Value) -> Option<Value> {
    match tool {
        "claude" => claude_style(input, Flavor::Claude),
        "codex" => claude_style(input, Flavor::Codex),
        "qwen" => claude_style(input, Flavor::Qwen),
        "copilot" => claude_style(input, Flavor::Copilot),
        "gemini" => gemini(input),
        "cursor" => cursor(input),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &str = "sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123";

    #[test]
    fn codex_patches_and_shell() {
        let patch =
            format!("*** Begin Patch\n*** Add File: src/config.ts\n+const k = '{KEY}';\n*** End Patch");
        let out = handle(
            "codex",
            &json!({"hook_event_name":"PreToolUse","tool_name":"apply_patch","tool_input":{"command": patch}}),
        )
        .unwrap();
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
        assert!(handle(
            "codex",
            &json!({"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"printenv"}})
        )
        .is_some());
        let blocked = handle(
            "codex",
            &json!({"hook_event_name":"UserPromptSubmit","prompt": KEY}),
        )
        .unwrap();
        assert_eq!(blocked["decision"], "block");
        assert!(
            blocked.get("hookSpecificOutput").is_none(),
            "only Claude gets suppressOriginalPrompt"
        );
    }

    #[test]
    fn argv_commands_multiedit_and_grep() {
        let v = json!({"hook_event_name":"PreToolUse","tool_name":"shell",
            "tool_input":{"command":["bash","-lc","cat .env"]}});
        assert!(handle("codex", &v).is_some(), "argv form");
        let v = json!({"hook_event_name":"PreToolUse","tool_name":"MultiEdit",
            "tool_input":{"file_path":"/p/a.ts","edits":[{"old_string":"x","new_string": format!("k='{KEY}'")}]}});
        assert!(handle("claude", &v).is_some(), "MultiEdit");
        let v = json!({"hook_event_name":"PreToolUse","tool_name":"Grep",
            "tool_input":{"pattern":"KEY","path":"/p/.env"}});
        assert!(handle("claude", &v).is_some(), "Grep on .env");
        let v = json!({"hook_event_name":"PreToolUse","tool_name":"Grep",
            "tool_input":{"pattern":"KEY","path":"/p","glob":".env*","output_mode":"content"}});
        assert!(handle("claude", &v).is_some(), "Grep limited to .env files");
        let v = json!({"hook_event_name":"PreToolUse","tool_name":"Grep",
            "tool_input":{"pattern":"KEY","path":"/p","glob":"*.rs"}});
        assert!(handle("claude", &v).is_none(), "Grep in source files");
    }

    #[test]
    fn grep_r_reads_dotenv() {
        let t = tempfile::tempdir().unwrap();
        std::fs::write(t.path().join(".env"), "A=1").unwrap();
        let cwd = t.path().to_str().unwrap();
        assert!(policy::bash_in("grep -rn OPENAI_API_KEY .", Some(cwd)).is_some());
        assert!(policy::bash_in("grep -rn --exclude='.env*' OPENAI_API_KEY .", Some(cwd)).is_none());
        assert!(policy::bash_in("grep -n x src/main.rs", Some(cwd)).is_none());
    }

    #[test]
    fn gemini_contract() {
        let out = gemini(&json!({"hook_event_name":"BeforeTool","tool_name":"run_shell_command","tool_input":{"command":"cat .env"}})).unwrap();
        assert_eq!(out["decision"], "deny");
        let out = gemini(&json!({"hook_event_name":"BeforeTool","tool_name":"write_file","tool_input":{"file_path":"/p/a.py","content": format!("k='{KEY}'")}})).unwrap();
        assert_eq!(out["decision"], "deny");
        assert!(gemini(&json!({"hook_event_name":"BeforeAgent","prompt":"hello"})).is_none());
        assert_eq!(
            gemini(&json!({"hook_event_name":"BeforeAgent","prompt":KEY})).unwrap()["decision"],
            "deny"
        );
    }

    #[test]
    fn cursor_contract() {
        let out =
            cursor(&json!({"hook_event_name":"beforeShellExecution","command":"sealctl secret get a/b"}))
                .unwrap();
        assert_eq!(out["permission"], "deny");
        let out = cursor(&json!({"hook_event_name":"beforeSubmitPrompt","prompt":KEY})).unwrap();
        assert_eq!(out["continue"], false);
        assert!(cursor(&json!({"hook_event_name":"beforeShellExecution","command":"cargo test"})).is_none());
    }

    #[test]
    fn copilot_has_both_shapes() {
        let out = handle(
            "copilot",
            &json!({"hook_event_name":"PreToolUse","tool_name":"bash","tool_input":{"command":"echo $GITHUB_TOKEN"}}),
        )
        .unwrap();
        assert_eq!(out["permissionDecision"], "deny");
        assert_eq!(out["hookSpecificOutput"]["permissionDecision"], "deny");
    }

    #[test]
    fn garbage_never_fails() {
        for tool in ["claude", "codex", "gemini", "cursor", "copilot", "qwen", "nope"] {
            assert!(handle(tool, &Value::Null).is_none());
            assert!(handle(tool, &json!({"hook_event_name": 5})).is_none());
        }
    }
}
