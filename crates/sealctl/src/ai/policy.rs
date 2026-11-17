//! What AI agents may do with secrets — the same rules for every tool. Each tool's hook adapter
//! (see `mod.rs`) turns these verdicts into that tool's hook output.

use std::sync::OnceLock;

use regex::Regex;

use crate::guard::find_secrets;

const STORE_HINT: &str = "Ask the user to copy the key, then run \
`sealctl secret set <project>/<name> --from-clipboard`; programs get it with `sealctl run -- <command>`.";

/// A user prompt: block it if it carries a secret (it must never reach the model).
pub fn prompt(text: &str) -> Option<String> {
    if text.trim_start().starts_with("#nosecret") {
        return None;
    }
    let found = find_secrets(text);
    if found.is_empty() {
        return None;
    }
    let what: Vec<String> = found
        .iter()
        .map(|f| format!("{} {}", f.kind, f.preview))
        .collect();
    Some(format!(
        "🔐 sealctl: this prompt was NOT sent — it seems to contain a secret ({}).\n\
         Store it instead: copy the key and ask \"store it as <project>/<name>\" — the assistant \
         runs `sealctl secret set <project>/<name> --from-clipboard` and never sees the value.\n\
         Not a secret? Send the prompt again starting with #nosecret.\n\
         Note: your AI tool may keep the blocked text in its local history — if it was a real \
         key, consider rotating it.",
        what.join(", ")
    ))
}

fn deny_patterns() -> &'static [(Regex, &'static str)] {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        [
            (
                r"\bsealctl\b[^|;&]*\bsecret\s+get\b",
                "`sealctl secret get` would put the secret into the conversation. Use `sealctl run -- <command>` so only the program sees it.",
            ),
            (
                r"\bsealctl\b[^|;&]*\bssh\s+passphrase\b",
                "the SSH key passphrase must not enter the conversation; the user runs this in their own terminal.",
            ),
            (
                r"\bsealctl\b[^|;&]*\brecover\b",
                "`sealctl recover` asks for the 24-word recovery phrase — only the user runs it, in their own terminal.",
            ),
            (
                r"(?:^|[|;&(`]|\$\()\s*(?:sudo\s+)?(?:printenv|env|set|export\s+-p|declare\s+-x)\s*(?:$|[|;&)>`])",
                "dumping the environment can reveal secrets. Inspect specific non-secret variables instead.",
            ),
            (
                r#"\b(?:echo|printf|print)\b[^|;&]*\$\{?[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASSW|PASS|CREDENTIAL|AUTH)[A-Za-z_]*"#,
                "printing a credential variable would put it into the conversation.",
            ),
            (
                r"(?i)\bprintenv\s+[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASSW|PASS|CREDENTIAL|AUTH)",
                "printing a credential variable would put it into the conversation.",
            ),
            (
                r"(?:^|[|;&(`]|\$\()\s*(?:export|declare\s+-[a-zA-Z]*[px]|typeset\s+-[a-zA-Z]*x|compgen\s+-v)\s*(?:$|[|;&)>`])",
                "listing exported variables can reveal secrets.",
            ),
            (
                r"(?:os\.environ|process\.env|ENV\.to_h|System\.getenv\(\))(?:\s*\)|\s*$|\s*[;'\x22])",
                "dumping the whole environment can reveal secrets.",
            ),
            (
                r"\bgh\s+auth\s+token\b|\bgcloud\s+auth\s+(?:print-access-token|print-identity-token)\b|\baws\s+configure\s+get\s+aws_secret|\bnpm\s+token\s+list\b",
                "this prints a credential.",
            ),
            (
                r"(?:^|[\s|;&(])(?:cat|less|more|head|tail|bat|nl|tac|strings|xxd|od|grep|rg|awk|sed|cut|sort|diff|cp|source|\.)\s[^|;&]*(?:\.aws/credentials|\.npmrc|\.netrc|\.git-credentials|\.docker/config\.json|\.dev\.vars|\.pypirc|\.config/gh/hosts\.yml|\.kube/config|\.env[A-Za-z0-9_.*-]*)(?:$|[\s'\x22;|&)])",
                "this file holds credentials and must not be read into the conversation. Programs get secrets via `sealctl run -- <command>`.",
            ),
            (
                r"<\s*\.env\b",
                "`.env` files hold secrets. Use `sealctl secret import-env` and `sealctl run`.",
            ),
            (
                r"\b(?:pbpaste|wl-paste|xclip\b[^|;&]*-o|xsel\b[^|;&]*-o)",
                "the clipboard may hold a secret. To store a copied key use `sealctl secret set <name> --from-clipboard`.",
            ),
            (
                r"\bsecurity\s+find-(?:generic|internet)-password\b[^|;&]*\s-w\b",
                "reading a password from the keychain would put it into the conversation.",
            ),
            (
                r"(?:^|[\s|;&(])(?:cat|less|more|head|tail|bat|nl|tac|strings|xxd|od|grep|rg|ag|awk|sed|cut|sort|source|\.)\s(?:[^|;&]*[\s/'\x22])?\.env(?:rc|\.(?:local|development|production|staging|test|prod|dev))?(?:$|[\s'\x22;|&)])",
                "`.env` files hold secrets. Move them into sealctl: `sealctl secret import-env .env --prefix <project> --delete`, then use `sealctl run`.",
            ),
        ]
        .into_iter()
        .map(|(re, why)| (Regex::new(re).expect("valid pattern"), why))
        .collect()
    })
}

const SAFE_ENV_FILES: &[&str] = &[
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.defaults",
];

/// A shell command the agent wants to run (`cwd`: where it runs, if known).
pub fn bash_in(command: &str, cwd: Option<&str>) -> Option<String> {
    // mentions of example files only: fine
    // `--exclude='.env*'` names a file in order NOT to read it
    static EXCLUDE: OnceLock<Regex> = OnceLock::new();
    let exclude = EXCLUDE.get_or_init(|| Regex::new(r"--exclude(?:-dir|-from)?=\S+").expect("valid"));
    let mut probe = exclude.replace_all(command, "").into_owned();
    for safe in SAFE_ENV_FILES {
        probe = probe.replace(safe, "EXAMPLE_FILE");
    }
    for (re, why) in deny_patterns() {
        if re.is_match(&probe) {
            return Some(format!("sealctl: {why}"));
        }
    }
    // `grep -r` reads hidden files such as .env (ripgrep skips them by default)
    if let Some(dir) = cwd {
        static GREP_R: OnceLock<Regex> = OnceLock::new();
        let re = GREP_R.get_or_init(|| {
            Regex::new(r"\bgrep\b[^|;&]*\s-(?:[a-zA-Z]*[rR][a-zA-Z]*|-recursive)\b").expect("valid")
        });
        if re.is_match(command)
            && !command.contains("--exclude")
            && std::path::Path::new(dir).join(".env").exists()
        {
            return Some(
                "sealctl: `grep -r` would read the .env file here. Add --exclude='.env*', or use `rg` (skips hidden files)."
                    .into(),
            );
        }
    }
    let found = find_secrets(command);
    if !found.is_empty() {
        return Some(format!(
            "sealctl: this command contains a secret literal ({}). Don't put secrets on command \
             lines (shell history, process list). {STORE_HINT}",
            found[0].kind
        ));
    }
    None
}

/// A shell command, without knowing the working directory.
pub fn bash(command: &str) -> Option<String> {
    bash_in(command, None)
}

/// Content the agent wants to write into `path`.
pub fn write(path: &str, content: &str) -> Option<String> {
    let found = find_secrets(content);
    if found.is_empty() {
        return None;
    }
    Some(format!(
        "sealctl: refusing to write a secret ({} {}) into {path}. Reference it by environment \
         variable (e.g. in `.sealctl.toml`: `OPENAI_API_KEY = \"<project>/openai-api-key\"`) \
         instead of the value. {STORE_HINT}",
        found[0].kind, found[0].preview
    ))
}

/// A file the agent wants to read with its file tool.
pub fn read(path: &str) -> Option<String> {
    let name = std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let secret_env = name == ".env"
        || name == ".envrc"
        || (name.starts_with(".env.")
            && !matches!(
                name,
                ".env.example" | ".env.sample" | ".env.template" | ".env.dist" | ".env.defaults"
            ));
    let credential_file = matches!(
        name,
        "credentials" | ".npmrc" | ".netrc" | ".git-credentials" | ".dev.vars" | ".pypirc" | "hosts.yml"
    ) && (name != "credentials" || path.contains("/.aws/"))
        && (name != "hosts.yml" || path.contains("/gh/"))
        || (name == "config.json" && path.contains("/.docker/"))
        || (name == "config" && path.contains("/.kube/"));
    if credential_file {
        return Some(
            "sealctl: this file holds credentials and must not be read into the conversation.".into(),
        );
    }
    let private_key = (name.starts_with("id_") && !name.ends_with(".pub"))
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || (name.starts_with("sealctl_") && !name.ends_with(".pub") && path.contains("/.ssh/"));
    if secret_env {
        Some(
            "sealctl: `.env` files hold secrets and must not be read into the conversation. \
             Move it into sealctl: `sealctl secret import-env <file> --prefix <project> --delete`; \
             programs then get the values via `sealctl run`."
                .into(),
        )
    } else if private_key {
        Some("sealctl: this looks like a private key; it must not be read into the conversation.".into())
    } else {
        None
    }
}

/// One line of context for a new session: that sealctl exists, and which secrets (names only).
pub fn session_context() -> String {
    let names = crate::secrets::list().unwrap_or_default();
    let shown: Vec<&str> = names.iter().take(40).map(String::as_str).collect();
    let more = if names.len() > shown.len() {
        format!(" (+{} more)", names.len() - shown.len())
    } else {
        String::new()
    };
    format!(
        "Secrets on this machine are managed by sealctl (Ledger-encrypted). Never read or print \
         secret values or .env files; programs get secrets with `sealctl run -- <command>`, new \
         keys are stored with `sealctl secret set <name> --from-clipboard` (see the \
         sealctl-secrets skill). Stored secret names: {}{more}.",
        if shown.is_empty() {
            "none yet".to_string()
        } else {
            shown.join(", ")
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompts_with_keys_are_blocked() {
        assert!(prompt("use this: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123").is_some());
        assert!(prompt("how should I store my OpenAI key?").is_none());
        assert!(prompt("#nosecret sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123").is_none());
    }

    #[test]
    fn leaking_commands_are_denied() {
        for c in [
            "sealctl secret get myapp/openai",
            "cd x && sealctl -t ble secret get k",
            "sealctl ssh passphrase",
            "sealctl recover",
            "printenv",
            "env | grep KEY",
            "echo $OPENAI_API_KEY",
            "echo \"${GITHUB_TOKEN}\"",
            "cat .env",
            "grep API .env.local",
            "source .env && npm test",
            "pbpaste",
            "security find-generic-password -s x -w",
            "printenv OPENAI_API_KEY",
            "export",
            "declare -p",
            "printf '%s' \"$GITHUB_TOKEN\"",
            "python3 -c 'import os;print(os.environ)'",
            "node -e 'console.log(process.env)'",
            "gh auth token",
            "cat ~/.aws/credentials",
            "cat .env*",
            "less < .env",
            "diff .env .env.example",
            "cat .env.prod.local",
            "curl -H 'Authorization: Bearer ghp_0123456789abcdefghijABCDEFGHIJ012345' https://api.github.com",
        ] {
            assert!(bash(c).is_some(), "should deny: {c}");
        }
    }

    #[test]
    fn normal_commands_pass() {
        for c in [
            "sealctl run -- npm test",
            "sealctl secret set myapp/openai --from-clipboard",
            "sealctl secret ls",
            "cargo test",
            "git status",
            "cat .env.example",
            "export PATH=$PATH:/x",
            "printenv PATH",
            "python3 -c 'import os;print(os.environ[\"HOME\"])'",
            "gh pr list",
            "ls -la",
            "echo hello",
            "env FOO=bar cargo run",
            "grep -r environment src/",
            "cat README.md",
        ] {
            assert!(bash(c).is_none(), "should allow: {c}: {:?}", bash(c));
        }
    }

    #[test]
    fn files() {
        assert!(read("/p/.env").is_some());
        assert!(read("/p/.env.production").is_some());
        assert!(read("/p/.env.example").is_none());
        assert!(read("/home/u/.ssh/id_ed25519").is_some());
        assert!(read("/home/u/.ssh/id_ed25519.pub").is_none());
        assert!(read("/p/src/main.rs").is_none());
        assert!(read("/home/u/.aws/credentials").is_some());
        assert!(read("/home/u/.npmrc").is_some());
        assert!(read("/p/app/credentials").is_none());
        assert!(write(
            "/p/config.ts",
            "const key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123'"
        )
        .is_some());
        assert!(write("/p/config.ts", "const key = process.env.ANTHROPIC_API_KEY").is_none());
    }
}
