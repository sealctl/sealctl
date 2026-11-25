//! What AI agents may do with secrets — the same rules for every tool. Each tool's hook adapter
//! (see `mod.rs`) turns these verdicts into that tool's hook output.

use std::collections::HashSet;
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
        "sealctl: this prompt was NOT sent — it seems to contain a secret ({}).\n\
         Store it instead: copy the key and ask \"store it as <project>/<name>\" — the assistant \
         runs `sealctl secret set <project>/<name> --from-clipboard` and never sees the value.\n\
         Not a secret? Send the prompt again starting with #nosecret.\n\
         Note: your AI tool may keep the blocked text in its local history — if it was a real \
         key, consider rotating it.",
        what.join(", ")
    ))
}

const PRINT_CREDENTIAL: &str = "printing a credential variable would put it into the conversation.";

/// Ends of variable names that hold where something is, not a credential (`SSH_AUTH_SOCK`,
/// `SSH_AGENT_PID`, `PASSWORD_STORE_DIR`, `KEY_FILE`): printing them shows no secret.
const HARMLESS_SUFFIXES: &[&str] = &["_SOCK", "_SOCKET", "_PID", "_DIR", "_PATH", "_FILE"];

/// Whether a command that matched a [`PRINT_CREDENTIAL`] pattern prints a variable that may hold
/// a credential, rather than only harmless ones such as `$SSH_AUTH_SOCK`.
fn prints_credential(text: &str) -> bool {
    static ECHO: OnceLock<Regex> = OnceLock::new();
    static VAR: OnceLock<Regex> = OnceLock::new();
    static PRINTENV: OnceLock<Regex> = OnceLock::new();
    let echo = ECHO.get_or_init(|| Regex::new(r"\b(?:echo|printf|print)\b([^|;&]*)").expect("valid"));
    let var = VAR.get_or_init(|| Regex::new(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)").expect("valid"));
    let printenv =
        PRINTENV.get_or_init(|| Regex::new(r"(?i)\bprintenv\s+([A-Za-z_][A-Za-z0-9_]*)").expect("valid"));
    let credential = |name: &str| {
        ["KEY", "TOKEN", "SECRET", "PASSW", "PASS", "CREDENTIAL", "AUTH"]
            .iter()
            .any(|k| name.contains(k))
            && !HARMLESS_SUFFIXES.iter().any(|s| name.ends_with(s))
    };
    echo.captures_iter(text)
        .any(|c| var.captures_iter(&c[1]).any(|v| credential(&v[1])))
        || printenv
            .captures_iter(&text.to_ascii_uppercase())
            .any(|c| credential(&c[1]))
}

fn deny_patterns() -> &'static [(Regex, &'static str)] {
    static P: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    P.get_or_init(|| {
        [
            (
                r"(?:^|[\s|;&(])(?:cat|less|more|head|tail|bat|nl|tac|strings|xxd|od|grep|rg|awk|sed|cut|cp|base64)\s[^|;&]*(?:\.sealed\b|machine\.json|\.local/state/sealctl|\.local/share/sealctl)",
                "sealctl's own files are not for the conversation. Use `sealctl secret ls` for names and `sealctl run` for values.",
            ),
            (
                r"(?:^|[|;&(`]|\$\()\s*(?:sudo\s+)?(?:printenv|env|set|export\s+-p|declare\s+-x)\s*(?:$|[|;&)>`])",
                "dumping the environment can reveal secrets. Inspect specific non-secret variables instead.",
            ),
            (
                r#"\b(?:echo|printf|print)\b[^|;&]*\$\{?[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASSW|PASS|CREDENTIAL|AUTH)[A-Za-z_]*"#,
                PRINT_CREDENTIAL,
            ),
            (
                r"(?i)\bprintenv\s+[A-Za-z_]*(?:KEY|TOKEN|SECRET|PASSW|PASS|CREDENTIAL|AUTH)",
                PRINT_CREDENTIAL,
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
                "`.env` files hold secrets. Use `sealctl seal env` and `sealctl run`.",
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
    if let Some(why) = sealctl_check(command) {
        return Some(format!("sealctl: {why}"));
    }
    for (re, why) in deny_patterns() {
        if re.is_match(&probe) {
            if *why == PRINT_CREDENTIAL && !prints_credential(&probe) {
                continue;
            }
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

/// The sealctl subcommands an agent must not run, by the words that name them.
fn denied_verb(verb: &str, sub: Option<&str>) -> Option<&'static str> {
    const USER_ONLY: &str =
        "only the user runs this, in their own terminal. Tell the user the command to run.";
    match (verb, sub) {
        ("secret", Some("get")) => Some(
            "`sealctl secret get` would put the secret into the conversation. Use `sealctl run -- <command>` so only the program sees it.",
        ),
        ("aws", Some("credentials")) | ("git", Some("credential")) => Some(
            "the credential helpers print values for git and the AWS CLI, not for the conversation. Run `git push` or `aws` itself.",
        ),
        ("recover", _) => Some(
            "`sealctl recover` asks for the 24-word recovery phrase — only the user runs it, in their own terminal.",
        ),
        ("seal" | "unseal" | "buy" | "unpair", _)
        | ("secret", Some("import-env"))
        | ("project", Some("trust"))
        | ("volume" | "ssh", Some("import")) => Some(USER_ONLY),
        _ => None,
    }
}

/// The simple commands of a shell command line, each as its words with quotes removed. Pipes,
/// lists, subshells and command substitutions (`$(…)`, backquotes, also inside double quotes)
/// separate commands. Not a full shell parser: it is meant to find which program each command
/// runs and with which arguments, erring towards splitting more. With `resume`, the text after a
/// substitution inside double quotes is double-quoted again (as the shell reads it); without, it
/// is not. With `track_case`, a `case … esac` is followed so that a pattern's `)` closes nothing
/// (as bash 4+ and zsh read it); without, a pattern's `)` closes an open `$(` (as bash 3.2, the
/// macOS `/bin/bash` and `/bin/sh`, reads it inside double quotes). Shells differ here and a `)`
/// can be misread either way, so callers check every reading.
///
/// Here-document bodies are text (only an unquoted body's substitutions are commands), unless
/// anything in the command line may run its input as commands (see [`RUNS_INPUT`]): a body can
/// reach such a program through a pipe or group that continues after it, so then every body is
/// read as commands.
fn simple_commands(text: &str, resume: bool, track_case: bool) -> Vec<Vec<String>> {
    let cmds = read_commands(text, resume, track_case, true, 0);
    let runs_input = cmds.iter().any(|words| {
        words.iter().enumerate().any(|(n, w)| {
            let base = w.rsplit('/').next().unwrap_or(w);
            RUNS_INPUT.contains(&base) || (n == 0 && base == ".")
        })
    });
    if runs_input {
        read_commands(text, resume, track_case, false, 0)
    } else {
        cmds
    }
}

/// How deeply here-documents inside here-documents (through `$(…)` in an unquoted body) are
/// read as text; deeper ones are read as commands.
const HERE_DOC_LEVELS: usize = 3;

/// [`simple_commands`], with here-document bodies read as text (`here_docs`) or as commands;
/// `level`: how deep in here-document bodies this text is.
fn read_commands(
    text: &str,
    resume: bool,
    track_case: bool,
    here_docs: bool,
    level: usize,
) -> Vec<Vec<String>> {
    let mut cmds = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut word = String::new();
    let mut in_word = false;
    let mut quote: Option<char> = None;
    // open subshells and command substitutions: `'('` or `` '`' ``, and whether the text after
    // the matching `)` or backquote is inside double quotes again (`"a $(b) c"`); `'c'` for an
    // open `case … esac`, whose patterns' `)` close nothing
    let mut open: Vec<(char, bool)> = Vec::new();
    let cs: Vec<char> = text.chars().collect();
    let mut i = 0;
    // whether every word of the current command so far is a shell keyword (`if`, `do`, `time`, …),
    // kept as a flag so each word costs O(1): a `case` or `esac` only counts in that position
    let mut all_kw = true;
    let end_word = |word: &mut String,
                    in_word: &mut bool,
                    words: &mut Vec<String>,
                    open: &mut Vec<(char, bool)>,
                    all_kw: &mut bool| {
        if *in_word {
            let w = std::mem::take(word);
            if track_case && *all_kw {
                if w == "case" {
                    open.push(('c', false));
                } else if w == "esac" && open.last() == Some(&('c', false)) {
                    open.pop();
                }
            }
            *all_kw = *all_kw && is_keyword(&w);
            words.push(w);
            *in_word = false;
        }
    };
    let end_cmd = |words: &mut Vec<String>, cmds: &mut Vec<Vec<String>>, all_kw: &mut bool| {
        if !words.is_empty() {
            cmds.push(std::mem::take(words));
        }
        *all_kw = true;
    };
    // here-documents opened on the current line, read at its end
    let mut pending: Vec<HereDoc> = Vec::new();
    // after a `#` that starts a word, the rest of the line is a comment: a `<<` there opens no
    // here-document (its text is still read as commands, which only errs towards denying)
    let mut in_comment = false;
    // open `$[ … ]` (old arithmetic): a `<<` there is a shift
    let mut old_arith = 0usize;
    while i < cs.len() {
        let c = cs[i];
        if quote.is_none() {
            match c {
                '#' if !in_word => in_comment = true,
                '\n' => in_comment = false,
                '$' if cs.get(i + 1) == Some(&'[') => old_arith += 1,
                ']' if old_arith > 0 => old_arith -= 1,
                _ => {}
            }
        }
        // a newline ending a line that opened here-documents: their bodies follow
        if quote.is_none() && c == '\n' && !pending.is_empty() {
            end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
            end_cmd(&mut words, &mut cmds, &mut all_kw);
            let docs = std::mem::take(&mut pending);
            // no delimiter line: the text is read as commands, line by line
            if let Some((bodies, end)) = here_bodies(&cs, i + 1, &docs) {
                for (doc, body) in docs.iter().zip(bodies) {
                    // an unquoted delimiter: `$(…)` and backquotes in the body still run
                    if !doc.quoted {
                        // one level deeper; past HERE_DOC_LEVELS, bodies in it are commands,
                        // which keeps the work linear in the text
                        cmds.extend(read_commands(
                            &as_double_quoted(&body),
                            resume,
                            track_case,
                            level + 1 < HERE_DOC_LEVELS,
                            level + 1,
                        ));
                    }
                }
                // `end`: the newline after the last delimiter line, or the end of the text
                i = end;
            }
            i += 1;
            continue;
        }
        // `<<` and `<<-` (not `<<<`, nor a shift inside `$(( ))` or `(( ))`): a here-document
        if here_docs
            && quote.is_none()
            && c == '<'
            && cs.get(i + 1) == Some(&'<')
            && cs.get(i + 2) != Some(&'<')
            && (i == 0 || cs[i - 1] != '<')
            && !open.iter().any(|&(o, _)| o == 'A')
            && !in_comment
            && old_arith == 0
        {
            if let Some((doc, next)) = here_delimiter(&cs, i + 2) {
                end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
                pending.push(doc);
                i = next;
                continue;
            }
        }
        match quote {
            Some('\'') => {
                if c == '\'' {
                    quote = None;
                } else {
                    word.push(c);
                }
            }
            Some(_) => match c {
                '"' => quote = None,
                '\\' if i + 1 < cs.len() => {
                    i += 1;
                    word.push(cs[i]);
                }
                // a command substitution inside double quotes runs a command too; the quotes
                // resume after it
                '`' => {
                    quote = None;
                    end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
                    end_cmd(&mut words, &mut cmds, &mut all_kw);
                    open.push(('`', true));
                }
                '$' if cs.get(i + 1) == Some(&'(') => {
                    quote = None;
                    i += 1;
                    end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
                    end_cmd(&mut words, &mut cmds, &mut all_kw);
                    open.push(('(', true));
                }
                c => word.push(c),
            },
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    in_word = true;
                }
                '\\' if i + 1 < cs.len() => {
                    i += 1;
                    if cs[i] != '\n' {
                        word.push(cs[i]);
                        in_word = true;
                    }
                }
                ' ' | '\t' => end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw),
                // `2>&1`, `>&2`, `&>file`: redirections, not separators
                '&' if i > 0 && matches!(cs[i - 1], '>' | '<') => word.push(c),
                '&' if cs.get(i + 1) == Some(&'>') => word.push(c),
                '|' | ';' | '&' | '\n' | '{' | '}' => {
                    end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
                    end_cmd(&mut words, &mut cmds, &mut all_kw);
                }
                '(' => {
                    end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
                    end_cmd(&mut words, &mut cmds, &mut all_kw);
                    // the second `(` of `((` or `$((`: arithmetic, where `<<` is a shift
                    let arithmetic = i > 0 && cs[i - 1] == '(';
                    open.push((if arithmetic { 'A' } else { '(' }, false));
                }
                '$' if cs.get(i + 1) == Some(&'(') => {
                    i += 1;
                    end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
                    end_cmd(&mut words, &mut cmds, &mut all_kw);
                    open.push(('(', false));
                }
                ')' | '`' => {
                    end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
                    end_cmd(&mut words, &mut cmds, &mut all_kw);
                    let opener = if c == ')' { '(' } else { '`' };
                    match open.last() {
                        Some(&(o, dq)) if o == opener || (opener == '(' && o == 'A') => {
                            open.pop();
                            if dq && resume {
                                quote = Some('"');
                                in_word = true;
                            }
                        }
                        // a `case` pattern's `)`, or a stray one
                        _ if c == ')' => {}
                        _ => open.push(('`', false)),
                    }
                }
                c => {
                    word.push(c);
                    in_word = true;
                }
            },
        }
        i += 1;
    }
    end_word(&mut word, &mut in_word, &mut words, &mut open, &mut all_kw);
    end_cmd(&mut words, &mut cmds, &mut all_kw);
    cmds
}

/// A here-document opened by `<<word` or `<<-word`.
struct HereDoc {
    delimiter: String,
    /// `<<-`: leading tabs are removed from body lines and the delimiter line.
    strip_tabs: bool,
    /// The delimiter was quoted (`'EOF'`, `"EOF"`, `\EOF`): the body is plain text, nothing in
    /// it runs. Unquoted, `$(…)` and backquotes in it run.
    quoted: bool,
}

/// Programs that may run their standard input as commands. When any word of a command line
/// names one (`.` only as a command), its here-documents are read as commands, as before
/// here-documents were known: a body can reach such a program through a pipe, group or loop
/// that continues after the body (`cat <<'EOF' |` … `EOF` / `sh`, `{ cat <<'EOF' … } | sh`).
const RUNS_INPUT: &[&str] = &[
    "sh",
    "bash",
    "zsh",
    "dash",
    "ksh",
    "mksh",
    "fish",
    "csh",
    "tcsh",
    "ash",
    "busybox",
    "source",
    "eval",
    "exec",
    "ssh",
    "su",
    "sudo",
    "doas",
    "xargs",
    "parallel",
    "osascript",
    "script",
    "expect",
];

/// The here-document whose operator ends just before `start`: its delimiter word and where the
/// text after it starts. `None` when no delimiter follows.
fn here_delimiter(cs: &[char], start: usize) -> Option<(HereDoc, usize)> {
    let mut i = start;
    let strip_tabs = cs.get(i) == Some(&'-');
    if strip_tabs {
        i += 1;
    }
    while matches!(cs.get(i), Some(' ' | '\t')) {
        i += 1;
    }
    let mut delimiter = String::new();
    let mut quoted = false;
    let mut quote: Option<char> = None;
    while let Some(&c) = cs.get(i) {
        match quote {
            Some(q) if c == q => quote = None,
            Some(_) => delimiter.push(c),
            None => match c {
                '\'' | '"' => {
                    quote = Some(c);
                    quoted = true;
                }
                '\\' => {
                    quoted = true;
                    i += 1;
                    if let Some(&n) = cs.get(i) {
                        delimiter.push(n);
                    }
                }
                ' ' | '\t' | '\n' | '|' | ';' | '&' | '<' | '>' | '(' | ')' => break,
                c => delimiter.push(c),
            },
        }
        i += 1;
    }
    if quote.is_some() || delimiter.is_empty() || delimiter.contains(['$', '`']) {
        return None;
    }
    Some((
        HereDoc {
            delimiter,
            strip_tabs,
            quoted,
        },
        i,
    ))
}

/// The bodies of `docs`, read one after another from `start` (the line after the one that
/// opened them), and the index of the newline ending the last delimiter line (or the end of the
/// text). `None` when a delimiter line is missing: then the text is read as commands instead.
fn here_bodies(cs: &[char], start: usize, docs: &[HereDoc]) -> Option<(Vec<String>, usize)> {
    let mut bodies = Vec::with_capacity(docs.len());
    let mut i = start;
    for doc in docs {
        let mut body = String::new();
        loop {
            if i >= cs.len() {
                return None;
            }
            let end = cs[i..]
                .iter()
                .position(|&c| c == '\n')
                .map_or(cs.len(), |p| i + p);
            let line: String = cs[i..end].iter().collect();
            let line = if doc.strip_tabs {
                line.trim_start_matches('\t')
            } else {
                &line
            };
            if line == doc.delimiter {
                i = end;
                break;
            }
            body.push_str(line);
            body.push('\n');
            i = end + 1;
        }
        bodies.push(body);
        // the next body starts on the line after this delimiter
        if i < cs.len() {
            i += 1;
        }
    }
    // back to the newline ending the last delimiter line (or the text's last character)
    Some((bodies, i - 1))
}

/// An unquoted here-document body as the text of a double-quoted word, so that only its
/// command substitutions read as commands. In such a body a backslash quotes only `$`, `` ` ``,
/// `\` and a newline, and `"` is an ordinary character.
fn as_double_quoted(body: &str) -> String {
    let cs: Vec<char> = body.chars().collect();
    let mut out = String::with_capacity(body.len() + 2);
    out.push('"');
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '\\' if matches!(cs.get(i + 1), Some('$' | '`' | '\\' | '\n')) => {
                out.push('\\');
                out.push(cs[i + 1]);
                i += 1;
            }
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            c => out.push(c),
        }
        i += 1;
    }
    out.push('"');
    out
}

/// The reason given when a command line is too deeply nested or too costly to check: the hook
/// must answer within its timeout, and a command it cannot check is denied, not let through.
const TOO_COMPLEX: &str = "this command is too complex to check (too deeply nested `eval`, `sh -c` or wrappers, or too much text to parse). Split it into simpler commands.";

/// How deeply `eval`, `sh -c`, wrappers and `sealctl run` may nest before a command line counts
/// as too complex to check.
const MAX_DEPTH: usize = 8;

/// The readings of a command line that are checked (see `simple_commands`): double quotes resumed
/// after a substitution or not, `case` patterns followed or not (bash 3.2 closes `$(` at a
/// pattern's `)`).
const READINGS: [(bool, bool); 4] = [(true, true), (true, false), (false, true), (false, false)];

/// The longest command line checked; macOS limits all of execve's arguments to 1 MiB.
const MAX_COMMAND_BYTES: usize = 1 << 20;

/// Why a whole command line may not run, if one of its commands runs a denied sealctl subcommand.
/// The work is bounded: every parse of every reading, at every nesting level, is paid for from
/// one budget of characters that grows linearly with the command's length; when it runs out the
/// command is denied as too complex to check.
fn sealctl_check(command: &str) -> Option<&'static str> {
    // Longer than any command line a shell accepts (execve limits): denied, so the check stays
    // well inside the hook's timeout for any input.
    if command.len() > MAX_COMMAND_BYTES {
        return Some(TOO_COMPLEX);
    }
    let mut budget = command.len().saturating_mul(32).saturating_add(1 << 20);
    sealctl_in(command, 0, &mut budget)
}

/// Why a command line may not run (`budget`: characters left to parse, shared by the recursion).
fn sealctl_in(text: &str, depth: usize, budget: &mut usize) -> Option<&'static str> {
    if depth > MAX_DEPTH {
        return Some(TOO_COMPLEX);
    }
    let cost = text.len().saturating_mul(READINGS.len()).max(1);
    if *budget < cost {
        return Some(TOO_COMPLEX);
    }
    *budget -= cost;
    // deny if any plausible reading finds a denied command; the readings mostly agree, so each
    // distinct simple command is looked into once (else the work grows as 4^depth)
    let mut seen: HashSet<Vec<String>> = HashSet::new();
    let mut distinct: Vec<Vec<String>> = Vec::new();
    for (resume, track_case) in READINGS {
        for words in simple_commands(text, resume, track_case) {
            if !seen.contains(&words) {
                seen.insert(words.clone());
                distinct.push(words);
            }
        }
    }
    distinct
        .iter()
        .find_map(|words| sealctl_argv(words, depth, budget))
}

/// The same for one command's words: the program is found past variable assignments, shell
/// keywords and wrappers (`env`, `command`, `sudo`, `xargs`, …), at any path; `sh -c` and `eval`
/// are looked into, and so is the command `sealctl run` starts.
fn sealctl_argv(words: &[String], depth: usize, budget: &mut usize) -> Option<&'static str> {
    if depth > MAX_DEPTH {
        return Some(TOO_COMPLEX);
    }
    let is_assignment = |w: &str| {
        w.split_once('=').is_some_and(|(k, _)| {
            !k.is_empty()
                && !k.starts_with(|c: char| c.is_ascii_digit())
                && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
    };
    let mut i = 0;
    while i < words.len() && (is_assignment(&words[i]) || is_keyword(&words[i])) {
        i += 1;
    }
    let names_switch = |w: &str| {
        let name = w.split_once('=').map_or(w, |(k, _)| k);
        crate::guard::agent_variables().any(|v| v == name)
    };
    // the agent variables are how sealctl knows an agent runs a command; changing them is the
    // user's call, not the agent's (`SEALCTL_AGENT=0 …`, `unset CLAUDECODE`, `env -u …`)
    const SWITCH: &str = "the agent variables (SEALCTL_AGENT, CLAUDECODE, …) tell sealctl an agent runs this; only the user changes them.";
    if words[..i].iter().any(|w| names_switch(w)) {
        return Some(SWITCH);
    }
    let prog = words.get(i)?;
    let base = prog.rsplit('/').next().unwrap_or(prog);
    let rest = &words[i + 1..];
    if matches!(
        base,
        "export" | "unset" | "env" | "declare" | "typeset" | "local" | "readonly" | "unsetenv" | "setenv"
    ) && rest.iter().any(|w| names_switch(w))
    {
        return Some(SWITCH);
    }
    if base == "git" {
        return git_credential(rest);
    }
    // options of a wrapper that take a value
    let wrapper_value_opts: &[&str] = match base {
        "env" => &["-u", "--unset", "-C", "--chdir", "-S", "--split-string"],
        "sudo" | "doas" => &["-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U"],
        "nice" => &["-n", "--adjustment"],
        "timeout" => &["-s", "--signal", "-k", "--kill-after"],
        "xargs" => &["-I", "-n", "-P", "-L", "-d", "-E", "-s", "-a"],
        "stdbuf" => &["-i", "-o", "-e"],
        "command" | "exec" | "nohup" | "time" | "caffeinate" | "builtin" => &[],
        "sh" | "bash" | "zsh" | "dash" | "ksh" | "fish" => {
            // `sh -c 'text'` (also `-lc`, `-ec`, …)
            let c = rest
                .iter()
                .position(|w| w.starts_with('-') && !w.starts_with("--") && w.contains('c'))?;
            return sealctl_in(rest.get(c + 1)?, depth + 1, budget);
        }
        "eval" => return sealctl_in(&rest.join(" "), depth + 1, budget),
        "sealctl" => return sealctl_args(rest, depth, budget),
        _ => return None,
    };
    let mut j = 0;
    while j < rest.len() {
        let w = rest[j].as_str();
        if w == "--" {
            j += 1;
            break;
        }
        if base == "env" && is_assignment(w) {
            j += 1;
        } else if w.starts_with('-') && w.len() > 1 {
            j += if wrapper_value_opts.contains(&w) { 2 } else { 1 };
        } else {
            break;
        }
    }
    // `timeout` has a duration before the command
    if base == "timeout" && j < rest.len() {
        j += 1;
    }
    sealctl_argv(rest.get(j..)?, depth + 1, budget)
}

/// `git credential fill` and `git credential-<helper> get` print the stored password or token.
fn git_credential(args: &[String]) -> Option<&'static str> {
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() && positional.len() < 2 {
        let w = args[i].as_str();
        i += 1;
        if positional.is_empty()
            && matches!(
                w,
                "-c" | "-C" | "--git-dir" | "--work-tree" | "--namespace" | "--config-env" | "--exec-path"
            )
        {
            i += 1;
        } else if !w.starts_with('-') {
            positional.push(w);
        }
    }
    let prints = match positional.as_slice() {
        ["credential", "fill", ..] => true,
        [helper, "get", ..] => helper.starts_with("credential-"),
        _ => false,
    };
    prints.then_some(
        "`git credential fill` prints the stored password or token. Run `git push` or `git fetch`, which use it without printing it.",
    )
}

fn is_keyword(w: &str) -> bool {
    matches!(
        w,
        "if" | "then" | "else" | "elif" | "do" | "while" | "until" | "!" | "{" | "}" | "time" | "exec"
    )
}

/// sealctl's arguments: its global options are skipped, the first word left is the subcommand,
/// and the next one its own subcommand (`secret get`, `git credential`).
fn sealctl_args(args: &[String], depth: usize, budget: &mut usize) -> Option<&'static str> {
    let mut positional: Vec<&str> = Vec::new();
    let mut i = 0;
    while i < args.len() && positional.len() < 2 {
        let w = args[i].as_str();
        if w == "--relay" {
            i += 2;
            continue;
        }
        if w == "--" {
            break;
        }
        if w.starts_with('-') && w.len() > 1 {
            i += 1;
            continue;
        }
        positional.push(w);
        i += 1;
        if positional == ["run"] {
            // the command `run` starts: after `--`, or the first word that is not an option
            let mut j = i;
            while j < args.len() {
                match args[j].as_str() {
                    "--" => {
                        j += 1;
                        break;
                    }
                    "-e" | "--env" | "--relay" => j += 2,
                    w if w.starts_with('-') => j += 1,
                    _ => break,
                }
            }
            return sealctl_argv(args.get(j..)?, depth + 1, budget);
        }
    }
    denied_verb(positional.first()?, positional.get(1).copied())
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
    if name.ends_with(".sealed")
        || (name == "machine.json" && path.contains("sealctl"))
        || path.contains("/.local/state/sealctl/")
        || path.contains("/.local/share/sealctl/")
    {
        return Some(
            "sealctl: sealctl's own files are not for the conversation. Use `sealctl secret ls` for names."
                .into(),
        );
    }
    let private_key = (name.starts_with("id_") && !name.ends_with(".pub"))
        || name.ends_with(".pem")
        || name.ends_with(".key")
        || (name.starts_with("sealctl_") && !name.ends_with(".pub") && path.contains("/.ssh/"));
    if secret_env {
        Some(
            "sealctl: `.env` files hold secrets and must not be read into the conversation. \
             Move it into sealctl: `sealctl secret import-env <file> --prefix <project> --delete` (the user runs it); \
             programs then get the values via `sealctl run`."
                .into(),
        )
    } else if private_key {
        Some("sealctl: this looks like a private key; it must not be read into the conversation.".into())
    } else {
        None
    }
}

/// A search with the agent's file tool in `path`, limited to the files `glob` names (several
/// globs separated by spaces or commas, braces allowed): denied when the glob itself picks files
/// that `read` keeps out (`.env*`, `**/.env.local`, `*.rs .env`, `{.env,.env.prod}`, `*.pem`).
pub fn search(path: &str, glob: &str) -> Option<String> {
    read(path).or_else(|| {
        glob_parts(glob)
            .iter()
            .flat_map(|part| expand_braces(part, 0))
            .map(|alt| alt.trim_end_matches('*').to_string())
            .filter(|alt| !alt.is_empty())
            .find_map(|alt| read(&alt))
    })
}

/// The globs of a glob list: split at spaces and commas outside braces.
fn glob_parts(glob: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut part = String::new();
    let mut depth = 0usize;
    for c in glob.chars() {
        match c {
            '{' => depth += 1,
            '}' => depth = depth.saturating_sub(1),
            _ => {}
        }
        if depth == 0 && (c == ',' || c.is_whitespace()) {
            parts.push(std::mem::take(&mut part));
        } else {
            part.push(c);
        }
    }
    parts.push(part);
    parts.retain(|p| !p.is_empty());
    parts
}

/// The globs a brace pattern stands for: `a{b,c{d,e}}` → `ab`, `acd`, `ace`.
fn expand_braces(glob: &str, depth: usize) -> Vec<String> {
    let Some(open) = glob.find('{').filter(|_| depth < 16) else {
        return vec![glob.to_string()];
    };
    let mut level = 0usize;
    let mut alts = Vec::new();
    let mut start = open + 1;
    for (i, c) in glob[open..].char_indices().map(|(i, c)| (open + i, c)) {
        match c {
            '{' => level += 1,
            '}' => {
                level -= 1;
                if level == 0 {
                    alts.push(&glob[start..i]);
                    let (head, tail) = (&glob[..open], &glob[i + 1..]);
                    return alts
                        .iter()
                        .flat_map(|alt| expand_braces(&format!("{head}{alt}{tail}"), depth + 1))
                        .take(256)
                        .collect();
                }
            }
            ',' if level == 1 => {
                alts.push(&glob[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    // no closing brace: a literal `{`
    vec![glob.to_string()]
}

/// One line of context for a new session: that sealctl exists, and which secrets (names only).
pub fn session_context() -> String {
    let names: Vec<String> = crate::store::Store::configured()
        .and_then(|s| s.list())
        .map(|l| l.into_iter().map(|x| x.name).collect())
        .unwrap_or_default();
    session_line(&names, crate::git::signs_through_sealctl())
}

/// The session line for these secret names; `signs`: git signs through sealctl here.
fn session_line(names: &[String], signs: bool) -> String {
    let shown: Vec<&str> = names.iter().take(40).map(String::as_str).collect();
    let more = if names.len() > shown.len() {
        format!(" (+{} more)", names.len() - shown.len())
    } else {
        String::new()
    };
    let line = format!(
        "sealctl: secrets are available by name through sealctl run (names: {}{more}). Values are never shown.",
        if shown.is_empty() {
            "none yet".to_string()
        } else {
            shown.join(", ")
        }
    );
    if signs {
        format!("{line} {GIT_SIGNING_CONTEXT}")
    } else {
        line
    }
}

/// Added to the session line where git signs through sealctl: the signer prints nothing while
/// the phone is asked, so an agent would otherwise look for a prompt on the computer.
pub const GIT_SIGNING_CONTEXT: &str = "Signed git commits and tags, git push over SSH and ssh \
    wait silently for approval in the sealctl app on the user's phone (not on this computer); \
    that request is the approval, so commit whenever you normally would without asking first. \
    \"agent refused operation\" means it was declined or not answered in time.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_git_signing_line_names_the_phone() {
        assert!(GIT_SIGNING_CONTEXT.contains("phone"));
        assert!(GIT_SIGNING_CONTEXT.contains("agent refused operation"));
        // agents must not wait for the user's go-ahead before committing
        assert!(GIT_SIGNING_CONTEXT.contains("without asking first"));
        assert!(!GIT_SIGNING_CONTEXT.contains("  "), "{GIT_SIGNING_CONTEXT}");
    }

    #[test]
    fn the_session_line_mentions_git_signing_only_where_git_signs_through_sealctl() {
        let names = vec!["shop/stripe".to_string()];
        let signs = session_line(&names, true);
        assert!(signs.ends_with(GIT_SIGNING_CONTEXT), "{signs}");
        assert!(signs.contains("names: shop/stripe"), "{signs}");
        let plain = session_line(&names, false);
        assert!(!plain.contains("agent refused operation"), "{plain}");
        assert!(plain.ends_with("Values are never shown."), "{plain}");
        assert!(session_line(&[], false).contains("names: none yet"));
    }

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
            "cd x && sealctl -v secret get k",
            "sealctl recover",
            "sealctl unseal --all",
            "sealctl seal volume safe disk3s5",
            "sealctl buy",
            "sealctl git credential get",
            "cat ~/.local/share/sealctl/store/x/a.sealed",
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
            "echo \"$(date) and $(case $x in a) echo sealctl;; esac)\" done",
            "echo \"`date`\" \"$(git rev-parse HEAD)\"",
            "env FOO=bar cargo run",
            "grep -r environment src/",
            "cat README.md",
        ] {
            assert!(bash(c).is_none(), "should allow: {c}: {:?}", bash(c));
        }
    }

    #[test]
    fn variables_that_only_name_a_place_may_be_printed() {
        for c in [
            "echo $SSH_AUTH_SOCK",
            "echo \"${SSH_AUTH_SOCK}\"",
            "printenv SSH_AUTH_SOCK",
            "echo $SSH_AGENT_PID $GPG_AGENT_SOCKET",
            "echo $PASSWORD_STORE_DIR",
            "echo $KEY_FILE $SSH_KEY_PATH",
        ] {
            assert!(bash(c).is_none(), "should allow: {c}: {:?}", bash(c));
        }
        for c in [
            "echo $SSH_AUTH_SOCK $OPENAI_API_KEY",
            "echo $AUTH_TOKEN",
            "printenv github_token",
            "echo ${SOCK}${API_KEY}",
            "printf '%s %s' \"$SSH_AUTH_SOCK\" \"$DB_PASSWORD\"",
        ] {
            assert!(bash(c).is_some(), "should deny: {c}");
        }
    }

    #[test]
    fn here_documents_for_other_programs_are_text() {
        for c in [
            // what was blocked in a real session: a quoted python here-document whose text
            // mentions a denied command in backquotes
            "python3 - <<'EOF'\nnote = 'never run `sealctl buy` or $(sealctl seal x)'\nEOF",
            "cat > notes.md <<'EOF'\nRun `sealctl seal volume safe <uuid>` yourself.\nEOF\ngit status",
            "cat <<\"EOF\" > a\nsealctl buy\nEOF",
            "cat <<\\EOF\nsealctl recover\nEOF",
            // unquoted: plain text in it runs nothing
            "cat <<EOF > a\nsealctl buy\nEOF",
            "cat <<-EOF\n\tsealctl unseal --all\n\tEOF\necho done",
            "gh pr create --body-file - <<'EOF'\nDon't run sealctl secret get.\nEOF",
            "cat <<A <<'B'\nsealctl buy\nA\n`sealctl recover`\nB",
            // without `-`, a tab-indented delimiter does not end the body (bash runs nothing)
            "cat <<EOF\n\tEOF\nsealctl buy\nEOF\n",
            // a comment after the operator does not stop the here-document
            "cat <<'EOF' # notes\nsealctl buy\nEOF",
            // `#` inside a word is no comment
            "cat a#b <<'EOF'\nsealctl buy\nEOF",
            // `.` as an argument is no `source`
            "git add . && git commit -m \"$(cat <<'EOF'\nNever run `sealctl buy`.\nEOF\n)\"",
        ] {
            assert!(bash(c).is_none(), "should allow: {c:?}: {:?}", bash(c));
        }
    }

    #[test]
    fn here_documents_that_run_are_still_checked() {
        for c in [
            // a shell reads its here-document as commands
            "bash <<'EOF'\nsealctl buy\nEOF",
            "sh -s <<EOF\nsealctl secret get k\nEOF",
            "cat <<'EOF' | sh\nsealctl recover\nEOF",
            "sudo -s <<EOF\nsealctl unpair\nEOF",
            "ssh host <<'EOF'\nsealctl buy\nEOF",
            // an unquoted body still runs its substitutions
            "cat <<EOF\n$(sealctl secret get k)\nEOF",
            "cat <<EOF\nvalue: `sealctl secret get k`\nEOF",
            "cat <<EOF\n\"$(sealctl buy)\"\nEOF",
            // commands after the delimiter run
            "cat <<'EOF'\ntext\nEOF\nsealctl buy",
            "cat <<'EOF' && sealctl buy\ntext\nEOF",
            // no delimiter line: everything is read as commands
            "cat <<'EOF'\nsealctl buy",
            // shifts are no here-documents
            "x=$((1<<2))\nsealctl buy\n2",
            "x=$(( 1 << 2 ))\nsealctl buy\n2",
            "(( y = 1 << 2 ))\nsealctl buy\n2",
            // a here-string is no here-document
            "cat <<< x\nsealctl buy\nx",
            // the delimiter line must match exactly
            "cat <<'EOF'\nEOF \nsealctl buy\n EOF",
            // a `<<` in a comment opens nothing (found by review)
            "# note <<EOF\nsealctl buy\nEOF",
            "echo x # see <<'EOF'\nsealctl buy\nEOF",
            "ls;#<<EOF\nsealctl buy\nEOF",
            // old arithmetic `$[ ]`: a shift
            "x=$[1<<2]\nsealctl buy\n2]",
            "x=$[ 1 << 2 ]\nsealctl buy\n2",
            // the body reaches a shell through a pipe, group or loop continuing after it
            "cat <<'EOF' |\nsealctl buy\nEOF\nsh",
            "cat <<'EOF' | # notes\nsealctl buy\nEOF\nbash",
            "{ cat <<'EOF'\nsealctl buy\nEOF\n} | sh",
            "( cat <<'EOF'\nsealctl buy\nEOF\n) | /bin/zsh",
            "for x in 1; do cat <<'EOF'\nsealctl buy\nEOF\ndone | sh",
            "cat <<'EOF' \\\n| sh\nsealctl buy\nEOF",
            ". /dev/stdin <<'EOF'\nsealctl buy\nEOF",
            // here-documents nested deeper than HERE_DOC_LEVELS are read as commands
            "cat <<A\n$(cat <<B\n$(cat <<C\n$(cat <<D\nsealctl buy\nD\n)\nC\n)\nB\n)\nA",
        ] {
            assert!(bash(c).is_some(), "should deny: {c:?}");
        }
    }

    #[test]
    fn sealctl_subcommands_are_matched_not_words() {
        // secret names, values and other arguments that contain a denied word
        for c in [
            "sealctl run -e KEY=shop/buy -- curl https://example.test",
            "sealctl run -e T=ops/unseal-token -- make deploy",
            "sealctl run -e K=x/recover -e L=app/seal -- ./deploy.sh",
            "sealctl run --env G=git/credential -- git push",
            "sealctl run -e A=aws/credentials -- aws s3 ls",
            "sealctl run -e K=shop/get -- npm test",
            "sealctl secret set shop/buy-key --from-clipboard",
            "sealctl secret set team/unpair --from-clipboard",
            "sealctl secret mv seal/get unseal/recover",
            "sealctl secret ls | grep buy",
            "sealctl status --relay https://buy.example.test",
            "sealctl -v run -- echo seal unseal buy recover",
            "echo sealctl secret get",
            "grep -rn 'sealctl secret get' docs/",
            "git commit -m 'deny sealctl buy and sealctl unseal'",
            "sealctl volume open recover",
            "sealctl ssh ls",
            "sealctl git setup",
            "command -v sealctl",
        ] {
            assert!(bash(c).is_none(), "should allow: {c}: {:?}", bash(c));
        }
        // the denied subcommands, however they are reached
        for c in [
            "sealctl secret get k",
            "/usr/local/bin/sealctl secret get k",
            "./target/debug/sealctl secret get k",
            "cd /tmp && ~/bin/sealctl secret get k",
            "\"sealctl\" recover",
            "'sealctl' 'secret' 'get' k",
            "sealc\\tl buy",
            "sealctl -vv --relay https://r.test secret get k",
            "sealctl --relay=https://r.test unpair --yes",
            "sealctl secret --relay https://r.test get k",
            "env sealctl secret get k",
            "env -i PATH=/usr/bin FOO=1 sealctl unseal --all",
            "env -u HOME -- sealctl seal env .env --prefix p",
            "FOO=1 sealctl aws credentials --profile p",
            "command sealctl buy",
            "exec sealctl recover",
            "sudo -u me sealctl unseal secrets",
            "nohup sealctl recover &",
            "time sealctl git credential get",
            "timeout 5 sealctl secret get k",
            "xargs sealctl secret get < names.txt",
            "echo k | xargs -n 1 sealctl secret get",
            "bash -c 'sealctl secret get k'",
            "sh -lc \"sealctl unpair --yes\"",
            "eval sealctl secret get k",
            "echo \"$(sealctl secret get k)\"",
            "echo \"$(date)\"; sealctl secret get k",
            "echo \"`id`\" && sealctl recover",
            "echo \"a $(echo \"b\") c\" | sealctl unseal --all",
            "x=\"$(echo \")\")\"; sealctl buy",
            "echo \"$(case x in a) sealctl secret get k;; esac)\"",
            "echo \"$(case x in a) echo '\"';; esac)\"; sealctl secret get k",
            "echo \"$(case x in (a) y;; b) z;; esac) w\"; sealctl recover",
            "echo \"$(date)\" \"$(case x in a) y;; esac)\"; sealctl unseal --all",
            "echo \"$(case x in a) X\"; sealctl secret get k; echo \"Y)\"",
            "bash -c 'echo \"$(case x in a) X\"; sealctl secret get k; echo \"Y)\"'",
            "x=`sealctl secret get k`; echo $x",
            "if sealctl secret get k >/dev/null; then echo y; fi",
            "true && (sealctl seal ssh ~/.ssh/id_ed25519)",
            "sealctl secret get k 2>&1 | cat",
            "sealctl run -- sealctl secret get k",
            "sealctl run -e K=a/b -- env sealctl aws credentials",
            "sealctl secret import-env .env --prefix p --delete",
            "sealctl volume import safe disk3s5",
            "sealctl ssh import ~/.ssh/id_ed25519",
            "sealctl project trust",
            "cd repo && sealctl project trust .sealctl.toml",
        ] {
            assert!(bash(c).is_some(), "should deny: {c}");
        }
    }

    #[test]
    fn nested_here_documents_are_checked_in_bounded_time() {
        // each level of a here-document inside a here-document's `$(…)` is read again; past
        // HERE_DOC_LEVELS they are commands, so the work stays linear
        let started = std::time::Instant::now();
        let n = 20_000;
        let mut line = String::new();
        for k in 0..n {
            line.push_str(&format!("cat <<E{k}\n$("));
        }
        line.push_str("sealctl buy\n");
        for k in (0..n).rev() {
            line.push_str(&format!(")\nE{k}\n"));
        }
        assert!(bash(&line).is_some(), "should deny");
        let took = started.elapsed();
        assert!(took < std::time::Duration::from_secs(15), "took {took:?}");
    }

    #[test]
    fn keyword_only_lines_are_checked_in_linear_time() {
        // a `case` counts only after keywords; that check must not rescan the command per word
        let started = std::time::Instant::now();
        let line = format!("{}; sealctl secret get k", "do ".repeat(100_000));
        let why = bash(&line);
        assert!(
            why.as_deref()
                .is_some_and(|w| w.contains("secret get") || w.contains(TOO_COMPLEX)),
            "should deny: {why:?}"
        );
        let eval = format!("eval {}; sealctl secret get k", "do ".repeat(100_000));
        assert!(bash(&eval).is_some(), "should deny the eval form");
        let took = started.elapsed();
        // normally well under a second; the quadratic rescan took tens of seconds. The limit is
        // the hook's own timeout (15 s), so a loaded CI machine does not fail it by chance
        assert!(took < std::time::Duration::from_secs(15), "took {took:?}");
        // `case` after keywords still opens a case
        assert!(bash("if case x in a) sealctl secret get k ;; esac").is_some());
    }

    #[test]
    fn oversized_command_lines_are_denied() {
        let line = format!("{}; true", "x".repeat(MAX_COMMAND_BYTES));
        assert_eq!(
            bash(&line).as_deref(),
            Some(format!("sealctl: {TOO_COMPLEX}").as_str())
        );
    }

    #[test]
    fn nested_commands_are_checked_in_bounded_time() {
        // many distinct `eval` and `sh -c` chains, each nested as deep as is checked, then a
        // denied command: every reading of every level used to be looked into separately
        // (4^depth work per chain)
        let chains: Vec<String> = (0..300)
            .map(|i| {
                if i % 2 == 0 {
                    format!("eval eval eval eval eval eval eval eval x{i}")
                } else {
                    format!("bash -c 'eval eval eval eval eval eval eval y{i}'")
                }
            })
            .collect();
        let line = format!("{} ; sealctl secret get k", chains.join(" ; "));
        let started = std::time::Instant::now();
        let why = bash(&line);
        let took = started.elapsed();
        assert!(
            why.as_deref().is_some_and(|w| w.contains("secret get")),
            "should deny: {why:?}"
        );
        // the hook's own timeout (15 s), as above: the exponential case took far longer, and a
        // loaded machine must not fail it by chance
        assert!(took < std::time::Duration::from_secs(15), "took {took:?}");
        // the chains alone are fine
        assert!(bash(&chains.join(" ; ")).is_none());

        // deeper than is checked: denied, not let through
        for c in [
            "eval eval eval eval eval eval eval eval eval sealctl secret get k",
            "eval eval eval eval eval eval eval eval eval x",
            "sh -c \"sh -c 'eval eval eval eval eval eval eval eval x'\"",
        ] {
            assert_eq!(
                bash(c).as_deref(),
                Some(format!("sealctl: {TOO_COMPLEX}").as_str()),
                "{c}"
            );
        }
        // when the budget runs out, the command is denied
        let mut budget = 100;
        assert_eq!(
            sealctl_in(&"echo hello ".repeat(10), 0, &mut budget),
            Some(TOO_COMPLEX)
        );
        let mut budget = 1000;
        assert_eq!(sealctl_in(&"echo hello ".repeat(10), 0, &mut budget), None);
    }

    #[test]
    fn git_credential_fill_and_the_agent_switch() {
        for c in [
            "printf 'host=github.com\\n' | git credential fill",
            "echo host=github.com | git -c credential.helper= credential fill",
            "git -C /repo credential fill < req",
            "git credential-osxkeychain get",
            "git credential-store get",
            "SEALCTL_AGENT=0 sealctl secret ls",
            "CLAUDECODE= sealctl run -- env",
            "env -u CLAUDECODE sealctl git credential get",
            "unset CLAUDECODE; git push",
            "export SEALCTL_AGENT=0",
            "env SEALCTL_AGENT=0 aws s3 ls",
        ] {
            assert!(bash(c).is_some(), "should deny: {c}");
        }
        for c in [
            "git push origin main",
            "git credential approve < x",
            "git log --grep credential",
            "git config --get credential.helper",
            "grep -rn SEALCTL_AGENT src/",
            "echo $CLAUDECODE",
            "export PATH=$PATH:/x",
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
        for g in [
            ".env*",
            "**/.env",
            ".env.*",
            "{.env,.env.local}",
            "*.pem",
            ".env *.rs",
            "*.rs .env",
            "*.rs,.env.local",
            "*.{rs,pem}",
            "**/{src,.}/.env",
            "{*.rs,{.env,x}}",
        ] {
            assert!(search("/p", g).is_some(), "should deny: {g}");
        }
        for g in [
            "",
            "*.rs",
            "**/*.{ts,tsx}",
            ".env.example",
            "src/**",
            "*.rs *.toml",
            "{.env.example,.env.sample}",
            "{unclosed",
        ] {
            assert!(search("/p", g).is_none(), "should allow: {g}");
        }
        assert!(write(
            "/p/config.ts",
            "const key = 'sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123'"
        )
        .is_some());
        assert!(write("/p/config.ts", "const key = process.env.ANTHROPIC_API_KEY").is_none());
    }
}
