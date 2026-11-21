//! Editing `~/.ssh/config` (and the files it `Include`s) and shell rc files when SSH keys leave
//! sealctl. Line based: comments, order, indentation and `Host`/`Match` blocks stay as they
//! are; only the lines below change.
//!
//! * `IdentityAgent <sealctl's socket>`: removed (once no sealctl key is left);
//! * `IdentityFile …/sealctl_<name>[.pub]`: pointed at the handed-back key file;
//! * macOS: `UseKeychain yes` and `AddKeysToAgent yes` under `Host *` when missing;
//! * shell rc files: `export SSH_AUTH_SOCK=<sealctl's socket>` commented out.

use std::path::{Path, PathBuf};

/// What to change.
#[derive(Debug, Clone, Default)]
pub struct Edit {
    /// Remove `IdentityAgent` lines naming sealctl's socket.
    pub remove_agent: bool,
    /// `sealctl_<name>` → the new key file, as it should be written (`~/.ssh/<name>`).
    pub renames: Vec<(String, String)>,
    /// Add `UseKeychain yes` / `AddKeysToAgent yes` under `Host *` (macOS).
    pub keychain: bool,
}

/// Does a socket path name sealctl's SSH agent?
pub fn is_sealctl_socket(value: &str, socket: &Path) -> bool {
    let v = unquote(value.trim());
    if v.contains("sealctl/ssh-agent.sock") {
        return true;
    }
    let home = std::env::var("HOME").unwrap_or_default();
    let expanded = if let Some(rest) = v.strip_prefix("~/") {
        format!("{home}/{rest}")
    } else {
        v.replace("${HOME}", &home).replace("$HOME", &home)
    };
    Path::new(&expanded) == socket
}

fn unquote(s: &str) -> &str {
    s.strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .or_else(|| s.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')))
        .unwrap_or(s)
}

/// Split a config line into (indent, keyword, separator, value, trailing). `None` for blank
/// lines and comments.
fn split(line: &str) -> Option<(&str, &str, &str, &str)> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || trimmed.starts_with('#') {
        return None;
    }
    let indent = &line[..line.len() - trimmed.len()];
    let kw_end = trimmed
        .find(|c: char| c.is_whitespace() || c == '=')
        .unwrap_or(trimmed.len());
    let keyword = &trimmed[..kw_end];
    let rest = &trimmed[kw_end..];
    let value_start = rest
        .find(|c: char| !(c.is_whitespace() || c == '='))
        .unwrap_or(rest.len());
    let sep = &rest[..value_start];
    let value = rest[value_start..].trim_end();
    Some((indent, keyword, sep, value))
}

/// The key file name an `IdentityFile` value names, if it is one of sealctl's.
fn sealctl_key_name(value: &str) -> Option<(String, bool)> {
    let v = unquote(value.trim());
    let file = v.rsplit('/').next()?;
    let (stem, is_pub) = match file.strip_suffix(".pub") {
        Some(s) => (s, true),
        None => (file, false),
    };
    stem.starts_with("sealctl_").then(|| (stem.to_string(), is_pub))
}

/// Rewrite one config file's text. Returns the new text and whether anything changed.
/// `main`: the top-level `~/.ssh/config` (where a missing `Host *` block may be added).
pub fn rewrite(text: &str, edit: &Edit, socket: &Path, main: bool) -> (String, bool) {
    let mut out: Vec<String> = Vec::new();
    let mut changed = false;
    // for UseKeychain/AddKeysToAgent: is each set before the first Host/Match, or in `Host *`?
    let mut in_star = false;
    let mut before_first_block = true;
    let mut star_header: Option<usize> = None;
    let mut have_use_keychain = false;
    let mut have_add_keys = false;
    let mut star_indent = String::from("    ");
    for line in text.split_inclusive('\n') {
        let (body, nl) = match line.strip_suffix('\n') {
            Some(b) => (b, "\n"),
            None => (line, ""),
        };
        let Some((indent, keyword, sep, value)) = split(body) else {
            out.push(line.to_string());
            continue;
        };
        let kw = keyword.to_ascii_lowercase();
        if kw == "host" || kw == "match" {
            before_first_block = false;
            in_star = kw == "host" && value.split_whitespace().collect::<Vec<_>>() == ["*"];
            out.push(line.to_string());
            if in_star && star_header.is_none() {
                star_header = Some(out.len() - 1);
            }
            continue;
        }
        if in_star && star_header == Some(out.len() - 1) && !indent.is_empty() {
            star_indent = indent.to_string();
        }
        if (in_star || before_first_block) && kw == "usekeychain" {
            have_use_keychain = true;
        }
        if (in_star || before_first_block) && kw == "addkeystoagent" {
            have_add_keys = true;
        }
        if kw == "identityagent" && edit.remove_agent && is_sealctl_socket(value, socket) {
            changed = true;
            continue;
        }
        if kw == "identityfile" {
            if let Some((stem, _is_pub)) = sealctl_key_name(value) {
                if let Some((_, new)) = edit.renames.iter().find(|(old, _)| *old == stem) {
                    let quoted = value.trim_start().starts_with('"');
                    let new_value = if quoted { format!("\"{new}\"") } else { new.clone() };
                    out.push(format!("{indent}{keyword}{sep}{new_value}{nl}"));
                    changed = true;
                    continue;
                }
            }
        }
        out.push(line.to_string());
    }
    if edit.keychain && (!have_use_keychain || !have_add_keys) {
        let mut add = String::new();
        let ind = star_indent.clone();
        if !have_use_keychain {
            add.push_str(&format!("{ind}UseKeychain yes\n"));
        }
        if !have_add_keys {
            add.push_str(&format!("{ind}AddKeysToAgent yes\n"));
        }
        match star_header {
            Some(i) => {
                if !out[i].ends_with('\n') {
                    out[i].push('\n');
                }
                out.insert(i + 1, add);
                changed = true;
            }
            None if main => {
                if out.last().is_some_and(|l| !l.ends_with('\n')) {
                    out.push("\n".into());
                }
                if !out.is_empty() {
                    out.push("\n".into());
                }
                out.push(format!("Host *\n{add}"));
                changed = true;
            }
            None => {}
        }
    }
    (out.concat(), changed)
}

/// `~/.ssh/config` and every file it includes (globs in the last path component), in order.
pub fn config_files(ssh_dir: &Path) -> Vec<PathBuf> {
    let main = ssh_dir.join("config");
    let mut out = vec![];
    let mut queue = vec![main];
    while let Some(f) = queue.pop() {
        if out.contains(&f) || out.len() > 64 {
            continue;
        }
        let Ok(text) = std::fs::read_to_string(&f) else {
            continue;
        };
        out.push(f.clone());
        let mut includes = vec![];
        for line in text.lines() {
            let Some((_, kw, _, value)) = split(line) else {
                continue;
            };
            if !kw.eq_ignore_ascii_case("include") {
                continue;
            }
            for pat in value.split_whitespace() {
                includes.extend(expand(unquote(pat), ssh_dir));
            }
        }
        // keep file order: push in reverse onto the stack
        for i in includes.into_iter().rev() {
            queue.push(i);
        }
    }
    out
}

fn expand(pat: &str, ssh_dir: &Path) -> Vec<PathBuf> {
    let home = std::env::var("HOME").unwrap_or_default();
    let p = if let Some(rest) = pat.strip_prefix("~/") {
        PathBuf::from(&home).join(rest)
    } else if pat.starts_with('/') {
        PathBuf::from(pat)
    } else {
        ssh_dir.join(pat)
    };
    let name = p
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    if !name.contains(['*', '?']) {
        return vec![p];
    }
    let dir = p.parent().map(Path::to_path_buf).unwrap_or_default();
    let mut v: Vec<PathBuf> = std::fs::read_dir(&dir)
        .map(|rd| {
            rd.flatten()
                .filter(|e| wildcard(&name, &e.file_name().to_string_lossy()))
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect()
        })
        .unwrap_or_default();
    v.sort();
    v
}

/// `*` and `?` matching.
fn wildcard(pat: &str, s: &str) -> bool {
    let (p, s): (Vec<char>, Vec<char>) = (pat.chars().collect(), s.chars().collect());
    fn go(p: &[char], s: &[char]) -> bool {
        match (p.first(), s.first()) {
            (None, None) => true,
            (Some('*'), _) => go(&p[1..], s) || (!s.is_empty() && go(p, &s[1..])),
            (Some('?'), Some(_)) => go(&p[1..], &s[1..]),
            (Some(a), Some(b)) if a == b => go(&p[1..], &s[1..]),
            _ => false,
        }
    }
    go(&p, &s)
}

/// Shell start-up files that may export `SSH_AUTH_SOCK`.
pub fn rc_files(home: &Path) -> Vec<PathBuf> {
    [
        ".zshrc",
        ".bashrc",
        ".bash_profile",
        ".profile",
        ".zprofile",
        ".config/fish/config.fish",
    ]
    .iter()
    .map(|f| home.join(f))
    .filter(|p| p.is_file())
    .collect()
}

pub const RC_MARK: &str = "# removed by sealctl unseal: ";

/// Comment out lines that point `SSH_AUTH_SOCK` at sealctl's socket.
pub fn rewrite_rc(text: &str, socket: &Path) -> (String, bool) {
    let mut changed = false;
    let mut out = String::with_capacity(text.len() + 64);
    for line in text.split_inclusive('\n') {
        let t = line.trim_start();
        let sets = !t.starts_with('#')
            && t.contains("SSH_AUTH_SOCK")
            && (t.starts_with("export ")
                || t.starts_with("SSH_AUTH_SOCK=")
                || t.starts_with("set ")
                || t.starts_with("setenv "));
        let value = t
            .split_once("SSH_AUTH_SOCK")
            .map(|(_, r)| r.trim_start_matches(['=', ' ', '\t']))
            .unwrap_or("");
        let value = value.split([';', '#']).next().unwrap_or("").trim();
        if sets && is_sealctl_socket(value, socket) {
            out.push_str(RC_MARK);
            out.push_str(line.trim_start());
            if !line.ends_with('\n') {
                out.push('\n');
            }
            changed = true;
        } else {
            out.push_str(line);
        }
    }
    (out, changed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sock() -> PathBuf {
        PathBuf::from("/home/u/.local/state/sealctl/ssh-agent.sock")
    }

    fn edit(keychain: bool) -> Edit {
        Edit {
            remove_agent: true,
            renames: vec![("sealctl_ed25519".into(), "~/.ssh/ed25519".into())],
            keychain,
        }
    }

    #[test]
    fn host_and_match_blocks_comments_and_order_are_kept() {
        let text = "# my config\n\
                    Include config.d/*\n\
                    \n\
                    Host github.com\n\
                    \tIdentityFile ~/.ssh/sealctl_ed25519.pub   \n\
                    \tIdentitiesOnly yes\n\
                    Match host *.corp exec \"true\"\n\
                    \x20   IdentityAgent \"~/.local/state/sealctl/ssh-agent.sock\"\n\
                    \x20   User me # trailing\n\
                    Host *\n\
                    \x20 IdentityAgent=/home/u/.local/state/sealctl/ssh-agent.sock\n\
                    \x20 ServerAliveInterval 30\n";
        let (out, changed) = rewrite(text, &edit(false), &sock(), true);
        assert!(changed);
        assert_eq!(
            out,
            "# my config\n\
             Include config.d/*\n\
             \n\
             Host github.com\n\
             \tIdentityFile ~/.ssh/ed25519\n\
             \tIdentitiesOnly yes\n\
             Match host *.corp exec \"true\"\n\
             \x20   User me # trailing\n\
             Host *\n\
             \x20 ServerAliveInterval 30\n"
        );
        // idempotent
        let (again, changed) = rewrite(&out, &edit(false), &sock(), true);
        assert!(!changed);
        assert_eq!(again, out);
    }

    #[test]
    fn keychain_lines_go_under_host_star() {
        let text = "Host *\n    ServerAliveInterval 30\nHost b\n    User x\n";
        let (out, _) = rewrite(text, &edit(true), &sock(), true);
        assert_eq!(
            out,
            "Host *\n    UseKeychain yes\n    AddKeysToAgent yes\n    ServerAliveInterval 30\nHost b\n    User x\n"
        );
        // already there: unchanged
        let (_, changed) = rewrite(&out, &edit(true), &sock(), true);
        assert!(!changed);
        // no Host * block: one is added at the end of the main file only
        let (out, changed) = rewrite("Host b\n  User x", &edit(true), &sock(), true);
        assert!(changed);
        assert_eq!(
            out,
            "Host b\n  User x\n\nHost *\n    UseKeychain yes\n    AddKeysToAgent yes\n"
        );
        let (out, changed) = rewrite("Host b\n  User x\n", &edit(true), &sock(), false);
        assert!(!changed);
        assert_eq!(out, "Host b\n  User x\n");
        // set globally before any block counts
        let (_, changed) = rewrite(
            "UseKeychain yes\nAddKeysToAgent yes\nHost b\n  User x\n",
            &edit(true),
            &sock(),
            true,
        );
        assert!(!changed);
    }

    #[test]
    fn other_agents_and_keys_are_left_alone() {
        let text = "Host x\n  IdentityAgent ~/.1password/agent.sock\n  IdentityFile ~/.ssh/id_rsa\n  IdentityFile \"~/.ssh/sealctl_ed25519\"\n";
        let (out, _) = rewrite(text, &edit(false), &sock(), false);
        assert_eq!(
            out,
            "Host x\n  IdentityAgent ~/.1password/agent.sock\n  IdentityFile ~/.ssh/id_rsa\n  IdentityFile \"~/.ssh/ed25519\"\n"
        );
        // agent lines stay while other sealctl keys are still in use
        let keep = Edit {
            remove_agent: false,
            ..edit(false)
        };
        let (out, _) = rewrite(
            "IdentityAgent ~/.local/state/sealctl/ssh-agent.sock\n",
            &keep,
            &sock(),
            true,
        );
        assert_eq!(out, "IdentityAgent ~/.local/state/sealctl/ssh-agent.sock\n");
    }

    #[test]
    fn includes_are_followed() {
        let t = tempfile::tempdir().unwrap();
        let ssh = t.path();
        std::fs::create_dir_all(ssh.join("config.d")).unwrap();
        std::fs::write(ssh.join("config"), "Include config.d/* extra\nHost *\n").unwrap();
        std::fs::write(ssh.join("config.d/b"), "Host b\n").unwrap();
        std::fs::write(ssh.join("config.d/a"), "Include nested\n").unwrap();
        std::fs::write(ssh.join("extra"), "Host e\n").unwrap();
        std::fs::write(ssh.join("nested"), "Host n\n").unwrap();
        let files: Vec<String> = config_files(ssh)
            .iter()
            .map(|p| p.strip_prefix(ssh).unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(files, ["config", "config.d/a", "nested", "config.d/b", "extra"]);
    }

    #[test]
    fn rc_lines() {
        let text = "export PATH=x\n\
                    export SSH_AUTH_SOCK=~/.local/state/sealctl/ssh-agent.sock\n\
                    export SSH_AUTH_SOCK=\"$HOME/.local/state/sealctl/ssh-agent.sock\" # sealctl\n\
                    # export SSH_AUTH_SOCK=~/.local/state/sealctl/ssh-agent.sock\n\
                    export SSH_AUTH_SOCK=/tmp/other.sock\n\
                    set -gx SSH_AUTH_SOCK /home/u/.local/state/sealctl/ssh-agent.sock\n";
        let (out, changed) = rewrite_rc(text, &sock());
        assert!(changed);
        assert_eq!(
            out,
            "export PATH=x\n\
             # removed by sealctl unseal: export SSH_AUTH_SOCK=~/.local/state/sealctl/ssh-agent.sock\n\
             # removed by sealctl unseal: export SSH_AUTH_SOCK=\"$HOME/.local/state/sealctl/ssh-agent.sock\" # sealctl\n\
             # export SSH_AUTH_SOCK=~/.local/state/sealctl/ssh-agent.sock\n\
             export SSH_AUTH_SOCK=/tmp/other.sock\n\
             # removed by sealctl unseal: set -gx SSH_AUTH_SOCK /home/u/.local/state/sealctl/ssh-agent.sock\n"
        );
        assert!(!rewrite_rc(&out, &sock()).1);
    }
}
