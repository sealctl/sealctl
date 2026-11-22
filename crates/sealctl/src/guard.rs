//! Keeping secrets away from AI coding agents: agent detection, a detector for pasted API keys,
//! and output masking for `sealctl run`.
//!
//! The rule: an agent may *use* secrets (`sealctl run` puts them in a program's environment) but
//! never *see* them. Hooks for each agent call into this module (see `ai.rs`).

use std::io::{Read, Write};
use std::sync::OnceLock;

use regex::Regex;

/// Environment variables that AI coding agents set for the commands they run.
const AGENT_ENV: &[(&str, &str)] = &[
    ("CLAUDECODE", "Claude Code"),
    ("CLAUDE_CODE_CHILD_SESSION", "Claude Code"),
    ("CODEX_THREAD_ID", "Codex"),
    ("CODEX_CI", "Codex"),
    ("CODEX_SANDBOX", "Codex"),
    ("GEMINI_CLI", "Gemini CLI"),
    ("GEMINI_CLI_IN_SHELL", "Gemini CLI"),
    ("QWEN_CODE", "Qwen Code"),
    ("COPILOT_AGENT_SESSION_ID", "Copilot CLI"),
    ("CURSOR_AGENT", "Cursor"),
    ("OPENCODE", "OpenCode"),
    ("OPENCODE_SESSION_ID", "OpenCode"),
    ("AI_AGENT", "an AI agent"),
];

/// The variables that mark a command as run by an agent (`SEALCTL_AGENT` first).
pub fn agent_variables() -> impl Iterator<Item = &'static str> {
    std::iter::once("SEALCTL_AGENT").chain(AGENT_ENV.iter().map(|(v, _)| *v))
}

/// The AI agent running this process, if one is recognisable. `SEALCTL_AGENT=1` forces it
/// (for agents we don't recognise yet); `SEALCTL_AGENT=0` disables detection.
pub fn ai_agent() -> Option<&'static str> {
    match std::env::var("SEALCTL_AGENT").ok().as_deref() {
        Some("0") => return None,
        Some(v) if !v.is_empty() => return Some("an AI agent"),
        _ => {}
    }
    AGENT_ENV
        .iter()
        .find(|(var, _)| std::env::var_os(var).is_some_and(|v| !v.is_empty()))
        .map(|(_, name)| *name)
}

/// Refuse to put a secret on stdout when an agent (or a terminal's scrollback) would keep it.
/// `show`: the user asked for it explicitly.
pub fn may_print_secret(show: bool) -> Result<(), String> {
    use std::io::IsTerminal;
    if let Some(agent) = ai_agent() {
        return Err(format!(
            "refusing to print a secret inside {agent} — it would enter the conversation.\n   \
             Use `sealctl run -- <command>` (the program gets it, the agent doesn't), or --clip."
        ));
    }
    if std::io::stdout().is_terminal() && !show {
        return Err(
            "not printing a secret to the terminal (scrollback, screen sharing).\n   \
             Use --clip to copy it (cleared after 30 s), --show to print anyway, or pipe it."
                .into(),
        );
    }
    Ok(())
}

/// A detected secret-looking string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub kind: &'static str,
    /// The match with most of it hidden, safe to show.
    pub preview: String,
}

fn patterns() -> &'static [(&'static str, Regex)] {
    static P: OnceLock<Vec<(&'static str, Regex)>> = OnceLock::new();
    P.get_or_init(|| {
        [
            ("Anthropic API key", r"sk-ant-[A-Za-z0-9_\-]{20,}"),
            ("OpenAI API key", r"sk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{32,}"),
            ("GitHub token", r"gh[pousr]_[A-Za-z0-9]{36,}"),
            ("GitHub token", r"github_pat_[A-Za-z0-9_]{40,}"),
            ("GitLab token", r"glpat-[A-Za-z0-9_\-]{20,}"),
            ("AWS access key id", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
            ("Google API key", r"AIza[0-9A-Za-z_\-]{35}"),
            ("Slack token", r"xox[abposr]-[A-Za-z0-9\-]{10,}"),
            ("Stripe key", r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}"),
            ("Cloudflare token", r"\bcf[a-z]t_[A-Za-z0-9_\-]{30,}"),
            ("Hugging Face token", r"\bhf_[A-Za-z0-9]{30,}"),
            ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b"),
            ("private key", r"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----"),
            (
                "credential",
                r#"(?i)(?:api[_\-]?key|secret|token|passw(?:or)?d|access[_\-]?key|auth)[A-Za-z0-9_\-]*["']?\s*[:=]\s*["']?([A-Za-z0-9_\-/+=.]{20,})"#,
            ),
        ]
        .into_iter()
        .map(|(k, re)| (k, Regex::new(re).expect("valid pattern")))
        .collect()
    })
}

/// Bits of Shannon entropy per character.
fn entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    for b in s.bytes() {
        counts[b as usize] += 1;
    }
    let n = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / n;
            -p * p.log2()
        })
        .sum()
}

fn preview(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let head: String = chars.iter().take(6).collect();
    format!("{head}…({} chars)", chars.len())
}

/// The secret-looking values in `text` with their kind (for `scan`, which masks them in
/// shell histories). Same rules as [`mask_command`].
pub fn find_secret_values(text: &str) -> Vec<(&'static str, String)> {
    let mut out = Vec::new();
    for (kind, re) in patterns() {
        for cap in re.captures_iter(text) {
            let m = cap.get(1).unwrap_or_else(|| cap.get(0).expect("match"));
            if *kind == "credential" && entropy(m.as_str()) < 3.5 {
                continue;
            }
            if *kind == "private key" {
                continue;
            }
            out.push((*kind, m.as_str().to_string()));
        }
    }
    out
}

/// `text` with every secret-looking substring replaced by `****` (commands shown on the phone).
pub fn mask_command(text: &str) -> String {
    let mut out = text.to_string();
    for (kind, re) in patterns() {
        let mut spans: Vec<(usize, usize)> = Vec::new();
        for cap in re.captures_iter(&out) {
            let m = cap.get(1).unwrap_or_else(|| cap.get(0).expect("match"));
            if *kind == "credential" && entropy(m.as_str()) < 3.5 {
                continue;
            }
            spans.push((m.start(), m.end()));
        }
        for (a, b) in spans.into_iter().rev() {
            out.replace_range(a..b, "****");
        }
    }
    out
}

/// Secret-looking strings in `text`. Known token formats always count; a generic
/// `key = value` only when the value looks random (so `password = hunter2` or a path doesn't).
pub fn find_secrets(text: &str) -> Vec<Finding> {
    let mut out: Vec<Finding> = Vec::new();
    for (kind, re) in patterns() {
        for cap in re.captures_iter(text) {
            let m = cap.get(1).unwrap_or_else(|| cap.get(0).expect("match"));
            let s = m.as_str();
            if *kind == "credential" && (entropy(s) < 3.5 || s.contains('/') && !s.contains('+')) {
                continue;
            }
            let f = Finding {
                kind,
                preview: preview(s),
            };
            if !out.contains(&f) {
                out.push(f);
            }
        }
    }
    out
}

// ---- output masking ----

fn base64(data: &[u8], url: bool) -> Vec<u8> {
    let alphabet: &[u8; 64] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = Vec::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        for i in 0..=chunk.len() {
            out.push(alphabet[((n >> (18 - 6 * i)) & 63) as usize]);
        }
    }
    if !url {
        while out.len() % 4 != 0 {
            out.push(b'=');
        }
    }
    out
}

fn percent(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    for &b in data {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            out.push(b);
        } else {
            out.extend_from_slice(format!("%{b:02X}").as_bytes());
        }
    }
    out
}

/// Replaces secret values in a byte stream with `****`: as-is, base64 (e.g. HTTP Basic auth
/// headers, which also hide `user:value` — that combination is not detected) and URL-encoded;
/// also when a value is split across reads or overlaps another. Values shorter than 6 bytes
/// are not masked (too many false hits).
pub struct Masker {
    secrets: Vec<Vec<u8>>,
    keep: usize,
    buf: Vec<u8>,
    /// bytes at the start of `buf` already written out
    emitted: usize,
    /// the last byte written was part of a masked run
    in_mask: bool,
}

impl Masker {
    pub fn new<I: IntoIterator<Item = Vec<u8>>>(values: I) -> Self {
        let mut secrets: Vec<Vec<u8>> = Vec::new();
        for v in values.into_iter().filter(|v| v.len() >= 6) {
            secrets.push(base64(&v, false));
            secrets.push(base64(&v, true));
            let p = percent(&v);
            if p != v {
                secrets.push(p);
            }
            secrets.push(v);
        }
        secrets.sort();
        secrets.dedup();
        let keep = secrets.iter().map(Vec::len).max().unwrap_or(1).saturating_sub(1);
        Masker {
            secrets,
            keep,
            buf: Vec::new(),
            emitted: 0,
            in_mask: false,
        }
    }

    fn process(&mut self, last: bool) -> Vec<u8> {
        let len = self.buf.len();
        let mut covered = vec![false; len];
        for i in 0..len {
            for s in &self.secrets {
                if self.buf[i..].starts_with(s) {
                    covered[i..i + s.len()].iter_mut().for_each(|c| *c = true);
                }
            }
        }
        // Everything before `limit` is final: a match covering it would have to start before
        // `limit` and, being at most keep+1 long, already be complete in `buf`.
        let mut limit = if last { len } else { len.saturating_sub(self.keep) };
        limit = limit.max(self.emitted);
        while limit > 0 && limit < len && covered[limit - 1] && covered[limit] {
            limit += 1; // don't split a masked run
        }
        let mut out = Vec::new();
        for (i, b) in self.buf.iter().enumerate().take(limit).skip(self.emitted) {
            if covered[i] {
                if !self.in_mask {
                    out.extend_from_slice(b"****");
                }
                self.in_mask = true;
            } else {
                out.push(*b);
                self.in_mask = false;
            }
        }
        self.emitted = limit;
        // keep what a match still being received could start in
        let keep_from = self.emitted.min(len.saturating_sub(self.keep));
        self.buf.drain(..keep_from);
        self.emitted -= keep_from;
        out
    }

    /// Feed bytes; returns what can be safely emitted now.
    pub fn push(&mut self, data: &[u8]) -> Vec<u8> {
        if self.secrets.is_empty() {
            return data.to_vec();
        }
        self.buf.extend_from_slice(data);
        self.process(false)
    }

    pub fn finish(&mut self) -> Vec<u8> {
        if self.secrets.is_empty() {
            return std::mem::take(&mut self.buf);
        }
        self.process(true)
    }
}

/// Copy `from` to `to`, masking secrets.
pub fn mask_stream(mut from: impl Read, mut to: impl Write, secrets: Vec<Vec<u8>>) -> std::io::Result<()> {
    let mut m = Masker::new(secrets);
    let mut chunk = [0u8; 8192];
    loop {
        let n = from.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        to.write_all(&m.push(&chunk[..n]))?;
        to.flush()?;
    }
    to.write_all(&m.finish())?;
    to.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_known_formats() {
        let text =
            "here: sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123 and ghp_0123456789abcdefghijABCDEFGHIJ012345";
        let kinds: Vec<_> = find_secrets(text).into_iter().map(|f| f.kind).collect();
        assert!(kinds.contains(&"Anthropic API key"), "{kinds:?}");
        assert!(kinds.contains(&"GitHub token"), "{kinds:?}");
        let f = &find_secrets("AKIAIOSFODNN7EXAMPLE")[0];
        assert_eq!(f.kind, "AWS access key id");
        assert!(!f.preview.contains("FODNN7EXAMPLE"), "preview hides the value");
    }

    #[test]
    fn generic_credentials_need_randomness() {
        assert!(!find_secrets("OPENAI_API_KEY=xK9fQ2mZ7pL4vR8tW1nB6cY3").is_empty());
        assert!(find_secrets("password = aaaaaaaaaaaaaaaaaaaaaaaa").is_empty());
        assert!(find_secrets("token: /usr/local/share/some/long/path/here").is_empty());
        assert!(find_secrets("let me know how to store an api key").is_empty());
        // hashes and UUIDs in ordinary text are not flagged
        assert!(
            find_secrets("commit 5baf0dc2a7c4e1f9 and 0dc23bb, id fa5a93d5-28d9-4c08-b608-c2b6f344b4d8")
                .is_empty()
        );
    }

    #[test]
    fn masks_across_chunk_boundaries() {
        let secret = b"s3cr3t-VALUE-123".to_vec();
        let input = b"before s3cr3t-VALUE-123 middle s3cr3t-VALUE-123 after".to_vec();
        for split in 1..input.len() {
            let mut m = Masker::new(vec![secret.clone()]);
            let mut out = m.push(&input[..split]);
            out.extend(m.push(&input[split..]));
            out.extend(m.finish());
            assert_eq!(
                String::from_utf8(out).unwrap(),
                "before **** middle **** after",
                "split at {split}"
            );
        }
    }

    fn run(secrets: &[&[u8]], input: &[u8], split: usize) -> String {
        let mut m = Masker::new(secrets.iter().map(|s| s.to_vec()));
        let mut out = m.push(&input[..split]);
        out.extend(m.push(&input[split..]));
        out.extend(m.finish());
        String::from_utf8_lossy(&out).into_owned()
    }

    #[test]
    fn overlapping_and_encoded_secrets() {
        let a: &[u8] = b"abcdefXYZ";
        let b: &[u8] = b"XYZsupersecrettoken123";
        let input = b"x abcdefXYZsupersecrettoken123 y".to_vec();
        for split in 0..=input.len() {
            let out = run(&[a, b], &input, split);
            assert_eq!(out, "x **** y", "split {split}");
        }
        let token: &[u8] = b"ghp_token-value/with+chars";
        let basic = format!(
            "Authorization: Basic {}",
            String::from_utf8(base64(token, false)).unwrap()
        );
        assert_eq!(run(&[token], basic.as_bytes(), 10), "Authorization: Basic ****");
        let url = format!("https://x/?t={}", String::from_utf8(percent(token)).unwrap());
        assert_eq!(run(&[token], url.as_bytes(), 5), "https://x/?t=****");
    }

    #[test]
    fn fuzz_never_leaks() {
        // random secrets and random text containing them, random chunking: no secret survives
        let mut seed = 12345u64;
        let mut rnd = move |n: u64| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed % n
        };
        for _ in 0..300 {
            let secrets: Vec<Vec<u8>> = (0..1 + rnd(3))
                .map(|_| (0..6 + rnd(10)).map(|_| b"abcxyz"[rnd(6) as usize]).collect())
                .collect();
            let mut text = Vec::new();
            for _ in 0..20 {
                if rnd(3) == 0 {
                    text.extend_from_slice(&secrets[rnd(secrets.len() as u64) as usize]);
                } else {
                    text.push(b"abcxyz "[rnd(7) as usize]);
                }
            }
            let mut m = Masker::new(secrets.clone());
            let mut out = Vec::new();
            let mut i = 0;
            while i < text.len() {
                let n = 1 + rnd(8) as usize;
                out.extend(m.push(&text[i..(i + n).min(text.len())]));
                i += n;
            }
            out.extend(m.finish());
            for s in &secrets {
                assert!(
                    !out.windows(s.len()).any(|w| w == s.as_slice()),
                    "secret {:?} leaked in {:?}",
                    String::from_utf8_lossy(s),
                    String::from_utf8_lossy(&out)
                );
            }
        }
    }

    #[test]
    fn short_values_are_not_masked() {
        let mut m = Masker::new(vec![b"abc".to_vec()]);
        let mut out = m.push(b"abc abc");
        out.extend(m.finish());
        assert_eq!(out, b"abc abc");
    }
}
