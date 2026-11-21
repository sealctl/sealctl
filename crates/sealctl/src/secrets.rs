//! Secret store for API keys and tokens.
//!
//! One `<name>.gpg` file per secret: a standard OpenPGP message encrypted with a **password
//! derived from the Ledger seed** (`crate::derive`, purpose "secrets"). Nothing else is needed
//! to read the store later — only the 24 words. Reading/writing goes through the sealctl agent,
//! so the PIN is entered once per session. The store is local only (no git).

use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use zeroize::Zeroizing;

use pgp::composed::{Message, MessageBuilder};
use pgp::crypto::sym::SymmetricKeyAlgorithm;
use pgp::types::{Password, StringToKey};
use rand::thread_rng;

use crate::derive::{self, Oracle, Purpose};
use crate::paths;

/// The store key: derived from the seed, used as the OpenPGP message password.
fn store_password(oracle: &mut dyn Oracle) -> Result<Zeroizing<String>> {
    derive::passphrase(oracle, Purpose::Secrets, "store")
}

fn seal(password: &str, value: &[u8]) -> Result<Vec<u8>> {
    let mut b =
        MessageBuilder::from_bytes("", value.to_vec()).seipd_v1(thread_rng(), SymmetricKeyAlgorithm::AES256);
    b.encrypt_with_password(StringToKey::new_default(thread_rng()), &Password::from(password))?;
    Ok(b.to_vec(thread_rng())?)
}

fn open(password: &str, blob: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let msg = Message::from_bytes(blob)?;
    let mut m = msg
        .decrypt_with_password(&Password::from(password))
        .context("cannot decrypt — a different Ledger seed?")?;
    if m.is_compressed() {
        m = m.decompress()?;
    }
    Ok(Zeroizing::new(m.as_data_vec()?))
}

pub fn store_dir() -> Result<PathBuf> {
    paths::secrets_dir()
}

fn validate(name: &str) -> Result<()> {
    let ok = !name.is_empty()
        && !name.starts_with('/')
        && name
            .split('/')
            .all(|seg| !seg.is_empty() && seg != "." && seg != ".." && !seg.starts_with('.'))
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_./@+".contains(c));
    if !ok {
        bail!("invalid secret name {name:?} (use letters, digits, - _ . @ + and / for folders)");
    }
    Ok(())
}

fn path_of(dir: &Path, name: &str) -> PathBuf {
    dir.join(format!("{name}.gpg"))
}

/// Store `value` under `name`.
pub fn set(oracle: &mut dyn Oracle, name: &str, value: &[u8], overwrite: bool) -> Result<()> {
    validate(name)?;
    let dir = store_dir()?;
    paths::ensure_private_dir(&dir)?;
    let p = path_of(&dir, name);
    if p.exists() && !overwrite {
        bail!("secret {name} exists — use --force to replace it");
    }
    let pw = store_password(oracle)?;
    paths::write_private(&p, &seal(&pw, value)?)
}

/// Read a value for `set`: from stdin when piped, otherwise a hidden prompt.
pub fn read_value(name: &str) -> Result<Zeroizing<Vec<u8>>> {
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        let v = crate::util::read_hidden(&format!("Value for {name}: "))?;
        Ok(Zeroizing::new(v.as_bytes().to_vec()))
    } else {
        let mut buf = Zeroizing::new(Vec::new());
        std::io::stdin().read_to_end(&mut buf)?;
        // a single trailing newline from `echo` is not part of the secret
        if buf.last() == Some(&b'\n') {
            buf.pop();
        }
        Ok(buf)
    }
}

pub fn exists(name: &str) -> Result<bool> {
    Ok(path_of(&store_dir()?, name).exists())
}

/// Decrypt several secrets (one store key, so at most one device round-trip).
pub fn get_many(oracle: &mut dyn Oracle, names: &[&str]) -> Result<Vec<Zeroizing<String>>> {
    let dir = store_dir()?;
    let blobs: Vec<Vec<u8>> = names
        .iter()
        .map(|n| {
            validate(n)?;
            fs::read(path_of(&dir, n)).with_context(|| format!("secret {n} not found"))
        })
        .collect::<Result<_>>()?;
    if blobs.is_empty() {
        return Ok(vec![]);
    }
    let pw = store_password(oracle)?;
    blobs
        .iter()
        .zip(names)
        .map(|(b, n)| {
            let v = open(&pw, b)?;
            let s = String::from_utf8(v.to_vec()).with_context(|| format!("secret {n} is not UTF-8"))?;
            Ok(Zeroizing::new(s))
        })
        .collect()
}

/// Open `names` (every secret when `None`) with one store key: names and raw values, the values
/// in buffers that are wiped on drop. For `sealctl unseal`.
pub fn open_all(
    oracle: &mut dyn Oracle,
    names: Option<&[String]>,
) -> Result<Vec<(String, Zeroizing<Vec<u8>>)>> {
    let names: Vec<String> = match names {
        Some(n) => n.to_vec(),
        None => list()?,
    };
    if names.is_empty() {
        return Ok(vec![]);
    }
    let dir = store_dir()?;
    let pw = store_password(oracle)?;
    names
        .into_iter()
        .map(|n| {
            validate(&n)?;
            let blob = fs::read(path_of(&dir, &n)).with_context(|| format!("secret {n} not found"))?;
            let v = open(&pw, &blob).with_context(|| format!("opening secret {n}"))?;
            Ok((n, v))
        })
        .collect()
}

pub fn get(oracle: &mut dyn Oracle, name: &str) -> Result<Zeroizing<String>> {
    Ok(get_many(oracle, &[name])?.pop().expect("one"))
}

pub fn list() -> Result<Vec<String>> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) -> Result<()> {
        let Ok(rd) = fs::read_dir(dir) else { return Ok(()) };
        for e in rd.flatten() {
            let p = e.path();
            let fname = e.file_name().to_string_lossy().into_owned();
            if fname.starts_with('.') {
                continue;
            }
            if p.is_dir() {
                walk(base, &p, out)?;
            } else if let Some(stem) = fname.strip_suffix(".gpg") {
                let rel = p
                    .parent()
                    .unwrap_or(base)
                    .strip_prefix(base)
                    .unwrap_or(Path::new(""));
                let name = if rel.as_os_str().is_empty() {
                    stem.to_string()
                } else {
                    format!("{}/{stem}", rel.to_string_lossy())
                };
                out.push(name);
            }
        }
        Ok(())
    }
    let dir = store_dir()?;
    let mut out = Vec::new();
    walk(&dir, &dir, &mut out)?;
    out.sort();
    Ok(out)
}

pub fn remove(name: &str) -> Result<()> {
    validate(name)?;
    let dir = store_dir()?;
    let p = path_of(&dir, name);
    fs::remove_file(&p).with_context(|| format!("secret {name} not found"))?;
    // drop folders that became empty (e.g. work/ after removing work/token)
    let mut parent = p.parent();
    while let Some(d) = parent {
        if d == dir || fs::remove_dir(d).is_err() {
            break; // not empty, or the store root
        }
        parent = d.parent();
    }
    Ok(())
}

/// Parse a dotenv file (KEY=value, optional quotes, # comments).
/// Parse a `.env` file the way common dotenv libraries do: `KEY=value`, optional `export `,
/// `#` comments (also after unquoted values), single quotes (literal), double quotes (escapes
/// `\n \r \t \" \\`), and quoted values spanning several lines. Anything it can't read
/// unambiguously is an error rather than a guess — the file may be deleted afterwards.
pub fn parse_dotenv(text: &str) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let mut out = BTreeMap::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut line = 1;
    let n = chars.len();
    let skip_ws = |i: &mut usize| {
        while *i < n && (chars[*i] == ' ' || chars[*i] == '\t') {
            *i += 1;
        }
    };
    while i < n {
        skip_ws(&mut i);
        if i >= n {
            break;
        }
        if chars[i] == '\n' || chars[i] == '\r' {
            if chars[i] == '\n' {
                line += 1;
            }
            i += 1;
            continue;
        }
        if chars[i] == '#' {
            while i < n && chars[i] != '\n' {
                i += 1;
            }
            continue;
        }
        let start_line = line;
        // key
        let rest: String = chars[i..n.min(i + 7)].iter().collect();
        if rest == "export " {
            i += 7;
            skip_ws(&mut i);
        }
        let ks = i;
        while i < n && (chars[i].is_ascii_alphanumeric() || matches!(chars[i], '_' | '.' | '-')) {
            i += 1;
        }
        let key: String = chars[ks..i].iter().collect();
        skip_ws(&mut i);
        if key.is_empty() || i >= n || chars[i] != '=' {
            bail!("line {start_line}: expected KEY=value");
        }
        if key.starts_with(|c: char| c.is_ascii_digit()) {
            bail!("line {start_line}: invalid variable name {key:?}");
        }
        i += 1;
        skip_ws(&mut i);
        let mut val = Zeroizing::new(String::new());
        if i < n && (chars[i] == '"' || chars[i] == '\'' || chars[i] == '`') {
            let q = chars[i];
            i += 1;
            loop {
                if i >= n {
                    bail!("line {start_line}: {key}: closing {q} missing");
                }
                let c = chars[i];
                if c == q {
                    i += 1;
                    break;
                }
                if c == '\n' {
                    line += 1;
                }
                if q == '"' && c == '\\' && i + 1 < n {
                    i += 1;
                    match chars[i] {
                        'n' => val.push('\n'),
                        'r' => val.push('\r'),
                        't' => val.push('\t'),
                        '"' => val.push('"'),
                        '\\' => val.push('\\'),
                        '$' => val.push('$'),
                        '`' => val.push('`'),
                        other => {
                            val.push('\\');
                            val.push(other);
                        }
                    }
                    i += 1;
                    continue;
                }
                val.push(c);
                i += 1;
            }
            // only a comment may follow a quoted value
            skip_ws(&mut i);
            if i < n && chars[i] != '\n' && chars[i] != '\r' && chars[i] != '#' {
                bail!("line {line}: {key}: unexpected text after the closing quote");
            }
        } else {
            while i < n && chars[i] != '\n' && chars[i] != '\r' {
                // `#` starts a comment only after whitespace (URLs and tokens may contain #)
                if chars[i] == '#' && (val.is_empty() || val.ends_with(' ') || val.ends_with('\t')) {
                    break;
                }
                val.push(chars[i]);
                i += 1;
            }
            let trimmed = Zeroizing::new(val.trim().to_string());
            val = trimmed;
        }
        while i < n && chars[i] != '\n' {
            i += 1;
        }
        out.insert(key, val);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotenv_parsing() {
        let text = "# comment\nexport A=1 # trailing comment\nB='single $x'\nC=\"line1\\nline2 \\\"q\\\"\"\nPEM=\"-----BEGIN KEY-----\nabc\n-----END KEY-----\"\nURL=https://x.test/#frag\nEMPTY=\n";
        let v = parse_dotenv(text).unwrap();
        assert_eq!(*v["A"], "1");
        assert_eq!(*v["B"], "single $x");
        assert_eq!(*v["C"], "line1\nline2 \"q\"");
        assert_eq!(*v["PEM"], "-----BEGIN KEY-----\nabc\n-----END KEY-----");
        assert_eq!(*v["URL"], "https://x.test/#frag");
        assert_eq!(*v["EMPTY"], "");
        assert!(parse_dotenv("K=\"unterminated\nX=1\n").is_err());
        assert!(parse_dotenv("just text\n").is_err());
        assert!(parse_dotenv("K=\"a\" b\n").is_err());
    }

    #[test]
    fn names_are_validated() {
        for ok in ["openai", "work/github-token", "a.b_c-d@e+f"] {
            assert!(validate(ok).is_ok(), "{ok}");
        }
        for bad in [
            "", "/abs", "../x", "a/../b", ".hidden", "a//b", "sp ace", "a/.git/x",
        ] {
            assert!(validate(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn dotenv_basics() {
        let m = parse_dotenv("# c\nA=1\nexport B=\"two words\"\nC='x=y'\n\n").unwrap();
        assert_eq!(m.get("A").unwrap().as_str(), "1");
        assert_eq!(m.get("B").unwrap().as_str(), "two words");
        assert_eq!(m.get("C").unwrap().as_str(), "x=y");
        assert_eq!(m.len(), 3);
        assert!(
            parse_dotenv("A=1\nbad line\n").is_err(),
            "unreadable lines are errors"
        );
    }
}
