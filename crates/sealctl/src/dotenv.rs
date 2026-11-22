//! A dotenv parser: what `seal env` and `scan` read, and what `unseal` writes back.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use zeroize::Zeroizing;

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
