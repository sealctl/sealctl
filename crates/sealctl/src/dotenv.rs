//! A dotenv parser: what `seal env` and `scan` read, and what `unseal` writes back.

use std::collections::BTreeMap;

use anyhow::{bail, Result};
use zeroize::Zeroizing;

/// Parse a `.env` file the way common dotenv libraries do: `KEY=value`, optional `export `,
/// `#` comments (also after unquoted values), single quotes (literal), double quotes (escapes
/// `\n \r \t \" \\`), and quoted values spanning several lines. Lines end at `\n`, `\r\n` or a
/// lone `\r`. Anything it can't read unambiguously is an error rather than a guess or a partial
/// result — the file may be deleted afterwards.
///
/// The text is copied once into a character buffer that is wiped when parsing ends, and each
/// value is built in a buffer sized up front, so no unwiped copy of a value is left behind.
pub fn parse_dotenv(text: &str) -> Result<BTreeMap<String, Zeroizing<String>>> {
    let chars: Zeroizing<Vec<char>> = Zeroizing::new(text.chars().collect());
    let chars: &[char] = &chars;
    let n = chars.len();
    let mut out = BTreeMap::new();
    let mut i = 0;
    let mut line = 1;
    let is_eol = |c: char| c == '\n' || c == '\r';
    let skip_ws = |i: &mut usize| {
        while *i < n && (chars[*i] == ' ' || chars[*i] == '\t') {
            *i += 1;
        }
    };
    // Consumes one line ending (`\n`, `\r\n` or `\r`) at `i`, if there is one.
    let eol = |i: &mut usize, line: &mut usize| -> bool {
        match chars.get(*i) {
            Some('\r') => {
                *i += if chars.get(*i + 1) == Some(&'\n') { 2 } else { 1 };
            }
            Some('\n') => *i += 1,
            _ => return false,
        }
        *line += 1;
        true
    };
    let skip_comment = |i: &mut usize| {
        while *i < n && !is_eol(chars[*i]) {
            *i += 1;
        }
    };
    let bytes = |s: &[char]| s.iter().map(|c| c.len_utf8()).sum::<usize>();
    while i < n {
        skip_ws(&mut i);
        if i >= n {
            break;
        }
        if eol(&mut i, &mut line) {
            continue;
        }
        if chars[i] == '#' {
            skip_comment(&mut i);
            continue;
        }
        let start_line = line;
        // key
        if chars[i..].starts_with(&['e', 'x', 'p', 'o', 'r', 't'])
            && matches!(chars.get(i + 6), Some(' ' | '\t'))
        {
            i += 6;
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
        let val = if i < n && matches!(chars[i], '"' | '\'' | '`') {
            let q = chars[i];
            i += 1;
            // find the closing quote first, so the value's buffer never grows (and never
            // leaves an unwiped copy behind); decoding escapes only makes it shorter
            let vs = i;
            let mut j = i;
            loop {
                if j >= n {
                    bail!("line {start_line}: {key}: closing {q} missing");
                }
                if chars[j] == q {
                    break;
                }
                j += if q == '"' && chars[j] == '\\' && j + 1 < n {
                    2
                } else {
                    1
                };
            }
            let mut val = Zeroizing::new(String::with_capacity(bytes(&chars[vs..j])));
            while i < j {
                let c = chars[i];
                if q == '"' && c == '\\' && i + 1 < j {
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
                } else {
                    val.push(c);
                }
                i += 1;
            }
            // lines inside the quotes
            line += chars[vs..j]
                .iter()
                .enumerate()
                .filter(|&(k, &c)| c == '\n' || (c == '\r' && chars.get(vs + k + 1) != Some(&'\n')))
                .count();
            i = j + 1;
            val
        } else {
            let vs = i;
            while i < n && !is_eol(chars[i]) {
                // `#` starts a comment only after whitespace (URLs and tokens may contain #)
                if chars[i] == '#' && (i == vs || chars[i - 1] == ' ' || chars[i - 1] == '\t') {
                    break;
                }
                i += 1;
            }
            let (mut vs, mut ve) = (vs, i);
            while ve > vs && chars[ve - 1].is_whitespace() {
                ve -= 1;
            }
            while vs < ve && chars[vs].is_whitespace() {
                vs += 1;
            }
            let mut val = Zeroizing::new(String::with_capacity(bytes(&chars[vs..ve])));
            val.extend(chars[vs..ve].iter());
            val
        };
        // only whitespace and a comment may follow the value on its line
        skip_ws(&mut i);
        if i < n && chars[i] == '#' {
            skip_comment(&mut i);
        }
        if i < n && !eol(&mut i, &mut line) {
            bail!("line {line}: {key}: unexpected text after the closing quote");
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

    #[test]
    fn every_line_ending() {
        for (text, what) in [
            ("A=one\nB=two\n", "LF"),
            ("A=one\r\nB=two\r\n", "CRLF"),
            ("A=one\rB=two\r", "CR only"),
            ("A=one\rB=two", "CR only, no final line end"),
            ("A=one\r\nB=two\r", "mixed"),
            ("# c\rA=one\r# c2\r\nB=two\n", "comments, CR only and mixed"),
            ("A=one # c\rB=two", "trailing comment, CR"),
            ("A=\"one\" # c\rB='two'\r", "quoted, CR"),
            ("\r\r\nA=one\n\rB=two\r\n\r", "blank lines of every kind"),
        ] {
            let m = parse_dotenv(text).unwrap_or_else(|e| panic!("{what}: {e}"));
            assert_eq!(m.len(), 2, "{what}: {:?}", m.keys().collect::<Vec<_>>());
            assert_eq!(m["A"].as_str(), "one", "{what}");
            assert_eq!(m["B"].as_str(), "two", "{what}");
        }
        // a quoted value keeps its own line endings
        let m = parse_dotenv("K=\"a\rb\r\nc\"\rL=2\r").unwrap();
        assert_eq!(m["K"].as_str(), "a\rb\r\nc");
        assert_eq!(m["L"].as_str(), "2");
    }

    #[test]
    fn errors_name_the_right_line_and_never_return_part() {
        for text in [
            "A=1\rbad line\r",
            "A=1\r\nbad\r\n",
            "A=1\nbad\n",
            "A=1\rB=\"x\" y\r",
        ] {
            assert!(parse_dotenv(text).is_err(), "{text:?}");
        }
        let e = parse_dotenv("A=1\rB=2\r\nC=3\nbad\r").unwrap_err().to_string();
        assert!(e.starts_with("line 4:"), "{e}");
        let e = parse_dotenv("A=\"x\ry\"\rbad").unwrap_err().to_string();
        assert!(e.starts_with("line 3:"), "{e}");
    }

    #[test]
    fn export_and_whitespace() {
        let m = parse_dotenv("export\tA=1\r  export B = two words  \rexporter=3\r").unwrap();
        assert_eq!(m["A"].as_str(), "1");
        assert_eq!(m["B"].as_str(), "two words");
        assert_eq!(m["exporter"].as_str(), "3");
        let m = parse_dotenv("A=\"x\\\\\"\rB=\"\\\"q\\\"\"\r").unwrap();
        assert_eq!(m["A"].as_str(), "x\\");
        assert_eq!(m["B"].as_str(), "\"q\"");
    }
}
