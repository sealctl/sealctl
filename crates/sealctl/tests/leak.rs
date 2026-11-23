//! Leak test (SPEC 21): a canary value in the store never shows in any encoding the masker
//! covers (raw, base64, base64url, URL-encoded, hex in both cases) in the output of
//! `sealctl run`, in `daemon.log`, or in any file under the throwaway HOME other than the sealed
//! store files.

mod common;

use common::{canary, Env};
use sealctl_fakerelay::Answer;

/// The forms of `v` the masker replaces, with their labels.
fn forms(v: &[u8]) -> Vec<(&'static str, String)> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut b64 = String::new();
    for c in v.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                b64.push(B64[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                b64.push('=');
            }
        }
    }
    let b64url = b64.replace('+', "-").replace('/', "_").replace('=', "");
    let percent: String = v
        .iter()
        .map(|&b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect();
    let hex: String = v.iter().map(|b| format!("{b:02x}")).collect();
    vec![
        ("raw", String::from_utf8_lossy(v).into_owned()),
        ("base64", b64),
        ("base64url", b64url),
        ("percent", percent),
        ("hex", hex.clone()),
        ("HEX", hex.to_ascii_uppercase()),
    ]
}

fn walk(d: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(d) {
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                out.extend(walk(&p));
            } else {
                out.push(p);
            }
        }
    }
    out
}

fn assert_no_form(what: &str, text: &[u8], forms: &[(&str, String)]) {
    for (label, f) in forms {
        assert!(
            !text.windows(f.len()).any(|w| w == f.as_bytes()),
            "the {label} form of the canary is in {what}"
        );
    }
}

#[test]
fn canary_never_leaks_in_any_form() {
    let mut env = Env::new();
    env.pair();
    // `+`, `/` and a space: the base64, base64url and URL-encoded forms all differ from the raw
    // value and from each other
    let value = format!("{}+/ {}", canary(), canary());
    let forms = forms(value.as_bytes());

    let ((code, out, err), _) = env.with_phone(Answer::Session, || {
        env.run_in(&["secret", "set", "leak/value"], format!("{value}\n").as_bytes())
    });
    assert_eq!(code, 0, "{err}");
    assert_no_form("`secret set` stdout", out.as_bytes(), &forms);
    assert_no_form("`secret set` stderr", err.as_bytes(), &forms);

    // the program prints the value in every form, to stdout and stderr; both are pipes, so
    // sealctl masks them
    let script = r#"
        b64=$(printf %s "$K" | base64 | tr -d '\n')
        hex=$(printf %s "$K" | od -An -v -tx1 | tr -d ' \n')
        for fd in 1 2; do
            {
                printf 'raw=%s\n' "$K"
                printf 'base64=%s\n' "$b64"
                printf 'base64url=%s\n' "$(printf %s "$b64" | tr '/+' '_-' | tr -d '=')"
                printf 'percent=%s\n' "$(printf %s "$K" | sed -e 's/%/%25/g' -e 's/+/%2B/g' -e 's|/|%2F|g' -e 's/ /%20/g')"
                printf 'hex=%s\n' "$hex"
                printf 'HEX=%s\n' "$(printf %s "$hex" | tr a-f A-F)"
            } >&$fd
        done
    "#;
    let (code, out, err) = env.run(&["run", "-e", "K=leak/value", "--", "sh", "-c", script]);
    assert_eq!(code, 0, "{err}");
    for (label, _) in &forms {
        // each line is there and masked: an encoding the masker misses shows here
        assert!(
            out.contains(&format!("{label}=****\n")),
            "{label} on stdout:\n{out}"
        );
        assert!(
            err.contains(&format!("{label}=****\n")),
            "{label} on stderr:\n{err}"
        );
    }
    assert_no_form("`run` stdout", out.as_bytes(), &forms);
    assert_no_form("`run` stderr", err.as_bytes(), &forms);

    // the daemon's log, and every file in the throwaway HOME (config, state, data) except the
    // sealed store files, which hold ciphertext
    env.stop_daemon();
    let log = env.h().join("s/sealctl/daemon.log");
    assert!(log.is_file(), "the daemon ran and kept a log");
    let files: Vec<_> = walk(env.h())
        .into_iter()
        .filter(|p| p.extension().is_none_or(|e| e != "sealed"))
        .collect();
    assert!(files.contains(&log));
    for f in files {
        let t = std::fs::read(&f).unwrap_or_default();
        assert_no_form(&f.display().to_string(), &t, &forms);
    }
}
