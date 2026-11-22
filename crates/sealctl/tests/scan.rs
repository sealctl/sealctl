//! `sealctl scan` (SPEC 10.4) on a fixture home: .env files, shell rc files, histories and
//! ~/.aws/credentials. Values are built at run time.

mod common;

use common::{canary, Env};
use sealctl_fakerelay::Answer;

fn random_alnum(n: usize) -> String {
    let c = canary();
    let mut s = String::new();
    while s.len() < n {
        s.push_str(&c[6..]);
    }
    s.truncate(n);
    s
}

#[test]
fn scan_finds_and_seals_keys_leaving_references() {
    let mut env = Env::new();
    env.pair();
    let h = env.h().to_path_buf();
    let repo = h.join("code/shop");
    std::fs::create_dir_all(&repo).unwrap();
    let a = format!("Ab1{}", random_alnum(30));
    std::fs::write(repo.join(".env"), format!("API_KEY={a}\nPORT=3000\n")).unwrap();
    std::fs::write(repo.join(".env.example"), "API_KEY=\n").unwrap();
    let rc_val = format!("Zq9{}", random_alnum(30));
    std::fs::write(
        h.join(".zshrc"),
        format!("alias ll='ls -l'\nexport OPENAI_API_KEY=\"{rc_val}\"\nexport PATH=/usr/bin\n"),
    )
    .unwrap();
    let token = ["gh", "p_", &random_alnum(36)].concat();
    std::fs::write(
        h.join(".zsh_history"),
        format!(": 1:0;ls\n: 2:0;curl -H 'Authorization: Bearer {token}' x\n"),
    )
    .unwrap();
    std::fs::create_dir_all(h.join(".aws")).unwrap();
    let akid = ["AK", "IA", "QWERTYUIOPASDFGH"].concat();
    let secret = random_alnum(40);
    std::fs::write(
        h.join(".aws/credentials"),
        format!(
            "[default]\naws_access_key_id = {akid}\naws_secret_access_key = {secret}\n[keep]\nregion = x\n"
        ),
    )
    .unwrap();

    // dry run: a list, nothing changed, never a value
    let (code, out, err) = env.run(&["scan", "--home", "--dry-run"]);
    assert_eq!(code, 0, "{err}");
    for v in [&a, &rc_val, &token, &secret] {
        assert!(
            !out.contains(v.as_str()) && !err.contains(v.as_str()),
            "a value was printed"
        );
    }
    assert!(
        out.contains("API_KEY")
            && out.contains("OPENAI_API_KEY")
            && out.contains("aws credentials")
            && out.contains("history"),
        "{out}"
    );
    assert!(!out.contains("PATH "), "{out}");
    assert!(repo.join(".env").exists());

    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&["scan", "--home", "--yes", "--json"])
    });
    assert_eq!(code, 0, "{err}");
    let (_, list, _) = env.run(&["secret", "ls"]);
    for n in ["shop/api-key", "shop/port", "env/openai-api-key", "aws/default"] {
        assert!(list.lines().any(|l| l == n), "{n} in {list}");
    }
    // references left behind
    assert!(!repo.join(".env").exists(), "the .env file is gone once empty");
    let toml = std::fs::read_to_string(repo.join(".sealctl.toml")).unwrap();
    assert!(toml.contains("API_KEY = \"shop/api-key\""), "{toml}");
    let rc = std::fs::read_to_string(h.join(".zshrc")).unwrap();
    assert!(rc.contains("# OPENAI_API_KEY moved to sealctl: sealctl run -e OPENAI_API_KEY=env/openai-api-key -- <command>"), "{rc}");
    assert!(!rc.contains(&rc_val) && rc.contains("alias ll"));
    let hist = std::fs::read_to_string(h.join(".zsh_history")).unwrap();
    assert!(!hist.contains(&token) && hist.contains("****"), "{hist}");
    let creds = std::fs::read_to_string(h.join(".aws/credentials")).unwrap();
    assert!(!creds.contains(&secret) && creds.contains("[keep]"), "{creds}");
    let cfg = std::fs::read_to_string(h.join(".aws/config")).unwrap();
    assert!(cfg.contains("aws credentials --profile default"), "{cfg}");
    // the AWS CLI's helper gets them back (to a pipe)
    let (code, out, err) = env.run(&["aws", "credentials", "--profile", "default"]);
    assert_eq!(code, 0, "{err}");
    let v: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(v["Version"], 1);
    assert_eq!(v["SecretAccessKey"], secret.as_str());
    // a run picks the .env value from the new mapping
    let mut c = env.cmd();
    c.current_dir(&repo)
        .env("WANT", &a)
        .args(["run", "--", "sh", "-c", "test \"$API_KEY\" = \"$WANT\""]);
    assert!(c.output().unwrap().status.success());
}

#[test]
fn the_same_value_twice_is_one_secret() {
    let mut env = Env::new();
    env.pair();
    let v = format!("Qx7{}", random_alnum(30));
    for d in ["a", "b"] {
        let dir = env.h().join(d);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(".env"), format!("SERVICE_TOKEN={v}\n")).unwrap();
    }
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        let a = env.h().join("a");
        let b = env.h().join("b");
        env.run(&["scan", a.to_str().unwrap(), b.to_str().unwrap(), "--yes"])
    });
    assert_eq!(code, 0, "{err}");
    let (_, list, _) = env.run(&["secret", "ls"]);
    assert_eq!(list.lines().count(), 1, "{list}");
    let tb = std::fs::read_to_string(env.h().join("b/.sealctl.toml")).unwrap();
    assert!(tb.contains("SERVICE_TOKEN = \"a/service-token\""), "{tb}");
}

/// A `.env` file with CR-only and mixed line endings and a quoted value over several lines: every
/// assignment is found, only the sealed ones are removed, and the rest stays byte for byte.
#[test]
fn env_files_with_any_line_ending_lose_only_what_was_sealed() {
    let mut env = Env::new();
    env.pair();
    let a = format!("Ab1{}", random_alnum(30));
    let b = format!("Bc2{}", random_alnum(30));
    let dir = env.h().join("cr");
    std::fs::create_dir_all(&dir).unwrap();
    let text = format!("# keep me\rFIRST_KEY={a}\r\nPEM_KEY=\"line one\r\n{b}\rline three\"\rEMPTY_KEY=\r\n");
    std::fs::write(dir.join(".env"), &text).unwrap();
    let (code, out, err) = env.run(&["scan", dir.to_str().unwrap(), "--dry-run"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("FIRST_KEY") && out.contains("PEM_KEY"), "{out}");
    let ((code, _, err), _) = env.with_phone(Answer::Session, || {
        env.run(&["scan", dir.to_str().unwrap(), "--yes"])
    });
    assert_eq!(code, 0, "{err}");
    let (_, list, _) = env.run(&["secret", "ls"]);
    for n in ["cr/first-key", "cr/pem-key"] {
        assert!(list.lines().any(|l| l == n), "{n} in {list}");
    }
    let (_, pem, _) = env.run(&["secret", "get", "cr/pem-key"]);
    assert_eq!(pem, format!("line one\r\n{b}\rline three"));
    // the empty variable and the comment are what is left, with their own line endings
    let kept = std::fs::read_to_string(dir.join(".env")).unwrap();
    assert_eq!(kept, "# keep me\rEMPTY_KEY=\r\n");
}
