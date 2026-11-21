//! `sealctl unseal --all` end to end on a fixture home (secrets, SSH keys, git signing, AI
//! integrations, local state): what is left behind in plain form, that no value is ever printed
//! or written outside the folder's plain files, and that a run killed with SIGKILL — or cut off
//! by a simulated power cut, losing whatever was not made durable — at any step resumes to the
//! same end state with no object ever left without a working key.

mod common;

use std::collections::BTreeMap;
use std::path::Path;
use std::process::Command;

use common::{new_home, serial, text, FixtureOpts, Home};

/// The default: everything into the folder.
const ARGS: &[&str] = &["--all", "--keep-env-rules"];

fn setup(o: &FixtureOpts) -> Home {
    let mut h = new_home();
    common::fixture(&h, o);
    common::start_agent();
    h.start_ssh_agent();
    h
}

fn git_get(file: &Path, key: &str) -> Option<String> {
    let out = Command::new("git")
        .args(["config", "--file"])
        .arg(file)
        .args(["--get", key])
        .output()
        .unwrap();
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_string())
}

/// The state a finished run leaves: files under HOME (contents normalised; encrypted key files
/// only by name, their salt is random), and the names in the run folder's kept/ and files/.
fn end_state(h: &Home) -> BTreeMap<String, String> {
    let home_s = h.home.display().to_string();
    let mut out = BTreeMap::new();
    for (rel, kind) in common::tree(&h.home) {
        if rel.starts_with("sealctl-unsealed-") {
            continue;
        }
        let p = h.home.join(&rel);
        let v = if kind == "dir" || kind.starts_with("->") {
            kind
        } else if rel.starts_with(".ssh/")
            && !rel.ends_with(".pub")
            && !rel.contains("config")
            && !rel.contains("allowed")
        {
            "private key".into()
        } else {
            let t = String::from_utf8_lossy(&std::fs::read(&p).unwrap()).replace(&home_s, "~");
            sealctl::util::sha256_hex(t.as_bytes())
        };
        out.insert(rel, v);
    }
    let run = h.run_dir();
    for sub in ["kept", "files"] {
        for (rel, _) in common::tree(&run.join(sub)) {
            out.insert(format!("RUN/{sub}/{rel}"), String::new());
        }
    }
    for f in [
        "plan.json",
        "journal.jsonl",
        "handback.json",
        "done",
        "README.txt",
        "passwords.txt",
        "run.lock",
    ] {
        out.insert(format!("RUN/{f}"), run.join(f).exists().to_string());
    }
    // the secrets come back the same, whatever stopped the run
    out.insert(
        "RUN/secrets.env".into(),
        sealctl::util::sha256_hex(&std::fs::read(run.join("secrets.env")).unwrap_or_default()),
    );
    // no temporary file is left anywhere
    for (rel, _) in common::tree(&h.home) {
        assert!(!rel.ends_with(".tmp~"), "left behind: {rel}");
    }
    out
}

/// Nothing sealctl had may be without a way in at any point: every secret is in the store
/// folder or in kept/ (still encrypted), every key file in ~/.ssh or kept/ssh.
fn nothing_lost(h: &Home) {
    let runs = h.run_dirs();
    let in_kept = |rel: &str| {
        runs.iter()
            .any(|r: &std::path::PathBuf| r.join("kept").join(rel).exists())
    };
    let store = h.home.join(".local/share/sealctl/secrets");
    for (n, _) in common::fixture_secrets() {
        let f = format!("{n}.gpg");
        assert!(
            store.join(&f).exists()
                || in_kept(&format!("secrets/{f}"))
                || in_kept(&format!("data/secrets/{f}")),
            "secret {n} lost"
        );
    }
    for (n, _) in common::FIXTURE_SSH {
        let f = format!("sealctl_{n}");
        assert!(
            h.home.join(".ssh").join(&f).exists() || in_kept(&format!("ssh/{f}")),
            "key {n} lost"
        );
    }
}

#[test]
fn full_run_hands_everything_back_and_leaks_nothing() {
    let _g = serial();
    let h = setup(&FixtureOpts::default());
    let ssh = h.home.join(".ssh");
    // values that must never be printed or copied anywhere but the chosen stores
    let mut ledger = common::SoftOracle::fixed();
    let mut canaries: Vec<String> = common::fixture_secrets().into_iter().map(|(_, v)| v).collect();
    canaries.push(
        sealctl::derive::passphrase(&mut ledger, sealctl::derive::Purpose::Secrets, "store")
            .unwrap()
            .to_string(),
    );
    for (n, _) in common::FIXTURE_SSH {
        let public = sealctl::ssh::read_public(&ssh.join(format!("sealctl_{n}"))).unwrap();
        canaries.push(
            sealctl::ssh::passphrase_for(&mut ledger, &public)
                .unwrap()
                .to_string(),
        );
    }

    let out = h.unseal(ARGS, "unseal\n", &[]);
    assert!(out.status.success(), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr).to_string();
    if std::env::var_os("SHOW_PLAN").is_some() {
        eprintln!("{err}");
    }
    let run = h.run_dir();
    let d = format!("~/{}", run.file_name().unwrap().to_string_lossy());
    assert!(err.contains("Done. sealctl 0.5 holds nothing on"), "{err}");
    assert!(err.contains(&format!("Everything is in {d}:")), "{err}");
    assert!(err.contains(&format!("  rm -rf {d}\n")), "{err}");
    assert!(err.contains("sealctl never deletes it."), "{err}");
    assert!(err.contains("[1/6] secrets: 7 secrets in secrets.env"), "{err}");
    assert!(run.join("done").exists());

    // the folder: visible, 0700, files 0600, README.txt
    {
        use std::os::unix::fs::PermissionsExt;
        assert!(run
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("sealctl-unsealed-"));
        assert_eq!(
            std::fs::metadata(&run).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for (rel, kind) in common::tree(&run) {
            if kind != "dir" && !rel.starts_with("kept/") && !rel.starts_with("files/") {
                let m = std::fs::metadata(run.join(&rel)).unwrap().permissions().mode() & 0o777;
                assert_eq!(m, 0o600, "{rel}");
            }
        }
    }
    let readme = std::fs::read_to_string(run.join("README.txt")).unwrap();
    for want in [
        format!("rm -rf {d}").as_str(),
        "sealctl never deletes it.",
        "ssh-keygen -y -f ~/.ssh/ed25519",
        "SHOP_OPENAI_API_KEY",
        "git log --show-signature",
    ] {
        assert!(readme.contains(want), "README.txt lacks {want:?}:\n{readme}");
    }

    // secrets: in secrets.env, plain, with the right values; the store kept, encrypted
    let map = h.folder_env("secrets.env");
    for (n, v) in common::fixture_secrets() {
        assert_eq!(map[&sealctl::unseal::store::env_var_name(n)].as_str(), v, "{n}");
    }
    assert!(run.join("kept/secrets/shop/openai-api-key.gpg").exists());
    assert!(!h.home.join("sealctl-secrets.env").exists());

    // SSH keys: plain standard files without a passphrase, the same keys
    for (n, seed) in common::FIXTURE_SSH {
        let dest = ssh.join(n);
        let want = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[*seed; 32]));
        assert!(sealctl::ssh::opens_with(&dest, None, want.public_key()).unwrap());
        // OpenSSH itself opens it without a passphrase
        let o = Command::new("ssh-keygen")
            .args(["-y", "-P", "", "-f"])
            .arg(&dest)
            .output()
            .unwrap();
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert!(
            String::from_utf8_lossy(&o.stdout).starts_with(&want.public_key().to_openssh().unwrap()[..60])
        );
        assert!(!ssh.join(format!("sealctl_{n}")).exists());
        assert!(run.join(format!("kept/ssh/sealctl_{n}")).exists());
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&dest).unwrap().permissions().mode() & 0o777,
            0o600
        );
        // nothing went to an agent or the keychain
        if let Some(sock) = h.ssh_agent_sock() {
            let listed = sealctl::ssh::agent_fingerprints(&sock);
            let fp = want
                .public_key()
                .fingerprint(ssh_key::HashAlg::Sha256)
                .to_string();
            assert!(!listed.contains(&fp), "{n} was added to an agent");
        }
    }
    let config = std::fs::read_to_string(ssh.join("config")).unwrap();
    assert!(!config.contains("sealctl"), "{config}");
    assert!(config.contains("IdentityFile ~/.ssh/github\n"), "{config}");
    assert!(!config.contains("UseKeychain"), "{config}");
    let zshrc = std::fs::read_to_string(h.home.join(".zshrc")).unwrap();
    assert!(
        zshrc.contains("# removed by sealctl unseal: export SSH_AUTH_SOCK="),
        "{zshrc}"
    );
    assert!(zshrc.starts_with("export PATH="), "{zshrc}");
    assert!(run.join("files/.ssh/config").exists() && run.join("files/.zshrc").exists());

    // git: standard ssh-keygen signing with the plain key file, allowed signers merged
    let global = h.home.join(".gitconfig");
    assert_eq!(git_get(&global, "gpg.ssh.program"), None);
    assert_eq!(
        git_get(&global, "user.signingkey").unwrap(),
        ssh.join("ed25519").display().to_string()
    );
    assert_eq!(git_get(&global, "gpg.format").as_deref(), Some("ssh"));
    assert_eq!(git_get(&global, "commit.gpgsign").as_deref(), Some("true"));
    let allowed = ssh.join("allowed_signers");
    assert_eq!(
        git_get(&global, "gpg.ssh.allowedSignersFile").unwrap(),
        allowed.display().to_string()
    );
    let repo = h.home.join("src/proj");
    let local = repo.join(".git/config");
    assert_eq!(
        git_get(&local, "user.signingkey").unwrap(),
        ssh.join("github").display().to_string()
    );
    assert_eq!(git_get(&local, "gpg.ssh.program"), None);
    let signers = std::fs::read_to_string(&allowed).unwrap();
    assert_eq!(signers.lines().count(), 2, "{signers}");
    // a real signed commit, no agent, verified by git
    let g = |args: &[&str]| {
        Command::new("git")
            .arg("-C")
            .arg(&repo)
            .args(args)
            .env_remove("SSH_AUTH_SOCK")
            .output()
            .unwrap()
    };
    let o = g(&["commit", "-q", "--allow-empty", "-m", "signed"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = g(&["log", "--show-signature", "-1"]);
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(all.contains("Good \"git\" signature"), "{all}");

    // AI tools: nothing of sealctl's, the .env rules kept, agents kept out of the folder
    let settings = std::fs::read_to_string(h.home.join(".claude/settings.json")).unwrap();
    assert!(!settings.contains("hook claude"), "{settings}");
    assert!(!settings.contains("sealctl secret get"), "{settings}");
    assert!(settings.contains("Read(**/.env)"), "{settings}");
    for rule in sealctl::ai::UNSEALED_DENY {
        assert!(settings.contains(rule), "{rule} missing: {settings}");
    }
    assert!(!h.home.join(".claude/skills/sealctl-secrets").exists());
    assert!(!h.home.join(".codex/rules/sealctl.rules").exists());
    assert!(sealctl::ai::installed().is_empty());
    assert!(run.join("files/.claude/settings.json").exists());

    // services and local state
    assert!(
        sealctl::agent::AgentClient::connect().is_err(),
        "session agent stopped"
    );
    for d in [".config/sealctl", ".local/share/sealctl", ".local/state/sealctl"] {
        assert!(!h.home.join(d).exists(), "{d}");
    }
    assert!(run.join("kept/keys/TEST.asc").exists());

    // the hand-back list: every object, no values
    let hb: serde_json::Value =
        serde_json::from_str(&std::fs::read_to_string(run.join("handback.json")).unwrap()).unwrap();
    assert_eq!(hb["kind"], "handback");
    assert_eq!(hb["from"], "0.6.0");
    let objs = hb["objects"].as_array().unwrap();
    assert_eq!(objs.iter().filter(|o| o["kind"] == "secret").count(), 7);
    assert_eq!(objs.iter().filter(|o| o["kind"] == "ssh").count(), 2);
    assert_eq!(objs[0]["value"]["store"], "folder");
    assert!(objs
        .iter()
        .all(|o| o.get("password").is_none() || o["kind"] != "ssh"));

    // nothing in a password store; no value anywhere but the folder's plain files
    assert!(h.fake_values().is_empty());
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let run_text = common::all_text_but_plain(&run);
    let argv = std::fs::read_to_string(h.fake.join("argv.log")).unwrap_or_default();
    for v in &canaries {
        for (what, hay) in [
            ("stdout", &stdout),
            ("stderr", &err),
            ("run folder (other than its plain files)", &run_text),
            ("argv", &argv),
        ] {
            assert!(!hay.contains(v.as_str()), "a value leaked into {what}");
        }
    }
    // sealctl's state folder is gone, so nothing can linger there
    assert!(!h.home.join(".local/state").join("sealctl").exists());
    nothing_lost(&h);
}

/// The steps of a clean run of `small`, and its end state.
fn reference(small: &FixtureOpts) -> (Vec<String>, BTreeMap<String, String>) {
    let h = setup(small);
    let out = h.unseal(ARGS, "unseal\n", &[]);
    assert!(out.status.success(), "{}", text(&out));
    let reference = end_state(&h);
    let journal = std::fs::read_to_string(h.run_dir().join("journal.jsonl")).unwrap();
    let steps: Vec<String> = journal
        .lines()
        .map(|l| serde_json::from_str::<serde_json::Value>(l).unwrap())
        .filter(|e| e["state"] == "done")
        .map(|e| e["step"].as_str().unwrap().to_string())
        .collect();
    assert!(steps.len() > 20, "{steps:?}");
    (steps, reference)
}

#[test]
fn killed_at_any_step_resumes_to_the_same_end() {
    let _g = serial();
    let small = FixtureOpts {
        services: false,
        ..Default::default()
    };
    let (steps, reference) = reference(&small);

    let quick = std::env::var_os("SEALCTL_TEST_QUICK").is_some();
    for (i, step) in steps.iter().enumerate() {
        // both points for every step: before it runs, and after it took effect but before the
        // journal says so (SEALCTL_TEST_QUICK: the second one only)
        for at in ["start", "before-done"] {
            if quick && at == "start" {
                continue;
            }
            let h = setup(&small);
            let kill = format!("{step}:{at}");
            let out = h.unseal(ARGS, "unseal\n", &[("SEALCTL_TEST_KILL", &kill)]);
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(out.status.signal(), Some(9), "{kill} (#{i}): {}", text(&out));
            }
            nothing_lost(&h);
            let out = h.unseal(&["--resume"], "", &[]);
            assert!(out.status.success(), "resume after {kill}: {}", text(&out));
            assert_eq!(end_state(&h), reference, "end state after a kill at {kill}");
            nothing_lost(&h);
        }
    }
}

/// A power cut, not just a kill: at each step boundary everything sealctl did not make durable
/// is thrown away (file data not fsynced, directory entries whose directory was not fsynced;
/// see sealctl::durable::tracker) and half a journal line is left, then the process dies.
/// `--resume` must end in the same state, nothing lost — and since every write of sealctl is
/// durable at once, the cut finds nothing to throw away.
#[test]
fn a_power_cut_at_any_step_loses_nothing_and_resumes_to_the_same_end() {
    let _g = serial();
    let small = FixtureOpts {
        services: false,
        ..Default::default()
    };
    let (steps, reference) = reference(&small);

    // after each step took effect, before the journal says so: the boundary where the object,
    // the folder and the journal disagree most (the kill test also covers the start of each
    // step); and the very first boundary, before anything was written in plain form
    for (i, step) in steps.iter().enumerate() {
        let points: &[&str] = if i == 0 {
            &["start", "before-done"]
        } else {
            &["before-done"]
        };
        for at in points {
            let h = setup(&small);
            let cut = format!("{step}:{at}");
            let report = h.tmp.path().join("powercut.txt");
            let out = h.unseal(
                ARGS,
                "unseal\n",
                &[
                    ("SEALCTL_TEST_POWERCUT", &cut),
                    ("SEALCTL_TEST_POWERCUT_REPORT", &report.display().to_string()),
                ],
            );
            {
                use std::os::unix::process::ExitStatusExt;
                assert_eq!(out.status.signal(), Some(9), "{cut} (#{i}): {}", text(&out));
            }
            let lost = std::fs::read_to_string(&report).expect("the cut wrote its report");
            assert_eq!(lost, "", "not durable at the power cut at {cut}:\n{lost}");
            let journal = std::fs::read_to_string(h.run_dir().join("journal.jsonl")).unwrap();
            assert!(!journal.ends_with('\n'), "a torn line was left at {cut}");
            nothing_lost(&h);
            let out = h.unseal(&["--resume"], "", &[]);
            assert!(
                out.status.success(),
                "resume after a power cut at {cut}: {}",
                text(&out)
            );
            assert_eq!(end_state(&h), reference, "end state after a power cut at {cut}");
            nothing_lost(&h);
        }
    }
}
