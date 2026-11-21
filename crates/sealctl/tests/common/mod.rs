//! Test helpers: a software OpenPGP key stands in for the Ledger, so the OS-tool and restic
//! code paths can be exercised in CI without hardware.

#![allow(dead_code)]

use std::path::Path;

use pgp::composed::{
    EncryptionCaps, KeyType, Message, SecretKeyParamsBuilder, SignedPublicKey, SignedSecretKey,
    SubkeyParamsBuilder,
};
use pgp::crypto::ecc_curve::ECCCurve;
use rand::thread_rng;

pub fn software_key() -> (SignedSecretKey, SignedPublicKey) {
    let sk = SecretKeyParamsBuilder::default()
        .key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("sealctl test <test@example.org>".into())
        .subkeys(vec![SubkeyParamsBuilder::default()
            .key_type(KeyType::ECDH(ECCCurve::Curve25519Legacy))
            .can_encrypt(EncryptionCaps::All)
            .build()
            .unwrap()])
        .build()
        .unwrap()
        .generate(thread_rng())
        .unwrap();
    let pk = SignedPublicKey::from(sk.clone());
    (sk, pk)
}

/// Point sealctl's config/data/state dirs into `root` and install the test certificate.
pub fn isolated_home(root: &Path, pk: &SignedPublicKey) {
    std::env::set_var("XDG_CONFIG_HOME", root.join("config"));
    std::env::set_var("XDG_DATA_HOME", root.join("data"));
    std::env::set_var("XDG_STATE_HOME", root.join("state"));
    let keys = sealctl::paths::keys_dir().unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    let armored = pk.to_armored_string(Default::default()).unwrap();
    std::fs::write(keys.join("TEST.asc"), armored).unwrap();
}

/// Decrypt an OpenPGP message with the software key (what the Ledger does in real use).
pub fn decrypt(sk: &SignedSecretKey, data: &[u8]) -> Vec<u8> {
    let (msg, _) = Message::from_armor(data).unwrap();
    let mut m = msg.decrypt(&"".into(), sk).unwrap();
    if m.is_compressed() {
        m = m.decompress().unwrap();
    }
    m.as_data_vec().unwrap()
}

pub fn have(bin: &str) -> bool {
    sealctl::util::which(bin)
}

/// Software stand-in for the Ledger's X25519 decryption key.
pub struct SoftOracle(pub x25519_dalek::StaticSecret);

impl SoftOracle {
    pub fn fixed() -> Self {
        SoftOracle(x25519_dalek::StaticSecret::from([7u8; 32]))
    }
}

impl sealctl::derive::Oracle for SoftOracle {
    fn x25519(&mut self, u: &[u8; 32]) -> anyhow::Result<[u8; 32]> {
        Ok(self
            .0
            .diffie_hellman(&x25519_dalek::PublicKey::from(*u))
            .to_bytes())
    }
}

// ---------------------------------------------------------------- unseal fixtures ----

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::sync::{Mutex, MutexGuard};
use std::time::Duration;

/// A test switch set by CI (`1`); unset or empty means off.
pub fn flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|v| !v.is_empty())
}

/// Tests in one file share the process environment (HOME): run them one at a time.
pub fn serial() -> MutexGuard<'static, ()> {
    static M: Mutex<()> = Mutex::new(());
    M.lock().unwrap_or_else(|e| e.into_inner())
}

/// Variables that would point sealctl, git or an AI tool outside the test's HOME.
const OUTSIDE: &[&str] = &[
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_STATE_HOME",
    "CLAUDE_CONFIG_DIR",
    "CODEX_HOME",
    "GEMINI_CLI_HOME",
    "QWEN_HOME",
    "COPILOT_HOME",
    "SEALCTL_SSH_DIR",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "SSH_AUTH_SOCK",
];

/// AI agents set these; the tests may themselves run inside one.
const AGENT_VARS: &[&str] = &[
    "CLAUDECODE",
    "CLAUDE_CODE_CHILD_SESSION",
    "CODEX_THREAD_ID",
    "CODEX_CI",
    "CODEX_SANDBOX",
    "GEMINI_CLI",
    "GEMINI_CLI_IN_SHELL",
    "QWEN_CODE",
    "COPILOT_AGENT_SESSION_ID",
    "CURSOR_AGENT",
    "OPENCODE",
    "OPENCODE_SESSION_ID",
    "AI_AGENT",
];

/// A throw-away HOME (in /tmp: socket paths must stay short). The process environment points
/// at it, so library calls and the agent use it too.
pub struct Home {
    pub tmp: tempfile::TempDir,
    pub home: PathBuf,
    /// Where the fake `op` and `bw` keep values.
    pub fake: PathBuf,
    /// A private ssh-agent standing in for the system one.
    pub ssh_agent: Option<(std::process::Child, PathBuf)>,
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = sealctl::agent::stop();
        if let Some((mut c, _)) = self.ssh_agent.take() {
            let _ = c.kill();
            let _ = c.wait();
        }
    }
}

pub fn new_home() -> Home {
    let tmp = tempfile::Builder::new().prefix("us").tempdir_in("/tmp").unwrap();
    let home = tmp.path().join("h");
    std::fs::create_dir_all(&home).unwrap();
    for v in OUTSIDE {
        std::env::remove_var(v);
    }
    std::env::set_var("HOME", &home);
    std::env::set_var("GIT_CONFIG_NOSYSTEM", "1");
    std::env::set_var("SEALCTL_NO_NOTIFY", "1");
    let fake = tmp.path().join("fake");
    Home {
        tmp,
        home,
        fake,
        ssh_agent: None,
    }
}

impl Home {
    /// `sealctl` (the binary under test) in this HOME, as a person at a terminal would run it.
    pub fn sealctl(&self) -> Command {
        let mut c = Command::new(env!("CARGO_BIN_EXE_sealctl"));
        for v in AGENT_VARS {
            c.env_remove(v);
        }
        for v in OUTSIDE {
            c.env_remove(v);
        }
        let bin = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bin");
        let path = format!("{}:{}", bin.display(), std::env::var("PATH").unwrap_or_default());
        c.env("HOME", &self.home)
            .env("PATH", path)
            .env("SEALCTL_AGENT", "0")
            .env("SEALCTL_NO_NOTIFY", "1")
            .env("SEALCTL_TEST_ASSUME_TTY", "1")
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("FAKE_STORE", &self.fake);
        if !flag("SEALCTL_TEST_KEYCHAIN") {
            c.env("SEALCTL_TEST_NO_APPLE_KEYCHAIN", "1");
        }
        if let Some((_, sock)) = &self.ssh_agent {
            c.env("SSH_AUTH_SOCK", sock);
        }
        c
    }

    /// Run `sealctl unseal <args>` with `input` on stdin.
    pub fn unseal(&self, args: &[&str], input: &str, extra_env: &[(&str, &str)]) -> Output {
        let mut c = self.sealctl();
        c.arg("unseal").args(args);
        for (k, v) in extra_env {
            c.env(k, v);
        }
        let mut child = c
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write;
            let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        }
        child.wait_with_output().unwrap()
    }

    /// Start a private ssh-agent (the "system" agent of the test).
    pub fn start_ssh_agent(&mut self) {
        if !have("ssh-agent") {
            return;
        }
        let sock = self.tmp.path().join("sa.sock");
        let child = Command::new("ssh-agent")
            .arg("-D")
            .arg("-a")
            .arg(&sock)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        for _ in 0..100 {
            if sock.exists() {
                break;
            }
            std::thread::sleep(Duration::from_millis(30));
        }
        self.ssh_agent = Some((child, sock));
    }

    pub fn ssh_agent_sock(&self) -> Option<PathBuf> {
        self.ssh_agent.as_ref().map(|(_, s)| s.clone())
    }

    /// Every value the fake `op` / `bw` hold.
    pub fn fake_values(&self) -> Vec<String> {
        let mut out = vec![];
        for sub in ["op", "bw"] {
            if let Ok(rd) = std::fs::read_dir(self.fake.join(sub)) {
                for e in rd.flatten() {
                    let p = e.path();
                    if p.extension().is_none() {
                        out.push(std::fs::read_to_string(p).unwrap());
                    }
                }
            }
        }
        out
    }

    /// The value the fake store holds for an item titled `sealctl: <kind> <name>`.
    pub fn fake_value(&self, title: &str) -> Option<String> {
        let rd = std::fs::read_dir(self.fake.join("op")).ok()?;
        for e in rd.flatten() {
            let p = e.path();
            if p.extension().is_some_and(|x| x == "title")
                && std::fs::read_to_string(&p).ok()?.trim() == title
            {
                return std::fs::read_to_string(p.with_extension("")).ok();
            }
        }
        None
    }

    /// The newest run folder (`~/sealctl-unsealed-<date>[-n]`).
    pub fn run_dir(&self) -> PathBuf {
        self.run_dirs().pop().expect("a run folder")
    }

    /// Every run folder in this HOME, oldest first.
    pub fn run_dirs(&self) -> Vec<PathBuf> {
        let mut v: Vec<(String, u32, PathBuf)> = std::fs::read_dir(&self.home)
            .unwrap()
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().into_owned();
                let rest = name.strip_prefix("sealctl-unsealed-")?.to_string();
                let (date, n) = match rest.get(10..) {
                    Some("") => (rest.clone(), 1),
                    Some(s) => (rest[..10].to_string(), s.trim_start_matches('-').parse().ok()?),
                    None => return None,
                };
                Some((date, n, e.path()))
            })
            .collect();
        v.sort();
        v.into_iter().map(|(_, _, p)| p).collect()
    }

    /// A line `<what>: <password>` of passwords.txt in the newest run folder.
    pub fn folder_password(&self, what: &str) -> Option<String> {
        let text = std::fs::read_to_string(self.run_dir().join("passwords.txt")).ok()?;
        text.lines()
            .filter(|l| !l.starts_with('#'))
            .find_map(|l| l.strip_prefix(&format!("{what}: ")).map(str::to_string))
    }

    /// The variables of a dotenv file in the newest run folder.
    pub fn folder_env(&self, file: &str) -> BTreeMap<String, String> {
        let text = std::fs::read_to_string(self.run_dir().join(file)).unwrap();
        sealctl::secrets::parse_dotenv(&text)
            .unwrap()
            .into_iter()
            .map(|(k, v)| (k, v.to_string()))
            .collect()
    }
}

/// Text of every file below `root` except the plain files `sealctl unseal` writes on purpose
/// (passwords.txt, secrets.env, backup-*.env, secrets-binary/): where no value may appear.
pub fn all_text_but_plain(root: &Path) -> String {
    let mut s = String::new();
    for (rel, kind) in tree(root) {
        let plain = rel == "passwords.txt"
            || rel == "secrets.env"
            || rel.starts_with("secrets-binary")
            || (rel.starts_with("backup-") && rel.ends_with(".env"));
        if plain || kind == "dir" || kind.starts_with("->") || kind == "special" {
            continue;
        }
        s.push_str(&String::from_utf8_lossy(&std::fs::read(root.join(rel)).unwrap()));
        s.push('\n');
    }
    s
}

/// Start the session agent with the software key standing in for the Ledger.
pub fn start_agent() {
    std::thread::spawn(|| {
        sealctl::agent::run_with(
            sealctl::Ctx {
                select: sealctl_ledger::Select::Usb,
                scan: Duration::from_secs(1),
            },
            sealctl::agent::Limits::default(),
            Some(Box::new(SoftOracle::fixed())),
        )
    });
    for _ in 0..100 {
        if sealctl::agent::AgentClient::connect().is_ok() {
            return;
        }
        std::thread::sleep(Duration::from_millis(30));
    }
    panic!("agent did not start");
}

/// Secret names and values of the fixture (canaries: they must never be printed).
pub fn fixture_secrets() -> Vec<(&'static str, String)> {
    vec![
        ("shop/openai-api-key", "CANARY-openai-0f3a9c7e51d2".into()),
        ("shop/database-url", "postgres://u:CANARY-db-77a1@h/db".into()),
        ("work/github-token", "CANARY-gh-6c2e81b0".into()),
        ("mail", "CANARY \"quoted\" $HOME \\ end".into()),
        ("a.b", "CANARY-dots-1".into()),
        ("x/y/z", "CANARY-deep-2".into()),
        ("cloud@acct+1", "CANARY-at-plus-3".into()),
    ]
}

/// SSH keys of the fixture: name → seed (deterministic, so two fixtures are alike).
pub const FIXTURE_SSH: &[(&str, u8)] = &[("ed25519", 1), ("github", 2)];

pub struct FixtureOpts {
    pub secrets: bool,
    pub ssh: bool,
    pub git: bool,
    pub ai: bool,
    pub shell: bool,
    pub services: bool,
}

impl Default for FixtureOpts {
    fn default() -> Self {
        FixtureOpts {
            secrets: true,
            ssh: true,
            git: true,
            ai: true,
            shell: true,
            services: flag("SEALCTL_TEST_SERVICES"),
        }
    }
}

/// A home set up with the 0.5.0 code: certificate, secret store, encrypted SSH key files, git
/// signing (global and one repository), Claude Code and Codex integrations, an IdentityAgent
/// line and an SSH_AUTH_SOCK export; services only with SEALCTL_TEST_SERVICES=1 (CI), since they
/// would replace the real ones of the machine running the tests.
pub fn fixture(h: &Home, o: &FixtureOpts) {
    let (_sk, pk) = software_key_fixed();
    let keys = sealctl::paths::keys_dir().unwrap();
    std::fs::create_dir_all(&keys).unwrap();
    std::fs::write(
        keys.join("TEST.asc"),
        pk.to_armored_string(Default::default()).unwrap(),
    )
    .unwrap();
    let mut ledger = SoftOracle::fixed();
    if o.secrets {
        for (n, v) in fixture_secrets() {
            sealctl::secrets::set(&mut ledger, n, v.as_bytes(), false).unwrap();
        }
    }
    let ssh = h.home.join(".ssh");
    if o.ssh {
        std::fs::create_dir_all(&ssh).unwrap();
        for (name, seed) in FIXTURE_SSH {
            let kp = ssh_key::private::Ed25519Keypair::from_seed(&[*seed; 32]);
            let mut key = ssh_key::PrivateKey::from(kp);
            key.set_comment(format!("{name}@sealctl-test"));
            let pass = sealctl::ssh::passphrase_for(&mut ledger, key.public_key()).unwrap();
            let enc = key.encrypt(&mut rand::rngs::OsRng, pass.as_bytes()).unwrap();
            let path = ssh.join(format!("sealctl_{name}"));
            sealctl::paths::write_private(&path, enc.to_openssh(ssh_key::LineEnding::LF).unwrap().as_bytes())
                .unwrap();
            std::fs::write(
                path.with_extension("pub"),
                format!("{}\n", key.public_key().to_openssh().unwrap()),
            )
            .unwrap();
        }
        std::fs::write(
            ssh.join("config"),
            "# test config\n\
             Host github.com\n\
             \x20   IdentityFile ~/.ssh/sealctl_github.pub\n\
             \x20   IdentitiesOnly yes\n\
             \n\
             Host *\n\
             \x20   IdentityAgent ~/.local/state/sealctl/ssh-agent.sock\n",
        )
        .unwrap();
    }
    if o.shell {
        std::fs::write(
            h.home.join(".zshrc"),
            "export PATH=\"$HOME/bin:$PATH\"\nexport SSH_AUTH_SOCK=$HOME/.local/state/sealctl/ssh-agent.sock\n",
        )
        .unwrap();
    }
    if o.git && o.ssh {
        let out = Command::new("git")
            .args(["config", "--global", "user.email", "test@example.org"])
            .output()
            .unwrap();
        assert!(out.status.success());
        sealctl::git::setup(false, Some("ed25519")).expect("git setup --global");
        let repo = h.home.join("src").join("proj");
        std::fs::create_dir_all(&repo).unwrap();
        assert!(Command::new("git")
            .args(["init", "-q"])
            .arg(&repo)
            .status()
            .unwrap()
            .success());
        let cfg = repo.join(".git/config");
        let line = sealctl::ssh::read_public(&ssh.join("sealctl_github"))
            .unwrap()
            .to_openssh()
            .unwrap();
        let shim = sealctl::paths::config_dir().unwrap().join("git-ssh-keygen");
        for (k, v) in [
            ("gpg.format", "ssh".to_string()),
            ("user.signingkey", format!("key::{line}")),
            ("gpg.ssh.program", shim.display().to_string()),
            ("commit.gpgsign", "true".into()),
        ] {
            assert!(Command::new("git")
                .args(["config", "--file"])
                .arg(&cfg)
                .args([k, &v])
                .status()
                .unwrap()
                .success());
        }
    }
    if o.ai {
        let reports = sealctl::ai::install(&["claude".into(), "codex".into()]).unwrap();
        assert_eq!(reports.len(), 2);
    }
    if o.services {
        for (label, every) in [
            (sealctl::ssh::AGENT_LABEL, None),
            (sealctl::backup::SCHEDULE_LABEL, Some(3600)),
        ] {
            // a harmless program under the real labels; files stay even if loading fails
            let _ = sealctl::service::install(&sealctl::service::Service {
                label,
                args: vec!["/bin/sleep".into(), "86400".into()],
                every_secs: every,
                description: "sealctl unseal test",
            });
        }
    }
}

/// A software key whose certificate is the same in every fixture.
pub fn software_key_fixed() -> (SignedSecretKey, SignedPublicKey) {
    use std::sync::OnceLock;
    static K: OnceLock<(SignedSecretKey, SignedPublicKey)> = OnceLock::new();
    K.get_or_init(software_key).clone()
}

/// Relative path → SHA-256 (files), `dir`, or `-> target` (links), below `root`.
pub fn tree(root: &Path) -> BTreeMap<String, String> {
    fn walk(base: &Path, p: &Path, out: &mut BTreeMap<String, String>) {
        let Ok(rd) = std::fs::read_dir(p) else { return };
        for e in rd.flatten() {
            let path = e.path();
            let rel = path.strip_prefix(base).unwrap().to_string_lossy().into_owned();
            let meta = std::fs::symlink_metadata(&path).unwrap();
            if meta.file_type().is_symlink() {
                out.insert(
                    rel,
                    format!("-> {}", std::fs::read_link(&path).unwrap().display()),
                );
            } else if meta.is_dir() {
                out.insert(rel.clone(), "dir".into());
                walk(base, &path, out);
            } else if meta.file_type().is_file() {
                out.insert(rel, sealctl::util::sha256_hex(&std::fs::read(&path).unwrap()));
            } else {
                out.insert(rel, "special".into());
            }
        }
    }
    let mut out = BTreeMap::new();
    walk(root, root, &mut out);
    out
}

/// All bytes of every regular file below `root`, as text (for leak checks).
pub fn all_text(root: &Path) -> String {
    let mut s = String::new();
    for (rel, kind) in tree(root) {
        if kind != "dir" && !kind.starts_with("->") && kind != "special" {
            s.push_str(&String::from_utf8_lossy(&std::fs::read(root.join(rel)).unwrap()));
            s.push('\n');
        }
    }
    s
}

/// Text of an `Output` (stdout + stderr) for messages.
pub fn text(o: &Output) -> String {
    format!(
        "status {:?}\n--- stdout\n{}\n--- stderr\n{}",
        o.status,
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}
