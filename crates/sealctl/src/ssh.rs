//! SSH agent for encrypted key files (`~/.ssh/sealctl_<name>`, made by `sealctl ssh keygen`):
//! standard OpenSSH private keys whose passphrase is derived on the Ledger from the key's own
//! public fingerprint. The agent decrypts a key on first use and keeps it for the sealctl
//! session (`sealctl agent`): signing counts as activity, and the key is forgotten when the
//! session ends — 1 h without use, 24 h at most (`SEALCTL_AGENT_IDLE_MIN`,
//! `SEALCTL_AGENT_MAX_HOURS`), `sealctl lock`, or `ssh-add -D`.
//!
//! (Until 0.4 the agent also offered the Ledger's OpenPGP authentication key, signing every
//! login on the device. That made each connection depend on the device being awake and
//! unlocked, so it was removed in 0.5.)

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context, Result};
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

use crate::derive::{self, Oracle, Purpose};
use crate::device::Ctx;
use crate::paths;

// ---- encrypted key files ----

const FILE_PREFIX: &str = "sealctl_";

/// The passphrase of an encrypted key file, derived from its public key's fingerprint.
pub fn passphrase_for(oracle: &mut dyn Oracle, public: &PublicKey) -> Result<Zeroizing<String>> {
    derive::passphrase(
        oracle,
        Purpose::Ssh,
        &public.fingerprint(HashAlg::Sha256).to_string(),
    )
}

pub fn key_path(name: &str) -> Result<PathBuf> {
    if name.is_empty()
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        bail!("key names use letters, digits, '-' and '_'");
    }
    Ok(paths::ssh_dir()?.join(format!("{FILE_PREFIX}{name}")))
}

/// Encrypted key files sealctl manages: `~/.ssh/sealctl_*` (without `.pub`).
pub fn key_files() -> Vec<PathBuf> {
    let Ok(dir) = paths::ssh_dir() else {
        return vec![];
    };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut v: Vec<PathBuf> = rd
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with(FILE_PREFIX) && !n.ends_with(".pub"))
        })
        .collect();
    v.sort();
    v
}

/// The public half of an encrypted key file (readable without the passphrase).
pub fn read_public(path: &Path) -> Result<PublicKey> {
    let text = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    Ok(PrivateKey::from_openssh(text)
        .with_context(|| format!("{} is not an OpenSSH private key", path.display()))?
        .public_key()
        .clone())
}

/// Decrypt a key file with its derived passphrase.
pub fn unlock_file(oracle: &mut dyn Oracle, path: &Path) -> Result<PrivateKey> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let enc = PrivateKey::from_openssh(&*text)?;
    if !enc.is_encrypted() {
        bail!("{} is not encrypted — refusing to use it", path.display());
    }
    let pass = passphrase_for(oracle, enc.public_key())?;
    enc.decrypt(pass.as_bytes())
        .with_context(|| format!("decrypting {} (made with another seed?)", path.display()))
}

/// `sealctl ssh keygen`: a random Ed25519 key, encrypted with the passphrase derived from its
/// fingerprint. Writes `~/.ssh/sealctl_<name>` (0600) and `.pub`.
pub fn keygen(oracle: &mut dyn Oracle, name: &str, comment: &str) -> Result<PathBuf> {
    let path = key_path(name)?;
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let mut rng = rand::rngs::OsRng;
    let mut key = PrivateKey::random(&mut rng, Algorithm::Ed25519)?;
    key.set_comment(comment);
    let pass = passphrase_for(oracle, key.public_key())?;
    let enc = key.encrypt(&mut rng, pass.as_bytes())?;
    // prove it opens again before anything is written
    if enc.decrypt(pass.as_bytes())?.public_key() != key.public_key() {
        bail!("encrypted key does not round-trip");
    }
    std::fs::create_dir_all(path.parent().context("ssh dir")?)?;
    paths::write_private(&path, enc.to_openssh(LineEnding::LF)?.as_bytes())?;
    std::fs::write(
        path.with_extension("pub"),
        format!("{}\n", key.public_key().to_openssh()?),
    )?;
    Ok(path)
}

/// `sealctl ssh import`: re-encrypt an existing (unencrypted) OpenSSH key with the passphrase
/// derived from its fingerprint, as `~/.ssh/sealctl_<name>`. Same key pair — servers need no
/// change. The original file is left untouched (delete it yourself once the import works).
pub fn import(oracle: &mut dyn Oracle, src: &Path, name: &str) -> Result<PathBuf> {
    let path = key_path(name)?;
    if path.exists() {
        bail!("{} already exists", path.display());
    }
    let text =
        Zeroizing::new(std::fs::read_to_string(src).with_context(|| format!("reading {}", src.display()))?);
    let key = PrivateKey::from_openssh(&*text)
        .with_context(|| format!("{} is not an OpenSSH private key", src.display()))?;
    if key.is_encrypted() {
        bail!(
            "{} has a passphrase — remove it first (ssh-keygen -p -f {}) or import a copy",
            src.display(),
            src.display()
        );
    }
    let pass = passphrase_for(oracle, key.public_key())?;
    let mut rng = rand::rngs::OsRng;
    let enc = key.encrypt(&mut rng, pass.as_bytes())?;
    if enc.decrypt(pass.as_bytes())?.public_key() != key.public_key() {
        bail!("encrypted key does not round-trip");
    }
    std::fs::create_dir_all(path.parent().context("ssh dir")?)?;
    paths::write_private(&path, enc.to_openssh(LineEnding::LF)?.as_bytes())?;
    std::fs::write(
        path.with_extension("pub"),
        format!("{}\n", key.public_key().to_openssh()?),
    )?;
    Ok(path)
}

/// Forget decrypted keys in the running agent (`ssh-add -D`).
pub fn forget() -> bool {
    let Ok(sock) = socket_path() else {
        return false;
    };
    sock.exists()
        && std::process::Command::new("ssh-add")
            .arg("-D")
            .env("SSH_AUTH_SOCK", &sock)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok_and(|s| s.success())
}

struct Unlocked {
    key: PrivateKey,
    since: crate::util::Since,
    used: crate::util::Since,
}

/// Decrypted keys, by fingerprint.
struct SoftKeys {
    limits: crate::agent::Limits,
    keys: HashMap<String, Unlocked>,
    /// Bumped by "forget all": an unlock that was in flight meanwhile must not be cached.
    generation: u64,
}

impl SoftKeys {
    fn prune(&mut self) {
        let l = self.limits;
        self.keys
            .retain(|_, u| u.used.elapsed() < l.idle && u.since.elapsed() < l.max_life);
    }
}

pub const AGENT_LABEL: &str = "io.github.oleksiyp.sealctl.ssh-agent";

#[derive(Clone)]
struct Agent {
    ctx: Ctx,
    soft: Arc<Mutex<SoftKeys>>,
}

fn agent_err(msg: impl std::fmt::Display) -> AgentError {
    AgentError::other(std::io::Error::other(msg.to_string()))
}

impl Agent {
    /// Sign with an encrypted key file, decrypting it first if needed (Ledger, once a session).
    async fn sign_soft(&self, path: PathBuf, fp: String, data: Vec<u8>) -> Result<Signature, AgentError> {
        use signature::Signer;
        {
            let mut soft = self.soft.lock().unwrap_or_else(|e| e.into_inner());
            soft.prune();
            if let Some(u) = soft.keys.get_mut(&fp) {
                u.used = crate::util::Since::now();
                let sig = u.key.try_sign(&data).map_err(agent_err);
                // signing keeps the sealctl session alive, like any other use of it
                tokio::task::spawn_blocking(|| {
                    let _ = crate::agent::AgentClient::connect().and_then(|mut c| c.touch());
                });
                return sig;
            }
        }
        let ctx = self.ctx;
        let generation = self.soft.lock().unwrap_or_else(|e| e.into_inner()).generation;
        let key = tokio::task::spawn_blocking(move || -> Result<PrivateKey> {
            let mut oracle = crate::agent::oracle(&ctx)?;
            unlock_file(oracle.as_mut(), &path)
        })
        .await
        .map_err(agent_err)?
        .map_err(|e| {
            eprintln!("unlocking key failed: {e:#}");
            agent_err(format!("{e:#}"))
        })?;
        log::info!("unlocked {fp} for this session");
        let sig = key.try_sign(&data).map_err(agent_err)?;
        let now = crate::util::Since::now();
        let mut soft = self.soft.lock().unwrap_or_else(|e| e.into_inner());
        if soft.generation != generation {
            // forgotten while we were waiting for the Ledger: sign this once, keep nothing
            return Ok(sig);
        }
        soft.keys.insert(
            fp,
            Unlocked {
                key,
                since: now,
                used: now,
            },
        );
        Ok(sig)
    }
}

#[ssh_agent_lib::async_trait]
impl Session for Agent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(key_files()
            .iter()
            .filter_map(|p| read_public(p).ok())
            .map(|k| Identity {
                credential: PublicCredential::Key(k.key_data().clone()),
                comment: k.comment().to_string(),
            })
            .collect())
    }

    async fn remove_all_identities(&mut self) -> Result<(), AgentError> {
        // the key files stay; only the decrypted copies are forgotten
        let mut soft = self.soft.lock().unwrap_or_else(|e| e.into_inner());
        soft.keys.clear();
        soft.generation += 1;
        log::info!("forgot all decrypted keys");
        Ok(())
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        let PublicCredential::Key(wanted) = &req.credential else {
            return Err(agent_err("unknown key"));
        };
        for path in key_files() {
            if let Ok(public) = read_public(&path) {
                if public.key_data() == wanted {
                    let fp = public.fingerprint(HashAlg::Sha256).to_string();
                    log::info!("sign request with {fp} ({} bytes)", req.data.len());
                    return self.sign_soft(path, fp, req.data.clone()).await;
                }
            }
        }
        Err(agent_err("unknown key"))
    }
}

pub fn socket_path() -> Result<PathBuf> {
    paths::ssh_agent_socket()
}

/// Run the agent in the foreground.
pub fn run_agent(ctx: Ctx, socket: Option<PathBuf>) -> Result<()> {
    let socket = match socket {
        // A caller-chosen location: only make sure the folder exists (it may be /tmp).
        Some(s) => {
            let dir = s.parent().context("socket dir")?;
            std::fs::create_dir_all(dir)?;
            // someone else's (or a group-writable) folder would let them swap the socket
            {
                use std::os::unix::fs::MetadataExt;
                let m = std::fs::metadata(dir)?;
                let sticky = m.mode() & 0o1000 != 0; // like /tmp: others can't replace our file
                if m.uid() != current_uid() && !sticky {
                    bail!(
                        "{} belongs to another user — choose a folder of your own",
                        dir.display()
                    );
                }
                if m.mode() & 0o022 != 0 && !sticky {
                    bail!(
                        "{} is writable by others — choose a private folder",
                        dir.display()
                    );
                }
            }
            s
        }
        // Our own state folder: keep it private to the user.
        None => {
            let s = socket_path()?;
            paths::ensure_private_dir(s.parent().context("socket dir")?)?;
            s
        }
    };
    let _ = std::fs::remove_file(&socket);

    let soft = Arc::new(Mutex::new(SoftKeys {
        limits: crate::agent::Limits::from_env(),
        keys: HashMap::new(),
        generation: 0,
    }));
    let agent = Agent {
        ctx,
        soft: soft.clone(),
    };
    eprintln!("sealctl ssh-agent listening on {}", socket.display());
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async move {
        let listener = tokio::net::UnixListener::bind(&socket)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o600))?;
        }
        // Forget decrypted keys when they expire, and when the sealctl session they were
        // unlocked in ends (idle, 24 h, `sealctl lock`): one session for volumes, secrets, SSH.
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(15));
            loop {
                tick.tick().await;
                let has_keys = !soft.lock().unwrap_or_else(|e| e.into_inner()).keys.is_empty();
                let alive = !has_keys
                    || tokio::task::spawn_blocking(crate::agent::session_alive)
                        .await
                        .unwrap_or(false);
                let mut s = soft.lock().unwrap_or_else(|e| e.into_inner());
                if !alive && !s.keys.is_empty() {
                    log::info!("sealctl session ended — forgetting SSH keys");
                    s.keys.clear();
                    s.generation += 1;
                }
                s.prune();
            }
        });
        tokio::select! {
            r = listen(listener, agent) => r.map_err(|e| anyhow::anyhow!("{e}")),
            _ = tokio::signal::ctrl_c() => Ok(()),
        }
    })
}

pub fn install(ctx_args: Vec<String>) -> Result<()> {
    let exe = crate::util::stable_exe()?;
    let mut args = vec![exe.to_string_lossy().into_owned()];
    args.extend(ctx_args);
    args.extend(["ssh".into(), "agent".into()]);
    crate::service::install(&crate::service::Service {
        label: AGENT_LABEL,
        args,
        every_secs: None,
        description: "sealctl SSH agent (key files unlocked by the Ledger)",
    })?;
    let sock = socket_path()?;
    println!("✅ ssh-agent installed, socket: {}", sock.display());
    println!("\nUse it for all SSH connections — add to ~/.ssh/config:\n");
    println!("    Host *\n        IdentityAgent {}\n", sock.display());
    println!("or per shell:  export SSH_AUTH_SOCK={}", sock.display());
    if key_files().is_empty() {
        println!("\nNo SSH key yet — create one: sealctl ssh keygen");
    }
    Ok(())
}

fn current_uid() -> u32 {
    // the current user's uid, via the owner of a file we just created in our state dir
    paths::state_dir()
        .ok()
        .and_then(|d| {
            std::fs::create_dir_all(&d).ok()?;
            use std::os::unix::fs::MetadataExt;
            std::fs::metadata(&d).ok().map(|m| m.uid())
        })
        .unwrap_or(u32::MAX)
}
