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

/// Hand an encrypted key file back as a standard OpenSSH key: decrypt `path` with its derived
/// passphrase and write it to `dest` (0600) and `dest.pub` (0644), encrypted with `passphrase`
/// (`None`: no passphrase), as `ssh-keygen` would. The written file is read back and must give
/// the same public key. Returns that public key.
pub fn export(
    oracle: &mut dyn Oracle,
    path: &Path,
    dest: &Path,
    passphrase: Option<&[u8]>,
) -> Result<PublicKey> {
    let key = unlock_file(oracle, path)?;
    let public = key.public_key().clone();
    let text = match passphrase {
        Some(p) => key
            .encrypt(&mut rand::rngs::OsRng, p)?
            .to_openssh(LineEnding::LF)?,
        None => key.to_openssh(LineEnding::LF)?,
    };
    if let Some(dir) = dest.parent() {
        std::fs::create_dir_all(dir)?;
    }
    paths::write_private(dest, text.as_bytes())?;
    let pub_path = public_path(dest);
    std::fs::write(&pub_path, format!("{}\n", public.to_openssh()?))?;
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&pub_path, std::fs::Permissions::from_mode(0o644))?;
    }
    if !opens_with(dest, passphrase, &public)? {
        bail!("{} does not open again with its new passphrase", dest.display());
    }
    Ok(public)
}

/// `<key>.pub` next to a private key file.
pub fn public_path(private: &Path) -> PathBuf {
    let mut s = private.as_os_str().to_owned();
    s.push(".pub");
    PathBuf::from(s)
}

/// Does the OpenSSH key file at `path` open with `passphrase` and give `public`?
pub fn opens_with(path: &Path, passphrase: Option<&[u8]>, public: &PublicKey) -> Result<bool> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let key = PrivateKey::from_openssh(&*text)?;
    let key = match (key.is_encrypted(), passphrase) {
        (true, Some(p)) => match key.decrypt(p) {
            Ok(k) => k,
            Err(_) => return Ok(false),
        },
        (false, None) => key,
        _ => return Ok(false),
    };
    Ok(key.public_key().key_data() == public.key_data())
}

/// Open a standard key file with its passphrase (for the checks of `sealctl unseal`).
pub fn open_file(path: &Path, passphrase: Option<&[u8]>) -> Result<PrivateKey> {
    let text = Zeroizing::new(std::fs::read_to_string(path)?);
    let key = PrivateKey::from_openssh(&*text)?;
    match passphrase {
        Some(p) if key.is_encrypted() => key
            .decrypt(p)
            .with_context(|| format!("{} does not open with its passphrase", path.display())),
        _ => Ok(key),
    }
}

/// macOS: `ssh-add --apple-use-keychain <dest>` against the system agent (`agent_sock`), the
/// passphrase handed over by the hidden `sealctl askpass` reading the FIFO `fifo` (never an
/// argument or environment value). Without `keychain` the key is only added to the agent.
pub fn ssh_add_keychain(
    dest: &Path,
    passphrase: Option<&[u8]>,
    agent_sock: &Path,
    fifo_dir: &Path,
    keychain: bool,
) -> Result<()> {
    let mut cmd = std::process::Command::new("ssh-add");
    if keychain {
        cmd.arg("--apple-use-keychain");
    }
    cmd.arg(dest)
        .env("SSH_AUTH_SOCK", agent_sock)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let feeder = match passphrase {
        None => None,
        Some(p) => {
            let fifo = fifo_dir.join("askpass.fifo");
            let _ = std::fs::remove_file(&fifo);
            let c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes())?;
            // SAFETY: mkfifo with a valid NUL-terminated path.
            if unsafe { libc::mkfifo(c.as_ptr(), 0o600) } != 0 {
                bail!("mkfifo {}: {}", fifo.display(), std::io::Error::last_os_error());
            }
            // SSH_ASKPASS is one program run as `<program> <prompt>`: a wrapper adds `askpass`
            let wrapper = fifo_dir.join("askpass.sh");
            let exe = crate::util::stable_exe()?;
            std::fs::write(
                &wrapper,
                format!(
                    "#!/bin/sh\nexec '{}' askpass \"$@\"\n",
                    exe.to_string_lossy().replace('\'', r"'\''")
                ),
            )?;
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&wrapper, std::fs::Permissions::from_mode(0o700))?;
            }
            cmd.env("SSH_ASKPASS", &wrapper)
                .env("SSH_ASKPASS_REQUIRE", "force")
                .env(
                    "DISPLAY",
                    std::env::var("DISPLAY").unwrap_or_else(|_| ":0".into()),
                )
                .env("SEALCTL_ASKPASS_FD", &fifo);
            let data = Zeroizing::new(p.to_vec());
            let f2 = fifo.clone();
            Some((
                fifo,
                std::thread::spawn(move || {
                    use std::io::Write;
                    // blocks until askpass opens the FIFO; ssh-add asks only once
                    if let Ok(mut w) = std::fs::OpenOptions::new().write(true).open(&f2) {
                        let _ = w.write_all(&data);
                    }
                }),
            ))
        }
    };
    let out = cmd.output().context("running ssh-add")?;
    if let Some((fifo, t)) = feeder {
        if !t.is_finished() {
            // unblock the writer if askpass never ran
            let _ = std::fs::OpenOptions::new().read(true).open(&fifo);
        }
        let _ = t.join();
        let _ = std::fs::remove_file(&fifo);
    }
    if !out.status.success() {
        bail!("ssh-add failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

/// `sealctl askpass`: print the passphrase waiting in the FIFO (or inherited descriptor) named
/// by `SEALCTL_ASKPASS_FD` to stdout, for `ssh-add`. Reads it once.
pub fn askpass() -> Result<()> {
    use std::io::{Read, Write};
    let src = std::env::var("SEALCTL_ASKPASS_FD").context("SEALCTL_ASKPASS_FD is not set")?;
    let mut buf = Zeroizing::new(Vec::new());
    if let Ok(fd) = src.parse::<i32>() {
        if fd <= 2 {
            bail!("SEALCTL_ASKPASS_FD must name a pipe");
        }
        use std::os::fd::FromRawFd;
        // SAFETY: the descriptor was inherited for this purpose and is used once.
        let mut f = unsafe { std::fs::File::from_raw_fd(fd) };
        f.read_to_end(&mut buf)?;
    } else {
        let p = Path::new(&src);
        use std::os::unix::fs::FileTypeExt;
        if !std::fs::metadata(p)?.file_type().is_fifo() {
            bail!("{} is not a pipe", p.display());
        }
        std::fs::File::open(p)?.read_to_end(&mut buf)?;
    }
    let mut out = std::io::stdout().lock();
    out.write_all(&buf)?;
    out.write_all(b"\n")?;
    Ok(())
}

/// Fingerprints (SHA256) of the keys an agent holds (`ssh-add -l`).
pub fn agent_fingerprints(agent_sock: &Path) -> Vec<String> {
    std::process::Command::new("ssh-add")
        .arg("-l")
        .env("SSH_AUTH_SOCK", agent_sock)
        .stdin(std::process::Stdio::null())
        .output()
        .map(|o| {
            String::from_utf8_lossy(&o.stdout)
                .lines()
                .filter_map(|l| l.split_whitespace().nth(1).map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
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
