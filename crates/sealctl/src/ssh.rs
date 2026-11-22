//! SSH keys in the store (`ssh/<name>`, an OpenSSH private key) and the SSH agent the daemon
//! serves on `~/.local/state/sealctl/ssh-agent.sock`. Public keys live in
//! `~/.ssh/sealctl_<name>.pub`. Signing uses the session's store key; while Locked, the first
//! signature opens the session (the phone is asked).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use ssh_agent_lib::agent::{listen, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::{Algorithm, LineEnding, PrivateKey, PublicKey, Signature};
use zeroize::Zeroizing;

use crate::daemon::{client, Daemon, Events, ValuesReq};
use crate::exit::{self, fail};
use crate::paths;

/// Valid SSH key names: letters, digits, `-` and `_`.
pub fn check_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 40
        || !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(fail(exit::USAGE, "SSH key names use letters, digits, - and _."));
    }
    Ok(())
}

/// `~/.ssh/sealctl_<name>.pub`.
pub fn pub_path(name: &str) -> Result<PathBuf> {
    Ok(paths::ssh_dir()?.join(format!("sealctl_{name}.pub")))
}

/// Names of the SSH keys this machine has public halves for.
pub fn names() -> Vec<String> {
    let Ok(dir) = paths::ssh_dir() else { return vec![] };
    let Ok(rd) = std::fs::read_dir(dir) else {
        return vec![];
    };
    let mut v: Vec<String> = rd
        .flatten()
        .filter_map(|e| {
            let n = e.file_name().to_string_lossy().into_owned();
            n.strip_prefix("sealctl_")
                .and_then(|r| r.strip_suffix(".pub"))
                .map(str::to_owned)
        })
        .collect();
    v.sort();
    v
}

/// The public key of `name`.
pub fn read_public(name: &str) -> Result<PublicKey> {
    let p = pub_path(name)?;
    let text =
        std::fs::read_to_string(&p).map_err(|_| fail(exit::NOT_FOUND, format!("No SSH key {name}.")))?;
    PublicKey::from_openssh(text.trim()).with_context(|| format!("{} is not a public key", p.display()))
}

fn store_key(name: &str, key: &PrivateKey, force: bool) -> Result<()> {
    let text = Zeroizing::new(key.to_openssh(LineEnding::LF)?.to_string());
    client::store_set(&format!("ssh/{name}"), text.as_bytes(), false, force)?;
    let pubp = pub_path(name)?;
    std::fs::create_dir_all(pubp.parent().context("ssh dir")?)?;
    paths::write_mode(
        &pubp,
        format!("{}\n", key.public_key().to_openssh()?).as_bytes(),
        0o644,
    )?;
    Ok(())
}

/// `sealctl ssh keygen`: a new Ed25519 key stored as `ssh/<name>`. Returns the public line.
pub fn keygen(name: &str, comment: &str) -> Result<String> {
    check_name(name)?;
    if pub_path(name)?.exists() {
        return Err(fail(exit::USAGE, format!("SSH key {name} exists already.")));
    }
    let mut key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519)?;
    key.set_comment(comment);
    store_key(name, &key, false)?;
    Ok(key.public_key().to_openssh()?)
}

/// `sealctl seal ssh <file>`: stores an existing OpenSSH private key as `ssh/<name>`.
pub fn import(src: &Path, name: &str) -> Result<String> {
    import_given(src, name, None)
}

/// [`import`] with the key's passphrase given (from a hand-back list).
pub fn import_given(src: &Path, name: &str, given: Option<&[u8]>) -> Result<String> {
    check_name(name)?;
    let text = Zeroizing::new(
        std::fs::read_to_string(src)
            .map_err(|_| fail(exit::NOT_FOUND, format!("Cannot read {}.", src.display())))?,
    );
    let mut key = PrivateKey::from_openssh(&*text).map_err(|_| {
        fail(
            exit::USAGE,
            format!("{} is not an OpenSSH private key.", src.display()),
        )
    })?;
    if key.is_encrypted() {
        let pass = match given {
            Some(g) => Zeroizing::new(String::from_utf8_lossy(g).into_owned()),
            None => {
                crate::term::require_person("reading a key passphrase", None)?;
                crate::util::read_hidden(&format!("Passphrase of {}: ", src.display()))?
            }
        };
        key = key
            .decrypt(pass.as_bytes())
            .map_err(|_| fail(exit::WRONG_KEY, "Wrong passphrase."))?;
    }
    store_key(name, &key, true)?;
    // check: the stored key's public half equals the file's
    let back = client::values(&[format!("ssh/{name}")], Some(("ssh", name)))?;
    let stored = PrivateKey::from_openssh(std::str::from_utf8(&back[0].1).unwrap_or(""))?;
    if stored.public_key().key_data() != key.public_key().key_data() {
        return Err(fail(exit::ERROR, "The stored key does not match the file."));
    }
    Ok(key.public_key().to_openssh()?)
}

#[derive(Clone)]
struct Agent {
    daemon: Arc<Daemon>,
}

fn agent_err(msg: impl std::fmt::Display) -> AgentError {
    AgentError::other(std::io::Error::other(msg.to_string()))
}

#[ssh_agent_lib::async_trait]
impl Session for Agent {
    async fn request_identities(&mut self) -> Result<Vec<Identity>, AgentError> {
        Ok(names()
            .iter()
            .filter_map(|n| read_public(n).ok())
            .map(|k| Identity {
                credential: PublicCredential::Key(k.key_data().clone()),
                comment: k.comment().to_string(),
            })
            .collect())
    }

    async fn sign(&mut self, req: SignRequest) -> Result<Signature, AgentError> {
        let PublicCredential::Key(wanted) = &req.credential else {
            return Err(agent_err("unknown key"));
        };
        let name = names()
            .into_iter()
            .find(|n| read_public(n).is_ok_and(|k| k.key_data() == wanted))
            .ok_or_else(|| agent_err("unknown key"))?;
        let ev: Events = Arc::new(|_| {});
        let vals = self
            .daemon
            .op_values(
                ValuesReq {
                    names: vec![format!("ssh/{name}")],
                    agent: None,
                    cmd: format!("ssh signature with {name}"),
                    cwd: String::new(),
                    subject: Some(("ssh".into(), name.clone())),
                    notify: true,
                },
                &ev,
            )
            .await
            .map_err(|e| agent_err(exit::message_of(&e)))?;
        let text = Zeroizing::new(String::from_utf8_lossy(&vals[0].1).into_owned());
        let key = PrivateKey::from_openssh(&*text).map_err(agent_err)?;
        use signature::Signer;
        key.try_sign(&req.data).map_err(agent_err)
    }
}

/// The agent socket.
pub fn socket_path() -> Result<PathBuf> {
    paths::ssh_agent_socket()
}

/// Binds the agent socket and serves it from the daemon.
pub fn start_agent(daemon: Arc<Daemon>) {
    let Ok(sock) = socket_path() else { return };
    let _ = std::fs::remove_file(&sock);
    let listener = match tokio::net::UnixListener::bind(&sock) {
        Ok(l) => l,
        Err(e) => {
            log::warn!("SSH agent socket: {e}");
            return;
        }
    };
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o600));
    tokio::spawn(async move {
        if let Err(e) = listen(listener, Agent { daemon }).await {
            log::warn!("SSH agent: {e}");
        }
    });
}

/// `sealctl ssh setup`: the `~/.ssh/config` lines.
pub fn setup_text() -> Result<String> {
    let sock = socket_path()?;
    Ok(format!("Host *\n    IdentityAgent {}\n", sock.display()))
}
