//! SSH keys in the store (`ssh/<name>`, an OpenSSH private key) and the SSH agent the daemon
//! serves on `~/.local/state/sealctl/ssh-agent.sock`. Public keys live in
//! `~/.ssh/sealctl_<name>.pub`. Signing uses the session's store key; while Locked, the first
//! signature opens the session (the phone is asked).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use ssh_agent_lib::agent::{listen, ListeningSocket, Session};
use ssh_agent_lib::error::AgentError;
use ssh_agent_lib::proto::{Identity, PublicCredential, SignRequest};
use ssh_key::private::KeypairData;
use ssh_key::public::KeyData;
use ssh_key::{Algorithm, HashAlg, LineEnding, PrivateKey, PublicKey, Signature};
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
    /// The process at the other end of the agent socket (`ssh`, `ssh-keygen`), when known.
    peer: Option<i32>,
    /// Becomes `true` when that process closed the connection.
    gone: tokio::sync::watch::Receiver<bool>,
}

/// One [`Agent`] per connection, knowing the process that connected.
struct Agents {
    daemon: Arc<Daemon>,
}

impl ssh_agent_lib::agent::Agent<Listener> for Agents {
    fn new_session(&mut self, socket: &Conn) -> impl Session {
        Agent {
            daemon: self.daemon.clone(),
            peer: socket.peer,
            gone: socket.gone.clone(),
        }
    }
}

/// The agent socket. Each connection is served through an in-memory pipe: the agent protocol
/// reads a request only after it answered the last one, so the pipe is what sees the client
/// close its end (Ctrl-C of `ssh`) while a signature waits for the phone, and withdraws it.
#[derive(Debug)]
struct Listener(tokio::net::UnixListener);

#[ssh_agent_lib::async_trait]
impl ListeningSocket for Listener {
    type Stream = Conn;

    async fn accept(&mut self) -> std::io::Result<Conn> {
        let (s, _) = self.0.accept().await?;
        Ok(Conn::serve(s))
    }
}

/// One connection as the agent protocol sees it.
struct Conn {
    io: tokio::io::DuplexStream,
    peer: Option<i32>,
    gone: tokio::sync::watch::Receiver<bool>,
}

impl std::fmt::Debug for Conn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Conn")
            .field("peer", &self.peer)
            .finish_non_exhaustive()
    }
}

impl Conn {
    /// Copies between the client and the pipe until both ends are closed; the client closing
    /// its end (or failing) marks the connection gone.
    fn serve(client: tokio::net::UnixStream) -> Conn {
        use tokio::io::AsyncWriteExt;
        let peer = client.peer_cred().ok().and_then(|c| c.pid());
        let (io, ours) = tokio::io::duplex(64 * 1024);
        let (gone_tx, gone) = tokio::sync::watch::channel(false);
        tokio::spawn(async move {
            let (mut from_client, mut to_client) = client.into_split();
            let (mut from_agent, mut to_agent) = tokio::io::split(ours);
            let up = async {
                let _ = tokio::io::copy(&mut from_client, &mut to_agent).await;
                let _ = gone_tx.send(true);
                let _ = to_agent.shutdown().await;
            };
            let down = async {
                let _ = tokio::io::copy(&mut from_agent, &mut to_client).await;
                let _ = to_client.shutdown().await;
            };
            tokio::join!(up, down);
        });
        Conn { io, peer, gone }
    }
}

impl tokio::io::AsyncRead for Conn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Conn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.io).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

/// What a signature with key `name` is for, from the process that asked: a git commit or tag
/// (with its repository and agent), an SSH login (with its host), or the key (SPEC 5.2).
fn about_signature(name: &str, peer: Option<i32>) -> crate::desktop::About {
    let Some(pid) = peer else {
        return crate::desktop::ssh_about(name, &[], None, None);
    };
    let chain = crate::caller::chain(pid, 12);
    let agent = crate::guard::agent_in_env(&crate::caller::env_of(pid))
        .or_else(|| crate::caller::agent_in(&chain))
        .map(str::to_owned);
    let repo = crate::caller::cwd_of(pid)
        .and_then(|cwd| crate::approve::repo_of(&cwd))
        .map(|r| r.name)
        .filter(|r| !r.is_empty());
    crate::desktop::ssh_about(name, &chain, repo, agent)
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
        // refused before the phone is asked, which would approve a signature nobody can make
        if let KeyData::Rsa(public) = wanted {
            if rsa_hash(req.flags).is_none() {
                return Err(agent_err(
                    "ssh-rsa (SHA-1) signatures are not supported; use rsa-sha2-256 or rsa-sha2-512",
                ));
            }
            if rsa_bits(&public.n) < MIN_RSA_BITS {
                return Err(agent_err(RSA_TOO_SHORT));
            }
        }
        let name = names()
            .into_iter()
            .find(|n| read_public(n).is_ok_and(|k| k.key_data() == wanted))
            .ok_or_else(|| agent_err("unknown key"))?;
        let ev: Events = Arc::new(|_| {});
        let peer = self.peer;
        let key = name.clone();
        let about = tokio::task::spawn_blocking(move || about_signature(&key, peer))
            .await
            .ok();
        // the client closing the connection (Ctrl-C) withdraws the request on the phone
        let vals = crate::daemon::for_client(
            self.gone.clone(),
            self.daemon.op_values(
                ValuesReq {
                    names: vec![format!("ssh/{name}")],
                    agent: None,
                    cmd: format!("ssh signature with {name}"),
                    cwd: String::new(),
                    subject: Some(("ssh".into(), name.clone())),
                    // nobody watches a terminal: git hides the signer's output
                    notify: true,
                    about,
                },
                &ev,
            ),
        )
        .await
        .map_err(|e| agent_err(exit::message_of(&e)))?;
        let text = Zeroizing::new(String::from_utf8_lossy(&vals[0].1).into_owned());
        let key = PrivateKey::from_openssh(&*text).map_err(agent_err)?;
        sign_with(&key, &req.data, req.flags).map_err(agent_err)
    }
}

/// `SSH_AGENT_RSA_SHA2_256` and `SSH_AGENT_RSA_SHA2_512`: the hash an RSA signature uses.
const RSA_SHA2_256: u32 = 2;
const RSA_SHA2_512: u32 = 4;

/// The hash a sign request asks of an RSA key; `None` for plain `ssh-rsa` (SHA-1).
fn rsa_hash(flags: u32) -> Option<HashAlg> {
    if flags & RSA_SHA2_512 != 0 {
        Some(HashAlg::Sha512)
    } else if flags & RSA_SHA2_256 != 0 {
        Some(HashAlg::Sha256)
    } else {
        None
    }
}

/// Signs `data` as the request's flags ask: an RSA key with the requested SHA-2 hash, any other
/// key by its own algorithm.
fn sign_with(key: &PrivateKey, data: &[u8], flags: u32) -> Result<Signature> {
    use rsa::signature::{SignatureEncoding, Signer};
    let KeypairData::Rsa(pair) = key.key_data() else {
        return Ok(key.try_sign(data)?);
    };
    let private = rsa_private_key(pair)?;
    let (hash, sig) = match rsa_hash(flags) {
        Some(HashAlg::Sha256) => (
            HashAlg::Sha256,
            rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha256>::new(private)
                .try_sign(data)?
                .to_vec(),
        ),
        Some(HashAlg::Sha512) => (
            HashAlg::Sha512,
            rsa::pkcs1v15::SigningKey::<rsa::sha2::Sha512>::new(private)
                .try_sign(data)?
                .to_vec(),
        ),
        _ => anyhow::bail!("ssh-rsa (SHA-1) signatures are not supported"),
    };
    Ok(Signature::new(Algorithm::Rsa { hash: Some(hash) }, sig)?)
}

/// The shortest RSA modulus the agent signs with, as ssh-key's own conversion requires.
const MIN_RSA_BITS: usize = 2048;
const RSA_TOO_SHORT: &str = "RSA keys shorter than 2048 bits are not supported";

/// The size of an RSA modulus in bits, counted in whole bytes as ssh-key and the `rsa` crate do.
fn rsa_bits(n: &ssh_key::Mpint) -> usize {
    n.as_positive_bytes().map_or(0, |b| b.len() * 8)
}

/// The `rsa` crate's key for an OpenSSH RSA key pair. Built here from its components: ssh-key
/// 0.6's own conversion passes `p` twice instead of `p` and `q`, which the `rsa` crate rejects.
/// Like that conversion, it refuses a modulus under 2048 bits.
fn rsa_private_key(pair: &ssh_key::private::RsaKeypair) -> Result<rsa::RsaPrivateKey> {
    use rsa::traits::PublicKeyParts;
    let big = |m: &ssh_key::Mpint| rsa::BigUint::try_from(m);
    let key = rsa::RsaPrivateKey::from_components(
        big(&pair.public.n)?,
        big(&pair.public.e)?,
        big(&pair.private.d)?,
        vec![big(&pair.private.p)?, big(&pair.private.q)?],
    )?;
    if key.size().saturating_mul(8) < MIN_RSA_BITS {
        anyhow::bail!(RSA_TOO_SHORT);
    }
    Ok(key)
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
        if let Err(e) = listen(Listener(listener), Agents { daemon }).await {
            log::warn!("SSH agent: {e}");
        }
    });
}

/// `sealctl ssh setup`: the `~/.ssh/config` lines.
pub fn setup_text() -> Result<String> {
    let sock = socket_path()?;
    Ok(format!("Host *\n    IdentityAgent {}\n", sock.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::signature::Verifier;

    /// An RSA key signs with the hash the request asks for, and the signature verifies.
    #[test]
    fn rsa_signs_with_the_requested_hash() {
        // ssh-keygen: generating an RSA key in a debug build takes minutes
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("k");
        let made = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "rsa", "-b", "2048", "-N", "", "-f"])
            .arg(&file)
            .status();
        if !made.is_ok_and(|s| s.success()) {
            eprintln!("skipped: needs ssh-keygen");
            return;
        }
        let key = PrivateKey::from_openssh(std::fs::read_to_string(&file).unwrap()).unwrap();
        let data = b"session data";
        for (flags, want) in [(RSA_SHA2_256, HashAlg::Sha256), (RSA_SHA2_512, HashAlg::Sha512)] {
            let sig = sign_with(&key, data, flags).unwrap();
            assert_eq!(sig.algorithm(), Algorithm::Rsa { hash: Some(want) });
            key.public_key().key_data().verify(data, &sig).unwrap();
        }
        assert!(sign_with(&key, data, 0).is_err(), "ssh-rsa (SHA-1) is refused");
        let KeyData::Rsa(public) = key.public_key().key_data() else {
            unreachable!()
        };
        assert_eq!(rsa_bits(&public.n), 2048);
    }

    #[test]
    fn rsa_keys_under_2048_bits_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("k");
        let made = std::process::Command::new("ssh-keygen")
            .args(["-q", "-t", "rsa", "-b", "1024", "-N", "", "-f"])
            .arg(&file)
            .status();
        if !made.is_ok_and(|s| s.success()) {
            eprintln!("skipped: needs ssh-keygen that still makes 1024-bit RSA keys");
            return;
        }
        let key = PrivateKey::from_openssh(std::fs::read_to_string(&file).unwrap()).unwrap();
        let KeyData::Rsa(public) = key.public_key().key_data() else {
            unreachable!()
        };
        assert!(rsa_bits(&public.n) < MIN_RSA_BITS);
        let err = sign_with(&key, b"x", RSA_SHA2_256).unwrap_err();
        assert!(err.to_string().contains("2048"), "{err}");
    }

    #[test]
    fn ed25519_ignores_rsa_flags() {
        let key = PrivateKey::random(&mut ssh_key::rand_core::OsRng, Algorithm::Ed25519).unwrap();
        let sig = sign_with(&key, b"x", 0).unwrap();
        assert_eq!(sig.algorithm(), Algorithm::Ed25519);
    }
}
