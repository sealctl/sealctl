//! Asking the phone (SPEC 9, protocol.md Request and reply): seal a request, send it on a
//! wait socket, open and check the reply, take the keys out of it.

use std::path::Path;
use std::time::Duration;

use anyhow::Result;
use sealctl_core::request::{new_request_id, seal_request, SealedRequest};
use sealctl_core::wire::{ReplyBody, Repository, RequestBody, RequestContext, RequestItem};
use sealctl_core::{ObjectKey, PhonePublic};
use serde_json::Value;

use crate::exit::{self, fail};
use crate::machine::{self, Paired};
use crate::relay::{self, Relay, WaitEnd};

/// How long the CLI waits for the phone.
pub const WAIT: Duration = Duration::from_secs(300);

/// What a sent request turned into.
#[allow(clippy::large_enum_variant)]
pub enum Asked {
    /// The phone answered.
    Reply {
        /// The opened and verified reply.
        reply: ReplyBody,
        /// The request id.
        id: String,
        /// The request as sent.
        request: SealedRequest,
    },
    /// The phone approved with a delay; the reply is held by the relay until `release_at`.
    Delayed {
        /// The request, kept for its one-time key.
        request: SealedRequest,
        /// When the reply is released, Unix ms.
        release_at: u64,
    },
}

/// A request body with the common fields.
pub fn body(why: &str) -> RequestBody {
    RequestBody {
        v: 1,
        t: machine::now_ms(),
        why: why.to_string(),
        ..RequestBody::default()
    }
}

/// Seals and sends `body`, calling `waiting` once with the number match (if any) before
/// waiting. Handles a move to a new phone key once.
pub async fn send(
    relay: &Relay,
    paired: &mut Paired,
    body: RequestBody,
    waiting: &mut (dyn FnMut(Option<u8>) + Send),
) -> Result<Asked> {
    send_for(relay, paired, body, waiting, WAIT).await
}

/// [`send`] with another wait than 5 minutes.
pub async fn send_for(
    relay: &Relay,
    paired: &mut Paired,
    body: RequestBody,
    waiting: &mut (dyn FnMut(Option<u8>) + Send),
    wait: Duration,
) -> Result<Asked> {
    send_shared(relay, &tokio::sync::Mutex::new(paired), body, waiting, wait).await
}

/// A pairing [`send_shared`] locks: the daemon's shared one, or a command's own.
pub trait PairedMut: Send {
    /// The pairing.
    fn get(&mut self) -> &mut Paired;
}

impl PairedMut for Paired {
    fn get(&mut self) -> &mut Paired {
        self
    }
}

impl PairedMut for &mut Paired {
    fn get(&mut self) -> &mut Paired {
        self
    }
}

/// [`send_for`] for a pairing others may use too (the daemon). The pairing is locked only to
/// seal the request and to follow a move, never while the phone is waited for, so that
/// statuses and machine messages (a `lock` from the phone) go on during a wait of up to 5
/// minutes.
pub async fn send_shared<P: PairedMut>(
    relay: &Relay,
    paired: &tokio::sync::Mutex<P>,
    body: RequestBody,
    waiting: &mut (dyn FnMut(Option<u8>) + Send),
    wait: Duration,
) -> Result<Asked> {
    let mut moved_once = false;
    let mut slowed = 0;
    loop {
        let (id, request, keys, phone_id, phone_key) = {
            let mut guard = paired.lock().await;
            let paired = guard.get();
            let id = new_request_id().map_err(|e| anyhow::anyhow!("{e}"))?;
            let request = seal_request(&paired.keys, &paired.phone, &id, body.clone())
                .map_err(|e| anyhow::anyhow!("sealing the request: {e}"))?;
            (
                id,
                request,
                paired.keys_copy()?,
                paired.phone_id().to_string(),
                paired.phone.identity,
            )
        };
        waiting(request.number);
        let deadline = tokio::time::Instant::now() + wait;
        let end = relay
            .wait(
                &keys,
                &phone_id,
                &id,
                &request.sealed,
                wait.as_secs().clamp(1, 300),
                deadline,
            )
            .await;
        let end = match end {
            Ok(e) => e,
            Err(e) => match relay::refused(&e).cloned() {
                Some(a) if a.status == 403 => WaitEnd::Error("forbidden".into()),
                Some(a) if slowed < 3 && relay::backoff(&a).is_some() => {
                    slowed += 1;
                    relay::slow_down(relay::backoff(&a).unwrap_or(10)).await;
                    continue;
                }
                Some(a) => return Err(relay::error_for(&a)),
                None => return Err(e),
            },
        };
        match end {
            WaitEnd::Reply(sealed) => {
                let reply = request
                    .open_reply(keys.public(), &phone_key, &sealed)
                    .map_err(|_| {
                        fail(
                            exit::ERROR,
                            "The phone's reply did not check out (bad_reply). Nothing was used.",
                        )
                    })?;
                return Ok(Asked::Reply { reply, id, request });
            }
            WaitEnd::Delayed { release_at, .. } => return Ok(Asked::Delayed { request, release_at }),
            WaitEnd::Expired => return Err(fail(exit::NO_ANSWER, "No answer from your phone in 5 minutes.")),
            WaitEnd::Error(code) if matches!(code.as_str(), "unpaired" | "moved" | "forbidden") => {
                if !moved_once && look_up(relay, paired.lock().await.get()).await? {
                    moved_once = true;
                    continue;
                }
                return Err(exit::unpaired());
            }
            WaitEnd::Error(code) => {
                return Err(fail(
                    exit::RELAY,
                    format!(
                        "The relay refused the request ({code}). Status: {}",
                        relay::STATUS_PAGE
                    ),
                ))
            }
        }
    }
}

/// After `403` or a wait closed with `unpaired`/`moved`: `GET /v1/machines/{M}`. A valid move
/// proof moves this machine to the new phone key (returns `true`); `404` means unpaired.
pub async fn look_up(relay: &Relay, paired: &mut Paired) -> Result<bool> {
    let path = format!("/v1/machines/{}", paired.file.machine);
    let a = relay.request(Some(&paired.keys), "GET", &path, None).await?;
    if a.status == 404 {
        return Err(exit::unpaired());
    }
    if !a.ok() {
        return Err(relay::error_for(&a));
    }
    let phone = a.body["phone"].as_str().unwrap_or("");
    let proof = a.body["proof"].as_str().unwrap_or("");
    if phone == paired.file.phone {
        return Ok(false);
    }
    let (Some(new_p), Some(old_p)) = (
        machine::decode_key32(phone),
        machine::decode_key32(&paired.file.phone),
    ) else {
        return Err(exit::unpaired());
    };
    let x_new = sealctl_core::pairing::verify_move_proof(&old_p, &new_p, paired.keys.public(), proof)
        .map_err(|_| exit::unpaired())?;
    let x_b64 = machine::b64u(&x_new);
    paired.file.previous_phone = Some(std::mem::replace(&mut paired.file.phone, phone.to_string()));
    paired.file.phone_box = x_b64.clone();
    paired.phone = PhonePublic::from_b64u(phone, &x_b64).map_err(|e| anyhow::anyhow!("{e}"))?;
    paired.file.save()?;
    log::info!("moved to the new phone key");
    if crate::daemon::IN_DAEMON.load(std::sync::atomic::Ordering::SeqCst) {
        // the daemon has no terminal: its objects move to the new words by themselves
        crate::migrate::rewrap_in_background();
    }
    Ok(true)
}

/// The error for a reply with `ok: false` (SPEC 5.5). `number` is the number shown.
pub fn refusal(reply: &ReplyBody, number: Option<u8>, words_hint: Option<&str>) -> anyhow::Error {
    let err = reply.err.as_deref().unwrap_or("declined");
    match err {
        "declined" => fail(exit::DECLINED, "Declined on your phone."),
        "no_match" => fail(
            exit::DECLINED,
            match number {
                Some(n) => format!("The number picked on your phone was not {n}. Nothing was changed."),
                None => "Your phone needs the number shown at the machine's terminal. Nothing was changed.".into(),
            },
        ),
        "held" => {
            let at = jiff::Timestamp::now() + jiff::SignedDuration::from_hours(1);
            fail(
                exit::DECLINED,
                format!(
                    "Your phone holds sensitive requests from this machine for an hour after a wrong number. Try again after {}.",
                    at.to_zoned(jiff::tz::TimeZone::system()).strftime("%H:%M")
                ),
            )
        }
        "not_near" => fail(
            exit::DECLINED,
            "Your phone could not tell it is near this machine. Run this at the machine's terminal and pick the number on your phone.",
        ),
        "no_biometrics" => fail(
            exit::DECLINED,
            format!(
                "Your phone needs Face ID or a fingerprint for this. Fix that on the phone, or use your card: {} --words",
                words_hint.unwrap_or("sealctl unseal")
            ),
        ),
        "phone_locked" => fail(exit::DECLINED, "Your phone was locked. Unlock it and try again."),
        "wrong_key" => fail(exit::WRONG_KEY, "Your phone's words do not open this object."),
        "retired_words" => fail(
            exit::WRONG_KEY,
            "This object is sealed with retired words. Type them on the phone to move it to your current words.",
        ),
        "outside_plan" => fail(exit::ERROR, "Your phone refused a key outside the approved plan."),
        "plan_expired" => fail(
            exit::DECLINED,
            "The approval on your phone expired. Run the command again for a new approval.",
        ),
        other => fail(exit::ERROR, format!("Your phone refused the request ({other}).")),
    }
}

/// The keys of `wanted` from a reply, each checked against the check on file (`c`).
pub fn keys_from(reply: &ReplyBody, wanted: &[RequestItem]) -> Result<Vec<ObjectKey>> {
    let mut out = Vec::with_capacity(wanted.len());
    for item in wanted {
        let Some(k) = reply.keys.iter().find(|k| k.p == item.purpose && k.i == item.id) else {
            return Err(fail(
                exit::ERROR,
                format!("Your phone sent no key for {}:{}.", item.purpose, item.id),
            ));
        };
        if let Some(err) = &k.err {
            return Err(key_error(err, k.retired.as_deref(), item, reply.w.as_deref()));
        }
        let text = k.k.as_ref().map(|s| s.as_str()).unwrap_or("");
        let key =
            ObjectKey::from_b64u(text).map_err(|_| fail(exit::ERROR, "The phone sent a malformed key."))?;
        if let Some(c) = &item.check {
            if &key.check() != c {
                return Err(fail(
                    exit::WRONG_KEY,
                    format!(
                        "The key from your phone does not open {}:{} (check mismatch).",
                        item.purpose, item.id
                    ),
                ));
            }
        }
        out.push(key);
    }
    Ok(out)
}

/// The error for a key item the phone could not answer.
pub fn key_error(
    err: &str,
    retired: Option<&str>,
    item: &RequestItem,
    phone_words: Option<&str>,
) -> anyhow::Error {
    let words = item.words.as_deref().unwrap_or("????");
    match (err, retired) {
        ("retired_words", Some(date)) => fail(
            exit::WRONG_KEY,
            format!("Sealed with words {words}, retired {date}. Type them on the phone to move this object to your current words."),
        ),
        _ => match phone_words {
            Some(pw) if pw != words => fail(
                exit::WRONG_KEY,
                format!("Sealed with words {words}; your phone has words {pw}."),
            ),
            _ => fail(
                exit::WRONG_KEY,
                format!("Your phone's words do not open {}:{}.", item.purpose, item.id),
            ),
        },
    }
}

/// `ctx` for a request: agent, repository, command, folder and this machine's name.
pub fn context(paired: &Paired, agent: Option<&str>, cmd: &str, cwd: &Path) -> RequestContext {
    RequestContext {
        agent: agent.map(str::to_owned),
        repo: repo_of(cwd),
        command: crate::guard::mask_command(cmd).chars().take(120).collect(),
        cwd: crate::paths::tilde(cwd).chars().take(120).collect(),
        user: paired.file.name.clone(),
        subject: None,
        names: Vec::new(),
    }
}

/// The repository of `cwd` (protocol.md `ctx.repo`): the `origin` remote normalised to
/// `host/owner/name`, or the root path without a remote.
pub fn repo_of(cwd: &Path) -> Option<Repository> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(cwd)
        .stderr(std::process::Stdio::null())
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let root = String::from_utf8_lossy(&out.stdout).trim().to_string();
    let remote = std::process::Command::new("git")
        .args(["config", "--get", "remote.origin.url"])
        .current_dir(cwd)
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .filter(|s| !s.is_empty());
    let folder = Path::new(&root)
        .file_name()
        .map(|f| f.to_string_lossy().into_owned())
        .unwrap_or_default();
    match remote.as_deref().and_then(normalise_remote) {
        Some(id) => {
            let name = id.split_once('/').map_or(id.as_str(), |x| x.1).to_string();
            Some(Repository { id, name })
        }
        None => Some(Repository {
            id: root,
            name: folder,
        }),
    }
}

/// `git@github.com:acme/shop.git` and `https://user@GitHub.com:443/acme/shop` → `github.com/acme/shop`.
pub fn normalise_remote(url: &str) -> Option<String> {
    let url = url.trim();
    let (host, path) = if let Some((_, rest)) = url.split_once("://") {
        let rest = rest.rsplit_once('@').map_or(rest, |(_, r)| r);
        rest.split_once('/')?
    } else {
        let rest = url.rsplit_once('@').map_or(url, |(_, r)| r);
        rest.split_once(':')?
    };
    let host = host.split(':').next()?.to_lowercase();
    let path = path.trim_matches('/').trim_end_matches(".git");
    (!host.is_empty() && !path.is_empty()).then(|| format!("{host}/{path}"))
}

/// One delayed approval as the relay lists it.
#[derive(Debug, Clone)]
pub struct Delayed {
    /// Its id.
    pub id: String,
    /// The machine that asked, or `None` for an action on the phone.
    pub machine: Option<String>,
    /// When it takes effect, Unix ms.
    pub release_at: u64,
    /// `waiting`, `released` or `cancelled`.
    pub state: String,
    /// Who cancelled it: `phone` or a machine key.
    pub by: Option<String>,
    /// The sealed reply, for the machine that asked once released.
    pub sealed: Option<String>,
}

impl Delayed {
    /// From a relay answer (one item of `GET .../delayed`, or `GET .../delayed/{id}`).
    pub fn from_json(v: &Value) -> Delayed {
        let by = v["cancelled"]["by"]
            .as_str()
            .or_else(|| v["by"].as_str())
            .map(str::to_owned);
        Delayed {
            id: v["id"].as_str().unwrap_or("").to_string(),
            machine: v["machine"].as_str().map(str::to_owned),
            release_at: v["releaseAt"].as_u64().unwrap_or(0),
            state: v["state"]
                .as_str()
                .unwrap_or(if by.is_some() { "cancelled" } else { "waiting" })
                .to_string(),
            by,
            sealed: v["sealed"].as_str().map(str::to_owned),
        }
    }
}

/// `GET /v1/phones/{phone}/delayed`.
pub async fn delayed_list(relay: &Relay, paired: &Paired) -> Result<Vec<Delayed>> {
    let v = relay
        .call(
            &paired.keys,
            "GET",
            &format!("/v1/phones/{}/delayed", paired.phone_id()),
            None,
        )
        .await?;
    Ok(v["delayed"]
        .as_array()
        .map(|a| a.iter().map(Delayed::from_json).collect())
        .unwrap_or_default())
}

/// `GET /v1/phones/{phone}/delayed/{id}`; `None` when gone.
pub async fn delayed_get(relay: &Relay, paired: &Paired, id: &str) -> Result<Option<Delayed>> {
    let a = relay
        .request(
            Some(&paired.keys),
            "GET",
            &format!("/v1/phones/{}/delayed/{id}", paired.phone_id()),
            None,
        )
        .await?;
    if a.status == 404 {
        return Ok(None);
    }
    if !a.ok() {
        return Err(relay::error_for(&a));
    }
    Ok(Some(Delayed::from_json(&a.body)))
}

/// `POST /v1/phones/{phone}/delayed/{id}/cancel`; `false` when gone.
pub async fn delayed_cancel(relay: &Relay, paired: &Paired, id: &str) -> Result<bool> {
    let a = relay
        .request(
            Some(&paired.keys),
            "POST",
            &format!("/v1/phones/{}/delayed/{id}/cancel", paired.phone_id()),
            Some(&serde_json::json!({})),
        )
        .await?;
    if a.status == 404 {
        return Ok(false);
    }
    if !a.ok() {
        return Err(relay::error_for(&a));
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remotes() {
        assert_eq!(
            normalise_remote("git@github.com:acme/shop.git").unwrap(),
            "github.com/acme/shop"
        );
        assert_eq!(
            normalise_remote("https://user@GitHub.com:443/acme/shop/").unwrap(),
            "github.com/acme/shop"
        );
        assert_eq!(
            normalise_remote("ssh://git@gitlab.example.com:2222/a/b/c.git").unwrap(),
            "gitlab.example.com/a/b/c"
        );
        assert!(normalise_remote("nonsense").is_none());
    }
}
