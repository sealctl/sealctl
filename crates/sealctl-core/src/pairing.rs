//! Pairing: the QR link, the pairing proof, the move proof after new words, and the licence
//! move proof.

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::phone::PhoneKeys;
use crate::time;

/// The link the QR code holds, up to the `#`.
pub const LINK_PREFIX: &str = "https://sealctl.com/p#";
/// The relay used when the link has no `r`.
pub const DEFAULT_RELAY: &str = "https://relay.sealctl.com";
/// Protocol major version this core speaks.
pub const PROTOCOL_VERSION: u32 = 1;

const MAX_FIELD: usize = 200;

/// A scanned or typed pairing code. The pairing code itself stays inside the core.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PairingOffer {
    machine: [u8; 32],
    machine_box: [u8; 32],
    code: Zeroizing<[u8; 16]>,
    name: String,
    os: String,
    model: Option<String>,
    hint: Option<String>,
    relay: Option<String>,
    version: u32,
    expires: u64,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PairingOffer {
    /// Parses the link `https://sealctl.com/p#v=1&…`, or the part after `#` on its own.
    /// Refuses a newer major version, malformed fields and an expired code.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn parse(text: String) -> Result<Self> {
        Self::parse_at(&text, time::now_unix_secs())
    }

    /// The machine id `M`, 43 characters.
    pub fn machine_key(&self) -> String {
        crypto::b64u(&self.machine)
    }

    /// The machine box key `MX`, 43 characters.
    pub fn machine_box_key(&self) -> String {
        crypto::b64u(&self.machine_box)
    }

    /// `user@full-hostname`.
    pub fn name(&self) -> String {
        self.name.clone()
    }

    /// OS name and version; empty when the link has none.
    pub fn os(&self) -> String {
        self.os.clone()
    }

    /// Hardware model, when known.
    pub fn model(&self) -> Option<String> {
        self.model.clone()
    }

    /// Hardware hint, when known.
    pub fn hint(&self) -> Option<String> {
        self.hint.clone()
    }

    /// The relay origin the machine uses (the default when the link has no `r`).
    pub fn relay_origin(&self) -> String {
        self.relay.clone().unwrap_or_else(|| DEFAULT_RELAY.to_owned())
    }

    /// The protocol major version of the link.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Expiry, Unix seconds.
    pub fn expires(&self) -> u64 {
        self.expires
    }

    /// The machine's duplicate-name tag.
    pub fn tag(&self) -> String {
        crate::machine::tag(&self.machine)
    }
}

impl PairingOffer {
    /// [`PairingOffer::parse`] against a given clock (Unix seconds).
    pub fn parse_at(text: &str, now_unix: u64) -> Result<Self> {
        let text = text.trim();
        let payload = match text.split_once('#') {
            Some((prefix, rest)) if prefix == &LINK_PREFIX[..LINK_PREFIX.len() - 1] => rest,
            Some(_) => return Err(CoreError::BadLink),
            None => text,
        };
        let mut v = None;
        let (mut m, mut x, mut s, mut n, mut o, mut d, mut h, mut e, mut r) =
            (None, None, None, None, None, None, None, None, None);
        for pair in payload.split('&') {
            let (key, value) = pair.split_once('=').ok_or(CoreError::BadLink)?;
            let value = percent_decode(value).ok_or(CoreError::BadLink)?;
            let slot = match key {
                "v" => &mut v,
                "m" => &mut m,
                "x" => &mut x,
                "s" => &mut s,
                "n" => &mut n,
                "o" => &mut o,
                "d" => &mut d,
                "h" => &mut h,
                "e" => &mut e,
                "r" => &mut r,
                _ => continue, // unknown parameters are ignored
            };
            if slot.replace(value).is_some() {
                return Err(CoreError::BadLink);
            }
        }
        let version: u32 = v
            .ok_or(CoreError::BadLink)?
            .parse()
            .map_err(|_| CoreError::BadLink)?;
        if version > PROTOCOL_VERSION {
            return Err(CoreError::NewerVersion);
        }
        if version != PROTOCOL_VERSION {
            return Err(CoreError::BadLink);
        }
        let key32 = |t: Option<String>| -> Result<[u8; 32]> {
            crypto::b64u_decode_fixed::<32>(&t.ok_or(CoreError::BadLink)?).ok_or(CoreError::BadLink)
        };
        let machine = key32(m)?;
        let machine_box = key32(x)?;
        let code = Zeroizing::new(
            crypto::b64u_decode_fixed::<16>(&s.ok_or(CoreError::BadLink)?).ok_or(CoreError::BadLink)?,
        );
        let name = n.ok_or(CoreError::BadLink)?;
        if !field_ok(&name, 1) {
            return Err(CoreError::BadLink);
        }
        let os = o.unwrap_or_default();
        if !field_ok(&os, 0) {
            return Err(CoreError::BadLink);
        }
        if d.as_deref().is_some_and(|d| !field_ok(d, 1)) {
            return Err(CoreError::BadLink);
        }
        if h.as_deref()
            .is_some_and(|h| crypto::b64u_decode_fixed::<16>(h).is_none())
        {
            return Err(CoreError::BadLink);
        }
        let relay = match r {
            Some(r) => Some(valid_origin(&r).ok_or(CoreError::BadLink)?),
            None => None,
        };
        let expires: u64 = e
            .ok_or(CoreError::BadLink)?
            .parse()
            .map_err(|_| CoreError::BadLink)?;
        if now_unix > expires {
            return Err(CoreError::Expired);
        }
        Ok(Self {
            machine,
            machine_box,
            code,
            name,
            os,
            model: d,
            hint: h,
            relay,
            version,
            expires,
        })
    }

    /// `M`.
    pub fn machine_public(&self) -> &[u8; 32] {
        &self.machine
    }

    /// `MX`.
    pub fn machine_box_public(&self) -> &[u8; 32] {
        &self.machine_box
    }
}

/// What a machine puts in its pairing link.
pub struct PairingLink<'a> {
    /// `M`.
    pub machine: &'a [u8; 32],
    /// `MX`.
    pub machine_box: &'a [u8; 32],
    /// The pairing code `c`.
    pub code: &'a [u8; 16],
    /// `user@full-hostname`.
    pub name: &'a str,
    /// OS name and version.
    pub os: &'a str,
    /// Hardware model.
    pub model: Option<&'a str>,
    /// Hardware hint.
    pub hint: Option<&'a str>,
    /// Expiry, Unix seconds.
    pub expires: u64,
    /// Relay origin, `None` for the default.
    pub relay: Option<&'a str>,
}

impl PairingLink<'_> {
    /// The fragment after `#`, parameters in the order protocol.md lists them.
    pub fn payload(&self) -> String {
        let mut out = format!(
            "v={}&m={}&x={}&s={}&n={}&o={}",
            PROTOCOL_VERSION,
            crypto::b64u(self.machine),
            crypto::b64u(self.machine_box),
            crypto::b64u(self.code),
            percent_encode(self.name),
            percent_encode(self.os)
        );
        if let Some(d) = self.model {
            out.push_str(&format!("&d={}", percent_encode(d)));
        }
        if let Some(h) = self.hint {
            out.push_str(&format!("&h={}", percent_encode(h)));
        }
        out.push_str(&format!("&e={}", self.expires));
        if let Some(r) = self.relay.filter(|r| *r != DEFAULT_RELAY) {
            out.push_str(&format!("&r={}", percent_encode(r)));
        }
        out
    }

    /// The whole link for the QR code.
    pub fn link(&self) -> String {
        format!("{LINK_PREFIX}{}", self.payload())
    }
}

fn field_ok(text: &str, min: usize) -> bool {
    let n = text.chars().count();
    n >= min && n <= MAX_FIELD && !text.chars().any(char::is_control)
}

/// An `https://` origin (or a loopback `http://` origin for test relays), without a path.
fn valid_origin(text: &str) -> Option<String> {
    let text = text.strip_suffix('/').unwrap_or(text);
    let rest = text.strip_prefix("https://").or_else(|| {
        let rest = text.strip_prefix("http://")?;
        let host = rest.rsplit_once(':').map_or(rest, |(h, _)| h);
        matches!(host, "localhost" | "127.0.0.1" | "[::1]").then_some(rest)
    })?;
    let ok = !rest.is_empty()
        && rest.len() <= MAX_FIELD
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']'));
    ok.then(|| text.to_owned())
}

fn percent_encode(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for b in text.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn percent_decode(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            out.push(u8::from_str_radix(std::str::from_utf8(hex).ok()?, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

// ---------- proofs ----------

fn pair_mac_message(p: &[u8; 32], x: &[u8; 32], m: &[u8; 32]) -> Vec<u8> {
    crypto::cat(&[b"sealctl/v1/pair", &[0], p, x, m])
}

fn move_message(p_new: &[u8; 32], x_new: &[u8; 32], m: &[u8; 32]) -> Vec<u8> {
    crypto::cat(&[b"sealctl/v1/move", &[0], p_new, x_new, m])
}

/// The pairing proof `b64u(X ‖ HMAC(c, "sealctl/v1/pair" ‖ 0x00 ‖ P ‖ X ‖ M))`, 86 characters.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn pairing_proof(keys: &PhoneKeys, offer: &PairingOffer) -> String {
    let x = keys.box_public();
    let mac = crypto::hmac_sha256(
        offer.code.as_slice(),
        &pair_mac_message(keys.identity_public(), x, &offer.machine),
    );
    crypto::b64u(&crypto::cat(&[x, &mac]))
}

/// The machine's check of a pairing proof. Returns the phone box key `X` on success.
pub fn verify_pairing_proof(
    code: &[u8; 16],
    machine: &[u8; 32],
    phone: &[u8; 32],
    proof: &str,
) -> Result<[u8; 32]> {
    let raw = crypto::b64u_decode_fixed::<64>(proof).ok_or(CoreError::BadProof)?;
    let x: [u8; 32] = raw[..32].try_into().expect("32 bytes");
    if !crypto::hmac_sha256_verify(code, &pair_mac_message(phone, &x, machine), &raw[32..]) {
        return Err(CoreError::BadProof);
    }
    Ok(x)
}

/// The move proof after new words: `b64u(X_new ‖ Ed25519-Sign(old identity, …))`, 128 characters.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn key_change_proof(old_keys: &PhoneKeys, new_keys: &PhoneKeys, machine_key: String) -> Result<String> {
    let m = crypto::decode_key32(&machine_key)?;
    let sig = old_keys.sign(&move_message(
        new_keys.identity_public(),
        new_keys.box_public(),
        &m,
    ));
    Ok(crypto::b64u(&crypto::cat(&[new_keys.box_public(), &sig])))
}

/// The machine's check of a move proof with the old phone key it trusts. Returns `X_new`.
pub fn verify_move_proof(
    old_phone: &[u8; 32],
    new_phone: &[u8; 32],
    machine: &[u8; 32],
    proof: &str,
) -> Result<[u8; 32]> {
    let raw = crypto::b64u_decode_fixed::<96>(proof).ok_or(CoreError::BadProof)?;
    let x: [u8; 32] = raw[..32].try_into().expect("32 bytes");
    crypto::ed25519_verify(old_phone, &move_message(new_phone, &x, machine), &raw[32..])
        .map_err(|_| CoreError::BadProof)?;
    Ok(x)
}

/// The licence move proof: the new key's signature over
/// `sealctl-licence-move-v1\n<old phone key>\n<new phone key>`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn licence_move_proof(new_keys: &PhoneKeys, old_public_id: String) -> Result<String> {
    crypto::decode_key32(&old_public_id)?;
    let text = format!(
        "sealctl-licence-move-v1\n{}\n{}",
        old_public_id,
        new_keys.public_id()
    );
    Ok(crypto::b64u(&new_keys.sign(text.as_bytes())))
}
