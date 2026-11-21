//! Relay API signing: the `sealctl-relay-v1` canonical string and its Ed25519 signature.

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::machine::MachineKeys;
use crate::phone::PhoneKeys;

/// How far a signed call's time may be from the relay's clock, in seconds.
pub const TIME_WINDOW_SECS: u64 = 300;

/// The three header values of a signed relay call.
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayHeaders {
    /// `Sealctl-Key`: the signer's public key, 43 characters.
    pub key: String,
    /// `Sealctl-Time`: Unix seconds.
    pub time: String,
    /// `Sealctl-Signature`: 86 characters.
    pub signature: String,
}

/// The five lines the signature covers, joined with `\n` and no trailing newline.
pub fn canonical(method: &str, path_and_query: &str, unix_time: u64, body: &[u8]) -> String {
    format!(
        "sealctl-relay-v1\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        path_and_query,
        unix_time,
        crypto::b64u(&crypto::sha256(body))
    )
}

fn headers(seed: &[u8; 32], method: &str, path_and_query: &str, unix_time: u64, body: &[u8]) -> RelayHeaders {
    let text = canonical(method, path_and_query, unix_time, body);
    RelayHeaders {
        key: crypto::b64u(&crypto::ed25519_public(seed)),
        time: unix_time.to_string(),
        signature: crypto::b64u(&crypto::ed25519_sign(seed, text.as_bytes())),
    }
}

/// Signs a relay call as the phone.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn relay_headers(
    keys: &PhoneKeys,
    method: String,
    path_and_query: String,
    unix_time: u64,
    body: Vec<u8>,
) -> RelayHeaders {
    let text = canonical(&method, &path_and_query, unix_time, &body);
    RelayHeaders {
        key: keys.public_id(),
        time: unix_time.to_string(),
        signature: crypto::b64u(&keys.sign(text.as_bytes())),
    }
}

/// Signs a relay call as a machine, with its pairing key.
pub fn machine_relay_headers(
    keys: &MachineKeys,
    method: &str,
    path_and_query: &str,
    unix_time: u64,
    body: &[u8],
) -> RelayHeaders {
    headers(keys.pairing_seed(), method, path_and_query, unix_time, body)
}

/// Verifies a signed call as the relay does: key, time window, signature.
pub fn verify_relay_headers(
    headers: &RelayHeaders,
    method: &str,
    path_and_query: &str,
    body: &[u8],
    now_unix: u64,
) -> Result<()> {
    let key = crypto::decode_key32(&headers.key)?;
    let time: u64 = headers.time.parse().map_err(|_| CoreError::BadSignature)?;
    if time.abs_diff(now_unix) > TIME_WINDOW_SECS {
        return Err(CoreError::Expired);
    }
    let sig = crypto::b64u_decode_fixed::<64>(&headers.signature).ok_or(CoreError::BadSignature)?;
    let text = canonical(method, path_and_query, time, body);
    crypto::ed25519_verify(&key, text.as_bytes(), &sig)
}
