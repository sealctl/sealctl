//! The phone's state blob on the relay: `0x01 ‖ nonce ‖ AEAD(state key, nonce, aad, plaintext)`.

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::phone::PhoneKeys;
use crate::root::Root;

const FORMAT: u8 = 0x01;
/// Largest blob the relay stores, decoded.
pub const MAX_BLOB: usize = 1_048_576;

fn aad(root: &Root) -> Vec<u8> {
    let keys = PhoneKeys::from_root(root);
    crypto::cat(&[b"sealctl/v1/state", &[0], keys.identity_public()])
}

/// Seals the state plaintext; returns the blob as base64url, as `PUT .../state` takes it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn state_seal(root: &Root, plaintext: Vec<u8>) -> Result<String> {
    let plaintext = Zeroizing::new(plaintext);
    state_seal_with_nonce(root, &plaintext, &crypto::random_array::<12>()?)
}

pub(crate) fn state_seal_with_nonce(root: &Root, plaintext: &[u8], nonce: &[u8; 12]) -> Result<String> {
    if 1 + 12 + plaintext.len() + crypto::TAG_LEN > MAX_BLOB {
        return Err(CoreError::TooLarge);
    }
    let ct = crypto::aead_seal(&root.state_key(), nonce, &aad(root), plaintext)?;
    Ok(crypto::b64u(&crypto::cat(&[&[FORMAT], nonce, &ct])))
}

/// Opens a blob read from `GET .../state` (base64url).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn state_open(root: &Root, blob: String) -> Result<Vec<u8>> {
    if blob.len() > MAX_BLOB.div_ceil(3) * 4 {
        return Err(CoreError::TooLarge);
    }
    let raw = crypto::b64u_decode(&blob).ok_or(CoreError::BadSealed)?;
    match raw.first() {
        Some(&FORMAT) => {}
        Some(&v) if v > FORMAT => return Err(CoreError::NewerVersion),
        _ => return Err(CoreError::BadSealed),
    }
    if raw.len() < 1 + 12 + crypto::TAG_LEN {
        return Err(CoreError::BadSealed);
    }
    let nonce: [u8; 12] = raw[1..13].try_into().expect("12 bytes");
    let pt = crypto::aead_open(&root.state_key(), &nonce, &aad(root), &raw[13..])?;
    Ok(pt.to_vec())
}
