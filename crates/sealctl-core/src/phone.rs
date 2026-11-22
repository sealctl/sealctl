//! The phone's keys, its storage formats and the allowance by place.

use std::sync::Arc;

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::root::{self, Root};
use crate::words::{Words, ENTROPY_LEN};

/// The phone identity (Ed25519 seed) and box key (X25519), 64 bytes in storage.
/// Wiped on drop; no `Debug`, `Clone` or `Serialize`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct PhoneKeys {
    identity_seed: Zeroizing<[u8; 32]>,
    box_secret: Zeroizing<[u8; 32]>,
    identity_public: [u8; 32],
    box_public: [u8; 32],
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl PhoneKeys {
    /// `derive(root, "phone:identity", 32)` and `derive(root, "phone:box", 32)`.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_root(root: &Root) -> Self {
        Self::from_parts(root.phone_identity_seed(), root.phone_box_secret())
    }

    /// The 64-byte storage form: identity seed ‖ box private key.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() != 64 {
            return Err(CoreError::BadKey);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut boxk = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[..32]);
        boxk.copy_from_slice(&bytes[32..]);
        Ok(Self::from_parts(seed, boxk))
    }

    /// The 64-byte storage form, for the keychain only.
    pub fn to_bytes(&self) -> Vec<u8> {
        crypto::cat(&[self.identity_seed.as_slice(), self.box_secret.as_slice()])
    }

    /// The phone id: its identity public key as 43 base64url characters.
    pub fn public_id(&self) -> String {
        crypto::b64u(&self.identity_public)
    }

    /// The box public key (`X`) as 43 base64url characters.
    pub fn box_public_key(&self) -> String {
        crypto::b64u(&self.box_public)
    }
}

impl PhoneKeys {
    fn from_parts(identity_seed: Zeroizing<[u8; 32]>, box_secret: Zeroizing<[u8; 32]>) -> Self {
        let identity_public = crypto::ed25519_public(&identity_seed);
        let box_public = crypto::x25519_public(&box_secret);
        Self {
            identity_seed,
            box_secret,
            identity_public,
            box_public,
        }
    }

    /// `P`.
    pub fn identity_public(&self) -> &[u8; 32] {
        &self.identity_public
    }

    /// `X`.
    pub fn box_public(&self) -> &[u8; 32] {
        &self.box_public
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        crypto::ed25519_sign(&self.identity_seed, msg)
    }

    pub(crate) fn box_secret(&self) -> &[u8; 32] {
        &self.box_secret
    }
}

/// The public half of a phone, as a machine stores it after pairing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhonePublic {
    /// `P`, the identity public key.
    pub identity: [u8; 32],
    /// `X`, the box public key.
    pub box_key: [u8; 32],
}

impl PhonePublic {
    /// From the two 43-character keys.
    pub fn from_b64u(identity: &str, box_key: &str) -> Result<Self> {
        Ok(Self {
            identity: crypto::decode_key32(identity)?,
            box_key: crypto::decode_key32(box_key)?,
        })
    }

    /// The phone id.
    pub fn id(&self) -> String {
        crypto::b64u(&self.identity)
    }
}

/// Where the phone is when it approves; sets the machine's allowance.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Place {
    /// Inside a trusted place.
    Trusted,
    /// Places are on and the phone is elsewhere.
    Other,
    /// No location permission (`none` on the wire).
    NoLocation,
}

/// Idle allowance numbers sent in a reply.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Allowance {
    /// Cap in seconds.
    pub cap: u32,
    /// Base in seconds.
    pub base: u32,
    /// Seconds added per minute worked.
    pub rate: u32,
}

impl Place {
    /// The wire name (`place`).
    pub fn as_str(self) -> &'static str {
        match self {
            Place::Trusted => "trusted",
            Place::Other => "other",
            Place::NoLocation => "none",
        }
    }

    /// Parses the wire name.
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "trusted" => Place::Trusted,
            "other" => Place::Other,
            "none" => Place::NoLocation,
            _ => return None,
        })
    }

    /// `trusted` 14,400 / 1,800 / 120, `other` 600 / 600 / 0, `none` 3,600 / 1,800 / 120.
    pub fn allowance(self) -> Allowance {
        match self {
            Place::Trusted => Allowance {
                cap: 14_400,
                base: 1_800,
                rate: 120,
            },
            Place::Other => Allowance {
                cap: 600,
                base: 600,
                rate: 0,
            },
            Place::NoLocation => Allowance {
                cap: 3_600,
                base: 1_800,
                rate: 120,
            },
        }
    }
}

// ---------- words backup item ----------

const BACKUP_ITEM_VERSION: u8 = 0x01;
/// `0x01 ‖ entropy (32) ‖ fingerprint (4) ‖ created ms (8)`.
pub const BACKUP_ITEM_LEN: usize = 1 + ENTROPY_LEN + 4 + 8;

/// A decoded words backup item (iCloud Keychain, Block Store).
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct BackupItem {
    /// The words it holds.
    pub words: Arc<Words>,
    /// Their fingerprint as stored.
    pub fingerprint: String,
    /// When the words were made, Unix milliseconds.
    pub created: u64,
}

/// Encodes the 45-byte words backup item.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn backup_item_encode(words: &Words, fingerprint: String, created: u64) -> Result<Vec<u8>> {
    if !root::is_fingerprint(&fingerprint) {
        return Err(CoreError::BadKey);
    }
    Ok(crypto::cat(&[
        &[BACKUP_ITEM_VERSION],
        words.entropy_bytes(),
        fingerprint.as_bytes(),
        &created.to_be_bytes(),
    ]))
}

/// Decodes the 45-byte words backup item.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn backup_item_decode(bytes: Vec<u8>) -> Result<BackupItem> {
    let bytes = Zeroizing::new(bytes);
    match bytes.first() {
        Some(&BACKUP_ITEM_VERSION) => {}
        Some(&v) if v > BACKUP_ITEM_VERSION => return Err(CoreError::NewerVersion),
        _ => return Err(CoreError::BadSealed),
    }
    if bytes.len() != BACKUP_ITEM_LEN {
        return Err(CoreError::BadSealed);
    }
    let words = Words::from_entropy(bytes[1..1 + ENTROPY_LEN].to_vec())?;
    let fp = &bytes[1 + ENTROPY_LEN..1 + ENTROPY_LEN + 4];
    let fingerprint = String::from_utf8(fp.to_vec()).map_err(|_| CoreError::BadSealed)?;
    if !root::is_fingerprint(&fingerprint) {
        return Err(CoreError::BadSealed);
    }
    let created = u64::from_be_bytes(bytes[BACKUP_ITEM_LEN - 8..].try_into().expect("8 bytes"));
    Ok(BackupItem {
        words: Arc::new(words),
        fingerprint,
        created,
    })
}
