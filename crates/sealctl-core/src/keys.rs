//! Object keys: the 16-byte keys a phone hands to a machine, their labels and checks.

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::root::Root;

/// Object key length: 16 bytes, typeable as 22 characters.
pub const OBJECT_KEY_LEN: usize = 16;

/// The four purposes a phone hands out keys for.
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Purpose {
    /// The secret store key, id = store id.
    Secrets,
    /// The own-approval key of one secret, id = file id.
    Secret,
    /// A volume key, id = volume id.
    Volume,
    /// A backup repository key, id = repository id.
    Backup,
}

impl Purpose {
    /// The wire name (`p`).
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Secrets => "secrets",
            Purpose::Secret => "secret",
            Purpose::Volume => "volume",
            Purpose::Backup => "backup",
        }
    }

    /// Parses a wire name; anything else is `None` (answered `bad_label`).
    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "secrets" => Purpose::Secrets,
            "secret" => Purpose::Secret,
            "volume" => Purpose::Volume,
            "backup" => Purpose::Backup,
            _ => return None,
        })
    }
}

/// `^[A-Za-z0-9._-]{1,64}$`: the ids a phone derives keys for.
pub fn is_valid_object_id(id: &str) -> bool {
    (1..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// A 16-byte object key. Wiped on drop; never crosses the UniFFI boundary.
pub struct ObjectKey {
    bytes: Zeroizing<[u8; OBJECT_KEY_LEN]>,
}

impl ObjectKey {
    /// `derive(root, purpose ‖ ":" ‖ id, 16)`, refusing ids outside the allowed set.
    pub fn derive(root: &Root, purpose: Purpose, id: &str) -> Result<Self> {
        if !is_valid_object_id(id) {
            return Err(CoreError::BadLabel);
        }
        let label = Zeroizing::new(format!("{}:{}", purpose.as_str(), id));
        Ok(Self {
            bytes: root.derive::<OBJECT_KEY_LEN>(&label),
        })
    }

    /// A key typed or received as 22 base64url characters.
    pub fn from_b64u(text: &str) -> Result<Self> {
        let bytes = crypto::b64u_decode_fixed::<OBJECT_KEY_LEN>(text).ok_or(CoreError::BadKey)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// A key from its 16 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let bytes: [u8; OBJECT_KEY_LEN] = bytes.try_into().map_err(|_| CoreError::BadKey)?;
        Ok(Self {
            bytes: Zeroizing::new(bytes),
        })
    }

    /// The raw bytes.
    pub fn as_bytes(&self) -> &[u8; OBJECT_KEY_LEN] {
        &self.bytes
    }

    /// `check(key)`: 11 characters, safe to store in `.id` files.
    pub fn check(&self) -> String {
        key_check(self.bytes.as_slice())
    }

    /// `hex(key)`: the passphrase given to `diskutil`, `cryptsetup` and restic.
    pub fn hex(&self) -> Zeroizing<String> {
        Zeroizing::new(hex::encode(self.bytes.as_slice()))
    }

    /// `b64u(key)`: the form in reply bodies and the air-gapped variant.
    pub fn b64u(&self) -> Zeroizing<String> {
        Zeroizing::new(crypto::b64u(self.bytes.as_slice()))
    }
}

/// `check(key) = b64u(HKDF(key, "sealctl/v1/check", 8))`.
pub fn key_check(key: &[u8]) -> String {
    let okm = crypto::hkdf_array::<8>(key, b"sealctl/v1/check");
    crypto::b64u(okm.as_slice())
}
