//! The root: `HKDF(seed, "sealctl/v1/root", 32)`, and `derive(root, label, L)`.

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::words::Words;

/// Root length in bytes.
pub const ROOT_LEN: usize = 32;

const B58: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// The 32-byte root every key comes from. Wiped on drop; no `Debug`, `Clone` or `Serialize`.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Root {
    bytes: Zeroizing<[u8; ROOT_LEN]>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Root {
    /// The root of a set of words. The BIP39 seed exists only inside this call.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_words(words: &Words) -> Self {
        let seed = words.seed();
        Self {
            bytes: crypto::hkdf_array::<ROOT_LEN>(seed.as_slice(), b"sealctl/v1/root"),
        }
    }

    /// A root read back from the keychain (32 bytes).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        let root: [u8; ROOT_LEN] = bytes.as_slice().try_into().map_err(|_| CoreError::BadKey)?;
        Ok(Self {
            bytes: Zeroizing::new(root),
        })
    }

    /// The 32 bytes, for the keychain only.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.bytes.to_vec()
    }
}

impl Root {
    /// `derive(root, label, L) = HKDF(root, "sealctl/v1/" ‖ label, L)`.
    pub fn derive<const N: usize>(&self, label: &str) -> Zeroizing<[u8; N]> {
        let info = crypto::cat(&[b"sealctl/v1/", label.as_bytes()]);
        crypto::hkdf_array::<N>(self.bytes.as_slice(), &info)
    }

    /// The words fingerprint: 4 base58 characters.
    pub fn fingerprint(&self) -> String {
        let okm = self.derive::<8>("fingerprint");
        let mut n = u64::from_be_bytes(*okm) % 58u64.pow(4);
        let mut out = [b'1'; 4];
        for slot in out.iter_mut().rev() {
            *slot = B58[(n % 58) as usize];
            n /= 58;
        }
        String::from_utf8(out.to_vec()).expect("base58 alphabet is ASCII")
    }

    /// The AEAD key of the phone's state blob.
    pub(crate) fn state_key(&self) -> Zeroizing<[u8; 32]> {
        self.derive::<32>("state")
    }

    /// Ed25519 seed of the phone identity.
    pub(crate) fn phone_identity_seed(&self) -> Zeroizing<[u8; 32]> {
        self.derive::<32>("phone:identity")
    }

    /// X25519 private key of the phone box key.
    pub(crate) fn phone_box_secret(&self) -> Zeroizing<[u8; 32]> {
        self.derive::<32>("phone:box")
    }
}

/// The words fingerprint of a root, as printed in `.id` files and `sealctl status`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn fingerprint(root: &Root) -> String {
    root.fingerprint()
}

/// Whether text is a well-formed words fingerprint (4 base58 characters).
pub(crate) fn is_fingerprint(text: &str) -> bool {
    text.len() == 4 && text.bytes().all(|b| B58.contains(&b))
}
