//! `.sealed` files of the secret store.

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};
use crate::ids;
use crate::keys::ObjectKey;
use crate::root;

const MAGIC: &[u8; 4] = b"SCS1";
/// Header length: magic, mode, fingerprint, file id, nonce.
pub const HEADER_LEN: usize = 37;
/// Largest value a secret holds.
pub const MAX_VALUE: usize = 65_536;

/// Which key a `.sealed` file opens with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// `0x01`: the store key.
    StoreKey,
    /// `0x02`: the secret's own-approval key.
    OwnApproval,
}

impl Mode {
    fn byte(self) -> u8 {
        match self {
            Mode::StoreKey => 1,
            Mode::OwnApproval => 2,
        }
    }
}

/// The public header of a `.sealed` file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// Mode.
    pub mode: Mode,
    /// Words fingerprint.
    pub words: String,
    /// File id, 36 characters.
    pub file_id: String,
    /// Nonce.
    pub nonce: [u8; 12],
}

impl Header {
    /// Parses the first 37 bytes.
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
            return Err(CoreError::BadSealed);
        }
        let mode = match bytes[4] {
            1 => Mode::StoreKey,
            2 => Mode::OwnApproval,
            _ => return Err(CoreError::BadSealed),
        };
        let words = String::from_utf8(bytes[5..9].to_vec()).map_err(|_| CoreError::BadSealed)?;
        if !root::is_fingerprint(&words) {
            return Err(CoreError::BadSealed);
        }
        let file_id = ids::format_uuid(&bytes[9..25].try_into().expect("16 bytes"));
        let nonce = bytes[25..37].try_into().expect("12 bytes");
        Ok(Self {
            mode,
            words,
            file_id,
            nonce,
        })
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        let id = ids::parse_uuid(&self.file_id).ok_or(CoreError::BadLabel)?;
        if !root::is_fingerprint(&self.words) {
            return Err(CoreError::BadLabel);
        }
        Ok(crypto::cat(&[
            MAGIC,
            &[self.mode.byte()],
            self.words.as_bytes(),
            &id,
            &self.nonce,
        ]))
    }
}

/// `HKDF(store key or own-approval key, "sealctl/v1/file:" ‖ file-id, 32)`.
pub fn file_key(key: &ObjectKey, file_id: &str) -> Zeroizing<[u8; 32]> {
    crypto::hkdf_array::<32>(
        key.as_bytes(),
        &crypto::cat(&[b"sealctl/v1/file:", file_id.as_bytes()]),
    )
}

/// A secret name: `/`-separated segments of 1 to 64 of `A-Z a-z 0-9 - _ . @ +`, not starting
/// with `.`, at most 128 characters.
pub fn is_valid_name(name: &str) -> bool {
    name.len() <= 128
        && name.split('/').all(|seg| {
            (1..=64).contains(&seg.len())
                && !seg.starts_with('.')
                && seg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'@' | b'+'))
        })
}

fn aad(header: &[u8], store_id: &str, name: &str) -> Vec<u8> {
    crypto::cat(&[header, store_id.as_bytes(), &[0], name.as_bytes()])
}

/// Seals one value with a fresh random nonce.
pub fn seal(header: &Header, key: &ObjectKey, store_id: &str, name: &str, value: &[u8]) -> Result<Vec<u8>> {
    if value.is_empty() || value.len() > MAX_VALUE {
        return Err(CoreError::TooLarge);
    }
    if !is_valid_name(name) || ids::parse_uuid(store_id).is_none() {
        return Err(CoreError::BadLabel);
    }
    let head = header.to_bytes()?;
    let ct = crypto::aead_seal(
        &file_key(key, &header.file_id),
        &header.nonce,
        &aad(&head, store_id, name),
        value,
    )?;
    Ok(crypto::cat(&[&head, &ct]))
}

/// A header for a new write: the given mode, fingerprint and file id, and a random nonce.
pub fn new_header(mode: Mode, words: &str, file_id: &str) -> Result<Header> {
    Ok(Header {
        mode,
        words: words.to_owned(),
        file_id: file_id.to_owned(),
        nonce: crypto::random_array()?,
    })
}

/// Opens a `.sealed` file read from `<store>/<name>.sealed`.
pub fn open(bytes: &[u8], key: &ObjectKey, store_id: &str, name: &str) -> Result<Zeroizing<Vec<u8>>> {
    let header = Header::parse(bytes)?;
    if bytes.len() < HEADER_LEN + crypto::TAG_LEN {
        return Err(CoreError::BadSealed);
    }
    let head = &bytes[..HEADER_LEN];
    crypto::aead_open(
        &file_key(key, &header.file_id),
        &header.nonce,
        &aad(head, store_id, name),
        &bytes[HEADER_LEN..],
    )
}
