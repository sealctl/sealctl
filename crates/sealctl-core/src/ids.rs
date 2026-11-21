//! Object ids (UUID v4) and `.id` files.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::crypto;
use crate::error::{CoreError, Result};

/// A new random version 4 UUID, lower case with hyphens.
pub fn new_uuid() -> Result<String> {
    let mut b = crypto::random_array::<16>()?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    Ok(format_uuid(&b))
}

/// The 36-character form of 16 bytes.
pub fn format_uuid(b: &[u8; 16]) -> String {
    let h = hex::encode(b);
    format!(
        "{}-{}-{}-{}-{}",
        &h[..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..]
    )
}

/// The 16 bytes of a lower-case UUID with hyphens; anything else is `None`.
pub fn parse_uuid(text: &str) -> Option<[u8; 16]> {
    let b = text.as_bytes();
    if b.len() != 36 || [8, 13, 18, 23].iter().any(|&i| b[i] != b'-') {
        return None;
    }
    let digits: String = text.chars().filter(|&c| c != '-').collect();
    if digits.len() != 32 || !digits.bytes().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')) {
        return None;
    }
    hex::decode(digits).ok()?.try_into().ok()
}

/// A version 1 `.id` file. It is public and holds no key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IdFile {
    /// Always `1`.
    pub sealctl: u32,
    /// `store`, `volume` or `backup`.
    pub kind: String,
    /// The object id.
    pub id: String,
    /// Words fingerprint of the words that sealed it.
    pub words: String,
    /// `check(key)` of its key.
    pub check: String,
    /// RFC 3339 time in UTC.
    pub created: String,
    /// Stores only: `sealed-v1`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Stores only: own-approval checks by file id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub own: Option<BTreeMap<String, String>>,
    /// Volumes only: `apfs`, `sparsebundle` or `luks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
}

/// What an `.id` file holds: the version 1 object, or a 0.5.0 sparse bundle's bare UUID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IdFileContent {
    /// A version 1 `.id` file.
    V1(IdFile),
    /// A 0.5.0 `sealctl.id`: only the UUID and a newline, sealed through the Ledger.
    Legacy(String),
}

impl IdFile {
    /// Parses either form.
    pub fn parse(text: &str) -> Result<IdFileContent> {
        let trimmed = text.trim();
        if parse_uuid(trimmed).is_some() {
            return Ok(IdFileContent::Legacy(trimmed.to_owned()));
        }
        let file: IdFile = serde_json::from_str(text).map_err(|_| CoreError::BadSealed)?;
        if file.sealctl > 1 {
            return Err(CoreError::NewerVersion);
        }
        if file.sealctl != 1 {
            return Err(CoreError::BadSealed);
        }
        Ok(IdFileContent::V1(file))
    }

    /// Pretty JSON with a trailing newline.
    pub fn to_json(&self) -> String {
        let mut s = serde_json::to_string_pretty(self).expect("IdFile serialises");
        s.push('\n');
        s
    }
}
