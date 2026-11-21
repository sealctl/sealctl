//! The 24 words (BIP39 English, 256 bits of entropy, empty passphrase).

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

/// Number of words sealctl uses.
pub const WORD_COUNT: usize = 24;
/// Entropy behind 24 words.
pub const ENTROPY_LEN: usize = 32;

/// 24 valid words, held as their 32 bytes of entropy and wiped on drop.
#[cfg_attr(feature = "uniffi", derive(uniffi::Object))]
pub struct Words {
    entropy: Zeroizing<[u8; ENTROPY_LEN]>,
}

#[cfg_attr(feature = "uniffi", uniffi::export)]
impl Words {
    /// 24 new words from the OS random source.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn generate() -> Result<Self> {
        let mut entropy = Zeroizing::new([0u8; ENTROPY_LEN]);
        getrandom::fill(entropy.as_mut_slice()).map_err(|_| CoreError::Internal)?;
        Ok(Self { entropy })
    }

    /// The words for 32 bytes of entropy (the words backup item holds these).
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn from_entropy(bytes: Vec<u8>) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        let entropy: [u8; ENTROPY_LEN] = bytes.as_slice().try_into().map_err(|_| CoreError::Count)?;
        Ok(Self {
            entropy: Zeroizing::new(entropy),
        })
    }

    /// Parses 24 typed words. Case and surrounding spaces are ignored; a word may be given by
    /// its first four letters (or more) when they name exactly one word, as on the card.
    #[cfg_attr(feature = "uniffi", uniffi::constructor)]
    pub fn parse(list: Vec<String>) -> Result<Self> {
        let list = Zeroizing::new(list);
        if list.len() != WORD_COUNT {
            return Err(CoreError::Count);
        }
        let mut phrase = Zeroizing::new(String::with_capacity(WORD_COUNT * 9));
        for (index, typed) in list.iter().enumerate() {
            let word = resolve_word(typed).ok_or(CoreError::UnknownWord { index: index as u32 })?;
            if index > 0 {
                phrase.push(' ');
            }
            phrase.push_str(word);
        }
        let mnemonic = Mnemonic::parse_in_normalized(Language::English, &phrase).map_err(|e| match e {
            bip39::Error::UnknownWord(i) => CoreError::UnknownWord { index: i as u32 },
            bip39::Error::BadWordCount(_) => CoreError::Count,
            _ => CoreError::Checksum,
        })?;
        let (full, len) = mnemonic.to_entropy_array();
        let full = Zeroizing::new(full);
        let entropy: [u8; ENTROPY_LEN] = full[..len].try_into().map_err(|_| CoreError::Count)?;
        Ok(Self {
            entropy: Zeroizing::new(entropy),
        })
    }

    /// The 32 bytes of entropy, for the words backup item only.
    pub fn entropy(&self) -> Vec<u8> {
        self.entropy.to_vec()
    }

    /// The 24 words in order, for the protected view only.
    pub fn list(&self) -> Vec<String> {
        self.mnemonic().words().map(str::to_owned).collect()
    }
}

impl Words {
    fn mnemonic(&self) -> Mnemonic {
        Mnemonic::from_entropy_in(Language::English, self.entropy.as_slice())
            .expect("32 bytes are valid BIP39 entropy")
    }

    /// The 64-byte BIP39 seed with the empty passphrase.
    pub(crate) fn seed(&self) -> Zeroizing<[u8; 64]> {
        Zeroizing::new(self.mnemonic().to_seed_normalized(""))
    }

    pub(crate) fn entropy_bytes(&self) -> &[u8; ENTROPY_LEN] {
        &self.entropy
    }
}

fn resolve_word(typed: &str) -> Option<&'static str> {
    let typed = Zeroizing::new(typed.trim().to_lowercase());
    let english = Language::English;
    if let Some(i) = english.find_word(&typed) {
        return Some(english.word_list()[i as usize]);
    }
    if typed.chars().count() < 4 {
        return None;
    }
    let mut matches = english.words_by_prefix_iter(&typed);
    match (matches.next(), matches.next()) {
        (Some(only), None) => Some(only),
        _ => None,
    }
}

/// BIP39 English words starting with `prefix` (case ignored), in list order. Drives the
/// word keypad: the next letters that can follow, and the completion once four letters are in.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn complete_word(prefix: String) -> Vec<String> {
    let prefix = prefix.trim().to_lowercase();
    if prefix.is_empty() {
        return Vec::new();
    }
    Language::English
        .words_by_prefix_iter(&prefix)
        .map(str::to_owned)
        .collect()
}
