//! The core's one error type. Messages never contain key material, words or bodies.

/// Every failure the core reports, to Rust callers and through UniFFI.
#[cfg_attr(feature = "uniffi", derive(uniffi::Error))]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CoreError {
    /// Word number `index` (from 0) is not a BIP39 English word.
    #[error("word {index} is not on the word list")]
    UnknownWord {
        /// Position of the word, from 0.
        index: u32,
    },
    /// The words are all on the list but their BIP39 checksum fails.
    #[error("these words do not belong together (checksum)")]
    Checksum,
    /// Not 24 words.
    #[error("expected 24 words")]
    Count,
    /// Not a sealctl pairing link or code.
    #[error("not a sealctl pairing code")]
    BadLink,
    /// A pairing code past its expiry, or a request outside the 10-minute window.
    #[error("expired")]
    Expired,
    /// The other side speaks a newer protocol version.
    #[error("This machine runs a newer sealctl. Update the app.")]
    NewerVersion,
    /// A pairing or move proof that does not check out.
    #[error("bad proof")]
    BadProof,
    /// An Ed25519 signature that does not verify.
    #[error("bad signature")]
    BadSignature,
    /// A sealed string or blob that cannot be decoded or opened, or is too long.
    #[error("cannot open this sealed data")]
    BadSealed,
    /// This request was already answered.
    #[error("already answered")]
    Replay,
    /// A key purpose or object id outside the allowed set.
    #[error("bad key label")]
    BadLabel,
    /// A plan that breaks the plan rules or does not match its hash.
    #[error("bad plan")]
    BadPlan,
    /// Bytes or text that are not a valid key (wrong length or encoding).
    #[error("not a valid key")]
    BadKey,
    /// The answer does not fit the request's kind (for example keys for a `report`).
    #[error("this answer does not fit this request")]
    WrongDecision,
    /// The body does not fit in its sealed form (4,096 characters, state blob 1 MiB).
    #[error("too large")]
    TooLarge,
    /// A failure that should not happen (the OS random source, an encoder).
    #[error("internal error")]
    Internal,
}

/// Shorthand used across the crate.
pub type Result<T> = std::result::Result<T, CoreError>;
