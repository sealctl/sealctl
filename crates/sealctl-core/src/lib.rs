//! `sealctl-core`: the sealctl protocol (docs/protocol.md) shared by the CLI and the phone apps.
//!
//! Everything both sides must agree on byte for byte lives here: the words and the root,
//! derivation, fingerprints and key checks, relay signing, pairing and its proofs, sealed
//! requests and replies with the number match and plan signature, machine status and
//! messages, the phone's state blob and storage formats, `.sealed` and `.id` files, and the
//! checks on buy intent and feedback bodies.
//!
//! No primitive is implemented here: hashes, HKDF, HMAC, Ed25519, X25519, HPKE, the AEAD and
//! BIP39 come from established crates. The only I/O is the clock and the OS random source.
//!
//! With the `uniffi` feature the app-facing API carries UniFFI proc-macro annotations
//! (library mode, no UDL). Secret-holding types are UniFFI objects that zeroise on drop and
//! have no `Debug`, `Clone` or `Serialize`; object keys never cross the boundary.

#![cfg_attr(not(feature = "uniffi"), forbid(unsafe_code))]
#![cfg_attr(feature = "uniffi", deny(unsafe_code))]
#![warn(missing_docs)]

#[cfg(feature = "uniffi")]
uniffi::setup_scaffolding!();

pub mod channel;
mod crypto;
pub mod error;
pub mod feedback;
pub mod ids;
pub mod keys;
pub mod machine;
pub mod pairing;
pub mod phone;
pub mod plan;
pub mod relay_auth;
pub mod reply;
pub mod request;
pub mod root;
pub mod sealed;
pub mod state_blob;
mod time;
pub mod wire;
pub mod words;

#[cfg(test)]
mod tests;

pub use channel::{open_machine_status, seal_machine_message};
pub use error::{CoreError, Result};
pub use keys::{key_check, ObjectKey, Purpose};
pub use machine::{machine_tag, MachineKeys};
pub use pairing::{key_change_proof, licence_move_proof, pairing_proof, PairingOffer};
pub use phone::{backup_item_decode, backup_item_encode, BackupItem, PhoneKeys, PhonePublic, Place};
pub use plan::{plan_approval, KeyRef, PlanApproval, PlanAssembler, RequestPlan};
pub use relay_auth::{relay_headers, RelayHeaders};
pub use reply::{
    seal_old_words_reply, seal_plan_keys_reply, seal_plan_part_reply, seal_reply, seal_reply_with_retired,
    seal_report_reply, seal_rewrap_reply, Decision, RefuseReason, RetiredWords,
};
pub use request::{open_request, Request, RequestKind};
pub use root::{fingerprint, Root};
pub use state_blob::{state_open, state_seal};
pub use words::{complete_word, Words};

/// This crate's version, e.g. `"0.7.0"`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").to_owned()
}

/// The protocol major version, `"1"`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn protocol_version() -> String {
    pairing::PROTOCOL_VERSION.to_string()
}
