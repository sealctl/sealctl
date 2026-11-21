//! sealctl — your hardware wallet as an everyday developer key.
//!
//! The library holds all logic; `main.rs` is only the command-line front end.
//! OpenPGP is done by rPGP + openpgp-card on the Ledger OpenPGP app, volumes by APFS / LUKS2,
//! backups by restic. The one custom construction — seed-derived keys — lives in `derive` and
//! is specified in `docs/derived-keys.md`.

pub mod agent;
pub mod ai;
pub mod backup;
pub mod card;
pub mod cert;
pub mod crypto;
pub mod derive;
pub mod device;
pub mod doctor;
pub mod git;
pub mod guard;
pub mod kit;
pub mod paths;
pub mod pin;
pub mod project;
pub mod recover;
pub mod secrets;
pub mod service;
pub mod setup;
pub mod ssh;
pub mod unseal;
pub mod util;
pub mod volume;

pub use device::Ctx;
