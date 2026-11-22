//! sealctl: keys for developer machines, approved on your phone.
//!
//! The library holds the logic; `main.rs` is the command-line front end. Wire formats, keys and
//! crypto come from `sealctl-core` (docs/protocol.md); this crate is transport and glue: the relay
//! client, pairing, the session daemon, the secret store, `sealctl run`, SSH and git, volumes,
//! backups, `seal` and `unseal`, and the licence.

pub mod ai;
pub mod approve;
pub mod backup;
pub mod cli;
pub mod config;
pub mod daemon;
pub mod dotenv;
pub mod exit;
pub mod git;
pub mod guard;
pub mod legacy;
pub mod licence;
pub mod machine;
pub mod pair;
pub mod paths;
pub mod project;
pub mod recover;
pub mod relay;
pub mod scan;
pub mod seal;
pub mod service;
pub mod ssh;
pub mod status;
pub mod store;
pub mod term;
pub mod util;
pub mod volume;
