//! Exit codes (SPEC 5.4) and the error that carries one.
//!
//! Every error ends as one line on stderr starting with `sealctl: `, then at most one line
//! saying what to do. Errors that need a specific exit code are [`Fail`]; anything else exits 1.

use std::fmt;

/// Error not listed below.
pub const ERROR: i32 = 1;
/// Usage error (bad arguments, conflicting relay, another run active).
pub const USAGE: i32 = 2;
/// Not paired, or this machine was unpaired.
pub const NOT_PAIRED: i32 = 3;
/// Declined on the phone (also a wrong number, `held`, `no_biometrics`, a cancelled delay).
pub const DECLINED: i32 = 4;
/// No answer from the phone in time.
pub const NO_ANSWER: i32 = 5;
/// Relay unreachable or relay error.
pub const RELAY: i32 = 6;
/// Relay limit reached (`429`).
pub const LIMIT: i32 = 7;
/// Refused: inside an AI agent, or needs a terminal.
pub const REFUSED: i32 = 8;
/// Not found: secret, volume, backup, object.
pub const NOT_FOUND: i32 = 9;
/// Wrong words or wrong key.
pub const WRONG_KEY: i32 = 10;
/// Volume busy.
pub const BUSY: i32 = 11;
/// Clock off by more than 5 minutes.
pub const CLOCK: i32 = 12;
/// Stopped part way: `seal` or `unseal` kept its journal.
pub const PARTWAY: i32 = 13;

/// An error with an exit code and the exact text to print after `sealctl: `.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fail {
    /// Exit code (section 5.4).
    pub code: i32,
    /// The message, without the `sealctl: ` prefix; at most two lines.
    pub message: String,
}

impl fmt::Display for Fail {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Fail {}

/// An [`anyhow::Error`] carrying an exit code.
pub fn fail(code: i32, message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(Fail {
        code,
        message: message.into(),
    })
}

/// The exit code of an error: its [`Fail`] code, else 1.
pub fn code_of(e: &anyhow::Error) -> i32 {
    e.chain()
        .find_map(|c| c.downcast_ref::<Fail>())
        .map_or(ERROR, |f| f.code)
}

/// The text to print for an error: a [`Fail`]'s own message, else the error chain.
pub fn message_of(e: &anyhow::Error) -> String {
    match e.chain().find_map(|c| c.downcast_ref::<Fail>()) {
        Some(f) => f.message.clone(),
        None => format!("{e:#}"),
    }
}

/// `This machine is not paired. Run: sealctl pair`.
pub fn not_paired() -> anyhow::Error {
    fail(NOT_PAIRED, "This machine is not paired. Run: sealctl pair")
}

/// `This machine was unpaired on your phone. Run: sealctl pair`.
pub fn unpaired() -> anyhow::Error {
    fail(
        NOT_PAIRED,
        "This machine was unpaired on your phone. Run: sealctl pair",
    )
}

/// The refusal inside an AI agent (exit 8).
pub fn agent_refusal(what: &str) -> anyhow::Error {
    fail(
        REFUSED,
        format!("Not inside an AI agent: {what}. Use sealctl run -- <command>."),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_survive_context() {
        let e = fail(DECLINED, "Declined on your phone.");
        let e = e.context("opening the session");
        assert_eq!(code_of(&e), DECLINED);
        assert_eq!(message_of(&e), "Declined on your phone.");
        assert_eq!(code_of(&anyhow::anyhow!("x")), ERROR);
    }
}
