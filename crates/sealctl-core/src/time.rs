//! The clock: the only I/O the core does besides the random source.

use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn now_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

pub(crate) fn now_unix_secs() -> u64 {
    now_unix_ms() / 1000
}
