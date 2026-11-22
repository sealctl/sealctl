//! The git credential helper input: the host never becomes a path.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = std::str::from_utf8(data) {
        let h = sealctl::git::credential_host(t);
        assert!(!h.contains('/'));
    }
});
