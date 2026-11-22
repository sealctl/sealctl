//! `.id` files (both forms).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = std::str::from_utf8(data) {
        let _ = sealctl_core::ids::IdFile::parse(t);
    }
});
