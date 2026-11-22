//! Relay answers: delayed approvals and error bodies.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = sealctl::approve::Delayed::from_json(&v);
        let a = sealctl::relay::Answer { status: 429, body: v.clone() };
        let _ = sealctl::relay::backoff(&a);
        let _ = sealctl::relay::error_for(&sealctl::relay::Answer { status: 401, body: v });
    }
});
