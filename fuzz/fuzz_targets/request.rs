//! A sealed request as the phone gets it (HPKE open, signature, body checks).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let root = sealctl_core::Root::from_bytes(vec![1u8; 32]).unwrap();
    let keys = sealctl_core::PhoneKeys::from_root(&root);
    if let Ok(t) = std::str::from_utf8(data) {
        let _ = sealctl_core::request::open_request_at(
            &keys,
            "0F1KEPyKdmRmXeKvFt-eqoWgd_KglZaTGvTE2uYiKJ8",
            "MDEyMzQ1Njc4OTo7PD0-Pw",
            t,
            1_795_251_600_000,
        );
    }
});
