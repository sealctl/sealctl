//! `.sealed` headers and files.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = sealctl_core::sealed::Header::parse(data);
    let key = sealctl_core::ObjectKey::from_bytes(&[7u8; 16]).unwrap();
    let _ = sealctl_core::sealed::open(data, &key, "0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f", "shop/key");
});
