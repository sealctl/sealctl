//! Sealed status (phone side) and sealed machine messages (machine side).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(t) = std::str::from_utf8(data) else { return };
    let root = sealctl_core::Root::from_bytes(vec![2u8; 32]).unwrap();
    let keys = sealctl_core::PhoneKeys::from_root(&root);
    let _ = sealctl_core::open_machine_status(&keys, "0F1KEPyKdmRmXeKvFt-eqoWgd_KglZaTGvTE2uYiKJ8".into(), t.into());
    let machine = sealctl_core::MachineKeys::from_bytes(&[3u8; 64]).unwrap();
    let _ = sealctl_core::channel::open_message(&machine, keys.identity_public(), t);
});
