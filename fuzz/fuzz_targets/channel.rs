//! Sealed status (phone side) and sealed machine messages (machine side). The raw input is
//! tried as the sealed text; when it reads as a status or message body, it is also sealed and
//! signed with test keys and opened, so the checks after HPKE and the signature are reached too.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sealctl_core::channel::{open_message, seal_status};
use sealctl_core::wire::{MachineMessage, MachineStatus};
use sealctl_core::{open_machine_status, seal_machine_message, MachineKeys, PhoneKeys, PhonePublic, Root};

/// Unpadded base64url, for the machine box key that `seal_machine_message` takes as text.
fn b64u(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = c
            .iter()
            .enumerate()
            .fold(0u32, |n, (i, b)| n | (u32::from(*b) << (16 - 8 * i)));
        for i in 0..=c.len() {
            out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let root = Root::from_bytes(vec![2u8; 32]).unwrap();
    let keys = PhoneKeys::from_root(&root);
    let machine = MachineKeys::from_bytes(&[3u8; 64]).unwrap();
    if let Ok(t) = std::str::from_utf8(data) {
        let _ = open_machine_status(
            &keys,
            "0F1KEPyKdmRmXeKvFt-eqoWgd_KglZaTGvTE2uYiKJ8".into(),
            t.into(),
        );
        let _ = open_message(&machine, keys.identity_public(), t);
    }

    if let Ok(status) = serde_json::from_slice::<MachineStatus>(data) {
        let phone = PhonePublic {
            identity: *keys.identity_public(),
            box_key: *keys.box_public(),
        };
        if let Ok(sealed) = seal_status(&machine, &phone, &status) {
            let _ = open_machine_status(&keys, machine.id(), sealed);
        }
    }
    if let Ok(message) = serde_json::from_slice::<MachineMessage>(data) {
        if let Ok(sealed) = seal_machine_message(&keys, machine.id(), b64u(machine.box_public()), message) {
            let _ = open_message(&machine, keys.identity_public(), &sealed);
        }
    }
});
