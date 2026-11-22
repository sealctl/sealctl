//! Request and reply bodies, status and message bodies as JSON.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sealctl_core::wire::{MachineMessage, MachineStatus, ReplyBody, RequestBody};

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<RequestBody>(data);
    let _ = serde_json::from_slice::<ReplyBody>(data);
    let _ = serde_json::from_slice::<MachineStatus>(data);
    let _ = serde_json::from_slice::<MachineMessage>(data);
});
