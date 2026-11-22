//! A sealed request as the phone gets it. The raw input is tried as the sealed text (size,
//! base64 and HPKE checks); when it reads as a request body, it is also sealed and signed with
//! test keys and opened, so the version, time window and plan checks are reached too.
#![no_main]
use libfuzzer_sys::fuzz_target;
use sealctl_core::pairing::PROTOCOL_VERSION;
use sealctl_core::request::{open_request_at, seal_request};
use sealctl_core::wire::RequestBody;
use sealctl_core::{MachineKeys, PhoneKeys, PhonePublic, Root};

const ID: &str = "MDEyMzQ1Njc4OTo7PD0-Pw";

fuzz_target!(|data: &[u8]| {
    let root = Root::from_bytes(vec![1u8; 32]).unwrap();
    let keys = PhoneKeys::from_root(&root);
    if let Ok(t) = std::str::from_utf8(data) {
        let _ = open_request_at(
            &keys,
            "0F1KEPyKdmRmXeKvFt-eqoWgd_KglZaTGvTE2uYiKJ8",
            ID,
            t,
            1_795_251_600_000,
        );
    }

    let Ok(mut body) = serde_json::from_slice::<RequestBody>(data) else {
        return;
    };
    // The version and the clock are fixed up so that inputs get on to the plan checks.
    body.v = PROTOCOL_VERSION;
    let now = body.t;
    let machine = MachineKeys::from_bytes(&[3u8; 64]).unwrap();
    let phone = PhonePublic {
        identity: *keys.identity_public(),
        box_key: *keys.box_public(),
    };
    // Bodies over the size limit are refused when sealing; nothing to open then.
    let Ok(sent) = seal_request(&machine, &phone, ID, body) else {
        return;
    };
    let _ = open_request_at(&keys, &machine.id(), ID, &sent.sealed, now);
});
