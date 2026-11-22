//! A daemon socket line (the values request it carries).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(data) {
        let _ = serde_json::from_value::<sealctl::daemon::ValuesReq>(v.clone());
        let _ = serde_json::from_value::<Vec<sealctl_core::wire::RequestItem>>(v["items"].clone());
    }
});
