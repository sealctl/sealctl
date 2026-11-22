//! The dotenv parser (`seal env`, `scan`, the folder store read-back).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(t) = std::str::from_utf8(data) {
        if let Ok(m) = sealctl::dotenv::parse_dotenv(t) {
            // what the folder store writes reads back the same
            for (k, v) in m.iter() {
                let line = format!("{k}={}\n", sealctl::seal::journal::quote_env(v));
                let back = sealctl::dotenv::parse_dotenv(&line).expect("quoted values parse");
                assert_eq!(back[k].as_str(), v.as_str());
            }
        }
    }
});
