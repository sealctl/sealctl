//! `.sealctl.toml` and the mappings for a command line.
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(t) = std::str::from_utf8(data) else { return };
    if let Ok(p) = toml::from_str::<sealctl::project::ProjectFile>(t) {
        let argv: Vec<String> = t.split_whitespace().take(8).map(str::to_owned).collect();
        let _ = sealctl::project::mappings_for(Some(&p), &argv, &[]);
    }
});
