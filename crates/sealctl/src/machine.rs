//! `machine.json`: this machine's pairing with a phone (SPEC 3, 8), and the machine facts
//! shown on the phone (name, OS, model, hardware hint).

use anyhow::{Context, Result};
use base64::Engine;
use sealctl_core::{MachineKeys, PhonePublic};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::exit::{self, fail};
use crate::paths;

const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::URL_SAFE_NO_PAD;

/// The stored pairing. The keys are secret (0600 file); everything else is public.
#[derive(Serialize, Deserialize)]
pub struct MachineFile {
    /// `b64u(pairing seed ‖ machine box key)`.
    keys: Zeroizing<String>,
    /// The machine id `b64u(M)`.
    pub machine: String,
    /// `#tag`.
    pub tag: String,
    /// `user@full-hostname`.
    pub name: String,
    /// Relay origin recorded at pairing.
    pub relay: String,
    /// Phone identity key `P`.
    pub phone: String,
    /// Phone box key `X`.
    pub phone_box: String,
    /// The phone key before a words change, kept until objects are rewrapped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_phone: Option<String>,
    /// Paired time, Unix ms.
    pub paired: u64,
    /// Last machine message `seq` seen.
    #[serde(default)]
    pub msg_seq: u64,
    /// Last status `seq` sent.
    #[serde(default)]
    pub status_seq: u64,
}

/// A paired machine, ready to sign and seal.
pub struct Paired {
    /// The pairing and box keys.
    pub keys: MachineKeys,
    /// The phone's public keys.
    pub phone: PhonePublic,
    /// The stored record.
    pub file: MachineFile,
}

impl Paired {
    /// The phone id (43 characters) used in relay paths.
    pub fn phone_id(&self) -> &str {
        &self.file.phone
    }

    /// `name #tag`.
    pub fn label(&self) -> String {
        format!("{} #{}", self.file.name, self.file.tag)
    }
}

impl MachineFile {
    /// A new record after a successful pairing.
    pub fn new(keys: &MachineKeys, name: &str, relay: &str, phone: &str, phone_box: &str) -> Result<Self> {
        Ok(MachineFile {
            keys: Zeroizing::new(B64.encode(keys.to_bytes().as_slice())),
            machine: keys.id(),
            tag: sealctl_core::machine::tag(keys.public()),
            name: name.to_string(),
            relay: relay.to_string(),
            phone: phone.to_string(),
            phone_box: phone_box.to_string(),
            previous_phone: None,
            paired: now_ms(),
            msg_seq: 0,
            status_seq: 0,
        })
    }

    /// Saves `machine.json` (0600).
    pub fn save(&self) -> Result<()> {
        paths::ensure_private_dir(&paths::config_dir()?)?;
        let text = Zeroizing::new(serde_json::to_vec_pretty(self)?);
        paths::write_private(&paths::machine_file()?, &text)
    }
}

/// Unix milliseconds now.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Is there a `machine.json`?
pub fn is_paired() -> bool {
    paths::machine_file().map(|p| p.exists()).unwrap_or(false)
}

/// Loads the pairing. Exit 3 when not paired; refuses a file others can read.
pub fn load() -> Result<Paired> {
    let p = paths::machine_file()?;
    let meta = match std::fs::metadata(&p) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(exit::not_paired()),
        Err(e) => return Err(e).context("reading machine.json"),
    };
    use std::os::unix::fs::PermissionsExt;
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(fail(
            exit::ERROR,
            format!(
                "{} is readable by others.\nRun: chmod 600 {}",
                p.display(),
                p.display()
            ),
        ));
    }
    let text = Zeroizing::new(std::fs::read(&p).context("reading machine.json")?);
    let file: MachineFile = serde_json::from_slice(&text).context("machine.json is damaged")?;
    let raw = Zeroizing::new(B64.decode(file.keys.as_bytes()).context("machine.json keys")?);
    let keys = MachineKeys::from_bytes(&raw).map_err(|e| anyhow::anyhow!("machine.json keys: {e}"))?;
    let phone = PhonePublic::from_b64u(&file.phone, &file.phone_box)
        .map_err(|e| anyhow::anyhow!("machine.json phone keys: {e}"))?;
    Ok(Paired { keys, phone, file })
}

/// Loads the pairing and checks the requested relay against the recorded one (exit 2).
pub fn load_for(relay_flag: Option<&str>) -> Result<Paired> {
    let p = load()?;
    if let Some(r) = crate::config::requested_relay(relay_flag)? {
        // compared in normalized form: a pairing recorded before normalization may differ
        // in case or in a default port only
        let recorded = crate::config::validate_origin(&p.file.relay).unwrap_or_else(|_| p.file.relay.clone());
        if r != recorded {
            return Err(fail(
                exit::USAGE,
                format!(
                    "This machine is paired through {}, not {r}. Unset SEALCTL_RELAY, or pair again: sealctl pair --relay {r}",
                    p.file.relay
                ),
            ));
        }
    }
    Ok(p)
}

/// Deletes the pairing.
pub fn forget() -> Result<()> {
    match std::fs::remove_file(paths::machine_file()?) {
        Err(e) if e.kind() != std::io::ErrorKind::NotFound => Err(e.into()),
        _ => Ok(()),
    }
}

// ---------- machine facts ----------

fn output(cmd: &str, args: &[&str]) -> Option<String> {
    let out = crate::util::system_cmd(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    (!s.is_empty()).then_some(s)
}

/// `$USER@` plus the full hostname.
pub fn default_name() -> String {
    let user = std::env::var("USER")
        .ok()
        .filter(|u| !u.is_empty())
        .or_else(|| output("id", &["-un"]))
        .unwrap_or_else(|| "user".into());
    let host = if cfg!(target_os = "macos") {
        output("scutil", &["--get", "HostName"])
            .or_else(|| output("scutil", &["--get", "LocalHostName"]).map(|h| format!("{h}.local")))
            .or_else(|| output("hostname", &[]))
    } else {
        output("hostname", &["-f"]).or_else(|| output("hostname", &[]))
    }
    .unwrap_or_else(|| "localhost".into());
    format!("{user}@{host}")
}

/// OS name and version: `macOS 15.2`, `Ubuntu 24.04`.
pub fn os_name() -> String {
    if cfg!(target_os = "macos") {
        return output("sw_vers", &["-productVersion"])
            .map(|v| format!("macOS {v}"))
            .unwrap_or_else(|| "macOS".into());
    }
    if let Ok(t) = std::fs::read_to_string("/etc/os-release") {
        let get = |k: &str| {
            t.lines()
                .find_map(|l| l.strip_prefix(&format!("{k}=")))
                .map(|v| v.trim_matches('"').to_string())
        };
        if let Some(n) = get("PRETTY_NAME") {
            return n;
        }
        if let (Some(n), Some(v)) = (get("NAME"), get("VERSION_ID")) {
            return format!("{n} {v}");
        }
    }
    std::env::consts::OS.to_string()
}

/// Hardware model: `Mac15,3`, or the DMI product name.
pub fn model() -> Option<String> {
    if cfg!(target_os = "macos") {
        output("sysctl", &["-n", "hw.model"])
    } else {
        std::fs::read_to_string("/sys/class/dmi/id/product_name")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    }
    .map(|s| s.chars().take(200).collect())
}

/// The hardware hint (protocol.md): from `IOPlatformUUID` or `/etc/machine-id`.
pub fn hint() -> Option<String> {
    let raw = if cfg!(target_os = "macos") {
        let out = output("ioreg", &["-rd1", "-c", "IOPlatformExpertDevice"])?;
        out.lines().find_map(|l| {
            let l = l.trim();
            l.strip_prefix("\"IOPlatformUUID\" = ")
                .map(|v| v.trim_matches('"').to_string())
        })?
    } else {
        std::fs::read_to_string("/etc/machine-id")
            .ok()?
            .trim()
            .to_string()
    };
    (!raw.is_empty()).then(|| sealctl_core::machine::hardware_hint(&raw))
}

/// Uses ssh-agent-lib-free base64url decoding for 32-byte keys from the wire.
pub fn decode_key32(text: &str) -> Option<[u8; 32]> {
    B64.decode(text).ok()?.try_into().ok()
}

/// base64url without padding.
pub fn b64u(bytes: &[u8]) -> String {
    B64.encode(bytes)
}
