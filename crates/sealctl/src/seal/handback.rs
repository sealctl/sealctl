//! `handback.json`: what `sealctl unseal` handed back and where each password went. It holds
//! no password or value, so it can be kept anywhere; `sealctl seal --from <file>` (0.7) reads it.

use serde::{Deserialize, Serialize};

use super::store::Location;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Handback {
    pub sealctl: u32,
    pub kind: String,
    pub created: String,
    pub machine: String,
    pub from: String,
    pub objects: Vec<Object>,
}

/// One handed-back object.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Object {
    pub kind: String,
    pub name: String,
    /// Volumes: `apfs`, `sparsebundle`, `luks`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub volume: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<Location>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub credentials: Vec<Credential>,
    /// Secrets: where the value went.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Location>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Credential {
    pub var: String,
    #[serde(flatten)]
    pub location: Location,
}

impl Handback {
    pub fn new(machine: &str) -> Self {
        Handback {
            sealctl: 1,
            kind: "handback".into(),
            created: crate::clock::local_rfc3339(jiff::Timestamp::now()),
            machine: machine.to_string(),
            from: env!("CARGO_PKG_VERSION").to_string(),
            objects: vec![],
        }
    }
}

/// `~/…` for paths under `$HOME` (the list is meant to be read and moved between machines).
pub fn tilde(p: &std::path::Path) -> String {
    let home = std::env::var_os("HOME").map(std::path::PathBuf::from);
    match home.as_deref().and_then(|h| p.strip_prefix(h).ok()) {
        Some(rel) => format!("~/{}", rel.display()),
        None => p.display().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::seal::store::StoreKind;

    #[test]
    fn shape_matches_the_spec() {
        let mut h = Handback::new("dev@mbp");
        let loc: Location = serde_json::from_value(serde_json::json!({
            "store": "keychain", "service": "sealctl-unsealed", "account": "volume/safe"
        }))
        .unwrap();
        assert_eq!(loc.store, StoreKind::Keychain);
        h.objects.push(Object {
            kind: "volume".into(),
            name: "safe".into(),
            volume: Some("apfs".into()),
            uuid: Some("U".into()),
            password: Some(loc.clone()),
            ..Default::default()
        });
        h.objects.push(Object {
            kind: "backup".into(),
            name: "safe".into(),
            url: Some("/r".into()),
            password: Some(loc.clone()),
            credentials: vec![Credential {
                var: "AWS_ACCESS_KEY_ID".into(),
                location: loc,
            }],
            ..Default::default()
        });
        let v = serde_json::to_value(&h).unwrap();
        assert_eq!(v["kind"], "handback");
        assert_eq!(v["from"], env!("CARGO_PKG_VERSION"));
        assert_eq!(v["objects"][0]["password"]["account"], "volume/safe");
        assert_eq!(v["objects"][1]["credentials"][0]["var"], "AWS_ACCESS_KEY_ID");
        assert_eq!(v["objects"][1]["credentials"][0]["store"], "keychain");
        assert!(v["objects"][0].get("credentials").is_none());
    }
}
