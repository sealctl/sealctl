//! Tests: every value in `docs/vectors/*.json`, RFC vectors through the chosen crates,
//! negative cases, property tests and the secret-type rules.

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;

use rand_core::{TryCryptoRng, TryRng};
use serde_json::Value;

use crate::crypto;
use crate::machine::MachineKeys;
use crate::phone::{PhoneKeys, PhonePublic};
use crate::root::Root;
use crate::words::Words;

mod flows;
mod negative;
mod props;
mod rfc;
mod secret_types;
mod vectors;

/// A random source that hands out given bytes in order, so the HPKE `DeriveKeyPair(ikm)` keys
/// of the vectors come out (HPKE's `GenerateKeyPair` is `DeriveKeyPair(random 32 bytes)`).
pub(crate) struct FixedRng(Vec<u8>);

impl FixedRng {
    pub(crate) fn new(chunks: &[&[u8]]) -> Self {
        Self(chunks.concat())
    }
}

impl Drop for FixedRng {
    fn drop(&mut self) {
        if !std::thread::panicking() {
            assert!(self.0.is_empty(), "FixedRng: {} bytes not used", self.0.len());
        }
    }
}

impl TryRng for FixedRng {
    type Error = Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        let mut b = [0u8; 4];
        self.try_fill_bytes(&mut b)?;
        Ok(u32::from_le_bytes(b))
    }
    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        let mut b = [0u8; 8];
        self.try_fill_bytes(&mut b)?;
        Ok(u64::from_le_bytes(b))
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        assert!(self.0.len() >= dst.len(), "FixedRng ran out");
        let rest = self.0.split_off(dst.len());
        dst.copy_from_slice(&self.0);
        self.0 = rest;
        Ok(())
    }
}

impl TryCryptoRng for FixedRng {}

pub(crate) fn sha(text: &str) -> [u8; 32] {
    crypto::sha256(text.as_bytes())
}

pub(crate) fn unhex(text: &str) -> Vec<u8> {
    hex::decode(text).expect("hex")
}

/// RFC 7748 clamping. x25519-dalek keeps a private key clamped, while HPKE `DeriveKeyPair`
/// (and the vectors) print it unclamped; both are the same key, since X25519 clamps on use.
pub(crate) fn clamped(hex_key: &str) -> String {
    let mut k = unhex(hex_key);
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    hex::encode(k)
}

fn read_vectors(name: &str) -> Value {
    let path = format!("{}/../../docs/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&text).expect("vector JSON")
}

/// `docs/vectors/v1.json`, recording which values a test read, so a test can prove that
/// every value was checked.
pub(crate) struct V1 {
    map: BTreeMap<String, Value>,
    used: RefCell<BTreeSet<String>>,
}

impl V1 {
    pub(crate) fn load() -> Self {
        let Value::Object(map) = read_vectors("v1.json") else {
            panic!("v1.json is an object")
        };
        Self {
            map: map.into_iter().collect(),
            used: RefCell::new(BTreeSet::new()),
        }
    }

    pub(crate) fn s(&self, key: &str) -> String {
        self.used.borrow_mut().insert(key.to_owned());
        match self.map.get(key) {
            Some(Value::String(s)) => s.clone(),
            other => panic!("v1.json {key}: {other:?}"),
        }
    }

    pub(crate) fn n(&self, key: &str) -> u64 {
        self.used.borrow_mut().insert(key.to_owned());
        self.map
            .get(key)
            .and_then(Value::as_u64)
            .unwrap_or_else(|| panic!("v1.json {key}"))
    }

    /// A value the script wrote as `JSON.stringify(text)`.
    pub(crate) fn json_text(&self, key: &str) -> String {
        serde_json::from_str(&self.s(key)).expect("JSON string")
    }

    pub(crate) fn unused(&self) -> Vec<String> {
        let used = self.used.borrow();
        self.map.keys().filter(|k| !used.contains(*k)).cloned().collect()
    }
}

pub(crate) fn relay_vectors() -> Value {
    read_vectors("relay-signing.json")
}

// ---------- fixtures from protocol.md Appendix A ----------

pub(crate) const STORE: &str = "0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f";
pub(crate) const FILE: &str = "3d7e1b9a-2c4f-4a8e-b6d1-5f0e9c2a7b34";
pub(crate) const VOL: &str = "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8";
pub(crate) const REPO: &str = "6c1f0b2e-8d3a-4f7b-a9e4-2b5c7d8e9f01";

pub(crate) fn words_a() -> Words {
    Words::from_entropy(vec![0; 32]).unwrap()
}

pub(crate) fn words_b() -> Words {
    Words::from_entropy(sha("sealctl test vector B").to_vec()).unwrap()
}

thread_local! {
    static ROOTS: (Vec<u8>, Vec<u8>) = (Root::from_words(&words_a()).to_bytes(), Root::from_words(&words_b()).to_bytes());
}

/// Root A (PBKDF2 runs once per thread).
pub(crate) fn root_a() -> Root {
    ROOTS.with(|r| Root::from_bytes(r.0.clone()).unwrap())
}

/// Root B.
pub(crate) fn root_b() -> Root {
    ROOTS.with(|r| Root::from_bytes(r.1.clone()).unwrap())
}

pub(crate) fn machine() -> MachineKeys {
    let bytes = [sha("sealctl test machine"), sha("sealctl test machine box")].concat();
    MachineKeys::from_bytes(&bytes).unwrap()
}

pub(crate) fn phone_public(keys: &PhoneKeys) -> PhonePublic {
    PhonePublic {
        identity: *keys.identity_public(),
        box_key: *keys.box_public(),
    }
}

/// The relay request id of the first vector (bytes `30` to `3f`).
pub(crate) fn id_open() -> String {
    crypto::b64u(&(0x30u8..0x40).collect::<Vec<_>>())
}

// ---------- building requests in tests ----------

/// The clock of the tests' requests: 2026-11-21T09:00:00Z.
pub(crate) const T: u64 = 1_795_251_600_000;

pub(crate) fn keys_b() -> PhoneKeys {
    PhoneKeys::from_root(&root_b())
}

pub(crate) fn body(why: &str) -> crate::wire::RequestBody {
    crate::wire::RequestBody {
        v: 1,
        t: T,
        why: why.into(),
        ctx: Some(crate::wire::RequestContext {
            command: "npm test".into(),
            cwd: "~/src/shop".into(),
            user: "dev@mbp.example.com".into(),
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub(crate) fn item(purpose: &str, id: &str) -> crate::wire::RequestItem {
    crate::wire::RequestItem {
        purpose: purpose.into(),
        id: id.into(),
        ..Default::default()
    }
}

/// An item with the words fingerprint and check of root B, as an `.id` file gives them.
pub(crate) fn item_b(p: crate::keys::Purpose, id: &str) -> crate::wire::RequestItem {
    let key = crate::keys::ObjectKey::derive(&root_b(), p, id).unwrap();
    crate::wire::RequestItem {
        purpose: p.as_str().into(),
        id: id.into(),
        words: Some(root_b().fingerprint()),
        check: Some(key.check()),
        object: None,
    }
}

/// Seals a request from the test machine to phone B and opens it at `T`.
pub(crate) fn send(
    body: crate::wire::RequestBody,
) -> (crate::request::SealedRequest, crate::request::Request) {
    let m = machine();
    let keys = keys_b();
    let id = crate::request::new_request_id().unwrap();
    let sent = crate::request::seal_request(&m, &phone_public(&keys), &id, body).unwrap();
    let req = crate::request::open_request_at(&keys, &m.id(), &id, &sent.sealed, T).unwrap();
    (sent, req)
}

/// Opens a reply as the test machine.
pub(crate) fn read_reply(sent: &crate::request::SealedRequest, sealed: &str) -> crate::wire::ReplyBody {
    sent.open_reply(machine().public(), keys_b().identity_public(), sealed)
        .unwrap()
}

pub(crate) fn plan_items() -> Vec<crate::wire::PlanItem> {
    let it = |k: &str, n: &str, p: Option<&str>, i: Option<&str>| crate::wire::PlanItem {
        kind: k.into(),
        name: n.into(),
        purpose: p.map(Into::into),
        id: i.map(Into::into),
    };
    vec![
        it("secrets", "store", Some("secrets"), Some(STORE)),
        it("volume", "safe", Some("volume"), Some(VOL)),
        it("ssh", "ed25519", Some("secrets"), Some(STORE)),
        it("git", "signing", None, None),
    ]
}

/// An `unseal` body carrying `items` as a one-part plan.
pub(crate) fn unseal_body(items: Vec<crate::wire::PlanItem>, all: bool) -> crate::wire::RequestBody {
    let h = crypto::b64u(&crate::plan::plan_hash(&machine().id(), &items));
    crate::wire::RequestBody {
        has_match: true,
        plan: Some(crate::wire::PlanBody {
            all,
            h,
            items,
            n: None,
            i: None,
        }),
        ..body("unseal")
    }
}
