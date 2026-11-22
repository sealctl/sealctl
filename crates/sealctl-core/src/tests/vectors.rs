//! Every value in `docs/vectors/v1.json` and `docs/vectors/relay-signing.json`, byte for byte.

use super::*;
use crate::channel;
use crate::keys::{key_check, ObjectKey, Purpose};
use crate::machine::{hardware_hint, tag};
use crate::pairing::{self, PairingLink, PairingOffer};
use crate::phone::{backup_item_decode, backup_item_encode, Place};
use crate::plan;
use crate::relay_auth::{self, RelayHeaders};
use crate::reply::{self, Decision};
use crate::request::{self, open_request_at};
use crate::sealed::{self, Header, Mode};
use crate::state_blob;
use crate::wire::{MachineMessage, MachineStatus, PlanItem, RequestBody};

#[test]
fn every_v1_vector() {
    let v = V1::load();
    words_and_roots(&v);
    object_keys(&v);
    sealed_files(&v);
    state_blob_and_backup_item(&v);
    machine_and_pairing(&v);
    request_and_reply(&v);
    status_and_message(&v);
    unseal(&v);
    relay_signature(&v);
    assert_eq!(v.unused(), Vec::<String>::new(), "v1.json values no test checked");
}

fn words_and_roots(v: &V1) {
    assert_eq!(hex::encode(sha("sealctl test vector B")), v.s("B.entropy"));
    for (k, words) in [("A", words_a()), ("B", words_b())] {
        let mnemonic = v.s(&format!("{k}.mnemonic"));
        assert_eq!(words.list().join(" "), mnemonic);
        let parsed = Words::parse(mnemonic.split(' ').map(str::to_owned).collect()).unwrap();
        assert_eq!(parsed.entropy(), words.entropy());
        assert_eq!(hex::encode(words.seed().as_slice()), v.s(&format!("{k}.seed")));
        let root = Root::from_words(&words);
        assert_eq!(hex::encode(root.to_bytes()), v.s(&format!("{k}.root")));
        assert_eq!(
            hex::encode(root.derive::<8>("fingerprint").as_slice()),
            v.s(&format!("{k}.fingerprint_okm"))
        );
        assert_eq!(crate::fingerprint(&root), v.s(&format!("{k}.fingerprint")));
        assert_eq!(
            hex::encode(root.phone_identity_seed().as_slice()),
            v.s(&format!("{k}.phone_identity_seed"))
        );
        assert_eq!(
            hex::encode(root.phone_box_secret().as_slice()),
            v.s(&format!("{k}.phone_box_private"))
        );
        let keys = PhoneKeys::from_root(&root);
        assert_eq!(keys.public_id(), v.s(&format!("{k}.phone_identity_public_b64u")));
        assert_eq!(keys.box_public_key(), v.s(&format!("{k}.phone_box_public_b64u")));
        assert_eq!(
            hex::encode(root.state_key().as_slice()),
            v.s(&format!("{k}.state_key"))
        );
        // The 64-byte storage form gives the same keys back.
        let again = PhoneKeys::from_bytes(keys.to_bytes()).unwrap();
        assert_eq!(again.public_id(), keys.public_id());
        assert_eq!(again.box_public_key(), keys.box_public_key());
    }
}

fn object_keys(v: &V1) {
    let root = root_b();
    for (p, id) in [
        (Purpose::Secrets, STORE),
        (Purpose::Secret, FILE),
        (Purpose::Volume, VOL),
        (Purpose::Backup, REPO),
    ] {
        let key = ObjectKey::derive(&root, p, id).unwrap();
        let name = format!("{} {id}", p.as_str());
        assert_eq!(key.hex().as_str(), v.s(&format!("B.key {name}")));
        assert_eq!(key.b64u().as_str(), v.s(&format!("B.key_b64u {name}")));
        assert_eq!(key.check(), v.s(&format!("B.check {name}")));
        assert_eq!(
            key_check(ObjectKey::from_b64u(&key.b64u()).unwrap().as_bytes()),
            key.check()
        );
    }
}

fn sealed_files(v: &V1) {
    let root = root_b();
    let name = "shop/openai-api-key";
    let value = b"test-value-not-a-real-key";
    for (mode, key, nonce, tag) in [
        (
            Mode::StoreKey,
            ObjectKey::derive(&root, Purpose::Secrets, STORE).unwrap(),
            "000102030405060708090a0b",
            "mode1",
        ),
        (
            Mode::OwnApproval,
            ObjectKey::derive(&root, Purpose::Secret, FILE).unwrap(),
            "0c0d0e0f1011121314151617",
            "mode2",
        ),
    ] {
        assert_eq!(
            hex::encode(sealed::file_key(&key, FILE).as_slice()),
            v.s(&format!("B.file_key_{tag}"))
        );
        let label = sealed::Label {
            mode,
            words: root.fingerprint(),
            file_id: FILE.into(),
        };
        let nonce: [u8; 12] = unhex(nonce).try_into().unwrap();
        let file = sealed::seal_with_nonce(&label, &nonce, &key, STORE, name, value).unwrap();
        assert_eq!(hex::encode(&file), v.s(&format!("B.sealed_{tag}")));
        let header = Header::parse(&file).unwrap();
        assert_eq!((header.label(), header.nonce), (label.clone(), nonce));
        assert_eq!(sealed::open(&file, &key, STORE, name).unwrap().as_slice(), value);
    }
}

fn state_blob_and_backup_item(v: &V1) {
    let root = root_b();
    let nonce: [u8; 12] = unhex("18191a1b1c1d1e1f20212223").try_into().unwrap();
    let blob = state_blob::state_seal_with_nonce(&root, br#"{"v":1}"#, &nonce).unwrap();
    assert_eq!(blob, v.s("B.state_blob_b64u"));
    assert_eq!(state_blob::state_open(&root, blob).unwrap(), br#"{"v":1}"#);

    let created = 1_795_251_600_000; // 2026-11-21T09:00:00Z
    let item = backup_item_encode(&words_b(), root.fingerprint(), created).unwrap();
    assert_eq!(hex::encode(&item), v.s("backup_item"));
    let back = backup_item_decode(item).unwrap();
    assert_eq!(back.words.entropy(), words_b().entropy());
    assert_eq!((back.fingerprint.as_str(), back.created), ("qHWf", created));
}

fn machine_and_pairing(v: &V1) {
    let m = machine();
    assert_eq!(hex::encode(sha("sealctl test machine")), v.s("machine.seed"));
    assert_eq!(
        hex::encode(sha("sealctl test machine box")),
        v.s("machine.box_private")
    );
    assert_eq!(m.id(), v.s("machine.public_b64u"));
    assert_eq!(crypto::b64u(m.box_public()), v.s("machine.box_public_b64u"));
    assert_eq!(tag(m.public()), v.s("machine.tag"));
    assert_eq!(crate::machine_tag(m.id()).unwrap(), v.s("machine.tag"));
    let hint = hardware_hint("0123456789abcdef0123456789abcdef");
    assert_eq!(hint, v.s("machine.hint"));

    let code: [u8; 16] = unhex("000102030405060708090a0b0c0d0e0f").try_into().unwrap();
    let expires = 1_795_252_200; // 2026-11-21T09:10:00Z
    let link = PairingLink {
        machine: m.public(),
        machine_box: m.box_public(),
        code: &code,
        name: "dev@mbp.example.com",
        os: "macOS 15.2",
        model: Some("Mac15,3"),
        hint: Some(&hint),
        expires,
        relay: None,
    }
    .link();
    assert_eq!(link, v.s("pair.link"));

    for text in [link.clone(), link.split_once('#').unwrap().1.to_owned()] {
        let offer = PairingOffer::parse_at(&text, expires - 60).unwrap();
        assert_eq!(offer.machine_key(), m.id());
        assert_eq!(offer.machine_box_key(), crypto::b64u(m.box_public()));
        assert_eq!(offer.name(), "dev@mbp.example.com");
        assert_eq!(offer.os(), "macOS 15.2");
        assert_eq!(offer.model().as_deref(), Some("Mac15,3"));
        assert_eq!(offer.hint(), Some(hint.clone()));
        assert_eq!(offer.relay_origin(), pairing::DEFAULT_RELAY);
        assert_eq!((offer.version(), offer.expires()), (1, expires));
        assert_eq!(offer.tag(), v.s("machine.tag"));
    }

    let keys = PhoneKeys::from_root(&root_b());
    let offer = PairingOffer::parse_at(&link, expires).unwrap();
    let proof = crate::pairing_proof(&keys, &offer);
    assert_eq!(proof, v.s("pair.proof"));
    let raw = crypto::b64u_decode(&proof).unwrap();
    assert_eq!(hex::encode(&raw[32..]), v.s("pair.hmac"));
    let x = pairing::verify_pairing_proof(&code, m.public(), keys.identity_public(), &proof).unwrap();
    assert_eq!(&x, keys.box_public());

    let old = PhoneKeys::from_root(&root_a());
    let mv = crate::key_change_proof(&old, &keys, m.id()).unwrap();
    assert_eq!(mv, v.s("move.proof"));
    assert_eq!(mv.len() as u64, v.n("move.proof_length"));
    assert_eq!(
        hex::encode(&crypto::b64u_decode(&mv).unwrap()[32..]),
        v.s("move.signature")
    );
    let x_new =
        pairing::verify_move_proof(old.identity_public(), keys.identity_public(), m.public(), &mv).unwrap();
    assert_eq!(&x_new, keys.box_public());
}

/// Parses a vector body and checks that the serde types write it back byte for byte.
fn exact<T: serde::Serialize + serde::de::DeserializeOwned>(text: &str) -> T {
    let value: T = serde_json::from_str(text).unwrap();
    assert_eq!(
        serde_json::to_string(&value).unwrap(),
        text,
        "serde field order or form differs"
    );
    value
}

fn request_and_reply(v: &V1) {
    let m = machine();
    let root = root_b();
    let keys = PhoneKeys::from_root(&root);
    let id = id_open();
    assert_eq!(id, v.s("request.id"));
    let t = v.n("request.t");

    // Machine side: the one-time key and the HPKE ephemeral key come from the vector inputs.
    let body_text = v.s("request.body");
    let mut body: RequestBody = exact(&body_text);
    body.ot = None;
    let mut rng = FixedRng::new(&[
        &sha("sealctl test one-time key"),
        &sha("sealctl test ephemeral request"),
    ]);
    let sent = request::seal_request_with_rng(&m, &phone_public(&keys), &id, body, &mut rng).unwrap();
    drop(rng);
    assert_eq!(crypto::b64u(sent_ot(&sent)), v.s("onetime.public_b64u"));
    assert_eq!(
        hex::encode(sent_ot_secret(&sent)),
        clamped(&v.s("onetime.private"))
    );
    assert_eq!(String::from_utf8(sent.body.clone()).unwrap(), body_text);
    assert_eq!(sent.sealed, v.s("request.sealed"));
    assert_eq!(sent.sealed.len() as u64, v.n("request.sealed_length"));
    assert_eq!(sent.number, None);
    let raw = crypto::b64u_decode(&sent.sealed).unwrap();
    assert_eq!(hex::encode(&raw[..32]), v.s("request.enc"));
    let (pt, _) = crypto::hpke_open(
        keys.box_secret(),
        b"sealctl/v1/request",
        &request::aad(&id, m.public()),
        &raw,
    )
    .unwrap();
    assert_eq!(hex::encode(&pt[..64]), v.s("request.signature"));

    // Phone side.
    let req = open_request_at(&keys, &m.id(), &id, &sent.sealed, t).unwrap();
    assert_eq!(req.kind(), crate::RequestKind::Open);
    assert_eq!(req.rq(), v.s("reply.rq"));
    assert_eq!(req.level(), 1);
    assert!(!req.has_match());
    assert_eq!(req.ctx().unwrap().agent.as_deref(), Some("Claude Code"));
    assert_eq!(req.items()[0].check.as_deref(), Some("Je_Q_YPg3B0"));
    assert_eq!(req.uses()[0].repository, "github.com/acme/shop");

    let reply_text = v.s("reply.body");
    let rbody = reply::reply_body(
        Some(&root),
        &keys,
        &req,
        Decision::Remember {
            place: Place::Trusted,
        },
        &[],
    )
    .unwrap();
    assert_eq!(serde_json::to_string(&rbody).unwrap(), reply_text);
    let mut rng = FixedRng::new(&[&sha("sealctl test ephemeral reply")]);
    let sealed = reply::seal_body_with_rng(&keys, &req, &rbody, &mut rng).unwrap();
    drop(rng);
    assert_eq!(sealed, v.s("reply.sealed"));
    assert_eq!(sealed.len() as u64, v.n("reply.sealed_length"));
    let raw = crypto::b64u_decode(&sealed).unwrap();
    let (pt, _) = crypto::hpke_open(
        sent_ot_secret(&sent),
        b"sealctl/v1/reply",
        &request::aad(&id, m.public()),
        &raw,
    )
    .unwrap();
    assert_eq!(hex::encode(&pt[..64]), v.s("reply.signature"));

    // Machine reads the reply.
    let got = sent
        .open_reply(m.public(), keys.identity_public(), &sealed)
        .unwrap();
    assert!(got.ok);
    assert_eq!(
        got.keys[0].k.as_deref().map(String::as_str),
        Some(v.s(&format!("B.key_b64u secrets {STORE}")).as_str())
    );
}

fn sent_ot(sent: &request::SealedRequest) -> &[u8; 32] {
    sent.one_time_for_tests().0
}

fn sent_ot_secret(sent: &request::SealedRequest) -> &[u8; 32] {
    sent.one_time_for_tests().1
}

fn status_and_message(v: &V1) {
    let m = machine();
    let keys = PhoneKeys::from_root(&root_b());

    let sbody = v.s("status.body");
    let status: MachineStatus = exact(&sbody);
    let mut rng = FixedRng::new(&[&sha("sealctl test ephemeral status")]);
    let sealed = channel::seal_status_bytes(&m, &phone_public(&keys), sbody.as_bytes(), &mut rng).unwrap();
    drop(rng);
    assert_eq!(sealed, v.s("status.sealed"));
    let raw = crypto::b64u_decode(&sealed).unwrap();
    let (pt, _) = crypto::hpke_open(keys.box_secret(), b"sealctl/v1/status", m.public(), &raw).unwrap();
    assert_eq!(hex::encode(&pt[..64]), v.s("status.signature"));
    assert_eq!(crate::open_machine_status(&keys, m.id(), sealed).unwrap(), status);

    let mbody = v.s("message.body");
    let message: MachineMessage = exact(&mbody);
    let mut rng = FixedRng::new(&[&sha("sealctl test ephemeral message")]);
    let sealed =
        channel::seal_message_bytes(&keys, m.public(), m.box_public(), mbody.as_bytes(), &mut rng).unwrap();
    drop(rng);
    assert_eq!(sealed, v.s("message.sealed"));
    let raw = crypto::b64u_decode(&sealed).unwrap();
    let (pt, _) = crypto::hpke_open(
        &sha("sealctl test machine box"),
        b"sealctl/v1/message",
        m.public(),
        &raw,
    )
    .unwrap();
    assert_eq!(hex::encode(&pt[..64]), v.s("message.signature"));
    assert_eq!(
        channel::open_message(&m, keys.identity_public(), &sealed).unwrap(),
        message
    );
}

fn unseal(v: &V1) {
    let m = machine();
    let root = root_b();
    let keys = PhoneKeys::from_root(&root);
    let id = crypto::b64u(&(0x40u8..0x50).collect::<Vec<_>>());
    assert_eq!(id, v.s("unseal.request.id"));

    let body_text = v.s("unseal.request.body");
    let mut body: RequestBody = exact(&body_text);
    let t = body.t;
    let items: Vec<PlanItem> = body.plan.as_ref().unwrap().items.clone();
    assert_eq!(plan::plan_text(&m.id(), &items), v.json_text("plan.text"));
    let ph = plan::plan_hash(&m.id(), &items);
    assert_eq!(crypto::b64u(&ph), v.s("plan.hash_b64u"));

    body.ot = None;
    let mut rng = FixedRng::new(&[
        &sha("sealctl test one-time key unseal"),
        &sha("sealctl test ephemeral unseal"),
    ]);
    let sent = request::seal_request_with_rng(&m, &phone_public(&keys), &id, body, &mut rng).unwrap();
    drop(rng);
    assert_eq!(crypto::b64u(sent_ot(&sent)), v.s("unseal.onetime.public_b64u"));
    assert_eq!(String::from_utf8(sent.body.clone()).unwrap(), body_text);
    assert_eq!(sent.sealed, v.s("unseal.request.sealed"));
    assert_eq!(sent.sealed.len() as u64, v.n("unseal.request.sealed_length"));
    let raw = crypto::b64u_decode(&sent.sealed).unwrap();
    assert_eq!(hex::encode(&raw[..32]), v.s("unseal.request.enc"));
    let (pt, export) = crypto::hpke_open(
        keys.box_secret(),
        b"sealctl/v1/request",
        &request::aad(&id, m.public()),
        &raw,
    )
    .unwrap();
    assert_eq!(hex::encode(&pt[..64]), v.s("unseal.request.signature"));
    assert_eq!(hex::encode(export), v.s("match.export"));
    let number = v.n("match.number");
    assert_eq!(sent.number.map(u64::from), Some(number));

    // Phone: the number match, then the plan, then the plan signature.
    let req = open_request_at(&keys, &m.id(), &id, &sent.sealed, t).unwrap();
    assert_eq!(req.kind(), crate::RequestKind::Unseal);
    assert!(req.has_match());
    assert_eq!(req.level(), 3);
    let plan = req.plan().unwrap();
    assert!(plan.complete && plan.all);
    assert_eq!(plan.items, items);
    let choices = req.match_choices();
    assert_eq!(choices.len(), 3);
    assert!(choices.contains(&(number as u32)));
    assert!(req.check_match(number as u32));

    let nb = v.n("plan.not_before");
    assert_eq!(
        hex::encode(plan::plan_message(&id, m.public(), &ph, nb)),
        v.s("plan.message_hex")
    );
    let rbody = reply::reply_body(
        Some(&root),
        &keys,
        &req,
        Decision::Plan {
            place: Place::Other,
            not_before: nb,
        },
        &[],
    )
    .unwrap();
    assert_eq!(serde_json::to_string(&rbody).unwrap(), v.s("unseal.reply.body"));
    let sig = rbody.plan.as_ref().unwrap().sig.clone();
    assert_eq!(
        hex::encode(crypto::b64u_decode(&sig).unwrap()),
        v.s("plan.signature")
    );
    let mut rng = FixedRng::new(&[&sha("sealctl test ephemeral unseal reply")]);
    let sealed = reply::seal_body_with_rng(&keys, &req, &rbody, &mut rng).unwrap();
    drop(rng);
    assert_eq!(sealed, v.s("unseal.reply.sealed"));
    assert_eq!(sealed.len() as u64, v.n("unseal.reply.sealed_length"));
    let raw = crypto::b64u_decode(&sealed).unwrap();
    let (pt, _) = crypto::hpke_open(
        sent_ot_secret(&sent),
        b"sealctl/v1/reply",
        &request::aad(&id, m.public()),
        &raw,
    )
    .unwrap();
    assert_eq!(hex::encode(&pt[..64]), v.s("unseal.reply.signature"));

    // Machine: reply, then the plan signature against its own plan hash.
    let got = sent
        .open_reply(m.public(), keys.identity_public(), &sealed)
        .unwrap();
    let ps = got.plan.unwrap();
    plan::verify_plan_signature(keys.identity_public(), &id, m.public(), &ph, ps.nb, &ps.sig).unwrap();
    assert_eq!(got.keys.len(), 2);
}

fn relay_signature(v: &V1) {
    let m = machine();
    let p = PhoneKeys::from_root(&root_b()).public_id();
    let path = format!("/v1/phones/{p}/licence");
    let time = 1_795_251_600;
    assert_eq!(
        relay_auth::canonical("GET", &path, time, b""),
        v.json_text("relay.canonical")
    );
    let h = relay_auth::machine_relay_headers(&m, "GET", &path, time, b"");
    assert_eq!(h.signature, v.s("relay.signature"));
}

#[test]
fn every_relay_signing_vector() {
    let r = relay_vectors();
    assert_eq!(r["scheme"], "sealctl-relay-v1");
    let phone = PhoneKeys::from_root(&root_b());
    let old = PhoneKeys::from_root(&root_a());
    let m = machine();
    let keys = &r["keys"];
    assert_eq!(keys["machine"]["seed"], hex::encode(sha("sealctl test machine")));
    assert_eq!(keys["machine"]["public"], m.id());
    assert_eq!(
        keys["phone"]["seed"],
        hex::encode(root_b().phone_identity_seed().as_slice())
    );
    assert_eq!(keys["phone"]["public"], phone.public_id());
    assert_eq!(
        keys["oldPhone"]["seed"],
        hex::encode(root_a().phone_identity_seed().as_slice())
    );
    assert_eq!(keys["oldPhone"]["public"], old.public_id());

    let vectors = r["vectors"].as_array().unwrap();
    assert_eq!(vectors.len(), 6);
    for vec in vectors {
        let s = |k: &str| vec[k].as_str().unwrap().to_owned();
        let time: u64 = s("time").parse().unwrap();
        let body = s("body");
        assert_eq!(crypto::b64u(&crypto::sha256(body.as_bytes())), s("bodyHash"));
        assert_eq!(
            relay_auth::canonical(&s("method"), &s("path"), time, body.as_bytes()),
            s("canonical")
        );
        let headers = match s("signer").as_str() {
            "phone" => crate::relay_headers(&phone, s("method"), s("path"), time, body.clone().into_bytes()),
            "machine" => {
                relay_auth::machine_relay_headers(&m, &s("method"), &s("path"), time, body.as_bytes())
            }
            other => panic!("signer {other}"),
        };
        assert_eq!(
            headers,
            RelayHeaders {
                key: s("key"),
                time: s("time"),
                signature: s("signature")
            },
            "{}",
            s("name")
        );
        relay_auth::verify_relay_headers(&headers, &s("method"), &s("path"), body.as_bytes(), time).unwrap();
    }

    let mv = &r["licenceMove"];
    assert_eq!(mv["old"], old.public_id());
    assert_eq!(mv["new"], phone.public_id());
    assert_eq!(
        mv["message"],
        format!(
            "sealctl-licence-move-v1\n{}\n{}",
            old.public_id(),
            phone.public_id()
        )
    );
    assert_eq!(
        mv["proof"],
        crate::licence_move_proof(&phone, old.public_id()).unwrap()
    );
}
