//! What must fail, and how.

use super::*;
use crate::error::CoreError;
use crate::keys::{ObjectKey, Purpose};
use crate::pairing::{self, PairingLink, PairingOffer};
use crate::phone::Place;
use crate::relay_auth;
use crate::reply::{self, Decision, RetiredWords};
use crate::request::{self, open_request_at, MAX_SEALED, REQUEST_INFO, TIME_WINDOW_MS};
use crate::state_blob;
use crate::wire::{PlanItem, RequestBody};

/// Seals body bytes with a chosen signer and signature, bypassing the checks of
/// `seal_request`, so the phone's checks can be tested.
fn seal_raw(signer: &MachineKeys, named: &MachineKeys, id: &str, body: &[u8], tamper_sig: bool) -> String {
    let keys = keys_b();
    let mut sig = signer.sign(&request::request_message(id, keys.identity_public(), body));
    if tamper_sig {
        sig[10] ^= 0x01;
    }
    let pt = crypto::cat(&[&sig, body]);
    let s = crypto::hpke_seal(
        keys.box_public(),
        REQUEST_INFO,
        &request::aad(id, named.public()),
        &pt,
        &mut crypto::os_rng(),
    )
    .unwrap();
    crypto::b64u(&s.bytes)
}

fn body_bytes(mut b: RequestBody) -> Vec<u8> {
    b.ot = Some(crypto::b64u(&[9u8; 32]));
    serde_json::to_vec(&b).unwrap()
}

#[test]
fn request_with_tampered_signature() {
    let m = machine();
    let id = request::new_request_id().unwrap();
    let sealed = seal_raw(&m, &m, &id, &body_bytes(body("open")), true);
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, &sealed, T).err(),
        Some(CoreError::BadSignature)
    );
    // The same, untampered, opens.
    let sealed = seal_raw(&m, &m, &id, &body_bytes(body("open")), false);
    assert!(open_request_at(&keys_b(), &m.id(), &id, &sealed, T).is_ok());
}

#[test]
fn request_signed_by_another_machine() {
    let m = machine();
    let other = MachineKeys::generate().unwrap();
    let id = request::new_request_id().unwrap();
    let sealed = seal_raw(&other, &m, &id, &body_bytes(body("open")), false);
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, &sealed, T).err(),
        Some(CoreError::BadSignature)
    );
}

#[test]
fn request_under_wrong_machine_id_or_id_or_phone() {
    let m = machine();
    let other = MachineKeys::generate().unwrap();
    let id = request::new_request_id().unwrap();
    let sent = request::seal_request(&m, &phone_public(&keys_b()), &id, body("open")).unwrap();
    // The relay names another machine: the HPKE aad no longer matches.
    assert_eq!(
        open_request_at(&keys_b(), &other.id(), &id, &sent.sealed, T).err(),
        Some(CoreError::BadSealed)
    );
    // Another request id.
    let id2 = request::new_request_id().unwrap();
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id2, &sent.sealed, T).err(),
        Some(CoreError::BadSealed)
    );
    // The wrong phone (words A).
    let keys_a = PhoneKeys::from_root(&root_a());
    assert_eq!(
        open_request_at(&keys_a, &m.id(), &id, &sent.sealed, T).err(),
        Some(CoreError::BadSealed)
    );
    // Not a key, not an id.
    assert_eq!(
        open_request_at(&keys_b(), "short", &id, &sent.sealed, T).err(),
        Some(CoreError::BadKey)
    );
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), "not-an-id", &sent.sealed, T).err(),
        Some(CoreError::BadSealed)
    );
}

#[test]
fn request_with_tampered_ciphertext() {
    let m = machine();
    let id = request::new_request_id().unwrap();
    let sent = request::seal_request(&m, &phone_public(&keys_b()), &id, body("open")).unwrap();
    for at in [0, 40, sent.sealed.len() / 2, sent.sealed.len() - 2] {
        let mut chars: Vec<char> = sent.sealed.chars().collect();
        chars[at] = if chars[at] == 'A' { 'B' } else { 'A' };
        let bad: String = chars.into_iter().collect();
        assert_eq!(
            open_request_at(&keys_b(), &m.id(), &id, &bad, T).err(),
            Some(CoreError::BadSealed),
            "at {at}"
        );
    }
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, "", T).err(),
        Some(CoreError::BadSealed)
    );
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, "@@@", T).err(),
        Some(CoreError::BadSealed)
    );
}

#[test]
fn request_outside_the_time_window() {
    let m = machine();
    let id = request::new_request_id().unwrap();
    let sent = request::seal_request(&m, &phone_public(&keys_b()), &id, body("open")).unwrap();
    let open = |now| open_request_at(&keys_b(), &m.id(), &id, &sent.sealed, now).err();
    assert_eq!(open(T + TIME_WINDOW_MS), None);
    assert_eq!(open(T - TIME_WINDOW_MS), None);
    assert_eq!(open(T + TIME_WINDOW_MS + 1), Some(CoreError::Expired));
    assert_eq!(open(T - TIME_WINDOW_MS - 1), Some(CoreError::Expired));
}

#[test]
fn oversize_requests() {
    let m = machine();
    let id = request::new_request_id().unwrap();
    // More than 4,096 characters is refused before any decoding.
    let long = "A".repeat(MAX_SEALED + 1);
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, &long, T).err(),
        Some(CoreError::BadSealed)
    );
    // A body over 2,960 bytes is refused when sealing.
    let mut b = body("open");
    b.ctx.as_mut().unwrap().names = vec!["x".repeat(100); 30];
    let err = request::seal_request(&m, &phone_public(&keys_b()), &id, b).err();
    assert_eq!(err, Some(CoreError::TooLarge));
    // The largest body that fits seals to at most 4,096 characters and opens.
    let mut b = body("open");
    let ctx = b.ctx.as_mut().unwrap();
    ctx.command.clear();
    let base = body_bytes(b.clone()).len();
    b.ctx.as_mut().unwrap().command = "c".repeat(request::MAX_BODY - base);
    let sent = request::seal_request(&m, &phone_public(&keys_b()), &id, b).unwrap();
    assert_eq!(sent.body.len(), request::MAX_BODY);
    assert_eq!(sent.sealed.len(), MAX_SEALED);
    assert!(open_request_at(&keys_b(), &m.id(), &id, &sent.sealed, T).is_ok());
}

#[test]
fn newer_or_missing_version() {
    let m = machine();
    let id = request::new_request_id().unwrap();
    let newer = br#"{"v":2,"t":1795251600000,"why":"open","future":{"x":[1,2]}}"#;
    let sealed = seal_raw(&m, &m, &id, newer, false);
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, &sealed, T).err(),
        Some(CoreError::NewerVersion)
    );
    let none = br#"{"t":1795251600000,"why":"open"}"#;
    let sealed = seal_raw(&m, &m, &id, none, false);
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, &sealed, T).err(),
        Some(CoreError::BadSealed)
    );
    let junk = b"not json";
    let sealed = seal_raw(&m, &m, &id, junk, false);
    assert_eq!(
        open_request_at(&keys_b(), &m.id(), &id, &sealed, T).err(),
        Some(CoreError::BadSealed)
    );
}

#[test]
fn a_request_is_answered_once() {
    let (_, req) = send(body("open"));
    let keys = keys_b();
    reply::seal_reply(None, &keys, &req, Decision::Deny).unwrap();
    assert_eq!(
        reply::seal_reply(None, &keys, &req, Decision::Deny).err(),
        Some(CoreError::Replay)
    );
}

#[test]
fn tampered_or_foreign_replies() {
    let keys = keys_b();
    let m = machine();
    let (sent, req) = send(body("open"));
    let sealed = reply::seal_reply(None, &keys, &req, Decision::Deny).unwrap();
    // Signed by another phone.
    let keys_a = PhoneKeys::from_root(&root_a());
    assert_eq!(
        sent.open_reply(m.public(), keys_a.identity_public(), &sealed)
            .err(),
        Some(CoreError::BadSignature)
    );
    // Tampered.
    let mut chars: Vec<char> = sealed.chars().collect();
    chars[50] = if chars[50] == 'A' { 'B' } else { 'A' };
    let bad: String = chars.into_iter().collect();
    assert_eq!(
        sent.open_reply(m.public(), keys.identity_public(), &bad).err(),
        Some(CoreError::BadSealed)
    );
    // Sealed for another request.
    let (sent2, _) = send(body("open"));
    assert_eq!(
        sent2
            .open_reply(m.public(), keys.identity_public(), &sealed)
            .err(),
        Some(CoreError::BadSealed)
    );
    // A reply whose `rq` names another body.
    let (sent3, req3) = send(body("open"));
    let mut rb = reply::reply_body(None, &keys, &req3, Decision::Deny, &[]).unwrap();
    rb.rq = req.rq();
    let mut rng = FixedRng::new(&[&[7u8; 32]]);
    let sealed3 = reply::seal_body_with_rng(&keys, &req3, &rb, &mut rng).unwrap();
    drop(rng);
    assert_eq!(
        sent3
            .open_reply(m.public(), keys.identity_public(), &sealed3)
            .err(),
        Some(CoreError::BadSealed)
    );
}

#[test]
fn level_3_needs_a_right_pick() {
    let keys = keys_b();
    let root = Arc::new(root_b());
    let nb = T + 3_600_000;
    let plan = Decision::Plan {
        place: Place::Other,
        not_before: nb,
    };

    // No pick at all: answered no_match.
    let (sent, req) = send(unseal_body(plan_items(), true));
    assert_eq!(req.level(), 3);
    let r = read_reply(
        &sent,
        &reply::seal_reply(Some(root.clone()), &keys, &req, plan).unwrap(),
    );
    assert_eq!((r.ok, r.err.as_deref()), (false, Some("no_match")));

    // A wrong pick is final, even if the right one follows.
    let (sent, req) = send(unseal_body(plan_items(), true));
    let n = sent.number.unwrap() as u32;
    let choices = req.match_choices();
    assert_eq!(req.match_choices(), choices, "choices are stable");
    let wrong = *choices.iter().find(|&&c| c != n).unwrap();
    assert!(!req.check_match(wrong));
    assert!(!req.check_match(n));
    let r = read_reply(
        &sent,
        &reply::seal_reply(Some(root.clone()), &keys, &req, plan).unwrap(),
    );
    assert_eq!(r.err.as_deref(), Some("no_match"));

    // A number not offered is wrong even if it is right.
    let (sent, req) = send(unseal_body(plan_items(), true));
    assert!(
        !req.check_match(sent.number.unwrap() as u32),
        "no choices drawn yet"
    );

    // A machine cannot lower the level: lvl 1 on `unseal --all` is still level 3.
    let mut b = unseal_body(plan_items(), true);
    b.lvl = Some(1);
    assert_eq!(send(b).1.level(), 3);
    // A pairing step makes a plan level 3 too.
    let mut items = plan_items();
    items.push(PlanItem {
        kind: "pairing".into(),
        name: "dev@mbp.example.com".into(),
        purpose: None,
        id: None,
    });
    assert_eq!(send(unseal_body(items, false)).1.level(), 3);
    assert_eq!(send(unseal_body(plan_items(), false)).1.level(), 2);
}

#[test]
fn decisions_that_do_not_fit() {
    let keys = keys_b();
    let root = || Some(Arc::new(root_b()));
    let (_, open) = send(body("open"));
    let plan = Decision::Plan {
        place: Place::Trusted,
        not_before: T,
    };
    assert_eq!(
        reply::seal_reply(root(), &keys, &open, plan).err(),
        Some(CoreError::WrongDecision)
    );
    let (_, unseal) = send(unseal_body(plan_items(), false));
    let once = Decision::Once {
        place: Place::Trusted,
    };
    assert_eq!(
        reply::seal_reply(root(), &keys, &unseal, once).err(),
        Some(CoreError::WrongDecision)
    );
    let (_, report) = send(body("report"));
    assert_eq!(
        reply::seal_reply(root(), &keys, &report, once).err(),
        Some(CoreError::WrongDecision)
    );
    assert_eq!(
        reply::seal_rewrap_reply(&root_a(), &root_b(), &keys, &open).err(),
        Some(CoreError::WrongDecision)
    );
    assert_eq!(
        reply::seal_report_reply(&keys, &open, None, vec![]).err(),
        Some(CoreError::WrongDecision)
    );
    // Unknown kinds can be denied, and are level 3.
    let (sent, odd) = send(body("teleport"));
    assert_eq!(odd.kind(), crate::RequestKind::Unknown);
    assert_eq!(odd.level(), 3);
    let r = read_reply(
        &sent,
        &reply::seal_reply(None, &keys, &odd, Decision::Deny).unwrap(),
    );
    assert_eq!(
        (r.ok, r.err.as_deref(), r.lvl),
        (false, Some("declined"), Some(3))
    );
}

#[test]
fn keys_without_the_root_or_with_bad_labels() {
    let keys = keys_b();
    let once = Decision::Once { place: Place::Other };
    let mut b = body("open");
    b.keys = vec![item_b(Purpose::Secrets, STORE)];
    let (sent, req) = send(b);
    let r = read_reply(&sent, &reply::seal_reply(None, &keys, &req, once).unwrap());
    assert_eq!(r.err.as_deref(), Some("phone_locked"));

    for (p, i) in [
        ("ssh", STORE),
        ("secrets", "../etc"),
        ("volume", ""),
        ("backup", &"x".repeat(65)),
    ] {
        let mut b = body("keys");
        b.keys = vec![item_b(Purpose::Secrets, STORE), item(p, i)];
        let (sent, req) = send(b);
        let r = read_reply(
            &sent,
            &reply::seal_reply(Some(Arc::new(root_b())), &keys, &req, once).unwrap(),
        );
        assert_eq!(
            (r.ok, r.err.as_deref(), r.keys.len()),
            (false, Some("bad_label"), 0),
            "{p} {i}"
        );
    }
}

#[test]
fn wrong_and_retired_keys_per_item() {
    let keys = keys_b();
    let mut b = body("open");
    let mut wrong_check = item_b(Purpose::Volume, VOL);
    wrong_check.check = Some("AAAAAAAAAAA".into());
    let mut retired = item_b(Purpose::Backup, REPO);
    retired.words = Some("hYNi".into());
    let mut unknown = item_b(Purpose::Secret, FILE);
    unknown.words = Some("zzzz".into());
    b.keys = vec![
        item_b(Purpose::Secrets, STORE),
        wrong_check,
        retired,
        unknown,
        item("secrets", "new-store"),
    ];
    let (sent, req) = send(b);
    let r = read_reply(
        &sent,
        &reply::seal_reply_with_retired(
            Some(Arc::new(root_b())),
            &keys,
            &req,
            Decision::Session {
                place: Place::Trusted,
            },
            vec![RetiredWords {
                fingerprint: "hYNi".into(),
                retired: "2026-01-02".into(),
            }],
        )
        .unwrap(),
    );
    assert!(r.ok);
    let errs: Vec<Option<&str>> = r.keys.iter().map(|k| k.err.as_deref()).collect();
    assert_eq!(
        errs,
        [
            None,
            Some("wrong_key"),
            Some("retired_words"),
            Some("wrong_key"),
            None
        ]
    );
    assert_eq!(r.keys[2].retired.as_deref(), Some("2026-01-02"));
    assert!(r.keys[1].k.is_none() && r.keys[2].k.is_none() && r.keys[3].k.is_none());
    let new_key = ObjectKey::derive(&root_b(), Purpose::Secrets, "new-store").unwrap();
    assert_eq!(
        r.keys[4].k.as_deref().map(|s| s.as_str()),
        Some(new_key.b64u().as_str())
    );
}

#[test]
fn plan_rules() {
    let m = machine();
    let id = request::new_request_id().unwrap();
    let phone = phone_public(&keys_b());
    let open = |b: RequestBody| {
        let sent = request::seal_request(&m, &phone, &id, b).unwrap();
        open_request_at(&keys_b(), &m.id(), &id, &sent.sealed, T).err()
    };
    // The hash must match the items.
    let mut b = unseal_body(plan_items(), false);
    b.plan.as_mut().unwrap().items[1].name = "other".into();
    assert_eq!(open(b), Some(CoreError::BadPlan));
    // Control characters, unknown kinds, half a key, long names.
    let bad_items = [
        PlanItem {
            kind: "local".into(),
            name: "a\nb".into(),
            purpose: None,
            id: None,
        },
        PlanItem {
            kind: "rocket".into(),
            name: "x".into(),
            purpose: None,
            id: None,
        },
        PlanItem {
            kind: "volume".into(),
            name: "x".into(),
            purpose: Some("volume".into()),
            id: None,
        },
        PlanItem {
            kind: "volume".into(),
            name: "x".into(),
            purpose: Some("disk".into()),
            id: Some(VOL.into()),
        },
        PlanItem {
            kind: "local".into(),
            name: "x".repeat(201),
            purpose: None,
            id: None,
        },
    ];
    for bad in bad_items {
        let mut items = plan_items();
        items.push(bad.clone());
        assert_eq!(
            open(unseal_body(items, false)),
            Some(CoreError::BadPlan),
            "{bad:?}"
        );
    }
    // Part numbers.
    let mut b = unseal_body(plan_items(), false);
    b.plan.as_mut().unwrap().n = Some(2);
    b.plan.as_mut().unwrap().i = Some(3);
    assert_eq!(open(b), Some(CoreError::BadPlan));
}

#[test]
fn plan_keys_outside_the_plan_or_window() {
    let keys = keys_b();
    let root = root_b();
    let (_, first) = send(unseal_body(plan_items(), false));
    let approval = crate::plan_approval(&first, T).unwrap();
    let later = |keys_asked: Vec<crate::wire::RequestItem>| {
        let mut b = body("unseal");
        b.plan = Some(crate::wire::PlanBody {
            h: approval.hash.clone(),
            ..Default::default()
        });
        b.keys = keys_asked;
        send(b)
    };
    let (_, req) = later(vec![item_b(Purpose::Volume, VOL)]);
    let at = |now| reply::plan_keys_body(&root, &req, &approval, now).unwrap();
    assert_eq!(at(T - 1).err.as_deref(), Some("plan_expired"));
    assert_eq!(
        at(T + crate::plan::PLAN_WINDOW_MS + 1).err.as_deref(),
        Some("plan_expired")
    );
    let ok = at(T + 60_000);
    assert!(ok.ok && ok.keys.len() == 1 && ok.grant.as_deref() == Some("plan"));

    let (_, req) = later(vec![item_b(Purpose::Backup, REPO)]);
    let r = reply::plan_keys_body(&root, &req, &approval, T + 1).unwrap();
    assert_eq!(r.err.as_deref(), Some("outside_plan"));

    // Another plan hash or machine is a caller error.
    let mut other = approval.clone();
    other.hash = crypto::b64u(&[0u8; 32]);
    assert_eq!(
        reply::plan_keys_body(&root, &req, &other, T).err(),
        Some(CoreError::BadPlan)
    );
    let mut other = approval.clone();
    other.machine = keys.public_id();
    assert_eq!(
        reply::plan_keys_body(&root, &req, &other, T).err(),
        Some(CoreError::BadPlan)
    );

    // The first reply may only hand out keys the plan names.
    let mut b = unseal_body(plan_items(), false);
    b.keys = vec![item_b(Purpose::Backup, REPO)];
    let (sent, req) = send(b);
    let d = Decision::Plan {
        place: Place::Trusted,
        not_before: T,
    };
    let r = read_reply(
        &sent,
        &reply::seal_reply(Some(Arc::new(root_b())), &keys, &req, d).unwrap(),
    );
    assert_eq!(r.err.as_deref(), Some("outside_plan"));
}

#[test]
fn pairing_links_that_are_refused() {
    let m = machine();
    let code = [5u8; 16];
    let link = |relay: Option<&str>| {
        PairingLink {
            machine: m.public(),
            machine_box: m.box_public(),
            code: &code,
            name: "dev@box",
            os: "Ubuntu 24.04",
            model: None,
            hint: None,
            expires: 2_000,
            relay,
        }
        .link()
    };
    let good = link(None);
    assert!(PairingOffer::parse_at(&good, 2_000).is_ok());
    assert_eq!(
        PairingOffer::parse_at(&good, 2_001).err(),
        Some(CoreError::Expired)
    );
    let newer = good.replace("#v=1&", "#v=2&");
    assert_eq!(
        PairingOffer::parse_at(&newer, 0).err(),
        Some(CoreError::NewerVersion)
    );
    let cases = [
        good.replace("https://sealctl.com/p#", "https://evil.example/p#"),
        good.replace("v=1&", "v=0&"),
        good.replace(&format!("m={}", m.id()), "m=AAAA"),
        good.replace("&e=2000", ""),
        good.replace("n=dev%40box", "n="),
        format!("{good}&n=again"),
        good.replace("n=dev%40box", "n=dev%0Abox"),
        good.replace("n=dev%40box", "n=dev%4"),
        format!("{good}&h=short"),
        format!("{good}&r=http%3A%2F%2Frelay.example.com"),
        format!("{good}&r=https%3A%2F%2Frelay.example.com%2Fpath"),
        "hello".into(),
    ];
    for bad in cases {
        assert_eq!(
            PairingOffer::parse_at(&bad, 0).err(),
            Some(CoreError::BadLink),
            "{bad}"
        );
    }
    // Unknown parameters are ignored; a staging or loopback relay is accepted.
    let staging = link(Some("https://relay-staging.sealctl.com"));
    let offer = PairingOffer::parse_at(&format!("{staging}&zz=1"), 0).unwrap();
    assert_eq!(offer.relay_origin(), "https://relay-staging.sealctl.com");
    let local = PairingOffer::parse_at(&link(Some("http://127.0.0.1:8787")), 0).unwrap();
    assert_eq!(local.relay_origin(), "http://127.0.0.1:8787");
    assert_eq!(offer.os(), "Ubuntu 24.04");
    assert_eq!((offer.model(), offer.hint()), (None, None));

    // A proof made from another code, or for another phone, is refused.
    let keys = keys_b();
    let proof = crate::pairing_proof(&keys, &offer);
    assert!(pairing::verify_pairing_proof(&code, m.public(), keys.identity_public(), &proof).is_ok());
    assert_eq!(
        pairing::verify_pairing_proof(&[6u8; 16], m.public(), keys.identity_public(), &proof).err(),
        Some(CoreError::BadProof)
    );
    let keys_a = PhoneKeys::from_root(&root_a());
    assert_eq!(
        pairing::verify_pairing_proof(&code, m.public(), keys_a.identity_public(), &proof).err(),
        Some(CoreError::BadProof)
    );
    assert_eq!(
        pairing::verify_pairing_proof(&code, m.public(), keys.identity_public(), &proof[..80]).err(),
        Some(CoreError::BadProof)
    );
    // A move proof checked against the wrong old key.
    let mv = crate::key_change_proof(&keys_a, &keys, m.id()).unwrap();
    assert_eq!(
        pairing::verify_move_proof(keys.identity_public(), keys.identity_public(), m.public(), &mv).err(),
        Some(CoreError::BadProof)
    );
}

#[test]
fn words_that_are_refused() {
    let good = words_b().list();
    let mut short = good.clone();
    short.pop();
    assert_eq!(Words::parse(short).err(), Some(CoreError::Count));
    let mut unknown = good.clone();
    unknown[3] = "sealctl".into();
    assert_eq!(
        Words::parse(unknown).err(),
        Some(CoreError::UnknownWord { index: 3 })
    );
    let mut swapped = good.clone();
    swapped.swap(0, 1);
    assert_eq!(Words::parse(swapped).err(), Some(CoreError::Checksum));
    // Four letters, upper case and spaces are fine; three letters are not.
    let typed: Vec<String> = good
        .iter()
        .map(|w| format!(" {} ", w.chars().take(4).collect::<String>().to_uppercase()))
        .collect();
    assert_eq!(Words::parse(typed).unwrap().entropy(), words_b().entropy());
    let mut three = words_a().list();
    three[0] = "aba".into();
    assert_eq!(
        Words::parse(three).err(),
        Some(CoreError::UnknownWord { index: 0 })
    );
    assert_eq!(Words::from_entropy(vec![0; 16]).err(), Some(CoreError::Count));
    // Completion.
    assert_eq!(crate::complete_word("abando".into()), ["abandon"]);
    assert_eq!(crate::complete_word("ZOO".into()), ["zoo"]);
    assert!(crate::complete_word("qq".into()).is_empty());
    assert_eq!(crate::complete_word("ab".into()).len(), 10);
}

#[test]
fn relay_signatures_that_are_refused() {
    let m = machine();
    let h = relay_auth::machine_relay_headers(&m, "post", "/v1/x?y=1", 1_000, b"{}");
    assert!(relay_auth::verify_relay_headers(&h, "POST", "/v1/x?y=1", b"{}", 1_300).is_ok());
    assert_eq!(
        relay_auth::verify_relay_headers(&h, "POST", "/v1/x?y=1", b"{}", 1_301).err(),
        Some(CoreError::Expired)
    );
    assert_eq!(
        relay_auth::verify_relay_headers(&h, "POST", "/v1/x?y=1", b"{} ", 1_000).err(),
        Some(CoreError::BadSignature)
    );
    assert_eq!(
        relay_auth::verify_relay_headers(&h, "POST", "/v1/x?y=2", b"{}", 1_000).err(),
        Some(CoreError::BadSignature)
    );
    assert_eq!(
        relay_auth::verify_relay_headers(&h, "GET", "/v1/x?y=1", b"{}", 1_000).err(),
        Some(CoreError::BadSignature)
    );
}

#[test]
fn state_blobs_that_are_refused() {
    let blob = state_blob::state_seal(&root_b(), b"state".to_vec()).unwrap();
    assert_eq!(
        state_blob::state_open(&root_a(), blob.clone()).err(),
        Some(CoreError::BadSealed)
    );
    let mut raw = crypto::b64u_decode(&blob).unwrap();
    raw[0] = 2;
    assert_eq!(
        state_blob::state_open(&root_b(), crypto::b64u(&raw)).err(),
        Some(CoreError::NewerVersion)
    );
    raw[0] = 1;
    raw.truncate(20);
    assert_eq!(
        state_blob::state_open(&root_b(), crypto::b64u(&raw)).err(),
        Some(CoreError::BadSealed)
    );
    // Two seals of the same state differ (fresh nonce).
    assert_ne!(
        state_blob::state_seal(&root_b(), b"state".to_vec()).unwrap(),
        blob
    );
    assert_eq!(
        state_blob::state_seal(&root_b(), vec![0; state_blob::MAX_BLOB]).err(),
        Some(CoreError::TooLarge)
    );
}

#[test]
fn backup_items_that_are_refused() {
    let item = crate::backup_item_encode(&words_b(), "qHWf".into(), 1).unwrap();
    let mut newer = item.clone();
    newer[0] = 2;
    assert_eq!(
        crate::backup_item_decode(newer).err(),
        Some(CoreError::NewerVersion)
    );
    assert_eq!(
        crate::backup_item_decode(item[..44].to_vec()).err(),
        Some(CoreError::BadSealed)
    );
    assert_eq!(
        crate::backup_item_encode(&words_b(), "qHW".into(), 1).err(),
        Some(CoreError::BadKey)
    );
    assert_eq!(
        crate::backup_item_encode(&words_b(), "qHW0".into(), 1).err(),
        Some(CoreError::BadKey)
    );
}

#[test]
fn status_and_messages_that_are_refused() {
    let m = machine();
    let other = MachineKeys::generate().unwrap();
    let keys = keys_b();
    let status = crate::wire::MachineStatus {
        seq: 1,
        time: T,
        ..Default::default()
    };
    let sealed = crate::channel::seal_status(&other, &phone_public(&keys), &status).unwrap();
    // The relay files another machine's status under this machine.
    assert_eq!(
        crate::open_machine_status(&keys, m.id(), sealed).err(),
        Some(CoreError::BadSealed)
    );
    let msg = crate::wire::MachineMessage {
        version: 1,
        time: T,
        seq: 1,
        kind: crate::wire::MessageKind::Lock {
            reason: "phone".into(),
        },
    };
    let sealed = crate::seal_machine_message(&keys, m.id(), crypto::b64u(m.box_public()), msg).unwrap();
    assert_eq!(
        crate::channel::open_message(&other, keys.identity_public(), &sealed).err(),
        Some(CoreError::BadSealed)
    );
    let keys_a = PhoneKeys::from_root(&root_a());
    assert_eq!(
        crate::channel::open_message(&m, keys_a.identity_public(), &sealed).err(),
        Some(CoreError::BadSignature)
    );
}

#[test]
fn sealed_files_that_are_refused() {
    use crate::sealed::{self, Mode};
    let key = ObjectKey::derive(&root_b(), Purpose::Secrets, STORE).unwrap();
    let header = sealed::Label {
        mode: Mode::StoreKey,
        words: "qHWf".into(),
        file_id: FILE.into(),
    };
    let file = sealed::seal(&header, &key, STORE, "a/b", b"v").unwrap();
    assert!(sealed::open(&file, &key, STORE, "a/b").is_ok());
    assert_eq!(
        sealed::open(&file, &key, STORE, "a/c").err(),
        Some(CoreError::BadSealed)
    );
    assert_eq!(
        sealed::open(&file, &key, VOL, "a/b").err(),
        Some(CoreError::BadSealed)
    );
    let other = ObjectKey::derive(&root_a(), Purpose::Secrets, STORE).unwrap();
    assert_eq!(
        sealed::open(&file, &other, STORE, "a/b").err(),
        Some(CoreError::BadSealed)
    );
    for name in ["", ".env", "a//b", "a/.b", "a b", &"x".repeat(129)] {
        assert!(!sealed::is_valid_name(name), "{name}");
        assert_eq!(
            sealed::seal(&header, &key, STORE, name, b"v").err(),
            Some(CoreError::BadLabel)
        );
    }
    assert_eq!(
        sealed::seal(&header, &key, STORE, "a", b"").err(),
        Some(CoreError::TooLarge)
    );
}

use std::sync::Arc;
