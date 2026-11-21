//! Property tests: what is sealed opens to the same thing, on both sides.

use std::sync::Arc;

use proptest::prelude::*;

use super::*;
use crate::keys::{ObjectKey, Purpose};
use crate::pairing::{PairingLink, PairingOffer};
use crate::phone::Place;
use crate::reply::Decision;
use crate::wire::{
    AgentUse, LogEntry, MachineMessage, MachineStatus, MessageKind, RequestContext, SessionState,
};

fn text() -> impl Strategy<Value = String> {
    "\\PC{0,40}"
}

fn object_id() -> impl Strategy<Value = String> {
    "[A-Za-z0-9._-]{1,64}"
}

fn purpose() -> impl Strategy<Value = Purpose> {
    prop_oneof![
        Just(Purpose::Secrets),
        Just(Purpose::Secret),
        Just(Purpose::Volume),
        Just(Purpose::Backup)
    ]
}

fn place() -> impl Strategy<Value = Place> {
    prop_oneof![Just(Place::Trusted), Just(Place::Other), Just(Place::NoLocation)]
}

proptest! {
    #![proptest_config(ProptestConfig { cases: 48, ..ProptestConfig::default() })]

    #[test]
    fn request_and_reply_round_trip(
        agent in proptest::option::of(text()),
        cmd in text(),
        names in proptest::collection::vec(text(), 0..5),
        objects in proptest::collection::vec((purpose(), object_id()), 0..6),
        skew in -600_000i64..=600_000,
        has_match in any::<bool>(),
        place in place(),
        remember in any::<bool>(),
    ) {
        let mut b = body("open");
        b.has_match = has_match;
        b.t = (T as i64 + skew) as u64;
        b.ctx = Some(RequestContext { agent: agent.clone(), command: cmd, names: names.clone(), ..Default::default() });
        b.keys = objects.iter().map(|(p, i)| item_b(*p, i)).collect();
        b.uses = vec![AgentUse { agent: "a".into(), repository: "r".into(), names }];
        let expected = b.clone();
        let (sent, req) = send(b);
        let mut opened = req.body().clone();
        opened.ot = None;
        prop_assert_eq!(&opened, &expected);
        prop_assert_eq!(req.rq(), crypto::b64u(&crypto::sha256(&sent.body)));
        prop_assert_eq!(req.has_match(), has_match);
        if let Some(n) = sent.number {
            // Both ends derive the same number from the HPKE context.
            prop_assert!((10..=99).contains(&n));
            let choices = req.match_choices();
            prop_assert_eq!(choices.len(), 3);
            prop_assert!(choices.contains(&u32::from(n)));
            let distinct: std::collections::BTreeSet<_> = choices.iter().collect();
            prop_assert_eq!(distinct.len(), 3);
            prop_assert!(req.check_match(u32::from(n)));
        }

        let decision = if remember { Decision::Remember { place } } else { Decision::Once { place } };
        let sealed = crate::seal_reply(Some(Arc::new(root_b())), &keys_b(), &req, decision).unwrap();
        prop_assert!(sealed.len() <= crate::request::MAX_SEALED);
        let r = read_reply(&sent, &sealed);
        prop_assert!(r.ok);
        prop_assert_eq!(r.place.as_deref(), Some(place.as_str()));
        prop_assert_eq!(r.keys.len(), objects.len());
        for ((p, i), k) in objects.iter().zip(&r.keys) {
            let want = ObjectKey::derive(&root_b(), *p, i).unwrap().b64u();
            prop_assert_eq!(k.k.as_deref().map(|s| s.as_str()), Some(want.as_str()));
        }
    }

    #[test]
    fn status_and_message_round_trip(
        seq in any::<u64>(),
        left in proptest::option::of(any::<u64>()),
        command in text(),
        names in proptest::collection::vec(text(), 0..4),
        reason in text(),
    ) {
        let m = machine();
        let keys = keys_b();
        let status = MachineStatus {
            version: 1,
            time: T,
            seq,
            state: Some(SessionState { session: "open".into(), left, ..Default::default() }),
            log: vec![LogEntry { time: T, agent: None, repository: None, command, names, own: true }],
            ..Default::default()
        };
        let sealed = crate::channel::seal_status(&m, &phone_public(&keys), &status).unwrap();
        prop_assert_eq!(crate::open_machine_status(&keys, m.id(), sealed).unwrap(), status);

        let msg = MachineMessage { version: 1, time: T, seq, kind: MessageKind::Lock { reason } };
        let sealed = crate::seal_machine_message(&keys, m.id(), crypto::b64u(m.box_public()), msg.clone()).unwrap();
        prop_assert_eq!(crate::channel::open_message(&m, keys.identity_public(), &sealed).unwrap(), msg);
    }

    #[test]
    fn state_blob_round_trip(plaintext in proptest::collection::vec(any::<u8>(), 0..4096)) {
        let blob = crate::state_seal(&root_b(), plaintext.clone()).unwrap();
        prop_assert_eq!(crate::state_open(&root_b(), blob).unwrap(), plaintext);
    }

    #[test]
    fn sealed_file_round_trip(
        value in proptest::collection::vec(any::<u8>(), 1..2048),
        name in "[a-z0-9@+_-][a-z0-9.@+_-]{0,20}(/[a-z0-9@+_-][a-z0-9.@+_-]{0,20}){0,3}",
        own in any::<bool>(),
    ) {
        use crate::sealed::{self, Mode};
        let (mode, key) = if own {
            (Mode::OwnApproval, ObjectKey::derive(&root_b(), Purpose::Secret, FILE).unwrap())
        } else {
            (Mode::StoreKey, ObjectKey::derive(&root_b(), Purpose::Secrets, STORE).unwrap())
        };
        let header = sealed::new_header(mode, &root_b().fingerprint(), FILE).unwrap();
        let file = sealed::seal(&header, &key, STORE, &name, &value).unwrap();
        prop_assert_eq!(sealed::Header::parse(&file).unwrap(), header);
        prop_assert_eq!(sealed::open(&file, &key, STORE, &name).unwrap().to_vec(), value);
    }

    #[test]
    fn words_round_trip(entropy in proptest::array::uniform32(any::<u8>())) {
        let words = Words::from_entropy(entropy.to_vec()).unwrap();
        let list = words.list();
        prop_assert_eq!(list.len(), 24);
        prop_assert_eq!(Words::parse(list).unwrap().entropy(), entropy.to_vec());
    }

    #[test]
    fn pairing_link_round_trip(
        name in "\\PC{1,60}",
        os in "\\PC{0,60}",
        model in proptest::option::of("\\PC{1,30}"),
        code in proptest::array::uniform16(any::<u8>()),
        expires in 1u64..u64::MAX,
    ) {
        let m = machine();
        let link = PairingLink {
            machine: m.public(), machine_box: m.box_public(), code: &code,
            name: &name, os: &os, model: model.as_deref(), hint: None, expires, relay: None,
        }.link();
        let offer = PairingOffer::parse_at(&link, expires).unwrap();
        prop_assert_eq!(offer.name(), name);
        prop_assert_eq!(offer.os(), os);
        prop_assert_eq!(offer.model(), model);
        let keys = keys_b();
        let proof = crate::pairing_proof(&keys, &offer);
        prop_assert!(crate::pairing::verify_pairing_proof(&code, m.public(), keys.identity_public(), &proof).is_ok());
    }

    #[test]
    fn relay_headers_round_trip(
        method in "(GET|POST|PUT|DELETE)",
        path in "/v1/[a-z0-9/_?=&-]{0,60}",
        body in proptest::collection::vec(any::<u8>(), 0..512),
        time in 0u64..4_000_000_000,
    ) {
        let keys = keys_b();
        let h = crate::relay_headers(&keys, method.clone(), path.clone(), time, body.clone());
        prop_assert_eq!(&h.key, &keys.public_id());
        prop_assert!(crate::relay_auth::verify_relay_headers(&h, &method, &path, &body, time).is_ok());
    }
}
