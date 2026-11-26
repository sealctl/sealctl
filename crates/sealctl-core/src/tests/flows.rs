//! Whole exchanges: each request kind answered by the phone and read by the machine.

use std::sync::Arc;

use super::*;
use crate::keys::{ObjectKey, Purpose};
use crate::phone::Place;
use crate::plan::PlanAssembler;
use crate::reply::{self, Decision};
use crate::wire::{
    AgentUse, Answer, Handback, HandbackItem, MachineMessage, MachineStatus, MessageKind, Notice, PlanBody,
    PlanItem, SessionState, Subject,
};
use crate::{plan, RequestKind};

fn key_b64u(root: &Root, p: Purpose, id: &str) -> String {
    ObjectKey::derive(root, p, id).unwrap().b64u().to_string()
}

#[test]
fn open_once_and_session_with_allowance() {
    let keys = keys_b();
    for (decision, grant, cap) in [
        (
            Decision::Once {
                place: Place::NoLocation,
            },
            "once",
            3_600,
        ),
        (Decision::Session { place: Place::Other }, "session", 600),
    ] {
        let mut b = body("open");
        b.keys = vec![item_b(Purpose::Volume, VOL)];
        let (sent, req) = send(b);
        let r = read_reply(
            &sent,
            &crate::seal_reply(Some(Arc::new(root_b())), &keys, &req, decision).unwrap(),
        );
        assert!(r.ok);
        assert_eq!(
            (r.grant.as_deref(), r.cap, r.remember, r.lvl),
            (Some(grant), Some(cap), None, None)
        );
        assert_eq!(r.w.as_deref(), Some("qHWf"));
        assert_eq!(
            r.keys[0].k.as_deref().map(|s| s.to_string()),
            Some(key_b64u(&root_b(), Purpose::Volume, VOL))
        );
    }
}

#[test]
fn agent_answer_without_keys_needs_no_root() {
    let keys = keys_b();
    let mut b = body("agent");
    b.uses = vec![AgentUse {
        agent: "Claude Code".into(),
        repository: "github.com/acme/shop".into(),
        names: vec!["a".into()],
    }];
    let (sent, req) = send(b);
    assert_eq!(req.uses().len(), 1);
    let r = read_reply(
        &sent,
        &crate::seal_reply(
            None,
            &keys,
            &req,
            Decision::Remember {
                place: Place::Trusted,
            },
        )
        .unwrap(),
    );
    assert!(r.ok);
    assert_eq!((r.remember, r.w), (Some(true), None));
}

#[test]
fn keys_for_seal_is_level_2() {
    let mut b = body("keys");
    b.ctx.as_mut().unwrap().subject = Some(Subject {
        kind: "machine".into(),
        name: "seal".into(),
    });
    let (sent, req) = send(b);
    assert_eq!(req.level(), 2);
    let r = read_reply(
        &sent,
        &crate::seal_reply(
            None,
            &keys_b(),
            &req,
            Decision::Once {
                place: Place::Trusted,
            },
        )
        .unwrap(),
    );
    assert_eq!(r.lvl, Some(2));
    // A machine may raise the level of its own request.
    let mut b = body("open");
    b.lvl = Some(2);
    assert_eq!(send(b).1.level(), 2);
}

#[test]
fn unseal_in_parts_then_later_keys() {
    let keys = keys_b();
    let m = machine();
    let mut items = plan_items();
    items.extend((0..6).map(|i| PlanItem {
        kind: "local".into(),
        name: format!("file {i}"),
        purpose: None,
        id: None,
    }));
    let h = crypto::b64u(&plan::plan_hash(&m.id(), &items));
    let parts: Vec<Vec<PlanItem>> = items.chunks(4).map(<[PlanItem]>::to_vec).collect();
    assert_eq!(parts.len(), 3);

    let assembler = PlanAssembler::new();
    let mut last = None;
    for (n, part) in parts.iter().enumerate() {
        let i = n as u32 + 1;
        let mut b = body("unseal");
        b.plan = Some(PlanBody {
            all: false,
            h: h.clone(),
            items: part.clone(),
            n: Some(3),
            i: Some(i),
        });
        b.has_match = i == 3;
        if i == 3 {
            b.keys = vec![item_b(Purpose::Secrets, STORE)];
        }
        let (sent, req) = send(b);
        let req = Arc::new(req);
        let got = assembler.add(req.clone()).unwrap();
        if i < 3 {
            assert!(got.is_none());
            let plan = req.plan().unwrap();
            assert_eq!((plan.part, plan.parts, plan.complete), (Some(i), Some(3), false));
            let r = read_reply(&sent, &crate::seal_plan_part_reply(&keys, &req).unwrap());
            assert_eq!((r.ok, r.part), (true, Some(i)));
        } else {
            let whole = got.unwrap();
            assert!(whole.complete);
            assert_eq!(whole.items, items);
            assert_eq!(req.plan().unwrap(), whole, "attached to the last part");
            assert_eq!(
                crate::seal_plan_part_reply(&keys, &req).err(),
                Some(crate::CoreError::BadPlan)
            );
            last = Some((sent, req));
        }
    }
    let (sent, req) = last.unwrap();
    let n = sent.number.unwrap() as u32;
    assert!(req.match_choices().contains(&n));
    assert!(req.check_match(n));
    let d = Decision::Plan {
        place: Place::Trusted,
        not_before: T,
    };
    let r = read_reply(
        &sent,
        &crate::seal_reply(Some(Arc::new(root_b())), &keys, &req, d).unwrap(),
    );
    assert_eq!(
        (r.ok, r.grant.as_deref(), r.lvl, r.more),
        (true, Some("plan"), Some(2), None)
    );
    let ps = r.plan.unwrap();
    let ph: [u8; 32] = crypto::b64u_decode(&h).unwrap().try_into().unwrap();
    plan::verify_plan_signature(keys.identity_public(), &req.id(), m.public(), &ph, ps.nb, &ps.sig).unwrap();

    // A later request of the same plan, inside the 30 minutes.
    let approval = crate::plan_approval(&req, T).unwrap();
    assert_eq!(approval.keys.len(), 2);
    let mut b = body("unseal");
    b.plan = Some(PlanBody {
        h: h.clone(),
        ..Default::default()
    });
    b.keys = vec![item_b(Purpose::Volume, VOL)];
    let (sent, req) = send(b);
    // The apps pass every `unseal` through the assembler: a later request is not a part.
    let req = Arc::new(req);
    assert_eq!(assembler.add(req.clone()).unwrap(), None);
    let r = read_reply(
        &sent,
        &reply::plan_keys_body(&root_b(), &req, &approval, T + 1)
            .unwrap()
            .into_sealed(&req),
    );
    assert!(r.ok);
    assert_eq!(
        r.keys[0].k.as_deref().map(|s| s.to_string()),
        Some(key_b64u(&root_b(), Purpose::Volume, VOL))
    );
}

#[test]
fn a_later_plan_request_between_parts_keeps_the_parts() {
    let items = plan_items();
    let h = crypto::b64u(&plan::plan_hash(&machine().id(), &items));
    let part = |i: u32| {
        let mut b = body("unseal");
        b.plan = Some(PlanBody {
            all: false,
            h: h.clone(),
            items: items.chunks(2).nth(i as usize - 1).unwrap().to_vec(),
            n: Some(2),
            i: Some(i),
        });
        Arc::new(send(b).1)
    };
    let assembler = PlanAssembler::new();
    assert_eq!(assembler.add(part(1)).unwrap(), None);
    let mut b = body("unseal");
    b.plan = Some(PlanBody {
        h: h.clone(),
        ..Default::default()
    });
    b.keys = vec![item_b(Purpose::Volume, VOL)];
    assert_eq!(assembler.add(Arc::new(send(b).1)).unwrap(), None);
    let whole = assembler.add(part(2)).unwrap().unwrap();
    assert_eq!((whole.complete, whole.items), (true, items));
}

/// Seals a body built by a `pub(crate)` builder, for the tests above.
trait IntoSealed {
    fn into_sealed(self, req: &crate::Request) -> String;
}

impl IntoSealed for crate::wire::ReplyBody {
    fn into_sealed(self, req: &crate::Request) -> String {
        reply::seal_body_with_rng(&keys_b(), req, &self, &mut crypto::os_rng()).unwrap()
    }
}

#[test]
fn a_plan_too_big_for_one_reply_says_more() {
    // 28 keys with 64-character ids fit in the last request but not, with their keys, in
    // one reply. The items go in the first two parts, the keys in the third.
    let keys = keys_b();
    let ids: Vec<String> = (0..28).map(|i| format!("{i:02}{}", "x".repeat(62))).collect();
    let items: Vec<PlanItem> = ids
        .iter()
        .map(|i| PlanItem {
            kind: "volume".into(),
            name: "v".into(),
            purpose: Some("volume".into()),
            id: Some(i.clone()),
        })
        .collect();
    let h = crypto::b64u(&plan::plan_hash(&machine().id(), &items));
    let assembler = PlanAssembler::new();
    let parts = [items[..14].to_vec(), items[14..].to_vec(), Vec::new()];
    let mut last = None;
    for (n, part) in parts.into_iter().enumerate() {
        let mut b = body("unseal");
        b.plan = Some(PlanBody {
            all: false,
            h: h.clone(),
            items: part,
            n: Some(3),
            i: Some(n as u32 + 1),
        });
        if n == 2 {
            b.keys = ids.iter().map(|i| item("volume", i)).collect();
        }
        let (sent, req) = send(b);
        let req = Arc::new(req);
        if assembler.add(req.clone()).unwrap().is_some() {
            last = Some((sent, req));
        }
    }
    let (sent, req) = last.unwrap();
    assert_eq!(req.level(), 2);
    let d = Decision::Plan {
        place: Place::Trusted,
        not_before: T,
    };
    let sealed = crate::seal_reply(Some(Arc::new(root_b())), &keys, &req, d).unwrap();
    assert!(sealed.len() <= crate::request::MAX_SEALED);
    let r = read_reply(&sent, &sealed);
    assert!(r.ok && r.more == Some(true));
    assert!(
        !r.keys.is_empty() && r.keys.len() < ids.len(),
        "{} keys",
        r.keys.len()
    );
}

#[test]
fn rewrap_and_old_words() {
    let keys = keys_b();
    let (a, b_root) = (root_a(), root_b());
    let mut b = body("rewrap");
    let mut old_item = item("volume", VOL);
    old_item.words = Some(a.fingerprint());
    old_item.check = Some(ObjectKey::derive(&a, Purpose::Volume, VOL).unwrap().check());
    let mut bad = old_item.clone();
    bad.id = STORE.into();
    bad.purpose = "secrets".into();
    b.keys = vec![old_item.clone(), item_b(Purpose::Backup, REPO), bad];
    let (sent, req) = send(b);
    assert_eq!((req.kind(), req.level()), (RequestKind::Rewrap, 2));
    let r = read_reply(
        &sent,
        &crate::seal_rewrap_reply(&a, &b_root, &keys, &req).unwrap(),
    );
    assert_eq!(
        (r.ok, r.w.as_deref(), r.grant.as_deref(), r.lvl),
        (true, Some("qHWf"), Some("once"), Some(2))
    );
    assert_eq!(
        r.keys[0].k.as_deref().map(|s| s.to_string()),
        Some(key_b64u(&b_root, Purpose::Volume, VOL))
    );
    assert_eq!(
        r.keys[0].old.as_deref().map(|s| s.to_string()),
        Some(key_b64u(&a, Purpose::Volume, VOL))
    );
    assert!(r.keys[1].k.is_some() && r.keys[1].err.is_none());
    assert_eq!(r.keys[2].err.as_deref(), Some("wrong_key"));

    let mut b = body("old_words");
    b.old = Some(a.fingerprint());
    b.keys = vec![old_item, item_b(Purpose::Backup, REPO)];
    let (sent, req) = send(b);
    assert_eq!(req.old().as_deref(), Some("hYNi"));
    let r = read_reply(
        &sent,
        &crate::seal_old_words_reply(&a, &b_root, &keys, &req).unwrap(),
    );
    assert!(r.ok);
    assert_eq!(
        r.keys[0].old.as_deref().map(|s| s.to_string()),
        Some(key_b64u(&a, Purpose::Volume, VOL))
    );
    assert_eq!(
        r.keys[1].err.as_deref(),
        Some("wrong_key"),
        "not sealed with the old words"
    );

    let mut b = body("old_words");
    b.old = Some("zzzz".into());
    let (sent, req) = send(b);
    let r = read_reply(
        &sent,
        &crate::seal_old_words_reply(&a, &b_root, &keys, &req).unwrap(),
    );
    assert_eq!(r.err.as_deref(), Some("wrong_key"));
}

#[test]
fn report_with_status_and_handback() {
    let keys = keys_b();
    let mut b = body("report");
    b.seq = Some(7);
    b.state = Some(SessionState {
        session: "open".into(),
        left: Some(60),
        ..Default::default()
    });
    b.handback = Some(Handback {
        hash: "h".into(),
        items: vec![HandbackItem {
            kind: "volume".into(),
            name: "safe".into(),
            to: "shown once".into(),
            state: "done".into(),
        }],
        run: "~/.sealctl-unseal/x".into(),
    });
    let (sent, req) = send(b);
    assert_eq!(req.level(), 1);
    let status = req.status().unwrap();
    assert_eq!((status.seq, status.state.unwrap().left), (7, Some(60)));
    assert_eq!(req.handback().unwrap().items[0].to, "shown once");
    let msgs = vec![
        MachineMessage {
            version: 1,
            time: T,
            seq: 3,
            kind: MessageKind::Ack { ack: 7 },
        },
        MachineMessage {
            version: 1,
            time: T,
            seq: 4,
            kind: MessageKind::Answers {
                answers: vec![Answer {
                    agent: "a".into(),
                    repository: "r".into(),
                    names: vec!["n".into()],
                    last: T,
                }],
                more: false,
            },
        },
    ];
    let r = read_reply(
        &sent,
        &crate::seal_report_reply(&keys, &req, Some(7), msgs.clone()).unwrap(),
    );
    assert_eq!((r.ok, r.ack), (true, Some(7)));
    assert_eq!(r.msgs, msgs);
}

#[test]
fn every_message_kind_round_trips() {
    let m = machine();
    let keys = keys_b();
    let kinds = [
        MessageKind::Lock {
            reason: "words".into(),
        },
        MessageKind::Answers {
            answers: vec![],
            more: true,
        },
        MessageKind::Ack { ack: 9 },
        MessageKind::Notice {
            notice: Notice {
                what: "unseal_all".into(),
                state: "pending".into(),
                machine: Some("dev@box".into()),
                delay: None,
                at: Some(T),
                report: None,
                place: None,
            },
        },
        MessageKind::Notice {
            notice: Notice {
                what: "place".into(),
                state: "pending".into(),
                machine: None,
                delay: Some("-dLy1d".into()),
                at: Some(T),
                report: None,
                place: Some("Home".into()),
            },
        },
    ];
    for (seq, kind) in kinds.into_iter().enumerate() {
        let msg = MachineMessage {
            version: 1,
            time: T,
            seq: seq as u64,
            kind,
        };
        let sealed =
            crate::seal_machine_message(&keys, m.id(), crypto::b64u(m.box_public()), msg.clone()).unwrap();
        assert_eq!(
            crate::channel::open_message(&m, keys.identity_public(), &sealed).unwrap(),
            msg
        );
    }
    let status = MachineStatus {
        time: T,
        seq: 2,
        ..Default::default()
    };
    let sealed = crate::channel::seal_status(&m, &phone_public(&keys), &status).unwrap();
    assert_eq!(
        crate::open_machine_status(&keys, m.id(), sealed).unwrap(),
        MachineStatus { version: 1, ..status }
    );
}

/// `notice.place` (a place the phone trusted) is left out of the other kinds, so their bytes
/// are as before, and a notice from an app that does not send it reads without it.
#[test]
fn a_notice_carries_the_place_only_when_it_has_one() {
    let unseal = Notice {
        what: "unseal_all".into(),
        state: "pending".into(),
        ..Notice::default()
    };
    let v = serde_json::to_value(&unseal).unwrap();
    assert!(v.get("place").is_none(), "{v}");
    let place = Notice {
        what: "place".into(),
        state: "pending".into(),
        place: Some("Home".into()),
        ..Notice::default()
    };
    assert_eq!(serde_json::to_value(&place).unwrap()["place"], "Home");
    let old: Notice = serde_json::from_str(
        r#"{"what":"words","state":"pending","machine":null,"delay":"d","at":1,"report":null}"#,
    )
    .unwrap();
    assert_eq!(old.place, None);
    assert_eq!(old.what, "words");
}

/// `idle` and `allow` are optional: a status from an older machine reads without them, and a
/// newer one names them in `state` next to `left`.
#[test]
fn a_status_carries_idle_and_allowance_when_the_machine_sends_them() {
    let old: MachineStatus =
        serde_json::from_str(r#"{"v":1,"t":1,"seq":1,"state":{"s":"open","left":600}}"#).unwrap();
    let st = old.state.unwrap();
    assert_eq!((st.left, st.idle, st.allow), (Some(600), None, None));
    let new = MachineStatus {
        version: 1,
        time: T,
        seq: 3,
        state: Some(SessionState {
            session: "open".into(),
            left: Some(13_080),
            idle: Some(720),
            allow: Some(13_800),
            ..Default::default()
        }),
        ..Default::default()
    };
    let json = serde_json::to_string(&new).unwrap();
    assert!(
        json.contains(r#""state":{"s":"open","left":13080,"idle":720,"allow":13800}"#),
        "{json}"
    );
    let keys = keys_b();
    let m = machine();
    let sealed = crate::channel::seal_status(&m, &phone_public(&keys), &new).unwrap();
    assert_eq!(crate::open_machine_status(&keys, m.id(), sealed).unwrap(), new);
}

#[test]
fn versions() {
    assert_eq!(crate::core_version(), "0.7.1");
    assert_eq!(crate::protocol_version(), "1");
}
