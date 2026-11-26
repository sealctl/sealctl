//! The fake relay answers buy intent, feedback and the feedback licence the way
//! docs/protocol.md (Licence) says the relay does.

use serde_json::{json, Value};

use sealctl_fakerelay::{FakeRelay, Options, Phone};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

fn call(phone: &Phone, method: &str, tail: &str, body: Option<Value>) -> (u16, Value) {
    rt().block_on(phone.call(method, &format!("/v1/phones/{}{tail}", phone.id()), body))
        .unwrap()
}

fn licence(phone: &Phone) -> Value {
    let (s, v) = call(phone, "GET", "/licence", None);
    assert_eq!(s, 200, "{v}");
    v
}

fn feedback() -> Value {
    json!({"v": 1, "use": ["agents", "volumes"], "price": "fair", "missing": ["windows"], "text": " more please "})
}

const YEAR_MS: u64 = 365 * 24 * 3600 * 1000;

#[test]
fn intent_is_recorded_once_and_replaced() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    assert_eq!(licence(&phone)["intent"], false);
    assert_eq!(
        call(&phone, "POST", "/intent", Some(json!({}))),
        (200, json!({"recorded": true}))
    );
    let first = relay.intent_of(&phone.id()).unwrap();
    assert!(first.get("note").is_none());
    let (s, v) = call(
        &phone,
        "POST",
        "/intent",
        Some(json!({"note": " when it is on the store "})),
    );
    assert_eq!((s, &v), (200, &json!({"recorded": true})));
    let second = relay.intent_of(&phone.id()).unwrap();
    assert_eq!(
        second["note"], "when it is on the store",
        "the latest replaces the earlier"
    );
    assert!(second["at"].as_u64() >= first["at"].as_u64());
    assert_eq!(licence(&phone)["intent"], true);
    // nothing about the person, nothing unchecked
    for bad in [
        json!({"email": "dev@mbp.example.com"}),
        json!({"note": 5}),
        json!({"note": "a\u{1b}[2Jb"}),
        json!({"note": "x".repeat(281)}),
        json!([]),
    ] {
        let (s, v) = call(&phone, "POST", "/intent", Some(bad.clone()));
        assert_eq!((s, v["error"].as_str()), (400, Some("bad_intent")), "{bad}");
    }
    // a stranger cannot record it for someone else's phone
    let stranger = Phone::new(&relay.origin);
    let (s, _) = rt()
        .block_on(stranger.call(
            "POST",
            &format!("/v1/phones/{}/intent", phone.id()),
            Some(json!({})),
        ))
        .unwrap();
    assert_eq!(s, 403);
}

#[test]
fn the_first_feedback_grants_a_year_once() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    relay.set_days_used(&phone.id(), 41);
    let before = licence(&phone);
    assert_eq!(before["ask"], true);
    assert_eq!(before["feedback"], false);
    assert!(
        before.get("kind").is_none() && before.get("until").is_none(),
        "{before}"
    );

    let t0 = now_ms();
    let (s, v) = call(&phone, "POST", "/feedback", Some(feedback()));
    assert_eq!(s, 200, "{v}");
    assert_eq!(v["granted"], true);
    assert_eq!(v["licence"], "unpaid", "a feedback licence is not a payment");
    assert_eq!(v["kind"], "feedback");
    let until = v["until"].as_u64().unwrap();
    assert!(until >= t0 + YEAR_MS && until <= now_ms() + YEAR_MS, "{until}");
    let stored = relay.feedback_of(&phone.id()).unwrap();
    assert_eq!(stored["text"], "more please");
    assert_eq!(stored["use"], json!(["agents", "volumes"]));

    let l = licence(&phone);
    assert_eq!(
        (l["licence"].as_str(), l["kind"].as_str()),
        (Some("unpaid"), Some("feedback"))
    );
    assert_eq!(l["until"].as_u64(), Some(until));
    assert_eq!(l["ask"], false, "no ask while the feedback licence is valid");
    assert_eq!(l["feedback"], true);

    // a second feedback replaces the answers and grants nothing new
    let mut again = feedback();
    again["price"] = json!("more");
    again.as_object_mut().unwrap().remove("text");
    let (s, v) = call(&phone, "POST", "/feedback", Some(again));
    assert_eq!(s, 200);
    assert_eq!(
        v,
        json!({"licence": "unpaid", "kind": "feedback", "until": until, "granted": false})
    );
    let stored = relay.feedback_of(&phone.id()).unwrap();
    assert_eq!(stored["price"], "more");
    assert!(stored.get("text").is_none());
}

#[test]
fn a_paid_phone_gets_no_feedback_licence() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    relay.pay(&phone.id(), 1);
    let (s, v) = call(&phone, "POST", "/feedback", Some(feedback()));
    assert_eq!(s, 200);
    assert_eq!(v, json!({"licence": "paid", "kind": "paid", "granted": false}));
    assert!(relay.feedback_of(&phone.id()).is_some(), "stored all the same");
    let l = licence(&phone);
    assert_eq!(l["kind"], "paid");
    assert!(l.get("until").is_none());
}

#[test]
fn bad_feedback_is_refused_and_not_stored() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    let mut cases = Vec::new();
    for (field, value) in [
        ("v", json!(2)),
        ("use", json!(["agents", "email"])),
        ("use", json!([])),
        ("price", json!("free")),
        ("missing", json!(["nothing", "teams"])),
        ("text", json!("x".repeat(281))),
        ("text", json!("bell\u{7}")),
        ("name", json!("someone")),
    ] {
        let mut b = feedback();
        b[field] = value;
        cases.push(b);
    }
    cases.push(json!({}));
    for b in cases {
        let (s, v) = call(&phone, "POST", "/feedback", Some(b.clone()));
        assert_eq!((s, v["error"].as_str()), (400, Some("bad_feedback")), "{b}");
    }
    assert!(relay.feedback_of(&phone.id()).is_none());
    assert!(licence(&phone).get("kind").is_none(), "nothing granted");
}

#[test]
fn the_feedback_licence_ends_and_is_not_given_twice() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    relay.set_days_used(&phone.id(), 41);
    assert_eq!(call(&phone, "POST", "/feedback", Some(feedback())).0, 200);
    relay.set_feedback_until(&phone.id(), now_ms() - 1);
    let l = licence(&phone);
    assert_eq!(l["licence"], "unpaid");
    assert!(l.get("kind").is_none() && l.get("until").is_none(), "{l}");
    assert_eq!(l["ask"], true, "the usual ask resumes");
    assert_eq!(l["feedback"], true);
    let (s, v) = call(&phone, "POST", "/feedback", Some(feedback()));
    assert_eq!((s, &v), (200, &json!({"licence": "unpaid", "granted": false})));
}

#[test]
fn payments_flag_follows_the_relay_settings() {
    let relay = FakeRelay::start(Options {
        payments: false,
        ..Options::default()
    });
    let phone = Phone::new(&relay.origin);
    assert_eq!(licence(&phone)["payments"], false);
    let (s, v) = call(&phone, "POST", "/checkout", Some(json!({"seats": 1})));
    assert_eq!((s, v["error"].as_str()), (503, Some("payments_not_configured")));
    relay.set(|o| o.payments = true);
    assert_eq!(licence(&phone)["payments"], true);
}

#[test]
fn deleting_the_phone_drops_feedback_intent_and_the_feedback_licence() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    assert_eq!(call(&phone, "POST", "/feedback", Some(feedback())).0, 200);
    assert_eq!(call(&phone, "POST", "/intent", None).0, 200);
    let (s, v) = call(&phone, "DELETE", "", None);
    assert_eq!((s, v["deleted"].as_bool()), (200, Some(true)));
    assert!(relay.feedback_of(&phone.id()).is_none());
    assert!(relay.intent_of(&phone.id()).is_none());
    let l = licence(&phone);
    assert!(l.get("kind").is_none(), "{l}");
    assert_eq!(
        (l["feedback"].as_bool(), l["intent"].as_bool()),
        (Some(false), Some(false))
    );

    // a paid licence record stays
    let paid = Phone::new(&relay.origin);
    relay.pay(&paid.id(), 1);
    assert_eq!(call(&paid, "POST", "/feedback", Some(feedback())).0, 200);
    assert_eq!(call(&paid, "DELETE", "", None).0, 200);
    let l = licence(&paid);
    assert_eq!(
        (l["licence"].as_str(), l["kind"].as_str()),
        (Some("paid"), Some("paid"))
    );
    assert!(relay.feedback_of(&paid.id()).is_none());
}
