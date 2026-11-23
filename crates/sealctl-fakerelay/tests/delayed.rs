//! The fake relay answers delayed approvals the way the relay does (relay/src/phone.ts).

use serde_json::json;

use sealctl_fakerelay::{FakeRelay, Options, Phone};

fn rt() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// A 22-character request id.
fn rid(n: usize) -> String {
    format!("{n:0>22}")
}

#[test]
fn delayed_limits_count_live_records() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    let path = format!("/v1/phones/{}/delayed", phone.id());
    let add = |n: usize, delay: serde_json::Value| {
        rt().block_on(phone.call("POST", &path, Some(json!({"id": rid(n), "delay": delay}))))
            .unwrap()
            .0
    };
    for bad in [
        json!(0),
        json!(7201),
        json!(1.5),
        json!(-1),
        json!("60"),
        json!(null),
    ] {
        assert_eq!(add(99, bad.clone()), 400, "delay {bad}");
    }
    for n in 0..4 {
        assert_eq!(add(n, json!(60)), 201);
    }
    assert_eq!(add(0, json!(60)), 409, "duplicate_id");
    assert_eq!(add(4, json!(60)), 429, "four live ones");
    // a cancelled one no longer counts
    rt().block_on(phone.cancel(&rid(0))).unwrap();
    assert_eq!(add(4, json!(60)), 201);
    assert_eq!(add(5, json!(60)), 429);
}

#[test]
fn a_reply_with_a_bad_delay_is_refused_first() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    let path = format!("/v1/phones/{}/requests/{}/reply", phone.id(), rid(1));
    for bad in [
        json!(0),
        json!(7201),
        json!(1.5),
        json!(-1),
        json!("60"),
        json!(null),
    ] {
        let (s, v) = rt()
            .block_on(phone.call("POST", &path, Some(json!({"sealed": "AAAA", "delay": bad}))))
            .unwrap();
        assert_eq!((s, v["error"].as_str()), (400, Some("bad_delay")), "delay {bad}");
    }
}

/// protocol.md, Delayed approvals: `expires` is `releaseAt` + 900 s, and a cancel moves it to
/// `releaseAt` + 2,400 s (the 30-minute plan window plus the 300 s signature window twice).
/// Cancelled tombstones do not count toward the 4 live records, but 16 records in all is the cap.
#[test]
fn a_cancelled_record_is_kept_longer_and_counts_toward_sixteen() {
    let relay = FakeRelay::start(Options::default());
    let phone = Phone::new(&relay.origin);
    let path = format!("/v1/phones/{}/delayed", phone.id());
    let add = |n: usize| {
        rt().block_on(phone.call("POST", &path, Some(json!({"id": rid(n), "delay": 60}))))
            .unwrap()
    };
    let (s, v) = add(0);
    assert_eq!(s, 201);
    let release_at = v["releaseAt"].as_u64().unwrap();
    assert_eq!(v["expires"].as_u64(), Some(release_at + 900_000));
    rt().block_on(phone.cancel(&rid(0))).unwrap();
    let (s, v) = rt()
        .block_on(phone.call("GET", &format!("{path}/{}", rid(0)), None))
        .unwrap();
    assert_eq!(s, 200);
    assert_eq!(v["state"], "cancelled");
    assert_eq!(v["expires"].as_u64(), Some(release_at + 2_400_000), "{v}");
    let (s, v) = rt().block_on(phone.call("GET", &path, None)).unwrap();
    assert_eq!(s, 200);
    assert_eq!(
        v["delayed"][0]["expires"].as_u64(),
        Some(release_at + 2_400_000),
        "{v}"
    );

    // 15 more tombstones: 16 records, none live, and a new one is refused
    for n in 1..16 {
        assert_eq!(add(n).0, 201, "record {n}");
        rt().block_on(phone.cancel(&rid(n))).unwrap();
    }
    assert_eq!(add(16).0, 429, "16 records, tombstones included");
}
