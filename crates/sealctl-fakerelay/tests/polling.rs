//! The scripted phone never hammers a relay that refuses it (staging incident 2026-11-22:
//! a test phone that retried at once after `429` sent ~86,000 calls in 35 minutes).

use std::sync::Arc;
use std::time::{Duration, Instant};

use sealctl_fakerelay::{Answer, Background, FakeRelay, Options, Phone};

#[test]
fn a_refused_phone_backs_off() {
    let relay = FakeRelay::start(Options::default());
    relay.phone_over_daily_limit(true);
    let phone = Arc::new(Phone::new(&relay.origin));
    let started = Instant::now();
    let bg = Background::start(phone.clone(), Answer::Session);
    std::thread::sleep(Duration::from_secs(3));
    drop(bg);
    let calls = relay.phone_calls();
    let secs = started.elapsed().as_secs_f64();
    // 150 ms, then 300, 600, 1200, 2400 ms: five or six calls in three seconds. The old loop
    // made one call per round trip (thousands on loopback).
    assert!(calls >= 2, "the phone polled at all: {calls}");
    assert!(calls <= 8, "{calls} calls in {secs:.1} s while refused");
}

#[test]
fn an_idle_phone_polls_at_its_interval() {
    let relay = FakeRelay::start(Options::default());
    let phone = Arc::new(Phone::new(&relay.origin));
    let bg = Background::start(phone.clone(), Answer::Session);
    std::thread::sleep(Duration::from_secs(3));
    drop(bg);
    // one call per 150 ms at most (20 in 3 s), plus the one in flight when stopped
    let calls = relay.phone_calls();
    assert!((5..=22).contains(&calls), "{calls} calls in 3 s");
}

#[test]
fn the_pause_grows_and_is_capped() {
    let phone = Phone::new("https://relay.example");
    assert_eq!(phone.failure_pause(0), Duration::from_millis(1500));
    assert_eq!(phone.failure_pause(1), Duration::from_millis(3000));
    assert_eq!(phone.failure_pause(4), Duration::from_secs(24));
    assert_eq!(phone.failure_pause(5), Duration::from_secs(30));
    assert_eq!(phone.failure_pause(1000), Duration::from_secs(30));
}
