//! Timing and interleaving of the session (SPEC 6.3 to 6.5): locks against opens, slow steps,
//! the hard stop, sleep and clock changes. Driven by a fake wall clock, paused tokio time and
//! gates that hold the on-lock backup and the mount until the test lets them go.

use std::sync::Arc;
use std::time::Duration;

use sealctl_core::wire::{MachineMessage, MessageKind, RequestContext, RequestItem};

use super::testing::{self, item, session_reply, t0};
use super::{approve, session, Daemon, Events};

/// Nothing listens here; no test reaches it.
const DEAD: &str = "http://127.0.0.1:9";
const STORE: &str = "0f8c6d2e-4b1a-4c3d-9e5f-7a6b8c9d0e1f";
/// The idle allowance right after an open from a trusted place: 1,800 s + 120 s for the minute
/// of the open.
const ALLOWANCE_MS: u64 = 1_920_000;

fn ev() -> Events {
    Arc::new(|_| {})
}

fn store_items() -> Vec<RequestItem> {
    vec![item("secrets", STORE)]
}

/// The phone grants a session for `items`.
async fn open(d: &Arc<Daemon>, items: &[RequestItem]) {
    d.t.answer(session_reply(items), None);
    let (session, _) = d
        .open_with(
            items.to_vec(),
            STORE,
            vec![],
            RequestContext::default(),
            &ev(),
            false,
            |_, _| Ok(()),
        )
        .await
        .unwrap();
    assert!(session);
}

/// Lets every task that can run, run.
async fn settle() {
    for _ in 0..200 {
        tokio::task::yield_now().await;
    }
}

fn at(events: &[String], e: &str) -> usize {
    events
        .iter()
        .position(|x| x == e)
        .unwrap_or_else(|| panic!("{e:?} not in {events:?}"))
}

fn lock_message(time: u64, seq: u64, reason: &str) -> MachineMessage {
    MachineMessage {
        version: 1,
        time,
        seq,
        kind: MessageKind::Lock {
            reason: reason.into(),
        },
    }
}

#[tokio::test(start_paused = true)]
async fn a_hard_stop_keeps_the_first_open_of_a_session_approved_during_its_backups() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let stop = session::hard_stop(t0());
    d.t.set_now(stop + 1_000);
    let tick = tokio::spawn({
        let d = d.clone();
        async move { d.tick().await }
    });
    settle().await;
    assert!(d.t.events().contains(&"backup start".to_string()));
    // the phone approves a new session while the on-lock backup runs
    open(&d, &store_items()).await;
    assert_eq!(d.st().saved.first_open, Some(stop + 1_000));
    d.t.backup.release();
    tick.await.unwrap();
    settle().await;
    let st = d.st();
    assert!(st.open);
    assert_eq!(st.saved.first_open, Some(stop + 1_000), "the new session has its hard stop");
}

#[tokio::test(start_paused = true)]
async fn a_second_lock_waits_for_the_first_locks_backups_before_unmounting() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let first = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    // `sealctl lock --force` while the on-lock backup runs
    let second = tokio::spawn({
        let d = d.clone();
        async move { d.lock("cli", false, true).await }
    });
    settle().await;
    let e = d.t.events();
    assert!(
        !e.iter().any(|x| x.starts_with("unmount")),
        "nothing is unmounted under the running backup: {e:?}"
    );
    d.t.backup.release();
    first.await.unwrap();
    second.await.unwrap();
    let e = d.t.events();
    assert!(at(&e, "backup end") < at(&e, "unmount"), "{e:?}");
    assert!(at(&e, "unmount") < at(&e, "unmount force"), "{e:?}");
}

#[tokio::test(start_paused = true)]
async fn the_tick_goes_on_while_on_lock_backups_run() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let t = t0() + ALLOWANCE_MS;
    d.t.set_now(t);
    // the idle lock starts its backup; the tick itself does not wait for it
    tokio::time::timeout(Duration::from_secs(5), d.tick())
        .await
        .expect("the tick returned while the backup ran");
    assert!(!d.st().open);
    // a session approved meanwhile still gets its idle lock on time (an hour is past its
    // allowance, the credit of the first session included)
    open(&d, &store_items()).await;
    d.t.set_now(t + 3_600_000);
    tokio::time::timeout(Duration::from_secs(5), d.tick())
        .await
        .expect("the tick returned");
    assert!(!d.st().open, "the new session locked for idle");
    d.t.backup.release();
    d.t.backup.release();
    settle().await;
}

#[tokio::test(start_paused = true)]
async fn a_lock_during_the_mount_unmounts_after_it_and_starts_no_channel() {
    let (d, _) = testing::daemon(DEAD);
    d.t.mount.hold();
    let opening = tokio::spawn({
        let d = d.clone();
        async move { open(&d, &store_items()).await }
    });
    settle().await;
    let locking = tokio::spawn({
        let d = d.clone();
        async move { d.lock("cli", true, false).await }
    });
    settle().await;
    let e = d.t.events();
    assert!(!e.contains(&"unmount".to_string()), "{e:?}");
    d.t.mount.release();
    opening.await.unwrap();
    locking.await.unwrap();
    settle().await;
    let e = d.t.events();
    assert!(at(&e, "mount end") < at(&e, "unmount"), "{e:?}");
    assert!(!d.st().open);
    assert!(d.st().channel.is_none(), "no machine channel for a Locked session");
}

#[tokio::test(start_paused = true)]
async fn the_old_machine_channel_stops_when_a_new_session_opens() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    settle().await;
    let locking = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    open(&d, &store_items()).await;
    settle().await;
    let e = d.t.events();
    assert_eq!(
        e.iter().filter(|x| *x == "channel stopped").count(),
        1,
        "two machine sockets would evict each other: {e:?}"
    );
    d.t.backup.release();
    locking.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn the_daemon_exits_only_after_a_running_lock_unmounted() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let locking = tokio::spawn({
        let d = d.clone();
        async move { d.lock("phone", false, false).await }
    });
    settle().await;
    let exiting = tokio::spawn({
        let d = d.clone();
        async move { d.on_exit().await }
    });
    settle().await;
    assert!(!exiting.is_finished(), "the exit waits for the lock");
    d.t.backup.release();
    exiting.await.unwrap();
    assert!(d.t.events().contains(&"unmount".to_string()));
    locking.await.unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_session_approved_during_the_backups_keeps_its_volumes() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let locking = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    // the phone approves a new session while the on-lock backup runs; it mounts at once
    tokio::time::timeout(Duration::from_secs(5), open(&d, &store_items()))
        .await
        .expect("the open does not wait for the old session's backups");
    d.t.backup.release();
    locking.await.unwrap();
    let e = d.t.events();
    assert!(!e.iter().any(|x| x.starts_with("unmount")), "{e:?}");
    assert!(d.st().open);
}

#[tokio::test(start_paused = true)]
async fn waking_with_a_key_press_still_locks_for_the_time_asleep() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    // asleep for two hours; the key press that woke the machine is input
    d.t.advance(2 * 3_600_000);
    d.t.set_idle(Some(0));
    d.tick().await;
    assert!(!d.st().open, "time asleep counts as idle");
}

#[tokio::test(start_paused = true)]
async fn an_expired_session_hands_out_no_key_before_the_tick() {
    let (d, _) = testing::daemon(DEAD);
    let vol = item("volume", "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8");
    open(&d, &[item("secrets", STORE), vol.clone()]).await;
    // just woken from a long sleep; the tick has not run yet
    d.t.advance(ALLOWANCE_MS + 60_000);
    let r = d.op_keys(vec![vol], None, &ev(), false).await;
    assert!(r.is_err(), "no key from a session past its idle allowance");
    assert!(!d.st().open);
}

#[tokio::test(start_paused = true)]
async fn past_the_hard_stop_a_session_hands_out_no_key_before_the_tick() {
    let (d, _) = testing::daemon(DEAD);
    let vol = item("volume", "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8");
    open(&d, &[item("secrets", STORE), vol.clone()]).await;
    let stop = session::hard_stop(t0());
    // worked up to the hard stop (a use every minute), then a request just after it
    let mut t = t0();
    while t + 60_000 < stop {
        t += 60_000;
        d.t.set_now(t);
        d.st().saved.work(t);
    }
    d.t.set_now(stop + 1);
    let r = d.op_keys(vec![vol], None, &ev(), false).await;
    assert!(r.is_err());
    assert!(!d.st().open);
    assert_eq!(d.st().saved.worked, 0, "the hard stop reset the credit");
}

#[tokio::test(start_paused = true)]
async fn a_clock_set_back_locks_the_session() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    d.t.set_now(t0() - 10 * 60_000);
    d.tick().await;
    assert!(!d.st().open, "idle time and the hard stop cannot be trusted any more");
}

#[tokio::test(start_paused = true)]
async fn a_first_open_in_the_future_does_not_carry_its_credit() {
    let (d, _) = testing::daemon(DEAD);
    {
        // saved while the clock was a day ahead
        let mut st = d.st();
        st.saved.first_open = Some(t0() + 86_400_000);
        st.saved.worked = 500;
        st.saved.last_minute = (t0() + 86_400_000) / 60_000;
        st.saved.last_work = t0() + 86_400_000;
    }
    open(&d, &store_items()).await;
    let st = d.st();
    assert_eq!(st.saved.first_open, Some(t0()));
    assert_eq!(st.saved.worked, 1);
}
