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

#[tokio::test(start_paused = true)]
async fn the_phone_hears_the_session_is_open_before_the_next_request() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    // an agent asks right after the open
    d.t.answer(testing::grant("once", &[]), None);
    d.ask(approve::body("agent"), &ev(), false).await.unwrap();
    settle().await;
    let e = d.t.events();
    assert!(at(&e, "status open") < at(&e, "ask agent"), "{e:?}");
}

#[tokio::test(start_paused = true)]
async fn the_end_of_a_wait_is_told_to_the_phone() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    settle().await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    d.t.answer(testing::grant("once", &[]), Some(gate.clone()));
    let asking = tokio::spawn({
        let d = d.clone();
        async move { d.ask(approve::body("agent"), &ev(), false).await.is_ok() }
    });
    settle().await;
    // a status goes out while the phone is asked
    d.send_status(&[]).await.unwrap();
    gate.add_permits(1);
    assert!(asking.await.unwrap());
    let before = d.t.events().len();
    d.t.advance(15_000);
    d.tick().await;
    let e = d.t.events();
    assert!(
        e[before..].contains(&"status open".to_string()),
        "the phone learns the wait ended: {e:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_lock_message_is_applied_while_the_phone_is_asked() {
    use base64::Engine;
    // a relay that takes the connection and never answers
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        let _ = tx.send(());
        std::thread::sleep(Duration::from_secs(30));
        drop(conn);
    });
    let (d, phone) = testing::daemon(&origin);
    open(&d, &store_items()).await;
    let sealed = {
        let p = d.paired.lock().await;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        sealctl_core::seal_machine_message(
            &phone,
            p.file.machine.clone(),
            b64.encode(p.keys.box_public()),
            lock_message(t0() + 1_000, 1, "phone"),
        )
        .unwrap()
    };
    let asking = tokio::spawn({
        let d = d.clone();
        async move { d.ask(approve::body("agent"), &ev(), false).await.is_ok() }
    });
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), d.on_message(&sealed))
        .await
        .expect("the lock message did not wait for the request on the phone");
    assert!(!d.st().open);
    asking.abort();
}

#[tokio::test(start_paused = true)]
async fn a_lock_made_just_after_the_approval_locks_despite_clock_skew() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    // the phone's clock is half a second behind the machine's
    d.apply_message(lock_message(t0() - 500, 1, "place")).await;
    settle().await;
    assert!(!d.st().open);
    // a lock held for an offline machine since yesterday is still ignored
    open(&d, &store_items()).await;
    d.apply_message(lock_message(t0() - 86_400_000, 2, "phone")).await;
    settle().await;
    assert!(d.st().open);
}

#[tokio::test(start_paused = true)]
async fn a_session_grant_answered_after_a_lock_is_not_kept_for_the_next_session() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    let vol = item("volume", "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8");
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    d.t.answer(testing::session_reply(std::slice::from_ref(&vol)), Some(gate.clone()));
    let asking = tokio::spawn({
        let d = d.clone();
        let vol = vol.clone();
        async move { d.op_keys(vec![vol], None, &ev(), false).await.is_ok() }
    });
    settle().await;
    d.lock("phone", true, false).await;
    gate.add_permits(1);
    assert!(asking.await.unwrap(), "the waiting command gets the key it asked for");
    open(&d, &store_items()).await;
    let held = d.st().keys.contains_key(&super::key_name(&vol.purpose, &vol.id));
    assert!(!held, "the new session does not hold the old session's grant");
}

#[tokio::test(start_paused = true)]
async fn a_spawned_daemon_does_not_exit_while_the_phone_is_asked() {
    let (d, _) = testing::daemon(DEAD);
    d.st().last_client = t0() - 11 * 60_000;
    assert!(d.idle_exit_due());
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    d.t.answer(testing::grant("once", &[]), Some(gate.clone()));
    let asking = tokio::spawn({
        let d = d.clone();
        async move { d.ask(approve::body("open"), &ev(), false).await.is_ok() }
    });
    settle().await;
    assert!(!d.idle_exit_due(), "an SSH signature is waiting for the phone");
    gate.add_permits(1);
    assert!(asking.await.unwrap());
}

#[tokio::test(start_paused = true)]
async fn a_busy_volume_is_tried_again_every_minute() {
    let (d, _) = testing::daemon(DEAD);
    d.t.vol_busy
        .lock()
        .unwrap()
        .extend([true, true, false]);
    open(&d, &store_items()).await;
    d.lock("cli", true, false).await;
    let e = d.t.events();
    assert!(e.contains(&"status locked busy 1".to_string()), "{e:?}");
    let tries = |d: &Daemon| d.t.events().iter().filter(|x| x.starts_with("close safe")).count();
    assert_eq!(tries(&d), 1);
    tokio::time::sleep(Duration::from_secs(59)).await;
    assert_eq!(tries(&d), 1);
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(tries(&d), 2, "tried again after a minute");
    tokio::time::sleep(Duration::from_secs(60)).await;
    let e = d.t.events();
    assert_eq!(e.last().map(String::as_str), Some("status locked"), "{e:?}");
    assert!(e.contains(&"close safe".to_string()));
    tokio::time::sleep(Duration::from_secs(600)).await;
    assert_eq!(tries(&d), 3, "no tries once closed");
}

#[tokio::test(start_paused = true)]
async fn a_lock_whose_status_failed_tells_the_phone_later() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    settle().await;
    *d.t.status_failures.lock().unwrap() = 1;
    d.lock("cli", true, false).await;
    settle().await;
    let sent = |d: &Daemon| {
        d.t.events()
            .iter()
            .filter(|x| *x == "status locked")
            .count()
    };
    assert!(d.t.events().contains(&"status locked failed".to_string()));
    assert_eq!(sent(&d), 0);
    d.t.advance(61_000);
    d.tick().await;
    assert_eq!(sent(&d), 1, "the phone took the session as Open: {:?}", d.t.events());
    // once heard, no more
    d.t.advance(3_600_000);
    d.tick().await;
    assert_eq!(sent(&d), 1);
}
