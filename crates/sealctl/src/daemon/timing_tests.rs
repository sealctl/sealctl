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
    assert_eq!(
        st.saved.first_open,
        Some(stop + 1_000),
        "the new session has its hard stop"
    );
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
    assert!(
        d.st().channel.is_none(),
        "no machine channel for a Locked session"
    );
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
    // the backup stops at the exit; the exit waits for the lock's unmount
    let exiting = tokio::spawn({
        let d = d.clone();
        async move { d.on_exit().await }
    });
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
    assert!(
        !d.st().open,
        "idle time and the hard stop cannot be trusted any more"
    );
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
    // a status goes out while the phone is asked; the one at the end of the wait fails
    d.send_status().await.unwrap();
    *d.t.status_failures.lock().unwrap() = 1;
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

/// `msg` sealed by the phone for `d`, as the relay hands it over.
async fn sealed(d: &Daemon, phone: &sealctl_core::PhoneKeys, msg: MachineMessage) -> String {
    use base64::Engine;
    let p = d.paired.lock().await;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    sealctl_core::seal_machine_message(
        phone,
        p.file.machine.clone(),
        b64.encode(p.keys.box_public()),
        msg,
    )
    .unwrap()
}

#[tokio::test(start_paused = true)]
async fn a_lock_from_an_install_whose_seq_is_behind_still_locks() {
    let (d, phone) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    // Each install of the app numbers its messages by its own clock. Install A's clock is
    // ahead of install B's: A's message sets the high-water mark above B's next seq.
    let ahead = t0() + 120_000;
    let a = MachineMessage {
        version: 1,
        time: ahead,
        seq: ahead,
        kind: MessageKind::Ack { ack: 0 },
    };
    d.on_message(&sealed(&d, &phone, a).await).await;
    assert_eq!(d.paired.lock().await.file.msg_seq, ahead);
    // a message other than `lock` with a seq at or below the mark is still ignored
    let old = MachineMessage {
        version: 1,
        time: t0() + 1_000,
        seq: t0() + 1_000,
        kind: MessageKind::Answers {
            answers: vec![sealctl_core::wire::Answer {
                agent: "Claude Code".into(),
                repository: "r".into(),
                names: vec!["k".into()],
                last: t0(),
            }],
            more: true,
        },
    };
    d.on_message(&sealed(&d, &phone, old).await).await;
    assert!(
        d.st().answers_parts.is_empty(),
        "an old answers message is ignored"
    );
    // install B's Lock, made during this session, has a seq below the mark
    let lock = lock_message(t0() + 2_000, t0() + 2_000, "phone");
    d.on_message(&sealed(&d, &phone, lock).await).await;
    settle().await;
    assert!(!d.st().open, "the lock applies whatever its seq");
    assert_eq!(
        d.paired.lock().await.file.msg_seq,
        ahead,
        "an older seq does not lower the mark"
    );
    // a lock held from before this session stays ignored, old seq or not
    open(&d, &store_items()).await;
    let held = lock_message(t0() - 86_400_000, t0() - 86_400_000, "phone");
    d.on_message(&sealed(&d, &phone, held).await).await;
    settle().await;
    assert!(d.st().open);
}

#[tokio::test(start_paused = true)]
async fn a_session_grant_answered_after_a_lock_is_not_kept_for_the_next_session() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    let vol = item("volume", "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8");
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    d.t.answer(
        testing::session_reply(std::slice::from_ref(&vol)),
        Some(gate.clone()),
    );
    let asking = tokio::spawn({
        let d = d.clone();
        let vol = vol.clone();
        async move { d.op_keys(vec![vol], None, &ev(), false).await.is_ok() }
    });
    settle().await;
    d.lock("phone", true, false).await;
    gate.add_permits(1);
    assert!(
        asking.await.unwrap(),
        "the waiting command gets the key it asked for"
    );
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
    d.t.vol_busy.lock().unwrap().extend([true, true, false]);
    open(&d, &store_items()).await;
    d.lock("cli", true, false).await;
    let e = d.t.events();
    assert!(e.contains(&"status locked busy 1".to_string()), "{e:?}");
    let tries = |d: &Daemon| {
        d.t.events()
            .iter()
            .filter(|x| x.starts_with("close safe"))
            .count()
    };
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
    let sent = |d: &Daemon| d.t.events().iter().filter(|x| *x == "status locked").count();
    assert!(d.t.events().contains(&"status locked failed".to_string()));
    assert_eq!(sent(&d), 0);
    d.t.advance(61_000);
    d.tick().await;
    assert_eq!(
        sent(&d),
        1,
        "the phone took the session as Open: {:?}",
        d.t.events()
    );
    // once heard, no more
    d.t.advance(3_600_000);
    d.tick().await;
    assert_eq!(sent(&d), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connecting_the_machine_socket_does_not_hold_up_requests() {
    // a relay that takes the connection and never answers the upgrade
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let (tx, rx) = tokio::sync::oneshot::channel();
    std::thread::spawn(move || {
        let (conn, _) = listener.accept().unwrap();
        let _ = tx.send(());
        std::thread::sleep(Duration::from_secs(30));
        drop(conn);
    });
    let (d, _) = testing::daemon(&origin);
    open(&d, &store_items()).await;
    let channel = tokio::spawn(super::channel::run(d.clone()));
    tokio::time::timeout(Duration::from_secs(5), rx)
        .await
        .unwrap()
        .unwrap();
    // statuses take the pairing for a moment; the connect (up to 10 s) must not
    assert!(
        tokio::time::timeout(Duration::from_secs(1), d.paired.lock())
            .await
            .is_ok(),
        "the pairing is free while the socket connects"
    );
    channel.abort();
}

#[tokio::test(start_paused = true)]
async fn the_next_request_after_a_wait_finds_the_phone_told() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    settle().await;
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    d.t.answer(testing::grant("once", &[]), Some(gate.clone()));
    d.t.answer(testing::grant("once", &[]), None);
    let first = tokio::spawn({
        let d = d.clone();
        async move { d.ask(approve::body("agent"), &ev(), false).await.is_ok() }
    });
    settle().await;
    // the periodic status goes out while the phone is asked
    d.send_status().await.unwrap();
    gate.add_permits(1);
    assert!(first.await.unwrap());
    // the next request follows at once
    d.ask(approve::body("keys"), &ev(), false).await.unwrap();
    let e = d.t.events();
    let waiting = at(&e, "status waiting");
    let open_again = e[waiting..]
        .iter()
        .position(|x| x == "status open")
        .map(|i| i + waiting);
    assert!(
        open_again.is_some_and(|o| o < at(&e, "ask keys")),
        "the phone knows the session is Open when the next request comes: {e:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn the_credit_stays_across_locks_and_the_place_sets_the_allowance() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    for m in 1..60 {
        d.st().saved.work(t0() + m * 60_000);
    }
    d.t.set_now(t0() + 60 * 60_000);
    d.lock("cli", true, false).await;
    assert_eq!(d.st().saved.worked, 60);
    // away from a trusted place: 10 minutes flat, whatever the credit
    let mut other = session_reply(&store_items());
    other.place = Some("other".into());
    other.cap = Some(600);
    other.base = Some(600);
    other.rate = Some(0);
    d.t.answer(other, None);
    d.open_with(
        store_items(),
        STORE,
        vec![],
        RequestContext::default(),
        &ev(),
        false,
        |_, _| Ok(()),
    )
    .await
    .unwrap();
    assert_eq!(d.st().saved.left(t0() + 60 * 60_000), 600);
    d.lock("place", true, false).await;
    // back at the trusted place: the credit counts again
    d.t.advance(60_000);
    open(&d, &store_items()).await;
    let worked = d.st().saved.worked;
    assert!(worked >= 61);
    assert_eq!(
        d.st().saved.left(d.now()),
        session::idle_allowance(14_400, 1_800, 120, worked)
    );
}

#[tokio::test(start_paused = true)]
async fn the_credit_survives_a_restart_until_the_hard_stop() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    for m in 1..30 {
        d.st().saved.work(t0() + m * 60_000);
    }
    d.lock("cli", true, false).await;
    let saved = serde_json::to_vec(&d.st().saved).unwrap();
    // a new daemon reads session.json
    let (d2, _) = testing::daemon(DEAD);
    d2.st().saved = serde_json::from_slice(&saved).unwrap();
    d2.t.set_now(t0() + 2 * 3_600_000);
    open(&d2, &store_items()).await;
    assert_eq!(d2.st().saved.first_open, Some(t0()));
    assert_eq!(d2.st().saved.worked, 31);
    // after the hard stop it starts over
    d2.lock("cli", true, false).await;
    let stop = session::hard_stop(t0());
    d2.t.set_now(stop + 60_000);
    open(&d2, &store_items()).await;
    assert_eq!(d2.st().saved.first_open, Some(stop + 60_000));
    assert_eq!(d2.st().saved.worked, 1);
}

#[tokio::test(start_paused = true)]
async fn asleep_across_the_hard_stop_locks_on_wake_and_resets_the_credit() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    let stop = session::hard_stop(t0());
    // working right up to the stop, asleep across it, woken by a key press
    d.st().saved.work(stop - 60_000);
    d.t.set_now(stop + 3_600_000);
    d.t.set_idle(Some(0));
    d.tick().await;
    settle().await;
    let st = d.st();
    assert!(!st.open);
    assert_eq!(st.saved.worked, 0);
    assert!(st.saved.first_open.is_none());
}

#[tokio::test(start_paused = true)]
async fn unit_tests_keep_their_files_out_of_home() {
    use crate::paths;
    let root = paths::unit_test_root();
    for dir in [paths::config_dir(), paths::data_dir(), paths::state_dir()] {
        let dir = dir.unwrap();
        assert!(
            dir.starts_with(&root),
            "{} is not under {}",
            dir.display(),
            root.display()
        );
    }
    // a lock saves the session where the tests keep it
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    d.lock("cli", true, false).await;
    assert!(paths::session_file().unwrap().starts_with(&root));
    assert!(paths::session_file().unwrap().exists());
}

#[tokio::test(start_paused = true)]
async fn an_exit_stops_running_backups_and_opens_no_session() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let locking = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    // the service manager stops the daemon while the on-lock backup runs
    let exiting = tokio::spawn({
        let d = d.clone();
        async move { d.on_exit().await }
    });
    tokio::task::yield_now().await;
    // an SSH signature asks for a session meanwhile, and the phone approves
    d.t.answer(session_reply(&store_items()), None);
    let r = d
        .open_with(
            store_items(),
            STORE,
            vec![],
            RequestContext::default(),
            &ev(),
            false,
            |_, _| Ok(()),
        )
        .await;
    assert!(r.is_err(), "no session opens while the daemon exits");
    tokio::time::timeout(Duration::from_secs(5), exiting)
        .await
        .expect("the exit does not wait out the backups")
        .unwrap();
    locking.await.unwrap();
    let e = d.t.events();
    assert!(at(&e, "backup stopped") < at(&e, "unmount"), "{e:?}");
    assert!(!d.st().open);
    assert_eq!(*d.locks_done.borrow(), d.st().locks_begun);
}

#[tokio::test(start_paused = true)]
async fn an_approval_that_arrives_during_the_exit_opens_no_session() {
    let (d, _) = testing::daemon(DEAD);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    d.t.answer(session_reply(&store_items()), Some(gate.clone()));
    let asking = tokio::spawn({
        let d = d.clone();
        async move {
            d.open_with(
                store_items(),
                STORE,
                vec![],
                RequestContext::default(),
                &ev(),
                false,
                |_, _| Ok(()),
            )
            .await
            .map(|(session, set)| (session, set.0.len()))
        }
    });
    settle().await;
    d.on_exit().await;
    // the phone answers after the exit's lock
    gate.add_permits(1);
    let (session, keys) = asking.await.unwrap().unwrap();
    assert!(!session, "the keys go to the waiting command only");
    assert_eq!(keys, 1);
    settle().await;
    assert!(!d.st().open);
    assert!(d.st().store_key.is_none());
    assert!(!d.t.events().iter().any(|e| e.starts_with("mount")));
}

#[tokio::test(start_paused = true)]
async fn a_session_that_runs_out_while_a_request_waits_its_turn_hands_out_no_value() {
    let (d, _) = testing::daemon(DEAD);
    let id = testing::with_store(&d);
    let items = vec![item("secrets", &id)];
    d.t.answer(session_reply(&items), None);
    d.open_with(
        items.clone(),
        &id,
        vec![],
        RequestContext::default(),
        &ev(),
        false,
        |_, _| Ok(()),
    )
    .await
    .unwrap();
    let store = d.store().unwrap();
    let key = super::copy_key(d.st().store_key.as_ref().unwrap());
    store
        .write(
            "API",
            sealctl_core::sealed::Mode::StoreKey,
            &key,
            "qHWf",
            b"value",
            None,
        )
        .unwrap();
    // a status holds the pairing (up to 10 s) while a request reads its context
    let paired = d.paired.lock().await;
    let asking = tokio::spawn({
        let d = d.clone();
        async move {
            let req = super::ValuesReq {
                names: vec!["API".into()],
                ..Default::default()
            };
            d.op_values(req, &ev()).await.is_ok()
        }
    });
    settle().await;
    // the machine sleeps past the idle allowance meanwhile
    d.t.advance(ALLOWANCE_MS + 60_000);
    drop(paired);
    assert!(
        !asking.await.unwrap(),
        "no value from a session whose time ran out"
    );
    assert!(!d.st().open);
}

#[tokio::test(start_paused = true)]
async fn a_lock_while_the_phone_is_asked_to_open_leaves_the_approval_with_its_command() {
    let (d, _) = testing::daemon(DEAD);
    let gate = Arc::new(tokio::sync::Semaphore::new(0));
    d.t.answer(session_reply(&store_items()), Some(gate.clone()));
    let asking = tokio::spawn({
        let d = d.clone();
        async move {
            d.open_with(
                store_items(),
                STORE,
                vec![],
                RequestContext::default(),
                &ev(),
                false,
                |_, _| Ok(()),
            )
            .await
            .map(|(session, set)| (session, set.0.len()))
        }
    });
    settle().await;
    // `sealctl lock` while the phone shows the request; then it is approved
    d.lock("cli", true, false).await;
    gate.add_permits(1);
    let (session, keys) = asking.await.unwrap().unwrap();
    assert!(!session, "the approval serves the waiting command only");
    assert_eq!(keys, 1);
    assert!(!d.st().open);
    assert!(d.st().store_key.is_none());
    // the next open is a session again
    open(&d, &store_items()).await;
    assert!(d.st().open);
}

#[tokio::test(start_paused = true)]
async fn a_failed_status_with_a_busy_volume_is_sent_again_with_it() {
    let (d, _) = testing::daemon(DEAD);
    d.t.vol_busy.lock().unwrap().push_back(true);
    open(&d, &store_items()).await;
    settle().await;
    *d.t.status_failures.lock().unwrap() = 1;
    d.lock("cli", true, false).await;
    assert!(d.t.events().contains(&"status locked failed".to_string()));
    d.t.advance(61_000);
    d.tick().await;
    let e = d.t.events();
    assert_eq!(
        e.last().map(String::as_str),
        Some("status locked busy 1"),
        "the phone hears of the busy volume: {e:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_busy_volume_that_closed_is_told_even_when_that_status_failed() {
    let (d, _) = testing::daemon(DEAD);
    d.t.vol_busy.lock().unwrap().extend([true, false]);
    open(&d, &store_items()).await;
    d.lock("cli", true, false).await;
    assert!(d.t.events().contains(&"status locked busy 1".to_string()));
    // the retry a minute later closes it; its status fails
    *d.t.status_failures.lock().unwrap() = 1;
    tokio::time::sleep(Duration::from_secs(61)).await;
    assert!(d.t.events().contains(&"status locked failed".to_string()));
    d.t.advance(61_000);
    d.tick().await;
    let e = d.t.events();
    assert_eq!(
        e.last().map(String::as_str),
        Some("status locked"),
        "the phone hears the volume closed: {e:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn a_hung_mount_holds_up_a_lock_for_two_minutes_at_most() {
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
    tokio::time::timeout(Duration::from_secs(600), locking)
        .await
        .expect("the lock does not wait for a hung mount")
        .unwrap();
    opening.await.unwrap();
    let e = d.t.events();
    assert!(e.contains(&"unmount".to_string()), "{e:?}");
    assert!(!e.contains(&"mount end".to_string()), "{e:?}");
    // the mount finishes after all: the session is Locked, so the volume closes again
    d.t.mount.release();
    settle().await;
    let e = d.t.events();
    assert!(at(&e, "mount end") < at(&e, "close safe"), "{e:?}");
    assert!(d.st().mounted.is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_lock_message_for_a_session_approved_during_the_backups_locks_at_once_and_takes_its_turn() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let first = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    // a new session during the first lock's backups, then the phone leaves the place
    open(&d, &store_items()).await;
    let t = d.now();
    d.apply_message(lock_message(t, 1, "place")).await;
    assert!(!d.st().open, "locked at once");
    assert!(d.st().store_key.is_none());
    settle().await;
    let e = d.t.events();
    assert!(!e.iter().any(|x| x.starts_with("unmount")), "{e:?}");
    // the first lock finishes, then the second runs its own backups and unmount
    d.t.backup.release();
    d.t.backup.release();
    first.await.unwrap();
    settle().await;
    let e = d.t.events();
    let starts: Vec<usize> = e
        .iter()
        .enumerate()
        .filter(|(_, x)| *x == "backup start")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(starts.len(), 2, "{e:?}");
    assert!(at(&e, "unmount") < starts[1], "{e:?}");
    assert_eq!(e.iter().filter(|x| *x == "unmount").count(), 2, "{e:?}");
    assert_eq!(*d.locks_done.borrow(), 2);
}

#[tokio::test(start_paused = true)]
async fn the_tick_and_a_request_both_past_the_allowance_lock_once() {
    let (d, _) = testing::daemon(DEAD);
    let vol = item("volume", "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8");
    open(&d, &[item("secrets", STORE), vol.clone()]).await;
    settle().await;
    d.t.advance(ALLOWANCE_MS + 60_000);
    let events = ev();
    let (_, r) = tokio::join!(d.tick(), d.op_keys(vec![vol], None, &events, false));
    assert!(r.is_err(), "no key past the allowance");
    settle().await;
    assert_eq!(d.st().locks_begun, 1, "one lock");
    let e = d.t.events();
    assert_eq!(e.iter().filter(|x| *x == "backup start").count(), 1, "{e:?}");
    assert_eq!(e.iter().filter(|x| *x == "status locked").count(), 1, "{e:?}");
}

#[tokio::test(start_paused = true)]
async fn a_lock_that_waits_for_an_earlier_locks_backups_says_so() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let first = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
    let ev: Events = {
        let seen = seen.clone();
        Arc::new(move |v| {
            seen.lock()
                .unwrap()
                .push(v["event"].as_str().unwrap_or("").to_string())
        })
    };
    let second = tokio::spawn({
        let d = d.clone();
        async move { d.handle(serde_json::json!({"op": "lock"}), ev).await }
    });
    settle().await;
    assert_eq!(*seen.lock().unwrap(), ["lock-waits"]);
    d.t.backup.release();
    first.await.unwrap();
    second.await.unwrap().unwrap();
}

#[tokio::test(start_paused = true)]
async fn a_restarted_daemon_tells_the_phone_what_the_last_one_could_not() {
    let (d, _) = testing::daemon(DEAD);
    open(&d, &store_items()).await;
    settle().await;
    // the exit's status fails (relay down), then the daemon is gone
    *d.t.status_failures.lock().unwrap() = 1;
    d.on_exit().await;
    assert!(d.t.events().contains(&"status locked failed".to_string()));
    let saved = serde_json::to_vec(&d.st().saved).unwrap();
    // the next daemon reads session.json
    let (d2, _) = testing::daemon(DEAD);
    *d2.st() = super::State::restored(serde_json::from_slice(&saved).unwrap(), t0());
    d2.tick().await;
    assert_eq!(
        d2.t.events(),
        ["status locked"],
        "the phone still took the session as Open"
    );
    // a daemon whose last status was heard sends nothing
    let saved = serde_json::to_vec(&d2.st().saved).unwrap();
    let (d3, _) = testing::daemon(DEAD);
    *d3.st() = super::State::restored(serde_json::from_slice(&saved).unwrap(), t0());
    d3.tick().await;
    assert!(d3.t.events().is_empty());
}

#[tokio::test(start_paused = true)]
async fn a_spawned_daemon_does_not_exit_while_a_lock_runs_its_backups() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let locking = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    // no client for 11 minutes while the on-lock backup runs; an exit would stop it
    d.st().last_client = t0() - 11 * 60_000;
    assert!(!d.idle_exit_due(), "the backup runs to its end");
    d.t.backup.release();
    locking.await.unwrap();
    assert!(d.idle_exit_due());
}

#[tokio::test(start_paused = true)]
async fn an_unpaired_answer_holds_up_no_other_request() {
    let (d, _) = testing::daemon(DEAD);
    d.t.backup.hold();
    open(&d, &store_items()).await;
    let locking = tokio::spawn({
        let d = d.clone();
        async move { d.lock("idle", false, false).await }
    });
    settle().await;
    // the relay says the machine is unpaired while the on-lock backup runs
    let mut gone = testing::grant("once", &[]);
    gone.err = Some(testing::UNPAIRED.into());
    d.t.answer(gone, None);
    d.t.answer(testing::grant("once", &[]), None);
    let r = tokio::time::timeout(
        Duration::from_secs(5),
        d.ask(approve::body("agent"), &ev(), false),
    )
    .await
    .expect("the unpaired answer does not wait for the lock's backups");
    assert!(r.is_err());
    tokio::time::timeout(Duration::from_secs(5), d.ask(approve::body("keys"), &ev(), false))
        .await
        .expect("the next request does not wait for the lock's backups")
        .unwrap();
    d.t.backup.release();
    locking.await.unwrap();
    settle().await;
    assert_eq!(*d.locks_done.borrow(), 2);
}

#[tokio::test(start_paused = true)]
async fn an_exit_does_not_wait_for_a_hung_mount() {
    let (d, _) = testing::daemon(DEAD);
    d.t.mount.hold();
    let opening = tokio::spawn({
        let d = d.clone();
        async move { open(&d, &store_items()).await }
    });
    settle().await;
    // the service manager gives the exit 60 seconds
    tokio::time::timeout(Duration::from_secs(10), d.on_exit())
        .await
        .expect("the exit unmounts without waiting out the mount");
    opening.await.unwrap();
    assert!(!d.st().open);
    assert!(d.t.events().contains(&"unmount".to_string()));
    d.t.mount.release();
    settle().await;
    let e = d.t.events();
    assert!(at(&e, "mount end") < at(&e, "close safe"), "{e:?}");
}
