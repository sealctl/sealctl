//! Agent session lifecycle (no device: only STATUS / STOP / expiry are exercised).

use std::time::{Duration, Instant};

use sealctl::agent::{self, AgentClient, AgentSession, Limits};
use sealctl::Ctx;
use sealctl_ledger::Select;

fn ctx() -> Ctx {
    Ctx {
        select: Select::Usb,
        scan: Duration::from_secs(1),
    }
}

fn wait_for_agent() -> AgentClient {
    for _ in 0..50 {
        if let Ok(c) = AgentClient::connect() {
            return c;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("agent did not start");
}

#[test]
fn agent_session_lifecycle() {
    // Unix socket paths are short-limited: use a short temp dir.
    let tmp = tempfile::Builder::new().prefix("sa").tempdir_in("/tmp").unwrap();
    std::env::set_var("XDG_STATE_HOME", tmp.path());

    // 1. STATUS and STOP
    let h = std::thread::spawn(|| {
        agent::run(
            ctx(),
            Limits {
                idle: Duration::from_secs(60),
                max_life: Duration::from_secs(3600),
            },
        )
    });
    let mut c = wait_for_agent();
    let (cached, idle_left, life_left) = c.status().unwrap();
    assert_eq!(cached, 0);
    assert!(idle_left > 50 && idle_left <= 60, "{idle_left}");
    assert!(life_left > 3500 && life_left <= 3600, "{life_left}");
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(agent::socket_path().unwrap())
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "socket private to the user");
    }
    assert!(agent::stop().unwrap());
    h.join().unwrap().unwrap();
    assert!(AgentClient::connect().is_err(), "gone after STOP");
    assert!(!agent::stop().unwrap(), "stop is a no-op when not running");

    // 2. idle expiry
    let start = Instant::now();
    let h = std::thread::spawn(|| {
        agent::run(
            ctx(),
            Limits {
                idle: Duration::from_secs(1),
                max_life: Duration::from_secs(3600),
            },
        )
    });
    drop(wait_for_agent());
    h.join().unwrap().unwrap();
    assert!(start.elapsed() < Duration::from_secs(5), "exited after idle");

    // 3. maximum lifetime, even while being used
    let start = Instant::now();
    let h = std::thread::spawn(|| {
        agent::run(
            ctx(),
            Limits {
                idle: Duration::from_secs(60),
                max_life: Duration::from_secs(2),
            },
        )
    });
    let mut c = wait_for_agent();
    while AgentClient::connect().is_ok() && start.elapsed() < Duration::from_secs(6) {
        let _ = c.status(); // keep it busy
        std::thread::sleep(Duration::from_millis(200));
        if let Ok(n) = AgentClient::connect() {
            c = n;
        }
    }
    h.join().unwrap().unwrap();
    assert!(
        start.elapsed() < Duration::from_secs(6),
        "exited at max lifetime despite activity"
    );

    // 4. a session whose connection the agent dropped connects again (unseal 0.6.0 failed
    //    with "Broken pipe" when restic kept it silent past the agent's 30 s client limit)
    let limits = Limits {
        idle: Duration::from_secs(60),
        max_life: Duration::from_secs(3600),
    };
    let h = std::thread::spawn(move || agent::run(ctx(), limits));
    drop(wait_for_agent());
    let mut session = AgentSession::open(&ctx(), limits).unwrap();
    session.status().unwrap();
    assert!(agent::stop().unwrap());
    h.join().unwrap().unwrap();
    let h = std::thread::spawn(move || agent::run(ctx(), limits));
    drop(wait_for_agent());
    let (cached, _, _) = session.status().expect("reconnected to the new agent");
    assert_eq!(cached, 0);
    assert!(agent::stop().unwrap());
    h.join().unwrap().unwrap();
}
