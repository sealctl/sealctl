//! Password stores of `sealctl unseal`: fake `op` and `bw` on PATH record every argv and keep
//! values in a temporary folder. No value may ever be an argument; a changed read-back stops the
//! run before sealctl's key goes. The OS keychain is tested against a test service name only
//! where the CI asks for it (it would otherwise write to the login keychain of the machine).

mod common;

use common::{new_home, serial, text, FixtureOpts};

fn ssh_only() -> FixtureOpts {
    FixtureOpts {
        secrets: true,
        ssh: true,
        git: false,
        ai: false,
        shell: false,
        services: false,
    }
}

#[test]
fn op_and_bw_never_see_a_value_in_argv() {
    let _g = serial();
    let mut h = new_home();
    common::fixture(&h, &ssh_only());
    common::start_agent();
    h.start_ssh_agent();

    let out = h.unseal(
        &["ssh", "ed25519", "--to", "bw", "--bw-folder", "Work"],
        "y\n",
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    let out = h.unseal(
        &["ssh", "github", "--to", "op", "--op-vault", "Private"],
        "y\n",
        &[],
    );
    assert!(out.status.success(), "{}", text(&out));
    // with a password store, today's behaviour: a passphrase, the agent and keychain on macOS
    if cfg!(target_os = "macos") {
        let want = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[2; 32]));
        let fp = want
            .public_key()
            .fingerprint(ssh_key::HashAlg::Sha256)
            .to_string();
        let listed = sealctl::ssh::agent_fingerprints(&h.ssh_agent_sock().unwrap());
        assert!(listed.contains(&fp), "github not in the agent: {listed:?}");
        let config = std::fs::read_to_string(h.home.join(".ssh/config")).unwrap();
        assert!(
            config.contains("Host *\n    UseKeychain yes\n    AddKeysToAgent yes\n"),
            "{config}"
        );
    }
    let out = h.unseal(&["secret", "mail", "--secrets-to", "op"], "y\n", &[]);
    assert!(out.status.success(), "{}", text(&out));
    let out = h.unseal(&["secrets", "--secrets-to", "bw"], "y\n", &[]);
    assert!(out.status.success(), "{}", text(&out));

    let argv = std::fs::read_to_string(h.fake.join("argv.log")).unwrap();
    assert!(
        argv.contains("op item create --format json --vault Private"),
        "{argv}"
    );
    assert!(argv.contains("bw create item\n"), "{argv}");
    assert!(argv.contains("op read --no-newline op://Private/"), "{argv}");
    let values = h.fake_values();
    assert_eq!(values.len(), 2 + 7 + 1, "2 passphrases, 7 + 1 secrets");
    for (_, v) in common::fixture_secrets() {
        assert!(values.contains(&v), "secret stored");
    }
    for v in &values {
        assert!(!argv.contains(v.as_str()), "a value was passed as an argument");
    }
    // `unseal secret <name>` left the store in place; `unseal secrets` moved it to kept/
    assert!(!h.home.join(".local/share/sealctl/secrets/shop").exists());
    // the SSH keys open with what the stores hold
    let bw_pass = std::fs::read_to_string(h.fake.join("bw/id1")).unwrap();
    let want = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[1; 32]));
    assert!(sealctl::ssh::opens_with(
        &h.home.join(".ssh/ed25519"),
        Some(bw_pass.as_bytes()),
        want.public_key()
    )
    .unwrap());
}

#[test]
fn a_changed_read_back_stops_before_sealctls_key_goes() {
    let _g = serial();
    let h = new_home();
    common::fixture(&h, &ssh_only());
    common::start_agent();
    let before = common::tree(&h.home.join(".ssh"));
    let out = h.unseal(
        &["ssh", "ed25519", "--to", "op"],
        "y\n",
        &[("FAKE_OP_CORRUPT", "1")],
    );
    assert_eq!(out.status.code(), Some(13), "{}", text(&out));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("read back"), "{err}");
    assert!(err.contains("sealctl unseal --resume"), "{err}");
    assert_eq!(
        common::tree(&h.home.join(".ssh")),
        before,
        "nothing changed in ~/.ssh"
    );
    let journal = std::fs::read_to_string(h.run_dir().join("journal.jsonl")).unwrap();
    assert!(
        journal.contains("\"step\":\"ssh:ed25519:password\",\"state\":\"failed\""),
        "{journal}"
    );

    // the same with secrets: the store stays
    let out = h.unseal(&["--resume"], "", &[]);
    assert!(out.status.success(), "{}", text(&out));
    let out = h.unseal(
        &["secrets", "--secrets-to", "op"],
        "y\n",
        &[("FAKE_OP_CORRUPT", "1")],
    );
    assert_eq!(out.status.code(), Some(13), "{}", text(&out));
    assert!(h
        .home
        .join(".local/share/sealctl/secrets/shop/openai-api-key.gpg")
        .exists());
}

/// The keychain store against a test service name: on macOS in a keychain file of its own
/// (SEALCTL_TEST_KEYCHAIN_PATH, made and unlocked by CI; never the default or login
/// keychain), on Linux the Secret Service. Only with SEALCTL_TEST_KEYCHAIN=1 (CI). A watchdog
/// fails the test after 60 s instead of letting a keychain call hold the job.
#[test]
fn keychain_store_roundtrip() {
    if !common::flag("SEALCTL_TEST_KEYCHAIN") {
        eprintln!("set SEALCTL_TEST_KEYCHAIN=1 to test the OS keychain store");
        return;
    }
    if cfg!(target_os = "macos") && std::env::var_os("SEALCTL_TEST_KEYCHAIN_PATH").is_none() {
        eprintln!("set SEALCTL_TEST_KEYCHAIN_PATH to a keychain file to test the macOS keychain store");
        return;
    }
    let _g = serial();
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let r = std::panic::catch_unwind(keychain_roundtrip_body);
        let _ = tx.send(r);
    });
    match rx.recv_timeout(std::time::Duration::from_secs(60)) {
        Ok(Ok(())) => {}
        Ok(Err(p)) => std::panic::resume_unwind(p),
        Err(_) => panic!("the keychain store did not answer in 60 s (a keychain call waiting for a dialog?)"),
    }
}

fn keychain_roundtrip_body() {
    use sealctl::unseal::store::{self, Config, Item, StoreKind, Stores};
    let service = format!("sealctl-unseal-test-{}", std::process::id());
    std::env::set_var("SEALCTL_TEST_KEYCHAIN_SERVICE", &service);
    assert!(store::keychain_available(), "keychain not reachable");
    let mut s = Stores::new(Config {
        to: StoreKind::Keychain,
        secrets_to: StoreKind::Keychain,
        env_file: None,
        op_vault: None,
        bw_folder: None,
        type_passwords: false,
    });
    let item = Item {
        kind: "volume",
        name: "unseal-test",
        notes: "test".into(),
        credential: false,
        var: None,
    };
    let value = store::generate_password().unwrap();
    let loc = s
        .put_checked(StoreKind::Keychain, &item, value.as_bytes(), &|_| Ok(()))
        .unwrap();
    assert_eq!(loc.service.as_deref(), Some(service.as_str()));
    assert_eq!(loc.account.as_deref(), Some("volume/unseal-test"));
    assert_eq!(&*s.read(&loc).unwrap(), value.as_bytes());
    // the item has a readable label (Keychain Access shows it)
    #[cfg(target_os = "macos")]
    let keychain = std::env::var_os("SEALCTL_TEST_KEYCHAIN_PATH").unwrap();
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("security")
            .args([
                "find-generic-password",
                "-s",
                &service,
                "-a",
                "volume/unseal-test",
            ])
            .arg(&keychain)
            .output()
            .unwrap();
        let attrs = String::from_utf8_lossy(&out.stdout);
        // the label attribute: printed as "labl" or by its number, 0x00000007
        let label = "<blob>=\"sealctl: volume unseal-test\"";
        assert!(
            attrs
                .lines()
                .any(|l| (l.contains("\"labl\"") || l.contains("0x00000007")) && l.contains(label)),
            "{attrs}"
        );
    }
    #[cfg(target_os = "linux")]
    {
        let attrs = keyring::Entry::new(&service, "volume/unseal-test")
            .unwrap()
            .get_attributes()
            .unwrap();
        assert_eq!(
            attrs.get("label").map(String::as_str),
            Some("sealctl: volume unseal-test")
        );
    }
    // stored again (a resumed step): the new value
    let again = store::generate_password().unwrap();
    let loc = s
        .put_checked(StoreKind::Keychain, &item, again.as_bytes(), &|_| Ok(()))
        .unwrap();
    assert_eq!(&*s.read(&loc).unwrap(), again.as_bytes());
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("security")
            .args([
                "delete-generic-password",
                "-s",
                &service,
                "-a",
                "volume/unseal-test",
            ])
            .arg(&keychain)
            .output()
            .unwrap();
        assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    }
    #[cfg(not(target_os = "macos"))]
    keyring::Entry::new(&service, "volume/unseal-test")
        .unwrap()
        .delete_credential()
        .unwrap();
    assert!(s.read(&loc).is_err(), "removed after the test");
}
