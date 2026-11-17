//! Connecting to the Ledger OpenPGP app and PIN handling.

use std::time::Duration;

use anyhow::{bail, Context, Result};
use openpgp_card::state::{Open, Transaction};
use openpgp_card::Card;
use sealctl_ledger::{LedgerBackend, Select, TransportKind};

/// Global options shared by all commands.
#[derive(Debug, Clone, Copy)]
pub struct Ctx {
    pub select: Select,
    pub scan: Duration,
}

impl Ctx {
    pub fn transport_name(&self) -> &'static str {
        match self.select {
            Select::Auto => "auto",
            Select::Usb => "usb",
            Select::Ble => "ble",
        }
    }

    /// Connect to the OpenPGP app, telling the user what to do on the Ledger (stderr + desktop
    /// notification) and waiting while it is off, locked or on another app — up to
    /// `SEALCTL_WAIT` seconds (default 90).
    pub fn open_card(&self) -> Result<Card<Open>> {
        let wait = std::env::var("SEALCTL_WAIT")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .unwrap_or(90);
        let deadline = std::time::Instant::now() + Duration::from_secs(wait);
        loop {
            let e = match self.try_open_card() {
                Ok(card) => return Ok(card),
                Err(e) => e,
            };
            let Some(todo) = needs_user(&e) else {
                return Err(e);
            };
            if std::time::Instant::now() >= deadline {
                return Err(e);
            }
            crate::util::notify(todo);
            std::thread::sleep(Duration::from_secs(2));
        }
    }

    /// One connection attempt.
    fn try_open_card(&self) -> Result<Card<Open>> {
        let mut t = sealctl_ledger::open(self.select, self.scan)?;
        let mut kind = t.kind();
        let (mut app, mut version) = sealctl_ledger::running_app(t.as_mut()).map_err(explain)?;

        // On the dashboard: ask the device to open OpenPGP (confirmed on the Ledger), then
        // reconnect — launching an app resets the USB/Bluetooth link.
        if app == "BOLOS" && std::env::var_os("SEALCTL_NO_AUTO_OPEN").is_none() {
            crate::util::notify("Opening the OpenPGP app — confirm on the Ledger if asked");
            match sealctl_ledger::open_app(t.as_mut(), "OpenPGP") {
                Ok(()) => {
                    drop(t);
                    let deadline = std::time::Instant::now() + Duration::from_secs(30);
                    let mut last_err;
                    loop {
                        std::thread::sleep(Duration::from_millis(1500));
                        // reconnect over the same transport that worked
                        let sel = match kind {
                            TransportKind::Usb => Select::Usb,
                            TransportKind::Ble => Select::Ble,
                        };
                        match sealctl_ledger::open(sel, self.scan.min(Duration::from_secs(15)))
                            .and_then(|mut t2| sealctl_ledger::running_app(t2.as_mut()).map(|a| (t2, a)))
                        {
                            Ok((t2, (a, v))) if a == "OpenPGP" => {
                                t = t2;
                                kind = t.kind();
                                (app, version) = (a, v);
                                break;
                            }
                            Ok((_, (a, _))) => last_err = anyhow::anyhow!("device is on {a}"),
                            Err(e) => last_err = e,
                        }
                        if std::time::Instant::now() > deadline {
                            bail!("couldn't reconnect after opening OpenPGP: {last_err:#}");
                        }
                    }
                }
                Err(e) => log::info!("auto-open failed: {e:#}"),
            }
        }
        if app != "OpenPGP" {
            let place = if app == "BOLOS" {
                "its dashboard".to_string()
            } else {
                format!("the \"{app}\" app")
            };
            bail!(
                "the Ledger is on {place} — open the OpenPGP app on the device and retry{}",
                if kind == TransportKind::Ble {
                    " (Bluetooth needs the Bluetooth-enabled OpenPGP build)"
                } else {
                    ""
                }
            );
        }
        log::info!("connected via {kind}: OpenPGP {version}");
        Card::new(LedgerBackend::new(t)).context("selecting the OpenPGP application")
    }
}

/// What the user has to do on the Ledger for this error to go away, if anything.
fn needs_user(e: &anyhow::Error) -> Option<&'static str> {
    let s = format!("{e:#}");
    if s.contains("5515") || s.contains("is locked") {
        Some("Unlock your Ledger")
    } else if s.contains("no Ledger found") {
        Some("Turn on and unlock your Ledger (Bluetooth on, or USB connected)")
    } else if s.contains("the Ledger is on") || s.contains("6e00") || s.contains("6d00") {
        Some("Open the OpenPGP app on your Ledger")
    } else {
        None
    }
}

/// Turn Ledger status words into actionable messages.
pub fn explain(e: anyhow::Error) -> anyhow::Error {
    let s = format!("{e:#}");
    let hint = if s.contains("5515") {
        Some("the Ledger is locked — unlock it with your PIN")
    } else if s.contains("6985") || s.contains("5501") {
        Some("the request was rejected on the Ledger")
    } else if s.contains("6e00") || s.contains("6d00") || s.contains("6e01") {
        Some("the wrong app is open on the Ledger — open OpenPGP")
    } else {
        None
    };
    match hint {
        Some(h) => anyhow::anyhow!("{h} ({s})"),
        None => e,
    }
}

pub fn prompt(msg: &str) -> impl Fn() + '_ {
    move || crate::util::notify(msg)
}

/// Make sure the user PIN (PW1, decrypt/authenticate) is verified; the Ledger keeps it
/// verified until the app closes or the device locks, so this usually asks only once.
pub fn ensure_user_pin(tx: &mut Card<Transaction>) -> Result<()> {
    if tx.check_user_verified().is_ok() {
        return Ok(());
    }
    tx.verify_user_pinpad(&prompt("Enter your PIN on the Ledger"))
        .context("PIN verification")
}
