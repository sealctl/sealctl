//! Ledger transports (USB HID, Bluetooth LE) for the OpenPGP card application,
//! exposed as a [`card_backend::CardBackend`] so that `openpgp-card` does all
//! OpenPGP card protocol work. This crate only moves bytes.

pub mod ble;
pub mod framing;
pub mod hid;

use std::fmt;
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{anyhow, Result};
use card_backend::{CardBackend, CardCaps, CardTransaction, PinType, SmartcardError};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportKind {
    Usb,
    Ble,
}

impl fmt::Display for TransportKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            TransportKind::Usb => "usb",
            TransportKind::Ble => "bluetooth",
        })
    }
}

#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub transport: TransportKind,
    pub name: String,
    pub id: String,
}

/// Raw APDU exchange: returns response data followed by the 2-byte status word.
pub trait Exchange: Send {
    fn exchange(&mut self, apdu: &[u8]) -> Result<Vec<u8>>;
    fn kind(&self) -> TransportKind;
}

/// Which transport to use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Select {
    Auto,
    Usb,
    Ble,
}

pub fn open(select: Select, ble_scan: Duration) -> Result<Box<dyn Exchange>> {
    match select {
        Select::Usb => Ok(Box::new(hid::HidTransport::open_first()?)),
        Select::Ble => Ok(Box::new(ble::BleTransport::open_first(ble_scan)?)),
        Select::Auto => match hid::HidTransport::open_first() {
            Ok(t) => Ok(Box::new(t)),
            Err(usb_err) => {
                log::debug!("USB not available ({usb_err}), trying Bluetooth");
                ble::BleTransport::open_first(ble_scan)
                    .map(|t| Box::new(t) as Box<dyn Exchange>)
                    .map_err(|ble_err| anyhow!("no Ledger found.\n  USB: {usb_err}\n  Bluetooth: {ble_err}"))
            }
        },
    }
}

/// Ledger dashboard / app-level commands (CLA 0xB0 / 0xE0).
pub fn running_app(t: &mut dyn Exchange) -> Result<(String, String)> {
    let r = t.exchange(&[0xb0, 0x01, 0x00, 0x00, 0x00])?;
    let (data, sw) = r.split_at(r.len().saturating_sub(2));
    if sw != [0x90, 0x00] || data.len() < 2 {
        return Err(anyhow!("GET APP AND VERSION failed: {}", hex(sw)));
    }
    let nlen = data[1] as usize;
    let name = data
        .get(2..2 + nlen)
        .map(|n| String::from_utf8_lossy(n).into_owned())
        .ok_or_else(|| anyhow!("malformed GET APP AND VERSION reply"))?;
    let vlen = data.get(2 + nlen).copied().unwrap_or(0) as usize;
    let version = data
        .get(3 + nlen..3 + nlen + vlen)
        .map(|v| String::from_utf8_lossy(v).into_owned())
        .unwrap_or_default();
    Ok((name, version))
}

/// Ask the dashboard to launch an app by name (the user confirms on the device).
/// The link resets afterwards; reconnect to talk to the app.
pub fn open_app(t: &mut dyn Exchange, name: &str) -> Result<()> {
    let n = name.as_bytes();
    let mut apdu = vec![0xe0, 0xd8, 0x00, 0x00, n.len() as u8];
    apdu.extend_from_slice(n);
    let r = t.exchange(&apdu)?;
    let sw = &r[r.len().saturating_sub(2)..];
    match sw {
        [0x90, 0x00] => Ok(()),
        [0x55, 0x01] | [0x69, 0x85] => Err(anyhow!("opening {name} was rejected on the device")),
        [0x68, 0x07] => Err(anyhow!("{name} is not installed on the device")),
        _ => Err(anyhow!("opening {name} failed: {}", hex(sw))),
    }
}

pub fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// CLA used by the Ledger OpenPGP app for "PIN pad" (on-device PIN entry).
const CLA_PINPAD: u8 = 0xef;

/// [`CardBackend`] over a Ledger [`Exchange`].
pub struct LedgerBackend {
    inner: Mutex<Box<dyn Exchange>>,
}

impl LedgerBackend {
    pub fn new(t: Box<dyn Exchange>) -> Self {
        Self { inner: Mutex::new(t) }
    }
}

impl From<LedgerBackend> for Box<dyn CardBackend + Send + Sync> {
    fn from(b: LedgerBackend) -> Self {
        Box::new(b)
    }
}

fn sc_err(e: anyhow::Error) -> SmartcardError {
    SmartcardError::Error(format!("{e:#}"))
}

impl CardBackend for LedgerBackend {
    fn limit_card_caps(&self, caps: CardCaps) -> CardCaps {
        // Ledger I/O buffers are small: short APDUs with command chaining.
        CardCaps::new(false, true, 255, 256, caps.pw1_max_len(), caps.pw3_max_len())
    }

    fn transaction(
        &mut self,
        reselect: Option<&[u8]>,
    ) -> Result<Box<dyn CardTransaction + Send + Sync + '_>, SmartcardError> {
        let mut tx = LedgerTx { backend: self };
        if let Some(aid) = reselect {
            tx.select(aid)?;
        }
        Ok(Box::new(tx))
    }
}

struct LedgerTx<'a> {
    backend: &'a LedgerBackend,
}

impl LedgerTx<'_> {
    fn xfer(&mut self, apdu: &[u8]) -> Result<Vec<u8>, SmartcardError> {
        let mut t = self
            .backend
            .inner
            .lock()
            .map_err(|_| SmartcardError::Error("poisoned".into()))?;
        log::trace!("> {}", hex(apdu));
        let r = t.exchange(apdu).map_err(sc_err)?;
        log::trace!("< {}", hex(&r));
        Ok(r)
    }
}

impl CardTransaction for LedgerTx<'_> {
    fn transmit(&mut self, cmd: &[u8], _buf_size: usize) -> Result<Vec<u8>, SmartcardError> {
        self.xfer(cmd)
    }

    fn max_cmd_len(&self) -> Option<usize> {
        Some(255)
    }

    // PIN entry always happens on the Ledger screen; the host never sees the PIN.
    fn feature_pinpad_verify(&self) -> bool {
        true
    }

    fn feature_pinpad_modify(&self) -> bool {
        true
    }

    fn pinpad_verify(&mut self, pin: PinType, _caps: &Option<CardCaps>) -> Result<Vec<u8>, SmartcardError> {
        self.xfer(&[CLA_PINPAD, 0x20, 0x00, pin.id(), 0x00])
    }

    fn pinpad_modify(&mut self, pin: PinType, _caps: &Option<CardCaps>) -> Result<Vec<u8>, SmartcardError> {
        // CHANGE REFERENCE DATA without data => the app asks for old/new PIN on screen.
        self.xfer(&[0x00, 0x24, 0x00, pin.id(), 0x00])
    }

    fn was_reset(&self) -> bool {
        false
    }
}
