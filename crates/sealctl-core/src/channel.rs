//! Machine status (machine to phone) and machine messages (phone to machine): sealed and
//! signed like requests, without a request id.

use rand_core::CryptoRng;
use zeroize::Zeroizing;

use crate::crypto::{self, ENC_LEN, SIG_LEN, TAG_LEN};
use crate::error::{CoreError, Result};
use crate::machine::MachineKeys;
use crate::pairing::PROTOCOL_VERSION;
use crate::phone::{PhoneKeys, PhonePublic};
use crate::request::check_version;
use crate::wire::{MachineMessage, MachineStatus};

/// Longest sealed status, in characters.
pub const MAX_STATUS: usize = 8192;
/// Longest sealed machine message, in characters.
pub const MAX_MESSAGE: usize = 4096;

const STATUS_INFO: &[u8] = b"sealctl/v1/status";
const MESSAGE_INFO: &[u8] = b"sealctl/v1/message";

fn status_message(phone: &[u8; 32], body: &[u8]) -> Vec<u8> {
    crypto::cat(&[STATUS_INFO, &[0], phone, body])
}

fn machine_message(machine: &[u8; 32], body: &[u8]) -> Vec<u8> {
    crypto::cat(&[MESSAGE_INFO, &[0], machine, body])
}

fn open_signed(
    secret: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    sealed: &str,
    max: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    if sealed.len() > max {
        return Err(CoreError::BadSealed);
    }
    let raw = crypto::b64u_decode(sealed).ok_or(CoreError::BadSealed)?;
    if raw.len() < ENC_LEN + TAG_LEN + SIG_LEN {
        return Err(CoreError::BadSealed);
    }
    Ok(crypto::hpke_open(secret, info, aad, &raw)?.0)
}

fn seal_signed(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    sig: &[u8; 64],
    body: &[u8],
    max: usize,
    rng: &mut impl CryptoRng,
) -> Result<String> {
    let pt = Zeroizing::new(crypto::cat(&[sig, body]));
    let sealed = crypto::b64u(&crypto::hpke_seal(recipient, info, aad, &pt, rng)?.bytes);
    if sealed.len() > max {
        return Err(CoreError::TooLarge);
    }
    Ok(sealed)
}

/// Seals a status to the phone (machine side).
pub fn seal_status(machine: &MachineKeys, phone: &PhonePublic, status: &MachineStatus) -> Result<String> {
    let status = MachineStatus {
        version: PROTOCOL_VERSION,
        ..status.clone()
    };
    let body = serde_json::to_vec(&status).map_err(|_| CoreError::Internal)?;
    seal_status_bytes(machine, phone, &body, &mut crypto::os_rng())
}

pub(crate) fn seal_status_bytes(
    machine: &MachineKeys,
    phone: &PhonePublic,
    body: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<String> {
    let sig = machine.sign(&status_message(&phone.identity, body));
    seal_signed(
        &phone.box_key,
        STATUS_INFO,
        machine.public(),
        &sig,
        body,
        MAX_STATUS,
        rng,
    )
}

/// Opens a machine's status with the phone keys and checks the machine's signature.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn open_machine_status(keys: &PhoneKeys, machine_key: String, sealed: String) -> Result<MachineStatus> {
    let machine = crypto::decode_key32(&machine_key)?;
    let pt = open_signed(keys.box_secret(), STATUS_INFO, &machine, &sealed, MAX_STATUS)?;
    let (sig, body) = pt.split_at(SIG_LEN);
    crypto::ed25519_verify(&machine, &status_message(keys.identity_public(), body), sig)?;
    check_version(body)?;
    serde_json::from_slice(body).map_err(|_| CoreError::BadSealed)
}

/// Seals a message to a machine's box key (from its pairing offer), signed by the phone.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn seal_machine_message(
    keys: &PhoneKeys,
    machine_key: String,
    machine_box_key: String,
    message: MachineMessage,
) -> Result<String> {
    let machine = crypto::decode_key32(&machine_key)?;
    let machine_box = crypto::decode_key32(&machine_box_key)?;
    let message = MachineMessage {
        version: PROTOCOL_VERSION,
        ..message
    };
    let body = serde_json::to_vec(&message).map_err(|_| CoreError::Internal)?;
    seal_message_bytes(keys, &machine, &machine_box, &body, &mut crypto::os_rng())
}

pub(crate) fn seal_message_bytes(
    keys: &PhoneKeys,
    machine: &[u8; 32],
    machine_box: &[u8; 32],
    body: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<String> {
    let sig = keys.sign(&machine_message(machine, body));
    seal_signed(machine_box, MESSAGE_INFO, machine, &sig, body, MAX_MESSAGE, rng)
}

/// Opens a message from the paired phone (machine side).
pub fn open_message(machine: &MachineKeys, phone: &[u8; 32], sealed: &str) -> Result<MachineMessage> {
    let pt = open_signed(
        machine.box_secret(),
        MESSAGE_INFO,
        machine.public(),
        sealed,
        MAX_MESSAGE,
    )?;
    let (sig, body) = pt.split_at(SIG_LEN);
    crypto::ed25519_verify(phone, &machine_message(machine.public(), body), sig)?;
    check_version(body)?;
    serde_json::from_slice(body).map_err(|_| CoreError::BadSealed)
}
