//! Keys derived from the Ledger seed — no key files anywhere.
//!
//! sealctl's one custom construction (see `docs/derived-keys.md`). It is the *2HashDH* PRF —
//! the same structure as the OPRF evaluation in RFC 9497 — instantiated on Curve25519 with the
//! Ledger OpenPGP app's X25519 decryption key `k` (derived from the seed in seed mode):
//!
//! ```text
//! u   = H1(purpose, id)                      hash onto the curve (no known discrete log)
//! S   = X25519(k, u)                         computed on the Ledger (PSO:DECIPHER)
//! key = HKDF-SHA256(salt = "sealctl/derive/v1",
//!                   ikm  = S,
//!                   info = purpose ‖ 0x00 ‖ id ‖ 0x00 ‖ u)         → 32 bytes
//! ```
//!
//! H1 is try-and-increment: `u_i = SHA-512("sealctl/derive/v1" ‖ 0 ‖ purpose ‖ 0 ‖ id ‖ 0 ‖ i₃₂)
//! mod p`, taking the first `u_i ≠ 0` for which `u³ + 486662·u² + u` is a non-zero square mod p
//! (so the point is on Curve25519, not its twist). The check runs on the host, so a firmware
//! change can never alter which point is used. Small-order components are irrelevant because
//! X25519 scalars are multiples of 8; an all-zero `S` is rejected.
//!
//! Security rests on the card key never leaving the device: the point has no known discrete
//! log, so `S` cannot be computed from the public key (which a scalar-multiple-of-G point would
//! allow).
//!
//! **Blinding (transport protection).** The device is never asked for `X25519(k, u)` directly.
//! As in RFC 9497 (Blind / Finalize), the host picks a fresh random scalar `r`, sends `r·u`,
//! receives `k·r·u` and computes `r⁻¹·(k·r·u) = k·u` locally. USB / Bluetooth only ever carry
//! random-looking points: an eavesdropper learns neither `S` nor which id is being derived.
//! The result is identical to the unblinded one (the clamped `k` is a multiple of 8, so torsion
//! components vanish and `r⁻¹` cancels `r` on the prime-order part).

use anyhow::{bail, Context, Result};
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use num_bigint::BigUint;
use openpgp_card::ocard::crypto::Cryptogram;
use openpgp_card::state::Open;
use openpgp_card::Card;
use sha2::{Digest, Sha256, Sha512};
use zeroize::Zeroizing;

use crate::device::{ensure_user_pin, Ctx};

pub const LABEL: &[u8] = b"sealctl/derive/v1";

/// What a derived key is for. The string is part of the derivation — never change it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Purpose {
    /// Volume passphrase; id = volume UUID.
    Volume,
    /// restic repository password; id = key id (volume name; the URL for 0.2.0 repositories).
    Restic,
    /// Secret store key; id = "store".
    Secrets,
    /// Passphrase of an encrypted OpenSSH private key; id = its public key's SHA256 fingerprint
    /// as OpenSSH prints it ("SHA256:…").
    Ssh,
}

impl Purpose {
    pub fn as_str(self) -> &'static str {
        match self {
            Purpose::Volume => "volume",
            Purpose::Restic => "restic",
            Purpose::Secrets => "secrets",
            Purpose::Ssh => "ssh",
        }
    }
}

/// Something that computes `X25519(k, u)` with a secret `k` — the Ledger, or a software key in tests.
pub trait Oracle {
    fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]>;
}

fn p() -> BigUint {
    (BigUint::from(1u8) << 255u32) - BigUint::from(19u8)
}

/// H1: deterministically map (purpose, id) to a Curve25519 u-coordinate (little-endian).
pub fn hash_to_u(purpose: Purpose, id: &str) -> [u8; 32] {
    let p = p();
    let exp = (&p - BigUint::from(1u8)) >> 1u32; // (p-1)/2, Euler's criterion
    let a = BigUint::from(486_662u32);
    for i in 0u32.. {
        let mut h = Sha512::new();
        h.update(LABEL);
        h.update([0]);
        h.update(purpose.as_str().as_bytes());
        h.update([0]);
        h.update(id.as_bytes());
        h.update([0]);
        h.update(i.to_be_bytes());
        let u = BigUint::from_bytes_le(&h.finalize()) % &p;
        if u == BigUint::from(0u8) {
            continue;
        }
        let rhs = (u.pow(3) + &a * u.pow(2) + &u) % &p;
        if rhs == BigUint::from(0u8) || rhs.modpow(&exp, &p) != BigUint::from(1u8) {
            continue; // on the twist (or a 2-torsion point): try the next counter
        }
        let mut out = [0u8; 32];
        let bytes = u.to_bytes_le();
        out[..bytes.len()].copy_from_slice(&bytes);
        return out;
    }
    unreachable!("about half of all candidates are valid")
}

/// Derive the 32-byte key for (purpose, id).
pub fn derive(oracle: &mut dyn Oracle, purpose: Purpose, id: &str) -> Result<Zeroizing<[u8; 32]>> {
    let u = hash_to_u(purpose, id);
    let s = Zeroizing::new(oracle.x25519(&u)?);
    if s.iter().all(|b| *b == 0) {
        bail!("degenerate key agreement result");
    }
    let mut info = Vec::with_capacity(64 + id.len());
    info.extend_from_slice(purpose.as_str().as_bytes());
    info.push(0);
    info.extend_from_slice(id.as_bytes());
    info.push(0);
    info.extend_from_slice(&u);
    let mut out = Zeroizing::new([0u8; 32]);
    hkdf::Hkdf::<Sha256>::new(Some(LABEL), s.as_slice())
        .expand(&info, out.as_mut_slice())
        .map_err(|_| anyhow::anyhow!("hkdf length"))?;
    Ok(out)
}

/// Derived key as a passphrase for OS tools (64 hex characters).
pub fn passphrase(oracle: &mut dyn Oracle, purpose: Purpose, id: &str) -> Result<Zeroizing<String>> {
    let key = derive(oracle, purpose, id)?;
    Ok(Zeroizing::new(hex::encode(key.as_slice())))
}

/// Short fingerprint of a derived key, for "is this the same key?" checks without revealing it.
pub fn key_check(key: &[u8]) -> String {
    hex::encode(&Sha256::digest([b"sealctl/key-check\0".as_slice(), key].concat())[..4])
}

/// Wraps an oracle so it only ever sees blinded points (RFC 9497-style Blind / Finalize).
pub struct Blinded<O: Oracle>(pub O);

impl<O: Oracle> Oracle for Blinded<O> {
    fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]> {
        blinded_call(u, |b| self.0.x25519(b))
    }
}

/// Send `r·u` instead of `u`, unblind the answer with `r⁻¹`.
fn blinded_call(u: &[u8; 32], call: impl FnOnce(&[u8; 32]) -> Result<[u8; 32]>) -> Result<[u8; 32]> {
    use zeroize::Zeroize;
    let mut wide = Zeroizing::new([0u8; 64]);
    getrandom::fill(wide.as_mut_slice()).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
    let mut r = Scalar::from_bytes_mod_order_wide(&wide);
    if r == Scalar::ZERO {
        bail!("degenerate blinding scalar");
    }
    let blinded = MontgomeryPoint(*u) * r;
    let mut r_inv = r.invert();
    r.zeroize();
    let resp = call(&blinded.0);
    let out = resp.map(|s| (MontgomeryPoint(s) * r_inv).0);
    r_inv.zeroize();
    out
}

/// The Ledger as oracle: PSO:DECIPHER with the card's X25519 decryption key, always blinded.
/// One connection; the PIN is asked for at most once.
pub struct CardOracle {
    card: Card<Open>,
    pin_checked: bool,
}

impl CardOracle {
    pub fn open(ctx: &Ctx) -> Result<Self> {
        Ok(Self {
            card: ctx.open_card()?,
            pin_checked: false,
        })
    }
}

impl Oracle for CardOracle {
    fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]> {
        let mut tx = self.card.transaction()?;
        if !self.pin_checked {
            ensure_user_pin(&mut tx)?;
            self.pin_checked = true;
        }
        blinded_call(u, |b| {
            let s = Zeroizing::new(
                tx.card()
                    .decipher(Cryptogram::ECDH(b))
                    .map_err(|e| crate::device::explain(anyhow::anyhow!("{e}")))
                    .context("key derivation on the Ledger")?,
            );
            s.as_slice()
                .try_into()
                .map_err(|_| anyhow::anyhow!("unexpected ECDH result length {}", s.len()))
        })
    }
}

/// A random RFC 4122 version-4 UUID (lowercase), used as the id of new sparsebundle/LUKS volumes.
pub fn new_uuid() -> Result<String> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
    b[6] = (b[6] & 0x0f) | 0x40;
    b[8] = (b[8] & 0x3f) | 0x80;
    let h = hex::encode(b);
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &h[0..8],
        &h[8..12],
        &h[12..16],
        &h[16..20],
        &h[20..32]
    ))
}

/// Canonical form of ids that are UUIDs (case-insensitive on input).
pub fn canonical_id(id: &str) -> String {
    let t = id.trim();
    let is_uuid = t.len() == 36 && t.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    if is_uuid {
        t.to_ascii_lowercase()
    } else {
        t.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Soft(x25519_dalek::StaticSecret, Vec<[u8; 32]>);

    impl Oracle for Soft {
        fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]> {
            self.1.push(*u); // what the "device" saw
            Ok(self
                .0
                .diffie_hellman(&x25519_dalek::PublicKey::from(*u))
                .to_bytes())
        }
    }

    #[test]
    fn blinding_gives_identical_results_and_hides_the_input() {
        let key = [7u8; 32];
        for i in 0..64 {
            let id = format!("id-{i}");
            for purpose in [Purpose::Volume, Purpose::Restic, Purpose::Secrets] {
                let u = hash_to_u(purpose, &id);
                let mut plain = Soft(x25519_dalek::StaticSecret::from(key), vec![]);
                let mut blind = Blinded(Soft(x25519_dalek::StaticSecret::from(key), vec![]));
                assert_eq!(
                    plain.x25519(&u).unwrap(),
                    blind.x25519(&u).unwrap(),
                    "{purpose:?} {id}"
                );
                assert_ne!(blind.0 .1[0], u, "device never sees u");
                // and derived keys match end to end
                let a = derive(&mut plain, purpose, &id).unwrap();
                let b = derive(&mut blind, purpose, &id).unwrap();
                assert_eq!(a, b);
            }
        }
    }

    #[test]
    fn blinding_is_fresh_each_time() {
        let u = hash_to_u(Purpose::Volume, "same");
        let mut blind = Blinded(Soft(x25519_dalek::StaticSecret::from([3u8; 32]), vec![]));
        blind.x25519(&u).unwrap();
        blind.x25519(&u).unwrap();
        assert_ne!(
            blind.0 .1[0], blind.0 .1[1],
            "requests for the same id are unlinkable"
        );
    }

    #[test]
    fn hash_to_u_is_deterministic_and_on_curve() {
        let a = hash_to_u(Purpose::Volume, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8");
        let b = hash_to_u(Purpose::Volume, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8");
        assert_eq!(a, b);
        assert_ne!(
            a,
            hash_to_u(Purpose::Restic, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8")
        );
        assert_ne!(
            a,
            hash_to_u(Purpose::Volume, "fa5a93d5-28d9-4c08-b608-c2b6f344b4d9")
        );
        assert!(a[31] & 0x80 == 0, "u < p fits in 255 bits");
    }

    #[test]
    fn uuids() {
        let u = new_uuid().unwrap();
        assert_eq!(u.len(), 36);
        assert_eq!(&u[14..15], "4");
        assert_eq!(
            canonical_id("FA5A93D5-28D9-4C08-B608-C2B6F344B4D8"),
            "fa5a93d5-28d9-4c08-b608-c2b6f344b4d8"
        );
        assert_eq!(canonical_id("s3:https://X/y"), "s3:https://X/y");
    }
}
