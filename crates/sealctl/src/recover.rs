//! Recovery without a Ledger: recompute the OpenPGP app's seed-derived **decryption** key from
//! the 24-word recovery phrase, in software.
//!
//! This reproduces `app-openpgp` (LedgerHQ) seed mode "v2" — the mode its GENERATE uses by
//! default when Seed mode is on (`src/gpg_gen.c`):
//!
//! ```text
//! seed  = BIP39(words, passphrase)                         (PBKDF2-HMAC-SHA512, 2048 rounds)
//! Sn    = BIP32-secp256k1(seed, m/0x80475047'/(slot+1)')   (private key, 32 bytes)
//! h     = SHA-256("kdf2" ‖ Sn ‖ "dec " ‖ u16be(1) ‖ u8(len A) ‖ A)
//!         A = the key's algorithm attributes, 12 2B060104019755010501 for cv25519 ECDH
//! d     = (SHAKE-256(h, 64 bytes) as big-endian) mod ℓ, clamped (RFC 7748), big-endian
//! k     = d little-endian                                  (the X25519 scalar)
//! ```
//!
//! The result is checked against the decryption subkey of your certificate, so a wrong word,
//! passphrase or slot can never silently produce a wrong key.
//!
//! Typing the recovery phrase into a computer exposes it to that computer. This is for disaster
//! recovery (Ledger lost or the app gone), ideally on an offline machine.

use anyhow::{bail, Context, Result};
use curve25519_dalek::montgomery::MontgomeryPoint;
use hmac::{Hmac, Mac};
use num_bigint::BigUint;
use sha2::{Digest, Sha256, Sha512};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use zeroize::{Zeroize, Zeroizing};

/// Algorithm attributes sealctl sets for the decryption key: ECDH (0x12) over cv25519.
pub const ATTR_CV25519_ECDH: [u8; 11] = [0x12, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

const APP_PATH: u32 = 0x8047_5047;
const HARDENED: u32 = 0x8000_0000;

/// secp256k1 group order n.
const SECP256K1_N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
/// Curve25519 prime-subgroup order ℓ = 2^252 + 27742317777372353535851937790883648493.
const CURVE25519_L: &str = "1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed";

fn big(hex_str: &str) -> BigUint {
    BigUint::parse_bytes(hex_str.as_bytes(), 16).expect("constant")
}

/// BIP39 seed from a recovery phrase (the checksum is verified).
pub fn bip39_seed(words: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>> {
    let mut normalized = Zeroizing::new(String::with_capacity(words.len()));
    for (i, w) in words.split_whitespace().enumerate() {
        if i > 0 {
            normalized.push(' ');
        }
        normalized.extend(w.chars().flat_map(char::to_lowercase));
    }
    let m = bip39::Mnemonic::parse_in(bip39::Language::English, normalized.as_str())
        .map_err(|e| anyhow::anyhow!("not a valid recovery phrase: {e}"))?;
    Ok(Zeroizing::new(m.to_seed(passphrase)))
}

fn to32(n: &BigUint) -> Zeroizing<[u8; 32]> {
    let b = n.to_bytes_be();
    let mut out = Zeroizing::new([0u8; 32]);
    out[32 - b.len()..].copy_from_slice(&b);
    out
}

/// BIP32 private derivation on secp256k1, hardened steps only (all the app uses in v2).
pub fn bip32_hardened(seed: &[u8], path: &[u32]) -> Result<Zeroizing<[u8; 32]>> {
    let n = big(SECP256K1_N);
    let mut mac = Hmac::<Sha512>::new_from_slice(b"Bitcoin seed").expect("any key length");
    Mac::update(&mut mac, seed);
    let i = Zeroizing::new(mac.finalize().into_bytes());
    let mut k = Zeroizing::new([0u8; 32]);
    let mut c = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&i[..32]);
    c.copy_from_slice(&i[32..]);
    let kn = BigUint::from_bytes_be(&k[..]);
    if kn == BigUint::ZERO || kn >= n {
        bail!("invalid BIP32 master key");
    }
    for &index in path {
        if index & HARDENED == 0 {
            bail!("only hardened derivation is supported");
        }
        let mut mac = Hmac::<Sha512>::new_from_slice(&c[..]).expect("any key length");
        Mac::update(&mut mac, &[0]);
        Mac::update(&mut mac, &k[..]);
        Mac::update(&mut mac, &index.to_be_bytes());
        let i = Zeroizing::new(mac.finalize().into_bytes());
        let il = BigUint::from_bytes_be(&i[..32]);
        if il >= n {
            bail!("invalid BIP32 child (index {index:#x})");
        }
        let child = (il + BigUint::from_bytes_be(&k[..])) % &n;
        if child == BigUint::ZERO {
            bail!("invalid BIP32 child (index {index:#x})");
        }
        k = to32(&child);
        c.copy_from_slice(&i[32..]);
    }
    Ok(k)
}

/// The X25519 decryption scalar (little-endian) of OpenPGP-app key slot `slot` (0-based).
pub fn decryption_key(seed: &[u8], slot: u32, attributes: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let sn = bip32_hardened(seed, &[APP_PATH, (HARDENED | slot) + 1])?;
    let mut h = Sha256::new();
    Digest::update(&mut h, b"kdf2");
    Digest::update(&mut h, &sn[..]);
    Digest::update(&mut h, b"dec ");
    Digest::update(&mut h, [0x00, 0x01, attributes.len() as u8]);
    Digest::update(&mut h, attributes);
    let mut h = h.finalize();

    let mut shake = sha3::Shake256::default();
    shake.update(&h);
    h.zeroize();
    let mut wide = Zeroizing::new([0u8; 64]);
    shake.finalize_xof().read(&mut wide[..]);
    let d = BigUint::from_bytes_be(&wide[..]) % big(CURVE25519_L);
    let mut d = to32(&d);
    d[31] &= 0xF8;
    d[0] = (d[0] & 0x7F) | 0x40;
    d.reverse();
    Ok(d)
}

/// X25519 public key (little-endian) of a scalar.
pub fn public_key(k: &[u8; 32]) -> [u8; 32] {
    MontgomeryPoint::mul_base_clamped(*k).to_bytes()
}

/// The cv25519 public key of the certificate's decryption subkey.
pub fn cert_decryption_key(cert: &pgp::composed::SignedPublicKey) -> Option<[u8; 32]> {
    use pgp::types::{EcdhPublicParams, KeyDetails, PublicParams};
    cert.public_subkeys
        .iter()
        .find_map(|s| match s.key.public_params() {
            PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { p, .. }) => Some(*p.as_bytes()),
            _ => None,
        })
}

/// Derive the decryption key from the phrase and make sure it is the one in `cert`.
/// Tries the attribute encodings a card may have stored (with and without import format 0xFF).
pub fn recover_key(
    words: &str,
    passphrase: &str,
    slot: u32,
    expected_public: &[u8; 32],
) -> Result<Zeroizing<[u8; 32]>> {
    let seed = bip39_seed(words, passphrase)?;
    let mut with_ff = ATTR_CV25519_ECDH.to_vec();
    with_ff.push(0xFF);
    for attrs in [&ATTR_CV25519_ECDH[..], &with_ff[..]] {
        let k = decryption_key(&seed[..], slot, attrs)?;
        if &public_key(&k) == expected_public {
            return Ok(k);
        }
    }
    bail!(
        "the phrase does not produce the decryption key of your certificate.\n   \
         Check the words, the passphrase (if you use one), and the key slot."
    )
}

/// Read a recovery phrase without echo.
pub fn read_phrase() -> Result<Zeroizing<String>> {
    eprintln!(
        "⚠️  Typing the recovery phrase exposes it to this computer. Do this only to recover\n   \
         (Ledger lost or broken), ideally offline. Words are not shown while you type."
    );
    let words = crate::util::read_hidden("Recovery phrase (24 words, separated by spaces): ")?;
    if words.split_whitespace().count() < 12 {
        bail!("expected 12–24 words");
    }
    Ok(words)
}

/// A software oracle holding the recovered key, for the agent.
pub struct SeedOracle(pub Zeroizing<[u8; 32]>);

impl crate::derive::Oracle for SeedOracle {
    fn x25519(&mut self, u: &[u8; 32]) -> Result<[u8; 32]> {
        let s = MontgomeryPoint(*u).mul_clamped(*self.0);
        Ok(s.to_bytes())
    }
}

/// Recovered-key checks run against `cert` if present.
pub fn expected_public() -> Result<[u8; 32]> {
    let cert = crate::cert::own().context(
        "your certificate is needed to verify the recovered key — restore it first \
         (`sealctl kit import`), or regenerate it on a new Ledger with `sealctl setup`",
    )?;
    cert_decryption_key(&cert).context("the certificate has no cv25519 decryption subkey")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// BIP32 test vector 1 (seed 000102…0f): m/0' private key.
    #[test]
    fn bip32_vector_1() {
        let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let k = bip32_hardened(&seed, &[HARDENED]).unwrap();
        assert_eq!(
            hex::encode(&k[..]),
            "edb2e14f9ee77d26dd93b4ecede8d16ed408ce149b6cd80b0715a2d911a0afea"
        );
    }

    /// BIP39 test vector (TREZOR passphrase), "abandon … about".
    #[test]
    fn bip39_vector() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon about";
        let seed = bip39_seed(words, "TREZOR").unwrap();
        assert_eq!(
            hex::encode(&seed[..]),
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553\
             1f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
        );
    }

    #[test]
    fn bad_checksum_is_rejected() {
        let words = "abandon abandon abandon abandon abandon abandon abandon abandon abandon \
                     abandon abandon abandon";
        assert!(bip39_seed(words, "").is_err());
    }

    /// Run by scripts/speculos-recover-check.sh with the emulator's phrase and the public key
    /// the OpenPGP app generated from it; skipped otherwise.
    #[test]
    fn matches_device() {
        let (Ok(words), Ok(want)) = (
            std::env::var("SEALCTL_TEST_PHRASE"),
            std::env::var("SEALCTL_EXPECT_DEC_PUB"),
        ) else {
            return;
        };
        let want: [u8; 32] = hex::decode(want.trim()).unwrap().try_into().unwrap();
        let k = recover_key(&words, "", 0, &want).expect("software key equals the device key");
        println!("software decryption public key: {}", hex::encode(public_key(&k)));
    }

    #[test]
    fn decryption_key_is_clamped() {
        let k = decryption_key(&[1u8; 64], 0, &ATTR_CV25519_ECDH).unwrap();
        assert_eq!(k[0] & 7, 0);
        assert_eq!(k[31] & 0xC0, 0x40);
    }
}
