//! Thin wrappers over the established primitive crates. Nothing here implements a primitive;
//! it only fixes the parameters protocol.md uses (empty HKDF salt, HPKE suite, encodings).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use hkdf::Hkdf;
use hmac::{KeyInit as _, Mac as _};
use hpke::kem::X25519HkdfSha256;
use hpke::{Deserializable as _, Kem as _, OpModeR, OpModeS, Serializable as _};
use rand_core::CryptoRng;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

use crate::error::{CoreError, Result};

pub(crate) type HpkeKem = X25519HkdfSha256;
type HpkeKdf = hpke::kdf::HkdfSha256;
type HpkeAead = hpke::aead::ChaCha20Poly1305;

/// HPKE `enc` length for X25519.
pub(crate) const ENC_LEN: usize = 32;
/// AEAD tag length.
pub(crate) const TAG_LEN: usize = 16;
/// Ed25519 signature length.
pub(crate) const SIG_LEN: usize = 64;
/// The exporter context of the number match.
pub(crate) const MATCH_EXPORT: &[u8] = b"sealctl/v1/match";

// ---------- encodings ----------

pub(crate) fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Strict base64url without padding; non-canonical trailing bits are refused.
pub(crate) fn b64u_decode(text: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(text.as_bytes()).ok()
}

pub(crate) fn b64u_decode_fixed<const N: usize>(text: &str) -> Option<[u8; N]> {
    // The exact length is known up front; refusing other lengths early keeps junk out.
    if text.len() != (N * 4).div_ceil(3) {
        return None;
    }
    let v = Zeroizing::new(b64u_decode(text)?);
    v.as_slice().try_into().ok()
}

/// A 32-byte public key written as 43 base64url characters.
pub(crate) fn decode_key32(text: &str) -> Result<[u8; 32]> {
    b64u_decode_fixed::<32>(text).ok_or(CoreError::BadKey)
}

// ---------- hashes ----------

pub(crate) fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

pub(crate) fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.finalize().into_bytes().into()
}

/// Constant-time HMAC check.
pub(crate) fn hmac_sha256_verify(key: &[u8], msg: &[u8], tag: &[u8]) -> bool {
    let mut mac = hmac::Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(msg);
    mac.verify_slice(tag).is_ok()
}

/// `HKDF(ikm, info, L)` of protocol.md: HKDF-SHA256 with an empty salt.
pub(crate) fn hkdf_into(ikm: &[u8], info: &[u8], out: &mut [u8]) {
    Hkdf::<Sha256>::new(None, ikm)
        .expand(info, out)
        .expect("output lengths used here are valid");
}

pub(crate) fn hkdf_array<const N: usize>(ikm: &[u8], info: &[u8]) -> Zeroizing<[u8; N]> {
    let mut out = Zeroizing::new([0u8; N]);
    hkdf_into(ikm, info, out.as_mut_slice());
    out
}

// ---------- Ed25519 ----------

pub(crate) fn ed25519_public(seed: &[u8; 32]) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

pub(crate) fn ed25519_sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
    SigningKey::from_bytes(seed).sign(msg).to_bytes()
}

/// RFC 8032 verification with the strict checks (no small-order keys, canonical `S`).
pub(crate) fn ed25519_verify(public: &[u8; 32], msg: &[u8], sig: &[u8]) -> Result<()> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| CoreError::BadSignature)?;
    let sig = Signature::from_slice(sig).map_err(|_| CoreError::BadSignature)?;
    key.verify_strict(msg, &sig).map_err(|_| CoreError::BadSignature)
}

// ---------- X25519 and HPKE ----------

/// The X25519 public key of a 32-byte private key (clamped when used, RFC 7748).
pub(crate) fn x25519_public(secret: &[u8; 32]) -> [u8; 32] {
    let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(secret).expect("any 32 bytes are an X25519 key");
    let pk = HpkeKem::sk_to_pk(&sk);
    let mut out = [0u8; 32];
    out.copy_from_slice(&pk.to_bytes());
    out
}

/// A fresh X25519 key pair, made as HPKE's `DeriveKeyPair(random 32 bytes)`.
pub(crate) fn x25519_generate(rng: &mut impl CryptoRng) -> (Zeroizing<[u8; 32]>, [u8; 32]) {
    let (sk, pk) = HpkeKem::gen_keypair_with_rng(rng);
    let mut secret = Zeroizing::new([0u8; 32]);
    secret.copy_from_slice(&sk.to_bytes());
    let mut public = [0u8; 32];
    public.copy_from_slice(&pk.to_bytes());
    (secret, public)
}

/// The result of one single-shot HPKE seal: `enc ‖ ct`, and the 4-byte number-match export.
pub(crate) struct HpkeSealed {
    pub bytes: Vec<u8>,
    pub match_export: [u8; 4],
}

/// RFC 9180 base mode `SetupBaseS`, `Seal`, `Export` on one context.
pub(crate) fn hpke_seal(
    recipient: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    plaintext: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<HpkeSealed> {
    let pk = <HpkeKem as hpke::Kem>::PublicKey::from_bytes(recipient).map_err(|_| CoreError::BadKey)?;
    let (enc, mut ctx) =
        hpke::setup_sender_with_rng::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeS::Base, &pk, info, rng)
            .map_err(|_| CoreError::BadKey)?;
    let ct = ctx.seal(plaintext, aad).map_err(|_| CoreError::Internal)?;
    let mut match_export = [0u8; 4];
    ctx.export(MATCH_EXPORT, &mut match_export)
        .map_err(|_| CoreError::Internal)?;
    let mut bytes = Vec::with_capacity(ENC_LEN + ct.len());
    bytes.extend_from_slice(&enc.to_bytes());
    bytes.extend_from_slice(&ct);
    Ok(HpkeSealed { bytes, match_export })
}

/// RFC 9180 base mode `SetupBaseR`, `Open`, `Export` on one context.
pub(crate) fn hpke_open(
    secret: &[u8; 32],
    info: &[u8],
    aad: &[u8],
    sealed: &[u8],
) -> Result<(Zeroizing<Vec<u8>>, [u8; 4])> {
    if sealed.len() < ENC_LEN + TAG_LEN {
        return Err(CoreError::BadSealed);
    }
    let sk = <HpkeKem as hpke::Kem>::PrivateKey::from_bytes(secret).map_err(|_| CoreError::BadKey)?;
    let enc = <HpkeKem as hpke::Kem>::EncappedKey::from_bytes(&sealed[..ENC_LEN])
        .map_err(|_| CoreError::BadSealed)?;
    let mut ctx = hpke::setup_receiver::<HpkeAead, HpkeKdf, HpkeKem>(&OpModeR::Base, &sk, &enc, info)
        .map_err(|_| CoreError::BadSealed)?;
    let pt = Zeroizing::new(
        ctx.open(&sealed[ENC_LEN..], aad)
            .map_err(|_| CoreError::BadSealed)?,
    );
    let mut match_export = [0u8; 4];
    ctx.export(MATCH_EXPORT, &mut match_export)
        .map_err(|_| CoreError::Internal)?;
    Ok((pt, match_export))
}

/// `N = 10 + (x mod 90)` from the 4 exported bytes.
pub(crate) fn match_number(export: &[u8; 4]) -> u8 {
    (10 + u32::from_be_bytes(*export) % 90) as u8
}

// ---------- AEAD ----------

pub(crate) fn aead_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    use chacha20poly1305::aead::{Aead as _, Payload};
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(nonce.into(), Payload { msg: plaintext, aad })
        .map_err(|_| CoreError::Internal)
}

pub(crate) fn aead_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    use chacha20poly1305::aead::{Aead as _, Payload};
    let cipher = chacha20poly1305::ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(nonce.into(), Payload { msg: ciphertext, aad })
        .map(Zeroizing::new)
        .map_err(|_| CoreError::BadSealed)
}

// ---------- randomness ----------

/// The OS random source as a `CryptoRng`. It panics only if the OS source fails, which
/// UniFFI turns into a thrown error rather than a crash.
pub(crate) fn os_rng() -> rand_core::UnwrapErr<getrandom::SysRng> {
    rand_core::UnwrapErr(getrandom::SysRng)
}

pub(crate) fn random_array<const N: usize>() -> Result<[u8; N]> {
    let mut out = [0u8; N];
    getrandom::fill(&mut out).map_err(|_| CoreError::Internal)?;
    Ok(out)
}

/// A uniform number in `0..n` from the OS source, by rejection (no modulo bias).
pub(crate) fn random_below(n: u32) -> Result<u32> {
    debug_assert!(n > 0);
    let zone = u32::MAX - (u32::MAX % n);
    loop {
        let v = u32::from_be_bytes(random_array::<4>()?);
        if v < zone {
            return Ok(v % n);
        }
    }
}

/// Concatenation helper for the signed and authenticated byte strings of protocol.md.
pub(crate) fn cat(parts: &[&[u8]]) -> Vec<u8> {
    let mut out = Vec::with_capacity(parts.iter().map(|p| p.len()).sum());
    for p in parts {
        out.extend_from_slice(p);
    }
    out
}
