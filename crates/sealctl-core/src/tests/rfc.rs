//! RFC vectors through the crates and wrappers the core uses.

use super::*;

#[test]
fn rfc5869_hkdf_empty_salt() {
    // RFC 5869 A.3: zero-length salt and info.
    let mut okm = [0u8; 42];
    crypto::hkdf_into(&[0x0b; 22], b"", &mut okm);
    assert_eq!(
        hex::encode(okm),
        "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8"
    );
}

#[test]
fn rfc8032_ed25519_test1() {
    let seed: [u8; 32] = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .try_into()
        .unwrap();
    let public = crypto::ed25519_public(&seed);
    assert_eq!(
        hex::encode(public),
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    );
    let sig = crypto::ed25519_sign(&seed, b"");
    assert_eq!(
        hex::encode(sig),
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
    );
    crypto::ed25519_verify(&public, b"", &sig).unwrap();
}

#[test]
fn rfc7748_x25519_alice() {
    let sk: [u8; 32] = unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .try_into()
        .unwrap();
    assert_eq!(
        hex::encode(crypto::x25519_public(&sk)),
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    );
}

#[test]
fn rfc8439_chacha20poly1305() {
    // RFC 8439 2.8.2.
    let key: [u8; 32] = (0x80u8..0xa0).collect::<Vec<_>>().try_into().unwrap();
    let nonce: [u8; 12] = unhex("070000004041424344454647").try_into().unwrap();
    let aad = unhex("50515253c0c1c2c3c4c5c6c7");
    let pt = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let ct = crypto::aead_seal(&key, &nonce, &aad, pt).unwrap();
    assert_eq!(
        hex::encode(&ct),
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116\
         1ae10b594f09e26a7e902ecbd0600691"
    );
    assert_eq!(crypto::aead_open(&key, &nonce, &aad, &ct).unwrap().as_slice(), pt);
}

#[test]
fn rfc9180_a21_base_chacha() {
    // RFC 9180 A.2.1: DHKEM(X25519), HKDF-SHA256, ChaCha20Poly1305, base mode, sequence 0.
    let mut rng = FixedRng::new(&[&unhex(
        "1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df",
    )]);
    let (sk_r, pk_r) = crypto::x25519_generate(&mut rng);
    drop(rng);
    assert_eq!(
        hex::encode(sk_r.as_slice()),
        clamped("8057991eef8f1f1af18f4a9491d16a1ce333f695d4db8e38da75975c4478e0fb")
    );
    assert_eq!(
        hex::encode(pk_r),
        "4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"
    );
    let info = unhex("4f6465206f6e2061204772656369616e2055726e");
    let aad = unhex("436f756e742d30");
    let pt = unhex("4265617574792069732074727574682c20747275746820626561757479");
    let mut rng = FixedRng::new(&[&unhex(
        "909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b",
    )]);
    let sealed = crypto::hpke_seal(&pk_r, &info, &aad, &pt, &mut rng).unwrap();
    drop(rng);
    assert_eq!(
        hex::encode(&sealed.bytes[..32]),
        "1afa08d3dec047a643885163f1180476fa7ddb54c6a8029ea33f95796bf2ac4a"
    );
    assert_eq!(
        hex::encode(&sealed.bytes[32..]),
        "1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"
    );
    let (opened, export) = crypto::hpke_open(&sk_r, &info, &aad, &sealed.bytes).unwrap();
    assert_eq!(opened.as_slice(), pt.as_slice());
    assert_eq!(export, sealed.match_export);
}

#[test]
fn bip39_english_list() {
    // The list bip39 carries is the published one (protocol.md Appendix B).
    let list = bip39::Language::English.word_list().join("\n") + "\n";
    assert_eq!(
        hex::encode(crypto::sha256(list.as_bytes())),
        "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
    );
    // BIP39's own vector for this mnemonic with passphrase TREZOR.
    let m = bip39::Mnemonic::from_entropy(&[0; 32]).unwrap();
    assert!(hex::encode(m.to_seed_normalized("TREZOR")).starts_with("bda85446"));
}
