//! The machine's own keys: the pairing key (Ed25519) and the machine box key (X25519).
//! Used by the CLI; not exported to the apps.

use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{CoreError, Result};

/// A machine's pairing seed and box private key. Wiped on drop.
pub struct MachineKeys {
    pairing_seed: Zeroizing<[u8; 32]>,
    box_secret: Zeroizing<[u8; 32]>,
    pairing_public: [u8; 32],
    box_public: [u8; 32],
}

impl MachineKeys {
    /// New random keys for `sealctl pair`.
    pub fn generate() -> Result<Self> {
        let seed = Zeroizing::new(crypto::random_array::<32>()?);
        let (box_secret, _) = crypto::x25519_generate(&mut crypto::os_rng());
        Ok(Self::from_parts(seed, box_secret))
    }

    /// From the stored seed and box private key (64 bytes: seed ‖ box key).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != 64 {
            return Err(CoreError::BadKey);
        }
        let mut seed = Zeroizing::new([0u8; 32]);
        let mut boxk = Zeroizing::new([0u8; 32]);
        seed.copy_from_slice(&bytes[..32]);
        boxk.copy_from_slice(&bytes[32..]);
        Ok(Self::from_parts(seed, boxk))
    }

    /// The 64-byte storage form.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(crypto::cat(&[
            self.pairing_seed.as_slice(),
            self.box_secret.as_slice(),
        ]))
    }

    fn from_parts(pairing_seed: Zeroizing<[u8; 32]>, box_secret: Zeroizing<[u8; 32]>) -> Self {
        let pairing_public = crypto::ed25519_public(&pairing_seed);
        let box_public = crypto::x25519_public(&box_secret);
        Self {
            pairing_seed,
            box_secret,
            pairing_public,
            box_public,
        }
    }

    /// `M`.
    pub fn public(&self) -> &[u8; 32] {
        &self.pairing_public
    }

    /// The machine id: `b64u(M)`.
    pub fn id(&self) -> String {
        crypto::b64u(&self.pairing_public)
    }

    /// `MX`.
    pub fn box_public(&self) -> &[u8; 32] {
        &self.box_public
    }

    pub(crate) fn sign(&self, msg: &[u8]) -> [u8; 64] {
        crypto::ed25519_sign(&self.pairing_seed, msg)
    }

    pub(crate) fn pairing_seed(&self) -> &[u8; 32] {
        &self.pairing_seed
    }

    pub(crate) fn box_secret(&self) -> &[u8; 32] {
        &self.box_secret
    }
}

/// `tag`: the first 20 bits of `SHA256("sealctl/v1/tag" ‖ 0x00 ‖ M)` in lower-case Crockford base32.
pub fn tag(machine_public: &[u8; 32]) -> String {
    const CROCK: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";
    let h = crypto::sha256(&crypto::cat(&[b"sealctl/v1/tag", &[0], machine_public]));
    let v = (u32::from(h[0]) << 12) | (u32::from(h[1]) << 4) | (u32::from(h[2]) >> 4);
    [15u32, 10, 5, 0]
        .iter()
        .map(|s| CROCK[((v >> s) & 31) as usize] as char)
        .collect()
}

/// `hint = b64u(first 16 bytes of SHA256("sealctl/v1/hint" ‖ 0x00 ‖ raw))`.
pub fn hardware_hint(raw: &str) -> String {
    let h = crypto::sha256(&crypto::cat(&[b"sealctl/v1/hint", &[0], raw.as_bytes()]));
    crypto::b64u(&h[..16])
}

/// The duplicate-name tag of a machine, from its 43-character id.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn machine_tag(machine_key: String) -> Result<String> {
    Ok(tag(&crypto::decode_key32(&machine_key)?))
}
