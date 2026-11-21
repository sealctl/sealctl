//! `sealctl doctor`: prove that everything needed for recovery still works.

use anyhow::{bail, Result};
use openpgp_card::ocard::KeyType;
use pgp::types::KeyDetails;

use crate::device::Ctx;
use crate::{cert, crypto};

pub fn run(ctx: &Ctx, full: bool) -> Result<()> {
    let mut ok = true;
    let mut report = |good: bool, msg: String| {
        println!("{} {msg}", if good { "✅" } else { "❌" });
        ok &= good;
    };

    // 0. A `sealctl unseal` run that stopped part way.
    if let Some(run) = crate::unseal::unfinished_run() {
        report(
            false,
            format!(
                "an unseal run stopped part way ({}) — continue it with `sealctl unseal --resume`",
                crate::unseal::tilde(&run)
            ),
        );
    }

    // 1. Certificate on disk.
    let cert = match cert::own() {
        Ok(c) => {
            report(
                true,
                format!(
                    "certificate {} ({})",
                    cert::fingerprint_hex(&c),
                    cert::primary_user_id(&c)
                ),
            );
            c
        }
        Err(e) => {
            report(false, format!("certificate: {e:#}"));
            bail!("doctor found problems");
        }
    };

    // 2. Card fingerprints match the certificate (keys reproducible from the seed).
    let mut card = ctx.open_card()?;
    {
        let mut tx = card.transaction()?;
        let fps = tx.fingerprints()?;
        let cert_fps: Vec<String> = std::iter::once(hex::encode(cert.fingerprint().as_bytes()))
            .chain(
                cert.public_subkeys
                    .iter()
                    .map(|s| hex::encode(s.key.fingerprint().as_bytes())),
            )
            .collect();
        for (name, kt, fp) in [
            ("signature", KeyType::Signing, fps.signature()),
            ("decryption", KeyType::Decryption, fps.decryption()),
            ("authentication", KeyType::Authentication, fps.authentication()),
        ] {
            let _ = kt;
            match fp {
                Some(fp) if cert_fps.contains(&fp.to_hex()) => {
                    report(true, format!("card {name} key matches the certificate"))
                }
                Some(fp) => report(false, format!("card {name} key {} is not in the certificate", fp.to_hex())),
                None => report(
                    false,
                    format!("card {name} key slot is empty — re-run `sealctl setup --force` (seed-derived keys come back identical)"),
                ),
            }
        }
    }
    drop(card);

    // 3. End-to-end decryption through the device.
    if full {
        let probe = b"sealctl doctor probe";
        let ct = crypto::encrypt(std::slice::from_ref(&cert), probe, true)?;
        match crypto::decrypt(ctx, &ct) {
            Ok(pt) if pt.as_slice() == probe => report(true, "test decryption on the Ledger works".into()),
            Ok(_) => report(false, "test decryption returned wrong data".into()),
            Err(e) => report(false, format!("test decryption failed: {e:#}")),
        }
    }

    // 4. Key derivation on the device is deterministic (fresh connection, no agent cache).
    if full {
        let mut a = crate::derive::CardOracle::open(ctx)?;
        let k1 = crate::derive::derive(&mut a, crate::derive::Purpose::Volume, "sealctl-doctor-probe")?;
        drop(a);
        let mut b = crate::derive::CardOracle::open(ctx)?;
        let k2 = crate::derive::derive(&mut b, crate::derive::Purpose::Volume, "sealctl-doctor-probe")?;
        report(
            k1 == k2,
            format!(
                "seed-derived keys are reproducible (check {})",
                crate::derive::key_check(k1.as_slice())
            ),
        );
    }

    // 5. Volumes use derived keys.
    for v in crate::volume::Volume::list()? {
        if v.is_legacy() {
            report(
                false,
                format!(
                    "volume '{}' still uses a key file — run `sealctl volume rekey {}`",
                    v.name, v.name
                ),
            );
        } else {
            report(
                true,
                format!("volume '{}' key derives from the seed + id {}", v.name, v.id),
            );
        }
    }

    if !ok {
        bail!("doctor found problems");
    }
    Ok(())
}
