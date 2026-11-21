//! Device discovery, read-only card inspection, and the overall status overview.

use std::time::Duration;

use anyhow::{bail, Result};
use openpgp_card::ocard::KeyType;
use sealctl_ledger::Select;

use crate::device::Ctx;

pub fn devices(select: Select, scan: Duration) -> Result<()> {
    let mut any = false;
    if select != Select::Ble {
        for d in sealctl_ledger::hid::list()? {
            println!("usb        {:<24} {}", d.name, d.id);
            any = true;
        }
    }
    if select != Select::Usb {
        let scan = scan.min(Duration::from_secs(10));
        eprintln!("scanning Bluetooth for {}s…", scan.as_secs());
        match sealctl_ledger::ble::list(scan) {
            Ok(list) => {
                for d in list {
                    println!("bluetooth  {:<24} {}", d.name, d.id);
                    any = true;
                }
            }
            Err(e) => eprintln!("bluetooth unavailable: {e:#}"),
        }
    }
    if !any {
        bail!("no Ledger found (unlocked? Bluetooth on and not connected to a phone?)");
    }
    Ok(())
}

pub fn status(ctx: &Ctx) -> Result<()> {
    let mut card = ctx.open_card()?;
    let mut tx = card.transaction()?;

    let aid = tx.application_identifier()?;
    println!(
        "Card:        {} serial {:08X}, OpenPGP card v{}.{}",
        manufacturer(aid.manufacturer(), aid.manufacturer_name()),
        aid.serial(),
        aid.version() >> 8,
        aid.version() & 0xff
    );
    println!("Ident:       {}", aid.ident());
    if let Ok(name) = tx.cardholder_name() {
        if !name.is_empty() {
            println!("Cardholder:  {name}");
        }
    }
    if let Ok(Some(url)) = tx.url().map(|u| (!u.is_empty()).then_some(u)) {
        println!("URL:         {url}");
    }

    let fps = tx.fingerprints()?;
    let times = tx.key_generation_times()?;
    for (label, kt, fp, t) in [
        ("Signature ", KeyType::Signing, fps.signature(), times.signature()),
        (
            "Decryption",
            KeyType::Decryption,
            fps.decryption(),
            times.decryption(),
        ),
        (
            "Auth      ",
            KeyType::Authentication,
            fps.authentication(),
            times.authentication(),
        ),
    ] {
        let algo = tx
            .algorithm_attributes(kt)
            .map(|a| a.to_string())
            .unwrap_or_else(|e| format!("? ({e})"));
        let fp = fp.map(|f| f.to_hex()).unwrap_or_else(|| "— (empty)".into());
        let created = t.map(|t| utc_date(t.get())).unwrap_or_default();
        println!("{label}   {algo:<14} {fp} {created}");
    }

    let pws = tx.pw_status_bytes()?;
    println!(
        "PIN retries: user {}, reset {}, admin {}",
        pws.err_count_pw1(),
        pws.err_count_rc(),
        pws.err_count_pw3()
    );
    Ok(())
}

/// openpgp-card's vendor table doesn't know Ledger's id yet.
fn manufacturer(id: u16, name: &'static str) -> &'static str {
    match id {
        0x2c97 => "Ledger",
        _ => name,
    }
}

/// Format unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (UTC), without a date library.
/// Days-to-civil conversion from Howard Hinnant's public-domain algorithm.
pub fn utc_date(secs: u32) -> String {
    let secs = secs as i64;
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// `sealctl status`: what's set up and what's unlocked — no device needed.
pub fn overview() -> Result<()> {
    match crate::cert::own() {
        Ok(c) => println!(
            "Key:       {} {}",
            crate::cert::fingerprint_hex(&c),
            crate::cert::primary_user_id(&c)
        ),
        Err(_) => println!("Key:       not set up — run `sealctl setup`"),
    }
    let vols = crate::volume::Volume::list()?;
    if vols.is_empty() {
        println!("Volumes:   none — `sealctl volume create <name> --size 50g`");
    }
    for v in vols {
        let open = v.is_unlocked().unwrap_or(false);
        let backup = match &v.backup {
            None => "no backup".to_string(),
            Some(_) => {
                let st = crate::backup::load_state(&v.name);
                match (st.last_success, st.last_error) {
                    (_, Some(e)) => format!("last backup FAILED: {}", e.lines().next().unwrap_or("")),
                    (Some(t), None) => format!("backed up {}", crate::backup::age(t)),
                    (None, None) => "never backed up".into(),
                }
            }
        };
        println!(
            "Volume:    {:<12} {} {:<28} {backup}",
            v.name,
            if open { "🔓" } else { "🔒" },
            if open {
                v.mountpoint.display().to_string()
            } else {
                "locked".into()
            },
        );
    }
    let secrets = crate::secrets::list().map(|l| l.len()).unwrap_or(0);
    println!("Secrets:   {secrets}");
    let svc = |label| {
        if crate::service::is_installed(label) {
            "installed"
        } else {
            "not installed"
        }
    };
    println!("SSH agent: {}", svc(crate::ssh::AGENT_LABEL));
    println!("Schedule:  {}", svc(crate::backup::SCHEDULE_LABEL));
    if let Some(run) = crate::unseal::unfinished_run() {
        println!(
            "Unseal:    unfinished run in {} — continue with `sealctl unseal --resume`",
            crate::unseal::tilde(&run)
        );
    }
    println!("Leaving the Ledger: sealctl unseal --all");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::utc_date;

    #[test]
    fn formats_utc_dates() {
        assert_eq!(utc_date(0), "1970-01-01T00:00:00Z");
        assert_eq!(utc_date(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(utc_date(1_767_225_600), "2026-01-01T00:00:00Z");
        assert_eq!(utc_date(u32::MAX), "2106-02-07T06:28:15Z");
    }
}
