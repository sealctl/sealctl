//! `sealctl pair` and `sealctl unpair` (SPEC 8).

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use qrcode::{Color, EcLevel, QrCode};
use sealctl_core::pairing::{verify_pairing_proof, PairingLink};
use sealctl_core::MachineKeys;

use crate::config::{self, Config, DEFAULT_RELAY};
use crate::exit::{self, fail};
use crate::machine::{self, MachineFile};
use crate::relay::Relay;
use crate::{licence, paths, service, term};

/// How long a pairing code lives.
pub const PAIRING_SECS: u64 = 600;

/// Options of `sealctl pair`.
pub struct PairOpts {
    /// `--name`.
    pub name: Option<String>,
    /// `--force`.
    pub force: bool,
    /// `--relay`.
    pub relay: Option<String>,
}

/// The QR code as UTF-8 half blocks with a quiet zone of 2, dark modules dark.
pub fn qr_text(link: &str, colour: bool) -> Result<String> {
    let code = QrCode::with_error_correction_level(link.as_bytes(), EcLevel::M)
        .map_err(|e| anyhow::anyhow!("QR code: {e:?}"))?;
    let w = code.width() as isize;
    let colors = code.to_colors();
    let q = 2isize;
    let size = w + 2 * q;
    let dark = |x: isize, y: isize| {
        let (x, y) = (x - q, y - q);
        x >= 0 && y >= 0 && x < w && y < w && colors[(y * w + x) as usize] == Color::Dark
    };
    let mut out = String::new();
    let mut y = 0;
    while y < size {
        if colour {
            out.push_str("\x1b[30;107m");
        }
        for x in 0..size {
            let (t, b) = (dark(x, y), dark(x, y + 1));
            // With colour: black on white, so the code reads on any terminal theme.
            // Without: blocks are the dark modules.
            out.push(match (t, b) {
                (true, true) => '█',
                (true, false) => '▀',
                (false, true) => '▄',
                (false, false) => ' ',
            });
        }
        if colour {
            out.push_str("\x1b[0m");
        }
        out.push('\n');
        y += 2;
    }
    Ok(out)
}

fn valid_name(n: &str) -> bool {
    let c = n.chars().count();
    (1..=200).contains(&c) && !n.chars().any(char::is_control)
}

/// `sealctl pair`.
pub fn pair(opts: PairOpts) -> Result<()> {
    let person = term::is_person();
    if machine::is_paired() {
        let label = machine::load()
            .map(|p| p.label())
            .unwrap_or_else(|_| "this machine".into());
        if person && !opts.force {
            if !term::confirm(
                &format!("This machine is paired as {label}. Pair again? This replaces its pairing."),
                false,
            )? {
                return Ok(());
            }
        } else if !opts.force {
            return Err(fail(
                exit::USAGE,
                format!("This machine is paired as {label}. To replace the pairing: sealctl pair --force"),
            ));
        }
    }
    let origin = config::relay_for_pairing(opts.relay.as_deref())?;
    let relay = Relay::new(&origin)?;
    let keys = MachineKeys::generate().map_err(|e| anyhow::anyhow!("{e}"))?;
    let mut code = zeroize::Zeroizing::new([0u8; 16]);
    getrandom::fill(code.as_mut()).map_err(|e| anyhow::anyhow!("system RNG failed: {e}"))?;
    let name = opts.name.unwrap_or_else(machine::default_name);
    if !valid_name(&name) {
        return Err(fail(exit::USAGE, "--name must be 1 to 200 characters."));
    }
    let os: String = machine::os_name().chars().take(200).collect();
    let model = machine::model();
    let hint = machine::hint();
    let expires = machine::now_ms() / 1000 + PAIRING_SECS;
    let link = PairingLink {
        machine: keys.public(),
        machine_box: keys.box_public(),
        code: &code,
        name: &name,
        os: &os,
        model: model.as_deref(),
        hint: hint.as_deref(),
        expires,
        relay: (origin != DEFAULT_RELAY).then_some(origin.as_str()),
    }
    .link();

    if term::stderr_tty() && std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        let colour = std::env::var_os("NO_COLOR").is_none();
        let mut err = std::io::stderr().lock();
        writeln!(err, "{}", qr_text(&link, colour)?)?;
        writeln!(
            err,
            "Scan with the sealctl app on your phone. Or open this link on the phone:"
        )?;
        writeln!(err, "{link}")?;
        writeln!(err, "Waiting for your phone (10 min)")?;
    } else {
        println!("{link}");
        std::io::stdout().flush()?;
        eprintln!("Waiting for your phone (10 min)");
    }

    let rt = crate::relay::runtime()?;
    let (phone, phone_box) = rt.block_on(async {
        let path = format!("/v1/machines/{}", keys.id());
        loop {
            if machine::now_ms() / 1000 >= expires {
                return Err(fail(
                    exit::NO_ANSWER,
                    "The pairing code expired. Run: sealctl pair",
                ));
            }
            let a = relay.request(Some(&keys), "GET", &path, None).await?;
            match a.status {
                200 => {
                    let phone = a.body["phone"].as_str().unwrap_or("").to_string();
                    let proof = a.body["proof"].as_str().unwrap_or("");
                    let p = machine::decode_key32(&phone).ok_or_else(|| {
                        fail(
                            exit::ERROR,
                            "This pairing did not come from your phone. Run sealctl pair again.",
                        )
                    })?;
                    let x = verify_pairing_proof(&code, keys.public(), &p, proof).map_err(|_| {
                        fail(
                            exit::ERROR,
                            "This pairing did not come from your phone. Run sealctl pair again.",
                        )
                    })?;
                    return Ok((phone, machine::b64u(&x)));
                }
                404 => tokio::time::sleep(Duration::from_secs(2)).await,
                _ => return Err(crate::relay::error_for(&a)),
            }
        }
    })?;

    // A daemon of the old pairing holds old keys: stop it before switching.
    crate::daemon::client::stop_running();
    let file = MachineFile::new(&keys, &name, &origin, &phone, &phone_box)?;
    file.save()?;
    let mut cfg = Config::load()?;
    if cfg.store.is_none() {
        let id = sealctl_core::ids::new_uuid().map_err(|e| anyhow::anyhow!("{e}"))?;
        let dir = paths::store_root()?.join(&id);
        paths::ensure_private_dir(&paths::store_root()?)?;
        paths::ensure_private_dir(&dir)?;
        cfg.store = Some(paths::tilde(&dir));
    }
    cfg.save()?;
    install_service();
    println!("Paired: {} #{}", file.name, file.tag);
    if person && licence::first_pairing() {
        eprintln!("Free to use. If it earns its place, $5.99 once keeps the relay running: sealctl buy");
    }
    Ok(())
}

/// Installs the daemon's login service where allowed; otherwise the CLI starts the daemon.
pub fn install_service() {
    if !service::allowed() {
        return;
    }
    let Ok(exe) = crate::util::stable_exe() else {
        return;
    };
    let r = service::install(&service::Service {
        label: service::DAEMON_LABEL,
        args: vec![exe.to_string_lossy().into_owned(), "daemon".into()],
        every_secs: None,
        description: "sealctl session daemon",
    });
    if let Err(e) = r {
        eprintln!(
            "sealctl: could not install the login service ({e:#}); sealctl starts the daemon when needed."
        );
    }
}

/// `sealctl unpair`.
pub fn unpair(yes: bool, relay_flag: Option<&str>) -> Result<()> {
    term::refuse_agent("sealctl unpair")?;
    let paired = machine::load_for(relay_flag)?;
    if !yes {
        if !term::is_person() {
            return Err(fail(exit::REFUSED, "Unpairing needs a terminal. Use --yes."));
        }
        if !term::confirm(&format!("Unpair {}?", paired.label()), false)? {
            return Ok(());
        }
    }
    let relay = Relay::new(&paired.file.relay)?;
    let rt = crate::relay::runtime()?;
    let path = format!(
        "/v1/phones/{}/machines/{}",
        paired.phone_id(),
        paired.file.machine
    );
    let gone = rt.block_on(async { relay.request(Some(&paired.keys), "DELETE", &path, None).await });
    match gone {
        Ok(a) if a.ok() || a.status == 404 || a.status == 403 => {}
        Ok(a) => return Err(crate::relay::error_for(&a)),
        Err(_) => eprintln!(
            "sealctl: The relay could not be reached. Unpair {} on your phone.",
            paired.file.name
        ),
    }
    crate::daemon::client::lock_and_stop();
    service::uninstall(service::DAEMON_LABEL)?;
    machine::forget()?;
    eprintln!("Unpaired {}.", paired.label());
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn qr_renders() {
        let t = super::qr_text("https://sealctl.com/p#v=1", false).unwrap();
        assert!(t.lines().count() > 10);
        assert!(t.contains('█'));
    }
}
