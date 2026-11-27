//! User-level background services: launchd agents on macOS, systemd user units on Linux.

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{bail, Context, Result};

use crate::paths;

pub struct Service<'a> {
    /// Reverse-DNS label (macOS) — the systemd unit name is derived from it.
    pub label: &'a str,
    pub args: Vec<String>,
    /// Run periodically (timer) instead of keeping a long-running process alive.
    pub every_secs: Option<u64>,
    pub description: &'a str,
}

fn home() -> Result<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).context("$HOME")
}

fn uid() -> String {
    String::from_utf8_lossy(
        &Command::new("id")
            .arg("-u")
            .output()
            .map(|o| o.stdout)
            .unwrap_or_default(),
    )
    .trim()
    .to_string()
}

fn unit_name(label: &str) -> String {
    if label == DAEMON_LABEL {
        return "sealctl".into();
    }
    format!("sealctl-{}", label.rsplit('.').next().unwrap_or(label))
}

/// The session daemon's service label.
pub const DAEMON_LABEL: &str = "com.sealctl.daemon";
/// The backup schedule's label.
pub const BACKUP_LABEL: &str = "com.sealctl.backup";

/// Whether login services may be installed here. Not when `SEALCTL_NO_SERVICE` is set, and not
/// when `$HOME` is not this user's home folder (a temporary HOME for tests or trials): a
/// launchd or systemd unit would be loaded into the real login session.
pub fn allowed() -> bool {
    if std::env::var_os("SEALCTL_NO_SERVICE").is_some_and(|v| !v.is_empty()) {
        return false;
    }
    let Ok(home) = home() else { return false };
    match nix::unistd::User::from_uid(nix::unistd::getuid()) {
        Ok(Some(u)) => crate::volume::same_path(&u.dir, &home),
        _ => false,
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

fn plist_path(label: &str) -> Result<PathBuf> {
    Ok(home()?
        .join("Library/LaunchAgents")
        .join(format!("{label}.plist")))
}

pub fn install(s: &Service) -> Result<()> {
    if !allowed() {
        bail!("login services are not installed from a temporary HOME or with SEALCTL_NO_SERVICE");
    }
    let log = paths::state_dir()?.join(format!("{}.log", unit_name(s.label)));
    fs::create_dir_all(paths::state_dir()?)?;
    // Services run with a minimal PATH; keep the user's so restic/ssh-keygen are found.
    let path_env =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin".into());

    if cfg!(target_os = "macos") {
        let plist = launchd_plist(s, &path_env, &log.to_string_lossy());
        let p = plist_path(s.label)?;
        fs::create_dir_all(p.parent().context("dir")?)?;
        let _ = crate::util::system_cmd("launchctl")
            .args(["bootout", &format!("gui/{}", uid())])
            .arg(&p)
            .output();
        fs::write(&p, plist)?;
        let out = crate::util::system_cmd("launchctl")
            .args(["bootstrap", &format!("gui/{}", uid())])
            .arg(&p)
            .output()?;
        if !out.status.success() {
            bail!(
                "launchctl bootstrap failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
    } else {
        let dir = home()?.join(".config/systemd/user");
        fs::create_dir_all(&dir)?;
        let name = unit_name(s.label);
        fs::write(dir.join(format!("{name}.service")), systemd_service(s, &path_env))?;
        let mut enable = format!("{name}.service");
        if let Some(secs) = s.every_secs {
            fs::write(
                dir.join(format!("{name}.timer")),
                format!(
                    "[Unit]\nDescription={}\n\n[Timer]\nOnBootSec=5min\nOnUnitActiveSec={secs}s\nPersistent=true\n\n[Install]\nWantedBy=timers.target\n",
                    s.description
                ),
            )?;
            enable = format!("{name}.timer");
        }
        run(crate::util::system_cmd("systemctl").args(["--user", "daemon-reload"]))?;
        run(crate::util::system_cmd("systemctl").args(["--user", "enable", "--now", &enable]))?;
    }
    Ok(())
}

/// How long the service manager lets the daemon stop (SIGTERM, then SIGKILL): the exit locks,
/// stops on-lock backups still running (restic has 10 s to remove its repository lock),
/// unmounts and tells the phone.
const STOP_TIMEOUT_SECS: u64 = 60;

fn launchd_plist(s: &Service, path_env: &str, log: &str) -> String {
    let args: String = s
        .args
        .iter()
        .map(|a| format!("    <string>{}</string>\n", xml_escape(a)))
        .collect();
    render_plist(
        s.label,
        &args,
        s.every_secs,
        &xml_escape(path_env),
        &xml_escape(log),
    )
}

/// The plist text, from its parts as written in it (`args`: the `<string>` lines; `path`
/// and `log` already escaped).
fn render_plist(label: &str, args: &str, every_secs: Option<u64>, path: &str, log: &str) -> String {
    let schedule = match every_secs {
        Some(secs) => format!("  <key>StartInterval</key><integer>{secs}</integer>\n"),
        None => format!(
            "  <key>KeepAlive</key><true/>\n  <key>ExitTimeOut</key><integer>{STOP_TIMEOUT_SECS}</integer>\n"
        ),
    };
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}  </array>
  <key>RunAtLoad</key><true/>
{schedule}  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>{path}</string></dict>
  <key>StandardOutPath</key><string>{log}</string>
  <key>StandardErrorPath</key><string>{log}</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
"#,
    )
}

fn systemd_service(s: &Service, path_env: &str) -> String {
    let exec = s
        .args
        .iter()
        .map(|a| systemd_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    render_unit(
        s.description,
        s.every_secs,
        &systemd_quote(&format!("PATH={path_env}")),
        &exec,
    )
}

/// The unit text, from its parts as written in it (`environment` and `exec` already quoted).
fn render_unit(description: &str, every_secs: Option<u64>, environment: &str, exec: &str) -> String {
    // A long-running daemon gets SIGTERM alone (`KillMode=mixed`): it stops its own restic
    // child with SIGINT. Whatever is left gets SIGKILL after the stop timeout.
    let (svc_type, extra) = if every_secs.is_some() {
        ("oneshot", String::new())
    } else {
        (
            "simple",
            format!("Restart=on-failure\nKillMode=mixed\nTimeoutStopSec={STOP_TIMEOUT_SECS}\n"),
        )
    };
    format!(
        "[Unit]\nDescription={description}\n\n[Service]\nType={svc_type}\nEnvironment={environment}\nExecStart={exec}\n{extra}\n[Install]\nWantedBy=default.target\n",
    )
}

/// The text between `start` and the next `end` in `text`.
fn between<'a>(text: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = &text[text.find(start)? + start.len()..];
    Some(&rest[..rest.find(end)?])
}

/// What this version writes for the daemon's service file `text` (`launchd`: a plist, else a
/// systemd unit), keeping what came from where it was installed (the program and its
/// arguments, `PATH`, the log file) as written in it. `None` when `text` is not one sealctl
/// wrote for the daemon (changed by hand): such a file is left as it is. Only the lines a
/// version changed may differ (0.7.0: the stop timeout); a version that changes another line
/// names it here too.
fn daemon_file_now(text: &str, launchd: bool) -> Option<String> {
    if launchd {
        if between(text, "<key>Label</key><string>", "</string>")? != DAEMON_LABEL {
            return None;
        }
        let args = between(text, "<key>ProgramArguments</key>\n  <array>\n", "  </array>\n")?;
        let path = between(text, "<key>PATH</key><string>", "</string>")?;
        let log = between(text, "<key>StandardOutPath</key><string>", "</string>")?;
        let now = render_plist(DAEMON_LABEL, args, None, path, log);
        // only the lines this version changed may differ
        same_but(text, &now, &["ExitTimeOut"]).then_some(now)
    } else {
        let line = |key: &str| text.lines().find_map(|l| l.strip_prefix(key));
        let description = line("Description=")?;
        let environment = line("Environment=")?;
        let exec = line("ExecStart=")?;
        let now = render_unit(description, None, environment, exec);
        same_but(text, &now, &["KillMode=", "TimeoutStopSec="]).then_some(now)
    }
}

/// Whether `a` and `b` have the same lines once the lines that contain one of `keys` are
/// left out of both.
fn same_but(a: &str, b: &str, keys: &[&str]) -> bool {
    let rest = |t: &str| -> Vec<String> {
        t.lines()
            .filter(|l| !keys.iter().any(|k| l.contains(k)))
            .map(str::to_string)
            .collect()
    };
    rest(a) == rest(b)
}

/// Rewrites the daemon's service file at `path` when it differs from what this version
/// writes ([`daemon_file_now`]). The new text goes to a file beside it that is then renamed
/// over it, so the service manager never reads half a file. A missing file, a symbolic link
/// (a unit managed elsewhere, e.g. by Nix) and a file changed by hand are left alone.
/// Returns whether it was rewritten.
fn refresh_file(path: &std::path::Path, launchd: bool) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(m) if m.file_type().is_file() => {}
        Ok(_) => return Ok(false),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e.into()),
    }
    let text = fs::read_to_string(path)?;
    if !launchd && text.contains("\nType=oneshot\n") {
        return Ok(false);
    }
    let Some(now) = daemon_file_now(&text, launchd) else {
        log::info!("{} was changed by hand; left as it is", path.display());
        return Ok(false);
    };
    if now == text {
        return Ok(false);
    }
    let name = path.file_name().context("service file name")?.to_string_lossy();
    let tmp = path.with_file_name(format!(".{name}.new"));
    fs::write(&tmp, &now)?;
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(&tmp, fs::Permissions::from_mode(0o644))?;
    fs::rename(&tmp, path)?;
    Ok(true)
}

/// At the start of a daemon run by its login service: brings the service file that an
/// earlier version installed up to what this version writes (the stop timeout, SPEC 6.1),
/// without stopping this daemon.
///
/// The file is replaced first (written beside it, then renamed over it). Then:
/// - systemd: `systemctl --user daemon-reload`, which reads the unit again and leaves running
///   services running; the new stop settings apply to this daemon's next stop. Never `restart`.
/// - launchd: nothing more. launchd reads the plist only when the job is loaded (the next
///   login, or the reinstall of `sealctl pair`). Loading it now takes `launchctl bootout`,
///   which stops the job's running process, this daemon, with the old timeout, and would end
///   the `bootstrap` that must follow along with it.
///
/// Not from a temporary HOME or with `SEALCTL_NO_SERVICE` ([`allowed`]). Errors are logged.
pub fn refresh_daemon() {
    if !allowed() {
        return;
    }
    let launchd = cfg!(target_os = "macos");
    let path = if launchd {
        plist_path(DAEMON_LABEL)
    } else {
        home().map(|h| {
            h.join(".config/systemd/user")
                .join(format!("{}.service", unit_name(DAEMON_LABEL)))
        })
    };
    let r = path.and_then(|p| {
        if !refresh_file(&p, launchd)? {
            return Ok(());
        }
        log::info!("updated {}", p.display());
        if !launchd {
            run(crate::util::system_cmd("systemctl").args(["--user", "daemon-reload"]))?;
        }
        Ok(())
    });
    if let Err(e) = r {
        log::warn!("service file: {e:#}");
    }
}

pub fn uninstall(label: &str) -> Result<()> {
    if !allowed() {
        return Ok(());
    }
    if cfg!(target_os = "macos") {
        let p = plist_path(label)?;
        let _ = crate::util::system_cmd("launchctl")
            .args(["bootout", &format!("gui/{}", uid())])
            .arg(&p)
            .output();
        let _ = fs::remove_file(&p);
    } else {
        let name = unit_name(label);
        for u in [format!("{name}.timer"), format!("{name}.service")] {
            let _ = crate::util::system_cmd("systemctl")
                .args(["--user", "disable", "--now", &u])
                .output();
            let _ = fs::remove_file(home()?.join(".config/systemd/user").join(u));
        }
        let _ = crate::util::system_cmd("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
    }
    log::info!("removed {label}");
    Ok(())
}

pub fn is_installed(label: &str) -> bool {
    if !allowed() {
        return false;
    }
    if cfg!(target_os = "macos") {
        crate::util::system_cmd("launchctl")
            .args(["print", &format!("gui/{}/{label}", uid())])
            .output()
            .is_ok_and(|o| o.status.success())
    } else {
        let name = unit_name(label);
        [format!("{name}.timer"), format!("{name}.service")]
            .iter()
            .any(|u| {
                crate::util::system_cmd("systemctl")
                    .args(["--user", "is-enabled", u])
                    .output()
                    .is_ok_and(|o| o.status.success())
            })
    }
}

fn run(cmd: &mut Command) -> Result<()> {
    let out = cmd.output()?;
    if !out.status.success() {
        bail!(
            "{:?} failed: {}",
            cmd.get_program(),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// One systemd.service word: double-quoted with C escapes, and `%` / `$` doubled so systemd
/// doesn't expand specifiers or variables inside paths.
fn systemd_quote(a: &str) -> String {
    let mut out = String::from("\"");
    for c in a.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '%' => out.push_str("%%"),
            '$' => out.push_str("$$"),
            '\n' => out.push_str("\\n"),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod systemd_tests {
    use super::*;

    fn daemon() -> Service<'static> {
        Service {
            label: DAEMON_LABEL,
            args: vec!["/usr/local/bin/sealctl".into(), "daemon".into()],
            every_secs: None,
            description: "sealctl session daemon",
        }
    }

    #[test]
    fn the_daemon_has_time_to_lock_when_stopped() {
        let plist = launchd_plist(&daemon(), "/usr/bin", "/tmp/sealctl.log");
        assert!(
            plist.contains("<key>ExitTimeOut</key><integer>60</integer>"),
            "{plist}"
        );
        let unit = systemd_service(&daemon(), "/usr/bin");
        assert!(unit.contains("\nKillMode=mixed\n"), "{unit}");
        assert!(unit.contains("\nTimeoutStopSec=60\n"), "{unit}");
        assert!(unit.contains("\nRestart=on-failure\n"), "{unit}");
        // a timer job keeps the defaults
        let timer = Service {
            every_secs: Some(3600),
            ..daemon()
        };
        assert!(!launchd_plist(&timer, "/usr/bin", "/tmp/x.log").contains("ExitTimeOut"));
        assert!(systemd_service(&timer, "/usr/bin").contains("Type=oneshot\n"));
    }

    /// The daemon's plist as versions before 0.7.0 wrote it (no `ExitTimeOut`: launchd's 20 s).
    const OLD_PLIST: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.sealctl.daemon</string>
  <key>ProgramArguments</key>
  <array>
    <string>/opt/homebrew/bin/sealctl</string>
    <string>daemon</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>EnvironmentVariables</key>
  <dict><key>PATH</key><string>/opt/homebrew/bin:/a&amp;b:/usr/bin</string></dict>
  <key>StandardOutPath</key><string>/Users/u/.local/state/sealctl/sealctl.log</string>
  <key>StandardErrorPath</key><string>/Users/u/.local/state/sealctl/sealctl.log</string>
  <key>ProcessType</key><string>Background</string>
</dict>
</plist>
"#;

    /// The daemon's unit as versions before 0.7.0 wrote it (no `KillMode`, no stop timeout).
    const OLD_UNIT: &str = "[Unit]\nDescription=sealctl session daemon\n\n[Service]\nType=simple\nEnvironment=\"PATH=/usr/bin:/a b\"\nExecStart=\"/home/u/.local/bin/sealctl\" \"daemon\"\nRestart=on-failure\n\n[Install]\nWantedBy=default.target\n";

    #[test]
    fn a_service_file_from_an_earlier_version_gets_the_stop_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let plist = dir.path().join("com.sealctl.daemon.plist");
        std::fs::write(&plist, OLD_PLIST).unwrap();
        assert!(refresh_file(&plist, true).unwrap());
        let s = Service {
            args: vec!["/opt/homebrew/bin/sealctl".into(), "daemon".into()],
            ..daemon()
        };
        // what `sealctl pair` writes today, with the program, PATH and log it was installed with
        assert_eq!(
            std::fs::read_to_string(&plist).unwrap(),
            launchd_plist(
                &s,
                "/opt/homebrew/bin:/a&b:/usr/bin",
                "/Users/u/.local/state/sealctl/sealctl.log"
            )
        );
        assert!(!refresh_file(&plist, true).unwrap(), "up to date: left alone");

        let unit = dir.path().join("sealctl.service");
        std::fs::write(&unit, OLD_UNIT).unwrap();
        assert!(refresh_file(&unit, false).unwrap());
        let s = Service {
            args: vec!["/home/u/.local/bin/sealctl".into(), "daemon".into()],
            ..daemon()
        };
        assert_eq!(
            std::fs::read_to_string(&unit).unwrap(),
            systemd_service(&s, "/usr/bin:/a b")
        );
        assert!(!refresh_file(&unit, false).unwrap());
        assert!(!dir.path().join(".sealctl.service.new").exists());
    }

    #[test]
    fn a_service_file_changed_by_hand_or_linked_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let unit = dir.path().join("sealctl.service");
        assert!(!refresh_file(&unit, false).unwrap(), "no file");
        let edited = OLD_UNIT.replace("Restart=on-failure\n", "Restart=always\nNice=5\n");
        std::fs::write(&unit, &edited).unwrap();
        assert!(!refresh_file(&unit, false).unwrap());
        assert_eq!(std::fs::read_to_string(&unit).unwrap(), edited);
        let plist = dir.path().join("p.plist");
        let other = OLD_PLIST.replace("com.sealctl.daemon", "com.example.other");
        std::fs::write(&plist, &other).unwrap();
        assert!(!refresh_file(&plist, true).unwrap());
        assert_eq!(std::fs::read_to_string(&plist).unwrap(), other);
        // a unit managed elsewhere (a link into a read-only store)
        let target = dir.path().join("managed.service");
        std::fs::write(&target, OLD_UNIT).unwrap();
        let link = dir.path().join("linked.service");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(!refresh_file(&link, false).unwrap());
        assert_eq!(std::fs::read_to_string(&target).unwrap(), OLD_UNIT);
    }

    #[test]
    fn quoting() {
        assert_eq!(super::systemd_quote("/a b/sealctl"), "\"/a b/sealctl\"");
        assert_eq!(super::systemd_quote("100%$HOME\"x"), "\"100%%$$HOME\\\"x\"");
    }
}
