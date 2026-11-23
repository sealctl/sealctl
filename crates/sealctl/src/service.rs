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
    let schedule = match s.every_secs {
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
        label = s.label,
        path = xml_escape(path_env),
        log = xml_escape(log),
    )
}

fn systemd_service(s: &Service, path_env: &str) -> String {
    let exec = s
        .args
        .iter()
        .map(|a| systemd_quote(a))
        .collect::<Vec<_>>()
        .join(" ");
    // A long-running daemon gets SIGTERM alone (`KillMode=mixed`): it stops its own restic
    // child with SIGINT. Whatever is left gets SIGKILL after the stop timeout.
    let (svc_type, extra) = if s.every_secs.is_some() {
        ("oneshot", String::new())
    } else {
        (
            "simple",
            format!("Restart=on-failure\nKillMode=mixed\nTimeoutStopSec={STOP_TIMEOUT_SECS}\n"),
        )
    };
    format!(
        "[Unit]\nDescription={}\n\n[Service]\nType={svc_type}\nEnvironment={}\nExecStart={exec}\n{extra}\n[Install]\nWantedBy=default.target\n",
        s.description,
        systemd_quote(&format!("PATH={path_env}"))
    )
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

    #[test]
    fn quoting() {
        assert_eq!(super::systemd_quote("/a b/sealctl"), "\"/a b/sealctl\"");
        assert_eq!(super::systemd_quote("100%$HOME\"x"), "\"100%%$$HOME\\\"x\"");
    }
}
