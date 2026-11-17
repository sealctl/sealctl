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
    format!("sealctl-{}", label.rsplit('.').next().unwrap_or(label))
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
    let log = paths::state_dir()?.join(format!("{}.log", unit_name(s.label)));
    fs::create_dir_all(paths::state_dir()?)?;
    // Services run with a minimal PATH; keep the user's so restic/ssh-keygen are found.
    let path_env =
        std::env::var("PATH").unwrap_or_else(|_| "/usr/local/bin:/opt/homebrew/bin:/usr/bin:/bin".into());

    if cfg!(target_os = "macos") {
        let args: String = s
            .args
            .iter()
            .map(|a| format!("    <string>{}</string>\n", xml_escape(a)))
            .collect();
        let schedule = match s.every_secs {
            Some(secs) => format!("  <key>StartInterval</key><integer>{secs}</integer>\n"),
            None => "  <key>KeepAlive</key><true/>\n".into(),
        };
        let plist = format!(
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
            path = xml_escape(&path_env),
            log = xml_escape(&log.to_string_lossy()),
        );
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
        let exec = s
            .args
            .iter()
            .map(|a| systemd_quote(a))
            .collect::<Vec<_>>()
            .join(" ");
        let (svc_type, restart) = if s.every_secs.is_some() {
            ("oneshot", "")
        } else {
            ("simple", "Restart=on-failure\n")
        };
        fs::write(
            dir.join(format!("{name}.service")),
            format!(
                "[Unit]\nDescription={}\n\n[Service]\nType={svc_type}\nEnvironment={}\nExecStart={exec}\n{restart}\n[Install]\nWantedBy=default.target\n",
                s.description,
                systemd_quote(&format!("PATH={path_env}"))
            ),
        )?;
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

pub fn uninstall(label: &str) -> Result<()> {
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
    println!("removed {label}");
    Ok(())
}

pub fn is_installed(label: &str) -> bool {
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
    #[test]
    fn quoting() {
        assert_eq!(super::systemd_quote("/a b/sealctl"), "\"/a b/sealctl\"");
        assert_eq!(super::systemd_quote("100%$HOME\"x"), "\"100%%$$HOME\\\"x\"");
    }
}
