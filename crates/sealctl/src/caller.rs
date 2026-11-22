//! Who started this process: the chain of parent processes (executable path and arguments, read
//! from the kernel: `/proc` on Linux, `proc_pidinfo`/`proc_pidpath`/`KERN_PROCARGS2` on macOS),
//! and the checks the credential helpers make with it (SPEC 10.6, 11).
//!
//! `sealctl git credential` and `sealctl aws credentials` print a credential, by design, to the
//! program that runs them. Inside an AI agent they answer only when that program is git or the
//! AWS CLI: an agent that runs `git push` or `aws` gets the tool to use the key, while an agent
//! that runs the helper itself (from its shell, `sh -c`, `git credential fill`, …) is refused.
//!
//! This is a check on the process tree, not a security boundary against code running as the same
//! user: such code can name a copy of a shell `git`. The agent hooks and deny rules (section 11)
//! are the other layer; every value given out is still a use of the secret, approved and logged.

use std::path::{Path, PathBuf};

/// One process above this one.
#[derive(Debug, Clone, Default)]
pub struct Proc {
    pub pid: i32,
    pub ppid: i32,
    /// The executable the kernel ran (not `argv[0]`, which the caller chooses).
    pub exe: Option<PathBuf>,
    pub argv: Vec<String>,
}

impl Proc {
    /// The executable's file name (`git`, `bash`, `python3.12`), or `argv[0]`'s if unknown.
    fn name(&self) -> &str {
        self.exe
            .as_deref()
            .and_then(Path::file_name)
            .and_then(|n| n.to_str())
            .or_else(|| self.argv.first().map(|a| base(a)))
            .unwrap_or("")
    }
}

fn base(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// The processes above this one, parent first, at most `max`. Stops at pid 1 or at the first
/// process it can't read.
pub fn ancestors(max: usize) -> Vec<Proc> {
    let mut out = Vec::new();
    let mut pid = std::os::unix::process::parent_id() as i32;
    while pid > 1 && out.len() < max {
        let Some(p) = info(pid) else { break };
        pid = p.ppid;
        out.push(p);
    }
    out
}

#[cfg(target_os = "linux")]
fn info(pid: i32) -> Option<Proc> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // `pid (comm) state ppid …`: comm may hold spaces and parentheses
    let rest = &stat[stat.rfind(')')? + 1..];
    let ppid = rest.split_whitespace().nth(1)?.parse().ok()?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe")).ok();
    let argv = std::fs::read(format!("/proc/{pid}/cmdline"))
        .map(|b| split_nul(&b))
        .unwrap_or_default();
    Some(Proc { pid, ppid, exe, argv })
}

#[cfg(target_os = "macos")]
fn info(pid: i32) -> Option<Proc> {
    use std::ffi::c_void;
    use std::mem::{size_of, MaybeUninit};

    let mut bsd = MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let size = size_of::<libc::proc_bsdinfo>() as i32;
    // SAFETY: the buffer is a zeroed proc_bsdinfo of exactly `size` bytes.
    let n = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDTBSDINFO,
            0,
            bsd.as_mut_ptr() as *mut c_void,
            size,
        )
    };
    if n != size {
        return None;
    }
    // SAFETY: proc_pidinfo filled all `size` bytes.
    let ppid = unsafe { bsd.assume_init() }.pbi_ppid as i32;

    let mut path = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: the buffer holds PROC_PIDPATHINFO_MAXSIZE bytes.
    let n = unsafe { libc::proc_pidpath(pid, path.as_mut_ptr() as *mut c_void, path.len() as u32) };
    let exe = (n > 0).then(|| {
        use std::os::unix::ffi::OsStrExt;
        PathBuf::from(std::ffi::OsStr::from_bytes(&path[..n as usize]))
    });

    Some(Proc {
        pid,
        ppid,
        exe,
        argv: procargs(pid).unwrap_or_default(),
    })
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn info(_pid: i32) -> Option<Proc> {
    None
}

/// `KERN_PROCARGS2`: `argc` (a native int), the executable path, NUL padding, then the
/// arguments, each ending in NUL (then the environment, not read here).
#[cfg(target_os = "macos")]
fn procargs(pid: i32) -> Option<Vec<String>> {
    use std::ffi::c_void;

    let mut argmax: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib = [libc::CTL_KERN, libc::KERN_ARGMAX];
    // SAFETY: `argmax` is a c_int and `size` its size.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            2,
            &mut argmax as *mut libc::c_int as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 || argmax <= 0 {
        return None;
    }
    let mut buf = vec![0u8; argmax as usize];
    let mut size = buf.len();
    let mut mib = [libc::CTL_KERN, libc::KERN_PROCARGS2, pid];
    // SAFETY: `buf` holds `size` bytes; the kernel writes at most that and updates `size`.
    let r = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            3,
            buf.as_mut_ptr() as *mut c_void,
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if r != 0 {
        return None;
    }
    parse_procargs(&buf[..size.min(buf.len())])
}

#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
fn parse_procargs(buf: &[u8]) -> Option<Vec<String>> {
    let argc = i32::from_ne_bytes(buf.get(..4)?.try_into().ok()?);
    let mut rest = &buf[4..];
    // the executable path, then NUL padding
    let end = rest.iter().position(|&b| b == 0)?;
    rest = &rest[end..];
    let start = rest.iter().position(|&b| b != 0)?;
    rest = &rest[start..];
    let mut argv = split_nul(rest);
    argv.truncate(usize::try_from(argc).ok()?);
    Some(argv)
}

fn split_nul(b: &[u8]) -> Vec<String> {
    let b = b.strip_suffix(&[0]).unwrap_or(b);
    if b.is_empty() {
        return Vec::new();
    }
    b.split(|&c| c == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect()
}

/// The program a credential helper serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tool {
    Git,
    Aws,
}

const SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "busybox"];

fn is_shell(p: &Proc) -> bool {
    SHELLS.contains(&p.name())
}

fn is_git(p: &Proc) -> bool {
    let n = p.name();
    n == "git" || n.starts_with("git-")
}

/// A git process asked for a credential on someone else's behalf: `git credential fill` (also
/// through `-c alias.x=credential`), whose answer goes to whoever ran it.
fn is_git_front_end(p: &Proc) -> bool {
    p.argv.iter().skip(1).any(|a| a.contains("credential"))
}

fn is_aws(p: &Proc) -> bool {
    let n = p.name();
    if n == "aws" {
        return true;
    }
    // AWS CLI v1: `python3 /usr/local/bin/aws …`
    n.starts_with("python") && p.argv.get(1).is_some_and(|a| base(a) == "aws")
}

/// Whether `chain` (parent first) shows the helper started by `tool` itself: git (or one of its
/// `git-*` programs) or the AWS CLI, with at most one shell in between (git runs `!` helpers
/// through `sh -c`). A git process that only relays the answer (`git credential fill`) counts
/// only if git started it in turn, as git-lfs and git-send-email do.
pub fn started_by(tool: Tool, chain: &[Proc]) -> bool {
    let mut i = 0;
    // up to 4 relays (git credential fill run by git-lfs run by git …)
    for _ in 0..4 {
        if chain.get(i).is_some_and(is_shell) {
            i += 1;
        }
        let Some(p) = chain.get(i) else { return false };
        match tool {
            Tool::Aws => return is_aws(p),
            Tool::Git if !is_git(p) => return false,
            Tool::Git if !is_git_front_end(p) => return true,
            Tool::Git => i += 1,
        }
    }
    false
}

/// Agents recognised by their process when their environment variables were removed.
const AGENT_PROGRAMS: &[&str] = &[
    "claude",
    "codex",
    "gemini",
    "qwen",
    "opencode",
    "cursor-agent",
    "copilot",
];
const AGENT_PACKAGES: &[&str] = &[
    "@anthropic-ai/claude-code",
    "@openai/codex",
    "@google/gemini-cli",
    "@qwen-code/qwen-code",
    "@github/copilot",
    "opencode-ai",
];

/// The first process in `chain` that is a known AI agent's command line program.
pub fn agent_in(chain: &[Proc]) -> Option<&'static str> {
    chain.iter().find_map(|p| {
        let names = [Some(p.name()), p.argv.first().map(|a| base(a))];
        let by_name = AGENT_PROGRAMS
            .iter()
            .find(|a| names.iter().flatten().any(|n| n == *a));
        let by_package = || {
            AGENT_PACKAGES
                .iter()
                .find(|pkg| p.argv.iter().take(2).any(|a| a.contains(*pkg)))
        };
        by_name.or_else(by_package).map(|_| "an AI agent")
    })
}

/// The rule for `sealctl git credential get` and `sealctl aws credentials`: inside an agent
/// (its variables, or an agent process above this one), only `tool` itself may run the helper.
/// `SEALCTL_AGENT=0` turns agent detection off, as everywhere.
pub fn check_helper(tool: Tool, what: &str) -> anyhow::Result<()> {
    if std::env::var("SEALCTL_AGENT").as_deref() == Ok("0") {
        return Ok(());
    }
    let chain = ancestors(32);
    let agent = crate::guard::ai_agent().or_else(|| agent_in(&chain));
    if agent.is_none() || started_by(tool, &chain) {
        return Ok(());
    }
    let program = match tool {
        Tool::Git => "git",
        Tool::Aws => "the AWS CLI",
    };
    Err(crate::exit::fail(
        crate::exit::REFUSED,
        format!(
            "Not inside an AI agent: {what} answers {program} only. Run {} itself, or use sealctl run -- <command>.",
            match tool {
                Tool::Git => "git push / git fetch",
                Tool::Aws => "aws",
            }
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(exe: &str, argv: &[&str]) -> Proc {
        Proc {
            exe: Some(PathBuf::from(exe)),
            argv: argv.iter().map(|s| s.to_string()).collect(),
            ..Proc::default()
        }
    }

    fn agent() -> Proc {
        p(
            "/opt/homebrew/bin/node",
            &["node", "/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js"],
        )
    }
    fn agent_shell() -> Proc {
        p(
            "/bin/zsh",
            &["/bin/zsh", "-c", "-l", "eval 'sealctl git credential get'"],
        )
    }

    #[test]
    fn git_itself_may_ask() {
        // git push → git-remote-https → sh -c '<sealctl> git credential get'
        let chain = [
            p(
                "/bin/sh",
                &["/bin/sh", "-c", "'/usr/local/bin/sealctl' git credential get"],
            ),
            p(
                "/usr/libexec/git-core/git-remote-https",
                &["git-remote-https", "origin", "https://github.com/a/b"],
            ),
            p("/usr/bin/git", &["git", "push"]),
            agent_shell(),
            agent(),
        ];
        assert!(started_by(Tool::Git, &chain));
        // without the shell (a helper configured without `!`)
        assert!(started_by(Tool::Git, &chain[1..]));
        // git-lfs runs `git credential fill`, which runs the helper
        let lfs = [
            p("/bin/sh", &["sh", "-c", "sealctl git credential get"]),
            p("/usr/bin/git", &["git", "credential", "fill"]),
            p("/opt/homebrew/bin/git-lfs", &["git-lfs", "pre-push", "origin"]),
            p("/bin/sh", &["sh", "-c", "git lfs pre-push \"$@\""]),
            p("/usr/bin/git", &["git", "push"]),
            agent(),
        ];
        assert!(started_by(Tool::Git, &lfs));
    }

    #[test]
    fn an_agent_may_not_ask_directly() {
        for chain in [
            // the agent's shell runs the helper
            vec![agent_shell(), agent()],
            // the agent itself execs it
            vec![agent()],
            // through sh -c
            vec![
                p("/bin/sh", &["sh", "-c", "sealctl git credential get"]),
                agent_shell(),
                agent(),
            ],
            // through `git credential fill`, run by the agent
            vec![
                p("/bin/sh", &["sh", "-c", "sealctl git credential get"]),
                p("/usr/bin/git", &["git", "credential", "fill"]),
                agent_shell(),
                agent(),
            ],
            // through a git alias that runs `git credential fill`
            vec![
                p("/bin/sh", &["sh", "-c", "sealctl git credential get"]),
                p("/usr/bin/git", &["git", "credential", "fill"]),
                p("/bin/sh", &["sh", "-c", "git credential fill"]),
                p(
                    "/usr/bin/git",
                    &["git", "-c", "alias.x=!git credential fill", "x"],
                ),
                agent_shell(),
                agent(),
            ],
            // two shells deep
            vec![
                p("/bin/sh", &["sh", "-c", "x"]),
                p("/bin/bash", &["bash", "-c", "x"]),
                p("/usr/bin/git", &["git", "push"]),
            ],
            // a program that only calls itself git (argv[0]); the executable is bash
            vec![p("/bin/bash", &["git", "push"]), agent()],
            vec![],
        ] {
            assert!(!started_by(Tool::Git, &chain), "{chain:?}");
        }
    }

    #[test]
    fn aws_cli_itself_may_ask() {
        assert!(started_by(
            Tool::Aws,
            &[p("/usr/local/aws-cli/aws", &["aws", "s3", "ls"]), agent()]
        ));
        assert!(started_by(
            Tool::Aws,
            &[p(
                "/usr/bin/python3.12",
                &["python3", "/usr/local/bin/aws", "s3", "ls"]
            )]
        ));
        for chain in [
            vec![agent_shell(), agent()],
            vec![
                p("/usr/bin/python3.12", &["python3", "-c", "import subprocess"]),
                agent(),
            ],
            vec![
                p("/bin/sh", &["sh", "-c", "sealctl aws credentials"]),
                agent_shell(),
            ],
            vec![p("/usr/bin/git", &["git", "push"])],
            vec![p("/bin/bash", &["aws"])],
        ] {
            assert!(!started_by(Tool::Aws, &chain), "{chain:?}");
        }
    }

    #[test]
    fn agents_by_process() {
        assert!(agent_in(&[agent_shell(), agent()]).is_some());
        assert!(agent_in(&[p("/Users/u/.local/share/claude/versions/2.1.0", &["claude"])]).is_some());
        assert!(agent_in(&[p("/opt/homebrew/bin/codex", &["codex", "exec"])]).is_some());
        assert!(agent_in(&[
            p("/bin/zsh", &["-zsh"]),
            p("/Applications/iTerm.app/Contents/MacOS/iTerm2", &["iTerm2"]),
        ])
        .is_none());
        // a package name further down the arguments is not the program
        assert!(agent_in(&[p(
            "/usr/bin/npm",
            &["npm", "view", "x", "@anthropic-ai/claude-code"]
        )])
        .is_none());
    }

    #[test]
    fn procargs_layout() {
        let mut b = 3i32.to_ne_bytes().to_vec();
        b.extend_from_slice(b"/usr/bin/git\0\0\0\0git\0push\0origin\0HOME=/x\0");
        assert_eq!(parse_procargs(&b).unwrap(), ["git", "push", "origin"]);
        assert!(parse_procargs(b"\x01").is_none());
    }

    #[test]
    fn this_process_has_a_parent() {
        let chain = ancestors(4);
        let me = std::os::unix::process::parent_id() as i32;
        assert_eq!(chain.first().map(|p| p.pid), Some(me));
        assert!(chain[0].exe.is_some(), "{:?}", chain[0]);
        assert!(!chain[0].argv.is_empty(), "{:?}", chain[0]);
    }
}
