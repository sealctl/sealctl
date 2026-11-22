//! Who is reading (SPEC 5.2): a person at a terminal, an AI agent, or a pipe, CI or service.

use std::io::IsTerminal;

use anyhow::Result;

use crate::exit::{self, fail};

/// Who reads this process's output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reader {
    /// stdin and stderr are terminals, no agent, no `CI`.
    Person,
    /// Agent environment variables or `SEALCTL_AGENT=1`.
    Agent(&'static str),
    /// A pipe, CI or a service.
    Pipe,
}

/// The current reader.
pub fn reader() -> Reader {
    if let Some(a) = crate::guard::ai_agent() {
        return Reader::Agent(a);
    }
    if std::env::var_os("CI").is_some() || !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal()
    {
        return Reader::Pipe;
    }
    Reader::Person
}

/// A person at a terminal (prompts allowed, the ask may show).
pub fn is_person() -> bool {
    reader() == Reader::Person
}

/// stderr is a terminal (QR codes, rewritten lines).
pub fn stderr_tty() -> bool {
    std::io::stderr().is_terminal()
}

/// Refuses inside an AI agent (exit 8).
pub fn refuse_agent(what: &str) -> Result<()> {
    if crate::guard::ai_agent().is_some() {
        return Err(exit::agent_refusal(what));
    }
    Ok(())
}

/// Needs a person at a terminal: refused inside an agent, and without terminals (exit 8).
pub fn require_person(what: &str, flag_hint: Option<&str>) -> Result<()> {
    refuse_agent(what)?;
    if !std::io::stdin().is_terminal() || !std::io::stderr().is_terminal() {
        let hint = flag_hint.map(|f| format!(" Use {f}.")).unwrap_or_default();
        return Err(fail(
            exit::REFUSED,
            format!("This needs a terminal: {what}.{hint}"),
        ));
    }
    Ok(())
}

/// `Waiting for your phone`, with the number when one is shown.
pub fn waiting_line(number: Option<u8>, level3: bool) -> String {
    match number {
        Some(n) if level3 => format!("Waiting for your phone. On your phone, pick {n}."),
        Some(n) => format!("Waiting for your phone. On your phone, pick {n} if it asks."),
        None => "Waiting for your phone".into(),
    }
}

/// Asks a yes/no question on the terminal; `default` for an empty answer.
pub fn confirm(question: &str, default: bool) -> Result<bool> {
    use std::io::Write;
    let hint = if default { "[Y/n]" } else { "[y/N]" };
    eprint!("{question} {hint} ");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(match line.trim() {
        "" => default,
        a => matches!(a, "y" | "Y" | "yes" | "Yes"),
    })
}

/// Reads one line from the terminal (visible).
pub fn ask_line(prompt: &str) -> Result<String> {
    use std::io::Write;
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}
