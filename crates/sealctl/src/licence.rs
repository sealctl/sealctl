//! Licence (SPEC 19): everything is free. The relay says whether to ask; the CLI decides when
//! and where. `sealctl buy` opens a checkout on the relay.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::exit::{self, fail};
use crate::machine::{self, Paired};
use crate::relay::{self, Relay};
use crate::{paths, term};

/// `licence.json`: the last licence answer, when it came, and the last ask.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Cache {
    /// The relay's licence answer.
    #[serde(default)]
    pub answer: Option<Value>,
    /// When it came, Unix ms.
    #[serde(default)]
    pub fetched: u64,
    /// The last time the ask was shown, Unix ms.
    #[serde(default)]
    pub last_ask: u64,
    /// The first-pairing note was shown.
    #[serde(default)]
    pub first_pair_shown: bool,
}

const HOUR: u64 = 3600 * 1000;
const WEEK: u64 = 7 * 24 * HOUR;

impl Cache {
    /// Loads `licence.json`.
    pub fn load() -> Cache {
        paths::licence_file()
            .ok()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    /// Saves it.
    pub fn save(&self) {
        if let (Ok(p), Ok(b)) = (paths::licence_file(), serde_json::to_vec_pretty(self)) {
            let _ = paths::ensure_private_dir(p.parent().expect("state dir"));
            let _ = paths::write_private(&p, &b);
        }
    }

    /// `paid`, `unpaid` or `unknown`.
    pub fn licence(&self) -> &'static str {
        match self.answer.as_ref().and_then(|a| a["licence"].as_str()) {
            Some("paid") => "paid",
            Some("unpaid") => "unpaid",
            _ => "unknown",
        }
    }
}

/// True once: the first pairing of this user shows the note about paying.
pub fn first_pairing() -> bool {
    let mut c = Cache::load();
    if c.first_pair_shown {
        return false;
    }
    c.first_pair_shown = true;
    c.save();
    true
}

/// `GET /v1/phones/{phone}/licence`.
pub async fn fetch(relay: &Relay, paired: &Paired) -> Result<Value> {
    relay
        .call(
            &paired.keys,
            "GET",
            &format!("/v1/phones/{}/licence", paired.phone_id()),
            None,
        )
        .await
}

/// Refreshes a cache older than an hour, waiting at most `timeout`; returns the cache.
pub fn refreshed(paired: &Paired, timeout: Duration) -> Cache {
    let mut c = Cache::load();
    if c.answer.is_some() && machine::now_ms().saturating_sub(c.fetched) < HOUR {
        return c;
    }
    let Ok(relay) = Relay::new(&paired.file.relay) else {
        return c;
    };
    let Ok(rt) = relay::runtime() else { return c };
    let got = rt.block_on(async { tokio::time::timeout(timeout, fetch(&relay, paired)).await });
    if let Ok(Ok(v)) = got {
        c.answer = Some(v);
        c.fetched = machine::now_ms();
        c.save();
    }
    c
}

/// The soft ask (19.1): one line on stderr after `status`, `pair`, `secret ls` or `migrate`
/// typed by a person, when the relay says to ask and the last ask was 7 or more days ago.
pub fn maybe_ask() {
    if !term::is_person() {
        return;
    }
    let mut c = Cache::load();
    let Some(a) = c.answer.clone() else { return };
    if machine::now_ms().saturating_sub(c.fetched) > HOUR || a["ask"] != json!(true) {
        return;
    }
    if machine::now_ms().saturating_sub(c.last_ask) < WEEK {
        return;
    }
    let days = a["daysUsed"].as_u64().unwrap_or(30);
    eprintln!("You've used sealctl on {days} days. It's $5.99 once: sealctl buy");
    c.last_ask = machine::now_ms();
    c.save();
}

/// A checkout link from the relay, if it is one to open: `https://`, nothing but visible
/// ASCII (no spaces, no control characters).
fn checkout_link(url: &str) -> Option<&str> {
    let ok = url.len() > "https://".len()
        && url.starts_with("https://")
        && url.bytes().all(|b| b.is_ascii_graphic());
    ok.then_some(url)
}

/// The seat codes in a licence answer.
fn codes_of(v: &Value) -> Vec<Value> {
    v["codes"].as_array().cloned().unwrap_or_default()
}

/// A code in `v` that is not in `before` (codes from earlier purchases stay in the answer).
fn new_code(v: &Value, before: &[String]) -> Option<Value> {
    codes_of(v)
        .into_iter()
        .rev()
        .find(|c| c["code"].as_str().is_some_and(|s| !before.iter().any(|b| b == s)))
}

/// A seat code fit to print: letters, digits and `-` only.
fn printable_code(code: &str) -> String {
    code.chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-')
        .collect()
}

fn open_link(url: &str) {
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener)
        .arg(url)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

fn copy(text: &str) -> bool {
    crate::util::copy_to_clipboard_with_clear(text, 3600).is_ok()
}

fn checkout_error(a: &relay::Answer, seats: u32) -> anyhow::Error {
    match a.error() {
        "already_paid" if seats == 1 => fail(0, "Already paid. Thank you."),
        "payments_not_configured" | "payments_unavailable" => fail(
            exit::RELAY,
            format!(
                "Payments are not available on this relay right now. Status: {}",
                relay::STATUS_PAGE
            ),
        ),
        "bad_seats" => fail(exit::USAGE, "--seats must be 2 to 1,000."),
        _ => relay::error_for(a),
    }
}

/// `sealctl buy [--seats N] [--code CODE]`.
pub fn buy(seats: Option<u32>, code: Option<String>, relay_flag: Option<&str>) -> Result<()> {
    term::refuse_agent("sealctl buy")?;
    let paired = machine::load_for(relay_flag)?;
    let relay = Relay::new(&paired.file.relay)?;
    let rt = relay::runtime()?;
    let base = format!("/v1/phones/{}", paired.phone_id());

    if let Some(code) = code {
        let a = rt.block_on(relay.request(
            Some(&paired.keys),
            "POST",
            &format!("{base}/claim"),
            Some(&json!({"code": code})),
        ))?;
        if a.ok() {
            let left = a.body["left"].as_u64().unwrap_or(0);
            eprintln!("Paid with a seat from {code}. {left} seats left.");
            refresh_now(&rt, &relay, &paired);
            return Ok(());
        }
        return Err(match a.error() {
            "unknown_code" => fail(exit::NOT_FOUND, "No such code."),
            "bad_code" => fail(exit::USAGE, "That is not a seat code (XXXX-XXXX)."),
            "no_seats_left" => fail(exit::ERROR, "That code has no seats left."),
            "already_paid" => fail(0, "This phone is already paid."),
            _ => relay::error_for(&a),
        });
    }

    let (choice, n) = match seats {
        Some(n) if (2..=1000).contains(&n) => (1, n),
        Some(_) => return Err(fail(exit::USAGE, "--seats must be 2 to 1,000.")),
        None => {
            term::require_person("sealctl buy", Some("--seats N or --code CODE"))?;
            eprintln!("Who pays?");
            eprintln!("  1  Me             card, opens checkout");
            eprintln!("  2  My company     invoice with VAT ID, opens checkout");
            eprintln!("  3  Someone else   copies a payment link to send");
            let c = term::ask_line("Choose 1, 2 or 3: ")?;
            match c.as_str() {
                "1" => (1, 1),
                "2" => (2, 1),
                "3" => (3, 1),
                _ => return Err(fail(exit::USAGE, "Choose 1, 2 or 3.")),
            }
        }
    };
    // codes bought before: the wait below looks for a new one
    let before: Vec<String> = if n > 1 {
        let v = rt
            .block_on(fetch(&relay, &paired))
            .ok()
            .or_else(|| Cache::load().answer)
            .unwrap_or(Value::Null);
        codes_of(&v)
            .iter()
            .filter_map(|c| c["code"].as_str().map(String::from))
            .collect()
    } else {
        Vec::new()
    };
    let a = rt.block_on(relay.request(
        Some(&paired.keys),
        "POST",
        &format!("{base}/checkout"),
        Some(&json!({"seats": n})),
    ))?;
    if !a.ok() {
        return Err(checkout_error(&a, n));
    }
    let url = a.body["url"]
        .as_str()
        .and_then(checkout_link)
        .map(String::from)
        .ok_or_else(|| {
            fail(
                exit::RELAY,
                "The relay sent a checkout link that is not https; nothing opened.",
            )
        })?;
    match choice {
        3 => {
            let copied = copy(&url);
            println!("{url}");
            eprintln!(
                "{}Anyone can pay it; sealctl status shows Paid afterwards.",
                if copied { "Link copied. " } else { "" }
            );
            return Ok(());
        }
        2 => {
            let msg = format!(
                "Could we get sealctl for me? It keeps API keys away from AI agents. $5.99 once: {url}"
            );
            if copy(&msg) {
                eprintln!("A message for your team chat is copied.");
            }
            open_link(&url);
        }
        _ => open_link(&url),
    }
    println!("{url}");
    let _ = std::io::stdout().flush();
    eprintln!("Waiting for the payment. Ctrl-C stops waiting; sealctl status shows it later.");
    let paid = rt.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Ok(v) = fetch(&relay, &paired).await {
                if (n == 1 && v["licence"] == "paid") || (n > 1 && new_code(&v, &before).is_some()) {
                    return Some(v);
                }
            }
        }
        None
    });
    match paid {
        Some(v) => {
            let mut c = Cache::load();
            c.answer = Some(v.clone());
            c.fetched = machine::now_ms();
            c.save();
            if n > 1 {
                let code = new_code(&v, &before).unwrap_or(Value::Null);
                let code_s = printable_code(code["code"].as_str().unwrap_or(""));
                eprintln!(
                    "Seat code {code_s} ({n} seats, {} used by you). Each developer runs: sealctl buy --code {code_s}",
                    code["claimed"].as_u64().unwrap_or(1)
                );
            } else {
                eprintln!("Paid. Thank you.");
            }
            Ok(())
        }
        None => Err(fail(
            exit::NO_ANSWER,
            "No payment seen in 15 minutes. sealctl status shows it when it arrives.",
        )),
    }
}

fn refresh_now(rt: &tokio::runtime::Runtime, relay: &Relay, paired: &Paired) {
    if let Ok(v) = rt.block_on(fetch(relay, paired)) {
        let mut c = Cache::load();
        c.answer = Some(v);
        c.fetched = machine::now_ms();
        c.save();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkout_links() {
        assert_eq!(
            checkout_link("https://pay.example.com/c/abc?x=1"),
            Some("https://pay.example.com/c/abc?x=1")
        );
        for bad in [
            "",
            "https://",
            "http://pay.example.com/",
            "file:///Applications/Calculator.app",
            "smb://host/share",
            "-a Terminal",
            "https://pay.example.com/\x1b]0;x\x07",
            "https://pay.example.com/a b",
        ] {
            assert_eq!(checkout_link(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn the_wait_takes_only_a_new_code() {
        let v = json!({"codes": [{"code": "AAAA-BBBB", "seats": 5}]});
        assert!(new_code(&v, &["AAAA-BBBB".into()]).is_none());
        let v = json!({"codes": [{"code": "CCCC-DDDD", "seats": 10}, {"code": "AAAA-BBBB", "seats": 5}]});
        assert_eq!(new_code(&v, &["AAAA-BBBB".into()]).unwrap()["code"], "CCCC-DDDD");
        assert_eq!(new_code(&v, &[]).unwrap()["code"], "AAAA-BBBB");
        assert_eq!(printable_code("AB\x1b[2JCD-12"), "AB2JCD-12");
    }
}
