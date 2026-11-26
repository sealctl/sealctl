//! Licence (SPEC 19): everything is free. The relay says whether to ask; the CLI decides when
//! and where. `sealctl buy` opens a checkout on the relay or, while card payments are not open,
//! records that the person would buy or trades a few answers for a year's licence.

use std::io::Write;
use std::time::Duration;

use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use sealctl_core::feedback::{clean_text, MISSING, PRICES, USES};

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
    /// The note that card payments are open was shown (to a phone that said it would buy).
    #[serde(default)]
    pub intent_told: bool,
    /// The feedback licence end whose last-30-days note was shown, Unix ms.
    #[serde(default)]
    pub ending_told: u64,
}

const HOUR: u64 = 3600 * 1000;
const DAY: u64 = 24 * HOUR;
const WEEK: u64 = 7 * DAY;

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

    /// `paid`, `feedback` (a feedback licence still valid by this computer's clock), `unpaid`
    /// or `unknown`. An ended feedback licence is `unpaid` at once, whatever the cache's age.
    pub fn licence(&self) -> &'static str {
        match self.answer.as_ref().and_then(|a| a["licence"].as_str()) {
            Some("paid") => "paid",
            Some("unpaid") if self.feedback_until().is_some() => "feedback",
            Some("unpaid") => "unpaid",
            _ => "unknown",
        }
    }

    /// The end of a feedback licence that is still valid, Unix ms.
    pub fn feedback_until(&self) -> Option<u64> {
        feedback_until(self.answer.as_ref()?, machine::now_ms())
    }

    /// Older than an hour, or holding a feedback licence that has ended since.
    fn stale(&self, now: u64) -> bool {
        let Some(a) = &self.answer else { return true };
        now.saturating_sub(self.fetched) >= HOUR
            || (a["kind"] == "feedback" && feedback_until(a, now).is_none())
    }
}

/// The end of the feedback licence in a licence answer, while it is valid at `now`.
fn feedback_until(a: &Value, now: u64) -> Option<u64> {
    if a["licence"] != "unpaid" || a["kind"] != "feedback" {
        return None;
    }
    a["until"].as_u64().filter(|u| *u > now)
}

/// A date in local time: `26 Nov 2027`.
fn long_date(ms: u64) -> String {
    crate::clock::from_ms(ms)
        .map(|t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%-d %b %Y")
                .to_string()
        })
        .unwrap_or_default()
}

/// A date in local time: `2027-11-26`.
pub fn short_date(ms: u64) -> String {
    crate::clock::from_ms(ms)
        .map(|t| {
            t.to_zoned(jiff::tz::TimeZone::system())
                .strftime("%Y-%m-%d")
                .to_string()
        })
        .unwrap_or_default()
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
    if !c.stale(machine::now_ms()) {
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
/// typed by a person, at most once in 7 days, from a cache at most an hour old. It is one of:
/// the end of a feedback licence in its last 30 days (once per licence); card payments being
/// open, for a phone that said it would buy (once); or the ask, when the relay says to ask.
pub fn maybe_ask() {
    if !term::is_person() {
        return;
    }
    let mut c = Cache::load();
    if let Some(line) = ask_line_for(&mut c, machine::now_ms()) {
        eprintln!("{line}");
        c.save();
    }
}

/// The line `maybe_ask` shows at `now`, if any, noting it in the cache.
fn ask_line_for(c: &mut Cache, now: u64) -> Option<String> {
    let a = c.answer.clone()?;
    if now.saturating_sub(c.fetched) > HOUR || now.saturating_sub(c.last_ask) < WEEK {
        return None;
    }
    let line = if let Some(until) = feedback_until(&a, now) {
        if until - now > 30 * DAY || c.ending_told == until {
            return None;
        }
        c.ending_told = until;
        format!(
            "Your free year of sealctl ends on {}. It's $5.99 once: sealctl buy",
            long_date(until)
        )
    } else if a["licence"] == "unpaid"
        && a["intent"] == json!(true)
        && a["payments"] == json!(true)
        && !c.intent_told
    {
        c.intent_told = true;
        "Card payments are open, as you asked to hear. It's $5.99 once: sealctl buy".to_string()
    } else if a["ask"] == json!(true) {
        let days = a["daysUsed"].as_u64().unwrap_or(30);
        format!("You've used sealctl on {days} days. It's $5.99 once: sealctl buy")
    } else {
        return None;
    };
    c.last_ask = now;
    Some(line)
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

/// A checkout refused because card payments are not open on this relay.
fn payments_closed(a: &relay::Answer) -> bool {
    matches!(a.error(), "payments_not_configured" | "payments_unavailable")
}

/// What `buy` talks to.
struct Ctx {
    rt: tokio::runtime::Runtime,
    relay: Relay,
    paired: Paired,
    base: String,
}

impl Ctx {
    fn post(&self, tail: &str, body: Value) -> Result<relay::Answer> {
        self.rt.block_on(self.relay.request(
            Some(&self.paired.keys),
            "POST",
            &format!("{}/{tail}", self.base),
            Some(&body),
        ))
    }
}

/// `sealctl buy [--seats N] [--code CODE]`.
pub fn buy(seats: Option<u32>, code: Option<String>, relay_flag: Option<&str>) -> Result<()> {
    term::refuse_agent("sealctl buy")?;
    let paired = machine::load_for(relay_flag)?;
    let relay = Relay::new(&paired.file.relay)?;
    let rt = relay::runtime()?;
    let base = format!("/v1/phones/{}", paired.phone_id());
    let ctx = Ctx {
        rt,
        relay,
        paired,
        base,
    };

    if let Some(code) = code {
        let a = ctx.post("claim", json!({"code": code}))?;
        if a.ok() {
            let left = a.body["left"].as_u64().unwrap_or(0);
            eprintln!("Paid with a seat from {code}. {left} seats left.");
            refresh_now(&ctx);
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

    if let Some(n) = seats {
        if !(2..=1000).contains(&n) {
            return Err(fail(exit::USAGE, "--seats must be 2 to 1,000."));
        }
        return checkout(&ctx, 1, n).and_then(|r| r.map_err(|a| checkout_error(&a, n)));
    }

    // the menus need a person at a terminal: never a pipe, CI or an agent
    term::require_person("sealctl buy", Some("--seats N or --code CODE"))?;
    if term::reader() != term::Reader::Person {
        return Err(fail(
            exit::REFUSED,
            "This needs a terminal: sealctl buy. Use --seats N or --code CODE.",
        ));
    }
    let lic = match ctx.rt.block_on(fetch(&ctx.relay, &ctx.paired)) {
        Ok(v) => {
            save_answer(v.clone());
            v
        }
        Err(_) => Cache::load().answer.unwrap_or(Value::Null),
    };
    if lic["payments"] == json!(false) {
        return payments_soon(&ctx, &lic);
    }
    let offer_feedback = lic["feedback"] != json!(true);
    eprintln!("Who pays?");
    eprintln!("  1  Me             card, opens checkout");
    eprintln!("  2  My company     invoice with VAT ID, opens checkout");
    eprintln!("  3  Someone else   copies a payment link to send");
    let choice = if offer_feedback {
        eprintln!("  4  Give feedback instead");
        choose_one("Choose 1, 2, 3 or 4: ", 4)?
    } else {
        choose_one("Choose 1, 2 or 3: ", 3)?
    };
    let Some(choice) = choice else { return Ok(()) };
    if choice == 4 {
        return give_feedback(&ctx);
    }
    match checkout(&ctx, choice, 1)? {
        Ok(()) => Ok(()),
        // a relay that does not say `payments` yet: the same choices as `payments: false`
        Err(a) if payments_closed(&a) => {
            eprintln!();
            payments_soon(&ctx, &lic)
        }
        Err(a) => Err(checkout_error(&a, 1)),
    }
}

/// Card payments are not open yet: say you'd buy, or trade feedback for a year.
fn payments_soon(ctx: &Ctx, lic: &Value) -> Result<()> {
    if lic["licence"] == "paid" {
        eprintln!("Already paid. Thank you.");
        return Ok(());
    }
    eprintln!("sealctl is $5.99 once. Card payments open soon.");
    eprintln!("  1  I'd buy it      sealctl tells you here when you can (nothing is charged)");
    eprintln!("  2  Give feedback   2 minutes; you get a year free");
    eprintln!("  3  Not now");
    match choose_one("Choose 1, 2 or 3: ", 3)? {
        Some(1) => {
            let a = ctx.post("intent", json!({}))?;
            if !a.ok() {
                return Err(relay::error_for(&a));
            }
            refresh_now(ctx);
            eprintln!("Noted. Thank you: sealctl will tell you here when you can buy.");
            Ok(())
        }
        Some(2) => give_feedback(ctx),
        _ => Ok(()),
    }
}

/// The questionnaire, then `POST .../feedback`.
fn give_feedback(ctx: &Ctx) -> Result<()> {
    let Some(body) = questionnaire()? else {
        return Err(fail(exit::ERROR, "Nothing sent."));
    };
    eprintln!("Sent with this phone's id; no name or email.");
    let a = ctx.post("feedback", body)?;
    if !a.ok() {
        return Err(relay::error_for(&a));
    }
    refresh_now(ctx);
    eprintln!("{}", feedback_result(&a.body));
    Ok(())
}

/// What the relay's answer to feedback means for this phone.
fn feedback_result(v: &Value) -> String {
    let until = v["until"].as_u64().map(long_date);
    match (v["granted"].as_bool(), v["kind"].as_str(), until) {
        (Some(true), _, Some(d)) => format!("Sent. Licensed until {d}. Thank you."),
        (_, Some("paid"), _) => "Sent. This phone is already paid. Thank you.".into(),
        (_, Some("feedback"), Some(d)) => {
            format!("Sent. Thank you. This phone has its free year already: licensed until {d}.")
        }
        _ => "Sent. Thank you. The free year comes once per phone, and this one has had it.".into(),
    }
}

const USE_LABELS: [&str; 5] = [
    "AI agents and API keys",
    "SSH and git signing",
    "Encrypted volumes",
    "Backups",
    "Something else",
];
const PRICE_LABELS: [&str; 4] = ["Yes", "I'd pay more", "Too much", "I wouldn't pay"];
const MISSING_LABELS: [&str; 6] = [
    "Windows",
    "The iPhone app on the App Store",
    "Teams",
    "Password managers",
    "Nothing",
    "Something else",
];

fn list(labels: &[&str]) {
    for (i, l) in labels.iter().enumerate() {
        eprintln!("  {}  {l}", i + 1);
    }
}

/// Four questions; `None` when the terminal closed before the end.
fn questionnaire() -> Result<Option<Value>> {
    eprintln!("What do you use sealctl for? Pick any, like 1,3 or 1 3.");
    list(&USE_LABELS);
    let Some(uses) = choose_many("Choose: ", USE_LABELS.len(), None)? else {
        return Ok(None);
    };
    eprintln!("Would $5.99 once be fair?");
    list(&PRICE_LABELS);
    let Some(price) = choose_one("Choose 1 to 4: ", PRICE_LABELS.len())? else {
        return Ok(None);
    };
    eprintln!("What's missing? Pick any, like 1,3 or 1 3.");
    list(&MISSING_LABELS);
    let nothing = MISSING.iter().position(|m| *m == "nothing").expect("nothing");
    let alone = Some((nothing + 1, MISSING_LABELS[nothing]));
    let Some(missing) = choose_many("Choose: ", MISSING_LABELS.len(), alone)? else {
        return Ok(None);
    };
    let text = loop {
        let Some(line) = read_answer("Anything else? One line, or Enter to skip: ")? else {
            return Ok(None);
        };
        match clean_text(&line) {
            Some(t) => break t,
            None => eprintln!("One line of at most 280 characters, please."),
        }
    };
    let mut body = json!({
        "v": sealctl_core::feedback::FEEDBACK_VERSION,
        "use": uses.iter().map(|i| USES[i - 1]).collect::<Vec<_>>(),
        "price": PRICES[price - 1],
        "missing": missing.iter().map(|i| MISSING[i - 1]).collect::<Vec<_>>(),
    });
    if !text.is_empty() {
        body["text"] = json!(text);
    }
    Ok(Some(body))
}

/// One line from the terminal without its line ending; `None` at the end of input.
fn read_answer(prompt: &str) -> Result<Option<String>> {
    eprint!("{prompt}");
    std::io::stderr().flush()?;
    let mut line = String::new();
    if std::io::stdin().read_line(&mut line)? == 0 {
        eprintln!();
        return Ok(None);
    }
    let line = line.strip_suffix('\n').unwrap_or(&line);
    Ok(Some(line.strip_suffix('\r').unwrap_or(line).to_string()))
}

/// One number from 1 to `n`, asked again until it is one; `None` at the end of input.
fn choose_one(prompt: &str, n: usize) -> Result<Option<usize>> {
    loop {
        let Some(line) = read_answer(prompt)? else {
            return Ok(None);
        };
        match parse_one(&line, n) {
            Some(c) => return Ok(Some(c)),
            None => eprintln!("Type a number from 1 to {n}."),
        }
    }
}

/// Several numbers from 1 to `n`, asked again until they are; `alone` (a number and its label)
/// may not be combined with others.
fn choose_many(prompt: &str, n: usize, alone: Option<(usize, &str)>) -> Result<Option<Vec<usize>>> {
    loop {
        let Some(line) = read_answer(prompt)? else {
            return Ok(None);
        };
        match parse_many(&line, n) {
            Some(v) if alone.is_some_and(|(a, _)| v.len() > 1 && v.contains(&a)) => {
                let label = alone.map_or("", |(_, l)| l);
                eprintln!("{label} goes on its own.");
            }
            Some(v) => return Ok(Some(v)),
            None => eprintln!("Type numbers from 1 to {n}, like 1,3 or 1 3."),
        }
    }
}

fn parse_one(line: &str, n: usize) -> Option<usize> {
    line.trim().parse::<usize>().ok().filter(|c| (1..=n).contains(c))
}

/// `1,3`, `1 3`, `1, 3`: distinct numbers from 1 to `n` in the order typed (repeats dropped).
fn parse_many(line: &str, n: usize) -> Option<Vec<usize>> {
    let mut out = Vec::new();
    for part in line
        .split(|c: char| c == ',' || c.is_whitespace())
        .filter(|p| !p.is_empty())
    {
        let c = parse_one(part, n)?;
        if !out.contains(&c) {
            out.push(c);
        }
    }
    (!out.is_empty()).then_some(out)
}

/// Asks the relay for a checkout and goes on with `choice` (1 me, 2 my company, 3 someone
/// else). A refused checkout comes back as the relay's answer.
fn checkout(ctx: &Ctx, choice: usize, n: u32) -> Result<std::result::Result<(), relay::Answer>> {
    // codes bought before: the wait below looks for a new one
    let before: Vec<String> = if n > 1 {
        let v = ctx
            .rt
            .block_on(fetch(&ctx.relay, &ctx.paired))
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
    let a = ctx.post("checkout", json!({"seats": n}))?;
    if !a.ok() {
        return Ok(Err(a));
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
            return Ok(Ok(()));
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
    let paid = ctx.rt.block_on(async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(15 * 60);
        while tokio::time::Instant::now() < deadline {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Ok(v) = fetch(&ctx.relay, &ctx.paired).await {
                if (n == 1 && v["licence"] == "paid") || (n > 1 && new_code(&v, &before).is_some()) {
                    return Some(v);
                }
            }
        }
        None
    });
    match paid {
        Some(v) => {
            save_answer(v.clone());
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
            Ok(Ok(()))
        }
        None => Err(fail(
            exit::NO_ANSWER,
            "No payment seen in 15 minutes. sealctl status shows it when it arrives.",
        )),
    }
}

/// Keeps a fresh licence answer in `licence.json`.
fn save_answer(v: Value) {
    let mut c = Cache::load();
    c.answer = Some(v);
    c.fetched = machine::now_ms();
    c.save();
}

fn refresh_now(ctx: &Ctx) {
    if let Ok(v) = ctx.rt.block_on(fetch(&ctx.relay, &ctx.paired)) {
        save_answer(v);
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
    fn choices_are_numbers_in_range() {
        assert_eq!(parse_one(" 2 ", 3), Some(2));
        for bad in ["", "0", "4", "1,2", "x", "-1"] {
            assert_eq!(parse_one(bad, 3), None, "{bad:?}");
        }
        assert_eq!(parse_many("1,2", 5), Some(vec![1, 2]));
        assert_eq!(parse_many("3 1", 5), Some(vec![3, 1]));
        assert_eq!(parse_many(" 1, 3 ,1 ", 5), Some(vec![1, 3]));
        for bad in ["", " , ", "1,6", "1;2", "a"] {
            assert_eq!(parse_many(bad, 5), None, "{bad:?}");
        }
    }

    #[test]
    fn labels_match_the_protocol_values() {
        assert_eq!(USE_LABELS.len(), USES.len());
        assert_eq!(PRICE_LABELS.len(), PRICES.len());
        assert_eq!(MISSING_LABELS.len(), MISSING.len());
        assert_eq!(
            MISSING_LABELS[MISSING.iter().position(|m| *m == "nothing").unwrap()],
            "Nothing"
        );
    }

    fn cache(answer: Value, now: u64) -> Cache {
        Cache {
            answer: Some(answer),
            fetched: now,
            ..Cache::default()
        }
    }

    #[test]
    fn an_ended_feedback_licence_is_unpaid_at_once() {
        let now = machine::now_ms();
        let a = json!({"licence": "unpaid", "kind": "feedback", "until": now + HOUR, "ask": false});
        let c = cache(a.clone(), now);
        assert_eq!(c.licence(), "feedback");
        assert!(!c.stale(now));
        let mut ended = a;
        ended["until"] = json!(now - 1);
        let c = cache(ended, now);
        assert_eq!(c.licence(), "unpaid");
        assert!(c.stale(now), "refetched without waiting for the hour");
        // a 0.7-style answer without kind
        assert_eq!(cache(json!({"licence": "unpaid"}), now).licence(), "unpaid");
        assert_eq!(
            cache(json!({"licence": "paid", "kind": "paid"}), now).licence(),
            "paid"
        );
    }

    #[test]
    fn the_last_thirty_days_say_so_once() {
        let now = machine::now_ms();
        let until = now + 20 * DAY;
        let mut c = cache(
            json!({"licence": "unpaid", "kind": "feedback", "until": until, "ask": false}),
            now,
        );
        let line = ask_line_for(&mut c, now).unwrap();
        assert!(line.starts_with("Your free year of sealctl ends on "), "{line}");
        assert!(line.ends_with(". It's $5.99 once: sealctl buy"), "{line}");
        c.last_ask = 0;
        assert_eq!(ask_line_for(&mut c, now), None, "once per licence");
        let mut early = cache(
            json!({"licence": "unpaid", "kind": "feedback", "until": now + 40 * DAY, "ask": false}),
            now,
        );
        assert_eq!(ask_line_for(&mut early, now), None, "not before the last 30 days");
    }

    #[test]
    fn a_phone_that_would_buy_hears_when_payments_open() {
        let now = machine::now_ms();
        let a = json!({"licence": "unpaid", "intent": true, "payments": false, "ask": false});
        let mut c = cache(a.clone(), now);
        assert_eq!(ask_line_for(&mut c, now), None, "not while payments are closed");
        let mut open = a;
        open["payments"] = json!(true);
        let mut c = cache(open, now);
        let line = ask_line_for(&mut c, now).unwrap();
        assert_eq!(
            line,
            "Card payments are open, as you asked to hear. It's $5.99 once: sealctl buy"
        );
        c.last_ask = 0;
        assert_eq!(ask_line_for(&mut c, now), None, "once");
    }

    #[test]
    fn feedback_answers_in_words() {
        let until = 1_827_000_000_000; // 2027-11-23 or so
        let d = long_date(until);
        assert!(d.ends_with(" 2027") && d.split(' ').count() == 3, "{d}");
        assert_eq!(
            feedback_result(
                &json!({"granted": true, "licence": "unpaid", "kind": "feedback", "until": until})
            ),
            format!("Sent. Licensed until {d}. Thank you.")
        );
        assert_eq!(
            feedback_result(&json!({"granted": false, "licence": "paid", "kind": "paid"})),
            "Sent. This phone is already paid. Thank you."
        );
        assert!(feedback_result(
            &json!({"granted": false, "licence": "unpaid", "kind": "feedback", "until": until})
        )
        .contains("has its free year already"));
        assert!(feedback_result(&json!({"granted": false, "licence": "unpaid"})).contains("once per phone"));
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
