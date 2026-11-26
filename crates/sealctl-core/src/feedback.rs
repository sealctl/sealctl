//! Buy intent and feedback (docs/protocol.md, Licence): the values the relay accepts and the
//! checks it applies, shared by the CLI and the tests' fake relay.
//!
//! No name or email is part of either body; the relay keeps them with the phone id.

use serde_json::{json, Map, Value};

/// The `v` of a feedback body.
pub const FEEDBACK_VERSION: u64 = 1;

/// `use`: what sealctl is used for.
pub const USES: [&str; 5] = ["agents", "ssh", "volumes", "backups", "other"];

/// `price`: is $5.99 once fair.
pub const PRICES: [&str; 4] = ["fair", "more", "too_much", "would_not_pay"];

/// `missing`: what is missing. `nothing` only stands alone.
pub const MISSING: [&str; 6] = [
    "windows",
    "ios_store",
    "teams",
    "password_managers",
    "nothing",
    "other",
];

/// Most characters (Unicode code points) in `text` or `note`, after trimming.
pub const TEXT_MAX: usize = 280;

/// How long a feedback licence lasts: 365 days, in milliseconds.
pub const FEEDBACK_LICENCE_MS: u64 = 365 * 24 * 3600 * 1000;

/// A free-text answer as the relay keeps it: refused (`None`) when it has a control character
/// (Unicode category Cc) anywhere, then trimmed of White_Space and U+FEFF at both ends (as
/// JavaScript's `trim()` does once control characters are excluded), and refused when longer
/// than [`TEXT_MAX`] code points. An empty result means no text.
pub fn clean_text(s: &str) -> Option<String> {
    if s.chars().any(char::is_control) {
        return None;
    }
    let t = s.trim_matches(|c: char| c.is_whitespace() || c == '\u{feff}');
    (t.chars().count() <= TEXT_MAX).then(|| t.to_string())
}

/// A list of distinct values from `allowed`, at least one.
fn pick_list(v: &Value, allowed: &[&str]) -> Option<Vec<String>> {
    let items = v.as_array()?;
    if items.is_empty() || items.len() > allowed.len() {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(items.len());
    for it in items {
        let s = it.as_str().filter(|s| allowed.contains(s))?;
        if out.iter().any(|o| o == s) {
            return None;
        }
        out.push(s.to_string());
    }
    Some(out)
}

/// Checks a feedback body (`POST /v1/phones/{phone}/feedback`) and returns it as the relay
/// stores it, or `None` for `400 bad_feedback`: an object with exactly `v` (1), `use` and
/// `missing` (distinct known values, at least one; `nothing` alone), `price` (one known value)
/// and an optional `text` string ([`clean_text`]; dropped when empty). Any other field, a
/// `null`, or a value of the wrong type is refused.
pub fn check_feedback(body: &Value) -> Option<Value> {
    let obj = body.as_object()?;
    if obj
        .keys()
        .any(|k| !matches!(k.as_str(), "v" | "use" | "price" | "missing" | "text"))
    {
        return None;
    }
    if obj.get("v")?.as_u64()? != FEEDBACK_VERSION {
        return None;
    }
    let uses = pick_list(obj.get("use")?, &USES)?;
    let price = obj
        .get("price")?
        .as_str()
        .filter(|p| PRICES.contains(p))?
        .to_string();
    let missing = pick_list(obj.get("missing")?, &MISSING)?;
    if missing.len() > 1 && missing.iter().any(|m| m == "nothing") {
        return None;
    }
    let mut out = Map::new();
    out.insert("v".into(), json!(FEEDBACK_VERSION));
    out.insert("use".into(), json!(uses));
    out.insert("price".into(), json!(price));
    out.insert("missing".into(), json!(missing));
    if let Some(t) = obj.get("text") {
        let t = clean_text(t.as_str()?)?;
        if !t.is_empty() {
            out.insert("text".into(), json!(t));
        }
    }
    Some(Value::Object(out))
}

/// Checks an intent body (`POST /v1/phones/{phone}/intent`) and returns it as the relay stores
/// it, or `None` for `400 bad_intent`: no body, `{}`, or `{"note": <string>}` ([`clean_text`];
/// dropped when empty). Any other field is refused.
pub fn check_intent(body: &Value) -> Option<Value> {
    let mut out = Map::new();
    match body {
        Value::Null => {}
        Value::Object(obj) => {
            if obj.keys().any(|k| k != "note") {
                return None;
            }
            if let Some(n) = obj.get("note") {
                let n = clean_text(n.as_str()?)?;
                if !n.is_empty() {
                    out.insert("note".into(), json!(n));
                }
            }
        }
        _ => return None,
    }
    Some(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn good() -> Value {
        json!({"v": 1, "use": ["agents", "ssh"], "price": "fair", "missing": ["nothing"], "text": "  thanks  "})
    }

    #[test]
    fn a_good_body_is_kept_trimmed() {
        let v = check_feedback(&good()).unwrap();
        assert_eq!(v["text"], "thanks");
        assert_eq!(v["use"], json!(["agents", "ssh"]));
        let mut b = good();
        b["text"] = json!("   ");
        assert!(
            check_feedback(&b).unwrap().get("text").is_none(),
            "empty text is dropped"
        );
        b.as_object_mut().unwrap().remove("text");
        assert!(check_feedback(&b).is_some(), "text is optional");
    }

    #[test]
    fn bad_bodies_are_refused() {
        let cases: Vec<(&str, Value)> = vec![
            ("v", json!(2)),
            ("v", json!("1")),
            ("use", json!([])),
            ("use", json!(["agents", "agents"])),
            ("use", json!(["email"])),
            ("use", json!("agents")),
            ("price", json!("cheap")),
            ("price", Value::Null),
            ("missing", json!(["nothing", "windows"])),
            ("missing", json!(["android"])),
            ("text", json!("a\u{7}b")),
            ("text", json!("line\nline")),
            ("text", json!("x".repeat(281))),
            ("text", json!(5)),
            ("name", json!("someone")),
        ];
        for (field, value) in cases {
            let mut b = good();
            b[field] = value.clone();
            assert!(check_feedback(&b).is_none(), "{field} = {value}");
        }
        for field in ["v", "use", "price", "missing"] {
            let mut b = good();
            b.as_object_mut().unwrap().remove(field);
            assert!(check_feedback(&b).is_none(), "without {field}");
        }
        assert!(check_feedback(&json!([])).is_none());
    }

    #[test]
    fn text_counts_code_points_after_trimming() {
        assert_eq!(clean_text(&"é".repeat(280)).unwrap().chars().count(), 280);
        assert!(clean_text(&"é".repeat(281)).is_none());
        assert_eq!(
            clean_text(&format!("\u{feff} {} ", "a".repeat(280)))
                .unwrap()
                .len(),
            280
        );
        assert!(clean_text("tab\tinside").is_none());
        assert!(
            clean_text("ends with a newline\n").is_none(),
            "control characters anywhere"
        );
        assert!(clean_text("next line\u{85}").is_none());
    }

    #[test]
    fn intent_bodies() {
        assert_eq!(check_intent(&Value::Null).unwrap(), json!({}));
        assert_eq!(check_intent(&json!({})).unwrap(), json!({}));
        assert_eq!(
            check_intent(&json!({"note": " soon "})).unwrap(),
            json!({"note": "soon"})
        );
        assert_eq!(check_intent(&json!({"note": ""})).unwrap(), json!({}));
        assert!(check_intent(&json!({"note": 1})).is_none());
        assert!(check_intent(&json!({"email": "a@b"})).is_none());
        assert!(check_intent(&json!({"note": "x".repeat(281)})).is_none());
        assert!(check_intent(&json!("note")).is_none());
    }
}
