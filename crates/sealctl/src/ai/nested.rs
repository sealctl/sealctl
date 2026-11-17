//! Editing hook configs shaped like Claude Code's:
//! `{"hooks": {"<Event>": [ {"matcher": "...", "hooks": [ {..., "command": "..."} ]} ]}}`
//! (Claude Code, Qwen Code, Codex hooks.json, Gemini CLI). Only entries whose command contains
//! our marker are ever touched.

use serde_json::{json, Value};

/// The hook command line, with the path shell-quoted.
pub fn command(exe: &str, tool: &str) -> String {
    format!("'{}' hook {tool}", exe.replace('\'', r"'\''"))
}

fn ours(h: &Value, marker: &str) -> bool {
    h["command"]
        .as_str()
        .is_some_and(|c| c.contains("sealctl") && c.contains(marker))
}

pub fn strip(settings: &mut Value, marker: &str) {
    if let Some(hooks) = settings.get_mut("hooks").and_then(Value::as_object_mut) {
        for groups in hooks.values_mut() {
            if let Some(arr) = groups.as_array_mut() {
                for g in arr.iter_mut() {
                    if let Some(hs) = g.get_mut("hooks").and_then(Value::as_array_mut) {
                        hs.retain(|h| !ours(h, marker));
                    }
                }
                arr.retain(|g| g["hooks"].as_array().is_none_or(|h| !h.is_empty()));
            }
        }
        hooks.retain(|_, v| v.as_array().is_none_or(|a| !a.is_empty()));
    }
    if settings["hooks"].as_object().is_some_and(|h| h.is_empty()) {
        if let Some(o) = settings.as_object_mut() {
            o.remove("hooks");
        }
    }
}

/// Add one group per event with `hook` as its only hook.
pub fn add(settings: &mut Value, events: &[(&str, Option<&str>)], hook: Value) {
    if !settings.is_object() {
        *settings = json!({});
    }
    let o = settings.as_object_mut().expect("object");
    let hooks = o.entry("hooks").or_insert_with(|| json!({}));
    if !hooks.is_object() {
        *hooks = json!({});
    }
    for (event, matcher) in events {
        let list = hooks
            .as_object_mut()
            .expect("hooks object")
            .entry(*event)
            .or_insert_with(|| json!([]));
        if !list.is_array() {
            *list = json!([]);
        }
        let mut g = json!({ "hooks": [hook.clone()] });
        if let Some(m) = matcher {
            g["matcher"] = json!(m);
        }
        list.as_array_mut().expect("array").push(g);
    }
}

fn at<'a>(v: &'a mut Value, path: &[&str]) -> Option<&'a mut Vec<Value>> {
    let mut cur = v;
    for k in path {
        cur = cur.get_mut(*k)?;
    }
    cur.as_array_mut()
}

/// Remove our strings from the list at `path` (e.g. permissions.deny).
pub fn strip_list(settings: &mut Value, path: &[&str], items: &[&str]) {
    if let Some(a) = at(settings, path) {
        a.retain(|d| !d.as_str().is_some_and(|s| items.contains(&s)));
    }
}

/// Append our strings to the list at `path`, creating objects on the way.
pub fn add_list(settings: &mut Value, path: &[&str], items: &[&str]) {
    if !settings.is_object() {
        *settings = json!({});
    }
    let mut cur = settings;
    for (i, k) in path.iter().enumerate() {
        let last = i + 1 == path.len();
        let o = cur.as_object_mut().expect("object on path");
        cur = o
            .entry(*k)
            .or_insert_with(|| if last { json!([]) } else { json!({}) });
        if !last && !cur.is_object() {
            *cur = json!({});
        }
    }
    if !cur.is_array() {
        *cur = json!([]);
    }
    let a = cur.as_array_mut().expect("array");
    for it in items {
        if !a.iter().any(|x| x.as_str() == Some(it)) {
            a.push(json!(it));
        }
    }
}
