//! Port of `hydralysis/decompile_result.py`: partial-decompile fields (`fragments`, `truncated`, `bytes_emitted`,
//! `reason`, paging) carried, summarised and turned into evidence coverage. Values are `serde_json::Value` with
//! insertion order preserved, so key order matches the Python dicts.

use serde_json::{Map, Value, json};

pub const CLASSES: [&str; 3] = ["code", "data", "unknown"];
pub const MAX_FRAGMENTS: usize = 4096;
pub const LIMIT_TRUNCATED: &str = "decompile_truncated";
pub const LIMIT_NON_CODE: &str = "non_code_fragments";
pub const LIMIT_BUDGET: &str = "decompile_budget_limited";
pub const LIMIT_PAGED: &str = "decompile_paged";

/// Python `int(text, 0)` on an already-stripped-by-Python string: sign, `0x`/`0o`/`0b`, single underscores between
/// digits, no leading zeros in decimal unless the value is zero.
pub fn py_int0(text: &str) -> Option<i128> {
    let t = text.trim_matches(|c: char| c.is_whitespace());
    let (neg, rest) = match t.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, t.strip_prefix('+').unwrap_or(t)),
    };
    let lower = rest.to_ascii_lowercase();
    let (radix, digits) = if let Some(d) = lower.strip_prefix("0x") {
        (16, d)
    } else if let Some(d) = lower.strip_prefix("0o") {
        (8, d)
    } else if let Some(d) = lower.strip_prefix("0b") {
        (2, d)
    } else {
        (10, lower.as_str())
    };
    if digits.is_empty() || digits.starts_with('_') || digits.ends_with('_') || digits.contains("__") {
        return None;
    }
    // base-prefixed literals may carry one underscore right after the prefix: "0x_ff"
    let clean: String = digits.chars().filter(|c| *c != '_').collect();
    if radix == 10 && clean.len() > 1 && clean.starts_with('0') && clean.chars().any(|c| c != '0') {
        return None;
    }
    let v = i128::from_str_radix(&clean, radix).ok()?;
    Some(if neg { -v } else { v })
}

/// `_address`: a non-negative integer from an int or an int-looking string, else None.
fn address(value: &Value) -> Option<i128> {
    match value {
        Value::Bool(_) => None,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                (i >= 0).then_some(i128::from(i))
            } else {
                n.as_u64().map(i128::from) // a float is None: str(1.0) is not an int literal
            }
        }
        Value::String(s) => py_int0(s).filter(|n| *n >= 0),
        _ => None,
    }
}

fn is_int(v: Option<&Value>) -> Option<u64> {
    match v {
        Some(Value::Number(n)) => n.as_u64(),
        _ => None,
    }
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn is_true(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Bool(true)))
}

/// `(well-formed fragments in the engine's order, "" or why some were dropped)`.
pub fn fragments(value: Option<&Value>) -> (Vec<Value>, String) {
    let value = match value {
        None | Some(Value::Null) => return (Vec::new(), String::new()),
        Some(v) => v,
    };
    let Value::Array(items) = value else {
        return (Vec::new(), "fragments is not a list".to_string());
    };
    let (mut kept, mut bad) = (Vec::new(), 0usize);
    for item in items.iter().take(MAX_FRAGMENTS) {
        let obj = item.as_object();
        let start = obj.and_then(|o| o.get("start")).and_then(address);
        let end = obj.and_then(|o| o.get("end")).and_then(address);
        let class = obj.and_then(|o| o.get("class")).and_then(Value::as_str).filter(|c| CLASSES.contains(c));
        let (Some(o), Some(s), Some(e), Some(_)) = (obj, start, end, class) else {
            bad += 1;
            continue;
        };
        if e < s {
            bad += 1;
            continue;
        }
        let mut row = Map::new();
        row.insert("start".into(), o["start"].clone());
        row.insert("end".into(), o["end"].clone());
        row.insert("class".into(), o["class"].clone());
        if let Some(Value::Bool(b)) = o.get("decompiled") {
            row.insert("decompiled".into(), Value::Bool(*b));
        }
        kept.push(Value::Object(row));
    }
    let mut note = Vec::new();
    if bad > 0 {
        note.push(format!("{bad} malformed fragment(s) dropped"));
    }
    if items.len() > MAX_FRAGMENTS {
        note.push(format!("only the first {MAX_FRAGMENTS} fragments are kept"));
    }
    (kept, note.join("; "))
}

fn pick(src: &Map<String, Value>, keys: &[&str]) -> Value {
    let mut m = Map::new();
    for k in keys {
        if let Some(v) = src.get(*k) {
            m.insert((*k).to_string(), v.clone());
        }
    }
    Value::Object(m)
}

/// `summarize`: empty when the reply carries none of the completeness fields and is not truncated.
pub fn summarize(reply: &Value) -> Map<String, Value> {
    let Some(r) = reply.as_object() else {
        return Map::new();
    };
    let named = ["fragments", "bytes_emitted", "reason", "cut", "budget", "next_offset", "partial"];
    if !(is_true(r.get("truncated")) || named.iter().any(|n| r.contains_key(*n))) {
        return Map::new();
    }
    let (kept, note) = fragments(r.get("fragments"));
    let mut out = Map::new();
    out.insert("partial".into(), Value::Bool(is_true(r.get("truncated")) || is_true(r.get("partial"))));
    if let Some(Value::String(s)) = r.get("reason")
        && !s.is_empty()
    {
        out.insert("reason".into(), json!(s.chars().take(200).collect::<String>()));
    }
    if let Some(n) = is_int(r.get("bytes_emitted")) {
        out.insert("bytes_emitted".into(), json!(n));
    }
    if let Some(Value::Object(cut)) = r.get("cut") {
        out.insert("cut".into(), pick(cut, &["kind", "response_bytes_read", "c_recovered", "c_chars", "c_lines", "c_returned_chars"]));
    }
    if let Some(Value::Object(budget)) = r.get("budget") {
        out.insert("budget".into(), pick(budget, &["mode", "bytes", "mb", "in_flight"]));
    }
    for name in ["offset", "next_offset"] {
        if let Some(n) = is_int(r.get(name)) {
            out.insert(name.into(), json!(n));
        }
    }
    if out.contains_key("next_offset") {
        out.insert("partial".into(), Value::Bool(true));
    }
    if r.contains_key("fragments") {
        let mut totals = [0i128; 3];
        for item in &kept {
            let class = item["class"].as_str().unwrap_or("");
            let idx = CLASSES.iter().position(|c| *c == class).unwrap_or(0);
            totals[idx] += address(&item["end"]).unwrap_or(0) - address(&item["start"]).unwrap_or(0);
        }
        let mut ft = Map::new();
        for (i, c) in CLASSES.iter().enumerate() {
            ft.insert((*c).into(), json!(totals[i] as i64));
        }
        out.insert("fragment_bytes".into(), Value::Object(ft));
        out.insert("fragment_count".into(), json!(kept.len()));
        if !note.is_empty() {
            out.insert("fragments_note".into(), json!(note));
        }
    }
    out
}

/// `annotate`: the reply with `decompile` (the summary) added when there is one.
pub fn annotate(mut reply: Value) -> Value {
    let summary = summarize(&reply);
    if !summary.is_empty()
        && let Some(o) = reply.as_object_mut()
    {
        o.insert("decompile".into(), Value::Object(summary));
    }
    reply
}

pub fn limitations(reply: &Value) -> Vec<&'static str> {
    let summary = summarize(reply);
    let mut codes = Vec::new();
    if is_true(reply.get("truncated")) {
        let auto = reply.get("budget").and_then(Value::as_object).is_some_and(|b| b.get("mode") == Some(&json!("auto")));
        codes.push(if auto { LIMIT_BUDGET } else { LIMIT_TRUNCATED });
    }
    if summary.get("next_offset").is_some_and(Value::is_u64) {
        codes.push(LIMIT_PAGED);
    }
    let fb = summary.get("fragment_bytes").and_then(Value::as_object);
    let nonzero = |k: &str| fb.and_then(|f| f.get(k)).and_then(Value::as_i64).is_some_and(|n| n != 0);
    if nonzero("data") || nonzero("unknown") {
        codes.push(LIMIT_NON_CODE);
    }
    codes
}

fn coverage_codes(reply: &Value) -> Vec<&'static str> {
    let mut codes = limitations(reply);
    if is_true(reply.get("truncated")) {
        codes.retain(|c| *c != LIMIT_NON_CODE);
    }
    if codes.is_empty() { vec![LIMIT_NON_CODE] } else { codes }
}

pub fn coverage(reply: &Value) -> Value {
    let summary = summarize(reply);
    if summary.is_empty() {
        return json!({"status": "unknown", "reason": "the decompile reply carries no truncated/fragments fields"});
    }
    if summary.get("partial") == Some(&Value::Bool(true)) {
        return json!({"status": "partial", "limitations": coverage_codes(reply)});
    }
    json!({"status": "complete"})
}

/// `merge`: RESPONSE (RusticQuery's answer) with the engine's `decompile` REPLY folded in.
/// `None` means RESPONSE comes back unchanged (Python returns the same object).
pub fn merge(response: &Value, reply: &Value) -> Option<Value> {
    let (Some(resp), Some(rep)) = (response.as_object(), reply.as_object()) else {
        return None;
    };
    let mut carried = Map::new();
    for name in ["partial", "reason", "fragments", "bytes_emitted", "cut", "budget", "offset", "next_offset"] {
        if let Some(v) = rep.get(name) {
            carried.insert(name.into(), v.clone());
        }
    }
    if rep.get("completed") == Some(&Value::Bool(false)) && is_true(rep.get("truncated")) {
        let mut out = Map::new();
        for name in ["id", "program", "sha256", "image_base", "address_kind", "overlay_state", "engine", "function"] {
            if let Some(v) = resp.get(name) {
                out.insert(name.into(), v.clone());
            }
        }
        out.insert("ok".into(), Value::Bool(false));
        out.insert("truncated".into(), Value::Bool(true));
        out.insert("error".into(), rep.get("error").cloned().unwrap_or_else(|| json!("decompile stopped at the size bound")));
        for name in ["c", "signature", "chars"] {
            if let Some(v) = rep.get(name) {
                out.insert(name.into(), v.clone());
            }
        }
        for (k, v) in carried {
            out.insert(k, v);
        }
        return Some(Value::Object(out));
    }
    let text = match rep.get("c") {
        Some(Value::String(s)) if rep.get("completed") == Some(&Value::Bool(true)) => s,
        _ => return None,
    };
    let text_len = text.chars().count();
    let chars = rep.get("chars").cloned().unwrap_or_else(|| json!(text_len));
    let mut merged = resp.clone();
    if resp.get("ok") == Some(&Value::Bool(false)) {
        merged = Map::new();
        for name in ["id", "program", "sha256", "image_base", "address_kind", "overlay_state", "engine"] {
            if let Some(v) = resp.get(name) {
                merged.insert(name.into(), v.clone());
            }
        }
        merged.insert("ok".into(), Value::Bool(true));
        merged.insert("c".into(), rep["c"].clone());
        merged.insert(
            "function".into(),
            json!({
                "address": rep.get("entry").cloned().unwrap_or(Value::Null),
                "name": rep.get("name").cloned().unwrap_or(Value::Null),
                "signature": rep.get("signature").cloned().unwrap_or(Value::Null),
            }),
        );
        merged.insert("total_characters".into(), chars.clone());
        merged.insert("max_characters".into(), json!(text_len));
    }
    for (k, v) in carried {
        merged.insert(k, v);
    }
    if rep.contains_key("offset") {
        merged.insert("c".into(), rep["c"].clone());
        merged.insert("total_characters".into(), chars);
        merged.insert("max_characters".into(), json!(text_len));
    }
    let clipped = resp.get("ok") != Some(&Value::Bool(false)) && truthy(resp.get("truncated")) && !rep.contains_key("offset");
    merged.insert("truncated".into(), Value::Bool(clipped || is_true(rep.get("truncated"))));
    Some(Value::Object(merged))
}

/// `from_error`: the reply behind a RuntimeError message when it is a partial decompile.
pub fn from_error(message: &str) -> Option<Value> {
    let reply: Value = serde_json::from_str(message).ok()?;
    let r = reply.as_object()?;
    if !is_true(r.get("truncated")) {
        return None;
    }
    let has_text = matches!(r.get("c"), Some(Value::String(_)));
    if !(has_text || truthy(r.get("fragments")) || r.contains_key("bytes_emitted") || r.contains_key("cut")) {
        return None;
    }
    Some(reply)
}
