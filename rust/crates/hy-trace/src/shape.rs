//! Bounding an engine reply: `hydralysis.trace.shape` (and `_collect_ids`, `_size`).
//!
//! The engine's reply is data and is never trusted for size. Every list is cut at the page limit; the whole reply is then
//! halved list by list until it fits `MAX_REPLY_BYTES`, and the answer says what was cut, carries the coverage the engine
//! reported (or says it reported none) and cites the event ids it names.
//!
//! The Python builds dicts in a given key order and that order reaches the caller's JSON text, so the order is kept here
//! (`serde_json` with `preserve_order`; removals shift, never swap).

use crate::pyfmt::{float_repr, json_string_len};
use serde_json::{Map, Value};

pub const MAX_REPLY_BYTES: usize = 48 * 1024;
const MAX_CITATIONS: usize = 50;

const LIST_KEYS: [&str; 27] = [
    "rows",
    "groups",
    "nodes",
    "edges",
    "boundaries",
    "results",
    "sessions",
    "sources",
    "files",
    "entries",
    "unmatched_a",
    "unmatched_b",
    "rejected",
    "events",
    "items",
    "counterexamples",
    "only_a",
    "only_b",
    "different_under_matched_coverage",
    "not_comparable",
    "paths",
    "unresolved",
    "assertions",
    "jobs",
    "decodings",
    "evicted",
    "reasons",
];
const NESTED: [&str; 4] = ["diff", "aligned", "symbols", "decoded"];
const ID_KEYS: [&str; 9] =
    ["event_id", "from_event", "to_event", "representative", "first_event", "last_event", "first_a", "first_b", "root"];
const ID_LISTS: [&str; 4] = ["event_ids", "counterexamples", "representatives", "events"];

fn list_keys() -> impl Iterator<Item = &'static str> {
    LIST_KEYS.iter().copied()
}

/// `len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode("ascii"))`.
pub fn json_len(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => {
            if let Some(n) = number.as_i64() {
                int_len(n.unsigned_abs(), n < 0)
            } else if let Some(n) = number.as_u64() {
                int_len(n, false)
            } else {
                float_repr(number.as_f64().unwrap_or(0.0)).len()
            }
        }
        Value::String(text) => json_string_len(text),
        Value::Array(items) => map_sum(items.iter().map(json_len), items.len()),
        Value::Object(map) => map_len(map),
    }
}

fn int_len(magnitude: u64, negative: bool) -> usize {
    usize::from(negative) + magnitude.checked_ilog10().map_or(1, |digits| digits as usize + 1)
}

fn map_sum(parts: impl Iterator<Item = usize>, count: usize) -> usize {
    2 + parts.sum::<usize>() + count.saturating_sub(1)
}

fn map_len(map: &Map<String, Value>) -> usize {
    map_sum(map.iter().map(|(key, value)| json_string_len(key) + 1 + json_len(value)), map.len())
}

/// `_EVENT_ID.match(text)` for `^[A-Za-z0-9_][A-Za-z0-9_.:-]{0,119}$` (Python's `$` also matches before one final newline).
fn is_event_id(text: &str) -> bool {
    let body = text.strip_suffix('\n').unwrap_or(text).as_bytes();
    let Some((first, rest)) = body.split_first() else { return false };
    (first.is_ascii_alphanumeric() || *first == b'_')
        && rest.len() <= 119
        && rest.iter().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b':' | b'-'))
}

fn collect_members(map: &Map<String, Value>, found: &mut Vec<String>, depth: usize) {
    if depth > 5 || found.len() >= MAX_CITATIONS * 4 {
        return;
    }
    for (key, item) in map {
        if let (true, Some(text)) = (ID_KEYS.contains(&key.as_str()), item.as_str()) {
            found.push(text.to_owned());
        } else if let (true, Some(entries)) = (ID_LISTS.contains(&key.as_str()), item.as_array()) {
            for entry in entries {
                match entry {
                    Value::String(text) => found.push(text.clone()),
                    Value::Object(inner) => collect_members(inner, found, depth + 1),
                    _ => {}
                }
            }
        } else {
            collect_ids(item, found, depth + 1);
        }
    }
}

fn collect_ids(value: &Value, found: &mut Vec<String>, depth: usize) {
    if depth > 5 || found.len() >= MAX_CITATIONS * 4 {
        return;
    }
    match value {
        Value::Object(map) => collect_members(map, found, depth),
        Value::Array(items) => {
            for item in items {
                collect_ids(item, found, depth + 1);
            }
        }
        _ => {}
    }
}

/// The ordered `truncated` dict: assignment keeps the first position of a key.
#[derive(Default)]
struct Truncated(Vec<(String, u64)>);

impl Truncated {
    fn set(&mut self, key: &str, value: u64) {
        match self.0.iter_mut().find(|(name, _)| name == key) {
            Some(slot) => slot.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }

    fn get(&self, key: &str) -> u64 {
        self.0.iter().find(|(name, _)| name == key).map_or(0, |slot| slot.1)
    }
}

/// The holders of lists in OUT: the reply itself, then each nested member that is an object, in `_NESTED` order.
fn holders(out: &Map<String, Value>) -> Vec<Option<&'static str>> {
    let mut found = vec![None];
    found.extend(NESTED.iter().copied().filter(|key| out.get(*key).is_some_and(Value::is_object)).map(Some));
    found
}

fn holder_mut<'a>(out: &'a mut Map<String, Value>, nested: Option<&str>) -> &'a mut Map<String, Value> {
    match nested {
        None => out,
        Some(key) => match out.get_mut(key) {
            Some(Value::Object(map)) => map,
            _ => unreachable!("a holder was chosen because it is an object"),
        },
    }
}

fn label(nested: Option<&str>, key: &str) -> String {
    nested.map_or_else(|| key.to_owned(), |name| format!("{name}.{key}"))
}

/// Bound REPLY and add the fields every trace answer carries: revision, coverage, citations and what was cut.
pub fn shape(reply: &Value, session: Option<&str>, command: &str, limit: usize, requested_revision: Option<&Value>) -> Value {
    let mut out: Map<String, Value> = match reply {
        Value::Object(map) => map.clone(),
        other => {
            let mut map = Map::new();
            map.insert("result".to_owned(), other.clone());
            map
        }
    };
    let mut truncated = Truncated::default();
    for nested in holders(&out) {
        for key in list_keys() {
            let holder = holder_mut(&mut out, nested);
            if let Some(Value::Array(items)) = holder.get_mut(key)
                && items.len() > limit
            {
                truncated.set(&label(nested, key), (items.len() - limit) as u64);
                items.truncate(limit);
            }
        }
    }
    let coverage: Option<Map<String, Value>> = out.get("coverage").and_then(Value::as_object).cloned();
    let gaps_value: Option<Value> = match &coverage {
        Some(map) if !map.is_empty() => map.get("gaps").cloned().or_else(|| out.get("gaps").cloned()),
        _ => out.get("gaps").cloned(),
    };
    let mut reported = coverage.is_some() || gaps_value.as_ref().is_some_and(Value::is_array);
    let nested_gaps: Option<Map<String, Value>> = match out.get("diff") {
        Some(Value::Object(diff)) if diff.contains_key("gaps_a") => Some(diff.clone()),
        _ => None,
    };
    let mut gaps = match gaps_value {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    if nested_gaps.is_some() {
        reported = true;
    }
    if gaps.len() > limit {
        truncated.set("gaps", (gaps.len() - limit) as u64);
        gaps.truncate(limit);
    }
    let revision: Value = out.get("revision").cloned().unwrap_or_else(|| requested_revision.cloned().unwrap_or(Value::Null));
    let mut fresh = Map::new();
    fresh.insert("revision".to_owned(), revision.clone());
    fresh.insert("gaps".to_owned(), Value::Array(gaps));
    fresh.insert("reported".to_owned(), Value::Bool(reported));
    if let Some(diff) = &nested_gaps {
        for key in ["gaps_a", "gaps_b", "revision_a", "revision_b"] {
            fresh.insert(key.to_owned(), diff.get(key).cloned().unwrap_or(Value::Null));
        }
    }
    out.shift_remove("coverage_revision");
    out.shift_remove("gaps");
    if !reported {
        fresh.insert(
            "note".to_owned(),
            Value::from("the engine reported no coverage for this answer; absence of events is not evidence of absence"),
        );
    }
    if let Some(map) = coverage.filter(|map| !map.is_empty()) {
        for (key, value) in map {
            if key != "revision" && key != "gaps" {
                fresh.insert(key, value);
            }
        }
    }
    out.insert("coverage".to_owned(), Value::Object(fresh));
    let mut ids = Vec::new();
    collect_members(&out, &mut ids, 0);
    let mut unique: Vec<String> = Vec::new();
    for id in ids.into_iter().filter(|id| is_event_id(id)) {
        if !unique.contains(&id) {
            unique.push(id);
        }
    }
    if let Some(session) = session {
        let citations = unique
            .iter()
            .take(MAX_CITATIONS)
            .map(|id| {
                let mut citation = Map::new();
                citation.insert("session".to_owned(), Value::from(session));
                citation.insert("event_id".to_owned(), Value::from(id.as_str()));
                citation.insert("revision".to_owned(), revision.clone());
                Value::Object(citation)
            })
            .collect();
        out.insert("citations".to_owned(), Value::Array(citations));
    }
    if unique.len() > MAX_CITATIONS {
        truncated.set("citations", (unique.len() - MAX_CITATIONS) as u64);
    }
    out.insert("revision".to_owned(), revision.clone());
    while map_len(&out) > MAX_REPLY_BYTES {
        let mut best: Option<(usize, String, Option<&'static str>, &'static str)> = None;
        for nested in holders(&out) {
            for key in list_keys() {
                let Some(Value::Array(items)) = holder_mut(&mut out, nested).get(key) else { continue };
                if items.len() <= 1 {
                    continue;
                }
                let candidate = (map_sum(items.iter().map(json_len), items.len()), label(nested, key), nested, key);
                if best.as_ref().is_none_or(|current| (candidate.0, &candidate.1) > (current.0, &current.1)) {
                    best = Some(candidate);
                }
            }
        }
        let Some((_, name, nested, key)) = best else { break };
        if let Some(Value::Array(items)) = holder_mut(&mut out, nested).get_mut(key) {
            let keep = (items.len() / 2).max(1);
            truncated.set(&name, truncated.get(&name) + (items.len() - keep) as u64);
            items.truncate(keep);
        }
    }
    if map_len(&out) > MAX_REPLY_BYTES {
        out = Map::new();
        out.insert("error".to_owned(), Value::from("reply_too_large"));
        out.insert(
            "message".to_owned(),
            Value::from(format!(
                "the engine's answer to {command} does not fit {MAX_REPLY_BYTES} bytes even cut to its heads; narrow the filter"
            )),
        );
        out.insert("revision".to_owned(), revision);
        truncated.set("reply", 1);
    }
    let complete = truncated.0.is_empty();
    let truncated_map: Map<String, Value> = truncated.0.into_iter().map(|(key, value)| (key, Value::from(value))).collect();
    let mut bounds = Map::new();
    bounds.insert("limit".to_owned(), Value::from(limit as u64));
    bounds.insert("max_reply_bytes".to_owned(), Value::from(MAX_REPLY_BYTES as u64));
    bounds.insert("truncated".to_owned(), Value::Object(truncated_map));
    bounds.insert("complete".to_owned(), Value::Bool(complete));
    out.insert("bounds".to_owned(), Value::Object(bounds));
    Value::Object(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn run(reply: Value, limit: usize) -> Value {
        shape(&reply, Some("s1"), "trace_query", limit, None)
    }

    #[test]
    fn json_len_is_the_length_of_the_compact_ascii_text() {
        for value in [
            json!(null),
            json!(true),
            json!(-12),
            json!(0),
            json!(u64::MAX),
            json!(1.5),
            json!(1e20),
            json!("é\u{1f600}\n"),
            json!([]),
            json!({}),
            json!([1, [2, 3], {"a": null, "\u{e9}": [true, false]}]),
        ] {
            let mut text = String::new();
            write_text(&value, &mut text);
            assert_eq!(json_len(&value), text.len(), "{value}");
        }
    }

    /// An independent writer of the compact ASCII text, for the length check.
    fn write_text(value: &Value, out: &mut String) {
        match value {
            Value::String(text) => crate::pyfmt::write_json_string(text, out),
            Value::Number(n) if n.is_f64() => out.push_str(&float_repr(n.as_f64().unwrap())),
            Value::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    write_text(item, out);
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                for (i, (key, item)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    crate::pyfmt::write_json_string(key, out);
                    out.push(':');
                    write_text(item, out);
                }
                out.push('}');
            }
            other => out.push_str(&other.to_string()),
        }
    }

    #[test]
    fn event_ids_follow_the_python_pattern_including_one_trailing_newline() {
        for (text, ok) in [
            ("e1", true),
            ("_x.y:z-1", true),
            ("e1\n", true),
            ("e1\n\n", false),
            ("", false),
            ("-a", false),
            ("a b", false),
            ("\u{e9}", false),
            (&"a".repeat(120), true),
            (&"a".repeat(121), false),
        ] {
            assert_eq!(is_event_id(text), ok, "{text:?}");
        }
    }

    #[test]
    fn lists_are_cut_at_the_limit_and_the_cut_is_reported() {
        let out = run(json!({"rows": [1, 2, 3, 4, 5], "revision": 7, "gaps": [1, 2, 3]}), 2);
        assert_eq!(out["rows"], json!([1, 2]));
        assert_eq!(out["bounds"]["truncated"], json!({"rows": 3, "gaps": 1}));
        assert_eq!(out["bounds"]["complete"], json!(false));
        assert_eq!(out["coverage"], json!({"revision": 7, "gaps": [1, 2], "reported": true}));
        assert!(out.get("gaps").is_none());
    }

    #[test]
    fn a_reply_without_coverage_says_so_and_a_non_object_reply_is_wrapped() {
        let out = run(json!([1]), 5);
        assert_eq!(out["result"], json!([1]));
        assert_eq!(out["coverage"]["reported"], json!(false));
        assert!(out["coverage"]["note"].as_str().unwrap().starts_with("the engine reported no coverage"));
        assert_eq!(out["bounds"]["complete"], json!(true));
    }

    #[test]
    fn citations_are_the_unique_event_ids_in_order() {
        let out = run(
            json!({"rows": [{"event_id": "e1"}, {"event_id": "e2"}, {"event_id": "e1"}], "root": "r", "events": ["x", {"event_id": "y"}, "bad id"]}),
            25,
        );
        let ids: Vec<&str> = out["citations"].as_array().unwrap().iter().map(|c| c["event_id"].as_str().unwrap()).collect();
        assert_eq!(ids, ["e1", "e2", "r", "x", "y"]);
    }

    #[test]
    fn nested_gaps_and_the_engines_own_coverage_are_carried() {
        let out = run(
            json!({"diff": {"gaps_a": [1], "revision_a": 3, "entries": [1, 2, 3]}, "coverage": {"revision": 9, "gaps": [], "extra": true, "reported": false}}),
            2,
        );
        assert_eq!(out["coverage"]["gaps_a"], json!([1]));
        assert_eq!(out["coverage"]["gaps_b"], json!(null));
        assert_eq!(out["coverage"]["extra"], json!(true));
        assert_eq!(out["coverage"]["reported"], json!(false));
        assert_eq!(out["diff"]["entries"], json!([1, 2]));
        assert_eq!(out["bounds"]["truncated"], json!({"diff.entries": 1}));
    }

    #[test]
    fn a_reply_over_the_byte_bound_is_halved_largest_list_first() {
        let rows: Vec<Value> = (0..200).map(|n| json!({"n": n, "text": "x".repeat(400)})).collect();
        let out = run(json!({"rows": rows, "nodes": [1, 2, 3]}), 200);
        assert!(map_len(out.as_object().unwrap()) <= MAX_REPLY_BYTES + 400);
        assert!(out["rows"].as_array().unwrap().len() < 200);
        assert_eq!(out["nodes"], json!([1, 2, 3]));
        assert!(out["bounds"]["truncated"]["rows"].as_u64().unwrap() > 0);
    }

    #[test]
    fn a_reply_that_cannot_be_cut_small_enough_is_refused() {
        let out = run(json!({"blob": "x".repeat(60_000), "revision": 4}), 25);
        assert_eq!(out["error"], json!("reply_too_large"));
        assert_eq!(out["revision"], json!(4));
        assert_eq!(out["bounds"]["truncated"], json!({"reply": 1}));
        assert!(out["message"].as_str().unwrap().contains("trace_query"));
    }

    #[test]
    fn key_order_is_the_pythons() {
        let out = run(json!({"rows": [], "coverage_revision": 1, "gaps": [], "revision": 2, "extra": 1}), 5);
        let keys: Vec<&String> = out.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["rows", "revision", "extra", "coverage", "citations", "bounds"]);
    }
}
