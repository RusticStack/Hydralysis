//! Revisions, subjects, effects and the dependency rule (`hydralysis.revisions`). Pure functions over JSON values.

use std::collections::BTreeSet;

use serde_json::{Map, Value, json};

use crate::classify::{ABSENT, WILDCARD};
use crate::error::{Error, Result};

pub const MAX_JOURNAL: usize = 1024;
pub const MAX_SUBJECTS: usize = 256;
pub const MAX_EFFECTS: usize = 4096;
pub const REPORT: &str = "report";
pub const FIELD_KINDS: [&str; 10] =
    ["name", "label", "comment", "signature", "type", "variable", "definition", "body", "existence", "report"];
const STRUCTURE_KINDS: [&str; 3] = ["function_create", "function_body", "function_delete"];
const BULK_KINDS: [&str; 2] = ["import_types", "import_archive"];

pub type Pair = (String, String);

/// `"address:" + hex(int(text.removeprefix("0x"), 16))`; `None` when the text is not hexadecimal.
fn address_subject(text: &str) -> Option<String> {
    let digits = text.strip_prefix("0x").unwrap_or(text);
    let value = u128::from_str_radix(digits, 16).ok()?;
    Some(format!("address:{value:#x}"))
}

fn as_str<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// What one edit record (address plus options) touches, as sorted subject strings.
pub fn subjects_of(address: &str, options: &Value) -> Vec<String> {
    let mut found: BTreeSet<String> = BTreeSet::new();
    let kind = as_str(options, "kind");
    if BULK_KINDS.contains(&kind) {
        found.insert(WILDCARD.into());
    } else if kind == "batch" {
        for child in options.get("edits").and_then(Value::as_array).into_iter().flatten() {
            let child_options = child.get("options").cloned().unwrap_or_else(|| json!({}));
            found.extend(subjects_of(as_str(child, "address"), &child_options));
        }
    } else {
        let path = as_str(options, "path");
        if kind == "struct" && !path.is_empty() {
            found.insert(format!("type:{path}"));
        }
        if !address.is_empty()
            && let Some(subject) = address_subject(address)
        {
            found.insert(subject);
        }
        if STRUCTURE_KINDS.contains(&kind) {
            found.insert("structure:functions".into());
        }
    }
    if found.is_empty() || found.len() > MAX_SUBJECTS {
        return vec![WILDCARD.into()];
    }
    found.into_iter().collect()
}

pub fn journal_entry(revision: i64, op: &str, subjects: &[String], by: Option<&Value>, at: f64) -> Value {
    let subjects: Vec<String> =
        if !subjects.is_empty() && subjects.len() <= MAX_SUBJECTS { subjects.to_vec() } else { vec![WILDCARD.into()] };
    json!({"revision": revision, "op": op, "subjects": subjects, "by": by.cloned().unwrap_or(Value::Null), "at": at})
}

/// `(journal + [entry])[-MAX_JOURNAL:]`
pub fn append(journal: &[Value], entry: Value) -> Vec<Value> {
    let mut all: Vec<Value> = journal.to_vec();
    all.push(entry);
    let skip = all.len().saturating_sub(MAX_JOURNAL);
    all.split_off(skip)
}

/// A stored journal as entries; anything malformed is dropped.
pub fn clean_journal(raw: Option<&Value>) -> Vec<Value> {
    let mut kept = Vec::new();
    for item in raw.and_then(Value::as_array).into_iter().flatten() {
        let Some(revision) = item.get("revision").and_then(Value::as_i64).filter(|_| item.get("revision").is_some_and(Value::is_number))
        else {
            continue;
        };
        let Some(subjects) = item.get("subjects").and_then(Value::as_array).filter(|a| a.iter().all(Value::is_string)) else {
            continue;
        };
        let op = match item.get("op") {
            None => String::new(),
            Some(Value::String(s)) => s.clone(),
            Some(Value::Null) => "None".into(),
            Some(other) => other.to_string(),
        };
        let by = item.get("by").filter(|b| b.is_object()).cloned().unwrap_or(Value::Null);
        kept.push(
            json!({"revision": revision, "op": op, "subjects": subjects, "by": by, "at": item.get("at").cloned().unwrap_or(Value::Null)}),
        );
    }
    let skip = kept.len().saturating_sub(MAX_JOURNAL);
    kept.split_off(skip)
}

/// Subjects of `left` that `right` also touches; a wildcard on either side overlaps everything.
pub fn overlaps(left: &BTreeSet<String>, right: &BTreeSet<String>) -> BTreeSet<String> {
    if left.contains(WILDCARD) {
        return if right.is_empty() { BTreeSet::from([WILDCARD.to_string()]) } else { right.clone() };
    }
    if right.contains(WILDCARD) {
        return left.clone();
    }
    left.intersection(right).cloned().collect()
}

/// Decide what a stale (or current) expected revision means for an edit touching `subjects`.
pub fn reconcile(expected: Option<i64>, revision: i64, journal: &[Value], subjects: &[String]) -> Value {
    let rev_of = |e: &Value| e.get("revision").and_then(Value::as_i64).unwrap_or(0);
    let later: Vec<&Value> = journal.iter().filter(|e| expected.is_some_and(|x| rev_of(e) > x)).collect();
    let latest = journal.iter().max_by_key(|e| rev_of(e));
    let editor = |e: &Value| json!({"by": e.get("by"), "at": e.get("at")});
    let mut result = Map::new();
    result.insert("current_revision".into(), json!(revision));
    result.insert("view_revision".into(), json!(revision));
    result.insert("latest_editor".into(), latest.map_or(Value::Null, editor));
    result.insert("subjects_changed_since".into(), json!([]));
    result.insert("history_complete".into(), json!(true));
    result.insert("overlapping".into(), json!([]));
    let finish = |mut r: Map<String, Value>, outcome: &str| {
        r.insert("outcome".into(), json!(outcome));
        Value::Object(r)
    };
    if expected == Some(revision) {
        return finish(result, "current");
    }
    if expected.is_none_or(|x| x > revision) {
        result.insert("history_complete".into(), json!(false));
        return finish(result, "conflict");
    }
    let expected = expected.unwrap_or(0);
    let have: BTreeSet<i64> = later.iter().map(|e| rev_of(e)).collect();
    let complete = ((expected + 1)..=revision).all(|n| have.contains(&n));
    result.insert("history_complete".into(), json!(complete));
    let mut changed: BTreeSet<String> = BTreeSet::new();
    for entry in &later {
        changed.extend(entry.get("subjects").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string));
    }
    result.insert("subjects_changed_since".into(), json!(changed));
    if let Some(last) = later.iter().max_by_key(|e| rev_of(e)) {
        result.insert("latest_editor".into(), editor(last));
    }
    let mine: BTreeSet<String> = subjects.iter().cloned().collect();
    let overlapping = if changed.is_empty() { BTreeSet::new() } else { overlaps(&mine, &changed) };
    let none = overlapping.is_empty();
    result.insert("overlapping".into(), json!(overlapping));
    finish(result, if complete && none { "rebased" } else { "conflict" })
}

/// The error body an agent receives: enough to decide whether to re-read or simply retry.
pub fn conflict_payload(expected: Option<i64>, decision: &Value, subjects: &[String]) -> Value {
    let current = decision["current_revision"].as_i64().unwrap_or(0);
    let reason = if expected.is_none_or(|x| x > current) {
        "expect_revision is not a revision of this view's store"
    } else if decision["history_complete"] != json!(true) {
        "history after your revision is incomplete; the edit cannot be proven independent"
    } else {
        "an edit after your revision touched the same subject"
    };
    json!({
        "conflict": "overlay revision changed", "reason": reason, "expected_revision": expected,
        "current_revision": decision["current_revision"], "view_revision": decision["view_revision"],
        "latest_editor": decision["latest_editor"], "last_edit_by": decision["latest_editor"].get("by").cloned().unwrap_or(Value::Null),
        "subjects_changed_since": decision["subjects_changed_since"], "history_complete": decision["history_complete"],
        "edit_subjects": subjects, "overlapping": decision["overlapping"],
        "suggest": format!("re-read the affected subjects (ghidra_query status shows the revision), then edit again with expect_revision={current}"),
    })
}

pub fn missing_payload(revision: i64, view: &str, what: &str) -> Value {
    json!({
        "error": "expect_revision_required", "view": view, "current_revision": revision, "view_revision": revision,
        "message": format!("{what} requires expect_revision on every view, including the shared one"),
        "suggest": format!("retry with expect_revision={revision} (the view's current revision), or read it with ghidra_query status"),
    })
}

pub fn field_kind(field: &str) -> &str {
    field.split(':').next().unwrap_or(field)
}

/// A stored or engine-reported effect list, validated; `None` stays `None` (a v2 record). Malformed is an error.
pub fn clean_effects(raw: Option<&Value>) -> Result<Option<Vec<Value>>> {
    let raw = match raw {
        None | Some(Value::Null) => return Ok(None),
        Some(r) => r,
    };
    let Some(list) = raw.as_array().filter(|l| l.len() <= MAX_EFFECTS) else {
        return Err(Error::value(format!("effects must be a list of at most {MAX_EFFECTS} entries")));
    };
    let mut clean = Vec::with_capacity(list.len());
    for item in list {
        let ok_keys =
            item.as_object().is_some_and(|m| m.len() == 4 && ["subject", "field", "before", "after"].iter().all(|k| m.contains_key(*k)));
        if !ok_keys {
            return Err(Error::value("an effect is {subject, field, before, after}"));
        }
        if item["subject"].as_str().is_none_or(str::is_empty) {
            return Err(Error::value("an effect needs a subject string"));
        }
        match item["field"].as_str() {
            Some(f) if FIELD_KINDS.contains(&field_kind(f)) => {}
            other => {
                return Err(Error::value(format!("unknown effect field {}", py_repr(&item["field"], other))));
            }
        }
        for side in ["before", "after"] {
            if !item[side].is_null() && !item[side].is_string() {
                return Err(Error::value(format!(
                    "effect {side} of {} must be text or null",
                    item["subject"].as_str().unwrap_or_default()
                )));
            }
        }
        clean.push(json!({"subject": item["subject"], "field": item["field"], "before": item["before"], "after": item["after"]}));
    }
    Ok(Some(clean))
}

/// `%r` of a JSON value for the common cases (str, None, number).
fn py_repr(v: &Value, s: Option<&str>) -> String {
    match (v, s) {
        (_, Some(s)) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        (Value::Null, _) => "None".into(),
        (Value::Bool(b), _) => if *b { "True" } else { "False" }.into(),
        (other, _) => other.to_string(),
    }
}

/// The (subject, field) pairs a record touches, from its options alone.
pub fn fields_of(address: &str, options: &Value) -> Vec<Pair> {
    let kind = as_str(options, "kind");
    let p = |a: &str, b: String| (a.to_string(), b);
    if BULK_KINDS.contains(&kind) {
        return vec![p(WILDCARD, REPORT.into())];
    }
    if kind == "batch" {
        let mut found: Vec<Pair> = Vec::new();
        for child in options.get("edits").and_then(Value::as_array).into_iter().flatten() {
            let child_options = child.get("options").cloned().unwrap_or_else(|| json!({}));
            for pair in fields_of(as_str(child, "address"), &child_options) {
                if !found.contains(&pair) {
                    found.push(pair);
                }
            }
        }
        return found;
    }
    if kind == "struct" {
        return vec![p(&format!("type:{}", as_str(options, "path")), "definition".into())];
    }
    let Some(where_) = (!address.is_empty()).then(|| address_subject(address)).flatten() else {
        return Vec::new();
    };
    let w = |f: String| (where_.clone(), f);
    match kind {
        "rename" => vec![w("name".into())],
        "label" => vec![w(format!("label:{}", as_str(options, "name")))],
        "comment" => vec![w("comment:plate".into())],
        "signature" => vec![w("signature".into())],
        "apply" => vec![w("type".into())],
        "variable" => vec![w(format!("variable:{}", as_str(options, "variable")))],
        "function_create" | "function_delete" => {
            vec![w("existence".into()), w("body".into()), w("name".into())]
        }
        "function_body" => {
            let mut v = vec![w("body".into())];
            if options.get("name").is_some_and(crate::records::truthy) {
                v.push(w("name".into()));
            }
            v
        }
        _ => Vec::new(),
    }
}

/// (subject, field) pairs of a stored record: its effects when it has them, else what its options imply.
pub fn touches(record: &Value) -> BTreeSet<Pair> {
    if let Some(effects) = record.get("effects").and_then(Value::as_array).filter(|e| !e.is_empty()) {
        return effects.iter().map(|e| (as_str(e, "subject").to_string(), as_str(e, "field").to_string())).collect();
    }
    let options = record.get("options").cloned().unwrap_or_else(|| json!({}));
    fields_of(as_str(record, "address"), &options).into_iter().collect()
}

/// Ids of the pending records, after the selected ones, whose `before` rests on a selected record's `after`; closed
/// (a record pulled in has dependents of its own), in `seq` order.
pub fn dependents(records: &[Value], selected: &BTreeSet<String>, committed: &BTreeSet<String>) -> Vec<String> {
    let seq = |r: &Value| r.get("seq").and_then(Value::as_i64).unwrap_or(0);
    let mut chain: Vec<&Value> = records.iter().filter(|r| !committed.contains(as_str(r, "id"))).collect();
    chain.sort_by_key(|r| seq(r));
    let mut taken: BTreeSet<String> = selected.clone();
    let mut found: Vec<String> = Vec::new();
    let non_report = |r: &Value| -> BTreeSet<Pair> { touches(r).into_iter().filter(|p| p.1 != REPORT).collect() };
    let mut changed = true;
    while changed {
        changed = false;
        for record in &chain {
            let id = as_str(record, "id");
            if taken.contains(id) {
                continue;
            }
            let mine = non_report(record);
            if mine.is_empty() {
                continue;
            }
            for earlier in &chain {
                if !taken.contains(as_str(earlier, "id")) || seq(earlier) >= seq(record) {
                    continue;
                }
                if !mine.is_disjoint(&non_report(earlier)) {
                    taken.insert(id.to_string());
                    found.push(id.to_string());
                    changed = true;
                    break;
                }
            }
        }
    }
    found.sort_by_key(|id| chain.iter().find(|r| as_str(r, "id") == id).map_or(0, |r| seq(r)));
    found
}

/// `ABSENT` as text (kept here so callers need not import `classify`).
pub const ABSENT_TEXT: &str = ABSENT;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subjects_by_kind() {
        assert_eq!(subjects_of("0x401000", &json!({"kind": "rename"})), ["address:0x401000"]);
        assert_eq!(subjects_of("401000", &json!({"kind": "function_body"})), ["address:0x401000", "structure:functions"]);
        assert_eq!(subjects_of("", &json!({"kind": "struct", "path": "/a/B"})), ["type:/a/B"]);
        assert_eq!(subjects_of("1", &json!({"kind": "import_types"})), ["*"]);
        assert_eq!(subjects_of("", &json!({"kind": "rename"})), ["*"]);
        let batch = json!({"kind": "batch", "edits": [{"address": "10", "options": {"kind": "rename"}}, {"address": "0x20", "options": {"kind": "label"}}]});
        assert_eq!(subjects_of("", &batch), ["address:0x10", "address:0x20"]);
    }

    #[test]
    fn journal_append_caps_and_clean_drops_malformed() {
        let mut j: Vec<Value> = Vec::new();
        for r in 0..(MAX_JOURNAL as i64 + 5) {
            j = append(&j, journal_entry(r, "edit", &[], None, 1.0));
        }
        assert_eq!(j.len(), MAX_JOURNAL);
        assert_eq!(j[0]["revision"], 5);
        assert_eq!(j[0]["subjects"], json!(["*"]));
        let raw =
            json!([{"revision": 1, "subjects": ["a"], "op": 3}, {"revision": true, "subjects": []}, {"revision": 2, "subjects": [1]}, "x"]);
        let c = clean_journal(Some(&raw));
        assert_eq!(c, vec![json!({"revision": 1, "op": "3", "subjects": ["a"], "by": null, "at": null})]);
    }

    #[test]
    fn reconcile_outcomes() {
        let j = vec![journal_entry(1, "e", &["a".into()], None, 1.0), journal_entry(2, "e", &["b".into()], None, 2.0)];
        assert_eq!(reconcile(Some(2), 2, &j, &["a".into()])["outcome"], "current");
        assert_eq!(reconcile(Some(1), 2, &j, &["a".into()])["outcome"], "rebased");
        let c = reconcile(Some(1), 2, &j, &["b".into()]);
        assert_eq!((c["outcome"].as_str(), c["overlapping"].clone()), (Some("conflict"), json!(["b"])));
        assert_eq!(reconcile(Some(0), 2, &j[1..], &["z".into()])["history_complete"], false);
        let n = reconcile(None, 2, &j, &["a".into()]);
        assert_eq!((n["outcome"].as_str(), n["history_complete"].clone()), (Some("conflict"), json!(false)));
        assert_eq!(
            conflict_payload(Some(9), &reconcile(Some(9), 2, &j, &[]), &[])["reason"],
            "expect_revision is not a revision of this view's store"
        );
    }

    #[test]
    fn effects_validation_and_dependents() {
        assert!(clean_effects(None).unwrap().is_none());
        assert_eq!(
            clean_effects(Some(&json!([{"subject": "s", "field": "label:x", "before": null, "after": "y"}]))).unwrap().unwrap().len(),
            1
        );
        for (bad, msg) in [
            (json!([{"subject": "s"}]), "an effect is {subject, field, before, after}"),
            (json!([{"subject": "", "field": "name", "before": null, "after": null}]), "an effect needs a subject string"),
            (json!([{"subject": "s", "field": "bogus", "before": null, "after": null}]), "unknown effect field 'bogus'"),
            (json!([{"subject": "s", "field": "name", "before": 1, "after": null}]), "effect before of s must be text or null"),
            (json!("x"), "effects must be a list of at most 4096 entries"),
        ] {
            assert_eq!(clean_effects(Some(&bad)).unwrap_err().to_string(), msg);
        }
        let rec = |id: &str, seq: i64, subject: &str| json!({"id": id, "seq": seq, "effects": [{"subject": subject, "field": "name", "before": null, "after": "x"}]});
        let records = vec![rec("a", 1, "s1"), rec("b", 2, "s2"), rec("c", 3, "s1"), rec("d", 4, "s1")];
        let sel: BTreeSet<String> = ["a".to_string()].into();
        assert_eq!(dependents(&records, &sel, &BTreeSet::new()), ["c", "d"]);
        assert_eq!(dependents(&records, &sel, &BTreeSet::from(["c".to_string()])), ["d"]);
    }
}
