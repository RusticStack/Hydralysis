//! The one rule of rebase, merge and publish: decide each record against the values live in the program it is going
//! into (`views.classify` and its helpers). Pure functions over JSON values; differential-tested against Python.

use std::collections::{BTreeSet, HashMap, HashSet};

use serde_json::{Map, Value, json};

/// `revisions.WILDCARD`: the subject of a bulk report, which cannot be checked.
pub const WILDCARD: &str = "*";
/// `revisions.ABSENT`: the text of a value that is not there.
pub const ABSENT: &str = "absent";

pub type Pair = (String, String);

/// `views._text`: `None` is `ABSENT`.
fn text(value: Option<&Value>) -> Value {
    match value {
        None | Some(Value::Null) => Value::String(ABSENT.into()),
        Some(v) => v.clone(),
    }
}

fn s(value: &Value, key: &str) -> String {
    value.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

/// The distinct (subject, field) pairs the records touch, in first-seen order, bulk subjects excluded.
pub fn probe_pairs(records: &[Value]) -> Vec<Pair> {
    let mut found = Vec::new();
    let mut seen = HashSet::new();
    for record in records {
        for effect in record.get("effects").and_then(Value::as_array).into_iter().flatten() {
            let pair = (s(effect, "subject"), s(effect, "field"));
            if pair.0 != WILDCARD && seen.insert(pair.clone()) {
                found.push(pair);
            }
        }
    }
    found
}

/// Decide each record against the values `live` (a probe of the program the records are going into). Records are taken
/// in `seq` order. Returns (verdicts, the chain after the accepted records).
pub fn classify(
    records: &[Value],
    live: &HashMap<Pair, Value>,
    chain: Option<&HashMap<Pair, Value>>,
) -> (Vec<Value>, HashMap<Pair, Value>) {
    let mut chain: HashMap<Pair, Value> = chain.cloned().unwrap_or_default();
    let mut blocked: HashSet<Pair> = HashSet::new();
    let mut verdicts = Vec::new();
    for record in records {
        let id = record.get("id").cloned().unwrap_or(Value::Null);
        let effects: &[Value] = record.get("effects").and_then(Value::as_array).map_or(&[], Vec::as_slice);
        if effects.is_empty() {
            verdicts.push(json!({"id": id, "outcome": "unchecked", "reason": "before_unknown"}));
            continue;
        }
        let mut states: Vec<&str> = Vec::new();
        let mut found: Option<Value> = None;
        let mut updates: HashMap<Pair, Value> = HashMap::new();
        for (index, effect) in effects.iter().enumerate() {
            let pair = (s(effect, "subject"), s(effect, "field"));
            let before = text(effect.get("before"));
            let after = text(effect.get("after"));
            if pair.0 == WILDCARD {
                states.push("unchecked");
                continue;
            }
            let raw_before = effect.get("before").cloned().unwrap_or(Value::Null);
            let raw_after = effect.get("after").cloned().unwrap_or(Value::Null);
            if blocked.contains(&pair) {
                found = Some(
                    json!({"subject": pair.0, "field": pair.1, "reason": "depends_on_conflict", "before": raw_before, "after": raw_after, "effect": index}),
                );
                break;
            }
            if chain.contains_key(&pair) || updates.contains_key(&pair) {
                let expected = updates.get(&pair).or_else(|| chain.get(&pair)).cloned().unwrap_or(Value::Null);
                if before != expected {
                    found = Some(
                        json!({"subject": pair.0, "field": pair.1, "reason": "chain", "before": raw_before, "now": expected, "after": raw_after, "effect": index}),
                    );
                    break;
                }
                states.push("apply");
            } else {
                match live.get(&pair) {
                    None | Some(Value::Null) => states.push("unchecked"),
                    Some(now) if *now == before => states.push("apply"),
                    Some(now) if *now == after => states.push("converged"),
                    Some(now) => {
                        found = Some(
                            json!({"subject": pair.0, "field": pair.1, "reason": "drift", "before": raw_before, "now": now, "after": raw_after, "effect": index}),
                        );
                        break;
                    }
                }
            }
            updates.insert(pair, after);
        }
        if found.is_none() && states.contains(&"converged") && states.iter().any(|st| *st != "converged") {
            let at = states.iter().position(|st| *st == "converged").unwrap_or(0);
            let first = &effects[at];
            let after = first.get("after").cloned().unwrap_or(Value::Null);
            found = Some(json!({"subject": first.get("subject"), "field": first.get("field"), "reason": "partially_converged",
                                "before": first.get("before"), "now": after, "after": after, "effect": at}));
        }
        if let Some(conflict) = found {
            for effect in effects {
                let subject = s(effect, "subject");
                if subject != WILDCARD {
                    blocked.insert((subject, s(effect, "field")));
                }
            }
            let mut row = Map::new();
            row.insert("id".into(), id);
            row.insert("outcome".into(), json!("conflict"));
            if let Value::Object(c) = conflict {
                row.extend(c);
            }
            verdicts.push(Value::Object(row));
            continue;
        }
        chain.extend(updates);
        let outcome = if !states.is_empty() && states.iter().all(|st| *st == "converged") {
            "converged"
        } else if !states.is_empty() && states.iter().all(|st| *st == "unchecked") {
            "unchecked"
        } else {
            "apply"
        };
        verdicts.push(json!({"id": id, "outcome": outcome}));
    }
    (verdicts, chain)
}

/// The conflict as an agent reads it: `theirs` is what the other side holds now.
pub fn conflict_row(verdict: &Value, record: &Value, editors: Option<&[Value]>) -> Value {
    let get = |k: &str| verdict.get(k).cloned().unwrap_or(Value::Null);
    let mut row = Map::new();
    row.insert("id".into(), record.get("id").cloned().unwrap_or(Value::Null));
    row.insert("subject".into(), get("subject"));
    row.insert("field".into(), get("field"));
    row.insert("reason".into(), get("reason"));
    row.insert("theirs".into(), get("now"));
    row.insert("mine".into(), get("after"));
    row.insert("before".into(), get("before"));
    row.insert("master_now".into(), get("now"));
    row.insert("after".into(), get("after"));
    row.insert("by".into(), record.get("by").cloned().unwrap_or(Value::Null));
    if let Some(editors) = editors.filter(|e| !e.is_empty()) {
        row.insert("editors".into(), Value::Array(editors.to_vec()));
    }
    Value::Object(row)
}

/// What `resolve` says about a conflict: by subject, else by `subject|field`. Empty strings count as unset, as in Python.
pub fn resolution(resolve: Option<&Map<String, Value>>, conflict: &Value) -> Option<String> {
    let resolve = resolve?;
    let subject = s(conflict, "subject");
    let pick = |k: &str| resolve.get(k).and_then(Value::as_str).filter(|v| !v.is_empty()).map(str::to_string);
    pick(&subject).or_else(|| pick(&format!("{subject}|{}", s(conflict, "field"))))
}

/// A set of subject names, sorted (helper for callers building `subjects` lists).
pub fn sorted_subjects<'a>(subjects: impl IntoIterator<Item = &'a str>) -> Vec<String> {
    subjects.into_iter().collect::<BTreeSet<_>>().into_iter().map(str::to_string).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn eff(subject: &str, field: &str, before: Option<&str>, after: Option<&str>) -> Value {
        json!({"subject": subject, "field": field, "before": before, "after": after})
    }

    fn rec(id: &str, effects: Vec<Value>) -> Value {
        json!({"id": id, "effects": effects})
    }

    fn live(items: &[(&str, &str, &str)]) -> HashMap<Pair, Value> {
        items.iter().map(|(a, b, v)| ((a.to_string(), b.to_string()), json!(v))).collect()
    }

    #[test]
    fn apply_converged_drift_and_unchecked() {
        let l = live(&[("a", "name", "old"), ("b", "name", "new"), ("c", "name", "other")]);
        let records = vec![
            rec("r1", vec![eff("a", "name", Some("old"), Some("new"))]),
            rec("r2", vec![eff("b", "name", Some("old"), Some("new"))]),
            rec("r3", vec![eff("c", "name", Some("old"), Some("new"))]),
            rec("r4", vec![eff("z", "name", Some("x"), Some("y"))]),
            json!({"id": "r5"}),
            rec("r6", vec![eff("*", "all", None, None)]),
        ];
        let (v, chain) = classify(&records, &l, None);
        let outcomes: Vec<_> = v.iter().map(|x| x["outcome"].as_str().unwrap()).collect();
        assert_eq!(outcomes, ["apply", "converged", "conflict", "unchecked", "unchecked", "unchecked"]);
        assert_eq!(v[2]["reason"], "drift");
        assert_eq!(v[2]["now"], "other");
        assert_eq!(v[2]["effect"], 0);
        assert_eq!(v[4]["reason"], "before_unknown");
        assert_eq!(chain[&("a".into(), "name".into())], "new");
        assert!(!chain.contains_key(&("c".to_string(), "name".to_string())));
    }

    #[test]
    fn chain_blocked_and_partial_convergence() {
        let l = live(&[("a", "n", "v0"), ("p", "n", "x1"), ("p", "m", "y0")]);
        let records = vec![
            rec("r1", vec![eff("a", "n", Some("v0"), Some("v1"))]),
            rec("r2", vec![eff("a", "n", Some("v1"), Some("v2"))]),
            rec("r3", vec![eff("a", "n", Some("WRONG"), Some("v3"))]),
            rec("r4", vec![eff("a", "n", Some("v2"), Some("v4"))]),
            rec("r5", vec![eff("p", "n", Some("x0"), Some("x1")), eff("p", "m", Some("y0"), Some("y1"))]),
        ];
        let (v, _) = classify(&records, &l, None);
        assert_eq!(v[1]["outcome"], "apply");
        assert_eq!((v[2]["outcome"].as_str(), v[2]["reason"].as_str()), (Some("conflict"), Some("chain")));
        assert_eq!(v[2]["now"], "v2");
        assert_eq!(v[3]["reason"], "depends_on_conflict");
        assert_eq!(v[4]["reason"], "partially_converged");
        assert_eq!(v[4]["effect"], 0);
        assert_eq!(v[4]["now"], "y1".replace("y1", "x1"));
    }

    #[test]
    fn probe_pairs_dedupes_in_order_and_skips_wildcard() {
        let rs = vec![rec(
            "a",
            vec![eff("s", "f", None, None), eff("*", "g", None, None), eff("s", "f", None, None), eff("t", "f", None, None)],
        )];
        assert_eq!(probe_pairs(&rs), [("s".to_string(), "f".to_string()), ("t".to_string(), "f".to_string())]);
    }

    #[test]
    fn resolution_by_subject_then_pair() {
        let c = json!({"subject": "s", "field": "f"});
        let r = json!({"s|f": "keep"});
        assert_eq!(resolution(r.as_object(), &c).as_deref(), Some("keep"));
        let r = json!({"s": "take_mine", "s|f": "keep"});
        assert_eq!(resolution(r.as_object(), &c).as_deref(), Some("take_mine"));
        assert_eq!(resolution(None, &c), None);
    }
}
