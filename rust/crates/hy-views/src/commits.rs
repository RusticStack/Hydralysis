//! Commit options, record selection, drift rule and the intent log (`commits.py`, the parts that need no engine).
//!
//! The engine-driven commit itself (`_commit`, `_verify_candidate`, `finalize`, `revert`) is not ported yet; it will use the
//! [`crate::engine::Engine`] trait.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{Map, Value, json};

use crate::classify::{ABSENT, WILDCARD};
use crate::error::{Error, Result};
use crate::gens;
use crate::layout::{Settings, lineage_dir, now_iso};
use crate::revisions;
use crate::store::{Store, pending_of};
use hy_core::appendlog::AppendLog;

pub const SAMPLE_PER_KIND: usize = 25;
pub const SPOT_CHECK: usize = 25;
pub const VERIFY_PARALLEL: usize = 8;
pub const SNAPSHOT_BUDGET_S: f64 = 20.0;
pub const STEPS: [&str; 12] = [
    "PREPARE",
    "BACKUP_DONE",
    "CANDIDATE_RESERVED",
    "FORKED",
    "APPLIED",
    "FILES_FORCED",
    "MANIFEST",
    "VERIFIED",
    "SEALED",
    "PUBLISHED",
    "FINALIZED",
    "ABORTED",
];
pub const CONFIRMATION: &str = "After this commit only engines whose program database version is at least this engine's can open the new generation (the original project is never changed, and a revert returns to it). Repeat with confirm_one_way_upgrade:true to go on.";
pub const COMMIT_KEYS: [&str; 14] = [
    "kind",
    "cid",
    "expect_revision",
    "confirm_one_way_upgrade",
    "on_drift",
    "only",
    "include_dependencies",
    "dry_run",
    "backup",
    "confirm_large",
    "allow_unverified_before",
    "resume_verified",
    "source",
    "snapshot_budget_s",
];

/// A commit refusal or abort with a stable `code` (`commits.CommitError`).
pub type CommitError = crate::error::ViewError;

/// `c-` plus eight hex digits.
pub fn new_cid() -> String {
    let mut b = [0u8; 4];
    getrandom::fill(&mut b).expect("OS randomness");
    format!("c-{}", hex::encode(b))
}

fn is_cid(text: &str) -> bool {
    text.strip_prefix("c-").is_some_and(|r| {
        (4..=16).contains(&r.len())
            && r.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

fn is_nonneg_int(v: &Value) -> bool {
    v.as_i64().is_some_and(|n| n >= 0) && v.is_number()
}

/// The commit options, checked. Unknown keys are refused, so a typo never silently changes a one-way operation.
pub fn validate(options: &Value) -> Result<Map<String, Value>> {
    let Value::Object(options) = options else {
        return Err(Error::value("options must be an object"));
    };
    let kind = options
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if !["commit", "commit_revert", "commit_abort"].contains(&kind) {
        return Err(Error::value(
            "kind must be commit, commit_revert or commit_abort",
        ));
    }
    let mut extra: Vec<&str> = options
        .keys()
        .map(String::as_str)
        .filter(|k| !COMMIT_KEYS.contains(k))
        .collect();
    if !extra.is_empty() {
        extra.sort_unstable();
        return Err(Error::value(format!(
            "options do not belong to {kind}: {}",
            extra.join(", ")
        )));
    }
    let out = options.clone();
    if kind != "commit_abort" && !out.get("expect_revision").is_some_and(is_nonneg_int) {
        return Err(Error::value(
            "expect_revision (the store revision you read) is required",
        ));
    }
    if out
        .get("cid")
        .is_some_and(|c| !c.as_str().is_some_and(is_cid))
    {
        return Err(Error::value("cid must look like c-1a2b3c4d"));
    }
    if kind == "commit_abort" && !out.contains_key("cid") {
        return Err(Error::value("commit_abort needs the cid"));
    }
    for name in [
        "confirm_one_way_upgrade",
        "include_dependencies",
        "dry_run",
        "confirm_large",
        "allow_unverified_before",
        "resume_verified",
    ] {
        if out.get(name).is_some_and(|v| !v.is_boolean()) {
            return Err(Error::value(format!("{name} must be a boolean")));
        }
    }
    if !matches!(
        out.get("on_drift").unwrap_or(&json!("refuse")).as_str(),
        Some("refuse" | "skip")
    ) {
        return Err(Error::value("on_drift must be refuse or skip"));
    }
    if let Some(only) = out.get("only").filter(|o| !o.is_null()) {
        let Some(only) = only
            .as_object()
            .filter(|o| o.keys().all(|k| k == "ids" || k == "authors"))
        else {
            return Err(Error::value("only is {ids, authors}"));
        };
        for name in ["ids", "authors"] {
            if let Some(v) = only.get(name).filter(|v| !v.is_null())
                && !v.as_array().is_some_and(|a| a.iter().all(Value::is_string))
            {
                return Err(Error::value(format!(
                    "only.{name} must be a list of text or null"
                )));
            }
        }
    }
    if let Some(b) = out.get("backup")
        && b.as_str() != Some("auto")
        && !b.is_string()
    {
        return Err(Error::value(
            "backup must be auto or the id of a verified backup",
        ));
    }
    let budget = out
        .get("snapshot_budget_s")
        .cloned()
        .unwrap_or_else(|| json!(SNAPSHOT_BUDGET_S));
    if !budget.is_number() || !budget.as_f64().is_some_and(|b| (1.0..=600.0).contains(&b)) {
        return Err(Error::value("snapshot_budget_s must be 1..600"));
    }
    Ok(out)
}

fn id_of(r: &Value) -> &str {
    r.get("id").and_then(Value::as_str).unwrap_or_default()
}

/// record id -> ids of the EARLIER pending records it depends on (a shared coarse subject; `*` shares with all).
pub fn depends(records: &[Value]) -> HashMap<String, BTreeSet<String>> {
    let subjects: Vec<BTreeSet<String>> = records
        .iter()
        .map(|r| {
            let options = r.get("options").cloned().unwrap_or_else(|| json!({}));
            revisions::subjects_of(
                r.get("address").and_then(Value::as_str).unwrap_or_default(),
                &options,
            )
            .into_iter()
            .collect()
        })
        .collect();
    let mut found = HashMap::new();
    for (index, record) in records.iter().enumerate() {
        let mine = &subjects[index];
        let earlier: BTreeSet<String> = (0..index)
            .filter(|&j| {
                !mine.is_disjoint(&subjects[j])
                    || mine.contains(WILDCARD)
                    || subjects[j].contains(WILDCARD)
            })
            .map(|j| id_of(&records[j]).to_string())
            .collect();
        found.insert(id_of(record).to_string(), earlier);
    }
    found
}

fn seq_of(r: &Value) -> i64 {
    r.get("seq").and_then(Value::as_i64).unwrap_or(0)
}

/// The records S of a commit in `seq` order, closed under dependency and batch (or `selection_not_closed`).
/// Returns (S, added): the ids the closure added because `include_dependencies` was set.
pub fn select(
    store: &Store,
    only: Option<&Value>,
    include_dependencies: bool,
) -> Result<(Vec<Value>, Vec<String>)> {
    let mut pending = pending_of(store);
    pending.sort_by_key(seq_of);
    let ids = only.and_then(|o| o.get("ids")).filter(|v| !v.is_null());
    let authors = only.and_then(|o| o.get("authors")).filter(|v| !v.is_null());
    if only.is_none_or(|o| !crate::records::truthy(o)) || (ids.is_none() && authors.is_none()) {
        return Ok((pending, Vec::new()));
    }
    let strings = |v: Option<&Value>| -> BTreeSet<String> {
        v.and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect()
    };
    let wanted = strings(ids);
    let authors = strings(authors);
    let batch_of = |r: &Value| {
        r.get("batch")
            .filter(|b| crate::records::truthy(b))
            .and_then(Value::as_str)
            .map(str::to_string)
    };
    let mut known: BTreeSet<String> = pending.iter().map(|r| id_of(r).to_string()).collect();
    known.extend(pending.iter().filter_map(batch_of));
    let unknown: Vec<String> = wanted
        .iter()
        .filter(|i| !known.contains(*i))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(CommitError::new(
            "unknown_records",
            format!(
                "these ids are not pending records or batches of this view: {}",
                unknown.join(", ")
            ),
        )
        .with("ids", json!(unknown))
        .into());
    }
    let by_author = |r: &Value| {
        let by = r.get("by");
        let get = |k: &str| {
            by.and_then(|b| b.get(k))
                .and_then(Value::as_str)
                .is_some_and(|v| authors.contains(v))
        };
        !authors.is_empty() && (get("harness") || get("client"))
    };
    let chosen: BTreeSet<String> = pending
        .iter()
        .filter(|r| {
            wanted.contains(id_of(r))
                || batch_of(r).is_some_and(|b| wanted.contains(&b))
                || by_author(r)
        })
        .map(|r| id_of(r).to_string())
        .collect();
    let deps = depends(&pending);
    let mut batches: HashMap<String, BTreeSet<String>> = HashMap::new();
    for r in &pending {
        if let Some(b) = batch_of(r) {
            batches.entry(b).or_default().insert(id_of(r).to_string());
        }
    }
    let mut closed = chosen.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for ident in closed.clone() {
            let mut needed = deps.get(&ident).cloned().unwrap_or_default();
            if let Some(record) = pending.iter().find(|r| id_of(r) == ident)
                && let Some(b) = batch_of(record)
            {
                needed.extend(batches[&b].iter().cloned());
            }
            if !needed.is_subset(&closed) {
                closed.extend(needed);
                changed = true;
            }
        }
    }
    let mut missing: Vec<String> = closed.difference(&chosen).cloned().collect();
    missing.sort_by_key(|i| pending.iter().find(|r| id_of(r) == i).map_or(0, seq_of));
    if !missing.is_empty() && !include_dependencies {
        return Err(CommitError::new(
            "selection_not_closed",
            format!("the selection depends on {} pending record(s) it does not name; name them or pass include_dependencies:true", missing.len()),
        )
        .with("missing", json!(missing))
        .into());
    }
    Ok((
        pending
            .into_iter()
            .filter(|r| closed.contains(id_of(r)))
            .collect(),
        missing,
    ))
}

/// Every later record of `records` that depends, directly or through others, on a drifted one.
pub fn later_dependents(records: &[Value], drifted: &BTreeSet<String>) -> BTreeSet<String> {
    let deps = depends(records);
    let mut taken = drifted.clone();
    let mut changed = true;
    while changed {
        changed = false;
        for r in records {
            let id = id_of(r);
            if !taken.contains(id) && deps.get(id).is_some_and(|d| !d.is_disjoint(&taken)) {
                taken.insert(id.to_string());
                changed = true;
            }
        }
    }
    taken
}

type Pair = (String, String);

/// The first effect of each (subject, field) in `seq` order: what a drift check must probe in the program, in the order the
/// pairs were first met.
pub fn drift_pairs(records: &[Value]) -> Vec<Pair> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for r in records {
        for e in r
            .get("effects")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let pair = (
                e["subject"].as_str().unwrap_or_default().to_string(),
                e["field"].as_str().unwrap_or_default().to_string(),
            );
            if pair.0 != WILDCARD && seen.insert(pair.clone()) {
                out.push(pair);
            }
        }
    }
    out
}

/// The records whose first effect on a (subject, field) no longer finds its `before` in the program (`live`), or whose chain
/// breaks. Later effects on a pair are chain-checked offline. Bulk reports (`*`) are checked by input hash elsewhere.
pub fn drift_verdicts(records: &[Value], live: &HashMap<Pair, Value>) -> Vec<Value> {
    let mut first: Vec<(Pair, &Value, &Value)> = Vec::new();
    let mut index: HashMap<Pair, usize> = HashMap::new();
    let mut drifted: HashMap<String, Value> = HashMap::new();
    let mut last_after: HashMap<Pair, Value> = HashMap::new();
    for r in records {
        for e in r
            .get("effects")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let pair = (
                e["subject"].as_str().unwrap_or_default().to_string(),
                e["field"].as_str().unwrap_or_default().to_string(),
            );
            if pair.0 == WILDCARD {
                continue;
            }
            if !index.contains_key(&pair) {
                index.insert(pair.clone(), first.len());
                first.push((pair.clone(), r, e));
            } else if e["before"] != *last_after.get(&pair).unwrap_or(&Value::Null)
                && !drifted.contains_key(id_of(r))
            {
                drifted.insert(
                    id_of(r).to_string(),
                    json!({"id": id_of(r), "subject": pair.0, "field": pair.1, "reason": "chain", "expected": e["before"],
                           "found": last_after.get(&pair).cloned().unwrap_or(Value::Null)}),
                );
            }
            last_after.insert(pair, e["after"].clone());
        }
    }
    for (pair, r, e) in &first {
        let expected = if e["before"].is_null() {
            json!(ABSENT)
        } else {
            e["before"].clone()
        };
        if let Some(found) = live.get(pair).filter(|f| !f.is_null())
            && *found != expected
            && !drifted.contains_key(id_of(r))
        {
            drifted.insert(
                id_of(r).to_string(),
                json!({"id": id_of(r), "subject": pair.0, "field": pair.1, "reason": "drift", "expected": e["before"], "found": found}),
            );
        }
    }
    records
        .iter()
        .filter_map(|r| drifted.get(id_of(r)).cloned())
        .collect()
}

// ---- intent log -------------------------------------------------------------------------------------------------

/// `lineage.intent_log`: `commits/<cid>.intent.log`.
pub fn intent_log(settings: &Settings, lineage_id: &str, cid: &str) -> Result<AppendLog> {
    if !is_cid(cid) {
        return Err(Error::value("invalid commit id"));
    }
    let mut log = AppendLog::new(
        lineage_dir(settings, lineage_id)?
            .join("commits")
            .join(format!("{cid}.intent.log")),
    );
    log.by = "commit".into();
    Ok(log)
}

/// One commit's intent log: forced, CRC-framed lines, each with the attempt number and the step.
pub struct Intent {
    log: AppendLog,
    pub cid: String,
    pub attempt: i64,
}

impl Intent {
    pub fn new(settings: &Settings, lineage_id: &str, cid: &str, attempt: i64) -> Result<Self> {
        Ok(Self {
            log: intent_log(settings, lineage_id, cid)?,
            cid: cid.into(),
            attempt,
        })
    }

    pub fn write(&self, step: &str, data: Map<String, Value>) -> Result<()> {
        let mut line = Map::new();
        line.insert("cid".into(), json!(self.cid));
        line.insert("attempt".into(), json!(self.attempt));
        line.insert("step".into(), json!(step));
        line.insert("at".into(), json!(now_iso()));
        line.extend(data);
        self.log.append(&Value::Object(line), false)?;
        Ok(())
    }
}

fn attempt_of(row: &Value) -> i64 {
    row.get("attempt").and_then(Value::as_i64).unwrap_or(0)
}

pub fn next_attempt(settings: &Settings, lineage_id: &str, cid: &str) -> Result<i64> {
    let rows = intent_log(settings, lineage_id, cid)?.scan().records;
    Ok(rows.iter().map(attempt_of).max().unwrap_or(0) + 1)
}

/// The newest attempt of a commit: its number, last step and the data of the steps it passed.
pub fn last_steps(settings: &Settings, lineage_id: &str, cid: &str) -> Result<Value> {
    let rows = intent_log(settings, lineage_id, cid)?.scan().records;
    if rows.is_empty() {
        return Ok(json!({"attempt": 0, "step": null, "data": {}}));
    }
    let attempt = rows.iter().map(attempt_of).max().unwrap_or(0);
    let mine: Vec<&Value> = rows
        .iter()
        .filter(|r| r.get("attempt").and_then(Value::as_i64) == Some(attempt))
        .collect();
    let mut data = Map::new();
    for row in &mine {
        for (k, v) in row.as_object().into_iter().flatten() {
            if !["cid", "attempt", "step", "at"].contains(&k.as_str()) {
                data.insert(k.clone(), v.clone());
            }
        }
    }
    Ok(
        json!({"attempt": attempt, "step": mine.last().and_then(|r| r.get("step")), "data": data, "rows": mine}),
    )
}

/// The cids that have an intent log, sorted.
pub fn intent_cids(settings: &Settings, lineage_id: &str) -> Result<Vec<String>> {
    let folder = lineage_dir(settings, lineage_id)?.join("commits");
    let Ok(entries) = std::fs::read_dir(folder) else {
        return Ok(Vec::new());
    };
    let mut found: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.starts_with("c-"))
        .filter_map(|n| n.strip_suffix(".intent.log").map(str::to_string))
        .collect();
    found.sort();
    Ok(found)
}

/// Group ids by their first character, only to keep `BTreeMap` used for deterministic reports in callers.
pub fn index_by_id(records: &[Value]) -> BTreeMap<String, &Value> {
    records.iter().map(|r| (id_of(r).to_string(), r)).collect()
}

/// `gens` re-export for callers that publish a commit line.
pub use gens::append_current;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::empty_store;

    #[test]
    fn option_refusals_match_python_text() {
        let m = |v: Value| validate(&v).unwrap_err().to_string();
        assert_eq!(m(json!(1)), "options must be an object");
        assert_eq!(
            m(json!({"kind": "x"})),
            "kind must be commit, commit_revert or commit_abort"
        );
        assert_eq!(
            m(json!({"kind": "commit", "bogus": 1, "a": 2})),
            "options do not belong to commit: a, bogus"
        );
        assert_eq!(
            m(json!({"kind": "commit"})),
            "expect_revision (the store revision you read) is required"
        );
        assert_eq!(
            m(json!({"kind": "commit", "expect_revision": 0, "cid": "c-xyz"})),
            "cid must look like c-1a2b3c4d"
        );
        assert_eq!(
            m(json!({"kind": "commit_abort"})),
            "commit_abort needs the cid"
        );
        assert_eq!(
            m(json!({"kind": "commit", "expect_revision": 0, "dry_run": 1})),
            "dry_run must be a boolean"
        );
        assert_eq!(
            m(json!({"kind": "commit", "expect_revision": 0, "on_drift": "x"})),
            "on_drift must be refuse or skip"
        );
        assert_eq!(
            m(json!({"kind": "commit", "expect_revision": 0, "only": {"zz": 1}})),
            "only is {ids, authors}"
        );
        assert_eq!(
            m(json!({"kind": "commit", "expect_revision": 0, "only": {"ids": [1]}})),
            "only.ids must be a list of text or null"
        );
        assert_eq!(
            m(json!({"kind": "commit", "expect_revision": 0, "snapshot_budget_s": 0})),
            "snapshot_budget_s must be 1..600"
        );
        assert!(validate(&json!({"kind": "commit_abort", "cid": "c-1a2b3c4d"})).is_ok());
    }

    fn rec(id: &str, seq: i64, address: &str, batch: Option<&str>, by: &str) -> Value {
        let mut r = json!({"id": id, "seq": seq, "address": address, "options": {"kind": "rename"}, "by": {"harness": by}, "effects": null});
        if let Some(b) = batch {
            r["batch"] = json!(b);
        }
        r
    }

    #[test]
    fn selection_closes_under_dependency_and_batch() {
        let mut store = empty_store("x");
        store.insert(
            "edits".into(),
            json!([
                rec("a", 1, "0x10", None, "h1"),
                rec("b", 2, "0x20", Some("B"), "h2"),
                rec("c", 3, "0x10", None, "h2"),
                rec("d", 4, "0x30", Some("B"), "h2")
            ]),
        );
        let (all, added) = select(&store, None, false).unwrap();
        assert_eq!((all.len(), added.len()), (4, 0));
        let only = json!({"ids": ["c"]});
        let e = select(&store, Some(&only), false).unwrap_err();
        assert_eq!(
            e.to_string(),
            "the selection depends on 1 pending record(s) it does not name; name them or pass include_dependencies:true"
        );
        let (sel, added) = select(&store, Some(&only), true).unwrap();
        assert_eq!(sel.iter().map(id_of).collect::<Vec<_>>(), ["a", "c"]);
        assert_eq!(added, ["a"]);
        let (sel, _) = select(&store, Some(&json!({"ids": ["B"]})), true).unwrap();
        assert_eq!(sel.iter().map(id_of).collect::<Vec<_>>(), ["b", "d"]);
        let e = select(&store, Some(&json!({"ids": ["nope"]})), false).unwrap_err();
        assert_eq!(
            e.to_string(),
            "these ids are not pending records or batches of this view: nope"
        );
        let (sel, _) = select(&store, Some(&json!({"authors": ["h1"]})), false).unwrap();
        assert_eq!(sel.iter().map(id_of).collect::<Vec<_>>(), ["a"]);
    }

    #[test]
    fn drift_chain_and_probe() {
        let e = |s: &str, b: Option<&str>, a: &str| json!({"subject": s, "field": "name", "before": b, "after": a});
        let records = vec![
            json!({"id": "r1", "effects": [e("s1", Some("o"), "n1")]}),
            json!({"id": "r2", "effects": [e("s1", Some("WRONG"), "n2")]}),
            json!({"id": "r3", "effects": [e("s2", None, "x")]}),
            json!({"id": "r4", "effects": [e("*", None, "x")]}),
        ];
        assert_eq!(
            drift_pairs(&records),
            [
                ("s1".to_string(), "name".to_string()),
                ("s2".to_string(), "name".to_string())
            ]
        );
        let live: HashMap<Pair, Value> = [
            (("s1".into(), "name".into()), json!("changed")),
            (("s2".into(), "name".into()), json!("absent")),
        ]
        .into();
        let v = drift_verdicts(&records, &live);
        assert_eq!(v.len(), 2);
        assert_eq!(
            (
                v[0]["id"].as_str(),
                v[0]["reason"].as_str(),
                v[0]["found"].clone()
            ),
            (Some("r1"), Some("drift"), json!("changed"))
        );
        assert_eq!(
            (v[1]["id"].as_str(), v[1]["reason"].as_str()),
            (Some("r2"), Some("chain"))
        );
        assert_eq!(
            later_dependents(
                &[
                    rec("a", 1, "0x10", None, "h"),
                    rec("b", 2, "0x20", None, "h"),
                    rec("c", 3, "0x10", None, "h")
                ],
                &BTreeSet::from(["a".to_string()])
            ),
            BTreeSet::from(["a".to_string(), "c".to_string()])
        );
    }

    #[test]
    fn intent_log_attempts_and_steps() {
        let d = tempfile::Builder::new().prefix("hc").tempdir().unwrap();
        let s: Settings = json!({"root": d.path().to_str().unwrap()})
            .as_object()
            .unwrap()
            .clone();
        let l = "L-0000abcd";
        assert_eq!(next_attempt(&s, l, "c-0001").unwrap(), 1);
        assert_eq!(
            last_steps(&s, l, "c-0001").unwrap(),
            json!({"attempt": 0, "step": null, "data": {}})
        );
        let one = Intent::new(&s, l, "c-0001", 1).unwrap();
        one.write("PREPARE", Map::new()).unwrap();
        one.write(
            "CANDIDATE_RESERVED",
            json!({"generation": 3}).as_object().unwrap().clone(),
        )
        .unwrap();
        let two = Intent::new(&s, l, "c-0001", 2).unwrap();
        two.write("PREPARE", json!({"x": 1}).as_object().unwrap().clone())
            .unwrap();
        assert_eq!(next_attempt(&s, l, "c-0001").unwrap(), 3);
        let st = last_steps(&s, l, "c-0001").unwrap();
        assert_eq!(
            (
                st["attempt"].clone(),
                st["step"].clone(),
                st["data"].clone()
            ),
            (json!(2), json!("PREPARE"), json!({"x": 1}))
        );
        Intent::new(&s, l, "c-0002", 1)
            .unwrap()
            .write("PREPARE", Map::new())
            .unwrap();
        assert_eq!(intent_cids(&s, l).unwrap(), ["c-0001", "c-0002"]);
        assert_eq!(
            intent_log(&s, l, "bad").err().unwrap().to_string(),
            "invalid commit id"
        );
    }
}
