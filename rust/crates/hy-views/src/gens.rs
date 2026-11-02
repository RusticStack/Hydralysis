//! The generation log as the views need it (`lineage.py`: `current_log`, `head`, `history`, `append_current`,
//! `read_manifest`) and what the master holds (`views.live_generations`, `master_ids`, `editors_since`).
//!
//! TODO(hy-store): the lineage half moves to the storage lane's `hy-store::lineage` when it lands; semantics are the same.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::classify::WILDCARD;
use crate::error::{Result, ViewError};
use crate::layout::{Settings, lineage_dir, now_iso};
use hy_core::appendlog::AppendLog;
use hy_core::json::canonical;
use hy_core::sealed::sha256_hex;

pub const MANIFEST: &str = "MANIFEST.json";

/// `lineage.current_log`.
pub fn current_log(settings: &Settings, lineage_id: &str) -> Result<AppendLog> {
    let mut log = AppendLog::new(lineage_dir(settings, lineage_id)?.join("CURRENT.log"));
    log.by = "lineage".into();
    Ok(log)
}

/// SHA-256 hex of the canonical JSON of `value` (`lineage.sha256_hex(lineage.canonical(value))`).
pub fn canonical_sha256(value: &Value) -> String {
    sha256_hex(&canonical(value))
}

/// Append one `CURRENT.log` line (the commit point of a publish). Fills `seq`, `at` and `prevHash`.
pub fn append_current(
    settings: &Settings,
    lineage_id: &str,
    record: &Map<String, Value>,
    lock_held: bool,
) -> Result<Value> {
    let log = current_log(settings, lineage_id)?;
    let build = |log: &AppendLog| -> Result<Value> {
        let previous = log.last(true)?;
        let mut line = Map::new();
        line.insert(
            "seq".into(),
            json!(
                previous
                    .as_ref()
                    .and_then(|p| p.get("seq"))
                    .and_then(Value::as_i64)
                    .map_or(1, |s| s + 1)
            ),
        );
        for (k, v) in record {
            line.insert(k.clone(), v.clone());
        }
        line.insert("at".into(), json!(now_iso()));
        line.insert(
            "prevHash".into(),
            previous
                .as_ref()
                .map_or(Value::Null, |p| json!(canonical_sha256(p))),
        );
        let line = Value::Object(line);
        log.append(&line, true)?;
        Ok(line)
    };
    if lock_held {
        return build(&log);
    }
    let _guard = hy_core::lock::lock(&log.lock_path, log.lock_timeout_s, "log CURRENT.log")?;
    log.repair(true)?;
    build(&log)
}

/// The head: the last valid `CURRENT.log` line, with what the reader saw (`torn_tail`, `corrupt`, `lines`).
/// A reader never repairs: a torn tail shows an older consistent state; a mid-log gap resolves to the last good line.
pub fn head(settings: &Settings, lineage_id: &str) -> Result<Map<String, Value>> {
    let log = current_log(settings, lineage_id)?;
    let scan = log.scan();
    let status = scan.as_status();
    let Some(last) = scan.records.last() else {
        return Err(ViewError::new(
            "no_lineage",
            format!("lineage {lineage_id} has no valid CURRENT.log line"),
        )
        .with("torn_tail", status["torn_tail"].clone())
        .with("corrupt", status["corrupt"].clone())
        .into());
    };
    for field in ["seq", "gen", "gpr"] {
        if last.get(field).is_none() {
            return Err(ViewError::new(
                "lineage_corrupt",
                format!("a CURRENT.log line has no {field}"),
            )
            .into());
        }
    }
    let mut result = last.as_object().cloned().unwrap_or_default();
    result.insert("torn_tail".into(), status["torn_tail"].clone());
    result.insert("corrupt".into(), status["corrupt"].clone());
    result.insert("lines".into(), json!(scan.records.len()));
    Ok(result)
}

pub fn history(settings: &Settings, lineage_id: &str) -> Result<Vec<Value>> {
    Ok(current_log(settings, lineage_id)?.scan().records)
}

/// `lineage.project_folder_of`: the folder of a `.gpr` path.
pub fn project_folder_of(gpr: &str) -> PathBuf {
    Path::new(gpr)
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_default()
}

/// `lineage.read_manifest`: the manifest of a generation folder, or `None` when missing or not a JSON object.
pub fn read_manifest(folder: &Path) -> Option<Map<String, Value>> {
    let data = std::fs::read(folder.join(MANIFEST)).ok()?;
    match serde_json::from_slice::<Value>(&data).ok()? {
        Value::Object(m) => Some(m),
        _ => None,
    }
}

fn manifest_of(row: &Value) -> Map<String, Value> {
    row.get("gpr")
        .and_then(Value::as_str)
        .and_then(|g| read_manifest(&project_folder_of(g)))
        .unwrap_or_default()
}

fn gen_of(row: &Value) -> Option<i64> {
    // Python `isinstance(row.get("gen"), int)` is true for bool too, but a log never carries one.
    row.get("gen").and_then(Value::as_i64)
}

/// The `CURRENT.log` lines of the generations that make up the master now, oldest first (a rollback removes later ones).
pub fn live_generations(settings: &Settings, lineage_id: &str) -> Result<Vec<Value>> {
    let mut chain: Vec<Value> = Vec::new();
    for row in history(settings, lineage_id)? {
        let Some(generation) = gen_of(&row) else {
            continue;
        };
        let reason = row.get("reason").and_then(Value::as_str);
        if reason == Some("commit") && generation > 0 {
            chain.retain(|item| gen_of(item).is_some_and(|g| g < generation));
            chain.push(row);
        } else if reason == Some("rollback") {
            chain.retain(|item| gen_of(item).is_some_and(|g| g <= generation));
        }
    }
    Ok(chain)
}

/// Ids of the records the master holds because of a generation after `after_generation`: `store.ids` of its manifest and
/// the ids the records were merged from.
pub fn master_ids(
    settings: &Settings,
    lineage_id: &str,
    after_generation: i64,
) -> Result<BTreeSet<String>> {
    let mut found = BTreeSet::new();
    for row in live_generations(settings, lineage_id)? {
        if gen_of(&row).is_some_and(|g| g > after_generation) {
            let manifest = manifest_of(&row);
            let store = manifest
                .get("store")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            for key in ["ids", "merged_from_ids"] {
                for id in store
                    .get(key)
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    if let Some(id) = id.as_str() {
                        found.insert(id.to_string());
                    }
                }
            }
        }
    }
    Ok(found)
}

pub fn in_master(record: &Value, ids: &BTreeSet<String>) -> bool {
    let id = record.get("id").and_then(Value::as_str).unwrap_or_default();
    ids.contains(id)
        || record
            .get("merged_from")
            .and_then(|m| m.get("id"))
            .and_then(Value::as_str)
            .is_some_and(|m| ids.contains(m))
}

/// Who moved the head after `base_generation`: the generation, its cid, the view(s) and the changesets. With `subjects`,
/// only the generations that touched one (`certain:true`) or that cannot say (`certain:false`).
pub fn editors_since(
    settings: &Settings,
    lineage_id: &str,
    base_generation: i64,
    subjects: Option<&BTreeSet<String>>,
) -> Result<Vec<Value>> {
    let mut rows = Vec::new();
    for row in live_generations(settings, lineage_id)? {
        let generation = gen_of(&row).unwrap_or(0);
        if generation <= base_generation {
            continue;
        }
        let manifest = manifest_of(&row);
        let store = manifest
            .get("store")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let touched = store
            .get("subjects")
            .filter(|v| !v.is_null())
            .and_then(Value::as_array);
        let certain = touched.is_some();
        if let (Some(wanted), Some(touched)) = (subjects, touched) {
            let names: BTreeSet<&str> = touched.iter().filter_map(Value::as_str).collect();
            if !names.iter().any(|n| wanted.contains(*n)) && !names.contains(WILDCARD) {
                continue;
            }
        }
        let views: BTreeSet<&str> = row
            .get("changesets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("view").and_then(Value::as_str))
            .filter(|v| !v.is_empty())
            .collect();
        rows.push(json!({
            "generation": generation, "cid": row.get("cid"), "view": store.get("view"),
            "views": if views.is_empty() { Value::Null } else { json!(views) },
            "at": row.get("at"), "certain": certain,
        }));
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(root: &Path) -> Settings {
        json!({"root": root.to_str().unwrap()})
            .as_object()
            .unwrap()
            .clone()
    }

    const L: &str = "L-0000abcd";

    fn gen_folder(root: &Path, n: u32, store: Value) -> String {
        let folder = root.join(format!("g{n}"));
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join(MANIFEST), json!({"store": store}).to_string()).unwrap();
        folder.join("p.gpr").display().to_string()
    }

    fn line(generation: i64, reason: &str, gpr: &str) -> Map<String, Value> {
        json!({"gen": generation, "reason": reason, "gpr": gpr, "cid": format!("c-{generation:04x}")}).as_object().unwrap().clone()
    }

    #[test]
    fn append_head_history_chain_the_hash() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path());
        assert_eq!(
            head(&s, L).unwrap_err().to_string(),
            "lineage L-0000abcd has no valid CURRENT.log line"
        );
        let a = append_current(&s, L, &line(0, "origin", "g0/p.gpr"), false).unwrap();
        let b = append_current(&s, L, &line(1, "commit", "g1/p.gpr"), false).unwrap();
        assert_eq!((a["seq"].as_i64(), b["seq"].as_i64()), (Some(1), Some(2)));
        assert_eq!(a["prevHash"], Value::Null);
        assert_eq!(b["prevHash"], json!(canonical_sha256(&a)));
        let h = head(&s, L).unwrap();
        assert_eq!((h["gen"].as_i64(), h["lines"].as_i64()), (Some(1), Some(2)));
        assert_eq!(h["torn_tail"], Value::Null);
        assert_eq!(history(&s, L).unwrap().len(), 2);
    }

    #[test]
    fn live_chain_master_ids_and_editors() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path());
        let g1 = gen_folder(
            d.path(),
            1,
            json!({"ids": ["e1"], "subjects": ["s1"], "view": "alice"}),
        );
        let g2 = gen_folder(
            d.path(),
            2,
            json!({"ids": ["e2"], "merged_from_ids": ["m9"], "subjects": ["s2"]}),
        );
        let g3 = gen_folder(d.path(), 3, json!({"ids": ["e3"]}));
        append_current(&s, L, &line(0, "origin", "x/p.gpr"), false).unwrap();
        append_current(&s, L, &line(1, "commit", &g1), false).unwrap();
        append_current(&s, L, &line(2, "commit", &g2), false).unwrap();
        append_current(&s, L, &line(3, "commit", &g3), false).unwrap();
        let ids = |after| {
            master_ids(&s, L, after)
                .unwrap()
                .into_iter()
                .collect::<Vec<_>>()
        };
        assert_eq!(ids(0), ["e1", "e2", "e3", "m9"]);
        assert_eq!(ids(1), ["e2", "e3", "m9"]);
        let mut rb = line(1, "rollback", &g1);
        rb.remove("cid");
        append_current(&s, L, &rb, false).unwrap();
        assert_eq!(ids(0), ["e1"]);
        assert!(in_master(
            &json!({"id": "x", "merged_from": {"id": "e1"}}),
            &master_ids(&s, L, 0).unwrap()
        ));
        let want: BTreeSet<String> = ["s1".to_string()].into();
        let rows = editors_since(&s, L, 0, Some(&want)).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(
            (
                rows[0]["generation"].as_i64(),
                rows[0]["certain"].as_bool(),
                rows[0]["view"].as_str()
            ),
            (Some(1), Some(true), Some("alice"))
        );
        let none: BTreeSet<String> = ["zzz".to_string()].into();
        assert!(editors_since(&s, L, 0, Some(&none)).unwrap().is_empty());
        assert_eq!(editors_since(&s, L, 0, None).unwrap().len(), 1);
    }
}
