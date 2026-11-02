//! The disk-only half of the publish/commit crash-safety story: finalizing a decided changeset in the view that sealed it,
//! settling publishes the leader did not finalize, finalizing a commit, and the per-view lock (`views.finalize_changeset`,
//! `views.settle`, `views._base_move_subjects`, `commits.finalize`, `commits._archive`, `workcopy.view_lock`).
//!
//! The engine-side effects of these in Python (`workcopy.retire_copies`) are a callback: the host closes the view's working
//! copies; a failure there never undoes the finalize.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::{Map, Value, json};

use crate::classify::WILDCARD;
use crate::commits::{CommitError, Intent};
use crate::error::{Error, Result};
use crate::gens::{live_generations, read_manifest};
use crate::layout::{Settings, generation_dir, now_f64, root_path};
use crate::records::{agent_name, truthy};
use crate::revisions;
use crate::store::{
    self, Store, Target, committed_ids, digest_of, load_store, pending_of, save_store,
};

/// The per-view lock bound (D44).
pub const SYNC_LOCK_S: f64 = 30.0;

/// `json.dumps(value)` with Python's default separators.
pub fn py_dumps(value: &Value) -> String {
    String::from_utf8_lossy(&hy_core::json::dumps(
        value,
        hy_core::json::Options {
            layout: hy_core::json::Layout::Spaced,
            sort_keys: false,
            ensure_ascii: true,
        },
    ))
    .into_owned()
}

fn tkey(target: &Target) -> &str {
    target
        .get("key")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// The per-view lock (`workcopy.view_lock`): bounded, OS-held, so a killed holder frees it. A wait that runs out is the
/// structured `busy`, carried as a `Runtime` error holding the JSON payload, as Python's RuntimeError does.
pub fn view_lock(
    settings: &Settings,
    target: &Target,
    wait_s: Option<f64>,
) -> Result<hy_core::lock::LockGuard> {
    let path = store::directory(settings, target).join(".view.lock");
    hy_core::lock::lock(&path, wait_s.unwrap_or(SYNC_LOCK_S), "working copy").map_err(|e| match e {
        hy_core::Error::LockBusy { what, lock, waited_s, retry_after_ms, .. } => Error::Runtime(py_dumps(&json!({
            "error": "busy", "what": what, "lock": lock, "waited_s": waited_s, "retryAfterMs": retry_after_ms,
            "suggest": "another client holds this lock; retry after retryAfterMs, nothing was changed",
        }))),
        other => other.into(),
    })
}

/// `{client, harness}` of the caller (`workcopy._attribution`).
pub fn attribution() -> Value {
    json!({"client": format!("rusticre:{}", std::process::id()), "harness": agent_name()})
}

fn archive_path(settings: &Settings, selected: &Target, cid: &str) -> PathBuf {
    root_path(settings)
        .join("overlays")
        .join("archive")
        .join(tkey(selected))
        .join(format!("{cid}.records.json"))
}

/// Move the previous live commit's records out of `edits[]` into a sealed archive file (4.2); never deleted.
pub fn archive(
    settings: &Settings,
    selected: &Target,
    store: &mut Store,
    entry: &Value,
) -> Result<()> {
    let ids: BTreeSet<&str> = entry["ids"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let edits = store["edits"].as_array().cloned().unwrap_or_default();
    let (records, rest): (Vec<Value>, Vec<Value>) = edits
        .into_iter()
        .partition(|r| ids.contains(r["id"].as_str().unwrap_or_default()));
    let cid = entry["cid"].as_str().unwrap_or_default();
    let path = archive_path(settings, selected, cid);
    let body = json!({"cid": cid, "ids_sha256": entry["ids_sha256"], "records": records});
    hy_core::sealed::write_sealed_default(&path, &body)?;
    store.insert("edits".into(), Value::Array(rest));
    let mut archived = store
        .get("archived")
        .filter(|a| truthy(a))
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    archived.push(json!({"cid": cid, "generation": entry["generation"], "count": records.len(), "ids_sha256": entry["ids_sha256"],
                         "archive": path.display().to_string()}));
    store.insert("archived".into(), Value::Array(archived));
    Ok(())
}

fn subjects_of_records(records: &[&Value]) -> Vec<String> {
    let set: BTreeSet<String> = records
        .iter()
        .flat_map(|r| {
            let options = r
                .get("options")
                .filter(|o| truthy(o))
                .cloned()
                .unwrap_or_else(|| json!({}));
            revisions::subjects_of(
                r.get("address").and_then(Value::as_str).unwrap_or_default(),
                &options,
            )
        })
        .collect();
    if set.is_empty() {
        vec![WILDCARD.into()]
    } else {
        set.into_iter().collect()
    }
}

fn manifest_store(row: &Value) -> Map<String, Value> {
    let manifest = row
        .get("gpr")
        .and_then(Value::as_str)
        .and_then(|g| read_manifest(&crate::gens::project_folder_of(g)))
        .unwrap_or_default();
    manifest
        .get("store")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default()
}

/// The subjects a base move from `old_base` to `generation` brings into the view, from the sealed manifests. A generation
/// whose manifest cannot be read leaves the set unknowable: the wildcard is kept, since a conflict is always safer than a
/// silent rebase onto a value the editor never saw.
pub fn base_move_subjects(
    settings: &Settings,
    lineage_id: &str,
    old_base: i64,
    generation: i64,
    current: Option<&Value>,
) -> Result<Vec<String>> {
    let Some(current) = current.and_then(Value::as_array) else {
        return Ok(vec![WILDCARD.into()]);
    };
    let to_text = |v: &Value| v.as_str().map_or_else(|| v.to_string(), str::to_string);
    let mut subjects: BTreeSet<String> = current.iter().map(to_text).collect();
    if generation > old_base + 1 {
        let rows = live_generations(settings, lineage_id)?;
        for number in (old_base + 1)..generation {
            let row = rows
                .iter()
                .find(|r| r.get("gen").and_then(Value::as_i64) == Some(number));
            let crossed = row
                .map(manifest_store)
                .and_then(|s| s.get("subjects").cloned());
            let Some(Value::Array(crossed)) = crossed else {
                return Ok(vec![WILDCARD.into()]);
            };
            subjects.extend(crossed.iter().map(to_text));
        }
    }
    if subjects.is_empty() || subjects.len() > revisions::MAX_SUBJECTS {
        return Ok(vec![WILDCARD.into()]);
    }
    Ok(subjects.into_iter().collect())
}

/// In one atomic store write of the sealing view: the decided records become a commit entry of the new generation (the
/// previous live entry is archived) and the base moves to it; with no generation (the values were already there) they are
/// dropped. Idempotent by `csid`. Returns whether anything was written.
///
/// The base moves to `generation` only when that is safe for what stays in the view: when records remain that were written
/// over the head the view had and the jump crosses another generation, the base stays, the view is stale, and `rebase`
/// classifies the remainder against the head.
#[allow(clippy::too_many_arguments)]
pub fn finalize_changeset(
    settings: &Settings,
    selected: &Target,
    lineage_id: &str,
    csid: &str,
    generation: Option<i64>,
    ids: &[String],
    snapshot: Option<i64>,
    wait_s: Option<f64>,
    subjects: Option<&Value>,
    retire_copies: Option<&dyn Fn() -> Result<()>>,
) -> Result<bool> {
    let _lock = view_lock(settings, selected, wait_s)?;
    let mut st = load_store(settings, selected)?;
    if st["changesets"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|c| c["csid"].as_str() == Some(csid))
    {
        return Ok(false);
    }
    let wanted: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    let committed = committed_ids(&st);
    let present: Vec<String> = st["edits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|r| r["id"].as_str())
        .filter(|i| wanted.contains(i) && !committed.contains(*i))
        .map(str::to_string)
        .collect();
    let present_set: BTreeSet<&str> = present.iter().map(String::as_str).collect();
    let records: Vec<Value> = st["edits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|r| present_set.contains(r["id"].as_str().unwrap_or_default()))
        .cloned()
        .collect();
    let remaining: Vec<String> = pending_of(&st)
        .iter()
        .filter_map(|r| r["id"].as_str())
        .filter(|i| !present_set.contains(i))
        .map(str::to_string)
        .collect();
    let generation_of = |s: &Store| {
        s.get("base")
            .and_then(|b| b.get("generation"))
            .and_then(Value::as_i64)
            .unwrap_or(0)
    };
    let base_before = generation_of(&st);
    let who = attribution();
    let now = now_f64();
    let published = subjects_of_records(&records.iter().collect::<Vec<_>>());
    let mut sorted_present = present.clone();
    sorted_present.sort();
    let (op, journal_subjects): (&str, Vec<String>);
    if let Some(generation) = generation {
        let commits = st["commits"].as_array().cloned().unwrap_or_default();
        let live: Vec<&Value> = commits
            .iter()
            .filter(|e| !e.get("reverted").is_some_and(truthy))
            .collect();
        if !present.is_empty() {
            let mut kept = commits.clone();
            if let Some(last) = live.last() {
                archive(settings, selected, &mut st, last)?;
                kept.retain(|e| e["cid"] != last["cid"]);
            }
            kept.push(json!({"cid": csid, "generation": generation, "snapshot": snapshot, "ids": sorted_present, "skipped": [],
                             "ids_sha256": digest_of(&sorted_present), "bundle_sha256": null, "at": now, "reverted": false}));
            st.insert("commits".into(), Value::Array(kept));
        }
        let old_base = generation_of(&st);
        let crosses_others = generation > old_base + 1;
        if generation >= old_base && !(!remaining.is_empty() && crosses_others) {
            st.insert(
                "base".into(),
                json!({"lineage": lineage_id, "generation": generation}),
            );
            st.insert("stale".into(), Value::Null);
        }
        op = "commit";
        journal_subjects =
            base_move_subjects(settings, lineage_id, old_base, generation, subjects)?;
    } else {
        let edits: Vec<Value> = st["edits"]
            .as_array()
            .into_iter()
            .flatten()
            .filter(|r| !present_set.contains(r["id"].as_str().unwrap_or_default()))
            .cloned()
            .collect();
        st.insert("edits".into(), Value::Array(edits));
        let mut reverted = st
            .get("reverted")
            .filter(|r| truthy(r))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        if !present.is_empty() {
            reverted.push(json!({"ids": present, "by": who, "at": now, "reason": "published:already_in_master"}));
        }
        st.insert("reverted".into(), Value::Array(reverted));
        op = "publish";
        journal_subjects = published;
    }
    let moved = generation_of(&st) != base_before;
    let mut changesets = st["changesets"].as_array().cloned().unwrap_or_default();
    changesets
        .push(json!({"csid": csid, "generation": generation, "ids": sorted_present, "at": now}));
    st.insert("changesets".into(), Value::Array(changesets));
    let revision = st["revision"].as_i64().unwrap_or(0) + 1;
    st.insert("revision".into(), json!(revision));
    let journal = revisions::append(
        st["journal"].as_array().map_or(&[], Vec::as_slice),
        revisions::journal_entry(revision, op, &journal_subjects, Some(&who), now),
    );
    st.insert("journal".into(), Value::Array(journal));
    save_store(settings, selected, &st)?;
    if (moved || pending_of(&st).is_empty())
        && let Some(retire) = retire_copies
    {
        // The changeset is final; the next sync of the view sweeps what is left.
        let _ = retire();
    }
    Ok(true)
}

/// Called before a view is read or edited: finalize the publishes of this view that the leader did not (it died between the
/// `CURRENT.log` line and the store write, or the view was busy). Never waits for a publish in progress.
pub fn settle(
    settings: &Settings,
    selected: &Target,
    retire_copies: Option<&dyn Fn() -> Result<()>>,
) -> Result<bool> {
    let Some(link) = selected.get("lineage").filter(|l| truthy(l)) else {
        return Ok(false);
    };
    let lineage_id = link["id"].as_str().unwrap_or_default().to_string();
    let key = tkey(selected);
    let rows: Vec<Value> = live_generations(settings, &lineage_id)?
        .into_iter()
        .filter(|r| r["via"] == "publish")
        .collect();
    let mut mine: Vec<(Value, Value)> = Vec::new();
    for row in &rows {
        for item in row
            .get("changesets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            if item["view_key"].as_str() == Some(key) {
                mine.push((row.clone(), item.clone()));
            }
        }
    }
    if mine.is_empty() {
        return Ok(false);
    }
    let known: BTreeSet<String> = load_store(settings, selected)?["changesets"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|c| c["csid"].as_str())
        .map(str::to_string)
        .collect();
    let mut changed = false;
    for (row, item) in mine
        .iter()
        .filter(|(_, i)| !known.contains(i["csid"].as_str().unwrap_or_default()))
    {
        let csid = item["csid"].as_str().unwrap_or_default();
        let manifest_store = manifest_store(row);
        let Some(info) = manifest_store
            .get("by_changeset")
            .and_then(|b| b.get(csid))
            .filter(|i| truthy(i))
        else {
            continue;
        };
        let ids: Vec<String> = info["ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let result = finalize_changeset(
            settings,
            selected,
            &lineage_id,
            csid,
            row["gen"].as_i64(),
            &ids,
            info.get("snapshot").and_then(Value::as_i64),
            None,
            manifest_store.get("subjects"),
            retire_copies,
        );
        match result {
            Ok(wrote) => changed |= wrote,
            Err(Error::Runtime(_)) => return Ok(changed), // busy: the next call settles it
            Err(other) => return Err(other),
        }
    }
    Ok(changed)
}

/// FINALIZED: in one atomic store write, append the commit entry (ids and skipped read from the generation's manifest), set
/// the base to the new generation and archive the previous live commit's records. Idempotent by `cid`.
pub fn finalize_commit(
    settings: &Settings,
    selected: &Target,
    lineage_id: &str,
    cid: &str,
    generation: i64,
    intent: Option<&Intent>,
    point: bool,
) -> Result<Value> {
    let folder = generation_dir(settings, lineage_id, generation as u64)?;
    let manifest = read_manifest(&folder);
    let Some(manifest) = manifest.filter(|m| m.get("cid").and_then(Value::as_str) == Some(cid))
    else {
        return Err(CommitError::new(
            "finalize_failed",
            format!("generation {generation} has no manifest for {cid}"),
        )
        .into());
    };
    let has_cid = |st: &Store| {
        st["commits"]
            .as_array()
            .into_iter()
            .flatten()
            .chain(st["archived"].as_array().into_iter().flatten())
            .any(|e| e["cid"].as_str() == Some(cid))
    };
    let settled = {
        let _lock = view_lock(settings, selected, None)?;
        let st = load_store(settings, selected)?;
        has_cid(&st).then(|| st["revision"].clone())
    };
    let write_intent = |revision: &Value| -> Result<()> {
        if let Some(intent) = intent {
            intent.write(
                "FINALIZED",
                json!({"gen": generation, "revision": revision})
                    .as_object()
                    .cloned()
                    .unwrap_or_default(),
            )?;
        }
        Ok(())
    };
    if let Some(revision) = settled {
        // The store write happened (a crash between it and the intent line): close the intent log now.
        write_intent(&revision)?;
        return Ok(json!({"revision": revision, "already": true}));
    }
    let revision = {
        let _lock = view_lock(settings, selected, None)?;
        let mut st = load_store(settings, selected)?;
        if has_cid(&st) {
            return Ok(json!({"revision": st["revision"], "already": true}));
        }
        let facts = manifest.get("store").cloned().unwrap_or_else(|| json!({}));
        let fact_ids: Vec<String> = facts["ids"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_string)
            .collect();
        let by_id: std::collections::HashMap<String, Value> = st["edits"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|r| (r["id"].as_str().unwrap_or_default().to_string(), r.clone()))
            .collect();
        let missing: Vec<&String> = fact_ids
            .iter()
            .filter(|i| !by_id.contains_key(*i))
            .collect();
        if !missing.is_empty() {
            let shown: Vec<&str> = missing.iter().take(5).map(|s| s.as_str()).collect();
            return Err(CommitError::new(
                "finalize_failed",
                format!(
                    "records of the commit are not in the store: {}",
                    shown.join(", ")
                ),
            )
            .with("ids", json!(missing))
            .into());
        }
        let commits = st["commits"].as_array().cloned().unwrap_or_default();
        let previous = commits
            .iter()
            .rfind(|e| !e.get("reverted").is_some_and(truthy))
            .cloned();
        let mut kept = commits.clone();
        if let Some(previous) = &previous {
            archive(settings, selected, &mut st, previous)?;
            kept.retain(|e| e["cid"] != previous["cid"]);
        }
        let skipped: Vec<Value> = facts
            .get("skipped")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .map(|i| json!({"id": i, "reason": "left_pending"}))
            .collect();
        kept.push(json!({"cid": cid, "generation": generation, "snapshot": facts.get("snapshot"), "ids": fact_ids, "skipped": skipped,
                         "ids_sha256": facts["ids_sha256"], "bundle_sha256": facts.get("bundle_sha256"), "at": now_f64(), "reverted": false}));
        st.insert("commits".into(), Value::Array(kept));
        st.insert(
            "base".into(),
            json!({"lineage": lineage_id, "generation": generation}),
        );
        st.insert("stale".into(), Value::Null);
        if point {
            hy_core::fault::fault("commit.finalize_mid")?;
        }
        let revision = st["revision"].as_i64().unwrap_or(0) + 1;
        st.insert("revision".into(), json!(revision));
        let records: Vec<&Value> = fact_ids.iter().filter_map(|i| by_id.get(i)).collect();
        let subjects = subjects_of_records(&records);
        let journal = revisions::append(
            st["journal"].as_array().map_or(&[], Vec::as_slice),
            revisions::journal_entry(
                revision,
                "commit",
                &subjects,
                Some(&attribution()),
                now_f64(),
            ),
        );
        st.insert("journal".into(), Value::Array(journal));
        save_store(settings, selected, &st)?;
        revision
    };
    write_intent(&json!(revision))?;
    Ok(json!({"revision": revision, "already": false}))
}
