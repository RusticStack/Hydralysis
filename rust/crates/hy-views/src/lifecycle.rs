//! What happens to a view after a commit or a revert: recovery of a dead commit, the in-flight record ids, revert, heal and
//! abort requests (`commits.py`: `recover`, `in_flight_ids`, `revert`, `_finish_revert`, `_rehydrate`, `heal`,
//! `_close_intent`, `request_abort`, `_published`, `_base_target`; `lineage.find`).
//!
//! All of it is disk state under the commit lock and the view lock; no engine is involved. The commit itself
//! (`commits._commit`, `_verify_candidate`) builds a candidate with the engine and stays in Python.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use serde_json::{Map, Value, json};

use crate::classify::WILDCARD;
use crate::commits::{CommitError, Intent, intent_cids, last_steps, validate};
use crate::error::{Error, Result};
use crate::generations::{manifest_file_sha256, verify_manifest};
use crate::gens::{append_current, current_log, head, history, project_folder_of, read_manifest};
use crate::layout::{Settings, generation_dir, lineage_dir, lineages_root, now_f64};
use crate::locks::LaneLock;
use crate::queue::MAX_HISTORY_BYTES;
use crate::records::truthy;
use crate::revisions;
use crate::settle::{archive_path, attribution, finalize_commit, py_dumps, view_lock};
use crate::store::{
    MAX_OVERLAYS, Store, Target, clean_record, digest_of, load_store, save_store, with_view,
};

fn commit_lock_path(settings: &Settings, lineage_id: &str) -> Result<std::path::PathBuf> {
    Ok(lineage_dir(settings, lineage_id)?.join(".commit.lock"))
}

fn is_lineage_id(text: &str) -> bool {
    text.strip_prefix("L-").is_some_and(|rest| {
        rest.len() == 8
            && rest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// `lineage.find`: the lineage of an origin key, from the lineage folders themselves (the registry is only a cache).
pub fn find_lineage(settings: &Settings, origin_key: &str) -> Result<Option<String>> {
    let root = lineages_root(settings);
    let Ok(entries) = std::fs::read_dir(&root) else {
        return Ok(None);
    };
    let mut names: Vec<String> = entries
        .flatten()
        .filter_map(|e| e.file_name().to_str().map(str::to_string))
        .collect();
    names.sort();
    for name in names {
        if is_lineage_id(&name) {
            let record = hy_core::sealed::read_sealed_info(
                &root.join(&name).join("lineage.json"),
                &hy_core::sealed::ReadOptions::default(),
                Some(json!({})),
            )?
            .0;
            if record.get("origin_key").and_then(Value::as_str) == Some(origin_key) {
                return Ok(Some(name));
            }
        }
    }
    Ok(None)
}

fn s_of<'a>(v: &'a Map<String, Value>, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn sv<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn gen_is(row: &Value, generation: i64) -> bool {
    row.get("gen").and_then(Value::as_i64) == Some(generation)
}

fn data(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}

/// `commits._base_target`: the target without its view (`with_view` derives the committing view's key from the origin key).
pub fn base_target(selected: &Target) -> Target {
    let mut plain = selected.clone();
    plain.remove("view");
    let origin = selected
        .get("origin_key")
        .filter(|v| truthy(v))
        .or_else(|| selected.get("key"))
        .cloned()
        .unwrap_or(Value::Null);
    plain.insert("key".into(), origin);
    plain
}

/// `commits._published`: whether `CURRENT.log` has this commit's line. Unreadable counts as published, so ABORTED is never
/// written; recovery reads the log again under the lock.
pub fn published(settings: &Settings, lineage_id: &str, cid: &str) -> bool {
    match history(settings, lineage_id) {
        Ok(rows) => rows
            .iter()
            .any(|r| r.get("cid").and_then(Value::as_str) == Some(cid) && r["reason"] == "commit"),
        Err(_) => true,
    }
}

// ---- recovery (4.6) --------------------------------------------------------------------------------------------

/// The recovery table, run when a lineage is opened and by a resubmission, under `.commit.lock`. Every row ends in the old
/// state or the new one. It is idempotent, and killing it half way leaves a state that the next run completes the same way.
pub fn recover(settings: &Settings, selected: &Target, lineage_id: &str) -> Result<Vec<Value>> {
    let mut done = Vec::new();
    let mut published_rows: BTreeMap<String, Value> = BTreeMap::new();
    for row in history(settings, lineage_id)? {
        if row["reason"] == "commit"
            && let Some(cid) = row
                .get("cid")
                .and_then(Value::as_str)
                .filter(|c| !c.is_empty())
        {
            published_rows.insert(cid.to_string(), row.clone());
        }
    }
    for cid in intent_cids(settings, lineage_id)? {
        let steps = last_steps(settings, lineage_id, &cid)?;
        let step = steps["step"].as_str();
        if matches!(step, None | Some("ABORTED" | "FINALIZED")) {
            continue;
        }
        let intent = Intent::new(
            settings,
            lineage_id,
            &cid,
            steps["attempt"].as_i64().unwrap_or(0),
        )?;
        if let Some(line) = published_rows.get(&cid) {
            let folder = project_folder_of(sv(line, "gpr"));
            let check = verify_manifest(&folder);
            if check.ok
                && manifest_file_sha256(&folder).as_deref()
                    == line.get("manifestSha256").and_then(Value::as_str)
            {
                // CURRENT.log has the line, FINALIZED is missing: roll forward from the manifest, wherever it died.
                let view = check
                    .manifest
                    .as_ref()
                    .and_then(|m| m.get("store")?.get("view")?.as_str().map(str::to_string))
                    .unwrap_or_else(|| "shared".into());
                let target = with_view(
                    &base_target(selected),
                    if view == "shared" { "" } else { &view },
                )?;
                let generation = line["gen"].as_i64().unwrap_or(0);
                finalize_commit(
                    settings,
                    &target,
                    lineage_id,
                    &cid,
                    generation,
                    Some(&intent),
                    true,
                )?;
                done.push(json!({"cid": cid, "action": "rolled_forward", "gen": line["gen"]}));
            } else {
                let previous = check
                    .manifest
                    .as_ref()
                    .and_then(|m| m.get("base")?.get("generation")?.as_i64())
                    .unwrap_or(0);
                let back = history(settings, lineage_id)?
                    .into_iter()
                    .rev()
                    .find(|row| gen_is(row, previous));
                if let Some(back) = back {
                    append_current(
                        settings,
                        lineage_id,
                        &data(&[
                            ("gen", json!(previous)),
                            ("cid", json!(cid)),
                            ("reason", json!("rollback")),
                            ("gpr", back["gpr"].clone()),
                            (
                                "manifestSha256",
                                back.get("manifestSha256").cloned().unwrap_or(Value::Null),
                            ),
                            ("detail", json!("candidate_failed_reverify")),
                        ]),
                        false,
                    )?;
                }
                let joined = check.problems.join("; ");
                intent.write(
                    "ABORTED",
                    data(&[
                        ("code", json!("candidate_failed_reverify")),
                        (
                            "message",
                            json!(joined.chars().take(300).collect::<String>()),
                        ),
                    ]),
                )?;
                done.push(json!({"cid": cid, "action": "rolled_back", "problems": check.problems}));
            }
            continue;
        }
        // Not published. Before the commit point there is nothing to undo: partial folders have no valid manifest (invisible),
        // a verified backup is kept (never deleted), a verified or sealed candidate stays unpublished.
        let reason = match step.unwrap_or_default() {
            "PREPARE" => "aborted_after_prepare",
            "BACKUP_DONE" => "aborted_backup_kept",
            "VERIFIED" | "SEALED" => "unpublished_candidate",
            "PUBLISHED" => "aborted_before_commit_point",
            _ => "aborted_partial_candidate",
        };
        intent.write(
            "ABORTED",
            data(&[
                ("code", json!(reason)),
                (
                    "message",
                    json!("recovered: no CURRENT.log line for this commit"),
                ),
            ]),
        )?;
        done.push(json!({"cid": cid, "action": "aborted", "reason": reason, "last_step": step}));
    }
    Ok(done)
}

/// Record id to commit id for every record a commit of this view's lineage is still working on. A commit is in flight from
/// its PREPARE line until FINALIZED or ABORTED. A commit whose process is gone and that was not published has nothing to
/// protect (recovery aborts it), so it is skipped; one that is published but not finalized still needs its records. Called
/// with the view lock held.
pub fn in_flight_ids(settings: &Settings, selected: &Target) -> Result<BTreeMap<String, String>> {
    let origin = selected
        .get("origin_key")
        .filter(|v| truthy(v))
        .or_else(|| selected.get("key"))
        .and_then(Value::as_str)
        .unwrap_or_default();
    let Some(lineage_id) = find_lineage(settings, origin)? else {
        return Ok(BTreeMap::new());
    };
    let mut found = BTreeMap::new();
    let st = load_store(settings, selected)?;
    let settled: BTreeSet<String> = ["commits", "archived"]
        .iter()
        .flat_map(|k| st[*k].as_array().cloned().unwrap_or_default())
        .filter_map(|e| e.get("cid").and_then(Value::as_str).map(str::to_string))
        .collect();
    for cid in intent_cids(settings, &lineage_id)? {
        let steps = last_steps(settings, &lineage_id, &cid)?;
        if matches!(steps["step"].as_str(), None | Some("ABORTED" | "FINALIZED")) {
            continue;
        }
        let ids: Vec<String> = steps["data"]
            .get("ids")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        if ids.is_empty() || settled.contains(&cid) {
            continue; // the store already holds the commit: nothing is in flight, whatever the intent log still says
        }
        if !published(settings, &lineage_id, &cid) {
            let mut probe = LaneLock::new(commit_lock_path(settings, &lineage_id)?);
            if probe.acquire() {
                probe.release();
                continue; // nobody holds the commit lock and nothing was published: a dead commit
            }
        }
        for id in ids {
            found.insert(id, cid.clone());
        }
    }
    Ok(found)
}

// ---- revert (4.6) ----------------------------------------------------------------------------------------------

fn lineage_of(selected: &Target) -> Option<&Map<String, Value>> {
    selected
        .get("lineage")
        .and_then(Value::as_object)
        .filter(|l| !l.is_empty())
}

/// `commit_revert`: only the latest live commit. The previous generation's manifest must still verify; a `rollback` line is
/// appended; the entry is marked reverted and its ids are pending again (rehydrated from the archive when the commit became
/// the latest only after a later revert).
pub fn revert(settings: &Settings, selected: &Target, options: &Value) -> Result<Value> {
    let options = validate(options)?;
    let Some(link) = lineage_of(selected) else {
        return Err(CommitError::new("no_lineage", "this target has no commit to revert").into());
    };
    let lineage_id = s_of(link, "id").to_string();
    let mut lock = LaneLock::new(commit_lock_path(settings, &lineage_id)?);
    if !lock.acquire() {
        return Err(CommitError::new(
            "commit_busy",
            "another commit or revert holds this lineage's commit lock",
        )
        .with("retryAfterMs", json!(5000))
        .into());
    }
    current_log(settings, &lineage_id)?.repair(false)?;
    recover(settings, selected, &lineage_id)?;
    let top = head(settings, &lineage_id)?;
    if top.get("corrupt").is_some_and(truthy) {
        return Err(CommitError::new(
            "lineage_corrupt",
            "CURRENT.log has a damaged line in the middle; reverts are refused until it is repaired",
        )
        .into());
    }
    let _view = view_lock(settings, selected, None)?;
    let mut st = load_store(settings, selected)?;
    let revision = st["revision"].as_i64().unwrap_or(0);
    let expect = options["expect_revision"].as_i64().unwrap_or(0);
    if revision != expect {
        return Err(CommitError::new(
            "revision_changed",
            format!("the store is at revision {revision}"),
        )
        .with("current_revision", json!(revision))
        .into());
    }
    let live: Vec<Value> = st["commits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|e| !e.get("reverted").is_some_and(truthy))
        .cloned()
        .collect();
    let (entry, rehydrate) = if let Some(last) = live.last() {
        (last.clone(), false)
    } else if let Some(last) = st
        .get("archived")
        .and_then(Value::as_array)
        .and_then(|a| a.last())
    {
        (last.clone(), true)
    } else {
        return Err(CommitError::new("nothing_to_revert", "this view has no live commit").into());
    };
    let top_gen = top["gen"].as_i64().unwrap_or(0);
    let entry_gen = entry["generation"].as_i64().unwrap_or(0);
    if top_gen != entry_gen {
        return Err(CommitError::new(
            "not_latest",
            format!("only the latest live commit can be reverted; the head is generation {top_gen}, this commit is generation {entry_gen}"),
        )
        .into());
    }
    let folder = generation_dir(settings, &lineage_id, entry_gen as u64)?;
    let manifest = read_manifest(&folder);
    let committed_view = manifest
        .as_ref()
        .and_then(|m| m.get("store")?.get("view")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "shared".into());
    let selected_view = selected
        .get("view")
        .and_then(Value::as_str)
        .unwrap_or("shared");
    let Some(manifest) = manifest.filter(|_| committed_view == selected_view) else {
        let shown = match read_manifest(&folder) {
            None => "?".to_string(),
            Some(m) => m
                .get("store")
                .and_then(|s| s.get("view"))
                .and_then(Value::as_str)
                .unwrap_or("?")
                .to_string(),
        };
        return Err(CommitError::new(
            "wrong_view",
            format!(
                "the commit {} was made in view {shown}; revert it there",
                sv(&entry, "cid")
            ),
        )
        .into());
    };
    let previous = manifest
        .get("base")
        .and_then(|b| b.get("generation"))
        .and_then(Value::as_i64)
        .unwrap_or(0);
    let rows = history(settings, &lineage_id)?;
    let back = rows
        .iter()
        .rev()
        .find(|r| gen_is(r, previous) && r["reason"] != "rollback")
        .or_else(|| rows.iter().rev().find(|r| gen_is(r, previous)))
        .cloned();
    let Some(back) = back else {
        return Err(CommitError::new(
            "revert_failed",
            format!("generation {previous} is not in CURRENT.log"),
        )
        .into());
    };
    if previous != 0 {
        let check = verify_manifest(&project_folder_of(sv(&back, "gpr")));
        if !check.ok {
            let shown: Vec<String> = check.problems.iter().take(3).cloned().collect();
            return Err(CommitError::new(
                "revert_failed",
                format!(
                    "generation {previous} no longer verifies: {}",
                    shown.join("; ")
                ),
            )
            .into());
        }
    } else if !Path::new(sv(&back, "gpr")).is_file() {
        return Err(CommitError::new(
            "revert_failed",
            format!("the adopted project {} is gone", sv(&back, "gpr")),
        )
        .into());
    }
    // Validate the whole store change first (a rehydration that would not fit changes nothing), then the commit point of the
    // revert, the rollback line, then the one atomic store write.
    if rehydrate {
        let mut scratch = st.clone();
        rehydrate_archived(settings, selected, &mut scratch, &entry)?;
    }
    append_current(
        settings,
        &lineage_id,
        &data(&[
            ("gen", json!(previous)),
            ("cid", entry["cid"].clone()),
            ("reason", json!("rollback")),
            ("gpr", back["gpr"].clone()),
            (
                "manifestSha256",
                back.get("manifestSha256").cloned().unwrap_or(Value::Null),
            ),
            ("engine", back.get("engine").cloned().unwrap_or(Value::Null)),
        ]),
        false,
    )?;
    hy_core::fault::fault("commit.revert_after_rollback")?;
    let (pending_again, rehydrated) = finish_revert(
        settings,
        selected,
        &mut st,
        &lineage_id,
        &entry,
        rehydrate,
        previous,
    )?;
    // `finish_revert` bumped the revision of the same store: the answer carries the new one, as in Python.
    let result = json!({"ok": true, "reverted": entry["cid"], "generation": previous, "pending_again": pending_again,
                        "rehydrated": rehydrated, "revision": st["revision"]});
    lock.release();
    Ok(result)
}

/// The store half of a revert, idempotent: the commit entry is reverted, its ids are pending, the base is the previous
/// generation. The caller holds the view lock and has appended (or found) the rollback line.
fn finish_revert(
    settings: &Settings,
    selected: &Target,
    store: &mut Store,
    lineage_id: &str,
    entry: &Value,
    archived: bool,
    previous: i64,
) -> Result<(usize, usize)> {
    let cid = sv(entry, "cid");
    let mut rehydrated = 0;
    let pending_again;
    let in_archive = store["archived"]
        .as_array()
        .into_iter()
        .flatten()
        .find(|a| sv(a, "cid") == cid)
        .cloned();
    if archived {
        if let Some(item) = in_archive {
            let restored = rehydrate_archived(settings, selected, store, &item)?;
            rehydrated = restored;
            pending_again = restored;
        } else {
            pending_again = store["commits"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|c| sv(c, "cid") == cid)
                .map_or(0, |c| c["ids"].as_array().map_or(0, Vec::len));
        }
    } else {
        let commits = store
            .get_mut("commits")
            .and_then(Value::as_array_mut)
            .ok_or_else(|| Error::value("store has no commits"))?;
        let live = commits
            .iter_mut()
            .find(|c| c["cid"].as_str() == Some(cid))
            .ok_or_else(|| Error::value("commit entry not found"))?;
        live["reverted"] = json!(true);
        pending_again = live["ids"].as_array().map_or(0, Vec::len);
    }
    let lineage_ref = json!({"lineage": lineage_id, "generation": previous});
    store.insert("base".into(), lineage_ref);
    let revision = store["revision"].as_i64().unwrap_or(0) + 1;
    store.insert("revision".into(), json!(revision));
    let journal = revisions::append(
        store["journal"].as_array().map_or(&[][..], Vec::as_slice),
        revisions::journal_entry(
            revision,
            "commit_revert",
            &[WILDCARD.to_string()],
            Some(&attribution()),
            now_f64(),
        ),
    );
    store.insert("journal".into(), Value::Array(journal));
    save_store(settings, selected, store)?;
    Ok((pending_again, rehydrated))
}

/// Move an archived commit's records back into `edits[]` as pending, in `seq` order, in the caller's atomic store write.
/// Refuses with `archive_unreadable` or `store_full` before anything changes. Returns how many records came back.
fn rehydrate_archived(
    settings: &Settings,
    selected: &Target,
    store: &mut Store,
    entry: &Value,
) -> Result<usize> {
    let cid = sv(entry, "cid");
    let path = archive_path(settings, selected, cid);
    let record = match hy_core::sealed::read_sealed_info(
        &path,
        &hy_core::sealed::ReadOptions {
            max_bytes: Some(MAX_HISTORY_BYTES + 4096),
            require_seal: false,
        },
        Some(Value::Null),
    ) {
        Ok((record, _)) => record,
        Err(error @ hy_core::Error::StoreCorrupt { .. }) => {
            return Err(CommitError::new("archive_unreadable", error.to_string()).into());
        }
        Err(other) => return Err(other.into()),
    };
    let Some(records) = record.get("records").and_then(Value::as_array) else {
        return Err(CommitError::new(
            "archive_unreadable",
            format!("{} is missing or holds no records", path.display()),
        )
        .into());
    };
    let mut items: Vec<Value> = Vec::new();
    let mut previous = 0;
    for (position, item) in records.iter().enumerate() {
        let clean = clean_record(item, position, previous)?;
        previous = clean["seq"].as_i64().unwrap_or(0);
        items.push(clean);
    }
    let mut ids: Vec<String> = items.iter().map(|i| sv(i, "id").to_string()).collect();
    ids.sort();
    if Some(digest_of(&ids).as_str()) != entry.get("ids_sha256").and_then(Value::as_str) {
        return Err(CommitError::new(
            "archive_unreadable",
            format!("{} does not match its ids_sha256", path.display()),
        )
        .into());
    }
    let edits = store["edits"].as_array().cloned().unwrap_or_default();
    if edits.len() + items.len() > MAX_OVERLAYS {
        return Err(CommitError::new(
            "store_full",
            format!(
                "rehydrating {} records would exceed the {MAX_OVERLAYS}-record cap; commit or export first",
                items.len()
            ),
        )
        .into());
    }
    let mut merged: Vec<Value> = edits.into_iter().chain(items.iter().cloned()).collect();
    merged.sort_by_key(|e| e["seq"].as_i64().unwrap_or(0));
    store.insert("edits".into(), Value::Array(merged));
    let archived: Vec<Value> = store["archived"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|a| sv(a, "cid") != cid)
        .cloned()
        .collect();
    store.insert("archived".into(), Value::Array(archived));
    let mut commits = store["commits"].as_array().cloned().unwrap_or_default();
    commits.push(json!({"cid": cid, "generation": entry["generation"], "snapshot": null, "ids": ids, "skipped": [],
                        "ids_sha256": entry["ids_sha256"], "at": now_f64(), "reverted": true}));
    store.insert("commits".into(), Value::Array(commits));
    Ok(items.len())
}

// ---- heal, abort --------------------------------------------------------------------------------------------------

/// The store holds the commit but its intent log never got FINALIZED (a crash between the two): close it under the commit
/// lock. A busy lock means a live commit or revert is working; it closes the log itself, so this returns without waiting.
fn close_intent(
    settings: &Settings,
    selected: &Target,
    lineage_id: &str,
    cid: &str,
) -> Result<bool> {
    if matches!(
        last_steps(settings, lineage_id, cid)?["step"].as_str(),
        None | Some("FINALIZED" | "ABORTED")
    ) {
        return Ok(false);
    }
    let mut lock = LaneLock::new(commit_lock_path(settings, lineage_id)?);
    if !lock.acquire() {
        return Ok(false);
    }
    let did = !recover(settings, selected, lineage_id)?.is_empty();
    lock.release();
    Ok(did)
}

/// Complete what a dead commit or revert left between its `CURRENT.log` line and its store write (the line is the truth).
/// Called before a view is read or edited. A live commit that is mid-finalize holds `.commit.lock`: the caller then gets a
/// structured `busy` and retries; it never reads a store that disagrees with the head. Returns whether anything was done.
pub fn heal(settings: &Settings, selected: &Target) -> Result<bool> {
    let Some(link) = lineage_of(selected) else {
        return Ok(false);
    };
    let reason = s_of(link, "reason");
    let cid = s_of(link, "cid").to_string();
    if !matches!(reason, "commit" | "rollback") || cid.is_empty() {
        return Ok(false);
    }
    let lineage_id = s_of(link, "id").to_string();
    let st = load_store(settings, selected)?;
    let mut known: BTreeMap<String, Value> = BTreeMap::new();
    for key in ["commits", "archived"] {
        for e in st[key].as_array().into_iter().flatten() {
            known.insert(sv(e, "cid").to_string(), e.clone());
        }
    }
    if reason == "commit" {
        if known.contains_key(&cid) {
            return close_intent(settings, selected, &lineage_id, &cid);
        }
    } else {
        let live_cids: BTreeSet<&str> = st["commits"]
            .as_array()
            .into_iter()
            .flatten()
            .map(|c| sv(c, "cid"))
            .collect();
        let base_generation = st
            .get("base")
            .and_then(|b| b.get("generation"))
            .and_then(Value::as_i64);
        match known.get(&cid) {
            None => return Ok(false),
            Some(entry)
                if (live_cids.contains(cid.as_str())
                    && entry.get("reverted").is_some_and(truthy))
                    || (base_generation.is_some()
                        && base_generation == link.get("generation").and_then(Value::as_i64)) =>
            {
                return Ok(false);
            }
            Some(_) => {}
        }
    }
    let manifest_generation = if reason == "commit" {
        link.get("generation").and_then(Value::as_i64).unwrap_or(0)
    } else {
        known[&cid]["generation"].as_i64().unwrap_or(0)
    };
    let manifest = read_manifest(&generation_dir(
        settings,
        &lineage_id,
        manifest_generation as u64,
    )?);
    let view_of_commit = manifest
        .as_ref()
        .and_then(|m| m.get("store")?.get("view")?.as_str().map(str::to_string))
        .unwrap_or_else(|| "shared".into());
    if manifest.is_none()
        || view_of_commit
            != selected
                .get("view")
                .and_then(Value::as_str)
                .unwrap_or("shared")
    {
        return Ok(false); // another view's commit: that view settles it; this one is stale until it rebases
    }
    let mut lock = LaneLock::new(commit_lock_path(settings, &lineage_id)?);
    if !lock.acquire() {
        return Err(Error::Runtime(py_dumps(&json!({
            "error": "busy", "what": "commit finalizing", "retryAfterMs": 1000,
            "suggest": "a commit or revert is finishing; retry",
        }))));
    }
    if reason == "commit" {
        recover(settings, selected, &lineage_id)?;
    } else {
        let _view = view_lock(settings, selected, None)?;
        let mut st = load_store(settings, selected)?;
        let entry = st["commits"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|c| sv(c, "cid") == cid && !c.get("reverted").is_some_and(truthy))
            .cloned();
        let archived = entry.is_none();
        let generation = link.get("generation").and_then(Value::as_i64).unwrap_or(0);
        finish_revert(
            settings,
            selected,
            &mut st,
            &lineage_id,
            &entry.unwrap_or_else(|| json!({"cid": cid})),
            archived,
            generation,
        )?;
    }
    lock.release();
    Ok(true)
}

/// `commit_abort`: honoured before the publish; after it the answer is `cancel_too_late`.
pub fn request_abort(settings: &Settings, selected: &Target, cid: &str) -> Result<Value> {
    let Some(link) = lineage_of(selected) else {
        return Err(CommitError::new("no_lineage", "this target has no commit in flight").into());
    };
    let lineage_id = s_of(link, "id");
    if history(settings, lineage_id)?
        .iter()
        .any(|r| r.get("cid").and_then(Value::as_str) == Some(cid) && r["reason"] == "commit")
    {
        return Err(CommitError::new(
            "cancel_too_late",
            format!("commit {cid} is already published"),
        )
        .into());
    }
    let flag = lineage_dir(settings, lineage_id)?
        .join("commits")
        .join(format!("{cid}.abort"));
    if let Some(parent) = flag.parent() {
        std::fs::create_dir_all(parent)?;
    }
    hy_core::fsio::atomic_write(&flag, b"abort\n")?;
    Ok(json!({"ok": true, "cid": cid, "requested": true}))
}
