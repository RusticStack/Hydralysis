//! Rebase, merge and the sealing half of publish (`views.py`), written against the [`Host`] collaborators.
//!
//! Everything that touches disk (the stores, the queue, the locks and their order) is native; everything that needs the
//! engine or another lane's module (a working-copy sync, a program open, a probe, target resolution, lineage creation) is
//! a `Host` call, so these functions run against a fake in tests and against the real engine in the MCP host.

use std::collections::{BTreeMap, BTreeSet, HashMap};

use serde_json::{Map, Value, json};

use crate::classify::{ABSENT, Pair, WILDCARD, classify, conflict_row, probe_pairs, resolution};
use crate::commits::{CONFIRMATION, CommitError, SAMPLE_PER_KIND};
use crate::error::{Error, Result, ViewError};
use crate::gens::{self, editors_since, in_master, master_ids};
use crate::layout::{Settings, new_csid, now_f64, now_iso, pending_path};
use crate::options::{FORMAT, validate};
use crate::queue::{self, JobLookup, MAX_HISTORY_BYTES, NoJobs, outstanding, pending_info};
use crate::records::truthy;
use crate::revisions;
use crate::settle::{attribution, py_dumps, view_lock};
use crate::store::{
    self, MAX_OVERLAYS, Store, Target, committed_ids, digest_of, edit_of, lineage_binding, load_store, pending_of, rebase_next, save_store,
    stale_reason, with_view,
};

/// What the views need from the rest of the system: the engine-backed working copy and the other lanes' modules.
pub trait Host: Send + Sync {
    /// `workcopy.heal`: settle a commit/revert/publish that died before its store write.
    fn heal(&self, settings: &Settings, target: &Target) -> Result<bool>;
    /// `lineage.ensure` (with the fast path of `views.ensure_lineage`): the lineage record `{id, ...}` of the target.
    fn ensure_lineage(&self, settings: &Settings, selected: &Target) -> Result<Value>;
    /// `targets.resolve(settings, name)`.
    fn resolve_target(&self, settings: &Settings, name: &str) -> Result<Target>;
    /// `query.open_program(engine, gpr, program, sha256, refresh=...)`: a program handle for `probe`.
    fn open_program(&self, gpr: &str, program: &str, sha256: &str, refresh: bool) -> Result<Value>;
    /// `workcopy.probe`: the live value of each (subject, field) in the program; a pair it cannot probe is absent or null.
    fn probe(&self, program: &Value, pairs: &[Pair]) -> Result<HashMap<Pair, Value>>;
    /// `workcopy._sync`: bring the target's working copy to `store` (plus `extra` records); returns the state
    /// (`fork_gpr`, `effects`, `last_sync`, ...). `sweep` false keeps other copies of the view open.
    fn sync(
        &self,
        settings: &Settings,
        target: &Target,
        store: &Store,
        timeout_s: i64,
        extra: Option<&[Value]>,
        sweep: bool,
    ) -> Result<Value>;
    /// `views._abandon_copy`: close a copy that was built but not switched to (best effort).
    fn abandon_copy(&self, settings: &Settings, selected: &Target, state: Option<&Value>);
    /// `views._adopt_copy`: the switch to the rebased copy; closes every other copy of the view.
    fn adopt_copy(&self, settings: &Settings, selected: &Target, built: &Value) -> Result<()>;
    /// The publish job lookup for queue status.
    fn jobs(&self) -> &dyn JobLookup {
        &NoJobs
    }
    /// `workcopy.retire_copies`: close the view's working copies after a finalize (best effort; the default does nothing).
    fn retire_copies(&self, _settings: &Settings, _target: &Target) -> Result<()> {
        Ok(())
    }
    /// `views._publish_candidate`: the engine-bound half of a publish. Builds the candidate generation for the accepted
    /// changesets (fork, replay, save, manifest, verification, seal), appends its `CURRENT.log` line and writes the results,
    /// and pushes what the leader must settle. The default refuses: only a host with an engine can publish.
    fn publish_candidate(
        &self,
        _request: &crate::publish::CandidateRequest<'_>,
        _settles: &mut Vec<crate::publish::Settle>,
    ) -> std::result::Result<crate::publish::Built, crate::publish::PublishError> {
        Err(crate::publish::PublishError::Other(Error::Runtime("this host has no engine to build a candidate".into())))
    }
}

fn s_of<'a>(v: &'a Map<String, Value>, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn view_of(t: &Target) -> String {
    t.get("view").and_then(Value::as_str).unwrap_or("shared").to_string()
}

fn revision_of(store: &Store) -> i64 {
    store["revision"].as_i64().unwrap_or(0)
}

fn rev_json(store: &Store) -> Value {
    store["revision"].clone()
}

fn base_generation(store: &Store) -> i64 {
    store.get("base").and_then(|b| b.get("generation")).and_then(Value::as_i64).unwrap_or(0)
}

/// `workcopy.reconcile`: current, rebased, or a conflict raised as the structured `RuntimeError`.
pub fn reconcile(store: &Store, expect: i64, subjects: &[String]) -> Result<Value> {
    let journal = store["journal"].as_array().map_or(&[][..], Vec::as_slice);
    let decision = revisions::reconcile(Some(expect), revision_of(store), journal, subjects);
    if decision["outcome"] == "conflict" {
        return Err(Error::Runtime(py_dumps(&revisions::conflict_payload(Some(expect), &decision, subjects))));
    }
    Ok(decision)
}

/// `workcopy._rebase_report`
pub fn rebase_report(expect: i64, decision: &Value) -> Map<String, Value> {
    let rebased = decision["outcome"] == "rebased";
    let mut out = Map::new();
    out.insert("rebased".into(), json!(rebased));
    if rebased {
        out.insert("rebased_from".into(), json!(expect));
        out.insert("subjects_changed_since".into(), decision["subjects_changed_since"].clone());
    }
    out
}

/// A mutation of a view behind the head is refused with `stale_view`, naming the generations that moved the head and the
/// `rebase` call that settles it (4.7, 4.10).
pub fn refuse_stale(store: &Store, target: &Target, what: &str, settings: Option<&Settings>) -> Result<()> {
    if stale_reason(store, target).is_none() {
        return Ok(());
    }
    let mut payload = json!({
        "error": "stale_view", "stale": "master_generation_changed", "what": what, "view": view_of(target), "base": store.get("base"),
        "head": lineage_binding(target), "next": rebase_next(store), "retried": false,
        "suggest": format!("another view published a new generation, and this view holds records on the older one; nothing was recorded and Hydralysis does not retry the {what}. Rebase the view with ghidra_query action=type_edit options.kind=rebase (the call in `next`; resolve any conflicts it lists with take_mine or keep), then send the {what} again with the view_revision the rebase answers"),
    });
    if let Some(settings) = settings {
        let lineage_id = target["lineage"]["id"].as_str().unwrap_or_default();
        payload["editors"] = Value::Array(editors_since(settings, lineage_id, base_generation(store), None)?);
    }
    Err(Error::Runtime(py_dumps(&payload)))
}

fn point(name: &str) -> Result<()> {
    hy_core::fault::fault(&format!("publish.{name}"))?;
    Ok(())
}

// ---- rebase (4.7) ----------------------------------------------------------------------------------------------------

const UNVERSIONED: [&str; 1] = ["published_through"];

fn strip(store: &Store) -> Value {
    Value::Object(store.iter().filter(|(k, _)| !UNVERSIONED.contains(&k.as_str())).map(|(k, v)| (k.clone(), v.clone())).collect())
}

fn norm(path: &str) -> String {
    std::path::absolute(path).map_or_else(|_| path.to_string(), |p| p.to_string_lossy().into_owned()).replace('/', "\\").to_lowercase()
}

/// Why the rebase switch must not happen (`None`: it may). The view lock is held.
fn switch_refusal(
    settings: &Settings,
    selected: &Target,
    store: &Store,
    fresh: &Store,
    state: Option<&Value>,
) -> Result<Option<&'static str>> {
    if fresh["revision"] != store["revision"] || hy_core::json::canonical(&strip(fresh)) != hy_core::json::canonical(&strip(store)) {
        return Ok(Some("the view changed while the rebase was building; nothing was changed"));
    }
    if let Some(gpr) = state.and_then(|s| s.get("fork_gpr")).and_then(Value::as_str).filter(|g| !g.is_empty()) {
        let retired: BTreeSet<String> = store::working_state(settings, selected)?
            .get("retired")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .filter(|i| !i.is_empty())
            .map(norm)
            .collect();
        if !std::path::Path::new(gpr).is_file() || retired.contains(&norm(gpr)) {
            return Ok(Some("the working copy the rebase built was closed while it was building; nothing was changed"));
        }
    }
    Ok(None)
}

fn switch_base(fresh: &Store, new_store: &Store) -> Store {
    let mut out = new_store.clone();
    for key in UNVERSIONED {
        match fresh.get(key) {
            Some(v) => {
                out.insert(key.into(), v.clone());
            }
            None => {
                out.shift_remove(key);
            }
        }
    }
    out
}

fn up_to_date(selected: &Target, store: &Store) -> Value {
    json!({"ok": true, "rebased": false, "outcome": "up_to_date", "view": view_of(selected), "revision": store["revision"],
           "view_revision": store["revision"], "base": store.get("base"),
           "note": "this view is already on the head generation and none of its records conflicts with it"})
}

fn shadow(target: &Target) -> Target {
    let mut t = target.clone();
    t.insert("key".into(), json!(format!("{}r", s_of(target, "key"))));
    t
}

fn text_of(v: &Value) -> Value {
    if v.is_null() { json!(ABSENT) } else { v.clone() }
}

fn heavy(store: &Store) -> bool {
    pending_of(store).iter().any(|e| matches!(e["options"].get("kind").and_then(Value::as_str), Some("import_types" | "import_archive")))
}

/// Build and verify the working copy of `new_store` in the rebase directory. Returns `{verified, state, checked}`.
fn build_rebased_copy(host: &dyn Host, settings: &Settings, selected: &Target, new_store: &Store, timeout_s: i64) -> Result<Value> {
    let pending = pending_of(new_store);
    if pending.is_empty() {
        return Ok(json!({"verified": "nothing_to_replay", "state": null}));
    }
    if heavy(new_store) {
        return Ok(json!({"verified": "deferred_bulk_replay", "state": null}));
    }
    let shadow = shadow(selected);
    let _ = std::fs::remove_file(store::directory(settings, &shadow).join("state.json"));
    let state = host.sync(settings, &shadow, new_store, timeout_s, None, false)?;
    let verify = || -> Result<(usize, Vec<Value>)> {
        let program =
            host.open_program(state["fork_gpr"].as_str().unwrap_or_default(), s_of(selected, "program"), s_of(selected, "sha256"), true)?;
        let mut expected: Vec<(Pair, Value)> = Vec::new();
        for record in &pending {
            for effect in record.get("effects").and_then(Value::as_array).into_iter().flatten() {
                if effect["subject"] != WILDCARD {
                    let pair = (
                        effect["subject"].as_str().unwrap_or_default().to_string(),
                        effect["field"].as_str().unwrap_or_default().to_string(),
                    );
                    let after = text_of(&effect["after"]);
                    match expected.iter_mut().find(|(p, _)| *p == pair) {
                        Some(slot) => slot.1 = after,
                        None => expected.push((pair, after)),
                    }
                }
            }
        }
        expected.truncate(SAMPLE_PER_KIND * 4);
        let pairs: Vec<Pair> = expected.iter().map(|(p, _)| p.clone()).collect();
        let live = if pairs.is_empty() { HashMap::new() } else { host.probe(&program, &pairs)? };
        let wrong: Vec<Value> = expected
            .iter()
            .filter(|(p, want)| live.get(p).is_some_and(|f| !f.is_null() && f != want))
            .map(|(p, want)| json!({"subject": p.0, "field": p.1, "expected": want, "found": live.get(p)}))
            .collect();
        Ok((pairs.len(), wrong))
    };
    let outcome = verify();
    let failure = match &outcome {
        Ok((_, wrong)) if wrong.is_empty() => None,
        Ok((_, wrong)) => Some(Error::from(
            ViewError::new(
                "rebase_verify_failed",
                "the rebuilt working copy does not hold the values of the kept records; the view was not changed",
            )
            .with("mismatches", json!(wrong.iter().take(20).collect::<Vec<_>>())),
        )),
        Err(_) => None,
    };
    if outcome.is_err() || failure.is_some() {
        // the build runs outside the view lock; the view's writer does not
        let _lock = view_lock(settings, selected, None);
        host.abandon_copy(settings, selected, Some(&state));
        return Err(match (failure, outcome) {
            (Some(f), _) => f,
            (None, Err(e)) => e,
            _ => unreachable!(),
        });
    }
    let checked = outcome.map(|(n, _)| n)?;
    Ok(json!({"verified": true, "state": state, "checked": checked}))
}

/// `type_edit kind=rebase`: move a view that is behind the head onto it. The new working copy is built first, in a directory
/// of its own, and verified; only then does one atomic store write move the base.
pub fn rebase(host: &dyn Host, settings: &Settings, selected: &Target, options: &Value, timeout_s: i64) -> Result<Value> {
    let mut opts = options.as_object().cloned().unwrap_or_default();
    opts.insert("kind".into(), json!("rebase"));
    let options = validate(&Value::Object(opts))?;
    host.heal(settings, selected)?;
    let binding = lineage_binding(selected);
    // The engine round trips run OUTSIDE the view's `.view.lock`; the rebase lane (the shadow directory's own lock) keeps one
    // rebase per view at a time. The switch takes the view lock and is a compare-and-swap on the store decided on.
    let _lane = view_lock(settings, &shadow(selected), None)?;
    let store = load_store(settings, selected)?;
    let expect = options["expect_revision"].as_i64().unwrap_or(0);
    let _decision = reconcile(&store, expect, &[WILDCARD.to_string()])?;
    let base_gen = base_generation(&store);
    let pending = pending_of(&store);
    let current = binding.as_ref().is_some_and(|b| b["generation"].as_i64() == Some(base_gen));
    let Some(binding) = binding.filter(|_| !(current && pending.is_empty())) else {
        return Ok(up_to_date(selected, &store));
    };
    let lineage_id = binding["lineage"].as_str().unwrap_or_default().to_string();
    let known = master_ids(settings, &lineage_id, base_gen)?;
    let (in_the_master, rest): (Vec<Value>, Vec<Value>) = pending.iter().cloned().partition(|r| in_master(r, &known));
    let mut verdicts: Vec<Value> = Vec::new();
    if !rest.is_empty() {
        let program = host.open_program(s_of(selected, "gpr"), s_of(selected, "program"), s_of(selected, "sha256"), false)?;
        let pairs = probe_pairs(&rest);
        let live = if pairs.is_empty() { HashMap::new() } else { host.probe(&program, &pairs)? };
        verdicts = classify(&rest, &live, None).0;
    }
    let id_of = |v: &Value| v["id"].as_str().unwrap_or_default().to_string();
    let by_id: HashMap<String, &Value> = rest.iter().map(|r| (id_of(r), r)).collect();
    let conflicts: Vec<&Value> = verdicts.iter().filter(|v| v["outcome"] == "conflict").collect();
    if current && conflicts.is_empty() && in_the_master.is_empty() && !verdicts.iter().any(|v| v["outcome"] == "converged") {
        return Ok(up_to_date(selected, &store));
    }
    let subjects_wanted: BTreeSet<String> = conflicts.iter().map(|c| c["subject"].as_str().unwrap_or_default().to_string()).collect();
    let editors = if conflicts.is_empty() { Vec::new() } else { editors_since(settings, &lineage_id, base_gen, Some(&subjects_wanted))? };
    let resolve = options.get("resolve").and_then(Value::as_object);
    let unresolved: Vec<&&Value> = conflicts.iter().filter(|c| resolution(resolve, c).is_none()).collect();
    if !unresolved.is_empty() {
        let rows: Vec<Value> = unresolved.iter().map(|c| conflict_row(c, by_id[&id_of(c)], Some(&editors))).collect();
        let resolve_hint: Map<String, Value> =
            unresolved.iter().map(|c| (c["subject"].as_str().unwrap_or_default().to_string(), json!("take_mine | keep"))).collect();
        return Ok(json!({
            "ok": false, "rebased": false, "outcome": "conflict", "view": view_of(selected), "conflicts": rows,
            "from_generation": base_gen, "to_generation": binding["generation"], "revision": store["revision"], "view_revision": store["revision"],
            "next": {"tool": "ghidra_query", "action": "type_edit", "options": {"kind": "rebase", "expect_revision": store["revision"], "resolve": resolve_hint}},
            "suggest": "nothing was changed: the master holds another value where this view's record rests on an older one. take_mine keeps your record and re-anchors it to the master's value; keep drops it (and the records that rest on it)",
        }));
    }
    let converged: Vec<String> = verdicts.iter().filter(|v| v["outcome"] == "converged").map(id_of).collect();
    let mut dropped_keep: BTreeSet<String> =
        conflicts.iter().filter(|c| resolution(resolve, c).as_deref() == Some("keep")).map(|c| id_of(c)).collect();
    if !dropped_keep.is_empty() {
        let committed = committed_ids(&store);
        let edits = store["edits"].as_array().cloned().unwrap_or_default();
        dropped_keep.extend(revisions::dependents(&edits, &dropped_keep.clone(), &committed));
        let batches: BTreeSet<String> = dropped_keep
            .iter()
            .filter_map(|i| by_id.get(i))
            .filter_map(|r| r.get("batch").filter(|b| truthy(b)).and_then(Value::as_str).map(str::to_string))
            .collect();
        dropped_keep
            .extend(pending.iter().filter(|r| r.get("batch").and_then(Value::as_str).is_some_and(|b| batches.contains(b))).map(id_of));
    }
    // take_mine: the record stays; the `before` that disagrees becomes the value the record will replace, so the next
    // publish finds nothing to dispute.
    let mut reanchored: BTreeMap<String, Vec<Value>> = BTreeMap::new();
    for item in &conflicts {
        let ident = id_of(item);
        if resolution(resolve, item).as_deref() == Some("take_mine")
            && matches!(item["reason"].as_str(), Some("drift" | "partially_converged" | "chain"))
            && !dropped_keep.contains(&ident)
        {
            let mut effects: Vec<Value> = by_id[&ident]["effects"].as_array().cloned().unwrap_or_default();
            if let Some(at) = item["effect"].as_u64().map(|a| a as usize).filter(|a| *a < effects.len()) {
                effects[at]["before"] = if item["now"] == ABSENT { Value::Null } else { item["now"].clone() };
            }
            reanchored.insert(ident, effects);
        }
    }
    let mut removed: BTreeSet<String> = in_the_master.iter().map(id_of).collect();
    removed.extend(converged.iter().cloned());
    removed.extend(dropped_keep.iter().cloned());
    let kept_ids: Vec<String> = rest.iter().map(id_of).filter(|i| !removed.contains(i)).collect();
    let mut edits = Vec::new();
    for record in store["edits"].as_array().into_iter().flatten() {
        let ident = id_of(record);
        if removed.contains(&ident) {
            continue;
        }
        match reanchored.get(&ident) {
            Some(effects) => {
                let mut r = record.clone();
                r["effects"] = Value::Array(effects.clone());
                edits.push(r);
            }
            None => edits.push(record.clone()),
        }
    }
    let who = attribution();
    let now = now_f64();
    let subjects: BTreeSet<String> = pending
        .iter()
        .filter(|r| removed.contains(&id_of(r)) || reanchored.contains_key(&id_of(r)))
        .flat_map(|r| revisions::subjects_of(r["address"].as_str().unwrap_or_default(), &r["options"]))
        .collect();
    let subjects: Vec<String> = if subjects.is_empty() { vec![WILDCARD.into()] } else { subjects.into_iter().collect() };
    let next_revision = revision_of(&store) + 1;
    let mut new_store = store.clone();
    new_store.insert("edits".into(), Value::Array(edits));
    new_store.insert("base".into(), binding.clone());
    new_store.insert("stale".into(), Value::Null);
    new_store.insert("revision".into(), json!(next_revision));
    let mut reverted = store["reverted"].as_array().cloned().unwrap_or_default();
    if !removed.is_empty() {
        reverted.push(json!({"ids": removed, "by": who, "at": now, "reason": "rebase"}));
    }
    new_store.insert("reverted".into(), Value::Array(reverted));
    let journal = revisions::append(
        store["journal"].as_array().map_or(&[][..], Vec::as_slice),
        revisions::journal_entry(next_revision, "rebase", &subjects, Some(&who), now),
    );
    new_store.insert("journal".into(), Value::Array(journal));
    // 1. the new working copy, beside the old one, verified; the old one keeps serving reads until the switch below.
    let verified = build_rebased_copy(host, settings, selected, &new_store, timeout_s)?;
    // 2. the switch, under the view lock: only if the store is still the one the rebase was decided on, then one store write.
    {
        let _lock = view_lock(settings, selected, None)?;
        let fresh = load_store(settings, selected)?;
        let now_rev = fresh["revision"].clone();
        if let Some(why) = switch_refusal(settings, selected, &store, &fresh, verified.get("state").filter(|s| !s.is_null()))? {
            host.abandon_copy(settings, selected, verified.get("state"));
            return Err(Error::Runtime(py_dumps(&json!({
                "conflict": "overlay revision changed", "reason": why, "expected_revision": store["revision"], "current_revision": now_rev,
                "view_revision": now_rev, "view": view_of(selected),
                "next": {"tool": "ghidra_query", "action": "type_edit", "options": {"kind": "rebase", "expect_revision": now_rev}},
            }))));
        }
        new_store = switch_base(&fresh, &new_store);
        if let Err(e) = save_store(settings, selected, &new_store) {
            host.abandon_copy(settings, selected, verified.get("state"));
            return Err(e);
        }
        point("after_rebase_store")?;
        // 3. the cache pointer follows (a crash before it is harmless: the marker mismatch rebuilds the copy).
        host.adopt_copy(settings, selected, &verified)?;
    }
    let outcome = if conflicts.is_empty() && removed.is_empty() {
        "clean"
    } else if !conflicts.is_empty() {
        "resolved"
    } else {
        "dropped"
    };
    Ok(json!({
        "ok": true, "rebased": true, "outcome": outcome, "view": view_of(selected), "from_generation": base_gen, "to_generation": binding["generation"],
        "kept": kept_ids, "dropped_in_master": in_the_master.iter().map(id_of).collect::<Vec<_>>(), "converged": converged,
        "dropped_keep": dropped_keep, "reanchored": reanchored.keys().collect::<Vec<_>>(),
        "unverified": verdicts.iter().filter(|v| v["outcome"] == "unchecked").map(id_of).collect::<Vec<_>>(),
        "revision": new_store["revision"], "view_revision": new_store["revision"], "verified": verified["verified"],
        "outcomes_checked": verified.get("checked").cloned().unwrap_or(json!(0)),
    }))
}

// ---- merge and publish to a view (4.8) ------------------------------------------------------------------------------------

/// Append `source`'s records after its `published_through` to `destination` when their `before` values match what the
/// destination holds now. `options` are already validated; `expect_revision` is the destination's. Conflicts are returned,
/// never resolved on their own.
pub fn merge(
    host: &dyn Host,
    settings: &Settings,
    source: &Target,
    destination: &Target,
    options: &Map<String, Value>,
    timeout_s: i64,
) -> Result<Value> {
    if source.get("key") == destination.get("key") {
        return Err(ViewError::new("same_view", "the source and the destination are the same view").into());
    }
    for t in [source, destination] {
        host.heal(settings, t)?;
    }
    // lexicographic order of the keys (4.8)
    let mut ordered = [source, destination];
    ordered.sort_by_key(|t| s_of(t, "key").to_string());
    let _locks = [view_lock(settings, ordered[0], None)?, view_lock(settings, ordered[1], None)?];
    let mut mine = load_store(settings, source)?;
    let mut theirs = load_store(settings, destination)?;
    refuse_stale(&mine, source, "merge", Some(settings))?;
    refuse_stale(&theirs, destination, "merge", Some(settings))?;
    let name = view_of(destination);
    let src_view = view_of(source);
    let through_of = |s: &Store| s.get("published_through").and_then(|p| p.get(&name)).and_then(Value::as_i64).unwrap_or(0);
    let through = through_of(&mine);
    let merged_already: BTreeSet<String> = theirs["edits"]
        .as_array()
        .into_iter()
        .flatten()
        .filter(|i| i.get("merged_from").and_then(|m| m.get("view")).and_then(Value::as_str) == Some(src_view.as_str()))
        .filter_map(|i| i["merged_from"]["id"].as_str().map(str::to_string))
        .collect();
    let seq = |r: &Value| r["seq"].as_i64().unwrap_or(0);
    let id_of = |v: &Value| v["id"].as_str().unwrap_or_default().to_string();
    let mine_pending = pending_of(&mine);
    let candidates: Vec<Value> = mine_pending.iter().filter(|r| seq(r) > through && !merged_already.contains(&id_of(r))).cloned().collect();
    // What a crash between the destination's write and the source's mark left behind: those are already there.
    let already_there: Vec<&Value> = mine_pending.iter().filter(|r| merged_already.contains(&id_of(r)) && seq(r) > through).collect();
    let set_through = |s: &mut Store, value: i64| {
        let mut p = s.get("published_through").and_then(Value::as_object).cloned().unwrap_or_default();
        p.insert(name.clone(), json!(value));
        s.insert("published_through".into(), Value::Object(p));
    };
    if candidates.is_empty() {
        if !already_there.is_empty() {
            set_through(&mut mine, already_there.iter().map(|r| seq(r)).max().unwrap_or(0));
            save_store(settings, source, &mine)?;
        }
        return Ok(json!({"ok": true, "outcome": "merged", "merged": 0, "view": name, "from": src_view, "revision": theirs["revision"],
                         "view_revision": theirs["revision"], "note": "nothing after published_through", "published_through": through_of(&mine)}));
    }
    let unknown: Vec<String> = candidates.iter().filter(|r| r.get("before_unknown").is_some_and(truthy)).map(id_of).collect();
    if !unknown.is_empty() && !options.get("allow_unverified_before").is_some_and(truthy) {
        return Err(ViewError::new(
            "before_unknown",
            format!("{} record(s) predate the subject record and cannot be compared with the destination; pass allow_unverified_before:true to merge them", unknown.len()),
        )
        .with("ids", json!(unknown))
        .into());
    }
    let subjects: Vec<String> = candidates
        .iter()
        .flat_map(|r| revisions::subjects_of(r["address"].as_str().unwrap_or_default(), &r["options"]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let expect = options["expect_revision"].as_i64().unwrap_or(0);
    let decision = reconcile(&theirs, expect, &subjects)?;
    let program = if pending_of(&theirs).is_empty() {
        host.open_program(s_of(destination, "gpr"), s_of(destination, "program"), s_of(destination, "sha256"), false)?
    } else {
        let state = host.sync(settings, destination, &theirs, timeout_s, None, true)?;
        host.open_program(state["fork_gpr"].as_str().unwrap_or_default(), s_of(destination, "program"), s_of(destination, "sha256"), true)?
    };
    let pairs = probe_pairs(&candidates);
    let live = if pairs.is_empty() { HashMap::new() } else { host.probe(&program, &pairs)? };
    let (verdicts, _) = classify(&candidates, &live, None);
    let by_id: HashMap<String, &Value> = candidates.iter().map(|r| (id_of(r), r)).collect();
    let resolve = options.get("resolve").and_then(Value::as_object);
    let conflicts: Vec<&Value> = verdicts.iter().filter(|v| v["outcome"] == "conflict").collect();
    let unresolved: Vec<&&Value> = conflicts.iter().filter(|c| resolution(resolve, c).is_none()).collect();
    if !unresolved.is_empty() {
        let rows: Vec<Value> = unresolved.iter().map(|c| conflict_row(c, by_id[&id_of(c)], None)).collect();
        let hint: Map<String, Value> =
            unresolved.iter().map(|c| (c["subject"].as_str().unwrap_or_default().to_string(), json!("take_mine | keep"))).collect();
        return Ok(json!({
            "ok": false, "outcome": "conflict", "merged": 0, "view": name, "from": src_view, "conflicts": rows,
            "revision": theirs["revision"], "view_revision": theirs["revision"],
            "next": {"tool": "ghidra_query", "action": "type_edit", "options": {"kind": "merge", "from": src_view, "view": name, "expect_revision": theirs["revision"], "resolve": hint}},
            "suggest": "nothing was merged: the destination holds another value where these records rest on an older one. take_mine applies the record over it; keep leaves the destination's value",
        }));
    }
    let (mut accepted, mut kept, mut converged): (Vec<&Value>, Vec<String>, Vec<String>) = (Vec::new(), Vec::new(), Vec::new());
    for verdict in &verdicts {
        let record = by_id[&id_of(verdict)];
        if verdict["outcome"] == "converged" {
            converged.push(id_of(record));
        } else if verdict["outcome"] == "conflict" && resolution(resolve, verdict).as_deref() == Some("keep") {
            kept.push(id_of(record));
        } else {
            accepted.push(record);
        }
    }
    let who = attribution();
    let now = now_f64();
    let mut added: Vec<Value> = Vec::new();
    for record in &accepted {
        let subset: Map<String, Value> =
            ["id", "address", "options"].iter().filter_map(|k| record.get(*k).map(|v| ((*k).to_string(), v.clone()))).collect();
        let mut edit = edit_of(&subset)?;
        let mut b = [0u8; 16];
        getrandom::fill(&mut b).expect("OS randomness");
        edit.insert("id".into(), json!(hex::encode(b)));
        edit.insert("by".into(), who.clone());
        edit.insert("at".into(), json!(now));
        edit.insert("merged_from".into(), json!({"view": src_view, "id": record["id"], "seq": record["seq"]}));
        added.push(Value::Object(edit));
    }
    let mut sync_state: Option<Value> = None;
    if !added.is_empty() {
        if theirs["edits"].as_array().map_or(0, Vec::len) + added.len() > MAX_OVERLAYS {
            return Err(Error::value("overlay history limit reached; export/review it before adding more edits"));
        }
        let sync = host.sync(settings, destination, &theirs, timeout_s, Some(&added), true)?;
        let effects = sync.get("effects").cloned().unwrap_or_else(|| json!({}));
        for item in &mut added {
            let ident = id_of(item);
            let cleaned = revisions::clean_effects(effects.get(&ident))?;
            item["effects"] = cleaned.clone().map_or(Value::Null, Value::Array);
            if cleaned.is_none() {
                item["before_unknown"] = json!(true);
            }
            let revision = revision_of(&theirs) + 1;
            theirs.insert("revision".into(), json!(revision));
            let max_seq = theirs["edits"].as_array().into_iter().flatten().map(seq).max().unwrap_or(0);
            item["seq"] = json!(revision.max(max_seq + 1));
            let mut edits = theirs["edits"].as_array().cloned().unwrap_or_default();
            edits.push(item.clone());
            theirs.insert("edits".into(), Value::Array(edits));
            let subj = revisions::subjects_of(item["address"].as_str().unwrap_or_default(), &item["options"]);
            let journal = revisions::append(
                theirs["journal"].as_array().map_or(&[][..], Vec::as_slice),
                revisions::journal_entry(revision, "merge", &subj, Some(&who), now),
            );
            theirs.insert("journal".into(), Value::Array(journal));
        }
        save_store(settings, destination, &theirs)?;
        point("after_merge_destination")?;
        sync_state = Some(sync);
    }
    set_through(&mut mine, candidates.iter().map(seq).max().unwrap_or(0));
    save_store(settings, source, &mine)?;
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert("outcome".into(), json!("merged"));
    out.insert("merged".into(), json!(added.len()));
    out.insert("ids".into(), json!(added.iter().map(id_of).collect::<Vec<_>>()));
    out.insert("converged".into(), json!(converged));
    out.insert("kept_destination".into(), json!(kept));
    out.insert("view".into(), json!(name));
    out.insert("from".into(), json!(src_view));
    out.insert("revision".into(), rev_json(&theirs));
    out.insert("view_revision".into(), rev_json(&theirs));
    out.insert("published_through".into(), json!(through_of(&mine)));
    out.extend(rebase_report(expect, &decision));
    if let Some(sync) = sync_state {
        out.insert("sync".into(), sync.get("last_sync").cloned().unwrap_or(Value::Null));
    }
    Ok(Value::Object(out))
}

// ---- sealing a changeset (the caller's half) -----------------------------------------------------------------------------------

/// `commits._plan_confirmation(options)` without an engine: a one-way upgrade needs the explicit confirmation.
fn plan_confirmation(options: &Map<String, Value>) -> Result<()> {
    if options.get("confirm_one_way_upgrade").is_some_and(truthy) {
        return Ok(());
    }
    Err(CommitError::new("confirmation_required", CONFIRMATION).with("confirm", json!("confirm_one_way_upgrade")).into())
}

/// Step 1 of 4.10: seal `pending/<csid>.json` (the view's pending records, their base, the agent) and return at once. No
/// engine call, no other view and no reader is involved. A second publish of the same pending records while the first waits
/// returns the first (`reused`).
pub fn seal_changeset(host: &dyn Host, settings: &Settings, selected: &Target, options: &Value) -> Result<Value> {
    let mut opts = options.as_object().cloned().unwrap_or_default();
    opts.insert("kind".into(), json!("publish"));
    let options = validate(&Value::Object(opts))?;
    plan_confirmation(&options)?;
    let link = host.ensure_lineage(settings, selected)?;
    let lineage_id = link["id"].as_str().unwrap_or_default().to_string();
    let resolved = host.resolve_target(settings, s_of(selected, "name"))?;
    let view = selected.get("view").and_then(Value::as_str).unwrap_or_default();
    let selected = with_view(&resolved, view)?;
    host.heal(settings, &selected)?;
    let head = gens::head(settings, &lineage_id)?;
    if head.get("corrupt").is_some_and(truthy) {
        return Err(CommitError::new(
            "lineage_corrupt",
            "CURRENT.log has a damaged line in the middle; publishes are refused until the owner repairs it",
        )
        .with("corrupt", head["corrupt"].clone())
        .into());
    }
    let _lock = view_lock(settings, &selected, None)?;
    let st = load_store(settings, &selected)?;
    let expect = options["expect_revision"].as_i64().unwrap_or(0);
    if revision_of(&st) != expect {
        return Err(CommitError::new("revision_changed", format!("the store is at revision {}, not {expect}", revision_of(&st)))
            .with("current_revision", rev_json(&st))
            .into());
    }
    let pending = pending_of(&st);
    if pending.is_empty() {
        return Err(CommitError::new("nothing_to_commit", "no pending record to publish").into());
    }
    let unknown: Vec<&Value> = pending.iter().filter(|r| r.get("before_unknown").is_some_and(truthy)).map(|r| &r["id"]).collect();
    if !unknown.is_empty() && !options.get("allow_unverified_before").is_some_and(truthy) {
        return Err(CommitError::new(
            "before_unknown",
            format!("{} record(s) predate the subject record and cannot be checked against the master; pass allow_unverified_before:true to publish them", unknown.len()),
        )
        .with("ids", json!(unknown))
        .into());
    }
    let mut sorted_ids: Vec<&str> = pending.iter().filter_map(|r| r["id"].as_str()).collect();
    sorted_ids.sort_unstable();
    let ids_sha = digest_of(&sorted_ids);
    let key = s_of(&selected, "key");
    for name in outstanding(settings, &lineage_id)? {
        let Ok(earlier) = queue::read_changeset(settings, &lineage_id, &name) else {
            continue;
        };
        if earlier.get("view_key").and_then(Value::as_str) == Some(key)
            && earlier.get("ids_sha256").and_then(Value::as_str) == Some(ids_sha.as_str())
        {
            let mut out = Map::new();
            out.insert("csid".into(), json!(name));
            out.insert("reused".into(), json!(true));
            out.insert("lineage".into(), json!(lineage_id));
            out.insert("records".into(), json!(pending.len()));
            out.insert("ids_sha256".into(), json!(ids_sha));
            if let Value::Object(info) = pending_info(settings, &lineage_id, &name, None, host.jobs())? {
                out.extend(info);
            }
            return Ok(Value::Object(out));
        }
    }
    let csid = new_csid();
    let origin = selected.get("origin_key").filter(|v| truthy(v)).or_else(|| selected.get("key")).cloned().unwrap_or(Value::Null);
    let kept_options: Map<String, Value> = ["allow_unverified_before", "backup", "confirm_large"]
        .iter()
        .filter_map(|k| options.get(*k).map(|v| ((*k).to_string(), v.clone())))
        .collect();
    let body = json!({
        "format": FORMAT, "csid": csid, "lineage": lineage_id, "view": view_of(&selected), "view_key": key,
        "target": {"name": selected.get("name"), "program": selected.get("program"), "sha256": selected.get("sha256"), "origin_key": origin},
        "agent": attribution(), "base": st.get("base"), "store_revision": st["revision"], "head_generation": head["gen"],
        "ids": pending.iter().map(|r| r["id"].clone()).collect::<Vec<_>>(), "ids_sha256": ids_sha, "records": pending,
        "options": kept_options, "sealed_at": now_iso(),
    });
    hy_core::sealed::write_sealed(
        &pending_path(settings, &lineage_id, &csid)?,
        &body,
        Some(2),
        Some(MAX_HISTORY_BYTES as usize),
        Some("the changeset would exceed 20 MiB; publish fewer records"),
    )?;
    point("after_seal_changeset")?;
    let mut out = Map::new();
    out.insert("csid".into(), json!(csid));
    out.insert("reused".into(), json!(false));
    out.insert("lineage".into(), json!(lineage_id));
    out.insert("records".into(), json!(pending.len()));
    out.insert("ids_sha256".into(), json!(ids_sha));
    out.insert("base_generation".into(), json!(base_generation(&st)));
    out.insert("head_generation".into(), head["gen"].clone());
    if let Value::Object(info) = pending_info(settings, &lineage_id, &csid, None, host.jobs())? {
        out.extend(info);
    }
    Ok(Value::Object(out))
}
