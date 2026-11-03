//! The publish leader and the publish job (`views.py`: `drain`, `reconcile`, `_build`, `_build_locked`, `_count_failure`,
//! `settle_one`, `run_publish_job`, `await_turn`, `wait_decision`, `outcome_of`).
//!
//! Everything that decides, queues, locks and records is native. The one step that needs the engine, building the candidate
//! generation (`views._publish_candidate`: fork, replay, save, manifest, verification, seal and the `CURRENT.log` line), is
//! [`Host::publish_candidate`](crate::views::Host::publish_candidate).

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::classify::{Pair, classify, conflict_row, probe_pairs};
use crate::error::{Error, PublishFailure, Result, ViewError};
use crate::generations::{manifest_file_sha256, tampered, verify_manifest};
use crate::gens::{
    append_current, current_log, editors_since, history, in_master, live_generations, master_ids,
    project_folder_of, read_manifest,
};
use crate::layout::{Settings, dir, failure_path, lineage_dir, now_iso, publish_lock_path};
use crate::locks::{LaneLock, locked};
use crate::queue::{
    PUBLISH_BATCH_MAX, outstanding, pending_info, read_changeset, read_done, write_done,
};
use crate::records::truthy;
use crate::settle::{finalize_changeset, py_dumps};
use crate::store::{Target, load_store, with_view};
use crate::views::Host;

/// How long one publish job waits for its changeset before it gives up (it stays queued).
pub const PUBLISH_WAIT_S: f64 = 3600.0;
/// How long a leader waits for a running commit (`.commit.lock`) before it yields.
pub const COMMIT_WAIT_S: f64 = 120.0;
pub const POLL_S: f64 = 0.1;
/// A follower waits in the kernel's queue of `publish.lock` for at most this long.
pub const TURN_WAIT_S: f64 = 1.0;
/// A waiting worker reports its progress when it changes, and at least this often.
pub const PROGRESS_HEARTBEAT_S: f64 = 10.0;
/// Counted candidate failures of one changeset before it ends as `candidate_failed`.
pub const MAX_ATTEMPTS: i64 = 3;
/// A status poll of a pending changeset waits at most this long for its decision.
pub const STATUS_WAIT_S: f64 = 0.5;

/// Why a build produced no generation: a [`PublishFailure`] (counted or not), or any other error (which ends the drain).
#[derive(Debug)]
pub enum PublishError {
    Failure(Box<PublishFailure>),
    Other(Error),
}

impl From<PublishFailure> for PublishError {
    fn from(value: PublishFailure) -> Self {
        Self::Failure(Box::new(value))
    }
}

impl From<Error> for PublishError {
    fn from(value: Error) -> Self {
        Self::Other(value)
    }
}

impl From<hy_core::Error> for PublishError {
    fn from(value: hy_core::Error) -> Self {
        Self::Other(value.into())
    }
}

impl PublishError {
    /// A simulated kill (`durable.FaultInjected`): nothing more is written, the next leader decides from the files.
    fn is_fault(&self) -> bool {
        matches!(
            self,
            Self::Other(Error::Core(hy_core::Error::FaultInjected(_)))
        )
    }
}

/// One changeset of a batch, decided against the head.
#[derive(Debug, Clone)]
pub struct Decided {
    pub cs: Map<String, Value>,
    pub outcome: String,
    /// The records to replay (`apply` and `unchecked` verdicts).
    pub apply: Vec<Value>,
    /// Record id to `applied | rebased | converged | conflict | skipped`.
    pub records: Map<String, Value>,
    pub unverified: Vec<String>,
    pub converged: Vec<String>,
    pub in_master: Vec<String>,
    pub conflicts: Vec<Value>,
}

/// What the engine side needs to build one candidate.
pub struct CandidateRequest<'a> {
    pub settings: &'a Settings,
    pub lineage_id: &'a str,
    pub head: &'a Map<String, Value>,
    pub target: &'a Target,
    pub accepted: &'a [Decided],
    pub timeout_s: i64,
    pub started: Instant,
}

/// A decided changeset to finalize in its view once the commit lock is released.
#[derive(Debug, Clone)]
pub struct Settle {
    pub cs: Map<String, Value>,
    pub generation: Option<i64>,
    pub ids: Vec<String>,
    pub subjects: Option<Vec<String>>,
}

/// What one build decided: `generation` is `None` when no candidate was needed.
#[derive(Debug, Clone, Default)]
pub struct Built {
    pub generation: Option<i64>,
    pub csids: Vec<String>,
    pub manifest_sha256: Option<String>,
}

/// What a drain did.
#[derive(Debug)]
pub struct Drained {
    pub led: bool,
    pub built: Vec<i64>,
    pub failure: Option<Value>,
}

fn s_of<'a>(v: &'a Map<String, Value>, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

fn base_generation(cs: &Map<String, Value>) -> i64 {
    cs.get("base")
        .and_then(|b| b.get("generation"))
        .and_then(Value::as_i64)
        .unwrap_or(0)
}

fn point(name: &str) -> Result<()> {
    hy_core::fault::fault(&format!("publish.{name}"))?;
    Ok(())
}

/// `publishBatchMax`: changesets per generation.
fn batch_max(settings: &Settings) -> usize {
    match settings.get("publish_batch_max").and_then(Value::as_i64) {
        Some(n) if n >= 1 => n as usize,
        _ => PUBLISH_BATCH_MAX as usize,
    }
}

fn truncate_chars(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

// ---- failures and reconciliation ---------------------------------------------------------------------------------------------

/// A counted failure is held against the changeset that caused it; at [`MAX_ATTEMPTS`] it ends as `candidate_failed`, so one
/// poisoned changeset cannot hold the queue for ever. The view's records stay pending: nothing is ever dropped.
pub fn count_failure(settings: &Settings, lineage_id: &str, error: &PublishFailure) -> Result<()> {
    let Some(csid) = error
        .csid
        .as_deref()
        .filter(|c| !c.is_empty() && error.counted)
    else {
        return Ok(());
    };
    let path = failure_path(settings, lineage_id, csid)?;
    let existing = hy_core::sealed::read_sealed_info(
        &path,
        &hy_core::sealed::ReadOptions::default(),
        Some(Value::Null),
    )?
    .0;
    let mut record = match existing {
        Value::Object(m) if !m.is_empty() => m,
        _ => json!({"csid": csid, "attempts": 0, "history": []})
            .as_object()
            .cloned()
            .unwrap_or_default(),
    };
    let attempts = record.get("attempts").and_then(Value::as_i64).unwrap_or(0) + 1;
    record.insert("attempts".into(), json!(attempts));
    let mut history: Vec<Value> = record
        .get("history")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    history.push(json!({"at": now_iso(), "code": error.code, "message": truncate_chars(&error.message, 300),
                        "candidate": error.detail.get("candidate").cloned().unwrap_or(Value::Null)}));
    let keep_from = history.len().saturating_sub(10);
    let history: Vec<Value> = history.split_off(keep_from);
    record.insert("history".into(), Value::Array(history.clone()));
    hy_core::sealed::write_sealed_default(&path, &Value::Object(record))?;
    if attempts >= MAX_ATTEMPTS {
        let candidates: Vec<Value> = history
            .iter()
            .filter_map(|h| h.get("candidate").filter(|c| truthy(c)).cloned())
            .collect();
        let mut done = Map::new();
        done.insert("outcome".into(), json!("candidate_failed"));
        done.insert("generation".into(), Value::Null);
        done.insert("record_outcomes".into(), json!({}));
        done.insert("attempts".into(), json!(attempts));
        done.insert(
            "failure".into(),
            history.last().cloned().unwrap_or(Value::Null),
        );
        done.insert("candidates".into(), Value::Array(candidates));
        write_done(settings, lineage_id, csid, &done)?;
    }
    Ok(())
}

/// Under `publish.lock`: settle what a dead leader left. A changeset the live history names, whose result file is missing, is
/// resolved from the manifest of its generation: the manifest still verifies, so the result is written (exactly once); if it
/// does not verify, a `rollback` line returns the head to the previous generation and the changesets stay in the queue.
pub fn reconcile(settings: &Settings, lineage_id: &str) -> Result<Vec<Value>> {
    let mut done = Vec::new();
    for row in live_generations(settings, lineage_id)? {
        let names: Vec<String> = row
            .get("changesets")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|item| item.get("csid").and_then(Value::as_str))
            .filter(|c| !c.is_empty())
            .map(str::to_string)
            .collect();
        let mut missing = Vec::new();
        for name in &names {
            if read_done(settings, lineage_id, name)?.is_none() {
                missing.push(name.clone());
            }
        }
        if missing.is_empty() {
            continue;
        }
        let folder = project_folder_of(s_of_value(&row, "gpr"));
        let check = verify_manifest(&folder);
        let named = manifest_file_sha256(&folder);
        if check.ok && named.as_deref() == row.get("manifestSha256").and_then(Value::as_str) {
            let manifest = check.manifest.clone().unwrap_or_default();
            let store = manifest.get("store").cloned().unwrap_or(Value::Null);
            for name in &missing {
                let info = store
                    .get("by_changeset")
                    .and_then(|b| b.get(name))
                    .cloned()
                    .unwrap_or(Value::Null);
                let mut record = Map::new();
                record.insert(
                    "outcome".into(),
                    info.get("outcome")
                        .cloned()
                        .unwrap_or_else(|| json!("applied")),
                );
                record.insert("generation".into(), row["gen"].clone());
                record.insert("gpr".into(), row["gpr"].clone());
                record.insert(
                    "manifestSha256".into(),
                    row.get("manifestSha256").cloned().unwrap_or(Value::Null),
                );
                record.insert(
                    "record_outcomes".into(),
                    info.get("records")
                        .filter(|r| truthy(r))
                        .cloned()
                        .unwrap_or_else(|| json!({})),
                );
                record.insert("resolved_from".into(), json!("manifest"));
                write_done(settings, lineage_id, name, &record)?;
                done.push(json!({"csid": name, "action": "resolved_from_manifest", "generation": row["gen"]}));
            }
        } else {
            let previous = check
                .manifest
                .as_ref()
                .and_then(|m| m.get("base"))
                .and_then(|b| b.get("generation"))
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let back = history(settings, lineage_id)?
                .into_iter()
                .rev()
                .find(|item| {
                    item.get("gen").and_then(Value::as_i64) == Some(previous)
                        && item.get("reason").and_then(Value::as_str) != Some("rollback")
                });
            if let Some(back) = back {
                let mut line = Map::new();
                line.insert("gen".into(), json!(previous));
                line.insert("cid".into(), row.get("cid").cloned().unwrap_or(Value::Null));
                line.insert("reason".into(), json!("rollback"));
                line.insert("gpr".into(), back["gpr"].clone());
                line.insert(
                    "manifestSha256".into(),
                    back.get("manifestSha256").cloned().unwrap_or(Value::Null),
                );
                line.insert("detail".into(), json!("candidate_failed_reverify"));
                append_current(settings, lineage_id, &line, false)?;
            }
            done.push(
                json!({"csid": missing, "action": "rolled_back", "problems": check.problems}),
            );
        }
    }
    Ok(done)
}

fn s_of_value<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or_default()
}

// ---- deciding a batch ----------------------------------------------------------------------------------------------------

/// `views._leader_target`: the master as a target for the leader.
pub fn leader_target(first: &Map<String, Value>, head: &Map<String, Value>) -> Target {
    let t = &first["target"];
    let origin = t["origin_key"].clone();
    let mut target = Map::new();
    target.insert("name".into(), t["name"].clone());
    target.insert("program".into(), t["program"].clone());
    target.insert("sha256".into(), t["sha256"].clone());
    target.insert("key".into(), origin.clone());
    target.insert("origin_key".into(), origin);
    target.insert("gpr".into(), head["gpr"].clone());
    target.insert("view".into(), json!("shared"));
    target
}

/// `views._settle_all`: a changeset with a generation does not wait for a busy view (`settle` replays it from `CURRENT.log` at
/// the view's next call); one decided without a generation is in no log row, so it keeps the bounded wait.
fn settle_all(
    host: &dyn Host,
    settings: &Settings,
    lineage_id: &str,
    settles: &[Settle],
) -> Result<()> {
    for item in settles {
        settle_one(
            host,
            settings,
            lineage_id,
            &item.cs,
            item.generation,
            &item.ids,
            item.generation.map(|_| 0.0),
            item.subjects.as_deref(),
        )?;
    }
    Ok(())
}

/// Finalize one decided changeset in the view that sealed it (best effort: a view that is busy settles at its next call).
#[allow(clippy::too_many_arguments)]
pub fn settle_one(
    host: &dyn Host,
    settings: &Settings,
    lineage_id: &str,
    cs: &Map<String, Value>,
    generation: Option<i64>,
    ids: &[String],
    wait_s: Option<f64>,
    subjects: Option<&[String]>,
) -> Result<bool> {
    let attempt = || -> Result<bool> {
        let name = cs
            .get("target")
            .and_then(|t| t.get("name"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let view = s_of(cs, "view");
        let resolved = host.resolve_target(settings, name)?;
        let target = with_view(&resolved, if view == "shared" { "" } else { view })?;
        let subjects = subjects.map(|s| json!(s));
        let retire = || host.retire_copies(settings, &target);
        finalize_changeset(
            settings,
            &target,
            lineage_id,
            s_of(cs, "csid"),
            generation,
            ids,
            cs.get("store_revision").and_then(Value::as_i64),
            wait_s,
            subjects.as_ref(),
            Some(&retire),
        )
    };
    match attempt() {
        Ok(changed) => Ok(changed),
        Err(Error::Core(hy_core::Error::FaultInjected(m))) => {
            Err(Error::Core(hy_core::Error::FaultInjected(m)))
        }
        Err(_) => Ok(false),
    }
}

/// Steps 3 to 5 of 4.10 for one batch. A publish and a commit both append generations: they take turns on `.commit.lock`.
/// The wait is bounded, and a wait that runs out is not a failure of the changeset. The decided changesets are settled in their
/// views after the commit lock is released.
pub fn build(
    host: &dyn Host,
    settings: &Settings,
    lineage_id: &str,
    batch_ids: &[String],
    timeout_s: i64,
) -> std::result::Result<Built, PublishError> {
    let started = Instant::now();
    let mut settles: Vec<Settle> = Vec::new();
    let result = {
        let lock = lineage_dir(settings, lineage_id)
            .map_err(PublishError::from)?
            .join(".commit.lock");
        match locked(&lock, COMMIT_WAIT_S, "commit lock") {
            Err(_) => Err(PublishError::from(PublishFailure::new(
                "commit_busy",
                "a commit holds this lineage's commit lock; the changesets stay queued",
                false,
            ))),
            // A commit that ran while this leader waited may have moved the head: everything below reads it afresh.
            Ok(_guard) => build_locked(
                host,
                settings,
                lineage_id,
                batch_ids,
                timeout_s,
                started,
                &mut settles,
            ),
        }
    };
    match result {
        Err(error) if error.is_fault() => Err(error),
        Err(error) => {
            // the changesets decided before the failure (their results are written)
            settle_all(host, settings, lineage_id, &settles)?;
            Err(error)
        }
        Ok(built) => {
            settle_all(host, settings, lineage_id, &settles)?;
            Ok(built)
        }
    }
}

fn probe_live(host: &dyn Host, program: &Value, records: &[Value]) -> Result<HashMap<Pair, Value>> {
    let pairs = probe_pairs(records);
    if pairs.is_empty() {
        Ok(HashMap::new())
    } else {
        host.probe(program, &pairs)
    }
}

fn sorted_union(a: &[String], b: &[String]) -> Vec<String> {
    let mut all: Vec<String> = a.iter().chain(b).cloned().collect();
    all.sort();
    all
}

/// Decide each changeset of the batch against the head and, when some have records to apply, hand them to the candidate
/// builder.
fn build_locked(
    host: &dyn Host,
    settings: &Settings,
    lineage_id: &str,
    batch_ids: &[String],
    timeout_s: i64,
    started: Instant,
    settles: &mut Vec<Settle>,
) -> std::result::Result<Built, PublishError> {
    let head = crate::gens::head(settings, lineage_id)?;
    if head.get("corrupt").is_some_and(truthy) {
        return Err(PublishFailure::new(
            "lineage_corrupt",
            format!(
                "CURRENT.log has a damaged line in the middle (offset {}); publishes are refused until the owner repairs it",
                match head["corrupt"].get("offset") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => "None".into(),
                    Some(other) => other.to_string(),
                }
            ),
            false,
        )
        .into());
    }
    let bad = tampered(settings, lineage_id)?;
    if !bad.is_empty() {
        return Err(PublishFailure::new(
            "tampered",
            "a published generation no longer matches its manifest; publishes are refused until the owner re-adopts",
            false,
        )
        .with("tampered", Value::Array(bad))
        .into());
    }
    let mut batch: Vec<Map<String, Value>> = Vec::new();
    for name in batch_ids {
        if read_done(settings, lineage_id, name)?.is_some() {
            continue;
        }
        match read_changeset(settings, lineage_id, name) {
            Ok(cs) => batch.push(cs),
            Err(
                error @ (Error::Core(
                    hy_core::Error::StoreCorrupt { .. }
                    | hy_core::Error::Io(_)
                    | hy_core::Error::Value(_)
                    | hy_core::Error::Json(_),
                )
                | Error::View(_)),
            ) => {
                let mut record = Map::new();
                record.insert("outcome".into(), json!("corrupt_changeset"));
                record.insert("generation".into(), Value::Null);
                record.insert("record_outcomes".into(), json!({}));
                record.insert(
                    "message".into(),
                    json!(truncate_chars(&error.to_string(), 300)),
                );
                write_done(settings, lineage_id, name, &record)?;
            }
            Err(other) => return Err(other.into()),
        }
    }
    if batch.is_empty() {
        return Ok(Built::default());
    }
    let target = leader_target(&batch[0], &head);
    let known = master_ids(settings, lineage_id, 0)?;
    let program = host.open_program(
        s_of_value(&Value::Object(head.clone()), "gpr"),
        s_of(&target, "program"),
        s_of(&target, "sha256"),
        false,
    )?;
    let records_of = |cs: &Map<String, Value>| -> Vec<Value> {
        cs.get("records")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default()
    };
    let everything: Vec<Value> = batch
        .iter()
        .flat_map(&records_of)
        .filter(|r| !in_master(r, &known))
        .collect();
    let live = probe_live(host, &program, &everything)?;
    let head_gen = head["gen"].as_i64().unwrap_or(0);
    let mut chain: HashMap<Pair, Value> = HashMap::new();
    let mut results: Vec<Decided> = Vec::new();
    for cs in &batch {
        let all = records_of(cs);
        let skipped: Vec<&Value> = all.iter().filter(|r| in_master(r, &known)).collect();
        let mine: Vec<Value> = all
            .iter()
            .filter(|r| !in_master(r, &known))
            .cloned()
            .collect();
        let id_of = |r: &Value| r["id"].as_str().unwrap_or_default().to_string();
        let unverified: Vec<String> = mine
            .iter()
            .filter(|r| r.get("before_unknown").is_some_and(truthy))
            .map(id_of)
            .collect();
        let (verdicts, after) = classify(&mine, &live, Some(&chain));
        let by_id: HashMap<String, &Value> = mine.iter().map(|r| (id_of(r), r)).collect();
        let conflicts: Vec<&Value> = verdicts
            .iter()
            .filter(|v| v["outcome"] == "conflict")
            .collect();
        let mut outcomes: Map<String, Value> = skipped
            .iter()
            .map(|r| (id_of(r), json!("skipped")))
            .collect();
        for verdict in &verdicts {
            let kind = match verdict["outcome"].as_str().unwrap_or_default() {
                "apply" | "unchecked" => "applied",
                "converged" => "converged",
                _ => "conflict",
            };
            outcomes.insert(id_of(verdict), json!(kind));
        }
        let apply: Vec<Value> = verdicts
            .iter()
            .filter(|v| matches!(v["outcome"].as_str(), Some("apply" | "unchecked")))
            .map(|v| by_id[&id_of(v)].clone())
            .collect();
        let converged: Vec<String> = verdicts
            .iter()
            .filter(|v| v["outcome"] == "converged")
            .map(id_of)
            .collect();
        let editors: Vec<Value>;
        let outcome: &str;
        if conflicts.is_empty() {
            editors = Vec::new();
            let moved = base_generation(cs) != head_gen;
            outcome = if !apply.is_empty() {
                if moved { "rebased" } else { "applied" }
            } else if !converged.is_empty() {
                "converged"
            } else {
                "skipped"
            };
            chain = after;
            if moved {
                for record in &apply {
                    outcomes.insert(id_of(record), json!("rebased"));
                }
            }
        } else {
            let subjects: BTreeSet<String> = conflicts
                .iter()
                .map(|c| c["subject"].as_str().unwrap_or_default().to_string())
                .collect();
            editors = editors_since(settings, lineage_id, base_generation(cs), Some(&subjects))?;
            outcome = "conflict";
        }
        let rows: Vec<Value> = conflicts
            .iter()
            .map(|c| conflict_row(c, by_id[&id_of(c)], Some(&editors)))
            .collect();
        results.push(Decided {
            cs: cs.clone(),
            outcome: outcome.into(),
            apply,
            records: outcomes,
            unverified,
            converged,
            in_master: skipped.iter().map(|r| id_of(r)).collect(),
            conflicts: rows,
        });
    }
    // Decided without a new generation: a conflict, records the master already holds, values it already has.
    let accepted: Vec<Decided> = results
        .iter()
        .filter(|d| !d.apply.is_empty())
        .cloned()
        .collect();
    let accepted_ids: BTreeSet<&str> = accepted.iter().map(|d| s_of(&d.cs, "csid")).collect();
    for item in &results {
        if accepted_ids.contains(s_of(&item.cs, "csid")) {
            continue;
        }
        let settled = sorted_union(&item.converged, &item.in_master);
        let mut record = Map::new();
        record.insert("outcome".into(), json!(item.outcome));
        record.insert("generation".into(), Value::Null);
        record.insert(
            "record_outcomes".into(),
            Value::Object(item.records.clone()),
        );
        record.insert("conflicts".into(), Value::Array(item.conflicts.clone()));
        record.insert("base_generation".into(), json!(head_gen));
        record.insert("settled".into(), json!(settled));
        record.insert("converged".into(), json!(item.converged));
        record.insert("in_master".into(), json!(item.in_master));
        record.insert("unverified".into(), json!(item.unverified));
        record.insert(
            "build_ms".into(),
            json!(started.elapsed().as_millis() as i64),
        );
        write_done(settings, lineage_id, s_of(&item.cs, "csid"), &record)?;
        if item.outcome != "conflict" {
            settles.push(Settle {
                cs: item.cs.clone(),
                generation: None,
                ids: settled,
                subjects: None,
            });
        }
    }
    if accepted.is_empty() {
        return Ok(Built {
            generation: None,
            csids: results
                .iter()
                .map(|d| s_of(&d.cs, "csid").to_string())
                .collect(),
            manifest_sha256: None,
        });
    }
    host.publish_candidate(
        &CandidateRequest {
            settings,
            lineage_id,
            head: &head,
            target: &target,
            accepted: &accepted,
            timeout_s,
            started,
        },
        settles,
    )
}

// ---- the leader ------------------------------------------------------------------------------------------------------------

/// Try to become the leader and drain the queue in id order, until it is empty or `stop_after` is decided. Non-blocking: when
/// another process holds `publish.lock` this returns `led: false` at once. `lock` is `publish.lock` already held by the caller
/// (a granted [`await_turn`]); the drain releases it.
pub fn drain(
    host: &dyn Host,
    settings: &Settings,
    lineage_id: &str,
    stop_after: Option<&str>,
    timeout_s: i64,
    lock: Option<LaneLock>,
) -> Result<Drained> {
    let _lock = match lock {
        Some(held) => held,
        None => {
            std::fs::create_dir_all(lineage_dir(settings, lineage_id)?)?;
            let mut fresh = LaneLock::new(publish_lock_path(settings, lineage_id)?);
            if !fresh.acquire() {
                return Ok(Drained {
                    led: false,
                    built: Vec::new(),
                    failure: None,
                });
            }
            fresh
        }
    };
    let mut built = Vec::new();
    let mut failure = None;
    // Who leads, for `status` and the doctor (the OS lock is the truth; this file is only a label and may be stale).
    hy_core::fsio::atomic_write_point(
        &lineage_dir(settings, lineage_id)?.join("publish.leader.json"),
        py_dumps(&json!({"pid": std::process::id(), "at": now_iso()})).as_bytes(),
        "leader",
        true,
    )?;
    point("after_lock")?;
    // Every acquisition repairs a torn CURRENT.log tail before any append (4.1), then settles what a dead leader left.
    current_log(settings, lineage_id)?.repair(false)?;
    reconcile(settings, lineage_id)?;
    loop {
        let queue = outstanding(settings, lineage_id)?;
        if queue.is_empty()
            || stop_after.is_some_and(|s| !s.is_empty() && !queue.iter().any(|q| q == s))
        {
            break;
        }
        let batch: Vec<String> = queue.into_iter().take(batch_max(settings)).collect();
        let step = match build(host, settings, lineage_id, &batch, timeout_s) {
            Ok(step) => step,
            Err(PublishError::Failure(error)) => {
                if batch.len() > 1 && error.code != "commit_busy" {
                    // A batch shares one candidate. A failed one says nothing about which changeset caused it, so it is held
                    // against none of them: the first of the batch is decided alone, as with publish_batch_max 1, and the
                    // loop reaches the rest the same way.
                    match build(host, settings, lineage_id, &batch[..1], timeout_s) {
                        Ok(step) => step,
                        Err(PublishError::Failure(single)) => {
                            failure = Some(single.payload());
                            count_failure(settings, lineage_id, &single)?;
                            break;
                        }
                        Err(PublishError::Other(other)) => return Err(other),
                    }
                } else {
                    failure = Some(error.payload());
                    count_failure(settings, lineage_id, &error)?;
                    break;
                }
            }
            Err(PublishError::Other(other)) => return Err(other),
        };
        if let Some(generation) = step.generation.filter(|g| *g != 0) {
            built.push(generation);
        }
    }
    Ok(Drained {
        led: true,
        built,
        failure,
    })
}

// ---- the publish job ---------------------------------------------------------------------------------------------------------

#[cfg(windows)]
pub use crate::locks::FolderWatch as Watch;

/// Where there is no change notification the wait is a plain sleep.
#[cfg(not(windows))]
pub struct Watch;

#[cfg(not(windows))]
impl Watch {
    pub fn rearm(&self) {}
}

/// A [`Watch`] on the lineage's `done/` and `declined/`, or `None` where there is no change notification.
pub fn decision_watch(settings: &Settings, lineage_id: &str) -> Option<Watch> {
    #[cfg(windows)]
    {
        let mut folders = Vec::new();
        for name in ["done", "declined"] {
            let Ok(folder) = dir(settings, lineage_id, name) else {
                continue;
            };
            if std::fs::create_dir_all(&folder).is_err() {
                continue;
            }
            folders.push(folder);
        }
        let watch = Watch::new(folders);
        if watch.handles.is_empty() {
            None
        } else {
            Some(watch)
        }
    }
    #[cfg(not(windows))]
    {
        let _ = (settings, lineage_id, dir);
        None
    }
}

/// Wait until `publish.lock` is free, at most `timeout_s`. Returns the lock held (the caller's [`drain`] leads with it, or
/// the caller releases it), or `None` when the time passed or `watch` was signalled first. Where the queued wait is
/// unavailable it sleeps [`POLL_S`] and returns `None`.
pub fn await_turn(
    settings: &Settings,
    lineage_id: &str,
    timeout_s: f64,
    watch: Option<&Watch>,
) -> Result<Option<LaneLock>> {
    #[cfg(windows)]
    {
        let wake: &[crate::locks::RawHandle] = watch.map_or(&[][..], |w| w.handles.as_slice());
        if let Ok(found) =
            LaneLock::queued(publish_lock_path(settings, lineage_id)?, timeout_s, wake)
        {
            return Ok(found);
        }
    }
    let _ = (settings, lineage_id, timeout_s, watch);
    std::thread::sleep(Duration::from_secs_f64(POLL_S));
    Ok(None)
}

/// Let a status poll of a changeset that is still queued wait (in the kernel, on the change notification of `done/` and
/// `declined/`) until its result is written or `timeout_s` passes. Returns at once for a decided, unknown or malformed
/// changeset, and where there is no change notification.
pub fn wait_decision(
    settings: &Settings,
    lineage_id: &str,
    csid: &str,
    timeout_s: f64,
) -> Result<()> {
    if !cfg!(windows) || !crate::layout::is_csid(csid) {
        return Ok(());
    }
    if !outstanding(settings, lineage_id)?.iter().any(|c| c == csid) {
        return Ok(());
    }
    let Some(watch) = decision_watch(settings, lineage_id) else {
        return Ok(());
    };
    let deadline = Instant::now() + Duration::from_secs_f64(timeout_s);
    while read_done(settings, lineage_id, csid)?.is_none() {
        let Some(left) = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
        else {
            return Ok(());
        };
        #[cfg(windows)]
        crate::locks::wait_handles(&watch.handles, left.as_secs_f64());
        #[cfg(not(windows))]
        let _ = left;
        watch.rearm();
    }
    Ok(())
}

/// The job of a decided changeset settles it in its own view before it reports the view's revision. Idempotent by csid.
fn settle_own(
    host: &dyn Host,
    settings: &Settings,
    lineage_id: &str,
    csid: &str,
    result: &Map<String, Value>,
) -> Result<bool> {
    if matches!(
        result.get("outcome").and_then(Value::as_str),
        Some("conflict" | "candidate_failed" | "corrupt_changeset")
    ) {
        return Ok(false);
    }
    let generation = result.get("generation").and_then(Value::as_i64);
    let ids: Vec<String> = if generation.is_some() {
        let mut ids: Vec<String> = result
            .get("record_outcomes")
            .and_then(Value::as_object)
            .into_iter()
            .flatten()
            .filter(|(_, kind)| kind.as_str() != Some("conflict"))
            .map(|(id, _)| id.clone())
            .collect();
        ids.sort();
        ids
    } else if let Some(settled) = result.get("settled") {
        let mut ids: Vec<String> = settled
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        ids.sort();
        ids
    } else {
        return Ok(false);
    };
    let Ok(cs) = read_changeset(settings, lineage_id, csid) else {
        return Ok(false);
    };
    // The generation's manifest is sealed before the result is written: its `store.subjects` is what the batch applied.
    let subjects: Option<Vec<String>> =
        if generation.is_some() && result.get("gpr").is_some_and(truthy) {
            read_manifest(&project_folder_of(s_of(result, "gpr")))
                .and_then(|m| m.get("store")?.get("subjects")?.as_array().cloned())
                .map(|a| {
                    a.iter()
                        .map(|v| v.as_str().map_or_else(|| v.to_string(), str::to_string))
                        .collect()
                })
        } else {
            None
        };
    settle_one(
        host,
        settings,
        lineage_id,
        &cs,
        generation,
        &ids,
        None,
        subjects.as_deref(),
    )
}

fn revision_of(settings: &Settings, selected: &Target) -> Option<i64> {
    load_store(settings, selected)
        .ok()
        .and_then(|s| s.get("revision").and_then(Value::as_i64))
}

/// The result of a decided changeset as the job reports it. With `revision` (the sealing view's store revision) the conflict
/// carries the exact `rebase` call that settles it.
pub fn outcome_of(result: &Map<String, Value>, revision: Option<i64>) -> Result<Value> {
    let outcome = result.get("outcome").and_then(Value::as_str);
    let csid = result.get("csid").cloned().unwrap_or(Value::Null);
    if outcome == Some("conflict") {
        let mut options = Map::new();
        options.insert("kind".into(), json!("rebase"));
        if let Some(r) = revision {
            options.insert("expect_revision".into(), json!(r));
        }
        let conflicts = result
            .get("conflicts")
            .cloned()
            .unwrap_or_else(|| json!([]));
        let resolve: Map<String, Value> = conflicts
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|c| {
                c.get("subject")
                    .and_then(Value::as_str)
                    .filter(|s| !s.is_empty())
            })
            .map(|s| (s.to_string(), json!("take_mine | keep")))
            .collect();
        options.insert("resolve".into(), Value::Object(resolve));
        return Err(ViewError::new(
            "publish_conflict",
            "the master holds other values where this changeset rests on older ones; nothing was published and the records stay pending in the view",
        )
        .with("csid", csid)
        .with("conflicts", conflicts)
        .with("next", json!({"tool": "ghidra_query", "action": "type_edit", "options": options}))
        .with("suggest", json!("rebase this view: it lists each conflict, and resolve decides it (take_mine re-anchors your record to the master's value, keep drops it); then publish again"))
        .into());
    }
    if let Some(kind @ ("candidate_failed" | "corrupt_changeset")) = outcome {
        return Err(ViewError::new(
            kind,
            "the changeset was not published; its records stay pending in the view",
        )
        .with("csid", csid)
        .with(
            "failure",
            result.get("failure").cloned().unwrap_or(Value::Null),
        )
        .with(
            "candidates",
            result.get("candidates").cloned().unwrap_or(Value::Null),
        )
        .into());
    }
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert(
        "generation".into(),
        result.get("generation").cloned().unwrap_or(Value::Null),
    );
    for key in [
        "csid",
        "outcome",
        "gpr",
        "record_outcomes",
        "base_generation",
        "seq",
        "build_ms",
        "manifestSha256",
        "converged",
        "in_master",
        "unverified",
    ] {
        if let Some(v) = result.get(key).filter(|v| !v.is_null()) {
            out.insert(key.into(), v.clone());
        }
    }
    Ok(Value::Object(out))
}

/// The worker of a publish job: wait for the changeset's result, and lead the queue whenever the lock is free. Fails with a
/// [`ViewError`] for a conflict or a failed candidate (the records stay pending in the view).
pub fn run_publish_job(
    host: &dyn Host,
    settings: &Settings,
    selected: &Target,
    options: &Map<String, Value>,
    timeout_s: i64,
    mut progress: Option<&mut dyn FnMut(&Value)>,
) -> Result<Value> {
    let csid = s_of(options, "csid").to_string();
    let lineage_id = s_of(options, "lineage").to_string();
    let wait = settings
        .get("publish_wait_s")
        .and_then(Value::as_f64)
        .unwrap_or(PUBLISH_WAIT_S);
    let deadline = Instant::now() + Duration::from_secs_f64(wait.max(0.0));
    let mut reported: Option<Value> = None;
    let mut reported_at = Instant::now();
    let mut reported_once = false;
    let mut turn: Option<LaneLock> = None; // `publish.lock`, when the last wait was granted it: the next drain leads with it
    // wakes the wait when a result is written (Windows), set before the first look
    let watch = decision_watch(settings, &lineage_id);
    loop {
        let mut result = read_done(settings, &lineage_id, &csid)?;
        if result.is_none() {
            let led = drain(
                host,
                settings,
                &lineage_id,
                Some(&csid),
                timeout_s,
                turn.take(),
            )?;
            result = read_done(settings, &lineage_id, &csid)?;
            if result.is_none()
                && let Some(failure) = led.failure
                && !failure["counted"].as_bool().unwrap_or(false)
                && failure["error"] != "commit_busy"
            {
                return Err(ViewError::new(
                    failure["error"].as_str().unwrap_or_default(),
                    failure["message"].as_str().unwrap_or_default(),
                )
                .with("csid", json!(csid))
                .with("retained", json!("the changeset stays queued and its records stay pending; this job ends, and no job drives the changeset now: it is published when any later publish on this lineage (from any view) leads the queue, so publish again once the cause is gone"))
                .into());
            }
        }
        turn = None;
        if let Some(result) = result {
            settle_own(host, settings, &lineage_id, &csid, &result)?;
            return outcome_of(&result, revision_of(settings, selected));
        }
        let info = pending_info(settings, &lineage_id, &csid, None, host.jobs())?;
        match info["state"].as_str() {
            Some("done") => continue,
            Some("unknown") => {
                return Err(ViewError::new(
                    "unknown_changeset",
                    format!("changeset {csid} is not in the queue"),
                )
                .into());
            }
            _ => {}
        }
        if let Some(report) = progress.as_mut()
            && (!reported_once
                || reported.as_ref() != Some(&info)
                || reported_at.elapsed().as_secs_f64() >= PROGRESS_HEARTBEAT_S)
        {
            report(&info);
            reported = Some(info.clone());
            reported_at = Instant::now();
            reported_once = true;
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            let mut error = ViewError::new(
                "publish_wait_expired",
                "the changeset was not decided within publish_wait_s; it stays queued and is published when a leader reaches it",
            )
            .with("csid", json!(csid));
            if let Value::Object(extra) =
                pending_info(settings, &lineage_id, &csid, None, host.jobs())?
            {
                error.detail.extend(extra);
            }
            return Err(error.into());
        }
        turn = await_turn(
            settings,
            &lineage_id,
            TURN_WAIT_S.min(POLL_S.max(left.as_secs_f64())),
            watch.as_ref(),
        )?;
        if let Some(w) = &watch {
            w.rearm(); // before the next look: a result written from here on signals the next wait at once
        }
    }
}
