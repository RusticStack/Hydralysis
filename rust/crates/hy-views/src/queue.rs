//! The publish queue's records and status (`views.py` section "queue"; PROTOCOL-3.md 4.10, D45).
//!
//! Records are sealed JSON, each written once by an atomic replace: `pending/<csid>.json` (a sealed changeset),
//! `done/<csid>.json` (a changeset the log names), `declined/<csid>.json` (a decided changeset that made no generation).
//! The order of the queue is the order of the changeset ids.
//!
//! The Python read memo (`_RECORDS`) is a pure CPU optimisation and is not ported yet; answers are identical.

use std::collections::BTreeSet;
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde_json::{Map, Value, json};

use crate::error::Result;
use crate::layout::{
    Settings, declined_path, dir, done_path, ids_in, lineage_dir, now_iso, pending_path,
    publish_lock_path,
};
use crate::options::FORMAT;
use hy_core::sealed::{self, ReadOptions};

pub const MAX_HISTORY_BYTES: u64 = 20 * 1024 * 1024;
pub const PUBLISH_BATCH_MAX: i64 = 8;
/// An outstanding changeset with no worker and no leader for this long is reported `unled`.
pub const UNLED_GRACE_S: f64 = 10.0;

/// `durable.read_sealed` of a write-once record: the file, else its `.bak`, else `default` (NotFound without one).
fn read_once(path: &Path, default: Option<Value>, max_bytes: Option<u64>) -> Result<Value> {
    let options = ReadOptions {
        max_bytes,
        require_seal: false,
    };
    Ok(sealed::read_sealed_info(path, &options, default)?.0)
}

fn as_map(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(m) => m,
        _ => Map::new(),
    }
}

pub fn read_changeset(
    settings: &Settings,
    lineage_id: &str,
    csid: &str,
) -> Result<Map<String, Value>> {
    let path = pending_path(settings, lineage_id, csid)?;
    let record = as_map(read_once(&path, None, Some(MAX_HISTORY_BYTES + 4096))?);
    let format_too_new = record
        .get("format")
        .and_then(Value::as_i64)
        .is_some_and(|f| f > FORMAT);
    if record.get("csid").and_then(Value::as_str) != Some(csid) || format_too_new {
        return Err(hy_core::Error::store_corrupt(
            &path,
            &path,
            vec![("csid".into(), "mismatch".into())],
        )
        .into());
    }
    Ok(record)
}

/// The result of a decided changeset: `done/` (published) or `declined/` (no generation was made), else `None`.
pub fn read_done(
    settings: &Settings,
    lineage_id: &str,
    csid: &str,
) -> Result<Option<Map<String, Value>>> {
    let found = read_once(
        &done_path(settings, lineage_id, csid)?,
        Some(Value::Null),
        None,
    )?;
    if let Value::Object(m) = found {
        return Ok(Some(m));
    }
    Ok(
        match read_once(
            &declined_path(settings, lineage_id, csid)?,
            Some(Value::Null),
            None,
        )? {
            Value::Object(m) => Some(m),
            _ => None,
        },
    )
}

/// The per-changeset result. Idempotent: an existing result is kept. A changeset that made a generation goes to `done/`
/// after the `CURRENT.log` line; any other result goes to `declined/`.
pub fn write_done(
    settings: &Settings,
    lineage_id: &str,
    csid: &str,
    record: &Map<String, Value>,
) -> Result<Map<String, Value>> {
    if let Some(existing) = read_done(settings, lineage_id, csid)? {
        return Ok(existing);
    }
    let mut body = Map::new();
    body.insert("format".into(), json!(FORMAT));
    body.insert("csid".into(), json!(csid));
    body.insert("lineage".into(), json!(lineage_id));
    body.insert("at".into(), json!(now_iso()));
    body.insert("leader".into(), json!({"pid": std::process::id()}));
    body.extend(record.clone());
    let made_generation = record.get("generation").is_some_and(|g| !g.is_null());
    let path = if made_generation {
        done_path(settings, lineage_id, csid)?
    } else {
        declined_path(settings, lineage_id, csid)?
    };
    sealed::write_sealed(&path, &Value::Object(body.clone()), Some(2), None, None)?;
    Ok(body)
}

/// The ids in `pending/`, `done/` and `declined/` of one lineage, listed once.
pub struct Listing {
    pub pending: Vec<String>,
    pub done: Vec<String>,
    pub declined: Vec<String>,
}

pub fn listing(settings: &Settings, lineage_id: &str) -> Result<Listing> {
    Ok(Listing {
        pending: ids_in(&dir(settings, lineage_id, "pending")?),
        done: ids_in(&dir(settings, lineage_id, "done")?),
        declined: ids_in(&dir(settings, lineage_id, "declined")?),
    })
}

impl Listing {
    /// Sealed and not yet decided, in the order of their ids (the FIFO of D45).
    pub fn outstanding(&self) -> Vec<String> {
        let finished: BTreeSet<&String> = self.done.iter().chain(self.declined.iter()).collect();
        self.pending
            .iter()
            .filter(|c| !finished.contains(c))
            .cloned()
            .collect()
    }
}

pub fn outstanding(settings: &Settings, lineage_id: &str) -> Result<Vec<String>> {
    Ok(listing(settings, lineage_id)?.outstanding())
}

fn median(samples: &mut [f64]) -> f64 {
    samples.sort_by(f64::total_cmp);
    let n = samples.len();
    if n % 2 == 1 {
        samples[n / 2]
    } else {
        (samples[n / 2 - 1] + samples[n / 2]) / 2.0
    }
}

/// Observed, never promised: the median build time of this lineage's last five builds times the changesets ahead.
pub fn eta_ms(settings: &Settings, lineage_id: &str, position: usize) -> Result<Option<i64>> {
    let folder = dir(settings, lineage_id, "done")?;
    let Ok(entries) = std::fs::read_dir(&folder) else {
        return Ok(None);
    };
    let mut found: Vec<(i128, String)> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| {
            let name = e.file_name().into_string().ok()?;
            if !name.ends_with(".json") {
                return None;
            }
            let ns = e
                .metadata()
                .ok()?
                .modified()
                .ok()?
                .duration_since(UNIX_EPOCH)
                .ok()?
                .as_nanos() as i128;
            Some((ns, name))
        })
        .collect();
    found.sort();
    let mut samples: Vec<f64> = Vec::new();
    for (_, name) in found.iter().rev().take(5) {
        if let Ok(Value::Object(record)) = read_once(&folder.join(name), Some(Value::Null), None)
            && let Some(ms) = record.get("build_ms").and_then(Value::as_f64)
        {
            samples.push(ms);
        }
    }
    if samples.is_empty() {
        return Ok(None);
    }
    Ok(Some((median(&mut samples) * position as f64) as i64))
}

pub fn position_of(
    settings: &Settings,
    lineage_id: &str,
    csid: &str,
    queue: Option<&[String]>,
) -> Result<Option<usize>> {
    let owned;
    let queue = match queue {
        Some(q) => q,
        None => {
            owned = outstanding(settings, lineage_id)?;
            &owned
        }
    };
    Ok(queue.iter().position(|c| c == csid).map(|i| i + 1))
}

/// What the publish worker's job record says (`overlayjobs.status` of the newest publish job of a changeset).
pub trait JobLookup {
    fn publish_job_of(&self, settings: &Settings, csid: &str) -> Option<Value>;
}

/// No job lookup (tests, and callers that have no job store).
pub struct NoJobs;
impl JobLookup for NoJobs {
    fn publish_job_of(&self, _: &Settings, _: &str) -> Option<Value> {
        None
    }
}

/// The terminal answer for an outstanding changeset whose worker failed or that no process is driving.
pub fn publish_job_failure(job: Option<&Value>, csid: &str, position: usize) -> Option<Value> {
    let job = job?;
    let state = job.get("state").and_then(Value::as_str)?;
    match state {
        "failed" | "cancelled" | "interrupted" => Some(json!({
            "state": "failed", "csid": csid, "position": position, "job": job.get("id"), "job_state": state,
            "reason": job.get("error").filter(|v| crate::records::truthy(v)).cloned().unwrap_or_else(|| json!("the publish worker ended without a result")),
            "next": "read the records with status show=changes; publish again (the changeset is reused) to rebuild it, or rebase the view if the worker's error names a conflict",
        })),
        "done" => Some(json!({
            "state": "failed", "csid": csid, "position": position, "job": job.get("id"), "job_state": state,
            "reason": "the publish worker finished without writing the changeset's result",
            "next": "publish again (the changeset is reused and its records stay pending)",
        })),
        _ => None,
    }
}

fn leader_held(settings: &Settings, lineage_id: &str) -> Result<bool> {
    Ok(hy_core::lock::held(&publish_lock_path(
        settings, lineage_id,
    )?))
}

/// `publish_pending{position, etaMs}`, or the result when the changeset is decided; `failed`/`unled` when nothing drives it.
pub fn pending_info(
    settings: &Settings,
    lineage_id: &str,
    csid: &str,
    queue: Option<&[String]>,
    jobs: &dyn JobLookup,
) -> Result<Value> {
    let mut result = read_done(settings, lineage_id, csid)?;
    let mut position = if result.is_some() {
        None
    } else {
        position_of(settings, lineage_id, csid, queue)?
    };
    if position.is_none() && result.is_none() {
        // The result may have been written between the two reads.
        result = read_done(settings, lineage_id, csid)?;
        position = None;
    }
    if let Some(result) = result {
        return Ok(
            json!({"state": "done", "outcome": result.get("outcome"), "generation": result.get("generation"), "csid": csid}),
        );
    }
    let Some(position) = position else {
        return Ok(json!({"state": "unknown", "csid": csid}));
    };
    let job = jobs.publish_job_of(settings, csid);
    if let Some(stopped) = publish_job_failure(job.as_ref(), csid, position) {
        return Ok(stopped);
    }
    let active = job
        .as_ref()
        .and_then(|j| j.get("state"))
        .and_then(Value::as_str)
        .is_some_and(|s| matches!(s, "queued" | "running" | "cancelling"));
    if !active {
        let leading = leader_held(settings, lineage_id)?;
        let age = std::fs::metadata(pending_path(settings, lineage_id, csid)?)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.elapsed().ok())
            .map_or(0.0, |d| d.as_secs_f64());
        if !leading && age >= UNLED_GRACE_S {
            return Ok(json!({
                "state": "unled", "csid": csid, "position": position,
                "reason": "no publish worker or leader is driving this changeset",
                "next": "publish again from this view: the same changeset is reused and its records stay pending; the new leader rebuilds it (a generation the dead leader sealed but never appended is moved aside)",
            }));
        }
    }
    let mut out = Map::new();
    out.insert("state".into(), json!("publish_pending"));
    out.insert("csid".into(), json!(csid));
    out.insert("position".into(), json!(position));
    out.insert(
        "etaMs".into(),
        json!(eta_ms(settings, lineage_id, position)?),
    );
    out.insert("leader".into(), json!(leader_held(settings, lineage_id)?));
    if let Some(job) = &job {
        out.insert("job".into(), job.get("id").cloned().unwrap_or(Value::Null));
        out.insert(
            "job_state".into(),
            job.get("state").cloned().unwrap_or(Value::Null),
        );
    }
    Ok(Value::Object(out))
}

/// `status show=queue`: who is waiting, whether a leader runs, the recent results.
pub fn queue_status(
    settings: &Settings,
    lineage_id: &str,
    csid: Option<&str>,
    jobs: &dyn JobLookup,
) -> Result<Value> {
    let listing = listing(settings, lineage_id)?;
    let queue = listing.outstanding();
    let mut rows = Vec::new();
    for (i, name) in queue.iter().take(50).enumerate() {
        let position = i + 1;
        match read_changeset(settings, lineage_id, name) {
            Ok(record) => rows.push(json!({
                "csid": name, "position": position, "view": record.get("view"),
                "records": record.get("records").and_then(Value::as_array).map_or(0, Vec::len),
                "sealed_at": record.get("sealed_at"), "agent": record.get("agent"),
            })),
            Err(_) => rows.push(json!({"csid": name, "position": position, "error": "unreadable"})),
        }
    }
    let done_ids: BTreeSet<&String> = listing.done.iter().collect();
    let mut latest: Vec<&String> = done_ids
        .iter()
        .copied()
        .chain(listing.declined.iter())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    latest.sort();
    latest.reverse();
    latest.truncate(10);
    let mut recent = Vec::new();
    for name in latest {
        // the listing says which folder holds it: `done/` wins when both do, as in read_done
        let mut result = if done_ids.contains(name) {
            as_map(read_once(
                &done_path(settings, lineage_id, name)?,
                Some(Value::Null),
                None,
            )?)
        } else {
            as_map(read_once(
                &declined_path(settings, lineage_id, name)?,
                Some(Value::Null),
                None,
            )?)
        };
        if result.is_empty() {
            result = read_done(settings, lineage_id, name)?.unwrap_or_default();
        }
        let mut row = Map::new();
        for key in ["csid", "outcome", "generation", "build_ms", "at"] {
            row.insert(key.into(), result.get(key).cloned().unwrap_or(Value::Null));
        }
        recent.push(Value::Object(row));
    }
    let leading = leader_held(settings, lineage_id)?;
    let who = if leading {
        std::fs::read_to_string(lineage_dir(settings, lineage_id)?.join("publish.leader.json"))
            .ok()
            .and_then(|t| serde_json::from_str::<Value>(&t).ok())
    } else {
        None
    };
    let mut out = Map::new();
    out.insert("lineage".into(), json!(lineage_id));
    out.insert("queue".into(), json!({"length": queue.len(), "leader": leading, "leader_info": who, "changesets": rows, "batch_max": PUBLISH_BATCH_MAX}));
    out.insert("recent".into(), Value::Array(recent));
    if let Some(csid) = csid {
        out.insert(
            "changeset".into(),
            pending_info(settings, lineage_id, csid, Some(&queue), jobs)?,
        );
    }
    Ok(Value::Object(out))
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

    fn seal(s: &Settings, csid: &str) {
        let body = json!({"format": 1, "csid": csid, "view": "alice", "records": [{"id": "e1"}], "sealed_at": "t", "agent": "a"});
        sealed::write_sealed(
            &pending_path(s, L, csid).unwrap(),
            &body,
            Some(2),
            None,
            None,
        )
        .unwrap();
    }

    #[test]
    fn outstanding_is_fifo_by_id_and_a_decision_removes_it() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path());
        seal(&s, "c-0000000000000bbb");
        seal(&s, "c-0000000000000aaa");
        assert_eq!(
            outstanding(&s, L).unwrap(),
            ["c-0000000000000aaa", "c-0000000000000bbb"]
        );
        assert_eq!(
            position_of(&s, L, "c-0000000000000bbb", None).unwrap(),
            Some(2)
        );
        let rec = json!({"outcome": "applied", "generation": 3, "build_ms": 100})
            .as_object()
            .unwrap()
            .clone();
        let written = write_done(&s, L, "c-0000000000000aaa", &rec).unwrap();
        assert_eq!(written["format"], 1);
        assert_eq!(written["leader"]["pid"], std::process::id());
        // idempotent: the first result is kept
        let again = write_done(
            &s,
            L,
            "c-0000000000000aaa",
            json!({"outcome": "other", "generation": 9})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(again["outcome"], "applied");
        assert!(done_path(&s, L, "c-0000000000000aaa").unwrap().is_file());
        assert_eq!(outstanding(&s, L).unwrap(), ["c-0000000000000bbb"]);
        // a decision with no generation lands in declined/
        write_done(
            &s,
            L,
            "c-0000000000000bbb",
            json!({"outcome": "conflict", "generation": null})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        assert!(
            declined_path(&s, L, "c-0000000000000bbb")
                .unwrap()
                .is_file()
        );
        assert!(outstanding(&s, L).unwrap().is_empty());
        let info = pending_info(&s, L, "c-0000000000000bbb", None, &NoJobs).unwrap();
        assert_eq!(
            info,
            json!({"state": "done", "outcome": "conflict", "generation": null, "csid": "c-0000000000000bbb"})
        );
    }

    #[test]
    fn read_changeset_checks_the_csid_and_pending_info_reports_state() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path());
        seal(&s, "c-0000000000000aaa");
        assert_eq!(
            read_changeset(&s, L, "c-0000000000000aaa").unwrap()["view"],
            "alice"
        );
        std::fs::copy(
            pending_path(&s, L, "c-0000000000000aaa").unwrap(),
            pending_path(&s, L, "c-0000000000000ccc").unwrap(),
        )
        .unwrap();
        let e = read_changeset(&s, L, "c-0000000000000ccc").unwrap_err();
        assert!(e.to_string().contains("csid: mismatch"), "{e}");
        assert_eq!(
            pending_info(&s, L, "c-0000000000000999", None, &NoJobs).unwrap()["state"],
            "unknown"
        );
        let info = pending_info(&s, L, "c-0000000000000aaa", None, &NoJobs).unwrap();
        assert_eq!(info["state"], "publish_pending");
        assert_eq!(info["position"], 1);
        assert_eq!(info["etaMs"], Value::Null);
        assert_eq!(info["leader"], false);
        struct Failed;
        impl JobLookup for Failed {
            fn publish_job_of(&self, _: &Settings, _: &str) -> Option<Value> {
                Some(json!({"id": "overlay-1", "state": "failed", "error": "boom"}))
            }
        }
        let info = pending_info(&s, L, "c-0000000000000aaa", None, &Failed).unwrap();
        assert_eq!(
            (info["state"].as_str(), info["reason"].as_str()),
            (Some("failed"), Some("boom"))
        );
    }

    #[test]
    fn queue_status_lists_rows_and_recent_results() {
        let d = tempfile::tempdir().unwrap();
        let s = settings(d.path());
        seal(&s, "c-0000000000000aaa");
        seal(&s, "c-0000000000000bbb");
        write_done(
            &s,
            L,
            "c-0000000000000aaa",
            json!({"outcome": "applied", "generation": 1, "build_ms": 10})
                .as_object()
                .unwrap(),
        )
        .unwrap();
        let st = queue_status(&s, L, Some("c-0000000000000bbb"), &NoJobs).unwrap();
        assert_eq!(st["queue"]["length"], 1);
        assert_eq!(st["queue"]["batch_max"], 8);
        assert_eq!(st["queue"]["changesets"][0]["records"], 1);
        assert_eq!(st["recent"][0]["csid"], "c-0000000000000aaa");
        assert_eq!(st["recent"][0]["build_ms"], 10);
        assert_eq!(st["changeset"]["etaMs"], 10);
    }
}
