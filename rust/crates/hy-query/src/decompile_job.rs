//! Port of `hydralysis/decompile_job.py`: a decompile that needs the engine's long path runs as a job.
//!
//! The record store (`backends.read_json` / `write_json`, sealed files), the process start probe and the worker
//! launch are traits, so the job life cycle is testable without a daemon or a child process.

use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc;
use std::time::{Duration, Instant};

pub const ACTIVE: [&str; 2] = ["queued", "running"];
pub const TICK_S: f64 = 5.0;

#[derive(Debug, thiserror::Error)]
pub enum JobError {
    /// Python `ValueError`.
    #[error("{0}")]
    Value(String),
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Json(#[from] serde_json::Error),
    /// A failure of the record store (`durable.StoreCorrupt` and the like).
    #[error("{0}")]
    Store(String),
}

pub trait Store: Send + Sync {
    /// A JSON object record; `{}` when it was never written.
    fn read(&self, path: &Path) -> Result<Map<String, Value>, JobError>;
    fn write(&self, path: &Path, value: &Map<String, Value>) -> Result<(), JobError>;
}

pub trait Processes: Send + Sync {
    /// `preparation.process_start_ms`: 0 when the process is gone.
    fn start_ms(&self, pid: i64) -> i64;
}

/// `job_path`: `<root>/decompile-jobs/<id>/job.json`, the id being `decompile-` and 12 lowercase hex digits.
pub fn job_path(root: &Path, job_id: &str) -> Result<PathBuf, JobError> {
    let valid = job_id
        .strip_prefix("decompile-")
        .is_some_and(|h| h.len() == 12 && h.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
    if !valid {
        return Err(JobError::Value("invalid decompile job id".into()));
    }
    Ok(root.join("decompile-jobs").join(job_id).join("job.json"))
}

/// `_update`: the record with CHANGES applied and `updated_at` stamped.
pub fn update(store: &dyn Store, path: &Path, now: f64, changes: &[(&str, Value)]) -> Result<Map<String, Value>, JobError> {
    let mut record = store.read(path)?;
    for (k, v) in changes {
        record.insert((*k).to_string(), v.clone());
    }
    record.insert("updated_at".into(), json!(now));
    store.write(path, &record)?;
    Ok(record)
}

fn is_active(record: &Map<String, Value>) -> bool {
    record.get("state").and_then(Value::as_str).is_some_and(|s| ACTIVE.contains(&s))
}

fn int_of(v: Option<&Value>) -> i64 {
    match v {
        Some(Value::Number(n)) => n.as_i64().or_else(|| n.as_f64().map(|f| f as i64)).unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().unwrap_or(0),
        _ => 0,
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

/// `status`: the job as the caller sees it; an active job whose worker is gone is marked failed.
pub fn status(store: &dyn Store, procs: &dyn Processes, root: &Path, job_id: &str, now: f64) -> Result<Value, JobError> {
    let path = job_path(root, job_id)?;
    let mut record = store.read(&path)?;
    if record.is_empty() {
        return Err(JobError::Value(format!("no decompile job {job_id}")));
    }
    let created_at = record.get("created_at").and_then(Value::as_f64).unwrap_or(0.0);
    if is_active(&record) && now - created_at > 5.0 {
        let pid = int_of(record.get("worker_pid"));
        let created = int_of(record.get("worker_started_ms"));
        if !(pid > 0 && created > 0 && procs.start_ms(pid) == created) {
            record = update(
                store,
                &path,
                now,
                &[
                    ("state", json!("failed")),
                    ("stage", json!("interrupted")),
                    ("error", json!("the decompile worker exited without a result")),
                ],
            )?;
        }
    }
    let mut out: Map<String, Value> =
        record.iter().filter(|(k, _)| !matches!(k.as_str(), "settings" | "call_key")).map(|(k, v)| (k.clone(), v.clone())).collect();
    if is_active(&record) {
        out.insert("elapsed_s".into(), json!(round1(now - created_at)));
    }
    let state = record.get("state").and_then(Value::as_str);
    let result = PathBuf::from(record.get("result_path").and_then(Value::as_str).unwrap_or(""));
    if state == Some("done") && result.is_file() {
        let text = std::fs::read_to_string(&result)?;
        out.insert("result".into(), serde_json::from_str(&text)?);
    }
    let log = PathBuf::from(record.get("log_path").and_then(Value::as_str).unwrap_or(""));
    if log.is_file() && state != Some("done") {
        let bytes = std::fs::read(&log)?;
        let from = bytes.len().saturating_sub(1000);
        out.insert("log_tail".into(), json!(String::from_utf8_lossy(&bytes[from..])));
    }
    Ok(Value::Object(out))
}

/// The `call_key` of a call: the five fields that make two calls the same decompile.
pub fn call_key(call: &Value) -> Value {
    let mut key = Map::new();
    for name in ["target", "action", "address", "timeout_s", "options"] {
        key.insert(name.into(), call.get(name).cloned().unwrap_or(Value::Null));
    }
    Value::Object(key)
}

/// `start`, first half: the running job of the same call, if there is one (the newest 50 records are looked at,
/// newest first). The returned status carries `reused: true`. `records` are the `job.json` paths of the directory.
pub fn find_running(
    store: &dyn Store,
    procs: &dyn Processes,
    root: &Path,
    records: &[PathBuf],
    key: &Value,
    now: f64,
) -> Result<Option<Value>, JobError> {
    for existing in records.iter().take(50) {
        let previous = store.read(existing)?;
        if previous.get("call_key") == Some(key) && is_active(&previous) {
            let id = previous.get("id").and_then(Value::as_str).unwrap_or_default();
            let current = status(store, procs, root, id, now)?;
            let active = current.get("state").and_then(Value::as_str).is_some_and(|s| ACTIVE.contains(&s));
            if active {
                let mut out = current;
                if let Some(m) = out.as_object_mut() {
                    m.insert("reused".into(), json!(true));
                }
                return Ok(Some(out));
            }
        }
    }
    Ok(None)
}

/// `start`, second half: the record of a new queued job (written by the caller before the worker is launched).
pub fn new_record(
    job_id: &str,
    target: &str,
    call: &Value,
    reason: &str,
    now: f64,
    settings: Value,
    directory: &Path,
) -> Map<String, Value> {
    let mut r = Map::new();
    r.insert("version".into(), json!(1));
    r.insert("id".into(), json!(job_id));
    r.insert("kind".into(), json!("decompile"));
    r.insert("target".into(), json!(target));
    r.insert("call".into(), call.clone());
    r.insert("call_key".into(), call_key(call));
    r.insert("fallback_reason".into(), json!(reason));
    r.insert("created_at".into(), json!(now));
    r.insert("updated_at".into(), json!(now));
    r.insert("state".into(), json!("queued"));
    r.insert("stage".into(), json!("starting"));
    r.insert("settings".into(), settings);
    r.insert("result_path".into(), json!(directory.join("result.json").to_string_lossy()));
    r.insert("log_path".into(), json!(directory.join("worker.log").to_string_lossy()));
    r
}

/// `run`: the worker. QUERY is `QueryRunner(settings).query(**call)` with the runner set inline; it returns the
/// reply text. Returns the process exit code (0 done, 1 failed).
pub fn run(
    store: &dyn Store,
    procs: &dyn Processes,
    path: &Path,
    pid: i64,
    clock: &(dyn Fn() -> f64 + Sync),
    tick: Duration,
    query: &(dyn Fn(&Value) -> Result<String, String> + Sync),
) -> Result<i32, JobError> {
    let record = store.read(path)?;
    let started = Instant::now();
    let guard = Mutex::new(());
    let set = |changes: &[(&str, Value)]| -> Result<(), JobError> {
        let _serial = guard.lock().unwrap_or_else(|p| p.into_inner());
        update(store, path, clock(), changes).map(|_| ())
    };
    set(&[
        ("state", json!("running")),
        ("stage", json!("engine decompile running")),
        ("worker_pid", json!(pid)),
        ("worker_started_ms", json!(procs.start_ms(pid))),
    ])?;
    let (stop, stopped) = mpsc::channel::<()>();
    let elapsed = |s: &Instant| round1(s.elapsed().as_secs_f64());
    std::thread::scope(|scope| {
        let set = &set;
        scope.spawn(move || {
            while let Err(mpsc::RecvTimeoutError::Timeout) = stopped.recv_timeout(tick) {
                let _ = set(&[("stage", json!(format!("engine decompile running ({} s)", started.elapsed().as_secs())))]);
            }
        });
        let outcome = (|| -> Result<(), String> {
            let mut call = record.get("call").cloned().unwrap_or_else(|| json!({}));
            if let Some(m) = call.as_object_mut() {
                let options = m.get("options").filter(|o| o.is_object()).cloned().unwrap_or_else(|| json!({}));
                m.insert("options".into(), options);
            }
            let text = query(&call)?;
            let mut reply: Value = serde_json::from_str(&text).map_err(|e| e.to_string())?;
            let id = record.get("id").cloned().unwrap_or(Value::Null);
            let reason = record.get("fallback_reason").cloned().unwrap_or_else(|| json!(""));
            let object = reply.as_object_mut().ok_or("reply is not an object")?;
            let fallback = object.entry("fallback").or_insert_with(|| json!({"via": "engine_decompile", "reason": reason}));
            fallback.as_object_mut().ok_or("fallback is not an object")?.insert("job".into(), id);
            let result = record.get("result_path").and_then(Value::as_str).unwrap_or("");
            std::fs::write(result, reply.to_string()).map_err(|e| e.to_string())?;
            Ok(())
        })();
        let code = match outcome {
            Ok(()) => {
                let _ = stop.send(());
                set(&[("state", json!("done")), ("stage", json!("done")), ("elapsed_run_s", json!(elapsed(&started)))]).map(|()| 0)
            }
            Err(e) => {
                let _ = stop.send(());
                let message: String = e.chars().take(4000).collect();
                set(&[
                    ("state", json!("failed")),
                    ("stage", json!("failed")),
                    ("error", json!(message)),
                    ("elapsed_run_s", json!(elapsed(&started))),
                ])
                .map(|()| 1)
            }
        };
        drop(stop);
        code
    })
}
