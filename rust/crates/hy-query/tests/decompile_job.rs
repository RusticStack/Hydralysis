//! Ports of `Job` in tests/test_decompile_e2e.py, plus the status/dedupe rules of decompile_job.py.

use hy_query::decompile_job::{JobError, Processes, Store, call_key, find_running, job_path, new_record, run, status};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};
use std::time::Duration;

const NO_PCODE: &str = "No pcode could be generated at 0x143020480";
const ID: &str = "decompile-0123456789ab";

/// Plain JSON files (the sealed store is Python's `durable`).
struct Files;

impl Store for Files {
    fn read(&self, path: &Path) -> Result<Map<String, Value>, JobError> {
        match std::fs::read_to_string(path) {
            Ok(t) => Ok(serde_json::from_str::<Value>(&t)?.as_object().cloned().unwrap_or_default()),
            Err(_) => Ok(Map::new()),
        }
    }
    fn write(&self, path: &Path, value: &Map<String, Value>) -> Result<(), JobError> {
        std::fs::write(path, Value::Object(value.clone()).to_string())?;
        Ok(())
    }
}

struct Procs(i64);
impl Processes for Procs {
    fn start_ms(&self, _pid: i64) -> i64 {
        self.0
    }
}

fn temp(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("hyq-job-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn record(root: &Path) -> PathBuf {
    let path = job_path(root, ID).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let call = json!({"target": "t", "action": "decompile", "address": "0x1", "options": {}});
    let mut r = new_record(ID, "t", &call, NO_PCODE, 1e12, json!({"root": root.to_string_lossy()}), path.parent().unwrap());
    r.insert("call_key".into(), json!({}));
    Files.write(&path, &r).unwrap();
    path
}

#[test]
fn the_worker_runs_the_query_inline_and_stores_the_labelled_result() {
    let root = temp("ok");
    let path = record(&root);
    let seen = std::sync::Mutex::new(None);
    let query = |call: &Value| -> Result<String, String> {
        *seen.lock().unwrap() = Some(call.clone());
        Ok(json!({"ok": true, "c": "x", "fallback": {"via": "engine_decompile", "reason": NO_PCODE}}).to_string())
    };
    let code = run(&Files, &Procs(7), &path, 99, &|| 1e12, Duration::from_secs(60), &query).unwrap();
    assert_eq!(code, 0);
    assert_eq!(seen.lock().unwrap().as_ref().unwrap()["address"], json!("0x1"));
    let done = status(&Files, &Procs(7), &root, ID, 1e12).unwrap();
    assert_eq!(done["state"], json!("done"));
    assert_eq!(done["result"]["fallback"]["job"], json!(ID));
    assert!(done.get("settings").is_none() && done.get("call_key").is_none());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_worker_failure_is_recorded() {
    let root = temp("fail");
    let path = record(&root);
    let query = |_: &Value| -> Result<String, String> { Err(NO_PCODE.into()) };
    let code = run(&Files, &Procs(7), &path, 99, &|| 1e12, Duration::from_secs(60), &query).unwrap();
    assert_eq!(code, 1);
    assert!(Files.read(&path).unwrap()["error"].as_str().unwrap().contains("No pcode"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_reply_without_a_fallback_label_gets_the_default_one() {
    let root = temp("label");
    let path = record(&root);
    let query = |_: &Value| -> Result<String, String> { Ok(r#"{"ok": true}"#.into()) };
    run(&Files, &Procs(7), &path, 99, &|| 1e12, Duration::from_secs(60), &query).unwrap();
    let done = status(&Files, &Procs(7), &root, ID, 1e12).unwrap();
    assert_eq!(done["result"]["fallback"], json!({"via": "engine_decompile", "reason": NO_PCODE, "job": ID}));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn the_tick_updates_the_stage_while_the_query_runs() {
    let root = temp("tick");
    let path = record(&root);
    let query = |_: &Value| -> Result<String, String> {
        std::thread::sleep(Duration::from_millis(300));
        Ok("{}".into())
    };
    run(&Files, &Procs(7), &path, 99, &|| 1e12, Duration::from_millis(50), &query).unwrap();
    // the last stage is "done"; the ticks must not have left the record unreadable
    assert_eq!(Files.read(&path).unwrap()["stage"], json!("done"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn job_ids_are_validated() {
    let root = Path::new("R");
    assert!(job_path(root, ID).is_ok());
    for bad in ["decompile-0123456789AB", "decompile-0123456789a", "decompile-0123456789abc", "x", "../decompile-0123456789ab"] {
        assert_eq!(job_path(root, bad).unwrap_err().to_string(), "invalid decompile job id", "{bad}");
    }
}

#[test]
fn an_unknown_job_is_refused() {
    let root = temp("none");
    assert_eq!(status(&Files, &Procs(1), &root, ID, 0.0).unwrap_err().to_string(), format!("no decompile job {ID}"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn an_active_job_whose_worker_is_gone_is_marked_interrupted() {
    let root = temp("gone");
    let path = record(&root);
    let mut r = Files.read(&path).unwrap();
    r.insert("created_at".into(), json!(100.0));
    r.insert("worker_pid".into(), json!(5));
    r.insert("worker_started_ms".into(), json!(1234));
    Files.write(&path, &r).unwrap();
    // within five seconds of creation nothing is judged
    let young = status(&Files, &Procs(0), &root, ID, 103.0).unwrap();
    assert_eq!(young["state"], json!("queued"));
    assert_eq!(young["elapsed_s"], json!(3.0));
    // the same worker is alive
    assert_eq!(status(&Files, &Procs(1234), &root, ID, 200.0).unwrap()["state"], json!("queued"));
    // a pid reused by another process (other start time) or gone (0)
    let failed = status(&Files, &Procs(999), &root, ID, 200.0).unwrap();
    assert_eq!((failed["state"].clone(), failed["stage"].clone()), (json!("failed"), json!("interrupted")));
    assert_eq!(failed["error"], json!("the decompile worker exited without a result"));
    assert!(failed.get("elapsed_s").is_none());
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_log_tail_is_the_last_thousand_bytes() {
    let root = temp("log");
    let path = record(&root);
    let log = path.parent().unwrap().join("worker.log");
    std::fs::write(&log, format!("{}END", "x".repeat(2000))).unwrap();
    let s = status(&Files, &Procs(0), &root, ID, 1e12 + 1.0).unwrap();
    let tail = s["log_tail"].as_str().unwrap();
    assert_eq!(tail.len(), 1000);
    assert!(tail.ends_with("END"));
    let _ = std::fs::remove_dir_all(root);
}

#[test]
fn a_running_job_of_the_same_call_is_reused() {
    let root = temp("reuse");
    let path = record(&root);
    let call = json!({"target": "t", "action": "decompile", "address": "0x1", "options": {}, "extra": 1});
    let key = call_key(&call);
    assert_eq!(key.as_object().unwrap().len(), 5);
    let mut r = Files.read(&path).unwrap();
    r.insert("call_key".into(), key.clone());
    Files.write(&path, &r).unwrap();
    let found = find_running(&Files, &Procs(0), &root, std::slice::from_ref(&path), &key, 1e12 + 1.0).unwrap().unwrap();
    assert_eq!(found["reused"], json!(true));
    assert_eq!(found["id"], json!(ID));
    let other = call_key(&json!({"target": "t", "action": "decompile", "address": "0x2"}));
    assert!(find_running(&Files, &Procs(0), &root, std::slice::from_ref(&path), &other, 1e12 + 1.0).unwrap().is_none());
    // a finished job is not reused
    r.insert("state".into(), json!("done"));
    Files.write(&path, &r).unwrap();
    assert!(find_running(&Files, &Procs(0), &root, std::slice::from_ref(&path), &key, 1e12 + 1.0).unwrap().is_none());
    let _ = std::fs::remove_dir_all(root);
}
