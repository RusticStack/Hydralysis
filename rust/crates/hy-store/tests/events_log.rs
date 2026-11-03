//! Port of the EventChain cases of tests/test_runtime_capture.py (the `runtime_events` module).

mod common;

use common::temp;
use hy_core::appendlog::scan_file;
use hy_store::events::{self, EventLog, LOG_NAME, genesis_hash, iter_records, read_events, record_hash, verify_log};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

const SESSION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

struct Case {
    _temp: tempfile::TempDir,
    dir: PathBuf,
}

fn case() -> Case {
    let t = temp();
    let dir = t.path().join("runtime-sessions").join(SESSION);
    fs::create_dir_all(&dir).unwrap();
    Case { _temp: t, dir }
}

fn messages(log: &EventLog, count: usize, pad: usize) {
    for index in 0..count {
        let mut payload = json!({"event": "enter", "hook_id": "hook", "hit": index + 1});
        if pad > 0 {
            payload["pad"] = json!("x".repeat(pad));
        }
        let message = json!({"type": "send", "payload": payload});
        log.count_message("hook", &message, false);
        log.record("hook", &message);
    }
}

fn logged(c: &Case, count: usize) -> EventLog {
    let log = EventLog::new(&c.dir, SESSION);
    messages(&log, count, 0);
    log.close();
    log
}

fn lines(c: &Case) -> Vec<Vec<u8>> {
    let data = fs::read(c.dir.join(LOG_NAME)).unwrap();
    let mut parts: Vec<Vec<u8>> = data.split(|b| *b == b'\n').map(<[u8]>::to_vec).collect();
    parts.pop();
    parts
}

fn rewrite(c: &Case, lines: &[Vec<u8>]) {
    let mut out = Vec::new();
    for l in lines {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    fs::write(c.dir.join(LOG_NAME), out).unwrap();
}

fn verify(c: &Case) -> Value {
    verify_log(&c.dir, SESSION, None, &BTreeMap::new())
}

fn body(line: &[u8]) -> Value {
    serde_json::from_slice(&line[9..]).unwrap()
}

fn reframe(record: &Value) -> Vec<u8> {
    let mut framed = events::frame(record);
    framed.pop();
    framed
}

#[test]
fn a_clean_log_verifies_and_ends_at_the_loggers_head() {
    let c = case();
    let log = logged(&c, 5);
    let result = verify(&c);
    assert_eq!(result["ok"], true, "{result}");
    assert_eq!(
        (result["records"].clone(), result["last_sequence"].clone(), result["head"].clone()),
        (json!(5), json!(5), json!(log.head_hash()))
    );
    assert_eq!(genesis_hash(SESSION), body(&lines(&c)[0])["prev"].as_str().unwrap());
    assert_ne!(genesis_hash(SESSION), genesis_hash(&"b".repeat(32)));
}

#[test]
fn the_log_is_the_durable_frame_format() {
    let c = case();
    logged(&c, 3);
    let scanned = scan_file(&c.dir.join(LOG_NAME), 0, true).unwrap();
    assert_eq!(scanned.records.iter().map(|r| r["n"].as_i64().unwrap()).collect::<Vec<_>>(), [1, 2, 3]);
    assert!(scanned.corrupt.is_none());
}

#[test]
fn a_flipped_byte_fails_the_crc() {
    let c = case();
    logged(&c, 4);
    let mut data = fs::read(c.dir.join(LOG_NAME)).unwrap();
    let at = lines(&c)[0].len() + 40;
    data[at] ^= 1;
    fs::write(c.dir.join(LOG_NAME), data).unwrap();
    let result = verify(&c);
    assert_eq!(result["ok"], false);
    assert_eq!(result["first_bad"]["after_sequence"], 1);
}

#[test]
fn an_edited_record_with_a_valid_crc_fails_its_hash() {
    let c = case();
    logged(&c, 4);
    let mut all = lines(&c);
    let mut record = body(&all[1]);
    record["message"]["payload"]["hit"] = json!(99);
    all[1] = reframe(&record);
    rewrite(&c, &all);
    let result = verify(&c);
    assert_eq!(result["ok"], false);
    assert_eq!(result["first_bad"]["sequence"], 2);
    assert!(result["first_bad"]["reason"].as_str().unwrap().contains("hash"));
}

#[test]
fn a_removed_record_breaks_the_chain() {
    let c = case();
    logged(&c, 5);
    let mut all = lines(&c);
    all.remove(2);
    rewrite(&c, &all);
    let result = verify(&c);
    assert_eq!(result["ok"], false);
    assert_eq!(result["first_bad"]["sequence"], 4);
    assert!(result["first_bad"]["reason"].as_str().unwrap().contains("missing"));
}

#[test]
fn reordered_records_are_found() {
    let c = case();
    logged(&c, 5);
    let mut all = lines(&c);
    all.swap(1, 2);
    rewrite(&c, &all);
    assert_eq!(verify(&c)["ok"], false);
}

#[test]
fn a_record_rehashed_after_an_edit_still_breaks_the_next_one() {
    let c = case();
    logged(&c, 4);
    let mut all = lines(&c);
    let mut record = body(&all[1]);
    record["message"]["payload"]["hit"] = json!(99);
    record["hash"] = json!(record_hash(&record));
    all[1] = reframe(&record);
    rewrite(&c, &all);
    let result = verify(&c);
    assert_eq!(result["ok"], false);
    assert_eq!(result["first_bad"]["sequence"], 3);
}

#[test]
fn a_torn_tail_is_reported_and_is_not_a_failure() {
    let c = case();
    logged(&c, 4);
    let data = fs::read(c.dir.join(LOG_NAME)).unwrap();
    fs::write(c.dir.join(LOG_NAME), &data[..data.len() - 20]).unwrap();
    let result = verify(&c);
    assert_eq!(result["ok"], true);
    assert_eq!(result["torn_tail"], true);
    assert_eq!(result["records"], 3);
    let seen: Vec<i64> =
        read_events(&c.dir, 0, 10, None)["events"].as_array().unwrap().iter().map(|e| e["sequence"].as_i64().unwrap()).collect();
    assert_eq!(seen, [1, 2, 3]);
}

#[test]
fn a_flipped_byte_in_the_last_record_is_corrupt_not_torn() {
    let c = case();
    logged(&c, 5);
    let mut data = fs::read(c.dir.join(LOG_NAME)).unwrap();
    assert_eq!(data.last(), Some(&b'\n'));
    let at = data.len() - 12;
    data[at] ^= 1; // inside the last, complete, LF-terminated record
    fs::write(c.dir.join(LOG_NAME), data).unwrap();
    let result = verify(&c);
    assert_eq!(result["ok"], false);
    assert!(result.get("torn_tail").is_none());
    assert_eq!(result["first_bad"]["after_sequence"], 4);
    assert_eq!(result["records"], 4);
    assert_eq!(iter_records(&c.dir.join(LOG_NAME)).last().unwrap().unwrap_err(), "corrupt");
    assert_eq!(read_events(&c.dir, 0, 10, None)["log_problem"], "corrupt");
}

#[test]
fn a_last_line_without_its_lf_is_torn_whether_or_not_it_parses() {
    let c = case();
    logged(&c, 3);
    let data = fs::read(c.dir.join(LOG_NAME)).unwrap();
    fs::write(c.dir.join(LOG_NAME), &data[..data.len() - 1]).unwrap(); // a complete record that lost only its LF
    let result = verify(&c);
    assert_eq!(result["ok"], true);
    assert_eq!(result["torn_tail"], true);
    assert_eq!(result["records"], 2);
}

#[test]
fn the_log_for_another_session_does_not_verify() {
    let c = case();
    logged(&c, 3);
    assert_eq!(verify_log(&c.dir, &"b".repeat(32), None, &BTreeMap::new())["ok"], false);
}

#[test]
fn counters_stay_true_when_the_record_is_incomplete() {
    let c = case();
    let log = EventLog::with_options(&c.dir, SESSION, 5, events::RING_BYTES, 3000, true);
    messages(&log, 40, 300);
    let counters = log.counters_copy();
    assert_eq!(counters["messages"], 40);
    assert_eq!(counters["by_event"], json!({"enter": 40}));
    assert_eq!(counters["by_script"]["hook"]["seen"], 40);
    assert_eq!(counters["ring_evicted"], 35);
    assert_eq!(log.dropped(), 35);
    assert_eq!(log.head_info()["full"], true);
    assert!(counters["log_full_dropped"].as_i64().unwrap() > 0);
    assert!(counters["recorded"].as_i64().unwrap() < 40);
    assert_eq!(counters["recorded"].as_i64().unwrap() + counters["log_full_dropped"].as_i64().unwrap(), 41); // the log_full marker is a record
    log.close();
    let result = verify(&c);
    assert_eq!(result["ok"], true, "{result}");
    let kinds: Vec<String> = iter_records(&c.dir.join(LOG_NAME)).map(|r| r.unwrap()["type"].as_str().unwrap().to_string()).collect();
    assert_eq!(kinds.last().unwrap(), "log_full");
}

#[test]
fn a_failed_write_leaves_a_hole_the_chain_reports() {
    let c = case();
    let log = EventLog::new(&c.dir, SESSION);
    messages(&log, 2, 0);
    log.inject_write_failure(Some((28, "no space")));
    messages(&log, 1, 0);
    log.inject_write_failure(None);
    messages(&log, 2, 0);
    log.close();
    assert_eq!(log.counters_copy()["log_failed"], 1);
    assert!(log.head_info()["error"].as_str().unwrap().contains("no space"));
    let result = verify(&c);
    assert_eq!(result["ok"], false);
    assert_eq!(result["first_bad"]["sequence"], 4);
}

#[test]
fn expected_hashes_name_the_records_a_capture_starts_and_stops_at() {
    let c = case();
    let log = EventLog::new(&c.dir, SESSION);
    messages(&log, 2, 0);
    let start = log.marker("capture_start", &json!({"capture": "c1"}));
    messages(&log, 2, 0);
    log.close();
    let mut expect = BTreeMap::new();
    expect.insert(start["n"].as_i64().unwrap(), start["hash"].as_str().unwrap().to_string());
    assert_eq!(verify_log(&c.dir, SESSION, None, &expect)["ok"], true);
    expect.insert(start["n"].as_i64().unwrap(), "0".repeat(64));
    assert_eq!(verify_log(&c.dir, SESSION, None, &expect)["first_bad"]["reason"], "the record is not the one the capture names");
    let mut missing = BTreeMap::new();
    missing.insert(99, "x".to_string());
    assert_eq!(verify_log(&c.dir, SESSION, None, &missing)["first_bad"]["reason"], "the record the capture names is not in the log");
}
