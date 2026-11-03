//! A runtime session's event record: a bounded ring for `status`, and a durable append-only log with a hash chain
//! (port of `hydralysis.runtime_events`).
//!
//! The log is CRC-framed JSON lines (the `AppendLog` format); each record carries the hash of the one before it,
//! so a removed, reordered or edited record is found by [`verify_log`]. The worker is the only writer; a record is
//! handed to the OS when appended and synced every [`SYNC_EVERY`] records and at capture markers.

use crate::config::py_str;
use hy_core::json::{self, FRAME, Layout, Options};
use hy_core::sealed::sha256_hex;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub const RING_EVENTS: usize = 1000;
pub const RING_BYTES: usize = 262_144;
pub const LOG_MAX_BYTES: u64 = 64 * 1024 * 1024;
/// Markers (capture start/stop, log_full) are still written past the limit.
pub const LOG_MARKER_SLACK: u64 = 1024 * 1024;
pub const SYNC_EVERY: u64 = 64;
pub const LOG_NAME: &str = "events.log";
pub const GENESIS: &str = "hydralysis-runtime-events/1\n";
pub const MAX_SCRIPT_COUNTERS: usize = 256;

pub fn genesis_hash(session: &str) -> String {
    sha256_hex(format!("{GENESIS}{session}").as_bytes())
}

/// The JSON value with non-finite numbers as strings. A `serde_json::Value` cannot hold NaN or Infinity (the
/// binding converts them to strings with Python's `repr` on the way in), so this is the identity here.
pub fn finite(value: &Value) -> Value {
    value.clone()
}

/// The chain hash of one record: SHA-256 of its canonical JSON (sorted, ASCII) without the `hash` field.
pub fn record_hash(record: &Value) -> String {
    let body: Map<String, Value> = record
        .as_object()
        .map(|m| m.iter().filter(|(k, _)| *k != "hash").map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    sha256_hex(&json::dumps(&Value::Object(body), Options { layout: Layout::Compact, sort_keys: true, ensure_ascii: true }))
}

/// `crc-hex8 SP json LF` (insertion-ordered keys, ASCII).
pub fn frame(record: &Value) -> Vec<u8> {
    hy_core::appendlog::frame(record)
}

/// The record of one framed line (without LF), or None when the CRC or the JSON is bad.
pub fn parse(line: &[u8]) -> Option<Map<String, Value>> {
    if line.len() < 10 || line[8] != b' ' {
        return None;
    }
    let head = std::str::from_utf8(&line[..8]).ok()?;
    if !head.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let crc = u32::from_str_radix(head, 16).ok()?;
    let body = &line[9..];
    if crc32fast::hash(body) != crc || !body.is_ascii() {
        return None;
    }
    match json::loads(body).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// One step of [`iter_records`]: `Ok(record)` or the error that ends the walk (`"torn"` or `"corrupt"`).
pub type Step = std::result::Result<Map<String, Value>, &'static str>;

/// The log's lines: a valid record per line, ending after the first bad one.
///
/// A last line without its LF is a torn tail (`"torn"`). A line that has its LF but fails its CRC or is not a
/// record is `"corrupt"`, wherever it sits, the last line included.
pub fn iter_records(path: &Path) -> impl Iterator<Item = Step> {
    let mut reader = File::open(path).ok().map(BufReader::new);
    let mut done = false;
    std::iter::from_fn(move || {
        if done {
            return None;
        }
        let reader = reader.as_mut()?;
        let mut line = Vec::new();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => {
                done = true;
                None
            }
            Ok(_) => {
                if line.last() != Some(&b'\n') {
                    done = true;
                    return Some(Err("torn"));
                }
                line.pop();
                match parse(&line) {
                    Some(record) => Some(Ok(record)),
                    None => {
                        done = true;
                        Some(Err("corrupt"))
                    }
                }
            }
        }
    })
}

/// Events (not markers) with sequence > `after`, at most `limit`, up to sequence `upto`, from the durable log.
pub fn read_events(directory: &Path, after: i64, limit: usize, upto: Option<i64>) -> Value {
    let (mut events, mut next_after, mut truncated, mut problem) = (Vec::new(), after, false, None);
    for step in iter_records(&directory.join(LOG_NAME)) {
        let record = match step {
            Ok(record) => record,
            Err(error) => {
                problem = Some(error);
                break;
            }
        };
        let n = record.get("n").and_then(Value::as_i64).unwrap_or(0);
        if n <= after {
            continue;
        }
        if upto.is_some_and(|u| n > u) {
            break;
        }
        if events.len() >= limit {
            truncated = true;
            break;
        }
        next_after = n;
        if record.get("type").and_then(Value::as_str) == Some("event") {
            events.push(json!({"sequence": n, "script": record.get("script").cloned().unwrap_or(Value::Null),
                               "t_ms": record.get("t").cloned().unwrap_or(Value::Null), "message": record.get("message").cloned().unwrap_or(Value::Null)}));
        }
    }
    let mut out = Map::new();
    out.insert("events".into(), Value::Array(events));
    out.insert("next_after".into(), json!(next_after));
    out.insert("truncated".into(), json!(truncated));
    if let Some(p) = problem {
        out.insert("log_problem".into(), json!(p));
    }
    Value::Object(out)
}

/// Walk the whole log from its genesis. `ok` is false at the first record that breaks the chain or the numbering.
///
/// A torn tail is reported but is not a failure. `expect` maps a sequence number to the hash its record must have.
pub fn verify_log(directory: &Path, session: &str, upto: Option<i64>, expect: &BTreeMap<i64, String>) -> Value {
    let mut previous = genesis_hash(session);
    let (mut count, mut last_n) = (0u64, 0i64);
    let mut pending = expect.clone();
    let mut result = Map::new();
    result.insert("ok".into(), json!(true));
    result.insert("records".into(), json!(0));
    result.insert("head".into(), json!(previous));
    result.insert("last_sequence".into(), json!(0));
    let bad = |result: &Map<String, Value>, first_bad: Value| {
        let mut out = result.clone();
        out.insert("ok".into(), json!(false));
        out.insert("first_bad".into(), first_bad);
        Value::Object(out)
    };
    for step in iter_records(&directory.join(LOG_NAME)) {
        let record = match step {
            Err("torn") => {
                result.insert("torn_tail".into(), json!(true));
                break;
            }
            Err(_) => {
                return bad(&result, json!({"after_sequence": last_n, "reason": "a line fails its CRC or is not a record"}));
            }
            Ok(record) => record,
        };
        let n = record.get("n").and_then(Value::as_i64);
        if let (Some(u), Some(n)) = (upto, n)
            && n > u
        {
            break;
        }
        let n_value = record.get("n").cloned().unwrap_or(Value::Null);
        let Some(n) = n.filter(|n| *n > last_n) else {
            return bad(&result, json!({"sequence": n_value, "reason": "sequence does not increase"}));
        };
        if record.get("prev").and_then(Value::as_str) != Some(previous.as_str()) {
            let mut reason = "prev does not match the record before it".to_string();
            if n != last_n + 1 {
                reason.push_str(" (a record is missing or a write failed here)");
            }
            return bad(&result, json!({"sequence": n, "reason": reason}));
        }
        let hash = record.get("hash").and_then(Value::as_str).unwrap_or("").to_string();
        if record.get("hash").and_then(Value::as_str) != Some(record_hash(&Value::Object(record.clone())).as_str()) {
            return bad(&result, json!({"sequence": n, "reason": "hash does not match the record's content"}));
        }
        if let Some(wanted) = pending.remove(&n)
            && wanted != hash
        {
            return bad(&result, json!({"sequence": n, "reason": "the record is not the one the capture names"}));
        }
        previous = hash.clone();
        count += 1;
        last_n = n;
        result.insert("records".into(), json!(count));
        result.insert("head".into(), json!(hash));
        result.insert("last_sequence".into(), json!(last_n));
    }
    if let Some(first) = pending.keys().next() {
        return bad(&result, json!({"sequence": first, "reason": "the record the capture names is not in the log"}));
    }
    Value::Object(result)
}

fn now_ms() -> i64 {
    (crate::config::unix_now() * 1000.0) as i64
}

fn inc(map: &mut Map<String, Value>, key: &str) {
    let next = map.get(key).and_then(Value::as_i64).unwrap_or(0) + 1;
    map.insert(key.to_string(), json!(next));
}

fn io_error_name(error: &std::io::Error) -> &'static str {
    match error.kind() {
        std::io::ErrorKind::NotFound => "FileNotFoundError",
        std::io::ErrorKind::PermissionDenied => "PermissionError",
        _ => "OSError",
    }
}

struct State {
    ring: VecDeque<(Value, usize)>,
    ring_size: usize,
    sequence: i64,
    dropped: u64,
    head: String,
    records: u64,
    log_bytes: u64,
    full: bool,
    error: String,
    file: Option<File>,
    unsynced: u64,
    counters: Map<String, Value>,
}

/// The ring, the counters and the durable chain of one session. Thread-safe.
pub struct EventLog {
    pub directory: PathBuf,
    pub session: String,
    pub path: PathBuf,
    ring_events: usize,
    ring_bytes: usize,
    log_max_bytes: u64,
    durable_log: bool,
    writer: Mutex<Option<LineWriter>>,
    state: Mutex<State>,
}

impl EventLog {
    pub fn new(directory: impl Into<PathBuf>, session: &str) -> Self {
        Self::with_options(directory, session, RING_EVENTS, RING_BYTES, LOG_MAX_BYTES, true)
    }

    pub fn with_options(
        directory: impl Into<PathBuf>,
        session: &str,
        ring_events: usize,
        ring_bytes: usize,
        log_max_bytes: u64,
        durable_log: bool,
    ) -> Self {
        let directory = directory.into();
        let counters = json!({"messages": 0, "by_type": {}, "by_event": {}, "by_script": {}, "ring_evicted": 0, "clipped": 0, "recorded": 0,
                              "log_failed": 0, "log_full_dropped": 0});
        EventLog {
            path: directory.join(LOG_NAME),
            directory,
            session: session.to_string(),
            ring_events,
            ring_bytes,
            log_max_bytes,
            durable_log,
            writer: Mutex::new(None),
            state: Mutex::new(State {
                ring: VecDeque::new(),
                ring_size: 0,
                sequence: 0,
                dropped: 0,
                head: genesis_hash(session),
                records: 0,
                log_bytes: 0,
                full: false,
                error: String::new(),
                file: None,
                unsynced: 0,
                counters: counters.as_object().cloned().unwrap_or_default(),
            }),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// Count a message the caller has just clipped (or not) and is about to record.
    pub fn count_message(&self, script: &str, message: &Value, clipped: bool) {
        let mut state = self.lock();
        let counters = &mut state.counters;
        let bump = |counters: &mut Map<String, Value>, key: &str| inc(counters, key);
        bump(counters, "messages");
        let kind = message.get("type").filter(|v| crate::config::py_truthy(v)).map(py_str).unwrap_or_default();
        let by_type = counters.entry("by_type").or_insert_with(|| json!({}));
        if let Some(map) = by_type.as_object_mut() {
            inc(map, &kind);
        }
        let event = message
            .get("payload")
            .and_then(Value::as_object)
            .and_then(|p| p.get("event"))
            .filter(|v| crate::config::py_truthy(v))
            .map(py_str)
            .unwrap_or_default();
        if !event.is_empty()
            && let Some(map) = counters.get_mut("by_event").and_then(Value::as_object_mut)
        {
            inc(map, &event);
        }
        if let Some(scripts) = counters.get_mut("by_script").and_then(Value::as_object_mut) {
            if !scripts.contains_key(script) && scripts.len() < MAX_SCRIPT_COUNTERS {
                scripts.insert(script.to_string(), json!({"seen": 0, "events": {}}));
            }
            if let Some(row) = scripts.get_mut(script).and_then(Value::as_object_mut) {
                inc(row, "seen");
                if !event.is_empty()
                    && let Some(events) = row.get_mut("events").and_then(Value::as_object_mut)
                {
                    inc(events, &event);
                }
            }
        }
        if clipped {
            inc(counters, "clipped");
        }
    }

    fn open(&self, state: &mut State) -> std::io::Result<()> {
        if state.file.is_none() {
            std::fs::create_dir_all(&self.directory)?;
            let mut file = OpenOptions::new().append(true).create(true).open(&self.path)?;
            state.log_bytes = file.seek(SeekFrom::End(0))?;
            state.file = Some(file);
        }
        Ok(())
    }

    /// Chain and write one record. False when it was not recorded (log full or a failed write).
    fn append(&self, state: &mut State, record: &mut Map<String, Value>, marker: bool) -> bool {
        record.insert("prev".into(), json!(state.head));
        let hash = record_hash(&Value::Object(record.clone()));
        record.insert("hash".into(), json!(hash));
        let line = frame(&Value::Object(record.clone()));
        if !self.durable_log {
            state.head = hash;
            return false;
        }
        let limit = self.log_max_bytes + if marker { LOG_MARKER_SLACK } else { 0 };
        if state.log_bytes + line.len() as u64 > limit && !marker {
            if !state.full {
                state.full = true;
                self.marker_locked(state, "log_full", &json!({"limit_bytes": self.log_max_bytes}));
            }
            inc_counter(state, "log_full_dropped");
            return false;
        }
        let substitute = self.writer.lock().ok().and_then(|slot| slot.clone());
        let written = match self.open(state) {
            Err(error) => Err(format!("{}: {error}", io_error_name(&error))),
            Ok(()) => match (&substitute, state.file.as_mut()) {
                (Some(write), _) => write(&line),
                (None, Some(file)) => file.write_all(&line).map_err(|error| format!("{}: {error}", io_error_name(&error))),
                (None, None) => Ok(()),
            },
        };
        if let Err(message) = written {
            inc_counter(state, "log_failed");
            state.error = message;
            // The logical stream goes on; the file has a hole here and verify_log says so.
            state.head = hash;
            return false;
        }
        state.head = hash;
        state.log_bytes += line.len() as u64;
        state.records += 1;
        inc_counter(state, "recorded");
        state.unsynced += 1;
        if state.unsynced >= SYNC_EVERY {
            sync_locked(state);
        }
        true
    }

    /// A record that is not a script event: it takes a sequence number and is written even when the log is full.
    fn marker_locked(&self, state: &mut State, kind: &str, body: &Value) -> Value {
        state.sequence += 1;
        let mut record = Map::new();
        record.insert("n".into(), json!(state.sequence));
        record.insert("t".into(), json!(now_ms()));
        record.insert("type".into(), json!(kind));
        if let Some(extra) = body.as_object() {
            for (k, v) in extra {
                record.insert(k.clone(), v.clone());
            }
        }
        self.append(state, &mut record, true);
        Value::Object(record)
    }

    pub fn sync(&self) {
        sync_locked(&mut self.lock());
    }

    pub fn close(&self) {
        let mut state = self.lock();
        sync_locked(&mut state);
        state.file = None;
    }

    /// Give a (counted, clipped) message its sequence number; ring it and append it to the log.
    pub fn record(&self, script: &str, message: &Value) -> Value {
        let message = finite(message);
        let mut state = self.lock();
        state.sequence += 1;
        let sequence = state.sequence;
        let event = json!({"sequence": sequence, "script": script, "message": message});
        let size = json::dumps(&event, Options { layout: Layout::Spaced, sort_keys: false, ensure_ascii: false }).len();
        state.ring.push_back((event.clone(), size));
        state.ring_size += size;
        while state.ring_size > self.ring_bytes || state.ring.len() > self.ring_events {
            let Some((_, old)) = state.ring.pop_front() else { break };
            state.ring_size -= old;
            state.dropped += 1;
            inc_counter(&mut state, "ring_evicted");
        }
        let mut record = Map::new();
        record.insert("n".into(), json!(sequence));
        record.insert("t".into(), json!(now_ms()));
        record.insert("type".into(), json!("event"));
        record.insert("script".into(), json!(script));
        record.insert("message".into(), message);
        self.append(&mut state, &mut record, false);
        event
    }

    pub fn marker(&self, kind: &str, body: &Value) -> Value {
        let mut state = self.lock();
        let record = self.marker_locked(&mut state, kind, body);
        sync_locked(&mut state);
        record
    }

    pub fn head_info(&self) -> Value {
        let state = self.lock();
        let mut out = Map::new();
        out.insert("records".into(), json!(state.records));
        out.insert("head".into(), json!(state.head));
        out.insert("last_sequence".into(), json!(state.sequence));
        out.insert("bytes".into(), json!(state.log_bytes));
        out.insert("full".into(), json!(state.full));
        if !state.error.is_empty() {
            out.insert("error".into(), json!(state.error));
        }
        Value::Object(out)
    }

    pub fn counters_copy(&self) -> Value {
        Value::Object(self.lock().counters.clone())
    }

    /// The events still in the ring, oldest first.
    pub fn ring(&self) -> Vec<Value> {
        self.lock().ring.iter().map(|(e, _)| e.clone()).collect()
    }

    pub fn sequence(&self) -> i64 {
        self.lock().sequence
    }

    pub fn dropped(&self) -> u64 {
        self.lock().dropped
    }

    pub fn head_hash(&self) -> String {
        self.lock().head.clone()
    }
}

fn inc_counter(state: &mut State, key: &str) {
    inc(&mut state.counters, key);
}

fn sync_locked(state: &mut State) {
    if state.unsynced > 0
        && let Some(file) = state.file.as_ref()
    {
        match file.sync_all() {
            Ok(()) => state.unsynced = 0,
            Err(error) => state.error = format!("{}: {error}", io_error_name(&error)),
        }
    }
}

/// What writes one framed record in place of the log file's handle; `Err` carries the text for `error` (`Name: message`).
pub type LineWriter = std::sync::Arc<dyn Fn(&[u8]) -> Result<(), String> + Send + Sync>;

/// `FRAME` re-export check helper for tests: the exact bytes `_frame` produces.
pub fn frame_bytes(record: &Value) -> Vec<u8> {
    let body = json::dumps(record, FRAME);
    let mut out = format!("{:08x} ", crc32fast::hash(&body)).into_bytes();
    out.extend_from_slice(&body);
    out.push(b'\n');
    out
}

impl EventLog {
    /// Seam for a caller that replaces how a record reaches the file (the Python tests patch `os.write`): while a writer is
    /// set it is used instead of the file handle, and its `Err` is counted as a failed log write like an I/O error.
    pub fn set_writer(&self, writer: Option<LineWriter>) {
        if let Ok(mut slot) = self.writer.lock() {
            *slot = writer;
        }
    }
}
