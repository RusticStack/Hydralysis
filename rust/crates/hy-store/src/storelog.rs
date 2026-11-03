//! The overlay store as a sealed snapshot plus a per-view append log (port of `hydralysis.storelog`, H16).
//!
//! Formats are byte-identical to the Python implementation: the snapshot is the v3 store record plus `log_anchor` and
//! `log_prev`; a log row is `{"a": anchor, "n": k, "set": {...}, "lists": {field: {"drop": i, "push": [..]}}}` and the
//! first row after a snapshot also carries `prev`. See the Python module docstring for the recovery and compaction
//! rules, which this port keeps unchanged.

use hy_core::appendlog::{self, AppendLog, frame};
use hy_core::error::{Error, Result};
use hy_core::fault::fault;
use hy_core::fsio::{self, atomic_write_point, file_identity, with_suffix};
use hy_core::lock;
use hy_core::sealed::{self, Kind, backup_path, dumps_sealed, path_key, write_sealed};
use serde_json::{Map, Value, json};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{LazyLock, Mutex};

pub const SNAPSHOT_EVERY: u64 = 64;
pub const SNAPSHOT_LOG_BYTES: usize = 4 * 1024 * 1024;
pub const LIST_FIELDS: [&str; 6] = ["edits", "reverted", "journal", "commits", "archived", "changesets"];
pub const READ_RETRIES: usize = 8;
pub const CACHE_ENTRIES: usize = 32;

static EVERY: AtomicU64 = AtomicU64::new(SNAPSHOT_EVERY);
static LOG_BYTES: AtomicUsize = AtomicUsize::new(SNAPSHOT_LOG_BYTES);
static ENTRIES: AtomicUsize = AtomicUsize::new(CACHE_ENTRIES);

/// Override the compaction thresholds and the cache bound (the Python module's patchable constants, used by tests).
pub fn configure(snapshot_every: u64, snapshot_log_bytes: usize, cache_entries: usize) {
    EVERY.store(snapshot_every, Ordering::Relaxed);
    LOG_BYTES.store(snapshot_log_bytes, Ordering::Relaxed);
    ENTRIES.store(cache_entries, Ordering::Relaxed);
}

/// Number of store paths currently cached by this process.
pub fn cache_len() -> usize {
    CACHE.lock().map_or(0, |cache| cache.entries.len())
}

/// `HYDRALYSIS_STORE_LOG=0` writes whole snapshots again (the reader always honours a log).
pub fn enabled() -> bool {
    std::env::var("HYDRALYSIS_STORE_LOG").map_or(true, |v| v != "0")
}

pub fn log_path(path: &Path) -> PathBuf {
    with_suffix(path, ".log")
}

fn file_name(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

// ------------------------------------------------------------------------------------------------- reading

fn rows(path: &Path) -> Result<Vec<Value>> {
    let target = log_path(path);
    if !target.is_file() {
        return Ok(Vec::new());
    }
    let scan = appendlog::scan_file(&target, 0, true)?;
    if let Some(corrupt) = scan.corrupt {
        return Err(Error::store_corrupt(path, &target, vec![(file_name(&target), format!("log corrupt at byte {}", corrupt.offset))]));
    }
    Ok(scan.records)
}

pub fn apply_row(record: &mut Value, row: &Value) {
    let Some(map) = record.as_object_mut() else { return };
    if let Some(set) = row.get("set").and_then(Value::as_object) {
        for (field, value) in set {
            map.insert(field.clone(), value.clone());
        }
    }
    if let Some(lists) = row.get("lists").and_then(Value::as_object) {
        for (field, change) in lists {
            let current: Vec<Value> = map.get(field).and_then(Value::as_array).cloned().unwrap_or_default();
            let drop = change.get("drop").and_then(Value::as_i64).unwrap_or(0).max(0) as usize;
            let mut next: Vec<Value> = current.into_iter().skip(drop).collect();
            if let Some(push) = change.get("push").and_then(Value::as_array) {
                next.extend(push.iter().cloned());
            }
            map.insert(field.clone(), Value::Array(next));
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct Position {
    pub anchor: Option<String>,
    pub n: u64,
    pub start: Option<String>,
}

/// Apply to RECORD (a snapshot) the rows that follow it.
pub fn chain(record: &mut Value, rows: &[Value]) -> Position {
    let Some(anchor) = record.get("log_anchor").and_then(Value::as_str).map(str::to_string) else {
        return Position { anchor: None, n: 0, start: None };
    };
    let (start, mut current, mut n) = (anchor.clone(), anchor, 0u64);
    for row in rows {
        let Some(object) = row.as_object() else { continue };
        let row_anchor = object.get("a").and_then(Value::as_str);
        let row_n = object.get("n").and_then(Value::as_u64);
        if row_anchor == Some(current.as_str()) && row_n == Some(n + 1) {
            apply_row(record, row);
            n += 1;
        } else if row_anchor != Some(current.as_str())
            && row_n == Some(1)
            && object.get("prev").and_then(Value::as_str) == Some(current.as_str())
            && n > 0
        {
            // The rows of the next snapshot: it holds exactly this state, so its rows continue the chain.
            current = object.get("a").and_then(Value::as_str).unwrap_or_default().to_string();
            apply_row(record, row);
            n = 1;
        }
    }
    Position { anchor: Some(current), n, start: Some(start) }
}

/// The store at PATH: RECORD (its snapshot, as the caller read it) with the log applied. `reread` reads the snapshot
/// again; it is used to retry when the snapshot file was replaced while the log was read.
pub fn read(path: &Path, record: Option<Value>, reread: Option<&dyn Fn() -> Result<Option<Value>>>) -> Result<Option<Value>> {
    read_with(path, record, reread, &|p| file_identity(p))
}

/// [`read`] with the snapshot-identity probe injectable (tests feign a snapshot replaced while the log was read).
pub fn read_with(
    path: &Path,
    record: Option<Value>,
    reread: Option<&dyn Fn() -> Result<Option<Value>>>,
    identity: &dyn Fn(&Path) -> Option<fsio::FileIdentity>,
) -> Result<Option<Value>> {
    let mut record = record;
    let mut before = identity(path);
    let mut log_rows = Vec::new();
    for attempt in 0..=READ_RETRIES {
        if attempt > 0 {
            before = identity(path);
            record = match reread {
                Some(f) => f()?,
                None => record,
            };
        }
        let anchored = record.as_ref().is_some_and(|r| r.get("log_anchor").is_some_and(Value::is_string));
        if !anchored {
            return Ok(record);
        }
        log_rows = rows(path)?;
        if reread.is_none() || identity(path) == before {
            break;
        }
    }
    if let Some(r) = record.as_mut() {
        chain(r, &log_rows);
    }
    Ok(record)
}

// ------------------------------------------------------------------------------------------------- writing

type Signature = (Option<(i128, u64)>, Option<(i128, u64)>);

#[derive(Clone)]
struct Cached {
    signature: Signature,
    record: Value,
    anchor: Option<String>,
    n: u64,
    prev: Option<String>,
    key: String,
    size: u64,
    since: usize,
}

struct Cache {
    seq: u64,
    entries: HashMap<String, (u64, Cached)>,
}

static CACHE: LazyLock<Mutex<Cache>> = LazyLock::new(|| Mutex::new(Cache { seq: 0, entries: HashMap::new() }));
/// The last compaction failure per store path (an I/O error after the mutation was durable): reported, never raised.
pub static UPKEEP_ERRORS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn stat(path: &Path) -> Option<(i128, u64)> {
    file_identity(path).map(|(_, mtime, size)| (mtime, size))
}

fn signature(path: &Path) -> Signature {
    (stat(path), stat(&log_path(path)))
}

fn cached(key: &str) -> Option<Cached> {
    CACHE.lock().ok()?.entries.get(key).map(|(_, c)| c.clone())
}

fn remember(key: &str, entry: Cached) {
    if let Ok(mut cache) = CACHE.lock() {
        cache.seq += 1;
        let seq = cache.seq;
        cache.entries.insert(key.to_string(), (seq, entry));
        while cache.entries.len() > ENTRIES.load(Ordering::Relaxed) {
            if let Some(oldest) = cache.entries.iter().min_by_key(|(_, (s, _))| *s).map(|(k, _)| k.clone()) {
                cache.entries.remove(&oldest);
            }
        }
    }
}

fn forget(key: &str) {
    if let Ok(mut cache) = CACHE.lock() {
        cache.entries.remove(key);
    }
}

/// Drop every cached store (tests and callers that changed the files behind this process).
pub fn clear_cache() {
    if let Ok(mut cache) = CACHE.lock() {
        cache.entries.clear();
    }
}

/// The clean `edits` of the store on disk as this process last wrote or read them, when the files are unchanged since.
pub fn known_edits(path: &Path) -> Option<Value> {
    // Under the lock, only the edits are copied: copying the whole entry (the store as a tree) to read one field is waste.
    let sig = signature(path);
    let cache = CACHE.lock().ok()?;
    let (_, found) = cache.entries.get(&path_key(path))?;
    if found.signature != sig {
        return None;
    }
    found.record.get("edits").filter(|e| e.is_array()).cloned()
}

fn current(path: &Path) -> Result<Option<Cached>> {
    let key = path_key(path);
    let sig = signature(path);
    if let Some(found) = cached(&key)
        && found.signature == sig
    {
        return Ok(Some(found));
    }
    let Ok((kind, snapshot, _)) = sealed::inspect_file(path, None, false) else { return Ok(None) };
    let Some(mut snapshot) = snapshot.filter(|_| kind == Kind::Sealed) else { return Ok(None) };
    if !snapshot.get("log_anchor").is_some_and(Value::is_string) || snapshot.get("version") != Some(&json!(3)) {
        return Ok(None); // no snapshot, a .bak-only read, an old format: the next write is a snapshot
    }
    let prev = snapshot.get("log_prev").and_then(Value::as_str).map(str::to_string);
    let log_rows = rows(path)?;
    let position = chain(&mut snapshot, &log_rows);
    // The log bytes of the current anchor's rows: the size trigger counts what was appended since the last snapshot.
    let since: usize = log_rows
        .iter()
        .filter(|row| row.is_object() && row.get("a").and_then(Value::as_str) == position.anchor.as_deref())
        .map(|row| frame(row).len())
        .sum();
    let found = Cached {
        signature: sig,
        record: snapshot,
        anchor: position.anchor,
        n: position.n,
        prev,
        key: key.clone(),
        size: std::fs::metadata(path)?.len(),
        since,
    };
    remember(&key, found.clone());
    Ok(Some(found))
}

fn list_change(old: &[Value], new: &[Value]) -> Option<(usize, Vec<Value>)> {
    if new.is_empty() {
        return None;
    }
    if new.len() >= old.len() && new[..old.len()] == *old {
        return Some((0, new[old.len()..].to_vec()));
    }
    for drop in 1..=old.len() {
        let kept = old.len() - drop;
        if kept <= new.len() && old[drop..] == new[..kept] {
            return Some((drop, new[kept..].to_vec()));
        }
    }
    None
}

/// The row body that turns OLD into NEW: whole fields in `set`, list fields as drop/push when they only shifted.
pub fn diff(old: &Value, new: &Value) -> Map<String, Value> {
    let mut row = Map::new();
    let (empty, old_map, new_map) = (Map::new(), old.as_object(), new.as_object());
    let (old_map, new_map) = (old_map.unwrap_or(&empty), new_map.unwrap_or(&empty));
    let mut sets = Map::new();
    let mut lists = Map::new();
    for (field, after) in new_map {
        if field == "log_anchor" || field == "log_prev" {
            continue;
        }
        let before = old_map.get(field);
        if let Some(before) = before
            && before == after
        {
            continue;
        }
        if LIST_FIELDS.contains(&field.as_str())
            && let (Some(Value::Array(b)), Value::Array(a)) = (before, after)
            && let Some((drop, push)) = list_change(b, a)
        {
            if drop > 0 || !push.is_empty() {
                lists.insert(field.clone(), json!({"drop": drop, "push": push}));
            }
            continue;
        }
        sets.insert(field.clone(), after.clone());
    }
    for field in old_map.keys() {
        if !new_map.contains_key(field) && field != "log_anchor" && field != "log_prev" {
            sets.insert(field.clone(), Value::Null);
        }
    }
    // Python builds `lists` and `set` lazily in the order they first occur; the row keys are written set-then-lists
    // only when both exist in that first-occurrence order, so reproduce it: recompute order from the field walk.
    let first_set = new_map.iter().position(|(f, _)| sets.contains_key(f));
    let first_list = new_map.iter().position(|(f, _)| lists.contains_key(f));
    let set_first = match (first_set, first_list) {
        (Some(s), Some(l)) => s < l,
        (None, Some(_)) => false,
        _ => true,
    };
    let (mut sets_opt, mut lists_opt) = ((!sets.is_empty()).then_some(sets), (!lists.is_empty()).then_some(lists));
    if set_first {
        if let Some(s) = sets_opt.take() {
            row.insert("set".into(), Value::Object(s));
        }
        if let Some(l) = lists_opt.take() {
            row.insert("lists".into(), Value::Object(l));
        }
    } else {
        if let Some(l) = lists_opt.take() {
            row.insert("lists".into(), Value::Object(l));
        }
        if let Some(s) = sets_opt.take() {
            row.insert("set".into(), Value::Object(s));
        }
    }
    row
}

fn is_os(error: &Error) -> bool {
    matches!(error, Error::Io(_))
}

/// Python `ValueError` and its subclasses (`LockBusy`, `StoreCorrupt`, `LineageCorrupt`, JSON decode errors).
fn is_value(error: &Error) -> bool {
    matches!(error, Error::Value(_) | Error::LockBusy { .. } | Error::StoreCorrupt { .. } | Error::LineageCorrupt { .. } | Error::Json(_))
}

fn upkeep_failed(path: &Path, what: &str, error: &Error) {
    if let Ok(mut map) = UPKEEP_ERRORS.lock() {
        map.insert(path_key(path), format!("{what}: {error}"));
        while map.len() > ENTRIES.load(Ordering::Relaxed) {
            let Some(first) = map.keys().next().cloned() else { break };
            map.remove(&first);
        }
    }
}

fn snapshot(path: &Path, record: &Value, prev: Option<&str>, max_bytes: Option<usize>, too_large: Option<&str>) -> Result<()> {
    let anchor = uuid::Uuid::new_v4().simple().to_string();
    let mut body = record.clone();
    if let Some(map) = body.as_object_mut() {
        map.insert("log_anchor".into(), Value::String(anchor.clone()));
        if let Some(prev) = prev.filter(|p| !p.is_empty()) {
            map.insert("log_prev".into(), Value::String(prev.to_string()));
        }
    }
    let payload = write_sealed(path, &body, Some(2), max_bytes, too_large)?;
    // From here the snapshot is durable: what follows is upkeep, and a failure of it must not be reported as a failed write.
    let key = path_key(path);
    let upkeep = (|| -> Result<()> {
        if prev.is_none() && !backup_path(path).is_file() {
            // The first snapshot is also the `.bak`: a damaged main file then still reads as the newest state.
            fsio::atomic_write_point(&backup_path(path), &payload, "backup", true)?;
        }
        fault("store.after_snapshot")?;
        trim(path, prev)
    })();
    if let Err(error) = upkeep {
        if is_os(&error) {
            upkeep_failed(path, "snapshot upkeep", &error);
            forget(&key);
            return Ok(());
        }
        return Err(error);
    }
    remember(
        &key,
        Cached {
            signature: signature(path),
            record: body,
            anchor: Some(anchor),
            n: 0,
            prev: prev.map(str::to_string),
            key: key.clone(),
            size: std::fs::metadata(path)?.len(),
            since: 0,
        },
    );
    Ok(())
}

/// Drop the log rows older than the `.bak` snapshot's (anchor KEEP_FROM); they can no longer be reached.
fn trim(path: &Path, keep_from: Option<&str>) -> Result<()> {
    let target = log_path(path);
    if !target.is_file() {
        return Ok(());
    }
    let log = AppendLog::new(&target);
    let _guard = lock::lock(&log.lock_path, log.lock_timeout_s, &format!("log {}", file_name(&target)))?;
    let scan = appendlog::scan_file(&target, 0, true)?;
    if scan.corrupt.is_some() {
        return Ok(()); // leave it for review; readers report it
    }
    let raw = {
        use std::io::Read;
        let mut buffer = Vec::new();
        std::fs::File::open(&target)?.take(scan.valid_end).read_to_end(&mut buffer)?;
        buffer
    };
    let mut data = Vec::new();
    let mut keeping = false;
    for (line, row) in raw.split_inclusive(|&b| b == b'\n').zip(scan.records.iter()) {
        if let Some(keep) = keep_from
            && row.is_object()
            && row.get("a").and_then(Value::as_str) == Some(keep)
        {
            keeping = true;
        }
        if keeping {
            data.extend_from_slice(line);
        }
    }
    if data == raw && scan.size == scan.valid_end {
        return Ok(());
    }
    atomic_write_point(&target, &data, "store.trim", true)?;
    log.remember(data.len() as u64);
    Ok(())
}

/// The whole-store writer's budget, measured exactly, before anything is written.
fn fits(record: &Value, max_bytes: Option<usize>, too_large: Option<&str>) -> Result<()> {
    if let Some(limit) = max_bytes {
        let mut probe = record.clone();
        if let Some(map) = probe.as_object_mut() {
            map.insert("log_anchor".into(), Value::String("0".repeat(32)));
            map.insert("log_prev".into(), Value::String("0".repeat(32)));
        }
        if dumps_sealed(&probe, Some(2))?.len() > limit {
            return Err(Error::value(
                too_large.map_or_else(|| format!("record would exceed {limit} bytes; existing file preserved"), str::to_string),
            ));
        }
    }
    Ok(())
}

/// Write RECORD (the complete v3 store) as one log row, or as a snapshot when there is none to append to or the log is
/// due for compaction. Durable (fsynced) before it returns.
pub fn save(path: &Path, record: &Value, max_bytes: Option<usize>, too_large: Option<&str>) -> Result<()> {
    if !enabled() {
        write_sealed(path, record, Some(2), max_bytes, too_large)?;
        return Ok(());
    }
    let Some(mut current) = current(path)? else {
        return snapshot(path, record, None, max_bytes, too_large);
    };
    let body = diff(&current.record, record);
    if body.is_empty() {
        return Ok(()); // nothing changed: the store on disk already is RECORD
    }
    let after = current.n + 1;
    let mut row = Map::new();
    row.insert("a".into(), current.anchor.clone().map_or(Value::Null, Value::String));
    row.insert("n".into(), json!(after));
    for (k, v) in body {
        row.insert(k, v);
    }
    if current.n == 0
        && let Some(prev) = current.prev.as_ref().filter(|p| !p.is_empty())
    {
        row.insert("prev".into(), Value::String(prev.clone()));
    }
    let row = Value::Object(row);
    let line_len = frame(&row).len();
    let due = after >= EVERY.load(Ordering::Relaxed) || current.since + line_len > LOG_BYTES.load(Ordering::Relaxed);
    // Budget: an upper estimate decides when to measure exactly, so a store that would pass the whole-store writer's limit
    // is refused here too, before the row is appended.
    let estimate = current.size + 4 * line_len as u64;
    if let Some(limit) = max_bytes
        && (due || estimate > (limit / 2) as u64)
    {
        fits(record, max_bytes, too_large)?;
    }
    AppendLog::new(log_path(path)).append(&row, false)?;
    fault("store.after_append")?;
    apply_row(&mut current.record, &row);
    let (key, anchor) = (current.key.clone(), current.anchor.clone());
    let since = current.since + line_len;
    remember(&key, Cached { n: after, size: estimate, signature: signature(path), since, ..current });
    if due {
        // The mutation is durable (the row above): compaction is best effort from here.
        if let Err(error) = snapshot(path, record, anchor.as_deref(), max_bytes, too_large) {
            if is_os(&error) || is_value(&error) {
                upkeep_failed(path, "compaction", &error);
                forget(&key);
            } else {
                return Err(error);
            }
        }
    }
    Ok(())
}
