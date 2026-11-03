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
use std::borrow::Cow;
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

pub fn apply_row(record: &mut Value, row: &Value) {
    apply_row_owned(record, row.clone());
}

/// [`apply_row`] for a row the caller gives up: its values are moved into the record, not copied.
pub fn apply_row_owned(record: &mut Value, row: Value) {
    let (Some(map), Value::Object(mut row)) = (record.as_object_mut(), row) else { return };
    if let Some(Value::Object(set)) = row.remove("set") {
        for (field, value) in set {
            map.insert(field, value);
        }
    }
    if let Some(Value::Object(lists)) = row.remove("lists") {
        for (field, change) in lists {
            let drop = change.get("drop").and_then(Value::as_i64).unwrap_or(0).max(0) as usize;
            let entry = map.entry(field).or_insert_with(|| Value::Array(Vec::new()));
            if !entry.is_array() {
                *entry = Value::Array(Vec::new());
            }
            // Edited in place: a list of thousands of records is not copied to drop a head and push a tail.
            let Value::Array(items) = entry else { continue };
            items.drain(..drop.min(items.len()));
            if let Value::Object(mut change) = change
                && let Some(Value::Array(push)) = change.remove("push")
            {
                items.extend(push);
            }
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
    chain_rows(record, rows.iter().map(Cow::Borrowed))
}

/// [`chain`] for rows the caller gives up: each is moved into the record and freed as it is applied, so a log of a few
/// large rows is not held twice (as rows and as the record they were copied into).
pub fn chain_owned(record: &mut Value, rows: Vec<Value>) -> Position {
    chain_rows(record, rows.into_iter().map(Cow::Owned))
}

fn chain_rows<'a>(record: &mut Value, rows: impl Iterator<Item = Cow<'a, Value>>) -> Position {
    let Some(mut chainer) = Chainer::of(record) else { return Position { anchor: None, n: 0, start: None } };
    for row in rows {
        chainer.feed(record, row.into_owned());
    }
    chainer.position()
}

/// The rows that follow a snapshot, applied one at a time as they arrive.
struct Chainer {
    start: String,
    current: String,
    n: u64,
}

impl Chainer {
    /// `None` when RECORD carries no anchor (no row can follow it).
    fn of(record: &Value) -> Option<Self> {
        let anchor = record.get("log_anchor").and_then(Value::as_str)?.to_string();
        Some(Chainer { start: anchor.clone(), current: anchor, n: 0 })
    }

    fn feed(&mut self, record: &mut Value, row: Value) {
        let Some(object) = row.as_object() else { return };
        let row_anchor = object.get("a").and_then(Value::as_str);
        let row_n = object.get("n").and_then(Value::as_u64);
        if row_anchor == Some(self.current.as_str()) && row_n == Some(self.n + 1) {
            self.n += 1;
        } else if row_anchor != Some(self.current.as_str())
            && row_n == Some(1)
            && object.get("prev").and_then(Value::as_str) == Some(self.current.as_str())
            && self.n > 0
        {
            // The rows of the next snapshot: it holds exactly this state, so its rows continue the chain.
            self.current = object.get("a").and_then(Value::as_str).unwrap_or_default().to_string();
            self.n = 1;
        } else {
            return;
        }
        apply_row_owned(record, row);
    }

    fn position(&self) -> Position {
        Position { anchor: Some(self.current.clone()), n: self.n, start: Some(self.start.clone()) }
    }
}

/// Read the log of PATH and apply its rows to RECORD (a snapshot) as they are read: one row is in memory at a time, not
/// the whole log twice. Returns where the chain ends and, per row, the anchor it names and its framed size. RECORD is
/// meaningless after an error.
/// The anchor a log row names and the size of its frame.
type RowSize = (Option<String>, usize);

fn apply_log(path: &Path, record: &mut Value) -> Result<(Position, Vec<RowSize>)> {
    let target = log_path(path);
    let mut chainer = Chainer::of(record);
    let mut sizes = Vec::new();
    if target.is_file() {
        let scan = appendlog::scan_file_each(&target, &mut |row| {
            if row.is_object() {
                sizes.push((row.get("a").and_then(Value::as_str).map(str::to_string), frame(&row).len()));
            }
            if let Some(chainer) = chainer.as_mut() {
                chainer.feed(record, row);
            }
        })?;
        if let Some(corrupt) = scan.corrupt {
            return Err(Error::store_corrupt(path, &target, vec![(file_name(&target), format!("log corrupt at byte {}", corrupt.offset))]));
        }
    }
    let position = chainer.map_or(Position { anchor: None, n: 0, start: None }, |c| c.position());
    Ok((position, sizes))
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
    for attempt in 0..=READ_RETRIES {
        if attempt > 0 {
            before = identity(path);
            record = match reread {
                Some(f) => f()?,
                None => record,
            };
        }
        let anchored = record.as_ref().is_some_and(|r| r.get("log_anchor").is_some_and(Value::is_string));
        let Some(snapshot) = record.as_mut().filter(|_| anchored) else { return Ok(record) };
        // The rows are applied as they are read; a snapshot replaced meanwhile is read again, so the half-applied one
        // is dropped (`reread` is what makes the identity differ).
        apply_log(path, snapshot)?;
        if reread.is_none() || identity(path) == before {
            break;
        }
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

/// The cached entry for KEY when its files are still SIGNATURE, taken out of the cache (not copied: the store is a tree of
/// thousands of records); the caller puts it back with [`remember`].
fn take_cached(key: &str, signature: &Signature) -> Option<Cached> {
    let mut cache = CACHE.lock().ok()?;
    if cache.entries.get(key)?.1.signature != *signature {
        return None;
    }
    cache.entries.remove(key).map(|(_, found)| found)
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

/// For each of ITEMS, whether it equals the clean record at its position in the store on disk as this process last wrote or
/// read it (all `false` when the files changed since or nothing is known). Nothing is copied out of the cache.
pub fn known_edits_equal(path: &Path, items: &[Value]) -> Vec<bool> {
    let sig = signature(path);
    let Ok(cache) = CACHE.lock() else { return vec![false; items.len()] };
    let known = cache
        .entries
        .get(&path_key(path))
        .filter(|(_, found)| found.signature == sig)
        .and_then(|(_, found)| found.record.get("edits"))
        .and_then(Value::as_array);
    match known {
        Some(known) => items.iter().enumerate().map(|(i, item)| known.get(i).is_some_and(|k| k == item)).collect(),
        None => vec![false; items.len()],
    }
}

fn current(path: &Path) -> Result<Option<Cached>> {
    let key = path_key(path);
    let sig = signature(path);
    if let Some(found) = take_cached(&key, &sig) {
        return Ok(Some(found));
    }
    let Ok((kind, snapshot, _)) = sealed::inspect_file(path, None, false) else { return Ok(None) };
    let Some(mut snapshot) = snapshot.filter(|_| kind == Kind::Sealed) else { return Ok(None) };
    if !snapshot.get("log_anchor").is_some_and(Value::is_string) || snapshot.get("version") != Some(&json!(3)) {
        return Ok(None); // no snapshot, a .bak-only read, an old format: the next write is a snapshot
    }
    let prev = snapshot.get("log_prev").and_then(Value::as_str).map(str::to_string);
    let (position, since) = {
        let (position, sizes) = apply_log(path, &mut snapshot)?;
        // The log bytes of the current anchor's rows: the size trigger counts what was appended since the last snapshot.
        let since = sizes.iter().filter(|(anchor, _)| *anchor == position.anchor).map(|(_, size)| size).sum();
        (position, since)
    };
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
    Ok(Some(found))
}

/// How NEW follows from OLD as a list: drop DROP from the head, then push `new[kept..]`; `None` when it does not.
fn list_shift(old: &[Value], new: &[Value]) -> Option<(usize, usize)> {
    if new.is_empty() {
        return None;
    }
    if new.len() >= old.len() && new[..old.len()] == *old {
        return Some((0, old.len()));
    }
    for drop in 1..=old.len() {
        let kept = old.len() - drop;
        if kept <= new.len() && old[drop..] == new[..kept] {
            return Some((drop, kept));
        }
    }
    None
}

/// The row body that turns OLD into NEW: whole fields in `set`, list fields as drop/push when they only shifted.
pub fn diff(old: &Value, new: &Value) -> Map<String, Value> {
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
            && let Some((drop, kept)) = list_shift(b, a)
        {
            if drop > 0 || kept < a.len() {
                lists.insert(field.clone(), json!({"drop": drop, "push": a[kept..].to_vec()}));
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
    let first_set = new_map.iter().position(|(f, _)| sets.contains_key(f));
    let first_list = new_map.iter().position(|(f, _)| lists.contains_key(f));
    build_row(sets, lists, first_set, first_list)
}

/// [`diff`] for a NEW the caller gives up: the values the row carries are moved out of it, not copied (NEW is left
/// emptied where they were). The row is the same as `diff(old, &new)` gives, byte for byte.
pub fn diff_owned(old: &Value, new: Value) -> Map<String, Value> {
    let empty = Map::new();
    let old_map = old.as_object().unwrap_or(&empty);
    let Value::Object(new_map) = new else { return diff(old, &new) };
    let mut sets = Map::new();
    let mut lists = Map::new();
    let (mut first_set, mut first_list) = (None, None);
    let new_keys: Vec<String> = new_map.keys().cloned().collect();
    for (position, (field, mut after)) in new_map.into_iter().enumerate() {
        if field == "log_anchor" || field == "log_prev" {
            continue;
        }
        let before = old_map.get(&field);
        if before == Some(&after) {
            continue;
        }
        if LIST_FIELDS.contains(&field.as_str())
            && let (Some(Value::Array(b)), Value::Array(a)) = (before, &mut after)
            && let Some((drop, kept)) = list_shift(b, a)
        {
            if drop > 0 || kept < a.len() {
                let push = a.split_off(kept);
                lists.insert(field, json!({"drop": drop, "push": push}));
                first_list.get_or_insert(position);
            }
            continue;
        }
        sets.insert(field, after);
        first_set.get_or_insert(position);
    }
    for field in old_map.keys() {
        if !new_keys.contains(field) && field != "log_anchor" && field != "log_prev" {
            sets.insert(field.clone(), Value::Null);
        }
    }
    build_row(sets, lists, first_set, first_list)
}

/// Python builds `lists` and `set` lazily in the order they first occur; the row keys are written set-then-lists only
/// when both exist in that first-occurrence order, so reproduce it from the positions of the first of each.
fn build_row(
    sets: Map<String, Value>,
    lists: Map<String, Value>,
    first_set: Option<usize>,
    first_list: Option<usize>,
) -> Map<String, Value> {
    let mut row = Map::new();
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
    snapshot_owned(path, record.clone(), prev, max_bytes, too_large)
}

/// [`snapshot`] of a RECORD the caller gives up: it becomes the cached store, not a copy of it.
fn snapshot_owned(path: &Path, record: Value, prev: Option<&str>, max_bytes: Option<usize>, too_large: Option<&str>) -> Result<()> {
    let anchor = uuid::Uuid::new_v4().simple().to_string();
    let mut body = record;
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
    if let Some(limit) = max_bytes
        && sealed_len(record)? > limit
    {
        return Err(Error::value(
            too_large.map_or_else(|| format!("record would exceed {limit} bytes; existing file preserved"), str::to_string),
        ));
    }
    Ok(())
}

/// Bytes of the sealed snapshot of RECORD once it carries `log_anchor` and `log_prev` (32 characters each).
///
/// The record is written as it is and the two entries are counted, not inserted: inserting them would copy a store of
/// thousands of records only to measure it. A record that already has either key, or none, is measured on a copy.
fn sealed_len(record: &Value) -> Result<usize> {
    const ENTRY: usize = ",
  "
    .len()
        + ": ".len()
        + 34; // plus the quoted key
    match record.as_object() {
        Some(map) if !map.is_empty() && !map.contains_key("log_anchor") && !map.contains_key("log_prev") => {
            let keys = ["log_anchor", "log_prev"].map(|key| key.len() + 2);
            Ok(dumps_sealed(record, Some(2))?.len() + keys.iter().map(|key| ENTRY + key).sum::<usize>())
        }
        _ => {
            let mut probe = record.clone();
            if let Some(map) = probe.as_object_mut() {
                map.insert("log_anchor".into(), Value::String("0".repeat(32)));
                map.insert("log_prev".into(), Value::String("0".repeat(32)));
            }
            Ok(dumps_sealed(&probe, Some(2))?.len())
        }
    }
}

/// Write RECORD (the complete v3 store) as one log row, or as a snapshot when there is none to append to or the log is
/// due for compaction. Durable (fsynced) before it returns.
pub fn save(path: &Path, record: &Value, max_bytes: Option<usize>, too_large: Option<&str>) -> Result<()> {
    write(path, Input::Borrowed(record), max_bytes, too_large)
}

/// [`save`] for a RECORD the caller gives up: the values a row carries are moved out of it and the store the process
/// keeps is built from them, so a store of thousands of records is never held in three copies at once.
pub fn save_owned(path: &Path, record: Value, max_bytes: Option<usize>, too_large: Option<&str>) -> Result<()> {
    write(path, Input::Owned(record), max_bytes, too_large)
}

enum Input<'a> {
    Borrowed(&'a Value),
    Owned(Value),
}

/// Whether OLD has a field (other than the log anchors) that NEW has not: the row then sets it to null, and the store the
/// process keeps would differ from NEW, so such a save cannot be built from NEW's moved values.
fn drops_a_field(old: &Value, new: &Value) -> bool {
    let (Some(old), Some(new)) = (old.as_object(), new.as_object()) else { return true };
    old.keys().any(|field| field != "log_anchor" && field != "log_prev" && !new.contains_key(field))
}

fn write(path: &Path, input: Input<'_>, max_bytes: Option<usize>, too_large: Option<&str>) -> Result<()> {
    if !enabled() {
        let record = match &input {
            Input::Borrowed(record) => record,
            Input::Owned(record) => record,
        };
        write_sealed(path, record, Some(2), max_bytes, too_large)?;
        return Ok(());
    }
    let Some(mut current) = current(path)? else {
        return match input {
            Input::Borrowed(record) => snapshot(path, record, None, max_bytes, too_large),
            Input::Owned(record) => snapshot_owned(path, record, None, max_bytes, too_large),
        };
    };
    // With an owned record the row takes its values (`moved`); the store the process keeps, the old one with the row
    // applied, is then the record, and that is what the budget and a compaction read.
    let held: Value;
    let (body, moved, given): (Map<String, Value>, bool, Option<&Value>) = match input {
        Input::Owned(record) if !drops_a_field(&current.record, &record) => (diff_owned(&current.record, record), true, None),
        Input::Owned(record) => {
            held = record;
            (diff(&current.record, &held), false, Some(&held))
        }
        Input::Borrowed(record) => (diff(&current.record, record), false, Some(record)),
    };
    if body.is_empty() {
        remember(&current.key.clone(), current);
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
    let line = frame(&row);
    let line_len = line.len();
    let due = after >= EVERY.load(Ordering::Relaxed) || current.since + line_len > LOG_BYTES.load(Ordering::Relaxed);
    let mut pending = Some(row);
    if moved && let Some(row) = pending.take() {
        apply_row_owned(&mut current.record, row);
    }
    // Budget: an upper estimate decides when to measure exactly, so a store that would pass the whole-store writer's limit
    // is refused here too, before the row is appended.
    let estimate = current.size + 4 * line_len as u64;
    if let Some(limit) = max_bytes
        && (due || estimate > (limit / 2) as u64)
    {
        fits(given.unwrap_or(&current.record), max_bytes, too_large)?;
    }
    AppendLog::new(log_path(path)).append_framed(&line, false)?;
    fault("store.after_append")?;
    if let Some(row) = pending {
        apply_row_owned(&mut current.record, row);
    }
    let (key, anchor) = (current.key.clone(), current.anchor.clone());
    let since = current.since + line_len;
    // The mutation is durable (the row above): compaction is best effort from here.
    let compaction = |result: Result<()>| -> Result<()> {
        match result {
            Err(error) if is_os(&error) || is_value(&error) => {
                upkeep_failed(path, "compaction", &error);
                forget(&key);
                Ok(())
            }
            other => other,
        }
    };
    if due && moved {
        // Nothing but the store itself is left to write: it is handed to the snapshot, which keeps it as the cached one.
        let record = std::mem::take(&mut current.record);
        return compaction(snapshot_owned(path, record, anchor.as_deref(), max_bytes, too_large));
    }
    remember(&key, Cached { n: after, size: estimate, signature: signature(path), since, ..current });
    if due && let Some(record) = given {
        compaction(snapshot(path, record, anchor.as_deref(), max_bytes, too_large))?;
    }
    Ok(())
}
