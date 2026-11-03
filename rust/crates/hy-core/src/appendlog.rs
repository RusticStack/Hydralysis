//! CRC-framed JSON-line append logs (`durable.AppendLog`).
//!
//! A line is `crc-hex8 SP json LF` with the CRC-32 (IEEE) of the JSON bytes. Readers never write and ignore a torn
//! final fragment; writers check the tail on every acquisition of the writer lock and repair a torn tail under that
//! lock before appending; an invalid line followed by a valid one is corruption (`lineage_corrupt`) and is refused.

use crate::error::{Error, Result};
use crate::fault::{die, fault};
use crate::fsio::{atomic_write_point, create_parent, fsync_directory, with_suffix};
use crate::json::{self, FRAME};
use crate::lock;
use crate::sealed::{LOCK_TIMEOUT_S, path_key, sha256_hex};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{LazyLock, Mutex};

pub const CHUNK: usize = 1 << 20;
pub const TAIL_WINDOW: u64 = 64 * 1024;
pub const TAIL_WINDOW_MAX: u64 = 8 * 1024 * 1024;

/// key -> end of the last line this process knows to be valid. An entry only lets a writer skip a scan.
static VERIFIED: LazyLock<Mutex<HashMap<String, u64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

static SCANS: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// How many log scans (`scan_file`) this process has made; tests use it to prove a check scanned nothing.
pub fn scan_count() -> u64 {
    SCANS.load(std::sync::atomic::Ordering::Relaxed)
}

/// The memo for KEY (`os.path.normcase(os.path.abspath(log))`), the mapping surface of `durable._VERIFIED`.
pub fn verified_get(key: &str) -> Option<u64> {
    VERIFIED.lock().ok()?.get(key).copied()
}

/// Set the memo for KEY.
pub fn verified_set(key: &str, valid_end: u64) {
    if let Ok(mut map) = VERIFIED.lock() {
        map.insert(key.to_string(), valid_end);
    }
}

/// Remove and return the memo for KEY.
pub fn verified_pop(key: &str) -> Option<u64> {
    VERIFIED.lock().ok()?.remove(key)
}

/// Forget every "verified up to" memo (tests that rewrite logs behind this process; `durable._VERIFIED.clear()`).
pub fn clear_verified() {
    if let Ok(mut map) = VERIFIED.lock() {
        map.clear();
    }
}

/// `crc-hex8 SP json LF` for a record.
pub fn frame(record: &Value) -> Vec<u8> {
    let body = json::dumps(record, FRAME);
    let mut out = Vec::with_capacity(body.len() + 10);
    out.extend_from_slice(format!("{:08x} ", crc32fast::hash(&body)).as_bytes());
    out.extend_from_slice(&body);
    out.push(b'\n');
    out
}

fn hex_nibble(byte: u8) -> Option<u32> {
    match byte {
        b'0'..=b'9' => Some(u32::from(byte - b'0')),
        b'a'..=b'f' => Some(u32::from(byte - b'a') + 10),
        _ => None,
    }
}

/// The frame check without the JSON decode (twin of `hydralysis_native.frame_lines`).
pub fn frame_ok(line: &[u8]) -> bool {
    if line.len() < 10 || line[8] != b' ' {
        return false;
    }
    let mut want = 0u32;
    for &byte in &line[..8] {
        match hex_nibble(byte) {
            Some(v) => want = (want << 4) | v,
            None => return false,
        }
    }
    crc32fast::hash(&line[9..]) == want
}

/// `Some(record)` when LINE (without LF) is a valid framed record.
pub fn parse_line(line: &[u8]) -> Option<Value> {
    if !frame_ok(line) {
        return None;
    }
    json::loads(&line[9..]).ok()
}

/// Every complete line of DATA as `(start, end, crc_ok)`, END the offset of its LF.
pub fn frame_lines(data: &[u8]) -> Vec<(usize, usize, bool)> {
    let mut out = Vec::new();
    let mut cursor = 0;
    while let Some(found) = data[cursor..].iter().position(|&b| b == b'\n') {
        let end = cursor + found;
        out.push((cursor, end, frame_ok(&data[cursor..end])));
        cursor = end + 1;
    }
    out
}

#[derive(Debug, Clone, PartialEq)]
pub struct Torn {
    pub offset: u64,
    pub bytes: u64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Corrupt {
    pub offset: u64,
    pub line: u64,
}

/// What a reader sees: the valid prefix, a torn tail (ignored) or mid-log corruption.
#[derive(Debug, Clone, Default)]
pub struct Scan {
    pub records: Vec<Value>,
    pub valid_end: u64,
    pub size: u64,
    pub torn_tail: Option<Torn>,
    pub corrupt: Option<Corrupt>,
}

impl Scan {
    pub fn as_status(&self) -> Value {
        json!({
            "records": self.records.len(), "valid_bytes": self.valid_end, "size": self.size,
            "torn_tail": self.torn_tail.as_ref().map(|t| json!({"offset": t.offset, "bytes": t.bytes})),
            "corrupt": self.corrupt.as_ref().map(|c| json!({"offset": c.offset, "line": c.line, "error": "lineage_corrupt"})),
        })
    }
}

/// Scan consecutive chunks starting at byte `base` (a line start). `size` overrides the reported total.
pub fn scan_chunks<I: IntoIterator<Item = Vec<u8>>>(chunks: I, base: u64, collect: bool, size: Option<u64>) -> Scan {
    let mut records = Vec::new();
    let mut scan = scan_chunks_with(chunks, base, size, &mut |record| {
        if collect {
            records.push(record);
        }
    });
    scan.records = records;
    scan
}

/// [`scan_chunks`] handing each valid record to SINK as it is read instead of collecting them (`records` stays empty), so
/// a reader that applies the records one by one holds one of them at a time. A record is handed over before a later
/// corrupt line is found: a caller that sees `corrupt` in the answer must discard what it built.
pub fn scan_chunks_with<I: IntoIterator<Item = Vec<u8>>>(chunks: I, base: u64, size: Option<u64>, sink: &mut dyn FnMut(Value)) -> Scan {
    let records = Vec::new();
    let mut pending: Vec<u8> = Vec::new();
    let (mut pending_start, mut seen) = (base, base);
    let (mut bad_from, mut bad_line, mut line_no): (Option<u64>, u64, u64) = (None, 0, 0);
    for chunk in chunks {
        seen += chunk.len() as u64;
        pending.extend_from_slice(&chunk);
        let mut cursor = 0;
        for (start, end, framed) in frame_lines(&pending) {
            line_no += 1;
            let parsed = if framed { json::loads(&pending[start + 9..end]).ok() } else { None };
            match parsed {
                None => {
                    if bad_from.is_none() {
                        bad_from = Some(pending_start + start as u64);
                        bad_line = line_no;
                    }
                }
                Some(record) => {
                    if let Some(offset) = bad_from {
                        return Scan {
                            records,
                            valid_end: offset,
                            size: size.unwrap_or(seen),
                            torn_tail: None,
                            corrupt: Some(Corrupt { offset, line: bad_line }),
                        };
                    }
                    sink(record);
                }
            }
            cursor = end + 1;
        }
        pending_start += cursor as u64;
        pending.drain(..cursor);
    }
    let total = size.unwrap_or(seen);
    if !pending.is_empty() && bad_from.is_none() {
        // An unterminated fragment is never valid, even if its CRC happens to match.
        bad_from = Some(pending_start);
    }
    match bad_from {
        None => Scan { records, valid_end: total, size: total, torn_tail: None, corrupt: None },
        Some(offset) => {
            Scan { records, valid_end: offset, size: total, torn_tail: Some(Torn { offset, bytes: total - offset }), corrupt: None }
        }
    }
}

pub fn scan_bytes(data: &[u8]) -> Scan {
    scan_chunks([data.to_vec()], 0, true, None)
}

/// Chunks of a file from `start` to `stop`. A seek or read failure, or a file that ends before `stop`, ends the stream
/// and is left in `error`: the caller must not take a short stream for a complete log.
struct FileChunks {
    handle: File,
    remaining: u64,
    error: Option<std::io::Error>,
}

impl FileChunks {
    fn new(mut handle: File, start: u64, stop: u64) -> Self {
        let error = handle.seek(SeekFrom::Start(start)).err();
        FileChunks { handle, remaining: stop.saturating_sub(start), error }
    }
}

impl Iterator for FileChunks {
    type Item = Vec<u8>;

    fn next(&mut self) -> Option<Vec<u8>> {
        if self.error.is_some() || self.remaining == 0 {
            return None;
        }
        let mut buffer = vec![0u8; self.remaining.min(CHUNK as u64) as usize];
        loop {
            match self.handle.read(&mut buffer) {
                Ok(0) => {
                    self.error = Some(std::io::Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        format!("log ended {} bytes before the size it had when opened", self.remaining),
                    ));
                    return None;
                }
                Ok(n) => {
                    buffer.truncate(n);
                    self.remaining -= n as u64;
                    return Some(buffer);
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => {
                    self.error = Some(e);
                    return None;
                }
            }
        }
    }
}

/// Scan a log by streaming from byte `start` (a line start) to its size at the moment it was opened.
///
/// # Errors
/// Any I/O failure other than the file not existing (sharing violation, permission, a read error part-way through):
/// an unreadable log is never reported as an empty or shorter valid one. A missing file is an empty scan.
pub fn scan_file(path: &Path, start: u64, collect: bool) -> std::io::Result<Scan> {
    SCANS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let handle = match File::open(path) {
        Ok(handle) => handle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Scan::default()),
        Err(e) => return Err(e),
    };
    let stop = handle.metadata()?.len();
    let start = if start > stop { 0 } else { start };
    let mut chunks = FileChunks::new(handle, start, stop);
    let scan = scan_chunks(chunks.by_ref(), start, collect, Some(stop));
    match chunks.error {
        Some(e) => Err(e),
        None => Ok(scan),
    }
}

/// [`scan_file`] handing each valid record to SINK (see [`scan_chunks_with`]); a missing file is an empty scan.
pub fn scan_file_each(path: &Path, sink: &mut dyn FnMut(Value)) -> std::io::Result<Scan> {
    SCANS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let handle = match File::open(path) {
        Ok(handle) => handle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Scan::default()),
        Err(e) => return Err(e),
    };
    let stop = handle.metadata()?.len();
    let mut chunks = FileChunks::new(handle, 0, stop);
    let scan = scan_chunks_with(chunks.by_ref(), 0, Some(stop), sink);
    match chunks.error {
        Some(e) => Err(e),
        None => Ok(scan),
    }
}

/// Every LF-terminated line of a file (a missing file yields nothing).
fn complete_lines(path: &Path) -> Vec<Vec<u8>> {
    let Ok(data) = std::fs::read(path) else { return Vec::new() };
    let mut lines: Vec<Vec<u8>> = data.split(|&b| b == b'\n').map(<[u8]>::to_vec).collect();
    lines.pop();
    lines
}

enum Tail {
    Found(Option<Value>),
    Unbounded,
}

/// Last valid line, reading from the end in growing windows; it trusts the tail.
fn tail_last_valid(path: &Path) -> std::io::Result<Tail> {
    let mut handle = match File::open(path) {
        Ok(handle) => handle,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Tail::Found(None)),
        Err(e) => return Err(e),
    };
    let size = handle.metadata()?.len();
    let mut window = TAIL_WINDOW;
    loop {
        let start = size.saturating_sub(window);
        let mut data = vec![0u8; (size - start) as usize];
        handle.seek(SeekFrom::Start(start))?;
        handle.read_exact(&mut data)?;
        let slice: &[u8] = if start > 0 {
            match data.iter().position(|&b| b == b'\n') {
                None => &[],
                Some(cut) => &data[cut + 1..],
            }
        } else {
            &data
        };
        let mut lines: Vec<&[u8]> = slice.split(|&b| b == b'\n').collect();
        lines.pop();
        for line in lines.into_iter().rev() {
            if let Some(record) = parse_line(line) {
                return Ok(Tail::Found(Some(record)));
            }
        }
        if start == 0 {
            return Ok(Tail::Found(None));
        }
        if window >= TAIL_WINDOW_MAX {
            return Ok(Tail::Unbounded);
        }
        window *= 4;
    }
}

#[derive(Debug, Clone)]
pub struct AppendLog {
    pub path: PathBuf,
    pub lock_path: PathBuf,
    pub by: String,
    pub lock_timeout_s: f64,
    key: String,
}

impl AppendLog {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let lock_path = with_suffix(&path, ".lock");
        Self::with_lock(path, lock_path)
    }

    pub fn with_lock(path: PathBuf, lock_path: PathBuf) -> Self {
        let key = path_key(&path);
        AppendLog { path, lock_path, by: format!("pid:{}", std::process::id()), lock_timeout_s: LOCK_TIMEOUT_S, key }
    }

    /// Scan the whole log.
    ///
    /// # Errors
    /// An I/O failure reading an existing log (see [`scan_file`]); a missing log is an empty scan.
    pub fn scan(&self) -> Result<Scan> {
        Ok(scan_file(&self.path, 0, true)?)
    }

    /// The valid prefix; a torn tail is ignored. Mid-log corruption is `LineageCorrupt`.
    pub fn read(&self) -> Result<Vec<Value>> {
        let result = self.scan()?;
        match result.corrupt {
            Some(c) => Err(Error::lineage_corrupt(&self.path, c.offset, result.records)),
            None => Ok(result.records),
        }
    }

    pub fn status(&self) -> Result<Value> {
        Ok(self.scan()?.as_status())
    }

    /// The last valid record (tail only, bounded) or whole-log strict with `strict`.
    pub fn last(&self, strict: bool) -> Result<Option<Value>> {
        if !strict && let Tail::Found(found) = tail_last_valid(&self.path)? {
            return Ok(found);
        }
        Ok(self.read()?.pop())
    }

    pub fn repairs(&self) -> Vec<Value> {
        complete_lines(&with_suffix(&self.path, ".repairs")).iter().filter_map(|l| parse_line(l)).collect()
    }

    /// Append one line, fsynced; returns its byte offset.
    pub fn append(&self, record: &Value, lock_held: bool) -> Result<u64> {
        self.append_framed(&frame(record), lock_held)
    }

    /// [`AppendLog::append`] for a record the caller has already framed (see [`frame`]): lets the caller measure the line
    /// before it decides to write it, without framing it twice.
    pub fn append_framed(&self, line: &[u8], lock_held: bool) -> Result<u64> {
        if lock_held {
            return self.append_locked(line, false);
        }
        create_parent(&self.path)?;
        let _guard = lock::lock(&self.lock_path, self.lock_timeout_s, &format!("log {}", self.file_name()))?;
        self.append_locked(line, true)
    }

    /// Repair a torn tail (and refuse corruption) without appending.
    pub fn repair(&self, lock_held: bool) -> Result<Option<Value>> {
        if lock_held {
            return self.check_tail();
        }
        let _guard = lock::lock(&self.lock_path, self.lock_timeout_s, &format!("log {}", self.file_name()))?;
        self.check_tail()
    }

    fn file_name(&self) -> String {
        self.path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }

    /// The end of the last line this process knows to be valid (`None` when it must scan before the next append).
    pub fn verified_end(&self) -> Option<u64> {
        self.known()
    }

    fn known(&self) -> Option<u64> {
        VERIFIED.lock().ok()?.get(&self.key).copied()
    }

    /// Record that this process knows the log valid up to `valid_end`.
    pub fn remember(&self, valid_end: u64) {
        if let Ok(mut map) = VERIFIED.lock() {
            map.insert(self.key.clone(), valid_end);
        }
    }

    fn forget(&self) {
        if let Ok(mut map) = VERIFIED.lock() {
            map.remove(&self.key);
        }
    }

    /// The check made on every acquisition of the writer lock; returns the repair record, if one was made.
    pub fn check_tail(&self) -> Result<Option<Value>> {
        let size = match std::fs::metadata(&self.path) {
            Ok(meta) => meta.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => return Err(e.into()),
        };
        if size == 0 {
            self.remember(0);
            return Ok(None);
        }
        let mut start = 0;
        if let Some(known) = self.known().filter(|&k| k > 0 && k <= size) {
            let mut handle = File::open(&self.path)?;
            handle.seek(SeekFrom::Start(known - 1))?;
            let mut byte = [0u8; 1];
            if handle.read(&mut byte)? == 1 && byte[0] == b'\n' {
                start = known;
            }
        }
        if start == size {
            return Ok(None);
        }
        let result = scan_file(&self.path, start, false)?;
        if let Some(c) = result.corrupt {
            return Err(Error::lineage_corrupt(&self.path, c.offset, Vec::new()));
        }
        let Some(torn) = result.torn_tail else {
            self.remember(result.size);
            return Ok(None);
        };
        let entry = self.repair_tail(torn.offset, result.size)?;
        self.remember(entry["offset"].as_u64().unwrap_or(0));
        Ok(Some(entry))
    }

    fn repair_tail(&self, offset: u64, size: u64) -> Result<Value> {
        let mut tail = vec![0u8; size.saturating_sub(offset) as usize];
        {
            let mut handle = File::open(&self.path)?;
            handle.seek(SeekFrom::Start(offset))?;
            handle.read_exact(&mut tail)?;
        }
        let digest = sha256_hex(&tail);
        // (c) preserve the fragment and force the copy; every step is idempotent.
        let aside = with_suffix(&self.path, &format!(".torn-{offset}-{}", &digest[..8]));
        atomic_write_point(&aside, &tail, "log.copy", true)?;
        fault("log.repair.after_copy")?;
        {
            let handle = OpenOptions::new().write(true).open(&self.path)?;
            handle.set_len(offset)?;
            handle.sync_all()?;
        }
        fault("log.repair.after_truncate")?;
        let at = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map_or(0.0, |d| d.as_secs_f64());
        let entry = json!({"at": at, "offset": offset, "bytes": tail.len(), "sha256": digest, "by": self.by});
        // Best effort: losing it costs only the record of the repair.
        let _ = raw_append(&with_suffix(&self.path, ".repairs"), &frame(&entry), true, false);
        Ok(entry)
    }

    fn append_locked(&self, line: &[u8], made: bool) -> Result<u64> {
        let outcome = (|| {
            if !made {
                create_parent(&self.path)?;
            }
            self.check_tail()?;
            let offset = raw_append(&self.path, line, false, true)?;
            self.remember(offset + line.len() as u64);
            fault("log.after_append")?;
            Ok(offset)
        })();
        if outcome.is_err() {
            self.forget();
        }
        outcome
    }
}

/// Append DATA to PATH (created if missing) and fsync; returns the offset it landed at.
pub fn raw_append(path: &Path, data: &[u8], repair_tail: bool, faults: bool) -> Result<u64> {
    let fresh = !path.exists();
    let mut handle = OpenOptions::new().append(true).create(true).open(path)?;
    let offset = handle.seek(SeekFrom::End(0))?;
    let mut data = data.to_vec();
    if repair_tail && offset > 0 {
        let mut probe = File::open(path)?;
        probe.seek(SeekFrom::Start(offset - 1))?;
        let mut byte = [0u8; 1];
        if probe.read(&mut byte)? == 1 && byte[0] != b'\n' {
            data.insert(0, b'\n');
        }
    }
    let torn = if faults { fault("log.torn_append")? } else { None };
    if let Some(n) = torn {
        handle.write_all(&data[..n.min(data.len())])?;
        handle.sync_all()?;
        die();
    }
    if faults {
        fault("log.before_write")?;
    }
    handle.write_all(&data)?;
    handle.sync_all()?;
    drop(handle);
    if fresh && let Some(parent) = path.parent() {
        fsync_directory(parent);
    }
    Ok(offset)
}
