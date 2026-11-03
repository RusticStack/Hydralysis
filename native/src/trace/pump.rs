//! The capture writer: agent batch bytes in, chained TRACE-1 lines on disk, the GIL released for all of it.
//!
//! `TracePump` is the Rust twin of the writer half of `hydralysis.trace_capture.TraceSource` (the lock, the transport
//! counters and the Frida callbacks stay in Python). One `batch` call decodes, redacts, canonically encodes and chains
//! the records (`SegmentEncoder`), makes any payload artifact durable, appends the lines to the segment and keeps the
//! sidecar `agent.seg.head` current, without touching Python state. The fsync policy is batched and off the callback:
//! once `sync_every` bytes are unsynced a background thread flushes them, so a slow disk never delays the agent's
//! acknowledgement; `close` (and `sync`) flush synchronously, so a finalized segment is durable.

use super::{ring_rows, SegmentEncoder};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use serde_json::Value;
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

const KEEP_ERRORS: usize = 5;
const MAX_PENDING_BYTES: usize = 8 << 20;
static TMP_COUNTER: AtomicU64 = AtomicU64::new(0);

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn os_error(error: &std::io::Error) -> String {
    format!("OSError: {error}")
}

#[derive(Default)]
struct SyncState {
    requested: bool,
    running: bool,
    quit: bool,
    syncs: u64,
    errors: Vec<String>,
}

/// The background fsync of the segment. Requests coalesce: one flush covers every byte written before it started.
struct Syncer {
    state: Mutex<SyncState>,
    wake: Condvar,
    idle: Condvar,
}

impl Syncer {
    fn run(&self, file: &File) {
        let mut state = lock(&self.state);
        loop {
            while !state.requested && !state.quit {
                state = self.wake.wait(state).unwrap_or_else(|p| p.into_inner());
            }
            if state.quit && !state.requested {
                return;
            }
            state.requested = false;
            state.running = true;
            drop(state);
            let result = file.sync_all();
            state = lock(&self.state);
            state.running = false;
            match result {
                Ok(()) => state.syncs += 1,
                Err(e) => {
                    state.errors.push(format!("fsync: {e}"));
                    let keep = state.errors.len().saturating_sub(KEEP_ERRORS);
                    state.errors.drain(..keep);
                }
            }
            self.idle.notify_all();
        }
    }

    fn request(&self) {
        lock(&self.state).requested = true;
        self.wake.notify_one();
    }

    fn wait_idle(&self) {
        let mut state = lock(&self.state);
        while state.requested || state.running {
            state = self.idle.wait(state).unwrap_or_else(|p| p.into_inner());
        }
    }

    fn quit(&self) {
        lock(&self.state).quit = true;
        self.wake.notify_one();
    }
}

#[derive(Default)]
struct Counters {
    lines: u64,
    bytes: u64,
    write_failed: u64,
    refused_after_full: u64,
    artifacts: u64,
    artifact_failed: u64,
}

enum Outcome {
    Ok { records: usize, batch_seq: u32 },
    Budget,
    Decode(String),
    Artifact,
}

struct Sink {
    dir: PathBuf,
    path: PathBuf,
    head_path: PathBuf,
    file: Option<Arc<File>>,
    syncer: Arc<Syncer>,
    thread: Option<JoinHandle<()>>,
    pending: Vec<u8>,
    counters: Counters,
    errors: Vec<String>,
    unsynced: u64,
    max_bytes: u64,
    sync_every: u64,
    full: bool,
    finalized: bool,
    last_notify: Option<Instant>,
    notified: bool,
    notify_every: Duration,
    fail_writes: u32,
}

impl Sink {
    fn error(&mut self, message: String) {
        self.errors.push(message);
        let keep = self.errors.len().saturating_sub(KEEP_ERRORS);
        self.errors.drain(..keep);
    }

    fn open(&mut self) -> std::io::Result<Arc<File>> {
        if let Some(file) = &self.file {
            return Ok(Arc::clone(file));
        }
        let file = Arc::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(&self.path)?,
        );
        let worker = Arc::clone(&file);
        let syncer = Arc::clone(&self.syncer);
        self.thread = std::thread::Builder::new()
            .name("trace-fsync".into())
            .spawn(move || syncer.run(&worker))
            .ok();
        self.file = Some(Arc::clone(&file));
        Ok(file)
    }

    /// Write the pending lines; a failed write keeps them (and the chain stays in step with what the file will hold).
    fn flush_pending(&mut self) -> bool {
        while !self.pending.is_empty() {
            let result = if self.fail_writes > 0 {
                self.fail_writes -= 1;
                Err(std::io::Error::other("injected write failure"))
            } else {
                self.open().and_then(|file| (&*file).write(&self.pending))
            };
            match result {
                Ok(0) => {
                    self.counters.write_failed += 1;
                    return false;
                }
                Ok(written) => {
                    self.counters.bytes += written as u64;
                    self.unsynced += written as u64;
                    self.pending.drain(..written);
                }
                Err(e) => {
                    self.counters.write_failed += 1;
                    self.error(os_error(&e));
                    return false;
                }
            }
        }
        if self.unsynced >= self.sync_every {
            self.unsynced = 0;
            self.syncer.request();
        }
        true
    }

    /// Flush and make everything written so far durable, before returning.
    fn sync(&mut self) {
        self.flush_pending();
        self.syncer.wait_idle();
        if let Some(file) = self.file.clone() {
            match file.sync_all() {
                Ok(()) => {
                    self.unsynced = 0;
                    lock(&self.syncer.state).syncs += 1;
                }
                Err(e) => self.error(format!("fsync: {e}")),
            }
        }
        self.pull_sync_errors();
    }

    fn pull_sync_errors(&mut self) {
        let taken: Vec<String> = std::mem::take(&mut lock(&self.syncer.state).errors);
        for message in taken {
            self.error(message);
        }
    }

    fn size(&self) -> u64 {
        self.counters.bytes + self.pending.len() as u64
    }

    fn append(&mut self, lines: &[u8], head: (u64, &str)) {
        if lines.is_empty() {
            return;
        }
        self.pending.extend_from_slice(lines);
        self.counters.lines += memchr::memchr_iter(b'\n', lines).count() as u64;
        self.flush_pending();
        self.notify(false, head);
    }

    /// The sidecar `agent.seg.head` (record count, chain head, bytes), replaced atomically at most every `notify_every`.
    /// True when it was written.
    fn notify(&mut self, force: bool, head: (u64, &str)) -> bool {
        let now = Instant::now();
        if !force
            && self
                .last_notify
                .is_some_and(|t| now.duration_since(t) < self.notify_every)
        {
            return false;
        }
        self.last_notify = Some(now);
        self.notified = true;
        let body = format!(
            "{{\"bytes\": {}, \"finalized\": {}, \"full\": {}, \"head\": \"{}\", \"records\": {}}}",
            self.counters.bytes, self.finalized, self.full, head.1, head.0
        );
        if let Err(e) = replace_file(&self.head_path, body.as_bytes(), false) {
            self.error(format!("notify: {e}"));
        }
        true
    }

    /// `Some(reason)` once the segment is at its size limit (empty when it was already full). Checked before each batch
    /// is encoded (a chained line cannot be un-made), so a segment may pass it by at most one batch.
    fn over_limit(&mut self) -> Option<&'static str> {
        if self.full {
            return Some("");
        }
        if self.size() < self.max_bytes && self.pending.len() <= MAX_PENDING_BYTES {
            return None;
        }
        self.full = true;
        Some(if self.size() >= self.max_bytes {
            "segment size limit"
        } else {
            "writer cannot keep up"
        })
    }

    /// A payload artifact, fsynced before the lines that name it are appended.
    fn artifact(&mut self, digest: &str, blob: &[u8]) -> bool {
        let target = self.dir.join("artifacts").join(digest);
        if target.exists() {
            return true;
        }
        match replace_file(&target, blob, true) {
            Ok(()) => {
                self.counters.artifacts += 1;
                true
            }
            Err(e) => {
                self.error(format!("artifact: {e}"));
                false
            }
        }
    }
}

/// Write BLOB beside TARGET and rename it over TARGET, so a reader sees the old file or the new one. A rename that
/// loses to a reader holding the file open is retried briefly.
fn replace_file(target: &Path, blob: &[u8], sync: bool) -> std::io::Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let temporary = target.with_file_name(format!(
        "{name}.{}.{}.tmp",
        std::process::id(),
        TMP_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(blob)?;
        if sync {
            file.sync_all()?;
        }
        drop(file);
        let mut delay = Duration::from_millis(2);
        let mut attempt = 0;
        loop {
            match std::fs::rename(&temporary, target) {
                Ok(()) => return Ok(()),
                Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied && attempt < 7 => {
                    attempt += 1;
                    std::thread::sleep(delay);
                    delay = (delay * 2).min(Duration::from_millis(100));
                }
                Err(e) => return Err(e),
            }
        }
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

/// The chained segment writer of one capture (the twin of the writer half of `trace_capture.TraceSource`).
#[pyclass]
pub struct TracePump {
    enc: SegmentEncoder,
    sink: Sink,
}

impl TracePump {
    fn run_batch(enc: &mut SegmentEncoder, sink: &mut Sink, data: &[u8], now_ns: u64) -> Outcome {
        if let Some(reason) = sink.over_limit() {
            sink.counters.refused_after_full += 1;
            if !reason.is_empty() {
                // The first refusal records the gap; later ones only count.
                let payload = serde_json::json!({"reason": "budget", "detail": reason,
                    "limit_bytes": sink.max_bytes, "out_of_band": false});
                if let Ok(line) = enc.control_event("core.capture.gap", now_ns, None, payload, 0) {
                    sink.append(&line, (enc.chain.n, &enc.chain.head));
                }
            }
            return Outcome::Budget;
        }
        let mut artifacts: BTreeMap<String, Vec<u8>> = BTreeMap::new();
        let (lines, batch_seq, records) = match enc.encode(data, &mut artifacts) {
            Ok(done) => done,
            Err(message) => return Outcome::Decode(message),
        };
        for (digest, blob) in &artifacts {
            if !sink.artifact(digest, blob) {
                // The reference must not commit without its bytes: refuse the whole batch's lines.
                sink.counters.artifact_failed += 1;
                return Outcome::Artifact;
            }
        }
        sink.append(&lines, (enc.chain.n, &enc.chain.head));
        Outcome::Ok { records, batch_seq }
    }
}

#[pymethods]
impl TracePump {
    #[new]
    #[pyo3(signature = (directory, segment_id, source_id, producer_gen, process_id, sites, key, qpc_freq, payload_authorized=false, max_payload=4096, max_bytes=1073741824, sync_every=1048576, notify_every_s=0.02))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        directory: &str,
        segment_id: &str,
        source_id: &str,
        producer_gen: u32,
        process_id: u32,
        sites: &Bound<'_, PyDict>,
        key: &[u8],
        qpc_freq: u64,
        payload_authorized: bool,
        max_payload: usize,
        max_bytes: u64,
        sync_every: u64,
        notify_every_s: f64,
    ) -> PyResult<Self> {
        let enc = SegmentEncoder::new(
            segment_id,
            source_id,
            producer_gen,
            process_id,
            sites,
            key,
            qpc_freq,
            payload_authorized,
            max_payload,
        )?;
        let dir = PathBuf::from(directory);
        std::fs::create_dir_all(&dir).map_err(|e| super::err(os_error(&e)))?;
        let path = dir.join("agent.seg");
        let head_path = dir.join("agent.seg.head");
        Ok(Self {
            enc,
            sink: Sink {
                dir,
                path,
                head_path,
                file: None,
                syncer: Arc::new(Syncer {
                    state: Mutex::new(SyncState::default()),
                    wake: Condvar::new(),
                    idle: Condvar::new(),
                }),
                thread: None,
                pending: Vec::new(),
                counters: Counters::default(),
                errors: Vec::new(),
                unsynced: 0,
                max_bytes,
                sync_every,
                full: false,
                finalized: false,
                last_notify: None,
                notified: false,
                notify_every: Duration::from_secs_f64(notify_every_s.max(0.0)),
                fail_writes: 0,
            },
        })
    }

    /// Decode, encode, chain and append one agent batch with the GIL released (NOW_NS stamps the size-limit gap, on the
    /// caller's clock). Returns
    /// `(status, reason, records, batch_seq)`, status one of ok, budget, decode, artifact.
    fn batch(
        &mut self,
        py: Python<'_>,
        data: &[u8],
        now_ns: u64,
    ) -> (&'static str, String, usize, u32) {
        let Self { enc, sink } = self;
        let outcome = py.detach(|| Self::run_batch(enc, sink, data, now_ns));
        sink.pull_sync_errors();
        match outcome {
            Outcome::Ok { records, batch_seq } => ("ok", String::new(), records, batch_seq),
            Outcome::Budget => ("budget", "budget".into(), 0, 0),
            Outcome::Decode(message) => ("decode", message, 0, 0),
            Outcome::Artifact => (
                "artifact",
                "artifact could not be made durable".into(),
                0,
                0,
            ),
        }
    }

    /// One control event (source, lifetime, gap) on the chain, appended.
    #[pyo3(signature = (kind, t_ns, payload, tid=None, skip=0))]
    fn event(
        &mut self,
        kind: &str,
        t_ns: u64,
        payload: &Bound<'_, PyAny>,
        tid: Option<u32>,
        skip: u64,
    ) -> PyResult<()> {
        let value: Value = super::py_to_value(payload)?;
        let line = self
            .enc
            .control_event(kind, t_ns, tid, value, skip)
            .map_err(super::err)?;
        let Self { enc, sink } = self;
        sink.append(&line, (enc.chain.n, &enc.chain.head));
        Ok(())
    }

    /// The loss only the out-of-band counters know, appended.
    #[pyo3(signature = (rings, t_ns, no_ring=0))]
    fn finalize_rings(
        &mut self,
        rings: &Bound<'_, PyList>,
        t_ns: u64,
        no_ring: u64,
    ) -> PyResult<()> {
        let rows = ring_rows(rings)?;
        let lines = self
            .enc
            .finalize_rows(rows, t_ns, no_ring)
            .map_err(super::err)?;
        let Self { enc, sink } = self;
        sink.append(&lines, (enc.chain.n, &enc.chain.head));
        Ok(())
    }

    /// Write what is pending and make it durable.
    fn sync(&mut self, py: Python<'_>) {
        let sink = &mut self.sink;
        py.detach(|| sink.sync());
    }

    /// The end: flush, fsync, write the final sidecar, close the file.
    fn close(&mut self, py: Python<'_>) {
        let Self { enc, sink } = self;
        py.detach(|| {
            sink.finalized = true;
            sink.sync();
            sink.notify(true, (enc.chain.n, &enc.chain.head));
            sink.syncer.quit();
            if let Some(thread) = sink.thread.take() {
                let _ = thread.join();
            }
            sink.file = None;
        });
        sink.pull_sync_errors();
    }

    /// Write the sidecar now (or only when the notify interval has passed). True when it was written.
    #[pyo3(signature = (force=false))]
    fn notify(&mut self, force: bool) -> bool {
        let Self { enc, sink } = self;
        sink.notify(force, (enc.chain.n, &enc.chain.head))
    }

    /// True once after the sidecar was replaced (the caller then runs its ingester callback).
    fn take_notified(&mut self) -> bool {
        std::mem::take(&mut self.sink.notified)
    }

    /// Test hook: the next N writes fail with an OS error (the lines stay pending and are retried in order).
    fn inject_write_failures(&mut self, count: u32) {
        self.sink.fail_writes = count;
    }

    #[getter]
    fn writer<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let syncs = lock(&self.sink.syncer.state).syncs;
        let c = &self.sink.counters;
        let d = PyDict::new(py);
        d.set_item("lines", c.lines)?;
        d.set_item("bytes", c.bytes)?;
        d.set_item("write_failed", c.write_failed)?;
        d.set_item("retried_bytes", 0)?;
        d.set_item("refused_after_full", c.refused_after_full)?;
        d.set_item("artifacts", c.artifacts)?;
        d.set_item("artifact_failed", c.artifact_failed)?;
        d.set_item("syncs", syncs)?;
        Ok(d)
    }

    #[getter]
    fn pending_bytes(&self) -> usize {
        self.sink.pending.len()
    }

    #[getter]
    fn full(&self) -> bool {
        self.sink.full
    }

    /// The writer's errors since the last call (the last few), for the caller's health report.
    fn take_errors(&mut self) -> Vec<String> {
        self.sink.pull_sync_errors();
        std::mem::take(&mut self.sink.errors)
    }

    #[getter]
    fn head(&self) -> String {
        self.enc.chain.head.clone()
    }

    #[getter]
    fn count(&self) -> u64 {
        self.enc.chain.n
    }

    #[getter]
    fn source_seq(&self) -> u64 {
        self.enc.source_seq
    }

    #[getter]
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in &self.enc.stats {
            d.set_item(k, v)?;
        }
        Ok(d)
    }

    fn site_hits<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in &self.enc.hits {
            d.set_item(*k, *v)?;
        }
        Ok(d)
    }

    /// Encode a control event without appending it (the encoder's own method, for callers that frame their own lines).
    #[pyo3(signature = (kind, t_ns, payload, tid=None, skip=0))]
    fn encode_event<'py>(
        &mut self,
        py: Python<'py>,
        kind: &str,
        t_ns: u64,
        payload: &Bound<'py, PyAny>,
        tid: Option<u32>,
        skip: u64,
    ) -> PyResult<Bound<'py, PyBytes>> {
        let value: Value = super::py_to_value(payload)?;
        let line = self
            .enc
            .control_event(kind, t_ns, tid, value, skip)
            .map_err(super::err)?;
        Ok(PyBytes::new(py, &line))
    }
}

impl Drop for TracePump {
    fn drop(&mut self) {
        self.sink.syncer.quit();
    }
}
