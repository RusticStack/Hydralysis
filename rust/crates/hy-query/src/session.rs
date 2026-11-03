//! Port of the engine-facing core of `hydralysis/query.py` (everything above `QueryRunner`).
//!
//! The engine client is the [`Engine`] trait, so the program cache, the open-in-flight gate, the cap eviction, the
//! script run and the engine decompile fallback are testable with a fake. The Python process-wide globals
//! (`_keys`, `_opening`, `_in_use`, `_held`) are one [`Registry`] value here.

// Engine refusals are the cold path (one per failed call), so the large `Err` variant is deliberate.
#![allow(clippy::result_large_err)]

use crate::analysis::py_dumps_string;
use crate::decompile;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};
use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::time::{Duration, Instant};

pub const MAX_CHARS: i64 = 16_000_000;
/// A background save of a large working copy holds its program for minutes; requests wait for it.
pub const BUSY_WAIT_MS: i64 = 180_000;
pub const READER_LANES: i64 = 1;
pub const FALLBACK_TIMEOUT_S: i64 = 3600;
/// `hydra.PATIENCE_S` in milliseconds.
pub const PATIENCE_MS: i64 = 25_000;
/// (RusticQuery option name, engine field name).
pub const ENGINE_FIELDS: [(&str, &str); 3] = [
    ("max_result_mb", "maxResultMb"),
    ("max_result_kb", "maxResultKb"),
    ("offset", "offset"),
];
const GONE: [&str; 4] = ["no_program", "no_project", "not_found", "closed"];

/// An `ok:false` answer from the engine (`hydra.EngineError`).
#[derive(Debug, Clone, PartialEq)]
pub struct EngineError {
    pub code: String,
    pub message: String,
    pub details: Map<String, Value>,
    pub command: String,
    /// `str(error)`: the JSON text an agent reads.
    pub text: String,
}

impl EngineError {
    pub fn new(code: &str, message: &str, details: Map<String, Value>, command: &str) -> Self {
        let text =
            json!({"engine_error": code, "message": message, "command": command}).to_string();
        Self {
            code: code.into(),
            message: message.into(),
            details,
            command: command.into(),
            text,
        }
    }
    /// hydra.4's per-connection view cap: `busy` with resource `client_cap`.
    pub fn at_client_cap(&self) -> bool {
        self.code == "busy"
            && self.details.get("resource").and_then(Value::as_str) == Some("client_cap")
    }
}

impl std::fmt::Display for EngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.text)
    }
}
impl std::error::Error for EngineError {}

/// The engine client. A stand-in without capabilities supports nothing.
pub trait Engine: Send + Sync {
    /// The connection key (`<root>|<role>`): the first element of every cache key.
    fn key(&self) -> &str;
    fn call(&self, command: &str, fields: &Map<String, Value>) -> Result<Value, EngineError>;
    fn supports(&self, _name: &str) -> bool {
        false
    }
}

/// `hydra.patience_ms`.
pub fn patience_ms(engine: &dyn Engine, default_ms: i64) -> i64 {
    if engine.supports("queueInfo") {
        default_ms.min(PATIENCE_MS)
    } else {
        default_ms
    }
}

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum OpenError {
    #[error("{0}")]
    Engine(EngineError),
    /// Python `ValueError`: the opened program is not the target build.
    #[error(
        "{program} in {gpr} reports SHA-256 {got}, not the target build {wanted}; nothing was answered"
    )]
    WrongBuild {
        program: String,
        gpr: String,
        got: String,
        wanted: String,
    },
    /// Python `KeyError`: the engine reply lacks a field the row needs.
    #[error("{0:?}")]
    Missing(String),
}

impl From<EngineError> for OpenError {
    fn from(e: EngineError) -> Self {
        OpenError::Engine(e)
    }
}

/// One cached program of a connection.
#[derive(Debug, Clone, PartialEq)]
pub struct Row {
    pub key: String,
    pub project: Value,
    pub gpr: String,
    pub revision: Value,
    pub project_revision: Value,
    pub image_base: Value,
    pub functions: Value,
    pub analyzed: Value,
    pub mode: Value,
}

impl Row {
    pub fn to_json(&self) -> Value {
        json!({"key": self.key, "project": self.project, "gpr": self.gpr, "revision": self.revision,
               "project_revision": self.project_revision, "image_base": self.image_base,
               "functions": self.functions, "analyzed": self.analyzed, "mode": self.mode})
    }
}

#[derive(Debug, Clone, Default)]
pub struct OpenOptions {
    pub writable: bool,
    pub upgrade: bool,
    pub refresh: bool,
    /// `share=False` opens a writable program for its caller alone.
    pub unshared: bool,
    pub backup: Option<String>,
    pub project: Option<String>,
}

/// (connection key, lowercased gpr path, program, writable).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct CacheKey(String, String, String, bool);

type Mark = (String, String);

thread_local! {
    /// The marks of the read this thread runs (`holding`).
    static HELD: RefCell<Option<Vec<Mark>>> = const { RefCell::new(None) };
}

#[derive(Default)]
struct State {
    keys: IndexMap<CacheKey, Row>,
    opening: HashMap<CacheKey, Arc<Flight>>,
    in_use: HashMap<Mark, usize>,
}

impl State {
    /// `_hold`: ROW marked in use when this thread runs a read.
    fn hold(&mut self, engine_key: &str, row: &Row) {
        HELD.with(|held| {
            if let Some(marks) = held.borrow_mut().as_mut() {
                let mark = (engine_key.to_string(), row.key.clone());
                *self.in_use.entry(mark.clone()).or_insert(0) += 1;
                marks.push(mark);
            }
        });
    }
}

type Outcome = Option<Result<Row, OpenError>>;

/// One open in progress: the threads that join it wait and take its row or refusal.
struct Flight {
    outcome: Mutex<Option<Outcome>>,
    done: Condvar,
}

impl Flight {
    fn new() -> Self {
        Self {
            outcome: Mutex::new(None),
            done: Condvar::new(),
        }
    }
    fn finish(&self, outcome: Outcome) {
        *lock(&self.outcome) = Some(outcome);
        self.done.notify_all();
    }
    fn wait(&self) -> Outcome {
        let mut guard = lock(&self.outcome);
        loop {
            if let Some(outcome) = guard.as_ref() {
                return outcome.clone();
            }
            guard = self.done.wait(guard).unwrap_or_else(|p| p.into_inner());
        }
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|p| p.into_inner())
}

/// Ends an open in flight even when the opener panics (Python: `finally`).
struct FlightEnd<'a> {
    registry: &'a Registry,
    cache_key: CacheKey,
    flight: Arc<Flight>,
    outcome: Option<Outcome>,
}

impl Drop for FlightEnd<'_> {
    fn drop(&mut self) {
        lock(&self.registry.state).opening.remove(&self.cache_key);
        self.flight.finish(self.outcome.take().unwrap_or(None));
    }
}

/// Marks every program this thread's opens hand out as used by its read; dropping it ends the marks.
pub struct Holding<'a> {
    registry: &'a Registry,
    previous: Option<Vec<Mark>>,
}

impl Drop for Holding<'_> {
    fn drop(&mut self) {
        let marks = HELD
            .with(|held| held.replace(self.previous.take()))
            .unwrap_or_default();
        let mut state = lock(&self.registry.state);
        for mark in marks {
            match state.in_use.get_mut(&mark) {
                Some(n) if *n > 1 => *n -= 1,
                _ => {
                    state.in_use.remove(&mark);
                }
            }
        }
    }
}

/// The process-wide program cache.
#[derive(Default)]
pub struct Registry {
    state: Mutex<State>,
    /// shared reader key -> lane -> connection key of that lane (`QueryRunner.reader`'s `_lanes`).
    lanes: Mutex<HashMap<String, std::collections::BTreeMap<i64, String>>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    /// `_holding()`.
    pub fn holding(&self) -> Holding<'_> {
        let previous = HELD.with(|held| held.replace(Some(Vec::new())));
        Holding {
            registry: self,
            previous,
        }
    }

    /// Cached rows of one connection, oldest first (a test and diagnostics view of `_keys`).
    pub fn rows(&self, engine_key: &str) -> Vec<Row> {
        lock(&self.state)
            .keys
            .iter()
            .filter(|(k, _)| k.0 == engine_key)
            .map(|(_, v)| v.clone())
            .collect()
    }

    /// `_in_use` as (connection key, program key, count), sorted.
    pub fn in_use(&self) -> Vec<(String, String, usize)> {
        let mut v: Vec<_> = lock(&self.state)
            .in_use
            .iter()
            .map(|((a, b), n)| (a.clone(), b.clone(), *n))
            .collect();
        v.sort();
        v
    }

    /// Number of opens in flight.
    pub fn opening(&self) -> usize {
        lock(&self.state).opening.len()
    }

    /// `open_program`: join (or open) one program and check the build before anything is answered from it.
    pub fn open_program(
        &self,
        engine: &dyn Engine,
        gpr: &str,
        program: &str,
        sha256: &str,
        options: &OpenOptions,
    ) -> Result<Row, OpenError> {
        let cache_key = CacheKey(
            engine.key().to_string(),
            windows_path(gpr).to_lowercase(),
            program.to_string(),
            options.writable,
        );
        let flight = loop {
            let waiting = {
                let mut state = lock(&self.state);
                if !options.refresh
                    && let Some(known) = state.keys.shift_remove(&cache_key)
                {
                    // most recently used last: eviction takes the oldest first
                    state.keys.insert(cache_key.clone(), known.clone());
                    state.hold(engine.key(), &known);
                    return Ok(known);
                }
                match state.opening.get(&cache_key) {
                    Some(f) => Arc::clone(f),
                    None => {
                        let f = Arc::new(Flight::new());
                        state.opening.insert(cache_key.clone(), Arc::clone(&f));
                        break f;
                    }
                }
            };
            let outcome = waiting.wait();
            if !options.refresh {
                match outcome {
                    Some(Err(e)) => return Err(e),
                    Some(Ok(row)) => {
                        let mut state = lock(&self.state);
                        state.hold(engine.key(), &row);
                        return Ok(row);
                    }
                    None => {}
                }
            }
            // A refresh opens again itself after the open in flight, and so does a waiter whose opener was interrupted.
        };
        let mut end = FlightEnd {
            registry: self,
            cache_key: cache_key.clone(),
            flight,
            outcome: None,
        };
        let result = self.open_now(engine, &cache_key, gpr, program, sha256, options);
        end.outcome = Some(Some(result.clone()));
        result
    }

    fn open_now(
        &self,
        engine: &dyn Engine,
        cache_key: &CacheKey,
        gpr: &str,
        program: &str,
        sha256: &str,
        options: &OpenOptions,
    ) -> Result<Row, OpenError> {
        let wait = patience_ms(engine, BUSY_WAIT_MS);
        // A project this connection has just made is open already: no `open_project` round trip.
        let opened: Value = match &options.project {
            Some(id) if !id.is_empty() => json!({"id": id, "gpr": gpr}),
            _ => {
                let mut f = Map::new();
                f.insert("path".into(), json!(gpr));
                f.insert("writable".into(), json!(options.writable));
                f.insert("wait".into(), json!(wait));
                engine.call("open_project", &f)?
            }
        };
        let project_id = opened
            .get("id")
            .cloned()
            .ok_or_else(|| OpenError::Missing("id".into()))?;
        let mut fields = Map::new();
        fields.insert("path".into(), json!(program));
        fields.insert("project".into(), project_id.clone());
        if options.writable {
            fields.insert("writable".into(), json!(true));
            fields.insert("share".into(), json!(!options.unshared));
            fields.insert("upgrade".into(), json!(options.upgrade));
            if let Some(backup) = options.backup.as_deref().filter(|b| !b.is_empty()) {
                fields.insert("backup".into(), json!(backup));
            }
        }
        let info = match call_open(engine, wait, &fields) {
            Ok(info) => info,
            Err(e) if e.at_client_cap() => {
                self.open_after_eviction(engine, cache_key, &fields, wait, e)?
            }
            Err(e) => return Err(e.into()),
        };
        let reported = info.get("sha256").map_or_else(String::new, py_str);
        if reported.to_lowercase() != sha256 {
            return Err(OpenError::WrongBuild {
                program: program.into(),
                gpr: opened.get("gpr").map_or_else(|| gpr.to_string(), py_str),
                got: info.get("sha256").map_or_else(|| "None".into(), py_str),
                wanted: sha256.into(),
            });
        }
        let key = info
            .get("key")
            .ok_or_else(|| OpenError::Missing("key".into()))?;
        let row = Row {
            key: py_str(key),
            project: project_id,
            gpr: opened.get("gpr").map_or_else(|| gpr.to_string(), py_str),
            revision: info.get("revision").cloned().unwrap_or(Value::Null),
            project_revision: opened.get("revision").cloned().unwrap_or(Value::Null),
            image_base: info.get("imageBase").cloned().unwrap_or(Value::Null),
            functions: info.get("functions").cloned().unwrap_or(Value::Null),
            analyzed: info.get("analyzed").cloned().unwrap_or(Value::Null),
            mode: info.get("mode").cloned().unwrap_or(Value::Null),
        };
        let mut state = lock(&self.state);
        state.keys.insert(cache_key.clone(), row.clone());
        state.hold(engine.key(), &row);
        Ok(row)
    }

    /// Open again after closing this connection's least recently used read-only programs, one at a time. A program no
    /// read of this process is using goes first; when nothing is left to close, the engine's refusal stands.
    fn open_after_eviction(
        &self,
        engine: &dyn Engine,
        cache_key: &CacheKey,
        fields: &Map<String, Value>,
        wait: i64,
        mut error: EngineError,
    ) -> Result<Value, OpenError> {
        loop {
            let program = {
                let state = lock(&self.state);
                let rows: Vec<&Row> = state
                    .keys
                    .iter()
                    .filter(|(k, _)| k.0 == engine.key() && *k != cache_key && !k.3)
                    .map(|(_, v)| v)
                    .collect();
                let idle: Vec<&&Row> = rows
                    .iter()
                    .filter(|r| {
                        state
                            .in_use
                            .get(&(engine.key().to_string(), r.key.clone()))
                            .copied()
                            .unwrap_or(0)
                            == 0
                    })
                    .collect();
                match idle.first() {
                    Some(r) => r.key.clone(),
                    None => match rows.first() {
                        Some(r) => r.key.clone(),
                        None => return Err(error.into()),
                    },
                }
            };
            let mut close = Map::new();
            close.insert("program".into(), json!(program));
            if let Err(closing) = engine.call("close_program", &close)
                && !GONE.contains(&closing.code.as_str())
            {
                return Err(error.into());
            }
            lock(&self.state)
                .keys
                .retain(|k, v| !(k.0 == engine.key() && v.key == program));
            match call_open(engine, wait, fields) {
                Ok(info) => return Ok(info),
                Err(again) if again.at_client_cap() => error = again,
                Err(again) => return Err(again.into()),
            }
        }
    }

    /// `forget`: drop the rows of one connection.
    pub fn forget(&self, engine_key: &str) {
        lock(&self.state).keys.retain(|k, _| k.0 != engine_key);
    }

    /// `_drop_program`: drop the rows of one daemon program on a connection.
    pub fn drop_program(&self, engine_key: &str, program: &str) {
        lock(&self.state)
            .keys
            .retain(|k, v| !(k.0 == engine_key && v.key == program));
    }

    /// `_drop_rows_under`: drop a connection's rows of programs whose project lies under one of FOLDERS.
    pub fn drop_rows_under(&self, engine_key: &str, folders: &[&str]) {
        let roots: Vec<PathBuf> = folders.iter().map(|f| resolve(Path::new(f))).collect();
        let rows: Vec<(CacheKey, Row)> = lock(&self.state)
            .keys
            .iter()
            .filter(|(k, _)| k.0 == engine_key)
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        // `resolve` asks the file system: outside the guard, and a row replaced meanwhile stays.
        let gone: Vec<(CacheKey, Row)> = rows
            .into_iter()
            .filter(|(k, _)| {
                let path = resolve(Path::new(&k.1));
                roots.iter().any(|root| is_relative_to(&path, root))
            })
            .collect();
        let mut state = lock(&self.state);
        for (key, row) in gone {
            if state.keys.get(&key) == Some(&row) {
                state.keys.shift_remove(&key);
            }
        }
    }

    /// `forget_role`: every row of the role, the shared connection's and every pool entry's (`<root>|<role>|`).
    pub fn forget_role(&self, engine_key: &str) {
        let prefix = format!("{engine_key}|");
        lock(&self.state)
            .keys
            .retain(|k, _| !(k.0 == engine_key || k.0.starts_with(&prefix)));
    }

    /// `QueryRunner.reader`'s lane table: remember connection KEY as LANE of the shared reader SHARED.
    pub fn add_lane(&self, shared: &str, lane: i64, key: &str) {
        lock(&self.lanes)
            .entry(shared.to_string())
            .or_default()
            .insert(lane, key.to_string());
    }

    /// `readers`: the shared connection and the lanes made beside it, as connection keys.
    pub fn readers(&self, engine_key: &str) -> Vec<String> {
        let mut out = vec![engine_key.to_string()];
        if let Some(lanes) = lock(&self.lanes).get(engine_key) {
            out.extend(lanes.values().filter(|k| k.as_str() != engine_key).cloned());
        }
        out
    }
}

fn call_open(
    engine: &dyn Engine,
    wait: i64,
    fields: &Map<String, Value>,
) -> Result<Value, EngineError> {
    let mut all = Map::new();
    all.insert("wait".into(), json!(wait));
    for (k, v) in fields {
        all.insert(k.clone(), v.clone());
    }
    engine.call("open_program", &all)
}

/// Python `str(value)` for the JSON shapes a reply holds.
pub fn py_str(v: &Value) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Null => "None".into(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        other => other.to_string(),
    }
}

/// `str(Path(text))` on Windows: forward slashes become backslashes, repeated separators collapse (a UNC prefix
/// keeps two), `.` components and a trailing separator go, the empty path is `.`.
pub fn windows_path(text: &str) -> String {
    let t = text.replace('/', "\\");
    let (prefix, rest) = split_drive(&t);
    let parts: Vec<&str> = rest
        .split('\\')
        .filter(|p| !p.is_empty() && *p != ".")
        .collect();
    let rooted = rest.starts_with('\\');
    let mut out = String::from(prefix);
    // a UNC share is a drive with a root of its own: a share path always ends in a separator
    if rooted || prefix.starts_with("\\\\") {
        out.push('\\');
    }
    out.push_str(&parts.join("\\"));
    if out.is_empty() { ".".into() } else { out }
}

fn split_drive(t: &str) -> (&str, &str) {
    let b = t.as_bytes();
    if b.len() >= 2 && b[1] == b':' && b[0].is_ascii_alphabetic() {
        return (&t[..2], &t[2..]);
    }
    if let Some(rest) = t.strip_prefix("\\\\") {
        // \\server\share is the drive
        let mut it = rest.splitn(3, '\\');
        if let (Some(server), Some(share)) = (it.next(), it.next())
            && !server.is_empty()
            && !share.is_empty()
        {
            let len = 2 + server.len() + 1 + share.len();
            return (&t[..len], &t[len..]);
        }
    }
    ("", t)
}

/// `Path.resolve()` (non-strict): the longest existing ancestor is canonicalised, the rest appended.
fn resolve(path: &Path) -> PathBuf {
    let mut tail = Vec::new();
    let mut cur = path.to_path_buf();
    loop {
        if let Ok(real) = std::fs::canonicalize(&cur) {
            let s = real.to_string_lossy().to_string();
            let mut base = PathBuf::from(s.strip_prefix(r"\\?\").unwrap_or(&s));
            for part in tail.iter().rev() {
                base.push(part);
            }
            return base;
        }
        match (
            cur.file_name().map(|n| n.to_owned()),
            cur.parent().map(Path::to_path_buf),
        ) {
            (Some(name), Some(parent)) if parent != cur => {
                tail.push(name);
                cur = parent;
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn is_relative_to(path: &Path, root: &Path) -> bool {
    let lower = |p: &Path| p.to_string_lossy().to_lowercase();
    let (p, r) = (lower(path), lower(root));
    let r = r.trim_end_matches('\\');
    p == r || p.strip_prefix(r).is_some_and(|rest| rest.starts_with('\\'))
}

/// `accepted`: an error raises; a decompile the engine stopped on purpose is a partial result and gains a `decompile`
/// summary. `Err` carries the JSON text of the (credential-free) refusal, the `RuntimeError` message.
pub fn accepted(action: &str, response: &Value) -> Result<Value, String> {
    let ok = response.get("ok").is_some_and(truthy);
    let mut out = if ok {
        response.clone()
    } else {
        let partial = if action == "decompile" {
            decompile::from_error(&py_dumps_string(response))
        } else {
            None
        };
        match partial {
            None => return Err(py_dumps_string(&public(response))),
            Some(Value::Object(mut p)) => {
                p.insert("ok".into(), Value::Bool(true));
                p.insert("engine_ok".into(), Value::Bool(false));
                Value::Object(p)
            }
            Some(other) => other,
        }
    };
    if action == "decompile" {
        out = decompile::annotate(out);
    }
    Ok(out)
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `_public`: engine credentials never enter output.
pub fn public(value: &Value) -> Value {
    match value {
        Value::Object(m) => Value::Object(
            m.iter()
                .filter(|(k, _)| !matches!(k.as_str(), "ipc" | "token" | "secret"))
                .map(|(k, v)| (k.clone(), public(v)))
                .collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(public).collect()),
        other => other.clone(),
    }
}

/// `reader_lanes`: 1..=64 from `readerLanes` / `reader_lanes`, else the default.
pub fn reader_lanes(settings: &Value) -> i64 {
    let value = settings
        .get("readerLanes")
        .or_else(|| settings.get("reader_lanes"));
    match value.and_then(|v| v.as_i64().filter(|_| v.is_i64() || v.is_u64())) {
        Some(n) if (1..=64).contains(&n) => n,
        _ => READER_LANES,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ScriptError {
    /// Python `ValueError`.
    #[error("request too large to send inline")]
    TooLarge,
    /// Python `OSError`.
    #[error("{0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Engine(#[from] EngineError),
    /// Python `RuntimeError`.
    #[error("RusticQuery returned no complete answer (truncated={truncated}): {tail}")]
    Incomplete { truncated: String, tail: String },
    /// Python `json.JSONDecodeError` (a `ValueError`).
    #[error("{0}")]
    Json(#[from] serde_json::Error),
}

static REQUESTS: AtomicU64 = AtomicU64::new(0);

fn unique_hex() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "{:016x}{:08x}{:08x}",
        nanos as u64,
        std::process::id(),
        REQUESTS.fetch_add(1, Ordering::Relaxed)
    )
}

/// `run_script`: one RusticQuery run. Large requests travel as a file, not a command argument.
pub fn run_script(
    engine: &dyn Engine,
    program_key: &str,
    request: &Value,
    timeout_s: i64,
    request_dir: Option<&Path>,
    wait_ms: i64,
    deadline_s: Option<f64>,
) -> Result<(Value, Value), ScriptError> {
    let body = py_dumps_string(request);
    let mut argument = body.clone();
    let mut path = None;
    if body.chars().count() > 256 * 1024 {
        let dir = request_dir.ok_or(ScriptError::TooLarge)?;
        std::fs::create_dir_all(dir)?;
        let file = dir.join(format!("request-{}.json", unique_hex()));
        std::fs::write(&file, &body)?;
        argument = format!("@{}", file.display());
        path = Some(file);
    }
    let mut fields = Map::new();
    fields.insert("script".into(), json!("RusticQuery.java"));
    fields.insert("program".into(), json!(program_key));
    fields.insert("args".into(), json!([argument]));
    fields.insert("maxChars".into(), json!(MAX_CHARS));
    fields.insert("timeout".into(), json!(timeout_s + 5));
    fields.insert(
        "wait".into(),
        json!(if wait_ms != 0 {
            wait_ms
        } else {
            patience_ms(engine, BUSY_WAIT_MS)
        }),
    );
    if engine.supports("laneHint") {
        fields.insert("lane".into(), json!("quick"));
    }
    if let Some(d) = deadline_s {
        fields.insert("deadline".into(), json!(d));
    }
    let result = engine.call("script", &fields);
    if let Some(p) = path {
        let _ = std::fs::remove_file(p);
    }
    let result = result?;
    let output = result.get("output").map_or_else(String::new, |v| {
        if v.is_null() {
            "None".into()
        } else {
            py_str(v)
        }
    });
    let line = py_splitlines(&output)
        .into_iter()
        .rfind(|l| l.starts_with('{'))
        .map(str::to_string);
    let truncated = result.get("truncated").is_some_and(truthy);
    match line {
        Some(line) if !truncated => Ok((serde_json::from_str(&line)?, result)),
        _ => {
            let chars: Vec<char> = output.chars().collect();
            let tail: String = chars[chars.len().saturating_sub(2000)..].iter().collect();
            Err(ScriptError::Incomplete {
                truncated: result
                    .get("truncated")
                    .map_or_else(|| "None".into(), py_str),
                tail,
            })
        }
    }
}

/// Python `str.splitlines()`: line boundaries are more than LF (a lone CR, VT, FF, FS, GS, RS, NEL, LS, PS).
pub fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        let boundary = matches!(
            c,
            '\n' | '\r'
                | '\x0b'
                | '\x0c'
                | '\x1c'
                | '\x1d'
                | '\x1e'
                | '\u{85}'
                | '\u{2028}'
                | '\u{2029}'
        );
        if !boundary {
            continue;
        }
        let mut end = i + c.len_utf8();
        if c == '\r'
            && let Some(&(_, '\n')) = chars.peek()
        {
            chars.next();
            end += 1;
        }
        lines.push(&text[start..i]);
        start = end;
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// Python `DeferDecompile`: the decompile needs the engine's long path and so runs as a job.
#[derive(Debug, thiserror::Error)]
#[error("{reason}")]
pub struct DeferDecompile {
    pub reason: String,
}

/// What `engine_decompile` can end in besides an answer.
#[derive(Debug, thiserror::Error)]
pub enum DecompileError {
    #[error("{0}")]
    Defer(#[from] DeferDecompile),
    /// Python `TypeError` (an `int()` of a value that is not a number or a string).
    #[error("{0}")]
    Type(String),
    /// Python `ValueError` (an `int()` of a malformed string).
    #[error("{0}")]
    Value(String),
    /// A shape this port does not model (a non-ASCII digit string, an integer past 64 bits): the caller runs the original.
    #[error("unsupported: {0}")]
    Unsupported(String),
}

impl DecompileError {
    /// The reason of a deferral.
    pub fn reason(&self) -> Option<&str> {
        match self {
            DecompileError::Defer(d) => Some(&d.reason),
            _ => None,
        }
    }
}

/// Python `int(value)` for a JSON value.
pub fn py_int(v: &Value) -> Result<i64, DecompileError> {
    let unsupported = |what: &str| DecompileError::Unsupported(what.to_string());
    match v {
        Value::Bool(b) => Ok(i64::from(*b)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i)
            } else if n.is_u64() {
                Err(unsupported("integer past 64 bits"))
            } else {
                let f = n.as_f64().unwrap_or(0.0).trunc();
                if f.is_finite() && f.abs() < 9.0e18 {
                    Ok(f as i64)
                } else {
                    Err(unsupported("float past 64 bits"))
                }
            }
        }
        Value::String(text) => {
            let t = text.trim();
            let digits = t.strip_prefix(['+', '-']).unwrap_or(t);
            let well_formed = !digits.is_empty()
                && !digits.starts_with('_')
                && !digits.ends_with('_')
                && !digits.contains("__")
                && digits.bytes().all(|b| b.is_ascii_digit() || b == b'_');
            if well_formed {
                let clean: String = t.chars().filter(|c| *c != '_').collect();
                return clean
                    .parse::<i64>()
                    .map_err(|_| unsupported("integer past 64 bits"));
            }
            if text.is_ascii()
                && !text.contains(['\'', '\\'])
                && !text.chars().any(char::is_control)
            {
                return Err(DecompileError::Value(format!(
                    "invalid literal for int() with base 10: '{text}'"
                )));
            }
            Err(unsupported("malformed number text"))
        }
        other => {
            let kind = match other {
                Value::Null => "NoneType",
                Value::Array(_) => "list",
                _ => "dict",
            };
            Err(DecompileError::Type(format!(
                "int() argument must be a string, a bytes-like object or a real number, not '{kind}'"
            )))
        }
    }
}

/// `engine_decompile`: RESPONSE of a decompile, completed with the engine's own `decompile` answer where that carries more.
pub fn engine_decompile(
    engine: &dyn Engine,
    program_key: &str,
    request: &Value,
    timeout_s: i64,
    response: &Value,
    inline: bool,
) -> Result<Value, DecompileError> {
    if request.get("action").and_then(Value::as_str) != Some("decompile") {
        return Ok(response.clone());
    }
    let empty = Map::new();
    let options = request
        .get("options")
        .and_then(Value::as_object)
        .filter(|o| !o.is_empty())
        .unwrap_or(&empty);
    let mut explicit = Map::new();
    for (name, engine_name) in ENGINE_FIELDS {
        if let Some(v) = options.get(name).filter(|v| !v.is_null()) {
            explicit.insert(engine_name.into(), v.clone());
        }
    }
    let failed = response.get("ok") == Some(&Value::Bool(false));
    if explicit.is_empty() && !failed {
        return Ok(response.clone());
    }
    let reason: String = if failed {
        let text = response
            .get("error")
            .filter(|v| truthy(v))
            .or_else(|| response.get("message").filter(|v| truthy(v)))
            .map_or_else(String::new, py_str);
        text.chars().take(600).collect()
    } else {
        String::new()
    };
    if failed && !inline {
        return Err(DeferDecompile {
            reason: if reason.is_empty() {
                "the script could not decompile".into()
            } else {
                reason
            },
        }
        .into());
    }
    let max_chars = match options.get("max_characters") {
        None => 32000,
        Some(v) => py_int(v)?,
    };
    let timeout = if failed {
        FALLBACK_TIMEOUT_S
    } else {
        timeout_s + 5
    };
    let started = Instant::now();
    let mut fields = Map::new();
    fields.insert("program".into(), json!(program_key));
    fields.insert(
        "address".into(),
        request.get("address").cloned().unwrap_or(Value::Null),
    );
    fields.insert("timeout".into(), json!(timeout));
    fields.insert("maxChars".into(), json!(max_chars));
    for (k, v) in explicit {
        fields.insert(k, v);
    }
    let reply = match engine.call("decompile", &fields) {
        Ok(r) => r,
        Err(error) => {
            let slow = matches!(error.code.as_str(), "timeout" | "deadline" | "timed_out")
                || error
                    .details
                    .get("reason")
                    .map_or_else(String::new, py_str)
                    .to_lowercase()
                    .contains("timeout")
                || error.message.to_lowercase().contains("timed out");
            if inline || !slow {
                // a refusal keeps the script's answer; only a clock that ran out becomes a job
                return Ok(response.clone());
            }
            let text: String = error.text.chars().take(300).collect();
            return Err(DeferDecompile {
                reason: format!("the engine decompile did not answer in {timeout} s: {text}"),
            }
            .into());
        }
    };
    match decompile::merge(response, &reply) {
        None => Ok(response.clone()),
        Some(mut merged) => {
            if failed && let Some(m) = merged.as_object_mut() {
                let secs = (started.elapsed().as_secs_f64() * 10.0).round() / 10.0;
                m.insert(
                    "fallback".into(),
                    json!({"via": "engine_decompile", "reason": reason, "engine_s": secs, "timeout_s": timeout}),
                );
            }
            Ok(merged)
        }
    }
}

/// Wait for a condition with a bounded sleep (test helper kept here so tests share one definition).
pub fn wait_until(limit: Duration, mut done: impl FnMut() -> bool) -> bool {
    let end = Instant::now() + limit;
    while Instant::now() < end {
        if done() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    done()
}
