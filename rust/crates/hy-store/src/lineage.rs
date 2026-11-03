//! Lineage and generations (PROTOCOL-3.md 4.4), the port of `hydralysis.lineage`.
//!
//! The analysed project in place is generation 0, never written; a commit makes generation N as a new, verified,
//! sealed project folder, and one append-only log, `CURRENT.log`, says which generation is the head.
//!
//! ```text
//! lineages/<id>/lineage.json            {format, id, origin_key, origin_gpr, program, sha256, createdAt}
//! lineages/<id>/CURRENT.log             CRC-framed lines (AppendLog); the head is the last valid line
//! lineages/<id>/commits/<cid>.intent.log
//! lineages/<id>/backups.log
//! lineages/<id>/gen/0002/<project>/...  a generation, invisible until its MANIFEST.json verifies
//! lineages/<id>/.commit.lock            OS lock: one commit per lineage
//! ```

use crate::config::{self, dumps_sorted, now_iso, py_str, py_truthy, read_json, root_path, unix_now, write_json};
use hy_core::appendlog::AppendLog;
use hy_core::fsio::{atomic_write_point, with_suffix};
use hy_core::json;
use hy_core::sealed::{LOCK_TIMEOUT_S, sha256_hex};
use hy_core::{Error as CoreError, lock};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

pub const FORMAT: i64 = 1;
pub const MANIFEST: &str = "MANIFEST.json";
pub const SEAL_MARKER: &str = "SEALED.json";
pub const TAMPER_CACHE_NAME: &str = ".tamper-checks.json";
pub const TAMPERED_CACHE_S: f64 = 0.0;
const EXCLUDED_NAMES: [&str; 4] = [MANIFEST, SEAL_MARKER, "projectState", "backup.json"];

/// A lineage refusal with a stable `code` (`lineage_corrupt`, `no_lineage`, `format_unreadable`, ...).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct LineageError {
    pub code: String,
    pub message: String,
    pub detail: Map<String, Value>,
}

impl LineageError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        LineageError { code: code.into(), message: message.into(), detail: Map::new() }
    }

    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.detail.insert(key.into(), value);
        self
    }

    pub fn payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("error".into(), Value::String(self.code.clone()));
        map.insert("message".into(), Value::String(self.message.clone()));
        for (k, v) in &self.detail {
            map.insert(k.clone(), v.clone());
        }
        Value::Object(map)
    }
}

/// A backup refusal with a stable `code` (`confirm_large_backup`, `backup_failed`, `backup_verify_failed`, ...).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{message}")]
pub struct BackupError {
    pub code: String,
    pub message: String,
    pub detail: Map<String, Value>,
}

impl BackupError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        BackupError { code: code.into(), message: message.into(), detail: Map::new() }
    }

    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.detail.insert(key.into(), value);
        self
    }

    pub fn payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("error".into(), Value::String(self.code.clone()));
        map.insert("message".into(), Value::String(self.message.clone()));
        for (k, v) in &self.detail {
            map.insert(k.clone(), v.clone());
        }
        Value::Object(map)
    }
}

/// The storage layer's error: every Python exception class the ported modules raise or let through.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Lineage(#[from] LineageError),
    #[error("{0}")]
    Backup(#[from] BackupError),
    /// `hydra.EngineError` from a pluggable engine (backups).
    #[error("{message}")]
    Engine { code: String, message: String },
    #[error("{0}")]
    Core(#[from] CoreError),
}

impl From<std::io::Error> for Error {
    fn from(error: std::io::Error) -> Self {
        Error::Core(error.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;

fn value_err(message: &str) -> Error {
    Error::Core(CoreError::value(message))
}

// ----------------------------------------------------------------------------------------------- canonical form

/// UTF-8, no whitespace, sorted keys (PROTOCOL-3.md 3.4 / 4.1).
pub fn canonical(value: &Value) -> Vec<u8> {
    json::canonical(value)
}

pub fn fileset_sha256(files: &[Value]) -> String {
    sha256_hex(&canonical(&Value::Array(files.to_vec())))
}

pub fn self_hash(manifest: &Value) -> String {
    let body: Map<String, Value> = manifest
        .as_object()
        .map(|m| m.iter().filter(|(k, _)| *k != "selfSha256").map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    sha256_hex(&canonical(&Value::Object(body)))
}

// ------------------------------------------------------------------------------------------------------ layout

fn valid_lineage_id(text: &str) -> bool {
    text.len() == 10 && text.starts_with("L-") && text[2..].bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub fn lineages_root(settings: &Value) -> Result<PathBuf> {
    let base = match settings.get("generations_root").filter(|v| py_truthy(v)) {
        Some(v) => PathBuf::from(py_str(v)),
        None => root_path(settings)?,
    };
    Ok(base.join("lineages"))
}

pub fn lineage_dir(settings: &Value, lineage_id: &str) -> Result<PathBuf> {
    if !valid_lineage_id(lineage_id) {
        return Err(value_err("invalid lineage id"));
    }
    Ok(lineages_root(settings)?.join(lineage_id))
}

pub fn generation_dir(settings: &Value, lineage_id: &str, number: i64) -> Result<PathBuf> {
    Ok(lineage_dir(settings, lineage_id)?.join("gen").join(format!("{number:04}")))
}

fn log_with(path: PathBuf, by: &str) -> AppendLog {
    let mut log = AppendLog::new(path);
    log.by = by.to_string();
    log
}

pub fn current_log(settings: &Value, lineage_id: &str) -> Result<AppendLog> {
    Ok(log_with(lineage_dir(settings, lineage_id)?.join("CURRENT.log"), "lineage"))
}

pub fn intent_log(settings: &Value, lineage_id: &str, cid: &str) -> Result<AppendLog> {
    let ok =
        cid.strip_prefix("c-").is_some_and(|h| (4..=16).contains(&h.len()) && h.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
    if !ok {
        return Err(value_err("invalid commit id"));
    }
    Ok(log_with(lineage_dir(settings, lineage_id)?.join("commits").join(format!("{cid}.intent.log")), "commit"))
}

pub fn backups_log(settings: &Value, lineage_id: &str) -> Result<AppendLog> {
    Ok(log_with(lineage_dir(settings, lineage_id)?.join("backups.log"), "backups"))
}

pub fn commit_lock_path(settings: &Value, lineage_id: &str) -> Result<PathBuf> {
    Ok(lineage_dir(settings, lineage_id)?.join(".commit.lock"))
}

// -------------------------------------------------------------------------------------- creation and lookup

fn dir_sort_key(name: &str) -> String {
    if cfg!(windows) { name.to_lowercase() } else { name.to_string() }
}

/// Directory entries sorted like Python's `sorted(path.iterdir())` (case-folded on Windows).
pub fn sorted_entries(dir: &Path) -> Vec<PathBuf> {
    let mut items: Vec<PathBuf> = fs::read_dir(dir).map(|rd| rd.filter_map(|e| e.ok().map(|e| e.path())).collect()).unwrap_or_default();
    items.sort_by_key(|p| dir_sort_key(&p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()));
    items
}

/// The lineage of an origin key, from the lineage folders themselves (the registry is only a cache).
pub fn find(settings: &Value, origin_key: &str) -> Result<Option<String>> {
    let root = lineages_root(settings)?;
    if !root.is_dir() {
        return Ok(None);
    }
    for folder in sorted_entries(&root) {
        let name = folder.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        if valid_lineage_id(&name) {
            let record = read_json(&folder.join("lineage.json"))?;
            if record.get("origin_key").and_then(Value::as_str) == Some(origin_key) {
                return Ok(Some(name));
            }
        }
    }
    Ok(None)
}

pub fn load(settings: &Value, lineage_id: &str) -> Result<Map<String, Value>> {
    let record = read_json(&lineage_dir(settings, lineage_id)?.join("lineage.json"))?;
    if record.is_empty() {
        return Err(LineageError::new("no_lineage", format!("lineage {lineage_id} has no lineage.json")).into());
    }
    if let Some(format) = record.get("format").and_then(Value::as_i64).filter(|f| *f > FORMAT) {
        return Err(
            LineageError::new("format_unreadable", format!("lineage.json has format {format}; this Hydralysis reads {FORMAT}")).into()
        );
    }
    Ok(record)
}

/// The mirror of a lineage into `targets.json` (a cache), supplied by the targets module.
pub trait TargetRegistry {
    /// The registry row of target NAME, if it has one.
    fn registered(&self, settings: &Value, name: &str) -> Option<Value>;
    /// `targets.register(settings, [name], row)`.
    fn register(&self, settings: &Value, name: &str, row: Value) -> Result<()>;
}

/// The lineage of TARGET (a resolved target), created at the first commit with generation 0 registered. Idempotent.
pub fn ensure(settings: &Value, target: &Value, registry: Option<&dyn TargetRegistry>) -> Result<Map<String, Value>> {
    let origin = match target.get("origin_key").filter(|v| py_truthy(v)) {
        Some(v) => py_str(v),
        None => py_str(&target["key"]),
    };
    let root = lineages_root(settings)?;
    fs::create_dir_all(&root)?;
    let lock_name = format!(".create.{}.lock", &sha256_hex(origin.as_bytes())[..24]);
    let _guard = lock::lock(&root.join(lock_name), LOCK_TIMEOUT_S, "lineage creation")?;
    let lineage_id = match find(settings, &origin)? {
        Some(id) => id,
        None => {
            let id = format!("L-{}", &uuid::Uuid::new_v4().simple().to_string()[..8]);
            let folder = lineage_dir(settings, &id)?;
            fs::create_dir_all(folder.parent().unwrap_or(&folder))?;
            fs::create_dir(&folder)?;
            write_json(
                &folder.join("lineage.json"),
                &json!({"format": FORMAT, "id": id, "origin_key": origin, "origin_gpr": target["gpr"], "program": target["program"],
                        "sha256": target["sha256"], "createdAt": now_iso()}),
            )?;
            id
        }
    };
    if current_log(settings, &lineage_id)?.last(false)?.is_none() {
        let gpr = load(settings, &lineage_id)?.get("origin_gpr").cloned().unwrap_or(Value::Null);
        append_current(
            settings,
            &lineage_id,
            &json!({"gen": 0, "cid": null, "reason": "register", "gpr": gpr, "manifestSha256": null, "engine": null}),
            false,
        )?;
    }
    if let Some(registry) = registry {
        register(settings, target, &lineage_id, &origin, registry)?;
    }
    load(settings, &lineage_id)
}

/// Mirror the lineage into targets.json (a cache; a crash before this is harmless).
pub fn register(settings: &Value, target: &Value, lineage_id: &str, origin: &str, registry: &dyn TargetRegistry) -> Result<()> {
    let name = py_str(&target["name"]);
    let Some(registered) = registry.registered(settings, &name) else { return Ok(()) };
    if registered.get("lineage").and_then(|l| l.get("id")).and_then(Value::as_str) == Some(lineage_id) {
        return Ok(());
    }
    let mut row = registered.as_object().cloned().unwrap_or_default();
    row.insert("lineage".into(), json!({"id": lineage_id, "origin_key": origin}));
    registry.register(settings, &name, Value::Object(row))
}

// --------------------------------------------------------------------------------------------------- CURRENT.log

/// Append one CURRENT.log line (the commit point of a publish). Fills `seq`, `at` and `prevHash`.
pub fn append_current(settings: &Value, lineage_id: &str, record: &Value, lock_held: bool) -> Result<Value> {
    let log = current_log(settings, lineage_id)?;
    let build = || -> Result<Value> {
        let previous = log.last(true)?;
        let seq = match &previous {
            Some(p) => p.get("seq").and_then(Value::as_i64).ok_or_else(|| value_err("KeyError: 'seq'"))? + 1,
            None => 1,
        };
        let mut line = Map::new();
        line.insert("seq".into(), Value::from(seq));
        if let Some(fields) = record.as_object() {
            for (k, v) in fields {
                line.insert(k.clone(), v.clone());
            }
        }
        line.insert("at".into(), Value::String(now_iso()));
        line.insert("prevHash".into(), previous.as_ref().map_or(Value::Null, |p| Value::String(sha256_hex(&canonical(p)))));
        let line = Value::Object(line);
        log.append(&line, true)?;
        Ok(line)
    };
    if lock_held {
        return build();
    }
    let _guard = lock::lock(&log.lock_path, log.lock_timeout_s, "log CURRENT.log")?;
    // The writer's tail check runs inside append(); read the previous line only after it, under the same hold.
    log.repair(true)?;
    build()
}

fn torn_corrupt(log: &AppendLog) -> Result<(hy_core::appendlog::Scan, Value, Value)> {
    let scan = log.scan()?;
    let status = scan.as_status();
    let torn = status["torn_tail"].clone();
    let corrupt = status["corrupt"].clone();
    Ok((scan, torn, corrupt))
}

/// The head: the last valid CURRENT.log line, with what the reader saw (`torn_tail`, `corrupt`, `lines`).
///
/// A reader never repairs. A torn tail shows an older, consistent state; a mid-log gap resolves to the last good
/// line before it and says so (`corrupt`).
pub fn head(settings: &Value, lineage_id: &str) -> Result<Map<String, Value>> {
    let log = current_log(settings, lineage_id)?;
    let (scan, torn, corrupt) = torn_corrupt(&log)?;
    let Some(last) = scan.records.last() else {
        return Err(LineageError::new("no_lineage", format!("lineage {lineage_id} has no valid CURRENT.log line"))
            .with("torn_tail", torn)
            .with("corrupt", corrupt)
            .into());
    };
    let empty = Map::new();
    let fields = last.as_object().unwrap_or(&empty);
    for field in ["seq", "gen", "gpr"] {
        if !fields.contains_key(field) {
            return Err(LineageError::new("lineage_corrupt", format!("a CURRENT.log line has no {field}")).into());
        }
    }
    let mut result = fields.clone();
    result.insert("torn_tail".into(), torn);
    result.insert("corrupt".into(), corrupt);
    result.insert("lines".into(), Value::from(scan.records.len()));
    Ok(result)
}

pub fn history(settings: &Value, lineage_id: &str) -> Result<Vec<Value>> {
    Ok(current_log(settings, lineage_id)?.scan()?.records)
}

/// What `targets.resolve` changes for a target with a lineage: `gpr` is the head, `key` the stored origin key.
pub fn resolve(settings: &Value, item: &Value) -> Result<Value> {
    let Some(link) = item.get("lineage").filter(|v| py_truthy(v)) else { return Ok(json!({})) };
    let top = match head(settings, link["id"].as_str().unwrap_or("")) {
        Ok(top) => top,
        Err(Error::Lineage(_)) => return Ok(json!({})),
        Err(other) => return Err(other),
    };
    Ok(json!({
        "gpr": top["gpr"], "key": link["origin_key"],
        "lineage": {"id": link["id"], "origin_key": link["origin_key"], "generation": top["gen"],
                    "cid": top.get("cid").cloned().unwrap_or(Value::Null), "reason": top.get("reason").cloned().unwrap_or(Value::Null)},
        "adopted_gpr": item.get("gpr").cloned().unwrap_or(Value::String(String::new())),
    }))
}

// ---------------------------------------------------------------------------- generations: files, manifests

fn excluded(path: &Path) -> bool {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    EXCLUDED_NAMES.contains(&name.as_str()) || name.ends_with(".lock") || name.ends_with(".lock~")
}

/// `(size, sha256)` of what the manifest records for PATH.
fn file_hash(path: &Path) -> std::io::Result<(u64, String)> {
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if name.ends_with(".fork.json") {
        // The sidecar's lifecycle `state` changes at seal time, so size and hash are taken without it (4.6 step 7).
        let record = fs::read(path).ok().and_then(|b| json::loads(&b).ok());
        if let Some(Value::Object(record)) = record {
            let body: Map<String, Value> = record.into_iter().filter(|(k, _)| k != "state").collect();
            let bytes = canonical(&Value::Object(body));
            return Ok((bytes.len() as u64, sha256_hex(&bytes)));
        }
    }
    let mut digest = Sha256::new();
    let mut handle = fs::File::open(path)?;
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = handle.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        digest.update(&buffer[..n]);
    }
    let size = handle.metadata()?.len();
    Ok((size, hex(&digest.finalize())))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Every file under DIR (symlinked files count, symlinked directories are not entered), like `Path.rglob("*")` + `is_file()`.
pub fn walk_files(dir: &Path) -> std::io::Result<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(current) = stack.pop() {
        for entry in fs::read_dir(&current)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else if kind.is_file() || (kind.is_symlink() && entry.path().is_file()) {
                out.push(entry.path());
            }
        }
    }
    Ok(out)
}

fn rel_posix(folder: &Path, path: &Path) -> String {
    path.strip_prefix(folder)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// `[{path, size, sha256}]` for every content file under FOLDER, sorted by path (forward slashes).
pub fn tree_files(folder: &Path) -> Result<Vec<Value>> {
    let mut rows: Vec<(String, Value)> = Vec::new();
    for path in walk_files(folder)? {
        if excluded(&path) {
            continue;
        }
        let (size, digest) = file_hash(&path)?;
        let rel = rel_posix(folder, &path);
        rows.push((rel.clone(), json!({"path": rel, "size": size, "sha256": digest})));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(rows.into_iter().map(|(_, v)| v).collect())
}

/// The oracle's tree hash (O1): the fileset hash of the folder.
pub fn tree_hash(folder: &Path) -> Result<String> {
    Ok(fileset_sha256(&tree_files(folder)?))
}

pub fn project_folder_of(gpr: &str) -> PathBuf {
    Path::new(gpr).parent().map(Path::to_path_buf).unwrap_or_default()
}

/// Write MANIFEST.json (forced, write-through replace) with its fileset and self hashes. Returns the manifest.
pub fn write_manifest(folder: &Path, body: &Value) -> Result<Value> {
    let files = tree_files(folder)?;
    let mut manifest = Map::new();
    manifest.insert("format".into(), Value::from(FORMAT));
    if let Some(fields) = body.as_object() {
        for (k, v) in fields {
            manifest.insert(k.clone(), v.clone());
        }
    }
    let fileset = fileset_sha256(&files);
    manifest.insert("files".into(), Value::Array(files));
    manifest.insert("filesetSha256".into(), Value::String(fileset));
    let mut manifest = Value::Object(manifest);
    let digest = self_hash(&manifest);
    manifest["selfSha256"] = Value::String(digest);
    atomic_write_point(&folder.join(MANIFEST), &canonical(&manifest), "manifest", true)?;
    Ok(manifest)
}

pub fn read_manifest(folder: &Path) -> Option<Value> {
    let data = fs::read(folder.join(MANIFEST)).ok()?;
    let manifest = json::loads(&data).ok()?;
    manifest.is_object().then_some(manifest)
}

pub fn manifest_file_sha256(folder: &Path) -> Option<String> {
    fs::read(folder.join(MANIFEST)).ok().map(|b| sha256_hex(&b))
}

/// An ordered `dict` of `row["path"] -> row` as Python builds it (a later duplicate replaces the value in place).
pub fn by_path(rows: &[Value]) -> Map<String, Value> {
    let mut map = Map::new();
    for row in rows {
        if let Some(path) = row.get("path").and_then(Value::as_str) {
            map.insert(path.to_string(), row.clone());
        }
    }
    map
}

fn as_rows(value: Option<&Value>) -> Vec<Value> {
    match value {
        Some(Value::Array(rows)) => rows.clone(),
        _ => Vec::new(),
    }
}

/// Re-hash every file against MANIFEST.json. `ok` is false when the manifest is missing or invalid, a file differs,
/// a file is missing, or an unlisted file appeared (`tampered`).
pub fn verify_manifest(folder: &Path) -> Result<Value> {
    let Some(manifest) = read_manifest(folder) else {
        return Ok(json!({"ok": false, "problems": ["no valid MANIFEST.json"], "manifest": null}));
    };
    let mut problems: Vec<String> = Vec::new();
    if let Some(format) = manifest.get("format").and_then(Value::as_i64).filter(|f| *f > FORMAT) {
        problems.push(format!("manifest format {format} is newer than {FORMAT} (format_unreadable)"));
    }
    if manifest.get("selfSha256").and_then(Value::as_str) != Some(self_hash(&manifest).as_str()) {
        problems.push("selfSha256 does not match".into());
    }
    let files = as_rows(manifest.get("files"));
    if manifest.get("filesetSha256").and_then(Value::as_str) != Some(fileset_sha256(&files).as_str()) {
        problems.push("filesetSha256 does not match the files list".into());
    }
    let listed = by_path(&files);
    let actual = by_path(&tree_files(folder)?);
    for (path, row) in &listed {
        match actual.get(path) {
            None => problems.push(format!("missing file {path}")),
            Some(found) if found["sha256"] != row["sha256"] || found["size"] != row["size"] => {
                problems.push(format!("changed file {path}"))
            }
            Some(_) => {}
        }
    }
    for path in actual.keys() {
        if !listed.contains_key(path) {
            problems.push(format!("unlisted file {path}"));
        }
    }
    let ok = problems.is_empty();
    problems.truncate(20);
    Ok(json!({"ok": ok, "problems": problems, "manifest": manifest}))
}

/// Every generation number that must never be reused: the log, the intent logs' reservations, and any folder.
pub fn reserved_generations(settings: &Value, lineage_id: &str) -> Result<BTreeSet<i64>> {
    let mut taken: BTreeSet<i64> = history(settings, lineage_id)?.iter().filter_map(|r| r.get("gen").and_then(Value::as_i64)).collect();
    let dir = lineage_dir(settings, lineage_id)?;
    let commits = dir.join("commits");
    if commits.is_dir() {
        for path in sorted_entries(&commits) {
            if path.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".intent.log")) {
                for record in AppendLog::new(path).scan()?.records {
                    if let Some(g) = record.get("gen").and_then(Value::as_i64) {
                        taken.insert(g);
                    }
                }
            }
        }
    }
    let gen_dir = dir.join("gen");
    if gen_dir.is_dir() {
        for path in sorted_entries(&gen_dir) {
            let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
            if !name.is_empty()
                && name.bytes().all(|b| b.is_ascii_digit())
                && let Ok(n) = name.parse::<i64>()
            {
                taken.insert(n);
            }
        }
    }
    Ok(taken)
}

pub fn next_generation(settings: &Value, lineage_id: &str) -> Result<i64> {
    Ok(reserved_generations(settings, lineage_id)?.into_iter().max().unwrap_or(0).max(0) + 1)
}

/// The head generation's manifest verifies (generation 0 has none: it is the adopted project, never written).
pub fn verify_head(settings: &Value, lineage_id: &str) -> Result<Value> {
    let top = head(settings, lineage_id)?;
    let generation = top["gen"].clone();
    if generation.as_i64() == Some(0) {
        return Ok(json!({"ok": true, "generation": 0, "problems": []}));
    }
    let folder = project_folder_of(top["gpr"].as_str().unwrap_or(""));
    let result = verify_manifest(&folder)?;
    let mut ok = result["ok"].as_bool().unwrap_or(false);
    let mut problems = result["problems"].clone();
    let named = if result["manifest"].is_null() { None } else { manifest_file_sha256(&folder) };
    if ok
        && let Some(wanted) = top.get("manifestSha256").filter(|v| py_truthy(v))
        && named.as_deref() != wanted.as_str()
    {
        ok = false;
        problems = json!(["the manifest is not the one CURRENT.log names"]);
    }
    Ok(json!({"ok": ok, "generation": generation, "problems": problems}))
}

// ----------------------------------------------------------------------------------------------- tamper cache

/// `(volume serial, file id)` of an existing file or directory, as `os.stat` reports `st_dev` and `st_ino`.
pub fn file_identity(path: &Path) -> Option<(u64, u64)> {
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, FILE_FLAG_BACKUP_SEMANTICS, GetFileInformationByHandle};
        let handle = fs::OpenOptions::new().access_mode(0).custom_flags(FILE_FLAG_BACKUP_SEMANTICS).open(path).ok()?;
        // SAFETY: zeroed plain-data struct filled by the call on a valid handle.
        let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
        // SAFETY: the handle stays open for the call.
        let ok = unsafe { GetFileInformationByHandle(handle.as_raw_handle(), &mut info) };
        (ok != 0).then(|| (u64::from(info.dwVolumeSerialNumber), (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow)))
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let meta = fs::metadata(path).ok()?;
        Some((meta.dev(), meta.ino()))
    }
}

fn mtime_ns(meta: &fs::Metadata) -> i128 {
    meta.modified().ok().and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos() as i128)
}

/// What a re-hash of FOLDER depends on, without reading the files: the manifest file's hash and, for every content
/// file, its path, size, modification time and file id. None when the folder cannot be listed.
fn tree_signature(folder: &Path) -> Option<Value> {
    let mut rows: Vec<(String, Value)> = Vec::new();
    for path in walk_files(folder).ok()? {
        if excluded(&path) {
            continue;
        }
        let meta = fs::metadata(&path).ok()?;
        let ino = file_identity(&path).map_or(0, |(_, i)| i);
        let rel = rel_posix(folder, &path);
        rows.push((rel.clone(), json!([rel, meta.len(), i64::try_from(mtime_ns(&meta)).unwrap_or(0), ino])));
    }
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    let manifest = manifest_file_sha256(folder).map_or(Value::Null, Value::String);
    Some(json!([manifest, rows.into_iter().map(|(_, v)| v).collect::<Vec<_>>()]))
}

fn tamper_cache_limit(settings: &Value) -> f64 {
    match settings.get("tampered_cache_s") {
        Some(Value::Number(n)) => n.as_f64().filter(|f| *f >= 0.0).unwrap_or(TAMPERED_CACHE_S),
        _ => TAMPERED_CACHE_S,
    }
}

fn read_tamper_cache(path: &Path) -> Map<String, Value> {
    fs::read(path).ok().and_then(|b| json::loads(&b).ok()).and_then(|v| v.as_object().cloned()).unwrap_or_default()
}

/// Best effort and not fsynced: losing it (or a race with another leader's write) only costs a re-hash.
fn write_tamper_cache(path: &Path, cache: &Map<String, Value>) {
    let temp = with_suffix(path, &format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let text = dumps_sorted(&Value::Object(cache.clone()));
    let outcome = fs::write(&temp, text).and_then(|()| fs::rename(&temp, path));
    if outcome.is_err() {
        let _ = fs::remove_file(&temp);
    }
}

fn cache_key(folder: &Path) -> String {
    config::resolved(folder).to_string_lossy().to_lowercase()
}

/// `verify_manifest(FOLDER)["problems"]`, re-hashed only when the folder changed (off unless `tampered_cache_s` > 0).
fn verified_problems(folder: &Path, cache: Option<&mut Map<String, Value>>, limit: f64) -> Result<Vec<Value>> {
    let key = cache_key(folder);
    let signature = if cache.is_some() { tree_signature(folder) } else { None };
    if let (Some(signature), Some(cache)) = (&signature, cache.as_deref())
        && let Some(Value::Array(cached)) = cache.get(&key)
        && cached.len() == 3
        && cached[0] == *signature
    {
        let age = unix_now() - cached[1].as_f64().unwrap_or(f64::NEG_INFINITY);
        if age >= 0.0 && age < limit {
            return Ok(cached[2].as_array().cloned().unwrap_or_default());
        }
    }
    let checked_at = unix_now();
    let check = verify_manifest(folder)?;
    let problems: Vec<Value> = if check["ok"].as_bool() == Some(true) { Vec::new() } else { as_rows(check.get("problems")) };
    // The signature is taken again after the hash: a file that changed while it was hashed does not leave a stale entry.
    if let (Some(signature), Some(cache)) = (signature, cache)
        && tree_signature(folder).as_ref() == Some(&signature)
    {
        cache.insert(key, json!([signature, checked_at, problems]));
    }
    Ok(problems)
}

/// Published generations whose folder no longer matches its manifest (4.7: a process wrote into one).
pub fn tampered(settings: &Value, lineage_id: &str) -> Result<Vec<Value>> {
    let limit = tamper_cache_limit(settings);
    let cache_path = lineage_dir(settings, lineage_id)?.join(TAMPER_CACHE_NAME);
    let mut cache = if limit > 0.0 { Some(read_tamper_cache(&cache_path)) } else { None };
    let before = cache.as_ref().map_or("null".to_string(), |c| dumps_sorted(&Value::Object(c.clone())));
    let mut found = Vec::new();
    let mut seen: BTreeSet<i64> = BTreeSet::new();
    for record in history(settings, lineage_id)? {
        let Some(generation) = record.get("gen").and_then(Value::as_i64).filter(|g| *g != 0) else { continue };
        let reason = record.get("reason").and_then(Value::as_str);
        if !seen.contains(&generation) && matches!(reason, Some("commit" | "recover")) {
            seen.insert(generation);
            let folder = project_folder_of(record.get("gpr").and_then(Value::as_str).unwrap_or(""));
            if folder.is_dir() {
                let problems = verified_problems(&folder, cache.as_mut(), limit)?;
                if !problems.is_empty() {
                    found.push(json!({"generation": generation, "problems": problems}));
                }
            }
        }
    }
    if let Some(cache) = &cache
        && dumps_sorted(&Value::Object(cache.clone())) != before
    {
        write_tamper_cache(&cache_path, cache);
    }
    Ok(found)
}

/// `ghidra_query action=status options.show=lineage`: where the head is and what is wrong with it.
pub fn status(settings: &Value, target: &Value) -> Result<Value> {
    let Some(link) = target.get("lineage").filter(|v| py_truthy(v)) else {
        return Ok(json!({"lineage": null, "generation": 0, "gpr": target["gpr"],
                         "note": "no commit has been made on this target; generation 0 is the adopted project, never written"}));
    };
    let id = link["id"].as_str().unwrap_or("");
    let top = match head(settings, id) {
        Ok(top) => top,
        Err(Error::Lineage(error)) => return Ok(json!({"lineage": id, "error": error.payload()})),
        Err(other) => return Err(other),
    };
    let rows = history(settings, id)?;
    let start = rows.len().saturating_sub(20);
    let generations: Vec<Value> = rows[start..]
        .iter()
        .map(|r| json!({"generation": r["gen"], "reason": r["reason"], "cid": r.get("cid").cloned().unwrap_or(Value::Null), "at": r.get("at").cloned().unwrap_or(Value::Null)}))
        .collect();
    let mut report = Map::new();
    let get = |k: &str| top.get(k).cloned().unwrap_or(Value::Null);
    report.insert("lineage".into(), json!(id));
    report.insert("origin_key".into(), link["origin_key"].clone());
    report.insert("generation".into(), top["gen"].clone());
    report.insert("gpr".into(), top["gpr"].clone());
    report.insert("cid".into(), get("cid"));
    report.insert("reason".into(), get("reason"));
    report.insert("seq".into(), top["seq"].clone());
    report.insert("engine".into(), get("engine"));
    report.insert("generations".into(), Value::Array(generations));
    report.insert("torn_tail".into(), top["torn_tail"].clone());
    report.insert("corrupt".into(), top["corrupt"].clone());
    if !top["corrupt"].is_null() {
        report.insert("error".into(), json!("lineage_corrupt"));
    }
    let problems = tampered(settings, id)?;
    if !problems.is_empty() {
        report.insert("tampered".into(), Value::Array(problems));
    }
    Ok(Value::Object(report))
}
