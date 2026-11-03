//! Backups of a lineage's head generation (PROTOCOL-3.md 4.5, 3.4, D28, D66), the port of `hydralysis.backups`.
//!
//! The client makes the backup: a fork of the source with `writable:false` into the backup folder, then every file
//! is re-hashed, `backup.json` is written last (the folder is invisible without one that verifies) and the copy is
//! sealed. The engine is pluggable through [`BackupEngine`]; everything else is ported here. Nothing deletes a
//! backup unless `remove` runs with `confirm: true`.

use crate::config::{dumps_indent2, now_iso, py_str, py_truthy, root_path};
use crate::lineage::{self, BackupError, Error, Result, SEAL_MARKER, backups_log, canonical, fileset_sha256, self_hash, tree_files};
use hy_core::fsio::atomic_write_point;
use hy_core::json;
use hy_core::sealed::{ReadOptions, Source, sha256_hex};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;

pub const FORMAT: i64 = 1;
pub const KIND: &str = "ghidra-session-backup";
pub const GIB: f64 = 1_073_741_824.0;
pub const ENGINE_BACKUP_CAPABILITY: &str = "backup";
pub const DEFAULTS: [(&str, i64); 4] =
    [("backup_min_verified", 1), ("backup_min_independent", 0), ("backup_confirm_gb", 50), ("backup_root_warn_gb", 200)];

/// The engine calls a backup needs (`hydra.Engine`); the engine lane plugs the real client in.
pub trait BackupEngine {
    /// `engine.call(command, **fields)`; an `Err(message)` is a `hydra.EngineError`.
    fn call(&self, command: &str, fields: Value) -> std::result::Result<Value, EngineFailure>;
    /// `engine.capabilities()`; an error means a hydra.2/3 engine.
    fn capabilities(&self) -> std::result::Result<Vec<String>, EngineFailure>;
    /// `engine.hello()`.
    fn hello(&self) -> Value;
    /// `hydra.identity()`: who is making the backup.
    fn identity(&self) -> Value;
}

#[derive(Debug, Clone)]
pub struct EngineFailure {
    pub code: String,
    pub message: String,
}

impl std::fmt::Display for EngineFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl From<EngineFailure> for Error {
    fn from(f: EngineFailure) -> Self {
        Error::Engine { code: f.code, message: f.message }
    }
}

fn value_err(message: impl Into<String>) -> Error {
    Error::Core(hy_core::Error::value(message))
}

// -------------------------------------------------------------------------------------------------------- policy

fn number_of(value: &Value) -> Option<f64> {
    match value {
        Value::Number(n) => n.as_f64(),
        _ => None,
    }
}

pub fn policy(settings: &Value) -> Result<Value> {
    let configured = settings.get("backup_roots").filter(|v| py_truthy(v)).cloned();
    let roots: Vec<Value> = match configured {
        Some(Value::Array(items)) => items,
        Some(other) => vec![other],
        None => vec![json!({"path": root_path(settings)?.join("backups").to_string_lossy(), "mode": "auto", "required": true})],
    };
    let mut clean = Vec::new();
    for (index, item) in roots.into_iter().enumerate() {
        let item = if let Value::String(path) = &item { json!({"path": path}) } else { item };
        let Some(path) = item.as_object().and_then(|o| o.get("path")).filter(|v| py_truthy(v)) else {
            return Err(value_err("backup_roots entries need a path"));
        };
        let mode = item.get("mode").cloned().unwrap_or_else(|| json!("auto"));
        if !matches!(mode.as_str(), Some("auto" | "copy")) {
            return Err(value_err("backup_roots mode must be auto or copy"));
        }
        // The first root is the primary; a secondary root is always a full copy (a clone shares blocks with its source).
        let required = item.get("required").map_or(index == 0, py_truthy);
        clean.push(json!({"path": py_str(path), "mode": if index == 0 { mode } else { json!("copy") }, "required": required}));
    }
    let mut result = Map::new();
    result.insert("roots".into(), Value::Array(clean));
    for (key, default) in DEFAULTS {
        let value = settings.get(key).cloned().unwrap_or_else(|| json!(default));
        if number_of(&value).is_none_or(|n| n < 0.0) {
            return Err(value_err(format!("{key} must be a non-negative number")));
        }
        result.insert(key.into(), value);
    }
    Ok(Value::Object(result))
}

pub fn size_of(folder: &Path) -> u64 {
    lineage::walk_files(folder).map(|files| files.iter().filter_map(|f| fs::metadata(f).ok()).map(|m| m.len()).sum()).unwrap_or(0)
}

/// `<stamp>-<revision[:8]>-<purpose>`.
pub fn backup_id(revision: &str, purpose: &str, when: Option<f64>) -> String {
    let secs = when.unwrap_or_else(crate::config::unix_now) as i64;
    let (y, mo, d, h, mi, s) = crate::config::gmtime(secs);
    let revision = if revision.is_empty() { "unknown" } else { revision };
    let short: String = revision.chars().take(8).collect();
    format!("{y:04}{mo:02}{d:02}T{h:02}{mi:02}{s:02}Z-{short}-{purpose}")
}

fn volume(path: &Path) -> Option<u64> {
    let mut probe = path.to_path_buf();
    while !probe.exists() {
        match probe.parent() {
            Some(parent) if parent != probe => probe = parent.to_path_buf(),
            _ => break,
        }
    }
    lineage::file_identity(&probe).map(|(v, _)| v)
}

/// Make FOLDER and everything under it writable (best effort), so it can be removed.
fn writable_tree(folder: &Path) {
    fn make(path: &Path) {
        if let Ok(meta) = fs::metadata(path) {
            let mut perms = meta.permissions();
            #[allow(clippy::permissions_set_readonly_false)]
            perms.set_readonly(false);
            let _ = fs::set_permissions(path, perms);
        }
    }
    make(folder);
    if let Ok(entries) = fs::read_dir(folder) {
        for entry in entries.flatten() {
            let path = entry.path();
            if entry.file_type().is_ok_and(|t| t.is_dir()) {
                writable_tree(&path);
            } else {
                make(&path);
            }
        }
    }
}

#[cfg(windows)]
fn free_bytes(path: &Path) -> Option<u64> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;
    let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
    wide.push(0);
    let mut free = 0u64;
    // SAFETY: wide is NUL-terminated; the out pointer is valid; the other two are optional.
    let ok = unsafe { GetDiskFreeSpaceExW(wide.as_ptr(), &mut free, std::ptr::null_mut(), std::ptr::null_mut()) };
    (ok != 0).then_some(free)
}

#[cfg(not(windows))]
fn free_bytes(_path: &Path) -> Option<u64> {
    None
}

// ----------------------------------------------------------------------------------------------------- the log

pub fn logged(settings: &Value, lineage_id: &str) -> Result<Vec<Value>> {
    Ok(backups_log(settings, lineage_id)?.scan()?.records)
}

/// Logical bytes of the lineage's verified backups under ROOT, from backups.log.
pub fn cumulative(settings: &Value, lineage_id: &str, root: &str) -> Result<u64> {
    Ok(logged(settings, lineage_id)?
        .iter()
        .filter(|row| row.get("root").and_then(Value::as_str) == Some(root) && !row.get("removed").is_some_and(py_truthy))
        .map(|row| row.get("bytes").map_or(0, |b| b.as_i64().or_else(|| b.as_f64().map(|f| f as i64)).unwrap_or(0)).max(0) as u64)
        .sum())
}

/// What a backup would cost, with the cumulative figures the confirmation text must state (4.5).
pub fn preview(settings: &Value, lineage_id: &str, source_gpr: &str) -> Result<Value> {
    let wanted = policy(settings)?;
    let size = size_of(&lineage::project_folder_of(source_gpr));
    let confirm_gb = number_of(&wanted["backup_confirm_gb"]).unwrap_or(0.0);
    let warn_gb = number_of(&wanted["backup_root_warn_gb"]).unwrap_or(0.0);
    let mut rows = Vec::new();
    for root in wanted["roots"].as_array().cloned().unwrap_or_default() {
        let path = root["path"].as_str().unwrap_or("");
        let base = PathBuf::from(path);
        let probe = if base.exists() { base.clone() } else { base.parent().map(Path::to_path_buf).unwrap_or_default() };
        let free = free_bytes(&probe);
        let before = cumulative(settings, lineage_id, path)?;
        rows.push(json!({
            "root": path, "mode": root["mode"], "required": root["required"], "this_backup_bytes": size,
            "cumulative_bytes_before": before, "cumulative_bytes_after": before + size, "free_bytes": free,
            "warn": ((before + size) as f64) > warn_gb * GIB,
            "note": if root["mode"] == "auto" { "a block clone's logical size overstates the physical blocks it adds" } else { "a full copy" },
        }));
    }
    Ok(
        json!({"bytes": size, "confirm_gb": wanted["backup_confirm_gb"], "needs_confirmation": (size as f64) > confirm_gb * GIB, "roots": rows}),
    )
}

// -------------------------------------------------------------------------------------------------- making one

/// A fork of the source that holds nothing open for writing (`writable:false`).
fn fork_into(settings: &Value, engine: &dyn BackupEngine, source_gpr: &str, destination: &Path, mode: &str) -> Result<Value> {
    let max_copy = settings.get("fork_max_copy_mb").and_then(Value::as_i64).unwrap_or(8192);
    let fields = json!({"project": source_gpr, "path": destination.to_string_lossy(), "writable": false,
                        "mode": if matches!(mode, "auto" | "copy") { mode } else { "auto" }, "maxCopyMb": max_copy});
    let forked = engine.call("fork_project", fields)?;
    let _ = engine.call("close_project", json!({"project": forked["project"]}));
    Ok(forked)
}

/// Where the project files of a backup live: `<folder>/project` for the client's writer, the folder itself for the engine's.
pub fn project_dir(folder: &Path) -> PathBuf {
    let nested = folder.join("project");
    if nested.is_dir() { nested } else { folder.to_path_buf() }
}

fn engine_backup(engine: &dyn BackupEngine) -> bool {
    engine.capabilities().is_ok_and(|caps| caps.iter().any(|c| c == ENGINE_BACKUP_CAPABILITY))
}

fn is_sidecar(path: &str) -> bool {
    path.rsplit('/').next().unwrap_or("").ends_with(".fork.json")
}

/// The file set a backup.json lists: the project's own files without the fork sidecar (one schema, two writers: 3.4).
pub fn manifest_files(rows: &[Value]) -> Vec<Value> {
    rows.iter().filter(|r| !is_sidecar(r["path"].as_str().unwrap_or(""))).cloned().collect()
}

fn sidecar_path(folder: &Path) -> Option<PathBuf> {
    let mut found: Vec<PathBuf> = fs::read_dir(folder)
        .ok()?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.file_name().is_some_and(|n| n.to_string_lossy().ends_with(".fork.json")))
        .collect();
    found.sort();
    found.into_iter().next()
}

fn rewrite_sidecar(folder: &Path, changes: &[(&str, Value)]) -> Result<Value> {
    let (path, mut record) = match sidecar_path(folder) {
        Some(path) => {
            let record =
                fs::read(&path).ok().and_then(|b| json::loads(&b).ok()).and_then(|v| v.as_object().cloned()).unwrap_or_else(|| {
                    let mut m = Map::new();
                    m.insert("format".into(), json!(1));
                    m
                });
            (path, record)
        }
        None => {
            let mut m = Map::new();
            m.insert("format".into(), json!(1));
            (folder.join("backup.fork.json"), m)
        }
    };
    for (k, v) in changes {
        record.insert((*k).into(), v.clone());
    }
    let record = Value::Object(record);
    atomic_write_point(&path, &dumps_indent2(&record), "sidecar", true)?;
    Ok(record)
}

/// On hydra.2/3 the client seals: SEALED.json and the sidecar's `state:"complete"`.
pub fn seal(folder: &Path, manifest_sha256: &str) -> Result<()> {
    let marker = json!({"manifestSha256": manifest_sha256, "sealedAt": now_iso(), "by": "hydralysis"});
    atomic_write_point(&folder.join(SEAL_MARKER), &dumps_indent2(&marker), "seal", true)?;
    rewrite_sidecar(folder, &[("state", json!("complete"))])?;
    Ok(())
}

fn root_str(root: &Value, key: &str) -> String {
    root[key].as_str().unwrap_or("").to_string()
}

/// hydra.4: `fork_project purpose:"backup"` copies, hashes both sides, writes backup.json (writer "engine") and seals.
/// The client re-hashes every file against the manifest and compares the copy with the source it hashed before (4.5).
#[allow(clippy::too_many_arguments)]
fn make_engine(
    settings: &Value,
    engine: &dyn BackupEngine,
    lineage_id: &str,
    source_gpr: &str,
    folder: &Path,
    identifier: &str,
    purpose: &str,
    generation: i64,
    root: &Value,
) -> Result<Value> {
    if folder.exists() {
        return Err(BackupError::new("backup_failed", format!("{} exists; a backup never overwrites", folder.display())).into());
    }
    if let Some(parent) = folder.parent() {
        fs::create_dir_all(parent)?;
    }
    let expected = lineage::by_path(&tree_files(&lineage::project_folder_of(source_gpr))?);
    let mode = root_str(root, "mode");
    let max_copy = settings.get("fork_max_copy_mb").and_then(Value::as_i64).unwrap_or(8192);
    let fields = json!({"project": source_gpr, "path": folder.to_string_lossy(), "purpose": "backup", "open": false, "verify": "hash",
                        "mode": if matches!(mode.as_str(), "auto" | "copy") { mode.as_str() } else { "auto" }, "maxCopyMb": max_copy});
    let forked = engine.call("fork_project", fields).map_err(|error| {
        BackupError::new("backup_failed", format!("the engine could not make the backup: {error}"))
            .with("folder", json!(folder.to_string_lossy()))
    })?;
    let checked = verify(folder)?;
    if checked["ok"] != true {
        let problems: Vec<String> = checked["problems"].as_array().map(|p| p.iter().take(5).map(py_str).collect()).unwrap_or_default();
        return Err(BackupError::new(
            "backup_verify_failed",
            format!(
                "the engine's backup does not verify: {}; the folder stays invisible and is listed for manual removal",
                problems.join("; ")
            ),
        )
        .with("folder", json!(folder.to_string_lossy()))
        .into());
    }
    let manifest = checked["manifest"].clone();
    let mismatches: Vec<Value> = manifest["files"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|row| {
            let path = row["path"].as_str()?;
            let want = expected.get(path)?;
            (want["sha256"] != row["sha256"] && !path.ends_with(".fork.json"))
                .then(|| json!({"path": path, "expected": want["sha256"], "actual": row["sha256"]}))
        })
        .collect();
    if !mismatches.is_empty() {
        return Err(BackupError::new("backup_verify_failed", "the backup does not match its source")
            .with("mismatches", Value::Array(mismatches.into_iter().take(20).collect()))
            .with("folder", json!(folder.to_string_lossy()))
            .into());
    }
    let digest = sha256_hex(&fs::read(folder.join("backup.json"))?);
    let independent = manifest.get("copy").and_then(|c| c.get("independent")).is_some_and(py_truthy);
    backups_log(settings, lineage_id)?.append(
        &json!({"id": identifier, "manifestSha256": digest, "root": root["path"], "verifiedAt": now_iso(), "bytes": size_of(folder),
                "independent": independent, "purpose": purpose, "generation": generation}),
        false,
    )?;
    Ok(json!({"id": identifier, "folder": folder.to_string_lossy(), "project": project_dir(folder).to_string_lossy(),
              "gpr": forked.get("gpr").filter(|v| py_truthy(v)).cloned().unwrap_or_else(|| json!("")), "manifest": manifest,
              "manifestSha256": digest, "root": root["path"], "writer": manifest.get("writer").cloned().unwrap_or(Value::Null)}))
}

/// Back up SOURCE_GPR into every configured root and re-hash each copy. Returns the primary backup and the others.
///
/// The primary must verify (a failure aborts); a secondary that fails aborts when the policy needs it
/// (`backup_min_verified`, a `required` root) and otherwise only warns.
#[allow(clippy::too_many_arguments)]
pub fn make(
    settings: &Value,
    engine: &dyn BackupEngine,
    lineage_id: &str,
    source_gpr: &str,
    purpose: &str,
    revision: &str,
    generation: i64,
    confirm_large: bool,
    by: Option<Value>,
) -> Result<Value> {
    let wanted = policy(settings)?;
    let plan = preview(settings, lineage_id, source_gpr)?;
    if plan["needs_confirmation"] == true && !confirm_large {
        let gb = plan["bytes"].as_f64().unwrap_or(0.0) / GIB;
        return Err(BackupError::new(
            "confirm_large_backup",
            format!(
                "this backup is {gb:.1} GB, above backup_confirm_gb ({}); the cumulative cost and the free space are in `plan`. Repeat with confirm_large:true",
                py_str(&wanted["backup_confirm_gb"])
            ),
        )
        .with("plan", plan)
        .into());
    }
    let roots = wanted["roots"].as_array().cloned().unwrap_or_default();
    let stamp = crate::config::unix_now();
    let base = backup_id(revision, purpose, Some(stamp));
    let (mut unique, mut number) = (base.clone(), 1);
    while roots.iter().any(|r| Path::new(&root_str(r, "path")).join(lineage_id).join(&unique).exists()) {
        number += 1; // a retry in the same second must not meet the earlier backup: a backup never overwrites
        unique = format!("{base}-{number}");
    }
    let identifier = unique;
    let (mut made, mut warnings): (Vec<Value>, Vec<Value>) = (Vec::new(), Vec::new());
    let by = by.unwrap_or_else(|| engine.identity());
    for (index, root) in roots.iter().enumerate() {
        let folder = Path::new(&root_str(root, "path")).join(lineage_id).join(&identifier);
        match make_one(settings, engine, lineage_id, source_gpr, &folder, &identifier, purpose, revision, generation, root, &by) {
            Ok(one) => made.push(one),
            Err(error @ (Error::Backup(_) | Error::Engine { .. } | Error::Core(hy_core::Error::Io(_)))) => {
                if index == 0 || root["required"] == true {
                    return Err(BackupError::new(
                        "backup_failed",
                        format!(
                            "the {} backup into {} failed: {error}",
                            if index == 0 { "primary" } else { "required" },
                            root_str(root, "path")
                        ),
                    )
                    .into());
                }
                warnings.push(json!({"root": root["path"], "error": error.to_string()}));
            }
            Err(other) => return Err(other),
        }
    }
    let min_verified = wanted["backup_min_verified"].as_f64().unwrap_or(0.0);
    if (made.len() as f64) < min_verified {
        return Err(BackupError::new(
            "backup_failed",
            format!("{} verified backup(s), the policy needs backup_min_verified={}", made.len(), py_str(&wanted["backup_min_verified"])),
        )
        .with("warnings", Value::Array(warnings))
        .into());
    }
    let independent = made.iter().filter(|m| m["manifest"]["copy"]["independent"] == true).count();
    let min_independent = wanted["backup_min_independent"].as_f64().unwrap_or(0.0);
    if (independent as f64) < min_independent {
        return Err(BackupError::new(
            "backup_failed",
            format!(
                "{independent} independent verified backup(s), the policy needs backup_min_independent={}",
                py_str(&wanted["backup_min_independent"])
            ),
        )
        .with("warnings", Value::Array(warnings))
        .into());
    }
    Ok(json!({"backup": made[0], "all": made, "warnings": warnings, "plan": plan}))
}

#[allow(clippy::too_many_arguments)]
fn make_one(
    settings: &Value,
    engine: &dyn BackupEngine,
    lineage_id: &str,
    source_gpr: &str,
    folder: &Path,
    identifier: &str,
    purpose: &str,
    revision: &str,
    generation: i64,
    root: &Value,
    by: &Value,
) -> Result<Value> {
    let started = Instant::now();
    let source_folder = lineage::project_folder_of(source_gpr);
    if engine_backup(engine) {
        return make_engine(settings, engine, lineage_id, source_gpr, folder, identifier, purpose, generation, root);
    }
    if folder.exists() {
        return Err(BackupError::new("backup_failed", format!("{} exists; a backup never overwrites", folder.display())).into());
    }
    let project = folder.join("project");
    if let Some(parent) = folder.parent() {
        fs::create_dir_all(parent)?;
    }
    // The copy is verified against the SOURCE as well: a source that changed during the copy makes a bad backup.
    let expected_rows = tree_files(&source_folder)?;
    let expected = lineage::by_path(&expected_rows);
    let forked = fork_into(settings, engine, source_gpr, &project, &root_str(root, "mode"))?;
    rewrite_sidecar(&project, &[("purpose", json!("backup")), ("disposable", json!(false)), ("state", json!("candidate"))])?;
    // The comparison with the source covers the sidecar too (by its state-free hash); the manifest's file set does not.
    let files = tree_files(folder)?;
    let mut mismatches = Vec::new();
    for row in &files {
        let path = row["path"].as_str().unwrap_or("");
        let Some(inner) = path.strip_prefix("project/") else { continue };
        if let Some(source) = expected.get(inner)
            && (source["sha256"] != row["sha256"] || source["size"] != row["size"])
            && !path.ends_with(".fork.json")
        {
            mismatches.push(json!({"path": path, "expected": source["sha256"], "actual": row["sha256"]}));
        }
    }
    if !mismatches.is_empty() {
        return Err(BackupError::new(
            "backup_verify_failed",
            "the backup does not match its source; no backup.json was written, the folder stays invisible and is listed for manual removal",
        )
        .with("mismatches", Value::Array(mismatches.into_iter().take(20).collect()))
        .with("folder", json!(folder.to_string_lossy()))
        .into());
    }
    let same_volume = volume(folder) == volume(&source_folder);
    let after = tree_files(&source_folder)?;
    let listed = manifest_files(&files);
    let method = forked
        .get("method")
        .filter(|v| py_truthy(v))
        .cloned()
        .unwrap_or_else(|| json!(if forked.get("cloned").is_some_and(py_truthy) { "clone" } else { "copy" }));
    let engine_info: Map<String, Value> = engine
        .hello()
        .as_object()
        .map(|m| {
            m.iter().filter(|(k, _)| matches!(k.as_str(), "hydraVersion" | "ghidraVersion")).map(|(k, v)| (k.clone(), v.clone())).collect()
        })
        .unwrap_or_default();
    let independent = !same_volume && root["mode"] == "copy";
    let source_unchanged = fileset_sha256(&after) == fileset_sha256(&expected.values().cloned().collect::<Vec<_>>());
    let stem = Path::new(source_gpr).file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
    let mut manifest = json!({
        "format": FORMAT, "kind": KIND, "writer": "hydralysis", "id": identifier, "purpose": purpose, "createdAt": now_iso(),
        "createdBy": by,
        "source": {"gpr": source_gpr, "name": stem, "revision": revision, "lineage": lineage_id, "generation": generation},
        "engine": engine_info,
        "files": listed, "filesetSha256": fileset_sha256(&manifest_files(&files)),
        "copy": {"method": method, "sameVolume": same_volume, "independent": independent, "ms": started.elapsed().as_millis() as u64},
        "verify": {"level": "hash", "ok": true, "at": now_iso(), "sourceUnchanged": source_unchanged},
    });
    if !source_unchanged {
        return Err(BackupError::new("backup_verify_failed", "the source changed while it was copied; no backup.json was written")
            .with("folder", json!(folder.to_string_lossy()))
            .into());
    }
    let digest_self = self_hash(&manifest);
    manifest["selfSha256"] = Value::String(digest_self);
    atomic_write_point(&folder.join("backup.json"), &canonical(&manifest), "backup_manifest", true)?;
    let digest = sha256_hex(&fs::read(folder.join("backup.json"))?);
    seal(&project, &digest)?;
    let row = json!({"id": identifier, "manifestSha256": digest, "root": root["path"], "verifiedAt": now_iso(), "bytes": size_of(folder),
                     "independent": manifest["copy"]["independent"], "purpose": purpose, "generation": generation});
    backups_log(settings, lineage_id)?.append(&row, false)?;
    Ok(json!({"id": identifier, "folder": folder.to_string_lossy(), "project": project.to_string_lossy(), "gpr": forked["gpr"],
              "manifest": manifest, "manifestSha256": digest, "root": root["path"]}))
}

// ------------------------------------------------------------------------------------------ reading, verifying

pub fn read_backup(folder: &Path) -> Option<Value> {
    let data = fs::read(folder.join("backup.json")).ok()?;
    let manifest = json::loads(&data).ok()?;
    (manifest.is_object() && manifest.get("kind").and_then(Value::as_str) == Some(KIND)).then_some(manifest)
}

/// Re-read and re-hash every file against backup.json, and check the self-hash (4.5).
pub fn verify(folder: &Path) -> Result<Value> {
    let Some(manifest) = read_backup(folder) else {
        return Ok(json!({"ok": false, "problems": ["no valid backup.json"], "manifest": null}));
    };
    let mut problems: Vec<String> = Vec::new();
    if let Some(format) = manifest.get("format").and_then(Value::as_i64).filter(|f| *f > FORMAT) {
        problems.push(format!("backup.json format {format} is newer than {FORMAT} (format_unreadable)"));
    }
    if manifest.get("selfSha256").and_then(Value::as_str) != Some(self_hash(&manifest).as_str()) {
        problems.push("selfSha256 does not match".into());
    }
    let files: Vec<Value> = manifest.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
    if manifest.get("filesetSha256").and_then(Value::as_str) != Some(fileset_sha256(&files).as_str()) {
        problems.push("filesetSha256 does not match the files list".into());
    }
    if !manifest.get("verify").and_then(|v| v.get("ok")).is_some_and(py_truthy) {
        problems.push("backup.json does not say verify.ok".into());
    }
    let listed = lineage::by_path(&files);
    let actual = lineage::by_path(&tree_files(folder)?);
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
        if !listed.contains_key(path) && !is_sidecar(path) {
            problems.push(format!("unlisted file {path}"));
        }
    }
    let ok = problems.is_empty();
    problems.truncate(20);
    Ok(json!({"ok": ok, "problems": problems, "manifest": manifest}))
}

/// A visible backup folder and the root it was found under.
#[derive(Debug, Clone, PartialEq)]
pub struct Found {
    pub folder: PathBuf,
    pub root: String,
}

#[derive(Debug, Clone, Default)]
pub struct Roots {
    pub visible: Vec<Found>,
    /// `{folder, root, note}` objects.
    pub invisible: Vec<Value>,
}

/// Every folder under the backup roots for this lineage: verified (visible), or without a valid backup.json (invisible).
pub fn scan_roots(settings: &Value, lineage_id: &str) -> Result<Roots> {
    let mut found = Roots::default();
    for root in policy(settings)?["roots"].as_array().cloned().unwrap_or_default() {
        let root_path = root_str(&root, "path");
        let base = Path::new(&root_path).join(lineage_id);
        if !base.is_dir() {
            continue;
        }
        for folder in lineage::sorted_entries(&base) {
            if !folder.is_dir() {
                continue;
            }
            if read_backup(&folder).is_some() {
                found.visible.push(Found { folder, root: root_path.clone() });
            } else {
                found.invisible.push(json!({"folder": folder.to_string_lossy(), "root": root_path,
                    "note": "no valid backup.json; invisible, never used as a restore source, listed for manual removal (D28)"}));
            }
        }
    }
    Ok(found)
}

fn name_of(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// A backup that may be relied on (commit, upgrade gate): present, verifies, and (when given) the one backups.log names.
pub fn usable(settings: &Value, lineage_id: &str, identifier: &str, manifest_sha256: Option<&str>) -> Result<Option<Value>> {
    for found in scan_roots(settings, lineage_id)?.visible {
        if name_of(&found.folder) == identifier {
            let result = verify(&found.folder)?;
            let digest = sha256_hex(&fs::read(found.folder.join("backup.json"))?);
            if result["ok"] == true && manifest_sha256.is_none_or(|m| m == digest) {
                return Ok(Some(
                    json!({"folder": found.folder.to_string_lossy(), "manifestSha256": digest, "manifest": result["manifest"]}),
                ));
            }
        }
    }
    Ok(None)
}

pub fn listing(settings: &Value, lineage_id: &str, verify_all: bool) -> Result<Value> {
    let scan = scan_roots(settings, lineage_id)?;
    let mut rows_logged: Map<String, Value> = Map::new();
    for row in logged(settings, lineage_id)? {
        if let (Some(id), Some(root)) = (row.get("id").and_then(Value::as_str), row.get("root").and_then(Value::as_str)) {
            rows_logged.insert(format!("{id}|{root}"), row.clone());
        }
    }
    let (mut rows, mut independent): (Vec<Value>, u64) = (Vec::new(), 0);
    for found in &scan.visible {
        let folder = &found.folder;
        let manifest = read_backup(folder).unwrap_or(Value::Null);
        let digest = sha256_hex(&fs::read(folder.join("backup.json"))?);
        let entry = rows_logged.get(&format!("{}|{}", name_of(folder), found.root));
        let sealed = project_dir(folder).join(SEAL_MARKER).is_file();
        let is_independent = manifest.get("copy").and_then(|c| c.get("independent")).is_some_and(py_truthy);
        let mut row = Map::new();
        row.insert("id".into(), json!(name_of(folder)));
        row.insert("root".into(), json!(found.root));
        row.insert("purpose".into(), manifest.get("purpose").cloned().unwrap_or(Value::Null));
        row.insert("createdAt".into(), manifest.get("createdAt").cloned().unwrap_or(Value::Null));
        row.insert("generation".into(), manifest.get("source").and_then(|s| s.get("generation")).cloned().unwrap_or(Value::Null));
        row.insert("writer".into(), manifest.get("writer").cloned().unwrap_or(Value::Null));
        row.insert("independent".into(), json!(is_independent));
        row.insert("sealed".into(), json!(sealed));
        row.insert("manifestSha256".into(), json!(digest));
        row.insert("logged".into(), json!(entry.is_some()));
        row.insert(
            "replaced".into(),
            json!(entry.is_some_and(|e| e.get("manifestSha256").and_then(Value::as_str) != Some(digest.as_str()))),
        );
        if !sealed {
            row.insert("label".into(), json!("legacy_unverified"));
            row.insert("note".into(), json!("legacy: not sealed; protected by client discipline only until `op=verify` adopts it"));
        }
        let mut verified = true;
        if verify_all {
            let checked = verify(folder)?;
            verified = checked["ok"] == true;
            row.insert("verified".into(), json!(verified));
            if !verified {
                row.insert("problems".into(), checked["problems"].clone());
            }
        }
        if is_independent && verified {
            independent += 1;
        }
        rows.push(Value::Object(row));
    }
    let missing: Vec<Value> = rows_logged
        .values()
        .filter(|row| !row.get("removed").is_some_and(py_truthy) && !rows.iter().any(|r| r["id"] == row["id"] && r["root"] == row["root"]))
        .map(|row| json!({"id": row["id"], "root": row["root"]}))
        .collect();
    let wanted = policy(settings)?;
    let policy_without_roots: Map<String, Value> = wanted
        .as_object()
        .map(|m| m.iter().filter(|(k, _)| *k != "roots").map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default();
    Ok(json!({"lineage": lineage_id, "backups": rows, "invisible": scan.invisible, "independent_verified": independent,
              "logged_but_missing": missing, "policy": policy_without_roots, "roots": wanted["roots"]}))
}

// ------------------------------------------------------------------------------ retention: remove is a dry run

/// Generations that `remove` refuses: generation 0, the head, every generation the revert chain can reach and the
/// base of a live view.
pub fn protected_generations(settings: &Value, lineage_id: &str) -> Result<BTreeMap<i64, String>> {
    let rows = lineage::history(settings, lineage_id)?;
    let top = rows.last().and_then(|r| r.get("gen")).and_then(Value::as_i64).unwrap_or(0);
    let mut keep: BTreeMap<i64, String> = BTreeMap::new();
    keep.insert(0, "generation 0 is the adopted project and is never removed".into());
    keep.insert(top, "the head generation".into());
    let published: std::collections::BTreeSet<i64> = rows
        .iter()
        .filter(|r| {
            r.get("gen").and_then(Value::as_i64).unwrap_or(0) < top
                && matches!(r.get("reason").and_then(Value::as_str), Some("commit" | "recover" | "rollback"))
        })
        .filter_map(|r| r.get("gen").and_then(Value::as_i64))
        .collect();
    let last = published.iter().next_back().copied();
    for number in &published {
        let why = if Some(*number) == last {
            "the revert target (the generation before the head)"
        } else {
            "a generation the revert chain can reach (commit_revert walks back to generation 0)"
        };
        keep.entry(*number).or_insert_with(|| why.to_string());
    }
    let bases = root_path(settings)?.join("bases");
    if bases.is_dir() {
        for first in lineage::sorted_entries(&bases) {
            if !first.is_dir() {
                continue;
            }
            for second in lineage::sorted_entries(&first) {
                if !second.is_dir() {
                    continue;
                }
                // Fail closed: a marker that cannot be read (locked, empty, torn, mis-sealed with no backup) might
                // be the base of a live view, so it must stop the removal, never silently unprotect its generation.
                // Only "no marker at all" (an unfinished, invisible base) protects nothing.
                let marker = second.join("COMPLETE.json");
                let record = match hy_core::sealed::read_sealed_info(&marker, &ReadOptions::default(), Some(Value::Null)) {
                    Ok((_, Source::Missing)) => continue,
                    Ok((record, _)) => record,
                    Err(error) => {
                        return Err(value_err(format!(
                            "cannot prove which generation the base marker {} protects: {error}; nothing was removed",
                            marker.display()
                        )));
                    }
                };
                if let Some(generation) = record.get("generation").and_then(Value::as_i64)
                    && record.get("lineage").and_then(Value::as_str) == Some(lineage_id)
                {
                    keep.entry(generation).or_insert_with(|| "the base of a live view".to_string());
                }
            }
        }
    }
    Ok(keep)
}

fn insert_all(target: &mut Map<String, Value>, extra: Value) {
    if let Value::Object(map) = extra {
        for (k, v) in map {
            target.insert(k, v);
        }
    }
}

/// `backends action=backups options.op=remove`: a dry run unless `confirm: true`.
pub fn remove(settings: &Value, lineage_id: &str, options: &Value) -> Result<Value> {
    let confirm = match options.get("confirm") {
        None => false,
        Some(Value::Bool(b)) => *b,
        Some(_) => return Err(value_err("confirm must be a boolean")),
    };
    let identifier = options.get("id").filter(|v| !v.is_null());
    let generation = options.get("generation").filter(|v| !v.is_null());
    if identifier.is_none() == generation.is_none() {
        return Err(value_err("backups remove needs exactly one of id (a backup) or generation (a generation folder)"));
    }
    let mut plan = Map::new();
    plan.insert("dry_run".into(), json!(!confirm));
    let reply = |plan: &Map<String, Value>, extra: Value| {
        let mut out = plan.clone();
        insert_all(&mut out, extra);
        Value::Object(out)
    };
    let victims: Vec<PathBuf>;
    let mut matches: Vec<Found> = Vec::new();
    if let Some(identifier) = identifier {
        let identifier = py_str(identifier);
        let scan = scan_roots(settings, lineage_id)?;
        let invisible: Vec<Found> =
            scan.invisible.iter().map(|i| Found { folder: PathBuf::from(py_str(&i["folder"])), root: py_str(&i["root"]) }).collect();
        matches = scan.visible.iter().cloned().chain(invisible).filter(|f| name_of(&f.folder) == identifier).collect();
        if matches.is_empty() {
            return Err(value_err(format!("no backup {identifier} under the configured roots of {lineage_id}")));
        }
        let mut verified = Vec::new();
        for found in &scan.visible {
            if verify(&found.folder)?["ok"] == true {
                verified.push(found.clone());
            }
        }
        let wanted = number_of(&policy(settings)?["backup_min_verified"]).unwrap_or(0.0);
        let target_ok = verified.iter().any(|f| f.folder == matches[0].folder);
        if target_ok && ((verified.len() as f64) - 1.0) < wanted {
            let wanted_text = py_str(&policy(settings)?["backup_min_verified"]);
            return Ok(reply(
                &plan,
                json!({"removed": false, "refused": "backup_min_verified",
                       "message": format!("removing it would leave {} verified backup(s), the policy needs {wanted_text}", verified.len() - 1)}),
            ));
        }
        plan.insert("what".into(), json!("backup"));
        plan.insert("folders".into(), Value::Array(matches.iter().map(|m| json!(m.folder.to_string_lossy())).collect()));
        victims = matches.iter().map(|m| m.folder.clone()).collect();
    } else {
        let Some(generation) = generation.and_then(Value::as_i64) else { return Err(value_err("generation must be an integer")) };
        let keep = protected_generations(settings, lineage_id)?;
        if let Some(why) = keep.get(&generation) {
            return Ok(reply(
                &plan,
                json!({"removed": false, "refused": "protected_generation", "generation": generation, "message": why}),
            ));
        }
        let folder = lineage::generation_dir(settings, lineage_id, generation)?;
        if !folder.is_dir() {
            return Err(value_err(format!("generation {generation} has no folder")));
        }
        plan.insert("what".into(), json!("generation"));
        plan.insert("folders".into(), json!([folder.to_string_lossy()]));
        victims = vec![folder];
    }
    plan.insert("bytes".into(), json!(victims.iter().map(|v| size_of(v)).sum::<u64>()));
    if !confirm {
        return Ok(reply(&plan, json!({"removed": false, "message": "dry run: nothing was removed; repeat with confirm:true"})));
    }
    for victim in &victims {
        writable_tree(victim);
        fs::remove_dir_all(victim)?;
    }
    if let Some(identifier) = identifier {
        for found in &matches {
            backups_log(settings, lineage_id)?
                .append(&json!({"id": identifier, "root": found.root, "removed": true, "removedAt": now_iso()}), false)?;
        }
    }
    Ok(reply(&plan, json!({"removed": true})))
}

/// `op=verify` on a backup without a seal: re-hash against backup.json, then seal it (a failed one is `legacy_unverified`).
///
/// On an engine with `seal_project` the engine's registry is told as well (best effort: the client's SEALED.json and
/// the sidecar are already a witness of the union, D66).
pub fn adopt_legacy(folder: &Path, engine: Option<&dyn BackupEngine>, lineage_id: Option<&str>) -> Result<Value> {
    let result = verify(folder)?;
    if result["ok"] != true {
        return Ok(json!({"ok": false, "label": "legacy_unverified", "problems": result["problems"]}));
    }
    let project = project_dir(folder);
    if project.join(SEAL_MARKER).is_file() {
        return Ok(json!({"ok": true, "adopted": false}));
    }
    seal(&project, &sha256_hex(&fs::read(folder.join("backup.json"))?))?;
    let mut outcome = Map::new();
    outcome.insert("ok".into(), json!(true));
    outcome.insert("adopted".into(), json!(true));
    if let Some(engine) = engine.filter(|e| engine_backup(*e)) {
        let mut gprs: Vec<PathBuf> =
            fs::read_dir(&project)?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "gpr")).collect();
        gprs.sort();
        let attempt = match gprs.first() {
            None => Err(EngineFailure { code: "not_found".into(), message: "no .gpr in the backup".into() }),
            Some(gpr) => {
                let mut fields = Map::new();
                fields.insert("project".into(), json!(gpr.to_string_lossy()));
                if let Some(id) = lineage_id.filter(|i| !i.is_empty()) {
                    fields.insert("lineage".into(), json!(id));
                }
                engine.call("seal_project", Value::Object(fields))
            }
        };
        match attempt {
            Ok(_) => {
                outcome.insert("engine_sealed".into(), json!(true));
            }
            Err(error) => {
                outcome.insert("engine_sealed".into(), json!(false));
                outcome.insert("engine_seal_error".into(), json!(error.message));
            }
        }
    }
    Ok(Value::Object(outcome))
}

/// `backend action=backups options.op=list|verify|remove` for an already resolved lineage (target resolution and the
/// engine factory belong to the caller). Returns the result object WITHOUT the `op` key; errors that Python turns into
/// a payload (`BackupError`, `LineageError`) stay errors here, the caller renders `payload()`.
pub fn run_op(settings: &Value, lineage_id: &str, options: &Value, adopter: &dyn Fn() -> Option<Box<dyn BackupEngine>>) -> Result<Value> {
    let op = options.get("op").and_then(Value::as_str).unwrap_or("list");
    match op {
        "list" => listing(settings, lineage_id, options.get("verify_all").is_some_and(py_truthy)),
        "verify" => {
            let scan = scan_roots(settings, lineage_id)?;
            let engine = if scan.visible.iter().any(|f| !project_dir(&f.folder).join(SEAL_MARKER).is_file()) { adopter() } else { None };
            let wanted = options.get("id").filter(|v| py_truthy(v)).map(py_str);
            let mut results = Vec::new();
            for found in scan.visible {
                if wanted.as_deref().is_some_and(|w| name_of(&found.folder) != w) {
                    continue;
                }
                let outcome = adopt_legacy(&found.folder, engine.as_deref(), Some(lineage_id))?;
                let mut row = Map::new();
                row.insert("id".into(), json!(name_of(&found.folder)));
                row.insert("root".into(), json!(found.root));
                insert_all(&mut row, outcome);
                results.push(Value::Object(row));
            }
            if let Some(w) = wanted
                && results.is_empty()
            {
                return Err(value_err(format!("no backup {w} under the configured roots")));
            }
            Ok(json!({"lineage": lineage_id, "results": results}))
        }
        _ => {
            let mut out = Map::new();
            out.insert("lineage".into(), json!(lineage_id));
            insert_all(&mut out, remove(settings, lineage_id, options)?);
            Ok(Value::Object(out))
        }
    }
}
