//! Generation folders and their manifests (`lineage.py`: `tree_files`, `write_manifest`, `verify_manifest`,
//! `manifest_file_sha256`, `reserved_generations`, `next_generation`, `tampered`) and the number a publish reserves
//! (`views.reserve_generation`).
//!
//! The tamper cache of Python (`tampered_cache_s`, off by default) is not ported: a nonzero setting re-hashes every time,
//! which is the same answer, only slower.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::error::Result;
use crate::gens::{MANIFEST, history, project_folder_of, read_manifest};
use crate::layout::{Settings, generation_dir, lineage_dir};
use hy_core::json::canonical;
use hy_core::sealed::sha256_hex;

/// `lineage.FORMAT`.
pub const FORMAT: i64 = 1;
/// `lineage.SEAL_MARKER`.
pub const SEAL_MARKER: &str = "SEALED.json";

fn excluded(name: &str) -> bool {
    matches!(name, MANIFEST | SEAL_MARKER | "projectState" | "backup.json") || name.ends_with(".lock") || name.ends_with(".lock~")
}

fn walk(folder: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(folder) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        match entry.file_type() {
            Ok(t) if t.is_dir() => walk(&path, out),
            Ok(t) if t.is_file() => out.push(path),
            _ => {}
        }
    }
}

fn hash_file(path: &Path) -> std::io::Result<(u64, String)> {
    use sha2::{Digest, Sha256};
    use std::io::Read;
    let mut file = std::fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut block = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        hasher.update(&block[..n]);
        size += n as u64;
    }
    Ok((size, hex::encode(hasher.finalize())))
}

/// (size, sha256) of what the manifest records for `path`; a `.fork.json` sidecar is taken without its lifecycle `state`.
fn file_hash(path: &Path) -> std::io::Result<(u64, String)> {
    if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".fork.json"))
        && let Ok(text) = std::fs::read_to_string(path)
        && let Ok(Value::Object(mut record)) = serde_json::from_str::<Value>(&text)
    {
        record.remove("state");
        let body = canonical(&Value::Object(record));
        return Ok((body.len() as u64, sha256_hex(&body)));
    }
    hash_file(path)
}

/// `[{path, size, sha256}]` for every content file under `folder`, sorted by path (forward slashes).
pub fn tree_files(folder: &Path) -> Vec<Value> {
    let mut files = Vec::new();
    walk(folder, &mut files);
    let mut rows: Vec<(String, Value)> = files
        .into_iter()
        .filter(|p| !p.file_name().and_then(|n| n.to_str()).is_some_and(excluded))
        .filter_map(|p| {
            let (size, digest) = file_hash(&p).ok()?;
            let rel = p
                .strip_prefix(folder)
                .ok()?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            Some((rel.clone(), json!({"path": rel, "size": size, "sha256": digest})))
        })
        .collect();
    rows.sort_by(|a, b| a.0.cmp(&b.0));
    rows.into_iter().map(|(_, v)| v).collect()
}

/// `lineage.fileset_sha256`.
pub fn fileset_sha256(files: &[Value]) -> String {
    sha256_hex(&canonical(&Value::Array(files.to_vec())))
}

/// `lineage.self_hash`: the hash of a manifest without its `selfSha256`.
pub fn self_hash(manifest: &Map<String, Value>) -> String {
    let rest: Map<String, Value> =
        manifest.iter().filter(|(k, _)| k.as_str() != "selfSha256").map(|(k, v)| (k.clone(), v.clone())).collect();
    sha256_hex(&canonical(&Value::Object(rest)))
}

/// `lineage.write_manifest`: write `MANIFEST.json` with its fileset and self hashes; returns the manifest.
pub fn write_manifest(folder: &Path, body: &Map<String, Value>) -> Result<Map<String, Value>> {
    let files = tree_files(folder);
    let mut manifest = Map::new();
    manifest.insert("format".into(), json!(FORMAT));
    manifest.extend(body.clone());
    manifest.insert("filesetSha256".into(), json!(fileset_sha256(&files)));
    manifest.insert("files".into(), Value::Array(files));
    let hash = self_hash(&manifest);
    manifest.insert("selfSha256".into(), json!(hash));
    hy_core::fsio::atomic_write_point(&folder.join(MANIFEST), &canonical(&Value::Object(manifest.clone())), "manifest", true)?;
    Ok(manifest)
}

/// `lineage.manifest_file_sha256`: the hash of the manifest file's bytes.
pub fn manifest_file_sha256(folder: &Path) -> Option<String> {
    std::fs::read(folder.join(MANIFEST)).ok().map(|b| sha256_hex(&b))
}

/// What [`verify_manifest`] found.
#[derive(Debug)]
pub struct Verified {
    pub ok: bool,
    pub problems: Vec<String>,
    pub manifest: Option<Map<String, Value>>,
}

/// `lineage.verify_manifest`: re-hash every file against `MANIFEST.json`.
pub fn verify_manifest(folder: &Path) -> Verified {
    let Some(manifest) = read_manifest(folder) else {
        return Verified { ok: false, problems: vec!["no valid MANIFEST.json".into()], manifest: None };
    };
    let mut problems = Vec::new();
    if let Some(format) = manifest.get("format").and_then(Value::as_i64)
        && format > FORMAT
    {
        problems.push(format!("manifest format {format} is newer than {FORMAT} (format_unreadable)"));
    }
    if manifest.get("selfSha256").and_then(Value::as_str) != Some(self_hash(&manifest).as_str()) {
        problems.push("selfSha256 does not match".into());
    }
    let listed_rows: Vec<Value> = manifest.get("files").and_then(Value::as_array).cloned().unwrap_or_default();
    if manifest.get("filesetSha256").and_then(Value::as_str) != Some(fileset_sha256(&listed_rows).as_str()) {
        problems.push("filesetSha256 does not match the files list".into());
    }
    // Python dicts keep first-insertion order with the last value; the listing order is what the messages follow.
    let mut listed: Vec<(String, &Value)> = Vec::new();
    for row in &listed_rows {
        let path = row["path"].as_str().unwrap_or_default().to_string();
        match listed.iter_mut().find(|(p, _)| *p == path) {
            Some(slot) => slot.1 = row,
            None => listed.push((path, row)),
        }
    }
    let actual_rows = tree_files(folder);
    let actual: std::collections::HashMap<&str, &Value> = actual_rows.iter().map(|r| (r["path"].as_str().unwrap_or_default(), r)).collect();
    for (path, row) in &listed {
        match actual.get(path.as_str()) {
            None => problems.push(format!("missing file {path}")),
            Some(found) if found["sha256"] != row["sha256"] || found["size"] != row["size"] => {
                problems.push(format!("changed file {path}"));
            }
            Some(_) => {}
        }
    }
    for row in &actual_rows {
        let path = row["path"].as_str().unwrap_or_default();
        if !listed.iter().any(|(p, _)| p == path) {
            problems.push(format!("unlisted file {path}"));
        }
    }
    let ok = problems.is_empty();
    problems.truncate(20);
    Verified { ok, problems, manifest: Some(manifest) }
}

/// Every generation number that must never be reused: the log, the intent logs' reservations and any folder.
pub fn reserved_generations(settings: &Settings, lineage_id: &str) -> Result<BTreeSet<i64>> {
    let mut taken: BTreeSet<i64> = history(settings, lineage_id)?.iter().filter_map(|r| r.get("gen").and_then(Value::as_i64)).collect();
    let dir = lineage_dir(settings, lineage_id)?;
    if let Ok(entries) = std::fs::read_dir(dir.join("commits")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.ends_with(".intent.log")) {
                taken.extend(
                    hy_core::appendlog::AppendLog::new(path).scan()?.records.iter().filter_map(|r| r.get("gen").and_then(Value::as_i64)),
                );
            }
        }
    }
    if let Ok(entries) = std::fs::read_dir(dir.join("gen")) {
        for entry in entries.flatten() {
            if let Some(n) = entry.file_name().to_str()
                && !n.is_empty()
                && n.bytes().all(|b| b.is_ascii_digit())
                && let Ok(number) = n.parse::<i64>()
            {
                taken.insert(number);
            }
        }
    }
    Ok(taken)
}

/// `lineage.next_generation`.
pub fn next_generation(settings: &Settings, lineage_id: &str) -> Result<i64> {
    Ok(reserved_generations(settings, lineage_id)?.into_iter().max().unwrap_or(0).max(0) + 1)
}

/// `lineage.tampered`: published generations whose folder no longer matches its manifest.
pub fn tampered(settings: &Settings, lineage_id: &str) -> Result<Vec<Value>> {
    let mut found = Vec::new();
    let mut seen = BTreeSet::new();
    for record in history(settings, lineage_id)? {
        let generation = record.get("gen").and_then(Value::as_i64).unwrap_or(0);
        let reason = record.get("reason").and_then(Value::as_str);
        if generation != 0 && !seen.contains(&generation) && matches!(reason, Some("commit" | "recover")) {
            seen.insert(generation);
            let folder = project_folder_of(record["gpr"].as_str().unwrap_or_default());
            if folder.is_dir() {
                let check = verify_manifest(&folder);
                if !check.ok {
                    found.push(json!({"generation": generation, "problems": check.problems}));
                }
            }
        }
    }
    Ok(found)
}

/// `views.reserve_generation`: the number of the next candidate, one more than the highest generation the log ever named.
/// A folder at that number that the log never named is an abandoned candidate: it is moved aside, not deleted; if it cannot
/// be, the number is skipped (a gap and nothing else).
pub fn reserve_generation(settings: &Settings, lineage_id: &str) -> Result<i64> {
    let logged: BTreeSet<i64> = history(settings, lineage_id)?.iter().filter_map(|r| r.get("gen").and_then(Value::as_i64)).collect();
    let number = logged.iter().copied().max().unwrap_or(0).max(0) + 1;
    let folder = generation_dir(settings, lineage_id, number as u64)?;
    if folder.exists() {
        let mut tag = [0u8; 4];
        getrandom::fill(&mut tag).expect("OS randomness");
        let aside = folder.with_file_name(format!("{number:04}.abandoned-{}", hex::encode(tag)));
        if hy_core::fsio::replace_file(&folder, &aside).is_err() {
            return next_generation(settings, lineage_id);
        }
    }
    Ok(number)
}
