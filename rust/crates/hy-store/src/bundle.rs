//! Exportable evidence bundles (Rust port of `hydralysis.evidence_bundle`): export, verify, compare, import.
//!
//! A bundle is a folder; everything in it is a file that `manifest.json` lists with its size and SHA-256. Formats,
//! hashes and error codes equal the Python implementation (`hydralysis.evidence-bundle/1`).

use crate::evidence::{
    self, Ctx, EvidenceError, EvidenceIntegrityError, Result, canonical_digest, canonical_json, id_like, py_repr_str, py_str, truthy,
};
use hy_core::sealed::sha256_hex;
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const FORMAT: &str = "hydralysis.evidence-bundle/1";
pub const MAX_STRING: usize = 16384;
pub const MAX_ENCODED_RUN: usize = 8192;
pub const MAX_CAPTURE_BYTES: usize = 1024 * 1024;
pub const MAX_FILE_BYTES: u64 = 64 * 1024 * 1024;
pub const MAX_CAPTURES: usize = 256;
pub const MAX_TRACES: usize = 64;
pub const TRACE_PIN_FORMAT: &str = "hydralysis.trace-pin/1";
/// Files whose bytes may differ between two exports of the same claims.
pub const VOLATILE_FILES: &[&str] = &["manifest.json", "environment.json", "evidence.jsonl"];
/// The version recorded in environment.json by default (`hydralysis.__version__`).
pub const HYDRALYSIS_VERSION: &str = "0.8.0";

pub const REA_BUNDLE_MAP: &[(&str, &str)] = &[
    ("records", "evidence.jsonl"),
    ("artifacts", "subjects.json"),
    ("providers", "evidence.jsonl (meta.client, meta.harness: attribution, not identity)"),
    ("environments", "environment.json (volatile)"),
    ("scenarios", "replay.json"),
    ("captures", "captures/"),
];
pub const REA_BUNDLE_GAPS: &[(&str, &str)] =
    &[("unknowns", "not modeled: Hydralysis has no residual-unknown records; a gap is a partial or unknown coverage")];

/// A bundle that cannot be written, read or trusted, with a stable code.
#[derive(Debug, Clone)]
pub struct BundleError {
    pub code: String,
    pub message: String,
    pub detail: Map<String, Value>,
}

impl BundleError {
    pub fn new(code: &str, message: impl Into<String>) -> Self {
        Self { code: code.into(), message: message.into(), detail: Map::new() }
    }
    pub fn with(mut self, key: &str, value: Value) -> Self {
        self.detail.insert(key.into(), value);
        self
    }
    /// `{error, message, **detail}`.
    pub fn payload(&self) -> Value {
        let mut map = Map::new();
        map.insert("error".into(), json!(self.code));
        map.insert("message".into(), json!(self.message));
        for (k, v) in &self.detail {
            map.insert(k.clone(), v.clone());
        }
        Value::Object(map)
    }
}

impl std::fmt::Display for BundleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn fail<T>(code: &str, message: impl Into<String>) -> Result<T> {
    Err(EvidenceError::Bundle(BundleError::new(code, message)))
}

fn bundle(error: BundleError) -> EvidenceError {
    EvidenceError::Bundle(error)
}

// ---- the payload guard ------------------------------------------------------------------------------------------

fn encoded_run(text: &str) -> bool {
    let space = |c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c);
    !text.is_empty()
        && (text.chars().all(|c| c.is_ascii_hexdigit() || space(c))
            || text.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-') || space(c)))
}

/// Refuse strings that look like game bytes or game text: too long, or a long run of hex or base64.
pub fn guard_payload(value: &Value, location: &str) -> Result<()> {
    match value {
        Value::String(text) => {
            let length = text.chars().count();
            if length > MAX_STRING {
                return fail(
                    "payload_refused",
                    format!("{location} is a string of {length} characters; a bundle carries at most {MAX_STRING}"),
                );
            }
            if length > MAX_ENCODED_RUN && encoded_run(text) {
                return fail(
                    "payload_refused",
                    format!(
                        "{location} looks like encoded bytes ({length} characters of hex or base64); a bundle carries bounded captured hex, not payloads"
                    ),
                );
            }
        }
        Value::Object(map) => {
            for (key, item) in map {
                guard_payload(&Value::String(key.clone()), &format!("{location}.<key>"))?;
                guard_payload(item, &format!("{location}.{key}"))?;
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                guard_payload(item, &format!("{location}[{index}]"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

// ---- building ---------------------------------------------------------------------------------------------------

pub fn jsonl(records: &[Value]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for record in records {
        out.extend_from_slice(canonical_json(record)?.as_bytes());
        out.push(b'\n');
    }
    Ok(out)
}

pub fn json_bytes(value: &Value) -> Result<Vec<u8>> {
    let mut text = canonical_json(value)?;
    text.push('\n');
    Ok(text.into_bytes())
}

fn s<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

pub fn subjects_of(records: &[Value]) -> Value {
    let mut counts: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    for record in records {
        let content = &record["content"];
        let digest = content["subject"].get("sha256").and_then(Value::as_str).unwrap_or_default();
        *counts.entry((s(content, "game").into(), s(content, "build").into(), digest.into())).or_insert(0) += 1;
    }
    let rows: Vec<Value> = counts
        .into_iter()
        .map(|((game, build, digest), count)| json!({"game": game, "build": build, "subject_sha256": if digest.is_empty() { Value::Null } else { json!(digest) }, "records": count}))
        .collect();
    json!({"subjects": rows})
}

pub fn replay_of(records: &[Value], captured: &BTreeSet<String>, traces: Option<&BTreeMap<String, Value>>) -> Value {
    let mut scenarios = Vec::new();
    let mut missing = BTreeSet::new();
    let mut unreproducible: BTreeMap<String, Value> = BTreeMap::new();
    for record in records {
        let content = &record["content"];
        let trace = content.get("from_trace").filter(|t| truthy(t));
        let capture = &content["from_capture"];
        if content["authority"] == "controlled-replay" || truthy(capture) || trace.is_some() {
            let mut scenario = Map::new();
            scenario.insert("evidence_id".into(), record["evidence_id"].clone());
            scenario.insert("authority".into(), content["authority"].clone());
            scenario.insert("name".into(), content["name"].clone());
            scenario.insert("source".into(), content["source"].clone());
            scenario.insert("from_capture".into(), capture.clone());
            if let Some(trace) = trace {
                scenario.insert("from_trace".into(), json!({"session": trace["session"], "revision": trace["revision"]}));
                let session = s(trace, "session").to_string();
                let pin = traces.and_then(|t| t.get(&session));
                if pin.is_none_or(|p| p.get("reproducible") != Some(&Value::Bool(true))) {
                    let listed = pin.and_then(|p| p.get("cannot_reproduce")).filter(|c| truthy(c)).cloned();
                    unreproducible.insert(
                        session.clone(),
                        listed.unwrap_or_else(|| json!([{"what": format!("trace session {session}"), "reason": "pin-not-supplied"}])),
                    );
                }
            }
            scenarios.push(Value::Object(scenario));
            if let Some(id) = capture.as_str().filter(|c| !c.is_empty())
                && !captured.contains(id)
            {
                missing.insert(id.to_string());
            }
        }
    }
    let mut result = Map::new();
    result.insert("scenarios".into(), Value::Array(scenarios));
    result.insert("missing_captures".into(), json!(missing.into_iter().collect::<Vec<_>>()));
    if !unreproducible.is_empty() {
        // only a bundle that cites traces carries this key, so older bundles keep their bytes
        result.insert("unreproducible_traces".into(), Value::Object(unreproducible.into_iter().collect()));
    }
    Value::Object(result)
}

/// Validate a trace pin (the `traces/<session>.json` member) and return it.
pub fn check_pin(pin: &Value, session: &str) -> Result<Value> {
    let bad = |message: &str| -> EvidenceError {
        bundle(BundleError::new("trace_pin_invalid", format!("trace pin {session}: {message}")).with("session", json!(session)))
    };
    let object = match pin {
        Value::Object(o) if o.get("format") == Some(&json!(TRACE_PIN_FORMAT)) && o.get("trace_id") == Some(&json!(session)) => o,
        _ => return Err(bad(&format!("must be a {TRACE_PIN_FORMAT} object whose trace_id is the session"))),
    };
    match object.get("revision") {
        Some(r) if (r.is_i64() || r.is_u64()) && r.as_i64().is_none_or(|i| i >= 0) => {}
        _ => return Err(bad("revision must be a non-negative integer")),
    }
    let Some(Value::Bool(reproducible)) = object.get("reproducible") else { return Err(bad("reproducible must be true or false")) };
    for key in ["events", "artifacts", "cannot_reproduce"] {
        if !object.get(key).is_some_and(Value::is_array) {
            return Err(bad(&format!("{key} must be a list")));
        }
    }
    if !object["events"].as_array().is_some_and(|a| a.iter().all(Value::is_string)) {
        return Err(bad("events are event id strings"));
    }
    for artifact in object["artifacts"].as_array().into_iter().flatten() {
        let ok = artifact.as_object().is_some_and(|a| {
            a.get("sha256").and_then(Value::as_str).is_some_and(|h| h.chars().count() == 64)
                && a.get("range").and_then(Value::as_array).is_some_and(|r| r.len() == 2)
                && a.get("authorized") == Some(&Value::Bool(true))
        });
        if !ok {
            return Err(bad(
                "an artifact is {id, sha256, range:[start,end], authorized:true}: unauthorized ranges are listed under cannot_reproduce, never pinned",
            ));
        }
        if artifact.get("bytes").is_some() || artifact.get("data").is_some() {
            return Err(bad("a pin carries artifact hashes and ranges, not bytes"));
        }
    }
    let cannot = object["cannot_reproduce"].as_array().cloned().unwrap_or_default();
    for item in &cannot {
        let ok =
            item.as_object().is_some_and(|o| o.get("what").is_some_and(Value::is_string) && o.get("reason").is_some_and(Value::is_string));
        if !ok {
            return Err(bad("cannot_reproduce entries are {what, reason}"));
        }
    }
    if *reproducible && !cannot.is_empty() {
        return Err(bad("reproducible is true but cannot_reproduce is not empty"));
    }
    if !*reproducible && cannot.is_empty() {
        return Err(bad("not reproducible without saying what cannot be reproduced"));
    }
    Ok(pin.clone())
}

/// The member written for a cited session whose pin was not supplied: it lists what cannot be reproduced.
pub fn stub_pin(session: &str, revision: &Value) -> Value {
    json!({
        "format": TRACE_PIN_FORMAT, "trace_id": session, "session": session, "revision": revision,
        "interpretation_revision": null, "events": [], "artifacts": [], "reproducible": false,
        "cannot_reproduce": [{"what": format!("trace session {session} at revision {}", py_str(revision)), "reason": "pin-not-supplied"}]
    })
}

fn parse_json(data: &[u8]) -> std::result::Result<Value, String> {
    let text = std::str::from_utf8(data).map_err(|e| e.to_string())?;
    serde_json::from_str(text).map_err(|e| e.to_string())
}

fn load_traces(traces_dir: Option<&Path>, records: &[Value]) -> Result<BTreeMap<String, Value>> {
    let mut cited: BTreeMap<String, i64> = BTreeMap::new();
    for record in records {
        if let Some(trace) = record["content"].get("from_trace").filter(|t| truthy(t)) {
            let entry = cited.entry(s(trace, "session").to_string()).or_insert(0);
            *entry = (*entry).max(trace["revision"].as_i64().unwrap_or(0));
        }
    }
    if cited.len() > MAX_TRACES {
        return fail("payload_refused", format!("too many cited trace sessions ({}, at most {MAX_TRACES})", cited.len()));
    }
    let mut found = BTreeMap::new();
    for (session, revision) in &cited {
        let file = traces_dir.map(|d| d.join(format!("{session}.json")));
        match file.filter(|f| f.is_file()) {
            Some(file) => {
                let data = std::fs::read(&file)?;
                if data.len() > MAX_CAPTURE_BYTES {
                    return fail("payload_refused", format!("trace pin {session} is {} bytes; at most {MAX_CAPTURE_BYTES}", data.len()));
                }
                let parsed = parse_json(&data)
                    .map_err(|e| bundle(BundleError::new("trace_pin_invalid", format!("trace pin {session} is not JSON: {e}"))))?;
                let pin = check_pin(&parsed, session)?;
                guard_payload(&pin, &format!("trace pin {session}"))?;
                found.insert(session.clone(), pin);
            }
            None => {
                found.insert(session.clone(), stub_pin(session, &json!(revision)));
            }
        }
    }
    Ok(found)
}

pub fn limitations_of(records: &[Value]) -> BTreeMap<String, Vec<String>> {
    let mut by_code: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for record in records {
        for code in record["content"]["limitations"].as_array().into_iter().flatten().filter_map(Value::as_str) {
            by_code.entry(code.to_string()).or_default().push(s(record, "evidence_id").to_string());
        }
    }
    for ids in by_code.values_mut() {
        ids.sort();
    }
    by_code
}

fn limitations_value(table: &BTreeMap<String, Vec<String>>) -> Value {
    Value::Object(table.iter().map(|(k, v)| (k.clone(), json!(v))).collect())
}

pub fn limitations_md(table: &BTreeMap<String, Vec<String>>) -> Vec<u8> {
    let mut lines: Vec<String> = vec![
        "# Limitations".into(),
        String::new(),
        "Each code below is stored with the claims that carry it. A code that bounds coverage means the claim does not cover the whole subject.".into(),
        String::new(),
    ];
    if table.is_empty() {
        lines.push("No claim in this bundle states a limitation.".into());
    }
    for (code, ids) in table {
        let meaning = evidence::limitation_entry(code).map_or("A code of the writer's own (no catalog text).", |e| e.2);
        lines.push(format!("## `{code}`{}", if evidence::bounds_coverage(code) { " (bounds coverage)" } else { "" }));
        lines.push(String::new());
        lines.push(meaning.to_string());
        lines.push(String::new());
        lines.extend(ids.iter().map(|id| format!("- {id}")));
        lines.push(String::new());
    }
    let mut text = lines.join("\n");
    text.push('\n');
    text.into_bytes()
}

/// The identity of what a bundle says; volatile fields never enter it.
pub fn bundle_id_of(
    records: &[Value],
    subjects: &Value,
    capture_hashes: &BTreeMap<String, String>,
    replay: &Value,
    limitations: &BTreeMap<String, Vec<String>>,
    trace_hashes: &BTreeMap<String, String>,
) -> Result<String> {
    let mut said = Map::new();
    said.insert("format".into(), json!(FORMAT));
    said.insert("records".into(), json!(records.iter().map(|r| r["evidence_id"].clone()).collect::<Vec<_>>()));
    said.insert("subjects".into(), subjects.clone());
    said.insert("captures".into(), json!(capture_hashes));
    said.insert("replay".into(), replay.clone());
    said.insert("limitations".into(), json!(limitations.keys().collect::<Vec<_>>()));
    if !trace_hashes.is_empty() {
        said.insert("traces".into(), json!(trace_hashes));
    }
    Ok(format!("eb_{}", canonical_digest(&Value::Object(said))?))
}

fn load_captures(captures_dir: Option<&Path>, wanted: &BTreeSet<String>) -> Result<BTreeMap<String, Vec<u8>>> {
    let mut found = BTreeMap::new();
    let Some(dir) = captures_dir else { return Ok(found) };
    for capture_id in wanted {
        let file = dir.join(format!("{capture_id}.json"));
        if !file.is_file() {
            continue;
        }
        let data = std::fs::read(&file)?;
        if data.len() > MAX_CAPTURE_BYTES {
            return fail(
                "payload_refused",
                format!("capture {capture_id} is {} bytes; a bundle carries at most {MAX_CAPTURE_BYTES} per capture", data.len()),
            );
        }
        let parsed =
            parse_json(&data).map_err(|e| bundle(BundleError::new("capture_invalid", format!("capture {capture_id} is not JSON: {e}"))))?;
        if parsed.get("capture_id") != Some(&json!(capture_id)) || !parsed.is_object() {
            return fail("capture_invalid", format!("capture {capture_id} must be a JSON object whose capture_id is {capture_id}"));
        }
        guard_payload(&parsed, &format!("capture {capture_id}"))?;
        found.insert(capture_id.clone(), json_bytes(&parsed)?); // canonical bytes: the same capture hashes the same everywhere
    }
    Ok(found)
}

#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    pub game: String,
    pub subsystem: String,
    pub build: String,
    pub captures_dir: Option<PathBuf>,
    pub traces_dir: Option<PathBuf>,
    pub overwrite: bool,
    pub ctx: Ctx,
    /// The environment.json content; `None` records this process (`hydralysis`, `python`, `platform`, ...).
    pub environment: Option<Value>,
}

fn platform_name() -> &'static str {
    if cfg!(windows) {
        "win32"
    } else if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    }
}

fn sha_map(map: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, String> {
    map.iter().map(|(k, v)| (k.clone(), sha256_hex(v))).collect()
}

/// Write the selected claims (superseded ones too) as a bundle folder, atomically.
pub fn export_bundle(db_path: &Path, out: &Path, options: &ExportOptions) -> Result<Value> {
    if out.exists() && !options.overwrite {
        return fail("bundle_exists", format!("{} exists; pass overwrite to replace a bundle", out.display()));
    }
    if out.exists() && !out.join("manifest.json").is_file() {
        return fail("not_a_bundle", format!("{} exists and is not a bundle folder; it is not replaced", out.display()));
    }
    let records = evidence::records_for_bundle(db_path, &options.game, &options.subsystem, &options.build)?;
    if records.is_empty() {
        return fail(
            "empty_selection",
            format!(
                "no claims match game={} subsystem={} build={}",
                py_repr_str(&options.game),
                py_repr_str(&options.subsystem),
                py_repr_str(&options.build)
            ),
        );
    }
    for record in &records {
        let id = s(record, "evidence_id");
        guard_payload(&record["content"], &format!("claim {id}"))?;
        guard_payload(&record["meta"], &format!("claim {id} meta"))?;
    }
    let cited: BTreeSet<String> =
        records.iter().filter_map(|r| r["content"]["from_capture"].as_str().filter(|c| !c.is_empty()).map(String::from)).collect();
    let captures = load_captures(options.captures_dir.as_deref(), &cited)?;
    if captures.len() > MAX_CAPTURES {
        return fail("payload_refused", format!("too many captures ({}, at most {MAX_CAPTURES})", captures.len()));
    }
    let pins = load_traces(options.traces_dir.as_deref(), &records)?;
    let mut trace_blobs = BTreeMap::new();
    for (session, pin) in &pins {
        trace_blobs.insert(session.clone(), json_bytes(pin)?);
    }
    let subjects = subjects_of(&records);
    let replay = replay_of(&records, &captures.keys().cloned().collect(), Some(&pins));
    let limitations = limitations_of(&records);
    let capture_hashes = sha_map(&captures);
    let trace_hashes = sha_map(&trace_blobs);
    let bundle_id = bundle_id_of(&records, &subjects, &capture_hashes, &replay, &limitations, &trace_hashes)?;
    let exported_at = options.ctx.now();
    let environment = options.environment.clone().unwrap_or_else(|| {
        json!({"hydralysis": HYDRALYSIS_VERSION, "python": "rust", "platform": platform_name(), "exported_at": exported_at, "exported_by": options.ctx.who().1})
    });
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    files.insert("evidence.jsonl".into(), jsonl(&records)?);
    files.insert("subjects.json".into(), json_bytes(&subjects)?);
    files.insert("replay.json".into(), json_bytes(&replay)?);
    files.insert("environment.json".into(), json_bytes(&environment)?);
    files.insert("limitations.md".into(), limitations_md(&limitations));
    for (key, data) in &captures {
        files.insert(format!("captures/{key}.json"), data.clone());
    }
    for (key, data) in &trace_blobs {
        files.insert(format!("traces/{key}.json"), data.clone());
    }
    let table: Map<String, Value> = files.iter().map(|(n, d)| (n.clone(), json!({"bytes": d.len(), "sha256": sha256_hex(d)}))).collect();
    let manifest = json!({
        "format": FORMAT, "bundle_id": bundle_id, "records": records.len(),
        "filter": {"game": options.game, "subsystem": options.subsystem, "build": options.build},
        "files": table,
        "volatile": {"exported_at": exported_at, "files": VOLATILE_FILES.iter().filter(|n| **n != "manifest.json").collect::<Vec<_>>()},
    });
    files.insert("manifest.json".into(), json_bytes(&manifest)?);
    let name = out.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    let parent = out.parent().filter(|p| !p.as_os_str().is_empty()).map_or_else(|| PathBuf::from("."), Path::to_path_buf);
    let stage = parent.join(format!("{name}.{}.staging", &uuid::Uuid::new_v4().simple().to_string()[..12]));
    std::fs::create_dir_all(&parent)?;
    let outcome = (|| -> Result<()> {
        for (file, data) in &files {
            hy_core::fsio::atomic_write(&stage.join(file), data)?;
        }
        let mut aside = None;
        if out.exists() {
            let moved = parent.join(format!("{name}.{}.old", &uuid::Uuid::new_v4().simple().to_string()[..12]));
            hy_core::fsio::replace_file(out, &moved)?; // a move to a name that is free: no folder is overwritten
            aside = Some(moved);
        }
        if let Err(error) = hy_core::fsio::replace_file(&stage, out) {
            if let Some(moved) = &aside {
                hy_core::fsio::replace_file(moved, out)?;
            }
            return Err(error.into());
        }
        if let Some(moved) = aside {
            let _ = std::fs::remove_dir_all(moved);
        }
        Ok(())
    })();
    if stage.exists() {
        let _ = std::fs::remove_dir_all(&stage);
    }
    outcome?;
    let mut result = Map::new();
    result.insert("bundle".into(), json!(out.display().to_string()));
    result.insert("bundle_id".into(), json!(bundle_id));
    result.insert("records".into(), json!(records.len()));
    result.insert("captures".into(), json!(captures.len()));
    result.insert("missing_captures".into(), replay["missing_captures"].clone());
    result.insert("limitations".into(), json!(limitations.keys().collect::<Vec<_>>()));
    if !pins.is_empty() {
        result.insert("traces".into(), json!(pins.len()));
        result.insert(
            "unreproducible_traces".into(),
            json!(pins.iter().filter(|(_, p)| p["reproducible"] != true).map(|(k, _)| k).collect::<Vec<_>>()),
        );
    }
    Ok(Value::Object(result))
}

// ---- reading and verifying -----------------------------------------------------------------------------------------

/// `^(?:manifest\.json|evidence\.jsonl|subjects\.json|replay\.json|environment\.json|limitations\.md|(?:captures|traces)/<id>\.json)$`
pub fn name_ok(name: &str) -> bool {
    let name = name.strip_suffix('\n').unwrap_or(name);
    if ["manifest.json", "evidence.jsonl", "subjects.json", "replay.json", "environment.json", "limitations.md"].contains(&name) {
        return true;
    }
    for prefix in ["captures/", "traces/"] {
        if let Some(rest) = name.strip_prefix(prefix)
            && let Some(stem) = rest.strip_suffix(".json")
        {
            return id_like(stem, &['.', '-'], 79);
        }
    }
    false
}

fn read_file(folder: &Path, name: &str, expected: Option<&Value>) -> Result<Vec<u8>> {
    if !name_ok(name) {
        return fail("bundle_path_refused", format!("{} is not a file a bundle may hold", py_repr_str(name)));
    }
    let file = folder.join(name);
    let is_link = std::fs::symlink_metadata(&file).is_ok_and(|m| m.file_type().is_symlink());
    if is_link || !file.is_file() {
        return Err(bundle(
            BundleError::new("bundle_file_missing", format!("{name} is missing from the bundle")).with("file", json!(name)),
        ));
    }
    let size = std::fs::metadata(&file)?.len();
    if size > MAX_FILE_BYTES {
        return Err(bundle(
            BundleError::new("bundle_file_too_large", format!("{name} is {size} bytes; at most {MAX_FILE_BYTES}"))
                .with("file", json!(name)),
        ));
    }
    let data = std::fs::read(&file)?;
    if let Some(expected) = expected {
        let Value::Object(map) = expected else {
            return Err(EvidenceError::value("'x' object has no attribute 'get'"));
        };
        if map.get("bytes").and_then(Value::as_u64) != Some(data.len() as u64)
            || map.get("sha256").and_then(Value::as_str) != Some(sha256_hex(&data).as_str())
        {
            return Err(bundle(
                BundleError::new("bundle_file_changed", format!("{name} does not match the hash in the manifest"))
                    .with("file", json!(name)),
            ));
        }
    }
    Ok(data)
}

fn walk(base: &Path, dir: &Path, out: &mut BTreeSet<String>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(base, &path, out);
        } else if path.is_file()
            && let Ok(rel) = path.strip_prefix(base)
        {
            out.insert(rel.to_string_lossy().replace('\\', "/"));
        }
    }
}

/// Python's `str.splitlines()`.
pub fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let (mut start, mut chars) = (0, text.char_indices().peekable());
    while let Some((index, c)) = chars.next() {
        let boundary = matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}');
        if boundary {
            lines.push(&text[start..index]);
            let mut end = index + c.len_utf8();
            if c == '\r'
                && let Some(&(next, '\n')) = chars.peek()
            {
                chars.next();
                end = next + 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

#[derive(Debug, Clone)]
pub struct LoadedBundle {
    pub bundle_id: String,
    pub manifest: Value,
    pub records: Vec<Value>,
    pub subjects: Value,
    pub replay: Value,
    pub limitations: BTreeMap<String, Vec<String>>,
    pub captures: BTreeMap<String, String>,
    pub traces: BTreeMap<String, Value>,
    pub files: Value,
    pub environment: Value,
    pub dangling_links: Vec<String>,
    pub capture_blobs: BTreeMap<String, Vec<u8>>,
}

impl LoadedBundle {
    /// The Python dict `load_bundle` returns.
    pub fn to_value(&self) -> Value {
        json!({
            "bundle_id": self.bundle_id, "manifest": self.manifest, "records": self.records, "subjects": self.subjects,
            "replay": self.replay, "limitations": limitations_value(&self.limitations), "captures": self.captures,
            "traces": self.traces, "files": self.files, "environment": self.environment, "dangling_links": self.dangling_links,
        })
    }
}

fn integrity_to_bundle(error: EvidenceError, number: usize) -> EvidenceError {
    match error {
        EvidenceError::Integrity(e) => {
            bundle(BundleError::new(&e.code, format!("evidence.jsonl line {number}: {e}")).with("evidence_id", json!(e.evidence_id)))
        }
        other => other,
    }
}

/// Read a bundle and prove it: file hashes, every evidence id, the derived files and the bundle id.
pub fn load_bundle(folder: &Path) -> Result<LoadedBundle> {
    if !folder.is_dir() {
        return fail("bundle_missing", format!("{} is not a bundle folder", folder.display()));
    }
    let manifest_bytes = read_file(folder, "manifest.json", None)?;
    let manifest = parse_json(&manifest_bytes)
        .map_err(|e| bundle(BundleError::new("bundle_manifest_invalid", format!("manifest.json is not JSON: {e}"))))?;
    let files_table = match manifest.get("files") {
        Some(Value::Object(f)) if manifest.get("format") == Some(&json!(FORMAT)) => f.clone(),
        _ => return fail("bundle_manifest_invalid", format!("manifest.json is not a {FORMAT} manifest")),
    };
    let listed: BTreeSet<String> = files_table.keys().cloned().collect();
    for name in &listed {
        if !name_ok(name) || name == "manifest.json" {
            return fail("bundle_path_refused", format!("the manifest lists {}, which a bundle may not hold", py_repr_str(name)));
        }
    }
    for required in ["evidence.jsonl", "subjects.json", "replay.json", "environment.json", "limitations.md"] {
        if !listed.contains(required) {
            return fail("bundle_manifest_invalid", format!("the manifest does not list {required}"));
        }
    }
    let mut present = BTreeSet::new();
    walk(folder, folder, &mut present);
    let extra: Vec<String> = present.iter().filter(|p| !listed.contains(*p) && *p != "manifest.json").cloned().collect();
    if !extra.is_empty() {
        return Err(bundle(
            BundleError::new("bundle_unlisted_file", format!("the bundle holds files the manifest does not list: {}", extra.join(", ")))
                .with("files", json!(extra)),
        ));
    }
    let mut blobs: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for name in &listed {
        blobs.insert(name.clone(), read_file(folder, name, Some(&files_table[name]))?);
    }
    let evidence_text = std::str::from_utf8(&blobs["evidence.jsonl"]).map_err(|e| EvidenceError::value(e.to_string()))?;
    let mut records: Vec<Value> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for (index, line) in splitlines(evidence_text).into_iter().enumerate() {
        let number = index + 1;
        let record = parse_json(line.as_bytes())
            .map_err(|e| bundle(BundleError::new("bundle_record_invalid", format!("evidence.jsonl line {number} is not JSON: {e}"))))?;
        let well_formed = record.as_object().is_some_and(|o| {
            o.len() == 3 && ["evidence_id", "content", "meta"].iter().all(|k| o.contains_key(*k)) && o["content"].is_object()
        });
        if !well_formed {
            return fail("bundle_record_invalid", format!("evidence.jsonl line {number} is not {{evidence_id, content, meta}}"));
        }
        if !evidence::content_keys_ok(record["content"].as_object().unwrap_or(&Map::new())) {
            return fail(
                "bundle_record_invalid",
                format!("evidence.jsonl line {number} has content fields that are not those of the evidence model"),
            );
        }
        evidence::check_content(&record["content"], &record["evidence_id"])
            .and_then(|()| evidence::check_meta(Some(&record["meta"])).map(|_| ()))
            .map_err(|e| integrity_to_bundle(e, number))?;
        let id = py_str(&record["evidence_id"]);
        if !seen.insert(id.clone()) {
            return fail("bundle_duplicate_record", format!("evidence.jsonl repeats {id}"));
        }
        guard_payload(&record["content"], &format!("claim {id}"))?;
        guard_payload(&record["meta"], &format!("claim {id} meta"))?;
        records.push(record);
    }
    let ids: Vec<String> = records.iter().map(|r| py_str(&r["evidence_id"])).collect();
    if ids != seen.iter().cloned().collect::<Vec<_>>() {
        return fail("bundle_not_canonical", "evidence.jsonl is not sorted by evidence_id");
    }
    let stated = manifest.get("records");
    if stated.and_then(Value::as_u64) != Some(records.len() as u64) {
        return fail(
            "bundle_manifest_invalid",
            format!(
                "the manifest says {} records, evidence.jsonl has {}",
                stated.map_or_else(|| "None".to_string(), py_str),
                records.len()
            ),
        );
    }
    let mut captures: BTreeMap<String, Vec<u8>> = BTreeMap::new();
    for (name, data) in &blobs {
        if let Some(id) = name.strip_prefix("captures/").and_then(|n| n.strip_suffix(".json")) {
            captures.insert(id.to_string(), data.clone());
        }
    }
    for (capture_id, data) in &captures {
        let parsed =
            parse_json(data).map_err(|e| bundle(BundleError::new("capture_invalid", format!("capture {capture_id} is not JSON: {e}"))))?;
        if !parsed.is_object() || parsed.get("capture_id") != Some(&json!(capture_id)) {
            return fail("capture_invalid", format!("capture {capture_id} does not carry its own capture_id"));
        }
        guard_payload(&parsed, &format!("capture {capture_id}"))?;
    }
    let mut pins: BTreeMap<String, Value> = BTreeMap::new();
    for (name, data) in &blobs {
        let Some(session) = name.strip_prefix("traces/").and_then(|n| n.strip_suffix(".json")) else { continue };
        let parsed =
            parse_json(data).map_err(|e| bundle(BundleError::new("trace_pin_invalid", format!("trace pin {session} is not JSON: {e}"))))?;
        let pin = check_pin(&parsed, session)?;
        guard_payload(&pin, &format!("trace pin {session}"))?;
        if *data != json_bytes(&pin)? {
            return Err(bundle(
                BundleError::new("bundle_not_canonical", format!("{name} is not in canonical form")).with("file", json!(name)),
            ));
        }
        pins.insert(session.to_string(), pin);
    }
    let cited: BTreeSet<String> =
        records.iter().filter_map(|r| r["content"].get("from_trace").filter(|t| truthy(t)).map(|t| s(t, "session").to_string())).collect();
    let pin_names: BTreeSet<String> = pins.keys().cloned().collect();
    if cited != pin_names {
        let show =
            |set: &BTreeSet<String>| if set.is_empty() { "none".to_string() } else { set.iter().cloned().collect::<Vec<_>>().join(", ") };
        return fail(
            "bundle_derived_mismatch",
            format!("the trace members are not the sessions the claims cite (cited: {}, present: {})", show(&cited), show(&pin_names)),
        );
    }
    for record in &records {
        let Some(trace) = record["content"].get("from_trace").filter(|t| truthy(t)) else { continue };
        let Some(pin) = pins.get(s(trace, "session")) else { continue };
        let pinned: BTreeSet<&str> = pin["events"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        let needs: Vec<&str> = trace["events"].as_array().into_iter().flatten().filter_map(Value::as_str).collect();
        if pin["reproducible"] == true
            && (pin["revision"].as_i64() < trace["revision"].as_i64() || !needs.iter().all(|e| pinned.contains(e)))
        {
            return Err(bundle(
                BundleError::new(
                    "trace_pin_invalid",
                    format!(
                        "trace pin {} does not pin revision {} and the events claim {} cites",
                        s(trace, "session"),
                        py_str(&trace["revision"]),
                        s(record, "evidence_id")
                    ),
                )
                .with("session", json!(s(trace, "session"))),
            ));
        }
    }
    let subjects = subjects_of(&records);
    let replay = replay_of(&records, &captures.keys().cloned().collect(), Some(&pins));
    let limitations = limitations_of(&records);
    for (name, expected) in
        [("subjects.json", json_bytes(&subjects)?), ("replay.json", json_bytes(&replay)?), ("limitations.md", limitations_md(&limitations))]
    {
        if blobs[name] != expected {
            return Err(bundle(
                BundleError::new("bundle_derived_mismatch", format!("{name} does not say what the records say")).with("file", json!(name)),
            ));
        }
    }
    let capture_hashes = sha_map(&captures);
    let trace_hashes: BTreeMap<String, String> =
        pins.keys().map(|k| (k.clone(), sha256_hex(&blobs[&format!("traces/{k}.json")]))).collect();
    let bundle_id = bundle_id_of(&records, &subjects, &capture_hashes, &replay, &limitations, &trace_hashes)?;
    if manifest.get("bundle_id") != Some(&json!(bundle_id)) {
        return fail(
            "bundle_id_mismatch",
            format!(
                "bundle_id is {} but the contents hash to {bundle_id}",
                manifest.get("bundle_id").map_or_else(|| "None".to_string(), py_str)
            ),
        );
    }
    let known: BTreeSet<&str> = records.iter().map(|r| s(r, "evidence_id")).collect();
    let dangling: BTreeSet<String> = records
        .iter()
        .flat_map(|r| r["content"]["evidence_links"].as_array().into_iter().flatten().filter_map(Value::as_str))
        .filter(|l| !known.contains(l))
        .map(String::from)
        .collect();
    let environment = parse_json(&blobs["environment.json"]).map_err(EvidenceError::Value)?;
    Ok(LoadedBundle {
        bundle_id,
        files: manifest["files"].clone(),
        manifest,
        records,
        subjects,
        replay,
        limitations,
        captures: capture_hashes,
        traces: pins,
        environment,
        dangling_links: dangling.into_iter().collect(),
        capture_blobs: captures,
    })
}

/// The verdict as data: `ok` and, when not, the stable code and the message.
pub fn verify_bundle(folder: &Path) -> Result<Value> {
    let loaded = match load_bundle(folder) {
        Ok(l) => l,
        Err(EvidenceError::Bundle(error)) => {
            let mut result = Map::new();
            result.insert("ok".into(), json!(false));
            if let Value::Object(payload) = error.payload() {
                result.extend(payload);
            }
            return Ok(Value::Object(result));
        }
        Err(other) => return Err(other),
    };
    let mut result = Map::new();
    result.insert("ok".into(), json!(true));
    result.insert("bundle_id".into(), json!(loaded.bundle_id));
    result.insert("records".into(), json!(loaded.records.len()));
    result.insert("captures".into(), json!(loaded.captures.len()));
    result.insert("missing_captures".into(), loaded.replay["missing_captures"].clone());
    result.insert("dangling_links".into(), json!(loaded.dangling_links));
    result.insert("limitations".into(), json!(loaded.limitations.keys().collect::<Vec<_>>()));
    if !loaded.traces.is_empty() {
        result.insert("traces".into(), json!(loaded.traces.len()));
        let unreproducible: Vec<&String> =
            loaded.replay.get("unreproducible_traces").and_then(Value::as_object).map(|o| o.keys().collect()).unwrap_or_default();
        let mut sorted = unreproducible;
        sorted.sort();
        result.insert("unreproducible_traces".into(), json!(sorted));
    }
    Ok(Value::Object(result))
}

// ---- comparing -------------------------------------------------------------------------------------------------

fn logical_key(content: &Value) -> String {
    ["game", "build", "kind", "name", "address", "subsystem"].iter().map(|k| s(content, k)).collect::<Vec<_>>().join("|")
}

fn classification(left: bool, right: bool) -> &'static str {
    match (left, right) {
        (true, true) => "changed",
        (true, false) => "removed",
        _ => "added",
    }
}

/// Classify the differences between two verified bundles; volatile fields are named, not compared.
pub fn compare_bundles(left: &Path, right: &Path) -> Result<Value> {
    let (one, two) = (load_bundle(left)?, load_bundle(right)?);
    let by_id =
        |b: &LoadedBundle| -> BTreeMap<String, Value> { b.records.iter().map(|r| (py_str(&r["evidence_id"]), r.clone())).collect() };
    let (left_ids, right_ids) = (by_id(&one), by_id(&two));
    let unchanged = left_ids.keys().filter(|k| right_ids.contains_key(*k)).count();
    let only_left: Vec<&String> = left_ids.keys().filter(|k| !right_ids.contains_key(*k)).collect();
    let only_right: Vec<&String> = right_ids.keys().filter(|k| !left_ids.contains_key(*k)).collect();
    let mut keys_left: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut keys_right: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for id in &only_left {
        keys_left.entry(logical_key(&left_ids[*id]["content"])).or_default().push((*id).clone());
    }
    for id in &only_right {
        keys_right.entry(logical_key(&right_ids[*id]["content"])).or_default().push((*id).clone());
    }
    let mut changes: Vec<Value> = Vec::new();
    let all_keys: BTreeSet<&String> = keys_left.keys().chain(keys_right.keys()).collect();
    for key in all_keys {
        let class = classification(keys_left.contains_key(key), keys_right.contains_key(key));
        changes.push(json!({
            "entity": "evidence", "key": key, "classification": class,
            "left_evidence_ids": keys_left.get(key).cloned().unwrap_or_default(),
            "right_evidence_ids": keys_right.get(key).cloned().unwrap_or_default(),
        }));
    }
    let capture_ids: BTreeSet<&String> = one.captures.keys().chain(two.captures.keys()).collect();
    for id in capture_ids {
        let (l, r) = (one.captures.get(id), two.captures.get(id));
        if l != r {
            changes.push(json!({
                "entity": "capture", "key": id,
                "classification": if l.is_none() { "added" } else if r.is_none() { "removed" } else { "changed" },
                "left_digest": l, "right_digest": r,
            }));
        }
    }
    let sessions: BTreeSet<&String> = one.traces.keys().chain(two.traces.keys()).collect();
    for session in sessions {
        let (l, r) = (one.traces.get(session), two.traces.get(session));
        if l != r {
            changes.push(json!({
                "entity": "trace", "key": session,
                "classification": if l.is_none() { "added" } else if r.is_none() { "removed" } else { "changed" },
                "left_revision": l.map(|p| p["revision"].clone()), "right_revision": r.map(|p| p["revision"].clone()),
            }));
        }
    }
    let codes: BTreeSet<&String> = one
        .limitations
        .keys()
        .filter(|k| !two.limitations.contains_key(*k))
        .chain(two.limitations.keys().filter(|k| !one.limitations.contains_key(*k)))
        .collect();
    for code in codes {
        changes.push(json!({"entity": "limitation", "key": code, "classification": if two.limitations.contains_key(code) { "added" } else { "removed" }}));
    }
    let names: BTreeSet<String> = [&one.files, &two.files].iter().filter_map(|f| f.as_object()).flat_map(|o| o.keys().cloned()).collect();
    let volatile: Vec<&String> =
        names.iter().filter(|n| VOLATILE_FILES.contains(&n.as_str()) && one.files.get(n.as_str()) != two.files.get(n.as_str())).collect();
    let changed = changes.iter().filter(|c| c["entity"] == "evidence" && c["classification"] == "changed").count();
    Ok(json!({
        "status": if one.bundle_id == two.bundle_id { "equal" } else { "different" },
        "left_bundle_id": one.bundle_id, "right_bundle_id": two.bundle_id,
        "summary": {"records_unchanged": unchanged, "records_added": only_right.len(), "records_removed": only_left.len(), "records_changed": changed},
        "changes": changes,
        "volatile_ignored": {
            "fields": ["manifest.volatile", "meta.created", "meta.client", "meta.harness", "meta.provenance", "environment.json"],
            "files_differing": volatile,
        },
    }))
}

// ---- importing -------------------------------------------------------------------------------------------------

/// Verify the bundle, then store its records in the ledger. Records already there are skipped.
pub fn import_bundle(folder: &Path, db_path: &Path, ctx: &Ctx) -> Result<Value> {
    let loaded = load_bundle(folder)?;
    let summary = evidence::import_records(db_path, &loaded.records, ctx)?;
    let mut result = Map::new();
    result.insert("bundle_id".into(), json!(loaded.bundle_id));
    result.insert("records".into(), json!(loaded.records.len()));
    if let Value::Object(map) = summary {
        result.extend(map);
    }
    result.insert("missing_captures".into(), loaded.replay["missing_captures"].clone());
    Ok(Value::Object(result))
}

// ---- the capability handler ------------------------------------------------------------------------------------------

fn absolute(value: Option<&Value>, what: &str) -> Result<PathBuf> {
    let text = value.filter(|v| truthy(v)).map(py_str).unwrap_or_default();
    let path = PathBuf::from(&text);
    if text.is_empty() || !path.is_absolute() {
        return fail("path_not_absolute", format!("{what} must be an absolute path"));
    }
    Ok(path)
}

/// `options.op` = export | verify | compare | import, answered as the Python handler does (`json.dumps(indent=2)`).
/// `evidence_path` resolves the ledger path from the explicit text (`config.evidence_path`).
pub fn handle(request: &Value, evidence_path: &dyn Fn(&str) -> PathBuf, ctx: &Ctx) -> String {
    let empty = json!({});
    let options = request.get("options").filter(|o| truthy(o)).unwrap_or(&empty);
    let args = request.get("args").filter(|o| truthy(o)).unwrap_or(&empty);
    let op = options.get("op").map_or_else(|| "verify".to_string(), py_str);
    let text =
        |keys: &[&str]| -> String { keys.iter().find_map(|k| options.get(*k).filter(|v| truthy(v)).map(py_str)).unwrap_or_default() };
    let run = || -> Result<Value> {
        let explicit =
            options.get("db").filter(|v| truthy(v)).or_else(|| args.get("db").filter(|v| truthy(v))).map(py_str).unwrap_or_default();
        let db = evidence_path(&explicit);
        match op.as_str() {
            "export" => {
                let out = absolute(options.get("out"), "options.out")?;
                let opts = ExportOptions {
                    game: text(&["target", "game"]),
                    subsystem: text(&["subsystem"]),
                    build: text(&["build"]),
                    captures_dir: match options.get("captures").filter(|v| truthy(v)) {
                        Some(v) => Some(absolute(Some(v), "options.captures")?),
                        None => None,
                    },
                    traces_dir: match options.get("traces").filter(|v| truthy(v)) {
                        Some(v) => Some(absolute(Some(v), "options.traces")?),
                        None => None,
                    },
                    overwrite: options.get("overwrite").is_some_and(truthy),
                    ctx: ctx.clone(),
                    environment: None,
                };
                export_bundle(&db, &out, &opts)
            }
            "verify" => verify_bundle(&absolute(options.get("bundle"), "options.bundle")?),
            "compare" => {
                compare_bundles(&absolute(options.get("left"), "options.left")?, &absolute(options.get("right"), "options.right")?)
            }
            "import" => import_bundle(&absolute(options.get("bundle"), "options.bundle")?, &db, ctx),
            _ => fail("unknown_op", "options.op must be export, verify, compare or import"),
        }
    };
    let dump = |value: &Value| {
        let o = hy_core::json::Options { layout: hy_core::json::Layout::Pretty(2), sort_keys: false, ensure_ascii: true };
        String::from_utf8(hy_core::json::dumps(value, o)).unwrap_or_default()
    };
    match run() {
        Ok(result) => {
            let mut map = Map::new();
            map.insert("op".into(), json!(op));
            if let Value::Object(r) = result {
                map.extend(r);
            }
            dump(&Value::Object(map))
        }
        Err(EvidenceError::Bundle(error)) => dump(&error.payload()),
        Err(EvidenceError::Integrity(error)) => dump(&json!({"error": error.code, "message": error.message})),
        Err(other) => dump(&json!({"error": "internal", "message": other.to_string()})),
    }
}

/// Re-exported for callers that build integrity errors themselves.
pub type IntegrityError = EvidenceIntegrityError;
