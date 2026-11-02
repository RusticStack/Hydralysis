//! Sealed JSON records (`durable` sealed section): a top-level `seal` over the canonical body, a `.bak` previous
//! version, and a reader that falls back to it. A record is never started empty over corruption.

use crate::error::{Error, Result};
use crate::fault::fault;
use crate::fsio::{abspath, atomic_write_point, read_optional, with_suffix};
use crate::json::{self, Layout, Options};
use crate::lock;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};

pub const LOCK_TIMEOUT_S: f64 = 30.0;

pub fn sha256_hex(data: &[u8]) -> String {
    let digest = Sha256::digest(data);
    let mut out = String::with_capacity(64);
    for byte in digest {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn seal_of(body: &Value) -> Value {
    let mut map = Map::new();
    map.insert("algo".into(), Value::String("sha256".into()));
    map.insert("value".into(), Value::String(sha256_hex(&json::canonical(body))));
    Value::Object(map)
}

/// Seal and encode. `indent = Some(n)` is `json.dumps(indent=n)`; `None` is the default `(", ", ": ")` layout.
pub fn dumps_sealed(value: &Value, indent: Option<usize>) -> Result<Vec<u8>> {
    let Value::Object(body) = value else {
        return Err(Error::value("a sealed record must be a JSON object"));
    };
    if body.contains_key("seal") {
        return Err(Error::value("a sealed record cannot carry its own top-level 'seal' key"));
    }
    let seal = seal_of(value);
    let mut full = body.clone();
    full.insert("seal".into(), seal);
    let layout = indent.map_or(Layout::Spaced, Layout::Pretty);
    Ok(json::dumps(&Value::Object(full), Options { layout, sort_keys: false, ensure_ascii: true }))
}

#[derive(Debug, Clone, PartialEq)]
pub enum Kind {
    Missing,
    Invalid,
    Sealed,
    Unsealed,
}

impl Kind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Kind::Missing => "missing",
            Kind::Invalid => "invalid",
            Kind::Sealed => "sealed",
            Kind::Unsealed => "unsealed",
        }
    }
}

/// `(kind, value, reason)` of raw file bytes (`durable._classify`).
pub fn classify(raw: Option<&[u8]>) -> (Kind, Option<Value>, String) {
    let Some(raw) = raw else { return (Kind::Missing, None, "missing".into()) };
    if raw.is_empty() {
        return (Kind::Invalid, None, "zero-length".into());
    }
    let value = match json::loads(raw) {
        Ok(v) => v,
        Err(error) => {
            let text = error.to_string();
            // Python parses a lone surrogate escape and then fails to canonicalise a sealed body; serde refuses it at parse
            // time. A sealed-looking file with that escape reports Python's reason.
            if (text.contains("surrogate") || text.contains("hex escape")) && raw.windows(6).any(|w| w == b"\"seal\"") {
                return (Kind::Invalid, None, "body cannot be canonicalised".into());
            }
            return (Kind::Invalid, None, format!("unparseable ({})", text.chars().take(80).collect::<String>()));
        }
    };
    let Value::Object(mut map) = value else {
        return (Kind::Invalid, None, "not a JSON object".into());
    };
    let Some(claimed) = map.shift_remove("seal") else {
        return (Kind::Unsealed, Some(Value::Object(map)), String::new());
    };
    let claimed_value = match &claimed {
        Value::Object(c) if c.get("algo").and_then(Value::as_str) == Some("sha256") => c.get("value").and_then(Value::as_str),
        _ => None,
    };
    let Some(claimed_value) = claimed_value else {
        return (Kind::Invalid, None, "malformed seal".into());
    };
    let body = Value::Object(map);
    let actual = seal_of(&body)["value"].as_str().unwrap_or_default().to_string();
    if actual != claimed_value {
        return (Kind::Invalid, None, "mis-sealed (content does not match its seal)".into());
    }
    (Kind::Sealed, Some(body), String::new())
}

pub fn backup_path(path: &Path) -> PathBuf {
    with_suffix(path, ".bak")
}

pub fn inspect_file(path: &Path, max_bytes: Option<u64>, require_seal: bool) -> Result<(Kind, Option<Value>, String)> {
    let raw = read_optional(path, max_bytes)?;
    let (kind, value, reason) = classify(raw.as_deref());
    if kind == Kind::Unsealed && require_seal {
        return Ok((Kind::Invalid, None, "no seal".into()));
    }
    Ok((kind, value, reason))
}

/// True when a record file or its previous version is present.
pub fn exists(path: &Path) -> bool {
    path.is_file() || backup_path(path).is_file()
}

#[derive(Default, Clone)]
pub struct ReadOptions {
    pub max_bytes: Option<u64>,
    pub require_seal: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Source {
    File,
    Backup,
    Missing,
}

/// `(record, source)`; `default` is returned (source `Missing`) when neither file exists, else `NotFound`.
pub fn read_sealed_info(path: &Path, options: &ReadOptions, default: Option<Value>) -> Result<(Value, Source)> {
    let (kind, value, reason) = inspect_file(path, options.max_bytes, options.require_seal)?;
    if let Some(value) = value {
        return Ok((value, Source::File));
    }
    let backup = backup_path(path);
    let (bkind, bvalue, breason) = inspect_file(&backup, options.max_bytes, options.require_seal)?;
    if let Some(value) = bvalue {
        return Ok((value, Source::Backup));
    }
    if kind == Kind::Missing && bkind == Kind::Missing {
        return match default {
            Some(value) => Ok((value, Source::Missing)),
            None => Err(std::io::Error::new(std::io::ErrorKind::NotFound, path.display().to_string()).into()),
        };
    }
    let name = |p: &Path| p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    Err(Error::store_corrupt(path, &backup, vec![(name(path), reason), (name(&backup), breason)]))
}

pub fn read_sealed(path: &Path) -> Result<Value> {
    Ok(read_sealed_info(path, &ReadOptions::default(), None)?.0)
}

/// Under the writer's exclusion: keep the current file as `.bak` if it is valid, else preserve it aside.
fn keep_previous(path: &Path) -> Result<()> {
    let raw = if path.exists() { read_optional(path, None)? } else { None };
    let (kind, _, _) = classify(raw.as_deref());
    match kind {
        Kind::Sealed | Kind::Unsealed => {
            let raw = raw.unwrap_or_default();
            let backup = backup_path(path);
            if read_optional(&backup, None)?.as_deref() != Some(raw.as_slice()) {
                // Not fsynced (H16): the file it copies is valid and stays on disk until the new version, which is
                // fsynced before its replace (O2), takes its place.
                atomic_write_point(&backup, &raw, "backup", false)?;
            }
            fault("sealed.after_backup")?;
        }
        Kind::Invalid => {
            if let Some(raw) = raw.filter(|r| !r.is_empty()) {
                let name = format!(".corrupt-{}", &sha256_hex(&raw)[..8]);
                atomic_write_point(&with_suffix(path, &name), &raw, "aside", true)?;
            }
        }
        Kind::Missing => {}
    }
    Ok(())
}

/// Seal, keep the previous valid version as `.bak`, then replace atomically. Returns the bytes written.
pub fn write_sealed(
    path: &Path,
    value: &Value,
    indent: Option<usize>,
    max_bytes: Option<usize>,
    too_large: Option<&str>,
) -> Result<Vec<u8>> {
    let payload = dumps_sealed(value, indent)?;
    if let Some(limit) = max_bytes
        && payload.len() > limit
    {
        return Err(Error::value(
            too_large.map_or_else(|| format!("record would exceed {limit} bytes; existing file preserved"), str::to_string),
        ));
    }
    crate::fsio::create_parent(path)?;
    keep_previous(path)?;
    crate::fsio::atomic_write(path, &payload)?;
    Ok(payload)
}

pub fn write_sealed_default(path: &Path, value: &Value) -> Result<Vec<u8>> {
    write_sealed(path, value, Some(2), None, None)
}

/// Read-modify-write a sealed record under a cross-process lock; no update is lost.
pub fn update_sealed(path: &Path, update: impl FnOnce(&mut Value) -> Option<Value>, default: Option<Value>) -> Result<Value> {
    let lock_path = with_suffix(path, ".lock");
    let _guard =
        lock::lock(&lock_path, LOCK_TIMEOUT_S, &format!("record {}", path.file_name().map(|n| n.to_string_lossy()).unwrap_or_default()))?;
    let mut current = read_sealed_info(path, &ReadOptions::default(), Some(default.unwrap_or_else(|| Value::Object(Map::new()))))?.0;
    let result = update(&mut current);
    let value = result.unwrap_or(current);
    write_sealed_default(path, &value)?;
    Ok(value)
}

/// `os.path.normcase(os.path.abspath(path))` as a map key.
pub fn path_key(path: &Path) -> String {
    let text = abspath(path).to_string_lossy().into_owned();
    if cfg!(windows) { text.replace('/', "\\").to_lowercase() } else { text }
}
