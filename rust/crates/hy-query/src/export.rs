//! Port of the pure parts of `hydralysis/export_worker.py` and `exporting.py`: JSONL replay with provenance and
//! C-text digest verification (parallel with rayon), body hashing over the PE, completeness and parity helpers.
//!
//! Anything that talks to the engine, locks or the job files stays with the caller; these functions take data and
//! return data, with the exact `ValueError` messages of the Python code.

use std::collections::HashSet;
use std::fs::File;
use std::path::Path;

use hy_pe::Image;
use memmap2::Mmap;
use rayon::prelude::*;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::decompile;

pub const MAX_OUTPUT_BYTES: u64 = 1024 * 1024 * 1024;
pub const MAX_ROW_BYTES: usize = 16 * 1024 * 1024;

fn hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

/// `_sha`: SHA-256 of a file, streamed through a map.
pub fn sha256_file(path: &Path) -> std::io::Result<String> {
    let file = File::open(path)?;
    if file.metadata()?.len() == 0 {
        return Ok(sha256_hex(b""));
    }
    // SAFETY: read-only map of a file we do not modify while hashing.
    let map = unsafe { Mmap::map(&file)? };
    Ok(sha256_hex(&map))
}

/// `exporting.code_sha256`: the implementation files' names and bytes, hashed in order.
pub fn code_sha256(package: &Path, names: &[&str]) -> std::io::Result<String> {
    let mut h = Sha256::new();
    for name in names {
        h.update(name.as_bytes());
        h.update(std::fs::read(package.join(name))?);
    }
    Ok(hex(&h.finalize()))
}

/// What a replay of a job's output file found.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Progress {
    /// Keys in file order.
    pub keys: Vec<String>,
    pub completed: u64,
    pub succeeded: u64,
    pub failed: u64,
    pub truncated: u64,
}

fn truthy(v: Option<&Value>) -> bool {
    match v {
        None | Some(Value::Null) => false,
        Some(Value::Bool(b)) => *b,
        Some(Value::Number(n)) => n.as_f64() != Some(0.0),
        Some(Value::String(s)) => !s.is_empty(),
        Some(Value::Array(a)) => !a.is_empty(),
        Some(Value::Object(o)) => !o.is_empty(),
    }
}

fn sha_text(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Stage-one result of one line: everything up to and including the key type check.
enum Line {
    Err(String),
    Row {
        key: String,
        post: Result<(bool, bool), String>,
    },
}

#[allow(clippy::too_many_arguments)] // one line plus the record fields it is checked against
fn check_line(
    n: usize,
    line: &[u8],
    has_nl: bool,
    job: &str,
    build: &str,
    mode: &str,
    provenance: &Value,
    max_row: usize,
) -> Line {
    if line.len() > max_row {
        return Line::Err(
            "export JSONL row exceeds the 16 MiB replay budget; output preserved".into(),
        );
    }
    if !has_nl {
        return Line::Err(format!(
            "torn export JSONL tail at line {n}; output preserved for recovery"
        ));
    }
    let Ok(row) = serde_json::from_slice::<Value>(line) else {
        return Line::Err(format!("invalid export JSONL line {n}; output preserved"));
    };
    let Some(obj) = row.as_object() else {
        return Line::Err(format!(
            "export JSONL line {n} is not an object; output preserved"
        ));
    };
    let is = |k: &str, want: &str| obj.get(k).and_then(Value::as_str) == Some(want);
    if !(is("job", job)
        && is("build_sha256", build)
        && is("mode", mode)
        && obj.get("provenance") == Some(provenance))
    {
        return Line::Err(format!("export JSONL provenance mismatch at line {n}"));
    }
    let Some(key) = obj.get("key").and_then(Value::as_str) else {
        return Line::Err(format!(
            "duplicate or missing export key at line {n}; output preserved"
        ));
    };
    let post = (|| {
        let state = obj.get("state").and_then(Value::as_str);
        if !matches!(state, Some("done" | "failed")) {
            return Err(format!(
                "invalid export row state at line {n}; output preserved"
            ));
        }
        let done = state == Some("done");
        let response = obj.get("result").and_then(Value::as_object);
        if done && response.is_none() {
            return Err(format!(
                "completed export row lacks a result at line {n}; output preserved"
            ));
        }
        let has_c = response.is_some_and(|r| r.contains_key("c"));
        if has_c || obj.contains_key("c_sha256") || (done && mode == "decompile") {
            let c = response.and_then(|r| r.get("c")).and_then(Value::as_str);
            let expected = obj.get("c_sha256").and_then(Value::as_str);
            match (c, expected) {
                (Some(c), Some(e)) if sha_text(e) && sha256_hex(c.as_bytes()) == e => {}
                _ => {
                    return Err(format!(
                        "export C SHA-256 mismatch at line {n}; output preserved"
                    ));
                }
            }
        }
        Ok((done, truthy(obj.get("truncated"))))
    })();
    Line::Row {
        key: key.to_string(),
        post,
    }
}

/// `replay` over the output file (the caller has checked the file exists and resolved its path).
pub fn replay_file(
    path: &Path,
    job: &str,
    build: &str,
    mode: &str,
    provenance: &Value,
    max_output: u64,
    max_row: usize,
) -> Result<Progress, String> {
    let file = File::open(path).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if meta.len() > max_output {
        return Err("export output exceeds the 1 GiB replay budget".into());
    }
    if meta.len() == 0 {
        return Ok(Progress::default());
    }
    // SAFETY: read-only map; the job's worker is the only writer and is not running during a replay.
    let map = unsafe { Mmap::map(&file) }.map_err(|e| e.to_string())?;
    let data: &[u8] = &map;
    let mut spans: Vec<(usize, usize, bool)> = Vec::new();
    let mut start = 0;
    while start < data.len() {
        match memchr::memchr(b'\n', &data[start..]) {
            Some(i) => {
                spans.push((start, start + i + 1, true));
                start += i + 1;
            }
            None => {
                spans.push((start, data.len(), false));
                break;
            }
        }
    }
    let lines: Vec<Line> = spans
        .par_iter()
        .enumerate()
        .map(|(i, &(s, e, nl))| {
            check_line(
                i + 1,
                &data[s..e],
                nl,
                job,
                build,
                mode,
                provenance,
                max_row,
            )
        })
        .collect();
    let mut out = Progress::default();
    let mut seen: HashSet<String> = HashSet::new();
    for (i, line) in lines.into_iter().enumerate() {
        match line {
            Line::Err(m) => return Err(m),
            Line::Row { key, post } => {
                if !seen.insert(key.clone()) {
                    return Err(format!(
                        "duplicate or missing export key at line {}; output preserved",
                        i + 1
                    ));
                }
                let (done, truncated) = post?;
                out.keys.push(key);
                out.completed += 1;
                if done {
                    out.succeeded += 1;
                } else {
                    out.failed += 1;
                }
                out.truncated += u64::from(truncated);
            }
        }
    }
    Ok(out)
}

fn py_repr(s: &str) -> String {
    let quote = if s.contains('\'') && !s.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::new();
    out.push(quote);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c == quote => {
                out.push('\\');
                out.push(c);
            }
            c if (c as u32) < 0x20 || c as u32 == 0x7f => {
                out.push_str(&format!("\\x{:02x}", c as u32))
            }
            c => out.push(c),
        }
    }
    out.push(quote);
    out
}

/// Python `int(text, 16)`; Err carries the ValueError text.
fn py_hex(text: &str) -> Result<u128, String> {
    let err = || format!("invalid literal for int() with base 16: {}", py_repr(text));
    let t = text.trim();
    let t = t.strip_prefix('+').unwrap_or(t);
    let t = t
        .strip_prefix("0x")
        .or_else(|| t.strip_prefix("0X"))
        .unwrap_or(t);
    if t.is_empty() || t.starts_with('_') || t.ends_with('_') || t.contains("__") {
        return Err(err());
    }
    let clean: String = t.chars().filter(|c| *c != '_').collect();
    u128::from_str_radix(&clean, 16).map_err(|_| err())
}

/// The outcome of `body_hash`. `Unsupported` means Python must answer (an input shape it would raise on).
pub enum BodyHash {
    Done(Value),
    Unsupported,
}

/// `body_hash(response, image)`.
pub fn body_hash(response: &Value, image: Option<&Image>) -> BodyHash {
    let Some(resp) = response.as_object() else {
        return BodyHash::Unsupported;
    };
    let reason = |r: &str| BodyHash::Done(json!({"body_sha256": null, "body_hash_reason": r}));
    let function_v = resp.get("function");
    let empty = Map::new();
    let function = match function_v {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(o)) if !o.is_empty() => o,
        Some(Value::Object(_)) => &empty,
        Some(_) => return BodyHash::Unsupported,
    };
    let Some(image) = image else {
        return reason("no configured PE below the 512 MiB hashing budget");
    };
    if truthy(function.get("body_truncated")) {
        return reason("function body ranges were truncated");
    }
    let ranges: Vec<Value> = match function.get("body") {
        Some(Value::Array(a)) => a.clone(),
        v if !truthy(v) => Vec::new(),
        Some(_) => return BodyHash::Unsupported,
        None => Vec::new(),
    };
    if ranges.is_empty() {
        return reason("no analysed function body ranges");
    }
    let mut digest = Sha256::new();
    digest.update(b"rusticre-body-ranges-v1\0");
    let mut total: i128 = 0;
    let base = match resp.get("image_base") {
        None => return reason("'image_base'"),
        Some(Value::String(s)) => match py_hex(s) {
            Ok(b) => b as i128,
            Err(m) => return reason(&m),
        },
        Some(_) => return BodyHash::Unsupported,
    };
    for item in &ranges {
        let Some(text) = item.as_str() else {
            return BodyHash::Unsupported;
        };
        let Some((start, end)) = parse_range(text) else {
            return reason("unsupported body range representation");
        };
        let (Ok(start), Ok(end)) = (i128::try_from(start), i128::try_from(end)) else {
            return BodyHash::Unsupported;
        };
        let size = end - start + 1;
        total += size;
        if size <= 0 || total > 16 * 1024 * 1024 {
            return reason("body exceeds the 16 MiB per-function hashing budget");
        }
        let (Ok(rva), Ok(size_i)) = (i64::try_from(start - base), i64::try_from(size)) else {
            return BodyHash::Unsupported;
        };
        match image.read_rva(rva, size_i) {
            Ok(data) => {
                digest.update((rva as u64).to_le_bytes());
                digest.update((data.len() as u64).to_le_bytes());
                digest.update(data);
            }
            Err(hy_pe::PeError::Value(m)) => return reason(&m),
            Err(_) => return BodyHash::Unsupported,
        }
    }
    BodyHash::Done(json!({
        "body_sha256": hex(&digest.finalize()),
        "body_bytes": total as i64,
        "body_hash_method": "SHA256(domain tag; ordered RVA/length little-endian uint64 pairs; raw file-backed body bytes)",
    }))
}

/// `\[([0-9a-fA-F]+),\s*([0-9a-fA-F]+)\]` fullmatch.
fn parse_range(text: &str) -> Option<(u128, u128)> {
    let inner = text.strip_prefix('[')?.strip_suffix(']')?;
    let (a, b) = inner.split_once(',')?;
    let b = b.trim_start();
    let ok = |s: &str| !s.is_empty() && s.bytes().all(|c| c.is_ascii_hexdigit()) && s.len() <= 32;
    (ok(a) && ok(b)).then(|| {
        (
            u128::from_str_radix(a, 16).unwrap(),
            u128::from_str_radix(b, 16).unwrap(),
        )
    })
}

/// `decompile_row`: the completeness fields of a decompile reply (empty for an engine without them).
pub fn decompile_row(response: &Value) -> Value {
    let summary = decompile::summarize(response);
    if summary.is_empty() {
        return json!({});
    }
    let mut out = Map::new();
    out.insert("decompile".into(), Value::Object(summary));
    out.insert("coverage".into(), decompile::coverage(response));
    let codes = decompile::limitations(response);
    if !codes.is_empty() {
        out.insert("limitations".into(), json!(codes));
    }
    Value::Object(out)
}

/// `partial`: any nested `truncated` or `body_truncated` flag set to true.
pub fn partial(response: &Value) -> bool {
    let mut pending = vec![response];
    while let Some(v) = pending.pop() {
        match v {
            Value::Object(o) => {
                if o.get("truncated") == Some(&Value::Bool(true))
                    || o.get("body_truncated") == Some(&Value::Bool(true))
                {
                    return true;
                }
                pending.extend(o.values());
            }
            Value::Array(a) => pending.extend(a),
            _ => {}
        }
    }
    false
}

/// `keys_sha256`.
pub fn keys_sha256(keys: &[&str]) -> String {
    sha256_hex(keys.join("\n").as_bytes())
}

/// `parity(snapshot, selected, progress)`; None when an input is not in the shape the Python code reads.
pub fn parity(
    snapshot: &Value,
    limit: i64,
    progress_keys: &[&str],
    succeeded: i64,
    failed: i64,
) -> Option<Value> {
    let keys: Vec<&str> = snapshot
        .get("keys")?
        .as_array()?
        .iter()
        .map(Value::as_str)
        .collect::<Option<_>>()?;
    let count = snapshot.get("count")?.as_i64()?;
    let take = usize::try_from(limit.max(0)).ok()?.min(keys.len());
    let expected_keys = &keys[..take];
    let listed: HashSet<&str> = keys.iter().copied().collect();
    let have: HashSet<&str> = progress_keys.iter().copied().collect();
    let expected = expected_keys.len() as i64;
    let missing = expected_keys.iter().filter(|k| !have.contains(**k)).count() as i64;
    let unexpected = progress_keys
        .iter()
        .filter(|k| !listed.contains(**k))
        .count() as i64;
    let accounted = succeeded + failed;
    let total = snapshot
        .get("engine_function_total")
        .cloned()
        .unwrap_or(Value::Null);
    // Python: isinstance(value, int) is true for bool as well
    let non_internal = match &total {
        Value::Bool(b) => json!(i64::from(*b) - count),
        v if v.is_i64() => json!(v.as_i64().unwrap_or(0) - count),
        _ => Value::Null,
    };
    Some(json!({
        "expected": expected, "written": succeeded, "failed": failed, "accounted": accounted,
        "missing": missing, "unexpected": unexpected, "snapshot_count": count,
        "engine_function_total": total, "non_internal": non_internal,
        "ok": accounted == expected && missing == 0 && unexpected == 0,
    }))
}
