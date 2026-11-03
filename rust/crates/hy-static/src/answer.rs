//! The engine-shaped JSON for the questions the static plane answers exactly.
//!
//! `RusticQuery.java` answers with the program envelope (`id`, `program`, `sha256`, `image_base`, `address_kind`),
//! then the rows of the action (`references`, `function`, `functions`), then `ok`. Anything else the script returns
//! for other actions (`decompile`, `types`, ...) needs data this plane does not read, and is not answered here.

use std::path::Path;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::cache::{self, Cache};
use crate::error::{Error, Result};
use crate::index::FunctionData;
use crate::program::{ProgramInfo, StaticProgram, address_text};

/// The actions [`answer`] can answer. Everything else goes to the engine.
pub const ACTIONS: &[&str] = &["xrefs", "function", "functions"];

/// The largest database file whose function rows the plane builds (once per program version, then cached).
pub const INDEX_FILE_MAX: u64 = 48 << 20;

fn text<'a>(request: &'a Value, key: &str) -> &'a str {
    request.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `RusticQuery.address(String)` for the default space: `rva:` adds the image base, `va:` and `0x` are dropped,
/// the rest is a hexadecimal offset. Anything `toAddr` would refuse is declined.
fn parse_address(info: &ProgramInfo, value: &str) -> Result<u64> {
    let value = value.trim();
    let hex = |digits: &str| -> Result<u64> {
        let digits = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")).unwrap_or(digits);
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::unsupported("address is not plain hexadecimal"));
        }
        u64::from_str_radix(digits, 16).map_err(|_| Error::unsupported("address too large"))
    };
    if let Some(rest) = value.strip_prefix("rva:") {
        return info.image_base.checked_add(hex(rest)?).ok_or_else(|| Error::unsupported("rva wraps the address space"));
    }
    hex(value.strip_prefix("va:").unwrap_or(value))
}

/// The checks every action shares, and the envelope the answer starts with.
fn head(info: &ProgramInfo, request: &Value) -> Result<(Map<String, Value>, usize)> {
    let action = text(request, "action");
    if !ACTIONS.contains(&action) {
        return Err(Error::unsupported(format!("action {action:?} needs the engine")));
    }
    let expected = text(request, "expected_sha256");
    if !expected.is_empty() && !expected.eq_ignore_ascii_case(&info.sha256) {
        return Err(Error::unsupported("the program hash differs from the target build (the engine refuses it with its own message)"));
    }
    let limit = request
        .get("limit")
        .and_then(Value::as_u64)
        .filter(|n| (1..=200).contains(n))
        .ok_or_else(|| Error::unsupported("limit outside 1..200"))? as usize;
    let mut out = Map::new();
    out.insert("id".into(), Value::String(text(request, "id").to_owned()));
    out.insert("program".into(), Value::String(info.name.clone()));
    out.insert("sha256".into(), Value::String(info.sha256.clone()));
    out.insert("image_base".into(), Value::String(format!("0x{}", address_text(info.image_base))));
    out.insert("address_kind".into(), Value::String("VA".into()));
    Ok((out, limit))
}

/// Answer `request` (the JSON `RusticQuery` is given) for `program` when this plane can do it exactly.
///
/// This reads what it needs from `program` and keeps nothing (function rows are rebuilt on every call);
/// [`answer_in_project`] is the cached path.
///
/// # Errors
///
/// `Unsupported` for any action not in [`ACTIONS`], an expected hash that differs from the program's, a cursor the
/// engine would reject, or anything the program itself does not allow; `Failed` for unreadable files.
pub fn answer(program: &StaticProgram, request: &Value) -> Result<Value> {
    let (mut out, limit) = head(program.info(), request)?;
    if text(request, "action") == "xrefs" {
        xrefs(program, request, limit, &mut out)?;
    } else {
        index_allowed(program.located().stamp.len)?;
        let data = FunctionData::build(program)?;
        function_actions(program.info(), &data, request, limit, &mut out)?;
    }
    out.insert("ok".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

fn xrefs(program: &StaticProgram, request: &Value, limit: usize, out: &mut Map<String, Value>) -> Result<()> {
    let address = parse_address(program.info(), text(request, "address"))?;
    let cursor = text(request, "cursor");
    let skip = if cursor.is_empty() {
        0
    } else {
        let digits = cursor.strip_prefix("0x").unwrap_or(cursor);
        let n = u64::from_str_radix(digits, 16).map_err(|_| Error::unsupported("cursor is not hexadecimal"))?;
        if n > i64::MAX as u64 {
            return Err(Error::unsupported("cursor outside the supported row range"));
        }
        n as usize
    };
    let refs = program.xrefs_to(address)?;
    let page: Vec<&_> = refs.iter().skip(skip).take(limit).collect();
    let more = refs.len() > skip.saturating_add(page.len());
    let rows: Vec<Value> = page
        .iter()
        .map(|r| json!({"from": format!("0x{}", r.from_text()), "to": format!("0x{}", r.to_text()), "type": r.ref_type}))
        .collect();
    out.insert("references".into(), Value::Array(rows));
    out.insert("truncated".into(), Value::Bool(more));
    if more {
        out.insert("next_cursor".into(), Value::String(format!("0x{:x}", skip + page.len())));
    }
    Ok(())
}

/// Building the function rows reads the whole symbol and function tables once per program version; above this size
/// the first answer would take longer than the engine's, so the plane declines (rows already cached are served at
/// any size).
fn index_allowed(file_len: u64) -> Result<()> {
    if file_len > INDEX_FILE_MAX {
        return Err(Error::unsupported("program database too large to index here; the engine is faster"));
    }
    Ok(())
}

fn function_actions(info: &ProgramInfo, data: &FunctionData, request: &Value, limit: usize, out: &mut Map<String, Value>) -> Result<()> {
    if text(request, "action") == "function" { function(info, data, request, out) } else { functions(info, data, request, limit, out) }
}

/// `RusticQuery`: `getFunctionContaining(address)`, or an error the engine words.
fn function(info: &ProgramInfo, data: &FunctionData, request: &Value, out: &mut Map<String, Value>) -> Result<()> {
    let address = parse_address(info, text(request, "address"))?;
    let found =
        data.containing(address).ok_or_else(|| Error::unsupported("no function contains the address (the engine words that error)"))?;
    let row = found.row.as_ref().map_err(Clone::clone)?;
    out.insert("function".into(), row.to_value());
    Ok(())
}

/// `RusticQuery` `functions`: entry order from the cursor, at most 2000 scanned and `limit` rows per page.
fn functions(info: &ProgramInfo, data: &FunctionData, request: &Value, limit: usize, out: &mut Map<String, Value>) -> Result<()> {
    let contains = text(request, "contains");
    if !contains.is_ascii() {
        return Err(Error::unsupported("non-ASCII filter (Java lower-cases with its own rules)"));
    }
    let cursor = text(request, "cursor");
    let from = if cursor.is_empty() { 0 } else { parse_address(info, cursor)? };
    let internal = data.rows();
    let start = internal.partition_point(|f| f.entry < from);
    let needle = contains.to_ascii_lowercase();
    let mut rows_out = Vec::new();
    let mut scanned = 0usize;
    let mut last = None;
    let mut at = start;
    while at < internal.len() && scanned < 2000 && rows_out.len() < limit {
        let f = &internal[at];
        last = Some(f.entry);
        scanned += 1;
        at += 1;
        let name = f.name.as_deref().ok_or_else(|| Error::unsupported("function without a computable name"))?;
        if !name.is_ascii() {
            return Err(Error::unsupported("non-ASCII function name"));
        }
        if name.to_ascii_lowercase().contains(&needle) {
            rows_out.push(f.row.as_ref().map_err(Clone::clone)?.to_value());
        }
    }
    let more = at < internal.len();
    out.insert("functions".into(), Value::Array(rows_out));
    out.insert("scanned".into(), json!(scanned));
    out.insert("truncated".into(), Value::Bool(more));
    if let (true, Some(last)) = (more, last) {
        out.insert("next_cursor".into(), Value::String(format!("0x{}", address_text(last + 1))));
    }
    Ok(())
}

/// Open `program` in `project` through the process-wide [`cache::global`] cache and [`answer`].
///
/// # Errors
///
/// As [`answer`]; `Failed` too when the files changed under the read.
pub fn answer_in_project(project: &Path, program: &str, request: &Value) -> Result<Value> {
    answer_in_project_with(cache::global(), project, program, request)
}

/// [`answer_in_project`] with a given cache.
///
/// # Errors
///
/// As [`answer_in_project`].
pub fn answer_in_project_with(cache: &Cache, project: &Path, program: &str, request: &Value) -> Result<Value> {
    // Refuse what no file can change before touching any.
    let action = text(request, "action");
    if !ACTIONS.contains(&action) {
        return Err(Error::unsupported(format!("action {action:?} needs the engine")));
    }
    let (meta, mut out) = if action == "xrefs" {
        let opened = cache.open(project, program)?;
        let (mut out, limit) = head(opened.info(), request)?;
        xrefs(&opened, request, limit, &mut out)?;
        (Arc::clone(opened.meta()), out)
    } else {
        let (meta, data) = cache.functions(project, program, INDEX_FILE_MAX)?;
        let (mut out, limit) = head(meta.info(), request)?;
        function_actions(meta.info(), &data, request, limit, &mut out)?;
        (meta, out)
    };
    if !meta.unchanged() {
        return Err(Error::failed("the project files changed while they were read"));
    }
    out.insert("ok".into(), Value::Bool(true));
    Ok(Value::Object(out))
}
