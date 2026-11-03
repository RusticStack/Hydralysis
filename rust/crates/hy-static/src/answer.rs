//! The engine-shaped JSON for the questions the static plane answers exactly.
//!
//! `RusticQuery.java` answers `xrefs` with the program envelope (`id`, `program`, `sha256`, `image_base`,
//! `address_kind`), then `references` (`from`, `to`, `type` per row), `truncated` and, when there is more,
//! `next_cursor`, then `ok`. Anything else the script returns for other actions (`function`, `functions`,
//! `decompile`, ...) needs data this plane does not read, and is not answered here.

use std::path::Path;

use serde_json::{Map, Value, json};

use crate::error::{Error, Result};
use crate::program::{StaticProgram, address_text};
use crate::rows;
use ghidra_progdb::Address;

/// The actions [`answer`] can answer. Everything else goes to the engine.
pub const ACTIONS: &[&str] = &["xrefs", "function", "functions"];

/// Function questions rebuild the function index on every call (nothing is kept open between calls), which grows with
/// the program; above this size the engine, warm, is the faster answer and the plane declines.
pub const INDEX_FILE_MAX: u64 = 48 << 20;

fn text<'a>(request: &'a Value, key: &str) -> &'a str {
    request.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `RusticQuery.address(String)` for the default space: `rva:` adds the image base, `va:` and `0x` are dropped,
/// the rest is a hexadecimal offset. Anything `toAddr` would refuse is declined.
fn parse_address(program: &StaticProgram, value: &str) -> Result<u64> {
    let value = value.trim();
    let hex = |digits: &str| -> Result<u64> {
        let digits = digits.strip_prefix("0x").or_else(|| digits.strip_prefix("0X")).unwrap_or(digits);
        if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(Error::unsupported("address is not plain hexadecimal"));
        }
        u64::from_str_radix(digits, 16).map_err(|_| Error::unsupported("address too large"))
    };
    if let Some(rest) = value.strip_prefix("rva:") {
        return program.info().image_base.checked_add(hex(rest)?).ok_or_else(|| Error::unsupported("rva wraps the address space"));
    }
    hex(value.strip_prefix("va:").unwrap_or(value))
}

/// Answer `request` (the JSON `RusticQuery` is given) for `program` when this plane can do it exactly.
///
/// # Errors
///
/// `Unsupported` for any action not in [`ACTIONS`], an expected hash that differs from the program's, a cursor the
/// engine would reject, or anything the program itself does not allow; `Failed` for unreadable files.
pub fn answer(program: &StaticProgram, request: &Value) -> Result<Value> {
    let action = text(request, "action");
    if !ACTIONS.contains(&action) {
        return Err(Error::unsupported(format!("action {action:?} needs the engine")));
    }
    let expected = text(request, "expected_sha256");
    let info = program.info();
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
    match action {
        "xrefs" => xrefs(program, request, limit, &mut out)?,
        "function" => function(program, request, &mut out)?,
        _ => functions(program, request, limit, &mut out)?,
    }
    out.insert("ok".into(), Value::Bool(true));
    Ok(Value::Object(out))
}

fn xrefs(program: &StaticProgram, request: &Value, limit: usize, out: &mut Map<String, Value>) -> Result<()> {
    let address = parse_address(program, text(request, "address"))?;
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

fn index_allowed(program: &StaticProgram) -> Result<()> {
    if program.located().stamp.len > INDEX_FILE_MAX {
        return Err(Error::unsupported("program database too large to index per call; the warm engine is faster"));
    }
    Ok(())
}

/// `RusticQuery`: `getFunctionContaining(address)`, or an error the engine words.
fn function(program: &StaticProgram, request: &Value, out: &mut Map<String, Value>) -> Result<()> {
    index_allowed(program)?;
    let address = parse_address(program, text(request, "address"))?;
    let prog = program.facade();
    let space = program.default_space();
    let found = prog
        .function_containing(&program.space_address(address))
        .filter(|f| rows::is_internal(f, space))
        .ok_or_else(|| Error::unsupported("no function contains the address (the engine words that error)"))?;
    out.insert("function".into(), rows::function_row(prog, found, space)?);
    Ok(())
}

/// `RusticQuery` `functions`: entry order from the cursor, at most 2000 scanned and `limit` rows per page.
fn functions(program: &StaticProgram, request: &Value, limit: usize, out: &mut Map<String, Value>) -> Result<()> {
    index_allowed(program)?;
    let contains = text(request, "contains");
    if !contains.is_ascii() {
        return Err(Error::unsupported("non-ASCII filter (Java lower-cases with its own rules)"));
    }
    let cursor = text(request, "cursor");
    let from = if cursor.is_empty() { 0 } else { parse_address(program, cursor)? };
    let prog = program.facade();
    let space = program.default_space();
    let mut internal: Vec<(u64, &ghidra_progdb::query::FunctionInfo)> = prog
        .functions()
        .iter()
        .filter(|f| rows::is_internal(f, space))
        .filter_map(|f| match &f.entry {
            Address::Space { offset, .. } => Some((*offset, f)),
            _ => None,
        })
        .collect();
    internal.sort_by_key(|(entry, _)| *entry);
    let start = internal.partition_point(|(entry, _)| *entry < from);
    let needle = contains.to_ascii_lowercase();
    let mut rows_out = Vec::new();
    let mut scanned = 0usize;
    let mut last = None;
    let mut at = start;
    while at < internal.len() && scanned < 2000 && rows_out.len() < limit {
        let (entry, f) = internal[at];
        last = Some(entry);
        scanned += 1;
        at += 1;
        let name = f.name.as_deref().ok_or_else(|| Error::unsupported("function without a computable name"))?;
        if !name.is_ascii() {
            return Err(Error::unsupported("non-ASCII function name"));
        }
        if name.to_ascii_lowercase().contains(&needle) {
            rows_out.push(rows::function_row(prog, f, space)?);
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

/// Open `program` in `project` and [`answer`], checking that the database file did not change while it was read.
///
/// # Errors
///
/// As [`answer`]; `Failed` too when the file changed under the read.
pub fn answer_in_project(project: &Path, program: &str, request: &Value) -> Result<Value> {
    let opened = StaticProgram::open(project, program)?;
    let result = answer(&opened, request)?;
    let before = opened.located().stamp;
    if opened.located().stamp_now()? != before {
        return Err(Error::failed("the database file changed while it was read"));
    }
    Ok(result)
}
