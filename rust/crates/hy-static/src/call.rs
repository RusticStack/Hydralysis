//! One JSON-in, JSON-out entry point over the plane, for the Python binding.
//!
//! `call(name, args)` takes the function name and its arguments as JSON values and returns the answer as JSON, so
//! the PyO3 layer stays a thin pipe and the calls are testable from Rust.

use std::path::Path;

use serde_json::{Value, json};

use crate::answer::{ACTIONS, answer_in_project};
use crate::error::{Error, Result};
use crate::program::{FunctionInfo, StaticProgram, SymbolInfo, Xref, address_text};

fn arg_str(args: &[Value], at: usize) -> Result<&str> {
    args.get(at).and_then(Value::as_str).ok_or_else(|| Error::unsupported(format!("argument {at} is not a string")))
}

fn arg_u64(args: &[Value], at: usize) -> Result<u64> {
    args.get(at).and_then(Value::as_u64).ok_or_else(|| Error::unsupported(format!("argument {at} is not an unsigned number")))
}

fn xref_json(x: &Xref) -> Value {
    json!({
        "from": format!("0x{}", x.from_text()), "to": format!("0x{}", x.to_text()), "type": x.ref_type,
        "op_index": x.op_index, "source": x.source, "primary": x.primary,
    })
}

fn function_json(f: &FunctionInfo) -> Value {
    json!({
        "id": f.id, "address": format!("0x{}", address_text(f.entry)), "name": f.name, "default_named": f.default_named,
        "thunk_of": f.thunk_of, "calling_convention": f.calling_convention, "no_return": f.no_return,
        "inline": f.inline, "var_args": f.var_args,
    })
}

fn symbol_json(s: &SymbolInfo) -> Value {
    json!({
        "id": s.id, "name": s.name, "space": s.space, "address": s.address.map(|a| format!("0x{}", address_text(a))),
        "type": s.symbol_type, "parent_id": s.parent_id, "source": s.source,
    })
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(char::from(DIGITS[usize::from(b >> 4)]));
        out.push(char::from(DIGITS[usize::from(b & 15)]));
    }
    out
}

/// Run the call `name`. Every call but `supports` starts with `project` and `program`.
///
/// | name | further arguments | answer |
/// | --- | --- | --- |
/// | `supports` | `action` | `true` when [`answer_in_project`] answers that action |
/// | `answer` | request object | the engine-shaped reply of `RusticQuery` |
/// | `info` | | name, path, language, compiler, image base, hash, database version |
/// | `xrefs_to`, `xrefs_from` | address | the references, in stored order |
/// | `functions` | | every internal function |
/// | `function_at_entry` | address | the function whose entry it is, or `null` |
/// | `symbols_named` | name | the symbols with that stored name |
/// | `read_bytes` | address, length | lower-case hex |
///
/// # Errors
///
/// [`Error::Unsupported`] or [`Error::Failed`]; the caller asks the engine.
pub fn call(name: &str, args: &[Value]) -> Result<Value> {
    if name == "supports" {
        return Ok(json!(ACTIONS.contains(&arg_str(args, 0)?)));
    }
    let project = Path::new(arg_str(args, 0)?);
    let program = arg_str(args, 1)?;
    if name == "answer" {
        return answer_in_project(project, program, args.get(2).ok_or_else(|| Error::unsupported("no request"))?);
    }
    let opened = StaticProgram::open(project, program)?;
    let value = match name {
        "info" => {
            let i = opened.info();
            json!({
                "name": i.name, "program_path": i.program_path, "language": i.language, "compiler": i.compiler,
                "image_base": format!("0x{}", address_text(i.image_base)), "sha256": i.sha256, "db_version": i.db_version,
            })
        }
        "xrefs_to" => Value::Array(opened.xrefs_to(arg_u64(args, 2)?)?.iter().map(xref_json).collect()),
        "xrefs_from" => Value::Array(opened.xrefs_from(arg_u64(args, 2)?)?.iter().map(xref_json).collect()),
        "functions" => Value::Array(opened.functions()?.iter().map(function_json).collect()),
        "function_at_entry" => opened.function_at_entry(arg_u64(args, 2)?)?.map_or(Value::Null, |f| function_json(&f)),
        "symbols_named" => Value::Array(opened.symbols_named(arg_str(args, 2)?)?.iter().map(symbol_json).collect()),
        "read_bytes" => {
            let len = usize::try_from(arg_u64(args, 3)?).map_err(|_| Error::unsupported("length too large"))?;
            Value::String(hex(&opened.read_bytes(arg_u64(args, 2)?, len)?))
        }
        other => return Err(Error::unsupported(format!("no call named {other:?}"))),
    };
    if opened.located().stamp_now()? != opened.located().stamp {
        return Err(Error::failed("the database file changed while it was read"));
    }
    Ok(value)
}

/// [`call`] as the binding returns it: `{"ok": value}` or `{"fallback": {"kind", "reason"}}`.
pub fn call_json(name: &str, args: &[Value]) -> Value {
    match call(name, args) {
        Ok(value) => json!({"ok": value}),
        Err(error) => json!({"fallback": {"kind": error.kind(), "reason": error.reason()}}),
    }
}
