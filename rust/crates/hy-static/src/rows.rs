//! `function` and `functions` rows: `RusticQuery.function(Function)` from the stored tables.
//!
//! The row is `{address, name, signature, body, body_truncated}`. `signature` is
//! `Function.getPrototypeString(false, false)`, built here from the return type, the stored parameters and their
//! names. That is exact only where Ghidra adds nothing of its own, so a function is declined (the engine answers)
//! when any of these holds: it is a thunk (the prototype is the thunked function's), uses custom storage (storage
//! shows in the prototype), is inline, `noreturn` or variadic (modifier text not verified), has a calling convention
//! that adds automatic parameters (`this`), or a type or name the stored tables do not give.

use ghidra_fmt_gbf::BufferFile;
use ghidra_progdb::Address;
use ghidra_progdb::query::{FunctionInfo, Program};
use serde_json::{Value, json};

use crate::error::{Error, Result};
use crate::program::address_text;

/// Characters `RusticQuery` keeps of a name and of a signature.
const NAME_MAX: usize = 512;
const SIGNATURE_MAX: usize = 2048;
/// Address ranges listed in `body`.
const BODY_MAX: usize = 200;

fn clip(text: &str, max: usize) -> String {
    // Java clips UTF-16 units; ASCII is the same, anything else is declined by the caller.
    text.chars().take(max).collect()
}

fn range_text(space_default: &str, min: u64, max: u64) -> Result<String> {
    let _ = space_default;
    Ok(format!("[{}, {}]", address_text(min), address_text(max)))
}

/// The function rows are for the default space only.
pub fn is_internal(f: &FunctionInfo, default_space: &str) -> bool {
    matches!(&f.entry, Address::Space { space, .. } if space == default_space)
}

/// The calling conventions whose prototype is the stored parameters and nothing else. `__thiscall` adds `this`.
const PLAIN_CONVENTIONS: &[&str] = &["__fastcall", "__stdcall", "__cdecl", "unknown", "default"];

/// A return type that never adds a hidden storage parameter (`__return_storage_ptr__`): built-ins, pointers, enums
/// and typedefs of those. Structures, unions, arrays and anything unresolved are declined.
fn plain_return(types: &ghidra_progdb::DataTypes, mut id: i64) -> bool {
    use ghidra_progdb::DataTypeKind as K;
    for _ in 0..16 {
        let Some(t) = types.get(id) else { return false };
        match t.kind {
            K::BuiltIn | K::Pointer | K::Enum | K::Default => return true,
            K::TypeDef => match t.base {
                Some(base) => id = base,
                None => return false,
            },
            _ => return false,
        }
    }
    false
}

/// `Function.getPrototypeString(false, false)` for the functions where that is exact; otherwise `Unsupported`.
///
/// A thunk prints its own name with the thunked function's return type and parameters.
pub fn signature(prog: &Program<BufferFile>, f: &FunctionInfo, name: &str, default_space: &str) -> Result<String> {
    let mut source = f;
    for _ in 0..16 {
        match source.thunk_target {
            Some(id) => {
                source = prog.function_by_id(id).ok_or_else(|| Error::unsupported("thunk target not found"))?;
                if !is_internal(source, default_space) {
                    return Err(Error::unsupported("thunk of an external function"));
                }
            }
            None => break,
        }
    }
    if source.thunk_target.is_some() {
        return Err(Error::unsupported("thunk chain too deep"));
    }
    if source.has_custom_storage() {
        return Err(Error::unsupported("custom variable storage"));
    }
    if source.is_inline() || source.has_var_args() {
        return Err(Error::unsupported("inline or variadic function"));
    }
    if !PLAIN_CONVENTIONS.contains(&source.calling_convention.as_str()) {
        return Err(Error::unsupported("calling convention that may add automatic parameters"));
    }
    let types = prog.data_types().map_err(Error::from)?;
    let type_name = |id: Option<i64>| -> Result<String> {
        let id = id.ok_or_else(|| Error::unsupported("parameter without a data type"))?;
        let t = types.get(id).ok_or_else(|| Error::unsupported("data type id not in the manager"))?;
        Ok(t.name.clone())
    };
    if !plain_return(types, source.return_datatype_id) {
        return Err(Error::unsupported("return type that may need hidden return storage"));
    }
    let returns = type_name(Some(source.return_datatype_id))?;
    let table = prog.symbol_table();
    let mut parameters = Vec::new();
    for v in &source.parameters {
        let symbol = table.get(v.symbol_id).ok_or_else(|| Error::failed("parameter without a symbol"))?;
        let pname = table.name(symbol).ok_or_else(|| Error::unsupported("parameter without a name"))?;
        parameters.push(format!("{} {}", type_name(v.datatype_id)?, pname));
    }
    let list = if parameters.is_empty() { "void".to_owned() } else { parameters.join(", ") };
    Ok(format!("{returns} {name}({list})"))
}

/// The row of one function.
pub fn function_row(prog: &Program<BufferFile>, f: &FunctionInfo, default_space: &str) -> Result<Value> {
    let name = f.name.clone().ok_or_else(|| Error::unsupported("function without a computable name"))?;
    let entry = match &f.entry {
        Address::Space { offset, .. } => *offset,
        _ => return Err(Error::unsupported("function entry outside an address space")),
    };
    let signature = signature(prog, f, &name, default_space)?;
    if !name.is_ascii() || !signature.is_ascii() {
        return Err(Error::unsupported("non-ASCII name or signature (Java clips UTF-16 units)"));
    }
    let mut body = Vec::new();
    for r in f.body.iter().take(BODY_MAX) {
        if r.space != default_space {
            return Err(Error::unsupported("function body outside the default space"));
        }
        body.push(Value::String(range_text(default_space, r.min, r.max)?));
    }
    Ok(json!({
        "address": format!("0x{}", address_text(entry)),
        "name": clip(&name, NAME_MAX),
        "signature": clip(&signature, SIGNATURE_MAX),
        "body": body,
        "body_truncated": f.body.len() > BODY_MAX,
    }))
}
