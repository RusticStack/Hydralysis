//! Small leaf modules: `jobowner.py` (who may cancel a job), `paths.py` (the pure checks), `localio.py` (bounded shared
//! reads) and `workflow_help.py` is deliberately absent (a static dict: nothing to compute).

use std::path::Path;

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::failure::{Failure, Res};
use crate::pytext::py_strip;

// ---- jobowner ---------------------------------------------------------------------------------------------------

/// `str(record.get("job_id") or record.get("id") or "")` for text values.
fn job_id(record: &Map<String, Value>) -> Res<String> {
    for key in ["job_id", "id"] {
        match record.get(key) {
            Some(Value::String(text)) if !text.is_empty() => return Ok(text.clone()),
            None | Some(Value::Null) | Some(Value::Bool(false)) => {}
            Some(Value::String(_)) => {}
            Some(_) => return Err(Failure::fallback("job id is not text")),
        }
    }
    Ok(String::new())
}

/// `str(value)` of an owner field: only text and `None` are modelled.
fn shown(value: Option<&Value>) -> Res<String> {
    match value {
        None | Some(Value::Null) => Ok("None".into()),
        Some(Value::String(text)) => Ok(text.clone()),
        Some(_) => Err(Failure::fallback("owner field is not text")),
    }
}

/// `jobowner.check`: refuse a cancel by anyone but the job's owner. TOKEN is the supplied token (`""` when none),
/// REMEMBERED the token this process remembers for the job (`_TOKENS.get(id, "")`).
pub fn owner_check(record: &Value, token: &str, remembered: &str) -> Res<()> {
    let Some(owner) = record.get("owner").and_then(Value::as_object) else {
        return Ok(());
    };
    let wanted = match owner.get("token_sha256") {
        None | Some(Value::Null) => return Ok(()),
        Some(Value::String(text)) if text.is_empty() => return Ok(()),
        Some(Value::String(text)) if text.is_ascii() => text.as_str(),
        Some(_) => return Err(Failure::fallback("token_sha256 is not ASCII text")),
    };
    let record = record.as_object().ok_or_else(|| Failure::fallback("record is not an object"))?;
    let supplied = if token.is_empty() { remembered } else { token };
    if !supplied.is_empty() {
        let digest: String = Sha256::digest(supplied.as_bytes()).iter().map(|b| format!("{b:02x}")).collect();
        if digest == wanted {
            return Ok(());
        }
    }
    Err(Failure::permission(format!(
        "job {} belongs to {} ({}); every client may read it, cancelling it needs owner, the token its start returned",
        job_id(record)?,
        shown(owner.get("client"))?,
        shown(owner.get("harness"))?
    )))
}

// ---- paths ------------------------------------------------------------------------------------------------------

/// `paths.forbidden_drives` for the `forbidden_drives` setting (None when absent) and the environment fallback.
pub fn forbidden_drives(setting: Option<&Value>, environment: &str) -> Res<Vec<String>> {
    let items: Vec<String> = match setting.filter(|v| !v.is_null()) {
        Some(Value::String(text)) => split_drives(text),
        Some(Value::Array(items)) => {
            let mut out = Vec::new();
            for item in items {
                match item {
                    Value::String(text) => out.push(text.clone()),
                    _ => return Err(drive_error()),
                }
            }
            out
        }
        Some(_) => return Err(drive_error()),
        None => split_drives(environment),
    };
    Ok(items.iter().map(|item| py_strip(item).to_uppercase().trim_end_matches(['\\', '/']).to_string()).collect())
}

fn split_drives(text: &str) -> Vec<String> {
    text.replace(';', ",").split(',').filter(|item| !py_strip(item).is_empty()).map(str::to_string).collect()
}

fn drive_error() -> Failure {
    Failure::value("forbidden_drives must be a list of drive names such as [\"C:\"]")
}

/// `any(part.startswith(".") for part in path.parts)` for a resolved Windows path.
pub fn has_dot_component(path: &str) -> bool {
    path.split(['\\', '/']).any(|part| part.starts_with('.'))
}

// ---- localio ----------------------------------------------------------------------------------------------------

/// The default read budget of `localio.read_bytes` (32 MiB).
pub const DEFAULT_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// `localio.read_bytes` for a budget already validated by the caller. Any file-system failure is a fallback: the original
/// raises the native error (`WinError` code and filename) that `std` does not reproduce.
pub fn read_bytes(path: &Path, max_bytes: u64) -> Res<Vec<u8>> {
    match hy_core::fsio::read_bytes_max(path, max_bytes) {
        Ok(data) => Ok(data),
        Err(hy_core::Error::Value(message)) if message.starts_with("metadata exceeds") => {
            Err(Failure::value(format!("metadata exceeds {max_bytes}-byte read budget: {}", path.display())))
        }
        Err(other) => Err(Failure::fallback(other.to_string())),
    }
}
