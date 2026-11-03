//! PyO3 binding for `hy_engine` (the pure logic of `hydra.py`, `api.py` and the small leaf modules).
//!
//! `engine_call_rs(name, args_json)` is the one JSON-in, JSON-out entry point: the answer is the JSON text of the result,
//! `None` when the Rust code does not model the input exactly (the Python original must run), and a Python exception when
//! the original raises one (`ValueError`, `TypeError`, `PermissionError`, with the original's message). A few functions
//! with bytes or large results have their own entry points so nothing is copied through JSON.

#![allow(clippy::result_large_err)] // the error type is pyo3's PyErr, which every #[pyfunction] must return

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use hy_engine::api;
use hy_engine::failure::{Failure, Kind, Res};
use hy_engine::hydra::{self, ErrorParts, Pins};
use hy_engine::pytext::{self, Dumps};
use hy_engine::{address_map, integrity, red4ext, small};
use pyo3::exceptions::{PyPermissionError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::{Map, Value};

/// The Python exception a [`Failure`] stands for, or `None` for a fallback.
fn outcome<T>(result: Res<T>) -> PyResult<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(Failure::Fallback(_)) => Ok(None),
        Err(Failure::Raise(raise)) => Err(match raise.kind {
            Kind::ValueError => PyValueError::new_err(raise.message),
            Kind::TypeError => PyTypeError::new_err(raise.message),
            Kind::PermissionError => PyPermissionError::new_err(raise.message),
        }),
    }
}

fn arguments(text: &str) -> Res<Vec<Value>> {
    match pytext::parse_json(text)? {
        Value::Array(items) => Ok(items),
        _ => Err(Failure::fallback("arguments are not a list")),
    }
}

fn text(args: &[Value], at: usize) -> Res<&str> {
    args.get(at)
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::fallback("expected a text argument"))
}

fn flag(args: &[Value], at: usize) -> Res<bool> {
    args.get(at)
        .and_then(Value::as_bool)
        .ok_or_else(|| Failure::fallback("expected a boolean argument"))
}

fn number(args: &[Value], at: usize) -> Res<i64> {
    args.get(at)
        .and_then(Value::as_i64)
        .ok_or_else(|| Failure::fallback("expected an integer argument"))
}

fn object(args: &[Value], at: usize) -> Res<&Map<String, Value>> {
    args.get(at)
        .and_then(Value::as_object)
        .ok_or_else(|| Failure::fallback("expected an object argument"))
}

fn pins(args: &[Value], at: usize) -> Res<Pins> {
    Ok(Pins {
        release: text(args, at)?.to_string(),
        protocol: number(args, at + 1)?,
        protocol_min: number(args, at + 2)?,
        client_version: text(args, at + 3)?.to_string(),
    })
}

fn dispatch(name: &str, args: &[Value]) -> Res<Value> {
    let null = Value::Null;
    match name {
        // [code, message, details, command, retry_after_ms, next, queue]
        "engine_error_text" => {
            let parts = ErrorParts {
                code: text(args, 0)?,
                message: text(args, 1)?,
                details: object(args, 2)?,
                command: text(args, 3)?,
                retry_after_ms: args.get(4),
                next: args.get(5),
                queue: args.get(6),
            };
            Ok(Value::String(hydra::engine_error_text(&parts)?))
        }
        // [first argument of a RusticQuery.java call]
        "script_action" => {
            Ok(hydra::script_action(text(args, 0)?)?.map_or(Value::Null, Value::String))
        }
        // [directory]
        "engine_release" => {
            Ok(hydra::engine_release(Path::new(text(args, 0)?)).map_or(Value::Null, Value::String))
        }
        // [resolved directory, allow_unpinned, release, protocol, protocol_min, client_version]
        "inspect_engine" => {
            hydra::inspect_engine(Path::new(text(args, 0)?), flag(args, 1)?, &pins(args, 2)?)
        }
        // [library path, shown path, allow_unpinned, release, protocol, protocol_min, client_version]
        "client_stamps" => {
            let stamps = hydra::check_client_file(
                Path::new(text(args, 0)?),
                text(args, 1)?,
                flag(args, 2)?,
                &pins(args, 3)?,
            )?;
            let one = |value: Option<String>| value.map_or(Value::Null, Value::String);
            let mut out = Map::new();
            out.insert("PROTOCOL".into(), one(stamps.protocol));
            out.insert("CLIENT_VERSION".into(), one(stamps.client_version));
            out.insert("HYDRA_RELEASE".into(), one(stamps.hydra_release));
            Ok(Value::Object(out))
        }
        // [settings, resolved root]
        "daemon_config" => hydra::daemon_config(object(args, 0)?, Path::new(text(args, 1)?)),
        // [health reply or null, stall_ms]
        "wedge_signal" => {
            let health = args.first().filter(|v| !v.is_null());
            Ok(hydra::wedge_signal(health, number(args, 1)?)?
                .map_or(Value::Null, |s| Value::String(s.into())))
        }
        // [capability, message, detail, epoch, catalog hash]
        "not_available" => Ok(Value::String(api::not_available(
            text(args, 0)?,
            text(args, 1)?,
            object(args, 2)?,
            number(args, 3)?,
            text(args, 4)?,
        ))),
        // [name, args]: the tool names are the catalog this build carries
        "validate_call" => {
            api::validate_call(
                args.first().unwrap_or(&null),
                args.get(1).unwrap_or(&null),
                &api::catalog().tool_names,
            )?;
            Ok(Value::Null)
        }
        // [records, limit]
        "job_listing" => {
            let records = args
                .first()
                .and_then(Value::as_array)
                .ok_or_else(|| Failure::fallback("records are not a list"))?;
            let limit = usize::try_from(number(args, 1)?)
                .map_err(|_| Failure::fallback("negative limit"))?;
            Ok(Value::String(api::job_listing(records, limit)?))
        }
        // [value]
        "prologue_sha256" => Ok(Value::String(api::prologue_sha256(
            args.first().unwrap_or(&null),
        )?)),
        // [value]: the integer as text (it can exceed 64 bits)
        "prologue_image_base" => Ok(Value::String(
            api::prologue_image_base(args.first().unwrap_or(&null))?.to_string(),
        )),
        // [path]
        "export_path_ok" => Ok(Value::Bool(api::export_path_ok(text(args, 0)?)?)),
        // [record, token, remembered token]
        "owner_check" => {
            small::owner_check(
                args.first().unwrap_or(&null),
                text(args, 1)?,
                text(args, 2)?,
            )?;
            Ok(Value::Null)
        }
        // [folder]
        "integrity_scan" => integrity::scan(Path::new(text(args, 0)?)),
        // [forbidden_drives setting or null, environment text]
        "forbidden_drives" => {
            let setting = args.first().filter(|v| !v.is_null());
            Ok(Value::from(small::forbidden_drives(
                setting,
                text(args, 1)?,
            )?))
        }
        // [path]
        "dot_component" => Ok(Value::Bool(small::has_dot_component(text(args, 0)?))),
        // [text, image base]
        "parse_address" => {
            let base = u64::try_from(number(args, 1)?)
                .map_err(|_| Failure::fallback("negative image base"))?;
            Ok(match api::parse_address(text(args, 0)?, base)? {
                api::Address::Mapped => serde_json::json!({"mapped": true}),
                api::Address::Parsed { rva, bare } => {
                    serde_json::json!({"rva": rva, "bare": bare.map(|v| v.to_string())})
                }
            })
        }
        // [value]
        "list_of" => Ok(Value::Array(api::list_of(args.first().unwrap_or(&null))?)),
        // [args]
        "options_bag" => Ok(Value::Object(api::options_bag(object(args, 0)?)?)),
        // [options]
        "script_options" => Ok(Value::Bool(api::script_options_dispatch(
            args.first().unwrap_or(&null),
        )?)),
        // [options]
        "backups_op" => Ok(Value::String(api::backups_op(object(args, 0)?)?)),
        // [job id]
        "job_kind" => Ok(Value::String(api::job_kind(text(args, 0)?).name().into())),
        // [job id]
        "script_job_id_ok" => Ok(Value::Bool(api::script_job_id_ok(text(args, 0)?))),
        other => Err(Failure::fallback(format!(
            "unknown native function {other}"
        ))),
    }
}

/// `engine_call_rs(name, args_json)`: see the module comment.
#[pyfunction]
fn engine_call_rs(py: Python<'_>, name: &str, args: &str) -> PyResult<Option<String>> {
    let result = py.detach(|| arguments(args).and_then(|list| dispatch(name, &list)));
    Ok(outcome(result)?.map(|value| pytext::dumps(&value, Dumps::CompactAscii)))
}

/// `api.catalog_hash()` of the table this build carries.
#[pyfunction]
fn engine_catalog_hash_rs() -> &'static str {
    api::default_catalog_hash()
}

/// `api.tool_table()` as compact JSON text.
#[pyfunction]
fn engine_tool_table_rs() -> &'static str {
    api::tool_table_json()
}

/// `api.instructions()` for a version.
#[pyfunction]
fn engine_instructions_rs(version: &str) -> String {
    api::instructions(version)
}

/// `" ".join("%02X" % byte for byte in data)`.
#[pyfunction]
fn engine_hex_bytes_rs(data: &[u8]) -> String {
    api::hex_bytes_upper_spaced(data)
}

/// `localio.read_bytes` for a validated budget: the bytes, a `ValueError` over budget, `None` for anything else.
#[pyfunction]
fn engine_read_bytes_rs<'py>(
    py: Python<'py>,
    path: &str,
    max_bytes: u64,
) -> PyResult<Option<Bound<'py, PyBytes>>> {
    let owned = PathBuf::from(path);
    let result = py.detach(|| small::read_bytes(&owned, max_bytes));
    Ok(outcome(result)?.map(|data| PyBytes::new(py, &data)))
}

/// `red4ext.lookup_hashes` (`kind` "hash") or `lookup_rvas` (`kind` "rva"): the formatted rows, or `None`.
#[pyfunction]
fn engine_red4ext_rs(
    py: Python<'_>,
    kind: &str,
    path: &str,
    wanted: Vec<String>,
    chunk_size: usize,
) -> PyResult<Option<Vec<String>>> {
    let mut set = HashSet::new();
    for item in &wanted {
        match item.parse::<u128>() {
            Ok(value) => {
                set.insert(value);
            }
            // a value Python's ints hold and ours cannot: it can still match nothing here, but say so by falling back
            Err(_) => return Ok(None),
        }
    }
    let owned = PathBuf::from(path);
    let hashes = kind == "hash";
    let result = py.detach(|| {
        if hashes {
            red4ext::lookup_hashes(&owned, &set, chunk_size)
        } else {
            red4ext::lookup_rvas(&owned, &set, chunk_size)
        }
    });
    outcome(result)
}

/// `address_maps` normalisation: `(map_sha256, entries, record_json)`, or `None` to fall back.
#[pyfunction]
fn engine_address_map_rs(
    py: Python<'_>,
    raw: &[u8],
    digest: &str,
    file: &str,
) -> PyResult<Option<(String, usize, String)>> {
    let result = py.detach(|| {
        address_map::normalise_text(raw, digest, file)
            .map(|done| (done.map_sha256, done.entries, done.record_json))
    });
    outcome(result)
}

/// `red4ext`-style file scans and the others run without the GIL; this lists what the module offers.
#[pyfunction]
fn engine_functions_rs() -> Vec<&'static str> {
    vec![
        "engine_call_rs",
        "engine_catalog_hash_rs",
        "engine_tool_table_rs",
        "engine_instructions_rs",
        "engine_hex_bytes_rs",
        "engine_read_bytes_rs",
        "engine_red4ext_rs",
        "engine_address_map_rs",
    ]
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(engine_call_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_catalog_hash_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_tool_table_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_instructions_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_hex_bytes_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_read_bytes_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_red4ext_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_address_map_rs, module)?)?;
    module.add_function(wrap_pyfunction!(engine_functions_rs, module)?)?;
    Ok(())
}
