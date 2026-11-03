//! Python bindings for `hy_runtime::snapshot` (`runtime_snapshot.py` under `HYDRALYSIS_IMPL=rust`).
//!
//! The Python wrappers validate masks and predicates first; these functions only run the heavy part. `Unmodelled` sends the
//! caller to the Python implementation.

use crate::convert::{to_py, to_value, unmodelled};
use hy_runtime::decode::float_repr;
use hy_runtime::snapshot;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde_json::Value;
use std::fmt::Write;

/// `runtime_snapshot.stable_sha256` with the full list of volatile patterns (defaults and mask).
#[pyfunction]
pub fn snapshot_stable_sha256(py: Python<'_>, record: &Bound<'_, PyAny>, volatile: Vec<String>) -> PyResult<String> {
    let record = to_value(record)?;
    py.detach(|| snapshot::stable_sha256(&record, &volatile)).map_err(|_| unmodelled())
}

/// The part of `runtime_snapshot.compare` after argument validation.
#[pyfunction]
pub fn snapshot_compare<'py>(
    py: Python<'py>,
    a: &Bound<'py, PyAny>,
    b: &Bound<'py, PyAny>,
    patterns: Vec<String>,
    volatile: Vec<String>,
    predicates: &Bound<'py, PyAny>,
    limit: usize,
) -> PyResult<Bound<'py, PyAny>> {
    let predicates = match to_value(predicates)? {
        Value::Array(items) => items,
        _ => return Err(unmodelled()),
    };
    let (a, b) = (to_value(a)?, to_value(b)?);
    to_py(py, &py.detach(|| snapshot::compare(&a, &b, &patterns, &volatile, &predicates, limit)).map_err(|_| unmodelled())?)
}

/// Deepest nesting written; deeper is left to Python (which raises `RecursionError` far later).
const MAX_DEPTH: usize = 200;

/// `json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)` of an object made of exact
/// `dict`, `list`, `str`, `int`, `float`, `bool` and `None`, written straight from the Python objects.
fn write_json(obj: &Bound<'_, PyAny>, out: &mut String, skip: Option<&str>, depth: usize) -> PyResult<()> {
    if depth > MAX_DEPTH {
        return Err(unmodelled());
    }
    if let Ok(text) = obj.cast_exact::<PyString>() {
        snapshot::write_string(text.to_str().map_err(|_| unmodelled())?, out);
    } else if obj.is_none() {
        out.push_str("null");
    } else if let Ok(dict) = obj.cast_exact::<PyDict>() {
        let items: Vec<(Bound<'_, PyAny>, Bound<'_, PyAny>)> = dict.iter().collect();
        let mut entries: Vec<(&str, &Bound<'_, PyAny>)> = Vec::with_capacity(items.len());
        for (key, value) in &items {
            let key = key.cast_exact::<PyString>().map_err(|_| unmodelled())?;
            let key = key.to_str().map_err(|_| unmodelled())?;
            if Some(key) != skip {
                entries.push((key, value));
            }
        }
        entries.sort_unstable_by(|a, b| a.0.cmp(b.0));
        out.push('{');
        for (index, (key, value)) in entries.into_iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            snapshot::write_string(key, out);
            out.push(':');
            write_json(value, out, None, depth + 1)?;
        }
        out.push('}');
    } else if let Ok(list) = obj.cast_exact::<PyList>() {
        out.push('[');
        for (index, item) in list.iter().enumerate() {
            if index > 0 {
                out.push(',');
            }
            write_json(&item, out, None, depth + 1)?;
        }
        out.push(']');
    } else if obj.is_exact_instance_of::<PyInt>() {
        match obj.extract::<i64>() {
            Ok(n) => write!(out, "{n}").expect("writing to a String cannot fail"),
            Err(_) => write!(out, "{}", obj.extract::<u64>().map_err(|_| unmodelled())?).expect("writing to a String cannot fail"),
        }
    } else if obj.is_exact_instance_of::<PyBool>() {
        out.push_str(if obj.is_truthy()? { "true" } else { "false" });
    } else if obj.is_exact_instance_of::<PyFloat>() {
        let value = obj.extract::<f64>()?;
        if !value.is_finite() {
            return Err(unmodelled());
        }
        out.push_str(&float_repr(value));
    } else {
        return Err(unmodelled());
    }
    Ok(())
}

/// `runtime_snapshot.snapshot_id`: `snap_` and the SHA-256 of the canonical JSON of the record without its own id.
#[pyfunction]
pub fn snapshot_id(record: &Bound<'_, PyAny>) -> PyResult<String> {
    let Ok(record) = record.cast_exact::<PyDict>() else { return Err(unmodelled()) };
    let mut json = String::with_capacity(1 << 12);
    write_json(record.as_any(), &mut json, Some("snapshot"), 0)?;
    Ok(format!("snap_{}", snapshot::sha256_hex(json.as_bytes())))
}
