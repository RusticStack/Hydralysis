//! Python bindings for `hy_runtime::snapshot` (`runtime_snapshot.py` under `HYDRALYSIS_IMPL=rust`).
//!
//! The Python wrappers validate masks and predicates first; these functions only run the heavy part. `Unmodelled` sends the
//! caller to the Python implementation.

use crate::convert::{to_py, to_value, unmodelled};
use hy_runtime::snapshot;
use pyo3::prelude::*;
use serde_json::Value;

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
