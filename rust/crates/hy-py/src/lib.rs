//! PyO3 binding of the Rust storage crates. JSON crosses the boundary as text (`str`), bytes as `bytes`.
//!
//! The Python side (`hydralysis._rust_store`) installs these over `hydralysis.durable` / `hydralysis.storelog`
//! when `HYDRALYSIS_IMPL=rust`, and the differential tests call them next to the Python implementation.

use hy_core::Error;
use hy_core::appendlog::{self, AppendLog, Scan};
use hy_core::{fsio, json, lock, sealed};
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

fn instance<'py>(py: Python<'py>, module: &str, class: &str, args: Vec<Bound<'py, PyAny>>) -> PyErr {
    let built = pyo3::types::PyTuple::new(py, args);
    match built.and_then(|tuple| py.import(module)?.getattr(class)?.call1(tuple)) {
        Ok(object) => PyErr::from_value(object),
        Err(error) => error,
    }
}

fn convert(py: Python<'_>, error: Error) -> PyErr {
    match error {
        Error::Io(e) => PyErr::from(e),
        Error::Value(m) | Error::Json(m) => PyValueError::new_err(m),
        Error::StoreCorrupt { path, backup, reasons } => {
            let dict = PyDict::new(py);
            for (k, v) in reasons {
                let _ = dict.set_item(k, v);
            }
            instance(
                py,
                "hydralysis.durable",
                "StoreCorrupt",
                vec![path.into_bound_py_any(py).unwrap(), backup.into_bound_py_any(py).unwrap(), dict.into_any()],
            )
        }
        Error::LineageCorrupt { path, offset, records } => {
            let list = PyList::empty(py);
            for r in records {
                let _ = list.append(to_py(py, &r).ok());
            }
            instance(
                py,
                "hydralysis.durable",
                "LineageCorrupt",
                vec![path.into_bound_py_any(py).unwrap(), offset.into_bound_py_any(py).unwrap(), list.into_any()],
            )
        }
        Error::LockBusy { what, path, waited_s, retry_after_ms, .. } => instance(
            py,
            "hydralysis.locks",
            "LockBusy",
            vec![
                what.into_bound_py_any(py).unwrap(),
                path.into_bound_py_any(py).unwrap(),
                waited_s.into_bound_py_any(py).unwrap(),
                retry_after_ms.into_bound_py_any(py).unwrap(),
            ],
        ),
        Error::FaultInjected(m) => instance(py, "hydralysis.durable", "FaultInjected", vec![m.into_bound_py_any(py).unwrap()]),
    }
}

trait PyRes<T> {
    fn py(self, py: Python<'_>) -> PyResult<T>;
}
impl<T> PyRes<T> for Result<T, Error> {
    fn py(self, py: Python<'_>) -> PyResult<T> {
        self.map_err(|e| convert(py, e))
    }
}

fn parse(text: &str) -> PyResult<Value> {
    serde_json::from_str(text).map_err(|e| PyValueError::new_err(e.to_string()))
}

fn to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    py.import("json")?.call_method1("loads", (String::from_utf8_lossy(&json::dumps(value, json::FRAME)).into_owned(),))
}

fn text(value: &Value) -> String {
    String::from_utf8_lossy(&json::dumps(value, json::FRAME)).into_owned()
}

fn scan_json(scan: &Scan) -> String {
    text(&json!({
        "records": scan.records, "valid_end": scan.valid_end, "size": scan.size,
        "torn_tail": scan.torn_tail.as_ref().map(|t| json!({"offset": t.offset, "bytes": t.bytes})),
        "corrupt": scan.corrupt.as_ref().map(|c| json!({"offset": c.offset, "line": c.line, "error": "lineage_corrupt"})),
    }))
}

// ---------------------------------------------------------------------------------------------- json / seal

#[pyfunction]
fn canonical<'py>(py: Python<'py>, value: &str) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &json::canonical(&parse(value)?)))
}

#[pyfunction]
fn frame<'py>(py: Python<'py>, value: &str) -> PyResult<Bound<'py, PyBytes>> {
    Ok(PyBytes::new(py, &appendlog::frame(&parse(value)?)))
}

#[pyfunction]
#[pyo3(signature = (value, indent=Some(2)))]
fn dumps_sealed<'py>(py: Python<'py>, value: &str, indent: Option<usize>) -> PyResult<Bound<'py, PyBytes>> {
    let bytes = sealed::dumps_sealed(&parse(value)?, indent).py(py)?;
    Ok(PyBytes::new(py, &bytes))
}

#[pyfunction]
fn float_repr(value: f64) -> String {
    json::float_repr(value)
}

// ---------------------------------------------------------------------------------------------- files

#[pyfunction]
#[pyo3(signature = (path, data, point="atomic", sync=true))]
fn atomic_write(py: Python<'_>, path: PathBuf, data: &[u8], point: &str, sync: bool) -> PyResult<()> {
    let data = data.to_vec();
    let point = point.to_string();
    py.detach(|| fsio::atomic_write_point(&path, &data, &point, sync)).py(py)
}

#[pyfunction]
fn replace_file(py: Python<'_>, source: PathBuf, destination: PathBuf) -> PyResult<()> {
    py.detach(|| fsio::replace_file(&source, &destination)).py(py)
}

#[pyfunction]
#[pyo3(signature = (path, max_bytes=None, require_seal=false))]
fn inspect_file(py: Python<'_>, path: PathBuf, max_bytes: Option<u64>, require_seal: bool) -> PyResult<(String, Option<String>, String)> {
    let (kind, value, reason) = py.detach(|| sealed::inspect_file(&path, max_bytes, require_seal)).py(py)?;
    Ok((kind.as_str().to_string(), value.as_ref().map(text), reason))
}

/// Returns `(record_json, source)`; `default_json` is returned (source `missing`) when neither file exists.
#[pyfunction]
#[pyo3(signature = (path, default_json=None, max_bytes=None, require_seal=false))]
fn read_sealed_info(
    py: Python<'_>,
    path: PathBuf,
    default_json: Option<String>,
    max_bytes: Option<u64>,
    require_seal: bool,
) -> PyResult<(String, String)> {
    let default = default_json.as_deref().map(parse).transpose()?;
    let options = sealed::ReadOptions { max_bytes, require_seal };
    let (value, source) = py.detach(|| sealed::read_sealed_info(&path, &options, default)).py(py)?;
    let source = match source {
        sealed::Source::File => "file",
        sealed::Source::Backup => "backup",
        sealed::Source::Missing => "missing",
    };
    Ok((text(&value), source.to_string()))
}

#[pyfunction]
#[pyo3(signature = (path, value, indent=Some(2), max_bytes=None, too_large=None))]
fn write_sealed<'py>(
    py: Python<'py>,
    path: PathBuf,
    value: &str,
    indent: Option<usize>,
    max_bytes: Option<usize>,
    too_large: Option<String>,
) -> PyResult<Bound<'py, PyBytes>> {
    let value = parse(value)?;
    let bytes = py.detach(|| sealed::write_sealed(&path, &value, indent, max_bytes, too_large.as_deref())).py(py)?;
    Ok(PyBytes::new(py, &bytes))
}

// ---------------------------------------------------------------------------------------------- scan

#[pyfunction]
fn scan_bytes(data: &[u8]) -> String {
    scan_json(&appendlog::scan_bytes(data))
}

#[pyfunction]
#[pyo3(signature = (path, start=0, collect=true))]
fn scan_file(py: Python<'_>, path: PathBuf, start: u64, collect: bool) -> String {
    scan_json(&py.detach(|| appendlog::scan_file(&path, start, collect)))
}

// ---------------------------------------------------------------------------------------------- append log

fn log_of(path: PathBuf, lock_path: Option<PathBuf>, by: Option<String>, timeout: Option<f64>) -> AppendLog {
    let mut log = match lock_path {
        Some(l) => AppendLog::with_lock(path, l),
        None => AppendLog::new(path),
    };
    if let Some(by) = by {
        log.by = by;
    }
    if let Some(t) = timeout {
        log.lock_timeout_s = t;
    }
    log
}

#[pyfunction]
#[pyo3(signature = (path, record, lock_path=None, by=None, timeout=None, lock_held=false))]
fn log_append(
    py: Python<'_>,
    path: PathBuf,
    record: &str,
    lock_path: Option<PathBuf>,
    by: Option<String>,
    timeout: Option<f64>,
    lock_held: bool,
) -> PyResult<u64> {
    let record = parse(record)?;
    let log = log_of(path, lock_path, by, timeout);
    py.detach(|| log.append(&record, lock_held)).py(py)
}

#[pyfunction]
#[pyo3(signature = (path, lock_path=None, by=None, timeout=None, lock_held=false))]
fn log_repair(
    py: Python<'_>,
    path: PathBuf,
    lock_path: Option<PathBuf>,
    by: Option<String>,
    timeout: Option<f64>,
    lock_held: bool,
) -> PyResult<Option<String>> {
    let log = log_of(path, lock_path, by, timeout);
    Ok(py.detach(|| log.repair(lock_held)).py(py)?.as_ref().map(text))
}

#[pyfunction]
#[pyo3(signature = (path, strict=false))]
fn log_last(py: Python<'_>, path: PathBuf, strict: bool) -> PyResult<Option<String>> {
    let log = AppendLog::new(path);
    Ok(py.detach(|| log.last(strict)).py(py)?.as_ref().map(text))
}

#[pyfunction]
fn log_repairs(py: Python<'_>, path: PathBuf) -> String {
    let log = AppendLog::new(path);
    text(&Value::Array(py.detach(|| log.repairs())))
}

// ---------------------------------------------------------------------------------------------- locks

/// A held cross-process lock; `release()` or dropping the object releases it.
#[pyclass]
struct FileLock {
    guard: Option<lock::LockGuard>,
}

#[pymethods]
impl FileLock {
    #[new]
    #[pyo3(signature = (path, timeout_s=30.0, what="durable record"))]
    fn new(py: Python<'_>, path: PathBuf, timeout_s: f64, what: &str) -> PyResult<Self> {
        let what = what.to_string();
        let guard = py.detach(|| lock::lock(&path, timeout_s, &what)).py(py)?;
        Ok(FileLock { guard: Some(guard) })
    }

    fn release(&mut self) {
        self.guard = None;
    }
}

#[pyfunction]
fn lock_held(path: PathBuf) -> bool {
    lock::held(&path)
}

// ---------------------------------------------------------------------------------------------- storelog

#[pyfunction]
fn storelog_diff(old: &str, new: &str) -> PyResult<String> {
    Ok(text(&Value::Object(hy_store::storelog::diff(&parse(old)?, &parse(new)?))))
}

/// `(record_json, anchor, n, start)` of the chain applied to a snapshot.
#[pyfunction]
fn storelog_chain(record: &str, rows: &str) -> PyResult<(String, Option<String>, u64, Option<String>)> {
    let (mut record, rows) = (parse(record)?, parse(rows)?);
    let position = hy_store::storelog::chain(&mut record, rows.as_array().map_or(&[][..], |v| v.as_slice()));
    Ok((text(&record), position.anchor, position.n, position.start))
}

#[pyfunction]
#[pyo3(signature = (path, record, max_bytes=None, too_large=None))]
fn storelog_save(py: Python<'_>, path: PathBuf, record: &str, max_bytes: Option<usize>, too_large: Option<String>) -> PyResult<()> {
    let record = parse(record)?;
    py.detach(|| hy_store::storelog::save(Path::new(&path), &record, max_bytes, too_large.as_deref())).py(py)
}

/// The store at `path`; `record_json` is the snapshot the caller read, `reread` (optional) returns it again as JSON text.
#[pyfunction]
#[pyo3(signature = (path, record_json=None, reread=None))]
fn storelog_read(py: Python<'_>, path: PathBuf, record_json: Option<String>, reread: Option<Py<PyAny>>) -> PyResult<Option<String>> {
    let record = record_json.as_deref().map(parse).transpose()?;
    let reader = reread.map(|callable| {
        move || -> hy_core::Result<Option<Value>> {
            Python::attach(|py| {
                let result = callable.call0(py).map_err(|e| Error::Value(e.to_string()))?;
                if result.is_none(py) {
                    return Ok(None);
                }
                let encoded: String = result.extract(py).map_err(|e: PyErr| Error::Value(e.to_string()))?;
                serde_json::from_str(&encoded).map(Some).map_err(Error::from)
            })
        }
    });
    let outcome = match &reader {
        Some(f) => hy_store::storelog::read(&path, record, Some(f)),
        None => hy_store::storelog::read(&path, record, None),
    };
    Ok(outcome.py(py)?.as_ref().map(text))
}

#[pyfunction]
fn storelog_known_edits(path: PathBuf) -> Option<String> {
    hy_store::storelog::known_edits(&path).as_ref().map(text)
}

#[pyfunction]
fn storelog_configure(snapshot_every: u64, snapshot_log_bytes: usize, cache_entries: usize) {
    hy_store::storelog::configure(snapshot_every, snapshot_log_bytes, cache_entries);
}

#[pyfunction]
fn storelog_cache_len() -> usize {
    hy_store::storelog::cache_len()
}

#[pyfunction]
fn log_clear_verified() {
    appendlog::clear_verified();
}

#[pyfunction]
fn storelog_clear_cache() {
    hy_store::storelog::clear_cache();
}

#[pymodule]
fn hydralysis_rs(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(canonical, module)?)?;
    module.add_function(wrap_pyfunction!(frame, module)?)?;
    module.add_function(wrap_pyfunction!(dumps_sealed, module)?)?;
    module.add_function(wrap_pyfunction!(float_repr, module)?)?;
    module.add_function(wrap_pyfunction!(atomic_write, module)?)?;
    module.add_function(wrap_pyfunction!(replace_file, module)?)?;
    module.add_function(wrap_pyfunction!(inspect_file, module)?)?;
    module.add_function(wrap_pyfunction!(read_sealed_info, module)?)?;
    module.add_function(wrap_pyfunction!(write_sealed, module)?)?;
    module.add_function(wrap_pyfunction!(scan_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(scan_file, module)?)?;
    module.add_function(wrap_pyfunction!(log_append, module)?)?;
    module.add_function(wrap_pyfunction!(log_repair, module)?)?;
    module.add_function(wrap_pyfunction!(log_last, module)?)?;
    module.add_function(wrap_pyfunction!(log_repairs, module)?)?;
    module.add_function(wrap_pyfunction!(lock_held, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_diff, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_chain, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_save, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_read, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_known_edits, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_clear_cache, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_configure, module)?)?;
    module.add_function(wrap_pyfunction!(storelog_cache_len, module)?)?;
    module.add_function(wrap_pyfunction!(log_clear_verified, module)?)?;
    module.add_class::<FileLock>()?;
    module.add("ABI", "abi3-py313")?;
    Ok(())
}
