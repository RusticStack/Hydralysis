//! PyO3 bindings of the lineage, backups and runtime-events ports (hy-store). JSON crosses as text, bytes as `bytes`.
//! The Python side is `hydralysis._rust_lineage`; every function here has the signature of its Python twin minus the
//! pieces that stay in Python (engines, the targets registry).

#![allow(clippy::result_large_err)] // hy-store's lineage::Error is large by design

use crate::{convert, parse, text};
use hy_store::{backups, events, lineage};
use pyo3::IntoPyObjectExt;
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;

/// Turn a lineage-layer error into the Python exception the Python module raises.
fn lerr(py: Python<'_>, error: lineage::Error) -> PyErr {
    let build = |module: &str, class: &str, code: &str, message: &str, detail: &Map<String, Value>| -> PyErr {
        let made = (|| -> PyResult<PyErr> {
            let loads = py.import("json")?.getattr("loads")?;
            let extra = loads.call1((text(&Value::Object(detail.clone())),))?;
            let args = pyo3::types::PyTuple::new(py, [code.into_bound_py_any(py)?, message.into_bound_py_any(py)?])?;
            let kwargs = extra.cast::<pyo3::types::PyDict>().map_err(PyErr::from)?;
            let object = py.import(module)?.getattr(class)?.call(args, Some(kwargs))?;
            Ok(PyErr::from_value(object))
        })();
        made.unwrap_or_else(|e| e)
    };
    match error {
        lineage::Error::Lineage(e) => build("hydralysis.lineage", "LineageError", &e.code, &e.message, &e.detail),
        lineage::Error::Backup(e) => build("hydralysis.backups", "BackupError", &e.code, &e.message, &e.detail),
        lineage::Error::Engine { message, .. } => pyo3::exceptions::PyRuntimeError::new_err(message),
        lineage::Error::Core(e) => convert(py, e),
    }
}

fn l<T>(py: Python<'_>, result: lineage::Result<T>) -> PyResult<T> {
    result.map_err(|e| lerr(py, e))
}

fn bytes<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    PyBytes::new(py, data)
}

// ---------------------------------------------------------------------------------------------------- lineage

#[pyfunction]
fn lin_canonical<'py>(py: Python<'py>, value: &str) -> PyResult<Bound<'py, PyBytes>> {
    Ok(bytes(py, &lineage::canonical(&parse(value)?)))
}

#[pyfunction]
fn lin_fileset_sha256(files: &str) -> PyResult<String> {
    let files = parse(files)?;
    Ok(lineage::fileset_sha256(files.as_array().map_or(&[][..], |v| v.as_slice())))
}

#[pyfunction]
fn lin_self_hash(manifest: &str) -> PyResult<String> {
    Ok(lineage::self_hash(&parse(manifest)?))
}

#[pyfunction]
fn lin_find(py: Python<'_>, settings: &str, origin_key: &str) -> PyResult<Option<String>> {
    let settings = parse(settings)?;
    l(py, py.detach(|| lineage::find(&settings, origin_key)))
}

#[pyfunction]
fn lin_load(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&Value::Object(l(py, py.detach(|| lineage::load(&settings, lineage_id)))?)))
}

/// `ensure` without the targets mirror (the Python wrapper calls `register` afterwards).
#[pyfunction]
fn lin_ensure(py: Python<'_>, settings: &str, target: &str) -> PyResult<String> {
    let (settings, target) = (parse(settings)?, parse(target)?);
    Ok(text(&Value::Object(l(py, py.detach(|| lineage::ensure(&settings, &target, None)))?)))
}

#[pyfunction]
#[pyo3(signature = (settings, lineage_id, record, lock_held=false))]
fn lin_append_current(py: Python<'_>, settings: &str, lineage_id: &str, record: &str, lock_held: bool) -> PyResult<String> {
    let (settings, record) = (parse(settings)?, parse(record)?);
    Ok(text(&l(py, py.detach(|| lineage::append_current(&settings, lineage_id, &record, lock_held)))?))
}

#[pyfunction]
fn lin_head(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&Value::Object(l(py, py.detach(|| lineage::head(&settings, lineage_id)))?)))
}

#[pyfunction]
fn lin_history(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&Value::Array(l(py, py.detach(|| lineage::history(&settings, lineage_id)))?)))
}

#[pyfunction]
fn lin_resolve(py: Python<'_>, settings: &str, item: &str) -> PyResult<String> {
    let (settings, item) = (parse(settings)?, parse(item)?);
    Ok(text(&l(py, lineage::resolve(&settings, &item))?))
}

#[pyfunction]
fn lin_tree_files(py: Python<'_>, folder: PathBuf) -> PyResult<String> {
    Ok(text(&Value::Array(l(py, py.detach(|| lineage::tree_files(&folder)))?)))
}

#[pyfunction]
fn lin_tree_hash(py: Python<'_>, folder: PathBuf) -> PyResult<String> {
    l(py, py.detach(|| lineage::tree_hash(&folder)))
}

#[pyfunction]
fn lin_write_manifest(py: Python<'_>, folder: PathBuf, body: &str) -> PyResult<String> {
    let body = parse(body)?;
    Ok(text(&l(py, py.detach(|| lineage::write_manifest(&folder, &body)))?))
}

#[pyfunction]
fn lin_read_manifest(folder: PathBuf) -> Option<String> {
    lineage::read_manifest(&folder).as_ref().map(text)
}

#[pyfunction]
fn lin_manifest_file_sha256(folder: PathBuf) -> Option<String> {
    lineage::manifest_file_sha256(&folder)
}

#[pyfunction]
fn lin_verify_manifest(py: Python<'_>, folder: PathBuf) -> PyResult<String> {
    Ok(text(&l(py, py.detach(|| lineage::verify_manifest(&folder)))?))
}

#[pyfunction]
fn lin_reserved_generations(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<Vec<i64>> {
    let settings = parse(settings)?;
    Ok(l(py, py.detach(|| lineage::reserved_generations(&settings, lineage_id)))?.into_iter().collect())
}

#[pyfunction]
fn lin_next_generation(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<i64> {
    let settings = parse(settings)?;
    l(py, py.detach(|| lineage::next_generation(&settings, lineage_id)))
}

#[pyfunction]
fn lin_verify_head(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&l(py, py.detach(|| lineage::verify_head(&settings, lineage_id)))?))
}

#[pyfunction]
fn lin_tampered(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&Value::Array(l(py, py.detach(|| lineage::tampered(&settings, lineage_id)))?)))
}

#[pyfunction]
fn lin_status(py: Python<'_>, settings: &str, target: &str) -> PyResult<String> {
    let (settings, target) = (parse(settings)?, parse(target)?);
    Ok(text(&l(py, py.detach(|| lineage::status(&settings, &target)))?))
}

// ---------------------------------------------------------------------------------------------------- backups

#[pyfunction]
fn bak_policy(py: Python<'_>, settings: &str) -> PyResult<String> {
    Ok(text(&l(py, backups::policy(&parse(settings)?))?))
}

#[pyfunction]
fn bak_size_of(py: Python<'_>, folder: PathBuf) -> u64 {
    py.detach(|| backups::size_of(&folder))
}

#[pyfunction]
#[pyo3(signature = (revision, purpose, when=None))]
fn bak_backup_id(revision: &str, purpose: &str, when: Option<f64>) -> String {
    backups::backup_id(revision, purpose, when)
}

#[pyfunction]
fn bak_logged(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&Value::Array(l(py, backups::logged(&settings, lineage_id))?)))
}

#[pyfunction]
fn bak_cumulative(py: Python<'_>, settings: &str, lineage_id: &str, root: &str) -> PyResult<u64> {
    let settings = parse(settings)?;
    l(py, backups::cumulative(&settings, lineage_id, root))
}

#[pyfunction]
fn bak_preview(py: Python<'_>, settings: &str, lineage_id: &str, source_gpr: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&l(py, py.detach(|| backups::preview(&settings, lineage_id, source_gpr)))?))
}

#[pyfunction]
fn bak_manifest_files(rows: &str) -> PyResult<String> {
    let rows = parse(rows)?;
    Ok(text(&Value::Array(backups::manifest_files(rows.as_array().map_or(&[][..], |v| v.as_slice())))))
}

#[pyfunction]
fn bak_read_backup(folder: PathBuf) -> Option<String> {
    backups::read_backup(&folder).as_ref().map(text)
}

#[pyfunction]
fn bak_verify(py: Python<'_>, folder: PathBuf) -> PyResult<String> {
    Ok(text(&l(py, py.detach(|| backups::verify(&folder)))?))
}

#[pyfunction]
#[pyo3(signature = (settings, lineage_id, identifier, manifest_sha256=None))]
fn bak_usable(
    py: Python<'_>,
    settings: &str,
    lineage_id: &str,
    identifier: &str,
    manifest_sha256: Option<String>,
) -> PyResult<Option<String>> {
    let settings = parse(settings)?;
    let found = l(py, py.detach(|| backups::usable(&settings, lineage_id, identifier, manifest_sha256.as_deref())))?;
    Ok(found.as_ref().map(text))
}

#[pyfunction]
#[pyo3(signature = (settings, lineage_id, verify_all=false))]
fn bak_listing(py: Python<'_>, settings: &str, lineage_id: &str, verify_all: bool) -> PyResult<String> {
    let settings = parse(settings)?;
    Ok(text(&l(py, py.detach(|| backups::listing(&settings, lineage_id, verify_all)))?))
}

/// `{generation: reason}` with string keys (JSON object).
#[pyfunction]
fn bak_protected_generations(py: Python<'_>, settings: &str, lineage_id: &str) -> PyResult<String> {
    let settings = parse(settings)?;
    let map = l(py, py.detach(|| backups::protected_generations(&settings, lineage_id)))?;
    let object: Map<String, Value> = map.into_iter().map(|(k, v)| (k.to_string(), Value::String(v))).collect();
    Ok(text(&Value::Object(object)))
}

#[pyfunction]
fn bak_remove(py: Python<'_>, settings: &str, lineage_id: &str, options: &str) -> PyResult<String> {
    let (settings, options) = (parse(settings)?, parse(options)?);
    Ok(text(&l(py, py.detach(|| backups::remove(&settings, lineage_id, &options)))?))
}

// ---------------------------------------------------------------------------------------------------- events

#[pyfunction]
fn ev_genesis_hash(session: &str) -> String {
    events::genesis_hash(session)
}

#[pyfunction]
fn ev_record_hash(record: &str) -> PyResult<String> {
    Ok(events::record_hash(&parse(record)?))
}

#[pyfunction]
fn ev_frame<'py>(py: Python<'py>, record: &str) -> PyResult<Bound<'py, PyBytes>> {
    Ok(bytes(py, &events::frame(&parse(record)?)))
}

/// `[[record_json | None, error | None], ...]`.
#[pyfunction]
fn ev_iter_records(py: Python<'_>, path: PathBuf) -> Vec<(Option<String>, Option<String>)> {
    py.detach(|| {
        events::iter_records(&path)
            .map(|step| match step {
                Ok(record) => (Some(text(&Value::Object(record))), None),
                Err(error) => (None, Some(error.to_string())),
            })
            .collect()
    })
}

#[pyfunction]
#[pyo3(signature = (directory, after=0, limit=200, upto=None))]
fn ev_read_events(py: Python<'_>, directory: PathBuf, after: i64, limit: usize, upto: Option<i64>) -> String {
    text(&py.detach(|| events::read_events(&directory, after, limit, upto)))
}

#[pyfunction]
#[pyo3(signature = (directory, session, upto=None, expect=None))]
fn ev_verify_log(py: Python<'_>, directory: PathBuf, session: &str, upto: Option<i64>, expect: Option<BTreeMap<i64, String>>) -> String {
    text(&py.detach(|| events::verify_log(&directory, session, upto, &expect.unwrap_or_default())))
}

/// The ring, the counters and the durable chain of one session (events.rs `EventLog`).
#[pyclass(name = "EventLog")]
struct PyEventLog {
    inner: Arc<events::EventLog>,
}

#[pymethods]
impl PyEventLog {
    #[new]
    #[pyo3(signature = (directory, session, ring_events=events::RING_EVENTS, ring_bytes=events::RING_BYTES, log_max_bytes=events::LOG_MAX_BYTES, durable_log=true))]
    fn new(directory: PathBuf, session: &str, ring_events: usize, ring_bytes: usize, log_max_bytes: u64, durable_log: bool) -> Self {
        PyEventLog {
            inner: Arc::new(events::EventLog::with_options(directory, session, ring_events, ring_bytes, log_max_bytes, durable_log)),
        }
    }

    fn count_message(&self, py: Python<'_>, script: &str, message: &str, clipped: bool) -> PyResult<()> {
        let message = parse(message)?;
        py.detach(|| self.inner.count_message(script, &message, clipped));
        Ok(())
    }

    fn record(&self, py: Python<'_>, script: &str, message: &str) -> PyResult<String> {
        let message = parse(message)?;
        Ok(text(&py.detach(|| self.inner.record(script, &message))))
    }

    fn marker(&self, py: Python<'_>, kind: &str, body: &str) -> PyResult<String> {
        let body = parse(body)?;
        Ok(text(&py.detach(|| self.inner.marker(kind, &body))))
    }

    fn sync(&self, py: Python<'_>) {
        py.detach(|| self.inner.sync());
    }

    fn close(&self, py: Python<'_>) {
        py.detach(|| self.inner.close());
    }

    fn head_info(&self) -> String {
        text(&self.inner.head_info())
    }

    fn counters_copy(&self) -> String {
        text(&self.inner.counters_copy())
    }

    fn ring(&self) -> Vec<String> {
        self.inner.ring().iter().map(text).collect()
    }

    fn sequence(&self) -> i64 {
        self.inner.sequence()
    }

    fn dropped(&self) -> u64 {
        self.inner.dropped()
    }

    fn head_hash(&self) -> String {
        self.inner.head_hash()
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    macro_rules! add {
        ($($f:ident),* $(,)?) => { $( module.add_function(wrap_pyfunction!($f, module)?)?; )* };
    }
    add!(
        lin_canonical,
        lin_fileset_sha256,
        lin_self_hash,
        lin_find,
        lin_load,
        lin_ensure,
        lin_append_current,
        lin_head,
        lin_history,
        lin_resolve,
        lin_tree_files,
        lin_tree_hash,
        lin_write_manifest,
        lin_read_manifest,
        lin_manifest_file_sha256,
        lin_verify_manifest,
        lin_reserved_generations,
        lin_next_generation,
        lin_verify_head,
        lin_tampered,
        lin_status,
        bak_policy,
        bak_size_of,
        bak_backup_id,
        bak_logged,
        bak_cumulative,
        bak_preview,
        bak_manifest_files,
        bak_read_backup,
        bak_verify,
        bak_usable,
        bak_listing,
        bak_protected_generations,
        bak_remove,
        ev_genesis_hash,
        ev_record_hash,
        ev_frame,
        ev_iter_records,
        ev_read_events,
        ev_verify_log,
    );
    module.add_class::<PyEventLog>()?;
    Ok(())
}
