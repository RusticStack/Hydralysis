//! Binding of `hy_trace::{schema, jsonl, shape}`: the schema check of `trace_schema`, the clean case of
//! `trace.read_jsonl` and `trace.shape`, behind `HYDRALYSIS_IMPL=rust`.

use super::port::{fallback, from_value, map_error, to_value, to_value_exact};
use hy_trace::{jsonl, schema, shape};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyList, PyTuple};

/// A compiled schema: the yes/no of `trace_schema.errors(...)`.
#[pyclass(name = "NativeSchema", module = "hydralysis_native", frozen)]
pub struct NativeSchema {
    inner: schema::Schema,
}

#[pymethods]
impl NativeSchema {
    /// SCHEMA: the parsed schema file. A schema the port cannot judge is a `TraceFallback`.
    #[new]
    fn new(schema: &Bound<'_, PyAny>) -> PyResult<Self> {
        let value = to_value(schema)?;
        Ok(Self {
            inner: schema::Schema::compile(&value).map_err(map_error)?,
        })
    }

    /// Whether the python validator would find no fault in INSTANCE.
    fn accepts(&self, instance: &Bound<'_, PyAny>) -> PyResult<bool> {
        let value = to_value(instance)?;
        self.inner.accepts(&value).map_err(map_error)
    }
}

/// `(events, lines)` of a clean JSONL file, or None when the Python reader must take it (any damage, any line it would
/// word a reason for, an over-the-bound file).
#[pyfunction]
fn trace_read_jsonl<'py>(
    py: Python<'py>,
    data: &Bound<'py, PyBytes>,
    max_events: usize,
    schema: &Bound<'py, NativeSchema>,
) -> PyResult<Option<Bound<'py, PyTuple>>> {
    let bytes = data.as_bytes();
    let schema = &schema.get().inner;
    let clean = py
        .detach(|| jsonl::read_clean(bytes, max_events, schema))
        .map_err(map_error)?;
    let Some(clean) = clean else { return Ok(None) };
    let events = PyList::empty(py);
    for event in &clean.events {
        events.append(from_value(py, event)?)?;
    }
    Ok(Some(PyTuple::new(
        py,
        [events.into_any(), clean.lines.into_pyobject(py)?.into_any()],
    )?))
}

/// `trace.shape(reply, session=..., command=..., limit=..., requested_revision=...)` for a reply of plain JSON values.
#[pyfunction]
#[pyo3(signature = (reply, session, command, limit, requested_revision=None))]
fn trace_shape<'py>(
    py: Python<'py>,
    reply: &Bound<'py, PyAny>,
    session: Option<&str>,
    command: &str,
    limit: i64,
    requested_revision: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let limit = usize::try_from(limit).map_err(|_| fallback("a negative limit"))?;
    let reply = to_value_exact(reply)?;
    let requested = requested_revision
        .map(|value| to_value(value))
        .transpose()?;
    let shaped = py.detach(|| shape::shape(&reply, session, command, limit, requested.as_ref()));
    from_value(py, &shaped)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<NativeSchema>()?;
    module.add_function(wrap_pyfunction!(trace_read_jsonl, module)?)?;
    module.add_function(wrap_pyfunction!(trace_shape, module)?)?;
    Ok(())
}
