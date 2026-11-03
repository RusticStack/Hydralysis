//! Python object <-> JSON value conversion shared by the pure-function bindings (`decode`, `snapshot`).
//!
//! Arguments are converted with exact-type checks: a subclass, a tuple, a non-string key, an integer beyond 64 bits, a
//! non-finite float, a lone surrogate or a nesting deeper than [`MAX_DEPTH`] raises `Unmodelled`, and the Python caller
//! runs the Python implementation instead.

use pyo3::create_exception;
use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};
use serde_json::{Map, Number, Value};

/// Deepest nesting converted from Python.
const MAX_DEPTH: usize = 200;

create_exception!(hydralysis_rt, Unmodelled, PyException, "The input is outside the shapes the Rust bindings model.");

pub(crate) fn unmodelled() -> PyErr {
    Unmodelled::new_err("outside the modelled shapes")
}

/// Python object to JSON value; `Err` when the object is not plain JSON data.
pub(crate) fn to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    convert(obj, 0)
}

fn convert(obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<Value> {
    if depth > MAX_DEPTH {
        return Err(unmodelled());
    }
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if obj.is_exact_instance_of::<PyBool>() {
        return Ok(Value::Bool(obj.is_truthy()?));
    }
    if obj.is_exact_instance_of::<PyInt>() {
        if let Ok(n) = obj.extract::<i64>() {
            return Ok(n.into());
        }
        return obj.extract::<u64>().map(Value::from).map_err(|_| unmodelled());
    }
    if obj.is_exact_instance_of::<PyFloat>() {
        return Number::from_f64(obj.extract::<f64>()?).map(Value::Number).ok_or_else(unmodelled);
    }
    if obj.is_exact_instance_of::<PyString>() {
        return obj.extract::<String>().map(Value::String).map_err(|_| unmodelled());
    }
    if let Ok(list) = obj.cast_exact::<PyList>() {
        return list.iter().map(|item| convert(&item, depth + 1)).collect::<PyResult<Vec<_>>>().map(Value::Array);
    }
    if let Ok(dict) = obj.cast_exact::<PyDict>() {
        let mut map = Map::new();
        for (key, value) in dict.iter() {
            if !key.is_exact_instance_of::<PyString>() {
                return Err(unmodelled());
            }
            map.insert(key.extract::<String>().map_err(|_| unmodelled())?, convert(&value, depth + 1)?);
        }
        return Ok(Value::Object(map));
    }
    Err(unmodelled())
}

/// JSON value to Python object, keeping object key order.
pub(crate) fn to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => PyBool::new(py, *b).to_owned().into_any(),
        Value::Number(n) => match (n.as_i64(), n.as_u64()) {
            (Some(i), _) => i.into_pyobject(py)?.into_any(),
            (None, Some(u)) => u.into_pyobject(py)?.into_any(),
            _ => PyFloat::new(py, n.as_f64().ok_or_else(unmodelled)?).into_any(),
        },
        Value::String(s) => PyString::new(py, s).into_any(),
        Value::Array(items) => PyList::new(py, items.iter().map(|v| to_py(py, v)).collect::<PyResult<Vec<_>>>()?)?.into_any(),
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, item) in map {
                dict.set_item(key, to_py(py, item)?)?;
            }
            dict.into_any()
        }
    })
}
