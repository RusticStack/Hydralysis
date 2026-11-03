//! Shared pieces of the bindings of `hy-trace`: the two exceptions the Python wrappers understand and the conversion
//! between Python objects and `serde_json::Value`.
//!
//! * `TraceFallback` means "this input has a shape the port does not model": the wrapper runs the Python implementation,
//!   which stays the specification and raises or answers as it always did.
//! * `TraceHashError(code, message)` is the Python `HashError`.
//!
//! The conversion is strict on purpose. Python's loose typing (a float that equals an int, a tuple for a list, a dict key
//! that is not text, an integer beyond 64 bits) is not modelled, so anything outside the plain JSON shapes is a
//! `TraceFallback` and never a silently different answer.

use pyo3::exceptions::PyException;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde_json::{Map, Number, Value};

pyo3::create_exception!(hydralysis_native, TraceFallback, PyException);
pyo3::create_exception!(hydralysis_native, TraceHashError, PyException);

pub fn fallback(message: impl Into<String>) -> PyErr {
    TraceFallback::new_err(message.into())
}

/// A `hy_trace::Error` as the Python exception that stands for it.
pub fn map_error(error: hy_trace::Error) -> PyErr {
    match error {
        hy_trace::Error::Hash { code, message } => TraceHashError::new_err((code, message)),
        hy_trace::Error::Unsupported(message) => fallback(message),
        hy_trace::Error::Encode {
            encoding,
            text,
            position,
        } => Python::attach(|py| {
            let args = (
                encoding,
                text,
                position,
                position + 1,
                "character not representable",
            );
            match py
                .get_type::<pyo3::exceptions::PyUnicodeEncodeError>()
                .call1(args)
            {
                Ok(value) => PyErr::from_value(value),
                Err(error) => error,
            }
        }),
    }
}

/// Any extraction failure (a lone surrogate, an integer beyond 64 bits, a wrong type) is a fallback, not an answer.
pub fn or_fallback<T>(result: PyResult<T>) -> PyResult<T> {
    result.map_err(|error| fallback(format!("not modelled: {error}")))
}

/// A Python object as a JSON value; anything that is not plain JSON is a `TraceFallback`. A tuple becomes an array.
pub fn to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    convert(obj, true)
}

/// As [`to_value`], but a tuple is a `TraceFallback` too: for answers that hand the input's own values back, where a list
/// in place of a tuple would be a visible change.
pub fn to_value_exact(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    convert(obj, false)
}

fn convert(obj: &Bound<'_, PyAny>, tuples: bool) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(flag) = obj.cast::<PyBool>() {
        return Ok(Value::Bool(flag.is_true()));
    }
    if obj.is_instance_of::<PyInt>() {
        if let Ok(v) = obj.extract::<i64>() {
            return Ok(Value::from(v));
        }
        if let Ok(v) = obj.extract::<u64>() {
            return Ok(Value::from(v));
        }
        return Err(fallback("integer beyond 64 bits"));
    }
    if obj.is_instance_of::<PyFloat>() {
        let v: f64 = obj.extract()?;
        return Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| fallback("non-finite float"));
    }
    if let Ok(text) = obj.cast::<PyString>() {
        return Ok(Value::String(or_fallback(
            text.to_str().map(str::to_owned),
        )?));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        return list
            .iter()
            .map(|item| convert(&item, tuples))
            .collect::<PyResult<Vec<_>>>()
            .map(Value::Array);
    }
    if let Ok(tuple) = obj.cast::<PyTuple>() {
        if !tuples {
            return Err(fallback("a tuple"));
        }
        // A tuple is kept as an array; the reports only ever compare it with another such value.
        return tuple
            .iter()
            .map(|item| convert(&item, tuples))
            .collect::<PyResult<Vec<_>>>()
            .map(Value::Array);
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = Map::with_capacity(dict.len());
        for (key, value) in dict.iter() {
            let key = key
                .cast::<PyString>()
                .map_err(|_| fallback("a key that is not text"))?;
            map.insert(
                or_fallback(key.to_str().map(str::to_owned))?,
                convert(&value, tuples)?,
            );
        }
        return Ok(Value::Object(map));
    }
    Err(fallback(format!(
        "not plain JSON: {}",
        obj.get_type().name()?
    )))
}

/// A JSON value as Python objects (dicts keep their order).
pub fn from_value<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    Ok(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(flag) => PyBool::new(py, *flag).to_owned().into_any(),
        Value::Number(number) => {
            if let Some(v) = number.as_i64() {
                v.into_pyobject(py)?.into_any()
            } else if let Some(v) = number.as_u64() {
                v.into_pyobject(py)?.into_any()
            } else {
                number
                    .as_f64()
                    .unwrap_or(f64::NAN)
                    .into_pyobject(py)?
                    .into_any()
            }
        }
        Value::String(text) => PyString::new(py, text).into_any(),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                list.append(from_value(py, item)?)?;
            }
            list.into_any()
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, item) in map {
                dict.set_item(key, from_value(py, item)?)?;
            }
            dict.into_any()
        }
    })
}
