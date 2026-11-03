//! Python bindings for `hy_runtime::decode` (`runtime_decode.py` under `HYDRALYSIS_IMPL=rust`).
//!
//! A `ValueError` is the one Python itself raises, with its message; `Unmodelled` sends the caller to the Python function.

use crate::convert::{to_py, to_value, unmodelled};
use hy_runtime::decode::{self, DecodeError};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

fn failure(error: DecodeError) -> PyErr {
    match error {
        DecodeError::Invalid(message) => PyValueError::new_err(message),
        _ => unmodelled(),
    }
}

/// `runtime_decode.normalize`.
#[pyfunction]
pub fn decode_normalize<'py>(py: Python<'py>, captures: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &decode::normalize(&to_value(captures)?).map_err(failure)?)
}

/// `runtime_decode.decode`.
#[pyfunction]
pub fn decode_value<'py>(py: Python<'py>, spec: &Bound<'py, PyAny>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &decode::decode(&to_value(spec)?, data).map_err(failure)?)
}

/// `runtime_decode.decode_event`.
#[pyfunction]
pub fn decode_event<'py>(py: Python<'py>, specs: &Bound<'py, PyAny>, captures: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &decode::decode_event(&to_value(specs)?, &to_value(captures)?).map_err(failure)?)
}

/// `runtime_decode.layout_values`.
#[pyfunction]
pub fn decode_layout_values<'py>(py: Python<'py>, fields: &Bound<'py, PyAny>, data: &[u8]) -> PyResult<Bound<'py, PyAny>> {
    to_py(py, &decode::layout_values(&to_value(fields)?, data).map_err(failure)?)
}
