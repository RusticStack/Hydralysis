//! PyO3 binding for `hy_query::session` and `hy_query::decompile_job::job_path`.
//!
//! Only the stateless pieces cross: `accepted`, `_public`, `reader_lanes`, the Windows path spelling of the cache key and
//! `engine_decompile` (the engine client is a Python object here, adapted to the `Engine` trait). The program cache
//! itself stays in Python: `query._keys` / `_in_use` are read by many Python callers and tests.

#![allow(clippy::result_large_err)] // the error type is pyo3's PyErr, which every #[pyfunction] must return

use hy_query::session::{self, Engine, EngineError};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};
use serde_json::{Map, Value};
use std::sync::Mutex;

fn parse(text: &str) -> PyResult<Value> {
    serde_json::from_str(text).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// A Python engine client (`hydra.Engine` or a stand-in): `call(command, **fields)`.
struct PyEngine {
    object: Py<PyAny>,
    key: String,
    /// The first Python exception that was not an `EngineError`; the binding raises it after the Rust call returns.
    fatal: Mutex<Option<PyErr>>,
}

fn to_py(py: Python<'_>, value: &Value) -> PyResult<Py<PyAny>> {
    let loads = py.import("json")?.getattr("loads")?;
    Ok(loads.call1((value.to_string(),))?.unbind())
}

fn from_py(py: Python<'_>, object: &Bound<'_, PyAny>) -> PyResult<Value> {
    let dumps = py.import("json")?.getattr("dumps")?;
    let kwargs = PyDict::new(py);
    kwargs.set_item("default", py.import("builtins")?.getattr("str")?)?;
    let text: String = dumps.call((object,), Some(&kwargs))?.extract()?;
    parse(&text)
}

impl Engine for PyEngine {
    fn key(&self) -> &str {
        &self.key
    }
    fn call(&self, command: &str, fields: &Map<String, Value>) -> Result<Value, EngineError> {
        Python::attach(|py| {
            let run = || -> PyResult<Result<Value, EngineError>> {
                let kwargs = PyDict::new(py);
                for (k, v) in fields {
                    kwargs.set_item(k, to_py(py, v)?)?;
                }
                match self
                    .object
                    .bind(py)
                    .call_method("call", (command,), Some(&kwargs))
                {
                    Ok(reply) => Ok(Ok(from_py(py, &reply)?)),
                    Err(e) => {
                        let value = e.value(py);
                        if let (Ok(code), Ok(details)) =
                            (value.getattr("code"), value.getattr("details"))
                        {
                            let code: String = code.extract()?;
                            let message = value
                                .getattr("message")
                                .and_then(|m| m.extract())
                                .unwrap_or_default();
                            let details = match from_py(py, &details)? {
                                Value::Object(m) => m,
                                _ => Map::new(),
                            };
                            let command = value
                                .getattr("command")
                                .and_then(|m| m.extract())
                                .unwrap_or_default();
                            let text = value.str()?.to_string();
                            return Ok(Err(EngineError {
                                code,
                                message,
                                details,
                                command,
                                text,
                            }));
                        }
                        Err(e)
                    }
                }
            };
            match run() {
                Ok(result) => result,
                Err(e) => {
                    let text = e.to_string();
                    let mut slot = self.fatal.lock().unwrap_or_else(|p| p.into_inner());
                    if slot.is_none() {
                        *slot = Some(e);
                    }
                    Err(EngineError::new("__python__", &text, Map::new(), command))
                }
            }
        })
    }
}

#[pyfunction]
fn session_accepted_rs(action: &str, response: &str) -> PyResult<String> {
    session::accepted(action, &parse(response)?)
        .map(|v| v.to_string())
        .map_err(PyRuntimeError::new_err)
}

#[pyfunction]
fn session_public_rs(value: &str) -> PyResult<String> {
    Ok(session::public(&parse(value)?).to_string())
}

#[pyfunction]
fn session_reader_lanes_rs(settings: &str) -> PyResult<i64> {
    Ok(session::reader_lanes(&parse(settings)?))
}

#[pyfunction]
fn session_windows_path_rs(text: &str) -> String {
    session::windows_path(text)
}

#[pyfunction]
fn decompile_job_path_rs(root: &str, job_id: &str) -> PyResult<String> {
    hy_query::decompile_job::job_path(std::path::Path::new(root), job_id)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| PyValueError::new_err(e.to_string()))
}

/// `("answer", json)`, `("defer", reason)` (a job: `DeferDecompile`), `("type", message)` / `("value", message)` (Python
/// `TypeError` / `ValueError`) or `("unsupported", why)` (the caller runs the Python original).
#[pyfunction]
#[pyo3(signature = (engine, program_key, request, timeout_s, response, inline=false))]
fn session_engine_decompile_rs(
    py: Python<'_>,
    engine: Py<PyAny>,
    program_key: &str,
    request: &str,
    timeout_s: i64,
    response: &str,
    inline: bool,
) -> PyResult<(&'static str, String)> {
    let (request, response) = (parse(request)?, parse(response)?);
    let key = engine
        .bind(py)
        .getattr("key")
        .ok()
        .and_then(|k| k.cast::<PyString>().ok().map(|s| s.to_string()));
    let adapter = PyEngine {
        object: engine,
        key: key.unwrap_or_default(),
        fatal: Mutex::new(None),
    };
    let outcome = py.detach(|| {
        session::engine_decompile(
            &adapter,
            program_key,
            &request,
            timeout_s,
            &response,
            inline,
        )
    });
    if let Some(error) = adapter
        .fatal
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .take()
    {
        return Err(error);
    }
    use session::DecompileError as E;
    Ok(match outcome {
        Ok(answer) => ("answer", answer.to_string()),
        Err(E::Defer(defer)) => ("defer", defer.reason),
        Err(E::Type(m)) => ("type", m),
        Err(E::Value(m)) => ("value", m),
        Err(E::Unsupported(m)) => ("unsupported", m),
    })
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(session_accepted_rs, module)?)?;
    module.add_function(wrap_pyfunction!(session_public_rs, module)?)?;
    module.add_function(wrap_pyfunction!(session_reader_lanes_rs, module)?)?;
    module.add_function(wrap_pyfunction!(session_windows_path_rs, module)?)?;
    module.add_function(wrap_pyfunction!(decompile_job_path_rs, module)?)?;
    module.add_function(wrap_pyfunction!(session_engine_decompile_rs, module)?)?;
    Ok(())
}
