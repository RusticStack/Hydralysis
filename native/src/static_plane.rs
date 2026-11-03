//! PyO3 binding for `hy_static`: `static_call_rs(name, args)`, JSON text in and out.
//!
//! The answer is `{"ok": value}` or `{"fallback": {"kind": "unsupported" | "failed", "reason": text}}`. A fallback is
//! not an error: it tells `hydralysis.staticplane` to ask the engine. The GIL is released while the files are read.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::Value;

#[pyfunction]
fn static_call_rs(py: Python<'_>, name: &str, args: &str) -> PyResult<String> {
    let parsed: Value =
        serde_json::from_str(args).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let list = parsed.as_array().cloned().unwrap_or_default();
    let answer = py.detach(|| hy_static::call_json(name, &list));
    Ok(answer.to_string())
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(static_call_rs, module)?)?;
    Ok(())
}
