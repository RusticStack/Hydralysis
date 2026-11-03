//! PyO3 binding for the disk-level parts of `hy_views`: one JSON-in, JSON-out entry point, `views_call_rs(name, args)`.
//!
//! Only functions whose arguments and results are plain JSON cross: the generation chain (`live_generations`, `master_ids`,
//! `editors_since`, `reserve_generation`), the queue listing (`outstanding`), the publish option check (`validate`) and the
//! commit lifecycle (`recover`, `in_flight_ids`, `request_abort`, `revert`). The engine-driven parts (`rebase`, `merge`,
//! `drain`, the candidate builds) need a host and stay in Python until the binding grows one.
//!
//! The answer is `{"ok": value}` or `{"err": {"kind": "view" | "runtime" | "value" | "other", ...}}`; the Python wrapper turns
//! it into the exception the original raises.

use hy_views::{Error, gens, generations, lifecycle, options, queue};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

type Settings = Map<String, Value>;

fn object(value: &Value) -> Result<Map<String, Value>, Error> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| Error::value("expected an object"))
}

fn text(args: &[Value], at: usize) -> Result<&str, Error> {
    args.get(at)
        .and_then(Value::as_str)
        .ok_or_else(|| Error::value("expected a string argument"))
}

fn dispatch(name: &str, args: &[Value]) -> Result<Value, Error> {
    let settings: Settings = object(args.first().unwrap_or(&Value::Null))?;
    match name {
        "views_live_generations" => Ok(Value::Array(gens::live_generations(&settings, text(args, 1)?)?)),
        "views_master_ids" => {
            let after = args.get(2).and_then(Value::as_i64).unwrap_or(0);
            Ok(json!(gens::master_ids(&settings, text(args, 1)?, after)?))
        }
        "views_editors_since" => {
            let subjects: Option<BTreeSet<String>> = args
                .get(3)
                .and_then(Value::as_array)
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect());
            let base = args.get(2).and_then(Value::as_i64).unwrap_or(0);
            Ok(Value::Array(gens::editors_since(&settings, text(args, 1)?, base, subjects.as_ref())?))
        }
        "views_outstanding" => Ok(json!(queue::outstanding(&settings, text(args, 1)?)?)),
        "views_reserve_generation" => Ok(json!(generations::reserve_generation(&settings, text(args, 1)?)?)),
        "views_validate" => Ok(Value::Object(options::validate(args.get(1).unwrap_or(&Value::Null))?)),
        "commits_recover" => {
            let selected = object(args.get(1).unwrap_or(&Value::Null))?;
            Ok(Value::Array(lifecycle::recover(&settings, &selected, text(args, 2)?)?))
        }
        "commits_in_flight_ids" => {
            let selected = object(args.get(1).unwrap_or(&Value::Null))?;
            Ok(json!(lifecycle::in_flight_ids(&settings, &selected)?))
        }
        "commits_request_abort" => {
            let selected = object(args.get(1).unwrap_or(&Value::Null))?;
            lifecycle::request_abort(&settings, &selected, text(args, 2)?)
        }
        "commits_revert" => {
            let selected = object(args.get(1).unwrap_or(&Value::Null))?;
            lifecycle::revert(&settings, &selected, args.get(2).unwrap_or(&Value::Null))
        }
        other => Err(Error::value(format!("unknown native function {other}"))),
    }
}

fn error_json(error: &Error) -> Value {
    match error {
        Error::View(v) => json!({"kind": "view", "payload": v.payload(), "code": v.code, "message": v.message}),
        Error::Runtime(m) => json!({"kind": "runtime", "message": m}),
        Error::Core(hy_views::hy_core::Error::Value(m)) => json!({"kind": "value", "message": m}),
        other => json!({"kind": "other", "message": other.to_string(), "code": match other {
            Error::Core(c) => c.code(),
            _ => None,
        }}),
    }
}

/// `views_call_rs(name, args_json)` with `args_json` a JSON array whose first element is the settings object.
#[pyfunction]
fn views_call_rs(py: Python<'_>, name: &str, args: &str) -> PyResult<String> {
    let parsed: Value = serde_json::from_str(args).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let list = parsed.as_array().cloned().unwrap_or_default();
    let answer = py.detach(|| dispatch(name, &list));
    Ok(match answer {
        Ok(v) => json!({"ok": v}),
        Err(e) => json!({"err": error_json(&e)}),
    }
    .to_string())
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(views_call_rs, module)?)?;
    Ok(())
}
