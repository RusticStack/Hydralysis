//! PyO3 binding for the disk-level parts of `hy_views`: one JSON-in, JSON-out entry point, `views_call_rs(name, args)`.
//!
//! Only functions whose arguments and results are plain JSON cross: the generation chain (`live_generations`, `master_ids`,
//! `editors_since`, `reserve_generation`), the queue listing (`outstanding`), the publish option check (`validate`) and the
//! commit lifecycle (`recover`, `in_flight_ids`, `request_abort`, `revert`). The engine-driven parts (`rebase`, `merge`,
//! `drain`, the candidate builds) need a host and stay in Python until the binding grows one.
//!
//! The answer is `{"ok": value}` or `{"err": {"kind": "view" | "runtime" | "value" | "other", ...}}`; the Python wrapper turns
//! it into the exception the original raises.

use hy_views::views::Host;
use hy_views::{generations, gens, lifecycle, options, queue, userscripts, workcopy, Error};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::{json, Map, Value};
use std::cell::RefCell;
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::Mutex;

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
        "views_live_generations" => Ok(Value::Array(gens::live_generations(
            &settings,
            text(args, 1)?,
        )?)),
        "views_master_ids" => {
            let after = args.get(2).and_then(Value::as_i64).unwrap_or(0);
            Ok(json!(gens::master_ids(&settings, text(args, 1)?, after)?))
        }
        "views_editors_since" => {
            let subjects: Option<BTreeSet<String>> =
                args.get(3).and_then(Value::as_array).map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                });
            let base = args.get(2).and_then(Value::as_i64).unwrap_or(0);
            Ok(Value::Array(gens::editors_since(
                &settings,
                text(args, 1)?,
                base,
                subjects.as_ref(),
            )?))
        }
        "views_outstanding" => Ok(json!(queue::outstanding(&settings, text(args, 1)?)?)),
        "views_reserve_generation" => Ok(json!(generations::reserve_generation(
            &settings,
            text(args, 1)?
        )?)),
        "views_validate" => Ok(Value::Object(options::validate(
            args.get(1).unwrap_or(&Value::Null),
        )?)),
        "commits_recover" => {
            let selected = object(args.get(1).unwrap_or(&Value::Null))?;
            Ok(Value::Array(lifecycle::recover(
                &settings,
                &selected,
                text(args, 2)?,
            )?))
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
        "workcopy_base_master_gpr" => {
            let (target, store) = (
                object(args.get(1).unwrap_or(&Value::Null))?,
                object(args.get(2).unwrap_or(&Value::Null))?,
            );
            Ok(json!(workcopy::base_master_gpr(
                &settings, &target, &store
            )?))
        }
        "workcopy_read_gpr" => {
            let target = object(args.get(1).unwrap_or(&Value::Null))?;
            Ok(json!(workcopy::read_gpr(&settings, &target)?))
        }
        "workcopy_store_corpus" => {
            let (digest, size) = workcopy::store_corpus(&settings, Path::new(text(args, 1)?))?;
            Ok(json!([digest, size]))
        }
        "workcopy_store_archive" => {
            let (digest, size) = workcopy::store_archive(&settings, Path::new(text(args, 1)?))?;
            Ok(json!([digest, size]))
        }
        "workcopy_verify_archive" => {
            let size = args
                .get(3)
                .and_then(Value::as_u64)
                .ok_or_else(|| Error::value("expected a size"))?;
            workcopy::verify_archive(Path::new(text(args, 1)?), text(args, 2)?, size)?;
            Ok(Value::Null)
        }
        "workcopy_replayable" => {
            let target = object(args.get(1).unwrap_or(&Value::Null))?;
            Ok(workcopy::replayable(
                &settings,
                &target,
                args.get(2).unwrap_or(&Value::Null),
            )?)
        }
        "userscripts_check_options" => match userscripts::check_options(args.get(1)) {
            Ok(map) => Ok(Value::Object(map)),
            Err(message) => Err(Error::value(message)),
        },
        "userscripts_choose" => {
            let level = args.get(1).and_then(Value::as_i64).unwrap_or(0);
            let flag = |at: usize| args.get(at).and_then(Value::as_bool).unwrap_or(false);
            match userscripts::choose(level, flag(2), flag(3), args.get(4).and_then(Value::as_str))
            {
                Ok(chosen) => Ok(json!({"isolation": chosen})),
                Err(userscripts::Refusal::NotAvailable {
                    capability,
                    message,
                }) => Ok(json!({"not_available": {"capability": capability, "message": message}})),
                Err(userscripts::Refusal::Value(message)) => Err(Error::value(message)),
            }
        }
        "userscripts_list_scripts" => {
            let folder = args.get(2).and_then(Value::as_str);
            Ok(json!(userscripts::list_scripts(
                text(args, 1)?,
                folder,
                text(args, 3)?,
                text(args, 4)?
            )?))
        }
        "userscripts_stage" => Ok(json!(userscripts::stage(
            Path::new(text(args, 1)?),
            Path::new(text(args, 2)?),
            Path::new(text(args, 3)?)
        )?)),
        other => Err(Error::value(format!("unknown native function {other}"))),
    }
}

fn error_json(error: &Error) -> Value {
    match error {
        Error::View(v) => {
            json!({"kind": "view", "payload": v.payload(), "code": v.code, "message": v.message})
        }
        Error::Runtime(m) => json!({"kind": "runtime", "message": m}),
        Error::Core(hy_views::hy_core::Error::Value(m)) => json!({"kind": "value", "message": m}),
        Error::Core(hy_views::hy_core::Error::Io(e)) => {
            json!({"kind": "io", "message": e.to_string(), "not_found": e.kind() == std::io::ErrorKind::NotFound})
        }
        Error::Core(hy_views::hy_core::Error::StoreCorrupt {
            path,
            backup,
            reasons,
        }) => {
            json!({"kind": "store_corrupt", "path": path, "backup": backup, "reasons": reasons})
        }
        Error::Core(hy_views::hy_core::Error::LockBusy {
            what,
            path,
            waited_s,
            retry_after_ms,
            ..
        }) => {
            json!({"kind": "lock_busy", "what": what, "path": path, "waited_s": waited_s, "retry_after_ms": retry_after_ms})
        }
        other => json!({"kind": "other", "message": other.to_string(), "code": match other {
            Error::Core(c) => c.code(),
            _ => None,
        }}),
    }
}

/// `views_call_rs(name, args_json)` with `args_json` a JSON array whose first element is the settings object.
#[pyfunction]
fn views_call_rs(py: Python<'_>, name: &str, args: &str) -> PyResult<String> {
    let parsed: Value =
        serde_json::from_str(args).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let list = parsed.as_array().cloned().unwrap_or_default();
    let answer = py.detach(|| dispatch(name, &list));
    Ok(match answer {
        Ok(v) => json!({"ok": v}),
        Err(e) => json!({"err": error_json(&e)}),
    }
    .to_string())
}

// ---- operations that call back into Python (the engine-bound seams of workcopy) ------------------------------------

thread_local! {
    /// The exception a Python callback raised during the current call: re-raised as itself when the Rust code returns.
    static PENDING: RefCell<Option<PyErr>> = const { RefCell::new(None) };
}

fn remember(error: PyErr) -> Error {
    let message = error.to_string();
    PENDING.with(|slot| *slot.borrow_mut() = Some(error));
    Error::Runtime(message)
}

fn from_text(text: &str) -> PyResult<Value> {
    serde_json::from_str(text).map_err(|e| PyValueError::new_err(e.to_string()))
}

/// The Python object that answers `heal`, `sync` and `attribution` (see `hydralysis.viewnative.WorkcopyHost`). Each method
/// takes one JSON array text and returns one JSON text, so values cross as text and exceptions cross as themselves.
struct PyHost {
    object: Py<PyAny>,
}

impl PyHost {
    fn call(&self, method: &str, args: &[Value]) -> hy_views::Result<Value> {
        Python::attach(|py| -> PyResult<Value> {
            let reply = self
                .object
                .bind(py)
                .call_method1(method, (Value::Array(args.to_vec()).to_string(),))?;
            from_text(&reply.extract::<String>()?)
        })
        .map_err(remember)
    }
}

impl Host for PyHost {
    fn heal(
        &self,
        settings: &Map<String, Value>,
        target: &Map<String, Value>,
    ) -> hy_views::Result<bool> {
        let reply = self.call(
            "heal",
            &[
                Value::Object(settings.clone()),
                Value::Object(target.clone()),
            ],
        )?;
        Ok(reply.as_bool().unwrap_or(false))
    }

    fn ensure_lineage(
        &self,
        _: &Map<String, Value>,
        _: &Map<String, Value>,
    ) -> hy_views::Result<Value> {
        Err(Error::Runtime(
            "lineage is not available through the workcopy host".into(),
        ))
    }

    fn resolve_target(
        &self,
        _: &Map<String, Value>,
        _: &str,
    ) -> hy_views::Result<Map<String, Value>> {
        Err(Error::Runtime(
            "targets are not available through the workcopy host".into(),
        ))
    }

    fn open_program(&self, _: &str, _: &str, _: &str, _: bool) -> hy_views::Result<Value> {
        Err(Error::Runtime(
            "programs are not available through the workcopy host".into(),
        ))
    }

    fn probe(
        &self,
        _: &Value,
        _: &[hy_views::classify::Pair],
    ) -> hy_views::Result<std::collections::HashMap<hy_views::classify::Pair, Value>> {
        Err(Error::Runtime(
            "probes are not available through the workcopy host".into(),
        ))
    }

    fn sync(
        &self,
        settings: &Map<String, Value>,
        target: &Map<String, Value>,
        store: &Map<String, Value>,
        timeout_s: i64,
        extra: Option<&[Value]>,
        sweep: bool,
    ) -> hy_views::Result<Value> {
        self.call(
            "sync",
            &[
                Value::Object(settings.clone()),
                Value::Object(target.clone()),
                Value::Object(store.clone()),
                json!(timeout_s),
                extra.map_or(Value::Null, |e| Value::Array(e.to_vec())),
                json!(sweep),
            ],
        )
    }

    fn abandon_copy(&self, _: &Map<String, Value>, _: &Map<String, Value>, _: Option<&Value>) {}

    fn adopt_copy(
        &self,
        _: &Map<String, Value>,
        _: &Map<String, Value>,
        _: &Value,
    ) -> hy_views::Result<()> {
        Err(Error::Runtime(
            "copies are not available through the workcopy host".into(),
        ))
    }

    fn attribution(&self) -> Value {
        self.call("attribution", &[])
            .unwrap_or_else(|_| hy_views::settle::attribution())
    }
}

fn hosted(host: &PyHost, name: &str, args: &[Value]) -> hy_views::Result<Value> {
    let settings = object(args.first().unwrap_or(&Value::Null))?;
    let target = object(args.get(1).unwrap_or(&Value::Null))?;
    let number = |at: usize| args.get(at).and_then(Value::as_i64);
    match name {
        "workcopy_revert" => {
            let ids: Vec<String> = args
                .get(2)
                .and_then(Value::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default();
            let cascade = args.get(4).and_then(Value::as_bool).unwrap_or(false);
            workcopy::revert(host, &settings, &target, &ids, number(3), cascade)
        }
        "workcopy_edit" => {
            let address = text(args, 2)?;
            workcopy::edit(
                host,
                &settings,
                &target,
                address,
                args.get(3).cloned().unwrap_or(Value::Null),
                number(4).unwrap_or(0),
            )
        }
        "workcopy_add_proposals" => {
            let records = args
                .get(2)
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            workcopy::add_proposals(
                host,
                &settings,
                &target,
                &records,
                number(3),
                number(4).unwrap_or(0),
                args.get(5).unwrap_or(&Value::Null),
            )
        }
        other => Err(Error::value(format!("unknown native function {other}"))),
    }
}

/// `workcopy_host_call_rs(name, args_json, host)`: `revert`, `edit` and `add_proposals`, whose engine-bound steps (`heal`,
/// `_sync`) and caller identity are answered by `host`. A Python exception raised by the host is raised again unchanged.
#[pyfunction]
fn workcopy_host_call_rs(
    py: Python<'_>,
    name: &str,
    args: &str,
    host: Py<PyAny>,
) -> PyResult<String> {
    let parsed = from_text(args)?;
    let list = parsed.as_array().cloned().unwrap_or_default();
    PENDING.with(|slot| slot.borrow_mut().take());
    let host = PyHost { object: host };
    let answer = py.detach(|| hosted(&host, name, &list));
    let raised = PENDING.with(|slot| slot.borrow_mut().take());
    if let (Err(_), Some(error)) = (&answer, raised) {
        return Err(error);
    }
    Ok(match answer {
        Ok(v) => json!({"ok": v}),
        Err(e) => json!({"err": error_json(&e)}),
    }
    .to_string())
}

static VALIDATOR: Mutex<Option<Py<PyAny>>> = Mutex::new(None);

/// `analysis.validate_options("type_edit", options, _record=True)`: the Rust validator first; the inputs that need Python
/// (files, Python regular expressions, a value that is not an object) go to the registered callable.
fn validate_record(options: &Value) -> hy_views::Result<Value> {
    use hy_query::analysis::{validate_options, Invalid};
    let object = options.as_object();
    if object.is_some() || options.is_null() {
        match validate_options("type_edit", object, true) {
            Ok(v) => return Ok(v),
            Err(Invalid::Value(message)) => return Err(Error::value(message)),
            Err(Invalid::Fallback) => {}
        }
    }
    Python::attach(|py| -> PyResult<Value> {
        let guard = VALIDATOR
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(callable) = guard.as_ref() else {
            return Err(PyValueError::new_err("no Python validator is registered"));
        };
        let reply = callable.bind(py).call1((options.to_string(),))?;
        from_text(&reply.extract::<String>()?)
    })
    .map_err(remember)
}

/// Register the Python implementation of `analysis.validate_options("type_edit", ..., _record=True)` (text in, text out) and
/// make the store use it for the records it cleans.
#[pyfunction]
fn workcopy_set_validator(callable: Py<PyAny>) {
    *VALIDATOR
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(callable);
    hy_views::store::set_validator(validate_record);
}

// ---- the warm publish workers (`viewpool`) --------------------------------------------------------------------------

/// A snapshot of one worker of the pool.
#[pyclass(name = "ViewWorker", frozen, get_all)]
struct ViewWorker {
    pid: u32,
    busy: bool,
    alive: bool,
}

#[pymethods]
impl ViewWorker {
    fn __repr__(&self) -> String {
        format!(
            "ViewWorker(pid={}, busy={}, alive={})",
            self.pid, self.busy, self.alive
        )
    }
}

/// The warm workers of this process (`hy_views::viewpool::Pool`). The command and the environment come with each `send`.
#[pyclass(name = "ViewPool", frozen)]
struct ViewPool {
    pool: hy_views::viewpool::Pool,
}

#[pymethods]
impl ViewPool {
    #[new]
    #[pyo3(signature = (idle_s=2.0, keep_idle=1, stop_grace_s=5.0, ready_timeout_s=10.0))]
    fn new(idle_s: f64, keep_idle: usize, stop_grace_s: f64, ready_timeout_s: f64) -> Self {
        let seconds = |s: f64| std::time::Duration::from_secs_f64(s.max(0.0));
        let config = hy_views::viewpool::Config {
            ready_timeout: seconds(ready_timeout_s),
            idle: seconds(idle_s),
            keep_idle,
            stop_grace: seconds(stop_grace_s),
            terminate: std::sync::Arc::new(|pid| {
                let _ = hy_query::proc::terminate_tree(pid);
            }),
        };
        Self {
            pool: hy_views::viewpool::Pool::new(config),
        }
    }

    /// Hand the job at PATH to a warm worker; False when the caller must spawn the one-shot worker.
    fn send(
        &self,
        py: Python<'_>,
        path: &str,
        command: Vec<String>,
        env: std::collections::HashMap<String, String>,
        max_workers: usize,
    ) -> bool {
        let env: Vec<(String, String)> = env.into_iter().collect();
        py.detach(|| self.pool.send(path, &command, &env, max_workers))
    }

    fn close_all(&self, py: Python<'_>) {
        py.detach(|| self.pool.close_all());
    }

    fn shutdown(&self, py: Python<'_>) {
        py.detach(|| self.pool.shutdown());
    }

    #[getter]
    fn broken(&self) -> bool {
        self.pool.broken()
    }

    #[getter]
    fn workers(&self) -> Vec<ViewWorker> {
        self.pool
            .workers()
            .into_iter()
            .map(|w| ViewWorker {
                pid: w.pid,
                busy: w.busy,
                alive: w.alive,
            })
            .collect()
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(views_call_rs, module)?)?;
    module.add_function(wrap_pyfunction!(workcopy_host_call_rs, module)?)?;
    module.add_function(wrap_pyfunction!(workcopy_set_validator, module)?)?;
    module.add_class::<ViewPool>()?;
    module.add_class::<ViewWorker>()?;
    Ok(())
}
