//! The Hydra Engine session client for Hydralysis: the framing, the request ids, the `hello` negotiation, the waits and
//! their deadlines, and the mapping of an engine answer to `SessionError`. Its Python twin is the engine's own
//! `ghidra_session.py` (library 1.1.0), which `hydralysis.engine_client` falls back to; both give the same results.
//!
//! The session core is the vendored `hydra-client` crate (a reader thread owns the socket and routes each reply to the
//! waiter of its id). What is added here is the Python surface of `ghidra_session.SocketSession`: the same attributes
//! and methods that `hydralysis.hydra` uses, with the GIL released for every wait, send and dial.
//!
//! Replies are parsed by Python's `json.loads` from the engine's own bytes (key order and number forms stay what the
//! Python library gave), and a request's fields are written in the order and the form `json.dumps` writes them.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use hydra_client::error::{code, Error as ClientError};
use hydra_client::{ConnectOptions, Endpoint, Session, CLIENT_VERSION, PROTOCOL, PROTOCOL_MIN};
use pyo3::exceptions::{PyKeyError, PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString, PyTuple};
use serde_json::Value;

/// The exception classes `hydralysis.engine_client` registers (they are Python classes, so that `except
/// module.SessionError` in `hydralysis.hydra` matches whichever client is in use).
struct Classes {
    session_error: Py<PyAny>,
    incompatible: Py<PyAny>,
}

static CLASSES: Mutex<Option<Classes>> = Mutex::new(None);

fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Registers the Python exception classes the session raises.
#[pyfunction]
fn register_errors(session_error: Py<PyAny>, incompatible: Py<PyAny>) {
    *locked(&CLASSES) = Some(Classes {
        session_error,
        incompatible,
    });
}

/// `(protocol, protocol_min, client_version)` this build speaks; `hydralysis.hydra` checks them against its pins.
#[pyfunction]
fn client_pins() -> (i64, i64, &'static str) {
    (PROTOCOL, PROTOCOL_MIN, CLIENT_VERSION)
}

fn session_error_class(py: Python<'_>) -> PyResult<Py<PyAny>> {
    locked(&CLASSES)
        .as_ref()
        .map(|c| c.session_error.clone_ref(py))
        .ok_or_else(|| PyValueError::new_err("hydralysis_native.register_errors was not called"))
}

fn py_session_error(
    py: Python<'_>,
    code: &Bound<'_, PyAny>,
    message: &Bound<'_, PyAny>,
    details: &Bound<'_, PyAny>,
    trace: &Bound<'_, PyAny>,
) -> PyResult<PyErr> {
    let class = session_error_class(py)?;
    let error = class.bind(py).call1((code, message, details, trace))?;
    Ok(PyErr::from_value(error))
}

fn loads<'py>(py: Python<'py>, text: &str) -> PyResult<Bound<'py, PyAny>> {
    py.import("json")?.getattr("loads")?.call1((text,))
}

fn value_to_py<'py>(py: Python<'py>, value: &Value) -> PyResult<Bound<'py, PyAny>> {
    loads(py, &value.to_string())
}

// ---- JSON as `json.dumps` writes it (ensure_ascii, ", " and ": ") ------------------------------------------------------

const MAX_DEPTH: usize = 200;

fn write_unit(out: &mut String, unit: u32) {
    out.push_str("\\u");
    for shift in [12, 8, 4, 0] {
        out.push(char::from_digit((unit >> shift) & 0xf, 16).unwrap_or('0'));
    }
}

fn write_text(out: &mut String, text: &str) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            _ => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write_unit(out, u32::from(*unit));
                }
            }
        }
    }
    out.push('"');
}

/// A `str` with lone surrogates (Python allows them, UTF-8 does not): written one UTF-16 unit at a time.
fn write_surrogate_text(out: &mut String, obj: &Bound<'_, PyAny>) -> PyResult<()> {
    let bytes: Vec<u8> = obj
        .call_method1("encode", ("utf-16-le", "surrogatepass"))?
        .extract()?;
    out.push('"');
    let (pairs, _) = bytes.as_chunks::<2>();
    for pair in pairs {
        let unit = u32::from(u16::from_le_bytes(*pair));
        match char::from_u32(unit) {
            Some(c @ (' '..='~')) if c != '"' && c != '\\' => out.push(c),
            Some('"') => out.push_str("\\\""),
            Some('\\') => out.push_str("\\\\"),
            Some('\n') => out.push_str("\\n"),
            Some('\r') => out.push_str("\\r"),
            Some('\t') => out.push_str("\\t"),
            Some('\u{8}') => out.push_str("\\b"),
            Some('\u{c}') => out.push_str("\\f"),
            _ => write_unit(out, unit),
        }
    }
    out.push('"');
    Ok(())
}

fn write_string(out: &mut String, obj: &Bound<'_, PyAny>) -> PyResult<()> {
    let text = obj.cast::<PyString>()?;
    match text.to_cow() {
        Ok(cow) => write_text(out, &cow),
        Err(_) => write_surrogate_text(out, obj)?,
    }
    Ok(())
}

fn write_float(out: &mut String, obj: &Bound<'_, PyAny>) -> PyResult<()> {
    let value: f64 = obj.extract()?;
    if value.is_nan() {
        out.push_str("NaN");
    } else if value.is_infinite() {
        out.push_str(if value > 0.0 { "Infinity" } else { "-Infinity" });
    } else {
        out.push_str(&obj.repr()?.to_cow()?);
    }
    Ok(())
}

fn write_key(out: &mut String, key: &Bound<'_, PyAny>) -> PyResult<()> {
    if key.is_instance_of::<PyString>() {
        return write_string(out, key);
    }
    let text = if key.is_none() {
        "null".to_owned()
    } else if let Ok(flag) = key.cast::<PyBool>() {
        (if flag.is_true() { "true" } else { "false" }).to_owned()
    } else if key.is_instance_of::<PyInt>() {
        key.str()?.to_cow()?.into_owned()
    } else if key.is_instance_of::<PyFloat>() {
        let mut text = String::new();
        write_float(&mut text, key)?;
        text
    } else {
        return Err(PyTypeError::new_err(format!(
            "keys must be str, int, float, bool or None, not {}",
            key.get_type().name()?
        )));
    };
    write_text(out, &text);
    Ok(())
}

fn write_pairs(
    out: &mut String,
    dict: &Bound<'_, PyDict>,
    depth: usize,
    first: &mut bool,
) -> PyResult<()> {
    for (key, value) in dict.iter() {
        if !*first {
            out.push_str(", ");
        }
        *first = false;
        write_key(out, &key)?;
        out.push_str(": ");
        write_value(out, &value, depth + 1)?;
    }
    Ok(())
}

fn write_value(out: &mut String, obj: &Bound<'_, PyAny>, depth: usize) -> PyResult<()> {
    if depth > MAX_DEPTH {
        return Err(PyValueError::new_err("Circular reference detected"));
    }
    if obj.is_none() {
        out.push_str("null");
    } else if let Ok(flag) = obj.cast::<PyBool>() {
        out.push_str(if flag.is_true() { "true" } else { "false" });
    } else if obj.is_instance_of::<PyInt>() {
        match obj.extract::<i64>() {
            Ok(n) => out.push_str(itoa::Buffer::new().format(n)),
            Err(_) => out.push_str(&obj.str()?.to_cow()?),
        }
    } else if obj.is_instance_of::<PyFloat>() {
        write_float(out, obj)?;
    } else if obj.is_instance_of::<PyString>() {
        write_string(out, obj)?;
    } else if let Ok(dict) = obj.cast::<PyDict>() {
        out.push('{');
        write_pairs(out, dict, depth, &mut true)?;
        out.push('}');
    } else if obj.is_instance_of::<PyList>() || obj.is_instance_of::<PyTuple>() {
        out.push('[');
        for (index, item) in obj.try_iter()?.enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            write_value(out, &item?, depth + 1)?;
        }
        out.push(']');
    } else {
        return Err(PyTypeError::new_err(format!(
            "Object of type {} is not JSON serializable",
            obj.get_type().name()?
        )));
    }
    Ok(())
}

/// `{"id": N, "cmd": "...", <fields>}` with the id left for the caller: the text before and after it.
fn request_parts(cmd: &str, fields: Option<&Bound<'_, PyDict>>) -> PyResult<(String, String)> {
    let mut head = String::from(", \"cmd\": ");
    write_text(&mut head, cmd);
    if let Some(fields) = fields {
        if fields.contains("id")? || fields.contains("cmd")? {
            return Err(PyTypeError::new_err(
                "a request field cannot be named id or cmd",
            ));
        }
        write_pairs(&mut head, fields, 0, &mut false)?;
    }
    head.push('}');
    Ok(("{\"id\": ".to_owned(), head))
}

// ---- errors -------------------------------------------------------------------------------------------------------

fn deadline_text(deadline: Option<&Bound<'_, PyAny>>) -> PyResult<String> {
    match deadline {
        Some(d) => Ok(d.call_method1("__format__", ("g",))?.extract()?),
        None => Ok("0".to_owned()),
    }
}

fn text<'py>(py: Python<'py>, value: &str) -> Bound<'py, PyAny> {
    PyString::new(py, value).into_any()
}

fn build_error(
    py: Python<'_>,
    error: ClientError,
    deadline: Option<&Bound<'_, PyAny>>,
) -> PyResult<PyErr> {
    let none = py.None().into_bound(py);
    match error {
        ClientError::Session(e) if e.code == code::CLOSED => py_session_error(
            py,
            &text(py, "closed"),
            &text(py, "the session connection ended"),
            &PyDict::new(py),
            &none,
        ),
        ClientError::Session(e) if e.code == code::DEADLINE_EXCEEDED => {
            let target = e.details.get("target").and_then(Value::as_u64).unwrap_or(0);
            let cancel_id = e.details.get("cancelId").and_then(Value::as_u64);
            let details = PyDict::new(py);
            match deadline {
                Some(d) => details.set_item("deadlineS", d)?,
                None => details.set_item("deadlineS", &none)?,
            }
            details.set_item("target", target)?;
            details.set_item("cancelId", cancel_id)?;
            let message = format!(
                "no answer to request {target} within {} s; cancel sent",
                deadline_text(deadline)?
            );
            py_session_error(
                py,
                &text(py, "deadline_exceeded"),
                &text(py, &message),
                &details,
                &none,
            )
        }
        ClientError::Session(e) if e.code == code::INCOMPATIBLE => {
            let class = locked(&CLASSES)
                .as_ref()
                .map(|c| c.incompatible.clone_ref(py))
                .ok_or_else(|| {
                    PyValueError::new_err("hydralysis_native.register_errors was not called")
                })?;
            Ok(PyErr::from_value(class.bind(py).call1((e.message,))?))
        }
        ClientError::Session(e) => {
            let details = value_to_py(py, &e.details)?;
            let trace = match &e.trace {
                Some(t) => value_to_py(py, t)?,
                None => none,
            };
            py_session_error(
                py,
                &text(py, &e.code),
                &text(py, &e.message),
                &details,
                &trace,
            )
        }
        ClientError::Io(e) => Ok(PyErr::from(e)),
        ClientError::Endpoint(m) => Ok(PyKeyError::new_err(m)),
        other => Ok(PyValueError::new_err(other.to_string())),
    }
}

fn map_error(py: Python<'_>, error: ClientError, deadline: Option<&Bound<'_, PyAny>>) -> PyErr {
    build_error(py, error, deadline).unwrap_or_else(|e| e)
}

/// `_check_deadline` minus the socket test: a positive number of seconds (not a bool), else `ValueError`.
/// `None` for no deadline, and for an infinite one (it never passes).
fn parse_deadline(deadline: Option<&Bound<'_, PyAny>>) -> PyResult<Option<f64>> {
    let Some(d) = deadline.filter(|d| !d.is_none()) else {
        return Ok(None);
    };
    let usable = !d.is_instance_of::<PyBool>()
        && (d.is_instance_of::<PyInt>() || d.is_instance_of::<PyFloat>());
    let seconds = if usable {
        d.extract::<f64>().ok()
    } else {
        None
    };
    match seconds {
        Some(s) if s > 0.0 => Ok(if s.is_finite() { Some(s) } else { None }),
        _ => Err(PyValueError::new_err(format!(
            "deadline must be a positive number of seconds, not {}",
            d.repr()?
        ))),
    }
}

// ---- the session --------------------------------------------------------------------------------------------------

struct EventSlot {
    callback: Mutex<Option<Py<PyAny>>>,
}

/// A connection to the engine daemon: the Python surface of `ghidra_session.SocketSession` (library 1.1.0).
#[pyclass(frozen, dict, name = "Session", module = "hydralysis_native")]
struct PySession {
    session: Arc<Session>,
    slot: Arc<EventSlot>,
    hello: Py<PyAny>,
    endpoint: Py<PyAny>,
    protocol: Py<PyAny>,
}

fn send_request(
    slf: &Bound<'_, PySession>,
    cmd: &str,
    fields: Option<&Bound<'_, PyDict>>,
    abandon: bool,
) -> PyResult<u64> {
    let py = slf.py();
    let (head, tail) = request_parts(cmd, fields)?;
    let session = Arc::clone(&slf.get().session);
    let sent = py.detach(|| session.send_with(abandon, |rid| format!("{head}{rid}{tail}")));
    sent.map_err(|e| map_error(py, e, None))
}

fn wait_message<'py>(
    slf: &Bound<'py, PySession>,
    rid: u64,
    deadline: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let py = slf.py();
    let seconds = parse_deadline(deadline)?;
    let session = Arc::clone(&slf.get().session);
    match py.detach(|| session.wait_line(rid, seconds)) {
        Ok(line) => {
            let message = loads(py, &line)?;
            let ms = message.call_method1("get", ("ms", 0))?;
            slf.setattr("last_ms", ms)?;
            slf.setattr("last_response", &message)?;
            Ok(message)
        }
        Err(error) => Err(map_error(py, error, deadline)),
    }
}

/// The engine's `ok:false` answer as the `SessionError` the library raises, with the whole `error` object on `.error`.
fn answer_error(py: Python<'_>, message: &Bound<'_, PyAny>) -> PyResult<PyErr> {
    let empty = PyDict::new(py);
    let error = message.call_method1("get", ("error", &empty))?;
    let get = |key: &str| error.call_method1("get", (key,));
    let (code, text, details, trace) = (
        get("code")?,
        get("message")?,
        get("details")?,
        get("trace")?,
    );
    let details = if details.is_truthy()? {
        details
    } else {
        PyDict::new(py).into_any()
    };
    let failure = py_session_error(py, &code, &text, &details, &trace)?;
    if error.is_instance_of::<PyDict>() {
        failure.value(py).setattr("error", &error)?;
    }
    Ok(failure)
}

#[pymethods]
impl PySession {
    #[classattr]
    #[pyo3(name = "supports_deadline")]
    const SUPPORTS_DEADLINE: bool = true;

    #[getter]
    fn hello(&self, py: Python<'_>) -> Py<PyAny> {
        self.hello.clone_ref(py)
    }

    #[getter]
    fn endpoint(&self, py: Python<'_>) -> Py<PyAny> {
        self.endpoint.clone_ref(py)
    }

    #[getter]
    fn protocol(&self, py: Python<'_>) -> Py<PyAny> {
        self.protocol.clone_ref(py)
    }

    #[getter(_closed)]
    fn closed(&self) -> bool {
        self.session.is_closed()
    }

    #[getter]
    fn events<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let list = PyList::empty(py);
        for line in self.session.event_lines() {
            list.append(loads(py, &line)?)?;
        }
        Ok(list)
    }

    #[getter]
    fn on_event(&self, py: Python<'_>) -> Option<Py<PyAny>> {
        locked(&self.slot.callback)
            .as_ref()
            .map(|c| c.clone_ref(py))
    }

    #[setter]
    fn set_on_event(&self, callback: Option<Py<PyAny>>) {
        *locked(&self.slot.callback) = callback;
    }

    /// `_check_deadline`: raises `ValueError` for a deadline that is not a positive number of seconds.
    #[pyo3(signature = (deadline))]
    fn _check_deadline(&self, deadline: Option<&Bound<'_, PyAny>>) -> PyResult<()> {
        parse_deadline(deadline).map(|_| ())
    }

    /// Sends one request without waiting; returns its id.
    #[pyo3(signature = (cmd, **fields))]
    fn send(slf: &Bound<'_, Self>, cmd: &str, fields: Option<&Bound<'_, PyDict>>) -> PyResult<u64> {
        send_request(slf, cmd, fields, false)
    }

    /// `send` with the fields as one dict; `abandon=True` drops the answer when it arrives.
    #[pyo3(signature = (cmd, fields, abandon = false))]
    fn _send_request(
        slf: &Bound<'_, Self>,
        cmd: &str,
        fields: &Bound<'_, PyDict>,
        abandon: bool,
    ) -> PyResult<u64> {
        send_request(slf, cmd, Some(fields), abandon)
    }

    /// The `result` of the answer to request `rid`; `SessionError` for `ok:false`, `deadline_exceeded` after `deadline`
    /// seconds (a `cancel` is sent and the late answer dropped; the connection stays usable).
    #[pyo3(signature = (rid, deadline = None))]
    fn wait<'py>(
        slf: &Bound<'py, Self>,
        rid: u64,
        deadline: Option<&Bound<'py, PyAny>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let message = wait_message(slf, rid, deadline)?;
        if !message.call_method1("get", ("ok",))?.is_truthy()? {
            return Err(answer_error(slf.py(), &message)?);
        }
        message.get_item("result")
    }

    /// Sends one request and waits for its `result`.
    #[pyo3(signature = (cmd, deadline = None, **fields))]
    fn call<'py>(
        slf: &Bound<'py, Self>,
        cmd: &str,
        deadline: Option<&Bound<'py, PyAny>>,
        fields: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        parse_deadline(deadline)?;
        let rid = send_request(slf, cmd, fields, false)?;
        Self::wait(slf, rid, deadline)
    }

    /// Like `call`, but returns the whole answer (`result` and the markers next to it).
    #[pyo3(signature = (cmd, deadline = None, **fields))]
    fn call_raw<'py>(
        slf: &Bound<'py, Self>,
        cmd: &str,
        deadline: Option<&Bound<'py, PyAny>>,
        fields: Option<&Bound<'py, PyDict>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        parse_deadline(deadline)?;
        let rid = send_request(slf, cmd, fields, false)?;
        let message = wait_message(slf, rid, deadline)?;
        if !message.call_method1("get", ("ok",))?.is_truthy()? {
            return Err(answer_error(slf.py(), &message)?);
        }
        Ok(message)
    }

    /// Shuts the connection down: a thread blocked in a wait returns with `closed`.
    fn close(&self, py: Python<'_>) {
        let session = Arc::clone(&self.session);
        py.detach(|| session.close_ref());
    }

    fn __enter__(slf: Py<Self>) -> Py<Self> {
        slf
    }

    #[pyo3(signature = (*_exc))]
    fn __exit__(&self, py: Python<'_>, _exc: &Bound<'_, PyTuple>) {
        self.close(py);
    }
}

fn deliver_event(slot: &EventSlot, line: &str) {
    let _ = Python::try_attach(|py| {
        let callback = locked(&slot.callback).as_ref().map(|c| c.clone_ref(py));
        let Some(callback) = callback else { return };
        let outcome =
            loads(py, line).and_then(|event| callback.bind(py).call1((event,)).map(|_| ()));
        if let Err(error) = outcome {
            error.write_unraisable(py, None);
        }
    });
}

/// Dials the daemon the endpoint file names and negotiates: `hello` with the endpoint's token, then the compatibility
/// check. `endpoint` is the text of `<state>/<instance>.json`. Raises `IncompatibleError`, `SessionError`, `OSError` or
/// `KeyError` (an unusable endpoint) as `SocketSession(...)` does.
#[pyfunction]
#[pyo3(signature = (endpoint, client = "", harness = "", hello_deadline = None))]
fn connect_endpoint<'py>(
    py: Python<'py>,
    endpoint: &str,
    client: &str,
    harness: &str,
    hello_deadline: Option<f64>,
) -> PyResult<Bound<'py, PySession>> {
    let parsed: Value =
        serde_json::from_str(endpoint).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let target = Endpoint::from_value(parsed).map_err(|e| map_error(py, e, None))?;
    let mut options = ConnectOptions::new(client, harness);
    options.hello_deadline = hello_deadline;
    let connected = py.detach(|| Session::connect(target, &options));
    let session = connected.map_err(|e| map_error(py, e, None))?;
    let hello = loads(py, session.hello_raw())?.get_item("result")?;
    let protocol = match hello.call_method1("get", ("protocol",)) {
        Ok(p) if p.is_instance_of::<PyInt>() && !p.is_instance_of::<PyBool>() => p,
        _ => py.None().into_bound(py),
    };
    let slot = Arc::new(EventSlot {
        callback: Mutex::new(None),
    });
    let handler = Arc::clone(&slot);
    session.set_raw_event_handler(move |line| deliver_event(&handler, line));
    let made = Bound::new(
        py,
        PySession {
            session: Arc::new(session),
            slot,
            hello: hello.unbind(),
            endpoint: loads(py, endpoint)?.unbind(),
            protocol: protocol.unbind(),
        },
    )?;
    made.setattr("last_ms", 0)?;
    made.setattr("last_response", py.None())?;
    made.setattr("launch", py.None())?;
    made.setattr("started", false)?;
    made.setattr("warnings", PyList::empty(py))?;
    Ok(made)
}

pub(crate) fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_class::<PySession>()?;
    module.add_function(wrap_pyfunction!(connect_endpoint, module)?)?;
    module.add_function(wrap_pyfunction!(register_errors, module)?)?;
    module.add_function(wrap_pyfunction!(client_pins, module)?)?;
    Ok(())
}
