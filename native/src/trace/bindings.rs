//! Binding of `hy_trace::bindings`: `hydralysis.trace_bindings.link_events` when `HYDRALYSIS_IMPL=rust`.
//!
//! Only the fields the link reads are copied out of each event. An event or table row of a shape the port does not model
//! (a thread generation that is a pair, an rva that is a float, a row without its status, a malformed RVA text) is a
//! `TraceFallback`: the Python then answers, or raises, as it always did.

use super::port::{fallback, from_value, or_fallback, to_value_exact};
use hy_trace::bindings::{link_events, BindingRow, LinkEvent};
use hy_trace::pyfmt::{parse_int_radix, IntParse};
use hy_trace::reports::Key;
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt, PyList, PyString};

fn key_of(obj: &Bound<'_, PyAny>) -> PyResult<Key> {
    if obj.is_none() {
        return Ok(Key::Null);
    }
    if obj.is_instance_of::<PyBool>() {
        return Err(fallback("a boolean where an id was expected"));
    }
    if obj.is_instance_of::<PyInt>() {
        return or_fallback(obj.extract::<i64>()).map(Key::Int);
    }
    if let Ok(text) = obj.cast::<PyString>() {
        return Ok(Key::Str(or_fallback(text.to_str().map(str::to_owned))?));
    }
    Err(fallback("a key that is not None, an integer or text"))
}

fn text(obj: &Bound<'_, PyAny>) -> PyResult<String> {
    let text = obj
        .cast::<PyString>()
        .map_err(|_| fallback("text expected"))?;
    or_fallback(text.to_str().map(str::to_owned))
}

fn extract_event<'py>(row: &Bound<'py, PyAny>) -> PyResult<LinkEvent> {
    let py = row.py();
    let row = row
        .cast::<PyDict>()
        .map_err(|_| fallback("an event that is not a dict"))?;
    let get = |name: &Bound<'py, PyString>| row.get_item(name);
    let seq = match get(intern!(py, "seq"))? {
        None => None,
        Some(seq) if seq.is_none() => None,
        Some(seq) if seq.is_instance_of::<PyInt>() && !seq.is_instance_of::<PyBool>() => {
            Some(or_fallback(seq.extract::<i64>())?)
        }
        Some(_) => return Err(fallback("a seq that is not an integer")),
    };
    let thread_gen = get(intern!(py, "thread_gen"))?.map_or(Ok(Key::Null), |v| key_of(&v))?;
    let rva = get(intern!(py, "rva"))?.map_or(Ok(Key::Null), |v| key_of(&v))?;
    let event_id = get(intern!(py, "event_id"))?
        .map_or(Ok(serde_json::Value::Null), |v| to_value_exact(&v))?;
    let is_function_enter = match get(intern!(py, "kind"))? {
        Some(kind) => kind
            .cast::<PyString>()
            .is_ok_and(|s| s.to_str().is_ok_and(|s| s == "core.function.enter")),
        None => false,
    };
    let script_function = match get(intern!(py, "payload"))? {
        Some(payload) if payload.is_truthy()? => {
            let payload = payload
                .cast::<PyDict>()
                .map_err(|_| fallback("a payload that is not a dict"))?;
            match payload.get_item(intern!(py, "script_function"))? {
                Some(name) if name.is_truthy()? => Some(text(&name)?),
                _ => None,
            }
        }
        _ => None,
    };
    Ok(LinkEvent {
        seq,
        thread_gen,
        script_function,
        event_id,
        rva,
        is_function_enter,
    })
}

/// `int(rva_text[4:], 16)`.
fn rva_of(obj: &Bound<'_, PyAny>) -> PyResult<i64> {
    let digits: String = text(obj)?.chars().skip(4).collect();
    match parse_int_radix(&digits, 16) {
        IntParse::Value(v) => i64::try_from(v).map_err(|_| fallback("an RVA beyond 64 bits")),
        IntParse::Invalid | IntParse::NotAscii => {
            Err(fallback("an RVA that is not hexadecimal text"))
        }
    }
}

fn extract_rows(table: &Bound<'_, PyAny>) -> PyResult<Vec<BindingRow>> {
    let py = table.py();
    let table = table
        .cast::<PyDict>()
        .map_err(|_| fallback("a table that is not a dict"))?;
    let rows = table
        .get_item(intern!(py, "rows"))?
        .ok_or_else(|| fallback("a table without rows"))?;
    let rows = rows
        .cast::<PyList>()
        .map_err(|_| fallback("rows that are not a list"))?;
    let mut out = Vec::new();
    for row in rows.iter() {
        let row = row
            .cast::<PyDict>()
            .map_err(|_| fallback("a row that is not a dict"))?;
        let status = row
            .get_item(intern!(py, "status"))?
            .ok_or_else(|| fallback("a row without a status"))?;
        if !status.eq("resolved")? {
            continue;
        }
        let script_name = row
            .get_item(intern!(py, "script_name"))?
            .ok_or_else(|| fallback("a row without a script_name"))?;
        let native = row
            .get_item(intern!(py, "native_rva"))?
            .ok_or_else(|| fallback("a row without a native_rva"))?;
        let implementation = match row.get_item(intern!(py, "implementation_rva"))? {
            Some(value) if value.is_truthy()? => value,
            _ => native.clone(),
        };
        out.push(BindingRow {
            script_name: text(&script_name)?,
            native_rva: rva_of(&native)?,
            implementation_rva: rva_of(&implementation)?,
        });
    }
    Ok(out)
}

/// `link_events(events, table, window=window)`.
#[pyfunction]
fn bindings_link_events<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyList>,
    table: &Bound<'py, PyAny>,
    window: i64,
) -> PyResult<Bound<'py, PyAny>> {
    let window = usize::try_from(window).map_err(|_| fallback("a negative window"))?;
    let rows = extract_rows(table)?;
    let events = events
        .iter()
        .map(|event| extract_event(&event))
        .collect::<PyResult<Vec<_>>>()?;
    let linked = py.detach(|| link_events(&events, &rows, window));
    from_value(py, &linked)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(bindings_link_events, module)?)
}
