//! Binding of `hy_trace::reports`: the report builders and the engine-row adapters behind `hydralysis.trace_reports`
//! when `HYDRALYSIS_IMPL=rust`.
//!
//! An event row is read the way `normalize_event` reads it, but only the payload keys a report needs are copied out of
//! Python. A row or a field of a shape the port does not model (a frame that is a float, a payload that is not a dict, ...)
//! is a `TraceFallback`: the Python implementation then answers, or raises, as it always did.

use super::port::{fallback, from_value, map_error, or_fallback, to_value};
use hy_trace::pyfmt::{parse_int_base0, parse_int_radix, IntParse};
use hy_trace::reports::{
    self, DispatchSite, Event, FieldSpan, Gap, Key, StaticSite, WriterOptions,
};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt, PyList, PyString, PyTuple};
use serde_json::{Map, Value};
use std::collections::HashMap;

fn as_dict<'py>(obj: &Bound<'py, PyAny>, what: &str) -> PyResult<Bound<'py, PyDict>> {
    obj.clone()
        .cast_into::<PyDict>()
        .map_err(|_| fallback(format!("{what} is not a dict")))
}

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
    if let Ok(tuple) = obj.cast::<PyTuple>() {
        return tuple
            .iter()
            .map(|item| key_of(&item))
            .collect::<PyResult<Vec<_>>>()
            .map(Key::Tuple);
    }
    Err(fallback(
        "a key that is not None, an integer, text or a tuple of them",
    ))
}

fn opt_text(obj: &Bound<'_, PyAny>) -> PyResult<Option<String>> {
    if obj.is_none() {
        return Ok(None);
    }
    let text = obj
        .cast::<PyString>()
        .map_err(|_| fallback("text expected"))?;
    or_fallback(text.to_str().map(str::to_owned)).map(Some)
}

fn text_list(obj: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    let items: Vec<Bound<'_, PyAny>> = if let Ok(list) = obj.cast::<PyList>() {
        list.iter().collect()
    } else if let Ok(tuple) = obj.cast::<PyTuple>() {
        tuple.iter().collect()
    } else {
        return Err(fallback("a list of text expected"));
    };
    items
        .iter()
        .map(|item| opt_text(item)?.ok_or_else(|| fallback("None in a list of text")))
        .collect()
}

/// The strings the extraction looks up, made once per call.
struct Names<'py> {
    event_id: Bound<'py, PyString>,
    kind: Bound<'py, PyString>,
    seq: Bound<'py, PyString>,
    frame: Bound<'py, PyString>,
    phase: Bound<'py, PyString>,
    role: Bound<'py, PyString>,
    thread_role: Bound<'py, PyString>,
    thread_gen: Bound<'py, PyString>,
    function: Bound<'py, PyString>,
    stack: Bound<'py, PyString>,
    va: Bound<'py, PyString>,
    ours: Bound<'py, PyString>,
    payload: Bound<'py, PyString>,
    static_: Bound<'py, PyString>,
    wanted: Vec<(String, Bound<'py, PyString>)>,
}

impl<'py> Names<'py> {
    fn new(py: Python<'py>, payload_keys: &[&str]) -> Self {
        Self {
            event_id: intern!(py, "event_id").clone(),
            kind: intern!(py, "kind").clone(),
            seq: intern!(py, "seq").clone(),
            frame: intern!(py, "frame").clone(),
            phase: intern!(py, "phase").clone(),
            role: intern!(py, "role").clone(),
            thread_role: intern!(py, "thread_role").clone(),
            thread_gen: intern!(py, "thread_gen").clone(),
            function: intern!(py, "function").clone(),
            stack: intern!(py, "stack").clone(),
            va: intern!(py, "va").clone(),
            ours: intern!(py, "ours").clone(),
            payload: intern!(py, "payload").clone(),
            static_: intern!(py, "static").clone(),
            wanted: payload_keys
                .iter()
                .map(|k| ((*k).to_owned(), PyString::new(py, k)))
                .collect(),
        }
    }
}

fn present<'py>(
    dict: &Bound<'py, PyDict>,
    key: &Bound<'py, PyString>,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    dict.get_item(key)
}

/// `normalize_event(row)`, reading only PAYLOAD_KEYS of the payload.
fn extract_event<'py>(row: &Bound<'py, PyAny>, names: &Names<'py>) -> PyResult<Event> {
    let row = row
        .cast::<PyDict>()
        .map_err(|_| fallback("an event row that is not a dict"))?;
    let static_dict = match present(row, &names.static_)? {
        Some(s) if s.is_truthy()? => Some(as_dict(&s, "static")?),
        _ => None,
    };
    let payload = match present(row, &names.payload)? {
        Some(p) if p.is_truthy()? => Some(as_dict(&p, "payload")?),
        _ => None,
    };
    let mut copied = Map::new();
    if let Some(payload) = &payload {
        for (name, key) in &names.wanted {
            if let Some(value) = payload.get_item(key)? {
                copied.insert(name.clone(), to_value(&value)?);
            }
        }
    }
    let stack_obj = match present(row, &names.stack)? {
        Some(s) if !s.is_none() => Some(s),
        _ => match &static_dict {
            Some(s) => present(s, &names.stack)?.filter(|v| v.is_truthy().unwrap_or(false)),
            None => None,
        },
    };
    let stack = match stack_obj {
        Some(s) => text_list(&s)?,
        None => Vec::new(),
    };
    let function = match present(row, &names.function)? {
        Some(f) if f.is_truthy()? => opt_text(&f)?,
        _ => match &static_dict {
            Some(s) => match present(s, &names.function)? {
                Some(f) => opt_text(&f)?,
                None => None,
            },
            None => None,
        },
    };
    let role = match present(row, &names.role)? {
        Some(r) if r.is_truthy()? => to_value(&r)?,
        _ => match present(row, &names.thread_role)? {
            Some(r) => to_value(&r)?,
            None => Value::Null,
        },
    };
    let none = |obj: Option<Bound<'py, PyAny>>| obj.filter(|o| !o.is_none());
    let seq = match none(present(row, &names.seq)?) {
        Some(s) if s.is_instance_of::<PyInt>() && !s.is_instance_of::<PyBool>() => {
            Some(or_fallback(s.extract::<i64>())?)
        }
        Some(_) => return Err(fallback("a sequence number that is not an integer")),
        None => None,
    };
    let va = match none(present(row, &names.va)?) {
        Some(v) if v.is_instance_of::<PyInt>() && !v.is_instance_of::<PyBool>() => {
            Some(or_fallback(v.extract::<u64>())?)
        }
        Some(_) => return Err(fallback("an address that is not an unsigned integer")),
        None => None,
    };
    let ours = match present(row, &names.ours)? {
        Some(o) => o.is_truthy()?,
        None => match &payload {
            Some(p) => p
                .get_item(&names.ours)?
                .is_some_and(|o| o.is_truthy().unwrap_or(false)),
            None => false,
        },
    };
    let key_field = |name: &Bound<'py, PyString>| -> PyResult<Key> {
        match present(row, name)? {
            Some(v) => key_of(&v),
            None => Ok(Key::Null),
        }
    };
    let frame = key_field(&names.frame)?;
    if matches!(frame, Key::Tuple(_)) {
        return Err(fallback("a frame that is a tuple"));
    }
    Ok(Event {
        event_id: match present(row, &names.event_id)? {
            Some(v) => to_value(&v)?,
            None => Value::Null,
        },
        kind: match present(row, &names.kind)? {
            Some(v) => opt_text(&v)?,
            None => None,
        },
        seq,
        frame,
        phase: match present(row, &names.phase)? {
            Some(v) => opt_text(&v)?,
            None => None,
        },
        role,
        thread_gen: key_field(&names.thread_gen)?,
        function,
        stack,
        va,
        ours,
        payload: copied,
    })
}

fn extract_events<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyAny>,
    payload_keys: &[&str],
) -> PyResult<Vec<Event>> {
    let names = Names::new(py, payload_keys);
    let list = events
        .cast::<PyList>()
        .map_err(|_| fallback("events is not a list"))?;
    list.iter().map(|row| extract_event(&row, &names)).collect()
}

fn json_object(obj: Option<&Bound<'_, PyAny>>) -> PyResult<Option<Map<String, Value>>> {
    match obj {
        None => Ok(None),
        Some(o) if o.is_none() => Ok(None),
        Some(o) => match to_value(o)? {
            Value::Object(map) => Ok(Some(map)),
            _ => Err(fallback("a mapping was expected")),
        },
    }
}

fn nonneg(value: i64) -> PyResult<usize> {
    usize::try_from(value).map_err(|_| fallback("a negative count"))
}

/// `write_survival(events, field=, consumer=, phases=, gaps=, representatives=)`.
#[pyfunction]
#[pyo3(signature = (events, field, consumer, phases, gaps, representatives))]
pub fn reports_write_survival<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyAny>,
    field: &str,
    consumer: &str,
    phases: Option<&Bound<'py, PyAny>>,
    gaps: Option<&Bound<'py, PyAny>>,
    representatives: i64,
) -> PyResult<Bound<'py, PyAny>> {
    let phases = match phases {
        Some(p) if !p.is_none() => text_list(p)?,
        _ => Vec::new(),
    };
    let mut parsed = Vec::new();
    if let Some(gaps) = gaps.filter(|g| !g.is_none()) {
        for gap in gaps
            .cast::<PyList>()
            .map_err(|_| fallback("gaps is not a list"))?
            .iter()
        {
            let gap = as_dict(&gap, "a gap")?;
            if let Some(frame) = gap.get_item("frame")? {
                let key = key_of(&frame)?;
                if matches!(key, Key::Tuple(_)) {
                    return Err(fallback("a gap frame that is a tuple"));
                }
                parsed.push(Gap::Frame(key));
            } else if let Some(first) = gap.get_item("first_frame")? {
                let int = |v: &Bound<'_, PyAny>| match key_of(v)? {
                    Key::Int(n) => Ok(n),
                    _ => Err(fallback("a gap range that is not integers")),
                };
                let last = match gap.get_item("last_frame")? {
                    Some(l) => int(&l)?,
                    None => int(&first)?,
                };
                parsed.push(Gap::Range(int(&first)?, last));
            }
        }
    }
    let events = extract_events(py, events, &["state_key", "key", "value"])?;
    let report = reports::write_survival(
        &events,
        field,
        consumer,
        &phases,
        &parsed,
        nonneg(representatives)?,
    )
    .map_err(map_error)?;
    from_value(py, &report)
}

/// `observed_edges(events, static_candidates=, frames_per_edge=)`.
#[pyfunction]
pub fn reports_observed_edges<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyAny>,
    static_candidates: Option<&Bound<'py, PyAny>>,
    frames_per_edge: i64,
) -> PyResult<Bound<'py, PyAny>> {
    let candidates = json_object(static_candidates)?;
    let events = extract_events(py, events, &["site", "target", "receiver_class", "slot"])?;
    let report = reports::observed_edges(&events, candidates.as_ref(), nonneg(frames_per_edge)?)
        .map_err(map_error)?;
    from_value(py, &report)
}

/// `hook_bypass(events, hook=, field=, siblings=, observed=, per_class=)`.
#[pyfunction]
pub fn reports_hook_bypass<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyAny>,
    hook: &str,
    field: &str,
    siblings: Option<&Bound<'py, PyAny>>,
    observed: Option<&Bound<'py, PyAny>>,
    per_class: i64,
) -> PyResult<Bound<'py, PyAny>> {
    let siblings = match siblings {
        Some(s) if !s.is_none() => text_list(s)?,
        _ => Vec::new(),
    };
    let observed = match observed.filter(|o| !o.is_none()) {
        Some(o) => match to_value(o)? {
            Value::Array(items) if items.iter().all(Value::is_object) => items,
            _ => return Err(fallback("observed edges are not a list of mappings")),
        },
        None => Vec::new(),
    };
    let events = extract_events(py, events, &["state_key", "key"])?;
    let report = reports::hook_bypass(
        &events,
        hook,
        field,
        &siblings,
        &observed,
        nonneg(per_class)?,
    )
    .map_err(map_error)?;
    from_value(py, &report)
}

fn value_list(obj: &Bound<'_, PyAny>) -> PyResult<Vec<Value>> {
    match to_value(obj)? {
        Value::Array(items) => Ok(items),
        _ => Err(fallback("a list was expected")),
    }
}

/// `discovery_report(exercised=, candidates=, observation_gaps=)`.
#[pyfunction]
pub fn reports_discovery<'py>(
    py: Python<'py>,
    exercised: &Bound<'py, PyAny>,
    candidates: &Bound<'py, PyAny>,
    observation_gaps: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let report = reports::discovery_report(
        &value_list(exercised)?,
        &value_list(candidates)?,
        &value_list(observation_gaps)?,
    )
    .map_err(map_error)?;
    from_value(py, &report)
}

/// `_entry(value)`: an int is itself, anything else `int(str(value), 16)` or None.
fn entry_of(value: &Bound<'_, PyAny>) -> PyResult<Option<i128>> {
    if value.is_none() || value.is_instance_of::<pyo3::types::PyFloat>() {
        return Ok(None); // int(str(None), 16) and int(str(1.5), 16) raise ValueError
    }
    if value.is_instance_of::<PyBool>() {
        return Err(fallback("a boolean address"));
    }
    if value.is_instance_of::<PyInt>() {
        return or_fallback(value.extract::<i64>()).map(|n| Some(i128::from(n)));
    }
    if let Ok(text) = value.cast::<PyString>() {
        return match parse_int_radix(or_fallback(text.to_str())?, 16) {
            IntParse::Value(v) => Ok(Some(v)),
            IntParse::Invalid => Ok(None),
            IntParse::NotAscii => Err(fallback("non-ASCII digits")),
        };
    }
    Err(fallback("an address that is neither an integer nor text"))
}

/// `field_writers(static_sites, events, object_addr=, offset=, size=, names=, escape_kind=, write_kinds=, per_site=)`.
#[pyfunction]
#[allow(clippy::too_many_arguments)]
pub fn reports_field_writers<'py>(
    py: Python<'py>,
    static_sites: &Bound<'py, PyAny>,
    events: &Bound<'py, PyAny>,
    object_addr: i64,
    offset: i64,
    size: i64,
    names: Option<&Bound<'py, PyAny>>,
    escape_kind: &str,
    write_kinds: &Bound<'py, PyAny>,
    per_site: i64,
) -> PyResult<Bound<'py, PyAny>> {
    let mut sites = Vec::new();
    for row in static_sites
        .cast::<PyList>()
        .map_err(|_| fallback("static sites is not a list"))?
        .iter()
    {
        let row = as_dict(&row, "a static site")?;
        let get = |key: &str| -> PyResult<Value> {
            match row.get_item(key)? {
                Some(v) => to_value(&v),
                None => Ok(Value::Null),
            }
        };
        let function = row.get_item("function")?;
        sites.push(StaticSite {
            function: get("function")?,
            function_name: get("function_name")?,
            site: get("site")?,
            instruction: get("instruction")?,
            entry: match &function {
                Some(f) => entry_of(f)?,
                None => None,
            },
        });
    }
    let mut table: HashMap<Option<i128>, String> = HashMap::new();
    if let Some(names) = names.filter(|n| !n.is_none() && n.is_truthy().unwrap_or(false)) {
        for (address, name) in as_dict(names, "names")?.iter() {
            table.insert(
                entry_of(&address)?,
                opt_text(&name)?.ok_or_else(|| fallback("a name that is None"))?,
            );
        }
    }
    let write_kinds = text_list(write_kinds)?;
    let events = extract_events(py, events, &["object", "offset", "size", "site", "callee"])?;
    let options = WriterOptions {
        escape_kind,
        write_kinds: &write_kinds,
        per_site: nonneg(per_site)?,
    };
    let report = reports::field_writers(
        &sites,
        &events,
        FieldSpan {
            object: object_addr,
            offset,
            size,
        },
        &table,
        &options,
    )
    .map_err(map_error)?;
    from_value(py, &report)
}

/// `edges_from_dispatch(events, dispatch_sites, receiver_class=, ignore=, candidates=)`.
#[pyfunction]
pub fn reports_edges_from_dispatch<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyAny>,
    dispatch_sites: &Bound<'py, PyAny>,
    receiver_class: Option<&Bound<'py, PyAny>>,
    ignore: &Bound<'py, PyAny>,
    candidates: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyAny>> {
    let mut sites = HashMap::new();
    for (site, info) in as_dict(dispatch_sites, "dispatch sites")?.iter() {
        let site = opt_text(&site)?.ok_or_else(|| fallback("a dispatch site that is None"))?;
        let slot = as_dict(&info, "a dispatch site entry")?.get_item("slot")?;
        sites.insert(
            site,
            DispatchSite {
                slot: slot.map_or(Ok(Value::Null), |s| to_value(&s))?,
            },
        );
    }
    let ignore = text_list(ignore)?;
    let candidates = json_object(candidates)?;
    let events = extract_events(py, events, &["receiver"])?;
    let callback = receiver_class.filter(|c| !c.is_none()).cloned();
    let mut class = |receiver: &Value| -> hy_trace::Result<Value> {
        let Some(callback) = &callback else {
            return Ok(Value::Null);
        };
        let answer = from_value(py, receiver)
            .and_then(|arg| callback.call1((arg,)))
            .and_then(|answer| to_value(&answer))
            .map_err(|error| hy_trace::Error::unsupported(format!("receiver_class: {error}")))?;
        Ok(answer)
    };
    let out =
        reports::edges_from_dispatch(&events, &sites, &ignore, candidates.as_ref(), &mut class)
            .map_err(map_error)?;
    let list = PyList::empty(py);
    for event in &out {
        list.append(from_value(py, event)?)?;
    }
    Ok(list.into_any())
}

fn has_float(value: &Value) -> bool {
    match value {
        Value::Number(n) => n.is_f64(),
        Value::Array(items) => items.iter().any(has_float),
        Value::Object(map) => map.values().any(has_float),
        _ => false,
    }
}

fn has_long_digit_run(text: &str) -> bool {
    let mut run = 0;
    for byte in text.bytes() {
        run = if byte.is_ascii_digit() { run + 1 } else { 0 };
        if run >= 19 {
            return true;
        }
    }
    false
}

/// `from_engine_rows(rows, names=, symbols=)`: engine query rows as report events.
#[pyfunction]
pub fn reports_from_engine_rows<'py>(
    py: Python<'py>,
    rows: &Bound<'py, PyAny>,
    names: Option<&Bound<'py, PyAny>>,
    symbols: Option<&Bound<'py, PyAny>>,
) -> PyResult<Bound<'py, PyList>> {
    let mut table: HashMap<i128, Bound<'py, PyAny>> = HashMap::new();
    if let Some(names) = names.filter(|n| !n.is_none()) {
        for (key, value) in as_dict(names, "names")?.iter() {
            let key = if key.is_instance_of::<PyBool>() {
                return Err(fallback("a boolean address"));
            } else if key.is_instance_of::<PyInt>() {
                i128::from(or_fallback(key.extract::<i64>())?)
            } else if let Ok(text) = key.cast::<PyString>() {
                match parse_int_radix(or_fallback(text.to_str())?, 16) {
                    IntParse::Value(v) => v,
                    _ => return Err(fallback("a name address that is not hex")),
                }
            } else {
                return Err(fallback("a name address of an unexpected type"));
            };
            table.insert(key, value);
        }
    }
    let symbols = match symbols.filter(|s| !s.is_none()) {
        Some(s) => Some(as_dict(s, "symbols")?),
        None => None,
    };
    let rename = |name: Bound<'py, PyAny>| -> PyResult<Bound<'py, PyAny>> {
        let Ok(text) = name.cast::<PyString>() else {
            return Ok(name);
        };
        let text = or_fallback(text.to_str().map(str::to_owned))?;
        let Some(tail) = text.strip_prefix("FUN_") else {
            return Ok(name);
        };
        match parse_int_radix(tail, 16) {
            IntParse::Value(v) => Ok(table.get(&v).cloned().unwrap_or(name)),
            IntParse::Invalid => Ok(name),
            IntParse::NotAscii => Err(fallback("non-ASCII digits")),
        }
    };
    let none = py.None().into_bound(py);
    let out = PyList::empty(py);
    for row in rows
        .cast::<PyList>()
        .map_err(|_| fallback("rows is not a list"))?
        .iter()
    {
        let row = as_dict(&row, "an engine row")?;
        let get = |key: &str| -> PyResult<Bound<'py, PyAny>> {
            Ok(row.get_item(key)?.unwrap_or_else(|| none.clone()))
        };
        let payload = match row.get_item("payload")? {
            Some(p) if p.is_instance_of::<PyString>() => {
                let text = or_fallback(
                    p.cast::<PyString>()
                        .map_err(|_| fallback("payload"))?
                        .to_str(),
                )?;
                let parsed: Value = serde_json::from_str(text)
                    .map_err(|e| fallback(format!("payload JSON: {e}")))?;
                if !parsed.is_object() {
                    return Err(fallback("a payload that is not an object"));
                }
                // serde_json reads an integer beyond 64 bits as a float, Python keeps it exact: leave such a payload to Python
                if has_float(&parsed) && has_long_digit_run(text) {
                    return Err(fallback("an integer beyond 64 bits"));
                }
                as_dict(&from_value(py, &parsed)?, "payload")?
            }
            Some(p) if p.is_truthy()? => as_dict(&p, "payload")?.copy()?,
            _ => PyDict::new(py),
        };
        let seq = get("seq")?;
        let known = match &symbols {
            Some(s) => s.get_item(&seq)?.filter(|k| k.is_truthy().unwrap_or(false)),
            None => None,
        };
        let known = match known {
            Some(k) => Some(as_dict(&k, "a symbol entry")?),
            None => None,
        };
        let known_get = |key: &str| -> PyResult<Option<Bound<'py, PyAny>>> {
            match &known {
                Some(k) => k.get_item(key),
                None => Ok(None),
            }
        };
        let function = match known_get("function")? {
            Some(f) => rename(f)?,
            None => none.clone(),
        };
        let function = if function.is_truthy()? {
            function
        } else {
            payload.get_item("site")?.unwrap_or_else(|| none.clone())
        };
        let stack = PyList::empty(py);
        if let Some(entries) = known_get("stack")?.filter(|s| s.is_truthy().unwrap_or(false)) {
            for entry in entries.try_iter()? {
                let entry = entry?;
                if entry.is_truthy()? {
                    stack.append(rename(entry)?)?;
                }
            }
        }
        let thread = get("thread_gen")?;
        let thread_gen: Bound<'py, PyAny> = if thread.is_none() {
            none.clone()
        } else {
            PyTuple::new(py, [get("process_gen")?, thread])?.into_any()
        };
        let rva: Bound<'py, PyAny> = match payload.get_item("rva")?.filter(|r| !r.is_none()) {
            None => none.clone(),
            Some(r) if r.is_instance_of::<PyBool>() => return Err(fallback("a boolean rva")),
            Some(r) if r.is_instance_of::<PyInt>() => r,
            Some(r) => {
                let text = r
                    .cast::<PyString>()
                    .map_err(|_| fallback("an rva of an unexpected type"))?;
                match parse_int_base0(or_fallback(text.to_str())?) {
                    IntParse::Value(v) => i64::try_from(v)
                        .map_err(|_| fallback("an rva beyond i64"))?
                        .into_pyobject(py)?
                        .into_any(),
                    _ => return Err(fallback("an rva that is not an integer literal")),
                }
            }
        };
        let event = PyDict::new(py);
        event.set_item("event_id", get("event_id")?)?;
        event.set_item("kind", get("kind")?)?;
        event.set_item("seq", seq)?;
        event.set_item(
            "frame",
            payload.get_item("frame")?.unwrap_or_else(|| none.clone()),
        )?;
        event.set_item(
            "phase",
            payload.get_item("phase")?.unwrap_or_else(|| none.clone()),
        )?;
        event.set_item(
            "role",
            payload.get_item("role")?.unwrap_or_else(|| none.clone()),
        )?;
        event.set_item("thread_gen", thread_gen)?;
        event.set_item("function", function)?;
        event.set_item("stack", stack)?;
        event.set_item("va", get("va")?)?;
        let ours = payload
            .get_item("ours")?
            .map_or(Ok(false), |o| o.is_truthy())?;
        event.set_item("ours", ours)?;
        event.set_item("payload", &payload)?;
        event.set_item("rva", rva)?;
        out.append(event)?;
    }
    Ok(out)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(reports_write_survival, module)?)?;
    module.add_function(wrap_pyfunction!(reports_observed_edges, module)?)?;
    module.add_function(wrap_pyfunction!(reports_hook_bypass, module)?)?;
    module.add_function(wrap_pyfunction!(reports_discovery, module)?)?;
    module.add_function(wrap_pyfunction!(reports_field_writers, module)?)?;
    module.add_function(wrap_pyfunction!(reports_edges_from_dispatch, module)?)?;
    module.add_function(wrap_pyfunction!(reports_from_engine_rows, module)?)?;
    Ok(())
}
