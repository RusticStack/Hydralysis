//! Binding of `hy_trace::pairing`: `hydralysis.trace_pairing.pair_report` when `HYDRALYSIS_IMPL=rust`.
//!
//! Only the fields the report reads are copied out of each event (`kind`, `event_id`, `t_mono_ns` and the four payload keys
//! the spec names), read as plain values: a tuple, a non-text key, an integer beyond 64 bits or a payload that is not a dict
//! is a `TraceFallback`, and so is any shape `hy-trace` does not model. The report is handed back as Python objects.

use super::port::{fallback, from_value, map_error, to_value_exact};
use hy_trace::pairing::{Key, PairEvent, Reading, Time};
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyFloat, PyInt, PyList, PyString};

/// Integers beyond this are not exactly representable as `f64`.
const EXACT: i64 = 1 << 53;

/// The payload keys `pair_report` reads, from the (merged) spec.
fn payload_keys(spec: &Bound<'_, PyAny>) -> PyResult<Vec<String>> {
    let spec = spec
        .cast::<PyDict>()
        .map_err(|_| fallback("a spec that is not a dict"))?;
    ["sync_key", "key", "seq", "value"]
        .iter()
        .map(|name| {
            let item = spec
                .get_item(name)?
                .ok_or_else(|| fallback("a spec without its keys"))?;
            item.extract::<String>()
                .map_err(|_| fallback("a spec key that is not text"))
        })
        .collect()
}

/// The key (`None`, an integer or text) at `name` of the payload.
fn key_at(payload: Option<&Bound<'_, PyDict>>, name: &str) -> PyResult<Key> {
    let Some(item) = payload.map(|p| p.get_item(name)).transpose()?.flatten() else {
        return Ok(Key::Null);
    };
    Key::from_value(&to_value_exact(&item)?).map_err(map_error)
}

/// The event with only the fields the report reads, as `PairEvent::from_value` reads them.
fn read_event(event: &Bound<'_, PyAny>, keys: &[String]) -> PyResult<PairEvent> {
    let event = event
        .cast::<PyDict>()
        .map_err(|_| fallback("an event that is not a dict"))?;
    let payload = match event.get_item("payload")? {
        Some(payload) if payload.is_truthy()? => Some(
            payload
                .cast_into::<PyDict>()
                .map_err(|_| fallback("a payload that is not a dict"))?,
        ),
        _ => None,
    };
    let value = match payload
        .as_ref()
        .map(|p| p.get_item(&keys[3]))
        .transpose()?
        .flatten()
    {
        None => Reading::Skipped,
        Some(item) if item.is_none() => Reading::Skipped,
        Some(item) if item.is_instance_of::<PyBool>() => Reading::Unmodelled,
        Some(item) if item.is_instance_of::<PyInt>() => match item.extract::<i64>() {
            Ok(v) if v.abs() <= EXACT => Reading::Number(v as f64, true),
            _ => Reading::Unmodelled,
        },
        Some(item) if item.is_instance_of::<PyFloat>() => {
            item.extract::<f64>().map_or(Reading::Unmodelled, |v| {
                if v.is_finite() {
                    Reading::Number(v, false)
                } else {
                    Reading::Unmodelled
                }
            })
        }
        Some(_) => Reading::Skipped,
    };
    let t_mono_ns = match event.get_item("t_mono_ns")? {
        None => Time::Missing,
        Some(t) if t.is_instance_of::<PyBool>() => Time::Unmodelled,
        Some(t) if t.is_instance_of::<PyInt>() => match t.extract::<i64>() {
            Ok(v) if v.abs() <= EXACT => Time::At(v as f64),
            _ => Time::Unmodelled,
        },
        Some(t) if t.is_instance_of::<PyFloat>() => {
            t.extract::<f64>().map_or(Time::Unmodelled, |v| {
                if v.is_finite() {
                    Time::At(v)
                } else {
                    Time::Unmodelled
                }
            })
        }
        Some(_) => Time::Unmodelled,
    };
    let kind = match event.get_item("kind")? {
        Some(kind) => kind
            .cast::<PyString>()
            .ok()
            .and_then(|s| s.to_str().ok().map(str::to_owned)),
        None => None,
    };
    let event_id = event
        .get_item("event_id")?
        .map(|id| to_value_exact(&id))
        .transpose()?;
    Ok(PairEvent {
        kind,
        event_id,
        t_mono_ns,
        sync_key: key_at(payload.as_ref(), &keys[0])?,
        object: key_at(payload.as_ref(), &keys[1])?,
        seq: key_at(payload.as_ref(), &keys[2])?,
        value,
    })
}

fn events(list: &Bound<'_, PyList>, keys: &[String]) -> PyResult<Vec<PairEvent>> {
    list.iter().map(|event| read_event(&event, keys)).collect()
}

/// `pair_report(owner_events, replica_events, spec)`; `spec` is already merged over the Python `DEFAULT_SPEC`.
#[pyfunction]
fn pairing_pair_report<'py>(
    py: Python<'py>,
    owner_events: &Bound<'py, PyList>,
    replica_events: &Bound<'py, PyList>,
    spec: &Bound<'py, PyAny>,
) -> PyResult<Bound<'py, PyAny>> {
    let keys = payload_keys(spec)?;
    let owner = events(owner_events, &keys)?;
    let replica = events(replica_events, &keys)?;
    let spec = to_value_exact(spec)?;
    let report = py
        .detach(|| hy_trace::pairing::pair_report(&owner, &replica, &spec))
        .map_err(map_error)?;
    from_value(py, &report)
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(pairing_pair_report, module)?)
}
