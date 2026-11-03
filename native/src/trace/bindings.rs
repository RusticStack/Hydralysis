//! Binding of `hy_trace::bindings`: `hydralysis.trace_bindings.link_events` when `HYDRALYSIS_IMPL=rust`.
//!
//! The events are read in place: per event a handful of dictionary lookups into a compact record, no copy of any text and
//! no copy of the event. The answer is built straight as Python lists and dicts, taking `event_id` and the script function
//! name from the original events by index. An event or table row of a shape the port does not model (a thread generation
//! that is a pair, an rva that is a float, a row without its status, a malformed RVA text) is a `TraceFallback`: the
//! Python then answers, or raises, as it always did.

use super::port::{fallback, or_fallback};
use hy_trace::bindings::{link_events, BindingTable, Link, LinkEvent, NO_SCRIPT, UNBOUND};
use hy_trace::pyfmt::{parse_int_radix, IntParse};
use pyo3::intern;
use pyo3::prelude::*;
use pyo3::types::{PyBool, PyDict, PyInt, PyList, PyString};
use std::collections::HashMap;

/// `kind` of the events whose `rva` can answer a script call.
const FUNCTION_ENTER: &str = "core.function.enter";

/// The thread generations seen so far, by identity of the generation (not by its text).
#[derive(Default)]
struct Threads {
    none: Option<u32>,
    ints: HashMap<i64, u32>,
    texts: HashMap<Box<str>, u32>,
    /// `str(thread_gen)` of every id, in id order.
    spelled: Vec<String>,
}

impl Threads {
    fn id_of(&mut self, thread_gen: Option<&Bound<'_, PyAny>>) -> PyResult<u32> {
        let next = u32::try_from(self.spelled.len())
            .map_err(|_| fallback("more than 2^32 thread generations"))?;
        let existing = match thread_gen {
            None => self.none,
            Some(value) if value.is_none() => self.none,
            Some(value) if value.is_instance_of::<PyBool>() => {
                return Err(fallback("a boolean where an id was expected"))
            }
            Some(value) if value.is_instance_of::<PyInt>() => {
                let n = or_fallback(value.extract::<i64>())?;
                match self.ints.get(&n) {
                    Some(id) => Some(*id),
                    None => {
                        self.ints.insert(n, next);
                        self.spelled.push(n.to_string());
                        return Ok(next);
                    }
                }
            }
            Some(value) => {
                let text = value
                    .cast::<PyString>()
                    .map_err(|_| fallback("a key that is not None, an integer or text"))?;
                let text = or_fallback(text.to_str())?;
                match self.texts.get(text) {
                    Some(id) => Some(*id),
                    None => {
                        self.texts.insert(text.into(), next);
                        self.spelled.push(text.to_owned());
                        return Ok(next);
                    }
                }
            }
        };
        Ok(existing.unwrap_or_else(|| {
            self.none = Some(next);
            self.spelled.push("None".to_owned());
            next
        }))
    }

    /// Rank of each id's text among all of them: equal text, equal rank.
    fn ranks(&self) -> Vec<u32> {
        let mut order: Vec<usize> = (0..self.spelled.len()).collect();
        order.sort_by(|a, b| self.spelled[*a].cmp(&self.spelled[*b]));
        let mut ranks = vec![0u32; order.len()];
        let mut rank = 0u32;
        for (place, id) in order.iter().enumerate() {
            if place > 0 && self.spelled[*id] != self.spelled[order[place - 1]] {
                rank += 1;
            }
            ranks[*id] = rank;
        }
        ranks
    }
}

/// `int(rva_text[4:], 16)`.
fn rva_of(obj: &Bound<'_, PyAny>) -> PyResult<i64> {
    let text = obj
        .cast::<PyString>()
        .map_err(|_| fallback("text expected"))?;
    let text = or_fallback(text.to_str())?;
    let digits: String = text.chars().skip(4).collect();
    match parse_int_radix(&digits, 16) {
        IntParse::Value(v) => i64::try_from(v).map_err(|_| fallback("an RVA beyond 64 bits")),
        IntParse::Invalid | IntParse::NotAscii => {
            Err(fallback("an RVA that is not hexadecimal text"))
        }
    }
}

fn read_table(table: &Bound<'_, PyAny>) -> PyResult<BindingTable> {
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
    let mut out = BindingTable::default();
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
        let script_name = script_name
            .cast::<PyString>()
            .map_err(|_| fallback("text expected"))?;
        let native = row
            .get_item(intern!(py, "native_rva"))?
            .ok_or_else(|| fallback("a row without a native_rva"))?;
        let implementation = match row.get_item(intern!(py, "implementation_rva"))? {
            Some(value) if value.is_truthy()? => value,
            _ => native.clone(),
        };
        out.insert(
            or_fallback(script_name.to_str())?,
            rva_of(&native)?,
            rva_of(&implementation)?,
        );
    }
    Ok(out)
}

/// The linkable events of the list, in input order: those with a `seq`.
fn read_events(events: &Bound<'_, PyList>, table: &BindingTable) -> PyResult<Vec<LinkEvent>> {
    let py = events.py();
    let mut threads = Threads::default();
    let mut out = Vec::with_capacity(events.len());
    for (index, event) in events.iter().enumerate() {
        let event = event
            .cast_exact::<PyDict>()
            .map_err(|_| fallback("an event that is not a dict"))?;
        let seq = match event.get_item(intern!(py, "seq"))? {
            None => continue,
            Some(seq) if seq.is_none() => continue,
            Some(seq) if seq.is_instance_of::<PyInt>() && !seq.is_instance_of::<PyBool>() => {
                or_fallback(seq.extract::<i64>())?
            }
            Some(_) => return Err(fallback("a seq that is not an integer")),
        };
        let thread = threads.id_of(event.get_item(intern!(py, "thread_gen"))?.as_ref())?;
        let entry_rva = match event.get_item(intern!(py, "kind"))? {
            Some(kind)
                if kind
                    .cast::<PyString>()
                    .is_ok_and(|s| s.to_str().is_ok_and(|s| s == FUNCTION_ENTER)) =>
            {
                match event.get_item(intern!(py, "rva"))? {
                    None => None,
                    Some(rva) if rva.is_none() || rva.is_exact_instance_of::<PyString>() => None,
                    Some(rva) if rva.is_exact_instance_of::<PyInt>() => {
                        Some(or_fallback(rva.extract::<i64>())?)
                    }
                    Some(_) => return Err(fallback("an rva that is not None, an integer or text")),
                }
            }
            _ => None,
        };
        let script = match event.get_item(intern!(py, "payload"))? {
            Some(payload) if payload.is_truthy()? => {
                let payload = payload
                    .cast::<PyDict>()
                    .map_err(|_| fallback("a payload that is not a dict"))?;
                match payload.get_item(intern!(py, "script_function"))? {
                    Some(name) if name.is_truthy()? => {
                        let name = name
                            .cast::<PyString>()
                            .map_err(|_| fallback("text expected"))?;
                        table.slot(or_fallback(name.to_str())?).unwrap_or(UNBOUND)
                    }
                    _ => NO_SCRIPT,
                }
            }
            _ => NO_SCRIPT,
        };
        let index = u32::try_from(index).map_err(|_| fallback("more than 2^32 events"))?;
        out.push(LinkEvent {
            seq,
            entry_rva,
            index,
            thread,
            rank: 0,
            script,
        });
    }
    let ranks = threads.ranks();
    for event in &mut out {
        event.rank = ranks[event.thread as usize];
    }
    Ok(out)
}

/// `events[index].get("event_id")`.
fn event_id<'py>(events: &Bound<'py, PyList>, index: u32) -> PyResult<Bound<'py, PyAny>> {
    let py = events.py();
    let event = events.get_item(index as usize)?;
    let event = event
        .cast_exact::<PyDict>()
        .map_err(|_| fallback("an event that is not a dict"))?;
    Ok(event
        .get_item(intern!(py, "event_id"))?
        .unwrap_or_else(|| py.None().into_bound(py)))
}

/// `events[index]["payload"]["script_function"]`.
fn script_function<'py>(events: &Bound<'py, PyList>, index: u32) -> PyResult<Bound<'py, PyAny>> {
    let py = events.py();
    let event = events.get_item(index as usize)?;
    let event = event
        .cast_exact::<PyDict>()
        .map_err(|_| fallback("an event that is not a dict"))?;
    let payload = event
        .get_item(intern!(py, "payload"))?
        .ok_or_else(|| fallback("a script call without a payload"))?;
    let payload = payload
        .cast::<PyDict>()
        .map_err(|_| fallback("a payload that is not a dict"))?;
    payload
        .get_item(intern!(py, "script_function"))?
        .ok_or_else(|| fallback("a script call without a name"))
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
    let table = read_table(table)?;
    let linkable = read_events(events, &table)?;
    let outcome = link_events(linkable, &table, window);

    let links = PyList::empty(py);
    let unlinked = PyList::empty(py);
    let not_bound = PyString::intern(py, "not in the binding table");
    let not_seen = PyString::new(
        py,
        &format!("no matching native entry within {window} events on the same thread (not observed, or not instrumented)"),
    );
    let unlinked_row = |from: u32, reason: &Bound<'py, PyString>| -> PyResult<()> {
        let row = PyDict::new(py);
        row.set_item(intern!(py, "event_id"), event_id(events, from)?)?;
        row.set_item(
            intern!(py, "script_function"),
            script_function(events, from)?,
        )?;
        row.set_item(intern!(py, "reason"), reason)?;
        unlinked.append(row)
    };
    for link in outcome {
        match link {
            Link::Linked { from, to } => {
                let row = PyDict::new(py);
                row.set_item(intern!(py, "relation"), intern!(py, "observed-call"))?;
                row.set_item(intern!(py, "status"), intern!(py, "supported"))?;
                row.set_item(intern!(py, "from"), event_id(events, from)?)?;
                row.set_item(intern!(py, "to"), event_id(events, to)?)?;
                row.set_item(
                    intern!(py, "script_function"),
                    script_function(events, from)?,
                )?;
                row.set_item(
                    intern!(py, "basis"),
                    PyList::new(
                        py,
                        [
                            intern!(py, "binding-table"),
                            intern!(py, "same thread order"),
                        ],
                    )?,
                )?;
                links.append(row)?;
            }
            Link::NotBound { from } => unlinked_row(from, &not_bound)?,
            Link::NotSeen { from } => unlinked_row(from, &not_seen)?,
        }
    }
    let answer = PyDict::new(py);
    answer.set_item(intern!(py, "links"), links)?;
    answer.set_item(intern!(py, "unlinked"), unlinked)?;
    Ok(answer.into_any())
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(bindings_link_events, module)?)
}
