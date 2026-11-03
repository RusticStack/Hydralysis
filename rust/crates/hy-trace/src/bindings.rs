//! Linking script-VM events to the native function events they invoked, ported from
//! `hydralysis.trace_bindings.link_events` (spec 15.8).
//!
//! A VM event carries the name of the script function it called. The invoked native is the first `core.function.enter` on
//! the same thread generation, after it in the thread's own order and within a window of events, whose `rva` is the bound
//! thunk or implementation. A call whose native was not seen is listed as unlinked, never dropped.
//!
//! The events are read by the binding into [`LinkEvent`]s (only the fields the link needs); a field of a shape this port
//! does not model never reaches here, it is [`crate::Error::Unsupported`] there and the Python answers.

use crate::reports::Key;
use serde_json::{Map, Value};
use std::collections::{BTreeMap, HashMap, HashSet};

/// The fields of one trace event that `link_events` reads.
#[derive(Debug, Clone)]
pub struct LinkEvent {
    /// `event["seq"]`; an event without one is not part of any thread order.
    pub seq: Option<i64>,
    pub thread_gen: Key,
    /// `payload.script_function` when it is set (a non-empty text); `None` for an event that calls no script function.
    pub script_function: Option<String>,
    pub event_id: Value,
    pub rva: Key,
    /// `kind == "core.function.enter"`.
    pub is_function_enter: bool,
}

/// A resolved row of the binding table: the script name and the two RVAs a native entry may carry.
#[derive(Debug, Clone)]
pub struct BindingRow {
    pub script_name: String,
    pub native_rva: i64,
    pub implementation_rva: i64,
}

fn object(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect::<Map<_, _>>())
}

/// `link_events(events, table, window=window)`.
///
/// Events are ordered by `(str(thread_gen), seq)` (stable, as Python's sort is) and each script call looks at the next
/// `window` events of that order for its native entry.
#[must_use]
pub fn link_events(events: &[LinkEvent], rows: &[BindingRow], window: usize) -> Value {
    let mut by_name: HashMap<&str, HashSet<i64>> = HashMap::new();
    for row in rows {
        by_name.entry(&row.script_name).or_default().extend([row.native_rva, row.implementation_rva]);
    }
    // `sorted(key=(str(thread_gen), seq))`: threads are ranked once by their text, so no event carries a string of its own.
    let threads: BTreeMap<String, ()> = events.iter().filter_map(|e| Some((e.thread_gen.py_str()?, ()))).collect();
    let rank: HashMap<&str, usize> = threads.keys().enumerate().map(|(i, k)| (k.as_str(), i)).collect();
    let mut ordered: Vec<(usize, i64, &LinkEvent)> =
        events.iter().filter_map(|e| Some((*rank.get(e.thread_gen.py_str()?.as_str())?, e.seq?, e))).collect();
    ordered.sort_by_key(|entry| (entry.0, entry.1));

    let mut links = Vec::new();
    let mut unlinked = Vec::new();
    for (position, (_, _, event)) in ordered.iter().enumerate() {
        let Some(name) = event.script_function.as_deref() else { continue };
        let Some(wanted) = by_name.get(name) else {
            unlinked.push(object(vec![
                ("event_id", event.event_id.clone()),
                ("script_function", name.into()),
                ("reason", "not in the binding table".into()),
            ]));
            continue;
        };
        let end = position.saturating_add(1).saturating_add(window).min(ordered.len());
        let found = ordered[position + 1..end].iter().map(|(_, _, follower)| *follower).find(|follower| {
            follower.thread_gen == event.thread_gen
                && follower.is_function_enter
                && matches!(follower.rva, Key::Int(rva) if wanted.contains(&rva))
        });
        match found {
            None => unlinked.push(object(vec![
                ("event_id", event.event_id.clone()),
                ("script_function", name.into()),
                (
                    "reason",
                    format!("no matching native entry within {window} events on the same thread (not observed, or not instrumented)")
                        .into(),
                ),
            ])),
            Some(found) => links.push(object(vec![
                ("relation", "observed-call".into()),
                ("status", "supported".into()),
                ("from", event.event_id.clone()),
                ("to", found.event_id.clone()),
                ("script_function", name.into()),
                ("basis", Value::Array(vec!["binding-table".into(), "same thread order".into()])),
            ])),
        }
    }
    object(vec![("links", Value::Array(links)), ("unlinked", Value::Array(unlinked))])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(id: &str, seq: i64, thread: i64, function: Option<&str>, rva: Key, enter: bool) -> LinkEvent {
        LinkEvent {
            seq: Some(seq),
            thread_gen: Key::Int(thread),
            script_function: function.map(str::to_owned),
            event_id: id.into(),
            rva,
            is_function_enter: enter,
        }
    }

    #[test]
    fn a_traced_script_call_links_to_its_native_event() {
        let rows = [BindingRow { script_name: "get_health".into(), native_rva: 0x1300, implementation_rva: 0x1400 }];
        let events = [
            event("ev_1", 1, 1, Some("get_health"), Key::Null, false),
            event("ev_2", 2, 2, None, Key::Int(0x1300), true),
            event("ev_3", 3, 1, None, Key::Int(0x1400), true),
            event("ev_5", 5, 1, Some("mystery"), Key::Null, false),
        ];
        let linked = link_events(&events, &rows, 8);
        assert_eq!(linked["links"][0]["from"], "ev_1");
        assert_eq!(linked["links"][0]["to"], "ev_3");
        assert_eq!(linked["unlinked"][0]["reason"], "not in the binding table");
    }

    #[test]
    fn the_window_bounds_the_search() {
        let rows = [BindingRow { script_name: "f".into(), native_rva: 1, implementation_rva: 1 }];
        let events = [
            event("a", 1, 1, Some("f"), Key::Null, false),
            event("b", 2, 1, None, Key::Int(9), true),
            event("c", 3, 1, None, Key::Int(1), true),
        ];
        assert_eq!(link_events(&events, &rows, 1)["links"].as_array().map(Vec::len), Some(0));
        assert_eq!(link_events(&events, &rows, 2)["links"].as_array().map(Vec::len), Some(1));
    }
}
