//! Frame, phase and thread role as first-class keys of an event: the Rust twin of `hydralysis.trace_keys.annotate`.
//!
//! The Python function is the specification (its docstring says what each key means and when it is unresolved). This
//! port works on the same Python objects (event dicts in, event dicts out, equal to what Python builds) and gives the
//! same answers; `tests/test_trace_keys_native.py` feeds both the same events. Anything the port does not understand
//! (a role without a key, a payload that is not a mapping, ids that are not text) is an error, and the Python wrapper
//! then runs the Python implementation, which raises or answers exactly as before.

use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyInt, PyList, PySet, PyString, PyTuple};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

fn shape(message: &str) -> PyErr {
    PyValueError::new_err(message.to_owned())
}

/// Python `a == b`, with plain text compared without the call.
fn same(a: &Bound<'_, PyAny>, b: &Bound<'_, PyAny>) -> PyResult<bool> {
    if let (Ok(x), Ok(y)) = (a.cast::<PyString>(), b.cast::<PyString>()) {
        return Ok(x.to_str()? == y.to_str()?);
    }
    a.eq(b)
}

struct Ev<'py> {
    payload: Option<Bound<'py, PyDict>>, // None for a missing or empty payload
    thread: usize,
    hook: Option<Bound<'py, PyAny>>,
}

type Unresolved = Vec<(&'static str, String)>;

fn set_unresolved(list: &mut Unresolved, key: &'static str, value: String) {
    if let Some(slot) = list.iter_mut().find(|(k, _)| *k == key) {
        slot.1 = value;
    } else {
        list.push((key, value));
    }
}

struct Stamp<'py> {
    frame: Option<Bound<'py, PyAny>>,
    phase: Option<usize>,
    unresolved: Unresolved,
}

struct Stage<'py> {
    id: Bound<'py, PyAny>,
    open: Bound<'py, PyAny>,
}

fn get<'py>(d: &Bound<'py, PyDict>, key: &str) -> PyResult<Bound<'py, PyAny>> {
    d.get_item(key)?.ok_or_else(|| shape("missing key"))
}

fn payload_get<'py>(
    payload: &Option<Bound<'py, PyDict>>,
    key: &str,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    match payload {
        Some(p) => p.get_item(key),
        None => Ok(None),
    }
}

#[allow(clippy::too_many_arguments)]
fn settle<'py>(
    stamp: &mut [Option<Stamp<'py>>],
    stages: &[Stage<'py>],
    frame: &Option<Bound<'py, PyAny>>,
    items: &[usize],
    markers: &[(usize, usize)],
) -> PyResult<()> {
    let positions: HashMap<usize, usize> = markers
        .iter()
        .enumerate()
        .map(|(pos, (_k, event))| (*event, pos))
        .collect();
    let opened: HashSet<usize> = markers.iter().map(|(k, _)| *k).collect();
    for &event_index in items {
        let mut unresolved: Unresolved = Vec::new();
        let mut phase = None;
        if stages.is_empty() {
            set_unresolved(
                &mut unresolved,
                "phase",
                "the profile declares no stage markers".into(),
            );
        } else if markers.is_empty() {
            set_unresolved(
                &mut unresolved,
                "phase",
                "thread-has-no-stage-marker".into(),
            );
        } else {
            let prev_k = markers
                .iter()
                .rfind(|(_k, i)| *i <= event_index)
                .map(|(k, _)| *k);
            let next_k = markers
                .iter()
                .find(|(_k, i)| *i > event_index)
                .map(|(k, _)| *k);
            let lo = prev_k.map_or(0, |k| k + 1);
            let hi = next_k.unwrap_or(stages.len());
            let mut gone: Vec<String> = Vec::new();
            for (j, stage) in stages.iter().enumerate().take(hi).skip(lo) {
                if !opened.contains(&j) {
                    gone.push(stage.id.extract::<String>()?);
                }
            }
            if prev_k.is_none() {
                set_unresolved(
                    &mut unresolved,
                    "phase",
                    if !gone.is_empty() && next_k.is_some() {
                        format!("missing-marker:{}", gone.join(","))
                    } else {
                        "before-first-stage-marker".into()
                    },
                );
            } else if next_k.is_some() && !gone.is_empty() {
                set_unresolved(
                    &mut unresolved,
                    "phase",
                    format!("missing-marker:{}", gone.join(",")),
                );
            } else {
                phase = prev_k;
            }
        }
        if let Some(&pos) = positions.get(&event_index) {
            phase = Some(markers[pos].0);
            unresolved.retain(|(k, _)| *k != "phase");
        }
        stamp[event_index] = Some(Stamp {
            frame: frame.clone(),
            phase,
            unresolved,
        });
    }
    Ok(())
}

/// `(events with frame/phase/role stamped, report)`; the events come back None when STRICT and a resolver is refused
/// (the report then names them). NORM is `trace_keys._norm_rva`.
#[pyfunction]
pub fn annotate_events<'py>(
    py: Python<'py>,
    events: &Bound<'py, PyList>,
    roles: &Bound<'py, PyList>,
    phases: &Bound<'py, PyList>,
    strict: bool,
    norm: &Bound<'py, PyAny>,
) -> PyResult<(Option<Bound<'py, PyList>>, Bound<'py, PyDict>)> {
    // ---- the profile ---------------------------------------------------------------------------------------------
    struct Role<'py> {
        id: Bound<'py, PyAny>,
        id_text: String,
        resolve: String,
        value: Bound<'py, PyAny>,
        norm: Option<String>,
    }
    let mut role_list: Vec<Role<'py>> = Vec::new();
    for item in roles.iter() {
        let d = item.cast::<PyDict>().map_err(|_| shape("role"))?;
        let id = get(d, "id")?;
        let resolve: String = get(d, "resolve")?.extract()?;
        let value = get(d, "value")?;
        let normalised = if resolve == "thread_start_rva" {
            let n = norm.call1((&value,))?;
            if n.is_none() {
                None
            } else {
                Some(n.extract::<String>()?)
            }
        } else {
            None
        };
        role_list.push(Role {
            id_text: id.extract()?,
            id,
            resolve,
            value,
            norm: normalised,
        });
    }
    let mut frame_phases: Vec<(Bound<'py, PyAny>, Bound<'py, PyAny>, bool)> = Vec::new(); // (open, close, close != open)
    let mut stages: Vec<Stage<'py>> = Vec::new();
    for item in phases.iter() {
        let d = item.cast::<PyDict>().map_err(|_| shape("phase"))?;
        let kind: String = get(d, "kind")?.extract()?;
        if kind == "frame" {
            let open = get(d, "open")?;
            let close = get(d, "close")?;
            let distinct = !same(&close, &open)?;
            frame_phases.push((open, close, distinct));
        } else if kind == "stage" {
            stages.push(Stage {
                id: get(d, "id")?,
                open: get(d, "open")?,
            });
        }
    }

    // ---- one pass over the events -------------------------------------------------------------------------------
    let thread_index = PyDict::new(py);
    let mut thread_keys: Vec<Bound<'py, PyTuple>> = Vec::new();
    let mut evs: Vec<Ev<'py>> = Vec::with_capacity(events.len());
    struct Seen {
        rva: BTreeSet<String>,
        name: HashSet<String>,
    }
    let mut starts: Vec<(usize, Seen)> = Vec::new(); // threads with a start/marker event, first seen first
    let mut start_slot: HashMap<usize, usize> = HashMap::new();
    let mut ran: Vec<Option<Bound<'py, PySet>>> = Vec::new();
    let mut hook_threads: Vec<usize> = Vec::new(); // threads with a hook event, first seen first
    let mut by_thread: Vec<Vec<usize>> = Vec::new();
    for event in events.iter() {
        let ev = event.cast::<PyDict>().map_err(|_| shape("event"))?;
        let payload_any = ev.get_item("payload")?;
        let payload = match payload_any {
            Some(p) if p.is_truthy()? => {
                Some(p.cast_into::<PyDict>().map_err(|_| shape("payload"))?)
            }
            _ => None,
        };
        let key = PyTuple::new(py, [ev.get_item("process_id")?, ev.get_item("thread_id")?])?;
        let thread = match thread_index.get_item(&key)? {
            Some(i) => i.extract::<usize>()?,
            None => {
                let i = thread_keys.len();
                thread_index.set_item(&key, i)?;
                thread_keys.push(key);
                ran.push(None);
                by_thread.push(Vec::new());
                i
            }
        };
        let hook = match &payload {
            Some(p) => p.get_item("hook")?.filter(|h| !h.is_none()),
            None => None,
        };
        let kind_text = match ev.get_item("kind")? {
            Some(k) => k.extract::<String>().ok(),
            None => None,
        };
        if matches!(
            kind_text.as_deref(),
            Some("core.thread.start" | "core.marker")
        ) {
            let slot = *start_slot.entry(thread).or_insert_with(|| {
                starts.push((
                    thread,
                    Seen {
                        rva: BTreeSet::new(),
                        name: HashSet::new(),
                    },
                ));
                starts.len() - 1
            });
            if let Some(p) = &payload {
                if let Some(rva) = p.get_item("start_rva")?.filter(|v| !v.is_none()) {
                    let n = norm.call1((&rva,))?;
                    if !n.is_none() {
                        starts[slot].1.rva.insert(n.extract::<String>()?);
                    }
                }
                if let Some(name) = p.get_item("name")? {
                    if let Ok(text) = name.cast::<PyString>() {
                        let thread_name = match p.get_item("thread_name")? {
                            Some(t) => t.is_truthy()?,
                            None => false,
                        };
                        if kind_text.as_deref() == Some("core.thread.start") || thread_name {
                            starts[slot].1.name.insert(text.to_str()?.to_owned());
                        }
                    }
                }
            }
        }
        if let Some(h) = &hook {
            if ran[thread].is_none() {
                ran[thread] = Some(PySet::empty(py)?);
                hook_threads.push(thread);
            }
            if let Some(set) = &ran[thread] {
                set.add(h)?;
            }
            by_thread[thread].push(evs.len());
        }
        evs.push(Ev {
            payload,
            thread,
            hook,
        });
    }

    // ---- refused resolvers ------------------------------------------------------------------------------------------
    let refused = PyDict::new(py);
    let any_rva = starts.iter().any(|(_, s)| !s.rva.is_empty());
    let any_name = starts.iter().any(|(_, s)| !s.name.is_empty());
    for r in &role_list {
        if r.resolve == "pool" {
            refused.set_item(&r.id, "the pool resolver is not evaluated by any producer")?;
        } else if r.resolve == "thread_start_rva" && !any_rva {
            refused.set_item(
                &r.id,
                "no core.thread.start event carries payload.start_rva",
            )?;
        } else if r.resolve == "thread_name" && !any_name {
            refused.set_item(&r.id, "no core.thread.start event carries payload.name")?;
        }
    }
    let mut unsupported_set: BTreeSet<String> = BTreeSet::new();
    for r in &role_list {
        if refused.contains(&r.id)? {
            unsupported_set.insert(r.resolve.clone());
        }
    }
    let unsupported: Vec<String> = unsupported_set.into_iter().collect();
    let report = PyDict::new(py);
    if strict && !refused.is_empty() {
        report.set_item("refused_resolvers", &refused)?;
        return Ok((None, report));
    }

    // ---- roles ----------------------------------------------------------------------------------------------------
    let mut thread_role: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for &thread in &hook_threads {
        let hooks = ran[thread].as_ref().ok_or_else(|| shape("hooks"))?;
        let mut found: Vec<String> = Vec::new();
        for r in &role_list {
            if r.resolve == "function" && hooks.contains(&r.value)? {
                found.push(r.id_text.clone());
            }
        }
        found.sort();
        thread_role.insert(thread, found);
    }
    for (thread, seen) in &starts {
        let mut extra: Vec<String> = Vec::new();
        for r in &role_list {
            let hit = (r.resolve == "thread_start_rva"
                && r.norm.as_ref().is_some_and(|n| seen.rva.contains(n)))
                || (r.resolve == "thread_name"
                    && r.value
                        .extract::<String>()
                        .is_ok_and(|v| seen.name.contains(&v)));
            if hit {
                extra.push(r.id_text.clone());
            }
        }
        let mut merged: BTreeSet<String> = thread_role
            .get(thread)
            .map(|v| v.iter().cloned().collect())
            .unwrap_or_default();
        merged.extend(extra);
        thread_role.insert(*thread, merged.into_iter().collect());
    }

    // ---- frames and stages, per thread, in the thread's own order ---------------------------------------------------
    let mut stamp: Vec<Option<Stamp<'py>>> = (0..evs.len()).map(|_| None).collect();
    for &thread in &hook_threads {
        let mut frame: Option<Bound<'py, PyAny>> = None;
        let mut seen: Vec<(usize, usize)> = Vec::new();
        let mut run: Vec<usize> = Vec::new();
        let mut frame_closed = true;
        for &index in &by_thread[thread] {
            let ev = &evs[index];
            let hook = ev.hook.as_ref().ok_or_else(|| shape("hook"))?;
            let mut opener = false;
            for (open, _close, _distinct) in &frame_phases {
                if same(hook, open)? {
                    opener = true;
                    break;
                }
            }
            let mut closer = false;
            for (_open, close, distinct) in &frame_phases {
                if *distinct && same(hook, close)? {
                    closer = true;
                    break;
                }
            }
            let mut stage_hit = None;
            for (j, stage) in stages.iter().enumerate() {
                if same(hook, &stage.open)? {
                    let number = payload_get(&ev.payload, "stage")?.filter(|n| !n.is_none());
                    let matches = match number {
                        None => true,
                        Some(n) => n.eq(j + 1)?,
                    };
                    if matches {
                        stage_hit = Some(j);
                        break;
                    }
                }
            }
            if opener {
                if !run.is_empty() {
                    settle(&mut stamp, &stages, &frame, &run, &seen)?;
                }
                frame = payload_get(&ev.payload, "frame")?.filter(|f| !f.is_none());
                frame_closed = false;
                seen.clear();
                run.clear();
            }
            if let Some(j) = stage_hit {
                seen.push((j, index));
            }
            if frame.is_some() && !frame_closed {
                run.push(index);
            } else {
                let mut unresolved: Unresolved = Vec::new();
                set_unresolved(
                    &mut unresolved,
                    "frame",
                    if frame_closed && !frame_phases.is_empty() {
                        "outside-frame".into()
                    } else {
                        "thread-has-no-frame-marker".into()
                    },
                );
                set_unresolved(&mut unresolved, "phase", "outside-frame".into());
                stamp[index] = Some(Stamp {
                    frame: payload_get(&ev.payload, "frame")?.filter(|f| !f.is_none()),
                    phase: None,
                    unresolved,
                });
            }
            if closer {
                settle(&mut stamp, &stages, &frame, &run, &seen)?;
                run.clear();
                seen.clear();
                frame_closed = true;
            }
        }
        if !run.is_empty() {
            settle(&mut stamp, &stages, &frame, &run, &seen)?;
        }
    }

    // ---- the stamped events ------------------------------------------------------------------------------------------
    let (mut c_events, mut c_frame, mut c_phase, mut c_role) = (0u64, 0u64, 0u64, 0u64);
    let out = PyList::empty(py);
    for (index, event) in events.iter().enumerate() {
        let ev = &evs[index];
        if ev.hook.is_none() {
            out.append(event)?;
            continue;
        }
        let source = event.cast::<PyDict>().map_err(|_| shape("event"))?;
        let payload = match &ev.payload {
            Some(p) => p.copy()?,
            None => PyDict::new(py),
        };
        let (mut frame, phase, mut unresolved) = match stamp[index].take() {
            Some(s) => (s.frame, s.phase, s.unresolved),
            None => (None, None, Vec::new()),
        };
        c_events += 1;
        if let Some(own) = payload.get_item("frame")? {
            if own.is_instance_of::<PyInt>() {
                frame = Some(own);
                unresolved.retain(|(k, _)| *k != "frame");
            }
        }
        if let Some(f) = frame {
            payload.set_item("frame", f)?;
            c_frame += 1;
        } else if !unresolved.iter().any(|(k, _)| *k == "frame") {
            set_unresolved(
                &mut unresolved,
                "frame",
                "no frame marker on this thread".into(),
            );
        }
        if let Some(k) = phase {
            payload.set_item("phase", &stages[k].id)?;
            c_phase += 1;
        } else if !unresolved.iter().any(|(k, _)| *k == "phase") {
            set_unresolved(
                &mut unresolved,
                "phase",
                "thread-has-no-stage-marker".into(),
            );
        }
        let found: &[String] = thread_role.get(&ev.thread).map_or(&[], Vec::as_slice);
        if found.len() == 1 {
            payload.set_item("role", &found[0])?;
            c_role += 1;
        } else if found.len() > 1 {
            set_unresolved(
                &mut unresolved,
                "role",
                format!("ambiguous: {}", found.join(",")),
            );
        } else {
            set_unresolved(
                &mut unresolved,
                "role",
                if unsupported.is_empty() {
                    "no role resolver matched this thread".into()
                } else {
                    format!(
                        "no role resolver matched this thread (unsupported resolvers: {})",
                        unsupported.join(", ")
                    )
                },
            );
        }
        if !unresolved.is_empty() {
            let d = PyDict::new(py);
            for (k, v) in &unresolved {
                d.set_item(k, v)?;
            }
            payload.set_item("unresolved", d)?;
        }
        let copy = source.copy()?;
        copy.set_item("payload", payload)?;
        out.append(copy)?;
    }

    // ---- the report -------------------------------------------------------------------------------------------------
    let counts = PyDict::new(py);
    counts.set_item("events", c_events)?;
    counts.set_item("frame", c_frame)?;
    counts.set_item("phase", c_phase)?;
    counts.set_item("role", c_role)?;
    report.set_item("counts", counts)?;
    report.set_item("unsupported_role_resolvers", &unsupported)?;
    report.set_item("refused_resolvers", &refused)?;
    let mut named: Vec<(String, String, &Vec<String>)> = Vec::new();
    for (thread, found) in &thread_role {
        let key = &thread_keys[*thread];
        let ordering = key.str()?.to_string();
        let name = format!(
            "{}/{}",
            key.get_item(0)?.str()?.to_str()?,
            key.get_item(1)?.str()?.to_str()?
        );
        named.push((ordering, name, found));
    }
    named.sort_by(|a, b| a.0.cmp(&b.0));
    let roles_out = PyDict::new(py);
    for (_ordering, name, found) in named {
        roles_out.set_item(name, found)?;
    }
    report.set_item("roles", roles_out)?;
    Ok((Some(out), report))
}
