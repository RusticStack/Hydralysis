//! Report builders over trace data (spec 15.3 and 15.4), ported from `hydralysis.trace_reports`: did my write survive, and
//! was my hook bypassed.
//!
//! Both work on a page of event rows and hold no store. An [`Event`] is the row as `normalize_event` reads it. Ordering is
//! the hard part: `seq` is the collector's ingestion ordinal, not execution order, so two events are only ordered when they
//! share a thread generation or when the profile's phases order them; anything else is *not established* and the verdict
//! says `unknown` with that reason. Ratios are parts per million, so a reply is byte-identical across runs.
//!
//! The Python is loose about the types of an event's fields. These functions model the shapes the producers emit (frames
//! and thread keys that are integers or text, sequence numbers that are integers) and the binding answers
//! [`crate::Error::Unsupported`] for anything else, so the Python implementation answers it.

use crate::{Error, Result};
use serde_json::{Map, Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};

pub const SURVIVED: &str = "survived";
pub const OVERWRITTEN: &str = "overwritten";
pub const READ_BEFORE_WRITE: &str = "consumer read before write";
pub const UNKNOWN: &str = "unknown";
const NO_PHASE: i64 = 1_000_000;

/// A hashable scalar of an event: a frame, a thread generation (possibly a pair), a site. Integers sort before text, as
/// `(str(type(x)), x)` sorts them in Python.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Key {
    Null,
    Int(i64),
    Str(String),
    Tuple(Vec<Key>),
}

impl Key {
    /// Python's `str(x)` for the scalars; `None` for a pair.
    pub fn py_str(&self) -> Option<String> {
        match self {
            Key::Null => Some("None".into()),
            Key::Int(n) => Some(n.to_string()),
            Key::Str(s) => Some(s.clone()),
            Key::Tuple(_) => None,
        }
    }

    pub fn to_value(&self) -> Value {
        match self {
            Key::Null => Value::Null,
            Key::Int(n) => json!(n),
            Key::Str(s) => json!(s),
            Key::Tuple(items) => Value::Array(items.iter().map(Key::to_value).collect()),
        }
    }

    /// The key of a JSON scalar (`null`, an integer or text).
    pub fn of(value: &Value) -> Result<Key> {
        match value {
            Value::Null => Ok(Key::Null),
            Value::String(s) => Ok(Key::Str(s.clone())),
            Value::Number(n) => n.as_i64().map(Key::Int).ok_or_else(|| Error::unsupported("a number that is not an i64")),
            _ => Err(Error::unsupported("a key that is not null, an integer or text")),
        }
    }
}

/// An event row as the reports read it (`normalize_event`).
#[derive(Debug, Clone)]
pub struct Event {
    pub event_id: Value,
    pub kind: Option<String>,
    pub seq: Option<i64>,
    pub frame: Key,
    pub phase: Option<String>,
    pub role: Value,
    pub thread_gen: Key,
    pub function: Option<String>,
    pub stack: Vec<String>,
    pub va: Option<u64>,
    pub ours: bool,
    /// The payload keys the report reads (the binding copies only those).
    pub payload: Map<String, Value>,
}

/// Python truthiness of a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn ppm(part: usize, whole: usize) -> Value {
    if whole == 0 { Value::Null } else { json!(part as u64 * 1_000_000 / whole as u64) }
}

fn py_hex(value: i128) -> String {
    if value < 0 { format!("-{:#x}", -value) } else { format!("{value:#x}") }
}

impl Event {
    /// `_site`: the symbolized function, else `va:0x...`, else `unresolved`.
    fn site(&self) -> String {
        match &self.function {
            Some(f) if !f.is_empty() => f.clone(),
            _ => self.va.map_or_else(|| "unresolved".to_owned(), |va| format!("va:{va:#x}")),
        }
    }

    fn state_key(&self) -> Option<&Value> {
        self.payload.get("state_key").or_else(|| self.payload.get("key"))
    }

    fn is_field(&self, field: &str) -> bool {
        matches!(self.state_key(), Some(Value::String(s)) if s == field)
    }

    fn function_is(&self, name: &str) -> bool {
        self.function.as_deref() == Some(name)
    }
}

/// A capture gap: a frame, or an inclusive frame range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Gap {
    Frame(Key),
    Range(i64, i64),
}

type PhaseOrder = HashMap<String, i64>;

fn phase_rank(order: &PhaseOrder, phase: &Option<String>) -> Option<i64> {
    phase.as_ref().and_then(|p| order.get(p)).copied()
}

/// `_before`: Some(true/false) when A is established to come before B, None when the order is not established.
fn before(a: &Event, b: &Event, order: &PhaseOrder) -> Option<bool> {
    if a.frame != b.frame {
        return None;
    }
    if let (Some(pa), Some(pb)) = (phase_rank(order, &a.phase), phase_rank(order, &b.phase))
        && pa != pb
    {
        return Some(pa < pb);
    }
    if a.thread_gen != Key::Null
        && a.thread_gen == b.thread_gen
        && let (Some(x), Some(y)) = (a.seq, b.seq)
    {
        return Some(x < y);
    }
    None
}

fn sort_key(order: &PhaseOrder, w: &Event) -> (i64, i64) {
    (phase_rank(order, &w.phase).unwrap_or(NO_PHASE), w.seq.unwrap_or(0))
}

/// 15.3: for FIELD (a state key) and CONSUMER (the function whose read of the field matters), per frame: the ordered
/// writes, the value the consumer read and which write produced it, and a verdict. A frame that overlaps a capture gap is
/// `unknown` because a missing write cannot be excluded.
pub fn write_survival(
    events: &[Event],
    field: &str,
    consumer: &str,
    phases: &[String],
    gaps: &[Gap],
    representatives: usize,
) -> Result<Value> {
    let mut order = PhaseOrder::new();
    for (index, name) in phases.iter().enumerate() {
        order.insert(name.clone(), index as i64);
    }
    let gap_frames: Vec<&Key> = gaps.iter().filter_map(|g| if let Gap::Frame(k) = g { Some(k) } else { None }).collect();
    let gap_ranges: Vec<(i64, i64)> = gaps.iter().filter_map(|g| if let Gap::Range(a, b) = g { Some((*a, *b)) } else { None }).collect();
    let gapped = |frame: &Key| {
        gap_frames.contains(&frame) || matches!(frame, Key::Int(n) if gap_ranges.iter().any(|&(lo, hi)| lo <= *n && *n <= hi))
    };

    let mut writes: BTreeMap<&Key, Vec<&Event>> = BTreeMap::new();
    let mut reads: BTreeMap<&Key, Vec<&Event>> = BTreeMap::new();
    for event in events {
        if !event.is_field(field) || event.frame == Key::Null {
            continue;
        }
        match event.kind.as_deref() {
            Some("core.state.write") => writes.entry(&event.frame).or_default().push(event),
            Some("core.state.read") if event.function_is(consumer) => reads.entry(&event.frame).or_default().push(event),
            _ => {}
        }
    }
    let mut frame_keys: BTreeSet<&Key> = writes.keys().copied().collect();
    frame_keys.extend(reads.keys().copied());

    let verdict_names = [SURVIVED, OVERWRITTEN, READ_BEFORE_WRITE, UNKNOWN];
    let mut counts = [0usize; 4];
    let mut frames: Vec<(Key, &'static str, Value)> = Vec::new();
    let mut overwriters: Vec<(String, usize)> = Vec::new();
    for frame in frame_keys {
        let mut frame_writes: Vec<&Event> = writes.get(frame).cloned().unwrap_or_default();
        frame_writes.sort_by_key(|w| sort_key(&order, w));
        let mut entry = Map::new();
        entry.insert("frame".into(), frame.to_value());
        let rows: Vec<Value> = frame_writes
            .iter()
            .map(|w| {
                json!({"event_id": w.event_id, "site": w.site(), "role": w.role, "phase": w.phase, "ours": w.ours,
                       "value": w.payload.get("value").cloned().unwrap_or(Value::Null)})
            })
            .collect();
        entry.insert("writes".into(), Value::Array(rows));
        let frame_reads: &[&Event] = reads.get(frame).map_or(&[], Vec::as_slice);
        let (mut verdict, mut reason, mut produced_by, mut culprit) = (UNKNOWN, None::<String>, None::<Value>, None::<String>);
        if frame_reads.is_empty() {
            reason = Some("no consumer read observed in this frame".into());
        } else if gapped(frame) {
            reason = Some("the frame overlaps a capture gap".into());
        } else if !frame_writes.iter().any(|w| w.ours) {
            reason = Some("none of our writes was observed in this frame".into());
        } else {
            let read = frame_reads[0];
            entry.insert(
                "read".into(),
                json!({"event_id": read.event_id, "site": read.site(), "phase": read.phase,
                       "value": read.payload.get("value").cloned().unwrap_or(Value::Null)}),
            );
            let relations: Vec<(Option<bool>, &Event)> = frame_writes.iter().map(|w| (before(w, read, &order), *w)).collect();
            if let Some((_, unordered)) = relations.iter().find(|(b, _)| b.is_none()) {
                reason = Some(format!("order not established between {} and the consumer's read", py_str(&unordered.event_id)?));
            } else {
                let prior: Vec<&Event> = relations.iter().filter(|(b, _)| *b == Some(true)).map(|(_, w)| *w).collect();
                if prior.is_empty() || !prior.iter().any(|w| w.ours) {
                    verdict = READ_BEFORE_WRITE;
                } else {
                    // `max` keeps the first of equal keys
                    let mut produced = prior[0];
                    for &candidate in &prior[1..] {
                        if sort_key(&order, candidate) > sort_key(&order, produced) {
                            produced = candidate;
                        }
                    }
                    let rival = prior.iter().find(|w| !std::ptr::eq(**w, produced) && before(w, produced, &order).is_none());
                    if let Some(rival) = rival {
                        reason = Some(format!(
                            "order not established between writes {} and {}",
                            py_str(&produced.event_id)?,
                            py_str(&rival.event_id)?
                        ));
                    } else {
                        produced_by = Some(produced.event_id.clone());
                        if produced.ours {
                            verdict = SURVIVED;
                        } else {
                            verdict = OVERWRITTEN;
                            culprit = Some(produced.site());
                        }
                    }
                }
            }
        }
        entry.insert("verdict".into(), json!(verdict));
        if let Some(reason) = reason {
            entry.insert("reason".into(), json!(reason));
        }
        if let Some(id) = produced_by.filter(truthy) {
            entry.insert("produced_by".into(), id);
        }
        if let Some(site) = culprit.filter(|c| !c.is_empty()) {
            entry.insert("overwritten_by".into(), json!(site));
            match overwriters.iter_mut().find(|(s, _)| *s == site) {
                Some((_, n)) => *n += 1,
                None => overwriters.push((site, 1)),
            }
        }
        if let Some(slot) = verdict_names.iter().position(|v| *v == verdict) {
            counts[slot] += 1;
        }
        frames.push((frame.clone(), verdict, Value::Object(entry)));
    }

    let total = frames.len();
    overwriters.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let summary = if counts[1] > 0 {
        let (site, count) = &overwriters[0];
        Value::String(format!(
            "{} of {} frames overwritten{}",
            counts[1],
            total,
            if overwriters.len() == 1 { " by one site".to_owned() } else { format!(", {count} of them by {site}") }
        ))
    } else {
        Value::Null
    };
    let mut verdicts = Map::new();
    let mut ratios = Map::new();
    let mut sample = Map::new();
    for (name, count) in verdict_names.iter().zip(counts) {
        verdicts.insert((*name).into(), json!(count));
        ratios.insert((*name).into(), ppm(count, total));
        let picked: Vec<Value> = frames.iter().filter(|(_, v, _)| v == name).take(representatives).map(|(f, _, _)| f.to_value()).collect();
        sample.insert((*name).into(), Value::Array(picked));
    }
    Ok(json!({
        "field": field,
        "consumer": consumer,
        "frames": total,
        "verdicts": verdicts,
        "ratios_ppm": ratios,
        "overwriters": overwriters.iter().map(|(site, frames)| json!({"site": site, "frames": frames})).collect::<Vec<_>>(),
        "summary": summary,
        "representatives": sample,
        "per_frame": frames.into_iter().map(|(_, _, entry)| entry).collect::<Vec<_>>(),
        "claim": if counts[3] > 0 { "may_not_be_complete" } else { "all_frames_decided" },
    }))
}

/// Python's `str(x)` for a JSON scalar (what `"%s" % x` writes).
pub fn py_str(value: &Value) -> Result<String> {
    match value {
        Value::Null => Ok("None".into()),
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.to_string()),
        _ => Err(Error::unsupported("a value whose str() the port does not follow")),
    }
}

/// An aggregated observed indirect-call edge.
struct Edge {
    site: Value,
    target: Value,
    receiver_class: Value,
    slot: Value,
    count: u64,
    frames: Vec<Key>,
    events: Vec<Value>,
}

/// 15.4: observed indirect-call edges as cited `observed-call` relations, apart from static candidates. An event with
/// payload {site, target, receiver_class?, slot?} is an observed edge, aggregated by (site, target, class). Static candidates
/// that were never observed stay `may call`: this never says `does not call`.
pub fn observed_edges(events: &[Event], static_candidates: Option<&Map<String, Value>>, frames_per_edge: usize) -> Result<Value> {
    let mut edges: Vec<Edge> = Vec::new();
    let mut index: HashMap<(Key, Key, Key), usize> = HashMap::new();
    for event in events {
        let (Some(site), Some(target)) = (event.payload.get("site"), event.payload.get("target")) else { continue };
        let receiver = event.payload.get("receiver_class").cloned().unwrap_or(Value::Null);
        let key = (Key::of(site)?, Key::of(target)?, Key::of(&receiver)?);
        let at = *index.entry(key).or_insert_with(|| {
            edges.push(Edge {
                site: site.clone(),
                target: target.clone(),
                receiver_class: receiver.clone(),
                slot: event.payload.get("slot").cloned().unwrap_or(Value::Null),
                count: 0,
                frames: Vec::new(),
                events: Vec::new(),
            });
            edges.len() - 1
        });
        let edge = &mut edges[at];
        edge.count += 1;
        if event.frame != Key::Null && !edge.frames.contains(&event.frame) && edge.frames.len() < frames_per_edge {
            edge.frames.push(event.frame.clone());
        }
        if truthy(&event.event_id) && edge.events.len() < 3 {
            edge.events.push(event.event_id.clone());
        }
    }
    let mut ordered: Vec<(String, String, String, &Edge)> = Vec::with_capacity(edges.len());
    for edge in &edges {
        let text = |v: &Value| Key::of(v).and_then(|k| k.py_str().ok_or_else(|| Error::unsupported("str of a pair")));
        ordered.push((text(&edge.site)?, text(&edge.target)?, text(&edge.receiver_class)?, edge));
    }
    ordered.sort_by(|a, b| (&a.0, &a.1, &a.2).cmp(&(&b.0, &b.1, &b.2)));
    let seen: std::collections::HashSet<(Key, Key)> =
        edges.iter().map(|e| Ok((Key::of(&e.site)?, Key::of(&e.target)?))).collect::<Result<_>>()?;
    let observed: Vec<Value> = ordered
        .iter()
        .map(|(_, _, _, e)| {
            json!({"relation": "observed-call", "status": "supported", "site": e.site, "target": e.target,
                   "receiver_class": e.receiver_class, "slot": e.slot, "count": e.count,
                   "frames": e.frames.iter().map(Key::to_value).collect::<Vec<_>>(), "events": e.events})
        })
        .collect();
    let mut unobserved = Vec::new();
    if let Some(candidates) = static_candidates {
        let mut sites: Vec<(&String, &Value)> = candidates.iter().collect();
        sites.sort_by(|a, b| a.0.cmp(b.0)); // str(site) of a text key is the key
        for (site, targets) in sites {
            let Value::Array(targets) = targets else { return Err(Error::unsupported("candidate targets that are not a list")) };
            let mut targets: Vec<(String, &Value)> = targets.iter().map(|t| Ok((py_str(t)?, t))).collect::<Result<_>>()?;
            targets.sort_by(|a, b| a.0.cmp(&b.0));
            for (_, target) in targets {
                if !seen.contains(&(Key::Str(site.clone()), Key::of(target)?)) {
                    unobserved.push(json!({"site": site, "target": target, "status": "may call",
                                           "basis": "static candidate (vcalls); never observed"}));
                }
            }
        }
    }
    Ok(json!({"observed": observed, "unobserved_candidates": unobserved,
              "note": "an unobserved slot is `may call`, never `does not call`"}))
}

/// 15.4: writes of FIELD that did not pass through HOOK, with the observed call path and why. A write passed through the
/// hook when HOOK is on its symbolized stack (or is its function). Otherwise its class is `sibling-overload`,
/// `different-slot`, `inlined-copy` or `unexplained`.
pub fn hook_bypass(events: &[Event], hook: &str, field: &str, siblings: &[String], observed: &[Value], per_class: usize) -> Result<Value> {
    let mut targets: HashMap<Key, &Value> = HashMap::new();
    for edge in observed {
        let target = edge.get("target").map_or(Ok(Key::Null), Key::of)?;
        targets.entry(target).or_insert(edge);
    }
    let (mut passed, mut total) = (0usize, 0usize);
    let mut bypasses: Vec<Value> = Vec::new();
    let mut by_class: BTreeMap<&'static str, usize> = BTreeMap::new();
    for event in events {
        if event.kind.as_deref() != Some("core.state.write") || !event.is_field(field) {
            continue;
        }
        total += 1;
        let mut path: Vec<&str> = event.function.as_deref().filter(|f| !f.is_empty()).into_iter().collect();
        path.extend(event.stack.iter().map(String::as_str).filter(|name| Some(*name) != event.function.as_deref()));
        if path.contains(&hook) {
            passed += 1;
            continue;
        }
        let function_key = event.function.as_ref().map_or(Key::Null, |f| Key::Str(f.clone()));
        let edge = targets.get(&function_key).copied();
        let kind = if event.function.as_ref().is_some_and(|f| siblings.contains(f)) {
            "sibling-overload"
        } else if edge.is_some() {
            "different-slot"
        } else if event.function.is_none() && event.va.is_some() {
            "inlined-copy"
        } else {
            "unexplained"
        };
        let get = |name: &str| edge.and_then(|e| e.get(name)).cloned().unwrap_or(Value::Null);
        let reached = match edge {
            Some(e) => {
                let site = py_str(e.get("site").ok_or_else(|| Error::unsupported("an edge without a site"))?)?;
                json!(format!("indirect call at {site} (slot {})", py_str(&get("slot"))?))
            }
            None => Value::Null,
        };
        *by_class.entry(kind).or_insert(0) += 1;
        let already = bypasses.iter().filter(|b| b["class"] == kind).count();
        if already < per_class {
            bypasses.push(json!({"class": kind, "event_id": event.event_id, "frame": event.frame.to_value(), "site": event.site(),
                                 "path": path, "receiver_class": get("receiver_class"), "via": get("site"), "reached_through": reached}));
        }
    }
    let bypassed = total - passed;
    Ok(json!({
        "hook": hook,
        "field": field,
        "writes_observed": total,
        "through_hook": passed,
        "bypassed": bypassed,
        "ratios_ppm": {"bypassed": ppm(bypassed, total)},
        "by_class": by_class,
        "bypasses": bypasses,
        "verdict": if bypassed > 0 { "hook_bypassed" } else if total > 0 { "hook_covers_observed_writes" } else { "no_writes_observed" },
        "caveat": "only the instrumented sites and the observed intervals are covered; a write that was not observed is not evidence that the hook sees every write",
    }))
}

/// M4: separate what the run exercised, the static candidates it never exercised and where observation was missing. The
/// three lists are never merged: an unobserved candidate is not a negative, and a gap is not an absence.
pub fn discovery_report(exercised: &[Value], candidates: &[Value], observation_gaps: &[Value]) -> Result<Value> {
    let key_of = |item: &Value| -> Result<Key> {
        item.as_object().ok_or_else(|| Error::unsupported("an item that is not a mapping"))?.get("key").map_or(Ok(Key::Null), Key::of)
    };
    let exercised_keys: std::collections::HashSet<Key> = exercised.iter().map(key_of).collect::<Result<_>>()?;
    let mut unobserved = Vec::new();
    for item in candidates {
        if !exercised_keys.contains(&key_of(item)?) {
            unobserved.push(item.clone());
        }
    }
    Ok(json!({
        "exercised_behavior": {"count": exercised.len(), "items": exercised},
        "unobserved_candidates": {"count": unobserved.len(), "items": unobserved,
                                  "meaning": "static candidates with no observed execution in the observed intervals"},
        "observation_gaps": {"count": observation_gaps.len(), "items": observation_gaps,
                             "meaning": "intervals or sites where nothing could be observed; absence there proves nothing"},
    }))
}

// ---- 14.4: who writes this field? -----------------------------------------------------------------------------------

/// One row of the static `writes` scan.
#[derive(Debug, Clone)]
pub struct StaticSite {
    pub function: Value,
    pub function_name: Value,
    pub site: Value,
    pub instruction: Value,
    /// `_entry(function)`.
    pub entry: Option<i128>,
}

/// The geometry of the field a writer search is about.
#[derive(Debug, Clone, Copy)]
pub struct FieldSpan {
    pub object: i64,
    pub offset: i64,
    pub size: i64,
}

/// `field_writers` options.
pub struct WriterOptions<'a> {
    pub escape_kind: &'a str,
    pub write_kinds: &'a [String],
    pub per_site: usize,
}

struct ByFunction {
    function: Value,
    sites: Vec<Value>,
}

struct Observed {
    count: u64,
    objects: BTreeSet<i64>,
    frames: Vec<Key>,
    events: Vec<Value>,
    static_candidate: bool,
}

struct Escape {
    callee: Value,
    count: u64,
    events: Vec<Value>,
}

/// 14.4: the writers of one field of one object, as three answers that are never merged: `observed`, `may_access` (a static
/// candidate with no observation) and `unresolved` (a pointer to the field reached uninstrumented code). NAMES maps a
/// function entry address to its name. Events carry `object`, `offset`, `size`, `site` and `callee` in their payload.
pub fn field_writers(
    static_sites: &[StaticSite],
    events: &[Event],
    span: FieldSpan,
    names: &HashMap<Option<i128>, String>,
    options: &WriterOptions<'_>,
) -> Result<Value> {
    let overflow = || Error::unsupported("address arithmetic beyond 64 bits");
    let lo = span.object.checked_add(span.offset).ok_or_else(overflow)?;
    let hi = lo.checked_add(span.size).ok_or_else(overflow)?;
    let mut by_function: Vec<(Option<i128>, ByFunction)> = Vec::new();
    for row in static_sites {
        let site = json!({"site": row.site, "instruction": row.instruction});
        if let Some((_, existing)) = by_function.iter_mut().find(|(entry, _)| *entry == row.entry) {
            existing.sites.push(site);
            continue;
        }
        let name = names.get(&row.entry).filter(|n| !n.is_empty()).map(|n| json!(n));
        let function = name
            .or_else(|| Some(row.function_name.clone()).filter(truthy))
            .or_else(|| Some(row.function.clone()).filter(truthy))
            .unwrap_or_else(|| row.function.clone());
        by_function.push((row.entry, ByFunction { function, sites: vec![site] }));
    }
    let candidate_names: Vec<&Value> = by_function.iter().map(|(_, f)| &f.function).collect();
    let mut observed: BTreeMap<String, Observed> = BTreeMap::new();
    let mut escapes: BTreeMap<String, Escape> = BTreeMap::new();
    for event in events {
        let base = match event.payload.get("object") {
            Some(Value::Number(n)) if n.is_i64() => n.as_i64().unwrap_or_default(),
            Some(Value::Bool(_)) => return Err(Error::unsupported("a boolean object address")),
            Some(Value::Number(n)) if n.is_u64() => return Err(Error::unsupported("an object address beyond i64")),
            _ => continue,
        };
        let int_of = |key: &str, default: i64| -> Result<i64> {
            match event.payload.get(key) {
                None => Ok(default),
                Some(Value::Number(n)) if n.is_i64() => Ok(n.as_i64().unwrap_or_default()),
                _ => Err(Error::unsupported("an offset or size that is not an integer")),
            }
        };
        let start = base.checked_add(int_of("offset", 0)?).ok_or_else(overflow)?;
        let name = match (&event.function, event.payload.get("site")) {
            (Some(f), _) if !f.is_empty() => f.clone(),
            (_, Some(Value::String(s))) if !s.is_empty() => s.clone(),
            (_, Some(other)) if truthy(other) => return Err(Error::unsupported("a site that is not text")),
            _ => "unresolved".to_owned(),
        };
        let kind = event.kind.as_deref();
        if kind.is_some_and(|k| options.write_kinds.iter().any(|w| w == k)) {
            let end = start.checked_add(int_of("size", span.size)?).ok_or_else(overflow)?;
            if start < hi && end > lo {
                let entry = observed.entry(name.clone()).or_insert_with(|| Observed {
                    count: 0,
                    objects: BTreeSet::new(),
                    frames: Vec::new(),
                    events: Vec::new(),
                    static_candidate: candidate_names.iter().any(|f| f.as_str() == Some(name.as_str())),
                });
                entry.count += 1;
                entry.objects.insert(base);
                if event.frame != Key::Null && entry.frames.len() < options.per_site * 2 && !entry.frames.contains(&event.frame) {
                    entry.frames.push(event.frame.clone());
                }
                if truthy(&event.event_id) && entry.events.len() < options.per_site {
                    entry.events.push(event.event_id.clone());
                }
            }
        } else if kind == Some(options.escape_kind) && lo <= start && start < hi {
            let entry = escapes.entry(name).or_insert_with(|| Escape {
                callee: event.payload.get("callee").cloned().unwrap_or(Value::Null),
                count: 0,
                events: Vec::new(),
            });
            entry.count += 1;
            if truthy(&event.event_id) && entry.events.len() < options.per_site {
                entry.events.push(event.event_id.clone());
            }
        }
    }
    let observed_rows: Vec<Value> = observed
        .iter()
        .map(|(name, row)| {
            let objects: Vec<i64> = row.objects.iter().copied().collect();
            let mut out = Map::new();
            out.insert("site".into(), json!(name));
            out.insert("count".into(), json!(row.count));
            out.insert("objects".into(), json!(objects));
            out.insert("frames".into(), Value::Array(row.frames.iter().map(Key::to_value).collect()));
            out.insert("events".into(), json!(row.events));
            out.insert("static_candidate".into(), json!(row.static_candidate));
            out.insert("status".into(), json!("observed"));
            out.insert("on_selected_object".into(), json!(row.objects.contains(&span.object)));
            if !row.static_candidate {
                out.insert("note".into(), json!("not among the static candidates: no scan of this field would have listed it"));
            }
            Value::Object(out)
        })
        .collect();
    let mut ordered: Vec<(String, &ByFunction)> = Vec::with_capacity(by_function.len());
    for (_, value) in &by_function {
        ordered.push((py_str(&value.function)?, value));
    }
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    let mut may = Vec::new();
    for (_, value) in ordered {
        if matches!(&value.function, Value::String(f) if observed.contains_key(f)) {
            continue;
        }
        may.push(json!({"site": value.function, "status": "may access", "static_sites": value.sites,
                        "basis": format!("static candidate (a store at offset {}); never observed in the observed intervals",
                                         py_hex(i128::from(span.offset)))}));
    }
    let mut unresolved = Vec::new();
    for (name, row) in &escapes {
        let callee = if truthy(&row.callee) { py_str(&row.callee)? } else { "an uninstrumented callee".to_owned() };
        unresolved.push(json!({
            "site": name, "status": "unresolved", "callee": row.callee, "count": row.count, "events": row.events,
            "stopped_by": format!("alias: a pointer into the field is passed to {callee}, which is not instrumented; whether it writes the field is neither observed nor excluded"),
        }));
    }
    Ok(json!({
        "field": {"object": span.object, "offset": span.offset, "size": span.size},
        "observed": observed_rows,
        "may_access": may,
        "unresolved": unresolved,
        "static_inventory_complete": false,
        "claim": "three distinct answers: observed writers, static candidates never seen to run, and aliases that stop the analysis; none of them is a complete writer inventory",
    }))
}

// ---- adapters: trace rows -> the events the reports read ------------------------------------------------------------

/// A dispatch site: the slot its indirect call goes through.
#[derive(Debug, Clone)]
pub struct DispatchSite {
    pub slot: Value,
}

/// 15.4: observed indirect-call edges from instrumented dispatch sites. The target is the very next instrumented event of the
/// same thread (events whose function is in IGNORE are skipped); if that is itself a dispatch event there is no observed
/// target. With CANDIDATES the next event only counts when it is one of the site's candidates. `receiver_class` names the
/// class of a receiver object where that is known.
pub fn edges_from_dispatch(
    events: &[Event],
    dispatch_sites: &HashMap<String, DispatchSite>,
    ignore: &[String],
    candidates: Option<&Map<String, Value>>,
    receiver_class: &mut dyn FnMut(&Value) -> Result<Value>,
) -> Result<Vec<Value>> {
    let mut rows: Vec<&Event> = events.iter().collect();
    rows.sort_by_key(|r| r.seq.unwrap_or(0));
    let mut threads: Vec<(Key, Vec<&Event>)> = Vec::new();
    let mut at: HashMap<&Key, usize> = HashMap::new();
    for row in rows {
        if row.function.as_ref().is_some_and(|f| ignore.contains(f)) {
            continue;
        }
        let slot = *at.entry(&row.thread_gen).or_insert_with(|| {
            threads.push((row.thread_gen.clone(), Vec::new()));
            threads.len() - 1
        });
        threads[slot].1.push(row);
    }
    let in_sites = |function: &Option<String>| function.as_ref().is_some_and(|f| dispatch_sites.contains_key(f));
    let mut out = Vec::new();
    for (_, thread) in &threads {
        for (index, row) in thread.iter().enumerate().take(thread.len().saturating_sub(1)) {
            let Some(site) = row.function.as_ref().filter(|f| dispatch_sites.contains_key(*f)) else { continue };
            let target = thread[index + 1];
            if in_sites(&target.function) {
                continue;
            }
            if candidates.is_some_and(|c| !c.is_empty()) {
                let listed = match candidates.and_then(|c| c.get(site)) {
                    None | Some(Value::Null) => false,
                    Some(Value::Array(list)) => list.iter().any(|t| matches!((t, &target.function), (Value::String(a), Some(b)) if a == b)),
                    Some(_) => return Err(Error::unsupported("candidate targets that are not a list")),
                };
                if !listed {
                    continue;
                }
            }
            let receiver = row.payload.get("receiver").cloned().unwrap_or(Value::Null);
            let class = if receiver.is_null() { Value::Null } else { receiver_class(&receiver)? };
            out.push(json!({
                "event_id": row.event_id, "kind": "core.function.enter", "seq": row.seq, "frame": row.frame.to_value(),
                "payload": {"site": site, "target": target.function, "slot": dispatch_sites[site].slot, "receiver_class": class,
                            "basis": format!("next instrumented event on the same thread after the dispatch ({})", py_str(&target.event_id)?)},
            }));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::too_many_arguments)]
    fn write(frame: i64, id: &str, phase: &str, site: &str, value: i64, ours: bool, seq: i64, thread: i64) -> Event {
        let mut payload = Map::new();
        payload.insert("state_key".into(), json!("Actor.speed"));
        payload.insert("value".into(), json!(value));
        Event {
            event_id: json!(id),
            kind: Some("core.state.write".into()),
            seq: Some(seq),
            frame: Key::Int(frame),
            phase: Some(phase.into()),
            role: json!("main"),
            thread_gen: Key::Int(thread),
            function: Some(site.into()),
            stack: vec![],
            va: None,
            ours,
            payload,
        }
    }

    fn read(frame: i64, id: &str, phase: &str, value: i64, seq: i64, thread: i64) -> Event {
        let mut event = write(frame, id, phase, "Render", value, false, seq, thread);
        event.kind = Some("core.state.read".into());
        event
    }

    fn phases() -> Vec<String> {
        ["input", "update", "late", "render"].iter().map(|s| (*s).to_owned()).collect()
    }

    fn frames(count: i64, overwritten_every: i64) -> Vec<Event> {
        let mut events = Vec::new();
        for frame in 0..count {
            let base = frame * 10;
            events.push(write(frame, &format!("w{frame}"), "update", "OurHook", 9, true, base + 1, 1));
            if frame % overwritten_every == 0 {
                events.push(write(frame, &format!("o{frame}"), "late", "HostAnimator::Tick", 1, false, base + 2, 1));
            }
            events.push(read(frame, &format!("r{frame}"), "render", if frame % overwritten_every == 0 { 1 } else { 9 }, base + 3, 1));
        }
        events
    }

    fn survival(events: &[Event], gaps: &[Gap]) -> Value {
        write_survival(events, "Actor.speed", "Render", &phases(), gaps, 3).unwrap()
    }

    // Reports.test_a_later_stage_overwrites_on_most_frames_and_the_report_names_it
    #[test]
    fn a_later_stage_overwrites_on_most_frames_and_the_report_names_it() {
        let report = survival(&frames(40, 1), &[]);
        assert_eq!(report["verdicts"], json!({"survived": 0, "overwritten": 40, "consumer read before write": 0, "unknown": 0}));
        assert_eq!(report["overwriters"], json!([{"site": "HostAnimator::Tick", "frames": 40}]));
        assert_eq!(report["summary"], "40 of 40 frames overwritten by one site");
        assert_eq!(report["ratios_ppm"]["overwritten"], 1_000_000);
        assert_eq!(report["claim"], "all_frames_decided");
        assert_eq!(report["per_frame"][0]["overwritten_by"], "HostAnimator::Tick");
        assert_eq!(report["per_frame"][0]["produced_by"], "o0");
        assert_eq!(report["representatives"]["overwritten"], json!([0, 1, 2]));
    }

    // Reports.test_removing_the_overwrite_turns_every_frame_to_survived
    #[test]
    fn removing_the_overwrite_turns_every_frame_to_survived() {
        let events: Vec<Event> = frames(40, 1).into_iter().filter(|e| !e.event_id.as_str().unwrap().starts_with('o')).collect();
        let report = survival(&events, &[]);
        assert_eq!(report["verdicts"]["survived"], 40);
        assert_eq!(report["summary"], Value::Null);
        assert_eq!(report["ratios_ppm"]["survived"], 1_000_000);
    }

    // Reports.test_a_mixed_run_gives_the_ratio
    #[test]
    fn a_mixed_run_gives_the_ratio() {
        let report = survival(&frames(10, 3), &[]);
        assert_eq!(report["verdicts"]["overwritten"], 4);
        assert_eq!(report["verdicts"]["survived"], 6);
        assert_eq!(report["summary"], "4 of 10 frames overwritten by one site");
        assert_eq!(report["ratios_ppm"]["overwritten"], 400_000);
    }

    // Reports.test_a_consumer_that_reads_before_our_write
    #[test]
    fn a_consumer_that_reads_before_our_write() {
        let events = [read(0, "r0", "input", 1, 1, 1), write(0, "w0", "update", "OurHook", 9, true, 2, 1)];
        assert_eq!(survival(&events, &[])["verdicts"]["consumer read before write"], 1);
    }

    // Reports.test_unknown_is_never_pass_gaps_missing_reads_and_unordered_writes
    #[test]
    fn unknown_is_never_pass_gaps_missing_reads_and_unordered_writes() {
        let events = frames(3, 1);
        let gapped = survival(&events, &[Gap::Frame(Key::Int(1))]);
        assert_eq!(gapped["per_frame"][1]["verdict"], "unknown");
        assert!(gapped["per_frame"][1]["reason"].as_str().unwrap().contains("capture gap"));
        assert_eq!(gapped["claim"], "may_not_be_complete");
        let ranged = survival(&events, &[Gap::Range(0, 1)]);
        assert_eq!(ranged["verdicts"]["unknown"], 2);
        let no_read: Vec<Event> = events.iter().filter(|e| e.kind.as_deref() != Some("core.state.read")).cloned().collect();
        assert_eq!(survival(&no_read, &[])["verdicts"]["unknown"], 3);
        // two writes in the same stage on different threads: their order is not established
        let mut rival: Vec<Event> = events.iter().filter(|e| !e.event_id.as_str().unwrap().starts_with('o')).cloned().collect();
        rival.push(write(0, "x0", "update", "OtherThread", 5, false, 99, 7));
        let report = survival(&rival, &[]);
        assert_eq!(report["per_frame"][0]["verdict"], "unknown");
        assert!(report["per_frame"][0]["reason"].as_str().unwrap().contains("order not established"));
        // without phases and on different threads nothing is ordered
        let bare = [write(0, "w", "u", "Our", 9, true, 1, 1), read(0, "r", "r", 9, 2, 2)];
        let report = write_survival(&bare, "Actor.speed", "Render", &[], &[], 3).unwrap();
        assert_eq!(report["per_frame"][0]["verdict"], "unknown");
    }

    // Reports.test_the_report_is_deterministic
    #[test]
    fn the_report_is_deterministic() {
        let events = frames(12, 2);
        let mut reversed = events.clone();
        reversed.reverse();
        assert_eq!(survival(&events, &[]), survival(&reversed, &[]));
    }

    fn overload(id: &str, function: &str, stack: &[&str], frame: i64) -> Event {
        let mut payload = Map::new();
        payload.insert("state_key".into(), json!("Actor.hp"));
        Event {
            event_id: json!(id),
            kind: Some("core.state.write".into()),
            seq: None,
            frame: Key::Int(frame),
            phase: None,
            role: Value::Null,
            thread_gen: Key::Null,
            function: Some(function.into()),
            stack: stack.iter().map(|s| (*s).to_owned()).collect(),
            va: Some(0x1000),
            ours: false,
            payload,
        }
    }

    fn overload_events() -> Vec<Event> {
        vec![
            overload("w1", "Actor::SetHp(int)", &["Caller"], 0),
            overload("w2", "Actor::SetHp(float)", &["VCaller"], 1),
            overload("w3", "Actor::SetHp(int)", &["Caller"], 2),
            overload("w4", "Wrapper", &["Actor::SetHp(int)", "Caller"], 3),
        ]
    }

    fn call_event(id: &str, frame: i64, class: &str) -> Event {
        let mut payload = Map::new();
        for (k, v) in
            [("site", json!("rva:0x500")), ("target", json!("Actor::SetHp(float)")), ("receiver_class", json!(class)), ("slot", json!(3))]
        {
            payload.insert(k.into(), v);
        }
        Event { kind: Some("core.function.enter".into()), function: None, va: None, payload, ..overload(id, "x", &[], frame) }
    }

    // Reports.test_hooking_one_overload_reports_the_other_as_a_bypass_with_its_path_and_class
    #[test]
    fn hooking_one_overload_reports_the_other_as_a_bypass_with_its_path_and_class() {
        let candidates: Map<String, Value> =
            serde_json::from_value(json!({"rva:0x500": ["Actor::SetHp(float)", "Actor::SetHp(double)"]})).unwrap();
        let edges = observed_edges(&[call_event("c1", 1, "Hero"), call_event("c2", 2, "Hero")], Some(&candidates), 5).unwrap();
        assert_eq!(edges["observed"][0]["count"], 2);
        assert_eq!(edges["observed"][0]["frames"], json!([1, 2]));
        assert_eq!(
            edges["unobserved_candidates"],
            json!([{"site": "rva:0x500", "target": "Actor::SetHp(double)", "status": "may call",
                    "basis": "static candidate (vcalls); never observed"}])
        );
        let observed = edges["observed"].as_array().unwrap().clone();
        let report = hook_bypass(&overload_events(), "Actor::SetHp(int)", "Actor.hp", &[], &observed, 5).unwrap();
        assert_eq!(
            (report["writes_observed"].clone(), report["through_hook"].clone(), report["bypassed"].clone()),
            (json!(4), json!(3), json!(1))
        );
        let bypass = &report["bypasses"][0];
        assert_eq!(bypass["class"], "different-slot");
        assert_eq!(bypass["event_id"], "w2");
        assert_eq!(bypass["receiver_class"], "Hero");
        assert_eq!(bypass["via"], "rva:0x500");
        assert_eq!(bypass["path"], json!(["Actor::SetHp(float)", "VCaller"]));
        assert_eq!(bypass["reached_through"], "indirect call at rva:0x500 (slot 3)");
        assert_eq!(report["verdict"], "hook_bypassed");
        let sibling = hook_bypass(&overload_events(), "Actor::SetHp(int)", "Actor.hp", &["Actor::SetHp(float)".into()], &[], 5).unwrap();
        assert_eq!(sibling["by_class"], json!({"sibling-overload": 1}));
    }

    // Reports.test_no_bypass_and_no_writes_are_different_answers
    #[test]
    fn no_bypass_and_no_writes_are_different_answers() {
        let clean: Vec<Event> = overload_events().into_iter().filter(|e| e.function.as_deref() != Some("Actor::SetHp(float)")).collect();
        assert_eq!(hook_bypass(&clean, "Actor::SetHp(int)", "Actor.hp", &[], &[], 5).unwrap()["verdict"], "hook_covers_observed_writes");
        assert_eq!(hook_bypass(&[], "x", "Actor.hp", &[], &[], 5).unwrap()["verdict"], "no_writes_observed");
        let mut copy = overload("w9", "x", &[], 0);
        copy.function = None;
        copy.va = Some(0x77);
        let report = hook_bypass(&[copy], "x", "Actor.hp", &[], &[], 5).unwrap();
        assert_eq!(report["bypasses"][0]["class"], "inlined-copy");
        assert_eq!(report["bypasses"][0]["site"], "va:0x77");
    }

    // Reports.test_the_discovery_report_keeps_three_kinds_of_answer_apart
    #[test]
    fn the_discovery_report_keeps_three_kinds_of_answer_apart() {
        let report = discovery_report(
            &[json!({"key": "a"}), json!({"key": "b"})],
            &[json!({"key": "b"}), json!({"key": "c"})],
            &[json!({"interval": [1, 2], "reason": "observer-inactive"})],
        )
        .unwrap();
        assert_eq!(report["exercised_behavior"]["count"], 2);
        assert_eq!(report["unobserved_candidates"]["items"], json!([{"key": "c"}]));
        assert_eq!(report["observation_gaps"]["count"], 1);
    }

    #[test]
    fn writers_are_three_distinct_answers() {
        let sites = [
            StaticSite {
                function: json!("0x2000"),
                function_name: Value::Null,
                site: json!("0x2010"),
                instruction: json!("mov"),
                entry: Some(0x2000),
            },
            StaticSite {
                function: json!("0x2100"),
                function_name: Value::Null,
                site: json!("0x2110"),
                instruction: Value::Null,
                entry: Some(0x2100),
            },
        ];
        let names = HashMap::from([(Some(0x2000), "Actor_Update".to_owned())]);
        let write_event = |id: &str, function: &str, object: i64| {
            let mut event = overload(id, function, &[], 4);
            event.payload.insert("object".into(), json!(object));
            event.payload.insert("offset".into(), json!(8));
            event.payload.insert("size".into(), json!(4));
            event
        };
        let mut escape = write_event("e1", "Actor_Hit", 0x5000);
        escape.kind = Some("app.escape".into());
        escape.payload.insert("callee".into(), json!("memcpy"));
        let events =
            [write_event("a", "Actor_Update", 0x5000), write_event("b", "Mystery", 0x5000), write_event("c", "Mystery", 0x9000), escape];
        let kinds = ["core.state.write".to_owned()];
        let options = WriterOptions { escape_kind: "app.escape", write_kinds: &kinds, per_site: 3 };
        let report = field_writers(&sites, &events, FieldSpan { object: 0x5000, offset: 8, size: 4 }, &names, &options).unwrap();
        let observed: Vec<(&str, u64, bool)> = report["observed"]
            .as_array()
            .unwrap()
            .iter()
            .map(|r| (r["site"].as_str().unwrap(), r["count"].as_u64().unwrap(), r["static_candidate"].as_bool().unwrap()))
            .collect();
        // the object at 0x9000 does not overlap the field of the selected object
        assert_eq!(observed, [("Actor_Update", 1, true), ("Mystery", 1, false)]);
        assert_eq!(report["observed"][1]["note"], "not among the static candidates: no scan of this field would have listed it");
        assert_eq!(report["may_access"][0]["site"], "0x2100");
        assert_eq!(report["may_access"][0]["basis"], "static candidate (a store at offset 0x8); never observed in the observed intervals");
        assert_eq!(report["unresolved"][0]["callee"], "memcpy");
        assert_eq!(report["static_inventory_complete"], false);
    }

    #[test]
    fn dispatch_edges_follow_the_next_event_on_the_same_thread() {
        let dispatch = |id: &str, function: &str, seq: i64, thread: i64| {
            let mut event = overload(id, function, &[], 0);
            event.seq = Some(seq);
            event.thread_gen = Key::Int(thread);
            event.payload.insert("receiver".into(), json!(0x40));
            event
        };
        let events = [
            dispatch("d1", "rva:0x500", 1, 1),
            dispatch("t1", "Target", 2, 1),
            dispatch("d2", "rva:0x500", 3, 2),
            dispatch("d3", "rva:0x500", 4, 2),
        ];
        let sites = HashMap::from([("rva:0x500".to_owned(), DispatchSite { slot: json!(3) })]);
        let mut class = |_: &Value| Ok(json!("Hero"));
        let edges = edges_from_dispatch(&events, &sites, &[], None, &mut class).unwrap();
        assert_eq!(edges.len(), 1);
        assert_eq!(edges[0]["payload"]["target"], "Target");
        assert_eq!(edges[0]["payload"]["receiver_class"], "Hero");
        assert_eq!(edges[0]["payload"]["basis"], "next instrumented event on the same thread after the dispatch (t1)");
        let candidates: Map<String, Value> = serde_json::from_value(json!({"rva:0x500": ["Other"]})).unwrap();
        assert!(edges_from_dispatch(&events, &sites, &[], Some(&candidates), &mut class).unwrap().is_empty());
        assert!(edges_from_dispatch(&events, &sites, &["Target".to_owned()], None, &mut class).unwrap().is_empty());
    }
}
