//! Pairing an owner session with a replica session (spec 15.5), ported from `hydralysis.trace_pairing.pair_report`.
//!
//! Shared sync markers give pairs of timestamps; a least-squares line maps the replica clock onto the owner clock and every
//! owner value is answered `reflected`, `not_reflected` or `unknown`. The arithmetic is the Python's, operation for
//! operation: `float` additions in the same order, CPython's compensated `sum`, and its float floor division, so the
//! numbers (and the JSON they serialise to) are the same bits.
//!
//! Events are dicts whose fields the Python reads loosely. This port models the shapes the producers emit (numeric
//! timestamps up to 2^53, object keys and sequence numbers that are integers, text or `None`, numeric values) and answers
//! [`Error::Unsupported`] for anything else, so the caller runs the Python, which stays the specification and raises or
//! answers as it always did. Where the Python looks a value up with a quadratic scan (the owner's latest value at each
//! mirror time) this port bisects over the already-sorted owner events; the answer is the same.

use crate::{Error, Result};
use serde_json::{Map, Number, Value};
use std::cmp::Ordering;
use std::collections::HashMap;

/// The Python `MIN_MARKERS`.
const MIN_MARKERS: usize = 3;
/// The Python `MIN_DRIFT_SPAN_NS`.
const MIN_DRIFT_SPAN_NS: f64 = 1_000_000_000.0;
/// Integers beyond this are not exactly representable as `f64`; the Python compares them exactly, this port does not.
const EXACT: i64 = 1 << 53;
/// An outage list or event list shown in a report is cut at this many ids.
const SHOWN: usize = 20;
const SHOWN_EXTRAPOLATED: usize = 10;

static NULL: Value = Value::Null;

fn unsupported<T>(what: &str) -> Result<T> {
    Err(Error::unsupported(what))
}

// ---- Python numbers --------------------------------------------------------------------------------------------------

/// An `int` or a `float`, with the type kept: `max`, `abs`, subtraction and `//` answer differently for each.
#[derive(Debug, Clone, Copy, PartialEq)]
enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    fn from_value(value: &Value) -> Result<Num> {
        let Value::Number(number) = value else {
            return unsupported("a number was expected");
        };
        if let Some(v) = number.as_i64() {
            return if v.abs() <= EXACT { Ok(Num::Int(v)) } else { unsupported("integer beyond 2^53") };
        }
        match number.as_f64() {
            Some(v) if number.is_f64() => Ok(Num::Float(v)),
            _ => unsupported("integer beyond 2^53"),
        }
    }

    fn float(self) -> f64 {
        match self {
            Num::Int(v) => v as f64,
            Num::Float(v) => v,
        }
    }

    fn abs(self) -> Num {
        match self {
            Num::Int(v) => Num::Int(v.abs()),
            Num::Float(v) => Num::Float(v.abs()),
        }
    }

    /// `self - other`, an int only when both are.
    fn sub(self, other: Num) -> Result<Num> {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => a.checked_sub(b).map(Num::Int).ok_or_else(|| Error::unsupported("integer overflow")),
            (a, b) => Ok(Num::Float(a.float() - b.float())),
        }
    }

    /// `self > other` (exact: both are within 2^53).
    fn gt(self, other: Num) -> bool {
        match (self, other) {
            (Num::Int(a), Num::Int(b)) => a > b,
            (a, b) => a.float() > b.float(),
        }
    }

    fn to_value(self) -> Result<Value> {
        match self {
            Num::Int(v) => Ok(Value::from(v)),
            Num::Float(v) => Number::from_f64(v).map(Value::Number).ok_or_else(|| Error::unsupported("non-finite float")),
        }
    }
}

/// `int(x)` for a float: truncation, answered only where the result is a 64-bit integer.
fn trunc(x: f64) -> Result<i64> {
    if x.is_finite() && x.abs() < 9.0e18 { Ok(x as i64) } else { unsupported("int() of a float beyond 64 bits") }
}

fn int_value(x: f64) -> Result<Value> {
    trunc(x).map(Value::from)
}

/// CPython's `sum` over floats (3.12 and later): Neumaier compensated summation, starting from START (the int sum so far).
fn compensated_sum(start: f64, values: impl IntoIterator<Item = f64>) -> f64 {
    let mut sum = start;
    let mut compensation = 0.0_f64;
    for x in values {
        let t = sum + x;
        if sum.abs() >= x.abs() {
            compensation += (sum - t) + x;
        } else {
            compensation += (x - t) + sum;
        }
        sum = t;
    }
    if compensation != 0.0 && compensation.is_finite() {
        sum += compensation;
    }
    sum
}

/// `sum(floats)`.
fn py_sum(values: impl IntoIterator<Item = f64>) -> f64 {
    compensated_sum(0.0, values)
}

/// `sum(numbers)` for ints and floats: exact while the items are ints, compensated once a float is seen.
fn py_sum_nums(values: &[Num]) -> Result<Num> {
    let mut int_sum: i64 = 0;
    let mut index = 0;
    while let Some(Num::Int(v)) = values.get(index) {
        int_sum = int_sum.checked_add(*v).ok_or_else(|| Error::unsupported("integer overflow"))?;
        index += 1;
    }
    if index == values.len() {
        return Ok(Num::Int(int_sum));
    }
    Ok(Num::Float(compensated_sum(int_sum as f64, values[index..].iter().map(|n| n.float()))))
}

/// `a // b` for floats with `b` positive, as CPython's `float_floor_div` computes it.
fn py_floordiv(a: f64, b: f64) -> f64 {
    let modulus = a % b;
    let mut div = (a - modulus) / b;
    if modulus != 0.0 && (b < 0.0) != (modulus < 0.0) {
        div -= 1.0;
    }
    if div != 0.0 {
        let mut floor = div.floor();
        if div - floor > 0.5 {
            floor += 1.0;
        }
        floor
    } else {
        0.0_f64.copysign(a / b)
    }
}

// ---- reading events --------------------------------------------------------------------------------------------------

/// A hashable correlation key or sequence number the producers emit.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Key {
    Null,
    Int(i128),
    Str(String),
}

impl Key {
    /// The key of a JSON scalar (`null`, an integer or text).
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for a float, a boolean, a list or an object.
    pub fn from_value(value: &Value) -> Result<Key> {
        match value {
            Value::Null => Ok(Key::Null),
            Value::String(text) => Ok(Key::Str(text.clone())),
            Value::Number(n) if n.is_i64() || n.is_u64() => {
                Ok(Key::Int(n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from)).unwrap_or_default()))
            }
            _ => unsupported("a key that is not None, an integer or text"),
        }
    }

    /// Python's `str(x)`.
    fn py_str(&self) -> String {
        match self {
            Key::Null => "None".into(),
            Key::Int(v) => v.to_string(),
            Key::Str(text) => text.clone(),
        }
    }
}

/// `event["t_mono_ns"]` as the report reads it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Time {
    /// The event has no `t_mono_ns`.
    Missing,
    /// A number: `float(value)`.
    At(f64),
    /// Present, but not a number this port models (text, an integer beyond 2^53, ...).
    Unmodelled,
}

/// `payload[value]` as the report reads it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Reading {
    /// Absent, `None` or anything that is not an `int` or `float` (the report skips it).
    Skipped,
    Number(f64, bool),
    /// A boolean, or an integer beyond 2^53: Python treats it as a number, this port does not model it.
    Unmodelled,
}

/// The fields of one trace event that `pair_report` reads (kept small: a session is hundreds of thousands of these).
#[derive(Debug, Clone)]
pub struct PairEvent {
    pub kind: Option<String>,
    pub event_id: Option<Value>,
    pub t_mono_ns: Time,
    pub sync_key: Key,
    pub object: Key,
    pub seq: Key,
    pub value: Reading,
}

impl PairEvent {
    /// The event as the report reads it, from a JSON object and the payload keys the spec names.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] for an event that is not an object, a payload that is not an object, or a key of an unmodelled
    /// shape.
    pub fn from_value(event: &Value, sync_key: &str, object: &str, seq: &str, value: &str) -> Result<PairEvent> {
        let map = event.as_object().ok_or_else(|| Error::unsupported("an event that is not an object"))?;
        let payload = match map.get("payload") {
            Some(p) if !is_falsy(p) => Some(p.as_object().ok_or_else(|| Error::unsupported("a payload that is not an object"))?),
            _ => None,
        };
        let get = |name: &str| payload.and_then(|p| p.get(name)).unwrap_or(&NULL);
        let reading = match get(value) {
            Value::Number(_) => match Num::from_value(get(value)) {
                Ok(Num::Int(v)) => Reading::Number(v as f64, true),
                Ok(Num::Float(v)) => Reading::Number(v, false),
                Err(_) => Reading::Unmodelled,
            },
            Value::Bool(_) => Reading::Unmodelled,
            _ => Reading::Skipped,
        };
        Ok(PairEvent {
            kind: map.get("kind").and_then(Value::as_str).map(str::to_owned),
            event_id: map.get("event_id").cloned(),
            t_mono_ns: match map.get("t_mono_ns") {
                None => Time::Missing,
                Some(v) => Num::from_value(v).map_or(Time::Unmodelled, |n| Time::At(n.float())),
            },
            sync_key: Key::from_value(get(sync_key))?,
            object: Key::from_value(get(object))?,
            seq: Key::from_value(get(seq))?,
            value: reading,
        })
    }

    fn number(&self) -> Result<Option<Num>> {
        match self.value {
            Reading::Skipped => Ok(None),
            Reading::Unmodelled => unsupported("a boolean or very large integer value"),
            Reading::Number(v, true) => Ok(Some(Num::Int(v as i64))),
            Reading::Number(v, false) => Ok(Some(Num::Float(v))),
        }
    }
}

fn is_falsy(value: &Value) -> bool {
    match value {
        Value::Null => true,
        Value::Bool(flag) => !flag,
        Value::Number(n) => n.as_f64() == Some(0.0),
        Value::String(text) => text.is_empty(),
        Value::Array(items) => items.is_empty(),
        Value::Object(map) => map.is_empty(),
    }
}

/// `float(event["t_mono_ns"])`.
fn t_mono(event: &PairEvent) -> Result<f64> {
    match event.t_mono_ns {
        Time::At(t) => Ok(t),
        Time::Missing => unsupported("an event without t_mono_ns"),
        Time::Unmodelled => unsupported("a t_mono_ns that is not a plain number"),
    }
}

/// `event["event_id"]`, handed back as it is.
fn event_id(event: &PairEvent) -> Result<Value> {
    event.event_id.clone().ok_or_else(|| Error::unsupported("an event without an event_id"))
}

// ---- calibration -----------------------------------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
struct Calibration {
    ok: bool,
    offset_ns: f64,
    drift: f64,
    uncertainty_ns: f64,
    markers: usize,
    reason: String,
    drift_estimated: bool,
}

impl Calibration {
    fn failed(markers: usize, reason: String) -> Self {
        Calibration { ok: false, offset_ns: 0.0, drift: 1.0, uncertainty_ns: 0.0, markers, reason, drift_estimated: true }
    }

    fn to_owner(&self, t_replica: f64) -> f64 {
        self.offset_ns + self.drift * t_replica
    }
}

/// `correlate(syncs_o, syncs_r, key=payload[sync_key])`: pairs of events with the same non-empty key, each key seen once
/// on each side, in the owner's order of first appearance.
fn correlate<'a>(owner: &[&'a PairEvent], replica: &[&'a PairEvent]) -> Vec<(&'a PairEvent, &'a PairEvent)> {
    type Index<'e> = (Vec<Key>, HashMap<Key, Vec<&'e PairEvent>>);
    fn index<'e>(events: &[&'e PairEvent]) -> Index<'e> {
        let mut order = Vec::new();
        let mut map: HashMap<Key, Vec<&PairEvent>> = HashMap::new();
        for event in events {
            let key = event.sync_key.clone();
            if key == Key::Null {
                continue;
            }
            match map.get_mut(&key) {
                Some(list) => list.push(event),
                None => {
                    order.push(key.clone());
                    map.insert(key, vec![event]);
                }
            }
        }
        (order, map)
    }
    let (order, owners) = index(owner);
    let (_, replicas) = index(replica);
    order
        .iter()
        .filter_map(|key| match (owners.get(key), replicas.get(key)) {
            (Some(o), Some(r)) if o.len() == 1 && r.len() == 1 => Some((o[0], r[0])),
            _ => None,
        })
        .collect()
}

/// `calibrate(pairs)` with the default minimum drift span.
fn calibrate(pairs: &[(&PairEvent, &PairEvent)]) -> Result<Calibration> {
    let mut points: Vec<(f64, f64)> = Vec::with_capacity(pairs.len());
    for (owner, replica) in pairs {
        if owner.t_mono_ns != Time::Missing && replica.t_mono_ns != Time::Missing {
            points.push((t_mono(replica)?, t_mono(owner)?));
        }
    }
    let n = points.len();
    if n < MIN_MARKERS {
        return Ok(Calibration::failed(n, format!("need {MIN_MARKERS} shared markers, have {n}")));
    }
    let max_x = points.iter().map(|p| p.0).fold(f64::NEG_INFINITY, f64::max);
    let min_x = points.iter().map(|p| p.0).fold(f64::INFINITY, f64::min);
    if max_x - min_x < MIN_DRIFT_SPAN_NS {
        let mut offsets: Vec<f64> = points.iter().map(|&(x, y)| y - x).collect();
        offsets.sort_by(f64::total_cmp);
        let offset = offsets[n / 2];
        let spread = offsets.iter().map(|o| (o - offset).abs()).fold(f64::NEG_INFINITY, f64::max);
        let span = trunc(max_x - min_x)?;
        return Ok(Calibration {
            ok: true,
            offset_ns: offset,
            drift: 1.0,
            uncertainty_ns: spread,
            markers: n,
            reason: format!("drift not estimable from markers spanning {span} ns; assumed 1"),
            drift_estimated: false,
        });
    }
    let count = n as f64;
    let mx = py_sum(points.iter().map(|p| p.0)) / count;
    let my = py_sum(points.iter().map(|p| p.1)) / count;
    let sxx = py_sum(points.iter().map(|&(x, _)| (x - mx) * (x - mx)));
    if sxx == 0.0 {
        return Ok(Calibration::failed(n, "markers do not span any time".into()));
    }
    let b = py_sum(points.iter().map(|&(x, y)| (x - mx) * (y - my))) / sxx;
    let a = my - b * mx;
    let spread = points.iter().map(|&(x, y)| (y - (a + b * x)).abs()).fold(f64::NEG_INFINITY, f64::max);
    Ok(Calibration { ok: true, offset_ns: a, drift: b, uncertainty_ns: spread, markers: n, reason: String::new(), drift_estimated: true })
}

// ---- the report ------------------------------------------------------------------------------------------------------

/// The `spec` of `pair_report` after the Python merged it over `DEFAULT_SPEC`.
struct Spec {
    owner_sync: String,
    replica_sync: String,
    truth: String,
    mirror: String,
    extrapolated: String,
    create: String,
    gap_factor: f64,
    min_gap_ns: f64,
    max_error: Option<Num>,
    latency_allowance_ns: i64,
}

impl Spec {
    fn from_value(spec: &Value) -> Result<Spec> {
        let map = spec.as_object().ok_or_else(|| Error::unsupported("a spec that is not an object"))?;
        let text = |name: &str| -> Result<String> {
            map.get(name).and_then(Value::as_str).map(str::to_owned).ok_or_else(|| Error::unsupported("a spec field that is not text"))
        };
        let number = |name: &str| -> Result<Num> { Num::from_value(map.get(name).unwrap_or(&NULL)) };
        let max_error = match map.get("max_error") {
            None | Some(Value::Null) => None,
            Some(value) => Some(Num::from_value(value)?),
        };
        Ok(Spec {
            owner_sync: text("owner_sync")?,
            replica_sync: text("replica_sync")?,
            truth: text("truth")?,
            mirror: text("mirror")?,
            extrapolated: text("extrapolated")?,
            create: text("create")?,
            gap_factor: number("gap_factor")?.float(),
            min_gap_ns: number("min_gap_ns")?.float(),
            max_error,
            latency_allowance_ns: trunc(number("latency_allowance_ns")?.float())?,
        })
    }
}

/// `sorted_values[min(len - 1, int(q * len))]`.
fn quantile(sorted: &[f64], q: f64) -> f64 {
    sorted[(sorted.len() - 1).min((q * sorted.len() as f64) as usize)]
}

struct Outage {
    start: i64,
    end: i64,
    silent: i64,
    from_event: Value,
    to_event: Value,
}

fn selected<'a>(events: &'a [PairEvent], kind: &str) -> Vec<&'a PairEvent> {
    events.iter().filter(|event| event.kind.as_deref() == Some(kind)).collect()
}

fn sort_by_time<'a>(events: &[&'a PairEvent]) -> Result<Vec<&'a PairEvent>> {
    let mut keyed: Vec<(f64, &PairEvent)> = events.iter().map(|e| Ok((t_mono(e)?, *e))).collect::<Result<_>>()?;
    keyed.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(Ordering::Equal));
    Ok(keyed.into_iter().map(|(_, e)| e).collect())
}

/// Owner and replica sessions captured at the same time, compared per correlated object: the Rust twin of
/// `hydralysis.trace_pairing.pair_report`. `spec` is the spec the Python already merged over `DEFAULT_SPEC`.
///
/// # Errors
///
/// [`Error::Unsupported`] for an event, key or value of a shape this port does not model (including every case in which the
/// Python would raise); the caller then runs the Python.
pub fn pair_report(owner_events: &[PairEvent], replica_events: &[PairEvent], spec: &Value) -> Result<Value> {
    let spec = Spec::from_value(spec)?;
    let syncs_owner = selected(owner_events, &spec.owner_sync);
    let syncs_replica = selected(replica_events, &spec.replica_sync);
    let calibration = calibrate(&correlate(&syncs_owner, &syncs_replica))?;

    let uncertainty =
        trunc(calibration.uncertainty_ns)?.checked_add(spec.latency_allowance_ns).ok_or_else(|| Error::unsupported("overflow"))?;
    let mut cal = Map::new();
    cal.insert("ok".into(), Value::Bool(calibration.ok));
    cal.insert("markers".into(), Value::from(calibration.markers));
    cal.insert("offset_ns".into(), int_value(calibration.offset_ns)?);
    cal.insert("drift".into(), Num::Float(calibration.drift).to_value()?);
    cal.insert("drift_estimated".into(), Value::Bool(calibration.drift_estimated));
    cal.insert("uncertainty_ns".into(), Value::from(uncertainty));
    cal.insert("spread_ns".into(), int_value(calibration.uncertainty_ns)?);
    cal.insert("units".into(), "ns (monotonic clock of each side)".into());
    cal.insert("reason".into(), calibration.reason.clone().into());
    let mut out = Map::new();
    out.insert("mode".into(), "pair".into());
    out.insert("roles".into(), roles());
    out.insert("calibration".into(), Value::Object(cal));
    if !calibration.ok {
        out.insert("usable".into(), Value::Bool(false));
        out.insert("objects".into(), Value::Object(Map::new()));
        out.insert(
            "note".into(),
            format!("the clocks could not be calibrated ({}): nothing is compared, every answer is unknown", calibration.reason).into(),
        );
        return Ok(Value::Object(out));
    }

    let truths = selected(owner_events, &spec.truth);
    let creates = selected(owner_events, &spec.create);
    let mirrors = selected(replica_events, &spec.mirror);
    let extrapolated = selected(replica_events, &spec.extrapolated);

    let object_id = |event: &PairEvent| -> String { event.object.py_str() };
    let mut on_owner = std::collections::HashSet::new();
    for event in truths.iter().chain(&creates) {
        on_owner.insert(object_id(event));
    }
    let mut on_replica = std::collections::HashSet::new();
    for event in mirrors.iter().chain(&extrapolated) {
        on_replica.insert(object_id(event));
    }
    let mut ids: Vec<&String> = on_owner.union(&on_replica).collect();
    ids.sort_by(|a, b| a.chars().count().cmp(&b.chars().count()).then_with(|| a.cmp(b)));

    // The events of each object, once, in their original order.
    let mut truths_by: HashMap<String, Vec<&PairEvent>> = HashMap::new();
    for event in &truths {
        truths_by.entry(object_id(event)).or_default().push(event);
    }
    let mut mirrors_by: HashMap<String, Vec<&PairEvent>> = HashMap::new();
    for event in &mirrors {
        mirrors_by.entry(object_id(event)).or_default().push(event);
    }

    let mut objects = Map::new();
    let mut owner_only = Vec::new();
    let mut replica_only = Vec::new();
    for id in ids {
        let mut entry = Map::new();
        let there_owner = on_owner.contains(id);
        let there_replica = on_replica.contains(id);
        let mut present: Vec<Value> = Vec::new();
        if there_owner {
            present.push("owner".into());
        }
        if there_replica {
            present.push("replica".into());
        }
        entry.insert("present_on".into(), Value::Array(present));
        if !there_replica {
            entry.insert("status".into(), "owner_only".into());
            let mut first = None;
            for event in creates.iter().chain(&truths) {
                if object_id(event) == *id {
                    first = Some(event_id(event)?);
                    break;
                }
            }
            entry.insert("first_event".into(), first.unwrap_or(Value::Null));
            owner_only.push(Value::String(id.clone()));
            objects.insert(id.clone(), Value::Object(entry));
            continue;
        }
        if !there_owner {
            entry.insert("status".into(), "replica_only".into());
            replica_only.push(Value::String(id.clone()));
            objects.insert(id.clone(), Value::Object(entry));
            continue;
        }
        let own = sort_by_time(truths_by.get(id).map_or(&[][..], Vec::as_slice))?;
        let rep = sort_by_time(mirrors_by.get(id).map_or(&[][..], Vec::as_slice))?;
        fill_paired(&mut entry, &own, &rep, &calibration, &spec, uncertainty)?;
        objects.insert(id.clone(), Value::Object(entry));
    }

    out.insert("usable".into(), Value::Bool(true));
    out.insert("objects".into(), Value::Object(objects));
    let mut extra = Map::new();
    extra.insert("count".into(), Value::from(extrapolated.len()));
    extra.insert("events".into(), Value::Array(extrapolated.iter().take(SHOWN_EXTRAPOLATED).map(|e| event_id(e)).collect::<Result<_>>()?));
    extra.insert("meaning".into(), "ticks where the replica showed a value it extrapolated, without owner data".into());
    out.insert("extrapolated".into(), Value::Object(extra));
    out.insert("owner_only".into(), Value::Array(owner_only));
    out.insert("replica_only".into(), Value::Array(replica_only));
    out.insert(
        "note".into(),
        "three-valued per owner value: reflected, not_reflected, unknown; a silent replica is never agreement".into(),
    );
    Ok(Value::Object(out))
}

fn roles() -> Value {
    let mut roles = Map::new();
    roles.insert("owner".into(), "authoritative order".into());
    roles.insert("replica".into(), "mapped onto the owner clock".into());
    Value::Object(roles)
}

/// The fields of an object with truth events on the owner and mirror events on the replica.
fn fill_paired(
    entry: &mut Map<String, Value>,
    own: &[&PairEvent],
    rep: &[&PairEvent],
    cal: &Calibration,
    spec: &Spec,
    uncertainty: i64,
) -> Result<()> {
    // The first mirror event per sequence number.
    let mut mirrored: HashMap<Key, &PairEvent> = HashMap::new();
    for event in rep {
        mirrored.entry(event.seq.clone()).or_insert(event);
    }
    let times: Vec<f64> = rep.iter().map(|e| Ok(cal.to_owner(t_mono(e)?))).collect::<Result<_>>()?;
    let mut spacing: Vec<f64> = times.windows(2).map(|w| w[1] - w[0]).collect();
    spacing.sort_by(f64::total_cmp);
    let median = if spacing.is_empty() { 0.0 } else { spacing[spacing.len() / 2] };
    let candidate = spec.gap_factor * median;
    let threshold = if candidate > spec.min_gap_ns { candidate } else { spec.min_gap_ns };

    let mut outages: Vec<Outage> = Vec::new();
    for (i, pair) in times.windows(2).enumerate() {
        let (a, b) = (pair[0], pair[1]);
        if b - a > threshold {
            outages.push(Outage {
                start: trunc(a)?,
                end: trunc(b)?,
                silent: trunc(b - a)?,
                from_event: event_id(rep[i])?,
                to_event: event_id(rep[i + 1])?,
            });
        }
    }
    if outages.iter().any(|o| o.start.abs() > EXACT || o.end.abs() > EXACT) {
        return unsupported("an outage beyond 2^53 ns");
    }

    let mut lags: Vec<f64> = Vec::new();
    for event in own {
        let seq = event.seq.clone();
        if let Some(mirror) = mirrored.get(&seq) {
            lags.push(cal.to_owner(t_mono(mirror)?) - t_mono(event)?);
        }
    }
    lags.sort_by(f64::total_cmp);
    let typical = if lags.is_empty() { 0.0 } else { quantile(&lags, 0.5) };

    let (mut reflected, mut not_reflected, mut unknown) = (0_i64, 0_i64, 0_i64);
    let mut unknown_events: Vec<Value> = Vec::new();
    let mut not_reflected_events: Vec<Value> = Vec::new();
    for event in own {
        let seq = event.seq.clone();
        if mirrored.contains_key(&seq) {
            reflected += 1;
            continue;
        }
        let expected = t_mono(event)? + typical;
        let inside = outages.iter().any(|o| o.start as f64 <= expected && expected <= o.end as f64);
        let beyond = times.last().is_none_or(|last| expected > *last);
        if inside || beyond {
            unknown += 1;
            unknown_events.push(event_id(event)?);
        } else {
            not_reflected += 1;
            not_reflected_events.push(event_id(event)?);
        }
    }

    // The owner's latest value at each mirror time: `own` is sorted by time, so the events at or before a time are a prefix.
    let owner_values: Vec<(f64, &PairEvent)> = own.iter().map(|e| Ok((t_mono(e)?, *e))).collect::<Result<_>>()?;
    let mut errors: Vec<(f64, Num, Value)> = Vec::new();
    for (event, now) in rep.iter().zip(&times) {
        let known = owner_values.partition_point(|(t, _)| *t <= *now);
        if known == 0 {
            continue;
        }
        let latest = owner_values[known - 1].1;
        if latest.value == Reading::Skipped || event.value == Reading::Skipped {
            continue;
        }
        if let (Some(latest), Some(shown)) = (latest.number()?, event.number()?) {
            errors.push((*now, latest.sub(shown)?, event_id(event)?));
        }
    }

    let mut answers = Map::new();
    answers.insert("reflected".into(), reflected.into());
    answers.insert("not_reflected".into(), not_reflected.into());
    answers.insert("unknown".into(), unknown.into());
    entry.insert("status".into(), "paired".into());
    entry.insert("truth_events".into(), Value::from(own.len()));
    entry.insert("mirror_events".into(), Value::from(rep.len()));
    entry.insert("answers".into(), Value::Object(answers));
    entry.insert("lag_ns".into(), lag_summary(&lags, typical)?);
    entry.insert("delay_estimate_ns".into(), if lags.is_empty() { Value::Null } else { int_value(quantile(&lags, 0.05))? });
    entry.insert(
        "delay_estimate_basis".into(),
        "the floor (5th percentile) of the lag distribution: scheduling slop only adds to a delay".into(),
    );
    entry.insert("delay_uncertainty_ns".into(), Value::from(uncertainty));
    entry.insert(
        "delay_uncertainty_basis".into(),
        "offset spread over the sync markers plus an allowance for the one-way transport latency the markers cannot separate from the clock offset"
            .into(),
    );
    let outage_values: Vec<Value> = outages
        .iter()
        .map(|o| {
            let mut m = Map::new();
            m.insert("start_owner_ns".into(), o.start.into());
            m.insert("end_owner_ns".into(), o.end.into());
            m.insert("silent_ns".into(), o.silent.into());
            m.insert("from_event".into(), o.from_event.clone());
            m.insert("to_event".into(), o.to_event.clone());
            m.insert("answer".into(), "unknown".into());
            m.insert("meaning".into(), "the replica reported nothing here; that is not agreement".into());
            Value::Object(m)
        })
        .collect();
    entry.insert("outages".into(), Value::Array(outage_values));
    entry.insert("unknown_events".into(), Value::Array(unknown_events.iter().take(SHOWN).cloned().collect()));
    entry.insert("unknown_total".into(), Value::from(unknown_events.len()));
    entry.insert("not_reflected_events".into(), Value::Array(not_reflected_events.iter().take(SHOWN).cloned().collect()));
    entry.insert("not_reflected_total".into(), Value::from(not_reflected_events.len()));
    if errors.is_empty() {
        return Ok(());
    }
    let magnitudes: Vec<Num> = errors.iter().map(|e| e.1.abs()).collect();
    let mut max_abs = magnitudes[0];
    for m in &magnitudes[1..] {
        if m.gt(max_abs) {
            max_abs = *m;
        }
    }
    let total = py_sum_nums(&magnitudes)?;
    let mean_abs = match total {
        Num::Int(v) => Num::Int(v.div_euclid(magnitudes.len() as i64)),
        Num::Float(v) => Num::Float(py_floordiv(v, magnitudes.len() as f64)),
    };
    let mut value_error = Map::new();
    value_error.insert("max_abs".into(), max_abs.to_value()?);
    value_error.insert("mean_abs".into(), mean_abs.to_value()?);
    value_error.insert("samples".into(), Value::from(errors.len()));
    value_error.insert("meaning".into(), "the owner's latest value at the mirror's mapped time minus the mirror's value".into());
    entry.insert("value_error".into(), Value::Object(value_error));
    if let Some(limit) = spec.max_error {
        entry.insert("divergence_intervals".into(), divergence(&errors, limit)?);
    }
    Ok(())
}

fn lag_summary(lags: &[f64], typical: f64) -> Result<Value> {
    if lags.is_empty() {
        return Ok(Value::Null);
    }
    let mut lag = Map::new();
    lag.insert("count".into(), Value::from(lags.len()));
    lag.insert("min".into(), int_value(lags[0])?);
    lag.insert("p50".into(), int_value(typical)?);
    lag.insert("p95".into(), int_value(quantile(lags, 0.95))?);
    lag.insert("max".into(), int_value(lags[lags.len() - 1])?);
    Ok(Value::Object(lag))
}

/// The runs of consecutive mirror samples whose error exceeds `limit`.
fn divergence(errors: &[(f64, Num, Value)], limit: Num) -> Result<Value> {
    let mut runs: Vec<Value> = Vec::new();
    let mut current: Option<Map<String, Value>> = None;
    for (t, error, id) in errors {
        if error.abs().gt(limit) {
            let run = match current.as_mut() {
                Some(run) => run,
                None => {
                    let mut run = Map::new();
                    run.insert("start_owner_ns".into(), int_value(*t)?);
                    run.insert("first_event".into(), id.clone());
                    run.insert("samples".into(), 0.into());
                    current.insert(run)
                }
            };
            run.insert("end_owner_ns".into(), int_value(*t)?);
            run.insert("last_event".into(), id.clone());
            let samples = run.get("samples").and_then(Value::as_i64).unwrap_or_default();
            run.insert("samples".into(), (samples + 1).into());
        } else if let Some(run) = current.take() {
            runs.push(Value::Object(run));
        }
    }
    if let Some(run) = current {
        runs.push(Value::Object(run));
    }
    Ok(Value::Array(runs))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floordiv_matches_python_cases() {
        // Python: 7.5 // 2 == 3.0, 6.0 // 4 == 1.0, 0.3 // 0.1 == 2.0
        assert_eq!(py_floordiv(7.5, 2.0), 3.0);
        assert_eq!(py_floordiv(6.0, 4.0), 1.0);
        assert_eq!(py_floordiv(0.3, 0.1), 2.0);
    }

    #[test]
    fn compensated_sum_recovers_cancelled_terms() {
        // Python 3.12+: sum([0.1] * 10) == 1.0 (the naive loop gives 0.9999999999999999)
        assert_eq!(py_sum(std::iter::repeat_n(0.1, 10)), 1.0);
    }

    #[test]
    fn uncalibrated_report_says_why() {
        let spec = json!({"owner_sync": "s", "replica_sync": "r", "sync_key": "n", "truth": "t", "mirror": "m", "extrapolated": "x",
            "create": "c", "key": "obj", "seq": "seq", "value": "value", "gap_factor": 5, "min_gap_ns": 1, "max_error": null,
            "latency_allowance_ns": 20});
        let report = pair_report(&[], &[], &spec).expect("an empty pairing is modelled");
        assert_eq!(report["usable"], json!(false));
        assert_eq!(report["calibration"]["reason"], json!("need 3 shared markers, have 0"));
        assert_eq!(report["calibration"]["drift"], json!(1.0));
    }

    #[test]
    fn events_of_an_unmodelled_shape_are_unsupported() {
        let bad = json!({"kind": "s", "payload": {"n": 1.5}, "t_mono_ns": 1});
        assert!(matches!(PairEvent::from_value(&bad, "n", "obj", "seq", "value"), Err(Error::Unsupported(_))));
        let not_object = json!([1]);
        assert!(matches!(PairEvent::from_value(&not_object, "n", "obj", "seq", "value"), Err(Error::Unsupported(_))));
    }

    #[test]
    fn a_session_is_paired_and_the_replica_silence_is_unknown() {
        let spec = json!({"owner_sync": "s", "replica_sync": "r", "sync_key": "n", "truth": "t", "mirror": "m", "extrapolated": "x",
            "create": "c", "key": "obj", "seq": "seq", "value": "value", "gap_factor": 5, "min_gap_ns": 1, "max_error": 2,
            "latency_allowance_ns": 0});
        let read = |events: Vec<Value>| -> Vec<PairEvent> {
            events.iter().map(|e| PairEvent::from_value(e, "n", "obj", "seq", "value").expect("modelled")).collect()
        };
        let mut owner = Vec::new();
        let mut replica = Vec::new();
        for n in 0..3_i64 {
            owner.push(json!({"event_id": format!("o{n}"), "kind": "s", "t_mono_ns": 1000 + n * 10, "payload": {"n": n}}));
            replica.push(json!({"event_id": format!("r{n}"), "kind": "r", "t_mono_ns": 500 + n * 10, "payload": {"n": n}}));
        }
        for seq in 0..4_i64 {
            owner.push(json!({"event_id": format!("t{seq}"), "kind": "t", "t_mono_ns": 2000 + seq * 100, "payload": {"obj": 1, "seq": seq, "value": 10 + seq}}));
        }
        // the replica mirrors seq 0 and 1 (value 5 off for seq 1), then falls silent
        replica.push(json!({"event_id": "m0", "kind": "m", "t_mono_ns": 1500, "payload": {"obj": 1, "seq": 0, "value": 10}}));
        replica.push(json!({"event_id": "m1", "kind": "m", "t_mono_ns": 1600, "payload": {"obj": 1, "seq": 1, "value": 6}}));
        let report = pair_report(&read(owner), &read(replica), &spec).expect("modelled");
        assert_eq!(report["usable"], json!(true));
        let object = &report["objects"]["1"];
        assert_eq!(object["status"], json!("paired"));
        assert_eq!(object["answers"], json!({"reflected": 2, "not_reflected": 0, "unknown": 2}));
        assert_eq!(object["value_error"]["max_abs"], json!(5));
        assert_eq!(object["divergence_intervals"][0]["samples"], json!(1));
    }
}
