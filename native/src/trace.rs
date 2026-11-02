//! The semantic trace's hot path in Rust: canonical JSON, the chained raw segment, keyed ids and the agent batch
//! decoder/encoder. The pure-Python twin is `hydralysis.trace_wire`; tests/test_trace_wire.py feeds both the same
//! input and requires identical bytes. See that module's docstring for the batch layout.

use hmac::{Hmac, Mac};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList, PyTuple};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

const GENESIS: &str = "hydra.trace.segment/1\n";
const MAGIC: u32 = 0x3142_5448;
const HEADER_BYTES: usize = 64;
const RECORD_BYTES: usize = 64;
const F_RET: u8 = 1;
const F_READ_FAILED: u8 = 2;
const F_TRUNCATED: u8 = 4;
const F_WIDE: u8 = 8;
const F_BUF: u8 = 16;

fn err(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

// ---- canonical JSON -------------------------------------------------------------------------------------------------
fn canon_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 || (c as u32) > 0x7e => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    let _ = write!(HexSink(out), "\\u{unit:04x}");
                }
            }
            c => out.push(c as u8),
        }
    }
    out.push(b'"');
}

struct HexSink<'a>(&'a mut Vec<u8>);

impl std::fmt::Write for HexSink<'_> {
    fn write_str(&mut self, s: &str) -> std::fmt::Result {
        self.0.extend_from_slice(s.as_bytes());
        Ok(())
    }
}

fn canon_write(value: &Value, out: &mut Vec<u8>) -> Result<(), String> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if n.is_f64() {
                return Err("not canonical: floating point number".into());
            }
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => canon_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canon_write(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // Keys are ASCII by contract, so the BTreeMap order is Python's sorted() order.
            let sorted: BTreeMap<&String, &Value> = map.iter().collect();
            out.push(b'{');
            for (i, (key, item)) in sorted.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                canon_string(key, out);
                out.push(b':');
                canon_write(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

fn canon_bytes(value: &Value) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(256);
    canon_write(value, &mut out)?;
    Ok(out)
}

fn py_to_value(obj: &Bound<'_, PyAny>) -> PyResult<Value> {
    if obj.is_none() {
        return Ok(Value::Null);
    }
    if let Ok(b) = obj.cast::<pyo3::types::PyBool>() {
        return Ok(Value::Bool(b.is_true()));
    }
    if obj.cast::<pyo3::types::PyInt>().is_ok() {
        if let Ok(v) = obj.extract::<u64>() {
            return Ok(Value::from(v));
        }
        return obj.extract::<i64>().map(Value::from).map_err(|_| err("integer out of range"));
    }
    if obj.cast::<pyo3::types::PyFloat>().is_ok() {
        return Err(err("not canonical: floating point number"));
    }
    if let Ok(s) = obj.extract::<String>() {
        return Ok(Value::String(s));
    }
    if let Ok(list) = obj.cast::<PyList>() {
        return list.iter().map(|item| py_to_value(&item)).collect::<PyResult<Vec<_>>>().map(Value::Array);
    }
    if let Ok(tuple) = obj.cast::<PyTuple>() {
        return tuple.iter().map(|item| py_to_value(&item)).collect::<PyResult<Vec<_>>>().map(Value::Array);
    }
    if let Ok(dict) = obj.cast::<PyDict>() {
        let mut map = Map::new();
        for (key, value) in dict.iter() {
            map.insert(key.str()?.to_string(), py_to_value(&value)?);
        }
        return Ok(Value::Object(map));
    }
    Err(err(format!("not canonical: {}", obj.get_type().name()?)))
}

/// The canonical bytes of a JSON value (the twin of `trace_wire.canon`).
#[pyfunction]
fn canon<'py>(py: Python<'py>, value: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyBytes>> {
    let v = py_to_value(value)?;
    Ok(PyBytes::new(py, &canon_bytes(&v).map_err(err)?))
}

/// HMAC-SHA256 of DATA under KEY, truncated to 128 bits, hex (the twin of `trace_wire.keyed_id`).
#[pyfunction]
fn keyed_id(key: &[u8], data: &[u8]) -> PyResult<String> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).map_err(|_| err("bad key"))?;
    mac.update(data);
    Ok(hex(&mac.finalize().into_bytes()[..16]))
}

fn keyed(key: &[u8], data: &[u8]) -> String {
    match <Hmac<Sha256> as Mac>::new_from_slice(key) {
        Ok(mut mac) => {
            mac.update(data);
            hex(&mac.finalize().into_bytes()[..16])
        }
        Err(_) => String::new(),
    }
}

// ---- the raw segment ------------------------------------------------------------------------------------------------
struct Chain {
    head: String,
    n: u64,
}

impl Chain {
    fn new(segment: &str) -> Self {
        Self { head: hex(&Sha256::digest(format!("{GENESIS}{segment}").as_bytes())), n: 0 }
    }

    fn push(&mut self, mut record: Map<String, Value>) -> Result<Vec<u8>, String> {
        record.insert("n".into(), Value::from(self.n));
        record.insert("prev".into(), Value::from(self.head.clone()));
        let hash = hex(&Sha256::digest(canon_bytes(&Value::Object(record.clone()))?));
        record.insert("hash".into(), Value::from(hash.clone()));
        let body = canon_bytes(&Value::Object(record))?;
        let mut line = format!("{:08x} ", crc32fast::hash(&body)).into_bytes();
        line.extend_from_slice(&body);
        line.push(b'\n');
        self.head = hash;
        self.n += 1;
        Ok(line)
    }
}

// ---- the batch ------------------------------------------------------------------------------------------------------
struct Header {
    producer_gen: u32,
    batch_seq: u32,
    qpc: u64,
    count: u32,
    attempted: u64,
    dropped: u64,
    read_failed: u64,
    no_ring: u64,
}

struct Rec {
    flags: u8,
    site: u16,
    ring: u16,
    qpc: u64,
    tid: u32,
    ring_seq: u32,
    ret_addr: u64,
    qpc_end: u64,
    retval: u64,
    last_error: u32,
    args: Vec<u64>,
    buf: Vec<u8>,
    buf_addr: u64,
}

fn u16_at(d: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([d[o], d[o + 1]])
}
fn u32_at(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn u64_at(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

fn decode(data: &[u8]) -> Result<(Header, Vec<Rec>), String> {
    if data.len() < HEADER_BYTES {
        return Err("batch shorter than its header".into());
    }
    if u32_at(data, 0) != MAGIC || u16_at(data, 4) != 1 || usize::from(u16_at(data, 6)) != HEADER_BYTES {
        return Err("not an HTB1 batch".into());
    }
    let plen = u32_at(data, 28) as usize;
    if HEADER_BYTES + plen != data.len() {
        return Err("batch length does not match its header".into());
    }
    let header = Header {
        producer_gen: u32_at(data, 8),
        batch_seq: u32_at(data, 12),
        qpc: u64_at(data, 16),
        count: u32_at(data, 24),
        attempted: u64_at(data, 32),
        dropped: u64_at(data, 40),
        read_failed: u64_at(data, 48),
        no_ring: u64_at(data, 56),
    };
    let mut records = Vec::with_capacity(header.count as usize);
    let mut cursor = HEADER_BYTES;
    for _ in 0..header.count {
        if cursor + RECORD_BYTES > data.len() {
            return Err("record runs past the batch".into());
        }
        let size = usize::from(u16_at(data, cursor));
        let nargs = usize::from(u16_at(data, cursor + 52));
        let buflen = usize::from(u16_at(data, cursor + 54));
        if size != RECORD_BYTES + 8 * nargs + buflen.div_ceil(8) * 8 || cursor + size > data.len() {
            return Err("record size is inconsistent".into());
        }
        let args = (0..nargs).map(|i| u64_at(data, cursor + RECORD_BYTES + 8 * i)).collect();
        let start = cursor + RECORD_BYTES + 8 * nargs;
        records.push(Rec {
            flags: data[cursor + 3],
            site: u16_at(data, cursor + 4),
            ring: u16_at(data, cursor + 6),
            qpc: u64_at(data, cursor + 8),
            tid: u32_at(data, cursor + 16),
            ring_seq: u32_at(data, cursor + 20),
            ret_addr: u64_at(data, cursor + 24),
            qpc_end: u64_at(data, cursor + 32),
            retval: u64_at(data, cursor + 40),
            last_error: u32_at(data, cursor + 48),
            args,
            buf: data[start..start + buflen].to_vec(),
            buf_addr: u64_at(data, cursor + 56),
        });
        cursor += size;
    }
    if cursor != data.len() {
        return Err("bytes after the last record".into());
    }
    Ok((header, records))
}

/// Decode a batch into `(header dict, [record dict])` (the twin of `trace_wire.decode_batch`).
#[pyfunction]
fn decode_batch<'py>(py: Python<'py>, data: &[u8]) -> PyResult<(Bound<'py, PyDict>, Bound<'py, PyList>)> {
    let (h, records) = decode(data).map_err(err)?;
    let header = PyDict::new(py);
    header.set_item("producer_gen", h.producer_gen)?;
    header.set_item("batch_seq", h.batch_seq)?;
    header.set_item("qpc", h.qpc)?;
    header.set_item("count", h.count)?;
    header.set_item("attempted", h.attempted)?;
    header.set_item("dropped", h.dropped)?;
    header.set_item("read_failed", h.read_failed)?;
    header.set_item("no_ring", h.no_ring)?;
    let list = PyList::empty(py);
    for r in records {
        let d = PyDict::new(py);
        d.set_item("kind", 1)?;
        d.set_item("flags", r.flags)?;
        d.set_item("site", r.site)?;
        d.set_item("ring", r.ring)?;
        d.set_item("qpc", r.qpc)?;
        d.set_item("tid", r.tid)?;
        d.set_item("ring_seq", r.ring_seq)?;
        d.set_item("ret_addr", r.ret_addr)?;
        d.set_item("qpc_end", r.qpc_end)?;
        d.set_item("retval", r.retval)?;
        d.set_item("last_error", r.last_error)?;
        d.set_item("args", r.args)?;
        d.set_item("buf", PyBytes::new(py, &r.buf))?;
        d.set_item("buf_addr", r.buf_addr)?;
        list.append(d)?;
    }
    Ok((header, list))
}

// ---- the encoder ----------------------------------------------------------------------------------------------------
#[derive(Clone)]
struct Site {
    name: String,
    kind: String,
    module: Option<String>,
    va: u64,
    payload_mode: bool,
}

fn tick_ns(ticks: u64, freq: u64) -> u64 {
    u64::try_from(u128::from(ticks) * 1_000_000_000 / u128::from(freq)).unwrap_or(u64::MAX)
}

fn normalize_path(units: &[u8]) -> Vec<u8> {
    let mut out = units.to_vec();
    let mut i = 0;
    while i + 1 < out.len() {
        if out[i + 1] == 0 {
            if (0x41..=0x5A).contains(&out[i]) {
                out[i] += 32;
            } else if out[i] == 0x2F {
                out[i] = 0x5C;
            }
        }
        i += 2;
    }
    out
}

fn cut_at_nul(units: &[u8]) -> &[u8] {
    let mut i = 0;
    while i + 1 < units.len() {
        if units[i] == 0 && units[i + 1] == 0 {
            return &units[..i];
        }
        i += 2;
    }
    units
}

fn is_device_path(units: &[u8]) -> bool {
    let mut head = Vec::new();
    let end = units.len().min(16);
    let mut i = 0;
    while i + 1 < end {
        if units[i + 1] != 0 {
            break;
        }
        head.push(units[i]);
        i += 2;
    }
    if !(head.starts_with(b"\\\\.\\") || head.starts_with(b"\\\\?\\")) {
        return false;
    }
    let rest = &head[4..];
    !(rest.len() >= 2 && rest[1] == b':' && rest[0].is_ascii_alphabetic())
}

/// Turns agent batches into chained TRACE-1 events (the twin of `trace_wire.SegmentEncoder`).
#[pyclass]
struct SegmentEncoder {
    source_id: String,
    producer_gen: u32,
    process_id: u32,
    sites: HashMap<u16, Site>,
    key: Vec<u8>,
    freq: u64,
    payload_ok: bool,
    max_payload: usize,
    chain: Chain,
    source_seq: u64,
    ring_next: HashMap<u16, u32>,
    batch_next: Option<u32>,
    dropped_seen: u64,
    handles: HashMap<u64, (Option<String>, bool)>,
    stats: BTreeMap<&'static str, u64>,
}

const STAT_KEYS: [&str; 15] = [
    "batches", "records", "events", "gaps", "ring_gaps", "transport_gaps", "dropped_in_band", "read_failures",
    "payload_refused", "last_attempted", "last_dropped", "last_read_failed", "last_no_ring", "bad_batches", "dummy",
];

impl SegmentEncoder {
    fn stat(&mut self, key: &'static str, add: u64) {
        *self.stats.entry(key).or_insert(0) += add;
    }

    fn event(&mut self, kind: &str, t_ns: u64, tid: Option<u32>, payload: Value, va: u64, callstack: &[u64], module: Option<&str>) -> Result<Vec<u8>, String> {
        let mut e = Map::new();
        e.insert("kind".into(), kind.into());
        e.insert("source_id".into(), self.source_id.clone().into());
        e.insert("source_seq".into(), self.source_seq.into());
        e.insert("producer_gen".into(), self.producer_gen.into());
        e.insert("clock_domain".into(), "qpc-10mhz".into());
        e.insert("t_mono_ns".into(), t_ns.into());
        e.insert("process_id".into(), self.process_id.into());
        e.insert("confidence".into(), "exact".into());
        e.insert("acquisition".into(), "atomic".into());
        e.insert("payload".into(), payload);
        if let Some(t) = tid {
            e.insert("thread_id".into(), t.into());
        }
        if va != 0 {
            e.insert("va".into(), va.into());
        }
        if !callstack.is_empty() {
            e.insert("callstack".into(), callstack.iter().map(|v| Value::from(*v)).collect::<Vec<_>>().into());
        }
        if let Some(m) = module {
            if !m.is_empty() {
                e.insert("module".into(), m.into());
            }
        }
        self.source_seq += 1;
        self.stat("events", 1);
        self.chain.push(e)
    }

    fn buffer(&mut self, site: &Site, r: &Rec, artifacts: &mut BTreeMap<String, Vec<u8>>) -> Option<Value> {
        if r.flags & F_BUF == 0 {
            return None;
        }
        let mut entry = Map::new();
        entry.insert("addr".into(), r.buf_addr.into());
        if r.flags & F_READ_FAILED != 0 {
            self.stat("read_failures", 1);
            entry.insert("read_failed".into(), true.into());
            entry.insert("len".into(), 0.into());
            return Some(Value::Object(entry));
        }
        let raw: &[u8] = if r.flags & F_WIDE != 0 { cut_at_nul(&r.buf) } else { &r.buf };
        entry.insert("id".into(), keyed(&self.key, raw).into());
        entry.insert("len".into(), raw.len().into());
        entry.insert("truncated".into(), (r.flags & F_TRUNCATED != 0).into());
        if site.payload_mode {
            if self.payload_ok {
                let kept = &raw[..raw.len().min(self.max_payload)];
                let digest = hex(&Sha256::digest(kept));
                artifacts.insert(digest.clone(), kept.to_vec());
                entry.insert("artifact".into(), json!({"sha256": digest, "len": kept.len(), "export": false}));
            } else {
                self.stat("payload_refused", 1);
                entry.insert("payload".into(), "payload-not-authorized".into());
            }
        }
        Some(Value::Object(entry))
    }

    #[allow(clippy::too_many_lines)]
    fn call(&mut self, r: &Rec, artifacts: &mut BTreeMap<String, Vec<u8>>) -> Result<Vec<u8>, String> {
        let t0 = tick_ns(r.qpc, self.freq);
        let Some(site) = self.sites.get(&r.site).cloned() else {
            return self.event("core.error", t0, Some(r.tid), json!({"error": "unknown-site", "site": r.site}), 0, &[], None);
        };
        let call = format!("{}:{}", r.ring, r.ring_seq);
        let stack: Vec<u64> = if r.ret_addr != 0 { vec![r.ret_addr] } else { vec![] };
        let has_ret = r.flags & F_RET != 0;
        let buf = self.buffer(&site, r, artifacts);
        let t_end = tick_ns(if r.qpc_end != 0 { r.qpc_end } else { r.qpc }, self.freq);
        let mut out = Vec::new();
        let arg = |i: usize| r.args.get(i).copied();
        let with_call = |mut v: Value| {
            if let Value::Object(m) = &mut v {
                m.insert("call".into(), call.clone().into());
            }
            v
        };
        let module = site.module.as_deref();
        match site.kind.as_str() {
            "open" => {
                let path: &[u8] = if r.flags & F_READ_FAILED != 0 { &[] } else { &r.buf };
                let norm_full = normalize_path(&path[..path.len() / 2 * 2]);
                let norm = cut_at_nul(&norm_full).to_vec();
                let device = is_device_path(path);
                let ok = has_ret && r.retval != u64::MAX && r.retval != 0;
                let rid = if r.flags & F_READ_FAILED != 0 { None } else { Some(keyed(&self.key, &norm)) };
                let payload = json!({
                    "api": site.name, "resource_kind": if device { "device" } else { "file" }, "resource_id": rid,
                    "path_len": norm.len(), "truncated": r.flags & F_TRUNCATED != 0,
                    "access": arg(1).map(|v| v & 0xFFFF_FFFF), "share": arg(2).map(|v| v & 0xFFFF_FFFF),
                    "disposition": arg(4).map(|v| v & 0xFFFF_FFFF),
                    "handle": if has_ret { Some(r.retval) } else { None }, "ok": ok, "last_error": r.last_error,
                    "read_failed": r.flags & F_READ_FAILED != 0, "buf_addr": r.buf_addr});
                if ok {
                    self.handles.insert(r.retval, (rid.clone(), device));
                }
                out.extend(self.event("core.resource.open", t_end, Some(r.tid), with_call(payload), site.va, &stack, module)?);
                if device {
                    let p = json!({"api": site.name, "resource_id": rid, "handle": if has_ret { Some(r.retval) } else { None }, "ok": ok});
                    out.extend(self.event("driver.device_open", t_end, Some(r.tid), with_call(p), site.va, &stack, module)?);
                }
            }
            "ioctl" => {
                let handle = arg(0).unwrap_or(0);
                let code = arg(1).map_or(0, |v| v & 0xFFFF_FFFF);
                let known = self.handles.get(&handle).cloned();
                let ok = has_ret && (r.retval & 0xFFFF_FFFF) != 0;
                let rid = known.as_ref().and_then(|k| k.0.clone());
                let unresolved = if known.is_some() { Value::Null } else { Value::from("lifetime-unresolved") };
                let in_size = arg(3).map_or(0, |v| v & 0xFFFF_FFFF);
                let out_size = arg(5).map_or(0, |v| v & 0xFFFF_FFFF);
                let ok_v = if has_ret { Value::from(ok) } else { Value::Null };
                let p = json!({"api": site.name, "handle": handle, "resource_id": rid, "resource_unresolved": unresolved,
                    "op": "ioctl", "bytes_in": in_size, "bytes_out": out_size, "ok": ok_v});
                out.extend(self.event("core.resource.write", t0, Some(r.tid), with_call(p), site.va, &stack, module)?);
                let mut p = json!({"api": site.name, "handle": handle, "resource_id": rid, "resource_unresolved": unresolved,
                    "in_size": in_size, "out_size": out_size, "code": code, "device_type": code >> 16,
                    "access": (code >> 14) & 3, "function": (code >> 2) & 0xFFF, "method": code & 3, "ok": ok_v,
                    "last_error": r.last_error, "end_ns": t_end});
                if let (Some(b), Value::Object(m)) = (buf, &mut p) {
                    m.insert("in_buffer".into(), b);
                }
                out.extend(self.event("driver.ioctl", t0, Some(r.tid), with_call(p), site.va, &stack, module)?);
            }
            "devquery" => {
                let family = if site.name.to_lowercase().starts_with("cm_") { "driver.cfgmgr" } else { "driver.setupapi" };
                let ret = if has_ret { Value::from(r.retval) } else { Value::Null };
                let mut p = json!({"api": site.name, "resource_kind": "device-enum", "ret": ret, "last_error": r.last_error, "args": r.args});
                let query_id = buf.as_ref().and_then(|b| b.get("id")).cloned().unwrap_or(Value::Null);
                if let (Some(b), Value::Object(m)) = (&buf, &mut p) {
                    m.insert("query".into(), b.clone());
                    m.insert("resource_id".into(), query_id.clone());
                }
                out.extend(self.event("core.resource.open", t0, Some(r.tid), with_call(p), site.va, &stack, module)?);
                let p = json!({"api": site.name, "ret": ret, "last_error": r.last_error, "query_id": query_id});
                out.extend(self.event(family, t0, Some(r.tid), with_call(p), site.va, &stack, module)?);
            }
            _ => {
                let mut p = json!({"site": site.name, "args": r.args});
                if let (Some(b), Value::Object(m)) = (buf, &mut p) {
                    m.insert("buf".into(), b);
                }
                out.extend(self.event("core.function.enter", t0, Some(r.tid), with_call(p), site.va, &stack, module)?);
                if has_ret {
                    let p = json!({"site": site.name, "ret": r.retval, "last_error": r.last_error});
                    out.extend(self.event("core.function.exit", t_end, Some(r.tid), with_call(p), site.va, &stack, module)?);
                }
            }
        }
        Ok(out)
    }

    fn encode(&mut self, data: &[u8], artifacts: &mut BTreeMap<String, Vec<u8>>) -> Result<(Vec<u8>, u32, usize), String> {
        let (header, records) = match decode(data) {
            Ok(v) => v,
            Err(e) => {
                self.stat("bad_batches", 1);
                return Err(e);
            }
        };
        let mut out = Vec::new();
        let t_flush = tick_ns(header.qpc, self.freq);
        if header.producer_gen != self.producer_gen {
            return Err(format!("batch is from producer generation {}, this encoder is generation {}", header.producer_gen, self.producer_gen));
        }
        if let Some(next) = self.batch_next {
            if header.batch_seq != next {
                let lost = header.batch_seq.wrapping_sub(next);
                self.stat("transport_gaps", 1);
                self.stat("gaps", 1);
                let p = json!({"reason": "producer-lost", "hop": "transport", "batches_missing": lost, "first_missing_batch": next, "out_of_band": false});
                out.extend(self.event("core.capture.gap", t_flush, None, p, 0, &[], None)?);
            }
        }
        self.batch_next = Some(header.batch_seq.wrapping_add(1));
        self.stat("batches", 1);
        self.stat("records", records.len() as u64);
        let mut keyed_idx: Vec<(u16, u32, usize)> = records
            .iter()
            .enumerate()
            .map(|(i, r)| (r.ring, r.ring_seq.wrapping_sub(self.ring_next.get(&r.ring).copied().unwrap_or(0)), i))
            .collect();
        keyed_idx.sort_by_key(|k| (k.0, k.1, k.2));
        let mut before: HashMap<usize, u32> = HashMap::new();
        for (_, _, i) in keyed_idx {
            let r = &records[i];
            let expect = self.ring_next.get(&r.ring).copied().unwrap_or(0);
            let missing = r.ring_seq.wrapping_sub(expect);
            if missing != 0 {
                before.insert(i, missing);
            }
            self.ring_next.insert(r.ring, r.ring_seq.wrapping_add(1));
        }
        let new_drops = header.dropped.saturating_sub(self.dropped_seen);
        self.dropped_seen = self.dropped_seen.max(header.dropped);
        let mut explained = new_drops;
        let mut order: Vec<usize> = (0..records.len()).collect();
        order.sort_by_key(|&i| (records[i].qpc, records[i].ring, records[i].ring_seq, i));
        for i in order {
            let r = &records[i];
            if let Some(&missing) = before.get(&i) {
                let ring_part = u64::from(missing).min(explained);
                explained -= ring_part;
                self.stat("dropped_in_band", ring_part);
                self.stat("ring_gaps", 1);
                self.stat("gaps", 1);
                let first = self.source_seq;
                self.source_seq += u64::from(missing);
                let reason = if ring_part == u64::from(missing) { "ring-overflow" } else { "producer-lost" };
                let p = json!({"reason": reason, "dropped": missing, "ring": r.ring, "out_of_band": false,
                    "first_missing_source_seq": first, "last_missing_source_seq": first + u64::from(missing) - 1,
                    "attributed_to_overflow": ring_part});
                out.extend(self.event("core.capture.gap", tick_ns(r.qpc, self.freq), Some(r.tid), p, 0, &[], None)?);
            }
            out.extend(self.call(r, artifacts)?);
        }
        self.stats.insert("last_attempted", header.attempted);
        self.stats.insert("last_dropped", header.dropped);
        self.stats.insert("last_read_failed", header.read_failed);
        self.stats.insert("last_no_ring", header.no_ring);
        Ok((out, header.batch_seq, records.len()))
    }
}

fn dict_str<'py>(d: &Bound<'py, PyDict>, key: &str) -> PyResult<Option<String>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(Some(v.extract()?)),
        _ => Ok(None),
    }
}

#[pymethods]
impl SegmentEncoder {
    #[new]
    #[pyo3(signature = (segment_id, source_id, producer_gen, process_id, sites, key, qpc_freq, payload_authorized=false, max_payload=4096))]
    #[allow(clippy::too_many_arguments)]
    fn new(
        segment_id: &str,
        source_id: &str,
        producer_gen: u32,
        process_id: u32,
        sites: &Bound<'_, PyDict>,
        key: &[u8],
        qpc_freq: u64,
        payload_authorized: bool,
        max_payload: usize,
    ) -> PyResult<Self> {
        if qpc_freq == 0 {
            return Err(err("qpc_freq must be positive"));
        }
        let mut table = HashMap::new();
        for (k, v) in sites.iter() {
            let d = v.cast::<PyDict>().map_err(|_| err("a site is a dict"))?;
            let id: u16 = k.extract()?;
            table.insert(
                id,
                Site {
                    name: dict_str(d, "name")?.unwrap_or_default(),
                    kind: dict_str(d, "kind")?.unwrap_or_else(|| "call".into()),
                    module: dict_str(d, "module")?,
                    va: match d.get_item("va")? {
                        Some(x) if !x.is_none() => x.extract()?,
                        _ => 0,
                    },
                    payload_mode: dict_str(d, "buf")?.as_deref() == Some("payload"),
                },
            );
        }
        let mut stats = BTreeMap::new();
        for key in STAT_KEYS {
            if key != "dummy" {
                stats.insert(key, 0);
            }
        }
        Ok(Self {
            source_id: source_id.into(),
            producer_gen,
            process_id,
            sites: table,
            key: key.to_vec(),
            freq: qpc_freq,
            payload_ok: payload_authorized,
            max_payload,
            chain: Chain::new(segment_id),
            source_seq: 0,
            ring_next: HashMap::new(),
            batch_next: None,
            dropped_seen: 0,
            handles: HashMap::new(),
            stats,
        })
    }

    #[getter]
    fn head(&self) -> String {
        self.chain.head.clone()
    }

    #[getter]
    fn count(&self) -> u64 {
        self.chain.n
    }

    #[getter]
    fn source_seq(&self) -> u64 {
        self.source_seq
    }

    #[getter]
    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let d = PyDict::new(py);
        for (k, v) in &self.stats {
            d.set_item(k, v)?;
        }
        Ok(d)
    }

    #[pyo3(signature = (kind, t_ns, payload, tid=None, skip=0))]
    fn encode_event<'py>(&mut self, py: Python<'py>, kind: &str, t_ns: u64, payload: &Bound<'py, PyAny>, tid: Option<u32>, skip: u64) -> PyResult<Bound<'py, PyBytes>> {
        let value = py_to_value(payload)?;
        self.source_seq += skip;
        if kind == "core.capture.gap" {
            self.stat("gaps", 1);
        }
        let line = self.event(kind, t_ns, tid, value, 0, &[], None).map_err(err)?;
        Ok(PyBytes::new(py, &line))
    }

    fn encode_batch<'py>(&mut self, py: Python<'py>, data: &[u8]) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyDict>, Bound<'py, PyDict>)> {
        let mut artifacts = BTreeMap::new();
        let (lines, batch_seq, records) = self.encode(data, &mut artifacts).map_err(err)?;
        let art = PyDict::new(py);
        for (k, v) in artifacts {
            art.set_item(k, PyBytes::new(py, &v))?;
        }
        let info = PyDict::new(py);
        info.set_item("records", records)?;
        info.set_item("batch_seq", batch_seq)?;
        Ok((PyBytes::new(py, &lines), art, info))
    }

    #[pyo3(signature = (rings, t_ns, no_ring=0))]
    fn finalize<'py>(&mut self, py: Python<'py>, rings: &Bound<'py, PyList>, t_ns: u64, no_ring: u64) -> PyResult<Bound<'py, PyBytes>> {
        let mut rows: Vec<(u16, u64, u64)> = Vec::new();
        for row in rings.iter() {
            let d = row.cast::<PyDict>().map_err(|_| err("a ring row is a dict"))?;
            let get = |k: &str| -> PyResult<u64> { Ok(d.get_item(k)?.map(|v| v.extract::<u64>()).transpose()?.unwrap_or(0)) };
            rows.push((get("ring")?.try_into().map_err(|_| err("ring id"))?, get("attempted")?, get("dropped")?));
        }
        rows.sort_by_key(|r| r.0);
        let mut out = Vec::new();
        for (ring, attempted, dropped) in rows {
            let expect = self.ring_next.get(&ring).copied().unwrap_or(0);
            let missing = (attempted as u32).wrapping_sub(expect);
            if attempted >= u64::from(expect) && missing != 0 {
                let first = self.source_seq;
                self.source_seq += u64::from(missing);
                self.ring_next.insert(ring, attempted as u32);
                self.stat("ring_gaps", 1);
                self.stat("gaps", 1);
                let reason = if dropped >= u64::from(missing) { "ring-overflow" } else { "producer-lost" };
                let p = json!({"reason": reason, "dropped": missing, "ring": ring, "out_of_band": true,
                    "first_missing_source_seq": first, "last_missing_source_seq": first + u64::from(missing) - 1});
                out.extend(self.event("core.capture.gap", t_ns, None, p, 0, &[], None).map_err(err)?);
            }
        }
        if no_ring != 0 {
            self.stat("gaps", 1);
            let p = json!({"reason": "budget", "dropped": no_ring, "out_of_band": true, "detail": "threads past the agent's ring budget"});
            out.extend(self.event("core.capture.gap", t_ns, None, p, 0, &[], None).map_err(err)?);
        }
        Ok(PyBytes::new(py, &out))
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(canon, module)?)?;
    module.add_function(wrap_pyfunction!(keyed_id, module)?)?;
    module.add_function(wrap_pyfunction!(decode_batch, module)?)?;
    module.add_class::<SegmentEncoder>()?;
    Ok(())
}
