//! Reading a chained raw segment: the fast path of `trace_pump.SegmentTail` and `trace_capture.verify_segment`.
//!
//! Both walk a segment's lines checking the CRC frame, the numbering, the back link and the record hash. The hash is
//! checked on the line's own bytes (cut the `"hash"` member out, SHA-256 the rest), the way
//! `trace_canon.body_hash_matches` does; a line that does not pass that, or anything else unusual, is never judged
//! here: the scan stops in front of it and the Python twin decides, so what is accepted does not change.

use super::{canon_bytes, hex};
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};
use serde_json::Value;
use sha2::{Digest, Sha256};

/// A JSON value as Python objects, without the `hash` member of the top-level object when SKIP_HASH. None when a number
/// is not an integer (the writer never emits one; Python's `json` would keep its exact form, this would not).
fn to_py<'py>(
    py: Python<'py>,
    value: &Value,
    skip_hash: bool,
) -> PyResult<Option<Bound<'py, PyAny>>> {
    Ok(Some(match value {
        Value::Null => py.None().into_bound(py),
        Value::Bool(b) => b.into_pyobject(py)?.to_owned().into_any(),
        Value::Number(n) => {
            if let Some(u) = n.as_u64() {
                u.into_pyobject(py)?.into_any()
            } else if let Some(i) = n.as_i64() {
                i.into_pyobject(py)?.into_any()
            } else {
                return Ok(None);
            }
        }
        Value::String(s) => s.into_pyobject(py)?.into_any(),
        Value::Array(items) => {
            let list = PyList::empty(py);
            for item in items {
                match to_py(py, item, false)? {
                    Some(v) => list.append(v)?,
                    None => return Ok(None),
                }
            }
            list.into_any()
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (key, item) in map {
                if skip_hash && key == "hash" {
                    continue;
                }
                match to_py(py, item, false)? {
                    Some(v) => dict.set_item(key, v)?,
                    None => return Ok(None),
                }
            }
            dict.into_any()
        }
    }))
}

/// SHA-256 hex of BODY with its `"hash":"<claimed>"` member cut out, or None when the body is not in the shape this
/// check understands (the member is not there exactly once, or has no neighbour comma).
fn cut_hash(body: &[u8], claimed: &str) -> Option<String> {
    let mut member = Vec::with_capacity(claimed.len() + 9);
    member.extend_from_slice(b"\"hash\":\"");
    member.extend_from_slice(claimed.as_bytes());
    member.push(b'"');
    let finder = memchr::memmem::Finder::new(&member);
    let at = finder.find(body)?;
    if finder.find(&body[at + 1..]).is_some() {
        return None;
    }
    let after = at + member.len();
    let mut hasher = Sha256::new();
    if at > 0 && body[at - 1] == b',' {
        hasher.update(&body[..at - 1]);
        hasher.update(&body[after..]);
    } else if at > 0 && body[at - 1] == b'{' && body.get(after) == Some(&b',') {
        hasher.update(&body[..at]);
        hasher.update(&body[after + 1..]);
    } else {
        return None;
    }
    Some(hex(&hasher.finalize()))
}

/// One line that passes the CRC frame, parses to an object with integer `n` and string `prev` and `hash`, and whose hash
/// is that of its own bytes. None for anything else.
fn accept(line: &[u8]) -> Option<(Value, u64, String, String)> {
    if !crate::frame_ok(line) {
        return None;
    }
    let body = &line[9..];
    let value: Value = serde_json::from_slice(body).ok()?;
    let object = value.as_object()?;
    let n = object.get("n")?.as_u64()?;
    let prev = object.get("prev")?.as_str()?.to_owned();
    let hash = object.get("hash")?.as_str()?.to_owned();
    if hash.len() != 64 || cut_hash(body, &hash).as_deref() != Some(hash.as_str()) {
        return None;
    }
    Some((value, n, prev, hash))
}

/// Walk the complete lines of DATA from CURSOR while they extend the chain after record COUNT with head HEAD.
/// Returns `(cursor, count, head, events, stopped)`: the offset after the last accepted line, the records accepted so
/// far in all, the new head, the accepted events past the first SKIP records (without `hash`), at most LIMIT of them,
/// and `stopped` true when a complete line was refused by the fast path (the caller judges it, then calls again).
#[pyfunction]
#[pyo3(signature = (data, cursor, count, head, skip, limit))]
#[allow(clippy::type_complexity)]
pub fn scan_chain<'py>(
    py: Python<'py>,
    data: &[u8],
    cursor: usize,
    count: u64,
    head: &str,
    skip: u64,
    limit: usize,
) -> PyResult<(usize, u64, String, Bound<'py, PyList>, bool)> {
    let events = PyList::empty(py);
    let mut at = cursor.min(data.len());
    let mut count = count;
    let mut head = head.to_owned();
    let mut returned = 0usize;
    let mut stopped = false;
    while returned < limit {
        let Some(found) = memchr::memchr(b'\n', &data[at..]) else {
            break;
        };
        let end = at + found;
        let Some((value, n, prev, hash)) = accept(&data[at..end]) else {
            stopped = true;
            break;
        };
        if n != count || prev != head {
            stopped = true;
            break;
        }
        if count + 1 > skip {
            match to_py(py, &value, true)? {
                Some(event) => {
                    events.append(event)?;
                    returned += 1;
                }
                None => {
                    stopped = true;
                    break;
                }
            }
        }
        count += 1;
        head = hash;
        at = end + 1;
    }
    Ok((at, count, head, events, stopped))
}

/// Walk the whole segment FILE the way `trace_capture.verify_segment` does, with the GIL released: CRC, numbering,
/// chain and the canonical record hash. None when the file holds a line this walk does not judge (the Python twin
/// then does the whole walk).
#[pyfunction]
pub fn verify_segment_file(py: Python<'_>, path: &str, genesis: &str) -> PyResult<Option<Verdict>> {
    let data = match std::fs::read(path) {
        Ok(data) => data,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(Some(("missing".into(), 0, None, None, None)))
        }
        Err(e) => return Err(super::err(format!("{e}"))),
    };
    Ok(py.detach(|| verify(&data, genesis)))
}

type Verdict = (String, u64, Option<usize>, Option<u64>, Option<String>);

fn verify(data: &[u8], genesis: &str) -> Option<Verdict> {
    if data.is_empty() {
        return Some(("empty".into(), 0, None, None, None));
    }
    let mut previous = genesis.to_owned();
    let (mut expect_n, mut cursor, mut records) = (0u64, 0usize, 0u64);
    while cursor < data.len() {
        let Some(found) = memchr::memchr(b'\n', &data[cursor..]) else {
            return Some(("torn-tail".into(), records, Some(cursor), None, None));
        };
        let end = cursor + found;
        let line = &data[cursor..end];
        if !crate::frame_ok(line) {
            let outcome = if end + 1 < data.len() {
                "corrupt"
            } else {
                "torn-tail"
            };
            return Some((outcome.into(), records, Some(cursor), None, None));
        }
        let body = &line[9..];
        let value: Value = serde_json::from_slice(body).ok()?;
        let object = value.as_object()?;
        let n = object.get("n").and_then(Value::as_u64);
        let prev = object.get("prev").and_then(Value::as_str);
        let claimed = object.get("hash").and_then(Value::as_str);
        // `record_hash`: the canonical form of the record without its hash (a body that is not canonical fails here).
        let hash_ok = match claimed {
            Some(hash) => {
                let mut rest = object.clone();
                rest.remove("hash");
                let canonical = canon_bytes(&Value::Object(rest)).ok()?;
                hex(&Sha256::digest(&canonical)) == hash
            }
            None => false,
        };
        if n != Some(expect_n) || prev != Some(previous.as_str()) || !hash_ok {
            return Some(("chain-break".into(), records, Some(cursor), n, None));
        }
        previous = claimed.map(str::to_owned)?;
        expect_n += 1;
        cursor = end + 1;
        records += 1;
    }
    Some(("clean".into(), records, None, None, Some(previous)))
}
