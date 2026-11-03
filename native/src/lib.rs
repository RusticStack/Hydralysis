//! Optional native helpers for Hydralysis. Every function has a pure-Python twin in `hydralysis.durable` that gives
//! identical results; tests/test_native.py compares the two. The trace helpers are in `trace.rs` (twin: `hydralysis.trace_wire`).

use pyo3::prelude::*;

mod trace;
mod views;
use pyo3::types::PyBytes;

const HEX: &[u8; 16] = b"0123456789abcdef";

fn hex_value(byte: u8) -> Option<u32> {
    HEX.iter().position(|&h| h == byte).map(|p| p as u32)
}

/// The CRC frame check of `durable._parse` without the JSON decode: `crc-hex8 SP body`, lowercase hex, CRC-32 (IEEE)
/// of the body equal to the header.
fn frame_ok(line: &[u8]) -> bool {
    if line.len() < 10 || line[8] != b' ' {
        return false;
    }
    let mut want: u32 = 0;
    for &byte in &line[..8] {
        match hex_value(byte) {
            Some(v) => want = (want << 4) | v,
            None => return false,
        }
    }
    crc32fast::hash(&line[9..]) == want
}

/// Every complete (LF-terminated) line of DATA from byte START: `(start, end, crc_ok)` with END the offset of its LF.
/// The caller decodes the JSON of the lines whose frame is valid.
#[pyfunction]
fn frame_lines(data: &Bound<'_, PyBytes>, start: usize) -> Vec<(usize, usize, bool)> {
    let bytes = data.as_bytes();
    let mut out = Vec::new();
    let mut cursor = start.min(bytes.len());
    while let Some(found) = memchr::memchr(b'\n', &bytes[cursor..]) {
        let end = cursor + found;
        out.push((cursor, end, frame_ok(&bytes[cursor..end])));
        cursor = end + 1;
    }
    out
}

#[pymodule]
fn hydralysis_native(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(frame_lines, module)?)?;
    trace::register(module)?;
    views::register(module)?;
    module.add("ABI", "abi3-py313")?;
    Ok(())
}
