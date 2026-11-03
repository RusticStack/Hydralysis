//! `hydralysis/red4ext.py`: lookups in the game's address table (`cyberpunk2077_addresses.json`, about 150 MB).
//!
//! Rows are scanned as text in chunks and never loaded as one JSON value. The chunk loop is the original's, step for step
//! (including its handling of a row split across two reads), so the same rows come out whatever the chunk size.
//! The row pattern of the original is matched by hand (no regex engine, no captures, no allocation per row); the parity test
//! compares it with the original on generated tables.

use std::collections::HashSet;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::sync::OnceLock;

use regex::bytes::Regex;

use crate::failure::{Failure, Res};

/// The chunk the original reads at a time (`4 * 1024 * 1024`).
pub const CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// One row of the table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Row {
    pub hash: u128,
    pub symbol: String,
    pub segment: String,
    pub offset: u128,
}

/// A row borrowed from the buffer it was found in.
struct RowRef<'a> {
    hash: u128,
    symbol: &'a [u8],
    segment: &'a [u8],
    offset: u128,
}

impl RowRef<'_> {
    fn owned(&self) -> Row {
        Row {
            hash: self.hash,
            symbol: String::from_utf8_lossy(self.symbol).into_owned(),
            segment: String::from_utf8_lossy(self.segment).into_owned(),
            offset: self.offset,
        }
    }
}

const ROW_START: &[u8] = br#"{"hash":"#;

/// The ASCII white space of a bytes regex without Unicode: tab, line feed, vertical tab, form feed, carriage return, space.
fn is_space(byte: u8) -> bool {
    matches!(byte, 9..=13 | b' ')
}

fn skip_space(buf: &[u8], mut at: usize) -> usize {
    while at < buf.len() && is_space(buf[at]) {
        at += 1;
    }
    at
}

fn byte(buf: &[u8], at: usize, wanted: u8) -> Option<usize> {
    (buf.get(at) == Some(&wanted)).then_some(at + 1)
}

fn literal(buf: &[u8], at: usize, text: &[u8]) -> Option<usize> {
    buf.get(at..at + text.len()).filter(|found| *found == text).map(|_| at + text.len())
}

/// A comma, white space, the quoted KEY, a colon, white space and an opening quote at AT; where the value starts.
fn field(buf: &[u8], at: usize, key: &[u8]) -> Option<usize> {
    let at = skip_space(buf, byte(buf, at, b',')?);
    let at = literal(buf, byte(buf, at, b'"')?, key)?;
    let at = skip_space(buf, literal(buf, byte(buf, at, b'"')?, b":")?);
    byte(buf, at, b'"')
}

fn run(buf: &[u8], at: usize, accept: impl Fn(u8) -> bool) -> usize {
    let mut end = at;
    while end < buf.len() && accept(buf[end]) {
        end += 1;
    }
    end
}

fn number(bytes: &[u8], radix: u32) -> Res<u128> {
    let text = std::str::from_utf8(bytes).unwrap_or_default();
    u128::from_str_radix(text, radix).map_err(|_| Failure::fallback("number past 128 bits"))
}

/// The row that starts exactly at AT as the original's pattern matches it, and where it ends: the hash in digits, an
/// optional secondary hash (lower-case hex), an optional symbol (anything but a quote), and the offset as `SSSS:hex`.
/// The optional parts begin with different keys, so a failed part never has to be retried another way.
fn row_at(buf: &[u8], at: usize) -> Res<Option<(RowRef<'_>, usize)>> {
    let Some(after) = literal(buf, at, ROW_START) else { return Ok(None) };
    let Some(start) = byte(buf, skip_space(buf, after), b'"') else { return Ok(None) };
    let end = run(buf, start, |b| b.is_ascii_digit());
    if end == start {
        return Ok(None);
    }
    let Some(mut at) = byte(buf, end, b'"') else { return Ok(None) };
    let hash = &buf[start..end];
    if let Some(value) = field(buf, at, b"secondary hash") {
        let digits = run(buf, value, |b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if digits > value
            && let Some(next) = byte(buf, digits, b'"')
        {
            at = next;
        }
    }
    let mut symbol: &[u8] = &[];
    if let Some(value) = field(buf, at, b"symbol") {
        let end = run(buf, value, |b| b != b'"');
        if let Some(next) = byte(buf, end, b'"') {
            symbol = &buf[value..end];
            at = next;
        }
    }
    let Some(value) = field(buf, at, b"offset") else { return Ok(None) };
    let segment_end = run(buf, value, |b| b.is_ascii_hexdigit());
    if segment_end != value + 4 {
        return Ok(None);
    }
    let Some(digits) = byte(buf, segment_end, b':') else { return Ok(None) };
    let end = run(buf, digits, |b| b.is_ascii_hexdigit());
    if end == digits {
        return Ok(None);
    }
    let Some(finish) = byte(buf, end, b'"').and_then(|quote| byte(buf, quote, b'}')) else { return Ok(None) };
    let row = RowRef { hash: number(hash, 10)?, symbol, segment: &buf[value..segment_end], offset: number(&buf[digits..end], 16)? };
    Ok(Some((row, finish)))
}

/// Every row of BUF in order, like `finditer` (a failed start moves one byte on), to SINK. The position where the last row
/// ended, or `None` without a row; `stopped` is set when the SINK asked to stop.
fn rows_of(buf: &[u8], sink: &mut impl FnMut(&RowRef<'_>) -> bool, stopped: &mut bool) -> Res<Option<usize>> {
    let mut at = 0;
    let mut last_end = None;
    while let Some(found) = memchr::memmem::find(&buf[at..], ROW_START) {
        let start = at + found;
        match row_at(buf, start)? {
            Some((row, end)) => {
                last_end = Some(end);
                if !sink(&row) {
                    *stopped = true;
                    return Ok(last_end);
                }
                at = end;
            }
            None => at = start + 1,
        }
    }
    Ok(last_end)
}

fn constant_regex() -> &'static Regex {
    static CCO: OnceLock<Regex> = OnceLock::new();
    CCO.get_or_init(|| Regex::new(r#"(?-u)"Code constant offset":[[:space:]]*"([0-9A-Fa-f]+)""#).expect("regex"))
}

fn io_fallback(error: std::io::Error) -> Failure {
    Failure::fallback(format!("cannot read the address table: {error}"))
}

/// `red4ext.code_constant_offset`: the `Code constant offset` of the first 600 bytes, else `0x1000`.
pub fn code_constant_offset(path: &Path) -> Res<u128> {
    let mut head = Vec::new();
    File::open(path).map_err(io_fallback)?.take(600).read_to_end(&mut head).map_err(io_fallback)?;
    match constant_regex().captures(&head) {
        Some(found) => {
            let digits = std::str::from_utf8(&found[1]).unwrap_or_default();
            u128::from_str_radix(digits, 16).map_err(|_| Failure::fallback("code constant offset past 128 bits"))
        }
        None => Ok(0x1000),
    }
}

/// Every row from the file in chunks, as the original's `iter_entries` does, to SINK; a SINK that returns `false` stops it.
fn scan(path: &Path, chunk_size: usize, mut sink: impl FnMut(&RowRef<'_>) -> bool) -> Res<()> {
    let chunk_size = chunk_size.max(1);
    let mut handle = File::open(path).map_err(io_fallback)?;
    let mut pending: Vec<u8> = Vec::new();
    let mut chunk: Vec<u8> = Vec::with_capacity(chunk_size.min(CHUNK_SIZE));
    loop {
        chunk.clear();
        (&mut handle).take(chunk_size as u64).read_to_end(&mut chunk).map_err(io_fallback)?;
        let ended = chunk.is_empty();
        pending.extend_from_slice(&chunk);
        let mut stopped = false;
        let last_end = rows_of(&pending, &mut sink, &mut stopped)?;
        if stopped || ended {
            return Ok(());
        }
        let Some(last_end) = last_end else {
            // no complete row: keep from the last row start, else the last 2048 bytes
            let keep = match memchr::memmem::rfind(&pending, ROW_START) {
                Some(start) => pending.split_off(start),
                None => pending.split_off(pending.len().saturating_sub(2048)),
            };
            pending = keep;
            continue;
        };
        pending.drain(..last_end);
    }
}

/// `red4ext.iter_entries`: every row, in file order, to SINK. A SINK that returns `false` stops the scan.
pub fn for_each_entry(path: &Path, chunk_size: usize, mut sink: impl FnMut(Row) -> bool) -> Res<()> {
    scan(path, chunk_size, |row| sink(row.owned()))
}

/// `red4ext.format_hit`.
pub fn format_hit(row: &Row, cco: u128) -> String {
    let place =
        if row.segment == "0001" { format!("{:#x}", row.offset + cco) } else { format!("{}:{:x} (not an RVA)", row.segment, row.offset) };
    format!("{} {:#x} {} {} {}", row.hash, row.hash, row.segment, place, row.symbol)
}

/// `red4ext.lookup_hashes`: the formatted rows whose hash is in WANTED.
pub fn lookup_hashes(path: &Path, wanted: &HashSet<u128>, chunk_size: usize) -> Res<Vec<String>> {
    let cco = code_constant_offset(path)?;
    let mut found = Vec::new();
    scan(path, chunk_size, |row| {
        if wanted.contains(&row.hash) {
            found.push(format_hit(&row.owned(), cco));
        }
        true
    })?;
    Ok(found)
}

/// `red4ext.lookup_rvas`: rows of segment `0001` whose offset plus the code constant offset is in RVAS.
pub fn lookup_rvas(path: &Path, rvas: &HashSet<u128>, chunk_size: usize) -> Res<Vec<String>> {
    let cco = code_constant_offset(path)?;
    let mut found = Vec::new();
    scan(path, chunk_size, |row| {
        if row.segment == b"0001" && rvas.contains(&(row.offset + cco)) {
            found.push(format_hit(&row.owned(), cco));
        }
        true
    })?;
    Ok(found)
}
