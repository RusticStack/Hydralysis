//! `hydralysis/red4ext.py`: lookups in the game's address table (`cyberpunk2077_addresses.json`, about 150 MB).
//!
//! Rows are scanned as text in chunks and never loaded as one JSON value. The chunk loop is the original's, step for step
//! (including its handling of a row split across two reads), so the same rows come out whatever the chunk size.

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

fn entry_regex() -> &'static Regex {
    static ENTRY: OnceLock<Regex> = OnceLock::new();
    ENTRY.get_or_init(|| {
        Regex::new(
            r#"(?-u)\{"hash":\s*"(\d+)"(?:,\s*"secondary hash":\s*"[0-9a-f]+")?(?:,\s*"symbol":\s*"([^"]*)")?,\s*"offset":\s*"([0-9A-Fa-f]{4}):([0-9A-Fa-f]+)"\}"#,
        )
        .expect("regex")
    })
}

fn constant_regex() -> &'static Regex {
    static CCO: OnceLock<Regex> = OnceLock::new();
    CCO.get_or_init(|| Regex::new(r#"(?-u)"Code constant offset":\s*"([0-9A-Fa-f]+)""#).expect("regex"))
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

fn row_of(found: &regex::bytes::Captures<'_>) -> Res<Row> {
    let number = |bytes: &[u8], radix: u32| -> Res<u128> {
        let text = std::str::from_utf8(bytes).unwrap_or_default();
        u128::from_str_radix(text, radix).map_err(|_| Failure::fallback("number past 128 bits"))
    };
    Ok(Row {
        hash: number(&found[1], 10)?,
        symbol: found.get(2).map(|m| String::from_utf8_lossy(m.as_bytes()).into_owned()).unwrap_or_default(),
        segment: String::from_utf8_lossy(&found[3]).into_owned(),
        offset: number(&found[4], 16)?,
    })
}

/// `red4ext.iter_entries`: every row, in file order, to SINK. A SINK that returns `false` stops the scan.
pub fn for_each_entry(path: &Path, chunk_size: usize, mut sink: impl FnMut(Row) -> bool) -> Res<()> {
    let chunk_size = chunk_size.max(1);
    let mut handle = File::open(path).map_err(io_fallback)?;
    let mut pending: Vec<u8> = Vec::new();
    let pattern = entry_regex();
    loop {
        let mut chunk = Vec::with_capacity(chunk_size);
        (&mut handle).take(chunk_size as u64).read_to_end(&mut chunk).map_err(io_fallback)?;
        let ended = chunk.is_empty();
        pending.extend_from_slice(&chunk);
        let matches: Vec<regex::bytes::Captures<'_>> = pattern.captures_iter(&pending).collect();
        if ended {
            for found in &matches {
                if !sink(row_of(found)?) {
                    return Ok(());
                }
            }
            return Ok(());
        }
        let Some(last_end) = matches.last().map(|found| found.get(0).map_or(0, |m| m.end())) else {
            // no complete row: keep from the last row start, else the last 2048 bytes
            let keep = match memchr::memmem::rfind(&pending, br#"{"hash":"#) {
                Some(start) => pending.split_off(start),
                None => pending.split_off(pending.len().saturating_sub(2048)),
            };
            pending = keep;
            continue;
        };
        for found in &matches {
            if !sink(row_of(found)?) {
                return Ok(());
            }
        }
        drop(matches);
        pending.drain(..last_end);
    }
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
    for_each_entry(path, chunk_size, |row| {
        if wanted.contains(&row.hash) {
            found.push(format_hit(&row, cco));
        }
        true
    })?;
    Ok(found)
}

/// `red4ext.lookup_rvas`: rows of segment `0001` whose offset plus the code constant offset is in RVAS.
pub fn lookup_rvas(path: &Path, rvas: &HashSet<u128>, chunk_size: usize) -> Res<Vec<String>> {
    let cco = code_constant_offset(path)?;
    let mut found = Vec::new();
    for_each_entry(path, chunk_size, |row| {
        if row.segment == "0001" && rvas.contains(&(row.offset + cco)) {
            found.push(format_hit(&row, cco));
        }
        true
    })?;
    Ok(found)
}
