//! Filesystem and environment leaves of `hydralysis/backends.py` and `hydralysis/doctor.py`.
//!
//! The orchestration around them (engine inspection, install lock, downloads, daemon probes) sits on `hydra`,
//! `durable` and `locks` of other lanes and stays in Python until those are available as crates.

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use indexmap::IndexMap;
use serde_json::Value;

/// Python `str.splitlines` separators.
fn is_line_break(c: char) -> bool {
    matches!(
        c,
        '\n' | '\r'
            | '\x0b'
            | '\x0c'
            | '\x1c'
            | '\x1d'
            | '\x1e'
            | '\u{85}'
            | '\u{2028}'
            | '\u{2029}'
    )
}

fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if is_line_break(c) {
            lines.push(&text[start..i]);
            let mut end = i + c.len_utf8();
            if c == '\r' && matches!(chars.peek(), Some((_, '\n'))) {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// `backends._properties`: `key=value` lines of a Java properties file, comments skipped, quotes stripped.
pub fn properties(path: &Path) -> IndexMap<String, String> {
    let mut result = IndexMap::new();
    if !path.is_file() {
        return result;
    }
    let Ok(raw) = fs::read(path) else {
        return result;
    };
    let text = String::from_utf8_lossy(&raw);
    for line in splitlines(&text) {
        if let Some((key, value)) = line.split_once('=')
            && !line.trim_start().starts_with('#')
        {
            result.insert(
                key.trim().to_string(),
                value.trim().trim_matches('"').to_string(),
            );
        }
    }
    result
}

fn fold(s: &str) -> String {
    if cfg!(windows) {
        s.to_lowercase()
    } else {
        s.to_string()
    }
}

/// Only the shapes `backends` and `doctor` use: `prefix*` and `prefix[0-9]*`; case-insensitive on Windows like the OS glob.
fn glob_matches(pattern: &str, name: &str) -> bool {
    let (name, pattern) = (fold(name), fold(pattern));
    if let Some(prefix) = pattern.strip_suffix("[0-9]*") {
        return name
            .strip_prefix(prefix)
            .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
    }
    if let Some(prefix) = pattern.strip_suffix('*') {
        return name.starts_with(prefix);
    }
    name == pattern
}

/// `backends._children`: matching entries of `root`, sorted descending (Windows: case-insensitive like `WindowsPath`).
pub fn children(root: &Path, pattern: &str) -> Vec<PathBuf> {
    if !root.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut found: Vec<PathBuf> = entries
        .flatten()
        .filter(|e| glob_matches(pattern, &e.file_name().to_string_lossy()))
        .map(|e| e.path())
        .collect();
    found.sort_by_key(|p| fold(&p.to_string_lossy()));
    found.reverse();
    found
}

fn take(handle: &mut fs::File, count: u64) -> Option<Vec<u8>> {
    let mut buffer = Vec::new();
    handle.take(count).read_to_end(&mut buffer).ok()?;
    Some(buffer)
}

/// `backends._native_compatible`: executable headers of the host's native format.
pub fn native_compatible(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Ok(mut handle) = fs::File::open(path) else {
        return false;
    };
    let Some(header) = take(&mut handle, 64) else {
        return false;
    };
    if cfg!(windows) {
        if header.len() < 64 || &header[..2] != b"MZ" {
            return false;
        }
        let offset = u64::from(u32::from_le_bytes([
            header[60], header[61], header[62], header[63],
        ]));
        if handle.seek(SeekFrom::Start(offset)).is_err() {
            return false;
        }
        let Some(signature) = take(&mut handle, 6) else {
            return false;
        };
        return signature.len() >= 6
            && &signature[..4] == b"PE\0\0"
            && signature[4..6] == [0x64, 0x86];
    }
    if header.starts_with(&[0xcf, 0xfa, 0xed, 0xfe]) {
        return true;
    }
    header.len() >= 20 && header.starts_with(b"\x7fELF\x02")
}

/// `backends._machine` without the `platform.machine()` fallback (None: Python answers).
pub fn machine() -> Option<String> {
    if cfg!(windows) {
        for name in ["PROCESSOR_ARCHITEW6432", "PROCESSOR_ARCHITECTURE"] {
            if let Ok(found) = std::env::var(name)
                && !found.is_empty()
            {
                return Some(found);
            }
        }
    }
    None
}

/// `doctor._read_json`: a JSON object from `path`, `{}` for anything else (missing, unreadable, not an object).
pub fn read_json_object(path: &Path) -> Value {
    let empty = || Value::Object(serde_json::Map::new());
    let Ok(raw) = fs::read(path) else {
        return empty();
    };
    let Ok(text) = String::from_utf8(raw) else {
        return empty();
    };
    match serde_json::from_str::<Value>(&text) {
        Ok(v @ Value::Object(_)) => v,
        _ => empty(),
    }
}

/// `doctor._instances`: names of the `*.json` records in `state` that have a sibling `.lock`.
pub fn instances(state: &Path) -> Vec<String> {
    if !state.is_dir() {
        return Vec::new();
    }
    let Ok(entries) = fs::read_dir(state) else {
        return Vec::new();
    };
    let mut names: Vec<String> = entries
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .filter(|n| fold(n).ends_with(".json"))
        .collect();
    names.sort_by_key(|s| fold(s));
    names
        .into_iter()
        .filter_map(|name| {
            let lower = name.to_lowercase();
            if lower.ends_with(".launch.json")
                || lower.ends_with(".supervisor.json")
                || lower == "supervisor.json"
            {
                return None;
            }
            // Path(".json").stem is the whole name: a dotfile has no suffix.
            let stem = if name.len() == 5 {
                name.clone()
            } else {
                name[..name.len() - 5].to_string()
            };
            state.join(format!("{stem}.lock")).exists().then_some(stem)
        })
        .collect()
}

/// `doctor._dir_size`: bytes under `folder`, unreadable entries skipped, directory links not followed.
pub fn dir_size(folder: &Path) -> u64 {
    let mut total = 0;
    let mut stack = vec![folder.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let Ok(entries) = fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            let path = entry.path();
            if kind.is_dir() {
                stack.push(path);
            } else if let Ok(meta) = fs::metadata(&path)
                && !meta.is_dir()
            {
                total += meta.len();
            }
        }
    }
    total
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_none_or(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `doctor._count_key`: how many dicts anywhere in `value` carry a truthy `key`.
pub fn count_key(value: &Value, key: &str) -> u64 {
    match value {
        Value::Object(map) => {
            u64::from(map.get(key).is_some_and(truthy))
                + map.values().map(|v| count_key(v, key)).sum::<u64>()
        }
        Value::Array(items) => items.iter().map(|v| count_key(v, key)).sum(),
        _ => 0,
    }
}
