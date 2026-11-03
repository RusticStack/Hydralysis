//! Small Python text and number semantics the ports need: `str.splitlines`, `str.strip`, `int()`, `repr(str)`, and
//! `json.dumps` in the three layouts Hydralysis writes.

pub use hy_core::json::Layout;
use hy_core::json::{self, Options};
use serde_json::Value;

use crate::failure::{Failure, Res};

/// The `json.dumps` layouts used here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dumps {
    /// `json.dumps(v, ensure_ascii=False)`: `", "` and `": "`.
    Spaced,
    /// `json.dumps(v, indent=2)` (`ensure_ascii=True`).
    Indent2,
    /// `json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=True)`.
    CanonicalAscii,
    /// `json.dumps(v, ensure_ascii=True, separators=(",", ":"))`.
    CompactAscii,
}

/// Serialise like Python's `json.dumps` with the chosen layout.
pub fn dumps(value: &Value, layout: Dumps) -> String {
    let options = match layout {
        Dumps::Spaced => Options { layout: Layout::Spaced, sort_keys: false, ensure_ascii: false },
        Dumps::Indent2 => Options { layout: Layout::Pretty(2), sort_keys: false, ensure_ascii: true },
        Dumps::CanonicalAscii => Options { layout: Layout::Compact, sort_keys: true, ensure_ascii: true },
        Dumps::CompactAscii => Options { layout: Layout::Compact, sort_keys: false, ensure_ascii: true },
    };
    // the encoder writes valid UTF-8 only
    String::from_utf8(json::dumps(value, options)).unwrap_or_default()
}

/// Serialise with an explicit layout, key sorting and `ensure_ascii`.
pub fn dumps_with(value: &Value, layout: Layout, sort_keys: bool, ensure_ascii: bool) -> String {
    String::from_utf8(json::dumps(value, Options { layout, sort_keys, ensure_ascii })).unwrap_or_default()
}

/// Whitespace as `str.isspace` sees it (Unicode White_Space plus the separators U+001C to U+001F).
pub fn is_py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

pub fn py_strip(text: &str) -> &str {
    text.trim_matches(is_py_space)
}

pub fn py_lstrip(text: &str) -> &str {
    text.trim_start_matches(is_py_space)
}

/// Python `str.splitlines()` (no keepends).
pub fn py_splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((i, c)) = chars.next() {
        if matches!(c, '\n' | '\r' | '\x0b' | '\x0c' | '\x1c' | '\x1d' | '\x1e' | '\u{85}' | '\u{2028}' | '\u{2029}') {
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

/// `text[-count:]` (by code points).
pub fn py_str_tail(text: &str, count: usize) -> String {
    let total = text.chars().count();
    if total <= count { text.to_string() } else { text.chars().skip(total - count).collect() }
}

/// Python `int(value)` for a JSON value as an `i64`.
pub fn py_int_value(value: &Value) -> Res<i64> {
    hy_query::session::py_int(value).map_err(Failure::from)
}

/// `repr(text)` for the text that appears in messages: plain printable ASCII without quotes or backslashes.
/// Anything else is not modelled (`None`).
pub fn py_repr_simple(text: &str) -> Option<String> {
    if text.bytes().all(|b| (0x20..0x7f).contains(&b) && !matches!(b, 39 | 34 | 92)) { Some(format!("'{text}'")) } else { None }
}

/// Parse JSON text that came from Python's `json.dumps`/`json.loads` world. Whatever `serde_json` cannot hold exactly is a
/// fallback, not an approximation: the constants `NaN`/`Infinity`, lone surrogates and, because serde turns them into
/// floats without a word, integers beyond 64 bits.
pub fn parse_json(text: &str) -> Res<Value> {
    let value: Value = serde_json::from_str(text).map_err(|_| Failure::fallback("json not parsed by serde"))?;
    if has_big_integer(text.as_bytes()) {
        return Err(Failure::fallback("integer past 64 bits"));
    }
    Ok(value)
}

/// Whether the JSON text has an integer token (outside strings) that fits neither `i64` nor `u64`.
pub fn has_big_integer(bytes: &[u8]) -> bool {
    let mut at = 0;
    let mut in_string = false;
    while at < bytes.len() {
        let byte = bytes[at];
        if in_string {
            match byte {
                92 => at += 1,
                34 => in_string = false,
                _ => {}
            }
            at += 1;
            continue;
        }
        if byte == 34 {
            in_string = true;
            at += 1;
        } else if byte == b'-' || byte.is_ascii_digit() {
            let start = at;
            while at < bytes.len() && matches!(bytes[at], b'0'..=b'9' | b'.' | b'e' | b'E' | b'+' | b'-') {
                at += 1;
            }
            let token = &bytes[start..at];
            if !token.iter().any(|b| matches!(b, b'.' | b'e' | b'E')) && token.len() > 18 {
                let text = std::str::from_utf8(token).unwrap_or_default();
                if text.parse::<i64>().is_err() && text.parse::<u64>().is_err() {
                    return true;
                }
            }
        } else {
            at += 1;
        }
    }
    false
}
