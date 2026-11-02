//! JSON encoding byte-identical to Python's `json.dumps` for the layouts Hydralysis uses.
//!
//! Layouts: [`Layout::Compact`] (`separators=(",", ":")`), [`Layout::Spaced`] (the default `(", ", ": ")`) and
//! [`Layout::Pretty`] (`indent=n`). Keys are written in insertion order unless `sort_keys` is set (sorting is by
//! code point, which equals UTF-8 byte order). Floats use Python's `repr`. Known limits: integers beyond 64 bits
//! and the non-finite constants `NaN` / `Infinity` are not representable in `serde_json::Value`.

use crate::error::{Error, Result};
use serde_json::Value;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    Compact,
    Spaced,
    Pretty(usize),
}

#[derive(Clone, Copy, Debug)]
pub struct Options {
    pub layout: Layout,
    pub sort_keys: bool,
    pub ensure_ascii: bool,
}

/// `json.dumps(v, ensure_ascii=False, separators=(",", ":"), sort_keys=True)` (PROTOCOL-3.md 3.4).
pub const CANONICAL: Options = Options { layout: Layout::Compact, sort_keys: true, ensure_ascii: false };
/// `json.dumps(v, separators=(",", ":"), ensure_ascii=True)` (log frames).
pub const FRAME: Options = Options { layout: Layout::Compact, sort_keys: false, ensure_ascii: true };

pub fn dumps(value: &Value, options: Options) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    write_value(&mut out, value, options, 0);
    out
}

/// Canonical bytes (`durable.canonical`).
pub fn canonical(value: &Value) -> Vec<u8> {
    dumps(value, CANONICAL)
}

/// Parse like `json.loads(bytes.decode("utf-8"))`.
pub fn loads(bytes: &[u8]) -> Result<Value> {
    let text = std::str::from_utf8(bytes).map_err(|e| Error::Json(e.to_string()))?;
    serde_json::from_str(text).map_err(Error::from)
}

fn newline(out: &mut Vec<u8>, indent: usize, depth: usize) {
    out.push(b'\n');
    out.resize(out.len() + indent * depth, b' ');
}

fn write_value(out: &mut Vec<u8>, value: &Value, o: Options, depth: usize) {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                out.extend_from_slice(i.to_string().as_bytes());
            } else if let Some(u) = n.as_u64() {
                out.extend_from_slice(u.to_string().as_bytes());
            } else if let Some(f) = n.as_f64() {
                out.extend_from_slice(float_repr(f).as_bytes());
            }
        }
        Value::String(s) => write_string(out, s, o.ensure_ascii),
        Value::Array(items) => {
            if items.is_empty() {
                out.extend_from_slice(b"[]");
                return;
            }
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    item_separator(out, o.layout);
                }
                if let Layout::Pretty(n) = o.layout {
                    newline(out, n, depth + 1);
                }
                write_value(out, item, o, depth + 1);
            }
            if let Layout::Pretty(n) = o.layout {
                newline(out, n, depth);
            }
            out.push(b']');
        }
        Value::Object(map) => {
            if map.is_empty() {
                out.extend_from_slice(b"{}");
                return;
            }
            out.push(b'{');
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            if o.sort_keys {
                entries.sort_by(|a, b| a.0.as_bytes().cmp(b.0.as_bytes()));
            }
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    item_separator(out, o.layout);
                }
                if let Layout::Pretty(n) = o.layout {
                    newline(out, n, depth + 1);
                }
                write_string(out, key, o.ensure_ascii);
                out.extend_from_slice(if o.layout == Layout::Compact { b":" } else { b": " });
                write_value(out, item, o, depth + 1);
            }
            if let Layout::Pretty(n) = o.layout {
                newline(out, n, depth);
            }
            out.push(b'}');
        }
    }
}

fn item_separator(out: &mut Vec<u8>, layout: Layout) {
    match layout {
        Layout::Compact | Layout::Pretty(_) => out.push(b','),
        Layout::Spaced => out.extend_from_slice(b", "),
    }
}

const HEX: &[u8; 16] = b"0123456789abcdef";

fn push_u_escape(out: &mut Vec<u8>, unit: u32) {
    out.extend_from_slice(b"\\u");
    for shift in [12, 8, 4, 0] {
        out.push(HEX[((unit >> shift) & 0xf) as usize]);
    }
}

pub fn write_string(out: &mut Vec<u8>, text: &str, ensure_ascii: bool) {
    out.push(b'"');
    for ch in text.chars() {
        match ch {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\r' => out.extend_from_slice(b"\\r"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\u{8}' => out.extend_from_slice(b"\\b"),
            '\u{c}' => out.extend_from_slice(b"\\f"),
            c if (c as u32) < 0x20 => push_u_escape(out, c as u32),
            c if ensure_ascii && !(' '..='~').contains(&c) => {
                let code = c as u32;
                if code > 0xFFFF {
                    let v = code - 0x10000;
                    push_u_escape(out, 0xD800 | (v >> 10));
                    push_u_escape(out, 0xDC00 | (v & 0x3FF));
                } else {
                    push_u_escape(out, code);
                }
            }
            c => {
                let mut buffer = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    out.push(b'"');
}

/// Python's `repr(float)`: shortest round-trip digits, exponent form when the decimal point is more than 16
/// digits to the right or more than 4 to the left.
pub fn float_repr(f: f64) -> String {
    if f == 0.0 {
        return if f.is_sign_negative() { "-0.0".into() } else { "0.0".into() };
    }
    let sci = format!("{:e}", f.abs());
    let (mantissa, exponent) = sci.split_once('e').unwrap_or((&sci, "0"));
    let exp10: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let decpt = exp10 + 1;
    let sign = if f < 0.0 { "-" } else { "" };
    let body = if -4 < decpt && decpt <= 16 {
        if decpt <= 0 {
            format!("0.{}{}", "0".repeat((-decpt) as usize), digits)
        } else if decpt as usize >= digits.len() {
            format!("{}{}.0", digits, "0".repeat(decpt as usize - digits.len()))
        } else {
            format!("{}.{}", &digits[..decpt as usize], &digits[decpt as usize..])
        }
    } else {
        let (first, rest) = digits.split_at(1);
        let exp_sign = if exp10 < 0 { '-' } else { '+' };
        let head = if rest.is_empty() { first.to_string() } else { format!("{first}.{rest}") };
        format!("{head}e{exp_sign}{:02}", exp10.abs())
    };
    format!("{sign}{body}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn floats_match_python_repr() {
        for (f, want) in [
            (1.0, "1.0"),
            (0.5, "0.5"),
            (1e16, "1e+16"),
            (1e15, "1000000000000000.0"),
            (1.5e-5, "1.5e-05"),
            (0.0001, "0.0001"),
            (123456789.125, "123456789.125"),
            (-2.5e-7, "-2.5e-07"),
            (1e22, "1e+22"),
            (0.1, "0.1"),
            (1.7976931348623157e308, "1.7976931348623157e+308"),
            (5e-324, "5e-324"),
        ] {
            assert_eq!(float_repr(f), want, "{f}");
        }
    }

    #[test]
    fn canonical_sorts_and_keeps_unicode() {
        let v = json!({"b": 1, "a": {"z": [1, 2.5, "é"], "y": null}});
        assert_eq!(String::from_utf8(canonical(&v)).unwrap(), r#"{"a":{"y":null,"z":[1,2.5,"é"]},"b":1}"#);
    }

    #[test]
    fn ascii_escapes_like_python() {
        let v = json!("a\u{7f}\u{e9}\u{1F600}\n");
        assert_eq!(String::from_utf8(dumps(&v, FRAME)).unwrap(), r#""a\u007fé😀\n""#);
    }

    #[test]
    fn pretty_layout() {
        let v = json!({"a": [], "b": {"c": [1, 2]}, "d": {}});
        let o = Options { layout: Layout::Pretty(2), sort_keys: false, ensure_ascii: true };
        let got = String::from_utf8(dumps(&v, o)).unwrap();
        assert_eq!(got, "{\n  \"a\": [],\n  \"b\": {\n    \"c\": [\n      1,\n      2\n    ]\n  },\n  \"d\": {}\n}");
    }
}
