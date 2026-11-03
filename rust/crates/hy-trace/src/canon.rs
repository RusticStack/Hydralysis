//! The TRACE-1 canonical JSON of `hydralysis.trace_canon.canonical_bytes` (TRACE-1 section 3).
//!
//! Keys sorted, separators `,` and `:` with no spaces, strings escaped as `"` `\` `\n` `\r` `\t` `\b` `\f` and every other
//! character below 0x20 or above 0x7e (so also 0x7f) as lowercase `\uXXXX` with UTF-16 surrogate pairs above the BMP, no
//! floating point numbers, integers within `-2^63 ..= 2^64-1`.

use serde_json::Value;
use std::fmt::Write;

/// A value TRACE-1 does not allow in a chained record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum NotCanonical {
    #[error("integer out of the 64-bit range")]
    IntegerRange,
    #[error("floating point number")]
    Float,
}

fn string(text: &str, out: &mut String) {
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            ' '..='~' => out.push(c),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    // Writing into a String cannot fail.
                    let _ = write!(out, "\\u{unit:04x}");
                }
            }
        }
    }
    out.push('"');
}

fn write_value(value: &Value, out: &mut String) -> Result<(), NotCanonical> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if let Some(n) = number.as_i64() {
                let _ = write!(out, "{n}");
            } else if let Some(n) = number.as_u64() {
                let _ = write!(out, "{n}");
            } else {
                // serde_json reads an integer beyond 64 bits as a float; the Python would say "out of range" for those
                // and "floating point" for real floats. Both are refusals; the text is the Python's for the reader of
                // the message (see `read_jsonl`, which leaves refusals to the Python).
                return Err(NotCanonical::Float);
            }
        }
        Value::String(text) => string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                string(key, out);
                out.push(':');
                write_value(&map[key.as_str()], out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// The canonical text of VALUE (ASCII).
pub fn canonical_text(value: &Value) -> Result<String, NotCanonical> {
    let mut out = String::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// The canonical bytes of VALUE (ASCII).
pub fn canonical_bytes(value: &Value) -> Result<Vec<u8>, NotCanonical> {
    canonical_text(value).map(String::into_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_and_separators_are_tight() {
        let value = json!({"b": [1, 2, {"z": null, "a": true}], "a": "x", "A": false});
        assert_eq!(canonical_text(&value).unwrap(), r#"{"A":false,"a":"x","b":[1,2,{"a":true,"z":null}]}"#);
    }

    #[test]
    fn strings_escape_everything_outside_printable_ascii_in_lowercase_with_surrogate_pairs() {
        let value = json!("a\"b\\c\n\r\t\u{8}\u{c}\u{1}\u{7f}\u{e9}\u{20ac}\u{1f600}~ ");
        assert_eq!(canonical_text(&value).unwrap(), r#""a\"b\\c\n\r\t\b\f\u0001\u007f\u00e9\u20ac\ud83d\ude00~ ""#);
    }

    #[test]
    fn integers_within_the_64_bit_range_are_written_and_floats_are_refused() {
        assert_eq!(canonical_text(&json!([i64::MIN, u64::MAX, 0])).unwrap(), "[-9223372036854775808,18446744073709551615,0]");
        assert_eq!(canonical_text(&json!(1.5)), Err(NotCanonical::Float));
        assert_eq!(canonical_text(&json!({"a": [1.0]})), Err(NotCanonical::Float));
    }

    #[test]
    fn keys_sort_by_code_point() {
        let value = json!({"\u{10000}": 1, "\u{ffff}": 2, "z": 3});
        assert_eq!(canonical_text(&value).unwrap(), r#"{"z":3,"\uffff":2,"\ud800\udc00":1}"#);
    }
}
