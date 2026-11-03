//! JSON text exactly as Python's `json.dumps` writes it.
//!
//! The wire form (`dumps`) uses `", "` and `": "` separators and `ensure_ascii=False`; `dumps_indent` is
//! `json.dumps(value, indent=2)` with the default `ensure_ascii=True`. Object keys keep their insertion order
//! (serde_json's `preserve_order`), like a Python dict.

use serde_json::Value;

fn escape(text: &str, out: &mut String, ascii: bool) {
    out.push('"');
    for ch in text.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c if ascii && (c as u32) > 0x7f => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

/// `json.dumps(value, ensure_ascii=False)`.
pub fn dumps(value: &Value) -> String {
    let mut out = String::new();
    write(value, &mut out);
    out
}

fn write(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(flag) => out.push_str(if *flag { "true" } else { "false" }),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => escape(text, out, false),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                escape(key, out, false);
                out.push_str(": ");
                write(item, out);
            }
            out.push('}');
        }
    }
}

/// `json.dumps(value, indent=2)`.
pub fn dumps_indent(value: &Value) -> String {
    let mut out = String::new();
    write_indent(value, &mut out, 0);
    out
}

fn write_indent(value: &Value, out: &mut String, depth: usize) {
    match value {
        Value::Array(items) if !items.is_empty() => {
            out.push_str("[\n");
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&" ".repeat(2 * (depth + 1)));
                write_indent(item, out, depth + 1);
            }
            out.push('\n');
            out.push_str(&" ".repeat(2 * depth));
            out.push(']');
        }
        Value::Object(map) if !map.is_empty() => {
            out.push_str("{\n");
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(",\n");
                }
                out.push_str(&" ".repeat(2 * (depth + 1)));
                escape(key, out, true);
                out.push_str(": ");
                write_indent(item, out, depth + 1);
            }
            out.push('\n');
            out.push_str(&" ".repeat(2 * depth));
            out.push('}');
        }
        Value::String(text) => escape(text, out, true),
        other => write(other, out),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn wire_form_matches_python() {
        let value = json!({"a": [1, 2], "b": "é\n\u{1}", "c": {}, "d": []});
        assert_eq!(
            dumps(&value),
            "{\"a\": [1, 2], \"b\": \"é\\n\\u0001\", \"c\": {}, \"d\": []}"
        );
    }

    #[test]
    fn indent_form_matches_python() {
        let value = json!({"a": [1, "é"], "b": [], "c": {"d": null}});
        assert_eq!(
            dumps_indent(&value),
            "{\n  \"a\": [\n    1,\n    \"\\u00e9\"\n  ],\n  \"b\": [],\n  \"c\": {\n    \"d\": null\n  }\n}"
        );
    }
}
