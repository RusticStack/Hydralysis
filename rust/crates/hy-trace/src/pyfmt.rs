//! The few Python text behaviors the traces depend on: `json.dumps` with `ensure_ascii`, `str.strip` emptiness, and
//! `int(text, 0)`.

use std::fmt::Write;

/// Python's `str.isspace` for one character.
pub fn is_py_space(c: char) -> bool {
    matches!(c, '\u{9}'..='\u{d}' | '\u{1c}'..='\u{20}' | '\u{85}' | '\u{a0}' | '\u{1680}' | '\u{2000}'..='\u{200a}'
        | '\u{2028}' | '\u{2029}' | '\u{202f}' | '\u{205f}' | '\u{3000}')
}

/// `bool(text.strip())`.
pub fn has_visible(text: &str) -> bool {
    text.chars().any(|c| !is_py_space(c))
}

/// Append TEXT as a JSON string the way `json.dumps(..., ensure_ascii=True)` writes it.
pub fn write_json_string(text: &str, out: &mut String) {
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
            c if (' '..='\u{7e}').contains(&c) || c == '\u{7f}' => out.push(c),
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

/// The outcome of `int(text.strip(), 0)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntParse {
    /// The integer (it may be negative or beyond 64 bits; `i128` holds anything a 64-bit hash check needs).
    Value(i128),
    /// Python raises `ValueError`.
    Invalid,
    /// Not ASCII: Python accepts other Unicode digits, which this port does not model.
    NotAscii,
}

/// `int(text.strip(), 0)`.
pub fn parse_int_base0(text: &str) -> IntParse {
    parse_with(text, None)
}

/// `int(text.strip(), radix)` for a radix of 16, where `0x` may still prefix the digits (the other prefixes are digits).
pub fn parse_int_radix(text: &str, radix: u32) -> IntParse {
    parse_with(text, Some(radix))
}

fn parse_with(text: &str, fixed: Option<u32>) -> IntParse {
    let text = text.trim_matches(is_py_space);
    if !text.is_ascii() {
        return IntParse::NotAscii;
    }
    parse_ascii(text, fixed).map_or(IntParse::Invalid, IntParse::Value)
}

fn parse_ascii(text: &str, fixed: Option<u32>) -> Option<i128> {
    let (negative, rest) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let lower = rest.to_ascii_lowercase();
    let (radix, digits) = match (fixed, lower.get(..2)) {
        (None | Some(16), Some("0x")) => (16, &lower[2..]),
        (None, Some("0o")) => (8, &lower[2..]),
        (None, Some("0b")) => (2, &lower[2..]),
        (Some(radix), _) => (radix, &lower[..]),
        (None, _) => (10, &lower[..]),
    };
    // Underscores are allowed singly between digits (and right after a radix prefix).
    let after_prefix = digits.len() != lower.len();
    let mut cleaned = String::with_capacity(digits.len());
    let mut previous_digit = after_prefix;
    for c in digits.chars() {
        if c == '_' {
            if !previous_digit {
                return None;
            }
            previous_digit = false;
        } else {
            cleaned.push(c);
            previous_digit = true;
        }
    }
    if cleaned.is_empty() || !previous_digit {
        return None;
    }
    if fixed.is_none() && radix == 10 && cleaned.len() > 1 && cleaned.starts_with('0') && cleaned.bytes().any(|b| b != b'0') {
        return None; // base 0 refuses a leading zero in a non-zero decimal
    }
    let value = i128::from_str_radix(&cleaned, radix).ok()?;
    Some(if negative { -value } else { value })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn int_base0_matches_python() {
        assert_eq!(parse_int_base0(" 0x1F "), IntParse::Value(31));
        assert_eq!(parse_int_base0("1_000"), IntParse::Value(1000));
        assert_eq!(parse_int_base0("0b101"), IntParse::Value(5));
        assert_eq!(parse_int_base0("0o17"), IntParse::Value(15));
        assert_eq!(parse_int_base0("-5"), IntParse::Value(-5));
        assert_eq!(parse_int_base0("00"), IntParse::Value(0));
        assert_eq!(parse_int_base0("010"), IntParse::Invalid);
        assert_eq!(parse_int_base0("1__0"), IntParse::Invalid);
        assert_eq!(parse_int_base0("_1"), IntParse::Invalid);
        assert_eq!(parse_int_base0("1_"), IntParse::Invalid);
        assert_eq!(parse_int_base0("0x_f"), IntParse::Value(15));
        assert_eq!(parse_int_base0("1.5"), IntParse::Invalid);
        assert_eq!(parse_int_base0(""), IntParse::Invalid);
        assert_eq!(parse_int_base0("\u{0661}"), IntParse::NotAscii);
        assert_eq!(parse_int_radix("0x2000", 16), IntParse::Value(0x2000));
        assert_eq!(parse_int_radix("0b1", 16), IntParse::Value(0xb1));
        assert_eq!(parse_int_radix(" -1F ", 16), IntParse::Value(-31));
        assert_eq!(parse_int_radix("zz", 16), IntParse::Invalid);
        assert_eq!(parse_int_radix("", 16), IntParse::Invalid);
    }

    #[test]
    fn json_strings_are_ascii_escaped() {
        let mut out = String::new();
        write_json_string("a\"b\\c\n\u{1}\u{e9}\u{1f600}\u{7f}", &mut out);
        assert_eq!(out, "\"a\\\"b\\\\c\\n\\u0001\\u00e9\\ud83d\\ude00\u{7f}\"");
    }

    #[test]
    fn python_space_includes_the_separators() {
        assert!(!has_visible(" \u{1c}\u{3000}"));
        assert!(has_visible(" a "));
    }
}
