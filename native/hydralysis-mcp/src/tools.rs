//! The tools the host answers itself: the offline PE reads of api.py. `native_call` returns the reply text exactly as
//! `hydralysis.api.call` would, or `None` for anything it does not handle (an argument of an unusual type, a PE it does
//! not model, an error, a tool that is not ported): the host then asks the Python worker, so every failure keeps the
//! Python error text and every unported tool keeps working.

use crate::pe::{parse_expect, parse_rva, Delegate, Image};
use regex::Regex;
use serde_json::{Map, Value};
use std::path::Path;

/// The tools with a native implementation.
pub const NATIVE_TOOLS: [&str; 8] = [
    "fingerprint",
    "imports",
    "function",
    "bytes",
    "strings",
    "sigscan",
    "callers",
    "xrefs",
];

pub fn is_native(name: &str) -> bool {
    NATIVE_TOOLS.contains(&name)
}

/// A JSON integer that Python's `int()` takes as is (not a bool, not a float).
fn integer(value: &Value) -> Option<i64> {
    match value {
        Value::Number(number) if !number.is_f64() => number.as_i64(),
        _ => None,
    }
}

fn text_or_empty(args: &Map<String, Value>, key: &str) -> Option<String> {
    match args.get(key) {
        None | Some(Value::Null) => Some(String::new()),
        Some(Value::String(text)) => Some(text.clone()),
        _ => None,
    }
}

/// A bound on a count argument: the value when present and valid, `default` when absent; `None` to delegate.
fn bounded(args: &Map<String, Value>, key: &str, default: usize) -> Option<usize> {
    match args.get(key) {
        None => Some(default),
        Some(value) => integer(value)
            .filter(|count| *count >= 1)
            .map(|count| count as usize),
    }
}

fn load(args: &Map<String, Value>) -> Option<Image> {
    let exe = args.get("exe")?.as_str().filter(|text| !text.is_empty())?;
    let path = Path::new(exe);
    if !path.is_file() {
        return None;
    }
    let name = path.file_name()?.to_str()?.to_string();
    let data = std::fs::read(path).ok()?;
    Image::parse(name, data)
}

/// api.py `_addr`, for plain `rva:`/`va:`/numeric addresses.
fn address(image: &Image, args: &Map<String, Value>) -> Option<u64> {
    let text = match args.get("address")? {
        Value::String(text) => text.trim().to_string(),
        value => integer(value)?.to_string(),
    };
    if text.starts_with("name:") || text.starts_with("hash:") {
        return None;
    }
    let parsed = parse_rva(&text, image.base)?;
    if let Some(value) = parsed.unprefixed {
        if value >= image.base {
            let raw_mapped = image.rva_to_offset(value).is_some();
            let va_mapped = image.rva_to_offset(parsed.rva).is_some();
            if raw_mapped && va_mapped {
                return None;
            }
            if raw_mapped {
                return Some(value);
            }
        }
    }
    Some(parsed.rva)
}

/// A pattern whose Python `re` and Rust `regex` meanings agree: plain ASCII with the common operators. Everything else
/// (lookaround, backreferences, named groups, flags, set operations, exotic escapes) is left to Python.
fn simple_regex(pattern: &str, ignore_case: bool) -> Option<Regex> {
    if !pattern.is_ascii()
        || pattern.contains("(?")
        || pattern.contains("[[")
        || pattern.contains("&&")
        || pattern.contains("~~")
        || pattern.contains("--")
    {
        return None;
    }
    let bytes = pattern.as_bytes();
    let mut in_class = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => {
                let next = *bytes.get(index + 1)?;
                let class_escape = matches!(next, b'd' | b'w' | b's' | b'D' | b'W' | b'S');
                let boundary = matches!(next, b'b' | b'B');
                let literal = matches!(
                    next,
                    b'.' | b'\\'
                        | b'+'
                        | b'*'
                        | b'?'
                        | b'('
                        | b')'
                        | b'['
                        | b']'
                        | b'{'
                        | b'}'
                        | b'|'
                        | b'^'
                        | b'$'
                        | b'/'
                );
                if !(class_escape
                    || (boundary && !in_class)
                    || literal
                    || (next == b'-' && in_class))
                {
                    return None;
                }
                index += 2;
                continue;
            }
            b'[' if !in_class => in_class = true,
            b']' if in_class => in_class = false,
            byte if byte < 0x20 || byte == 0x7f => return None,
            _ => {}
        }
        index += 1;
    }
    if in_class {
        return None;
    }
    let source = if ignore_case {
        format!("(?i){pattern}")
    } else {
        pattern.to_string()
    };
    Regex::new(&source).ok()
}

/// The reply of tool `name`, or `None` when the Python implementation must answer.
pub fn native_call(name: &str, arguments: Option<&Value>) -> Option<String> {
    if !is_native(name) {
        return None;
    }
    let empty = Map::new();
    let args = match arguments {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(map)) => map,
        Some(_) => return None,
    };
    for (key, maximum) in [("limit", 200i64), ("count", 200), ("size", 65536)] {
        if let Some(value) = args.get(key) {
            if !integer(value).is_some_and(|number| (1..=maximum).contains(&number)) {
                return None;
            }
        }
    }
    let image = load(args)?;
    reply(&image, name, args).ok()
}

fn reply(image: &Image, name: &str, args: &Map<String, Value>) -> Result<String, Delegate> {
    let none = |value: Option<usize>| value.ok_or_else(Delegate::at);
    match name {
        "fingerprint" => {
            let detail = match args.get("detail") {
                None => "header",
                Some(Value::String(text)) => text.as_str(),
                Some(_) => return Err(Delegate::at()),
            };
            match detail {
                "header" => {
                    let header = image.header().ok_or_else(Delegate::at)?;
                    let json = image.fingerprint_json().ok_or_else(Delegate::at)?;
                    Ok(format!("{header}\n{json}"))
                }
                "sections" => image.sections_text().ok_or_else(Delegate::at),
                _ => Err(Delegate::at()),
            }
        }
        "imports" => {
            let limit = none(bounded(args, "limit", 80))?;
            let pattern = text_or_empty(args, "pattern").ok_or_else(Delegate::at)?;
            let wanted = if pattern.is_empty() {
                None
            } else {
                Some(simple_regex(&pattern, true).ok_or_else(Delegate::at)?)
            };
            image.imports_text(limit, wanted.as_ref())
        }
        "function" => image.function_of(address(image, args).ok_or_else(Delegate::at)?),
        "bytes" => {
            let size = none(bounded(args, "size", 32))?;
            image.bytes_text(address(image, args).ok_or_else(Delegate::at)?, size)
        }
        "strings" => {
            let limit = none(bounded(args, "limit", 30))?;
            let pattern = text_or_empty(args, "pattern").ok_or_else(Delegate::at)?;
            let regex = simple_regex(&pattern, false).ok_or_else(Delegate::at)?;
            image.find_strings(&regex, limit)
        }
        "sigscan" => {
            let limit = none(bounded(args, "limit", 20))?;
            let pattern = text_or_empty(args, "pattern").ok_or_else(Delegate::at)?;
            let expect = parse_expect(&pattern).ok_or_else(Delegate::at)?;
            image.sigscan(&expect, &pattern, limit)
        }
        "callers" => {
            let limit = none(bounded(args, "limit", 50))?;
            image.callers(address(image, args).ok_or_else(Delegate::at)?, limit)
        }
        "xrefs" => {
            let limit = none(bounded(args, "limit", 40))?;
            image.xrefs(address(image, args).ok_or_else(Delegate::at)?, limit)
        }
        _ => Err(Delegate::at()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pe::find_pattern;

    #[test]
    fn simple_patterns_compile_and_exotic_ones_are_left_to_python() {
        assert!(simple_regex("Suffix|Wide", false).is_some());
        assert!(simple_regex("^kernel32\\.dll$", true).is_some());
        assert!(simple_regex("(?i)abc", false).is_none());
        assert!(simple_regex("(a)\\1", false).is_none());
        assert!(simple_regex("[[:alpha:]]", false).is_none());
        assert!(simple_regex("caf\u{e9}", false).is_none());
        assert!(simple_regex("a(b", false).is_none());
    }

    #[test]
    fn find_pattern_reports_overlaps_in_order() {
        let hits = find_pattern(&[0x90, 0x90, 0x90, 0xc3], &[Some(0x90), Some(0x90)], 10);
        assert_eq!(hits, vec![0, 1]);
        assert_eq!(find_pattern(&[1, 2, 3], &[Some(2), None], 5), vec![1]);
        assert_eq!(
            find_pattern(&[1, 2], &[Some(1), Some(2), Some(3)], 5),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn parse_expect_follows_the_python_grammar() {
        assert_eq!(
            parse_expect("48 89 ?? 5C"),
            Some(vec![Some(0x48), Some(0x89), None, Some(0x5c)])
        );
        assert_eq!(
            parse_expect("4889??5c"),
            Some(vec![Some(0x48), Some(0x89), None, Some(0x5c)])
        );
        assert_eq!(
            parse_expect("\\x48\\x89"),
            Some(vec![Some(0x48), Some(0x89)])
        );
        assert_eq!(
            parse_expect("0x48, 0x89"),
            Some(vec![Some(0x48), Some(0x89)])
        );
        assert_eq!(parse_expect("?? ??"), None);
        assert_eq!(parse_expect(""), None);
        assert_eq!(parse_expect("123"), None);
    }
}
