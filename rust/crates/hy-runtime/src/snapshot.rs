//! Flattening, hashing and comparison of runtime snapshots (port of the pure parts of `runtime_snapshot.py`).
//!
//! A snapshot is plain JSON. `flatten` turns it into `path -> scalar` rows; `compare` reports the rows that differ after the
//! volatile masks. Everything here reproduces the Python module's output byte for byte for the data a session produces; an
//! input it does not model (a bignum, a non-finite float, a mask with a `[` class, a deeper nesting than the Python
//! recursion limit would allow, a value whose `str()` is not plain) is [`Unmodelled`] and the Python function answers.
//! Argument validation (`check_mask`, `check_predicates`) stays in Python and runs before these functions are called.

use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::fmt::{self, Write as _};

/// Longest string shown in a difference before it is cut (`SHOWN` in Python).
const SHOWN: usize = 96;
/// Deepest nesting walked; Python's recursion limit would fail first on anything deeper, so the Python answers.
const MAX_DEPTH: usize = 200;
/// The input is outside the shapes this port models: run the Python implementation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Unmodelled;

impl fmt::Display for Unmodelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("outside the modelled shapes")
    }
}

impl std::error::Error for Unmodelled {}

type Result<T> = std::result::Result<T, Unmodelled>;

/// `str(value)` for the scalars a snapshot holds; floats and containers are left to Python (`repr` rules).
fn text_of(value: &Value) -> Result<String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Number(n) if n.is_i64() || n.is_u64() => Ok(n.to_string()),
        Value::Bool(true) => Ok("True".into()),
        Value::Bool(false) => Ok("False".into()),
        Value::Null => Ok("None".into()),
        _ => Err(Unmodelled),
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

fn key_of(text: &str) -> String {
    text.replace('/', "_")
}

/// The row key of list item `index` under the list at `last`, the last component of the list's path.
fn row_key(last: &str, index: usize, item: &Value) -> Result<String> {
    let Value::Object(item) = item else { return Ok(index.to_string()) };
    if last == "hooks" {
        let field = |name: &str| item.get(name).map_or(Ok(String::new()), text_of);
        let pick = |name: &str| item.get(name).filter(|v| truthy(v));
        let where_ = match pick("export").or_else(|| pick("rva")) {
            Some(v) => text_of(v)?,
            None => index.to_string(),
        };
        return Ok(format!("{}:{}:{}", field("module")?, where_, field("kind")?));
    }
    match item.get("name") {
        Some(Value::Null) | None => Ok(index.to_string()),
        Some(name) => {
            let name = text_of(name)?;
            Ok(if last == "modules" { name.to_lowercase() } else { name })
        }
    }
}

/// `path -> scalar` rows, in the order Python's `flatten` inserts them (a later row with the same path replaces the
/// value and keeps the earlier position).
///
/// # Errors
///
/// [`Unmodelled`] for non-object records, deep nesting or a value Python would format with `repr`.
fn flatten(record: &Value) -> Result<Map<String, Value>> {
    let mut rows = Map::new();
    walk("", record, &mut rows, 0)?;
    Ok(rows)
}

fn walk(path: &str, value: &Value, rows: &mut Map<String, Value>, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Unmodelled);
    }
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for key in keys {
                let child = if path.is_empty() { key_of(key) } else { format!("{path}/{}", key_of(key)) };
                walk(&child, &map[key], rows, depth + 1)?;
            }
        }
        Value::Array(items) => {
            let last = path.rsplit_once('/').map_or(path, |(_, tail)| tail);
            let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
            for (index, item) in items.iter().enumerate() {
                let key = key_of(&row_key(last, index, item)?);
                let count = seen.entry(key.clone()).and_modify(|n| *n += 1).or_insert(1);
                let child = if *count == 1 { format!("{path}/{key}") } else { format!("{path}/{key}#{count}") };
                walk(&child, item, rows, depth + 1)?;
            }
        }
        scalar => {
            rows.insert(path.to_owned(), scalar.clone());
        }
    }
    Ok(())
}

/// A number as Python compares it: integers exactly, floats exactly, bools as 0 and 1.
#[derive(Clone, Copy)]
enum Num {
    Int(i128),
    Float(f64),
}

fn num_of(value: &Value) -> Option<Num> {
    match value {
        Value::Bool(b) => Some(Num::Int(i128::from(*b))),
        Value::Number(n) => n
            .as_i64()
            .map(|i| Num::Int(i128::from(i)))
            .or_else(|| n.as_u64().map(|u| Num::Int(i128::from(u))))
            .or_else(|| n.as_f64().map(Num::Float)),
        _ => None,
    }
}

fn num_cmp(a: Num, b: Num) -> Option<Ordering> {
    match (a, b) {
        (Num::Int(x), Num::Int(y)) => Some(x.cmp(&y)),
        (Num::Float(x), Num::Float(y)) => x.partial_cmp(&y),
        (Num::Int(x), Num::Float(y)) => int_float_cmp(x, y),
        (Num::Float(x), Num::Int(y)) => int_float_cmp(y, x).map(Ordering::reverse),
    }
}

/// Exact comparison of an integer with a finite float.
fn int_float_cmp(int: i128, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    // JSON integers fit 64 bits, so a float beyond 1e30 in magnitude is past all of them.
    if float >= 1e30 {
        return Some(Ordering::Less);
    }
    if float <= -1e30 {
        return Some(Ordering::Greater);
    }
    let whole = float.floor();
    let whole_int = whole as i128;
    match int.cmp(&whole_int) {
        Ordering::Equal => Some(if float > whole { Ordering::Less } else { Ordering::Equal }),
        other => Some(other),
    }
}

/// Python's `a == b` for two JSON scalars.
fn py_eq(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Null, Value::Null) => true,
        _ => match (num_of(a), num_of(b)) {
            (Some(x), Some(y)) => num_cmp(x, y) == Some(Ordering::Equal),
            _ => false,
        },
    }
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False)`.
///
/// # Errors
///
/// [`Unmodelled`] for nesting deeper than the walk limit.
pub fn canonical(value: &Value) -> Result<String> {
    let mut out = String::new();
    write_canonical(value, &mut out, 0)?;
    Ok(out)
}

fn write_canonical(value: &Value, out: &mut String, depth: usize) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Unmodelled);
    }
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => match n.as_f64().filter(|_| !(n.is_i64() || n.is_u64())) {
            Some(f) => out.push_str(&crate::decode::float_repr(f)),
            None => write!(out, "{n}").expect("writing to a String cannot fail"),
        },
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out, depth + 1)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_canonical(&map[key], out, depth + 1)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

/// A JSON string with `ensure_ascii=True` escaping, appended to `out`.
pub fn write_string(text: &str, out: &mut String) {
    out.push('"');
    let mut run = 0; // start of the plain text not yet copied
    for (index, c) in text.char_indices() {
        if (' '..='~').contains(&c) && c != '"' && c != '\\' {
            continue;
        }
        out.push_str(&text[run..index]);
        run = index + c.len_utf8();
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            c => {
                let mut units = [0u16; 2];
                for unit in c.encode_utf16(&mut units) {
                    write!(out, "\\u{unit:04x}").expect("writing to a String cannot fail");
                }
            }
        }
    }
    out.push_str(&text[run..]);
    out.push('"');
}

/// Lower-case hex SHA-256 of `bytes`.
#[must_use]
pub fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes).iter().fold(String::with_capacity(64), |mut hex, byte| {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
        hex
    })
}

/// A path pattern as `fnmatch.fnmatchcase` reads it: `*` any run, `?` one character, everything else literal.
fn glob(pattern: &[char], text: &[char]) -> bool {
    let (mut p, mut t, mut star, mut mark) = (0, 0, None, 0);
    while t < text.len() {
        if p < pattern.len() && (pattern[p] == '?' || (pattern[p] != '*' && pattern[p] == text[t])) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == '*' {
            star = Some(p);
            mark = t;
            p += 1;
        } else if let Some(s) = star {
            p = s + 1;
            mark += 1;
            t = mark;
        } else {
            return false;
        }
    }
    pattern[p..].iter().all(|c| *c == '*')
}

/// The patterns, checked to be ones the glob above reads like `fnmatch` does.
struct Patterns(Vec<Vec<char>>);

impl Patterns {
    fn new(patterns: &[String]) -> Result<Self> {
        if patterns.iter().any(|p| p.contains('[')) {
            return Err(Unmodelled); // a character class: left to fnmatch
        }
        Ok(Self(patterns.iter().map(|p| p.chars().collect()).collect()))
    }

    fn masks(&self, path: &[char]) -> bool {
        self.0.iter().any(|pattern| glob(pattern, path))
    }
}

/// SHA-256 of the record's rows without those matching `volatile` (the default-volatile patterns plus the caller's mask):
/// equal for two runs that agree.
///
/// # Errors
///
/// [`Unmodelled`] as for [`flatten`] and for patterns with a `[` class.
pub fn stable_sha256(record: &Value, volatile: &[String]) -> Result<String> {
    let patterns = Patterns::new(volatile)?;
    let kept: Map<String, Value> =
        flatten(record)?.into_iter().filter(|(path, _)| !patterns.masks(&path.chars().collect::<Vec<_>>())).collect();
    Ok(sha256_hex(canonical(&Value::Object(kept))?.as_bytes()))
}

/// A string cut to `SHOWN` characters with its length and hash, as a difference shows it.
fn shown(value: Option<&Value>) -> Value {
    match value {
        None => Value::Null,
        Some(Value::String(s)) if s.chars().nth(SHOWN).is_some() => {
            let head: String = s.chars().take(SHOWN).collect();
            let digest = sha256_hex(s.as_bytes());
            Value::String(format!("{head}...[{} chars, sha256 {}]", s.chars().count(), &digest[..16]))
        }
        Some(other) => other.clone(),
    }
}

fn object(pairs: Vec<(&str, Value)>) -> Map<String, Value> {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

/// One predicate evaluated against the two row sets (`_evaluate` in Python). `predicate` is a checked `{path, op, value?}`.
fn evaluate(predicate: &Map<String, Value>, rows_a: &Map<String, Value>, rows_b: &Map<String, Value>) -> Result<Value> {
    let path = predicate.get("path").and_then(Value::as_str).ok_or(Unmodelled)?;
    let op = predicate.get("op").and_then(Value::as_str).ok_or(Unmodelled)?;
    let (a, b) = (rows_a.get(path), rows_b.get(path));
    let mut result = predicate.clone();
    result.insert("a".into(), shown(a));
    result.insert("b".into(), shown(b));
    let finish = |mut result: Map<String, Value>, ok: bool, reason: Option<&str>| {
        result.insert("ok".into(), Value::Bool(ok));
        if let Some(reason) = reason {
            result.insert("reason".into(), reason.into());
        }
        Ok(Value::Object(result))
    };
    let is_number = |v: Option<&Value>| matches!(v, Some(Value::Number(_)));
    let ordering = |x: &Value, y: &Value| match (num_of(x), num_of(y)) {
        (Some(x), Some(y)) => Ok(num_cmp(x, y)),
        _ => Err(Unmodelled),
    };
    let ok = match op {
        "present" => b.is_some(),
        "absent" => b.is_none(),
        _ => {
            let (Some(a), Some(b)) = (a, b) else {
                let reason = match (rows_a.contains_key(path), rows_b.contains_key(path)) {
                    (false, false) => "the path is not in both snapshots",
                    (true, _) => "the path is not in snapshot b",
                    (false, true) => "the path is not in snapshot a",
                };
                return finish(result, false, Some(reason));
            };
            match op {
                "unchanged" => py_eq(a, b),
                "changed" => !py_eq(a, b),
                "increased" | "decreased" => {
                    if !(is_number(Some(a)) && is_number(Some(b))) {
                        return finish(result, false, Some("not numbers"));
                    }
                    let want = if op == "increased" { Ordering::Greater } else { Ordering::Less };
                    ordering(b, a)? == Some(want)
                }
                _ => {
                    let value = predicate.get("value").ok_or(Unmodelled)?;
                    match op {
                        "eq" => py_eq(b, value),
                        "ne" => !py_eq(b, value),
                        _ if !is_number(Some(b)) => return finish(result, false, Some("snapshot b's value is not a number")),
                        "between" => {
                            let bounds = value.as_array().filter(|v| v.len() == 2).ok_or(Unmodelled)?;
                            ordering(&bounds[0], b)?.is_some_and(Ordering::is_le) && ordering(b, &bounds[1])?.is_some_and(Ordering::is_le)
                        }
                        "lt" => ordering(b, value)? == Some(Ordering::Less),
                        "le" => ordering(b, value)?.is_some_and(Ordering::is_le),
                        "gt" => ordering(b, value)? == Some(Ordering::Greater),
                        "ge" => ordering(b, value)?.is_some_and(Ordering::is_ge),
                        _ => return Err(Unmodelled),
                    }
                }
            }
        }
    };
    finish(result, ok, None)
}

/// What differs between two snapshots, and whether the checked predicates hold (`compare` in Python, after its argument
/// checks). `patterns` is the full mask list (defaults included when they apply); `volatile` is what `stable_sha256` hides
/// (the defaults plus the caller's own masks, whether or not the defaults apply to the differences).
///
/// # Errors
///
/// [`Unmodelled`] for inputs outside the modelled shapes.
pub fn compare(a: &Value, b: &Value, patterns: &[String], volatile: &[String], predicates: &[Value], limit: usize) -> Result<Value> {
    if !(a.is_object() && b.is_object()) {
        return Err(Unmodelled);
    }
    let compiled = Patterns::new(patterns)?;
    let (rows_a, rows_b) = (flatten(a)?, flatten(b)?);
    let mut paths: Vec<&String> = rows_a.keys().chain(rows_b.keys().filter(|k| !rows_a.contains_key(*k))).collect();
    paths.sort();
    let (mut differences, mut masked_count, mut only_a, mut only_b) = (Vec::new(), 0usize, Vec::new(), Vec::new());
    for path in &paths {
        let (in_a, in_b) = (rows_a.get(*path), rows_b.get(*path));
        if let (Some(x), Some(y)) = (in_a, in_b)
            && py_eq(x, y)
        {
            continue;
        }
        if compiled.masks(&path.chars().collect::<Vec<_>>()) {
            masked_count += 1;
            continue;
        }
        let mut row = object(vec![("path", Value::String((*path).clone())), ("a", shown(in_a)), ("b", shown(in_b))]);
        match (in_a.is_some(), in_b.is_some()) {
            (true, false) => {
                row.insert("only_in".into(), "a".into());
                only_a.push(Value::String((*path).clone()));
            }
            (false, true) => {
                row.insert("only_in".into(), "b".into());
                only_b.push(Value::String((*path).clone()));
            }
            _ => {}
        }
        differences.push(Value::Object(row));
    }
    let verdicts = predicates.iter().map(|p| evaluate(p.as_object().ok_or(Unmodelled)?, &rows_a, &rows_b)).collect::<Result<Vec<_>>>()?;
    let equal = differences.is_empty();
    let predicates_ok = verdicts.iter().all(|v| v["ok"] == Value::Bool(true));
    let count = differences.len();
    differences.truncate(limit);
    only_a.truncate(20);
    only_b.truncate(20);
    let snapshot = |record: &Value| -> Result<Value> {
        Ok(Value::Object(object(vec![
            ("snapshot", record.get("snapshot").cloned().unwrap_or(Value::Null)),
            ("stable_sha256", Value::String(stable_sha256(record, volatile)?)),
        ])))
    };
    Ok(Value::Object(object(vec![
        ("equal", equal.into()),
        ("ok", (if predicates.is_empty() { equal } else { predicates_ok }).into()),
        ("differences", Value::Array(differences)),
        ("difference_count", count.into()),
        ("truncated", (count > limit).into()),
        ("masked_differences", masked_count.into()),
        ("mask", Value::Array(patterns.iter().map(|p| Value::String(p.clone())).collect())),
        ("only_in_a", Value::Array(only_a)),
        ("only_in_b", Value::Array(only_b)),
        ("predicates", Value::Array(verdicts)),
        ("rows_compared", paths.len().into()),
        ("a", snapshot(a)?),
        ("b", snapshot(b)?),
    ])))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn canonical_escapes_like_json_dumps() {
        let value = json!({"b": [1, 2.5, null, true], "a": "é\"\n\u{1F600}\u{7f}\u{1}"});
        let bs = '\\';
        let want = format!(r#"{{"a":"{bs}u00e9{bs}"{bs}n{bs}ud83d{bs}ude00{bs}u007f{bs}u0001","b":[1,2.5,null,true]}}"#);
        assert_eq!(canonical(&value).unwrap(), want);
    }

    #[test]
    fn flatten_keys_lists_by_name_and_numbers_duplicates() {
        let record = json!({"modules": [{"name": "Game.EXE", "size": 1}, {"name": "kernel32.dll"}, {"name": "kernel32.dll"}],
                            "hooks": [{"module": "a", "rva": "0x10", "kind": "observe"}, {"module": "a", "kind": "break"}],
                            "regions": {"a/b": {"x": 1}}, "empty": {}, "plain": [5, 6]});
        let rows = flatten(&record).unwrap();
        let paths: Vec<&str> = rows.keys().map(String::as_str).collect();
        assert_eq!(
            paths,
            [
                "hooks/a:0x10:observe/kind",
                "hooks/a:0x10:observe/module",
                "hooks/a:0x10:observe/rva",
                "hooks/a:1:break/kind",
                "hooks/a:1:break/module",
                "modules/game.exe/name",
                "modules/game.exe/size",
                "modules/kernel32.dll/name",
                "modules/kernel32.dll#2/name",
                "plain/0",
                "plain/1",
                "regions/a_b/x"
            ]
        );
    }

    #[test]
    fn python_equality_across_numeric_types() {
        assert!(py_eq(&json!(1), &json!(1.0)));
        assert!(py_eq(&json!(true), &json!(1)));
        assert!(!py_eq(&json!("1"), &json!(1)));
        assert!(!py_eq(&json!(null), &json!(0)));
        assert!(!py_eq(&json!(9007199254740993_i64), &json!(9007199254740992.0)));
    }

    #[test]
    fn glob_reads_star_and_question() {
        let m = |p: &str, t: &str| glob(&p.chars().collect::<Vec<_>>(), &t.chars().collect::<Vec<_>>());
        assert!(m("hooks/*/hook_id", "hooks/a:1:b/hook_id"));
        assert!(m("counters/*", "counters/x/y"));
        assert!(!m("counters/*", "counter/x"));
        assert!(m("a?c", "abc") && !m("a?c", "ac"));
        assert!(m("*", "") && m("**a", "xxa") && !m("a*b", "acbc"));
    }

    #[test]
    fn compare_masks_and_counts() {
        let a = json!({"snapshot": "s1", "counters": {"n": 1}, "regions": {"r": {"v": 1}}});
        let b = json!({"snapshot": "s2", "counters": {"n": 2}, "regions": {"r": {"v": 1.0, "w": "x"}}});
        let patterns: Vec<String> = ["snapshot", "counters/*"].map(String::from).to_vec();
        let out = compare(&a, &b, &patterns, &patterns, &[], 200).unwrap();
        assert_eq!(out["equal"], false);
        assert_eq!(out["masked_differences"], 2, "snapshot and counters/n");
        assert_eq!(out["difference_count"], 1);
        assert_eq!(out["differences"][0], json!({"path": "regions/r/w", "a": null, "b": "x", "only_in": "b"}));
    }
}
