//! Whether an instance satisfies a TRACE-1 JSON Schema: the yes/no of `hydralysis.trace_schema.errors`.
//!
//! The Python validator returns the list of reasons; this port decides only whether that list would be empty, which is what
//! the importer needs to accept a line. A caller that wants the reasons asks the Python validator when the answer here is
//! "no", so the wording stays the Python's. Supported keywords are exactly the validator's: type, enum, const, pattern,
//! minimum, maximum, minLength, maxLength, required, properties, additionalProperties, items, minItems, maxItems, oneOf,
//! anyOf. A schema that uses another keyword, a pattern this port cannot translate faithfully, or a keyword value of an
//! unexpected type is [`Error::Unsupported`] (the Python then raises or answers as it always did).
//!
//! Python's equality is kept where the validator uses it: `const` and `enum` compare `1 == 1.0 == True`.

use crate::{Error, Result};
use fancy_regex::Regex;
use serde_json::{Map, Number, Value};
use std::cmp::Ordering;
use std::collections::HashMap;

const IGNORED: [&str; 7] = ["$schema", "$id", "title", "description", "$comment", "examples", "default"];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Object,
    Array,
    String,
    Null,
    Boolean,
    Integer,
    Number,
}

#[derive(Debug)]
enum Additional {
    /// Absent, `true` or anything the Python ignores.
    Allowed,
    Forbidden,
    Schema(Box<Node>),
}

#[derive(Debug)]
struct Node {
    kinds: Option<Vec<Kind>>,
    constant: Option<Value>,
    enumeration: Option<Vec<Value>>,
    pattern: Option<Regex>,
    min_length: u64,
    max_length: Option<u64>,
    minimum: Option<Number>,
    maximum: Option<Number>,
    required: Vec<String>,
    properties: HashMap<String, Node>,
    additional: Additional,
    min_items: u64,
    max_items: Option<u64>,
    items: Option<Box<Node>>,
    any_of: Option<Vec<Node>>,
    one_of: Option<Vec<Node>>,
}

/// A compiled schema.
#[derive(Debug)]
pub struct Schema {
    root: Node,
}

fn unsupported<T>(what: impl Into<String>) -> Result<T> {
    Err(Error::Unsupported(what.into()))
}

fn count(value: &Value, what: &str) -> Result<u64> {
    match value.as_u64() {
        Some(n) if value.is_u64() => Ok(n),
        _ => unsupported(format!("{what} is not a non-negative integer")),
    }
}

fn kind_of(name: &str) -> Result<Kind> {
    Ok(match name {
        "object" => Kind::Object,
        "array" => Kind::Array,
        "string" => Kind::String,
        "null" => Kind::Null,
        "boolean" => Kind::Boolean,
        "integer" => Kind::Integer,
        "number" => Kind::Number,
        other => return unsupported(format!("schema type {other:?}")),
    })
}

/// A Python `re` pattern as a `fancy_regex` one, for the constructs the schemas use. `$` matches at the end or before a
/// final newline in Python; everything the translation is not sure of is refused.
fn translate(pattern: &str) -> Result<String> {
    let chars: Vec<char> = pattern.chars().collect();
    let mut out = String::new();
    let mut at = 0;
    let mut in_class = false;
    let quantified = |c: char| matches!(c, '*' | '+' | '?' | '}');
    while at < chars.len() {
        let c = chars[at];
        let next = chars.get(at + 1).copied();
        match c {
            '\\' => {
                let Some(escaped) = next else { return unsupported("pattern ends with a backslash") };
                if escaped.is_ascii_alphanumeric() {
                    return unsupported("a letter or digit escape in a pattern");
                }
                out.push('\\');
                out.push(escaped);
                at += 2;
                continue;
            }
            '[' if in_class => return unsupported("a nested class in a pattern"),
            '[' => {
                in_class = true;
                out.push(c);
                at += 1;
                // a leading `^` and a literal `]` first in the class
                if chars.get(at) == Some(&'^') {
                    out.push('^');
                    at += 1;
                }
                if chars.get(at) == Some(&']') {
                    return unsupported("a literal bracket first in a class");
                }
                continue;
            }
            ']' if in_class => {
                in_class = false;
                out.push(c);
            }
            '&' | '~' | '-' if in_class && next == Some(c) => return unsupported("a class operator"),
            '$' if !in_class => out.push_str(r"(?=\n?\z)"),
            '(' if !in_class => {
                out.push('(');
                if next == Some('?') {
                    match chars.get(at + 2) {
                        Some(':') | Some('!') | Some('=') => {
                            out.push('?');
                            out.push(chars[at + 2]);
                            at += 3;
                            continue;
                        }
                        _ => return unsupported("a group flag or lookbehind in a pattern"),
                    }
                }
            }
            '{' if !in_class => {
                let close = chars[at..].iter().position(|&x| x == '}').map(|p| at + p);
                let Some(close) = close else { return unsupported("an unclosed brace in a pattern") };
                let body: String = chars[at + 1..close].iter().collect();
                let ok = !body.is_empty()
                    && body.split(',').count() <= 2
                    && body.split(',').all(|part| part.chars().all(|d| d.is_ascii_digit()))
                    && !body.starts_with(',');
                if !ok {
                    return unsupported("a brace that is not a counted repeat");
                }
                out.push_str(&format!("{{{body}}}"));
                at = close + 1;
                if chars.get(at).is_some_and(|&x| x == '+') {
                    return unsupported("a possessive quantifier");
                }
                continue;
            }
            c if quantified(c) && !in_class && c != '}' => {
                out.push(c);
                at += 1;
                if chars.get(at).is_some_and(|&x| x == '+') {
                    return unsupported("a possessive quantifier");
                }
                continue;
            }
            c => out.push(c),
        }
        at += 1;
    }
    if in_class {
        return unsupported("an unclosed class in a pattern");
    }
    Ok(out)
}

fn compile_node(schema: &Value) -> Result<Node> {
    let Some(map) = schema.as_object() else { return unsupported("a schema that is not an object") };
    for key in map.keys() {
        let known = matches!(
            key.as_str(),
            "type"
                | "enum"
                | "const"
                | "pattern"
                | "minimum"
                | "maximum"
                | "minLength"
                | "maxLength"
                | "required"
                | "properties"
                | "additionalProperties"
                | "items"
                | "minItems"
                | "maxItems"
                | "oneOf"
                | "anyOf"
        );
        if !known && !IGNORED.contains(&key.as_str()) {
            return unsupported(format!("schema keyword {key}"));
        }
    }
    let kinds = match map.get("type") {
        None => None,
        Some(Value::String(name)) => Some(vec![kind_of(name)?]),
        Some(Value::Array(names)) => Some(
            names
                .iter()
                .map(|name| name.as_str().map_or_else(|| unsupported("a type that is not text"), kind_of))
                .collect::<Result<Vec<_>>>()?,
        ),
        Some(_) => return unsupported("type is neither text nor a list"),
    };
    let enumeration = match map.get("enum") {
        None => None,
        Some(Value::Array(values)) => Some(values.clone()),
        Some(_) => return unsupported("enum is not a list"),
    };
    let pattern = match map.get("pattern") {
        None => None,
        Some(Value::String(text)) => {
            let translated = translate(text)?;
            Some(Regex::new(&translated).map_err(|error| Error::Unsupported(format!("pattern {text:?}: {error}")))?)
        }
        Some(_) => return unsupported("pattern is not text"),
    };
    let number = |key: &str| -> Result<Option<Number>> {
        match map.get(key) {
            None => Ok(None),
            Some(Value::Number(n)) => Ok(Some(n.clone())),
            Some(_) => unsupported(format!("{key} is not a number")),
        }
    };
    let counted = |key: &str| -> Result<Option<u64>> { map.get(key).map(|v| count(v, key)).transpose() };
    let mut properties = HashMap::new();
    match map.get("properties") {
        None => {}
        Some(Value::Object(entries)) => {
            for (name, schema) in entries {
                properties.insert(name.clone(), compile_node(schema)?);
            }
        }
        Some(_) => return unsupported("properties is not an object"),
    }
    let additional = match map.get("additionalProperties") {
        Some(Value::Bool(false)) => Additional::Forbidden,
        Some(value @ Value::Object(_)) => Additional::Schema(Box::new(compile_node(value)?)),
        _ => Additional::Allowed,
    };
    let required = match map.get("required") {
        None => Vec::new(),
        Some(Value::Array(names)) => names
            .iter()
            .map(|name| name.as_str().map(str::to_owned).ok_or_else(|| Error::Unsupported("required names are not text".to_owned())))
            .collect::<Result<Vec<_>>>()?,
        Some(_) => return unsupported("required is not a list"),
    };
    let items = match map.get("items") {
        None => None,
        Some(value @ Value::Object(_)) => Some(Box::new(compile_node(value)?)),
        Some(_) => return unsupported("items is not a schema"),
    };
    let alternatives = |key: &str| -> Result<Option<Vec<Node>>> {
        match map.get(key) {
            None => Ok(None),
            Some(Value::Array(options)) => options.iter().map(compile_node).collect::<Result<Vec<_>>>().map(Some),
            Some(_) => unsupported(format!("{key} is not a list")),
        }
    };
    Ok(Node {
        kinds,
        constant: map.get("const").cloned(),
        enumeration,
        pattern,
        min_length: counted("minLength")?.unwrap_or(0),
        max_length: counted("maxLength")?,
        minimum: number("minimum")?,
        maximum: number("maximum")?,
        required,
        properties,
        additional,
        min_items: counted("minItems")?.unwrap_or(0),
        max_items: counted("maxItems")?,
        items,
        any_of: alternatives("anyOf")?,
        one_of: alternatives("oneOf")?,
    })
}

/// Python's `==` between two JSON values (`1 == 1.0 == True`).
pub fn py_eq(a: &Value, b: &Value) -> bool {
    fn numeric(value: &Value) -> Option<Number> {
        match value {
            Value::Number(n) => Some(n.clone()),
            Value::Bool(flag) => Some(Number::from(u8::from(*flag))),
            _ => None,
        }
    }
    if let (Some(x), Some(y)) = (numeric(a), numeric(b)) {
        return compare(&x, &y) == Some(Ordering::Equal);
    }
    match (a, b) {
        (Value::Null, Value::Null) => true,
        (Value::String(x), Value::String(y)) => x == y,
        (Value::Array(x), Value::Array(y)) => x.len() == y.len() && x.iter().zip(y).all(|(p, q)| py_eq(p, q)),
        (Value::Object(x), Value::Object(y)) => {
            x.len() == y.len() && x.iter().all(|(key, value)| y.get(key).is_some_and(|other| py_eq(value, other)))
        }
        _ => false,
    }
}

/// The exact order of two JSON numbers, as Python compares an int with an int or a float.
pub fn compare(a: &Number, b: &Number) -> Option<Ordering> {
    fn integer(n: &Number) -> Option<i128> {
        n.as_i64().map(i128::from).or_else(|| n.as_u64().map(i128::from))
    }
    match (integer(a), integer(b)) {
        (Some(x), Some(y)) => Some(x.cmp(&y)),
        (Some(x), None) => compare_int_float(x, b.as_f64()?),
        (None, Some(y)) => compare_int_float(y, a.as_f64()?).map(Ordering::reverse),
        (None, None) => a.as_f64()?.partial_cmp(&b.as_f64()?),
    }
}

fn compare_int_float(int: i128, float: f64) -> Option<Ordering> {
    if float.is_nan() {
        return None;
    }
    if float >= 2f64.powi(100) {
        return Some(Ordering::Less);
    }
    if float <= -(2f64.powi(100)) {
        return Some(Ordering::Greater);
    }
    let floor = float.floor();
    match int.cmp(&(floor as i128)) {
        Ordering::Equal if float > floor => Some(Ordering::Less),
        other => Some(other),
    }
}

fn is_kind(kind: Kind, value: &Value) -> bool {
    match kind {
        Kind::Object => value.is_object(),
        Kind::Array => value.is_array(),
        Kind::String => value.is_string(),
        Kind::Null => value.is_null(),
        Kind::Boolean => value.is_boolean(),
        Kind::Integer => value.as_i64().is_some() || value.as_u64().is_some(),
        Kind::Number => value.is_number(),
    }
}

impl Node {
    fn accepts(&self, value: &Value) -> Result<bool> {
        if let Some(kinds) = &self.kinds
            && !kinds.iter().any(|kind| is_kind(*kind, value))
        {
            return Ok(false);
        }
        if let Some(constant) = &self.constant
            && !py_eq(value, constant)
        {
            return Ok(false);
        }
        if let Some(options) = &self.enumeration
            && !options.iter().any(|option| py_eq(value, option))
        {
            return Ok(false);
        }
        match value {
            Value::String(text) => {
                if let Some(pattern) = &self.pattern
                    && !pattern.is_match(text).map_err(|error| Error::Unsupported(format!("pattern match: {error}")))?
                {
                    return Ok(false);
                }
                let length = text.chars().count() as u64;
                if length < self.min_length || self.max_length.is_some_and(|max| length > max) {
                    return Ok(false);
                }
            }
            Value::Number(number) => {
                if self.minimum.as_ref().is_some_and(|min| compare(number, min) == Some(Ordering::Less)) {
                    return Ok(false);
                }
                if self.maximum.as_ref().is_some_and(|max| compare(number, max) == Some(Ordering::Greater)) {
                    return Ok(false);
                }
            }
            Value::Object(map) => {
                if !self.accepts_members(map)? {
                    return Ok(false);
                }
            }
            Value::Array(items) => {
                let length = items.len() as u64;
                if length < self.min_items || self.max_items.is_some_and(|max| length > max) {
                    return Ok(false);
                }
                if let Some(schema) = &self.items {
                    for item in items {
                        if !schema.accepts(item)? {
                            return Ok(false);
                        }
                    }
                }
            }
            _ => {}
        }
        if let Some(options) = &self.any_of {
            let mut any = false;
            for option in options {
                if option.accepts(value)? {
                    any = true;
                    break;
                }
            }
            if !any {
                return Ok(false);
            }
        }
        if let Some(options) = &self.one_of {
            let mut matched = 0usize;
            for option in options {
                if option.accepts(value)? {
                    matched += 1;
                }
            }
            if matched != 1 {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn accepts_members(&self, map: &Map<String, Value>) -> Result<bool> {
        if self.required.iter().any(|key| !map.contains_key(key)) {
            return Ok(false);
        }
        for (key, value) in map {
            if let Some(schema) = self.properties.get(key) {
                if !schema.accepts(value)? {
                    return Ok(false);
                }
            } else {
                match &self.additional {
                    Additional::Forbidden => return Ok(false),
                    Additional::Schema(schema) => {
                        if !schema.accepts(value)? {
                            return Ok(false);
                        }
                    }
                    Additional::Allowed => {}
                }
            }
        }
        Ok(true)
    }
}

impl Schema {
    /// Compile SCHEMA (the parsed schema file).
    pub fn compile(schema: &Value) -> Result<Self> {
        Ok(Self { root: compile_node(schema)? })
    }

    /// Whether `trace_schema.errors(instance, schema)` would be empty.
    pub fn accepts(&self, instance: &Value) -> Result<bool> {
        self.root.accepts(instance)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn event_schema() -> Schema {
        let text = include_str!("../../../../src/hydralysis/trace_schema/event.schema.json");
        Schema::compile(&serde_json::from_str(text).unwrap()).unwrap()
    }

    fn event() -> Value {
        json!({"kind": "core.state.write", "source_id": "s", "source_seq": 0, "producer_gen": 1, "clock_domain": "mono",
               "t_mono_ns": 5, "confidence": "exact", "payload": {"x": 1.5}, "callstack": [1, 2]})
    }

    #[test]
    fn a_valid_event_is_accepted() {
        assert!(event_schema().accepts(&event()).unwrap());
    }

    #[test]
    fn each_kind_of_fault_is_refused() {
        let schema = event_schema();
        let mut broken: Vec<Value> = Vec::new();
        for (key, bad) in [
            ("kind", json!("Core.state")),
            ("kind", json!("core.nothing")),
            ("kind", json!("a")),
            ("kind", json!(5)),
            ("kind", json!("core.state.write\n\n")),
            ("source_id", json!("")),
            ("source_seq", json!(-1)),
            ("source_seq", json!(1.5)),
            ("source_seq", json!(true)),
            ("confidence", json!("guess")),
            ("callstack", json!([-1])),
            ("callstack", json!("no")),
            ("payload", json!([])),
            ("hash", json!("xyz")),
            ("extra", json!(1)),
        ] {
            let mut event = event();
            event[key] = bad;
            broken.push(event);
        }
        let mut missing = event();
        missing.as_object_mut().unwrap().remove("clock_domain");
        broken.push(missing);
        broken.push(json!([]));
        broken.push(json!("text"));
        for event in &broken {
            assert!(!schema.accepts(event).unwrap(), "{event}");
        }
    }

    #[test]
    fn python_dollar_accepts_one_trailing_newline_and_the_lookahead_is_honoured() {
        let schema = event_schema();
        for (kind, ok) in [
            ("core.state.write\n", true),
            ("my_app.thing", true),
            ("my_app.thing\n", true),
            ("core.unknown", false),
            ("core.session.start", true),
            ("core.session.starts", false),
            ("a.b.c", false),
            ("a.b\n\n", false),
            ("é.b", false),
        ] {
            let mut event = event();
            event["kind"] = json!(kind);
            assert_eq!(schema.accepts(&event).unwrap(), ok, "{kind:?}");
        }
        let mut hashed = event();
        hashed["hash"] = json!(format!("{}\n", "a".repeat(64)));
        assert!(schema.accepts(&hashed).unwrap());
        hashed["hash"] = json!("A".repeat(64));
        assert!(!schema.accepts(&hashed).unwrap());
    }

    #[test]
    fn enum_and_const_compare_the_way_python_does() {
        let schema = Schema::compile(&json!({"enum": [1, "a", null]})).unwrap();
        for (value, ok) in [
            (json!(1), true),
            (json!(1.0), true),
            (json!(true), true),
            (json!("a"), true),
            (json!(null), true),
            (json!(2), false),
            (json!(false), false),
        ] {
            assert_eq!(schema.accepts(&value).unwrap(), ok, "{value}");
        }
        let constant = Schema::compile(&json!({"const": [1, {"a": 2}]})).unwrap();
        assert!(constant.accepts(&json!([1.0, {"a": 2}])).unwrap());
        assert!(!constant.accepts(&json!([1, {"a": 3}])).unwrap());
    }

    #[test]
    fn numeric_bounds_compare_exactly() {
        let schema = Schema::compile(&json!({"type": "number", "minimum": 0, "maximum": 18446744073709551615u64})).unwrap();
        assert!(schema.accepts(&json!(18446744073709551615u64)).unwrap());
        assert!(schema.accepts(&json!(0)).unwrap());
        assert!(schema.accepts(&json!(0.5)).unwrap());
        assert!(!schema.accepts(&json!(-0.5)).unwrap());
        assert!(!schema.accepts(&json!(1.9e19)).unwrap());
    }

    #[test]
    fn one_of_any_of_items_and_additional_schemas() {
        let schema = Schema::compile(&json!({
            "type": "object", "additionalProperties": {"type": "integer"},
            "properties": {"list": {"type": "array", "items": {"type": ["string", "null"]}, "minItems": 1, "maxItems": 2}},
            "oneOf": [{"required": ["a"]}, {"required": ["b"]}], "anyOf": [{"required": ["a"]}, {"required": ["list"]}]
        }))
        .unwrap();
        assert!(schema.accepts(&json!({"a": 1})).unwrap());
        assert!(!schema.accepts(&json!({"a": 1, "b": 2})).unwrap());
        assert!(!schema.accepts(&json!({"b": 1})).unwrap());
        assert!(schema.accepts(&json!({"b": 1, "list": ["x", null]})).unwrap());
        assert!(!schema.accepts(&json!({"a": 1, "list": []})).unwrap());
        assert!(!schema.accepts(&json!({"a": 1.5})).unwrap());
    }

    #[test]
    fn what_the_port_cannot_judge_is_unsupported() {
        for schema in [
            json!({"format": "date"}),
            json!({"type": "weird"}),
            json!({"pattern": "\\d+"}),
            json!({"pattern": "(?i)a"}),
            json!({"pattern": "a++"}),
            json!({"pattern": "[[a]]"}),
            json!({"minLength": -1}),
            json!({"enum": 1}),
            json!(true),
            json!({"properties": {"a": {"$ref": "#"}}}),
            json!({"pattern": "a{,3}"}),
        ] {
            assert!(matches!(Schema::compile(&schema), Err(Error::Unsupported(_))), "{schema}");
        }
    }
}
