//! Decoding of bytes a probe captured, outside the target process (port of `runtime_decode.py`).
//!
//! Everything works on `serde_json::Value` with `preserve_order`, so the key order of every row is the order the Python
//! module builds it in. An input the port does not model (a float where Python would call `int()`, a negative struct
//! offset, a non-string where Python would call `str()`, a bignum, ...) is [`DecodeError::Unmodelled`]: the caller runs
//! the Python function, which stays the specification. [`DecodeError::Invalid`] is a `ValueError` Python raises with
//! exactly that message.

use serde_json::{Map, Number, Value};
use std::fmt;

/// Most captures one probe accepts.
pub const MAX_CAPTURES: usize = 4;
/// Largest captured buffer, in bytes.
const MAX_SIZE: i64 = 4096;
/// Largest number of names one capture may carry.
const MAX_NAMES: usize = 100_000;
/// Longest label kept, in characters.
const MAX_LABEL: usize = 64;
/// Largest dereference offset (exclusive).
const MAX_OFFSET: u64 = 1 << 20;
/// Struct field offsets beyond this are not modelled (no overflow in the arithmetic below).
const MAX_FIELD_OFFSET: u64 = 1 << 40;
/// Number of argument registers a capture may name (`arg` is `0..MAX_ARG`).
const MAX_ARG: u64 = 7;

/// Why a decode call did not produce a value.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The Python module raises `ValueError` with this message.
    Invalid(String),
    /// Outside the modelled shapes: run the Python implementation.
    Unmodelled,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(message) => f.write_str(message),
            Self::Unmodelled => f.write_str("outside the modelled shapes"),
        }
    }
}

impl std::error::Error for DecodeError {}

fn invalid<T>(message: String) -> Result<T, DecodeError> {
    Err(DecodeError::Invalid(message))
}

/// A scalar type of the capture language (the keys of Python's `SCALARS`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scalar {
    I8,
    U8,
    I16,
    U16,
    I32,
    U32,
    I64,
    U64,
    F32,
    F64,
    Pointer,
    Bool,
}

impl Scalar {
    /// The canonical name, as Python spells it.
    pub fn name(self) -> &'static str {
        match self {
            Self::I8 => "i8",
            Self::U8 => "u8",
            Self::I16 => "i16",
            Self::U16 => "u16",
            Self::I32 => "i32",
            Self::U32 => "u32",
            Self::I64 => "i64",
            Self::U64 => "u64",
            Self::F32 => "f32",
            Self::F64 => "f64",
            Self::Pointer => "pointer",
            Self::Bool => "bool",
        }
    }

    /// Width in bytes.
    pub fn size(self) -> usize {
        match self {
            Self::I8 | Self::U8 | Self::Bool => 1,
            Self::I16 | Self::U16 => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 | Self::Pointer => 8,
        }
    }

    fn from_canonical(name: &str) -> Option<Self> {
        Some(match name {
            "i8" => Self::I8,
            "u8" => Self::U8,
            "i16" => Self::I16,
            "u16" => Self::U16,
            "i32" => Self::I32,
            "u32" => Self::U32,
            "i64" => Self::I64,
            "u64" => Self::U64,
            "f32" => Self::F32,
            "f64" => Self::F64,
            "pointer" => Self::Pointer,
            "bool" => Self::Bool,
            _ => return None,
        })
    }
}

/// Spellings from type corpora and Ghidra that name a canonical scalar.
fn alias(name: &str) -> &str {
    match name {
        "int8" | "char" => "i8",
        "uint8" | "byte" | "undefined1" | "uchar" => "u8",
        "int16" | "short" => "i16",
        "uint16" | "undefined2" | "word" | "ushort" => "u16",
        "int32" | "int" | "long" => "i32",
        "uint32" | "uint" | "undefined4" | "dword" | "ulong" => "u32",
        "int64" | "longlong" => "i64",
        "uint64" | "ulonglong" | "undefined8" | "qword" => "u64",
        "float" => "f32",
        "double" => "f64",
        other => other,
    }
}

/// Python's `str.strip()` whitespace: Unicode White_Space plus the four ASCII separators `\x1c..\x1f`.
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\x1c'..='\x1f').contains(&c)
}

/// The scalar a type name denotes (`scalar` in Python): trailing `*` is a pointer, aliases are resolved.
pub fn scalar(name: &str) -> Option<Scalar> {
    let name = name.trim_matches(py_space);
    if name.ends_with('*') {
        return Some(Scalar::Pointer);
    }
    Scalar::from_canonical(alias(name))
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

/// An integer-valued JSON number that is not a bool (Python's `isinstance(x, int) and not isinstance(x, bool)`).
fn plain_int(value: &Value) -> Option<&Number> {
    match value {
        Value::Number(n) if n.is_i64() || n.is_u64() => Some(n),
        _ => None,
    }
}

/// `int(value)` for the one shape the port models: an integer that fits `i64`.
fn int_of(value: &Value) -> Result<i64, DecodeError> {
    plain_int(value).and_then(Number::as_i64).ok_or(DecodeError::Unmodelled)
}

/// `str(value)` for strings only.
fn str_of(value: &Value) -> Result<&str, DecodeError> {
    value.as_str().ok_or(DecodeError::Unmodelled)
}

/// `int(text, 0)` for plain decimal, `0x`, `0o` and `0b` literals with an optional sign; anything else (whitespace,
/// underscores, leading zeros, junk) is `None` so that Python runs and answers or raises.
fn parse_int_base0(text: &str) -> Option<i128> {
    let (negative, rest) = match text.as_bytes().first()? {
        b'-' => (true, &text[1..]),
        b'+' => (false, &text[1..]),
        _ => (false, text),
    };
    let (radix, digits) = match rest.get(..2).map(str::to_ascii_lowercase).as_deref() {
        Some("0x") => (16, &rest[2..]),
        Some("0o") => (8, &rest[2..]),
        Some("0b") => (2, &rest[2..]),
        _ if rest.len() > 1 && rest.starts_with('0') => return None,
        _ => (10, rest),
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let value = i128::from_str_radix(digits, radix).ok()?;
    Some(if negative { -value } else { value })
}

/// `str(value)` for the JSON values a `names` entry holds in practice.
fn name_text(value: &Value) -> Result<String, DecodeError> {
    Ok(match value {
        Value::String(s) => s.clone(),
        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
        Value::Bool(true) => "True".into(),
        Value::Bool(false) => "False".into(),
        Value::Null => "None".into(),
        _ => return Err(DecodeError::Unmodelled),
    })
}

fn is_register_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (2..=5).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

fn object(pairs: Vec<(&str, Value)>) -> Value {
    Value::Object(pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect())
}

/// Validate the capture list of a probe request and return it normalised (`normalize` in Python).
///
/// # Errors
///
/// [`DecodeError::Invalid`] carries the `ValueError` message Python raises; [`DecodeError::Unmodelled`] means the
/// input has a shape Python would coerce and the caller must run the Python function.
pub fn normalize(captures: &Value) -> Result<Value, DecodeError> {
    let items = match captures {
        Value::Null => return Ok(Value::Array(Vec::new())),
        Value::Array(items) if items.len() <= MAX_CAPTURES => items,
        _ => return invalid(format!("capture must be a list of at most {MAX_CAPTURES} argument captures")),
    };
    items.iter().enumerate().map(|(index, item)| normalize_one(index, item)).collect::<Result<Vec<_>, _>>().map(Value::Array)
}

fn normalize_one(index: usize, item: &Value) -> Result<Value, DecodeError> {
    const KEYS: [&str; 7] = ["arg", "reg", "deref", "size", "as", "fields", "names"];
    let accepted = |key: &str| KEYS.contains(&key) || key == "label";
    let Some(item) = item.as_object().filter(|m| m.keys().all(|k| accepted(k))) else {
        return invalid(format!("capture {index} accepts arg or reg, deref, size, as, fields, names, label"));
    };
    let arg = item.get("arg").unwrap_or(&Value::Null);
    let reg = item.get("reg").unwrap_or(&Value::Null);
    if !reg.is_null() {
        let valid = arg.is_null() && reg.as_str().is_some_and(is_register_name);
        if !valid {
            return invalid(format!("capture {index}: reg is one register name (e.g. ecx, rdx), instead of arg"));
        }
    } else if !plain_int(arg).is_some_and(|n| n.as_u64().is_some_and(|v| v <= MAX_ARG)) {
        return invalid(format!("capture {index} needs arg 0..7 or reg"));
    }
    let deref_error = || invalid(format!("capture {index} deref is up to 4 offsets: read a pointer at each"));
    let deref = match item.get("deref") {
        None => Value::Array(Vec::new()),
        Some(Value::Array(offsets)) => {
            let in_range = |v: &Value| plain_int(v).is_some_and(|n| n.as_u64().is_some_and(|v| v < MAX_OFFSET));
            if offsets.len() > 4 || !offsets.iter().all(in_range) {
                return deref_error();
            }
            Value::Array(offsets.clone())
        }
        Some(_) => return deref_error(),
    };
    let mut kind = str_of(item.get("as").unwrap_or(&Value::String("hex".into())))?.to_owned();
    let mut fields = Vec::new();
    let needed: i64;
    if kind == "struct" {
        let listed = match item.get("fields") {
            None | Some(Value::Null) => &[][..],
            Some(Value::Array(listed)) => listed,
            Some(other) if !truthy(other) => &[][..],
            Some(_) => return Err(DecodeError::Unmodelled),
        };
        for field in listed {
            let field_error = || invalid(format!("capture {index} struct fields need name, offset and a scalar type"));
            let Some(field) = field.as_object() else { return field_error() };
            let type_name = match field.get("type") {
                None => "",
                Some(v) => str_of(v)?,
            };
            let (Some(Value::String(name)), Some(scalar)) = (field.get("name"), scalar(type_name)) else {
                return field_error();
            };
            let offset = field.get("offset").map_or(Ok(0), int_of)?;
            if offset.unsigned_abs() > MAX_FIELD_OFFSET {
                return Err(DecodeError::Unmodelled);
            }
            fields.push((name.clone(), offset, scalar));
        }
        if fields.is_empty() {
            return invalid(format!("capture {index} struct needs fields"));
        }
        needed = fields.iter().map(|(_, offset, scalar)| offset + scalar.size() as i64).max().unwrap_or(0);
    } else if matches!(kind.as_str(), "utf8" | "utf16" | "hex") {
        needed = 0;
    } else if let Some(scalar) = scalar(&kind) {
        kind = scalar.name().to_owned();
        needed = scalar.size() as i64;
    } else {
        return invalid(format!("capture {index}: unknown decoder {kind}"));
    }
    let size = match item.get("size") {
        None => {
            if needed != 0 {
                needed
            } else {
                256
            }
        }
        Some(v) => int_of(v)?,
    };
    if !(needed <= size && size <= MAX_SIZE) || size < 1 {
        return invalid(format!("capture {index} size must be 1..4096 and cover its decoder"));
    }
    let names = match item.get("names") {
        None => Map::new(),
        Some(Value::Object(listed)) if listed.len() > MAX_NAMES => {
            return invalid(format!("capture {index} names maps values to names"));
        }
        Some(Value::Object(listed)) => {
            let mut names = Map::new();
            for (key, value) in listed {
                let number = parse_int_base0(key).ok_or(DecodeError::Unmodelled)?;
                names.insert(number.to_string(), Value::String(name_text(value)?));
            }
            names
        }
        Some(other) if !truthy(other) => Map::new(),
        Some(_) => return invalid(format!("capture {index} names maps values to names")),
    };
    let label: String = str_of(item.get("label").unwrap_or(&Value::String(String::new())))?.chars().take(MAX_LABEL).collect();
    let value_only = matches!(&deref, Value::Array(d) if d.is_empty()) && scalar(&kind).is_some() && size <= 8;
    let fields = fields
        .into_iter()
        .map(|(name, offset, scalar)| object(vec![("name", name.into()), ("offset", offset.into()), ("type", scalar.name().into())]))
        .collect();
    Ok(object(vec![
        ("arg", arg.clone()),
        ("reg", reg.clone()),
        ("deref", deref),
        ("size", size.into()),
        ("as", kind.into()),
        ("fields", Value::Array(fields)),
        ("names", Value::Object(names)),
        ("label", label.into()),
        ("value_only", value_only.into()),
    ]))
}

/// Why `_unpack` could not read a value.
enum Unpack {
    /// Python's `struct.error`, with its message.
    Short(String),
    Unmodelled,
}

/// A decoded scalar: an integer, a float, a bool or a pointer string.
fn unpack(kind: Scalar, data: &[u8], offset: usize) -> Result<Value, Unpack> {
    let width = if kind == Scalar::Pointer && data.len() - offset.min(data.len()) == 4 { 4 } else { kind.size() };
    let Some(raw) = data.get(offset..).and_then(|rest| rest.get(..width)) else {
        return Err(Unpack::Short(format!(
            "unpack_from requires a buffer of at least {} bytes for unpacking {} bytes at offset {} (actual buffer size is {})",
            width + offset,
            width,
            offset,
            data.len()
        )));
    };
    let mut wide = [0u8; 8];
    wide[..width].copy_from_slice(raw);
    let unsigned = u64::from_le_bytes(wide);
    let float = |x: f64| Number::from_f64(x).map(Value::Number).ok_or(Unpack::Unmodelled);
    Ok(match kind {
        Scalar::I8 => i64::from(raw[0] as i8).into(),
        Scalar::U8 => raw[0].into(),
        Scalar::I16 => i64::from(unsigned as u16 as i16).into(),
        Scalar::U16 => (unsigned as u16).into(),
        Scalar::I32 => i64::from(unsigned as u32 as i32).into(),
        Scalar::U32 => (unsigned as u32).into(),
        Scalar::I64 => (unsigned as i64).into(),
        Scalar::U64 => unsigned.into(),
        Scalar::F32 => return float(f64::from(f32::from_bits(unsigned as u32))),
        Scalar::F64 => return float(f64::from_bits(unsigned)),
        Scalar::Pointer => format!("{unsigned:#x}").into(),
        Scalar::Bool => (raw[0] != 0).into(),
    })
}

/// The per-spec data `decode` needs, read out of a normalised capture spec.
struct Spec<'a> {
    kind: &'a str,
    fields: Vec<(&'a str, i64, Scalar)>,
    names: Option<&'a Map<String, Value>>,
}

impl<'a> Spec<'a> {
    fn read(spec: &'a Value) -> Result<Self, DecodeError> {
        let spec = spec.as_object().ok_or(DecodeError::Unmodelled)?;
        let kind = spec.get("as").and_then(Value::as_str).ok_or(DecodeError::Unmodelled)?;
        let mut fields = Vec::new();
        if kind == "struct" {
            for field in spec.get("fields").and_then(Value::as_array).ok_or(DecodeError::Unmodelled)? {
                let field = field.as_object().ok_or(DecodeError::Unmodelled)?;
                let name = field.get("name").and_then(Value::as_str).ok_or(DecodeError::Unmodelled)?;
                let offset = field.get("offset").map_or(Err(DecodeError::Unmodelled), int_of)?;
                let scalar = field.get("type").and_then(Value::as_str).and_then(Scalar::from_canonical).ok_or(DecodeError::Unmodelled)?;
                if offset < 0 {
                    return Err(DecodeError::Unmodelled);
                }
                fields.push((name, offset, scalar));
            }
        }
        let names = spec.get("names").and_then(Value::as_object);
        Ok(Self { kind, fields, names })
    }
}

fn decode_spec(spec: &Spec<'_>, data: &[u8]) -> Result<Value, Unpack> {
    match spec.kind {
        "utf8" => {
            let head = data.split(|b| *b == 0).next().unwrap_or(&[]);
            Ok(String::from_utf8_lossy(head).into_owned().into())
        }
        "utf16" => {
            let cut = (0..data.len().saturating_sub(1))
                .step_by(2)
                .find(|i| data[*i] == 0 && data[*i + 1] == 0)
                .unwrap_or(data.len() - data.len() % 2);
            let units = data[..cut].as_chunks::<2>().0.iter().map(|pair| u16::from_le_bytes(*pair));
            Ok(char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect::<String>().into())
        }
        "hex" => Ok(hex_spaced(data).into()),
        "struct" => {
            let mut row = Map::new();
            for (name, offset, scalar) in &spec.fields {
                let offset = *offset as usize;
                if offset + scalar.size() <= data.len() {
                    row.insert((*name).to_owned(), unpack(*scalar, data, offset)?);
                }
            }
            Ok(Value::Object(row))
        }
        other => {
            let kind = Scalar::from_canonical(other).ok_or(Unpack::Unmodelled)?;
            let value = unpack(kind, data, 0)?;
            let names = spec.names.ok_or(Unpack::Unmodelled)?;
            if names.is_empty() {
                return Ok(value);
            }
            let key = match &value {
                Value::String(pointer) => {
                    u64::from_str_radix(pointer.trim_start_matches("0x"), 16).map_err(|_| Unpack::Unmodelled)?.to_string()
                }
                Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
                _ => String::new(), // a float or a bool never spells an integer key
            };
            let name = names.get(&key).cloned().unwrap_or(Value::Null);
            Ok(object(vec![("value", value), ("name", name)]))
        }
    }
}

/// `data` as upper-case hex pairs separated by single spaces.
fn hex_spaced(data: &[u8]) -> String {
    let mut text = String::with_capacity(data.len() * 3);
    for (index, byte) in data.iter().enumerate() {
        if index > 0 {
            text.push(' ');
        }
        text.push_str(&format!("{byte:02X}"));
    }
    text
}

/// One captured buffer as its declared value (`decode` in Python).
///
/// # Errors
///
/// [`DecodeError::Unmodelled`] for a spec or buffer the port does not model, including every case where Python raises
/// `struct.error`.
pub fn decode(spec: &Value, data: &[u8]) -> Result<Value, DecodeError> {
    decode_spec(&Spec::read(spec)?, data).map_err(|_| DecodeError::Unmodelled)
}

/// `bytes.fromhex(text)` for the well-formed case: pairs of hex digits, ASCII whitespace between pairs.
fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<char> = text.chars().collect();
    let mut out = Vec::with_capacity(digits.len() / 2);
    let mut i = 0;
    while i < digits.len() {
        if matches!(digits[i], ' ' | '\t' | '\n' | '\x0b' | '\x0c' | '\r') {
            i += 1;
            continue;
        }
        let high = digits[i].to_digit(16)?;
        let low = digits.get(i + 1)?.to_digit(16)?;
        out.push(u8::try_from(high * 16 + low).ok()?);
        i += 2;
    }
    Some(out)
}

/// Decode every capture of one event against its spec (`decode_event` in Python).
///
/// # Errors
///
/// [`DecodeError::Unmodelled`] when the specs or captures are not plain lists of plain objects.
pub fn decode_event(specs: &Value, captures: &Value) -> Result<Value, DecodeError> {
    let specs = specs.as_array().ok_or(DecodeError::Unmodelled)?;
    let captures: &[Value] = match captures {
        Value::Null => &[],
        Value::Array(c) => c,
        other if !truthy(other) => &[],
        _ => return Err(DecodeError::Unmodelled),
    };
    let mut rows = Vec::new();
    for (spec_value, captured) in specs.iter().zip(captures) {
        let spec = Spec::read(spec_value)?;
        let spec_object = spec_value.as_object().ok_or(DecodeError::Unmodelled)?;
        let mut row = Map::new();
        match spec_object.get("reg").filter(|r| truthy(r)) {
            Some(reg) => row.insert("reg".into(), reg.clone()),
            None => row.insert("arg".into(), spec_object.get("arg").cloned().ok_or(DecodeError::Unmodelled)?),
        };
        let label = spec_object.get("label").and_then(Value::as_str).ok_or(DecodeError::Unmodelled)?;
        if !label.is_empty() {
            row.insert("label".into(), label.into());
        }
        let error = match captured {
            Value::Object(c) => c.get("error").filter(|e| truthy(e)),
            Value::Array(_) | Value::String(_) | Value::Number(_) | Value::Bool(_) if truthy(captured) => {
                return Err(DecodeError::Unmodelled);
            }
            _ => None,
        };
        match (captured, error) {
            (Value::Object(_), Some(error)) => {
                row.insert("error".into(), error.clone());
            }
            (Value::Object(c), None) => {
                row.insert("pointer".into(), c.get("pointer").cloned().unwrap_or(Value::Null));
                let text = match c.get("hex") {
                    None => "",
                    Some(v) => str_of(v)?,
                };
                let data = from_hex(text).ok_or(DecodeError::Unmodelled)?;
                match decode_spec(&spec, &data) {
                    Ok(value) => {
                        row.insert("value".into(), value);
                    }
                    Err(Unpack::Short(message)) => {
                        row.insert("error".into(), format!("decode: {message}").into());
                    }
                    Err(Unpack::Unmodelled) => return Err(DecodeError::Unmodelled),
                }
            }
            _ => {
                row.insert("error".into(), "not captured".into());
            }
        }
        rows.push(Value::Object(row));
    }
    Ok(Value::Array(rows))
}

/// A typed live read: each field of a layout from the bytes read at its object (`layout_values` in Python).
///
/// # Errors
///
/// [`DecodeError::Unmodelled`] for fields that are not plain objects with integer offsets and string types.
pub fn layout_values(fields: &Value, data: &[u8]) -> Result<Value, DecodeError> {
    let mut rows = Vec::new();
    for field in fields.as_array().ok_or(DecodeError::Unmodelled)? {
        let field = field.as_object().ok_or(DecodeError::Unmodelled)?;
        let type_value = field.get("type");
        let type_text = match type_value {
            None => "",
            Some(v) => str_of(v)?,
        };
        let kind = scalar(type_text);
        let offset = int_of(field.get("offset").ok_or(DecodeError::Unmodelled)?)?;
        let declared = match field.get("size") {
            None | Some(Value::Null) => 0,
            Some(v) if !truthy(v) => 0,
            Some(v) => int_of(v)?,
        };
        let size = if declared != 0 { declared } else { kind.map_or(0, |k| k.size() as i64) };
        if offset < 0 || size < 0 {
            return Err(DecodeError::Unmodelled);
        }
        let start = (offset as usize).min(data.len());
        let chunk = &data[start..start.saturating_add(size as usize).min(data.len())];
        let mut row = Map::new();
        row.insert("name".into(), field.get("name").cloned().unwrap_or(Value::Null));
        row.insert("offset".into(), format!("{offset:#x}").into());
        row.insert("type".into(), type_value.cloned().unwrap_or(Value::Null));
        if let Some(enum_name) = field.get("enum").filter(|e| truthy(e)) {
            row.insert("type".into(), enum_name.clone());
        }
        match kind.filter(|k| chunk.len() >= k.size()) {
            Some(kind) => {
                let value = unpack(kind, chunk, 0).map_err(|_| DecodeError::Unmodelled)?;
                if let Some(names) = field.get("names").and_then(Value::as_object) {
                    let text = match &value {
                        Value::String(s) => s.clone(),
                        Value::Number(n) if n.is_i64() || n.is_u64() => n.to_string(),
                        Value::Bool(b) => (if *b { "True" } else { "False" }).into(),
                        _ => return Err(DecodeError::Unmodelled), // Python's float repr is not reproduced
                    };
                    let named = names.get(&text).cloned().unwrap_or_else(|| format!("(no member {text})").into());
                    row.insert("value".into(), value);
                    row.insert("name".into(), named);
                    rows.push(Value::Object(row));
                    continue;
                }
                row.insert("value".into(), value);
            }
            None => {
                row.insert("bytes".into(), hex_spaced(chunk).into());
            }
        }
        rows.push(Value::Object(row));
    }
    Ok(Value::Array(rows))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn text(value: &Value) -> String {
        serde_json::to_string(value).expect("a Value always serialises")
    }

    #[test]
    fn scalar_resolves_aliases_pointers_and_whitespace() {
        assert_eq!(scalar(" uint32 "), Some(Scalar::U32));
        assert_eq!(scalar("Thing *"), Some(Scalar::Pointer));
        assert_eq!(scalar("SomeStruct"), None);
        assert_eq!(scalar("\x1fu8\x1f"), Some(Scalar::U8), "Python strips the ASCII separators too");
    }

    #[test]
    fn normalize_keeps_python_key_order_and_defaults() {
        let out = normalize(&json!([{"arg": 1, "as": "u32", "names": {"0x2a": "answer", "42": "again"}}])).unwrap();
        assert_eq!(
            text(&out),
            r#"[{"arg":1,"reg":null,"deref":[],"size":4,"as":"u32","fields":[],"names":{"42":"again"},"label":"","value_only":true}]"#
        );
    }

    #[test]
    fn normalize_messages_match_python() {
        let message = |v: Value| match normalize(&v) {
            Err(DecodeError::Invalid(m)) => m,
            other => panic!("{other:?}"),
        };
        assert_eq!(message(json!([{"arg": 9}])), "capture 0 needs arg 0..7 or reg");
        assert_eq!(message(json!([{"arg": 0, "as": "elf"}])), "capture 0: unknown decoder elf");
        assert_eq!(message(json!([{"arg": 0, "as": "struct"}])), "capture 0 struct needs fields");
        assert_eq!(message(json!([{"reg": "ecx", "arg": 0}])), "capture 0: reg is one register name (e.g. ecx, rdx), instead of arg");
        assert_eq!(message(Value::Array(vec![json!({"arg": 0}); 5])), "capture must be a list of at most 4 argument captures");
        assert_eq!(message(json!([{"arg": 0, "size": 2, "as": "u32"}])), "capture 0 size must be 1..4096 and cover its decoder");
    }

    #[test]
    fn coerced_inputs_are_left_to_python() {
        assert_eq!(normalize(&json!([{"arg": 0, "size": 8.5}])), Err(DecodeError::Unmodelled));
        assert_eq!(normalize(&json!([{"arg": 0, "names": {"0x1_0": "x"}}])), Err(DecodeError::Unmodelled));
    }

    #[test]
    fn decode_event_reads_text_numbers_structs_and_short_buffers() {
        let specs = normalize(&json!([
            {"arg": 0, "as": "utf16", "size": 16, "label": "name"},
            {"arg": 1, "as": "u32", "names": {"0x2a": "answer"}},
            {"arg": 2, "as": "struct", "fields": [{"name": "x", "offset": 0, "type": "float"}, {"name": "id", "offset": 4, "type": "uint32"}]},
            {"reg": "ecx", "as": "u64"}
        ]))
        .unwrap();
        let mut specs = specs.as_array().unwrap().clone();
        specs.extend(normalize(&json!([{"arg": 3}])).unwrap().as_array().unwrap().clone());
        let specs = Value::Array(specs);
        let captured = json!([
            {"pointer": "0x1", "hex": "61003a006200000000000000"},
            {"pointer": "0x2a", "hex": "2a000000"},
            {"pointer": "0x3", "hex": "0000c03f07000000"},
            {"pointer": "0x4", "hex": "0102"},
            {"error": "unreadable pointer at 0x10"}
        ]);
        let rows = decode_event(&specs, &captured).unwrap();
        assert_eq!(
            text(&rows),
            concat!(
                r#"[{"arg":0,"label":"name","pointer":"0x1","value":"a:b"},"#,
                r#"{"arg":1,"pointer":"0x2a","value":{"value":42,"name":"answer"}},"#,
                r#"{"arg":2,"pointer":"0x3","value":{"x":1.5,"id":7}},"#,
                r#"{"reg":"ecx","pointer":"0x4","error":"decode: unpack_from requires a buffer of at least 8 bytes for unpacking 8 bytes at offset 0 (actual buffer size is 2)"},"#,
                r#"{"arg":3,"error":"unreadable pointer at 0x10"}]"#
            )
        );
    }

    #[test]
    fn a_four_byte_pointer_is_a_32_bit_pointer() {
        let specs = normalize(&json!([{"arg": 0, "as": "pointer"}])).unwrap();
        let rows = decode_event(&specs, &json!([{"pointer": "0x4a4cb70", "hex": "70cba404"}])).unwrap();
        assert_eq!(rows[0]["value"], "0x4a4cb70");
    }

    #[test]
    fn layout_values_types_enums_and_raw_bytes() {
        let data = [0xfdu8, 0xff, 0xff, 0xff, 0, 0, 0, 0x40, 1, 0, 0, 0, 0, 0, 0, 0x40];
        let fields = json!([
            {"name": "count", "offset": 0, "type": "int"},
            {"name": "blob", "offset": 0, "type": "SomeStruct", "size": 4},
            {"name": "kind", "offset": 8, "type": "u8", "enum": "EKind", "names": {"1": "One"}},
            {"name": "other", "offset": 9, "type": "u8", "names": {"1": "One"}}
        ]);
        let rows = layout_values(&fields, &data).unwrap();
        assert_eq!(
            text(&rows),
            concat!(
                r#"[{"name":"count","offset":"0x0","type":"int","value":-3},"#,
                r#"{"name":"blob","offset":"0x0","type":"SomeStruct","bytes":"FD FF FF FF"},"#,
                r#"{"name":"One","offset":"0x8","type":"EKind","value":1},"#,
                r#"{"name":"(no member 0)","offset":"0x9","type":"u8","value":0}]"#
            )
        );
    }
}
