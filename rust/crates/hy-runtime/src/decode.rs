//! Decoding of bytes a probe captured, outside the target process (the pure half of `runtime_decode.py`).
//!
//! This module holds what needs no Python object: the scalar types of the capture language, the integer and register-name
//! grammars, reading a scalar out of a buffer, and the three text forms (`utf8`, `utf16`, spaced hex). The binding in
//! `hy-rt-py` walks the Python specs and captures directly and builds the answers from these pieces, so no intermediate
//! document is ever made. Anything it does not model it reports as `Unmodelled`, and the Python function, which stays the
//! specification, answers.

use std::borrow::Cow;
use std::fmt;

/// Most captures one probe accepts.
pub const MAX_CAPTURES: usize = 4;
/// Largest captured buffer, in bytes.
pub const MAX_SIZE: i64 = 4096;
/// Largest number of names one capture may carry.
pub const MAX_NAMES: usize = 100_000;
/// Longest label kept, in characters.
pub const MAX_LABEL: usize = 64;
/// Largest dereference offset (exclusive).
pub const MAX_OFFSET: i64 = 1 << 20;
/// Struct field offsets beyond this are not modelled (no overflow in the arithmetic around them).
pub const MAX_FIELD_OFFSET: i64 = 1 << 40;
/// Number of argument registers a capture may name (`arg` is `0..=MAX_ARG`).
pub const MAX_ARG: i64 = 7;

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
    #[must_use]
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
    #[must_use]
    pub fn size(self) -> usize {
        match self {
            Self::I8 | Self::U8 | Self::Bool => 1,
            Self::I16 | Self::U16 => 2,
            Self::I32 | Self::U32 | Self::F32 => 4,
            Self::I64 | Self::U64 | Self::F64 | Self::Pointer => 8,
        }
    }

    /// The scalar a canonical name (`"u32"`, `"pointer"`, ...) denotes; no aliases, no trimming.
    #[must_use]
    pub fn from_canonical(name: &str) -> Option<Self> {
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
#[must_use]
pub fn scalar(name: &str) -> Option<Scalar> {
    let name = name.trim_matches(py_space);
    if name.ends_with('*') {
        return Some(Scalar::Pointer);
    }
    Scalar::from_canonical(alias(name))
}

/// `int(text, 0)` for plain decimal, `0x`, `0o` and `0b` literals with an optional sign; anything else (whitespace,
/// underscores, leading zeros, junk) is `None` so that Python runs and answers or raises.
#[must_use]
pub fn parse_int_base0(text: &str) -> Option<i128> {
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

/// `re.fullmatch(r"[a-z][a-z0-9]{1,4}", name)`.
#[must_use]
pub fn is_register_name(name: &str) -> bool {
    let bytes = name.as_bytes();
    (2..=5).contains(&bytes.len())
        && bytes[0].is_ascii_lowercase()
        && bytes[1..].iter().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
}

/// A scalar read out of a buffer.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Raw {
    /// A signed integer type.
    Int(i64),
    /// An unsigned integer type.
    Uint(u64),
    /// A float type (may be non-finite).
    Float(f64),
    /// A `bool`.
    Bool(bool),
    /// A pointer, to be spelled `0x...`.
    Pointer(u64),
}

/// The buffer was too short: Python's `struct.error`, whose text [`fmt::Display`] reproduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShortBuffer {
    width: usize,
    offset: usize,
    actual: usize,
}

impl fmt::Display for ShortBuffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unpack_from requires a buffer of at least {} bytes for unpacking {} bytes at offset {} (actual buffer size is {})",
            self.width + self.offset,
            self.width,
            self.offset,
            self.actual
        )
    }
}

impl std::error::Error for ShortBuffer {}

/// Read `kind` at `offset` (`_unpack` in Python). A pointer read from exactly four remaining bytes is a 32-bit pointer.
///
/// # Errors
///
/// [`ShortBuffer`] when fewer than the scalar's width remain at `offset`.
pub fn unpack(kind: Scalar, data: &[u8], offset: usize) -> Result<Raw, ShortBuffer> {
    let width = if kind == Scalar::Pointer && data.len() - offset.min(data.len()) == 4 { 4 } else { kind.size() };
    let Some(raw) = data.get(offset..).and_then(|rest| rest.get(..width)) else {
        return Err(ShortBuffer { width, offset, actual: data.len() });
    };
    let mut wide = [0u8; 8];
    wide[..width].copy_from_slice(raw);
    let unsigned = u64::from_le_bytes(wide);
    Ok(match kind {
        Scalar::I8 => Raw::Int(i64::from(raw[0] as i8)),
        Scalar::U8 => Raw::Uint(u64::from(raw[0])),
        Scalar::I16 => Raw::Int(i64::from(unsigned as u16 as i16)),
        Scalar::U16 => Raw::Uint(u64::from(unsigned as u16)),
        Scalar::I32 => Raw::Int(i64::from(unsigned as u32 as i32)),
        Scalar::U32 => Raw::Uint(u64::from(unsigned as u32)),
        Scalar::I64 => Raw::Int(unsigned as i64),
        Scalar::U64 => Raw::Uint(unsigned),
        Scalar::F32 => Raw::Float(f64::from(f32::from_bits(unsigned as u32))),
        Scalar::F64 => Raw::Float(f64::from_bits(unsigned)),
        Scalar::Pointer => Raw::Pointer(unsigned),
        Scalar::Bool => Raw::Bool(raw[0] != 0),
    })
}

/// Python's `repr(float)`: the shortest text that reads back as the same double, in fixed notation for decimal exponents
/// -4..16 and in exponent notation (`1e+16`, `1.5e-05`) outside it.
#[must_use]
pub fn float_repr(value: f64) -> String {
    if value.is_nan() {
        return "nan".to_owned();
    }
    if value.is_infinite() {
        return if value < 0.0 { "-inf" } else { "inf" }.to_owned();
    }
    let sign = if value.is_sign_negative() { "-" } else { "" };
    if value == 0.0 {
        return format!("{sign}0.0");
    }
    // `{:e}` prints the shortest round-trip digits as `d.ddde<exp>`; printing again with that many digits rounds the exact
    // value half to even, which is the digit string Python picks when two shortest candidates tie.
    let shortest = format!("{:e}", value.abs());
    let places = shortest.split_once('e').map_or(0, |(mantissa, _)| mantissa.len().saturating_sub(2));
    let scientific = format!("{:.*e}", places, value.abs());
    let (mantissa, exponent) = scientific.split_once('e').expect("`{:e}` always has an exponent");
    let exponent: i32 = exponent.parse().expect("`{:e}` exponents are integers");
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    if !(-4..16).contains(&exponent) {
        let tail = &digits[1..];
        let point = if tail.is_empty() { String::new() } else { format!(".{tail}") };
        let exponent_sign = if exponent < 0 { '-' } else { '+' };
        return format!("{sign}{}{point}e{exponent_sign}{:02}", &digits[..1], exponent.abs());
    }
    let point = exponent + 1; // digits before the decimal point
    let count = digits.len() as i32;
    let body = if point <= 0 {
        format!("0.{}{digits}", "0".repeat(point.unsigned_abs() as usize))
    } else if point >= count {
        format!("{digits}{}.0", "0".repeat((point - count) as usize))
    } else {
        format!("{}.{}", &digits[..point as usize], &digits[point as usize..])
    };
    format!("{sign}{body}")
}

/// `data.split(b"\0", 1)[0].decode("utf-8", "replace")`.
#[must_use]
pub fn utf8_text(data: &[u8]) -> Cow<'_, str> {
    let end = data.iter().position(|b| *b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end])
}

/// NUL-terminated UTF-16LE bounded by the buffer, lone surrogates replaced (`decode` for `utf16` in Python).
#[must_use]
pub fn utf16_text(data: &[u8]) -> String {
    let (pairs, _) = data.as_chunks::<2>();
    let units = pairs.iter().map(|pair| u16::from_le_bytes(*pair)).take_while(|unit| *unit != 0);
    char::decode_utf16(units).map(|r| r.unwrap_or(char::REPLACEMENT_CHARACTER)).collect()
}

/// `data` as upper-case hex pairs separated by single spaces.
#[must_use]
pub fn hex_spaced(data: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789ABCDEF";
    let mut text = Vec::with_capacity((data.len() * 3).saturating_sub(1));
    for (index, byte) in data.iter().enumerate() {
        if index > 0 {
            text.push(b' ');
        }
        text.push(DIGITS[usize::from(byte >> 4)]);
        text.push(DIGITS[usize::from(byte & 15)]);
    }
    String::from_utf8(text).expect("hex digits and spaces are ASCII")
}

/// `bytes.fromhex(text)` for the well-formed case: pairs of hex digits, ASCII whitespace between pairs. `None` for any
/// other text (Python then answers or raises).
#[must_use]
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digits = text.as_bytes();
    let mut out = Vec::with_capacity(digits.len() / 2);
    let nibble = |byte: u8| char::from(byte).to_digit(16).map(|d| d as u8);
    let mut i = 0;
    while i < digits.len() {
        if matches!(digits[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
            i += 1;
            continue;
        }
        out.push(nibble(digits[i])? << 4 | nibble(*digits.get(i + 1)?)?);
        i += 2;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_resolves_aliases_pointers_and_whitespace() {
        assert_eq!(scalar(" uint32 "), Some(Scalar::U32));
        assert_eq!(scalar("Thing *"), Some(Scalar::Pointer));
        assert_eq!(scalar("SomeStruct"), None);
        assert_eq!(scalar("\x1fu8\x1f"), Some(Scalar::U8), "Python strips the ASCII separators too");
    }

    #[test]
    fn int_literals_follow_int_base_zero() {
        assert_eq!(parse_int_base0("0x2a"), Some(42));
        assert_eq!(parse_int_base0("-0b11"), Some(-3));
        assert_eq!(parse_int_base0("0o7"), Some(7));
        assert_eq!(parse_int_base0("007"), None, "leading zeros are Python's to judge");
        assert_eq!(parse_int_base0(" 1"), None);
        assert_eq!(parse_int_base0("0x"), None);
    }

    #[test]
    fn register_names() {
        for good in ["ecx", "r8", "xmm2", "rax"] {
            assert!(is_register_name(good), "{good}");
        }
        for bad in ["a", "AX", "abcdef", "1ax", "e-x"] {
            assert!(!is_register_name(bad), "{bad}");
        }
    }

    #[test]
    fn unpack_reads_little_endian_and_reports_short_buffers_like_struct() {
        assert_eq!(unpack(Scalar::I16, &[0xfe, 0xff], 0), Ok(Raw::Int(-2)));
        assert_eq!(unpack(Scalar::U32, &[1, 0, 0, 0, 9], 0), Ok(Raw::Uint(1)));
        let err = unpack(Scalar::U64, &[1, 2, 3], 0).unwrap_err();
        assert_eq!(
            err.to_string(),
            "unpack_from requires a buffer of at least 8 bytes for unpacking 8 bytes at offset 0 (actual buffer size is 3)"
        );
    }

    #[test]
    fn a_four_byte_pointer_is_a_32_bit_pointer() {
        assert_eq!(unpack(Scalar::Pointer, &[1, 2, 3, 4], 0), Ok(Raw::Pointer(0x0403_0201)));
        assert_eq!(unpack(Scalar::Pointer, &[1, 0, 0, 0, 0, 0, 0, 0], 0), Ok(Raw::Pointer(1)));
    }

    #[test]
    fn float_repr_matches_python() {
        for (value, want) in [
            (0.0, "0.0"),
            (-0.0, "-0.0"),
            (1.0, "1.0"),
            (1.5, "1.5"),
            (100.0, "100.0"),
            (0.1, "0.1"),
            (0.0001, "0.0001"),
            (0.00001, "1e-05"),
            (1.5e-7, "1.5e-07"),
            (1e15, "1000000000000000.0"),
            (1e16, "1e+16"),
            (1.2345e16, "1.2345e+16"),
            (123456789012345680.0, "1.2345678901234568e+17"),
            (f64::from(0.1f32), "0.10000000149011612"),
            (-2.5, "-2.5"),
            (f64::INFINITY, "inf"),
            (f64::NEG_INFINITY, "-inf"),
            (f64::NAN, "nan"),
            (1e300, "1e+300"),
            (1234567890123456.0, "1234567890123456.0"),
            (0.1 + 0.2, "0.30000000000000004"),
            (-2.5e-7, "-2.5e-07"),
            (f64::from(-574.251_04_f32), "-574.2510375976562"),
            (5e-324, "5e-324"),
        ] {
            assert_eq!(float_repr(value), want, "{value:e}");
        }
    }

    #[test]
    fn text_forms() {
        assert_eq!(utf8_text(b"ab\0cd"), "ab");
        assert_eq!(utf8_text(b"\xffx"), "\u{fffd}x");
        assert_eq!(utf16_text(&[b'a', 0, b'b', 0, 0, 0, b'c', 0]), "ab");
        assert_eq!(utf16_text(&[0x00, 0xd8, b'a', 0]), "\u{fffd}a", "a lone surrogate is replaced");
        assert_eq!(utf16_text(b"a"), "", "a trailing odd byte is dropped");
        assert_eq!(hex_spaced(&[0, 0xab, 0xff]), "00 AB FF");
        assert_eq!(hex_spaced(&[]), "");
    }

    #[test]
    fn from_hex_accepts_whitespace_between_pairs_only() {
        assert_eq!(from_hex(" 01 ff\n"), Some(vec![1, 255]));
        assert_eq!(from_hex("0100"), Some(vec![1, 0]));
        assert_eq!(from_hex("0 1"), None);
        assert_eq!(from_hex("zz"), None);
        assert_eq!(from_hex("0"), None);
        assert_eq!(from_hex("\u{661}0"), None, "non-ASCII digits are Python's to judge");
    }
}
