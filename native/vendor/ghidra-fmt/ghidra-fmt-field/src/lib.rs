//! Ghidra database fields, schemas and record encoding (`db.Field` and subclasses,
//! `db.Schema`, `db.DBRecord`, `db.SparseRecord`).
//!
//! Wire formats (big-endian):
//!
//! | type | code | encoding |
//! | --- | --- | --- |
//! | Byte | 0 | 1 byte |
//! | Short | 1 | 2 bytes |
//! | Int | 2 | 4 bytes |
//! | Long | 3 | 8 bytes |
//! | String | 4 | int length (-1 = null) + UTF-8 bytes |
//! | Binary | 5 | int length (-1 = null) + bytes |
//! | Boolean | 6 | 1 byte (the raw byte is kept) |
//! | Fixed10 | 7 | 10 bytes (unsigned big-endian order) |
//! | Index | `primary << 4 \| indexed` | indexed field followed by the primary key field |
//!
//! Null state of Java primitive fields is not modelled: the only nulls that exist in storage
//! are the `-1` length of strings and binaries and the absent sparse columns of a sparse record.

use std::cmp::Ordering;
use std::fmt;

use ghidra_fmt_bytes::{self as bytes, BytesError};

mod record;
mod schema;

pub use record::Record;
pub use schema::Schema;

/// Field type code of [`FieldType::Byte`].
pub const BYTE_TYPE: u8 = 0;
/// Field type code of [`FieldType::Short`].
pub const SHORT_TYPE: u8 = 1;
/// Field type code of [`FieldType::Int`].
pub const INT_TYPE: u8 = 2;
/// Field type code of [`FieldType::Long`].
pub const LONG_TYPE: u8 = 3;
/// Field type code of [`FieldType::String`].
pub const STRING_TYPE: u8 = 4;
/// Field type code of [`FieldType::Binary`].
pub const BINARY_OBJ_TYPE: u8 = 5;
/// Field type code of [`FieldType::Boolean`].
pub const BOOLEAN_TYPE: u8 = 6;
/// Field type code of [`FieldType::Fixed10`].
pub const FIXED_10_TYPE: u8 = 7;
/// Primary key nibble that selects a legacy index field.
pub const LEGACY_INDEX_LONG_TYPE: u8 = 8;
/// Reserved primary key nibble (`0xf0..=0xff`).
pub const FIELD_RESERVED_15_TYPE: u8 = 0xf;
/// Mask of the indexed (or plain) type nibble.
pub const FIELD_TYPE_MASK: u8 = 0x0f;
/// Mask of the primary key nibble of an index field.
pub const INDEX_PRIMARY_KEY_TYPE_MASK: u8 = 0xf0;
/// Maximum stored length of an indexed variable-length value.
pub const MAX_INDEX_FIELD_LENGTH: usize = 64;

/// Errors raised by the field layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldError {
    /// Read or write outside the buffer.
    Bytes(BytesError),
    /// Unknown or reserved field type code (`UnsupportedFieldException`).
    UnsupportedType(u8),
    /// Unsupported schema extension or bad sparse column data.
    UnsupportedSchema(String),
    /// Bad argument (`IllegalArgumentException`).
    IllegalArgument(&'static str),
    /// Fields of different types were compared or stored in the wrong column.
    TypeMismatch,
}

impl fmt::Display for FieldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bytes(e) => write!(f, "{e}"),
            Self::UnsupportedType(t) => write!(f, "Unsupported DB field type: {t:#x}"),
            Self::UnsupportedSchema(m) => write!(f, "{m}"),
            Self::IllegalArgument(m) => write!(f, "illegal argument: {m}"),
            Self::TypeMismatch => write!(f, "may only compare similar Field types"),
        }
    }
}

impl std::error::Error for FieldError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Bytes(e) => Some(e),
            _ => None,
        }
    }
}

impl From<BytesError> for FieldError {
    fn from(e: BytesError) -> Self {
        Self::Bytes(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, FieldError>;

/// The type of a column or key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldType {
    /// `ByteField`.
    Byte,
    /// `ShortField`.
    Short,
    /// `IntField`.
    Int,
    /// `LongField`.
    Long,
    /// `StringField`.
    String,
    /// `BinaryField`.
    Binary,
    /// `BooleanField`.
    Boolean,
    /// `FixedField10`.
    Fixed10,
    /// `IndexField`: an indexed value followed by a fixed-length primary key.
    Index {
        /// Type of the indexed value.
        indexed: Box<FieldType>,
        /// Type of the primary key (never variable length).
        primary: Box<FieldType>,
    },
    /// `LegacyIndexField` (code nibble 8): indexed value plus a long primary key that is
    /// treated as variable length for node selection.
    LegacyIndex {
        /// Type of the indexed value.
        indexed: Box<FieldType>,
    },
}

impl FieldType {
    /// Decode a type code (`Field.getField(byte)`).
    pub fn from_code(code: u8) -> Result<Self> {
        if code == 0x88 {
            return Err(FieldError::UnsupportedType(code)); // reserved
        }
        if code & INDEX_PRIMARY_KEY_TYPE_MASK == 0 {
            return Ok(match code & FIELD_TYPE_MASK {
                LONG_TYPE => Self::Long,
                INT_TYPE => Self::Int,
                STRING_TYPE => Self::String,
                SHORT_TYPE => Self::Short,
                BYTE_TYPE => Self::Byte,
                BOOLEAN_TYPE => Self::Boolean,
                BINARY_OBJ_TYPE => Self::Binary,
                FIXED_10_TYPE => Self::Fixed10,
                _ => return Err(FieldError::UnsupportedType(code)),
            });
        }
        let indexed = Box::new(Self::from_code(code & FIELD_TYPE_MASK)?);
        let primary_nibble = (code >> 4) & FIELD_TYPE_MASK;
        if primary_nibble == FIELD_RESERVED_15_TYPE {
            return Err(FieldError::UnsupportedType(code));
        }
        if primary_nibble == LEGACY_INDEX_LONG_TYPE {
            return Ok(Self::LegacyIndex { indexed });
        }
        let primary = Box::new(Self::from_code(primary_nibble)?);
        if primary.is_variable_length() {
            return Err(FieldError::IllegalArgument(
                "variable length primaryKey not supported",
            ));
        }
        Ok(Self::Index { indexed, primary })
    }

    /// Encode as a type code. A legacy index type encodes with a long primary key nibble, as in Java.
    pub fn code(&self) -> u8 {
        match self {
            Self::Byte => BYTE_TYPE,
            Self::Short => SHORT_TYPE,
            Self::Int => INT_TYPE,
            Self::Long => LONG_TYPE,
            Self::String => STRING_TYPE,
            Self::Binary => BINARY_OBJ_TYPE,
            Self::Boolean => BOOLEAN_TYPE,
            Self::Fixed10 => FIXED_10_TYPE,
            Self::Index { indexed, primary } => (primary.code() << 4) | indexed.code(),
            Self::LegacyIndex { indexed } => (LONG_TYPE << 4) | indexed.code(),
        }
    }

    /// True when values of this type have no fixed length.
    pub fn is_variable_length(&self) -> bool {
        match self {
            Self::String | Self::Binary | Self::LegacyIndex { .. } => true,
            Self::Index { indexed, .. } => indexed.is_variable_length(),
            _ => false,
        }
    }

    /// Stored length of a fixed-length type, `None` for variable-length types.
    pub fn fixed_length(&self) -> Option<usize> {
        Some(match self {
            Self::Byte | Self::Boolean => 1,
            Self::Short => 2,
            Self::Int => 4,
            Self::Long => 8,
            Self::Fixed10 => 10,
            Self::Index { indexed, primary } => indexed.fixed_length()? + primary.fixed_length()?,
            Self::String | Self::Binary | Self::LegacyIndex { .. } => return None,
        })
    }

    /// Length `Field.length()` reports for a default instance (4 for an empty string or binary).
    pub(crate) fn instance_length(&self) -> usize {
        match self {
            Self::String | Self::Binary => 4,
            Self::LegacyIndex { indexed } => indexed.instance_length() + 8,
            Self::Index { indexed, primary } => {
                indexed.instance_length() + primary.instance_length()
            }
            other => other.fixed_length().unwrap_or(0),
        }
    }

    /// `Field.canIndex`: false for index, boolean and byte fields.
    pub fn can_index(&self) -> bool {
        !matches!(
            self,
            Self::Index { .. } | Self::LegacyIndex { .. } | Self::Boolean | Self::Byte
        )
    }
}

/// A string as stored: the raw bytes are kept so an unmodified record writes back identically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JString {
    text: String,
    raw: Vec<u8>,
}

impl JString {
    /// Build from text (encoded as UTF-8).
    pub fn new(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            raw: text.as_bytes().to_vec(),
        }
    }

    /// Decode stored bytes. Malformed UTF-8 becomes U+FFFD (Java's decoder may use a different
    /// number of replacement characters; the raw bytes are kept for writing either way).
    pub fn from_stored(raw: &[u8]) -> Self {
        Self {
            text: String::from_utf8_lossy(raw).into_owned(),
            raw: raw.to_vec(),
        }
    }

    /// Decoded text.
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Stored bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.raw
    }
}

/// A key or column value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Field {
    /// `ByteField`.
    Byte(i8),
    /// `ShortField`.
    Short(i16),
    /// `IntField`.
    Int(i32),
    /// `LongField`.
    Long(i64),
    /// `BooleanField`; the raw stored byte (any non-zero value is true).
    Boolean(u8),
    /// `StringField`; `None` is the null string.
    String(Option<JString>),
    /// `BinaryField`; `None` is null.
    Binary(Option<Vec<u8>>),
    /// `FixedField10`.
    Fixed10([u8; 10]),
    /// `IndexField` / `LegacyIndexField`.
    Index(Box<IndexValue>),
}

/// Value of an index key: the indexed value then the primary key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexValue {
    /// Indexed value (possibly truncated).
    pub indexed: Field,
    /// Primary key of the indexed record (fixed length).
    pub primary: Field,
    /// True for a `LegacyIndexField`.
    pub legacy: bool,
}

fn utf16_prefix_to_string(text: &str, units: usize) -> String {
    let cut: Vec<u16> = text.encode_utf16().take(units).collect();
    // A cut inside a surrogate pair leaves a lone surrogate; Java encodes it as '?'.
    char::decode_utf16(cut).map(|r| r.unwrap_or('?')).collect()
}

impl Field {
    /// A non-null string field.
    pub fn string(text: &str) -> Self {
        Self::String(Some(JString::new(text)))
    }

    /// Build an index key; long indexed values are truncated to [`MAX_INDEX_FIELD_LENGTH`]
    /// stored bytes as `IndexField` does.
    pub fn new_index(indexed: Field, primary: Field, legacy: bool) -> Result<Self> {
        if primary.is_variable_length() {
            return Err(FieldError::IllegalArgument(
                "variable length primaryKey not supported",
            ));
        }
        let mut indexed = indexed;
        if indexed.is_variable_length() && indexed.length() >= MAX_INDEX_FIELD_LENGTH {
            let max_len = MAX_INDEX_FIELD_LENGTH - 4;
            indexed = match indexed {
                Field::String(Some(s)) if s.text.encode_utf16().count() > max_len => {
                    Field::string(&utf16_prefix_to_string(&s.text, max_len))
                }
                Field::Binary(Some(mut d)) if d.len() > max_len => {
                    d.truncate(max_len);
                    Field::Binary(Some(d))
                }
                other => other,
            };
        }
        Ok(Self::Index(Box::new(IndexValue {
            indexed,
            primary,
            legacy,
        })))
    }

    /// The type of this value.
    pub fn field_type(&self) -> FieldType {
        match self {
            Self::Byte(_) => FieldType::Byte,
            Self::Short(_) => FieldType::Short,
            Self::Int(_) => FieldType::Int,
            Self::Long(_) => FieldType::Long,
            Self::Boolean(_) => FieldType::Boolean,
            Self::String(_) => FieldType::String,
            Self::Binary(_) => FieldType::Binary,
            Self::Fixed10(_) => FieldType::Fixed10,
            Self::Index(i) if i.legacy => FieldType::LegacyIndex {
                indexed: Box::new(i.indexed.field_type()),
            },
            Self::Index(i) => FieldType::Index {
                indexed: Box::new(i.indexed.field_type()),
                primary: Box::new(i.primary.field_type()),
            },
        }
    }

    /// True for strings, binaries and variable-length index fields.
    pub fn is_variable_length(&self) -> bool {
        match self {
            Self::String(_) | Self::Binary(_) => true,
            Self::Index(i) => i.legacy || i.indexed.is_variable_length(),
            _ => false,
        }
    }

    /// True for the null string or null binary.
    pub fn is_null(&self) -> bool {
        matches!(self, Self::String(None) | Self::Binary(None))
    }

    /// Stored length in bytes (`Field.length()`).
    pub fn length(&self) -> usize {
        match self {
            Self::Byte(_) | Self::Boolean(_) => 1,
            Self::Short(_) => 2,
            Self::Int(_) => 4,
            Self::Long(_) => 8,
            Self::Fixed10(_) => 10,
            Self::String(s) => 4 + s.as_ref().map_or(0, |s| s.raw.len()),
            Self::Binary(b) => 4 + b.as_ref().map_or(0, Vec::len),
            Self::Index(i) => i.indexed.length() + i.primary.length(),
        }
    }

    /// Integer value of a primitive field (`getLongValue`).
    pub fn long_value(&self) -> Option<i64> {
        Some(match self {
            Self::Byte(v) => i64::from(*v),
            Self::Short(v) => i64::from(*v),
            Self::Int(v) => i64::from(*v),
            Self::Long(v) => *v,
            Self::Boolean(v) => i64::from(*v),
            _ => return None,
        })
    }

    /// Append the stored form to `out`.
    pub fn write(&self, out: &mut Vec<u8>) {
        match self {
            Self::Byte(v) => out.push(*v as u8),
            Self::Boolean(v) => out.push(*v),
            Self::Short(v) => out.extend_from_slice(&v.to_be_bytes()),
            Self::Int(v) => out.extend_from_slice(&v.to_be_bytes()),
            Self::Long(v) => out.extend_from_slice(&v.to_be_bytes()),
            Self::Fixed10(v) => out.extend_from_slice(v),
            Self::String(None) | Self::Binary(None) => {
                out.extend_from_slice(&(-1i32).to_be_bytes())
            }
            Self::String(Some(s)) => {
                out.extend_from_slice(&(s.raw.len() as i32).to_be_bytes());
                out.extend_from_slice(&s.raw);
            }
            Self::Binary(Some(d)) => {
                out.extend_from_slice(&(d.len() as i32).to_be_bytes());
                out.extend_from_slice(d);
            }
            Self::Index(i) => {
                i.indexed.write(out);
                i.primary.write(out);
            }
        }
    }

    /// The stored form as a new vector.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(self.length());
        self.write(&mut v);
        v
    }

    /// Read a value of type `ty` at `offset`; returns the value and the offset after it.
    pub fn read(ty: &FieldType, buf: &[u8], offset: usize) -> Result<(Field, usize)> {
        Ok(match ty {
            FieldType::Byte => (Field::Byte(bytes::get_i8(buf, offset)?), offset + 1),
            FieldType::Boolean => (Field::Boolean(bytes::get_u8(buf, offset)?), offset + 1),
            FieldType::Short => (Field::Short(bytes::get_i16(buf, offset)?), offset + 2),
            FieldType::Int => (Field::Int(bytes::get_i32(buf, offset)?), offset + 4),
            FieldType::Long => (Field::Long(bytes::get_i64(buf, offset)?), offset + 8),
            FieldType::Fixed10 => {
                let mut a = [0u8; 10];
                a.copy_from_slice(bytes::slice(buf, offset, 10)?);
                (Field::Fixed10(a), offset + 10)
            }
            FieldType::String | FieldType::Binary => {
                let len = bytes::get_i32(buf, offset)?;
                let offset = offset + 4;
                let value = if len < 0 {
                    None
                } else {
                    Some(bytes::slice(buf, offset, len as usize)?)
                };
                let next = offset + value.map_or(0, <[u8]>::len);
                let f = if *ty == FieldType::String {
                    Field::String(value.map(JString::from_stored))
                } else {
                    Field::Binary(value.map(<[u8]>::to_vec))
                };
                (f, next)
            }
            FieldType::Index { indexed, primary } => {
                let (i, off) = Field::read(indexed, buf, offset)?;
                let (p, off) = Field::read(primary, buf, off)?;
                (
                    Field::Index(Box::new(IndexValue {
                        indexed: i,
                        primary: p,
                        legacy: false,
                    })),
                    off,
                )
            }
            FieldType::LegacyIndex { indexed } => {
                let (i, off) = Field::read(indexed, buf, offset)?;
                let (p, off) = Field::read(&FieldType::Long, buf, off)?;
                (
                    Field::Index(Box::new(IndexValue {
                        indexed: i,
                        primary: p,
                        legacy: true,
                    })),
                    off,
                )
            }
        })
    }

    /// Stored length of the value of type `ty` at `offset` (`readLength`).
    pub fn read_length(ty: &FieldType, buf: &[u8], offset: usize) -> Result<usize> {
        Ok(match ty {
            FieldType::String | FieldType::Binary => {
                let len = bytes::get_i32(buf, offset)?;
                len.max(0) as usize + 4
            }
            FieldType::Index { indexed, primary } => {
                Self::read_length(indexed, buf, offset)? + primary.instance_length()
            }
            FieldType::LegacyIndex { indexed } => Self::read_length(indexed, buf, offset)? + 8,
            other => other.fixed_length().unwrap_or(0),
        })
    }

    /// `compareTo(Field)`: only values of the same type may be compared. Primitive null state
    /// is ignored; the null string/binary sorts before everything else.
    pub fn compare(&self, other: &Field) -> Result<Ordering> {
        Ok(match (self, other) {
            (Self::Byte(a), Self::Byte(b)) => a.cmp(b),
            (Self::Short(a), Self::Short(b)) => a.cmp(b),
            (Self::Int(a), Self::Int(b)) => a.cmp(b),
            (Self::Long(a), Self::Long(b)) => a.cmp(b),
            (Self::Boolean(a), Self::Boolean(b)) => a.cmp(b),
            (Self::Fixed10(a), Self::Fixed10(b)) => a.cmp(b),
            (Self::String(a), Self::String(b)) => match (a, b) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                // Java String.compareTo: UTF-16 code unit order
                (Some(a), Some(b)) => a.text.encode_utf16().cmp(b.text.encode_utf16()),
            },
            (Self::Binary(a), Self::Binary(b)) => match (a, b) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Less,
                (Some(_), None) => Ordering::Greater,
                (Some(a), Some(b)) => a.cmp(b), // unsigned lexicographic, then length
            },
            (Self::Index(a), Self::Index(b)) => match a.indexed.compare(&b.indexed)? {
                Ordering::Equal => a.primary.compare(&b.primary)?,
                o => o,
            },
            _ => return Err(FieldError::TypeMismatch),
        })
    }

    /// `compareTo(DataBuffer, offset)`: compare with the value of the same type stored at `offset`.
    pub fn compare_to_stored(&self, buf: &[u8], offset: usize) -> Result<Ordering> {
        let (other, _) = Field::read(&self.field_type(), buf, offset)?;
        self.compare(&other)
    }
}

#[cfg(test)]
mod tests;
