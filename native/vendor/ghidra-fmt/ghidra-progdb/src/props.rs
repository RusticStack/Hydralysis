//! Program options (`OptionsDB`, the "Property Table") and the user / analysis property maps
//! (`DBPropertyMapManager`, the "Property Map - <name>" tables).

use ghidra_fmt_db::Database;
use ghidra_fmt_field::Field;
use ghidra_fmt_gbf::BufferStore;

use crate::{Address, AddressMap, Cols, ProgError, Result};

const MAP_PREFIX: &str = "Property Map - ";

/// `OptionType` constants in ordinal order (the stored "Type" byte).
const OPTION_TYPES: [&str; 16] = [
    "INT_TYPE",
    "LONG_TYPE",
    "STRING_TYPE",
    "DOUBLE_TYPE",
    "BOOLEAN_TYPE",
    "DATE_TYPE",
    "NO_TYPE",
    "FLOAT_TYPE",
    "ENUM_TYPE",
    "CUSTOM_TYPE",
    "BYTE_ARRAY_TYPE",
    "FILE_TYPE",
    "COLOR_TYPE",
    "FONT_TYPE",
    "KEYSTROKE_TYPE",
    "ACTION_TRIGGER",
];

/// One option of the program's option lists, for example
/// `Program Information.Executable Format`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramOption {
    /// List name and option name joined with a dot, as stored.
    pub key: String,
    /// `OptionType` ordinal.
    pub type_id: u8,
    /// The stored string form of the value (a date is in milliseconds since the epoch).
    pub value: String,
}

impl ProgramOption {
    /// The `OptionType` constant name, `None` for an unknown ordinal.
    pub fn type_name(&self) -> Option<&'static str> {
        OPTION_TYPES.get(usize::from(self.type_id)).copied()
    }
}

/// The type of a property map (`DBPropertyMapManager.*_PROPERTY_TYPE`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyKind {
    /// `IntPropertyMap`.
    Int,
    /// `LongPropertyMap`.
    Long,
    /// `StringPropertyMap`.
    String,
    /// `VoidPropertyMap`: presence only.
    Void,
    /// `ObjectPropertyMap`: `Saveable` objects, stored per class; values are not decoded.
    Object,
}

impl PropertyKind {
    /// The name the oracle prints.
    pub fn name(self) -> &'static str {
        match self {
            Self::Int => "INT",
            Self::Long => "LONG",
            Self::String => "STRING",
            Self::Void => "VOID",
            Self::Object => "OBJECT",
        }
    }
}

/// The value at an address of a property map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PropertyValue {
    /// Integer.
    Int(i32),
    /// Long.
    Long(i64),
    /// String.
    String(String),
    /// Present, no value.
    Void,
    /// An object; not decoded.
    Object,
}

/// A user or analysis property map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyMap {
    /// Map name.
    pub name: String,
    /// Value type.
    pub kind: PropertyKind,
    /// Entries in address key order.
    pub entries: Vec<(Address, PropertyValue)>,
}

pub(crate) fn read_options<S: BufferStore>(db: &Database<S>) -> Result<Vec<ProgramOption>> {
    let Ok(table) = db.table("Property Table") else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        let key = match &rec.key {
            Field::String(Some(s)) => s.as_str().to_owned(),
            _ => continue,
        };
        out.push(ProgramOption {
            key,
            type_id: c.byte(&rec, "Type")?.unwrap_or(0) as u8,
            value: c.string(&rec, "Value")?.unwrap_or_default(),
        });
    }
    out.sort_by(|a, b| a.key.cmp(&b.key));
    Ok(out)
}

pub(crate) fn read_property_maps<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<PropertyMap>> {
    let Ok(registry) = db.table("Properties") else {
        return Ok(Vec::new());
    };
    let c = Cols::new(registry.schema());
    let mut out = Vec::new();
    for rec in registry.records()? {
        let rec = rec?;
        let Field::String(Some(name)) = &rec.key else {
            continue;
        };
        let name = name.as_str().to_owned();
        let kind = match c.byte(&rec, "Type")?.unwrap_or(-1) {
            0 => PropertyKind::Int,
            1 => PropertyKind::Long,
            2 => PropertyKind::String,
            3 => PropertyKind::Void,
            4 => PropertyKind::Object,
            other => {
                return Err(ProgError::Corrupt(format!(
                    "property map {name}: unknown type {other}"
                )));
            }
        };
        let mut entries = Vec::new();
        if let Ok(table) = db.table(&format!("{MAP_PREFIX}{name}")) {
            let vc = Cols::new(table.schema());
            for row in table.records()? {
                let row = row?;
                let key = row
                    .key
                    .long_value()
                    .ok_or_else(|| ProgError::Corrupt("property map key".into()))?;
                let value = match kind {
                    PropertyKind::Int => PropertyValue::Int(vc.int(&row, "Value")?.unwrap_or(0)),
                    PropertyKind::Long => PropertyValue::Long(vc.long(&row, "Value")?.unwrap_or(0)),
                    PropertyKind::String => {
                        PropertyValue::String(vc.string(&row, "Value")?.unwrap_or_default())
                    }
                    PropertyKind::Void => PropertyValue::Void,
                    PropertyKind::Object => PropertyValue::Object,
                };
                entries.push((map.decode(key)?, value));
            }
        }
        out.push(PropertyMap {
            name,
            kind,
            entries,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}
