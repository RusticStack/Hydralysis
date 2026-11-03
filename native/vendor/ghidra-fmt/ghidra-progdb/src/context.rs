//! Register values (`ProgramRegisterContextDB`): the "Range Map - Register_<name>" tables, one
//! `AddressRangeMapDB` per base register whose value is a `RegisterValue` byte string (value mask
//! followed by the value, each as wide as the register).
//!
//! Default values from the language and compiler specification are not stored in the database
//! and are not modelled.

use ghidra_fmt_db::Database;
use ghidra_fmt_field::Field;
use ghidra_fmt_gbf::BufferStore;

use crate::{Address, AddressMap, AddressRange, Cols, ProgError, Result};

const PREFIX: &str = "Range Map - Register_";

/// A range of addresses holding a value of a base register.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegisterValueRange {
    /// Base register name.
    pub register: String,
    /// The address range (both ends inclusive).
    pub range: AddressRange,
    /// Stored bytes: the mask, then the value (`RegisterValue.toBytes`).
    pub bytes: Vec<u8>,
}

impl RegisterValueRange {
    /// The bits of the register this range sets (all ones for the bits that are known).
    pub fn mask(&self) -> &[u8] {
        &self.bytes[..self.bytes.len() / 2]
    }

    /// The value bits (only those under [`RegisterValueRange::mask`] are meaningful).
    pub fn value(&self) -> &[u8] {
        &self.bytes[self.bytes.len() / 2..]
    }
}

/// Ranges painted in a range map table, in key order, with the stored value.
/// A record whose key range wraps the end of its space is split in two.
pub(crate) fn read_range_map<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
    table_name: &str,
) -> Result<Vec<(AddressRange, Option<Field>)>> {
    let Ok(table) = db.table(table_name) else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        let key = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("range map key".into()))?;
        let to = c
            .long(&rec, "To")?
            .ok_or_else(|| ProgError::Corrupt("range map without end".into()))?;
        let value = c.field(&rec, "Value")?.cloned();
        let (
            Address::Space { space, offset: lo },
            Address::Space {
                space: end_space,
                offset: hi,
            },
        ) = (map.decode(key)?, map.decode(to)?)
        else {
            continue;
        };
        if space != end_space {
            return Err(ProgError::Corrupt(
                "range map record spans two spaces".into(),
            ));
        }
        if lo <= hi {
            out.push((
                AddressRange {
                    space,
                    min: lo,
                    max: hi,
                },
                value,
            ));
        } else {
            let bits = map.spaces().find(&space).map_or(64, |s| s.bits);
            let top = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            out.push((
                AddressRange {
                    space: space.clone(),
                    min: 0,
                    max: hi,
                },
                value.clone(),
            ));
            out.push((
                AddressRange {
                    space,
                    min: lo,
                    max: top,
                },
                value,
            ));
        }
    }
    Ok(out)
}

/// Every stored register value range: registers by name, ranges in key order.
pub(crate) fn read_register_values<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<RegisterValueRange>> {
    let mut names: Vec<String> = db
        .tables()
        .filter_map(|t| t.name().strip_prefix(PREFIX).map(str::to_owned))
        .collect();
    names.sort();
    let mut out = Vec::new();
    for name in names {
        for (range, value) in read_range_map(db, map, &format!("{PREFIX}{name}"))? {
            if let Some(Field::Binary(Some(bytes))) = value {
                out.push(RegisterValueRange {
                    register: name.clone(),
                    range,
                    bytes,
                });
            }
        }
    }
    Ok(out)
}
