//! Port of the read side of `ghidra.program.database.map.AddressMapDB` (address key decoding)
//! and `AddressMapDBAdapterV1` (the "ADDRESS MAP" table of base addresses).

use std::fmt;

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::{Cols, ProgError, Result};

const ADDR_TYPE_SHIFT: u32 = 60;
const ADDR_OFFSET_SIZE: u32 = 32;
const ADDR_OFFSET_MASK: u64 = (1 << ADDR_OFFSET_SIZE) - 1;
const ID_MASK: u64 = (1 << (64 - 4 - ADDR_OFFSET_SIZE)) - 1;
const HASH_OFFSET_MASK: u64 = (1 << 60) - 1;
const EXT_FROM_ADDRESS_LONG: i64 = -2;

const ABSOLUTE_ADDR_TYPE: u64 = 0x1;
const RELOCATABLE_ADDR_TYPE: u64 = 0x2;
const REGISTER_ADDR_TYPE: u64 = 0x3;
const STACK_ADDR_TYPE: u64 = 0x4;
const EXTERNAL_ADDR_TYPE: u64 = 0x5;
const VARIABLE_ADDR_TYPE: u64 = 0x6;
const HASH_ADDR_TYPE: u64 = 0x7;
const NO_ADDR_TYPE: u64 = 0xf;

/// One address space of the program's language.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SpaceDef {
    /// Space name (`ram`, `register`, ...).
    pub name: String,
    /// Space id (`AddressSpace.getSpaceID`), the order addresses of different spaces sort in.
    pub id: i32,
    /// Address size in bits (`AddressSpace.getSize`).
    pub bits: u32,
}

/// The address spaces of a program, as its language defines them. The database stores only the
/// space names, so the caller supplies this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressSpaces {
    /// All spaces (the static ones, `EXTERNAL`, `VARIABLE` and `HASH`, are added when missing).
    pub spaces: Vec<SpaceDef>,
    /// Name of the default (code) space, the one the image base applies to.
    pub default_space: String,
    /// Name of the register space.
    pub register_space: String,
    /// Name of the stack space.
    pub stack_space: String,
}

impl AddressSpaces {
    /// Spaces with the usual `register` and `stack` names.
    pub fn new(spaces: Vec<SpaceDef>, default_space: &str) -> Self {
        let mut me = Self {
            spaces,
            default_space: default_space.to_owned(),
            register_space: "register".to_owned(),
            stack_space: "stack".to_owned(),
        };
        for (name, id, bits) in [
            ("EXTERNAL", 42, 32),
            ("VARIABLE", 36, 32),
            ("HASH", 126, 60),
        ] {
            if me.find(name).is_none() {
                me.spaces.push(SpaceDef {
                    name: name.to_owned(),
                    id,
                    bits,
                });
            }
        }
        me
    }

    /// Look a space up by name.
    pub fn find(&self, name: &str) -> Option<&SpaceDef> {
        self.spaces.iter().find(|s| s.name == name)
    }
}

/// A decoded address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Address {
    /// An offset in a space.
    Space {
        /// Space name.
        space: String,
        /// Offset (unsigned).
        offset: u64,
    },
    /// `Address.NO_ADDRESS`.
    NoAddress,
    /// `Address.EXT_FROM_ADDRESS`.
    ExtFrom,
}

impl fmt::Display for Address {
    /// `space:hex-offset`, `NO_ADDRESS` or `EXT_FROM` (the oracle format).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Space { space, offset } => write!(f, "{space}:{offset:x}"),
            Self::NoAddress => f.write_str("NO_ADDRESS"),
            Self::ExtFrom => f.write_str("EXT_FROM"),
        }
    }
}

/// A row of the "ADDRESS MAP" table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseEntry {
    /// Base index (record key).
    pub index: i64,
    /// Stored space name.
    pub space_name: String,
    /// Segment (the base offset is `segment << 32`).
    pub segment: i32,
    /// Deleted flag.
    pub deleted: bool,
}

#[derive(Debug, Clone)]
struct Base {
    space: String,
    bits: u32,
    offset: u64,
}

/// The decoded "ADDRESS MAP": base addresses plus the rules of `AddressMapDB.decodeAddress`.
#[derive(Debug, Clone)]
pub struct AddressMap {
    spaces: AddressSpaces,
    entries: Vec<BaseEntry>,
    bases: Vec<Base>,
    image_base: i64,
}

fn mask_bits(bits: u32) -> u64 {
    if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    }
}

impl AddressMap {
    pub(crate) fn read<S: BufferStore>(
        db: &Database<S>,
        spaces: AddressSpaces,
        image_base: i64,
    ) -> Result<Self> {
        let table = db
            .table("ADDRESS MAP")
            .map_err(|_| ProgError::MissingTable("ADDRESS MAP".into()))?;
        let version = table.schema().version();
        if version != 1 {
            return Err(ProgError::UnsupportedTableVersion {
                table: "ADDRESS MAP".into(),
                version,
            });
        }
        let cols = Cols::new(table.schema());
        let mut entries = Vec::new();
        for rec in table.records()? {
            let rec = rec?;
            let key = rec
                .key
                .long_value()
                .ok_or_else(|| ProgError::Corrupt("address map key is not a long".into()))?;
            entries.push(BaseEntry {
                index: key,
                space_name: cols.string(&rec, "Space Name")?.unwrap_or_default(),
                segment: cols.int(&rec, "Segment")?.unwrap_or(0),
                deleted: cols.boolean(&rec, "Deleted")?.unwrap_or(false),
            });
        }
        let mut bases: Vec<Option<Base>> = vec![None; entries.len()];
        for e in &entries {
            let idx = usize::try_from(e.index)
                .ok()
                .filter(|i| *i < bases.len())
                .ok_or_else(|| {
                    ProgError::Corrupt(format!("address map index {} out of range", e.index))
                })?;
            let base = match spaces.find(&e.space_name) {
                Some(sp) if !e.deleted => Base {
                    space: sp.name.clone(),
                    bits: sp.bits,
                    offset: (i64::from(e.segment) << ADDR_OFFSET_SIZE) as u64 & mask_bits(sp.bits),
                },
                _ => Base {
                    space: format!("Deleted_{}", e.space_name),
                    bits: 64,
                    offset: 0,
                },
            };
            bases[idx] = Some(base);
        }
        let bases = bases
            .into_iter()
            .map(|b| b.ok_or_else(|| ProgError::Corrupt("gap in address map indexes".into())))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            spaces,
            entries,
            bases,
            image_base,
        })
    }

    /// Rows of the "ADDRESS MAP" table.
    pub fn entries(&self) -> &[BaseEntry] {
        &self.entries
    }

    /// The stored image base offset.
    pub fn image_base(&self) -> i64 {
        self.image_base
    }

    /// The address spaces in use.
    pub fn spaces(&self) -> &AddressSpaces {
        &self.spaces
    }

    /// Sort key of an address (`Address.compareTo`): space id, then unsigned offset.
    pub fn sort_key(&self, a: &Address) -> (i32, u64) {
        match a {
            Address::Space { space, offset } => {
                (self.spaces.find(space).map_or(i32::MAX, |s| s.id), *offset)
            }
            Address::NoAddress => (i32::MIN, 0),
            Address::ExtFrom => (i32::MIN, 1),
        }
    }

    fn space(&self, name: &str) -> Result<&SpaceDef> {
        self.spaces
            .find(name)
            .ok_or_else(|| ProgError::UnknownSpace(name.to_owned()))
    }

    fn in_space(&self, name: &str, offset: u64) -> Result<Address> {
        let bits = self.space(name)?.bits;
        Ok(if offset > mask_bits(bits) {
            Address::NoAddress // AddressOutOfBoundsException in Java
        } else {
            Address::Space {
                space: name.to_owned(),
                offset,
            }
        })
    }

    /// HYDRALYSIS ADDITION (not in the engine): `AddressMapDB.getKey(addr, false)` for an address in the
    /// default space, which is stored relocatable (`encodeRelative`: the image base is removed, the high 32
    /// bits select a base entry, the low 32 bits are the offset). `None` when no base entry matches (Java
    /// answers `INVALID_ADDRESS_KEY`: nothing is stored for that address).
    pub fn encode_default(&self, offset: u64) -> Option<i64> {
        let default = self.spaces.find(&self.spaces.default_space)?;
        let mask = mask_bits(default.bits);
        let normalized = offset.wrapping_sub(self.image_base as u64) & mask;
        let base_offset = normalized & !ADDR_OFFSET_MASK;
        let index = self
            .bases
            .iter()
            .position(|b| b.space == default.name && b.offset == base_offset)?;
        Some(((RELOCATABLE_ADDR_TYPE << ADDR_TYPE_SHIFT) | ((index as u64) << ADDR_OFFSET_SIZE) | (normalized & ADDR_OFFSET_MASK)) as i64)
    }

    /// `AddressMapDB.decodeAddress(long)`: the address a key stands for.
    ///
    /// # Errors
    ///
    /// Old-style keys (type 0), namespace-qualified register, stack and external addresses and
    /// segmented spaces are refused; those only occur in databases Java upgrades.
    pub fn decode(&self, value: i64) -> Result<Address> {
        let kind = (value as u64 >> ADDR_TYPE_SHIFT) & 0xf;
        let low = value as u64 & ADDR_OFFSET_MASK;
        let id = (value as u64 >> ADDR_OFFSET_SIZE) & ID_MASK;
        match kind {
            ABSOLUTE_ADDR_TYPE => {
                let base = self.bases.get(id as usize).ok_or_else(|| {
                    ProgError::Corrupt(format!("address key {value:#x} uses base {id}"))
                })?;
                Ok(match base.offset.checked_add(low) {
                    Some(o) if o <= mask_bits(base.bits) => Address::Space {
                        space: base.space.clone(),
                        offset: o,
                    },
                    _ => Address::NoAddress,
                })
            }
            RELOCATABLE_ADDR_TYPE => {
                let Some(base) = self.bases.get(id as usize) else {
                    return Ok(Address::NoAddress);
                };
                let mut offset = low;
                if base.space == self.spaces.default_space {
                    offset = offset.wrapping_add(self.image_base as u64);
                }
                Ok(Address::Space {
                    space: base.space.clone(),
                    offset: base.offset.wrapping_add(offset) & mask_bits(base.bits),
                })
            }
            REGISTER_ADDR_TYPE => {
                global_only(value, id)?;
                let name = self.spaces.register_space.clone();
                self.in_space(&name, low)
            }
            STACK_ADDR_TYPE => {
                global_only(value, id)?;
                let name = self.spaces.stack_space.clone();
                let bits = self.space(&name)?.bits;
                // `(int)(value & mask)`: the stack offset is a signed 32-bit quantity
                let signed = i64::from(low as u32 as i32);
                let offset = if bits >= 64 {
                    signed as u64
                } else {
                    let max = (1i64 << (bits - 1)) - 1;
                    let min = -(1i64 << (bits - 1));
                    signed.clamp(min, max) as u64 & mask_bits(bits)
                };
                Ok(Address::Space {
                    space: name,
                    offset,
                })
            }
            EXTERNAL_ADDR_TYPE => {
                global_only(value, id)?;
                self.in_space("EXTERNAL", low)
            }
            VARIABLE_ADDR_TYPE => self.in_space("VARIABLE", low),
            HASH_ADDR_TYPE => self.in_space("HASH", value as u64 & HASH_OFFSET_MASK),
            NO_ADDR_TYPE => Ok(if value == EXT_FROM_ADDRESS_LONG {
                Address::ExtFrom
            } else {
                Address::NoAddress
            }),
            // type 0 is the pre-upgrade encoding (`oldGetAddressFromLong`)
            _ => Err(ProgError::UnsupportedAddressKey(value)),
        }
    }
}

fn global_only(value: i64, namespace_id: u64) -> Result<()> {
    if namespace_id == 0 {
        Ok(())
    } else {
        Err(ProgError::UnsupportedAddressKey(value))
    }
}
