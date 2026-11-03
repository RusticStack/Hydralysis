//! Port of the read side of the symbol table: `SymbolDatabaseAdapterV4` / `V5` record layout and
//! the flag decoding of `SymbolDatabaseAdapter`.

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::{Address, AddressMap, Cols, ProgError, Result};

const SYMBOL_SOURCE_LO_BITS: u8 = 0x3;
const SYMBOL_PINNED_FLAG: u8 = 0x4;
const SYMBOL_SOURCE_HI_BIT: u8 = 0x8;

/// `ghidra.program.model.symbol.SourceType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceType {
    /// Storage id 0.
    Analysis,
    /// Storage id 1.
    UserDefined,
    /// Storage id 2.
    Default,
    /// Storage id 3.
    Imported,
    /// Storage id 4.
    Ai,
}

impl SourceType {
    pub(crate) fn from_storage_id(id: u8) -> Result<Self> {
        Ok(match id {
            0 => Self::Analysis,
            1 => Self::UserDefined,
            2 => Self::Default,
            3 => Self::Imported,
            4 => Self::Ai,
            n => {
                return Err(ProgError::Corrupt(format!(
                    "SourceType storage ID not defined: {n}"
                )));
            }
        })
    }

    /// The enum constant name Java prints.
    pub fn name(self) -> &'static str {
        match self {
            Self::Analysis => "ANALYSIS",
            Self::UserDefined => "USER_DEFINED",
            Self::Default => "DEFAULT",
            Self::Imported => "IMPORTED",
            Self::Ai => "AI",
        }
    }
}

/// A row of the "Symbols" table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// Symbol id (record key).
    pub id: i64,
    /// Stored name (empty for default-named symbols).
    pub name: String,
    /// Decoded address.
    pub address: Address,
    /// Id of the parent namespace symbol (0 is the global namespace).
    pub parent_id: i64,
    /// `SymbolType` id: 0 label, 1 library, 3 namespace, 4 class, 5 function, 6 parameter,
    /// 7 local variable, 8 global register variable.
    pub symbol_type: u8,
    /// Raw flags byte.
    pub flags: u8,
    /// Source decoded from the flags.
    pub source: SourceType,
    /// The raw "anchored to address" flag bit; see [`Symbol::is_pinned`].
    pub pinned_flag: bool,
    /// True when the "Primary" column is set; see [`Symbol::is_primary`].
    pub primary_column: bool,
    /// Locator hash, when set.
    pub hash: Option<i64>,
    /// The raw address key (`AddressMapDB` encoding) stored in the record.
    pub address_key: i64,
    /// Data type id of a variable or parameter, when set.
    pub datatype_id: Option<i64>,
    /// Variable offset (stack offset or similar), when set.
    pub variable_offset: Option<i32>,
    /// Original imported name of an external symbol, when set.
    pub original_imported_name: Option<String>,
    /// External program address, when set.
    pub external_program_address: Option<String>,
    /// Comment, when set.
    pub comment: Option<String>,
    /// Library path of a library symbol, when set.
    pub library_path: Option<String>,
    /// Library ordinal (version 5 tables only), when set.
    pub library_ordinal: Option<i32>,
}

impl Symbol {
    /// True for symbols at an address in the external space (`Address.isExternalAddress`).
    pub fn is_external_address(&self) -> bool {
        matches!(&self.address, Address::Space { space, .. } if space == "EXTERNAL")
    }

    /// `Symbol.isPrimary` as the Java symbol classes answer it: libraries, namespaces,
    /// classes and functions are always primary, parameters and variables never, and a
    /// label is primary when it has a default name, lives in external space or has the
    /// Primary column set.
    pub fn is_primary(&self) -> bool {
        match self.symbol_type {
            0 => {
                self.source == SourceType::Default
                    || self.is_external_address()
                    || self.primary_column
            }
            1 | 3 | 4 | 5 => true,
            _ => false,
        }
    }

    /// `Symbol.isPinned`: only labels and functions can be pinned, and not external ones.
    pub fn is_pinned(&self) -> bool {
        matches!(self.symbol_type, 0 | 5) && !self.is_external_address() && self.pinned_flag
    }
}

pub(crate) fn read_symbols<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<Symbol>> {
    let table = db
        .table("Symbols")
        .map_err(|_| ProgError::MissingTable("Symbols".into()))?;
    let c = Cols::new(table.schema());
    let has_ordinal = c.index("LibOrdinal").is_ok();
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        let id = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("symbol key".into()))?;
        let addr_key = c
            .long(&rec, "Address")?
            .ok_or_else(|| ProgError::Corrupt("symbol without address".into()))?;
        let flags = c.byte(&rec, "Flags")?.unwrap_or(0) as u8;
        let lo = flags & SYMBOL_SOURCE_LO_BITS;
        let hi = (flags & SYMBOL_SOURCE_HI_BIT) >> 1;
        out.push(Symbol {
            id,
            name: c.string(&rec, "Name")?.unwrap_or_default(),
            address: map.decode(addr_key)?,
            address_key: addr_key,
            parent_id: c.long(&rec, "Namespace")?.unwrap_or(0),
            symbol_type: c.byte(&rec, "Symbol Type")?.unwrap_or(0) as u8,
            flags,
            source: SourceType::from_storage_id(hi | lo)?,
            pinned_flag: flags & SYMBOL_PINNED_FLAG != 0,
            primary_column: c.field(&rec, "Primary")?.is_some(),
            hash: c.long(&rec, "Locator Hash")?,
            datatype_id: c.long(&rec, "Datatype")?,
            variable_offset: c.int(&rec, "Variable Offset")?,
            original_imported_name: c.string(&rec, "ExtOrigImportName")?,
            external_program_address: c.string(&rec, "ExtProgAddr")?,
            comment: c.string(&rec, "Comment")?,
            library_path: c.string(&rec, "LibPath")?,
            library_ordinal: if has_ordinal {
                c.int(&rec, "LibOrdinal")?
            } else {
                None
            },
        });
    }
    Ok(out)
}
