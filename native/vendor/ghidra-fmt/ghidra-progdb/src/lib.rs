//! Read-only access to a Ghidra Program database (the `.gbf` of a Program).
//!
//! This is the Rust port of the read side of `ghidra.program.database.ProgramDB` for the parts
//! the engine needs first: the version policy and the "Program" metadata table, the address map
//! (`AddressMapDB`), the memory map (`MemoryMapDBAdapterV3`) and the symbol table
//! (`SymbolDatabaseAdapterV4/V5`). Everything is checked against Java by
//! `oracle/OracleProgram.java` (see `tests/oracle_diff.rs`).
//!
//! Upgrades stay in Java: a database older than the oldest version Java opens without an upgrade,
//! newer than the version this port knows, or holding a table version this port does not read,
//! is refused with a descriptive [`ProgError`] instead of being guessed at.

mod addrmap;
mod error;
mod functions;
mod listing;
mod memory;
mod references;
mod symbols;

use std::collections::BTreeMap;

use ghidra_fmt_db::Database;
use ghidra_fmt_field::{Field, Record, Schema};
use ghidra_fmt_gbf::BufferStore;

pub use addrmap::{Address, AddressMap, AddressSpaces, SpaceDef};
pub use error::ProgError;
pub use functions::Function;
pub use listing::{Comments, DataRow, InstructionRow};
pub use memory::{MemoryBlock, SubBlock, SubBlockKind};
pub use references::{RefKind, Reference, ref_type_name};
pub use symbols::{SourceType, Symbol};

/// Result type of this crate.
pub type Result<T> = std::result::Result<T, ProgError>;

/// `ProgramDB.DB_VERSION`: the newest database version this port understands.
pub const DB_VERSION: i32 = 33;

/// `ProgramDB.UPGRADE_REQUIRED_BEFORE_VERSION`: databases older than this need a Java upgrade
/// before they can be read at all.
pub const MIN_READABLE_VERSION: i32 = 19;

/// An open Program database.
pub struct ProgramDb<S: BufferStore> {
    db: Database<S>,
    stored_version: i32,
    metadata: BTreeMap<String, String>,
    address_map: AddressMap,
}

impl<S: BufferStore> ProgramDb<S> {
    /// Open the Program database in `store` read-only.
    ///
    /// `spaces` describes the address spaces of the program's language (name, id, size); the
    /// database stores space names only, so the caller supplies the rest.
    ///
    /// # Errors
    ///
    /// [`ProgError::NewerVersion`], [`ProgError::UpgradeRequired`] or
    /// [`ProgError::UnsupportedTableVersion`] when Java would have to upgrade (or this port does
    /// not know) the database, and the underlying error when the file is damaged.
    pub fn open(store: S, spaces: AddressSpaces) -> Result<Self> {
        let db = Database::open(store)?;
        let program = db
            .table("Program")
            .map_err(|_| ProgError::MissingTable("Program".into()))?;
        let mut metadata = BTreeMap::new();
        for rec in program.records()? {
            let rec = rec?;
            let key = string_of(Some(&rec.key)).unwrap_or_default();
            let value = rec
                .values
                .first()
                .and_then(|v| string_of(v.as_ref()))
                .unwrap_or_default();
            metadata.insert(key, value);
        }
        let stored_version = metadata
            .get("DB Version")
            .and_then(|v| v.parse::<i32>().ok())
            .unwrap_or(1);
        if stored_version > DB_VERSION {
            return Err(ProgError::NewerVersion {
                stored: stored_version,
                supported: DB_VERSION,
            });
        }
        if stored_version < MIN_READABLE_VERSION {
            return Err(ProgError::UpgradeRequired {
                stored: stored_version,
                minimum: MIN_READABLE_VERSION,
            });
        }
        let image_base = metadata
            .get("Image Offset")
            .map_or(Ok(0), |s| parse_hex_i64(s))?;
        let address_map = AddressMap::read(&db, spaces, image_base)?;
        let me = Self {
            db,
            stored_version,
            metadata,
            address_map,
        };
        me.check_table_versions()?;
        Ok(me)
    }

    fn check_table_versions(&self) -> Result<()> {
        let expect = |name: &str, versions: &[i32]| -> Result<()> {
            let t = self
                .db
                .table(name)
                .map_err(|_| ProgError::MissingTable(name.into()))?;
            let v = t.schema().version();
            if versions.contains(&v) {
                Ok(())
            } else {
                Err(ProgError::UnsupportedTableVersion {
                    table: name.into(),
                    version: v,
                })
            }
        };
        expect("Memory Blocks", &[3])?;
        expect("Sub Memory Blocks", &[3])?;
        expect("Symbols", &[4, 5])?;
        // listing tables are created on demand, so they may be absent
        let optional = |name: &str, versions: &[i32]| -> Result<()> {
            match self.db.table(name) {
                Ok(t) if !versions.contains(&t.schema().version()) => {
                    Err(ProgError::UnsupportedTableVersion {
                        table: name.into(),
                        version: t.schema().version(),
                    })
                }
                _ => Ok(()),
            }
        };
        optional("Function Data", &[3])?;
        optional("Thunk Functions", &[0])?;
        optional("FROM REFS", &[0])?;
        optional("TO REFS", &[1])?;
        optional("Instructions", &[1])?;
        optional("Data", &[0])?;
        optional("Comments", &[1])
    }

    /// The underlying database (for raw table access).
    pub fn database(&self) -> &Database<S> {
        &self.db
    }

    /// `ProgramDB.getStoredVersion`: the "DB Version" entry (1 when absent or malformed).
    pub fn stored_version(&self) -> i32 {
        self.stored_version
    }

    /// Every entry of the "Program" table.
    pub fn metadata(&self) -> &BTreeMap<String, String> {
        &self.metadata
    }

    /// The "Language ID" entry.
    pub fn language_id(&self) -> Option<&str> {
        self.metadata.get("Language ID").map(String::as_str)
    }

    /// The "Compiler Spec ID" entry.
    pub fn compiler_spec_id(&self) -> Option<&str> {
        self.metadata.get("Compiler Spec ID").map(String::as_str)
    }

    /// The stored image base offset (`Image Offset`, hexadecimal), 0 when absent.
    pub fn image_base_offset(&self) -> i64 {
        self.address_map.image_base()
    }

    /// The address map.
    pub fn address_map(&self) -> &AddressMap {
        &self.address_map
    }

    /// Memory blocks in memory map order (sorted by start address).
    pub fn memory_blocks(&self) -> Result<Vec<MemoryBlock>> {
        memory::read_blocks(&self.db, &self.address_map)
    }

    /// Every record of the symbol table in id order.
    pub fn symbols(&self) -> Result<Vec<Symbol>> {
        symbols::read_symbols(&self.db, &self.address_map)
    }

    /// Every function (row of "Function Data") in id order.
    pub fn functions(&self) -> Result<Vec<Function>> {
        let addresses = self
            .symbols()?
            .into_iter()
            .filter(|s| s.symbol_type == 5)
            .map(|s| (s.id, s.address))
            .collect();
        functions::read_functions(&self.db, &addresses)
    }

    /// Every "FROM REFS" row in key order: the from address and its references.
    pub fn references_from(&self) -> Result<Vec<(Address, Vec<Reference>)>> {
        references::read_table(&self.db, &self.address_map, "FROM REFS", true)
    }

    /// Every "TO REFS" row in key order: the to address and the references to it.
    pub fn references_to(&self) -> Result<Vec<(Address, Vec<Reference>)>> {
        references::read_table(&self.db, &self.address_map, "TO REFS", false)
    }

    /// HYDRALYSIS ADDITION (not in the engine): the references to one default-space address
    /// (`ReferenceManager.getReferencesTo(Address)`), in stored order, by key lookup.
    pub fn references_to_at(&self, to: &Address) -> Result<Vec<Reference>> {
        Ok(references::read_one(&self.db, &self.address_map, "TO REFS", false, to)?.unwrap_or_default())
    }

    /// HYDRALYSIS ADDITION (not in the engine): the references from one default-space address, by key lookup.
    pub fn references_from_at(&self, from: &Address) -> Result<Vec<Reference>> {
        Ok(references::read_one(&self.db, &self.address_map, "FROM REFS", true, from)?.unwrap_or_default())
    }

    /// Rows of "Instructions" in key order.
    pub fn instructions(&self) -> Result<Vec<InstructionRow>> {
        listing::read_instructions(&self.db, &self.address_map)
    }

    /// Rows of "Data" in key order.
    pub fn data(&self) -> Result<Vec<DataRow>> {
        listing::read_data(&self.db, &self.address_map)
    }

    /// Rows of "Comments" in key order.
    pub fn comments(&self) -> Result<Vec<(Address, Comments)>> {
        listing::read_comments(&self.db, &self.address_map)
    }
}

/// Text of a string field.
pub(crate) fn string_of(f: Option<&Field>) -> Option<String> {
    match f {
        Some(Field::String(Some(s))) => Some(s.as_str().to_owned()),
        _ => None,
    }
}

/// Parse `new BigInteger(s, 16).longValue()`.
fn parse_hex_i64(s: &str) -> Result<i64> {
    let (neg, digits) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s.strip_prefix('+').unwrap_or(s)),
    };
    let v = u128::from_str_radix(digits, 16)
        .map_err(|_| ProgError::Corrupt(format!("bad hexadecimal image offset {s:?}")))?;
    // longValue keeps the low 64 bits of the two's complement value
    let low = v as u64 as i64;
    Ok(if neg { low.wrapping_neg() } else { low })
}

/// Column accessors by schema position, with the column checked by name once per table.
pub(crate) struct Cols<'a> {
    schema: &'a Schema,
}

impl<'a> Cols<'a> {
    pub(crate) fn new(schema: &'a Schema) -> Self {
        Self { schema }
    }

    pub(crate) fn index(&self, name: &str) -> Result<usize> {
        self.schema
            .field_names()
            .iter()
            .position(|n| n == name)
            .ok_or_else(|| ProgError::Corrupt(format!("missing column {name}")))
    }

    pub(crate) fn field<'r>(&self, rec: &'r Record, name: &str) -> Result<Option<&'r Field>> {
        let i = self.index(name)?;
        Ok(rec.values.get(i).and_then(Option::as_ref))
    }

    pub(crate) fn long(&self, rec: &Record, name: &str) -> Result<Option<i64>> {
        Ok(match self.field(rec, name)? {
            Some(Field::Long(v)) => Some(*v),
            _ => None,
        })
    }

    pub(crate) fn int(&self, rec: &Record, name: &str) -> Result<Option<i32>> {
        Ok(match self.field(rec, name)? {
            Some(Field::Int(v)) => Some(*v),
            _ => None,
        })
    }

    pub(crate) fn byte(&self, rec: &Record, name: &str) -> Result<Option<i8>> {
        Ok(match self.field(rec, name)? {
            Some(Field::Byte(v)) => Some(*v),
            _ => None,
        })
    }

    pub(crate) fn string(&self, rec: &Record, name: &str) -> Result<Option<String>> {
        Ok(string_of(self.field(rec, name)?))
    }

    pub(crate) fn boolean(&self, rec: &Record, name: &str) -> Result<Option<bool>> {
        Ok(match self.field(rec, name)? {
            Some(Field::Boolean(v)) => Some(*v != 0),
            _ => None,
        })
    }
}

#[cfg(test)]
mod tests;
