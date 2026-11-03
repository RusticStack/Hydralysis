//! Equates (`EquateManager`), bookmarks (`BookmarkDBManager`) and relocations
//! (`RelocationManager`, adapter V6).

use std::collections::BTreeMap;

use ghidra_fmt_db::Database;
use ghidra_fmt_field::Field;
use ghidra_fmt_gbf::BufferStore;

use crate::{Address, AddressMap, Cols, Memory, ProgError, Result};

/// A place an equate is applied (`EquateReference`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EquateReference {
    /// Address of the code unit.
    pub address: Address,
    /// Operand index (`-1` for references made by dynamic hash).
    pub op_index: i16,
    /// Dynamic hash value (0 when the reference is by operand index).
    pub dynamic_hash: i64,
}

/// A named constant (`Equate`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Equate {
    /// Record key.
    pub id: i64,
    /// Name.
    pub name: String,
    /// Value.
    pub value: i64,
    /// Where it is applied, sorted by address, operand and hash.
    pub references: Vec<EquateReference>,
}

/// A bookmark (`Bookmark`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Bookmark {
    /// Bookmark id (record key; the type id is in the bits above bit 48).
    pub id: i64,
    /// Address.
    pub address: Address,
    /// Type name (`Note`, `Info`, `Warning`, `Error`, `Analysis` or a defined one).
    pub type_name: String,
    /// Category (may be empty).
    pub category: String,
    /// Comment.
    pub comment: String,
}

/// Relocation status (`Relocation.Status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelocationStatus {
    /// Unknown, assumed to have modified memory bytes.
    Unknown,
    /// Intentionally skipped.
    Skipped,
    /// Type not supported when relocations were applied.
    Unsupported,
    /// Failed to apply.
    Failure,
    /// Processed, relies on a later relocation to affect memory.
    Partial,
    /// Applied and modified memory.
    Applied,
    /// Memory was altered by the loader without a standard relocation type.
    AppliedOther,
}

impl RelocationStatus {
    /// `Relocation.Status.getStatus(int)`; unknown values give `Unknown` like the Java adapter.
    pub fn from_value(v: i32) -> Self {
        match v {
            1 => Self::Skipped,
            2 => Self::Unsupported,
            3 => Self::Failure,
            4 => Self::Partial,
            5 => Self::Applied,
            6 => Self::AppliedOther,
            _ => Self::Unknown,
        }
    }

    /// `Status.hasBytes`: the original bytes are meaningful.
    pub fn has_bytes(self) -> bool {
        matches!(self, Self::Unknown | Self::Applied | Self::AppliedOther)
    }

    /// The Java enum constant name.
    pub fn name(self) -> &'static str {
        match self {
            Self::Unknown => "UNKNOWN",
            Self::Skipped => "SKIPPED",
            Self::Unsupported => "UNSUPPORTED",
            Self::Failure => "FAILURE",
            Self::Partial => "PARTIAL",
            Self::Applied => "APPLIED",
            Self::AppliedOther => "APPLIED_OTHER",
        }
    }
}

/// A relocation (`Relocation`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Relocation {
    /// Address.
    pub address: Address,
    /// Status.
    pub status: RelocationStatus,
    /// Processor specific type.
    pub kind: i32,
    /// Relocation values (`None` when stored as a null array).
    pub values: Option<Vec<i64>>,
    /// Stored original bytes, or `None`.
    pub stored_bytes: Option<Vec<u8>>,
    /// Byte length recorded in the flags (used when no bytes are stored).
    pub length: i32,
    /// Symbol name, when set.
    pub symbol_name: Option<String>,
}

pub(crate) fn read_equates<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<Equate>> {
    let Ok(table) = db.table("Equates") else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut by_id: BTreeMap<i64, Equate> = BTreeMap::new();
    for rec in table.records()? {
        let rec = rec?;
        let id = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("equate key".into()))?;
        by_id.insert(
            id,
            Equate {
                id,
                name: c.string(&rec, "Equate Name")?.unwrap_or_default(),
                value: c.long(&rec, "Equate Value")?.unwrap_or(0),
                references: Vec::new(),
            },
        );
    }
    if let Ok(refs) = db.table("Equate References") {
        let c = Cols::new(refs.schema());
        for rec in refs.records()? {
            let rec = rec?;
            let Some(eq) = c.long(&rec, "Equate ID")?.and_then(|id| by_id.get_mut(&id)) else {
                continue;
            };
            let key = c
                .long(&rec, "Equate Reference")?
                .ok_or_else(|| ProgError::Corrupt("equate reference without address".into()))?;
            let op_index = match c.field(&rec, "Operand Index")? {
                Some(Field::Short(v)) => *v,
                _ => 0,
            };
            eq.references.push(EquateReference {
                address: map.decode(key)?,
                op_index,
                dynamic_hash: c.long(&rec, "Varnode Hash")?.unwrap_or(0),
            });
        }
    }
    let mut out: Vec<Equate> = by_id.into_values().collect();
    for e in &mut out {
        e.references
            .sort_by_key(|r| (r.address.to_string(), r.op_index, r.dynamic_hash));
    }
    Ok(out)
}

pub(crate) fn read_bookmarks<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<Bookmark>> {
    let Ok(types) = db.table("Bookmark Types") else {
        return Ok(Vec::new());
    };
    let mut names = BTreeMap::new();
    for rec in types.records()? {
        let rec = rec?;
        let id = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("bookmark type key".into()))?;
        let name = match rec.values.first() {
            Some(Some(Field::String(Some(s)))) => s.as_str().to_owned(),
            _ => String::new(),
        };
        names.insert(id, name);
    }
    let mut out = Vec::new();
    for (type_id, name) in &names {
        let Ok(table) = db.table(&format!("Bookmarks{type_id}")) else {
            continue;
        };
        let c = Cols::new(table.schema());
        for rec in table.records()? {
            let rec = rec?;
            let id = rec
                .key
                .long_value()
                .ok_or_else(|| ProgError::Corrupt("bookmark key".into()))?;
            let key = c
                .long(&rec, "Address")?
                .ok_or_else(|| ProgError::Corrupt("bookmark without address".into()))?;
            out.push(Bookmark {
                id,
                address: map.decode(key)?,
                type_name: name.clone(),
                category: c.string(&rec, "Category")?.unwrap_or_default(),
                comment: c.string(&rec, "Comment")?.unwrap_or_default(),
            });
        }
    }
    out.sort_by_key(|b| b.id);
    Ok(out)
}

/// The names of the defined bookmark types, sorted.
pub(crate) fn read_bookmark_types<S: BufferStore>(db: &Database<S>) -> Result<Vec<String>> {
    let Ok(types) = db.table("Bookmark Types") else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    for rec in types.records()? {
        let rec = rec?;
        if let Some(Some(Field::String(Some(s)))) = rec.values.first() {
            out.push(s.as_str().to_owned());
        }
    }
    out.sort();
    Ok(out)
}

/// Relocations in index order: by encoded address, then record key.
pub(crate) fn read_relocations<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<Relocation>> {
    let Ok(table) = db.table("Relocations") else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut rows = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        let key = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("relocation key".into()))?;
        let addr_key = c
            .long(&rec, "Address")?
            .ok_or_else(|| ProgError::Corrupt("relocation without address".into()))?;
        let flags = c.byte(&rec, "Status")?.unwrap_or(0) as u8;
        let stored_bytes = match c.field(&rec, "Bytes")? {
            Some(Field::Binary(Some(d))) => Some(d.clone()),
            _ => None,
        };
        let values = match c.field(&rec, "Values")? {
            Some(Field::Binary(Some(d))) => long_array(d)?,
            _ => None,
        };
        rows.push((
            (addr_key, key),
            Relocation {
                address: map.decode(addr_key)?,
                status: RelocationStatus::from_value(i32::from(flags & 0x7)),
                kind: c.int(&rec, "Type")?.unwrap_or(0),
                values,
                stored_bytes,
                length: i32::from((flags >> 3) & 0xF),
                symbol_name: c.string(&rec, "Symbol Name")?,
            },
        ));
    }
    rows.sort_by_key(|r| r.0);
    Ok(rows.into_iter().map(|r| r.1).collect())
}

/// `new BinaryCodedField(field).getLongArray()`.
fn long_array(d: &[u8]) -> Result<Option<Vec<i64>>> {
    if d.len() < 2 || d[0] != 5 {
        return Err(ProgError::Corrupt(
            "relocation values are not a long array".into(),
        ));
    }
    if (d[1] as i8) < 0 {
        return Ok(None);
    }
    Ok(Some(
        d[2..]
            .as_chunks::<8>()
            .0
            .iter()
            .map(|c| i64::from_be_bytes(*c))
            .collect(),
    ))
}

impl Relocation {
    /// `Relocation.getBytes`: the stored bytes, or for a status that has bytes the original file
    /// bytes at the address (`length` bytes, or the pointer size, 8 here when `pointer_size` is
    /// above 4, when the length was not recorded).
    ///
    /// # Errors
    ///
    /// A damaged "File Bytes" table.
    pub fn bytes<S: BufferStore>(
        &self,
        memory: &Memory<'_, S>,
        pointer_size: i32,
    ) -> Result<Option<Vec<u8>>> {
        if self.stored_bytes.is_some() || !self.status.has_bytes() {
            return Ok(self.stored_bytes.clone());
        }
        let count = if self.length > 0 {
            self.length
        } else if pointer_size > 4 {
            8
        } else {
            4
        };
        Ok(Some(memory.original_bytes(&self.address, count as usize)?))
    }
}
