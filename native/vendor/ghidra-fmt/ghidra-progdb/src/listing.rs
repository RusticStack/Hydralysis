//! Port of the read side of the code unit tables: "Instructions" (`InstDBAdapterV1`), "Data"
//! (`DataDBAdapterV0`) and "Comments" (`CommentsDBAdapterV1`).
//!
//! Instruction rows hold the prototype id and flags only; decoding mnemonics and operands needs
//! the language, which is not ported, so instruction rows stay raw.

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::{Address, AddressMap, Cols, ProgError, Result};

/// A row of "Instructions".
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstructionRow {
    /// Instruction address.
    pub address: Address,
    /// Id of the instruction prototype in the program's prototype table.
    pub proto_id: i32,
    /// Raw flags byte.
    pub flags: u8,
}

/// A row of "Data": a defined data code unit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataRow {
    /// Data address.
    pub address: Address,
    /// Data type id.
    pub datatype_id: i64,
}

/// The comments at one address.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Comments {
    /// End of line comment.
    pub eol: Option<String>,
    /// Pre comment.
    pub pre: Option<String>,
    /// Post comment.
    pub post: Option<String>,
    /// Plate comment.
    pub plate: Option<String>,
    /// Repeatable comment.
    pub repeatable: Option<String>,
}

pub(crate) fn read_instructions<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<InstructionRow>> {
    let Ok(table) = db.table("Instructions") else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        out.push(InstructionRow {
            address: map.decode(key_of(&rec)?)?,
            proto_id: c.int(&rec, "Proto ID")?.unwrap_or(0),
            flags: c.byte(&rec, "Flags")?.unwrap_or(0) as u8,
        });
    }
    Ok(out)
}

pub(crate) fn read_data<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<DataRow>> {
    let Ok(table) = db.table("Data") else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        out.push(DataRow {
            address: map.decode(key_of(&rec)?)?,
            datatype_id: c.long(&rec, "Data Type ID")?.unwrap_or(0),
        });
    }
    Ok(out)
}

pub(crate) fn read_comments<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<Vec<(Address, Comments)>> {
    let Ok(table) = db.table("Comments") else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        out.push((
            map.decode(key_of(&rec)?)?,
            Comments {
                eol: c.string(&rec, "EOL")?,
                pre: c.string(&rec, "Pre")?,
                post: c.string(&rec, "Post")?,
                plate: c.string(&rec, "Plate")?,
                repeatable: c.string(&rec, "Repeatable")?,
            },
        ));
    }
    Ok(out)
}

fn key_of(rec: &ghidra_fmt_field::Record) -> Result<i64> {
    rec.key
        .long_value()
        .ok_or_else(|| ProgError::Corrupt("listing key".into()))
}
