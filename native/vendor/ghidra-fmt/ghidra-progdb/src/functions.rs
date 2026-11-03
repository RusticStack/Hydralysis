//! Port of the read side of the function manager: `FunctionAdapterV3` ("Function Data"),
//! `ThunkFunctionAdapterV0` ("Thunk Functions") and the calling convention id mapping of
//! `DataTypeManagerDB.getCallingConventionName`.
//!
//! The function body (address set) is not read here; it is stored apart from these tables.

use std::collections::BTreeMap;

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::symbols::SourceType;
use crate::{Address, Cols, ProgError, Result};

const VARARG_FLAG: u8 = 0x1;
const INLINE_FLAG: u8 = 0x2;
const NO_RETURN_FLAG: u8 = 0x4;
const CUSTOM_STORAGE_FLAG: u8 = 0x8;
const SIGNATURE_SOURCE_MASK: u8 = 0x70;
const SIGNATURE_SOURCE_SHIFT: u8 = 4;

const UNKNOWN_CALLING_CONVENTION_ID: u8 = 0;
const DEFAULT_CALLING_CONVENTION_ID: u8 = 1;

/// A row of "Function Data", joined with its symbol address and thunk link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Function {
    /// Function id: the id of its function symbol.
    pub id: i64,
    /// Entry point: the address of the function symbol, when that symbol exists.
    pub entry: Option<Address>,
    /// Data type id of the return type.
    pub return_datatype_id: i64,
    /// Stored stack purge size.
    pub stack_purge: i32,
    /// Stored stack return offset.
    pub stack_return_offset: i32,
    /// Stored stack local size.
    pub stack_local_size: i32,
    /// Raw flags byte.
    pub flags: u8,
    /// Raw calling convention id.
    pub calling_convention_id: u8,
    /// Calling convention name (`default`, `unknown` or the name stored for the id).
    pub calling_convention: String,
    /// Serialized return storage, when set.
    pub return_storage: Option<String>,
    /// Id of the function this one is a thunk of.
    pub thunk_target: Option<i64>,
}

impl Function {
    /// `Function.hasVarArgs` (stored flag).
    pub fn has_var_args(&self) -> bool {
        self.flags & VARARG_FLAG != 0
    }

    /// `Function.isInline` (stored flag).
    pub fn is_inline(&self) -> bool {
        self.flags & INLINE_FLAG != 0
    }

    /// `Function.hasNoReturn` (stored flag).
    pub fn has_no_return(&self) -> bool {
        self.flags & NO_RETURN_FLAG != 0
    }

    /// `Function.hasCustomVariableStorage` (stored flag).
    pub fn has_custom_storage(&self) -> bool {
        self.flags & CUSTOM_STORAGE_FLAG != 0
    }

    /// The signature source stored in bits 4 to 6 of the flags.
    ///
    /// # Errors
    ///
    /// [`ProgError::Corrupt`] when the stored id is not a `SourceType`.
    pub fn signature_source(&self) -> Result<SourceType> {
        SourceType::from_storage_id((self.flags & SIGNATURE_SOURCE_MASK) >> SIGNATURE_SOURCE_SHIFT)
    }

    /// True when this function is a thunk.
    pub fn is_thunk(&self) -> bool {
        self.thunk_target.is_some()
    }
}

pub(crate) fn read_functions<S: BufferStore>(
    db: &Database<S>,
    symbol_addresses: &BTreeMap<i64, Address>,
) -> Result<Vec<Function>> {
    let Ok(table) = db.table("Function Data") else {
        return Ok(Vec::new());
    };
    let mut conventions: BTreeMap<u8, String> = BTreeMap::new();
    if let Ok(t) = db.table("Calling Conventions") {
        for rec in t.records()? {
            let rec = rec?;
            if let (Some(id), Some(ghidra_fmt_field::Field::String(Some(name)))) = (
                match &rec.key {
                    ghidra_fmt_field::Field::Byte(b) => Some(*b as u8),
                    _ => None,
                },
                rec.values.first().and_then(Option::as_ref),
            ) {
                conventions.insert(id, name.as_str().to_owned());
            }
        }
    }
    let mut thunks: BTreeMap<i64, i64> = BTreeMap::new();
    if let Ok(t) = db.table("Thunk Functions") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            let key = rec
                .key
                .long_value()
                .ok_or_else(|| ProgError::Corrupt("thunk key".into()))?;
            if let Some(target) = c.long(&rec, "Linked Function ID")? {
                thunks.insert(key, target);
            }
        }
    }
    let c = Cols::new(table.schema());
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        let id = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("function key".into()))?;
        let cc = c.byte(&rec, "Calling Convention ID")?.unwrap_or(0) as u8;
        let calling_convention = match cc {
            DEFAULT_CALLING_CONVENTION_ID => "default".to_owned(),
            UNKNOWN_CALLING_CONVENTION_ID => "unknown".to_owned(),
            n => conventions
                .get(&n)
                .cloned()
                .unwrap_or_else(|| "unknown".to_owned()),
        };
        out.push(Function {
            id,
            entry: symbol_addresses.get(&id).cloned(),
            return_datatype_id: c.long(&rec, "Return DataType ID")?.unwrap_or(0),
            stack_purge: c.int(&rec, "StackPurge")?.unwrap_or(0),
            stack_return_offset: c.int(&rec, "StackReturnOffset")?.unwrap_or(0),
            stack_local_size: c.int(&rec, "StackLocalSize")?.unwrap_or(0),
            flags: c.byte(&rec, "Flags")?.unwrap_or(0) as u8,
            calling_convention_id: cc,
            calling_convention,
            return_storage: c.string(&rec, "Return Storage")?,
            thunk_target: thunks.get(&id).copied(),
        });
    }
    Ok(out)
}
