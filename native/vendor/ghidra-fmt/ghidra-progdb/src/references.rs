//! Port of the read side of the reference manager: the "FROM REFS" (`FromAdapterSharedTable`
//! layout, version 0) and "TO REFS" (`ToAdapterV1`) tables and the `RefListV0` entry encoding.

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::symbols::SourceType;
use crate::{Address, AddressMap, Cols, ProgError, Result};

const BASE_REF_SIZE: usize = 11;
const OFFSET_SIZE: usize = 8;
const SYMBOL_ID_SIZE: usize = 8;

const IS_PRIMARY: u8 = 0x02;
const IS_OFFSET: u8 = 0x04;
const HAS_SYMBOL_ID: u8 = 0x08;
const IS_SHIFT: u8 = 0x10;

/// The Java class a reference decodes to (`RefListV0.decode`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// `MemReferenceDB`.
    Memory,
    /// `OffsetReferenceDB`, with the base offset.
    Offset(i64),
    /// `ShiftedReferenceDB`, with the shift.
    Shifted(i32),
    /// `ExternalReferenceDB`.
    External,
    /// `EntryPointReferenceDB`.
    EntryPoint,
    /// `StackReferenceDB`.
    Stack,
}

impl RefKind {
    /// The Java simple class name.
    pub fn class_name(self) -> &'static str {
        match self {
            Self::Memory => "MemReferenceDB",
            Self::Offset(_) => "OffsetReferenceDB",
            Self::Shifted(_) => "ShiftedReferenceDB",
            Self::External => "ExternalReferenceDB",
            Self::EntryPoint => "EntryPointReferenceDB",
            Self::Stack => "StackReferenceDB",
        }
    }
}

/// A decoded reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reference {
    /// From address.
    pub from: Address,
    /// To address.
    pub to: Address,
    /// Raw `RefType` value.
    pub ref_type: i8,
    /// Operand index (`-1` for mnemonic and data references).
    pub op_index: i8,
    /// Source of the reference.
    pub source: SourceType,
    /// Primary flag.
    pub primary: bool,
    /// Associated symbol id, when set.
    pub symbol_id: Option<i64>,
    /// Which Java class this decodes to.
    pub kind: RefKind,
}

impl Reference {
    /// The `RefType` constant name Java prints for [`Reference::ref_type`].
    pub fn ref_type_name(&self) -> &'static str {
        ref_type_name(self.ref_type)
    }
}

/// `RefTypeFactory.get(value).getName()`, including the stack read / write remapping.
pub fn ref_type_name(value: i8) -> &'static str {
    match value {
        -2 => "INVALID",
        -1 => "FLOW",
        0 => "FALL_THROUGH",
        1 => "UNCONDITIONAL_JUMP",
        2 => "CONDITIONAL_JUMP",
        3 => "UNCONDITIONAL_CALL",
        4 => "CONDITIONAL_CALL",
        5 => "TERMINATOR",
        6 => "COMPUTED_JUMP",
        7 => "CONDITIONAL_TERMINATOR",
        8 => "COMPUTED_CALL",
        9 => "INDIRECTION",
        10 => "CALL_TERMINATOR",
        11 => "JUMP_TERMINATOR",
        12 => "CONDITIONAL_COMPUTED_JUMP",
        13 => "CONDITIONAL_COMPUTED_CALL",
        14 => "CONDITIONAL_CALL_TERMINATOR",
        15 => "COMPUTED_CALL_TERMINATOR",
        16 => "CALL_OVERRIDE_UNCONDITIONAL",
        17 => "JUMP_OVERRIDE_UNCONDITIONAL",
        18 => "CALLOTHER_OVERRIDE_CALL",
        19 => "CALLOTHER_OVERRIDE_JUMP",
        100 => "DATA",
        101 | 110 => "READ",
        102 | 111 => "WRITE",
        103 => "READ_WRITE",
        104 => "READ_IND",
        105 => "WRITE_IND",
        106 => "READ_WRITE_IND",
        107 => "PARAM",
        113 => "EXTERNAL",
        114 => "DATA_IND",
        127 => "THUNK",
        _ => "UNDEFINED",
    }
}

fn source_of_ref_flags(flags: u8) -> Result<SourceType> {
    let lo = flags & 0x01;
    let hi = (flags & 0x60) >> 4;
    match hi | lo {
        0 => Ok(SourceType::Default),
        2 => Ok(SourceType::Analysis),
        n => SourceType::from_storage_id(n),
    }
}

fn get_long(data: &[u8], at: usize) -> Result<i64> {
    data.get(at..at + 8)
        .map(|b| i64::from_be_bytes(b.try_into().expect("8 bytes")))
        .ok_or_else(|| ProgError::Corrupt("truncated reference entry".into()))
}

/// Decode the entries of a reference list. `owner` is the list's own address (the from address
/// of a "FROM REFS" row, the to address of a "TO REFS" row).
pub(crate) fn decode_list(
    map: &AddressMap,
    owner: &Address,
    is_from: bool,
    count: usize,
    data: &[u8],
) -> Result<Vec<Reference>> {
    let mut out = Vec::with_capacity(count);
    let mut pos = 0;
    for _ in 0..count {
        if data.len() < pos + BASE_REF_SIZE {
            return Err(ProgError::Corrupt("truncated reference list".into()));
        }
        let other = map.decode(get_long(data, pos)?)?;
        let flags = data[pos + 8];
        let ref_type = data[pos + 9] as i8;
        let op_index = data[pos + 10] as i8;
        pos += BASE_REF_SIZE;
        let mut symbol_id = None;
        if flags & HAS_SYMBOL_ID != 0 {
            if data.len() < pos + SYMBOL_ID_SIZE {
                return Err(ProgError::Corrupt("truncated reference list".into()));
            }
            symbol_id = Some(get_long(data, pos)?);
            pos += SYMBOL_ID_SIZE;
        }
        let (from, to) = if is_from {
            (owner.clone(), other)
        } else {
            (other, owner.clone())
        };
        let kind = if flags & (IS_OFFSET | IS_SHIFT) != 0 {
            if data.len() < pos + OFFSET_SIZE {
                return Err(ProgError::Corrupt("truncated reference list".into()));
            }
            let v = get_long(data, pos)?;
            pos += OFFSET_SIZE;
            if flags & IS_SHIFT != 0 {
                RefKind::Shifted(v as i32)
            } else {
                RefKind::Offset(v)
            }
        } else if matches!(&to, Address::Space { space, .. } if space == "EXTERNAL") {
            RefKind::External
        } else if from == Address::ExtFrom {
            RefKind::EntryPoint
        } else if matches!(&to, Address::Space { space, .. } if *space == map.spaces().stack_space)
        {
            RefKind::Stack
        } else {
            RefKind::Memory
        };
        out.push(Reference {
            from,
            to,
            ref_type,
            op_index,
            source: source_of_ref_flags(flags)?,
            primary: flags & IS_PRIMARY != 0,
            symbol_id,
            kind,
        });
    }
    if pos != data.len() {
        return Err(ProgError::Corrupt(format!(
            "reference list has {} trailing bytes",
            data.len() - pos
        )));
    }
    Ok(out)
}

/// Every reference list of one table, keyed by the decoded owner address, in key order.
pub(crate) fn read_table<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
    name: &str,
    is_from: bool,
) -> Result<Vec<(Address, Vec<Reference>)>> {
    let Ok(table) = db.table(name) else {
        return Ok(Vec::new());
    };
    let c = Cols::new(table.schema());
    let mut out = Vec::new();
    for rec in table.records()? {
        let rec = rec?;
        let key = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("reference key".into()))?;
        let owner = map.decode(key)?;
        let count = c.int(&rec, "Number of Refs")?.unwrap_or(0).max(0) as usize;
        let data = match c.field(&rec, "Ref Data")? {
            Some(ghidra_fmt_field::Field::Binary(Some(b))) => b.as_slice(),
            _ => &[],
        };
        out.push((
            owner.clone(),
            decode_list(map, &owner, is_from, count, data)?,
        ));
    }
    Ok(out)
}

/// HYDRALYSIS ADDITION (not in the engine): the reference list of one address, found by key in the
/// table instead of reading the whole table. `Ok(None)` when no list is stored for the address.
pub(crate) fn read_one<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
    name: &str,
    is_from: bool,
    owner: &Address,
) -> Result<Option<Vec<Reference>>> {
    let Ok(table) = db.table(name) else {
        return Ok(None);
    };
    let Address::Space { offset, .. } = owner else {
        return Ok(None);
    };
    let Some(key) = map.encode_default(*offset) else {
        return Ok(None);
    };
    let Some(rec) = table.get(&ghidra_fmt_field::Field::Long(key))? else {
        return Ok(None);
    };
    let c = Cols::new(table.schema());
    let count = c.int(&rec, "Number of Refs")?.unwrap_or(0).max(0) as usize;
    let data = match c.field(&rec, "Ref Data")? {
        Some(ghidra_fmt_field::Field::Binary(Some(b))) => b.as_slice(),
        _ => &[],
    };
    Ok(Some(decode_list(map, owner, is_from, count, data)?))
}
