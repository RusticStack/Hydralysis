//! Function bodies and variables: `AddressRangeMapDB` ("Range Map - SCOPE ADDRESSES", the
//! address set of every namespace), `NamespaceManager.getAddressSet` and the variable symbols
//! (`VariableSymbolDB`) with their "Variable Storage" rows.

use std::collections::BTreeMap;

use ghidra_fmt_db::Database;
use ghidra_fmt_gbf::BufferStore;

use crate::symbols::SourceType;
use crate::{Address, AddressMap, Cols, ProgError, Result, Symbol};

/// A range of addresses in one space (`AddressRange`), both ends inclusive.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressRange {
    /// Space name.
    pub space: String,
    /// First offset.
    pub min: u64,
    /// Last offset.
    pub max: u64,
}

impl std::fmt::Display for AddressRange {
    /// `space:min-space:max`, the oracle format.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{0}:{1:x}-{0}:{2:x}", self.space, self.min, self.max)
    }
}

/// Sort and merge touching or overlapping ranges, like `AddressSet` keeps them.
pub(crate) fn normalize(map: &AddressMap, mut ranges: Vec<AddressRange>) -> Vec<AddressRange> {
    let id = |space: &str| map.spaces().find(space).map_or(i32::MAX, |s| s.id);
    ranges.sort_by_key(|a| (id(&a.space), a.min));
    let mut out: Vec<AddressRange> = Vec::new();
    for r in ranges {
        match out.last_mut() {
            Some(last) if last.space == r.space && r.min <= last.max.saturating_add(1) => {
                last.max = last.max.max(r.max);
            }
            _ => out.push(r),
        }
    }
    out
}

/// The ranges painted per namespace in "Range Map - SCOPE ADDRESSES"
/// (`AddressRangeMapDB.getRangesForRecord`), unmerged and keyed by namespace id.
fn read_scope_ranges<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
) -> Result<BTreeMap<i64, Vec<AddressRange>>> {
    let mut out: BTreeMap<i64, Vec<AddressRange>> = BTreeMap::new();
    let Ok(table) = db.table("Range Map - SCOPE ADDRESSES") else {
        return Ok(out);
    };
    let c = Cols::new(table.schema());
    for rec in table.records()? {
        let rec = rec?;
        let key = rec
            .key
            .long_value()
            .ok_or_else(|| ProgError::Corrupt("range map key".into()))?;
        let to = c
            .long(&rec, "To")?
            .ok_or_else(|| ProgError::Corrupt("range map without end".into()))?;
        let value = c
            .long(&rec, "Value")?
            .ok_or_else(|| ProgError::Corrupt("range map without value".into()))?;
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
        let list = out.entry(value).or_default();
        if lo <= hi {
            list.push(AddressRange {
                space,
                min: lo,
                max: hi,
            });
        } else {
            // the key range wraps around the end of the space (non-zero image base)
            let bits = map.spaces().find(&space).map_or(64, |s| s.bits);
            let top = if bits >= 64 {
                u64::MAX
            } else {
                (1u64 << bits) - 1
            };
            list.push(AddressRange {
                space: space.clone(),
                min: 0,
                max: hi,
            });
            list.push(AddressRange {
                space,
                min: lo,
                max: top,
            });
        }
    }
    Ok(out)
}

/// The body of each function id in `function_ids`: its own ranges plus the bodies of the
/// namespaces nested under it (`NamespaceManager.getAddressSet`), merged.
pub(crate) fn function_bodies<S: BufferStore>(
    db: &Database<S>,
    map: &AddressMap,
    symbols: &[Symbol],
    function_ids: &[i64],
) -> Result<BTreeMap<i64, Vec<AddressRange>>> {
    let scope = read_scope_ranges(db, map)?;
    let mut children: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
    for s in symbols {
        // only namespaces add to a body: libraries, namespaces, classes and functions
        if matches!(s.symbol_type, 1 | 3 | 4 | 5) {
            children.entry(s.parent_id).or_default().push(s.id);
        }
    }
    let mut out = BTreeMap::new();
    for &f in function_ids {
        let mut seen = std::collections::BTreeSet::new();
        let mut ranges = Vec::new();
        let mut stack = vec![f];
        while let Some(ns) = stack.pop() {
            if !seen.insert(ns) {
                continue;
            }
            if let Some(r) = scope.get(&ns) {
                ranges.extend(r.iter().cloned());
            }
            if let Some(c) = children.get(&ns) {
                stack.extend(c.iter().copied());
            }
        }
        out.insert(f, normalize(map, ranges));
    }
    Ok(out)
}

/// A parameter or local variable symbol, joined with its "Variable Storage" row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Variable {
    /// Symbol id.
    pub symbol_id: i64,
    /// Id of the function that owns it.
    pub function_id: i64,
    /// True for a parameter, false for a local variable.
    pub is_parameter: bool,
    /// Stored name (the name Java shows for default-sourced variables is generated).
    pub name: String,
    /// Source of the name.
    pub source: SourceType,
    /// Parameter ordinal among the stored parameters (automatic parameters are not stored).
    pub ordinal: Option<i32>,
    /// Local variable first-use offset.
    pub first_use_offset: Option<i32>,
    /// Data type id.
    pub datatype_id: Option<i64>,
    /// Serialized storage (`VariableStorage.getSerializationString`) when its row exists. For
    /// parameters of functions without custom storage Java ignores this and assigns storage from
    /// the calling convention, which is not ported.
    pub storage: Option<String>,
    /// Comment.
    pub comment: Option<String>,
}

pub(crate) fn read_variables<S: BufferStore>(
    db: &Database<S>,
    symbols: &[Symbol],
) -> Result<Vec<Variable>> {
    let mut storage: BTreeMap<i64, String> = BTreeMap::new();
    if let Ok(t) = db.table("Variable Storage") {
        let c = Cols::new(t.schema());
        for rec in t.records()? {
            let rec = rec?;
            if let (Some(id), Some(s)) = (rec.key.long_value(), c.string(&rec, "Storage")?) {
                storage.insert(id, s);
            }
        }
    }
    let mut out = Vec::new();
    for s in symbols {
        if s.symbol_type != 6 && s.symbol_type != 7 {
            continue;
        }
        let is_parameter = s.symbol_type == 6;
        let stored = match &s.address {
            Address::Space { space, offset } if space == "VARIABLE" => {
                storage.get(&(*offset as i64)).cloned()
            }
            _ => None,
        };
        out.push(Variable {
            symbol_id: s.id,
            function_id: s.parent_id,
            is_parameter,
            name: s.name.clone(),
            source: s.source,
            ordinal: is_parameter.then_some(s.variable_offset.unwrap_or(0)),
            first_use_offset: (!is_parameter).then_some(s.variable_offset.unwrap_or(0)),
            datatype_id: s.datatype_id,
            storage: stored,
            comment: s.comment.clone(),
        });
    }
    Ok(out)
}
