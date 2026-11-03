//! The function rows of a whole program as plain data: what the cache keeps so that `function` and `functions` need no
//! file at all on a hit.
//!
//! Built once per program version from the stored tables (`FunctionData::build`), it holds for every internal
//! function the entry, the name and either the finished row or the reason the row is declined, plus the body ranges
//! for `getFunctionContaining`. It has no handle and no reference to the database.

use crate::error::{Error, Result};
use crate::program::StaticProgram;
use crate::rows::{self, RowData};

/// One internal function.
pub struct FnRow {
    /// Entry point offset.
    pub entry: u64,
    /// The name Ghidra shows; `None` when it cannot be computed.
    pub name: Option<String>,
    /// The row, or why the plane declines it.
    pub row: Result<RowData>,
}

/// Every internal function of a program, in entry order.
pub struct FunctionData {
    rows: Vec<FnRow>,
    /// `(min, max, row index)` of every body range, by `min`.
    ranges: Vec<(u64, u64, u32)>,
    bytes: usize,
}

impl FunctionData {
    /// Read the function tables of `program` and finish every row.
    ///
    /// # Errors
    ///
    /// Whatever reading the tables fails with. A function whose row the plane cannot print exactly is *not* an error
    /// here: its [`FnRow::row`] is the refusal, raised only when a question needs that row.
    pub fn build(program: &StaticProgram) -> Result<Self> {
        let prog = program.facade();
        let space = program.default_space();
        let mut internal: Vec<&ghidra_progdb::query::FunctionInfo> =
            prog.functions().iter().filter(|f| rows::is_internal(f, space)).collect();
        internal.sort_by_key(|f| match &f.entry {
            ghidra_progdb::Address::Space { offset, .. } => *offset,
            _ => u64::MAX,
        });
        let mut out = Vec::with_capacity(internal.len());
        let mut ranges = Vec::new();
        let mut bytes = std::mem::size_of::<Self>();
        for f in internal {
            let ghidra_progdb::Address::Space { offset, .. } = &f.entry else {
                return Err(Error::failed("internal function without an address"));
            };
            let row = rows::build_row(prog, f, space);
            bytes += std::mem::size_of::<FnRow>() + f.name.as_ref().map_or(0, String::len) + row.as_ref().map_or(64, RowData::size);
            let index = u32::try_from(out.len()).map_err(|_| Error::unsupported("more functions than the index holds"))?;
            for r in &f.body {
                if r.space == space {
                    ranges.push((r.min, r.max, index));
                }
            }
            out.push(FnRow { entry: *offset, name: f.name.clone(), row });
        }
        ranges.sort_unstable();
        bytes += ranges.len() * std::mem::size_of::<(u64, u64, u32)>();
        Ok(Self { rows: out, ranges, bytes })
    }

    /// The functions, in entry order.
    pub fn rows(&self) -> &[FnRow] {
        &self.rows
    }

    /// The function whose body holds `address` (`getFunctionContaining`): the nearest start at or below it, looking
    /// back over a few candidates because nested ranges are possible in odd databases.
    pub fn containing(&self, address: u64) -> Option<&FnRow> {
        let at = self.ranges.partition_point(|&(min, _, _)| min <= address);
        self.ranges[..at]
            .iter()
            .rev()
            .take(8)
            .find(|&&(min, max, _)| min <= address && address <= max)
            .map(|&(_, _, i)| &self.rows[i as usize])
    }

    /// An estimate of the bytes held.
    pub fn size(&self) -> usize {
        self.bytes
    }
}
