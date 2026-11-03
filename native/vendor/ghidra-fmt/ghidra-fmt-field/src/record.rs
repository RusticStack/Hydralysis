//! `db.DBRecord` / `db.SparseRecord` encoding.
//!
//! A plain record is its columns back to back. A sparse record writes the non-sparse columns,
//! then a count byte, then for each present sparse column its index byte and its value.

use ghidra_fmt_bytes as bytes;

use crate::{Field, FieldError, Result, Schema};

/// A decoded record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Primary key.
    pub key: Field,
    /// One entry per column; `None` is an absent sparse column.
    pub values: Vec<Option<Field>>,
}

impl Schema {
    /// Stored length of `record` (`DBRecord.length()`).
    pub fn record_length(&self, record: &Record) -> usize {
        let mut len = usize::from(self.has_sparse_columns());
        for (i, v) in record.values.iter().enumerate() {
            match v {
                Some(f) if self.is_sparse_column(i) => {
                    // a null string/binary in a sparse column counts as absent
                    if !f.is_null() {
                        len += f.length() + 1;
                    }
                }
                Some(f) => len += f.length(),
                None => {}
            }
        }
        len
    }

    /// Decode a record whose data starts at `offset`; returns it and the offset after it.
    pub fn read_record(&self, key: Field, buf: &[u8], offset: usize) -> Result<(Record, usize)> {
        let mut offset = offset;
        let mut values = Vec::with_capacity(self.fields().len());
        for (i, ty) in self.fields().iter().enumerate() {
            if self.is_sparse_column(i) {
                values.push(None);
            } else {
                let (f, next) = Field::read(ty, buf, offset)?;
                values.push(Some(f));
                offset = next;
            }
        }
        if self.has_sparse_columns() {
            let count = bytes::get_i8(buf, offset)?;
            offset += 1;
            for _ in 0..count.max(0) {
                let index = bytes::get_i8(buf, offset)?;
                offset += 1;
                let col = usize::try_from(index)
                    .ok()
                    .filter(|&c| c < values.len())
                    .ok_or(FieldError::IllegalArgument(
                        "sparse column index out of range",
                    ))?;
                let (f, next) = Field::read(&self.fields()[col], buf, offset)?;
                values[col] = Some(f);
                offset = next;
            }
        }
        Ok((Record { key, values }, offset))
    }

    /// Encode `record` (without its key) onto `out`.
    pub fn write_record(&self, record: &Record, out: &mut Vec<u8>) -> Result<()> {
        if record.values.len() != self.fields().len() {
            return Err(FieldError::IllegalArgument("wrong number of columns"));
        }
        let mut sparse_present = Vec::new();
        for (i, v) in record.values.iter().enumerate() {
            match v {
                Some(f) => self.check_value(i, f)?,
                None if self.is_sparse_column(i) => continue,
                None => {
                    return Err(FieldError::IllegalArgument(
                        "null value supported for sparse column only",
                    ));
                }
            }
            if self.is_sparse_column(i) {
                if v.as_ref().is_some_and(|f| !f.is_null()) {
                    sparse_present.push(i);
                }
            } else if let Some(f) = v {
                f.write(out);
            }
        }
        if self.has_sparse_columns() {
            out.push(sparse_present.len() as u8);
            for i in sparse_present {
                out.push(i as u8);
                if let Some(f) = &record.values[i] {
                    f.write(out);
                }
            }
        }
        Ok(())
    }
}
