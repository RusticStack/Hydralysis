//! `db.DBParms`: 4-byte integer parameters kept in buffer 0 of a database file.
//!
//! Layout (mimics a one-buffer chained buffer):
//! `| 9 (1) | data length (4) | version = 1 (1) | parm0 (4) | parm1 (4) | ...`
//! where data length is `1 + 4 * parameter count`.

use ghidra_fmt_bytes as bytes;
use ghidra_fmt_gbf::{BufferStore, BufferStoreMut, DataBuffer};

use crate::{CHAINED_BUFFER_DATA_NODE, ChainError, Result};

const NODE_TYPE_OFFSET: usize = 0;
const DATA_LENGTH_OFFSET: usize = 1;
const VERSION_OFFSET: usize = 5;
const PARM_BASE_OFFSET: usize = 6;
const VERSION_SIZE: i32 = 1;
const VERSION: u8 = 1;

/// Parameter number of the master table root buffer id.
pub const MASTER_TABLE_ROOT_BUFFER_ID_PARM: usize = 0;
/// Parameter number of the high half of the database id.
pub const DATABASE_ID_HIGH_PARM: usize = 1;
/// Parameter number of the low half of the database id.
pub const DATABASE_ID_LOW_PARM: usize = 2;

/// Parsed `DBParms` values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DbParms {
    values: Vec<i32>,
}

fn check_header(buf: &[u8]) -> Result<()> {
    if bytes::get_u8(buf, NODE_TYPE_OFFSET)? != CHAINED_BUFFER_DATA_NODE {
        return Err(ChainError::BadParms("unexpected node type"));
    }
    if bytes::get_u8(buf, VERSION_OFFSET)? != VERSION {
        return Err(ChainError::BadParms("unsupported format"));
    }
    Ok(())
}

fn offset_of(parm: usize) -> usize {
    PARM_BASE_OFFSET + parm * 4
}

impl DbParms {
    /// Read the parameters from buffer 0 of `store` (`DBParms.refresh`).
    pub fn read<S: BufferStore + ?Sized>(store: &S) -> Result<Self> {
        let buf = store.get_buffer(0)?;
        let data = buf.data.ok_or(ChainError::BadParms("buffer 0 is empty"))?;
        check_header(&data)?;
        let size = (bytes::get_i32(&data, DATA_LENGTH_OFFSET)? - VERSION_SIZE) / 4;
        let values = (0..size.max(0) as usize)
            .map(|i| bytes::get_i32(&data, offset_of(i)).map_err(ChainError::from))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { values })
    }

    /// Create the parameter buffer; it must be the first allocation (id 0).
    pub fn create<S: BufferStoreMut + ?Sized>(store: &mut S) -> Result<Self> {
        let id = store.create_buffer()?;
        if id != 0 {
            return Err(ChainError::BadParms(
                "DBParms must be first buffer allocation",
            ));
        }
        let mut data = vec![0u8; store.buffer_size()];
        data[NODE_TYPE_OFFSET] = CHAINED_BUFFER_DATA_NODE;
        bytes::put_i32(&mut data, DATA_LENGTH_OFFSET, VERSION_SIZE)?;
        data[VERSION_OFFSET] = VERSION;
        store.put_buffer(&DataBuffer::new(0, data))?;
        Self::read(store)
    }

    /// Number of allocated parameters.
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// True when no parameter is allocated.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Value of parameter `parm`.
    pub fn get(&self, parm: usize) -> Result<i32> {
        self.values
            .get(parm)
            .copied()
            .ok_or(ChainError::ParmOutOfRange(parm as i32))
    }

    /// Set a parameter, growing the allocated range (new gap entries read as the buffer's
    /// existing bytes, zero in a fresh buffer).
    pub fn set<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        parm: usize,
        value: i32,
    ) -> Result<()> {
        let mut data = store
            .get_buffer(0)?
            .data
            .ok_or(ChainError::BadParms("buffer 0 is empty"))?;
        let max_parms = (data.len() - PARM_BASE_OFFSET) / 4;
        if parm >= max_parms {
            return Err(ChainError::ParmOutOfRange(parm as i32));
        }
        let size =
            ((bytes::get_i32(&data, DATA_LENGTH_OFFSET)? - VERSION_SIZE) / 4).max(0) as usize;
        if parm >= size {
            let data_len = (parm + 1) * 4;
            bytes::put_i32(
                &mut data,
                DATA_LENGTH_OFFSET,
                data_len as i32 + VERSION_SIZE,
            )?;
        }
        bytes::put_i32(&mut data, offset_of(parm), value)?;
        store.put_buffer(&DataBuffer::new(0, data))?;
        if parm >= self.values.len() {
            self.values.resize(parm + 1, 0);
        }
        self.values[parm] = value;
        Ok(())
    }

    /// Root buffer id of the master table (parameter 0).
    pub fn master_table_root(&self) -> Result<i32> {
        self.get(MASTER_TABLE_ROOT_BUFFER_ID_PARM)
    }

    /// 64-bit database id built from parameters 1 and 2, as `DBHandle` does.
    pub fn database_id(&self) -> Result<i64> {
        let hi = i64::from(self.get(DATABASE_ID_HIGH_PARM)?);
        let lo = i64::from(self.get(DATABASE_ID_LOW_PARM)?) & 0xffff_ffff;
        Ok((hi << 32).wrapping_add(lo))
    }
}
