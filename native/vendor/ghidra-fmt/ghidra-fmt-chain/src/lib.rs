//! `db.ChainedBuffer` and `db.DBParms`.
//!
//! A chained buffer stores a long byte string in database buffers:
//!
//! ```text
//! Data node (non-indexed): | 9 (1) | Obfuscation/DataLength (4) | data ...
//! Data node (indexed):     | 9 (1) | data ...
//! Index node:              | 8 (1) | Obfuscation/DataLength (4) | NextIndexId (4) | DataId1 (4) | ...
//! ```
//!
//! The most significant bit of the length field marks XOR obfuscation. Unwritten data
//! nodes have id -1 and read as zeros (or from an optional "uninitialized data source").
//! The state is kept in a [`ChainedBuffer`] value that is handed the buffer store on each
//! call, so no references are held between calls.

use std::fmt;
use std::sync::Arc;

use ghidra_fmt_bytes::{self as bytes, BytesError};
use ghidra_fmt_gbf::{BufferStore, BufferStoreMut, DataBuffer, GbfError};

mod dbparms;
pub use dbparms::DbParms;

/// Node type byte of a chained buffer index node.
pub const CHAINED_BUFFER_INDEX_NODE: u8 = 8;
/// Node type byte of a chained buffer data node.
pub const CHAINED_BUFFER_DATA_NODE: u8 = 9;

const NODE_TYPE_OFFSET: usize = 0;
const DATA_LENGTH_OFFSET: usize = 1;
const NEXT_INDEX_ID_OFFSET: usize = 5;
const INDEX_BASE_OFFSET: usize = 9;
const ID_SIZE: usize = 4;
const DATA_BASE_OFFSET_NONINDEXED: usize = 5;
const DATA_BASE_OFFSET_INDEXED: usize = 1;

#[rustfmt::skip]
const XOR_MASK_BYTES: [u8; 128] = [
    0x59, 0xea, 0x67, 0x23, 0xda, 0xb8, 0x00, 0xb8, 0xc3, 0x48, 0xdd, 0x8b, 0x21, 0xd6, 0x94, 0x78,
    0x35, 0xab, 0x2b, 0x7e, 0xb2, 0x4f, 0x82, 0x4e, 0x0e, 0x16, 0xc4, 0x57, 0x12, 0x8e, 0x7e, 0xe6,
    0xb6, 0xbd, 0x56, 0x91, 0x57, 0x72, 0xe6, 0x91, 0xdc, 0x52, 0x2e, 0xf2, 0x1a, 0xb7, 0xd6, 0x6f,
    0xda, 0xde, 0xe8, 0x48, 0xb1, 0xbb, 0x50, 0x6f, 0xf4, 0xdd, 0x11, 0xee, 0xf2, 0x67, 0xfe, 0x48,
    0x8d, 0xae, 0x69, 0x1a, 0xe0, 0x26, 0x8c, 0x24, 0x8e, 0x17, 0x76, 0x51, 0xe2, 0x60, 0xd7, 0xe6,
    0x83, 0x65, 0xd5, 0xf0, 0x7f, 0xf2, 0xa0, 0xd6, 0x4b, 0xbd, 0x24, 0xd8, 0xab, 0xea, 0x9e, 0xa6,
    0x48, 0x94, 0x3e, 0x7b, 0x2c, 0xf4, 0xce, 0xdc, 0x69, 0x11, 0xf8, 0x3c, 0xa7, 0x3f, 0x5d, 0x77,
    0x94, 0x3f, 0xe4, 0x8e, 0x48, 0x20, 0xdb, 0x56, 0x32, 0xc1, 0x87, 0x01, 0x2e, 0xe3, 0x7f, 0x40,
];

/// Errors raised by chained buffer and `DBParms` operations.
#[derive(Debug)]
pub enum ChainError {
    /// Block file layer failure.
    Gbf(GbfError),
    /// Offset arithmetic inside a database buffer failed.
    Bytes(BytesError),
    /// Not a chained buffer (`"Invalid Buffer"`), or the buffer was deleted.
    InvalidBuffer,
    /// Offset or length outside the buffer (`IndexOutOfBoundsException`).
    OutOfBounds,
    /// Mutation of a read-only buffer (`UnsupportedOperationException`).
    ReadOnly,
    /// Operation not allowed in this configuration (`UnsupportedOperationException`).
    Unsupported(&'static str),
    /// Bad argument (`IllegalArgumentException`).
    IllegalArgument(&'static str),
    /// The stored index chain is shorter than the data length requires.
    CorruptIndex,
    /// `DBParms` buffer has the wrong node type or version, or is truncated.
    BadParms(&'static str),
    /// `DBParms` parameter number outside the allocated range.
    ParmOutOfRange(i32),
}

impl fmt::Display for ChainError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gbf(e) => write!(f, "{e}"),
            Self::Bytes(e) => write!(f, "{e}"),
            Self::InvalidBuffer => write!(f, "Invalid Buffer"),
            Self::OutOfBounds => write!(f, "index out of bounds"),
            Self::ReadOnly => write!(f, "Read-only buffer"),
            Self::Unsupported(w) => write!(f, "unsupported operation: {w}"),
            Self::IllegalArgument(w) => write!(f, "illegal argument: {w}"),
            Self::CorruptIndex => write!(f, "corrupt chained buffer index"),
            Self::BadParms(w) => write!(f, "bad DBParms: {w}"),
            Self::ParmOutOfRange(p) => write!(f, "Invalid parameter index: {p}"),
        }
    }
}

impl std::error::Error for ChainError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Gbf(e) => Some(e),
            Self::Bytes(e) => Some(e),
            _ => None,
        }
    }
}

impl From<GbfError> for ChainError {
    fn from(e: GbfError) -> Self {
        Self::Gbf(e)
    }
}

impl From<BytesError> for ChainError {
    fn from(e: BytesError) -> Self {
        Self::Bytes(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, ChainError>;

/// Read-only source of initial values for never-written parts of a chained buffer.
pub trait ByteSource {
    /// Number of addressable bytes (Java `Buffer.length()`).
    fn len(&self) -> i64;
    /// True when [`ByteSource::len`] is zero.
    fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// Fill `out` with the bytes starting at `offset`.
    fn read(&self, offset: i64, out: &mut [u8]) -> Result<()>;
}

#[derive(Clone)]
struct Source {
    src: Arc<dyn ByteSource>,
    offset: i32,
}

impl fmt::Debug for Source {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Source(offset={})", self.offset)
    }
}

fn xor_mask_byte(buffer_offset: usize, v: u8) -> u8 {
    v ^ XOR_MASK_BYTES[buffer_offset % XOR_MASK_BYTES.len()]
}

fn xor_slice(first_offset: usize, data: &mut [u8]) {
    for (i, b) in data.iter_mut().enumerate() {
        *b = xor_mask_byte(first_offset + i, *b);
    }
}

fn load<S: BufferStore + ?Sized>(store: &S, id: i32) -> Result<Vec<u8>> {
    let buf = store.get_buffer(id)?;
    if buf.empty {
        return Err(ChainError::InvalidBuffer);
    }
    buf.data.ok_or(ChainError::InvalidBuffer)
}

fn save<S: BufferStoreMut + ?Sized>(store: &mut S, id: i32, data: Vec<u8>) -> Result<()> {
    store.put_buffer(&DataBuffer::new(id, data))?;
    Ok(())
}

/// State of one chained buffer.
#[derive(Debug, Clone)]
pub struct ChainedBuffer {
    size: i32,
    first_id: i32,
    use_xor: bool,
    read_only: bool,
    source: Option<Source>,
    index_ids: Option<Vec<i32>>,
    data_ids: Option<Vec<i32>>,
    indexes_per_buffer: usize,
    data_base_offset: usize,
    data_space: usize,
}

impl ChainedBuffer {
    fn blank(size: i32, first_id: i32, use_xor: bool) -> Self {
        Self {
            size,
            first_id,
            use_xor,
            read_only: false,
            source: None,
            index_ids: None,
            data_ids: None,
            indexes_per_buffer: 0,
            data_base_offset: 0,
            data_space: 0,
        }
    }

    // ---------------------------------------------------------------- opening

    /// Open an existing chained buffer (`new ChainedBuffer(bufferMgr, id)`).
    pub fn open<S: BufferStore + ?Sized>(store: &S, buffer_id: i32) -> Result<Self> {
        Self::open_with_source(store, buffer_id, None)
    }

    /// Open an existing chained buffer that was created with an uninitialized data source.
    pub fn open_with_source<S: BufferStore + ?Sized>(
        store: &S,
        buffer_id: i32,
        source: Option<(Arc<dyn ByteSource>, i32)>,
    ) -> Result<Self> {
        let first = load(store, buffer_id)?;
        let mut size = bytes::get_i32(&first, DATA_LENGTH_OFFSET)?;
        let mut use_xor = false;
        if size < 0 {
            use_xor = true;
            size &= i32::MAX;
        }
        let mut cb = Self::blank(size, buffer_id, use_xor);
        match bytes::get_u8(&first, NODE_TYPE_OFFSET)? {
            CHAINED_BUFFER_INDEX_NODE => cb.build_index(store, first)?,
            CHAINED_BUFFER_DATA_NODE => {
                cb.data_base_offset = DATA_BASE_OFFSET_NONINDEXED;
                cb.data_space = first.len() - DATA_BASE_OFFSET_NONINDEXED;
                cb.data_ids = Some(vec![buffer_id]);
            }
            _ => return Err(ChainError::InvalidBuffer),
        }
        if let Some((src, off)) = source {
            cb.set_source(src, off)?;
        }
        Ok(cb)
    }

    fn set_source(&mut self, src: Arc<dyn ByteSource>, offset: i32) -> Result<()> {
        if offset < 0 {
            return Err(ChainError::IllegalArgument("Invalid data source offset"));
        }
        // Java computes `offset - 1 + size` in int arithmetic; use i64 and reject the same cases.
        let max_offset = i64::from(offset) - 1 + i64::from(self.size);
        if max_offset < 0 || max_offset >= src.len() {
            return Err(ChainError::IllegalArgument(
                "Data source has insufficient bytes",
            ));
        }
        self.source = Some(Source { src, offset });
        Ok(())
    }

    fn allocate_index(&mut self, buffer_len: usize) -> usize {
        self.data_base_offset = DATA_BASE_OFFSET_INDEXED;
        self.data_space = buffer_len - self.data_base_offset;
        // Java int division truncates toward zero; so does Rust's.
        let index_count = ((i64::from(self.size) - 1) / self.data_space as i64 + 1) as usize;
        self.indexes_per_buffer = (buffer_len - INDEX_BASE_OFFSET) / ID_SIZE;
        index_count
    }

    fn build_index<S: BufferStore + ?Sized>(&mut self, store: &S, first: Vec<u8>) -> Result<()> {
        let index_count = self.allocate_index(first.len());
        let index_buffer_count = (index_count - 1) / self.indexes_per_buffer + 1;
        let mut data_ids = Vec::with_capacity(index_count);
        let mut index_ids = Vec::with_capacity(index_buffer_count);
        index_ids.push(self.first_id);
        let mut cur = first;
        let mut ix = 0usize;
        let mut offset = INDEX_BASE_OFFSET;
        for _ in 0..index_count {
            if ix == self.indexes_per_buffer {
                let next = bytes::get_i32(&cur, NEXT_INDEX_ID_OFFSET)?;
                if next < 0 {
                    return Err(ChainError::CorruptIndex);
                }
                cur = load(store, next)?;
                index_ids.push(next);
                ix = 0;
                offset = INDEX_BASE_OFFSET;
            }
            data_ids.push(bytes::get_i32(&cur, offset)?);
            offset += ID_SIZE;
            ix += 1;
        }
        self.data_ids = Some(data_ids);
        self.index_ids = Some(index_ids);
        Ok(())
    }

    // ------------------------------------------------------------- properties

    /// Buffer id of the first buffer; -1 after [`ChainedBuffer::delete`].
    pub fn id(&self) -> i32 {
        self.first_id
    }

    /// Logical length in bytes.
    pub fn len(&self) -> i32 {
        self.size
    }

    /// True when the logical length is zero.
    pub fn is_empty(&self) -> bool {
        self.size == 0
    }

    /// True when stored data is XOR obfuscated.
    pub fn has_obfuscated_storage(&self) -> bool {
        self.use_xor
    }

    /// Make every later mutation fail with [`ChainError::ReadOnly`].
    pub fn set_read_only(&mut self) {
        self.read_only = true;
    }

    /// Maximum number of database buffers this chained buffer can occupy.
    pub fn buffer_count(&self) -> usize {
        self.data_ids.as_ref().map_or(0, Vec::len) + self.index_ids.as_ref().map_or(0, Vec::len)
    }

    fn length_field(&self) -> i32 {
        self.size | if self.use_xor { i32::MIN } else { 0 }
    }

    // ------------------------------------------------------------------ reads

    fn check_range(&self, offset: i64, len: usize) -> Result<()> {
        if self.data_ids.is_none() {
            return Err(ChainError::InvalidBuffer);
        }
        if offset < 0 || offset + len as i64 > i64::from(self.size) {
            return Err(ChainError::OutOfBounds);
        }
        Ok(())
    }

    /// Read `out.len()` bytes starting at `offset`.
    pub fn get_into<S: BufferStore + ?Sized>(
        &self,
        store: &S,
        offset: i32,
        out: &mut [u8],
    ) -> Result<()> {
        self.check_range(i64::from(offset), out.len())?;
        let ids = self.data_ids.as_deref().ok_or(ChainError::InvalidBuffer)?;
        let mut offset = offset as usize;
        let mut index = offset / self.data_space;
        let mut bdo = offset % self.data_space;
        let mut done = 0;
        while done < out.len() {
            let n = (self.data_space - bdo).min(out.len() - done);
            let dest = &mut out[done..done + n];
            let id = *ids.get(index).ok_or(ChainError::OutOfBounds)?;
            if id < 0 {
                match &self.source {
                    Some(s) => s.src.read(i64::from(s.offset) + offset as i64, dest)?,
                    None => dest.fill(0),
                }
            } else {
                let buf = load(store, id)?;
                dest.copy_from_slice(bytes::slice(&buf, self.data_base_offset + bdo, n)?);
                if self.use_xor {
                    xor_slice(bdo, dest);
                }
            }
            done += n;
            offset += n;
            index += 1;
            bdo = 0;
        }
        Ok(())
    }

    /// Read `len` bytes starting at `offset`.
    pub fn get<S: BufferStore + ?Sized>(
        &self,
        store: &S,
        offset: i32,
        len: usize,
    ) -> Result<Vec<u8>> {
        let mut out = vec![0u8; len];
        self.get_into(store, offset, &mut out)?;
        Ok(out)
    }

    /// Read one byte.
    pub fn get_u8<S: BufferStore + ?Sized>(&self, store: &S, offset: i32) -> Result<u8> {
        Ok(self.get(store, offset, 1)?[0])
    }

    /// Read a big-endian `i16`.
    pub fn get_i16<S: BufferStore + ?Sized>(&self, store: &S, offset: i32) -> Result<i16> {
        Ok(bytes::get_i16(&self.get(store, offset, 2)?, 0)?)
    }

    /// Read a big-endian `i32`.
    pub fn get_i32<S: BufferStore + ?Sized>(&self, store: &S, offset: i32) -> Result<i32> {
        Ok(bytes::get_i32(&self.get(store, offset, 4)?, 0)?)
    }

    /// Read a big-endian `i64`.
    pub fn get_i64<S: BufferStore + ?Sized>(&self, store: &S, offset: i32) -> Result<i64> {
        Ok(bytes::get_i64(&self.get(store, offset, 8)?, 0)?)
    }

    // ------------------------------------------------------------ construction

    /// Create a chained buffer of `size` bytes (`new ChainedBuffer(size, obfuscate, mgr)`).
    pub fn create<S: BufferStoreMut + ?Sized>(
        store: &mut S,
        size: i32,
        obfuscate: bool,
    ) -> Result<Self> {
        Self::create_with_source(store, size, obfuscate, None)
    }

    /// Create a chained buffer whose unwritten parts read from `source`.
    pub fn create_with_source<S: BufferStoreMut + ?Sized>(
        store: &mut S,
        size: i32,
        obfuscate: bool,
        source: Option<(Arc<dyn ByteSource>, i32)>,
    ) -> Result<Self> {
        if size == 0 {
            return Err(ChainError::IllegalArgument(
                "Zero length buffer not permitted",
            ));
        }
        if size < 0 {
            return Err(ChainError::IllegalArgument("Maximum buffer size exceeded"));
        }
        let mut cb = Self::blank(size, -1, obfuscate);
        if let Some((src, off)) = source {
            cb.set_source(src, off)?;
        }
        let first_id = store.create_buffer()?;
        cb.first_id = first_id;
        let mut first = load(store, first_id)?;
        cb.data_base_offset = DATA_BASE_OFFSET_NONINDEXED;
        cb.data_space = store.buffer_size() - cb.data_base_offset;
        if size as usize <= cb.data_space {
            cb.data_ids = Some(vec![first_id]);
            cb.initialize_allocated_buffer(0, &mut first)?;
            first[NODE_TYPE_OFFSET] = CHAINED_BUFFER_DATA_NODE;
            bytes::put_i32(&mut first, DATA_LENGTH_OFFSET, cb.length_field())?;
            save(store, first_id, first)?;
        } else {
            cb.create_index(store, first)?;
        }
        Ok(cb)
    }

    fn create_index<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        mut first: Vec<u8>,
    ) -> Result<()> {
        first[NODE_TYPE_OFFSET] = CHAINED_BUFFER_INDEX_NODE;
        bytes::put_i32(&mut first, DATA_LENGTH_OFFSET, self.length_field())?;
        bytes::put_i32(&mut first, NEXT_INDEX_ID_OFFSET, -1)?;

        let index_count = self.allocate_index(first.len());
        self.data_ids = Some(vec![-1; index_count]);
        let index_buffer_count = (index_count - 1) / self.indexes_per_buffer + 1;
        let empty_index_data = vec![0xffu8; self.indexes_per_buffer * ID_SIZE];

        let mut index_ids = vec![self.first_id];
        bytes::put_bytes(&mut first, INDEX_BASE_OFFSET, &empty_index_data)?;
        save(store, self.first_id, first)?;
        let mut prev = self.first_id;
        for _ in 1..index_buffer_count {
            prev = Self::append_index_buffer(store, prev, &empty_index_data)?;
            index_ids.push(prev);
        }
        self.index_ids = Some(index_ids);
        Ok(())
    }

    /// Allocate an index node, link it after `prev` and initialize its index to all -1.
    fn append_index_buffer<S: BufferStoreMut + ?Sized>(
        store: &mut S,
        prev: i32,
        empty_index_data: &[u8],
    ) -> Result<i32> {
        let next_id = store.create_buffer()?;
        let mut next = load(store, next_id)?;
        next[NODE_TYPE_OFFSET] = CHAINED_BUFFER_INDEX_NODE;
        bytes::put_i32(&mut next, DATA_LENGTH_OFFSET, -1)?; // only used in the first buffer
        bytes::put_i32(&mut next, NEXT_INDEX_ID_OFFSET, -1)?;
        bytes::put_bytes(&mut next, INDEX_BASE_OFFSET, empty_index_data)?;
        save(store, next_id, next)?;
        let mut prev_buf = load(store, prev)?;
        bytes::put_i32(&mut prev_buf, NEXT_INDEX_ID_OFFSET, next_id)?;
        save(store, prev, prev_buf)?;
        Ok(next_id)
    }

    fn initialize_allocated_buffer(&self, chain_index: usize, buf: &mut [u8]) -> Result<()> {
        let offset = chain_index as i64 * self.data_space as i64;
        let mut len = i64::from(self.size) - offset;
        if len >= self.data_space as i64 {
            len = self.data_space as i64;
        } else {
            buf.fill(0); // partial fill - clear entire buffer first
        }
        let len = len as usize;
        let mut data = vec![0u8; len];
        if let Some(s) = &self.source {
            s.src.read(i64::from(s.offset) + offset, &mut data)?;
        }
        if self.use_xor {
            xor_slice(0, &mut data);
        }
        bytes::put_bytes(buf, self.data_base_offset, &data)?;
        Ok(())
    }

    // ----------------------------------------------------------------- writes

    fn check_writable(&self) -> Result<()> {
        if self.read_only {
            return Err(ChainError::ReadOnly);
        }
        if self.data_ids.is_none() {
            return Err(ChainError::InvalidBuffer);
        }
        Ok(())
    }

    /// Id of data node `index`, allocating and linking it if it does not exist yet.
    fn data_node_for_write<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        index: usize,
    ) -> Result<i32> {
        let id = *self
            .data_ids
            .as_ref()
            .and_then(|d| d.get(index))
            .ok_or(ChainError::OutOfBounds)?;
        if id >= 0 {
            return Ok(id);
        }
        let new_id = store.create_buffer()?;
        let mut buf = load(store, new_id)?;
        self.initialize_allocated_buffer(index, &mut buf)?;
        buf[NODE_TYPE_OFFSET] = CHAINED_BUFFER_DATA_NODE;
        save(store, new_id, buf)?;
        self.set_data_id(store, index, new_id)?;
        Ok(new_id)
    }

    fn set_data_id<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        index: usize,
        id: i32,
    ) -> Result<()> {
        self.data_ids.as_mut().ok_or(ChainError::InvalidBuffer)?[index] = id;
        let index_ids = self.index_ids.as_ref().ok_or(ChainError::InvalidBuffer)?;
        let index_buffer_id = index_ids[index / self.indexes_per_buffer];
        let index_offset = INDEX_BASE_OFFSET + (index % self.indexes_per_buffer) * ID_SIZE;
        let mut ib = load(store, index_buffer_id)?;
        bytes::put_i32(&mut ib, index_offset, id)?;
        save(store, index_buffer_id, ib)
    }

    /// Write `data` at `offset`; returns `offset + data.len()`.
    pub fn put<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        offset: i32,
        data: &[u8],
    ) -> Result<i32> {
        self.check_writable()?;
        self.check_range(i64::from(offset), data.len())?;
        let mut index = offset as usize / self.data_space;
        let mut bdo = offset as usize % self.data_space;
        let mut done = 0;
        while done < data.len() {
            let n = (self.data_space - bdo).min(data.len() - done);
            let id = self.data_node_for_write(store, index)?;
            let mut buf = load(store, id)?;
            let mut chunk = data[done..done + n].to_vec();
            if self.use_xor {
                xor_slice(bdo, &mut chunk);
            }
            bytes::put_bytes(&mut buf, self.data_base_offset + bdo, &chunk)?;
            save(store, id, buf)?;
            done += n;
            index += 1;
            bdo = 0;
        }
        Ok(offset + data.len() as i32)
    }

    /// Write one byte; returns `offset + 1`.
    pub fn put_u8<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        offset: i32,
        v: u8,
    ) -> Result<i32> {
        self.put(store, offset, &[v])
    }

    /// Write a big-endian `i16`; returns `offset + 2`.
    pub fn put_i16<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        offset: i32,
        v: i16,
    ) -> Result<i32> {
        self.put(store, offset, &v.to_be_bytes())
    }

    /// Write a big-endian `i32`; returns `offset + 4`.
    pub fn put_i32<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        offset: i32,
        v: i32,
    ) -> Result<i32> {
        self.put(store, offset, &v.to_be_bytes())
    }

    /// Write a big-endian `i64`; returns `offset + 8`.
    pub fn put_i64<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        offset: i32,
        v: i64,
    ) -> Result<i32> {
        self.put(store, offset, &v.to_be_bytes())
    }

    /// Fill `start..=end` with `fill_byte`.
    pub fn fill<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        start: i32,
        end: i32,
        fill_byte: u8,
    ) -> Result<()> {
        self.check_writable()?;
        if end < start {
            return Err(ChainError::IllegalArgument("end before start"));
        }
        if start < 0 || end >= self.size {
            return Err(ChainError::OutOfBounds);
        }
        let data = vec![fill_byte; (end - start) as usize + 1];
        self.put(store, start, &data)?;
        Ok(())
    }

    /// Free every database buffer of this chained buffer.
    pub fn delete<S: BufferStoreMut + ?Sized>(&mut self, store: &mut S) -> Result<()> {
        if self.read_only {
            return Err(ChainError::ReadOnly);
        }
        if self.first_id < 0 {
            return Err(ChainError::InvalidBuffer);
        }
        for id in self.data_ids.take().unwrap_or_default() {
            if id >= 0 {
                store.delete_buffer(id)?;
            }
        }
        for id in self.index_ids.take().unwrap_or_default() {
            store.delete_buffer(id)?;
        }
        self.size = 0;
        self.first_id = -1;
        Ok(())
    }

    // ------------------------------------------------------------ size changes

    /// Change the length (`setSize`). Existing data is kept when growing; when shrinking
    /// `preserve_data` decides whether data below the new size is moved (see PORTING.md).
    pub fn set_size<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        size: i32,
        preserve_data: bool,
    ) -> Result<()> {
        if self.read_only {
            return Err(ChainError::ReadOnly);
        }
        if self.source.is_some() {
            return Err(ChainError::Unsupported(
                "size may not be changed when using an uninitialized data source",
            ));
        }
        if self.data_ids.is_none() {
            return Err(ChainError::InvalidBuffer);
        }
        if size > self.size {
            self.grow(store, size, preserve_data)
        } else {
            self.shrink(store, size, preserve_data)
        }
    }

    fn store_length<S: BufferStoreMut + ?Sized>(&self, store: &mut S) -> Result<()> {
        let mut b = load(store, self.first_id)?;
        bytes::put_i32(&mut b, DATA_LENGTH_OFFSET, self.length_field())?;
        save(store, self.first_id, b)
    }

    fn grow<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        new_size: i32,
        preserve: bool,
    ) -> Result<()> {
        let old_size = self.size;
        self.size = new_size;
        let single = self.data_ids.as_ref().is_some_and(|d| d.len() == 1);

        if single {
            if new_size as usize > self.data_space {
                // Transition to an indexed chained buffer.
                let first = load(store, self.first_id)?;
                let mut new_first_data = None;
                if preserve {
                    let id = store.create_buffer()?;
                    let mut nb = load(store, id)?;
                    let old = old_size as usize;
                    let src = bytes::slice(&first, DATA_BASE_OFFSET_NONINDEXED, old)?.to_vec();
                    bytes::put_bytes(&mut nb, DATA_BASE_OFFSET_INDEXED, &src)?;
                    let indexed_space = nb.len() - DATA_BASE_OFFSET_INDEXED;
                    let mut zeros = vec![0u8; indexed_space - old];
                    if self.use_xor {
                        xor_slice(old, &mut zeros);
                    }
                    bytes::put_bytes(&mut nb, DATA_BASE_OFFSET_INDEXED + old, &zeros)?;
                    save(store, id, nb)?;
                    new_first_data = Some(id);
                }
                self.create_index(store, first)?;
                if let Some(id) = new_first_data {
                    let mut nb = load(store, id)?;
                    nb[NODE_TYPE_OFFSET] = CHAINED_BUFFER_DATA_NODE;
                    save(store, id, nb)?;
                    self.set_data_id(store, 0, id)?;
                }
                return Ok(());
            }
            return self.store_length(store);
        }

        // Already indexed: existing data is always preserved.
        let empty_index_data = vec![0xffu8; self.indexes_per_buffer * ID_SIZE];
        let new_index_count = ((i64::from(new_size) - 1) / self.data_space as i64 + 1) as usize;
        let new_index_buffer_count = (new_index_count - 1) / self.indexes_per_buffer + 1;

        let data_ids = self.data_ids.as_mut().ok_or(ChainError::InvalidBuffer)?;
        data_ids.resize(new_index_count, -1);

        let index_ids = self.index_ids.as_mut().ok_or(ChainError::InvalidBuffer)?;
        let old_count = index_ids.len();
        if old_count < new_index_buffer_count {
            let mut prev = index_ids[old_count - 1];
            for _ in old_count..new_index_buffer_count {
                prev = Self::append_index_buffer(store, prev, &empty_index_data)?;
                index_ids.push(prev);
            }
        }
        self.store_length(store)
    }

    fn shrink_to_single_buffer<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        preserve: bool,
    ) -> Result<bool> {
        let single_space = store.buffer_size() - DATA_BASE_OFFSET_NONINDEXED;
        if self.size as usize > single_space {
            return Ok(false);
        }
        let data_ids = self
            .data_ids
            .as_ref()
            .ok_or(ChainError::InvalidBuffer)?
            .clone();
        let index_ids = self
            .index_ids
            .as_ref()
            .ok_or(ChainError::InvalidBuffer)?
            .clone();

        let mut first = load(store, self.first_id)?;
        first[NODE_TYPE_OFFSET] = CHAINED_BUFFER_DATA_NODE;
        bytes::put_i32(&mut first, DATA_LENGTH_OFFSET, self.length_field())?;
        if preserve && data_ids[0] >= 0 {
            let old = load(store, data_ids[0])?;
            let src = bytes::slice(&old, DATA_BASE_OFFSET_INDEXED, self.size as usize)?;
            bytes::put_bytes(&mut first, DATA_BASE_OFFSET_NONINDEXED, src)?;
        }
        save(store, self.first_id, first)?;

        for id in data_ids {
            if id >= 0 {
                store.delete_buffer(id)?;
            }
        }
        for id in index_ids.iter().skip(1) {
            store.delete_buffer(*id)?;
        }

        self.data_base_offset = DATA_BASE_OFFSET_NONINDEXED;
        self.data_space = single_space;
        self.data_ids = Some(vec![self.first_id]);
        self.index_ids = None;
        Ok(true)
    }

    fn shrink<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        new_size: i32,
        preserve: bool,
    ) -> Result<()> {
        self.size = new_size;
        let single = self.data_ids.as_ref().is_some_and(|d| d.len() == 1);
        if single {
            return self.store_length(store);
        }
        if self.shrink_to_single_buffer(store, preserve)? {
            return Ok(());
        }
        let new_index_count = ((i64::from(new_size) - 1) / self.data_space as i64 + 1) as usize;
        let new_index_buffer_count = (new_index_count - 1) / self.indexes_per_buffer + 1;

        let data_ids = self.data_ids.as_mut().ok_or(ChainError::InvalidBuffer)?;
        for &id in data_ids.iter().skip(new_index_count) {
            if id >= 0 {
                store.delete_buffer(id)?;
            }
        }
        data_ids.truncate(new_index_count);

        let index_ids = self.index_ids.as_mut().ok_or(ChainError::InvalidBuffer)?;
        if index_ids.len() > new_index_buffer_count {
            for &id in index_ids.iter().skip(new_index_buffer_count) {
                store.delete_buffer(id)?;
            }
            index_ids.truncate(new_index_buffer_count);
        }
        self.store_length(store)
    }

    // ------------------------------------------------------ split and append

    /// Split at `offset`: this buffer keeps `0..offset`, the returned one gets the rest.
    pub fn split<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        offset: i32,
    ) -> Result<ChainedBuffer> {
        if self.read_only {
            return Err(ChainError::ReadOnly);
        }
        if self.first_id < 0 {
            return Err(ChainError::InvalidBuffer);
        }
        if offset < 0 || offset >= self.size {
            return Err(ChainError::OutOfBounds);
        }
        let mut cnt = (self.size - offset) as usize;
        let src = self
            .source
            .as_ref()
            .map(|s| (Arc::clone(&s.src), s.offset + offset));
        let mut new_buf = Self::create_with_source(store, cnt as i32, self.use_xor, src)?;

        let mut new_offset = 0i32;
        let mut data = vec![0u8; self.data_space];
        let mut bdo = offset as usize % self.data_space;
        let mut data_size = self.data_space - bdo;
        let first_index = offset as usize / self.data_space;
        let len = self
            .data_ids
            .as_ref()
            .ok_or(ChainError::InvalidBuffer)?
            .len();
        for index in first_index..len {
            if cnt < data_size {
                data_size = cnt;
            }
            let id = self.data_ids.as_ref().ok_or(ChainError::InvalidBuffer)?[index];
            if id >= 0 {
                let buf = load(store, id)?;
                data[..data_size].copy_from_slice(bytes::slice(
                    &buf,
                    bdo + self.data_base_offset,
                    data_size,
                )?);
                if self.use_xor {
                    xor_slice(bdo, &mut data[..data_size]);
                }
                new_buf.put(store, new_offset, &data[..data_size])?;
                // Delete the original data buffer if all of it was copied.
                if bdo == 0 {
                    store.delete_buffer(id)?;
                    self.data_ids.as_mut().ok_or(ChainError::InvalidBuffer)?[index] = -1;
                }
            }
            cnt -= data_size;
            new_offset += data_size as i32;
            bdo = 0;
            data_size = data.len();
        }
        self.shrink(store, offset, true)?;
        Ok(new_buf)
    }

    /// Append `other` to the end of this buffer; `other` becomes invalid (id -1).
    ///
    /// Java documents that both buffers must agree on obfuscation but does not check it; neither
    /// does this port (data is copied logically, so the result is still correct).
    pub fn append<S: BufferStoreMut + ?Sized>(
        &mut self,
        store: &mut S,
        other: &mut ChainedBuffer,
    ) -> Result<()> {
        if self.read_only {
            return Err(ChainError::ReadOnly);
        }
        if self.source.is_some() {
            return Err(ChainError::Unsupported(
                "size may not be changed when using an uninitialized data source",
            ));
        }
        if self.first_id < 0 {
            return Err(ChainError::InvalidBuffer);
        }
        if other.first_id < 0 || self.first_id == other.first_id {
            return Err(ChainError::IllegalArgument("Illegal DBBuffer argument"));
        }
        let mut offset = self.size;
        let new_size = self.size + other.size;
        self.grow(store, new_size, true)?;

        for id in other.index_ids.take().unwrap_or_default() {
            store.delete_buffer(id)?;
        }
        other.first_id = -1;

        let mut cnt = 0usize;
        let mut data_size = other.data_space;
        let mut data = vec![0u8; data_size];
        let other_ids = other.data_ids.take().ok_or(ChainError::InvalidBuffer)?;
        for id in other_ids {
            cnt += data_size;
            if cnt > other.size as usize {
                data_size -= cnt - other.size as usize;
            }
            if id >= 0 {
                let buf = load(store, id)?;
                data[..data_size].copy_from_slice(bytes::slice(
                    &buf,
                    other.data_base_offset,
                    data_size,
                )?);
                if other.use_xor {
                    xor_slice(0, &mut data[..data_size]);
                }
                self.put(store, offset, &data[..data_size])?;
                store.delete_buffer(id)?;
            }
            offset += data_size as i32;
        }
        other.size = 0;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
