//! Ghidra `.gbf` block files (`db.buffers.LocalBufferFile`).
//!
//! File layout (all big-endian, header version 1):
//!
//! * block 0 is the header: magic (8), file id (8), header version (4) = 1, block size (4),
//!   first free buffer index (4, -1 = none), parameter count (4), then per parameter
//!   name length (4), UTF-8 name, value (4);
//! * user buffer `k` lives in block `k + 1`; each block starts with a flag byte (bit 0 = empty)
//!   and a 4-byte field that is the buffer id when in use or the next free index when empty;
//! * the payload of a block is `block_size - 5` bytes.
//!
//! See `PORTING.md` for the behaviours kept from Java on purpose.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use ghidra_fmt_bytes::BytesError;

/// File magic number (`LocalBufferFile.MAGIC_NUMBER`).
pub const MAGIC_NUMBER: i64 = 0x2f30_312c_3429_2c2a;
/// Only header format version that exists.
pub const HEADER_FORMAT_VERSION: i32 = 1;
/// Smallest legal block size.
pub const MINIMUM_BLOCK_SIZE: i32 = 512;
/// Largest legal block size (`DataBuffer.MAX_BUFFER_SIZE`).
pub const MAXIMUM_BLOCK_SIZE: i32 = 65536;
/// Bytes before the payload in each block.
pub const BUFFER_PREFIX_SIZE: usize = 5;
/// Header bytes before the first parameter.
pub const VER1_FIXED_HEADER_LENGTH: usize = 32;
/// Maximum encoded parameter name length (`BufferFile.MAX_PARAM_NAME_LENGTH`).
pub const MAX_PARAM_NAME_LENGTH: usize = 40;
/// Largest buffer index (`LocalBufferFile.MAX_BUFFER_INDEX`).
pub const MAX_BUFFER_INDEX: i32 = i32::MAX - 1;
/// Flag bit marking an empty block.
pub const EMPTY_BUFFER: u8 = 0x01;
/// File extension of buffer files.
pub const BUFFER_FILE_EXTENSION: &str = ".gbf";

/// Errors raised by the block file layer.
#[derive(Debug)]
pub enum GbfError {
    /// Underlying I/O failure (including a file shorter than its header says).
    Io(io::Error),
    /// Magic number mismatch (`"Unrecognized file format"` in Java).
    BadMagic(i64),
    /// Header format version other than 1 (`"Unrecognized file format"` in Java).
    BadHeaderVersion(i32),
    /// Block size outside 512..=65536.
    UnsupportedBlockSize(i32),
    /// File length is not a multiple of the block size, or the free list is broken.
    CorruptFile(&'static str),
    /// A negative or oversized parameter name length in the header.
    BadParameterName(i32),
    /// Buffer index at or beyond the end of the file.
    IndexOutOfRange {
        /// Requested buffer index.
        index: i32,
        /// Number of buffers in the file.
        count: i32,
    },
    /// Buffer payload length differs from the file's buffer size.
    BadBufferSize {
        /// File buffer size.
        expected: usize,
        /// Length supplied.
        actual: usize,
    },
    /// Write attempted on a read-only file.
    ReadOnly,
    /// `create` found an existing file (`DuplicateFileException`).
    DuplicateFile(PathBuf),
    /// Parameter name longer than [`MAX_PARAM_NAME_LENGTH`] bytes.
    ParameterNameTooLong(String),
    /// Parameter not set (`NoSuchElementException`).
    NoSuchParameter(String),
    /// The parameter table does not fit in the header block (`"Buffer size too small"`).
    HeaderTooLarge,
    /// Requested buffer size gives a block size outside the legal range.
    UnsupportedBufferSize(usize),
    /// Offset arithmetic failed inside a buffer.
    Bytes(BytesError),
}

impl fmt::Display for GbfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::BadMagic(m) => write!(f, "Unrecognized file format (magic {m:#x})"),
            Self::BadHeaderVersion(v) => write!(f, "Unrecognized file format (version {v})"),
            Self::UnsupportedBlockSize(b) => write!(f, "Unsupported block size: {b}"),
            Self::CorruptFile(why) => write!(f, "Corrupt file: {why}"),
            Self::BadParameterName(n) => write!(f, "Bad parameter name length: {n}"),
            Self::IndexOutOfRange { index, count } => {
                write!(f, "Buffer index too large ({index} >= {count})")
            }
            Self::BadBufferSize { expected, actual } => {
                write!(f, "Bad buffer size (expected {expected}, got {actual})")
            }
            Self::ReadOnly => write!(f, "File is read-only"),
            Self::DuplicateFile(p) => write!(f, "File {} already exists", p.display()),
            Self::ParameterNameTooLong(n) => write!(f, "Parameter name is too long: {n}"),
            Self::NoSuchParameter(n) => write!(f, "No such parameter: {n}"),
            Self::HeaderTooLarge => write!(f, "Buffer size too small"),
            Self::UnsupportedBufferSize(s) => write!(f, "Unsupported buffer size: {s}"),
            Self::Bytes(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GbfError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            Self::Bytes(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for GbfError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<BytesError> for GbfError {
    fn from(e: BytesError) -> Self {
        Self::Bytes(e)
    }
}

/// Result alias for this crate.
pub type Result<T> = std::result::Result<T, GbfError>;

/// One user buffer (`db.buffers.DataBuffer`, storage part only).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataBuffer {
    /// Buffer id; -1 for an empty buffer read from a file.
    pub id: i32,
    /// True when the block is on the free list.
    pub empty: bool,
    /// Payload (`buffer_size` bytes); `None` for an empty buffer.
    pub data: Option<Vec<u8>>,
}

impl DataBuffer {
    /// A buffer holding `data` with the given id.
    pub fn new(id: i32, data: Vec<u8>) -> Self {
        Self {
            id,
            empty: false,
            data: Some(data),
        }
    }

    /// An empty buffer (payload absent).
    pub fn empty(id: i32) -> Self {
        Self {
            id,
            empty: true,
            data: None,
        }
    }
}

/// Anything that can hand out buffers by id; implemented by [`BufferFile`] and
/// [`MemoryBufferStore`]. In a saved file buffer ids equal buffer indexes.
pub trait BufferStore {
    /// Payload size of every buffer.
    fn buffer_size(&self) -> usize;
    /// Number of buffers (including empty ones).
    fn index_count(&self) -> i32;
    /// Fetch buffer `index`.
    fn get_buffer(&self, index: i32) -> Result<DataBuffer>;
}

/// A [`BufferStore`] that can also allocate, overwrite and free buffers (the part of
/// `db.buffers.BufferMgr` that `ChainedBuffer` needs).
pub trait BufferStoreMut: BufferStore {
    /// Allocate a buffer and return its id.
    fn create_buffer(&mut self) -> Result<i32>;
    /// Replace the buffer whose id is `buf.id`.
    fn put_buffer(&mut self, buf: &DataBuffer) -> Result<()>;
    /// Free buffer `id`.
    fn delete_buffer(&mut self, id: i32) -> Result<()>;
}

/// In-memory store used by tests and by callers that already hold the buffers.
#[derive(Debug, Clone)]
pub struct MemoryBufferStore {
    buffer_size: usize,
    buffers: Vec<DataBuffer>,
    free: Vec<i32>,
    /// Contents of freed buffers. `BufferMgr` keeps a deleted buffer in its cache and hands the
    /// same bytes out again, unchanged, when the index is reallocated.
    stale: BTreeMap<i32, Vec<u8>>,
}

impl MemoryBufferStore {
    /// Empty store with the given payload size.
    pub fn new(buffer_size: usize) -> Self {
        Self {
            buffer_size,
            buffers: Vec::new(),
            free: Vec::new(),
            stale: BTreeMap::new(),
        }
    }

    /// Number of buffers currently allocated (not on the free list).
    pub fn in_use_count(&self) -> usize {
        self.buffers.len() - self.free.len()
    }

    /// Ids of the buffers on the free list (most recently freed last).
    pub fn free_ids(&self) -> &[i32] {
        &self.free
    }

    /// Write the store as a new buffer file at `path` (what `BufferMgr.saveAs` produces: buffers
    /// in index order, empty buffers for freed indexes, the free list sorted ascending).
    pub fn save_to_file(&self, path: impl AsRef<Path>, file_id: i64) -> Result<()> {
        let mut out = BufferFile::create(path, self.buffer_size, file_id)?;
        for (i, b) in self.buffers.iter().enumerate() {
            let index = i as i32;
            if b.empty {
                out.put(&DataBuffer::empty(index), index)?;
            } else {
                out.put(
                    &DataBuffer::new(index, b.data.clone().unwrap_or_default()),
                    index,
                )?;
            }
        }
        out.set_free_indexes(&self.free);
        out.flush()?;
        out.close()
    }

    /// Mutable payload of buffer `id`.
    pub fn data_mut(&mut self, id: i32) -> Result<&mut [u8]> {
        let count = self.buffers.len() as i32;
        let bs = self.buffer_size;
        usize::try_from(id)
            .ok()
            .and_then(|i| self.buffers.get_mut(i))
            .and_then(|b| b.data.as_deref_mut())
            .ok_or(GbfError::IndexOutOfRange { index: id, count })
            .map(|d| &mut d[..bs])
    }
}

impl BufferStoreMut for MemoryBufferStore {
    fn create_buffer(&mut self) -> Result<i32> {
        let fresh = DataBuffer::new(0, vec![0; self.buffer_size]);
        if let Some(id) = self.free.pop() {
            let data = self
                .stale
                .remove(&id)
                .unwrap_or_else(|| vec![0; self.buffer_size]);
            self.buffers[id as usize] = DataBuffer::new(id, data);
            return Ok(id);
        }
        let id = self.buffers.len() as i32;
        self.buffers.push(DataBuffer { id, ..fresh });
        Ok(id)
    }

    fn put_buffer(&mut self, buf: &DataBuffer) -> Result<()> {
        let count = self.index_count();
        let slot = usize::try_from(buf.id)
            .ok()
            .and_then(|i| self.buffers.get_mut(i))
            .ok_or(GbfError::IndexOutOfRange {
                index: buf.id,
                count,
            })?;
        if let Some(d) = &buf.data
            && d.len() != self.buffer_size
        {
            return Err(GbfError::BadBufferSize {
                expected: self.buffer_size,
                actual: d.len(),
            });
        }
        *slot = buf.clone();
        Ok(())
    }

    fn delete_buffer(&mut self, id: i32) -> Result<()> {
        let count = self.index_count();
        let slot = usize::try_from(id)
            .ok()
            .and_then(|i| self.buffers.get_mut(i))
            .ok_or(GbfError::IndexOutOfRange { index: id, count })?;
        if !slot.empty {
            if let Some(old) = slot.data.take() {
                self.stale.insert(id, old);
            }
            *slot = DataBuffer::empty(id);
            self.free.push(id);
        }
        Ok(())
    }
}

impl BufferStore for MemoryBufferStore {
    fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    fn index_count(&self) -> i32 {
        self.buffers.len() as i32
    }

    fn get_buffer(&self, index: i32) -> Result<DataBuffer> {
        usize::try_from(index)
            .ok()
            .and_then(|i| self.buffers.get(i))
            .cloned()
            .ok_or(GbfError::IndexOutOfRange {
                index,
                count: self.index_count(),
            })
    }
}

fn read_i32<R: Read>(r: &mut R) -> io::Result<i32> {
    let mut b = [0u8; 4];
    r.read_exact(&mut b)?;
    Ok(i32::from_be_bytes(b))
}

fn read_i64<R: Read>(r: &mut R) -> io::Result<i64> {
    let mut b = [0u8; 8];
    r.read_exact(&mut b)?;
    Ok(i64::from_be_bytes(b))
}

/// A Ghidra buffer file, open for reading or reading and writing.
///
/// Like Java, nothing is committed (header, free list, length padding) until
/// [`BufferFile::close`] is called.
#[derive(Debug)]
pub struct BufferFile {
    file: Mutex<File>,
    path: PathBuf,
    read_only: bool,
    temporary: bool,
    file_id: i64,
    block_size: usize,
    buffer_size: usize,
    buffer_count: i32,
    /// Parameters in header order when read; sorted by name when written.
    params: BTreeMap<String, i32>,
    param_order: Vec<String>,
    free_indexes: Vec<i32>,
}

impl BufferFile {
    /// Open an existing buffer file (`new LocalBufferFile(file, readOnly)`).
    pub fn open(path: impl AsRef<Path>, read_only: bool) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .open(&path)?;
        let mut bf = Self {
            file: Mutex::new(file),
            path,
            read_only,
            temporary: false,
            file_id: 0,
            block_size: 0,
            buffer_size: 0,
            buffer_count: 0,
            params: BTreeMap::new(),
            param_order: Vec::new(),
            free_indexes: Vec::new(),
        };
        bf.read_header()?;
        Ok(bf)
    }

    /// Create a new, empty buffer file (`new LocalBufferFile(file, bufferSize)`).
    ///
    /// `file_id` is stored in the header; Java picks a random one, callers that want
    /// reproducible bytes pass a fixed value.
    pub fn create(path: impl AsRef<Path>, buffer_size: usize, file_id: i64) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if path.exists() {
            return Err(GbfError::DuplicateFile(path));
        }
        let block_size = Self::checked_block_size(buffer_size)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        Ok(Self::new_writable(
            file,
            path,
            false,
            file_id,
            block_size,
            buffer_size,
        ))
    }

    /// Create a temporary buffer file that is deleted on close/drop and never flushed
    /// (`new LocalBufferFile(bufferSize, prefix, ext)`).
    pub fn create_temp(
        dir: impl AsRef<Path>,
        prefix: &str,
        ext: &str,
        buffer_size: usize,
    ) -> Result<Self> {
        let block_size = Self::checked_block_size(buffer_size)?;
        let mut n = std::process::id() as u64 ^ 0x9e37_79b9;
        loop {
            let path = dir.as_ref().join(format!("{prefix}{n:x}{ext}"));
            match OpenOptions::new()
                .read(true)
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => {
                    return Ok(Self::new_writable(
                        file,
                        path,
                        true,
                        0,
                        block_size,
                        buffer_size,
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => n = n.wrapping_add(1),
                Err(e) => return Err(e.into()),
            }
        }
    }

    fn checked_block_size(buffer_size: usize) -> Result<usize> {
        let block = buffer_size + BUFFER_PREFIX_SIZE;
        if block < MINIMUM_BLOCK_SIZE as usize || block > MAXIMUM_BLOCK_SIZE as usize {
            return Err(GbfError::UnsupportedBufferSize(buffer_size));
        }
        Ok(block)
    }

    fn new_writable(
        file: File,
        path: PathBuf,
        temporary: bool,
        file_id: i64,
        block_size: usize,
        buffer_size: usize,
    ) -> Self {
        Self {
            file: Mutex::new(file),
            path,
            read_only: false,
            temporary,
            file_id,
            block_size,
            buffer_size,
            buffer_count: 0,
            params: BTreeMap::new(),
            param_order: Vec::new(),
            free_indexes: Vec::new(),
        }
    }

    fn file(&self) -> std::sync::MutexGuard<'_, File> {
        // A poisoned lock only means another thread panicked mid-read; the File is still valid.
        self.file.lock().unwrap_or_else(|p| p.into_inner())
    }

    fn read_header(&mut self) -> Result<()> {
        let mut file = self.file.lock().unwrap_or_else(|p| p.into_inner());
        file.seek(SeekFrom::Start(0))?;
        let magic = read_i64(&mut *file)?;
        if magic != MAGIC_NUMBER {
            return Err(GbfError::BadMagic(magic));
        }
        let file_id = read_i64(&mut *file)?;
        let version = read_i32(&mut *file)?;
        if version != HEADER_FORMAT_VERSION {
            return Err(GbfError::BadHeaderVersion(version));
        }
        let block_size = read_i32(&mut *file)?;
        if !(MINIMUM_BLOCK_SIZE..=MAXIMUM_BLOCK_SIZE).contains(&block_size) {
            return Err(GbfError::UnsupportedBlockSize(block_size));
        }
        let block_size = block_size as usize;
        let first_free = read_i32(&mut *file)?;
        let len = file.metadata()?.len();
        if len % block_size as u64 != 0 {
            return Err(GbfError::CorruptFile(
                "length is not a multiple of block size",
            ));
        }
        let buffer_count = (len / block_size as u64) as i64 - 1;
        let cnt = read_i32(&mut *file)?;
        let mut params = BTreeMap::new();
        let mut order = Vec::new();
        for _ in 0..cnt {
            let name_len = read_i32(&mut *file)?;
            if name_len < 0 || name_len as u64 > len {
                return Err(GbfError::BadParameterName(name_len));
            }
            let mut name = vec![0u8; name_len as usize];
            file.read_exact(&mut name)?;
            let name = String::from_utf8_lossy(&name).into_owned();
            let value = read_i32(&mut *file)?;
            if params.insert(name.clone(), value).is_none() {
                order.push(name);
            }
        }
        drop(file);

        self.file_id = file_id;
        self.block_size = block_size;
        self.buffer_size = block_size - BUFFER_PREFIX_SIZE;
        // Java stores bufferCount in an int; a >2G-block file is far outside any real use.
        self.buffer_count =
            i32::try_from(buffer_count).map_err(|_| GbfError::CorruptFile("too many blocks"))?;
        self.params = params;
        self.param_order = order;
        self.build_free_index_list(first_free)
    }

    fn build_free_index_list(&mut self, first_free: i32) -> Result<()> {
        let mut list = Vec::new();
        let mut next = first_free;
        while next >= 0 {
            list.push(next);
            // Java has no cycle check and would loop forever; a loop is certainly corruption.
            if list.len() > self.buffer_count.max(0) as usize + 1 {
                return Err(GbfError::CorruptFile("free list loops"));
            }
            let mut prefix = [0u8; BUFFER_PREFIX_SIZE];
            {
                let mut f = self.file();
                f.seek(SeekFrom::Start(self.block_offset(next)))?;
                f.read_exact(&mut prefix)?;
            }
            if prefix[0] & EMPTY_BUFFER == 0 {
                return Err(GbfError::CorruptFile("free list entry is not empty"));
            }
            next = i32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]);
        }
        self.set_free_indexes(&list);
        Ok(())
    }

    fn block_offset(&self, buffer_index: i32) -> u64 {
        (buffer_index as i64 + 1) as u64 * self.block_size as u64
    }

    /// Path of the underlying file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when opened read-only.
    pub fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// File id from the header.
    pub fn file_id(&self) -> i64 {
        self.file_id
    }

    /// Whole block size (payload plus 5-byte prefix).
    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Value of a user parameter.
    pub fn parameter(&self, name: &str) -> Result<i32> {
        self.params
            .get(name)
            .copied()
            .ok_or_else(|| GbfError::NoSuchParameter(name.to_owned()))
    }

    /// Set a user parameter.
    pub fn set_parameter(&mut self, name: &str, value: i32) -> Result<()> {
        if name.len() > MAX_PARAM_NAME_LENGTH {
            return Err(GbfError::ParameterNameTooLong(name.to_owned()));
        }
        if self.params.insert(name.to_owned(), value).is_none() {
            self.param_order.push(name.to_owned());
        }
        Ok(())
    }

    /// Remove all user parameters.
    pub fn clear_parameters(&mut self) {
        self.params.clear();
        self.param_order.clear();
    }

    /// Parameter names, in header order for files that were read.
    pub fn parameter_names(&self) -> &[String] {
        &self.param_order
    }

    /// Free buffer indexes, ascending.
    pub fn free_indexes(&self) -> &[i32] {
        &self.free_indexes
    }

    /// Replace the free list (sorted ascending, like Java).
    pub fn set_free_indexes(&mut self, indexes: &[i32]) {
        self.free_indexes = indexes.to_vec();
        self.free_indexes.sort_unstable();
    }

    /// Write buffer `index` (`put`). Empty buffers write only the prefix.
    pub fn put(&mut self, buf: &DataBuffer, index: i32) -> Result<()> {
        if self.read_only {
            return Err(GbfError::ReadOnly);
        }
        if !(0..=MAX_BUFFER_INDEX).contains(&index) {
            return Err(GbfError::IndexOutOfRange {
                index,
                count: self.buffer_count,
            });
        }
        if let Some(d) = &buf.data
            && d.len() != self.buffer_size
        {
            return Err(GbfError::BadBufferSize {
                expected: self.buffer_size,
                actual: d.len(),
            });
        }
        let offset = self.block_offset(index);
        let mut block = Vec::with_capacity(self.block_size);
        match (&buf.data, buf.empty) {
            (_, true) => {
                block.push(EMPTY_BUFFER);
                block.extend_from_slice(&buf.id.to_be_bytes());
            }
            (Some(d), false) => {
                block.push(0);
                block.extend_from_slice(&buf.id.to_be_bytes());
                block.extend_from_slice(d);
            }
            (None, false) => {
                // Java would NPE here; refuse instead of inventing a payload.
                return Err(GbfError::BadBufferSize {
                    expected: self.buffer_size,
                    actual: 0,
                });
            }
        }
        {
            let mut f = self.file();
            f.seek(SeekFrom::Start(offset))?;
            f.write_all(&block)?;
        }
        if index >= self.buffer_count {
            self.buffer_count = index + 1;
        }
        Ok(())
    }

    /// Write the header, free list and length padding. Returns false when nothing was
    /// written (read-only or temporary file).
    pub fn flush(&mut self) -> Result<bool> {
        if self.read_only || self.temporary {
            return Ok(false);
        }
        self.write_header()?;
        let f = self.file();
        let len = f.metadata()?.len();
        let d = len % self.block_size as u64;
        if d != 0 {
            f.set_len(len - d + self.block_size as u64)?;
        }
        f.sync_all()?;
        Ok(true)
    }

    fn write_header(&mut self) -> Result<()> {
        // Link the free list: each block points at the previous (smaller) free index and the
        // header points at the largest.
        let mut prev = -1i32;
        for index in self.free_indexes.clone() {
            self.put_free_block(index, prev)?;
            prev = index;
        }
        let mut hdr = Vec::new();
        hdr.extend_from_slice(&MAGIC_NUMBER.to_be_bytes());
        hdr.extend_from_slice(&self.file_id.to_be_bytes());
        hdr.extend_from_slice(&HEADER_FORMAT_VERSION.to_be_bytes());
        hdr.extend_from_slice(&(self.block_size as i32).to_be_bytes());
        hdr.extend_from_slice(&prev.to_be_bytes());
        hdr.extend_from_slice(&(self.params.len() as i32).to_be_bytes());
        let mut cnt = VER1_FIXED_HEADER_LENGTH;
        for (name, value) in &self.params {
            cnt += 8 + name.len();
            // Java compares against the buffer size (not the block size); keep that.
            if cnt > self.buffer_size {
                return Err(GbfError::HeaderTooLarge);
            }
            hdr.extend_from_slice(&(name.len() as i32).to_be_bytes());
            hdr.extend_from_slice(name.as_bytes());
            hdr.extend_from_slice(&value.to_be_bytes());
        }
        let mut f = self.file();
        f.seek(SeekFrom::Start(0))?;
        f.write_all(&hdr)?;
        Ok(())
    }

    fn put_free_block(&mut self, index: i32, next_free: i32) -> Result<()> {
        if index > self.buffer_count {
            return Err(GbfError::IndexOutOfRange {
                index,
                count: self.buffer_count,
            });
        }
        if index == self.buffer_count {
            self.buffer_count += 1;
        }
        let mut prefix = [0u8; BUFFER_PREFIX_SIZE];
        prefix[0] = EMPTY_BUFFER;
        prefix[1..].copy_from_slice(&next_free.to_be_bytes());
        let mut f = self.file();
        f.seek(SeekFrom::Start(self.block_offset(index)))?;
        f.write_all(&prefix)?;
        Ok(())
    }

    /// Flush (unless temporary or read-only) and close. A temporary file is deleted.
    pub fn close(mut self) -> Result<()> {
        self.flush()?;
        Ok(())
    }
}

impl Drop for BufferFile {
    fn drop(&mut self) {
        if self.temporary {
            let _ = fs::remove_file(&self.path);
        }
    }
}

impl BufferStore for BufferFile {
    fn buffer_size(&self) -> usize {
        self.buffer_size
    }

    fn index_count(&self) -> i32 {
        self.buffer_count
    }

    fn get_buffer(&self, index: i32) -> Result<DataBuffer> {
        // Java tests `index > bufferCount` and lets the read hit EOF for `==`; both end up as
        // an EOF error, so one range check covers them.
        if index < 0 || index >= self.buffer_count {
            return Err(GbfError::IndexOutOfRange {
                index,
                count: self.buffer_count,
            });
        }
        let mut f = self.file();
        f.seek(SeekFrom::Start(self.block_offset(index)))?;
        let mut prefix = [0u8; BUFFER_PREFIX_SIZE];
        f.read_exact(&mut prefix)?;
        let id = i32::from_be_bytes([prefix[1], prefix[2], prefix[3], prefix[4]]);
        // `get` tests the bit; `getDataBuffer` (block streams) tests equality. Bit test here.
        if prefix[0] & EMPTY_BUFFER != 0 {
            return Ok(DataBuffer::empty(-1));
        }
        let mut data = vec![0u8; self.buffer_size];
        f.read_exact(&mut data)?;
        Ok(DataBuffer::new(id, data))
    }
}

/// Convert a block read via a block stream the way `LocalBufferFile.getDataBuffer` does.
///
/// Unlike [`BufferStore::get_buffer`] this compares the flag byte for equality with
/// [`EMPTY_BUFFER`]; a block with other flag bits set is treated as in use.
pub fn data_buffer_from_block(block_index: i32, block: &[u8]) -> Result<Option<DataBuffer>> {
    if block_index <= 0 {
        return Ok(None);
    }
    let flags = ghidra_fmt_bytes::get_u8(block, 0)?;
    if flags == EMPTY_BUFFER {
        return Ok(Some(DataBuffer::empty(-1)));
    }
    let id = ghidra_fmt_bytes::get_i32(block, 1)?;
    let data =
        ghidra_fmt_bytes::slice(block, BUFFER_PREFIX_SIZE, block.len() - BUFFER_PREFIX_SIZE)?;
    Ok(Some(DataBuffer::new(id, data.to_vec())))
}

#[cfg(test)]
mod tests;
