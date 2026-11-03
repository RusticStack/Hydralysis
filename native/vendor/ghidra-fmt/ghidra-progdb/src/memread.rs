//! Memory content: the read side of `MemoryMapDB.getBytes`, `MemoryBlockDB.getBytes` and the
//! `SubMemoryBlock` classes (`BufferSubMemoryBlock`, `FileBytesSubMemoryBlock`,
//! `UninitializedSubMemoryBlock`, `ByteMappedSubMemoryBlock`, `BitMappedSubMemoryBlock`),
//! including the layered "File Bytes" buffers (`FileBytes.getModifiedBytes`) and
//! `ByteMappingScheme`.
//!
//! Overlay spaces are not modelled: an address is looked up by space name and offset only.

use ghidra_fmt_chain::ChainedBuffer;
use ghidra_fmt_db::Database;
use ghidra_fmt_field::Field;
use ghidra_fmt_gbf::BufferStore;

use crate::memory::{MemoryBlock, SubBlock, SubBlockKind};
use crate::{Address, AddressMap, Cols, ProgError, Result};

/// Nesting limit for mapped blocks that read other mapped blocks (Java relies on `ioPending`
/// and on a stack overflow for cycles; here a cycle is reported as an error).
const MAX_MAP_DEPTH: u32 = 16;

fn access<T>(msg: impl Into<String>) -> Result<T> {
    Err(ProgError::MemoryAccess(msg.into()))
}

/// The bytes of a program: its memory blocks and the buffers behind them.
pub struct Memory<'a, S: BufferStore> {
    db: &'a Database<S>,
    map: &'a AddressMap,
    blocks: &'a [MemoryBlock],
}

/// `ByteMappingScheme`: `mapped` bytes out of every `source` bytes of the mapped-to memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteMappingScheme {
    mapped: i64,
    source: i64,
}

impl ByteMappingScheme {
    /// Decode the stored scheme (`0` is 1:1).
    ///
    /// # Errors
    ///
    /// [`ProgError::Corrupt`] for a ratio `ByteMappingScheme.validateMappingScheme` rejects.
    pub fn from_encoded(encoded: i32) -> Result<Self> {
        if encoded == 0 {
            return Ok(Self {
                mapped: 1,
                source: 1,
            });
        }
        let mapped = i64::from((encoded >> 7) & 0x7f);
        let source = i64::from(encoded & 0x7f);
        if mapped <= 0 || source <= 0 || mapped > source {
            return Err(ProgError::Corrupt(format!(
                "invalid byte mapping ratio: {mapped}:{source}"
            )));
        }
        Ok(Self { mapped, source })
    }

    fn is_one_to_one(self) -> bool {
        self.source <= 1
    }
}

impl<'a, S: BufferStore> Memory<'a, S> {
    pub(crate) fn new(db: &'a Database<S>, map: &'a AddressMap, blocks: &'a [MemoryBlock]) -> Self {
        Self { db, map, blocks }
    }

    /// The blocks in memory map order.
    pub fn blocks(&self) -> &[MemoryBlock] {
        self.blocks
    }

    /// The block containing `addr`, if any (`Memory.getBlock(Address)`).
    pub fn block_at(&self, addr: &Address) -> Option<&MemoryBlock> {
        let Address::Space { space, offset } = addr else {
            return None;
        };
        self.blocks.iter().find(|b| match &b.start {
            Address::Space {
                space: s,
                offset: start,
            } => s == space && *offset >= *start && offset - start < b.length as u64,
            _ => false,
        })
    }

    /// `Memory.getBytes(addr, dest, 0, len)`: up to `len` bytes starting at `addr`, reading on
    /// across adjacent blocks. The result is shorter than `len` when memory ends (no block,
    /// or a block whose first part is uninitialized).
    ///
    /// # Errors
    ///
    /// [`ProgError::MemoryAccess`] when not a single byte could be read, or when a part inside
    /// an initialized block is uninitialized, as Java throws `MemoryAccessException`.
    pub fn read(&self, addr: &Address, len: usize) -> Result<Vec<u8>> {
        self.get_bytes(addr, len, 0)
    }

    /// The original (loader) bytes of `count` addresses starting at `addr`: what
    /// `RelocationManager.getOriginalBytes` collects from `AddressSourceInfo.getOriginalValue`.
    /// An address outside memory ends the walk (the rest stays 0); addresses backed by anything
    /// but file bytes (buffers, uninitialized or mapped blocks) read as 0, as in Java for
    /// everything that is not file backed (mapped blocks are not followed here).
    ///
    /// # Errors
    ///
    /// A damaged "File Bytes" table.
    pub fn original_bytes(&self, addr: &Address, count: usize) -> Result<Vec<u8>> {
        let mut out = vec![0u8; count];
        let mut cur = addr.clone();
        for (i, slot) in out.iter_mut().enumerate() {
            if i != 0 {
                match self.add_no_wrap(&cur, 1) {
                    Some(next) => cur = next,
                    None => break,
                }
            }
            let Some(block) = self.block_at(&cur) else {
                break;
            };
            let off = self.block_offset(block, &cur)?;
            let Some(sub) = block
                .sub_blocks
                .iter()
                .find(|s| off >= s.start_offset && off < s.start_offset + s.length)
            else {
                continue;
            };
            if sub.kind == SubBlockKind::FileBytes {
                *slot = self.file_bytes_original(
                    i64::from(sub.source_id),
                    sub.source_offset + (off - sub.start_offset),
                )?;
            }
        }
        Ok(out)
    }

    /// `FileBytes.getOriginalByte(offset)`.
    fn file_bytes_original(&self, id: i64, offset: i64) -> Result<u8> {
        let table = self
            .db
            .table("File Bytes")
            .map_err(|_| ProgError::Corrupt(format!("No File Bytes found for ID: {id}")))?;
        let rec = table
            .get(&Field::Long(id))?
            .ok_or_else(|| ProgError::Corrupt(format!("No File Bytes found for ID: {id}")))?;
        let c = Cols::new(table.schema());
        let size = c.long(&rec, "Size")?.unwrap_or(0);
        if offset < 0 || offset >= size {
            return Err(ProgError::Corrupt(format!(
                "file bytes {id}: offset {offset} outside 0..{size}"
            )));
        }
        let original = int_array(c.field(&rec, "Chain Buffer IDs")?)?;
        let store = self.db.store();
        let first = ChainedBuffer::open(
            store,
            *original
                .first()
                .ok_or_else(|| ProgError::Corrupt("file bytes without buffers".into()))?,
        )?;
        let max = i64::from(first.len());
        if max <= 0 {
            return Err(ProgError::Corrupt("file bytes buffer size".into()));
        }
        let index = (offset / max) as usize;
        let buf = ChainedBuffer::open(
            store,
            *original
                .get(index)
                .ok_or_else(|| ProgError::Corrupt("file bytes buffer index".into()))?,
        )?;
        Ok(buf.get(store, (offset % max) as i32, 1)?[0])
    }

    /// `Memory.getByte(addr)`.
    ///
    /// # Errors
    ///
    /// [`ProgError::MemoryAccess`] when `addr` is not in an initialized block.
    pub fn read_byte(&self, addr: &Address) -> Result<u8> {
        let Some(block) = self.block_at(addr) else {
            return access(format!("Address {addr} does not exist in memory"));
        };
        let off = self.block_offset(block, addr)?;
        Ok(self.block_read(block, off, 1, 0)?[0])
    }

    fn get_bytes(&self, addr: &Address, len: usize, depth: u32) -> Result<Vec<u8>> {
        if depth > MAX_MAP_DEPTH {
            return access("Cyclic Access");
        }
        let mut out = Vec::with_capacity(len.min(1 << 20));
        let mut cur = addr.clone();
        while out.len() < len {
            let Some(block) = self.block_at(&cur) else {
                break;
            };
            if !(block.is_initialized() || block.is_mapped()) {
                break;
            }
            let off = self.block_offset(block, &cur)?;
            let chunk = self.block_read(block, off, len - out.len(), depth)?;
            let n = chunk.len();
            out.extend_from_slice(&chunk);
            if n == 0 {
                break;
            }
            match self.add_no_wrap(&cur, n as u64) {
                Some(next) => cur = next,
                None => break,
            }
        }
        if out.is_empty() && len > 0 {
            return access(format!("Unable to read bytes at {cur}"));
        }
        Ok(out)
    }

    fn block_offset(&self, block: &MemoryBlock, addr: &Address) -> Result<i64> {
        match (&block.start, addr) {
            (
                Address::Space {
                    space: s1,
                    offset: o1,
                },
                Address::Space {
                    space: s2,
                    offset: o2,
                },
            ) if s1 == s2 && o2 >= o1 && o2 - o1 < block.length as u64 => Ok((o2 - o1) as i64),
            _ => access(format!("Address not contained in block: {addr}")),
        }
    }

    /// `Address.addNoWrap`: `None` past the end of the space.
    fn add_no_wrap(&self, addr: &Address, delta: u64) -> Option<Address> {
        let Address::Space { space, offset } = addr else {
            return None;
        };
        let bits = self.map.spaces().find(space)?.bits;
        let max = if bits >= 64 {
            u64::MAX
        } else {
            (1u64 << bits) - 1
        };
        let sum = offset.checked_add(delta)?;
        (sum <= max).then(|| Address::Space {
            space: space.clone(),
            offset: sum,
        })
    }

    /// `MemoryBlockDB.getBytes(long offset, ...)`.
    fn block_read(
        &self,
        block: &MemoryBlock,
        offset: i64,
        want: usize,
        depth: u32,
    ) -> Result<Vec<u8>> {
        let len = (want as i64).min(block.length - offset).max(0) as usize;
        let mut out = Vec::with_capacity(len.min(1 << 20));
        while out.len() < len {
            let at = offset + out.len() as i64;
            let sub = block
                .sub_blocks
                .iter()
                .find(|s| at >= s.start_offset && at < s.start_offset + s.length)
                .ok_or_else(|| ProgError::Corrupt("address or offset out of bounds".into()))?;
            let chunk = self.sub_read(sub, at, len - out.len(), depth)?;
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }

    /// `SubMemoryBlock.getBytes(offsetInMemBlock, ...)`.
    fn sub_read(
        &self,
        sub: &SubBlock,
        offset_in_block: i64,
        want: usize,
        depth: u32,
    ) -> Result<Vec<u8>> {
        let in_sub = offset_in_block - sub.start_offset;
        let len = (want as i64).min(sub.length - in_sub) as usize;
        match sub.kind {
            SubBlockKind::Buffer => {
                let chain = ChainedBuffer::open(self.db.store(), sub.source_id)?;
                let at = i32::try_from(in_sub)
                    .map_err(|_| ProgError::Corrupt("buffer offset beyond 2 GiB".into()))?;
                Ok(chain.get(self.db.store(), at, len)?)
            }
            SubBlockKind::FileBytes => {
                self.file_bytes_read(i64::from(sub.source_id), sub.source_offset + in_sub, len)
            }
            SubBlockKind::Uninitialized => access("Attempted to read from uninitialized block"),
            SubBlockKind::ByteMapped => {
                let scheme = ByteMappingScheme::from_encoded(sub.source_id)?;
                let base = self.map.decode(sub.source_offset)?;
                self.mapped_read(&base, scheme, in_sub, len, depth)
            }
            SubBlockKind::BitMapped => {
                let base = self.map.decode(sub.source_offset)?;
                let mut out = Vec::with_capacity(len);
                // Java indexes the bit by the offset in the block, not in the sub block
                for i in 0..len as i64 {
                    let bit = offset_in_block + i;
                    let Some(src) = self.add_no_wrap(&base, (bit / 8) as u64) else {
                        return access("No memory at address");
                    };
                    let b = self.get_byte_nested(&src, depth + 1)?;
                    out.push((b >> (bit % 8)) & 1);
                }
                Ok(out)
            }
        }
    }

    fn get_byte_nested(&self, addr: &Address, depth: u32) -> Result<u8> {
        if depth > MAX_MAP_DEPTH {
            return access("Cyclic Access");
        }
        let Some(block) = self.block_at(addr) else {
            return access(format!("Address {addr} does not exist in memory"));
        };
        let off = self.block_offset(block, addr)?;
        Ok(self.block_read(block, off, 1, depth)?[0])
    }

    /// `ByteMappingScheme.getBytes`.
    pub(crate) fn mapped_read(
        &self,
        base: &Address,
        scheme: ByteMappingScheme,
        offset_in_sub: i64,
        len: usize,
        depth: u32,
    ) -> Result<Vec<u8>> {
        if scheme.is_one_to_one() {
            let Some(src) = self.add_no_wrap(base, offset_in_sub as u64) else {
                return access("No memory at address");
            };
            return self.get_bytes(&src, len, depth + 1);
        }
        let pattern_count = offset_in_sub / scheme.mapped;
        let partial = offset_in_sub % scheme.mapped;
        let mapped_offset = scheme.source * pattern_count + partial;
        let buf_size = (scheme.source * (len as i64 / scheme.mapped + 1)) as usize;
        let Some(src) = self.add_no_wrap(base, mapped_offset as u64) else {
            return access("No memory at address");
        };
        let buf = self.get_bytes(&src, buf_size, depth + 1)?;
        let non_mapped = scheme.source - scheme.mapped;
        let mut out = Vec::with_capacity(len);
        let mut i = scheme.mapped - partial;
        let mut skip = false;
        for &b in &buf {
            if out.len() >= len {
                break;
            }
            if !skip {
                out.push(b);
                i -= 1;
                if i == 0 {
                    skip = true;
                    i = non_mapped;
                }
            } else {
                i -= 1;
                if i == 0 {
                    skip = false;
                    i = scheme.mapped;
                }
            }
        }
        Ok(out)
    }

    /// `FileBytes.getModifiedBytes(offset, ...)`: the layered buffers over the original bytes.
    fn file_bytes_read(&self, id: i64, offset: i64, want: usize) -> Result<Vec<u8>> {
        let table = self
            .db
            .table("File Bytes")
            .map_err(|_| ProgError::Corrupt(format!("No File Bytes found for ID: {id}")))?;
        let rec = table
            .get(&Field::Long(id))?
            .ok_or_else(|| ProgError::Corrupt(format!("No File Bytes found for ID: {id}")))?;
        let c = Cols::new(table.schema());
        let size = c.long(&rec, "Size")?.unwrap_or(0);
        let original = int_array(c.field(&rec, "Chain Buffer IDs")?)?;
        let layered = int_array(c.field(&rec, "Layered Chain Buffer IDs")?)?;
        if offset < 0 || offset >= size {
            return Err(ProgError::Corrupt(format!(
                "file bytes {id}: offset {offset} outside 0..{size}"
            )));
        }
        let len = (want as i64).min(size - offset) as usize;
        let store = self.db.store();
        let first = ChainedBuffer::open(
            store,
            *layered
                .first()
                .ok_or_else(|| ProgError::Corrupt("file bytes without buffers".into()))?,
        )?;
        let max = i64::from(first.len());
        if max <= 0 || layered.len() != original.len() {
            return Err(ProgError::Corrupt("file bytes buffer lists differ".into()));
        }
        let mut out = vec![0u8; len];
        let mut done = 0usize;
        let mut at = offset;
        while done < len {
            let index = (at / max) as usize;
            let local = (at % max) as i32;
            let n = ((max - i64::from(local)) as usize).min(len - done);
            let top = ChainedBuffer::open(
                store,
                *layered
                    .get(index)
                    .ok_or_else(|| ProgError::Corrupt("file bytes buffer index".into()))?,
            )?;
            let base = ChainedBuffer::open(store, original[index])?;
            top.get_into_over(store, &base, local, &mut out[done..done + n])?;
            done += n;
            at += n as i64;
        }
        Ok(out)
    }
}

/// `new BinaryCodedField(field).getIntArray()`.
fn int_array(f: Option<&Field>) -> Result<Vec<i32>> {
    let Some(Field::Binary(Some(d))) = f else {
        return Err(ProgError::Corrupt("missing buffer id list".into()));
    };
    if d.len() < 2 || d[0] != 4 {
        return Err(ProgError::Corrupt(
            "buffer id list is not an int array".into(),
        ));
    }
    if (d[1] as i8) < 0 {
        return Ok(Vec::new());
    }
    Ok(d[2..]
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| i32::from_be_bytes(*c))
        .collect())
}
