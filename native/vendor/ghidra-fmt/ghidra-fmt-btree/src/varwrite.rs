//! Write path of the variable-length-key B-tree: `db.VarKeyRecordNode` (type 4) and
//! `db.VarKeyInteriorNode` (type 3), for tables keyed by strings, binaries and variable-length
//! index fields.
//!
//! Unlike the long-key and fixed-key trees, the var-key interior code keeps and rewrites
//! `parent` links while it splits nodes (`keyChanged` can split an interior node when a longer
//! key no longer fits, `split` repairs the links of the nodes involved, and `getRoot()` follows
//! them). To stay byte-identical with Java this port keeps the same per-operation node cache
//! (`NodeMgr`'s node table) with the same `parent` links, instead of an ancestor list.

use std::collections::HashMap;

use ghidra_fmt_bytes as bytes;
use ghidra_fmt_chain::ChainedBuffer;
use ghidra_fmt_field::{Field, FieldType};
use ghidra_fmt_gbf::{BufferStoreMut, DataBuffer};

use crate::{BtreeError, NodeType, Result};

const KEY_TYPE_OFFSET: usize = 1;
const KEY_COUNT_OFFSET: usize = 2;
const NODE_HEADER: usize = 6;
const LEAF_HEADER: usize = 14;
const PREV_LEAF: usize = 6;
const NEXT_LEAF: usize = 10;
const LEAF_ENTRY: usize = 5;
const INT_ENTRY: usize = 8;
const HALF_KEY_CAPACITY: i64 = 4;
const MAX_DEPTH: usize = 64;

/// `VarKeyInteriorNode.getMaxKeyLength`.
fn max_key_length(buffer_len: usize) -> i64 {
    (((buffer_len - NODE_HEADER) / 8) as i64) - INT_ENTRY as i64
}

#[derive(Clone)]
struct N {
    d: Vec<u8>,
    parent: Option<i32>,
}

/// Writer for one var-key table tree.
#[derive(Debug, Clone)]
pub struct VarKeyWriter {
    root: i32,
    key_type: FieldType,
}

impl VarKeyWriter {
    /// Writer for the tree rooted at `root` (`-1` for an empty table) with keys of `key_type`.
    pub fn new(root: i32, key_type: &FieldType) -> Self {
        Self {
            root,
            key_type: key_type.clone(),
        }
    }

    /// Current root buffer id, `-1` when the table is empty.
    pub fn root(&self) -> i32 {
        self.root
    }

    /// Insert or replace the record for `key` with serialized body `data`. Returns true when a
    /// new record was added.
    pub fn put<S: BufferStoreMut + ?Sized>(
        &mut self,
        s: &mut S,
        key: &Field,
        data: &[u8],
    ) -> Result<bool> {
        let mut c = Ctx::new(s, &self.key_type);
        let root = if self.root < 0 {
            c.new_leaf(-1, -1)?
        } else {
            self.root
        };
        let leaf = c.get_leaf(root, key)?;
        let existed = c.leaf_index(leaf, key)?.is_ok();
        let new_root = c.put_record(leaf, key, data)?;
        c.flush()?;
        self.root = new_root;
        Ok(!existed)
    }

    /// Remove the record for `key`; returns whether it existed.
    pub fn delete<S: BufferStoreMut + ?Sized>(&mut self, s: &mut S, key: &Field) -> Result<bool> {
        if self.root < 0 {
            return Ok(false);
        }
        let mut c = Ctx::new(s, &self.key_type);
        let leaf = c.get_leaf(self.root, key)?;
        let existed = c.leaf_index(leaf, key)?.is_ok();
        let new_root = c.delete_record(leaf, key)?;
        c.flush()?;
        self.root = new_root.unwrap_or(-1);
        Ok(existed)
    }
}

struct Ctx<'a, S: BufferStoreMut + ?Sized> {
    s: &'a mut S,
    c: HashMap<i32, N>,
    kt: &'a FieldType,
}

impl<'a, S: BufferStoreMut + ?Sized> Ctx<'a, S> {
    fn new(s: &'a mut S, kt: &'a FieldType) -> Self {
        Self {
            s,
            c: HashMap::new(),
            kt,
        }
    }

    /// Write back every cached node (`NodeMgr.releaseNodes`).
    fn flush(&mut self) -> Result<()> {
        let mut ids: Vec<i32> = self.c.keys().copied().collect();
        ids.sort_unstable();
        for id in ids {
            let n = &self.c[&id];
            self.s.put_buffer(&DataBuffer::new(id, n.d.clone()))?;
        }
        self.c.clear();
        Ok(())
    }

    // ---- node cache and raw access ----

    fn load(&mut self, id: i32) -> Result<()> {
        if !self.c.contains_key(&id) {
            let d = self
                .s
                .get_buffer(id)?
                .data
                .ok_or(BtreeError::CorruptNode("node buffer is empty"))?;
            self.c.insert(id, N { d, parent: None });
        }
        Ok(())
    }

    fn n(&mut self, id: i32) -> Result<&mut N> {
        self.load(id)?;
        Ok(self.c.get_mut(&id).expect("loaded"))
    }

    fn ty(&mut self, id: i32) -> Result<u8> {
        Ok(self.n(id)?.d[0])
    }

    fn is_leaf(&mut self, id: i32) -> Result<bool> {
        let t = self.ty(id)?;
        if t == NodeType::VarKeyRec as u8 {
            Ok(true)
        } else if t == NodeType::VarKeyInterior as u8 {
            Ok(false)
        } else {
            Err(BtreeError::UnexpectedNodeType {
                found: t,
                buffer_id: id,
            })
        }
    }

    fn geti(&mut self, id: i32, off: usize) -> Result<i32> {
        Ok(bytes::get_i32(&self.n(id)?.d, off)?)
    }

    fn puti(&mut self, id: i32, off: usize, v: i32) -> Result<()> {
        Ok(bytes::put_i32(&mut self.n(id)?.d, off, v)?)
    }

    fn blen(&mut self, id: i32) -> Result<i64> {
        Ok(self.n(id)?.d.len() as i64)
    }

    fn cnt(&mut self, id: i32) -> Result<usize> {
        usize::try_from(self.geti(id, KEY_COUNT_OFFSET)?)
            .map_err(|_| BtreeError::CorruptNode("negative key count"))
    }

    fn set_cnt(&mut self, id: i32, v: usize) -> Result<()> {
        self.puti(id, KEY_COUNT_OFFSET, v as i32)
    }

    fn parent(&mut self, id: i32) -> Result<Option<i32>> {
        Ok(self.n(id)?.parent)
    }

    fn set_parent(&mut self, id: i32, p: Option<i32>) -> Result<()> {
        self.n(id)?.parent = p;
        Ok(())
    }

    fn mv(&mut self, id: i32, src: i64, dst: i64, len: i64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let d = &mut self.n(id)?.d;
        let n = d.len() as i64;
        if src < 0 || dst < 0 || len < 0 || src + len > n || dst + len > n {
            return Err(BtreeError::CorruptNode("buffer move out of range"));
        }
        d.copy_within(src as usize..(src + len) as usize, dst as usize);
        Ok(())
    }

    /// `DataBuffer.copy(dstOffset, srcBuffer, srcOffset, len)` between two nodes.
    fn copy(
        &mut self,
        dst: i32,
        dst_off: usize,
        src: i32,
        src_off: usize,
        len: usize,
    ) -> Result<()> {
        let part = bytes::slice(&self.n(src)?.d, src_off, len)?.to_vec();
        Ok(bytes::put_bytes(&mut self.n(dst)?.d, dst_off, &part)?)
    }

    fn put_bytes(&mut self, id: i32, off: usize, data: &[u8]) -> Result<()> {
        Ok(bytes::put_bytes(&mut self.n(id)?.d, off, data)?)
    }

    fn key_at(&mut self, id: i32, off: i32) -> Result<Field> {
        let kt = self.kt.clone();
        let d = &self.n(id)?.d;
        Ok(Field::read(&kt, d, off as usize)?.0)
    }

    fn key_len_at(&mut self, id: i32, off: i32) -> Result<i64> {
        let kt = self.kt.clone();
        let d = &self.n(id)?.d;
        Ok(Field::read_length(&kt, d, off as usize)? as i64)
    }

    fn cmp_at(&mut self, id: i32, key: &Field, off: i32) -> Result<std::cmp::Ordering> {
        let d = &self.n(id)?.d;
        Ok(key.compare_to_stored(d, off as usize)?)
    }

    fn new_node(&mut self, ty: NodeType) -> Result<i32> {
        let id = self.s.create_buffer()?;
        let mut d = self
            .s
            .get_buffer(id)?
            .data
            .ok_or(BtreeError::CorruptNode("new buffer is empty"))?;
        d[0] = ty as u8;
        d[KEY_TYPE_OFFSET] = self.kt.code();
        bytes::put_i32(&mut d, KEY_COUNT_OFFSET, 0)?;
        self.c.insert(id, N { d, parent: None });
        Ok(id)
    }

    fn delete_node(&mut self, id: i32) -> Result<()> {
        self.c.remove(&id);
        self.s.delete_buffer(id)?;
        Ok(())
    }

    fn get_root(&mut self, id: i32) -> Result<i32> {
        let mut cur = id;
        for _ in 0..MAX_DEPTH * 4 {
            match self.parent(cur)? {
                Some(p) => cur = p,
                None => return Ok(cur),
            }
        }
        Err(BtreeError::TooDeep)
    }

    // ---- shared by leaf and interior: variable-length data area ----

    /// `moveRecords` / `moveKeys`: shift the data area of entries `index..` by `offset`.
    /// `entry_base`/`entry` locate the 4 byte offset of entry i.
    fn move_area(
        &mut self,
        id: i32,
        base: usize,
        entry: usize,
        index: usize,
        offset: i64,
    ) -> Result<i32> {
        let kc = self.cnt(id)?;
        let blen = self.blen(id)?;
        let off_of = |c: &mut Self, i: usize| -> Result<i64> {
            Ok(i64::from(c.geti(id, base + i * entry)?))
        };
        if index == kc {
            if index == 0 {
                return Ok((blen + offset) as i32);
            }
            return Ok((off_of(self, kc - 1)? + offset) as i32);
        }
        let start = off_of(self, kc - 1)?;
        let end = if index == 0 {
            blen
        } else {
            off_of(self, index - 1)?
        };
        self.mv(id, start, start + offset, end - start)?;
        for i in index..kc {
            let o = off_of(self, i)? + offset;
            self.puti(id, base + i * entry, o as i32)?;
        }
        Ok((end + offset) as i32)
    }

    // ---- leaf ----

    fn koff(&mut self, leaf: i32, i: usize) -> Result<i32> {
        self.geti(leaf, LEAF_HEADER + i * LEAF_ENTRY)
    }

    fn set_koff(&mut self, leaf: i32, i: usize, v: i32) -> Result<()> {
        self.puti(leaf, LEAF_HEADER + i * LEAF_ENTRY, v)
    }

    fn indirect(&mut self, leaf: i32, i: usize) -> Result<bool> {
        Ok(self.n(leaf)?.d[LEAF_HEADER + 4 + i * LEAF_ENTRY] != 0)
    }

    fn set_indirect(&mut self, leaf: i32, i: usize, on: bool) -> Result<()> {
        self.n(leaf)?.d[LEAF_HEADER + 4 + i * LEAF_ENTRY] = u8::from(on);
        Ok(())
    }

    fn leaf_key(&mut self, leaf: i32, i: usize) -> Result<Field> {
        let off = self.koff(leaf, i)?;
        self.key_at(leaf, off)
    }

    fn data_offset(&mut self, leaf: i32, i: usize) -> Result<i32> {
        let off = self.koff(leaf, i)?;
        Ok(off + self.key_len_at(leaf, off)? as i32)
    }

    fn leaf_free(&mut self, leaf: i32) -> Result<i64> {
        let kc = self.cnt(leaf)?;
        let top = if kc == 0 {
            self.blen(leaf)?
        } else {
            i64::from(self.koff(leaf, kc - 1)?)
        };
        Ok(top - (kc * LEAF_ENTRY) as i64 - LEAF_HEADER as i64)
    }

    fn full_len(&mut self, leaf: i32, i: usize) -> Result<i64> {
        if i == 0 {
            Ok(self.blen(leaf)? - i64::from(self.koff(leaf, 0)?))
        } else {
            Ok(i64::from(self.koff(leaf, i - 1)?) - i64::from(self.koff(leaf, i)?))
        }
    }

    fn move_records(&mut self, leaf: i32, index: usize, offset: i64) -> Result<i32> {
        self.move_area(leaf, LEAF_HEADER, LEAF_ENTRY, index, offset)
    }

    /// `getKeyIndex`: `Ok(index)` when present, `Err(insertion point)` otherwise.
    fn leaf_index(&mut self, leaf: i32, key: &Field) -> Result<std::result::Result<usize, usize>> {
        let (mut min, mut max) = (0i64, self.cnt(leaf)? as i64 - 1);
        while min <= max {
            let i = (min + max) / 2;
            let off = self.koff(leaf, i as usize)?;
            match self.cmp_at(leaf, key, off)? {
                std::cmp::Ordering::Equal => return Ok(Ok(i as usize)),
                std::cmp::Ordering::Greater => min = i + 1,
                std::cmp::Ordering::Less => max = i - 1,
            }
        }
        Ok(Err(min as usize))
    }

    fn remove_chained(&mut self, id: i32) -> Result<()> {
        let mut cb = ChainedBuffer::open(self.s, id)?;
        cb.delete(self.s)?;
        Ok(())
    }

    fn new_leaf(&mut self, prev: i32, next: i32) -> Result<i32> {
        let id = self.new_node(NodeType::VarKeyRec)?;
        self.puti(id, PREV_LEAF, prev)?;
        self.puti(id, NEXT_LEAF, next)?;
        Ok(id)
    }

    /// `getLeafNode(key)` from node `id`, setting the `parent` links on the way down.
    fn get_leaf(&mut self, id: i32, key: &Field) -> Result<i32> {
        let mut cur = id;
        for _ in 0..MAX_DEPTH {
            if self.is_leaf(cur)? {
                return Ok(cur);
            }
            let idx = self.id_index(cur, key)?;
            let child = self.child(cur, idx)?;
            self.load(child)?;
            self.set_parent(child, Some(cur))?;
            cur = child;
        }
        Err(BtreeError::TooDeep)
    }

    fn split_index(&mut self, leaf: i32) -> Result<usize> {
        let kc = self.cnt(leaf)?;
        let blen = self.blen(leaf)?;
        let top = if kc == 0 {
            blen
        } else {
            i64::from(self.koff(leaf, kc - 1)?)
        };
        let halfway = (top + blen) / 2;
        let (mut min, mut max) = (0i64, kc as i64 - 1);
        while min <= max {
            let i = (min + max) / 2;
            let off = i64::from(self.koff(leaf, i as usize)?);
            if off == halfway {
                return Ok(i as usize);
            } else if off < halfway {
                max = i - 1;
            } else {
                min = i + 1;
            }
        }
        Ok(min as usize)
    }

    fn split_data(&mut self, left: i32, right: i32) -> Result<()> {
        let kc = self.cnt(left)?;
        let split_index = self.split_index(left)?;
        if split_index == 0 {
            return Err(BtreeError::Assertion("var-key leaf split index 0"));
        }
        let count = kc - split_index;
        let blen = self.blen(left)? as usize;
        let start = self.koff(left, kc - 1)? as usize;
        let end = self.koff(left, split_index - 1)? as usize;
        let split_len = end - start;
        let right_offset = blen - split_len;
        self.copy(right, right_offset, left, start, split_len)?;
        self.copy(
            right,
            LEAF_HEADER,
            left,
            LEAF_HEADER + split_index * LEAF_ENTRY,
            count * LEAF_ENTRY,
        )?;
        let correction = (blen - end) as i64;
        for i in 0..count {
            let o = i64::from(self.koff(right, i)?) + correction;
            self.set_koff(right, i, o as i32)?;
        }
        self.set_cnt(left, kc - count)?;
        self.set_cnt(right, count)
    }

    /// `VarKeyRecordNode.split`; returns the node `parent.insert` / the new root.
    fn split_leaf(&mut self, leaf: i32) -> Result<i32> {
        let old_sibling = self.geti(leaf, NEXT_LEAF)?;
        let new_leaf = self.new_leaf(leaf, old_sibling)?;
        self.puti(leaf, NEXT_LEAF, new_leaf)?;
        if old_sibling >= 0 {
            self.puti(old_sibling, PREV_LEAF, new_leaf)?;
        }
        self.split_data(leaf, new_leaf)?;
        if let Some(p) = self.parent(leaf)? {
            return self.insert_node(p, new_leaf);
        }
        let k0 = self.leaf_key(leaf, 0)?;
        let k1 = self.leaf_key(new_leaf, 0)?;
        self.new_interior(&k0, leaf, &k1, new_leaf)
    }

    fn append_leaf(&mut self, leaf: i32, new_leaf: i32) -> Result<i32> {
        self.puti(new_leaf, PREV_LEAF, leaf)?;
        let right = self.geti(leaf, NEXT_LEAF)?;
        self.puti(new_leaf, NEXT_LEAF, right)?;
        self.puti(leaf, NEXT_LEAF, new_leaf)?;
        if right >= 0 {
            self.puti(right, PREV_LEAF, new_leaf)?;
        }
        if let Some(p) = self.parent(leaf)? {
            return self.insert_node(p, new_leaf);
        }
        let k0 = self.leaf_key(leaf, 0)?;
        let k1 = self.leaf_key(new_leaf, 0)?;
        self.new_interior(&k0, leaf, &k1, new_leaf)
    }

    fn put_record(&mut self, leaf: i32, key: &Field, data: &[u8]) -> Result<i32> {
        let mut leaf = leaf;
        for _ in 0..MAX_DEPTH * 4 {
            match self.leaf_index(leaf, key)? {
                Ok(index) => return self.update_record(leaf, index, key, data),
                Err(index) => {
                    if self.insert_record(leaf, index, key, data)? {
                        if index == 0
                            && let Some(p) = self.parent(leaf)?
                        {
                            let old = self.leaf_key(leaf, 1)?;
                            self.key_changed(p, &old, key, leaf)?;
                        }
                        return self.get_root(leaf);
                    }
                    if index == self.cnt(leaf)? {
                        let new_leaf = self.new_leaf(-1, -1)?;
                        self.insert_record(new_leaf, 0, key, data)?;
                        return self.append_leaf(leaf, new_leaf);
                    }
                    let root = self.split_leaf(leaf)?;
                    leaf = self.get_leaf(root, key)?;
                }
            }
        }
        Err(BtreeError::TooDeep)
    }

    fn insert_record(&mut self, leaf: i32, index: usize, key: &Field, data: &[u8]) -> Result<bool> {
        let kbytes = key.to_bytes();
        let key_len = kbytes.len() as i64;
        let blen = self.blen(leaf)?;
        if key_len > max_key_length(blen as usize) {
            return Err(BtreeError::Assertion("key exceeds the maximum key length"));
        }
        let mut len = data.len() as i64;
        let max_rec = ((blen - LEAF_HEADER as i64) >> 2) - LEAF_ENTRY as i64 - key_len;
        let use_indirect = len > max_rec;
        if use_indirect {
            len = 4;
        }
        if len + key_len + LEAF_ENTRY as i64 > self.leaf_free(leaf)? {
            return Ok(false);
        }
        let kc = self.cnt(leaf)?;
        let offset = self.move_records(leaf, index, -(len + key_len))?;
        let start = LEAF_HEADER + index * LEAF_ENTRY;
        self.mv(
            leaf,
            start as i64,
            (start + LEAF_ENTRY) as i64,
            ((kc - index) * LEAF_ENTRY) as i64,
        )?;
        self.puti(leaf, start, offset)?;
        self.set_cnt(leaf, kc + 1)?;
        self.put_bytes(leaf, offset as usize, &kbytes)?;
        if use_indirect {
            let mut cb = ChainedBuffer::create(self.s, data.len() as i32, false)?;
            self.puti(leaf, offset as usize + kbytes.len(), cb.id())?;
            cb.put(self.s, 0, data)?;
        } else {
            self.put_bytes(leaf, offset as usize + kbytes.len(), data)?;
        }
        self.set_indirect(leaf, index, use_indirect)?;
        Ok(true)
    }

    fn update_record(&mut self, leaf: i32, index: usize, key: &Field, data: &[u8]) -> Result<i32> {
        let kbytes = key.to_bytes();
        let key_len = kbytes.len() as i64;
        let mut offset = self.koff(leaf, index)?;
        let old_len = self.full_len(leaf, index)? - key_len;
        let mut len = data.len() as i64;
        let blen = self.blen(leaf)?;
        let max_rec = ((blen - LEAF_HEADER as i64) >> 2) - LEAF_ENTRY as i64 - key_len;
        let was_indirect = self.indirect(leaf, index)?;
        let use_indirect = len > max_rec;
        if use_indirect {
            len = 4;
            if was_indirect {
                let id = self.geti(leaf, (i64::from(offset) + key_len) as usize)?;
                let mut cb = ChainedBuffer::open(self.s, id)?;
                cb.set_size(self.s, data.len() as i32, false)?;
                cb.put(self.s, 0, data)?;
            } else {
                // Java assumes the old record is at least 4 bytes
                if old_len < 4 {
                    return Err(BtreeError::Assertion(
                        "record shorter than 4 bytes cannot become indirect",
                    ));
                }
                let mut cb = ChainedBuffer::create(self.s, data.len() as i32, false)?;
                self.puti(
                    leaf,
                    (i64::from(offset) + key_len + old_len - 4) as usize,
                    cb.id(),
                )?;
                self.set_indirect(leaf, index, true)?;
                cb.put(self.s, 0, data)?;
            }
        } else if was_indirect {
            let id = self.geti(leaf, (i64::from(offset) + key_len) as usize)?;
            self.remove_chained(id)?;
            self.set_indirect(leaf, index, false)?;
        }
        if use_indirect || len <= self.leaf_free(leaf)? + old_len {
            let shift = old_len - len;
            if shift != 0 {
                offset = self.move_records(leaf, index + 1, shift)?;
                self.set_koff(leaf, index, offset)?;
                self.put_bytes(leaf, offset as usize, &kbytes)?;
            }
            if !use_indirect {
                self.put_bytes(leaf, offset as usize + kbytes.len(), data)?;
            }
            return self.get_root(leaf);
        }
        // not enough room: remove and add again
        let Some(root) = self.delete_record(leaf, key)? else {
            return Err(BtreeError::Assertion(
                "tree emptied while replacing a record",
            ));
        };
        let l = self.get_leaf(root, key)?;
        self.put_record(l, key, data)
    }

    /// `VarKeyRecordNode.deleteRecord`; `None` when the tree became empty.
    fn delete_record(&mut self, leaf: i32, key: &Field) -> Result<Option<i32>> {
        let Ok(index) = self.leaf_index(leaf, key)? else {
            return Ok(Some(self.get_root(leaf)?));
        };
        let kc = self.cnt(leaf)?;
        if kc == 1 {
            return self.remove_leaf(leaf);
        }
        self.remove(leaf, index)?;
        if index == 0
            && let Some(p) = self.parent(leaf)?
        {
            let k0 = self.leaf_key(leaf, 0)?;
            self.key_changed(p, key, &k0, leaf)?;
        }
        Ok(Some(self.get_root(leaf)?))
    }

    fn remove(&mut self, leaf: i32, index: usize) -> Result<()> {
        let kc = self.cnt(leaf)?;
        if index >= kc {
            return Err(BtreeError::Assertion("remove index"));
        }
        if self.indirect(leaf, index)? {
            let off = self.data_offset(leaf, index)?;
            let id = self.geti(leaf, off as usize)?;
            self.remove_chained(id)?;
            self.set_indirect(leaf, index, false)?;
        }
        let len = self.full_len(leaf, index)?;
        self.move_records(leaf, index + 1, len)?;
        let start = LEAF_HEADER + (index + 1) * LEAF_ENTRY;
        let l = (kc - index - 1) * LEAF_ENTRY;
        self.mv(leaf, start as i64, (start - LEAF_ENTRY) as i64, l as i64)?;
        self.set_cnt(leaf, kc - 1)
    }

    fn remove_leaf(&mut self, leaf: i32) -> Result<Option<i32>> {
        let kc = self.cnt(leaf)?;
        for i in 0..kc {
            if self.indirect(leaf, i)? {
                let off = self.data_offset(leaf, i)?;
                let id = self.geti(leaf, off as usize)?;
                self.remove_chained(id)?;
            }
        }
        let key = self.leaf_key(leaf, 0)?;
        let prev = self.geti(leaf, PREV_LEAF)?;
        let next = self.geti(leaf, NEXT_LEAF)?;
        if prev >= 0 {
            self.puti(prev, NEXT_LEAF, next)?;
        }
        if next >= 0 {
            self.puti(next, PREV_LEAF, prev)?;
        }
        let parent = self.parent(leaf)?;
        self.delete_node(leaf)?;
        match parent {
            None => Ok(None),
            Some(p) => Ok(Some(self.delete_child(p, &key)?)),
        }
    }

    // ---- interior ----

    fn ikoff(&mut self, n: i32, i: usize) -> Result<i32> {
        self.geti(n, NODE_HEADER + i * INT_ENTRY)
    }

    fn set_ikoff(&mut self, n: i32, i: usize, v: i32) -> Result<()> {
        self.puti(n, NODE_HEADER + i * INT_ENTRY, v)
    }

    fn child(&mut self, n: i32, i: usize) -> Result<i32> {
        self.geti(n, NODE_HEADER + i * INT_ENTRY + 4)
    }

    fn ikey(&mut self, n: i32, i: usize) -> Result<Field> {
        let off = self.ikoff(n, i)?;
        self.key_at(n, off)
    }

    fn ikey_len(&mut self, n: i32, i: usize) -> Result<i64> {
        let off = self.ikoff(n, i)?;
        self.key_len_at(n, off)
    }

    fn ifree(&mut self, n: i32) -> Result<i64> {
        let kc = self.cnt(n)?;
        let top = if kc == 0 {
            self.blen(n)?
        } else {
            i64::from(self.ikoff(n, kc - 1)?)
        };
        Ok(top - (kc * INT_ENTRY) as i64 - NODE_HEADER as i64)
    }

    fn move_keys(&mut self, n: i32, index: usize, offset: i64) -> Result<i32> {
        self.move_area(n, NODE_HEADER, INT_ENTRY, index, offset)
    }

    fn id_index(&mut self, n: i32, key: &Field) -> Result<usize> {
        let kc = self.cnt(n)? as i64;
        if kc == 0 {
            return Err(BtreeError::CorruptNode("interior node without keys"));
        }
        let (mut min, mut max) = (1i64, kc - 1);
        while min <= max {
            let i = (min + max) / 2;
            let off = self.ikoff(n, i as usize)?;
            match self.cmp_at(n, key, off)? {
                std::cmp::Ordering::Equal => return Ok(i as usize),
                std::cmp::Ordering::Greater => min = i + 1,
                std::cmp::Ordering::Less => max = i - 1,
            }
        }
        Ok(max as usize)
    }

    fn ikey_index(&mut self, n: i32, key: &Field) -> Result<std::result::Result<usize, usize>> {
        let (mut min, mut max) = (0i64, self.cnt(n)? as i64 - 1);
        while min <= max {
            let i = (min + max) / 2;
            let off = self.ikoff(n, i as usize)?;
            match self.cmp_at(n, key, off)? {
                std::cmp::Ordering::Equal => return Ok(Ok(i as usize)),
                std::cmp::Ordering::Greater => min = i + 1,
                std::cmp::Ordering::Less => max = i - 1,
            }
        }
        Ok(Err(min as usize))
    }

    fn offset_index(&mut self, n: i32, offset: i64) -> Result<usize> {
        let (mut min, mut max) = (0i64, self.cnt(n)? as i64 - 1);
        while min <= max {
            let i = (min + max) / 2;
            let o = i64::from(self.ikoff(n, i as usize)?);
            if o == offset {
                return Ok(i as usize);
            } else if o < offset {
                max = i - 1;
            } else {
                min = i + 1;
            }
        }
        Ok(min as usize)
    }

    fn insert_entry(&mut self, n: i32, index: usize, key: &Field, id: i32) -> Result<()> {
        let kb = key.to_bytes();
        let offset = self.move_keys(n, index, -(kb.len() as i64))?;
        let kc = self.cnt(n)?;
        let start = NODE_HEADER + index * INT_ENTRY;
        let end = NODE_HEADER + kc * INT_ENTRY;
        self.mv(
            n,
            start as i64,
            (start + INT_ENTRY) as i64,
            (end - start) as i64,
        )?;
        self.puti(n, start, offset)?;
        self.puti(n, start + 4, id)?;
        self.put_bytes(n, offset as usize, &kb)?;
        self.set_cnt(n, kc + 1)
    }

    fn update_key(&mut self, n: i32, index: usize, key: &Field) -> Result<()> {
        let kb = key.to_bytes();
        let old_len = self.ikey_len(n, index)?;
        let offset = self.move_keys(n, index + 1, old_len - kb.len() as i64)?;
        self.put_bytes(n, offset as usize, &kb)?;
        self.set_ikoff(n, index, offset)
    }

    fn delete_entry(&mut self, n: i32, index: usize) -> Result<()> {
        let kc = self.cnt(n)?;
        if kc < 3 || index >= kc {
            return Err(BtreeError::Assertion("interior deleteEntry"));
        }
        let move_index = index + 1;
        if move_index < kc {
            let l = self.ikey_len(n, index)?;
            self.move_keys(n, move_index, l)?;
            let start = NODE_HEADER + move_index * INT_ENTRY;
            let end = NODE_HEADER + kc * INT_ENTRY;
            self.mv(
                n,
                start as i64,
                (start - INT_ENTRY) as i64,
                (end - start) as i64,
            )?;
        }
        self.set_cnt(n, kc - 1)
    }

    /// `new VarKeyInteriorNode(nodeMgr, key1, id1, key2, id2)`: parent links are not set.
    fn new_interior(&mut self, k1: &Field, id1: i32, k2: &Field, id2: i32) -> Result<i32> {
        let id = self.new_node(NodeType::VarKeyInterior)?;
        self.insert_entry(id, 0, k1, id1)?;
        self.insert_entry(id, 1, k2, id2)?;
        Ok(id)
    }

    fn key_changed(&mut self, n: i32, old: &Field, new: &Field, child: i32) -> Result<()> {
        let Ok(index) = self.ikey_index(n, old)? else {
            return Err(BtreeError::Assertion("keyChanged: key not found"));
        };
        let len_change = new.length() as i64 - old.length() as i64;
        if len_change > 0 && len_change > self.ifree(n)? {
            return self.split_key_changed(n, index, old, new, child);
        }
        self.update_key(n, index, new)?;
        if index == 0
            && let Some(p) = self.parent(n)?
        {
            self.key_changed(p, old, new, n)?;
        }
        Ok(())
    }

    fn split_point(&mut self, n: i32) -> Result<usize> {
        let kc = self.cnt(n)?;
        let blen = self.blen(n)?;
        let top = if kc == 0 {
            blen
        } else {
            i64::from(self.ikoff(n, kc - 1)?)
        };
        self.offset_index(n, (top + blen) / 2)
    }

    fn split_key_changed(
        &mut self,
        n: i32,
        old_index: usize,
        old: &Field,
        new: &Field,
        child: i32,
    ) -> Result<()> {
        let new_node = self.new_node(NodeType::VarKeyInterior)?;
        let split_index = self.split_point(n)?;
        let kc = self.cnt(n)?;
        self.move_keys_right(n, new_node, kc - split_index)?;
        if split_index > old_index {
            self.update_key(n, old_index, new)?;
            if old_index == 0
                && let Some(p) = self.parent(n)?
            {
                self.key_changed(p, old, new, n)?;
            }
        } else {
            let kc2 = self.cnt(n)?;
            self.update_key(new_node, old_index - kc2, new)?;
            self.set_parent(child, Some(new_node))?;
        }
        if let Some(p) = self.parent(n)? {
            self.insert_node(p, new_node)?;
            if self.parent(new_node)? != Some(p) {
                let k0 = self.ikey(n, 0)?;
                if self.ikey_index(p, &k0)?.is_err() {
                    let np = self.parent(new_node)?;
                    self.set_parent(n, np)?;
                }
            }
            return Ok(());
        }
        let k0 = self.ikey(n, 0)?;
        let k1 = self.ikey(new_node, 0)?;
        let root = self.new_interior(&k0, n, &k1, new_node)?;
        self.set_parent(n, Some(root))?;
        self.set_parent(new_node, Some(root))
    }

    /// `VarKeyInteriorNode.insert(VarKeyNode)`.
    fn insert_node(&mut self, n: i32, node: i32) -> Result<i32> {
        let key = if self.is_leaf(node)? {
            self.leaf_key(node, 0)?
        } else {
            self.ikey(node, 0)?
        };
        if key.length() as i64 + INT_ENTRY as i64 > self.ifree(n)? {
            return self.split_insert(n, &key, node);
        }
        self.insert_id(n, node, &key)
    }

    fn insert_id(&mut self, n: i32, node: i32, key: &Field) -> Result<i32> {
        let Err(index) = self.ikey_index(n, key)? else {
            return Err(BtreeError::Assertion("interior insert: duplicate key"));
        };
        if node == 0 {
            return Err(BtreeError::Assertion("interior insert: id 0"));
        }
        self.insert_entry(n, index, key, node)?;
        self.set_parent(node, Some(n))?;
        if index == 0
            && let Some(p) = self.parent(n)?
        {
            let old = self.ikey(n, 1)?;
            self.key_changed(p, &old, key, n)?;
        }
        self.get_root(n)
    }

    fn split_insert(&mut self, n: i32, new_key: &Field, node: i32) -> Result<i32> {
        let new_node = self.new_node(NodeType::VarKeyInterior)?;
        let kc = self.cnt(n)?;
        let sp = self.split_point(n)?;
        self.move_keys_right(n, new_node, kc - sp)?;
        let right_key = self.ikey(new_node, 0)?;
        if new_key.compare(&right_key)? == std::cmp::Ordering::Less {
            self.insert_id(n, node, new_key)?;
        } else {
            self.insert_id(new_node, node, new_key)?;
        }
        if let Some(p) = self.parent(n)? {
            let root = self.insert_node(p, new_node)?;
            if self.parent(new_node)? != Some(p) {
                let k0 = self.ikey(n, 0)?;
                if self.ikey_index(p, &k0)?.is_err() {
                    let np = self.parent(new_node)?;
                    self.set_parent(n, np)?;
                }
            }
            return Ok(root);
        }
        let k0 = self.ikey(n, 0)?;
        let root = self.new_interior(&k0, n, &right_key, new_node)?;
        self.set_parent(n, Some(root))?;
        self.set_parent(new_node, Some(root))?;
        Ok(root)
    }

    fn delete_child(&mut self, n: i32, key: &Field) -> Result<i32> {
        let Ok(index) = self.ikey_index(n, key)? else {
            return Err(BtreeError::Assertion("deleteChild: key not found"));
        };
        if self.cnt(n)? == 2 {
            if self.parent(n)?.is_some() {
                return Err(BtreeError::Assertion("deleteChild: non-root with 2 keys"));
            }
            let other = self.child(n, 1 - index)?;
            self.load(other)?;
            self.set_parent(other, None)?;
            self.delete_node(n)?;
            return Ok(other);
        }
        self.delete_entry(n, index)?;
        if index == 0
            && let Some(p) = self.parent(n)?
        {
            let k0 = self.ikey(n, 0)?;
            self.key_changed(p, key, &k0, n)?;
        }
        match self.parent(n)? {
            Some(p) => self.balance_child(p, n),
            None => Ok(n),
        }
    }

    fn balance_child(&mut self, p: i32, node: i32) -> Result<i32> {
        let blen = self.blen(p)?;
        let max_key = max_key_length(blen as usize);
        if self.ifree(node)? < HALF_KEY_CAPACITY * (max_key + INT_ENTRY as i64) {
            return self.get_root(p);
        }
        let k0 = self.ikey(node, 0)?;
        let index = self.id_index(p, &k0)?;
        if index == self.cnt(p)? - 1 {
            if index == 0 {
                return Err(BtreeError::Assertion("balanceChild: no sibling"));
            }
            let left = self.child(p, index - 1)?;
            self.balance_pair(p, left, node)
        } else {
            let right = self.child(p, index + 1)?;
            self.balance_pair(p, node, right)
        }
    }

    fn balance_pair(&mut self, p: i32, left: i32, right: i32) -> Result<i32> {
        let lk = self.cnt(left)?;
        let rk = self.cnt(right)?;
        let len = self.blen(p)?;
        let left_space = len - i64::from(self.ikoff(left, lk - 1)?);
        let right_space = len - i64::from(self.ikoff(right, rk - 1)?);
        let right_key = self.ikey(right, 0)?;
        if right_space + (rk * INT_ENTRY) as i64
            <= len - NODE_HEADER as i64 - left_space - (lk * INT_ENTRY) as i64
        {
            self.move_keys_left(left, right, rk)?;
            self.delete_node(right)?;
            return self.delete_child(p, &right_key);
        }
        let half = (left_space + right_space) / 2;
        let balanced = if half < left_space {
            let index = self.offset_index(left, len - half)?;
            self.move_keys_right(left, right, (lk as i64 - index as i64 - 1).max(0) as usize)?
        } else {
            let index = self.offset_index(right, len - half)?;
            self.move_keys_left(left, right, (rk as i64 - index as i64 - 1).max(0) as usize)?
        };
        if balanced {
            let nk = self.ikey(right, 0)?;
            self.key_changed(p, &right_key, &nk, right)?;
        }
        self.get_root(p)
    }

    fn move_keys_right(&mut self, left: i32, right: i32, count: usize) -> Result<bool> {
        if count == 0 {
            return Ok(false);
        }
        let lk = self.cnt(left)?;
        let rk = self.cnt(right)?;
        if count >= lk {
            return Err(BtreeError::Assertion("moveKeysRight count"));
        }
        let left_offset = self.ikoff(left, lk - 1)? as usize;
        let len = self.ikoff(left, lk - count - 1)? as usize - left_offset;
        let right_offset = self.move_keys(right, 0, -(len as i64))? as usize;
        let correction = right_offset as i64 - left_offset as i64;
        self.copy(right, right_offset, left, left_offset, len)?;
        let left_entries = NODE_HEADER + (lk - count) * INT_ENTRY;
        let elen = count * INT_ENTRY;
        self.mv(
            right,
            NODE_HEADER as i64,
            (NODE_HEADER + elen) as i64,
            (rk * INT_ENTRY) as i64,
        )?;
        self.copy(right, NODE_HEADER, left, left_entries, elen)?;
        for i in 0..count {
            let o = i64::from(self.ikoff(right, i)?) + correction;
            self.set_ikoff(right, i, o as i32)?;
        }
        self.set_cnt(left, lk - count)?;
        self.set_cnt(right, rk + count)?;
        Ok(true)
    }

    fn move_keys_left(&mut self, left: i32, right: i32, count: usize) -> Result<bool> {
        if count == 0 {
            return Ok(false);
        }
        let lk = self.cnt(left)?;
        let mut rk = self.cnt(right)?;
        let right_offset = self.ikoff(right, count - 1)? as usize;
        let len = self.blen(right)? as usize - right_offset;
        let left_offset = self.ikoff(left, lk - 1)? as usize - len;
        self.copy(left, left_offset, right, right_offset, len)?;
        let elen = count * INT_ENTRY;
        self.copy(left, NODE_HEADER + lk * INT_ENTRY, right, NODE_HEADER, elen)?;
        let correction = left_offset as i64 - right_offset as i64;
        for i in lk..lk + count {
            let o = i64::from(self.ikoff(left, i)?) + correction;
            self.set_ikoff(left, i, o as i32)?;
        }
        self.set_cnt(left, lk + count)?;
        if count < rk {
            self.move_keys(right, count, len as i64)?;
            rk -= count;
            self.mv(
                right,
                (NODE_HEADER + elen) as i64,
                NODE_HEADER as i64,
                (rk * INT_ENTRY) as i64,
            )?;
            self.set_cnt(right, rk)?;
        }
        Ok(true)
    }
}
