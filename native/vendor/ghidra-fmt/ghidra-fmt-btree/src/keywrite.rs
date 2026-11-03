//! Write path shared by the long-key and the fixed-key B-trees: `db.LongKeyInteriorNode`,
//! `db.LongKeyRecordNode`, `db.VarRecNode`, `db.FixedRecNode` and their fixed-key twins
//! `db.FixedKeyInteriorNode`, `db.FixedKeyRecordNode`, `db.FixedKeyVarRecNode`,
//! `db.FixedKeyFixedRecNode`. The two families differ only in the key (8 bytes compared as a
//! signed long, or `keySize` bytes compared as a field of the table's key type) and in the node
//! type bytes, so one implementation serves both; the long-key layout is the fixed-key layout
//! with an 8 byte key.
//!
//! Java never merges leaves; an emptied leaf is removed and interior nodes are rebalanced, and
//! this port does the same operations in the same order so that, from the same operation
//! sequence, the buffers come out byte for byte identical (including stale bytes that Java
//! leaves behind in moved-from regions).
//!
//! Java keeps a `parent` pointer in each node it descended through. Here the same chain is an
//! explicit list of ancestor buffer ids (`path`, root first).

use std::cmp::Ordering;

use ghidra_fmt_bytes as bytes;
use ghidra_fmt_chain::ChainedBuffer;
use ghidra_fmt_field::{Field, FieldType};
use ghidra_fmt_gbf::{BufferStore, BufferStoreMut, DataBuffer};

use crate::{BtreeError, NodeType, Result};

const KEY_COUNT_OFFSET: usize = 1;
const NODE_HEADER: usize = 5;
const LEAF_HEADER: usize = 13;
const PREV_LEAF: usize = 5;
const NEXT_LEAF: usize = 9;
const MAX_DEPTH: usize = 64;

/// How keys compare.
#[derive(Debug, Clone)]
enum KeyCmp {
    /// Eight byte big-endian signed long.
    Long,
    /// A fixed-length field of this type.
    Field(FieldType),
}

impl KeyCmp {
    fn cmp(&self, a: &[u8], b: &[u8]) -> Result<Ordering> {
        match self {
            Self::Long => Ok(bytes::get_i64(a, 0)?.cmp(&bytes::get_i64(b, 0)?)),
            Self::Field(t) => {
                let (fa, _) = Field::read(t, a, 0)?;
                let (fb, _) = Field::read(t, b, 0)?;
                Ok(fa.compare(&fb)?)
            }
        }
    }
}

/// Node family: key size, comparison and node type bytes.
#[derive(Debug, Clone)]
struct Geo {
    ks: usize,
    cmp: KeyCmp,
    interior: NodeType,
    var_leaf: NodeType,
    fixed_leaf: NodeType,
}

impl Geo {
    fn var_entry(&self) -> usize {
        self.ks + 4 + 1
    }
    fn int_entry(&self) -> usize {
        self.ks + 4
    }
    fn fixed_entry(&self, n: usize) -> usize {
        self.ks + n
    }
    fn is_leaf_type(&self, t: u8) -> bool {
        t == self.var_leaf as u8 || t == self.fixed_leaf as u8
    }
}

/// A node buffer held in memory while it is being changed.
#[derive(Clone)]
struct Page {
    id: i32,
    d: Vec<u8>,
}

impl Page {
    fn load<S: BufferStore + ?Sized>(s: &S, id: i32) -> Result<Self> {
        let d = s
            .get_buffer(id)?
            .data
            .ok_or(BtreeError::CorruptNode("node buffer is empty"))?;
        Ok(Self { id, d })
    }

    fn save<S: BufferStoreMut + ?Sized>(&self, s: &mut S) -> Result<()> {
        s.put_buffer(&DataBuffer::new(self.id, self.d.clone()))?;
        Ok(())
    }

    fn len(&self) -> usize {
        self.d.len()
    }

    fn ty(&self) -> u8 {
        self.d.first().copied().unwrap_or(0xff)
    }

    fn i32(&self, off: usize) -> Result<i32> {
        Ok(bytes::get_i32(&self.d, off)?)
    }

    fn set_i32(&mut self, off: usize, v: i32) -> Result<()> {
        Ok(bytes::put_i32(&mut self.d, off, v)?)
    }

    fn key(&self, off: usize, ks: usize) -> Result<Vec<u8>> {
        Ok(bytes::slice(&self.d, off, ks)?.to_vec())
    }

    fn count(&self) -> Result<usize> {
        usize::try_from(self.i32(KEY_COUNT_OFFSET)?)
            .map_err(|_| BtreeError::CorruptNode("negative key count"))
    }

    fn set_count(&mut self, n: usize) -> Result<()> {
        self.set_i32(KEY_COUNT_OFFSET, n as i32)
    }

    /// `DataBuffer.move` (memmove inside the buffer).
    fn mv(&mut self, src: i64, dst: i64, len: i64) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        let n = self.d.len() as i64;
        if src < 0 || dst < 0 || len < 0 || src + len > n || dst + len > n {
            return Err(BtreeError::CorruptNode("buffer move out of range"));
        }
        self.d
            .copy_within(src as usize..(src + len) as usize, dst as usize);
        Ok(())
    }

    /// `DataBuffer.copy(dstOffset, srcBuffer, srcOffset, len)`.
    fn copy_from(&mut self, dst: usize, other: &Page, src: usize, len: usize) -> Result<()> {
        let s = bytes::slice(&other.d, src, len)?;
        Ok(bytes::put_bytes(&mut self.d, dst, s)?)
    }

    fn put_data(&mut self, off: usize, data: &[u8]) -> Result<()> {
        Ok(bytes::put_bytes(&mut self.d, off, data)?)
    }
}

fn new_page<S: BufferStoreMut + ?Sized>(s: &mut S, ty: NodeType) -> Result<Page> {
    let id = s.create_buffer()?;
    let d = s
        .get_buffer(id)?
        .data
        .ok_or(BtreeError::CorruptNode("new buffer is empty"))?;
    let mut p = Page { id, d };
    p.d[0] = ty as u8;
    p.set_count(0)?;
    Ok(p)
}

// ---- interior node primitives ------------------------------------------------------------

fn max_interior_keys(g: &Geo, p: &Page) -> usize {
    (p.len() - NODE_HEADER) / g.int_entry()
}

fn ikey(g: &Geo, p: &Page, i: usize) -> Result<Vec<u8>> {
    p.key(NODE_HEADER + i * g.int_entry(), g.ks)
}

fn ichild(g: &Geo, p: &Page, i: usize) -> Result<i32> {
    p.i32(NODE_HEADER + i * g.int_entry() + g.ks)
}

/// `getIdIndex`.
fn id_index(g: &Geo, p: &Page, key: &[u8]) -> Result<usize> {
    let kc = p.count()? as i64;
    if kc == 0 {
        return Err(BtreeError::CorruptNode("interior node without keys"));
    }
    let (mut min, mut max) = (1i64, kc - 1);
    while min <= max {
        let i = (min + max) / 2;
        let k = ikey(g, p, i as usize)?;
        match g.cmp.cmp(&k, key)? {
            Ordering::Equal => return Ok(i as usize),
            Ordering::Less => min = i + 1,
            Ordering::Greater => max = i - 1,
        }
    }
    Ok(max as usize)
}

/// Interior `getKeyIndex`: `Ok(i)` when present, `Err(insertion point)` otherwise.
fn ikey_index(g: &Geo, p: &Page, key: &[u8]) -> Result<std::result::Result<usize, usize>> {
    let (mut min, mut max) = (0i64, p.count()? as i64 - 1);
    while min <= max {
        let i = (min + max) / 2;
        let k = ikey(g, p, i as usize)?;
        match g.cmp.cmp(&k, key)? {
            Ordering::Equal => return Ok(Ok(i as usize)),
            Ordering::Less => min = i + 1,
            Ordering::Greater => max = i - 1,
        }
    }
    Ok(Err(min as usize))
}

fn put_entry(g: &Geo, p: &mut Page, i: usize, key: &[u8], id: i32) -> Result<()> {
    let off = NODE_HEADER + i * g.int_entry();
    p.put_data(off, key)?;
    p.set_i32(off + g.ks, id)
}

fn insert_entry(g: &Geo, p: &mut Page, index: usize, key: &[u8], id: i32) -> Result<()> {
    let kc = p.count()?;
    let es = g.int_entry();
    let start = NODE_HEADER + index * es;
    let end = NODE_HEADER + kc * es;
    p.mv(start as i64, (start + es) as i64, (end - start) as i64)?;
    p.put_data(start, key)?;
    p.set_i32(start + g.ks, id)?;
    p.set_count(kc + 1)
}

fn delete_entry(g: &Geo, p: &mut Page, index: usize) -> Result<()> {
    let kc = p.count()?;
    if kc < 3 || index >= kc {
        return Err(BtreeError::Assertion("interior deleteEntry"));
    }
    let es = g.int_entry();
    let index = index + 1;
    if index < kc {
        let start = NODE_HEADER + index * es;
        let end = NODE_HEADER + kc * es;
        p.mv(start as i64, (start - es) as i64, (end - start) as i64)?;
    }
    p.set_count(kc - 1)
}

fn move_keys_right(g: &Geo, left: &mut Page, right: &mut Page, count: usize) -> Result<()> {
    let es = g.int_entry();
    let lk = left.count()?;
    let rk = right.count()?;
    if count > lk {
        return Err(BtreeError::Assertion("moveKeysRight count"));
    }
    let left_offset = NODE_HEADER + (lk - count) * es;
    let len = count * es;
    right.mv(
        NODE_HEADER as i64,
        (NODE_HEADER + len) as i64,
        (rk * es) as i64,
    )?;
    right.copy_from(NODE_HEADER, left, left_offset, len)?;
    left.set_count(lk - count)?;
    right.set_count(rk + count)
}

fn move_keys_left(g: &Geo, left: &mut Page, right: &mut Page, count: usize) -> Result<()> {
    let es = g.int_entry();
    let lk = left.count()?;
    let mut rk = right.count()?;
    let left_offset = NODE_HEADER + lk * es;
    let len = count * es;
    left.copy_from(left_offset, right, NODE_HEADER, len)?;
    left.set_count(lk + count)?;
    if count < rk {
        rk -= count;
        right.mv(
            (NODE_HEADER + len) as i64,
            NODE_HEADER as i64,
            (rk * es) as i64,
        )?;
        right.set_count(rk)?;
    }
    Ok(())
}

// ---- leaf primitives ---------------------------------------------------------------------

fn leaf_search(
    g: &Geo,
    p: &Page,
    key: &[u8],
    entry: usize,
) -> Result<std::result::Result<usize, usize>> {
    let (mut min, mut max) = (0i64, p.count()? as i64 - 1);
    while min <= max {
        let i = (min + max) / 2;
        let k = p.key(LEAF_HEADER + i as usize * entry, g.ks)?;
        match g.cmp.cmp(&k, key)? {
            Ordering::Equal => return Ok(Ok(i as usize)),
            Ordering::Less => min = i + 1,
            Ordering::Greater => max = i - 1,
        }
    }
    Ok(Err(min as usize))
}

fn var_off(g: &Geo, p: &Page, i: usize) -> Result<i32> {
    p.i32(LEAF_HEADER + i * g.var_entry() + g.ks)
}

fn set_var_off(g: &Geo, p: &mut Page, i: usize, off: i32) -> Result<()> {
    p.set_i32(LEAF_HEADER + i * g.var_entry() + g.ks, off)
}

fn var_indirect(g: &Geo, p: &Page, i: usize) -> Result<bool> {
    Ok(bytes::get_u8(&p.d, LEAF_HEADER + i * g.var_entry() + g.ks + 4)? != 0)
}

fn set_var_indirect(g: &Geo, p: &mut Page, i: usize, on: bool) -> Result<()> {
    Ok(bytes::put_u8(
        &mut p.d,
        LEAF_HEADER + i * g.var_entry() + g.ks + 4,
        u8::from(on),
    )?)
}

fn leaf_key(g: &Geo, p: &Page, i: usize, fixed_len: Option<usize>) -> Result<Vec<u8>> {
    match p.ty() {
        t if t == g.var_leaf as u8 => p.key(LEAF_HEADER + i * g.var_entry(), g.ks),
        t if t == g.fixed_leaf as u8 => {
            let n = fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            p.key(LEAF_HEADER + i * g.fixed_entry(n), g.ks)
        }
        _ => Err(BtreeError::CorruptNode("not a leaf")),
    }
}

fn var_free_space(g: &Geo, p: &Page) -> Result<i64> {
    let kc = p.count()?;
    let top = if kc == 0 {
        p.len() as i64
    } else {
        i64::from(var_off(g, p, kc - 1)?)
    };
    Ok(top - (kc * g.var_entry()) as i64 - LEAF_HEADER as i64)
}

fn var_record_len(g: &Geo, p: &Page, i: usize) -> Result<i64> {
    if i == 0 {
        Ok(p.len() as i64 - i64::from(var_off(g, p, 0)?))
    } else {
        Ok(i64::from(var_off(g, p, i - 1)?) - i64::from(var_off(g, p, i)?))
    }
}

fn var_record_len_at(g: &Geo, p: &Page, i: usize, off: i32) -> Result<i64> {
    if i == 0 {
        Ok(p.len() as i64 - i64::from(off))
    } else {
        Ok(i64::from(var_off(g, p, i - 1)?) - i64::from(off))
    }
}

/// `VarRecNode.moveRecords`.
fn var_move_records(g: &Geo, p: &mut Page, index: usize, offset: i64) -> Result<i32> {
    let kc = p.count()?;
    if index == kc {
        if index == 0 {
            return Ok((p.len() as i64 + offset) as i32);
        }
        return Ok((i64::from(var_off(g, p, kc - 1)?) + offset) as i32);
    }
    let start = i64::from(var_off(g, p, kc - 1)?);
    let end = if index == 0 {
        p.len() as i64
    } else {
        i64::from(var_off(g, p, index - 1)?)
    };
    p.mv(start, start + offset, end - start)?;
    for i in index..kc {
        let o = i64::from(var_off(g, p, i)?) + offset;
        set_var_off(g, p, i, o as i32)?;
    }
    Ok((end + offset) as i32)
}

fn var_max_record_len(g: &Geo, p: &Page) -> i64 {
    (((p.len() - LEAF_HEADER) >> 2) as i64) - g.var_entry() as i64
}

fn var_split_index(g: &Geo, p: &Page) -> Result<usize> {
    let kc = p.count()?;
    let top = if kc == 0 {
        p.len() as i64
    } else {
        i64::from(var_off(g, p, kc - 1)?)
    };
    let halfway = (top + p.len() as i64) / 2;
    let (mut min, mut max) = (1i64, kc as i64 - 1);
    while min < max {
        let i = (min + max) / 2;
        let off = i64::from(var_off(g, p, i as usize)?);
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

fn var_split_data(g: &Geo, left: &mut Page, right: &mut Page) -> Result<()> {
    let es = g.var_entry();
    let kc = left.count()?;
    let split_index = var_split_index(g, left)?;
    let count = kc - split_index;
    let start = var_off(g, left, kc - 1)? as usize;
    let end = var_off(g, left, split_index - 1)? as usize;
    let split_len = end - start;
    let right_offset = left.len() - split_len;
    right.copy_from(right_offset, left, start, split_len)?;
    right.copy_from(
        LEAF_HEADER,
        left,
        LEAF_HEADER + split_index * es,
        count * es,
    )?;
    let correction = (left.len() - end) as i64;
    for i in 0..count {
        let o = i64::from(var_off(g, right, i)?) + correction;
        set_var_off(g, right, i, o as i32)?;
    }
    left.set_count(kc - count)?;
    right.set_count(count)
}

fn fixed_shift(g: &Geo, p: &mut Page, index: usize, right: bool, n: usize) -> Result<()> {
    let kc = p.count()?;
    if index == kc {
        return Ok(());
    }
    let es = g.fixed_entry(n);
    let start = LEAF_HEADER + index * es;
    let end = LEAF_HEADER + kc * es;
    let dst = if right { start + es } else { start - es };
    p.mv(start as i64, dst as i64, (end - start) as i64)
}

fn fixed_split_data(g: &Geo, left: &mut Page, right: &mut Page, n: usize) -> Result<()> {
    let kc = left.count()?;
    let es = g.fixed_entry(n);
    let split_index = kc / 2;
    let count = kc - split_index;
    let start = LEAF_HEADER + split_index * es;
    let end = LEAF_HEADER + kc * es;
    right.copy_from(LEAF_HEADER, left, start, end - start)?;
    left.set_count(kc - count)?;
    right.set_count(count)
}

/// Writer for one long-key table tree. It holds the root buffer id (`-1` while the table has
/// no records) and the fixed record length (`None` for variable-length records).
#[derive(Debug, Clone)]
pub struct LongKeyWriter {
    inner: TreeWriter,
}

impl LongKeyWriter {
    /// Writer for the tree rooted at `root` (`-1` for an empty table).
    pub fn new(root: i32, fixed_len: Option<usize>) -> Self {
        Self {
            inner: TreeWriter::new(
                Geo {
                    ks: 8,
                    cmp: KeyCmp::Long,
                    interior: NodeType::LongKeyInterior,
                    var_leaf: NodeType::LongKeyVarRec,
                    fixed_leaf: NodeType::LongKeyFixedRec,
                },
                root,
                fixed_len,
            ),
        }
    }

    /// Current root buffer id, `-1` when the table is empty.
    pub fn root(&self) -> i32 {
        self.inner.root
    }

    /// Insert or replace the record for `key` (`Table.putRecord` on a long-key table).
    /// `data` is the serialized non-key part of the record. Returns true when a new record was
    /// added, false when an existing one was replaced.
    pub fn put<S: BufferStoreMut + ?Sized>(
        &mut self,
        s: &mut S,
        key: i64,
        data: &[u8],
    ) -> Result<bool> {
        self.inner.put(s, &key.to_be_bytes(), data)
    }

    /// Remove the record for `key` (`Table.deleteRecord`). Returns whether it existed.
    pub fn delete<S: BufferStoreMut + ?Sized>(&mut self, s: &mut S, key: i64) -> Result<bool> {
        self.inner.delete(s, &key.to_be_bytes())
    }
}

/// Writer for one fixed-key table tree (node types 5 to 7): the key type must have a fixed
/// length; keys are passed as their stored bytes.
#[derive(Debug, Clone)]
pub struct FixedKeyWriter {
    inner: TreeWriter,
}

impl FixedKeyWriter {
    /// Writer for the tree rooted at `root` (`-1` for an empty table) with keys of `key_type`.
    pub fn new(root: i32, key_type: &FieldType, fixed_len: Option<usize>) -> Result<Self> {
        let ks = key_type.fixed_length().ok_or(BtreeError::CorruptNode(
            "fixed-key tree with variable key type",
        ))?;
        Ok(Self {
            inner: TreeWriter::new(
                Geo {
                    ks,
                    cmp: KeyCmp::Field(key_type.clone()),
                    interior: NodeType::FixedKeyInterior,
                    var_leaf: NodeType::FixedKeyVarRec,
                    fixed_leaf: NodeType::FixedKeyFixedRec,
                },
                root,
                fixed_len,
            ),
        })
    }

    /// Current root buffer id, `-1` when the table is empty.
    pub fn root(&self) -> i32 {
        self.inner.root
    }

    /// Insert or replace; `key` is the stored key bytes, `data` the serialized record body.
    /// Returns true when a new record was added.
    pub fn put<S: BufferStoreMut + ?Sized>(
        &mut self,
        s: &mut S,
        key: &Field,
        data: &[u8],
    ) -> Result<bool> {
        self.inner.put(s, &key.to_bytes(), data)
    }

    /// Remove the record for `key`. Returns whether it existed.
    pub fn delete<S: BufferStoreMut + ?Sized>(&mut self, s: &mut S, key: &Field) -> Result<bool> {
        self.inner.delete(s, &key.to_bytes())
    }
}

#[derive(Debug, Clone)]
struct TreeWriter {
    g: Geo,
    root: i32,
    fixed_len: Option<usize>,
}

impl TreeWriter {
    fn new(g: Geo, root: i32, fixed_len: Option<usize>) -> Self {
        Self { g, root, fixed_len }
    }

    fn entry(&self, p: &Page) -> Result<usize> {
        match p.ty() {
            t if t == self.g.var_leaf as u8 => Ok(self.g.var_entry()),
            t if t == self.g.fixed_leaf as u8 => Ok(self
                .g
                .fixed_entry(self.fixed_len.ok_or(BtreeError::MissingFixedLength)?)),
            _ => Err(BtreeError::CorruptNode("not a leaf")),
        }
    }

    fn lk(&self, p: &Page, i: usize) -> Result<Vec<u8>> {
        leaf_key(&self.g, p, i, self.fixed_len)
    }

    /// Walk from the root to the leaf for `key`; returns the leaf id and its ancestors.
    fn descend<S: BufferStore + ?Sized>(
        &self,
        s: &S,
        root: i32,
        key: &[u8],
    ) -> Result<(i32, Vec<i32>)> {
        let mut path = Vec::new();
        let mut id = root;
        for _ in 0..MAX_DEPTH {
            let p = Page::load(s, id)?;
            if p.ty() == self.g.interior as u8 {
                let child = ichild(&self.g, &p, id_index(&self.g, &p, key)?)?;
                path.push(id);
                id = child;
            } else if self.g.is_leaf_type(p.ty()) {
                return Ok((id, path));
            } else {
                return Err(BtreeError::UnexpectedNodeType {
                    found: p.ty(),
                    buffer_id: id,
                });
            }
        }
        Err(BtreeError::TooDeep)
    }

    fn new_leaf<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        prev: i32,
        next: i32,
    ) -> Result<Page> {
        let ty = if self.fixed_len.is_some() {
            self.g.fixed_leaf
        } else {
            self.g.var_leaf
        };
        let mut p = new_page(s, ty)?;
        p.set_i32(PREV_LEAF, prev)?;
        p.set_i32(NEXT_LEAF, next)?;
        Ok(p)
    }

    fn put<S: BufferStoreMut + ?Sized>(
        &mut self,
        s: &mut S,
        key: &[u8],
        data: &[u8],
    ) -> Result<bool> {
        if key.len() != self.g.ks {
            return Err(BtreeError::Assertion(
                "key length does not match the key type",
            ));
        }
        if let Some(n) = self.fixed_len
            && data.len() != n
        {
            return Err(BtreeError::BadRecordLength {
                expected: n,
                actual: data.len(),
            });
        }
        if self.root < 0 {
            let leaf = self.new_leaf(s, -1, -1)?;
            leaf.save(s)?;
            self.root = leaf.id;
        }
        let (leaf_id, path) = self.descend(s, self.root, key)?;
        let leaf = Page::load(s, leaf_id)?;
        let existed = leaf_search(&self.g, &leaf, key, self.entry(&leaf)?)?.is_ok();
        self.root = self.put_record(s, leaf_id, path, key, data)?;
        Ok(!existed)
    }

    fn delete<S: BufferStoreMut + ?Sized>(&mut self, s: &mut S, key: &[u8]) -> Result<bool> {
        if self.root < 0 {
            return Ok(false);
        }
        let (leaf_id, path) = self.descend(s, self.root, key)?;
        match self.delete_record(s, leaf_id, &path, key)? {
            Some(root) => {
                self.root = root.0;
                Ok(root.1)
            }
            None => {
                self.root = -1;
                Ok(true)
            }
        }
    }

    // ---- leaf level ----

    fn put_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf_id: i32,
        mut path: Vec<i32>,
        key: &[u8],
        data: &[u8],
    ) -> Result<i32> {
        for _ in 0..MAX_DEPTH * 4 {
            let mut leaf = Page::load(s, leaf_id)?;
            let entry = self.entry(&leaf)?;
            match leaf_search(&self.g, &leaf, key, entry)? {
                Ok(index) => return self.update_record(s, leaf, &path, index, key, data),
                Err(index) => {
                    if self.insert_record(s, &mut leaf, index, key, data)? {
                        leaf.save(s)?;
                        if index == 0 && !path.is_empty() {
                            let k1 = self.lk(&leaf, 1)?;
                            self.key_changed(s, &path, &k1, key)?;
                        }
                        return Ok(path.first().copied().unwrap_or(leaf_id));
                    }
                    if index == leaf.count()? {
                        return self.append_new_leaf(s, leaf, &path, key, data);
                    }
                    let root = self.split(s, leaf, &path)?;
                    let (l, p) = self.descend(s, root, key)?;
                    leaf_id = l;
                    path = p;
                }
            }
        }
        Err(BtreeError::TooDeep)
    }

    /// Returns `(root, existed)`, or `None` when the tree became empty.
    fn delete_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf_id: i32,
        path: &[i32],
        key: &[u8],
    ) -> Result<Option<(i32, bool)>> {
        let mut leaf = Page::load(s, leaf_id)?;
        let entry = self.entry(&leaf)?;
        let Ok(index) = leaf_search(&self.g, &leaf, key, entry)? else {
            return Ok(Some((path.first().copied().unwrap_or(leaf_id), false)));
        };
        if leaf.count()? == 1 {
            return Ok(self.remove_leaf(s, leaf, path)?.map(|r| (r, true)));
        }
        self.remove(s, &mut leaf, index)?;
        leaf.save(s)?;
        if index == 0 && !path.is_empty() {
            let k0 = self.lk(&leaf, 0)?;
            self.key_changed(s, path, key, &k0)?;
        }
        Ok(Some((path.first().copied().unwrap_or(leaf_id), true)))
    }

    fn remove<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf: &mut Page,
        index: usize,
    ) -> Result<()> {
        let g = &self.g;
        let kc = leaf.count()?;
        if index >= kc {
            return Err(BtreeError::Assertion("remove index"));
        }
        if leaf.ty() == g.fixed_leaf as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            fixed_shift(g, leaf, index + 1, false, n)?;
            return leaf.set_count(kc - 1);
        }
        if var_indirect(g, leaf, index)? {
            let id = leaf.i32(var_off(g, leaf, index)? as usize)?;
            remove_chained(s, id)?;
            set_var_indirect(g, leaf, index, false)?;
        }
        let len = var_record_len(g, leaf, index)?;
        var_move_records(g, leaf, index + 1, len)?;
        let es = g.var_entry();
        let start = LEAF_HEADER + (index + 1) * es;
        let l = (kc - index - 1) * es;
        leaf.mv(start as i64, (start - es) as i64, l as i64)?;
        leaf.set_count(kc - 1)
    }

    fn insert_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf: &mut Page,
        index: usize,
        key: &[u8],
        data: &[u8],
    ) -> Result<bool> {
        let g = &self.g;
        let kc = leaf.count()?;
        if leaf.ty() == g.fixed_leaf as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            if kc == (leaf.len() - LEAF_HEADER) / g.fixed_entry(n) {
                return Ok(false);
            }
            fixed_shift(g, leaf, index, true, n)?;
            let off = LEAF_HEADER + index * g.fixed_entry(n);
            leaf.put_data(off, key)?;
            leaf.put_data(off + g.ks, data)?;
            leaf.set_count(kc + 1)?;
            return Ok(true);
        }
        let mut len = data.len() as i64;
        let use_indirect = len > var_max_record_len(g, leaf);
        if use_indirect {
            len = 4;
        }
        if len + g.var_entry() as i64 > var_free_space(g, leaf)? {
            return Ok(false);
        }
        let offset = var_move_records(g, leaf, index, -len)?;
        let es = g.var_entry();
        let start = LEAF_HEADER + index * es;
        leaf.mv(
            start as i64,
            (start + es) as i64,
            ((kc - index) * es) as i64,
        )?;
        leaf.put_data(start, key)?;
        leaf.set_i32(start + g.ks, offset)?;
        leaf.set_count(kc + 1)?;
        if use_indirect {
            let mut cb = ChainedBuffer::create(s, data.len() as i32, false)?;
            leaf.set_i32(offset as usize, cb.id())?;
            cb.put(s, 0, data)?;
        } else {
            leaf.put_data(offset as usize, data)?;
        }
        set_var_indirect(g, leaf, index, use_indirect)?;
        Ok(true)
    }

    fn update_record<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf: Page,
        path: &[i32],
        index: usize,
        key: &[u8],
        data: &[u8],
    ) -> Result<i32> {
        let g = &self.g;
        let leaf_id = leaf.id;
        let root = path.first().copied().unwrap_or(leaf_id);
        if leaf.ty() == g.fixed_leaf as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            let off = LEAF_HEADER + index * g.fixed_entry(n) + g.ks;
            leaf.put_data(off, data)?;
            leaf.save(s)?;
            return Ok(root);
        }
        let mut offset = var_off(g, &leaf, index)?;
        let old_len = var_record_len_at(g, &leaf, index, offset)?;
        let mut len = data.len() as i64;
        let was_indirect = var_indirect(g, &leaf, index)?;
        let use_indirect = len > var_max_record_len(g, &leaf);
        if use_indirect {
            len = 4;
            if was_indirect {
                let id = leaf.i32(offset as usize)?;
                let mut cb = ChainedBuffer::open(s, id)?;
                cb.set_size(s, data.len() as i32, false)?;
                cb.put(s, 0, data)?;
            } else {
                // Java assumes the old record is at least 4 bytes (a variable-length schema
                // always stores a 4 byte length prefix); a shorter one would be corrupted
                if old_len < 4 {
                    return Err(BtreeError::Assertion(
                        "record shorter than 4 bytes cannot become indirect",
                    ));
                }
                let mut cb = ChainedBuffer::create(s, data.len() as i32, false)?;
                leaf.set_i32((i64::from(offset) + old_len - 4) as usize, cb.id())?;
                set_var_indirect(g, &mut leaf, index, true)?;
                cb.put(s, 0, data)?;
            }
        } else if was_indirect {
            let id = leaf.i32(offset as usize)?;
            remove_chained(s, id)?;
            set_var_indirect(g, &mut leaf, index, false)?;
        }
        if use_indirect || len <= var_free_space(g, &leaf)? + old_len {
            let shift = old_len - len;
            if shift != 0 {
                offset = var_move_records(g, &mut leaf, index + 1, shift)?;
                set_var_off(g, &mut leaf, index, offset)?;
            }
            if !use_indirect {
                leaf.put_data(offset as usize, data)?;
            }
            leaf.save(s)?;
            return Ok(root);
        }
        // not enough room: remove and add again
        leaf.save(s)?;
        let Some((new_root, _)) = self.delete_record(s, leaf_id, path, key)? else {
            return Err(BtreeError::Assertion(
                "tree emptied while replacing a record",
            ));
        };
        let (l, p) = self.descend(s, new_root, key)?;
        self.put_record(s, l, p, key, data)
    }

    fn append_new_leaf<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf: Page,
        path: &[i32],
        key: &[u8],
        data: &[u8],
    ) -> Result<i32> {
        let mut new_leaf = self.new_leaf(s, -1, -1)?;
        self.insert_record(s, &mut new_leaf, 0, key, data)?;
        // appendLeaf
        new_leaf.set_i32(PREV_LEAF, leaf.id)?;
        let right_id = leaf.i32(NEXT_LEAF)?;
        new_leaf.set_i32(NEXT_LEAF, right_id)?;
        leaf.set_i32(NEXT_LEAF, new_leaf.id)?;
        new_leaf.save(s)?;
        leaf.save(s)?;
        if right_id >= 0 {
            let mut right = Page::load(s, right_id)?;
            right.set_i32(PREV_LEAF, new_leaf.id)?;
            right.save(s)?;
        }
        let first_key = self.lk(&new_leaf, 0)?;
        if let Some((&parent, anc)) = path.split_last() {
            return self.interior_insert(s, anc, parent, new_leaf.id, &first_key);
        }
        let k0 = self.lk(&leaf, 0)?;
        self.new_root(s, &k0, leaf.id, &first_key, new_leaf.id)
    }

    fn split<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        mut leaf: Page,
        path: &[i32],
    ) -> Result<i32> {
        let old_sibling = leaf.i32(NEXT_LEAF)?;
        let mut new_leaf = self.new_leaf(s, leaf.id, old_sibling)?;
        leaf.set_i32(NEXT_LEAF, new_leaf.id)?;
        if old_sibling >= 0 {
            let mut sib = Page::load(s, old_sibling)?;
            sib.set_i32(PREV_LEAF, new_leaf.id)?;
            sib.save(s)?;
        }
        if leaf.ty() == self.g.fixed_leaf as u8 {
            let n = self.fixed_len.ok_or(BtreeError::MissingFixedLength)?;
            fixed_split_data(&self.g, &mut leaf, &mut new_leaf, n)?;
        } else {
            var_split_data(&self.g, &mut leaf, &mut new_leaf)?;
        }
        leaf.save(s)?;
        new_leaf.save(s)?;
        let right_key = self.lk(&new_leaf, 0)?;
        if let Some((&parent, anc)) = path.split_last() {
            return self.interior_insert(s, anc, parent, new_leaf.id, &right_key);
        }
        let k0 = self.lk(&leaf, 0)?;
        self.new_root(s, &k0, leaf.id, &right_key, new_leaf.id)
    }

    /// `removeLeaf`; `None` when the whole tree became empty.
    fn remove_leaf<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        leaf: Page,
        path: &[i32],
    ) -> Result<Option<i32>> {
        let g = &self.g;
        if leaf.ty() == g.var_leaf as u8 {
            for i in 0..leaf.count()? {
                if var_indirect(g, &leaf, i)? {
                    let id = leaf.i32(var_off(g, &leaf, i)? as usize)?;
                    remove_chained(s, id)?;
                }
            }
        }
        let key = self.lk(&leaf, 0)?;
        let prev = leaf.i32(PREV_LEAF)?;
        let next = leaf.i32(NEXT_LEAF)?;
        if prev >= 0 {
            let mut p = Page::load(s, prev)?;
            p.set_i32(NEXT_LEAF, next)?;
            p.save(s)?;
        }
        if next >= 0 {
            let mut n = Page::load(s, next)?;
            n.set_i32(PREV_LEAF, prev)?;
            n.save(s)?;
        }
        s.delete_buffer(leaf.id)?;
        match path.split_last() {
            None => Ok(None),
            Some((&parent, anc)) => Ok(Some(self.delete_child(s, anc, parent, &key)?)),
        }
    }

    // ---- interior level ----

    fn new_root<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        key1: &[u8],
        id1: i32,
        key2: &[u8],
        id2: i32,
    ) -> Result<i32> {
        let mut n = new_page(s, self.g.interior)?;
        n.set_count(2)?;
        put_entry(&self.g, &mut n, 0, key1, id1)?;
        put_entry(&self.g, &mut n, 1, key2, id2)?;
        n.save(s)?;
        Ok(n.id)
    }

    /// `keyChanged` on the last node of `path` (the parent of the node whose first key changed).
    fn key_changed<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        path: &[i32],
        old: &[u8],
        new: &[u8],
    ) -> Result<()> {
        let Some((&pid, anc)) = path.split_last() else {
            return Ok(());
        };
        let mut p = Page::load(s, pid)?;
        let Ok(index) = ikey_index(&self.g, &p, old)? else {
            return Err(BtreeError::Assertion("keyChanged: key not found"));
        };
        p.put_data(NODE_HEADER + index * self.g.int_entry(), new)?;
        p.save(s)?;
        if index == 0 && !anc.is_empty() {
            self.key_changed(s, anc, old, new)?;
        }
        Ok(())
    }

    /// `InteriorNode.insert` on node `node_id` whose ancestors are `anc`.
    fn interior_insert<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        node_id: i32,
        id: i32,
        key: &[u8],
    ) -> Result<i32> {
        let g = &self.g;
        let mut n = Page::load(s, node_id)?;
        if n.count()? == max_interior_keys(g, &n) {
            return self.interior_split(s, anc, n, key, id);
        }
        let Err(index) = ikey_index(g, &n, key)? else {
            return Err(BtreeError::Assertion("interior insert: duplicate key"));
        };
        if id == 0 {
            return Err(BtreeError::Assertion("interior insert: id 0"));
        }
        insert_entry(g, &mut n, index, key, id)?;
        n.save(s)?;
        if index == 0 && !anc.is_empty() {
            let k1 = ikey(g, &n, 1)?;
            self.key_changed(s, anc, &k1, key)?;
        }
        Ok(anc.first().copied().unwrap_or(node_id))
    }

    fn interior_split<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        mut left: Page,
        new_key: &[u8],
        new_id: i32,
    ) -> Result<i32> {
        let g = &self.g;
        let mut right = new_page(s, g.interior)?;
        let half = left.count()? / 2;
        move_keys_right(g, &mut left, &mut right, half)?;
        left.save(s)?;
        right.save(s)?;
        let right_key = ikey(g, &right, 0)?;
        if g.cmp.cmp(new_key, &right_key)? == Ordering::Less {
            self.interior_insert(s, anc, left.id, new_id, new_key)?;
        } else {
            // the new node has no parent link yet: it cannot be the target of keyChanged
            self.interior_insert(s, &[], right.id, new_id, new_key)?;
        }
        let left = Page::load(s, left.id)?;
        if let Some((&parent, anc2)) = anc.split_last() {
            return self.interior_insert(s, anc2, parent, right.id, &right_key);
        }
        let k0 = ikey(g, &left, 0)?;
        self.new_root(s, &k0, left.id, &right_key, right.id)
    }

    /// `deleteChild` on node `node_id` (ancestors `anc`); returns the root id.
    fn delete_child<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        node_id: i32,
        key: &[u8],
    ) -> Result<i32> {
        let g = &self.g;
        let mut n = Page::load(s, node_id)?;
        let Ok(index) = ikey_index(g, &n, key)? else {
            return Err(BtreeError::Assertion("deleteChild: key not found"));
        };
        if n.count()? == 2 {
            if !anc.is_empty() {
                return Err(BtreeError::Assertion("deleteChild: non-root with 2 keys"));
            }
            let other = ichild(g, &n, 1 - index)?;
            s.delete_buffer(n.id)?;
            return Ok(other);
        }
        delete_entry(g, &mut n, index)?;
        n.save(s)?;
        if index == 0 && !anc.is_empty() {
            let k0 = ikey(g, &n, 0)?;
            self.key_changed(s, anc, key, &k0)?;
        }
        match anc.split_last() {
            Some((&parent, anc2)) => self.balance_child(s, anc2, parent, node_id),
            None => Ok(node_id),
        }
    }

    /// `balanceChild(node)` on the parent `parent_id` (ancestors `anc`).
    fn balance_child<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        parent_id: i32,
        node_id: i32,
    ) -> Result<i32> {
        let g = &self.g;
        let parent = Page::load(s, parent_id)?;
        let node = Page::load(s, node_id)?;
        let root = anc.first().copied().unwrap_or(parent_id);
        if node.count()? > max_interior_keys(g, &parent) / 2 {
            return Ok(root);
        }
        let index = id_index(g, &parent, &ikey(g, &node, 0)?)?;
        if index == parent.count()? - 1 {
            if index == 0 {
                return Err(BtreeError::Assertion("balanceChild: no sibling"));
            }
            let left = ichild(g, &parent, index - 1)?;
            self.balance_pair(s, anc, parent, left, node_id)
        } else {
            let right = ichild(g, &parent, index + 1)?;
            self.balance_pair(s, anc, parent, node_id, right)
        }
    }

    fn balance_pair<S: BufferStoreMut + ?Sized>(
        &self,
        s: &mut S,
        anc: &[i32],
        parent: Page,
        left_id: i32,
        right_id: i32,
    ) -> Result<i32> {
        let g = &self.g;
        let mut left = Page::load(s, left_id)?;
        let mut right = Page::load(s, right_id)?;
        let right_key = ikey(g, &right, 0)?;
        let lk = left.count()?;
        let rk = right.count()?;
        let mut new_left = lk + rk;
        if new_left <= max_interior_keys(g, &parent) {
            move_keys_left(g, &mut left, &mut right, rk)?;
            left.save(s)?;
            s.delete_buffer(right.id)?;
            return self.delete_child(s, anc, parent.id, &right_key);
        }
        new_left /= 2;
        if new_left < lk {
            move_keys_right(g, &mut left, &mut right, lk - new_left)?;
        } else if new_left > lk {
            move_keys_left(g, &mut left, &mut right, new_left - lk)?;
        }
        left.save(s)?;
        right.save(s)?;
        let new_right_key = ikey(g, &right, 0)?;
        let mut chain = anc.to_vec();
        chain.push(parent.id);
        self.key_changed(s, &chain, &right_key, &new_right_key)?;
        Ok(anc.first().copied().unwrap_or(parent.id))
    }
}

fn remove_chained<S: BufferStoreMut + ?Sized>(s: &mut S, id: i32) -> Result<()> {
    let mut cb = ChainedBuffer::open(s, id)?;
    cb.delete(s)?;
    Ok(())
}
