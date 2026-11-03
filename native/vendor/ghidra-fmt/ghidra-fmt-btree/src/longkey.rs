//! Long-key B-tree: `LongKeyInteriorNode` (type 0), `VarRecNode` (1) and `FixedRecNode` (2).
//!
//! ```text
//! interior: | 0 (1) | KeyCount (4) | Key0 (8) | Id0 (4) | ... | KeyN (8) | IdN (4) |
//! var leaf: | 1 (1) | KeyCount (4) | PrevLeafId (4) | NextLeafId (4) |
//!           | Key0 (8) | RecOffset0 (4) | IndFlag0 (1) | ...   ...free...   | RecN | ... | Rec0 |
//! fixed leaf: | 2 (1) | KeyCount (4) | PrevLeafId (4) | NextLeafId (4) | Key0 (8) | Rec0 | ... |
//! ```
//!
//! In an interior node key `i` is the smallest key under child `i`. A variable record whose
//! indirect flag is set stores a 4-byte chained buffer id at its offset instead of the record.

use ghidra_fmt_bytes as bytes;
use ghidra_fmt_chain::ChainedBuffer;
use ghidra_fmt_gbf::BufferStore;

use crate::{BtreeError, NodeType, Result};

const KEY_COUNT_OFFSET: usize = 1;
const INTERIOR_BASE: usize = 5;
const INTERIOR_ENTRY: usize = 12;
const PREV_LEAF_OFFSET: usize = 5;
const NEXT_LEAF_OFFSET: usize = 9;
const LEAF_HEADER: usize = 13;
const KEY_SIZE: usize = 8;
const VAR_ENTRY: usize = KEY_SIZE + 4 + 1;
/// A real tree over 64 K buffers is at most a handful of levels deep.
const MAX_DEPTH: usize = 64;

/// One record: its key and the raw record bytes (not including the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
    /// Primary key.
    pub key: i64,
    /// Serialized non-key fields.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Interior,
    VarRec,
    FixedRec,
}

#[derive(Debug, Clone)]
struct Node {
    id: i32,
    kind: Kind,
    buf: Vec<u8>,
    key_count: i32,
}

impl Node {
    fn load<S: BufferStore + ?Sized>(store: &S, id: i32) -> Result<Self> {
        let buf = store
            .get_buffer(id)?
            .data
            .ok_or(BtreeError::CorruptNode("node buffer is empty"))?;
        let ty = bytes::get_u8(&buf, 0)?;
        let kind = match NodeType::from_byte(ty) {
            Some(NodeType::LongKeyInterior) => Kind::Interior,
            Some(NodeType::LongKeyVarRec) => Kind::VarRec,
            Some(NodeType::LongKeyFixedRec) => Kind::FixedRec,
            Some(
                NodeType::VarKeyInterior
                | NodeType::VarKeyRec
                | NodeType::FixedKeyInterior
                | NodeType::FixedKeyVarRec
                | NodeType::FixedKeyFixedRec,
            ) => return Err(BtreeError::UnsupportedNodeType(ty)),
            _ => {
                return Err(BtreeError::UnexpectedNodeType {
                    found: ty,
                    buffer_id: id,
                });
            }
        };
        let key_count = bytes::get_i32(&buf, KEY_COUNT_OFFSET)?;
        if key_count < 0 {
            return Err(BtreeError::CorruptNode("negative key count"));
        }
        Ok(Self {
            id,
            kind,
            buf,
            key_count,
        })
    }

    fn count(&self) -> usize {
        self.key_count as usize
    }

    fn leaf_entry_size(&self, fixed_len: Option<usize>) -> Result<usize> {
        match self.kind {
            Kind::VarRec => Ok(VAR_ENTRY),
            Kind::FixedRec => Ok(KEY_SIZE + fixed_len.ok_or(BtreeError::MissingFixedLength)?),
            Kind::Interior => Err(BtreeError::CorruptNode("interior node used as leaf")),
        }
    }

    fn key(&self, i: usize, fixed_len: Option<usize>) -> Result<i64> {
        let off = match self.kind {
            Kind::Interior => INTERIOR_BASE + i * INTERIOR_ENTRY,
            _ => LEAF_HEADER + i * self.leaf_entry_size(fixed_len)?,
        };
        Ok(bytes::get_i64(&self.buf, off)?)
    }

    fn child_id(&self, i: usize) -> Result<i32> {
        Ok(bytes::get_i32(
            &self.buf,
            INTERIOR_BASE + i * INTERIOR_ENTRY + KEY_SIZE,
        )?)
    }

    fn prev_leaf(&self) -> Result<i32> {
        Ok(bytes::get_i32(&self.buf, PREV_LEAF_OFFSET)?)
    }

    fn next_leaf(&self) -> Result<i32> {
        Ok(bytes::get_i32(&self.buf, NEXT_LEAF_OFFSET)?)
    }

    /// `LongKeyInteriorNode.getIdIndex`: the child that holds `key`.
    fn id_index(&self, key: i64) -> Result<usize> {
        if self.key_count == 0 {
            return Err(BtreeError::CorruptNode("interior node without keys"));
        }
        let (mut min, mut max) = (1i64, i64::from(self.key_count) - 1);
        while min <= max {
            let i = (min + max) / 2;
            let k = self.key(i as usize, None)?;
            match k.cmp(&key) {
                std::cmp::Ordering::Equal => return Ok(i as usize),
                std::cmp::Ordering::Less => min = i + 1,
                std::cmp::Ordering::Greater => max = i - 1,
            }
        }
        Ok(max as usize)
    }

    /// `LongKeyRecordNode.getKeyIndex`: `Ok(index)` if found, else `Err(insertion point)`.
    fn search(
        &self,
        key: i64,
        fixed_len: Option<usize>,
    ) -> Result<std::result::Result<usize, usize>> {
        let (mut min, mut max) = (0i64, i64::from(self.key_count) - 1);
        while min <= max {
            let i = (min + max) / 2;
            let k = self.key(i as usize, fixed_len)?;
            match k.cmp(&key) {
                std::cmp::Ordering::Equal => return Ok(Ok(i as usize)),
                std::cmp::Ordering::Less => min = i + 1,
                std::cmp::Ordering::Greater => max = i - 1,
            }
        }
        Ok(Err(min as usize))
    }

    fn var_offset(&self, i: usize) -> Result<usize> {
        let off = bytes::get_i32(&self.buf, LEAF_HEADER + i * VAR_ENTRY + KEY_SIZE)?;
        usize::try_from(off).map_err(|_| BtreeError::CorruptNode("negative record offset"))
    }

    fn record<S: BufferStore + ?Sized>(
        &self,
        store: &S,
        i: usize,
        fixed_len: Option<usize>,
    ) -> Result<Record> {
        let key = self.key(i, fixed_len)?;
        let data = match self.kind {
            Kind::FixedRec => {
                let len = fixed_len.ok_or(BtreeError::MissingFixedLength)?;
                let off = LEAF_HEADER + i * (KEY_SIZE + len) + KEY_SIZE;
                bytes::slice(&self.buf, off, len)?.to_vec()
            }
            Kind::VarRec => {
                let off = self.var_offset(i)?;
                let indirect =
                    bytes::get_u8(&self.buf, LEAF_HEADER + i * VAR_ENTRY + KEY_SIZE + 4)? != 0;
                if indirect {
                    let id = bytes::get_i32(&self.buf, off)?;
                    let cb = ChainedBuffer::open(store, id)?;
                    cb.get(store, 0, cb.len() as usize)?
                } else {
                    let end = if i == 0 {
                        self.buf.len()
                    } else {
                        self.var_offset(i - 1)?
                    };
                    let len = end
                        .checked_sub(off)
                        .ok_or(BtreeError::CorruptNode("record offsets out of order"))?;
                    bytes::slice(&self.buf, off, len)?.to_vec()
                }
            }
            Kind::Interior => return Err(BtreeError::CorruptNode("interior node used as leaf")),
        };
        Ok(Record { key, data })
    }

    fn is_leaf(&self) -> bool {
        self.kind != Kind::Interior
    }
}

/// A long-key table B-tree rooted at one buffer.
pub struct LongKeyTree<'a, S: BufferStore + ?Sized> {
    store: &'a S,
    root: i32,
    fixed_len: Option<usize>,
}

impl<'a, S: BufferStore + ?Sized> LongKeyTree<'a, S> {
    /// Tree rooted at buffer `root`. `fixed_len` is the record length from the table schema;
    /// it is only needed when the tree has fixed-record leaves (type 2).
    pub fn new(store: &'a S, root: i32, fixed_len: Option<usize>) -> Self {
        Self {
            store,
            root,
            fixed_len,
        }
    }

    fn load(&self, id: i32) -> Result<Node> {
        Node::load(self.store, id)
    }

    fn descend(&self, mut pick: impl FnMut(&Node) -> Result<usize>) -> Result<Node> {
        let mut node = self.load(self.root)?;
        for _ in 0..MAX_DEPTH {
            if node.is_leaf() {
                return Ok(node);
            }
            let child = node.child_id(pick(&node)?)?;
            node = self.load(child)?;
        }
        Err(BtreeError::TooDeep)
    }

    /// Record with `key`, if present.
    pub fn get(&self, key: i64) -> Result<Option<Record>> {
        let leaf = self.descend(|n| n.id_index(key))?;
        match leaf.search(key, self.fixed_len)? {
            Ok(i) => Ok(Some(leaf.record(self.store, i, self.fixed_len)?)),
            Err(_) => Ok(None),
        }
    }

    /// Iterate all records in key order.
    pub fn records(&self) -> Result<Records<'a, S>> {
        let leaf = self.descend(|_| Ok(0))?;
        Ok(Records {
            store: self.store,
            fixed_len: self.fixed_len,
            leaf: Some(leaf),
            index: 0,
            leaves_left: self.store.index_count().max(0) as usize,
        })
    }

    /// Number of records, counted by walking the leaves.
    pub fn record_count(&self) -> Result<u64> {
        let mut n = 0;
        for r in self.records()? {
            r?;
            n += 1;
        }
        Ok(n)
    }

    /// Port of `isConsistent`: returns one message per violated invariant (empty = consistent).
    pub fn check_consistency(&self) -> Result<Vec<String>> {
        let mut issues = Vec::new();
        let root = self.load(self.root)?;
        self.check_node(&root, &[], &mut issues)?;
        Ok(issues)
    }

    fn check_node(&self, node: &Node, parents: &[&Node], issues: &mut Vec<String>) -> Result<()> {
        if parents.len() > MAX_DEPTH {
            return Err(BtreeError::TooDeep);
        }
        if node.is_leaf() {
            return self.check_leaf(node, parents, issues);
        }
        let mut last_min: Option<i64> = None;
        let mut last_max: Option<i64> = None;
        let mut path: Vec<&Node> = parents.to_vec();
        path.push(node);
        for i in 0..node.count() {
            let key = node.key(i, None)?;
            if let Some(lm) = last_min
                && key <= lm
            {
                issues.push(format!(
                    "node {}: child[{i}].minKey <= child[{}].minKey",
                    node.id,
                    i - 1
                ));
            } else if let Some(lx) = last_max
                && key <= lx
            {
                issues.push(format!(
                    "node {}: child[{i}].minKey <= child[{}].maxKey",
                    node.id,
                    i - 1
                ));
            }
            last_min = Some(key);

            let child = match node.child_id(i).and_then(|id| self.load(id)) {
                Ok(c) => c,
                Err(e) => {
                    issues.push(format!("node {}: failed to fetch child: {e}", node.id));
                    last_max = Some(key); // for lack of a better solution
                    continue;
                }
            };
            if child.key_count == 0 {
                issues.push(format!("node {}: child {} has no keys", node.id, child.id));
                last_max = Some(key);
                continue;
            }
            last_max = Some(child.key(child.count() - 1, self.fixed_len)?);
            let child_key0 = child.key(0, self.fixed_len)?;
            if key != child_key0 {
                issues.push(format!(
                    "node {}: parent key entry mismatch with child[{i}].minKey",
                    node.id
                ));
            }
            self.check_node(&child, &path, issues)?;
        }
        Ok(())
    }

    fn check_leaf(&self, leaf: &Node, parents: &[&Node], issues: &mut Vec<String>) -> Result<()> {
        let mut prev: Option<i64> = None;
        for i in 0..leaf.count() {
            let key = leaf.key(i, self.fixed_len)?;
            if let Some(p) = prev
                && key <= p
            {
                issues.push(format!("leaf {}: key[{i}] <= key[{}]", leaf.id, i - 1));
            }
            prev = Some(key);
        }
        if leaf.key_count == 0 {
            return Ok(());
        }
        let key0 = leaf.key(0, self.fixed_len)?;
        let leftmost = parents.is_empty() || is_leftmost(parents, key0)?;
        if leftmost && leaf.prev_leaf()? >= 0 {
            issues.push(format!("leaf {}: previous-leaf should not exist", leaf.id));
        }
        let next_id = leaf.next_leaf()?;
        if next_id >= 0 {
            let next = self.load(next_id)?;
            if parents.is_empty() || is_rightmost(parents, key0)? {
                issues.push(format!("leaf {}: next-leaf should not exist", leaf.id));
            } else if next.is_leaf() && next.prev_leaf()? != leaf.id {
                issues.push(format!(
                    "leaf {}: next-leaf is not linked to this leaf",
                    leaf.id
                ));
            }
        } else if !parents.is_empty() && !is_rightmost(parents, key0)? {
            issues.push(format!(
                "leaf {}: this leaf is not linked to next-leaf",
                leaf.id
            ));
        }
        Ok(())
    }
}

/// `LongKeyInteriorNode.isLeftmostKey` over the ancestor path (root first).
fn is_leftmost(path: &[&Node], key: i64) -> Result<bool> {
    let Some((node, rest)) = path.split_last() else {
        return Ok(true);
    };
    if node.id_index(key)? == 0 {
        return is_leftmost(rest, key);
    }
    Ok(false)
}

/// `LongKeyInteriorNode.isRightmostKey` over the ancestor path (root first). Note the parent is
/// asked about this node's *first* key, as in Java.
fn is_rightmost(path: &[&Node], key: i64) -> Result<bool> {
    let Some((node, rest)) = path.split_last() else {
        return Ok(true);
    };
    if node.id_index(key)? + 1 == node.count() {
        if rest.is_empty() {
            return Ok(true);
        }
        return is_rightmost(rest, node.key(0, None)?);
    }
    Ok(false)
}

/// Iterator over all records of a tree, in key order.
pub struct Records<'a, S: BufferStore + ?Sized> {
    store: &'a S,
    fixed_len: Option<usize>,
    leaf: Option<Node>,
    index: usize,
    leaves_left: usize,
}

impl<S: BufferStore + ?Sized> Iterator for Records<'_, S> {
    type Item = Result<Record>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let leaf = self.leaf.as_ref()?;
            if self.index < leaf.count() {
                let r = leaf.record(self.store, self.index, self.fixed_len);
                self.index += 1;
                if r.is_err() {
                    self.leaf = None;
                }
                return Some(r);
            }
            let next = match leaf.next_leaf() {
                Ok(n) => n,
                Err(e) => {
                    self.leaf = None;
                    return Some(Err(e));
                }
            };
            if next < 0 {
                self.leaf = None;
                return None;
            }
            if self.leaves_left == 0 {
                self.leaf = None;
                return Some(Err(BtreeError::TooDeep));
            }
            self.leaves_left -= 1;
            match Node::load(self.store, next) {
                Ok(n) if n.is_leaf() => {
                    self.leaf = Some(n);
                    self.index = 0;
                }
                Ok(_) => {
                    self.leaf = None;
                    return Some(Err(BtreeError::CorruptNode("leaf link points at interior")));
                }
                Err(e) => {
                    self.leaf = None;
                    return Some(Err(e));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests;
