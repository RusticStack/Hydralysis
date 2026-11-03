//! Field-key B-trees: variable-length keys (`VarKeyInteriorNode` type 3, `VarKeyRecordNode` 4)
//! and fixed-length keys (`FixedKeyInteriorNode` 5, `FixedKeyVarRecNode` 6,
//! `FixedKeyFixedRecNode` 7).
//!
//! ```text
//! var interior:  | 3 | KeyType (1) | KeyCount (4) | KeyOffset0 (4) | Id0 (4) | ...  free  ... | KeyN | ... | Key0 |
//! var leaf:      | 4 | KeyType (1) | KeyCount (4) | Prev (4) | Next (4) | KeyOffset0 (4) | IndFlag0 (1) | ...
//!                                   ...  free  ... | KeyN | RecN | ... | Key0 | Rec0 |
//! fixed interior:| 5 | KeyCount (4) | Key0 (ks) | Id0 (4) | ...
//! fixed var leaf:| 6 | KeyCount (4) | Prev (4) | Next (4) | Key0 (ks) | RecOffset0 (4) | IndFlag0 (1) | ... | RecN | ... | Rec0 |
//! fixed fixed:   | 7 | KeyCount (4) | Prev (4) | Next (4) | Key0 (ks) | Rec0 | ...
//! ```
//!
//! A var-key node carries its key type byte; fixed-key nodes use the table's key type, which the
//! caller supplies (the key size is that type's fixed length).

use ghidra_fmt_bytes as bytes;
use ghidra_fmt_chain::ChainedBuffer;
use ghidra_fmt_field::{Field, FieldType};
use ghidra_fmt_gbf::BufferStore;

use crate::{BtreeError, NodeType, Result};

const MAX_DEPTH: usize = 64;

/// One record: its key and the raw record bytes (not including the key).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRecord {
    /// Primary key.
    pub key: Field,
    /// Serialized non-key fields.
    pub data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    VarInterior,
    VarLeaf,
    FixedInterior,
    FixedVarLeaf,
    FixedFixedLeaf,
}

impl Kind {
    fn is_leaf(self) -> bool {
        !matches!(self, Kind::VarInterior | Kind::FixedInterior)
    }
}

#[derive(Debug, Clone)]
struct Node {
    id: i32,
    kind: Kind,
    buf: Vec<u8>,
    count: usize,
    key_type: FieldType,
    key_size: usize,
}

impl Node {
    fn load<S: BufferStore + ?Sized>(
        store: &S,
        id: i32,
        fixed_key: Option<&FieldType>,
    ) -> Result<Self> {
        let buf = store
            .get_buffer(id)?
            .data
            .ok_or(BtreeError::CorruptNode("node buffer is empty"))?;
        let ty = bytes::get_u8(&buf, 0)?;
        let kind = match NodeType::from_byte(ty) {
            Some(NodeType::VarKeyInterior) => Kind::VarInterior,
            Some(NodeType::VarKeyRec) => Kind::VarLeaf,
            Some(NodeType::FixedKeyInterior) => Kind::FixedInterior,
            Some(NodeType::FixedKeyVarRec) => Kind::FixedVarLeaf,
            Some(NodeType::FixedKeyFixedRec) => Kind::FixedFixedLeaf,
            _ => {
                return Err(BtreeError::UnexpectedNodeType {
                    found: ty,
                    buffer_id: id,
                });
            }
        };
        let (key_type, key_size, count_off) = match kind {
            Kind::VarInterior | Kind::VarLeaf => {
                let kt = FieldType::from_code(bytes::get_u8(&buf, 1)?)
                    .map_err(|_| BtreeError::CorruptNode("unsupported key type"))?;
                (kt, 0, 2)
            }
            _ => {
                let kt = fixed_key.ok_or(BtreeError::MissingKeyType)?.clone();
                let ks = kt.fixed_length().ok_or(BtreeError::CorruptNode(
                    "fixed-key node with variable key type",
                ))?;
                (kt, ks, 1)
            }
        };
        let count = bytes::get_i32(&buf, count_off)?;
        let count =
            usize::try_from(count).map_err(|_| BtreeError::CorruptNode("negative key count"))?;
        Ok(Self {
            id,
            kind,
            buf,
            count,
            key_type,
            key_size,
        })
    }

    fn header(&self) -> usize {
        match self.kind {
            Kind::VarInterior => 6,
            Kind::VarLeaf => 14,
            Kind::FixedInterior => 5,
            _ => 13,
        }
    }

    fn prev_leaf(&self) -> Result<i32> {
        Ok(bytes::get_i32(&self.buf, self.header() - 8)?)
    }

    fn next_leaf(&self) -> Result<i32> {
        Ok(bytes::get_i32(&self.buf, self.header() - 4)?)
    }

    fn leaf_entry(&self, fixed_len: Option<usize>) -> Result<usize> {
        Ok(match self.kind {
            Kind::VarLeaf => 5,
            Kind::FixedVarLeaf => self.key_size + 5,
            Kind::FixedFixedLeaf => {
                self.key_size + fixed_len.ok_or(BtreeError::MissingFixedLength)?
            }
            _ => return Err(BtreeError::CorruptNode("interior node used as leaf")),
        })
    }

    /// Offset of key `i` in the buffer.
    fn key_offset(&self, i: usize, fixed_len: Option<usize>) -> Result<usize> {
        let off = match self.kind {
            Kind::VarInterior => bytes::get_i32(&self.buf, 6 + i * 8)?,
            Kind::VarLeaf => bytes::get_i32(&self.buf, 14 + i * 5)?,
            Kind::FixedInterior => return Ok(5 + i * (self.key_size + 4)),
            _ => return Ok(13 + i * self.leaf_entry(fixed_len)?),
        };
        usize::try_from(off).map_err(|_| BtreeError::CorruptNode("negative key offset"))
    }

    fn key(&self, i: usize, fixed_len: Option<usize>) -> Result<Field> {
        let off = self.key_offset(i, fixed_len)?;
        Ok(Field::read(&self.key_type, &self.buf, off)?.0)
    }

    fn compare_key(
        &self,
        key: &Field,
        i: usize,
        fixed_len: Option<usize>,
    ) -> Result<std::cmp::Ordering> {
        let off = self.key_offset(i, fixed_len)?;
        Ok(key.compare_to_stored(&self.buf, off)?)
    }

    fn child_id(&self, i: usize) -> Result<i32> {
        let off = match self.kind {
            Kind::VarInterior => 6 + i * 8 + 4,
            Kind::FixedInterior => 5 + i * (self.key_size + 4) + self.key_size,
            _ => return Err(BtreeError::CorruptNode("leaf node used as interior")),
        };
        Ok(bytes::get_i32(&self.buf, off)?)
    }

    /// `getIdIndex`: the child holding `key`.
    fn id_index(&self, key: &Field) -> Result<usize> {
        if self.count == 0 {
            return Err(BtreeError::CorruptNode("interior node without keys"));
        }
        let (mut min, mut max) = (1i64, self.count as i64 - 1);
        while min <= max {
            let i = (min + max) / 2;
            match self.compare_key(key, i as usize, None)? {
                std::cmp::Ordering::Equal => return Ok(i as usize),
                std::cmp::Ordering::Greater => min = i + 1,
                std::cmp::Ordering::Less => max = i - 1,
            }
        }
        Ok(max as usize)
    }

    fn search(
        &self,
        key: &Field,
        fixed_len: Option<usize>,
    ) -> Result<std::result::Result<usize, usize>> {
        let (mut min, mut max) = (0i64, self.count as i64 - 1);
        while min <= max {
            let i = (min + max) / 2;
            match self.compare_key(key, i as usize, fixed_len)? {
                std::cmp::Ordering::Equal => return Ok(Ok(i as usize)),
                std::cmp::Ordering::Greater => min = i + 1,
                std::cmp::Ordering::Less => max = i - 1,
            }
        }
        Ok(Err(min as usize))
    }

    fn record<S: BufferStore + ?Sized>(
        &self,
        store: &S,
        i: usize,
        fixed_len: Option<usize>,
    ) -> Result<FieldRecord> {
        let key = self.key(i, fixed_len)?;
        let data = match self.kind {
            Kind::FixedFixedLeaf => {
                let len = fixed_len.ok_or(BtreeError::MissingFixedLength)?;
                let off = 13 + i * (self.key_size + len) + self.key_size;
                bytes::slice(&self.buf, off, len)?.to_vec()
            }
            Kind::FixedVarLeaf | Kind::VarLeaf => {
                let entry = self.leaf_entry(fixed_len)?;
                let (data_off, flag_off) = if self.kind == Kind::VarLeaf {
                    let koff = self.key_offset(i, None)?;
                    let klen = Field::read_length(&self.key_type, &self.buf, koff)?;
                    (koff + klen, 14 + i * entry + 4)
                } else {
                    let base = 13 + i * entry + self.key_size;
                    let off = bytes::get_i32(&self.buf, base)?;
                    (
                        usize::try_from(off)
                            .map_err(|_| BtreeError::CorruptNode("negative record offset"))?,
                        base + 4,
                    )
                };
                if bytes::get_u8(&self.buf, flag_off)? != 0 {
                    let id = bytes::get_i32(&self.buf, data_off)?;
                    let cb = ChainedBuffer::open(store, id)?;
                    cb.get(store, 0, cb.len() as usize)?
                } else {
                    let end = if i == 0 {
                        self.buf.len()
                    } else if self.kind == Kind::VarLeaf {
                        self.key_offset(i - 1, None)?
                    } else {
                        let prev = 13 + (i - 1) * entry + self.key_size;
                        usize::try_from(bytes::get_i32(&self.buf, prev)?)
                            .map_err(|_| BtreeError::CorruptNode("negative record offset"))?
                    };
                    let len = end
                        .checked_sub(data_off)
                        .ok_or(BtreeError::CorruptNode("record offsets out of order"))?;
                    bytes::slice(&self.buf, data_off, len)?.to_vec()
                }
            }
            _ => return Err(BtreeError::CorruptNode("interior node used as leaf")),
        };
        Ok(FieldRecord { key, data })
    }
}

/// A B-tree keyed by [`Field`] values, rooted at one buffer.
pub struct FieldKeyTree<'a, S: BufferStore + ?Sized> {
    store: &'a S,
    root: i32,
    fixed_key: Option<FieldType>,
    fixed_len: Option<usize>,
}

impl<'a, S: BufferStore + ?Sized> FieldKeyTree<'a, S> {
    /// Tree rooted at `root`. `fixed_key` is the table key type (required for fixed-key node
    /// types 5-7); `fixed_len` the record length (required for fixed-record leaves, type 7).
    pub fn new(
        store: &'a S,
        root: i32,
        fixed_key: Option<FieldType>,
        fixed_len: Option<usize>,
    ) -> Self {
        Self {
            store,
            root,
            fixed_key,
            fixed_len,
        }
    }

    fn load(&self, id: i32) -> Result<Node> {
        Node::load(self.store, id, self.fixed_key.as_ref())
    }

    fn descend(&self, mut pick: impl FnMut(&Node) -> Result<usize>) -> Result<Node> {
        let mut node = self.load(self.root)?;
        for _ in 0..MAX_DEPTH {
            if node.kind.is_leaf() {
                return Ok(node);
            }
            let child = node.child_id(pick(&node)?)?;
            node = self.load(child)?;
        }
        Err(BtreeError::TooDeep)
    }

    /// Record with `key`, if present.
    pub fn get(&self, key: &Field) -> Result<Option<FieldRecord>> {
        let leaf = self.descend(|n| n.id_index(key))?;
        match leaf.search(key, self.fixed_len)? {
            Ok(i) => Ok(Some(leaf.record(self.store, i, self.fixed_len)?)),
            Err(_) => Ok(None),
        }
    }

    /// Iterate all records in key order.
    pub fn records(&self) -> Result<FieldRecords<'a, S>> {
        let leaf = self.descend(|_| Ok(0))?;
        Ok(FieldRecords {
            store: self.store,
            fixed_key: self.fixed_key.clone(),
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

    /// Port of `isConsistent`: one message per violated invariant (empty = consistent).
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
        if node.kind.is_leaf() {
            return self.check_leaf(node, parents, issues);
        }
        let mut last_min: Option<Field> = None;
        let mut last_max: Option<Field> = None;
        let mut path: Vec<&Node> = parents.to_vec();
        path.push(node);
        for i in 0..node.count {
            let key = node.key(i, None)?;
            if let Some(lm) = &last_min
                && key.compare(lm)?.is_le()
            {
                issues.push(format!(
                    "node {}: child[{i}].minKey <= child[{}].minKey",
                    node.id,
                    i - 1
                ));
            } else if let Some(lx) = &last_max
                && key.compare(lx)?.is_le()
            {
                issues.push(format!(
                    "node {}: child[{i}].minKey <= child[{}].maxKey",
                    node.id,
                    i - 1
                ));
            }
            last_min = Some(key.clone());

            let child = match node.child_id(i).and_then(|id| self.load(id)) {
                Ok(c) => c,
                Err(e) => {
                    issues.push(format!("node {}: failed to fetch child: {e}", node.id));
                    last_max = Some(key);
                    continue;
                }
            };
            if child.count == 0 {
                issues.push(format!("node {}: child {} has no keys", node.id, child.id));
                last_max = Some(key);
                continue;
            }
            last_max = Some(child.key(child.count - 1, self.fixed_len)?);
            if key.compare(&child.key(0, self.fixed_len)?)?.is_ne() {
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
        let mut prev: Option<Field> = None;
        for i in 0..leaf.count {
            let key = leaf.key(i, self.fixed_len)?;
            if let Some(p) = &prev
                && key.compare(p)?.is_le()
            {
                issues.push(format!("leaf {}: key[{i}] <= key[{}]", leaf.id, i - 1));
            }
            prev = Some(key);
        }
        if leaf.count == 0 {
            return Ok(());
        }
        let key0 = leaf.key(0, self.fixed_len)?;
        let leftmost = parents.is_empty() || is_leftmost(parents, &key0)?;
        if leftmost && leaf.prev_leaf()? >= 0 {
            issues.push(format!("leaf {}: previous-leaf should not exist", leaf.id));
        }
        let next_id = leaf.next_leaf()?;
        if next_id >= 0 {
            let next = self.load(next_id)?;
            if parents.is_empty() || is_rightmost(parents, &key0)? {
                issues.push(format!("leaf {}: next-leaf should not exist", leaf.id));
            } else if next.kind.is_leaf() && next.prev_leaf()? != leaf.id {
                issues.push(format!(
                    "leaf {}: next-leaf is not linked to this leaf",
                    leaf.id
                ));
            }
        } else if !parents.is_empty() && !is_rightmost(parents, &key0)? {
            issues.push(format!(
                "leaf {}: this leaf is not linked to next-leaf",
                leaf.id
            ));
        }
        Ok(())
    }
}

fn is_leftmost(path: &[&Node], key: &Field) -> Result<bool> {
    let Some((node, rest)) = path.split_last() else {
        return Ok(true);
    };
    if node.id_index(key)? == 0 {
        return is_leftmost(rest, key);
    }
    Ok(false)
}

fn is_rightmost(path: &[&Node], key: &Field) -> Result<bool> {
    let Some((node, rest)) = path.split_last() else {
        return Ok(true);
    };
    if node.id_index(key)? + 1 == node.count {
        if rest.is_empty() {
            return Ok(true);
        }
        return is_rightmost(rest, &node.key(0, None)?);
    }
    Ok(false)
}

/// Iterator over all records of a field-key tree, in key order.
pub struct FieldRecords<'a, S: BufferStore + ?Sized> {
    store: &'a S,
    fixed_key: Option<FieldType>,
    fixed_len: Option<usize>,
    leaf: Option<Node>,
    index: usize,
    leaves_left: usize,
}

impl<S: BufferStore + ?Sized> Iterator for FieldRecords<'_, S> {
    type Item = Result<FieldRecord>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let leaf = self.leaf.as_ref()?;
            if self.index < leaf.count {
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
            match Node::load(self.store, next, self.fixed_key.as_ref()) {
                Ok(n) if n.kind.is_leaf() => {
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
