//! Tests for the long-key read path. The synthetic trees are laid out by hand from the node
//! layout documentation, not by the code under test.

use super::*;
use ghidra_fmt_chain::{ChainedBuffer, DbParms};
use ghidra_fmt_gbf::{BufferFile, BufferStoreMut, MemoryBufferStore};
use std::path::Path;

const BUF: usize = 512;

fn store() -> MemoryBufferStore {
    MemoryBufferStore::new(BUF)
}

fn put_i32(d: &mut [u8], off: usize, v: i32) {
    d[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

fn put_i64(d: &mut [u8], off: usize, v: i64) {
    d[off..off + 8].copy_from_slice(&v.to_be_bytes());
}

/// `(key, record bytes, stored in a chained buffer)`
type VarRec = (i64, Vec<u8>, bool);

fn var_leaf(s: &mut MemoryBufferStore, recs: &[VarRec], prev: i32, next: i32) -> i32 {
    let id = s.create_buffer().unwrap();
    // chained buffers for indirect records first (they allocate from the same store)
    let mut bodies = Vec::new();
    for (_, data, indirect) in recs {
        if *indirect {
            let mut cb = ChainedBuffer::create(s, data.len() as i32, false).unwrap();
            cb.put(s, 0, data).unwrap();
            bodies.push(cb.id().to_be_bytes().to_vec());
        } else {
            bodies.push(data.clone());
        }
    }
    let d = s.data_mut(id).unwrap();
    d[0] = 1;
    put_i32(d, 1, recs.len() as i32);
    put_i32(d, 5, prev);
    put_i32(d, 9, next);
    let mut end = BUF;
    for (i, ((key, _, indirect), body)) in recs.iter().zip(&bodies).enumerate() {
        end -= body.len();
        d[end..end + body.len()].copy_from_slice(body);
        let e = LEAF_HEADER + i * VAR_ENTRY;
        put_i64(d, e, *key);
        put_i32(d, e + 8, end as i32);
        d[e + 12] = u8::from(*indirect);
    }
    id
}

fn fixed_leaf(s: &mut MemoryBufferStore, recs: &[(i64, Vec<u8>)], prev: i32, next: i32) -> i32 {
    let id = s.create_buffer().unwrap();
    let d = s.data_mut(id).unwrap();
    d[0] = 2;
    put_i32(d, 1, recs.len() as i32);
    put_i32(d, 5, prev);
    put_i32(d, 9, next);
    let mut off = LEAF_HEADER;
    for (k, r) in recs {
        put_i64(d, off, *k);
        d[off + 8..off + 8 + r.len()].copy_from_slice(r);
        off += 8 + r.len();
    }
    id
}

fn interior(s: &mut MemoryBufferStore, children: &[(i64, i32)]) -> i32 {
    let id = s.create_buffer().unwrap();
    let d = s.data_mut(id).unwrap();
    d[0] = 0;
    put_i32(d, 1, children.len() as i32);
    for (i, (k, c)) in children.iter().enumerate() {
        put_i64(d, 5 + i * 12, *k);
        put_i32(d, 5 + i * 12 + 8, *c);
    }
    id
}

fn rec(k: i64) -> VarRec {
    (k, format!("rec-{k}").into_bytes(), false)
}

fn two_level(s: &mut MemoryBufferStore) -> i32 {
    // ids are assigned in creation order; leaves link to each other by id
    let l1_id = s.in_use_count() as i32; // next id the store will hand out
    let l1 = var_leaf(s, &[rec(1), rec(5), rec(9)], -1, l1_id + 1);
    let l2 = var_leaf(s, &[rec(20), rec(30)], l1, -1);
    interior(s, &[(1, l1), (20, l2)])
}

#[test]
fn single_var_leaf_get_and_iterate() {
    let mut s = store();
    let big = vec![0xabu8; 40];
    let root = var_leaf(
        &mut s,
        &[rec(-7), (3, big.clone(), false), rec(100)],
        -1,
        -1,
    );
    let t = LongKeyTree::new(&s, root, None);
    assert_eq!(t.get(3).unwrap().unwrap().data, big);
    assert_eq!(t.get(-7).unwrap().unwrap().data, b"rec--7");
    assert_eq!(t.get(100).unwrap().unwrap().key, 100);
    assert!(t.get(4).unwrap().is_none());
    assert!(t.get(i64::MIN).unwrap().is_none());
    let keys: Vec<i64> = t.records().unwrap().map(|r| r.unwrap().key).collect();
    assert_eq!(keys, [-7, 3, 100]);
    assert_eq!(t.record_count().unwrap(), 3);
    assert!(t.check_consistency().unwrap().is_empty());
}

#[test]
fn empty_leaf_is_empty() {
    let mut s = store();
    let root = var_leaf(&mut s, &[], -1, -1);
    let t = LongKeyTree::new(&s, root, None);
    assert_eq!(t.record_count().unwrap(), 0);
    assert!(t.get(0).unwrap().is_none());
    assert!(t.check_consistency().unwrap().is_empty());
}

#[test]
fn two_level_tree_lookup_order_and_consistency() {
    let mut s = store();
    let root = two_level(&mut s);
    let t = LongKeyTree::new(&s, root, None);
    for k in [1, 5, 9, 20, 30] {
        assert_eq!(
            t.get(k).unwrap().unwrap().data,
            format!("rec-{k}").into_bytes()
        );
    }
    for k in [0, 2, 10, 19, 21, 31, i64::MAX, i64::MIN] {
        assert!(t.get(k).unwrap().is_none(), "key {k}");
    }
    let keys: Vec<i64> = t.records().unwrap().map(|r| r.unwrap().key).collect();
    assert_eq!(keys, [1, 5, 9, 20, 30]);
    assert!(t.check_consistency().unwrap().is_empty());
}

#[test]
fn indirect_record_is_read_from_chained_buffer() {
    let mut s = store();
    let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7) as u8).collect();
    let root = var_leaf(
        &mut s,
        &[rec(1), (2, payload.clone(), true), rec(3)],
        -1,
        -1,
    );
    let t = LongKeyTree::new(&s, root, None);
    assert_eq!(t.get(2).unwrap().unwrap().data, payload);
    assert_eq!(t.get(3).unwrap().unwrap().data, b"rec-3");
}

#[test]
fn fixed_leaf_needs_and_uses_record_length() {
    let mut s = store();
    let root = fixed_leaf(
        &mut s,
        &[(10, vec![1, 2, 3, 4]), (11, vec![5, 6, 7, 8])],
        -1,
        -1,
    );
    let none = LongKeyTree::new(&s, root, None);
    assert!(matches!(none.get(10), Err(BtreeError::MissingFixedLength)));
    let t = LongKeyTree::new(&s, root, Some(4));
    assert_eq!(t.get(11).unwrap().unwrap().data, [5, 6, 7, 8]);
    assert!(t.get(12).unwrap().is_none());
    assert_eq!(t.record_count().unwrap(), 2);
    assert!(t.check_consistency().unwrap().is_empty());
}

#[test]
fn consistency_check_reports_violations() {
    // wrong previous link on the second leaf
    let mut s = store();
    let root = two_level(&mut s);
    let l2 = {
        let n = Node::load(&s, root).unwrap();
        n.child_id(1).unwrap()
    };
    put_i32(s.data_mut(l2).unwrap(), 5, 99);
    let issues = LongKeyTree::new(&s, root, None)
        .check_consistency()
        .unwrap();
    assert!(
        issues.iter().any(|i| i.contains("not linked to this leaf")),
        "{issues:?}"
    );

    // parent key does not match child's first key
    let mut s = store();
    let root = two_level(&mut s);
    put_i64(s.data_mut(root).unwrap(), 5 + 12, 21);
    let issues = LongKeyTree::new(&s, root, None)
        .check_consistency()
        .unwrap();
    assert!(issues.iter().any(|i| i.contains("mismatch")), "{issues:?}");

    // keys out of order inside a leaf
    let mut s = store();
    let root = var_leaf(&mut s, &[rec(5), rec(5)], -1, -1);
    let issues = LongKeyTree::new(&s, root, None)
        .check_consistency()
        .unwrap();
    assert!(
        issues.iter().any(|i| i.contains("key[1] <= key[0]")),
        "{issues:?}"
    );

    // a stray previous-leaf pointer on the leftmost leaf
    let mut s = store();
    let root = var_leaf(&mut s, &[rec(5)], 0, -1);
    let issues = LongKeyTree::new(&s, root, None)
        .check_consistency()
        .unwrap();
    assert!(
        issues.iter().any(|i| i.contains("previous-leaf")),
        "{issues:?}"
    );
}

#[test]
fn unsupported_and_unexpected_node_types() {
    let mut s = store();
    for (ty, unsupported) in [
        (3u8, true),
        (4, true),
        (5, true),
        (6, true),
        (7, true),
        (9, false),
    ] {
        let id = s.create_buffer().unwrap();
        s.data_mut(id).unwrap()[0] = ty;
        let err = LongKeyTree::new(&s, id, None).get(1).unwrap_err();
        if unsupported {
            assert!(matches!(err, BtreeError::UnsupportedNodeType(t) if t == ty));
        } else {
            assert!(matches!(
                err,
                BtreeError::UnexpectedNodeType { found: 9, .. }
            ));
        }
    }
}

#[test]
fn corrupt_nodes_error_instead_of_panicking() {
    // negative key count
    let mut s = store();
    let id = var_leaf(&mut s, &[rec(1)], -1, -1);
    put_i32(s.data_mut(id).unwrap(), 1, -3);
    assert!(matches!(
        LongKeyTree::new(&s, id, None).get(1),
        Err(BtreeError::CorruptNode(_))
    ));

    // key count larger than the page can hold
    let mut s = store();
    let id = var_leaf(&mut s, &[rec(1)], -1, -1);
    put_i32(s.data_mut(id).unwrap(), 1, 1_000_000);
    assert!(LongKeyTree::new(&s, id, None).get(5).is_err());

    // record offset beyond the page
    let mut s = store();
    let id = var_leaf(&mut s, &[rec(1)], -1, -1);
    put_i32(s.data_mut(id).unwrap(), LEAF_HEADER + 8, 100_000);
    assert!(LongKeyTree::new(&s, id, None).get(1).is_err());

    // interior without keys
    let mut s = store();
    let id = interior(&mut s, &[]);
    assert!(matches!(
        LongKeyTree::new(&s, id, None).get(1),
        Err(BtreeError::CorruptNode(_))
    ));

    // interior whose child is itself
    let mut s = store();
    let id = s.in_use_count() as i32;
    let id2 = interior(&mut s, &[(0, id), (10, id)]);
    assert_eq!(id, id2);
    let t = LongKeyTree::new(&s, id, None);
    assert!(matches!(t.get(5), Err(BtreeError::TooDeep)));
    assert!(matches!(t.check_consistency(), Err(BtreeError::TooDeep)));

    // leaf chain that loops
    let mut s = store();
    let id = s.in_use_count() as i32;
    var_leaf(&mut s, &[rec(1)], -1, id);
    let t = LongKeyTree::new(&s, id, None);
    assert!(t.record_count().is_err());
}

// ---- real files ----

fn fixture(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures")
        .join(rel)
}

/// Sequential decoder for a `TableRecord` (master table row), independent of any schema code:
/// NAME(string) VERSION(int) BUFFER_ID(int) KEY_TYPE(byte) FIELD_TYPES(binary)
/// FIELD_NAMES(string) COLUMN_INDEXED(int) MAX_KEY(long) RECORD_COUNT(int)
struct TableRow {
    name: String,
    buffer_id: i32,
    key_type: u8,
    field_types: Vec<u8>,
    max_key: i64,
    record_count: i32,
}

fn decode_table_row(r: &Record) -> TableRow {
    let mut c = bytes::BeCursor::new(&r.data);
    let string = |c: &mut bytes::BeCursor<'_>| {
        let n = c.read_i32().unwrap();
        String::from_utf8(c.read_bytes(n as usize).unwrap().to_vec()).unwrap()
    };
    let name = string(&mut c);
    let _version = c.read_i32().unwrap();
    let buffer_id = c.read_i32().unwrap();
    let key_type = c.read_u8().unwrap();
    let n = c.read_i32().unwrap();
    let field_types = c.read_bytes(n as usize).unwrap().to_vec();
    let _names = string(&mut c);
    let _indexed = c.read_i32().unwrap();
    let max_key = c.read_i64().unwrap();
    let record_count = c.read_i32().unwrap();
    assert_eq!(c.remaining(), 0);
    TableRow {
        name,
        buffer_id,
        key_type,
        field_types,
        max_key,
        record_count,
    }
}

/// Fixed record length of a schema, or `None` when any field is variable length.
fn fixed_len(field_types: &[u8]) -> Option<usize> {
    field_types.iter().try_fold(0usize, |acc, t| {
        Some(
            acc + match t & 0x0f {
                0 | 6 => 1,
                1 => 2,
                2 => 4,
                3 => 8,
                7 => 10,
                _ => return None,
            },
        )
    })
}

#[test]
fn fixture_every_long_key_table_walks_and_matches_master_table() {
    for dir in ["legacy-12.1.4", "legacy-12.1.4-analysed"] {
        let bf = BufferFile::open(
            fixture(&format!("{dir}/legacy.rep/idata/00/~00000000.db/db.1.gbf")),
            true,
        )
        .unwrap();
        let root = DbParms::read(&bf).unwrap().master_table_root().unwrap();
        // master table schema: long key (table number), variable-length records
        let master = LongKeyTree::new(&bf, root, None);
        assert!(master.check_consistency().unwrap().is_empty());
        let rows: Vec<TableRow> = master
            .records()
            .unwrap()
            .map(|r| decode_table_row(&r.unwrap()))
            .collect();
        assert!(rows.len() > 10, "{dir}: only {} tables", rows.len());
        assert!(rows.iter().any(|r| r.name == "Program"));

        let mut walked = 0;
        for row in &rows {
            if row.buffer_id < 0 || row.key_type != 3 {
                continue; // unallocated, or not a plain long-key table
            }
            let t = LongKeyTree::new(&bf, row.buffer_id, fixed_len(&row.field_types));
            let issues = t.check_consistency().unwrap();
            assert!(issues.is_empty(), "{dir}/{}: {issues:?}", row.name);
            let mut count = 0i64;
            let mut max = i64::MIN;
            let mut prev = None;
            for r in t.records().unwrap() {
                let r = r.unwrap();
                assert!(prev.is_none_or(|p| p < r.key), "{dir}/{} order", row.name);
                prev = Some(r.key);
                max = max.max(r.key);
                count += 1;
            }
            assert_eq!(
                count,
                i64::from(row.record_count),
                "{dir}/{} count",
                row.name
            );
            if count > 0 {
                assert_eq!(max, row.max_key, "{dir}/{} max key", row.name);
                // point lookups agree with the scan
                assert!(t.get(max).unwrap().is_some());
            }
            walked += 1;
        }
        assert!(walked > 5, "{dir}: walked only {walked} long-key tables");
    }
}
