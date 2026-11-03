//! Tests for the field-key read path. Synthetic trees are laid out by hand from the layout
//! documentation; real files are covered by the fixture walk and the oracle comparison.

use super::*;
use ghidra_fmt_chain::{ChainedBuffer, DbParms};
use ghidra_fmt_field::Schema;
use ghidra_fmt_gbf::{BufferFile, BufferStoreMut, MemoryBufferStore};
use std::path::Path;

const BUF: usize = 512;

fn put_i32(d: &mut [u8], off: usize, v: i32) {
    d[off..off + 4].copy_from_slice(&v.to_be_bytes());
}

fn skey(s: &str) -> Field {
    Field::string(s)
}

/// `(key, record bytes, indirect)`
type Rec = (Field, Vec<u8>, bool);

fn var_leaf(s: &mut MemoryBufferStore, kt: &FieldType, recs: &[Rec], prev: i32, next: i32) -> i32 {
    let id = s.create_buffer().unwrap();
    let mut bodies = Vec::new();
    for (k, data, indirect) in recs {
        let mut b = k.to_bytes();
        if *indirect {
            let mut cb = ChainedBuffer::create(s, data.len() as i32, false).unwrap();
            cb.put(s, 0, data).unwrap();
            b.extend_from_slice(&cb.id().to_be_bytes());
        } else {
            b.extend_from_slice(data);
        }
        bodies.push(b);
    }
    let d = s.data_mut(id).unwrap();
    d[0] = 4;
    d[1] = kt.code();
    put_i32(d, 2, recs.len() as i32);
    put_i32(d, 6, prev);
    put_i32(d, 10, next);
    let mut end = BUF;
    for (i, ((_, _, indirect), b)) in recs.iter().zip(&bodies).enumerate() {
        end -= b.len();
        d[end..end + b.len()].copy_from_slice(b);
        put_i32(d, 14 + i * 5, end as i32);
        d[14 + i * 5 + 4] = u8::from(*indirect);
    }
    id
}

fn var_interior(s: &mut MemoryBufferStore, kt: &FieldType, children: &[(Field, i32)]) -> i32 {
    let id = s.create_buffer().unwrap();
    let d = s.data_mut(id).unwrap();
    d[0] = 3;
    d[1] = kt.code();
    put_i32(d, 2, children.len() as i32);
    let mut end = BUF;
    for (i, (k, c)) in children.iter().enumerate() {
        let kb = k.to_bytes();
        end -= kb.len();
        d[end..end + kb.len()].copy_from_slice(&kb);
        put_i32(d, 6 + i * 8, end as i32);
        put_i32(d, 6 + i * 8 + 4, *c);
    }
    id
}

fn fixed_interior(s: &mut MemoryBufferStore, children: &[(Field, i32)]) -> i32 {
    let id = s.create_buffer().unwrap();
    let ks = children[0].0.length();
    let d = s.data_mut(id).unwrap();
    d[0] = 5;
    put_i32(d, 1, children.len() as i32);
    for (i, (k, c)) in children.iter().enumerate() {
        let off = 5 + i * (ks + 4);
        d[off..off + ks].copy_from_slice(&k.to_bytes());
        put_i32(d, off + ks, *c);
    }
    id
}

fn fixed_var_leaf(s: &mut MemoryBufferStore, recs: &[Rec], prev: i32, next: i32) -> i32 {
    let id = s.create_buffer().unwrap();
    let ks = recs[0].0.length();
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
    d[0] = 6;
    put_i32(d, 1, recs.len() as i32);
    put_i32(d, 5, prev);
    put_i32(d, 9, next);
    let mut end = BUF;
    for (i, ((k, _, indirect), b)) in recs.iter().zip(&bodies).enumerate() {
        end -= b.len();
        d[end..end + b.len()].copy_from_slice(b);
        let e = 13 + i * (ks + 5);
        d[e..e + ks].copy_from_slice(&k.to_bytes());
        put_i32(d, e + ks, end as i32);
        d[e + ks + 4] = u8::from(*indirect);
    }
    id
}

fn fixed_fixed_leaf(
    s: &mut MemoryBufferStore,
    recs: &[(Field, Vec<u8>)],
    prev: i32,
    next: i32,
) -> i32 {
    let id = s.create_buffer().unwrap();
    let d = s.data_mut(id).unwrap();
    d[0] = 7;
    put_i32(d, 1, recs.len() as i32);
    put_i32(d, 5, prev);
    put_i32(d, 9, next);
    let mut off = 13;
    for (k, r) in recs {
        let kb = k.to_bytes();
        d[off..off + kb.len()].copy_from_slice(&kb);
        off += kb.len();
        d[off..off + r.len()].copy_from_slice(r);
        off += r.len();
    }
    id
}

fn srec(k: &str) -> Rec {
    (skey(k), format!("rec-{k}").into_bytes(), false)
}

fn var_tree(s: &mut MemoryBufferStore) -> i32 {
    let kt = FieldType::String;
    let next = s.in_use_count() as i32 + 1;
    let l1 = var_leaf(
        s,
        &kt,
        &[srec("apple"), srec("mango"), srec("pear")],
        -1,
        next,
    );
    let l2 = var_leaf(s, &kt, &[srec("quince"), srec("zebra")], l1, -1);
    var_interior(s, &kt, &[(skey("apple"), l1), (skey("quince"), l2)])
}

#[test]
fn var_key_tree_lookup_scan_and_consistency() {
    let mut s = MemoryBufferStore::new(BUF);
    let root = var_tree(&mut s);
    let t = FieldKeyTree::new(&s, root, None, None);
    for k in ["apple", "mango", "pear", "quince", "zebra"] {
        assert_eq!(
            t.get(&skey(k)).unwrap().unwrap().data,
            format!("rec-{k}").into_bytes()
        );
    }
    for k in ["", "a", "banana", "pearl", "zz"] {
        assert!(t.get(&skey(k)).unwrap().is_none(), "{k}");
    }
    let keys: Vec<Field> = t.records().unwrap().map(|r| r.unwrap().key).collect();
    assert_eq!(
        keys,
        ["apple", "mango", "pear", "quince", "zebra"].map(skey)
    );
    assert_eq!(t.record_count().unwrap(), 5);
    assert!(t.check_consistency().unwrap().is_empty());
}

#[test]
fn var_key_indirect_record_and_empty_value() {
    let mut s = MemoryBufferStore::new(BUF);
    let payload: Vec<u8> = (0..2000u32).map(|i| (i * 3) as u8).collect();
    let root = var_leaf(
        &mut s,
        &FieldType::String,
        &[
            (skey("a"), vec![], false),
            (skey("b"), payload.clone(), true),
            srec("c"),
        ],
        -1,
        -1,
    );
    let t = FieldKeyTree::new(&s, root, None, None);
    assert_eq!(t.get(&skey("a")).unwrap().unwrap().data, Vec::<u8>::new());
    assert_eq!(t.get(&skey("b")).unwrap().unwrap().data, payload);
    assert_eq!(t.get(&skey("c")).unwrap().unwrap().data, b"rec-c");
}

#[test]
fn var_key_ordering_is_utf16() {
    let mut s = MemoryBufferStore::new(BUF);
    // UTF-16 order: U+10000 (D800 DC00) sorts before U+FFFF
    let root = var_leaf(
        &mut s,
        &FieldType::String,
        &[
            (skey("\u{10000}"), vec![1], false),
            (skey("\u{ffff}"), vec![2], false),
        ],
        -1,
        -1,
    );
    let t = FieldKeyTree::new(&s, root, None, None);
    assert_eq!(t.get(&skey("\u{ffff}")).unwrap().unwrap().data, [2]);
    assert_eq!(t.get(&skey("\u{10000}")).unwrap().unwrap().data, [1]);
    assert!(t.check_consistency().unwrap().is_empty());
}

#[test]
fn fixed_key_trees_with_both_leaf_kinds() {
    let key = |n: i32| Field::Int(n);
    // variable-length records
    let mut s = MemoryBufferStore::new(BUF);
    let next = -1;
    let r = |n: i32| (key(n), vec![n as u8; 6], false);
    let l1 = fixed_var_leaf(
        &mut s,
        &[r(-5), r(1), (key(3), vec![9; 3000], true)],
        -1,
        next,
    );
    let l2 = fixed_var_leaf(&mut s, &[r(10), r(20)], l1, -1);
    put_i32(s.data_mut(l1).unwrap(), 9, l2);
    let root = fixed_interior(&mut s, &[(key(-5), l1), (key(10), l2)]);
    let t = FieldKeyTree::new(&s, root, Some(FieldType::Int), None);
    assert_eq!(t.get(&key(1)).unwrap().unwrap().data, [1; 6]);
    assert_eq!(t.get(&key(3)).unwrap().unwrap().data, vec![9; 3000]);
    assert_eq!(t.get(&key(20)).unwrap().unwrap().data, [20; 6]);
    assert!(t.get(&key(2)).unwrap().is_none());
    assert!(t.get(&key(-6)).unwrap().is_none());
    let keys: Vec<i64> = t
        .records()
        .unwrap()
        .map(|r| r.unwrap().key.long_value().unwrap())
        .collect();
    assert_eq!(keys, [-5, 1, 3, 10, 20]);
    assert!(t.check_consistency().unwrap().is_empty());

    // fixed-length records with a 10-byte key
    let mut s = MemoryBufferStore::new(BUF);
    let fk = |b: u8| {
        let mut a = [0u8; 10];
        a[0] = b;
        Field::Fixed10(a)
    };
    let root = fixed_fixed_leaf(
        &mut s,
        &[(fk(1), vec![1, 1]), (fk(0x90), vec![2, 2])],
        -1,
        -1,
    );
    let none = FieldKeyTree::new(&s, root, Some(FieldType::Fixed10), None);
    assert!(matches!(
        none.get(&fk(1)),
        Err(BtreeError::MissingFixedLength)
    ));
    let t = FieldKeyTree::new(&s, root, Some(FieldType::Fixed10), Some(2));
    assert_eq!(t.get(&fk(0x90)).unwrap().unwrap().data, [2, 2]);
    assert!(t.get(&fk(2)).unwrap().is_none());
    assert!(t.check_consistency().unwrap().is_empty());
    // fixed-key nodes need a key type
    let no_type = FieldKeyTree::new(&s, root, None, Some(2));
    assert!(matches!(
        no_type.get(&fk(1)),
        Err(BtreeError::MissingKeyType)
    ));
}

#[test]
fn consistency_reports_violations() {
    let mut s = MemoryBufferStore::new(BUF);
    let root = var_tree(&mut s);
    // break the second leaf's back link
    let l2 = {
        let n = Node::load(&s, root, None).unwrap();
        n.child_id(1).unwrap()
    };
    put_i32(s.data_mut(l2).unwrap(), 6, 99);
    let issues = FieldKeyTree::new(&s, root, None, None)
        .check_consistency()
        .unwrap();
    assert!(
        issues.iter().any(|i| i.contains("not linked to this leaf")),
        "{issues:?}"
    );

    let mut s = MemoryBufferStore::new(BUF);
    let root = var_leaf(&mut s, &FieldType::String, &[srec("b"), srec("a")], -1, -1);
    let issues = FieldKeyTree::new(&s, root, None, None)
        .check_consistency()
        .unwrap();
    assert!(
        issues.iter().any(|i| i.contains("key[1] <= key[0]")),
        "{issues:?}"
    );
}

#[test]
fn wrong_family_and_corrupt_nodes() {
    let mut s = MemoryBufferStore::new(BUF);
    let id = s.create_buffer().unwrap(); // type 0 = long-key interior
    let err = FieldKeyTree::new(&s, id, None, None)
        .get(&skey("x"))
        .unwrap_err();
    assert!(matches!(
        err,
        BtreeError::UnexpectedNodeType { found: 0, .. }
    ));

    // unsupported key type byte
    let mut s = MemoryBufferStore::new(BUF);
    let id = var_leaf(&mut s, &FieldType::String, &[srec("a")], -1, -1);
    s.data_mut(id).unwrap()[1] = 0x0f;
    assert!(matches!(
        FieldKeyTree::new(&s, id, None, None).get(&skey("a")),
        Err(BtreeError::CorruptNode(_))
    ));

    // key offset beyond the page
    let mut s = MemoryBufferStore::new(BUF);
    let id = var_leaf(&mut s, &FieldType::String, &[srec("a")], -1, -1);
    put_i32(s.data_mut(id).unwrap(), 14, 100_000);
    assert!(
        FieldKeyTree::new(&s, id, None, None)
            .get(&skey("a"))
            .is_err()
    );

    // interior that points at itself
    let mut s = MemoryBufferStore::new(BUF);
    let id = s.in_use_count() as i32;
    var_interior(
        &mut s,
        &FieldType::String,
        &[(skey("a"), id), (skey("b"), id)],
    );
    assert!(matches!(
        FieldKeyTree::new(&s, id, None, None).get(&skey("c")),
        Err(BtreeError::TooDeep)
    ));
}

// ---- real files ----

fn fixture(dir: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures")
        .join(dir)
        .join("legacy.rep/idata/00/~00000000.db/db.1.gbf")
}

struct Row {
    name: String,
    schema: Schema,
    root: i32,
    indexed_col: i32,
    max_key: i64,
    count: i32,
}

fn master_rows(bf: &BufferFile) -> Vec<Row> {
    let root = DbParms::read(bf).unwrap().master_table_root().unwrap();
    let mut out = Vec::new();
    for r in crate::longkey::LongKeyTree::new(bf, root, None)
        .records()
        .unwrap()
    {
        let r = r.unwrap();
        let mut c = bytes::BeCursor::new(&r.data);
        let text = |c: &mut bytes::BeCursor<'_>| {
            let n = c.read_i32().unwrap() as usize;
            String::from_utf8(c.read_bytes(n).unwrap().to_vec()).unwrap()
        };
        let name = text(&mut c);
        let version = c.read_i32().unwrap();
        let buffer_id = c.read_i32().unwrap();
        let key_type = c.read_u8().unwrap();
        let n = c.read_i32().unwrap() as usize;
        let ftypes = c.read_bytes(n).unwrap().to_vec();
        let names = text(&mut c);
        let indexed_col = c.read_i32().unwrap();
        let max_key = c.read_i64().unwrap();
        let count = c.read_i32().unwrap();
        let schema = Schema::from_encoded(version, key_type, &ftypes, &names).unwrap();
        out.push(Row {
            name,
            schema,
            root: buffer_id,
            indexed_col,
            max_key,
            count,
        });
    }
    out
}

#[test]
fn fixture_every_table_walks_with_the_right_node_family() {
    let mut seen = [0usize; 3]; // long, var, fixed
    for dir in ["legacy-12.1.4", "legacy-12.1.4-analysed"] {
        let bf = BufferFile::open(fixture(dir), true).unwrap();
        for row in master_rows(&bf) {
            if row.root < 0 {
                continue;
            }
            let root_type = bf.get_buffer(row.root).unwrap().data.unwrap()[0];
            let fixed_len = (!row.schema.is_variable_length()).then(|| row.schema.fixed_length());
            let ctx = format!("{dir}/{} (index col {})", row.name, row.indexed_col);
            let (count, issues) = match root_type {
                0..=2 => {
                    seen[0] += 1;
                    let t = crate::longkey::LongKeyTree::new(&bf, row.root, fixed_len);
                    let mut max = i64::MIN;
                    let mut n = 0;
                    for r in t.records().unwrap() {
                        max = max.max(r.unwrap().key);
                        n += 1;
                    }
                    if n > 0 && row.indexed_col == -1 {
                        assert_eq!(max, row.max_key, "{ctx}");
                    }
                    (n, t.check_consistency().unwrap())
                }
                3..=7 => {
                    seen[if root_type <= 4 { 1 } else { 2 }] += 1;
                    let kt = Some(row.schema.key_type().clone());
                    let t = FieldKeyTree::new(&bf, row.root, kt, fixed_len);
                    let mut prev: Option<Field> = None;
                    let mut n = 0;
                    for r in t.records().unwrap() {
                        let r = r.unwrap();
                        if let Some(p) = &prev {
                            assert!(p.compare(&r.key).unwrap().is_lt(), "{ctx} order");
                        }
                        // every record is found again by key
                        let again = t.get(&r.key).unwrap().unwrap();
                        assert_eq!(again, r, "{ctx}");
                        prev = Some(r.key);
                        n += 1;
                    }
                    (n, t.check_consistency().unwrap())
                }
                other => panic!("{ctx}: root node type {other}"),
            };
            assert!(issues.is_empty(), "{ctx}: {issues:?}");
            assert_eq!(count, i64::from(row.count), "{ctx} count");
        }
    }
    assert!(seen.iter().all(|&n| n > 0), "node families seen: {seen:?}");
}
