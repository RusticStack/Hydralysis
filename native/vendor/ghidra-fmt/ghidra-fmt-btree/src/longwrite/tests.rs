//! Model-based tests of the long-key write path: random operation sequences against a
//! `BTreeMap`, checked through the read path and the consistency check after every phase.
//! Byte-exactness against Java is checked by the `ghidra-fmt-db` differential tests.

use std::collections::BTreeMap;

use ghidra_fmt_gbf::{BufferStore, MemoryBufferStore};

use super::*;
use crate::BtreeError;
use crate::longkey::LongKeyTree;

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_f491_4f6c_dd1d)
    }
    fn below(&mut self, n: u64) -> u64 {
        (self.next() >> 11) % n
    }
}

fn data(rng: &mut Rng, fixed: Option<usize>, max: u64) -> Vec<u8> {
    // variable-length schemas always store at least a 4 byte length prefix
    let n = fixed.unwrap_or_else(|| 4 + rng.below(max + 1) as usize);
    (0..n).map(|_| rng.below(256) as u8).collect()
}

fn check(
    store: &MemoryBufferStore,
    w: &LongKeyWriter,
    model: &BTreeMap<i64, Vec<u8>>,
    fixed: Option<usize>,
) {
    if model.is_empty() {
        assert_eq!(w.root(), -1);
        return;
    }
    let t = LongKeyTree::new(store, w.root(), fixed);
    let got: Vec<(i64, Vec<u8>)> = t
        .records()
        .unwrap()
        .map(|r| {
            let r = r.unwrap();
            (r.key, r.data)
        })
        .collect();
    let want: Vec<(i64, Vec<u8>)> = model.iter().map(|(k, v)| (*k, v.clone())).collect();
    assert_eq!(got, want);
    assert!(t.check_consistency().unwrap().is_empty());
    for (k, v) in model.iter().step_by(7) {
        assert_eq!(&t.get(*k).unwrap().unwrap().data, v);
    }
}

/// Every buffer in use is reachable from the root (no leaks, nothing freed twice).
fn reachable(store: &MemoryBufferStore, root: i32, fixed: Option<usize>) -> usize {
    use ghidra_fmt_chain::ChainedBuffer;
    let mut n = 0;
    let mut stack = vec![root];
    while let Some(id) = stack.pop() {
        n += 1;
        let d = store.get_buffer(id).unwrap().data.unwrap();
        match d[0] {
            0 => {
                let kc = i32::from_be_bytes(d[1..5].try_into().unwrap()) as usize;
                for i in 0..kc {
                    let o = 5 + i * 12 + 8;
                    stack.push(i32::from_be_bytes(d[o..o + 4].try_into().unwrap()));
                }
            }
            1 => {
                let kc = i32::from_be_bytes(d[1..5].try_into().unwrap()) as usize;
                for i in 0..kc {
                    if d[13 + i * 13 + 12] != 0 {
                        let o = i32::from_be_bytes(
                            d[13 + i * 13 + 8..13 + i * 13 + 12].try_into().unwrap(),
                        ) as usize;
                        let cid = i32::from_be_bytes(d[o..o + 4].try_into().unwrap());
                        n += ChainedBuffer::open(store, cid).unwrap().buffer_count();
                    }
                }
            }
            2 => assert!(fixed.is_some()),
            t => panic!("type {t}"),
        }
    }
    n
}

fn run(buffer_size: usize, fixed: Option<usize>, seed: u64, ops: usize, keys: u64) {
    let mut store = MemoryBufferStore::new(buffer_size);
    let mut w = LongKeyWriter::new(-1, fixed);
    let mut model = BTreeMap::new();
    let mut rng = Rng(seed);
    for i in 0..ops {
        let k = rng.below(keys) as i64 - (keys / 4) as i64;
        if rng.below(10) < 7 {
            let d = data(&mut rng, fixed, (buffer_size / 2) as u64);
            let inserted = w.put(&mut store, k, &d).unwrap();
            assert_eq!(inserted, model.insert(k, d).is_none());
        } else {
            assert_eq!(w.delete(&mut store, k).unwrap(), model.remove(&k).is_some());
        }
        if i % 400 == 399 {
            check(&store, &w, &model, fixed);
        }
    }
    check(&store, &w, &model, fixed);
    if !model.is_empty() {
        assert_eq!(reachable(&store, w.root(), fixed), store.in_use_count());
    }
    // drain
    let all: Vec<i64> = model.keys().copied().collect();
    for (n, k) in all.iter().enumerate() {
        assert!(w.delete(&mut store, *k).unwrap());
        model.remove(k);
        if n % 150 == 0 {
            check(&store, &w, &model, fixed);
        }
    }
    assert_eq!(w.root(), -1);
    assert_eq!(store.in_use_count(), 0, "all buffers freed");
}

#[test]
fn variable_records_small_buffers() {
    run(507, None, 11, 4000, 900);
}

#[test]
fn variable_records_tiny_buffers_deep_tree() {
    run(128, None, 12, 3000, 700);
}

#[test]
fn fixed_records() {
    run(507, Some(14), 13, 4000, 900);
    run(256, Some(3), 14, 3000, 600);
}

#[test]
fn default_size_buffers() {
    run(16379, None, 15, 1500, 3000);
}

#[test]
fn sequential_and_reverse_inserts() {
    for rev in [false, true] {
        let mut store = MemoryBufferStore::new(507);
        let mut w = LongKeyWriter::new(-1, None);
        let mut model = BTreeMap::new();
        for i in 0..1200i64 {
            let k = if rev { 1200 - i } else { i };
            let d = vec![k as u8; 4 + (k % 37) as usize];
            w.put(&mut store, k, &d).unwrap();
            model.insert(k, d);
        }
        check(&store, &w, &model, None);
    }
}

#[test]
fn replace_with_different_sizes_including_indirect() {
    let mut store = MemoryBufferStore::new(507);
    let mut w = LongKeyWriter::new(-1, None);
    let mut model = BTreeMap::new();
    for k in 0..40i64 {
        w.put(&mut store, k, &[1u8; 10]).unwrap();
        model.insert(k, vec![1u8; 10]);
    }
    for round in 0..6usize {
        for k in (0..40i64).step_by(3) {
            let n = [5, 300, 20, 2000, 4, 90][(round + k as usize) % 6];
            let d = vec![(k + round as i64) as u8; n];
            assert!(!w.put(&mut store, k, &d).unwrap());
            model.insert(k, d);
        }
        check(&store, &w, &model, None);
    }
}

#[test]
fn wrong_fixed_length_is_rejected() {
    let mut store = MemoryBufferStore::new(507);
    let mut w = LongKeyWriter::new(-1, Some(4));
    assert!(matches!(
        w.put(&mut store, 1, &[1, 2, 3]),
        Err(BtreeError::BadRecordLength {
            expected: 4,
            actual: 3
        })
    ));
    assert_eq!(w.root(), -1);
    assert!(!w.delete(&mut store, 1).unwrap());
}

#[test]
fn short_record_cannot_become_indirect() {
    // Java writes the chained buffer id at oldOffset + oldLen - 4, which needs oldLen >= 4
    let mut store = MemoryBufferStore::new(507);
    let mut w = LongKeyWriter::new(-1, None);
    w.put(&mut store, 1, &[1, 2]).unwrap();
    assert!(matches!(
        w.put(&mut store, 1, &[7u8; 300]),
        Err(BtreeError::Assertion(_))
    ));
}
