//! Ports of `db.AbstractChainedBufferTest` (run as `ChainedBufferTest`,
//! `ObfuscatedChaninedBufferTest` and `ObfuscatedSourcedChaninedBufferTest`) plus `DBParms`
//! and fixture checks.

use super::*;
use ghidra_fmt_gbf::{BufferFile, MemoryBufferStore};
use std::path::Path;

const BUFFER_SIZE: usize = 256;
const BIG_DATA_SIZE: usize = BUFFER_SIZE * BUFFER_SIZE;
const SOURCE_OFFSET: i32 = 24;

/// The anonymous `Buffer` of the sourced Java test: byte at `offset` is `~offset`.
struct NotOffsetSource;

impl ByteSource for NotOffsetSource {
    fn len(&self) -> i64 {
        i64::from(i32::MAX)
    }

    fn read(&self, offset: i64, out: &mut [u8]) -> Result<()> {
        for (i, b) in out.iter_mut().enumerate() {
            *b = !((offset + i as i64) as u8);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug)]
struct Variant {
    obfuscated: bool,
    sourced: bool,
}

const VARIANTS: [Variant; 3] = [
    Variant {
        obfuscated: false,
        sourced: false,
    },
    Variant {
        obfuscated: true,
        sourced: false,
    },
    Variant {
        obfuscated: true,
        sourced: true,
    },
];

impl Variant {
    fn source(self) -> Option<(Arc<dyn ByteSource>, i32)> {
        self.sourced.then(|| {
            (
                Arc::new(NotOffsetSource) as Arc<dyn ByteSource>,
                SOURCE_OFFSET,
            )
        })
    }

    fn create(self, store: &mut MemoryBufferStore, size: usize) -> ChainedBuffer {
        ChainedBuffer::create_with_source(store, size as i32, self.obfuscated, self.source())
            .unwrap()
    }

    /// Expected initial content of a never-written buffer of `size` bytes.
    fn initial(self, size: usize) -> Vec<u8> {
        (0..size)
            .map(|i| {
                if self.sourced {
                    !((SOURCE_OFFSET as usize + i) as u8)
                } else {
                    0
                }
            })
            .collect()
    }
}

fn for_each_variant(f: impl Fn(Variant, &mut MemoryBufferStore)) {
    for v in VARIANTS {
        let mut store = MemoryBufferStore::new(BUFFER_SIZE);
        f(v, &mut store);
    }
}

/// Deterministic stand-in for `new Random(1).nextBytes`.
fn pseudo_random(seed: &mut u64, n: usize) -> Vec<u8> {
    (0..n)
        .map(|_| {
            *seed = seed
                .wrapping_mul(6364136223846793005)
                .wrapping_add(1442695040888963407);
            (*seed >> 33) as u8
        })
        .collect()
}

#[test]
fn test_create_chained_buffer() {
    for_each_variant(|v, store| {
        for size in [128 * 1024, BUFFER_SIZE / 2] {
            let cb = v.create(store, size);
            assert_eq!(cb.get(store, 0, size).unwrap(), v.initial(size));
        }
    });
}

#[test]
fn test_read_only_chained_buffer() {
    for_each_variant(|v, store| {
        let mut cb = v.create(store, 128 * 1024);
        let orig = vec![b'1'; 128 * 1024];
        assert_eq!(cb.put(store, 0, &orig).unwrap(), orig.len() as i32);
        cb.set_read_only();
        assert!(matches!(cb.put(store, 0, &orig), Err(ChainError::ReadOnly)));
    });
}

#[test]
fn test_fill_chained_buffer() {
    for_each_variant(|v, store| {
        let mut cb = v.create(store, BIG_DATA_SIZE);
        cb.fill(store, 0, BIG_DATA_SIZE as i32 - 1, 0x12).unwrap();
        assert!(
            cb.get(store, 0, BIG_DATA_SIZE)
                .unwrap()
                .iter()
                .all(|&b| b == 0x12)
        );
        // Re-instantiate buffer (sourced buffers must re-apply their source)
        let cb = ChainedBuffer::open_with_source(store, cb.id(), v.source()).unwrap();
        assert!(
            cb.get(store, 0, BIG_DATA_SIZE)
                .unwrap()
                .iter()
                .all(|&b| b == 0x12)
        );
    });
}

#[test]
fn test_small_fill_chained_buffer() {
    for_each_variant(|v, store| {
        let mut cb = v.create(store, 1);
        cb.fill(store, 0, 0, 0x12).unwrap();
        assert_eq!(cb.get_u8(store, 0).unwrap(), 0x12);
        let cb = ChainedBuffer::open_with_source(store, cb.id(), v.source()).unwrap();
        assert_eq!(cb.get_u8(store, 0).unwrap(), 0x12);
    });
}

#[test]
fn test_chained_buffer_overflow() {
    for_each_variant(|v, store| {
        let mut cb = v.create(store, 1);
        assert!(matches!(
            cb.fill(store, 0, 1, 0x12),
            Err(ChainError::OutOfBounds)
        ));
    });
}

#[test]
fn test_big_chained_buffer() {
    for_each_variant(|v, store| {
        let mut cb = v.create(store, BIG_DATA_SIZE);
        let cnt = (BIG_DATA_SIZE / 4) as i32;
        let mut offset = 0;
        for i in 0..cnt {
            assert_eq!(cb.put_i32(store, offset, i).unwrap(), offset + 4);
            offset += 4;
        }
        for pass in 0..2 {
            let cb = if pass == 0 {
                cb.clone()
            } else {
                ChainedBuffer::open_with_source(store, cb.id(), v.source()).unwrap()
            };
            let mut offset = 0;
            for i in 0..cnt {
                assert_eq!(cb.get_i32(store, offset).unwrap(), i);
                offset += 4;
            }
        }
    });
}

#[test]
fn test_put_and_get() {
    for_each_variant(|v, store| {
        let size = 32768usize;
        let bytes0 = vec![b'0'; size];
        let bytes1 = vec![b'1'; size];
        let bytes2 = vec![b'2'; 256];
        let mut cb = v.create(store, size);

        assert_eq!(cb.put(store, 0, &bytes0).unwrap(), size as i32);
        assert_eq!(cb.get(store, 0, size).unwrap(), bytes0);
        assert_eq!(cb.len(), size as i32);

        cb.put(store, 0, &bytes0).unwrap();
        assert_eq!(cb.put(store, 128, &bytes1[128..131]).unwrap(), 131);
        let mut expect = bytes0.clone();
        expect[128..131].fill(b'1');
        assert_eq!(cb.get(store, 0, size).unwrap(), expect);

        cb.put(store, 0, &bytes0).unwrap();
        assert_eq!(cb.put(store, 128, &bytes1[128..]).unwrap(), size as i32);
        expect[..128].fill(b'0');
        expect[128..].fill(b'1');
        assert_eq!(cb.get(store, 0, size).unwrap(), expect);

        for off in [-1, size as i32 - 1, size as i32 + 1] {
            assert!(matches!(
                cb.put(store, off, &bytes2),
                Err(ChainError::OutOfBounds)
            ));
            assert!(matches!(
                cb.get(store, off, 256),
                Err(ChainError::OutOfBounds)
            ));
        }
    });
}

#[test]
fn test_set_and_get_byte() {
    for_each_variant(|v, store| {
        let size = 400usize;
        let mut model = vec![b'a'; size];
        let mut cb = v.create(store, size);
        cb.put(store, 0, &model).unwrap();
        model[100] = b'B';
        assert_eq!(cb.put_u8(store, 100, b'B').unwrap(), 101);
        model[350] = b'L';
        assert_eq!(cb.put_u8(store, 350, b'L').unwrap(), 351);
        assert_eq!(cb.get(store, 0, size).unwrap(), model);
        assert!(cb.put_u8(store, -1, 0).is_err());
        assert!(cb.put_u8(store, size as i32 + 1, 0).is_err());
        assert!(cb.get_u8(store, -1).is_err());
        assert!(cb.get_u8(store, size as i32 + 1).is_err());

        // uninitialized and partially initialized areas (testGetByte)
        let size = 800usize;
        let mut cb = v.create(store, size);
        let init = v.initial(size);
        assert_eq!(cb.get_u8(store, 0).unwrap(), init[0]);
        assert_eq!(cb.get_u8(store, size as i32 - 1).unwrap(), init[size - 1]);
        let mut bytes = vec![b'a'; size / 2];
        bytes[120] = b'W';
        bytes[299] = 0x02;
        bytes[360] = b'x';
        cb.put(store, 50, &bytes).unwrap();
        assert_eq!(cb.get_u8(store, 50).unwrap(), b'a');
        assert_eq!(cb.get_u8(store, 50 + 120).unwrap(), b'W');
        assert_eq!(cb.get_u8(store, 50 + 299).unwrap(), 0x02);
        assert_eq!(cb.get_u8(store, 50 + 360).unwrap(), b'x');
        for off in [20usize, 450, 700] {
            assert_eq!(cb.get_u8(store, off as i32).unwrap(), init[off]);
        }
    });
}

fn multi_width_check(v: Variant, store: &mut MemoryBufferStore, width: usize) {
    // Values written at offsets inside and across the 255/256-byte data node boundaries
    // (index nodes give 255 payload bytes per node) must round trip and land big-endian.
    let size = 400usize;
    let mut model = vec![b'a'; size];
    let mut cb = v.create(store, size);
    cb.put(store, 0, &model).unwrap();
    for (i, off) in [100usize, 248, 250, 254, 255, 350].into_iter().enumerate() {
        let pat = (0x11 * (i as u8 + 1)).wrapping_add(7);
        let raw = vec![pat; width];
        model[off..off + width].copy_from_slice(&raw);
        let next = match width {
            2 => cb
                .put_i16(store, off as i32, i16::from_be_bytes([pat, pat]))
                .unwrap(),
            4 => cb
                .put_i32(store, off as i32, i32::from_be_bytes([pat; 4]))
                .unwrap(),
            _ => cb
                .put_i64(store, off as i32, i64::from_be_bytes([pat; 8]))
                .unwrap(),
        };
        assert_eq!(next, (off + width) as i32);
        assert_eq!(cb.get(store, 0, size).unwrap(), model);
        match width {
            2 => assert_eq!(
                cb.get_i16(store, off as i32).unwrap(),
                i16::from_be_bytes([pat, pat])
            ),
            4 => assert_eq!(
                cb.get_i32(store, off as i32).unwrap(),
                i32::from_be_bytes([pat; 4])
            ),
            _ => assert_eq!(
                cb.get_i64(store, off as i32).unwrap(),
                i64::from_be_bytes([pat; 8])
            ),
        }
    }
    for off in [-1, size as i32 - (width as i32 - 1), size as i32 + 1] {
        match width {
            2 => assert!(cb.put_i16(store, off, 0).is_err() && cb.get_i16(store, off).is_err()),
            4 => assert!(cb.put_i32(store, off, 0).is_err() && cb.get_i32(store, off).is_err()),
            _ => assert!(cb.put_i64(store, off, 0).is_err() && cb.get_i64(store, off).is_err()),
        }
    }
}

#[test]
fn test_set_and_get_short() {
    for_each_variant(|v, s| multi_width_check(v, s, 2));
}

#[test]
fn test_set_and_get_int() {
    for_each_variant(|v, s| multi_width_check(v, s, 4));
}

#[test]
fn test_set_and_get_long() {
    for_each_variant(|v, s| multi_width_check(v, s, 8));
}

#[test]
fn test_get_id() {
    for_each_variant(|v, store| {
        let mut seed = 1;
        let mut cb = v.create(store, 32768);
        let bytes = pseudo_random(&mut seed, 400);
        cb.put(store, 0, &bytes).unwrap();
        let cb = ChainedBuffer::open_with_source(store, cb.id(), v.source()).unwrap();
        assert_eq!(cb.get(store, 0, 400).unwrap(), bytes);
    });
}

#[test]
fn test_delete() {
    for_each_variant(|v, store| {
        let mut cb = v.create(store, 32768);
        let id = cb.id();
        cb.delete(store).unwrap();
        assert_eq!(cb.id(), -1);
        assert!(ChainedBuffer::open(store, id).is_err());
        assert_eq!(store.in_use_count(), 0, "buffers leaked");
    });
}

fn do_split_test(v: Variant, store: &mut MemoryBufferStore, size: usize) {
    let mut seed = 7;
    let mut cb = v.create(store, size);
    let bytes = pseudo_random(&mut seed, size);
    cb.put(store, 0, &bytes).unwrap();
    assert_eq!(cb.get(store, 0, size).unwrap(), bytes);
    let split = size / 2;
    let cb2 = cb.split(store, split as i32).unwrap();
    assert_eq!(cb.len() as usize, split);
    assert_eq!(cb2.len() as usize, size - split);
    assert_eq!(cb.get(store, 0, split).unwrap(), &bytes[..split]);
    assert_eq!(cb2.get(store, 0, size - split).unwrap(), &bytes[split..]);
}

#[test]
fn test_split() {
    for_each_variant(|v, store| {
        do_split_test(v, store, BUFFER_SIZE / 2); // single to single
        do_split_test(v, store, (BUFFER_SIZE as f64 * 1.5) as usize); // indexed to single
        do_split_test(v, store, BUFFER_SIZE * 4); // indexed to indexed
    });
}

fn do_append_test(v: Variant, store: &mut MemoryBufferStore, size1: usize, size2: usize) {
    let mut seed = 11;
    let mut cb1 = v.create(store, size1);
    let bytes1 = pseudo_random(&mut seed, size1);
    cb1.put(store, 0, &bytes1).unwrap();
    let mut cb2 = v.create(store, size2);
    let bytes2 = pseudo_random(&mut seed, size2);
    cb2.put(store, 0, &bytes2).unwrap();

    let r = cb1.append(store, &mut cb2);
    if v.sourced {
        assert!(matches!(r, Err(ChainError::Unsupported(_))));
        return;
    }
    r.unwrap();
    assert_eq!(cb1.len() as usize, size1 + size2);
    assert_eq!(cb2.id(), -1);
    assert_eq!(cb1.get(store, 0, size1).unwrap(), bytes1);
    assert_eq!(cb1.get(store, size1 as i32, size2).unwrap(), bytes2);
}

#[test]
fn test_append() {
    for_each_variant(|v, store| {
        let b = BUFFER_SIZE;
        do_append_test(v, store, b / 3, b / 3); // single + single = single
        do_append_test(v, store, b / 3, 2 * b); // single + indexed
        do_append_test(v, store, 2 * b, b / 3); // indexed + single
        do_append_test(v, store, 2 * b, 2 * b); // indexed + indexed
        do_append_test(v, store, 8 * b, 8 * b); // large indexed + large indexed
    });
}

#[test]
fn test_set_size() {
    for_each_variant(|v, store| {
        let mut seed = 3;
        let b = BUFFER_SIZE;
        let mut size = b / 2;
        let mut cb = v.create(store, size);
        let mut bytes = pseudo_random(&mut seed, size);
        cb.put(store, 0, &bytes).unwrap();

        let set = |cb: &mut ChainedBuffer, store: &mut MemoryBufferStore, n: usize| -> bool {
            match cb.set_size(store, n as i32, true) {
                Ok(()) => {
                    assert!(!v.sourced, "buffers with source data should refuse");
                    true
                }
                Err(ChainError::Unsupported(_)) => {
                    assert!(v.sourced);
                    false
                }
                Err(e) => panic!("{e}"),
            }
        };

        // Grow buffer (single index buffer)
        let new_size = (2.3 * b as f64) as usize;
        if set(&mut cb, store, new_size) {
            assert_eq!(cb.get(store, 0, size).unwrap(), bytes);
            let add = new_size - size;
            assert_eq!(cb.get(store, size as i32, add).unwrap(), vec![0; add]);
            let add_bytes = pseudo_random(&mut seed, add);
            cb.put(store, size as i32, &add_bytes).unwrap();
            assert_eq!(cb.get(store, 0, size).unwrap(), bytes);
            assert_eq!(cb.get(store, size as i32, add).unwrap(), add_bytes);
            bytes = cb.get(store, 0, new_size).unwrap();
            size = new_size;
            assert_eq!(cb.len() as usize, size);
        }

        // Grow buffer (multiple index buffers)
        let new_size = (b / 8) * b;
        if set(&mut cb, store, new_size) {
            let add = new_size - size;
            let add_bytes = pseudo_random(&mut seed, add);
            cb.put(store, size as i32, &add_bytes).unwrap();
            assert_eq!(cb.get(store, 0, size).unwrap(), bytes);
            assert_eq!(cb.get(store, size as i32, add).unwrap(), add_bytes);
            bytes = cb.get(store, 0, new_size).unwrap();
            size = new_size;
            assert_eq!(cb.len() as usize, size);
        }

        // Shrink buffer (single index buffer)
        let new_size = 2 * b;
        if set(&mut cb, store, new_size) {
            assert_eq!(cb.get(store, 0, new_size).unwrap(), &bytes[..new_size]);
            bytes = pseudo_random(&mut seed, new_size);
            cb.put(store, 0, &bytes).unwrap();
            assert_eq!(cb.get(store, 0, new_size).unwrap(), bytes);
            size = new_size;
            assert_eq!(cb.len() as usize, size);
        }

        // Shrink to small buffer
        let new_size = b / 2;
        if set(&mut cb, store, new_size) {
            assert_eq!(cb.get(store, 0, new_size).unwrap(), &bytes[..new_size]);
            bytes = pseudo_random(&mut seed, new_size);
            cb.put(store, 0, &bytes).unwrap();
            assert_eq!(cb.get(store, 0, new_size).unwrap(), bytes);
            assert_eq!(cb.len() as usize, new_size);
        }
    });
}

// ---- format-level checks (not in the Java suite) ----

#[test]
fn stored_layout_matches_documentation() {
    let mut store = MemoryBufferStore::new(BUFFER_SIZE);
    let mut cb = ChainedBuffer::create(&mut store, 10, true).unwrap();
    cb.put(&mut store, 0, &[1, 2, 3]).unwrap();
    let raw = store.get_buffer(cb.id()).unwrap().data.unwrap();
    assert_eq!(raw[0], CHAINED_BUFFER_DATA_NODE);
    // obfuscation bit set in the length field
    assert_eq!(&raw[1..5], &(10u32 | 0x8000_0000).to_be_bytes());
    assert_eq!(&raw[5..8], &[1 ^ 0x59, 2 ^ 0xea, 3 ^ 0x67]);
    // bytes never written hold the mask (obfuscated zero)
    assert_eq!(raw[8], 0x23);

    let big = ChainedBuffer::create(&mut store, 1000, false).unwrap();
    let raw = store.get_buffer(big.id()).unwrap().data.unwrap();
    assert_eq!(raw[0], CHAINED_BUFFER_INDEX_NODE);
    assert_eq!(&raw[1..5], &1000i32.to_be_bytes());
    assert_eq!(&raw[5..9], &(-1i32).to_be_bytes());
    // 255 data bytes per indexed node => 4 data nodes, none allocated yet
    assert_eq!(&raw[9..25], &[0xff; 16]);
    assert_eq!(big.buffer_count(), 4 + 1);
}

#[test]
fn open_rejects_non_chained_buffers_and_broken_index() {
    let mut store = MemoryBufferStore::new(BUFFER_SIZE);
    let id = store.create_buffer().unwrap();
    store.data_mut(id).unwrap()[0] = 3;
    assert!(matches!(
        ChainedBuffer::open(&store, id),
        Err(ChainError::InvalidBuffer)
    ));
    // index node claiming more data than its (single) index page can hold, no next link
    let id = store.create_buffer().unwrap();
    {
        let d = store.data_mut(id).unwrap();
        d[0] = CHAINED_BUFFER_INDEX_NODE;
        d[1..5].copy_from_slice(&(100_000i32).to_be_bytes());
        d[5..9].copy_from_slice(&(-1i32).to_be_bytes());
    }
    assert!(matches!(
        ChainedBuffer::open(&store, id),
        Err(ChainError::CorruptIndex)
    ));
}

#[test]
fn zero_and_negative_sizes_are_rejected() {
    let mut store = MemoryBufferStore::new(BUFFER_SIZE);
    assert!(ChainedBuffer::create(&mut store, 0, false).is_err());
    assert!(ChainedBuffer::create(&mut store, -5, false).is_err());
}

#[test]
fn dbparms_create_set_read() {
    let mut store = MemoryBufferStore::new(BUFFER_SIZE);
    let mut parms = DbParms::create(&mut store).unwrap();
    assert!(parms.is_empty());
    assert!(matches!(parms.get(0), Err(ChainError::ParmOutOfRange(0))));
    parms.set(&mut store, 0, 1).unwrap();
    parms.set(&mut store, 1, 0x3430_2ed5).unwrap();
    parms.set(&mut store, 2, 0x7e4d_460eu32 as i32).unwrap();
    let again = DbParms::read(&store).unwrap();
    assert_eq!(again, parms);
    assert_eq!(again.master_table_root().unwrap(), 1);
    assert_eq!(again.database_id().unwrap(), 0x3430_2ed5_7e4d_460e);
    let raw = store.get_buffer(0).unwrap().data.unwrap();
    assert_eq!(&raw[0..6], &[9, 0, 0, 0, 13, 1]);
    assert!(parms.set(&mut store, 1000, 1).is_err());
}

#[test]
fn dbparms_rejects_bad_node_type_and_version() {
    let mut store = MemoryBufferStore::new(BUFFER_SIZE);
    DbParms::create(&mut store).unwrap();
    store.data_mut(0).unwrap()[5] = 2;
    assert!(matches!(
        DbParms::read(&store),
        Err(ChainError::BadParms(_))
    ));
    store.data_mut(0).unwrap()[5] = 1;
    store.data_mut(0).unwrap()[0] = 8;
    assert!(matches!(
        DbParms::read(&store),
        Err(ChainError::BadParms(_))
    ));
}

fn fixture(rel: &str) -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures")
        .join(rel)
}

#[test]
fn fixture_dbparms() {
    for dir in ["legacy-12.1.4", "legacy-12.1.4-analysed"] {
        let bf = BufferFile::open(
            fixture(&format!("{dir}/legacy.rep/idata/00/~00000000.db/db.1.gbf")),
            true,
        )
        .unwrap();
        let parms = DbParms::read(&bf).unwrap();
        assert_eq!(parms.len(), 3);
        assert_eq!(parms.master_table_root().unwrap(), 1);
        if dir == "legacy-12.1.4" {
            assert_eq!(parms.database_id().unwrap(), 0x3430_2ed5_7e4d_460e);
        }
    }
}
