//! Ports of `db.buffers.LocalBufferFileTest` plus format-level checks.

use super::*;
use std::sync::atomic::{AtomicU32, Ordering};

const BUFFER_SIZE: usize = 1024;

struct TestDir(PathBuf);

impl TestDir {
    fn new(tag: &str) -> Self {
        static N: AtomicU32 = AtomicU32::new(0);
        let p = std::env::temp_dir().join(format!(
            "ghidra-fmt-gbf-{tag}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::SeqCst)
        ));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        Self(p)
    }

    fn file(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn filled(b: u8) -> Vec<u8> {
    vec![b; BUFFER_SIZE]
}

/// `doReadTest1`
fn do_read_test1(bf: &BufferFile) {
    for (idx, id, b) in [(0, 10, 0xf0u8), (2, 12, 0xf2), (1, 11, 0xf1)] {
        let buf = bf.get_buffer(idx).unwrap();
        assert_eq!(buf.id, id);
        assert!(!buf.empty);
        assert_eq!(buf.data.unwrap(), filled(b));
    }
}

/// `doReadTest2`: buffer 2 is now empty.
fn do_read_test2(bf: &BufferFile) {
    let b0 = bf.get_buffer(0).unwrap();
    assert_eq!(b0.id, 10);
    assert_eq!(b0.data.unwrap(), filled(0xf0));
    let b2 = bf.get_buffer(2).unwrap();
    assert_eq!(b2.id, -1);
    assert!(b2.empty);
    let b1 = bf.get_buffer(1).unwrap();
    assert_eq!(b1.id, 11);
    assert_eq!(b1.data.unwrap(), filled(0xf1));
}

/// `doWriteReadTest`; returns the static free list.
fn do_write_read_test(bf: &mut BufferFile) -> Vec<i32> {
    assert!(matches!(
        bf.get_buffer(0),
        Err(GbfError::IndexOutOfRange { .. })
    ));
    let small = DataBuffer::new(0, vec![0; BUFFER_SIZE - 1]);
    assert!(matches!(
        bf.put(&small, 0),
        Err(GbfError::BadBufferSize { .. })
    ));

    bf.put(&DataBuffer::new(10, filled(0xf0)), 0).unwrap();
    bf.put(&DataBuffer::new(11, filled(0xf1)), 1).unwrap();
    bf.put(&DataBuffer::new(12, filled(0xf2)), 2).unwrap();
    do_read_test1(bf);

    bf.put(&DataBuffer::empty(12), 2).unwrap();
    do_read_test2(bf);
    vec![2]
}

#[test]
fn test_temp_file() {
    let dir = TestDir::new("temp");
    let mut bf = BufferFile::create_temp(&dir.0, "test", ".tmp", BUFFER_SIZE).unwrap();
    let path = bf.path().to_path_buf();
    assert!(path.exists());
    assert_eq!(bf.buffer_size(), BUFFER_SIZE);
    assert!(bf.free_indexes().is_empty());
    assert_eq!(bf.index_count(), 0);
    do_write_read_test(&mut bf);
    bf.close().unwrap();
    assert!(!path.exists());
}

#[test]
fn test_file_save() {
    let dir = TestDir::new("save");
    let path = dir.file("test.bf");
    let mut bf = BufferFile::create(&path, BUFFER_SIZE, 0x1234_5678_9abc_def0).unwrap();
    assert!(path.exists());
    assert_eq!(bf.buffer_size(), BUFFER_SIZE);
    assert!(bf.free_indexes().is_empty());
    assert_eq!(bf.index_count(), 0);

    let free_list = do_write_read_test(&mut bf);
    let index_cnt = bf.index_count();
    bf.set_free_indexes(&free_list);
    let file_id = bf.file_id();
    assert_ne!(file_id, 0);
    bf.set_parameter("TestParm1", 0x321).unwrap();
    bf.set_parameter("TestParm2", 0x543).unwrap();
    bf.close().unwrap();
    assert!(path.exists());

    let bf = BufferFile::open(&path, true).unwrap();
    assert_eq!(bf.index_count(), index_cnt);
    assert_eq!(bf.free_indexes(), free_list.as_slice());
    assert_eq!(bf.file_id(), file_id);
    assert_eq!(bf.parameter("TestParm1").unwrap(), 0x321);
    assert_eq!(bf.parameter("TestParm2").unwrap(), 0x543);
    do_read_test2(&bf);
    bf.close().unwrap();
    assert!(path.exists());
}

#[test]
fn test_file_modify() {
    let dir = TestDir::new("modify");
    let path = dir.file("test.bf");
    let mut bf = BufferFile::create(&path, BUFFER_SIZE, 42).unwrap();
    let free_list = do_write_read_test(&mut bf);
    let index_cnt = bf.index_count();
    bf.set_free_indexes(&free_list);
    let file_id = bf.file_id();
    bf.set_parameter("TestParm1", 0x321).unwrap();
    bf.set_parameter("TestParm2", 0x543).unwrap();
    bf.close().unwrap();

    let mut bf = BufferFile::open(&path, false).unwrap();
    assert_eq!(bf.index_count(), index_cnt);
    assert_eq!(bf.free_indexes(), free_list.as_slice());
    assert_eq!(bf.file_id(), file_id);
    assert_eq!(bf.parameter("TestParm1").unwrap(), 0x321);
    do_read_test2(&bf);

    bf.set_parameter("TestParm1", 0x322).unwrap();
    bf.set_parameter("TestParm2", 0x544).unwrap();
    bf.put(&DataBuffer::new(12, filled(0xf2)), 2).unwrap();
    do_read_test1(&bf);
    bf.set_free_indexes(&[]);
    bf.close().unwrap();

    let bf = BufferFile::open(&path, true).unwrap();
    assert_eq!(bf.index_count(), index_cnt);
    assert!(bf.free_indexes().is_empty());
    assert_eq!(bf.file_id(), file_id);
    assert_eq!(bf.parameter("TestParm1").unwrap(), 0x322);
    assert_eq!(bf.parameter("TestParm2").unwrap(), 0x544);
    do_read_test1(&bf);
}

#[test]
fn test_create_existing_file_is_duplicate() {
    let dir = TestDir::new("dup");
    let path = dir.file("a.gbf");
    BufferFile::create(&path, BUFFER_SIZE, 1)
        .unwrap()
        .close()
        .unwrap();
    assert!(matches!(
        BufferFile::create(&path, BUFFER_SIZE, 1),
        Err(GbfError::DuplicateFile(_))
    ));
}

#[test]
fn test_unsupported_buffer_size() {
    let dir = TestDir::new("size");
    assert!(matches!(
        BufferFile::create(dir.file("a"), 100, 1),
        Err(GbfError::UnsupportedBufferSize(100))
    ));
    assert!(matches!(
        BufferFile::create(dir.file("b"), 65532, 1),
        Err(GbfError::UnsupportedBufferSize(65532))
    ));
}

#[test]
fn test_header_bytes_and_padding() {
    let dir = TestDir::new("hdr");
    let path = dir.file("h.gbf");
    let mut bf = BufferFile::create(&path, 507, 0x0102_0304_0506_0708).unwrap();
    bf.put(&DataBuffer::new(0, vec![7; 507]), 0).unwrap();
    bf.put(&DataBuffer::empty(-1), 1).unwrap();
    bf.set_free_indexes(&[1]);
    bf.set_parameter("P", 9).unwrap();
    bf.close().unwrap();

    let raw = fs::read(&path).unwrap();
    assert_eq!(raw.len(), 512 * 3);
    assert_eq!(&raw[0..8], &MAGIC_NUMBER.to_be_bytes());
    assert_eq!(&raw[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(&raw[16..20], &[0, 0, 0, 1]);
    assert_eq!(&raw[20..24], &512i32.to_be_bytes());
    assert_eq!(&raw[24..28], &1i32.to_be_bytes()); // first free = index 1
    assert_eq!(&raw[28..32], &1i32.to_be_bytes());
    assert_eq!(&raw[32..36], &1i32.to_be_bytes());
    assert_eq!(raw[36], b'P');
    assert_eq!(&raw[37..41], &9i32.to_be_bytes());
    // buffer 1 (block 2) is free, last in list
    assert_eq!(raw[1024], EMPTY_BUFFER);
    assert_eq!(&raw[1025..1029], &(-1i32).to_be_bytes());
    // buffer 0 (block 1) in use with id 0
    assert_eq!(raw[512], 0);
    assert_eq!(&raw[517..520], &[7, 7, 7]);
}

fn raw_header(magic: i64, version: i32, block: i32, len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&magic.to_be_bytes());
    v.extend_from_slice(&0i64.to_be_bytes());
    v.extend_from_slice(&version.to_be_bytes());
    v.extend_from_slice(&block.to_be_bytes());
    v.extend_from_slice(&(-1i32).to_be_bytes());
    v.extend_from_slice(&0i32.to_be_bytes());
    v.resize(len, 0);
    v
}

#[test]
fn test_negative_headers() {
    let dir = TestDir::new("neg");
    let p = dir.file("bad.gbf");
    type Check = fn(&GbfError) -> bool;
    let cases: Vec<(Vec<u8>, Check)> = vec![
        (raw_header(1, 1, 512, 512), |e| {
            matches!(e, GbfError::BadMagic(1))
        }),
        (raw_header(MAGIC_NUMBER, 2, 512, 512), |e| {
            matches!(e, GbfError::BadHeaderVersion(2))
        }),
        (raw_header(MAGIC_NUMBER, 1, 511, 512), |e| {
            matches!(e, GbfError::UnsupportedBlockSize(511))
        }),
        (raw_header(MAGIC_NUMBER, 1, 65537, 512), |e| {
            matches!(e, GbfError::UnsupportedBlockSize(65537))
        }),
        (raw_header(MAGIC_NUMBER, 1, 512, 700), |e| {
            matches!(e, GbfError::CorruptFile(_))
        }),
        (raw_header(MAGIC_NUMBER, 1, 512, 20), |e| {
            matches!(e, GbfError::Io(_))
        }),
    ];
    for (bytes, check) in cases {
        fs::write(&p, bytes).unwrap();
        let err = BufferFile::open(&p, true).unwrap_err();
        assert!(check(&err), "unexpected error {err}");
    }
}

#[test]
fn test_free_list_pointing_at_used_block_is_corrupt() {
    let dir = TestDir::new("freecorrupt");
    let p = dir.file("f.gbf");
    let mut bytes = raw_header(MAGIC_NUMBER, 1, 512, 1024);
    bytes[24..28].copy_from_slice(&0i32.to_be_bytes());
    fs::write(&p, bytes).unwrap();
    assert!(matches!(
        BufferFile::open(&p, true),
        Err(GbfError::CorruptFile(_))
    ));
}

#[test]
fn test_read_only_refuses_put() {
    let dir = TestDir::new("ro");
    let p = dir.file("r.gbf");
    BufferFile::create(&p, BUFFER_SIZE, 1)
        .unwrap()
        .close()
        .unwrap();
    let mut bf = BufferFile::open(&p, true).unwrap();
    assert!(matches!(
        bf.put(&DataBuffer::new(0, filled(1)), 0),
        Err(GbfError::ReadOnly)
    ));
}

#[test]
fn test_parameter_name_limit_and_missing() {
    let dir = TestDir::new("parm");
    let mut bf = BufferFile::create(dir.file("p.gbf"), BUFFER_SIZE, 1).unwrap();
    let long = "x".repeat(MAX_PARAM_NAME_LENGTH + 1);
    assert!(matches!(
        bf.set_parameter(&long, 1),
        Err(GbfError::ParameterNameTooLong(_))
    ));
    bf.set_parameter(&"x".repeat(MAX_PARAM_NAME_LENGTH), 1)
        .unwrap();
    assert!(matches!(
        bf.parameter("nope"),
        Err(GbfError::NoSuchParameter(_))
    ));
}

#[test]
fn test_block_conversion_uses_equality_for_empty() {
    let mut block = vec![0u8; 512];
    assert_eq!(data_buffer_from_block(0, &block).unwrap(), None);
    block[0] = EMPTY_BUFFER;
    assert_eq!(
        data_buffer_from_block(1, &block).unwrap(),
        Some(DataBuffer::empty(-1))
    );
    // flags 0x03 is "empty" for get() but in use for getDataBuffer() (Java quirk kept)
    block[0] = 3;
    block[4] = 5;
    let b = data_buffer_from_block(1, &block).unwrap().unwrap();
    assert!(!b.empty);
    assert_eq!(b.id, 5);
    assert_eq!(b.data.unwrap().len(), 507);
}

#[test]
fn memory_store_round_trips() {
    let mut m = MemoryBufferStore::new(512);
    let id = m.create_buffer().unwrap();
    m.data_mut(id).unwrap()[3] = 9;
    assert_eq!(m.get_buffer(id).unwrap().data.unwrap()[3], 9);
    assert!(m.get_buffer(5).is_err());
    assert!(m.data_mut(-1).is_err());
}

fn fixture(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures")
        .join(rel)
}

#[test]
fn fixture_legacy_gbf_header_and_buffers() {
    let bf = BufferFile::open(
        fixture("legacy-12.1.4/legacy.rep/idata/00/~00000000.db/db.1.gbf"),
        true,
    )
    .unwrap();
    assert_eq!(bf.block_size(), 0x4000);
    assert_eq!(bf.buffer_size(), 0x4000 - 5);
    assert_eq!(bf.index_count(), 95);
    // buffer 0 is DBParms: node type 9, data length 13, version 1, parm0 = 1
    let b0 = bf.get_buffer(0).unwrap();
    assert_eq!(b0.id, 0);
    let d = b0.data.unwrap();
    assert_eq!(d[0], 9);
    assert_eq!(&d[1..5], &13i32.to_be_bytes());
    assert_eq!(d[5], 1);
    assert_eq!(&d[6..10], &1i32.to_be_bytes());
    // in a saved file every in-use buffer's id equals its index
    for i in 0..bf.index_count() {
        let b = bf.get_buffer(i).unwrap();
        assert!(b.empty || b.id == i, "index {i} has id {}", b.id);
    }
}

#[test]
fn memory_store_reuses_freed_indexes_with_their_old_bytes() {
    let mut s = MemoryBufferStore::new(64);
    let a = s.create_buffer().unwrap();
    let b = s.create_buffer().unwrap();
    s.data_mut(a).unwrap().fill(7);
    s.data_mut(b).unwrap().fill(9);
    s.delete_buffer(a).unwrap();
    s.delete_buffer(b).unwrap();
    // stack order: most recently freed first, bytes are not cleared (BufferMgr cache)
    assert_eq!(s.create_buffer().unwrap(), b);
    assert_eq!(s.get_buffer(b).unwrap().data.unwrap(), vec![9; 64]);
    assert_eq!(s.create_buffer().unwrap(), a);
    assert_eq!(s.get_buffer(a).unwrap().data.unwrap(), vec![7; 64]);
    // a never used index is zero filled
    let c = s.create_buffer().unwrap();
    assert_eq!(s.get_buffer(c).unwrap().data.unwrap(), vec![0; 64]);
}
