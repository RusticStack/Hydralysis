//! Unit tests for the database read path.

use super::*;
use ghidra_fmt_gbf::MemoryBufferStore;
use std::path::Path;

fn fixture() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../../Features/HeadlessSession/examples/fixtures/legacy-12.1.4")
        .join("legacy.rep/idata/00/~00000000.db/db.1.gbf")
}

#[test]
fn master_schema_matches_table_record() {
    let s = master_schema();
    assert_eq!(s.fields().len(), 9);
    assert_eq!(s.key_name(), "TableNum");
    assert_eq!(s.key_type(), &FieldType::Long);
    assert!(s.is_variable_length());
    assert!(s.use_long_key_nodes());
}

#[test]
fn database_without_master_root_has_no_tables() {
    let mut store = MemoryBufferStore::new(512);
    let mut p = DbParms::create(&mut store).unwrap();
    p.set(&mut store, 0, -1).unwrap();
    let db = Database::open(store).unwrap();
    assert!(db.table_records().is_empty());
    assert!(matches!(db.table("x"), Err(DbError::TableNotFound(_))));
}

#[test]
fn missing_params_buffer_is_an_error() {
    let store = MemoryBufferStore::new(512);
    assert!(Database::open(store).is_err());
}

#[test]
fn fixture_lookup_by_key_name_and_index() {
    let bf = ghidra_fmt_gbf::BufferFile::open(fixture(), true).unwrap();
    let db = Database::open(bf).unwrap();
    let t = db.table("Comment History").unwrap();
    assert_eq!(t.record_count(), 228);
    let first = t.records().unwrap().next().unwrap().unwrap();
    let again = t.get(&first.key).unwrap().unwrap();
    assert_eq!(first, again);
    assert!(t.get(&Field::Long(i64::MAX)).unwrap().is_none());
    // primary table with root -1 is empty
    let e = db.table("Instructions").unwrap();
    assert_eq!(e.records().unwrap().count(), 0);
    assert!(e.get(&Field::Long(0)).unwrap().is_none());
    // a non-index table has no index entries
    assert!(t.index_entries().is_err());
    // an unindexed column has no index table
    assert!(t.find_primary_keys(7, &Field::Int(0)).unwrap().is_none());
    // the string-keyed Program table goes through the field-key reader
    let p = db.table("Program").unwrap();
    assert_eq!(p.records().unwrap().count(), 7);
    let k = p.records().unwrap().next().unwrap().unwrap().key;
    assert!(p.get(&k).unwrap().is_some());
}
