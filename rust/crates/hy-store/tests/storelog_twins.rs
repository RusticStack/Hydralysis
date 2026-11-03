//! Rust twin of test_storelog.py::test_a_reader_whose_snapshot_was_replaced_twice_meanwhile_reads_again (it patches
//! `storelog._identity`); the identity probe of `storelog::read_with` is injectable for the same purpose.

use hy_core::sealed::read_sealed;
use hy_store::storelog::{self, CACHE_ENTRIES, SNAPSHOT_LOG_BYTES};
use serde_json::{Value, json};
use std::path::Path;

fn base() -> Value {
    json!({"version": 3, "edits": [], "reverted": [], "journal": [], "commits": [], "archived": [], "changesets": []})
}

fn with_edit(store: &Value, i: u64) -> Value {
    let mut next = store.clone();
    next["edits"].as_array_mut().unwrap().push(json!({"i": i}));
    next
}

fn bare(mut record: Value) -> Value {
    let map = record.as_object_mut().unwrap();
    map.remove("log_anchor");
    map.remove("log_prev");
    record
}

#[test]
fn a_reader_whose_snapshot_was_replaced_meanwhile_reads_again() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("view.json");
    let mut store = base();
    storelog::configure(3, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
    storelog::save(&path, &store, None, None).unwrap();
    store = with_edit(&store, 0);
    storelog::save(&path, &store, None, None).unwrap();
    let stale = read_sealed(&path).unwrap();
    for i in 1..9 {
        store = with_edit(&store, i); // several compactions: the stale snapshot's rows are trimmed away
        storelog::save(&path, &store, None, None).unwrap();
    }
    let rereads = std::cell::Cell::new(0);
    let reread = || {
        rereads.set(rereads.get() + 1);
        Ok(Some(read_sealed(&path).unwrap()))
    };
    // The identity probe changes once, as if the snapshot file was replaced while the log was being read.
    let probes = std::cell::Cell::new(0u64);
    let identity = |_: &Path| {
        probes.set(probes.get() + 1);
        Some((probes.get() / 2, 0, 0))
    };
    let got = storelog::read_with(&path, Some(stale.clone()), Some(&reread), &identity).unwrap().unwrap();
    assert!(rereads.get() >= 1, "the snapshot must be read again");
    assert_eq!(bare(got), store);
    // Without the retry the stale chain silently stops at the stale snapshot.
    let stuck = storelog::read(&path, Some(stale), None).unwrap().unwrap();
    assert_ne!(bare(stuck), store);
    storelog::configure(storelog::SNAPSHOT_EVERY, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
}
