//! Rust twins of the white-box cases of tests/test_storelog.py (see TESTMAP.md). Tests share process-global state
//! (compaction thresholds, caches, environment), so they run one at a time under TEST_LOCK.

use hy_core::appendlog::{self, AppendLog};
use hy_core::sealed::{self, backup_path, read_sealed, write_sealed_default};
use hy_store::storelog::{self, CACHE_ENTRIES, SNAPSHOT_EVERY, SNAPSHOT_LOG_BYTES};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

static TEST_LOCK: Mutex<()> = Mutex::new(());

struct Fixture {
    _guard: std::sync::MutexGuard<'static, ()>,
    dir: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Self {
        let guard = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        storelog::configure(SNAPSHOT_EVERY, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
        storelog::clear_cache();
        appendlog::clear_verified();
        Fixture { _guard: guard, dir: tempfile::tempdir().unwrap() }
    }
    fn store(&self) -> PathBuf {
        self.dir.path().join("view.json")
    }
}

fn base() -> Value {
    json!({"version": 3, "edits": [], "reverted": [], "journal": [], "commits": [], "archived": [], "changesets": [], "meta": {"n": 0}})
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

fn read_back(path: &Path) -> Value {
    let snapshot = sealed::read_sealed_info(path, &Default::default(), None).unwrap().0;
    bare(storelog::read(path, Some(snapshot), None).unwrap().unwrap())
}

fn log_rows(path: &Path) -> Vec<Value> {
    AppendLog::new(storelog::log_path(path)).read().unwrap()
}

#[test]
fn a_mutation_is_one_framed_row_and_the_snapshot_is_not_rewritten() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::save(&path, &store, None, None).unwrap(); // first write: a snapshot
    let snapshot = std::fs::read(&path).unwrap();
    for i in 0..3 {
        store = with_edit(&store, i);
        storelog::save(&path, &store, None, None).unwrap();
    }
    assert_eq!(std::fs::read(&path).unwrap(), snapshot, "the snapshot must not be rewritten");
    let rows = log_rows(&path);
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["n"], 1);
    assert_eq!(rows[2]["lists"]["edits"], json!({"drop": 0, "push": [{"i": 2}]}));
    assert_eq!(read_back(&path), store);
}

#[test]
fn an_unchanged_store_writes_nothing() {
    let f = Fixture::new();
    let path = f.store();
    let store = base();
    storelog::save(&path, &store, None, None).unwrap();
    storelog::save(&path, &store, None, None).unwrap();
    assert!(!storelog::log_path(&path).exists() || log_rows(&path).is_empty());
}

#[test]
fn the_budget_is_refused_before_anything_is_written() {
    let f = Fixture::new();
    let path = f.store();
    let mut store = base();
    store["blob"] = json!("x".repeat(5000));
    let error = storelog::save(&path, &store, Some(1000), Some("store too big")).unwrap_err();
    assert_eq!(error.to_string(), "store too big");
    assert!(!path.exists());
    // An existing store: a later oversize mutation is refused before its row is appended.
    let small = base();
    storelog::save(&path, &small, Some(100_000), None).unwrap();
    let rows_before = storelog::log_path(&path).exists();
    let error = storelog::save(&path, &store, Some(1000), None).unwrap_err();
    assert!(error.to_string().starts_with("record would exceed 1000 bytes"));
    assert_eq!(storelog::log_path(&path).exists(), rows_before);
}

#[test]
fn a_failed_compaction_after_the_row_is_durable_is_not_reported_as_a_failed_write() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::configure(2, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
    storelog::save(&path, &store, None, None).unwrap();
    store = with_edit(&store, 1);
    storelog::save(&path, &store, None, None).unwrap();
    // The next mutation is due for compaction; a directory in place of the .bak makes the snapshot write fail.
    std::fs::remove_file(backup_path(&path)).unwrap();
    std::fs::create_dir(backup_path(&path)).unwrap();
    store = with_edit(&store, 2);
    storelog::save(&path, &store, None, None).expect("the mutation is durable, so the write is not reported as failed");
    assert!(storelog::UPKEEP_ERRORS.lock().unwrap().values().any(|m| m.starts_with("compaction:")));
    assert_eq!(read_back(&path), store);
}

#[test]
fn a_size_triggered_compaction_is_not_followed_at_once_by_another() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::configure(1000, 3000, CACHE_ENTRIES);
    storelog::save(&path, &store, None, None).unwrap();
    let mut snapshots = 0;
    let mut last = std::fs::read(&path).unwrap();
    let mut gaps = Vec::new();
    let mut since = 0;
    for i in 0..60 {
        store = with_edit(&store, i);
        storelog::save(&path, &store, None, None).unwrap();
        since += 1;
        let now = std::fs::read(&path).unwrap();
        if now != last {
            snapshots += 1;
            gaps.push(since);
            since = 0;
            last = now;
        }
    }
    assert!(snapshots >= 1, "the byte budget should have triggered a compaction");
    assert!(gaps.iter().all(|&g| g >= 2), "a compaction was followed at once by another: {gaps:?}");
    assert_eq!(read_back(&path), store);
}

#[test]
fn the_per_process_caches_are_bounded() {
    let f = Fixture::new();
    storelog::configure(SNAPSHOT_EVERY, SNAPSHOT_LOG_BYTES, 3);
    for n in 0..8 {
        let path = f.dir.path().join(format!("v{n}.json"));
        storelog::save(&path, &base(), None, None).unwrap();
        storelog::save(&path, &with_edit(&base(), 1), None, None).unwrap();
    }
    assert!(storelog::cache_len() <= 3);
}

#[test]
fn a_damaged_main_file_reads_the_newest_state_from_the_backup_and_the_log() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::configure(4, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
    storelog::save(&path, &store, None, None).unwrap();
    for i in 0..9 {
        store = with_edit(&store, i);
        storelog::save(&path, &store, None, None).unwrap();
    }
    std::fs::write(&path, b"{torn").unwrap();
    assert_eq!(read_back_via_backup(&path), store);
}

fn read_back_via_backup(path: &Path) -> Value {
    let (snapshot, source) = sealed::read_sealed_info(path, &Default::default(), None).unwrap();
    assert_eq!(source, sealed::Source::Backup);
    bare(storelog::read(path, Some(snapshot), None).unwrap().unwrap())
}

#[test]
fn a_torn_log_tail_is_ignored_and_repaired_by_the_next_append() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::save(&path, &store, None, None).unwrap();
    store = with_edit(&store, 1);
    storelog::save(&path, &store, None, None).unwrap();
    let log = storelog::log_path(&path);
    let mut bytes = std::fs::read(&log).unwrap();
    bytes.extend_from_slice(b"1234abcd {\"a\":\"half");
    std::fs::write(&log, bytes).unwrap();
    assert_eq!(read_back(&path), store);
    store = with_edit(&store, 2);
    storelog::save(&path, &store, None, None).unwrap();
    assert_eq!(read_back(&path), store);
    assert!(AppendLog::new(&log).scan().torn_tail.is_none());
}

#[test]
fn corruption_inside_the_log_is_store_corrupt() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::save(&path, &store, None, None).unwrap();
    for i in 0..3 {
        store = with_edit(&store, i);
        storelog::save(&path, &store, None, None).unwrap();
    }
    let log = storelog::log_path(&path);
    let mut lines: Vec<Vec<u8>> = std::fs::read(&log).unwrap().split_inclusive(|&b| b == b'\n').map(<[u8]>::to_vec).collect();
    lines[1] = b"00000000 {\"bad\"\n".to_vec();
    std::fs::write(&log, lines.concat()).unwrap();
    let snapshot = read_sealed(&path).unwrap();
    let error = storelog::read(&path, Some(snapshot), None).unwrap_err();
    assert_eq!(error.code(), Some("store_corrupt"));
    assert!(error.to_string().contains("view.json.log: log corrupt at byte"), "{error}");
}

#[test]
fn a_snapshot_without_an_anchor_never_takes_a_stale_log() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::save(&path, &store, None, None).unwrap();
    store = with_edit(&store, 1);
    storelog::save(&path, &store, None, None).unwrap();
    // A whole-store writer (older Hydralysis) replaces the snapshot without an anchor; the old log must not replay.
    let plain = with_edit(&with_edit(&base(), 7), 8);
    write_sealed_default(&path, &plain).unwrap();
    assert_eq!(read_back(&path), plain);
}

#[test]
fn another_writer_between_two_of_mine_is_seen() {
    let f = Fixture::new();
    let (path, mut store) = (f.store(), base());
    storelog::save(&path, &store, None, None).unwrap();
    store = with_edit(&store, 1);
    storelog::save(&path, &store, None, None).unwrap();
    // "Another process" appends a row behind this process's cache.
    let log = AppendLog::new(storelog::log_path(&path));
    let anchor = read_sealed(&path).unwrap()["log_anchor"].clone();
    log.append(&json!({"a": anchor, "n": 2, "set": {"meta": {"n": 99}}}), false).unwrap();
    let mut mine = store.clone();
    mine["scalar"] = json!(1);
    storelog::save(&path, &mine, None, None).unwrap();
    let back = read_back(&path);
    assert_eq!(back["scalar"], 1);
    assert_eq!(back["edits"], store["edits"]);
}

// ---------------------------------------------------------------------------------------------- crashes

fn child(path: &Path, fault: &str, every: u64) -> std::process::ExitStatus {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"]);
    command.env("HY_CHILD", "storelog").env("HY_CHILD_PATH", path).env("HY_CHILD_EVERY", every.to_string());
    command.env("HYDRALYSIS_TEST_MODE", "1").env("HYDRALYSIS_TEST_FAULT", fault);
    command.output().unwrap().status
}

#[test]
fn child_entry() {
    let Ok(case) = std::env::var("HY_CHILD") else { return };
    assert_eq!(case, "storelog");
    let path = PathBuf::from(std::env::var("HY_CHILD_PATH").unwrap());
    let every: u64 = std::env::var("HY_CHILD_EVERY").unwrap().parse().unwrap();
    storelog::configure(every, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
    let mut current = read_back(&path);
    for i in 0..3 {
        current = with_edit(&current, 1000 + i);
        let _ = storelog::save(&path, &current, None, None);
    }
}

#[test]
fn kill_points_of_an_append_and_of_a_compaction_leave_the_last_acknowledged_state_or_the_new_one() {
    for (fault, every, prior) in [
        ("log.before_write:exit", 1000, 2),
        ("log.torn_append:torn:7", 1000, 2),
        ("log.torn_append:torn:30", 1000, 2),
        ("store.after_append:exit", 1000, 2),
        ("log.after_append:exit", 1000, 2),
        ("atomic.before_replace:exit", 3, 5),
        ("atomic.after_replace:exit", 3, 5),
        ("store.after_snapshot:exit", 3, 5),
        ("store.trim.before_replace:exit", 3, 7),
        ("store.trim.after_replace:exit", 3, 7),
    ] {
        let f = Fixture::new();
        let (path, mut store) = (f.store(), base());
        storelog::configure(every, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
        storelog::save(&path, &store, None, None).unwrap();
        for i in 0..prior {
            store = with_edit(&store, i);
            storelog::save(&path, &store, None, None).unwrap();
        }
        assert_eq!(child(&path, fault, every).code(), Some(137), "{fault}");
        storelog::clear_cache();
        appendlog::clear_verified();
        let after = read_back(&path);
        // The last acknowledged state, or that state plus the first k edits of the killed writer (never a mixture).
        let mut allowed = vec![store.clone()];
        for i in 0..3 {
            let last = allowed.last().unwrap().clone();
            allowed.push(with_edit(&last, 1000 + i));
        }
        assert!(allowed.contains(&after), "{fault}: {after}");
        // and the store keeps working
        let next = with_edit(&after, 2000);
        storelog::save(&path, &next, None, None).unwrap();
        assert_eq!(read_back(&path), next, "{fault}");
    }
}

#[test]
fn random_mutation_sequences_load_identically_with_compaction() {
    let f = Fixture::new();
    let path = f.store();
    storelog::configure(5, SNAPSHOT_LOG_BYTES, CACHE_ENTRIES);
    let mut store = base();
    let mut seed = 0x9E37_79B9_7F4A_7C15_u64;
    let mut next = || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for i in 0..300u64 {
        let field = ["edits", "reverted", "journal", "commits", "archived", "changesets"][(next() % 6) as usize];
        match next() % 5 {
            0 | 1 => store[field].as_array_mut().unwrap().push(json!({"i": i})),
            2 => {
                let list = store[field].as_array_mut().unwrap();
                let drop = (next() as usize) % (list.len() + 1);
                list.drain(..drop);
                list.push(json!({"i": i}));
            }
            3 => store["meta"] = json!({"n": i}),
            _ => {
                store.as_object_mut().unwrap().insert("scalar".into(), json!(i));
            }
        }
        storelog::save(&path, &store, None, None).unwrap();
        if i % 7 == 0 {
            storelog::clear_cache(); // as another process would: the writer re-reads the chain
        }
        if i % 11 == 0 {
            assert_eq!(read_back(&path), store, "step {i}");
        }
    }
    assert_eq!(read_back(&path), store);
}
