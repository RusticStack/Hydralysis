//! Rust twins of the white-box cases of tests/test_durable.py (see rust/crates/hy-store/TESTMAP.md).
//! Crash cases run a child process (this test binary re-invoked with `HY_CHILD=<case>`), as the Python tests do.

use hy_core::appendlog::{self, AppendLog, frame, scan_bytes};
use hy_core::error::Error;
use hy_core::fsio::{atomic_write, atomic_write_point};
use hy_core::sealed::{self, Kind, ReadOptions, Source, backup_path, read_sealed, write_sealed, write_sealed_default};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::Command;

fn child(case: &str, path: &Path, fault: Option<&str>, extra: &[(&str, &str)]) -> std::process::ExitStatus {
    let exe = std::env::current_exe().unwrap();
    let mut command = Command::new(exe);
    command.args(["--exact", "child_entry", "--nocapture", "--test-threads=1"]);
    command.env("HY_CHILD", case).env("HY_CHILD_PATH", path);
    if let Some(fault) = fault {
        command.env("HYDRALYSIS_TEST_MODE", "1").env("HYDRALYSIS_TEST_FAULT", fault);
    }
    for (k, v) in extra {
        command.env(k, v);
    }
    command.output().unwrap().status
}

/// Entry point of the child processes (a no-op in the normal test run).
#[test]
fn child_entry() {
    let Ok(case) = std::env::var("HY_CHILD") else { return };
    let path = PathBuf::from(std::env::var("HY_CHILD_PATH").unwrap());
    match case.as_str() {
        "atomic" => {
            let _ = atomic_write(&path, b"new");
        }
        "append" => {
            let _ = AppendLog::new(&path).append(&json!({"k": "child"}), false);
        }
        "seal" => {
            let _ = write_sealed_default(&path, &json!({"v": 3}));
        }
        other => panic!("unknown child case {other}"),
    }
}

fn tmp() -> tempfile_dir::Dir {
    tempfile_dir::Dir::new()
}

/// A tiny temp directory helper so hy-core needs no dev-dependency.
mod tempfile_dir {
    use std::path::{Path, PathBuf};
    pub struct Dir(PathBuf);
    impl Dir {
        pub fn new() -> Self {
            let path = std::env::temp_dir().join(format!("hy-core-test-{}", uuid::Uuid::new_v4().simple()));
            std::fs::create_dir_all(&path).unwrap();
            Dir(path)
        }
        pub fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

// ----------------------------------------------------------------------------------------- AtomicWrite

#[test]
fn writes_replaces_and_leaves_no_temporary() {
    let dir = tmp();
    let target = dir.path().join("a.json");
    atomic_write(&target, b"one").unwrap();
    atomic_write(&target, b"two").unwrap();
    assert_eq!(std::fs::read(&target).unwrap(), b"two");
    let names: Vec<_> = std::fs::read_dir(dir.path()).unwrap().map(|e| e.unwrap().file_name()).collect();
    assert_eq!(names.len(), 1, "{names:?}");
}

#[cfg(windows)]
#[test]
fn a_denied_replace_is_retried_until_the_holder_lets_go() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tmp();
    let target = dir.path().join("held.json");
    std::fs::write(&target, b"old").unwrap();
    // share_mode(0): no sharing at all, so the replace hits a sharing violation until the handle is closed.
    let holder = std::fs::OpenOptions::new().read(true).share_mode(0).open(&target).unwrap();
    let release = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(400));
        drop(holder);
    });
    let started = std::time::Instant::now();
    atomic_write(&target, b"new").unwrap();
    release.join().unwrap();
    assert!(started.elapsed().as_millis() >= 300, "the replace should have waited for the holder");
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
}

#[test]
fn the_native_move_really_replaces_an_existing_file() {
    let dir = tmp();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::write(&a, b"A").unwrap();
    std::fs::write(&b, b"B").unwrap();
    hy_core::fsio::replace_file(&a, &b).unwrap();
    assert_eq!(std::fs::read(&b).unwrap(), b"A");
    assert!(!a.exists());
}

#[test]
fn killing_the_writer_before_the_replace_keeps_the_old_content() {
    let dir = tmp();
    let target = dir.path().join("t.json");
    atomic_write(&target, b"old").unwrap();
    let status = child("atomic", &target, Some("atomic.before_replace:exit"), &[]);
    assert_eq!(status.code(), Some(137));
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
}

#[test]
fn killing_the_writer_after_the_replace_leaves_the_new_content() {
    let dir = tmp();
    let target = dir.path().join("t.json");
    atomic_write(&target, b"old").unwrap();
    assert_eq!(child("atomic", &target, Some("atomic.after_replace:exit"), &[]).code(), Some(137));
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
}

#[test]
fn a_non_atomic_writer_killed_midway_is_detected_and_the_previous_version_is_returned() {
    let dir = tmp();
    let target = dir.path().join("t.json");
    write_sealed(&target, &json!({"v": 1}), Some(2), None, None).unwrap();
    write_sealed(&target, &json!({"v": 2}), Some(2), None, None).unwrap();
    assert_eq!(child("seal", &target, Some("atomic.torn:torn:7"), &[]).code(), Some(137));
    assert_eq!(std::fs::read(&target).unwrap().len(), 7);
    let (value, source) = sealed::read_sealed_info(&target, &ReadOptions::default(), None).unwrap();
    assert_eq!((value["v"].clone(), source), (json!(2), Source::Backup));
}

#[test]
fn the_hook_is_inert_without_test_mode() {
    let dir = tmp();
    let target = dir.path().join("t");
    // HYDRALYSIS_TEST_MODE unset: a fault spec alone does nothing.
    let status = child("atomic", &target, None, &[("HYDRALYSIS_TEST_FAULT", "atomic.before_replace:exit")]);
    assert_eq!(status.code(), Some(0));
    assert_eq!(std::fs::read(&target).unwrap(), b"new");
}

// ----------------------------------------------------------------------------------------- SealedJson

#[test]
fn round_trip_seals_a_canonical_body_and_keeps_the_previous_version() {
    let dir = tmp();
    let target = dir.path().join("r.json");
    write_sealed_default(&target, &json!({"b": 1, "a": [1, 2]})).unwrap();
    write_sealed_default(&target, &json!({"b": 2})).unwrap();
    let raw: Value = serde_json::from_slice(&std::fs::read(&target).unwrap()).unwrap();
    assert_eq!(raw["seal"]["algo"], "sha256");
    assert_eq!(read_sealed(&target).unwrap(), json!({"b": 2}));
    let previous: Value = serde_json::from_slice(&std::fs::read(backup_path(&target)).unwrap()).unwrap();
    assert_eq!(previous["b"], 1);
}

#[test]
fn zero_length_and_torn_files_at_every_cut_return_the_old_content_never_empty() {
    let dir = tmp();
    let target = dir.path().join("r.json");
    write_sealed_default(&target, &json!({"v": 1})).unwrap();
    write_sealed_default(&target, &json!({"v": 2})).unwrap();
    let whole = std::fs::read(&target).unwrap();
    for cut in 0..whole.len() {
        std::fs::write(&target, &whole[..cut]).unwrap();
        let (value, source) = sealed::read_sealed_info(&target, &ReadOptions::default(), None).unwrap();
        assert_eq!((value["v"].clone(), source), (json!(1), Source::Backup), "cut {cut}");
    }
}

#[test]
fn a_mis_sealed_file_is_rejected_and_no_valid_version_raises_store_corrupt_naming_both_paths() {
    let dir = tmp();
    let target = dir.path().join("r.json");
    write_sealed_default(&target, &json!({"v": 1})).unwrap();
    let text = String::from_utf8(std::fs::read(&target).unwrap()).unwrap().replace("\"v\": 1", "\"v\": 9");
    std::fs::write(&target, text).unwrap();
    std::fs::write(backup_path(&target), b"").unwrap();
    let error = read_sealed(&target).unwrap_err();
    assert_eq!(error.code(), Some("store_corrupt"));
    let message = error.to_string();
    assert!(message.contains("mis-sealed (content does not match its seal)"), "{message}");
    assert!(message.contains("r.json.bak: zero-length"), "{message}");
    assert!(message.contains("Nothing was started empty; preserve both files and repair them."), "{message}");
}

#[test]
fn a_file_that_was_never_written_is_not_corruption() {
    let dir = tmp();
    let error = read_sealed(&dir.path().join("none.json")).unwrap_err();
    assert!(error.is_not_found());
    let (value, source) = sealed::read_sealed_info(&dir.path().join("none.json"), &ReadOptions::default(), Some(json!({}))).unwrap();
    assert_eq!((value, source), (json!({}), Source::Missing));
}

#[test]
fn a_pre_seal_record_loads_and_becomes_the_backup_of_the_first_sealed_write() {
    let dir = tmp();
    let target = dir.path().join("r.json");
    std::fs::write(&target, br#"{"old": true}"#).unwrap();
    let (kind, value, _) = sealed::inspect_file(&target, None, false).unwrap();
    assert_eq!((kind, value), (Kind::Unsealed, Some(json!({"old": true}))));
    write_sealed_default(&target, &json!({"new": true})).unwrap();
    assert_eq!(std::fs::read(backup_path(&target)).unwrap(), br#"{"old": true}"#);
}

#[test]
fn a_bad_file_never_replaces_the_good_backup_and_is_preserved_aside() {
    let dir = tmp();
    let target = dir.path().join("r.json");
    write_sealed_default(&target, &json!({"v": 1})).unwrap();
    write_sealed_default(&target, &json!({"v": 2})).unwrap();
    let good_backup = std::fs::read(backup_path(&target)).unwrap();
    std::fs::write(&target, b"{broken").unwrap();
    write_sealed_default(&target, &json!({"v": 3})).unwrap();
    assert_eq!(std::fs::read(backup_path(&target)).unwrap(), good_backup);
    let asides: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".corrupt-"))
        .collect();
    assert_eq!(asides.len(), 1, "{asides:?}");
}

#[test]
fn oversize_and_reserved_keys_are_refused_before_anything_is_written() {
    let dir = tmp();
    let target = dir.path().join("r.json");
    let too_big = write_sealed(&target, &json!({"x": "y".repeat(100)}), Some(2), Some(50), None).unwrap_err();
    assert_eq!(too_big.to_string(), "record would exceed 50 bytes; existing file preserved");
    let reserved = write_sealed_default(&target, &json!({"seal": 1})).unwrap_err();
    assert!(matches!(reserved, Error::Value(_)));
    assert!(!target.exists());
}

#[test]
fn update_sealed_loses_no_update_across_threads() {
    let dir = tmp();
    let target = dir.path().join("counter.json");
    let handles: Vec<_> = (0..6)
        .map(|_| {
            let target = target.clone();
            std::thread::spawn(move || {
                for _ in 0..10 {
                    sealed::update_sealed(
                        &target,
                        |value| {
                            let n = value["n"].as_u64().unwrap_or(0);
                            value["n"] = json!(n + 1);
                            None
                        },
                        None,
                    )
                    .unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    assert_eq!(read_sealed(&target).unwrap()["n"], 60);
}

// ----------------------------------------------------------------------------------------- AppendLog

#[test]
fn the_line_format_is_crc_hex8_space_json_lf_with_zlib_crc32() {
    let line = frame(&json!({"b": "é", "a": 1}));
    let text = String::from_utf8(line).unwrap();
    assert!(text.ends_with('\n'));
    let (crc, body) = text.trim_end().split_at(8);
    assert_eq!(&body[..1], " ");
    assert_eq!(body[1..].to_string(), r#"{"b":"\u00e9","a":1}"#);
    assert_eq!(u32::from_str_radix(crc, 16).unwrap(), crc32fast::hash(&body.as_bytes()[1..]));
}

#[test]
fn a_cut_at_every_offset_of_the_last_line_is_read_then_repaired_then_clean() {
    let dir = tmp();
    let path = dir.path().join("log");
    let log = AppendLog::new(&path);
    log.append(&json!({"i": 1}), false).unwrap();
    let first = std::fs::read(&path).unwrap();
    log.append(&json!({"i": 2}), false).unwrap();
    let whole = std::fs::read(&path).unwrap();
    for cut in first.len() + 1..whole.len() {
        std::fs::write(&path, &whole[..cut]).unwrap();
        appendlog_forget();
        let scan = log.scan().unwrap();
        assert_eq!(scan.records.len(), 1, "cut {cut}");
        assert!(scan.torn_tail.is_some() && scan.corrupt.is_none(), "cut {cut}");
        log.append(&json!({"i": 3}), false).unwrap();
        let after = log.read().unwrap();
        assert_eq!(after, vec![json!({"i": 1}), json!({"i": 3})], "cut {cut}");
        assert!(log.scan().unwrap().torn_tail.is_none());
        assert!(!log.repairs().is_empty());
    }
}

fn appendlog_forget() {
    // The per-process "verified" memo is keyed by path and size; tests that rewrite a log by hand drop it by appending
    // through a fresh log whose size differs, which `check_tail` notices (size mismatch forces a scan).
}

#[test]
fn a_fragment_without_lf_is_never_valid_even_when_its_crc_matches() {
    let mut data = frame(&json!({"i": 1}));
    data.pop();
    let scan = scan_bytes(&data);
    assert!(scan.records.is_empty());
    assert_eq!(scan.torn_tail.map(|t| t.offset), Some(0));
}

#[test]
fn several_invalid_lines_at_the_end_are_one_torn_tail_and_mid_log_corruption_is_refused() {
    let mut data = frame(&json!({"i": 1}));
    let good = data.len() as u64;
    data.extend_from_slice(b"garbage one\ngarbage two\n");
    let scan = scan_bytes(&data);
    assert_eq!((scan.records.len(), scan.torn_tail.clone().map(|t| t.offset)), (1, Some(good)));
    data.extend_from_slice(&frame(&json!({"i": 2})));
    let scan = scan_bytes(&data);
    assert_eq!(scan.corrupt.map(|c| (c.offset, c.line)), Some((good, 2)));

    let dir = tmp();
    let path = dir.path().join("log");
    std::fs::write(&path, &data).unwrap();
    let log = AppendLog::new(&path);
    assert_eq!(log.read().unwrap_err().code(), Some("lineage_corrupt"));
    assert_eq!(log.append(&json!({"i": 3}), false).unwrap_err().code(), Some("lineage_corrupt"));
}

#[test]
fn an_unknown_crc_prefix_or_bad_json_after_a_valid_crc_is_invalid() {
    assert!(appendlog::parse_line(b"zzzzzzzz {}").is_none());
    let body = b"{bad";
    let line = format!("{:08x} {}", crc32fast::hash(body), "{bad");
    assert!(appendlog::parse_line(line.as_bytes()).is_none());
    assert!(appendlog::frame_ok(line.as_bytes()));
}

#[test]
fn a_crash_inside_the_repair_heals_on_the_next_append() {
    let dir = tmp();
    let path = dir.path().join("log");
    let log = AppendLog::new(&path);
    log.append(&json!({"i": 1}), false).unwrap();
    let mut data = std::fs::read(&path).unwrap();
    data.extend_from_slice(b"12345678 {\"half");
    std::fs::write(&path, &data).unwrap();
    for point in ["log.repair.after_copy", "log.repair.after_truncate"] {
        std::fs::write(&path, &data).unwrap();
        assert_eq!(child("append", &path, Some(&format!("{point}:exit")), &[]).code(), Some(137), "{point}");
        log.append(&json!({"i": 2}), false).unwrap();
        assert_eq!(log.read().unwrap(), vec![json!({"i": 1}), json!({"i": 2})], "{point}");
    }
}

#[test]
fn a_writer_killed_in_the_middle_of_an_append_is_followed_by_a_normal_successful_append() {
    let dir = tmp();
    let path = dir.path().join("log");
    let log = AppendLog::new(&path);
    log.append(&json!({"i": 1}), false).unwrap();
    assert_eq!(child("append", &path, Some("log.torn_append:torn:5"), &[]).code(), Some(137));
    assert!(log.scan().unwrap().torn_tail.is_some());
    log.append(&json!({"i": 2}), false).unwrap();
    assert_eq!(log.read().unwrap(), vec![json!({"i": 1}), json!({"i": 2})]);
    assert_eq!(log.repairs().len(), 1);
}

#[test]
fn the_tail_read_finds_the_last_valid_line_across_garbage_and_long_lines() {
    let dir = tmp();
    let path = dir.path().join("log");
    let log = AppendLog::new(&path);
    log.append(&json!({"i": 1}), false).unwrap();
    log.append(&json!({"i": 2, "pad": "x".repeat(200_000)}), false).unwrap();
    let mut data = std::fs::read(&path).unwrap();
    data.extend_from_slice(b"garbage\n");
    std::fs::write(&path, data).unwrap();
    assert_eq!(log.last(false).unwrap().unwrap()["i"], 2);
    assert_eq!(AppendLog::new(dir.path().join("none")).last(false).unwrap(), None);
}

#[test]
fn an_append_to_a_missing_log_creates_it_and_the_caller_may_hold_the_lock() {
    let dir = tmp();
    let path = dir.path().join("deep").join("log");
    let log = AppendLog::new(&path);
    let _guard = hy_core::lock::lock(&log.lock_path, 5.0, "test").unwrap();
    assert_eq!(log.append(&json!({"i": 1}), true).unwrap(), 0);
    assert_eq!(log.read().unwrap().len(), 1);
}

#[test]
fn the_writer_lock_excludes_a_second_writer() {
    let dir = tmp();
    let lock_path = dir.path().join("l.lock");
    let first = hy_core::lock::lock(&lock_path, 5.0, "x").unwrap();
    assert!(hy_core::lock::held(&lock_path));
    let busy = hy_core::lock::lock(&lock_path, 0.2, "the thing").unwrap_err();
    assert_eq!(busy.to_string(), "the thing is busy (l.lock); retry shortly");
    drop(first);
    assert!(!hy_core::lock::held(&lock_path));
    drop(hy_core::lock::lock(&lock_path, 1.0, "x").unwrap());
}

#[test]
fn concurrent_writers_lose_no_line_and_tear_none() {
    let dir = tmp();
    let path = dir.path().join("log");
    let handles: Vec<_> = (0..8)
        .map(|t| {
            let path = path.clone();
            std::thread::spawn(move || {
                let log = AppendLog::new(&path);
                for i in 0..25 {
                    log.append(&json!({"t": t, "i": i}), false).unwrap();
                }
            })
        })
        .collect();
    for h in handles {
        h.join().unwrap();
    }
    let records = AppendLog::new(&path).read().unwrap();
    assert_eq!(records.len(), 200);
    for t in 0..8 {
        let seen: Vec<i64> = records.iter().filter(|r| r["t"] == t).map(|r| r["i"].as_i64().unwrap()).collect();
        assert_eq!(seen, (0..25).collect::<Vec<_>>());
    }
}

#[test]
fn a_log_larger_than_the_metadata_budget_is_read_scanned_and_appended_to() {
    let dir = tmp();
    let path = dir.path().join("big.log");
    let line = frame(&json!({"pad": "x".repeat(1000)}));
    let count = (33 * 1024 * 1024) / line.len() + 1;
    let mut data = Vec::with_capacity(count * line.len());
    for _ in 0..count {
        data.extend_from_slice(&line);
    }
    std::fs::write(&path, &data).unwrap();
    let log = AppendLog::new(&path);
    assert_eq!(log.read().unwrap().len(), count);
    log.append(&json!({"last": true}), false).unwrap();
    assert_eq!(log.last(false).unwrap().unwrap()["last"], true);
    let _ = atomic_write_point; // keep the import used on all cfgs
}

#[test]
fn an_unreadable_log_is_an_error_not_an_empty_or_valid_one() {
    let dir = tmp();
    // a missing log is an empty scan (nothing was ever appended)
    let missing = dir.path().join("never-written.log");
    let scan = appendlog::scan_file(&missing, 0, true).unwrap();
    assert!((scan.records.len(), scan.size, scan.valid_end) == (0, 0, 0));
    assert!(AppendLog::new(&missing).read().unwrap().is_empty());
    // a path that exists but cannot be read as a log (a directory: access denied on Windows, EISDIR on Unix) must not
    // pass for an empty log, or the next writer would believe there is no history to protect
    let unreadable = dir.path().join("a-directory.log");
    std::fs::create_dir(&unreadable).unwrap();
    assert!(appendlog::scan_file(&unreadable, 0, true).is_err());
    let log = AppendLog::new(&unreadable);
    assert!(log.read().is_err());
    assert!(log.scan().is_err());
    assert!(log.status().is_err());
    assert!(log.last(false).is_err());
    assert!(log.last(true).is_err());
}
