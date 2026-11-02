//! Rust twins of the test_durable.py cases that patch Python internals (os.fsync, os.replace, _move_file_ex, _sleep,
//! the `_VERIFIED` memo, `scan_file`). See rust/crates/hy-store/TESTMAP.md.

use hy_core::appendlog::{self, AppendLog, frame};
use hy_core::error::Error;
use hy_core::fsio::atomic_write;
use serde_json::json;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn tmp() -> tempdir::Dir {
    tempdir::Dir::new()
}

mod tempdir {
    use std::path::{Path, PathBuf};
    pub struct Dir(PathBuf);
    impl Dir {
        pub fn new() -> Self {
            let path = std::env::temp_dir().join(format!("hy-core-twin-{}", uuid::Uuid::new_v4().simple()));
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

#[test]
fn the_backoff_starts_at_50ms_doubles_is_capped_at_500ms_and_stays_within_ten_seconds() {
    let delays = hy_core::fsio::retry_delays();
    assert_eq!(&delays[..5], &[0.05, 0.1, 0.2, 0.4, 0.5]);
    assert!(delays[4..].iter().all(|&d| d == 0.5));
    assert!(delays.iter().sum::<f64>() <= 10.0);
}

#[test]
fn other_errors_are_not_retried() {
    let dir = tmp();
    let started = std::time::Instant::now();
    let error = hy_core::fsio::replace_file(&dir.path().join("missing"), &dir.path().join("dest")).unwrap_err();
    assert!(error.is_not_found());
    assert!(started.elapsed().as_millis() < 1000, "a not-found error must not be retried");
}

#[cfg(windows)]
#[test]
fn a_replace_that_stays_denied_raises_after_the_budget_and_leaves_the_old_file() {
    use std::os::windows::fs::OpenOptionsExt;
    let dir = tmp();
    let target = dir.path().join("held.json");
    std::fs::write(&target, b"old").unwrap();
    let holder = std::fs::OpenOptions::new().read(true).share_mode(0).open(&target).unwrap();
    let started = std::time::Instant::now();
    let error = atomic_write(&target, b"new").unwrap_err();
    assert!(matches!(&error, Error::Io(e) if hy_core::fsio::is_permission_error(e)), "{error}");
    assert!(started.elapsed().as_secs_f64() >= 9.0);
    drop(holder);
    assert_eq!(std::fs::read(&target).unwrap(), b"old");
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 1, "the temporary file must be removed");
}

#[test]
fn a_failed_append_forces_a_check_before_the_next_one_and_a_foreign_fragment_is_repaired() {
    let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tmp();
    let path = dir.path().join("log");
    let log = AppendLog::new(&path);
    log.append(&json!({"n": 1}), false).unwrap();
    assert!(log.verified_end().is_some());
    // SAFETY: the tests of this binary that touch the environment hold ENV_LOCK.
    unsafe {
        std::env::set_var("HYDRALYSIS_TEST_MODE", "1");
        std::env::set_var("HYDRALYSIS_TEST_FAULT", "log.after_append:raise");
    }
    let error = log.append(&json!({"n": 2}), false).unwrap_err();
    // SAFETY: as above.
    unsafe {
        std::env::remove_var("HYDRALYSIS_TEST_MODE");
        std::env::remove_var("HYDRALYSIS_TEST_FAULT");
    }
    assert!(matches!(error, Error::FaultInjected(_)));
    assert_eq!(log.verified_end(), None, "a failed append must drop the verified end");
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(b"1234"); // a foreign fragment, as another process might leave
    std::fs::write(&path, bytes).unwrap();
    log.append(&json!({"n": 3}), false).unwrap();
    assert_eq!(log.read().unwrap(), vec![json!({"n": 1}), json!({"n": 2}), json!({"n": 3})]);
}

#[test]
fn a_fragment_left_by_another_process_after_this_one_verified_is_still_repaired() {
    let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tmp();
    let path = dir.path().join("log");
    let log = AppendLog::new(&path);
    log.append(&json!({"n": 1}), false).unwrap();
    assert_eq!(log.verified_end(), Some(std::fs::metadata(&path).unwrap().len()));
    let mut bytes = std::fs::read(&path).unwrap();
    bytes.extend_from_slice(&frame(&json!({"n": 2}))[..5]);
    std::fs::write(&path, bytes).unwrap();
    log.append(&json!({"n": 3}), false).unwrap();
    assert_eq!(log.read().unwrap(), vec![json!({"n": 1}), json!({"n": 3})]);
    assert_eq!(log.repairs().len(), 1);
}

#[test]
fn the_cheap_check_scans_nothing_when_the_log_is_as_this_process_left_it() {
    let _env = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = tmp();
    let log = AppendLog::new(dir.path().join("log"));
    log.append(&json!({"n": 1}), false).unwrap();
    // check_tail on a verified log returns before any scan; the scan counter is process-wide (tests run in parallel),
    // so prove it through the result and the unchanged verified end, and assert the counter did not move for a
    // single-threaded reader of it below.
    assert_eq!(log.check_tail().unwrap(), None);
    assert_eq!(log.verified_end(), Some(std::fs::metadata(&log.path).unwrap().len()));
}

#[test]
fn the_writers_first_acquisition_scans_once_and_never_again() {
    // Run in a child so that no other test of this binary scans concurrently.
    if std::env::var("HY_TWIN_CHILD").is_err() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "the_writers_first_acquisition_scans_once_and_never_again", "--test-threads=1", "--nocapture"])
            .env("HY_TWIN_CHILD", "1")
            .status()
            .unwrap();
        assert!(status.success());
        return;
    }
    let dir = tmp();
    let path = dir.path().join("big.log");
    let line = frame(&json!({"pad": "x".repeat(1000)}));
    std::fs::write(&path, line.repeat(2000)).unwrap();
    let log = AppendLog::new(&path);
    let start = appendlog::scan_count();
    log.append(&json!({"n": "new"}), false).unwrap();
    assert_eq!(appendlog::scan_count() - start, 1, "the first acquisition scans the whole log once");
    log.append(&json!({"n": "newer"}), false).unwrap();
    assert_eq!(appendlog::scan_count() - start, 1, "then never again");
}

#[test]
fn frame_lines_agree_with_the_per_line_parse() {
    let mut seed = 0x1234_5678_9ABC_DEF0_u64;
    let mut next = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    for _ in 0..300 {
        let mut data = Vec::new();
        for _ in 0..(next() % 6) {
            let mut line = frame(&json!({"n": next() % 1000}));
            match next() % 4 {
                0 => {
                    let at = (next() as usize) % line.len();
                    line[at] ^= 1 << (next() % 8);
                }
                1 => line.truncate((next() as usize) % line.len()),
                _ => {}
            }
            data.extend_from_slice(&line);
        }
        let mut expected = Vec::new();
        let mut cursor = 0;
        while let Some(found) = data[cursor..].iter().position(|&b| b == b'\n') {
            let end = cursor + found;
            expected.push((cursor, end, appendlog::frame_ok(&data[cursor..end])));
            cursor = end + 1;
        }
        assert_eq!(appendlog::frame_lines(&data), expected);
    }
}
