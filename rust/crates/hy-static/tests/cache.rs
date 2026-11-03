//! The process-local cache: answers equal the engine's through it, a changed file invalidates it, the byte budget
//! evicts, and no file handle is kept (the project folder can be renamed and deleted while entries are held).

use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use hy_static::{Cache, Error, answer, answer_in_project_with};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn truth(name: &str) -> Value {
    serde_json::from_str(&fs::read_to_string(fixtures().join("engine").join(name)).unwrap()).unwrap()
}

fn request(action: &str, address: &str, limit: u64, cursor: &str, contains: &str) -> Value {
    json!({"id": "t", "action": action, "address": address, "limit": limit, "cursor": cursor,
           "contains": contains, "timeout_s": 30, "options": {}, "expected_sha256": ""})
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap() {
        let entry = entry.unwrap();
        let target = to.join(entry.file_name());
        if entry.file_type().unwrap().is_dir() {
            copy_dir(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), target).unwrap();
        }
    }
}

/// A private copy of the analysed fixture project; the name keeps tests apart.
fn project(name: &str) -> PathBuf {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR")).join("hy-static-cache").join(name);
    let _ = fs::remove_dir_all(&root);
    copy_dir(&fixtures().join("legacy-12.1.4-analysed"), &root);
    root
}

fn database(project: &Path) -> PathBuf {
    let idata = project.join("legacy.rep").join("idata");
    for bucket in fs::read_dir(&idata).unwrap() {
        let bucket = bucket.unwrap().path();
        if !bucket.is_dir() {
            continue;
        }
        for item in fs::read_dir(&bucket).unwrap() {
            let item = item.unwrap().path();
            if item.is_dir() {
                for file in fs::read_dir(&item).unwrap() {
                    let file = file.unwrap().path();
                    if file.extension().is_some_and(|e| e == "gbf") {
                        return file;
                    }
                }
            }
        }
    }
    panic!("no database in {}", project.display());
}

const PROGRAM: &str = "/flow_fixture.exe";

#[test]
fn cached_answers_equal_the_engine_and_the_first_answer() {
    let dir = project("equal");
    let cache = Cache::new(64 << 20);
    let rows = truth("function.json");
    let (mut equal, mut declined) = (0, 0);
    for (address, want) in rows.as_object().unwrap() {
        let r = request("function", address, 40, "", "");
        let first = answer_in_project_with(&cache, &dir, PROGRAM, &r);
        let second = answer_in_project_with(&cache, &dir, PROGRAM, &r);
        match (first, second) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a, b, "cached answer differs at {address}");
                assert_eq!(a["function"], want["function"], "function at {address}");
                equal += 1;
            }
            (Err(Error::Unsupported(a)), Err(Error::Unsupported(b))) => {
                assert_eq!(a, b);
                declined += 1;
            }
            other => panic!("{address}: {other:?}"),
        }
    }
    assert!(equal > 300, "{equal} equal, {declined} declined");
    let pages = truth("functions.json");
    let mut cursor = String::new();
    for page in pages.as_array().unwrap() {
        let r = request("functions", "", 200, &cursor, "");
        if let Ok(got) = answer_in_project_with(&cache, &dir, PROGRAM, &r) {
            assert_eq!(got["functions"], page["functions"], "page at {cursor:?}");
            assert_eq!(got, answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap());
        }
        match page.get("next_cursor") {
            Some(next) if page["truncated"] == json!(true) => cursor = next.as_str().unwrap().to_owned(),
            _ => break,
        }
    }
    // The uncached path (`answer` over an open program) says the same as the cached one.
    let open = hy_static::StaticProgram::open(&dir, PROGRAM).unwrap();
    let r = request("function", "0x140001030", 40, "", "");
    assert_eq!(answer(&open, &r).ok(), answer_in_project_with(&cache, &dir, PROGRAM, &r).ok());
    let stats = cache.stats();
    assert_eq!(stats.entries, 1);
    assert_eq!(stats.misses, 1, "every later use must come from the held entry");
    assert!(stats.hits > 700);
    assert_eq!(stats.invalidations, 0);
}

#[test]
fn xrefs_use_the_held_meta_and_still_read_the_references() {
    let dir = project("xrefs");
    let cache = Cache::new(64 << 20);
    let r = request("xrefs", "0x140001030", 50, "", "");
    let a = answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap();
    let b = answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap();
    assert_eq!(a, b);
    let s = cache.stats();
    assert_eq!((s.misses, s.hits), (1, 1));
}

#[test]
fn a_changed_database_file_invalidates_the_entry() {
    let dir = project("changed");
    let cache = Cache::new(64 << 20);
    let r = request("function", "0x140001030", 40, "", "");
    let first = answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap();
    answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap();
    assert_eq!((cache.stats().misses, cache.stats().hits, cache.stats().invalidations), (1, 1, 0));
    // Same size, new write time: what a save of identical content looks like.
    let gbf = database(&dir);
    let file = fs::OpenOptions::new().write(true).open(&gbf).unwrap();
    file.set_modified(SystemTime::now() + Duration::from_secs(5)).unwrap();
    drop(file);
    let again = answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap();
    assert_eq!(again, first, "the content did not change, so neither does the answer");
    let s = cache.stats();
    assert_eq!(s.invalidations, 1, "the new write time must drop the entry");
    assert_eq!(s.misses, 2, "and the files are read again");
    // A different size: the entry is dropped and the read is attempted on the new content (a damaged file is not
    // answered from the old rows).
    let before = cache.stats().invalidations;
    let mut bytes = fs::read(&gbf).unwrap();
    bytes.truncate(bytes.len() - 4096);
    fs::write(&gbf, bytes).unwrap();
    assert!(answer_in_project_with(&cache, &dir, PROGRAM, &r).is_err(), "a truncated database must not be answered from the cache");
    assert_eq!(cache.stats().invalidations, before + 1);
}

#[test]
fn a_save_in_progress_drops_the_entry_and_is_declined() {
    let dir = project("saving");
    let cache = Cache::new(64 << 20);
    let r = request("function", "0x140001030", 40, "", "");
    answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap();
    // A save writes a new file beside the database (or a journal beside the index): the folder's write time moves.
    let db_dir = database(&dir).parent().unwrap().to_path_buf();
    fs::write(db_dir.join("db.7.gbf.tmp"), b"half a save").unwrap();
    match answer_in_project_with(&cache, &dir, PROGRAM, &r) {
        Err(Error::Unsupported(why)) => assert!(why.contains("save may be in progress"), "{why}"),
        other => panic!("{other:?}"),
    }
    assert_eq!(cache.stats().invalidations, 1);
    assert_eq!(cache.stats().entries, 0, "nothing is kept for a project that is being saved");
    fs::remove_file(db_dir.join("db.7.gbf.tmp")).unwrap();
    assert_eq!(answer_in_project_with(&cache, &dir, PROGRAM, &r).unwrap()["function"]["name"], json!("FUN_140001030"));
    // A journal beside the index.
    let jrn = dir.join("legacy.rep").join("idata").join("~index.jrn");
    fs::write(&jrn, b"x").unwrap();
    assert!(matches!(answer_in_project_with(&cache, &dir, PROGRAM, &r), Err(Error::Unsupported(_))));
    fs::remove_file(&jrn).unwrap();
    assert!(answer_in_project_with(&cache, &dir, PROGRAM, &r).is_ok());
}

#[test]
fn the_budget_evicts_the_least_recently_used_program() {
    let (a, b) = (project("evict-a"), project("evict-b"));
    let r = request("function", "0x140001030", 40, "", "");
    let probe = Cache::new(64 << 20);
    answer_in_project_with(&probe, &a, PROGRAM, &r).unwrap();
    let one = probe.stats().bytes;
    assert!(one > 0);

    // Room for one and a half programs.
    let cache = Cache::new(one + one / 2);
    answer_in_project_with(&cache, &a, PROGRAM, &r).unwrap();
    assert_eq!(cache.stats().entries, 1);
    answer_in_project_with(&cache, &b, PROGRAM, &r).unwrap();
    let s = cache.stats();
    assert_eq!(s.entries, 1, "a program had to go");
    assert_eq!(s.evictions, 1);
    assert!(s.bytes <= s.budget, "{} bytes held over a budget of {}", s.bytes, s.budget);
    // `b` is held (a hit), `a` is not (a read again).
    let misses = cache.stats().misses;
    answer_in_project_with(&cache, &b, PROGRAM, &r).unwrap();
    assert_eq!(cache.stats().misses, misses);
    answer_in_project_with(&cache, &a, PROGRAM, &r).unwrap();
    assert_eq!(cache.stats().misses, misses + 1);

    // Recency, not insertion order: touch `a`, add `b`: `a` stays if `b` is the one that does not fit... with room for
    // two, nothing goes; shrinking to one keeps the more recent.
    let roomy = Cache::new(4 * one);
    answer_in_project_with(&roomy, &a, PROGRAM, &r).unwrap();
    answer_in_project_with(&roomy, &b, PROGRAM, &r).unwrap();
    answer_in_project_with(&roomy, &a, PROGRAM, &r).unwrap();
    assert_eq!(roomy.stats().entries, 2);
    roomy.set_budget(one + one / 2);
    assert_eq!(roomy.stats().entries, 1);
    let misses = roomy.stats().misses;
    answer_in_project_with(&roomy, &a, PROGRAM, &r).unwrap();
    assert_eq!(roomy.stats().misses, misses, "the most recently used program stays");

    // Rows that alone exceed the budget are declined (the engine answers), and not rebuilt on every call.
    let tiny = Cache::new(one / 2);
    for _ in 0..3 {
        assert!(matches!(answer_in_project_with(&tiny, &a, PROGRAM, &r), Err(Error::Unsupported(_))));
    }
    assert_eq!(tiny.stats().builds, 1, "built once, then remembered as too big");
    assert!(tiny.stats().bytes <= tiny.stats().budget);
    // References need no rows: still answered with a budget that cannot hold them.
    assert!(answer_in_project_with(&tiny, &a, PROGRAM, &request("xrefs", "0x140001030", 5, "", "")).is_ok());

    // A budget of 0 is "no cache": function questions go to the engine, references are answered, nothing is kept.
    let none = Cache::new(0);
    assert!(matches!(answer_in_project_with(&none, &a, PROGRAM, &r), Err(Error::Unsupported(_))));
    assert!(answer_in_project_with(&none, &a, PROGRAM, &request("xrefs", "0x140001030", 5, "", "")).is_ok());
    assert_eq!((none.stats().entries, none.stats().bytes, none.stats().builds), (0, 0, 0));
}

#[test]
fn no_file_handle_is_kept_between_calls() {
    let dir = project("handles");
    let cache = Cache::new(64 << 20);
    for action in ["function", "functions", "xrefs"] {
        let r = request(action, "0x140001030", 40, "", "");
        let _ = answer_in_project_with(&cache, &dir, PROGRAM, &r);
    }
    assert_eq!(cache.stats().entries, 1);
    // Windows refuses to rename or delete a folder holding an open file.
    let moved = dir.with_file_name("handles-moved");
    let _ = fs::remove_dir_all(&moved);
    fs::rename(&dir, &moved).expect("the project folder is renamed while the cache holds its program");
    // The path is gone, so there is nothing to answer from; the held rows wait for eviction (the budget bounds them).
    let r = request("function", "0x140001030", 40, "", "");
    assert!(answer_in_project_with(&cache, &dir, PROGRAM, &r).is_err());
    fs::remove_dir_all(&moved).expect("and deleted");
}
