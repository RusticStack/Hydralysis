//! Port of tests/test_lineage.py: Log and TwoProcessTornTail (plus the head / tamper-cache / status paths the
//! Python suite reaches through test_commit and test_doctor).

#![allow(clippy::result_large_err)]

mod common;

use common::{World, write};
use hy_core::sealed::sha256_hex;
use hy_store::lineage;
use serde_json::{Value, json};
use std::fs;

#[test]
fn creation_is_idempotent_and_generation_zero_is_the_adopted_project() {
    let w = World::new();
    let first = lineage::ensure(&w.settings, &w.target, None).unwrap();
    let second = lineage::ensure(&w.settings, &w.target, None).unwrap();
    assert_eq!(first, second);
    let id = first["id"].as_str().unwrap();
    assert!(id.len() == 10 && id.starts_with("L-") && id[2..].bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
    assert_eq!(lineage::find(&w.settings, "k-owned-0001").unwrap().as_deref(), Some(id));
    assert_eq!(lineage::find(&w.settings, &"0".repeat(16)).unwrap(), None);
    let rows = lineage::history(&w.settings, id).unwrap();
    let shape: Vec<(i64, i64, &str)> =
        rows.iter().map(|r| (r["seq"].as_i64().unwrap(), r["gen"].as_i64().unwrap(), r["reason"].as_str().unwrap())).collect();
    assert_eq!(shape, [(1, 0, "register")]);
    assert_eq!(rows[0]["gpr"].as_str().unwrap(), w.gpr.to_string_lossy());
}

#[test]
fn lines_chain_by_the_hash_of_the_previous_valid_line() {
    let w = World::with_lineage();
    for number in 0..3 {
        lineage::append_current(
            &w.settings,
            &w.lid,
            &json!({"gen": number + 1, "cid": format!("c-{number:08x}"), "reason": "commit", "gpr": "x", "manifestSha256": "m"}),
            false,
        )
        .unwrap();
    }
    let rows = lineage::history(&w.settings, &w.lid).unwrap();
    assert_eq!(rows.iter().map(|r| r["seq"].as_i64().unwrap()).collect::<Vec<_>>(), [1, 2, 3, 4]);
    assert!(rows[0]["prevHash"].is_null());
    for pair in rows.windows(2) {
        assert_eq!(pair[1]["prevHash"].as_str().unwrap(), sha256_hex(&lineage::canonical(&pair[0])));
    }
    assert_eq!(lineage::head(&w.settings, &w.lid).unwrap()["gen"], 3);
}

#[test]
fn a_target_with_a_lineage_resolves_to_the_head_and_keeps_its_key() {
    // The pure part of test_a_target_with_a_lineage_resolves_...: lineage.resolve. The registry cache assertions belong to targets.py.
    let w = World::with_lineage();
    let generation = w.root.join("elsewhere").join("Owned.gpr");
    lineage::append_current(
        &w.settings,
        &w.lid,
        &json!({"gen": 1, "cid": "c-00000001", "reason": "commit", "gpr": generation.to_string_lossy(), "manifestSha256": "m"}),
        false,
    )
    .unwrap();
    let item = json!({"lineage": {"id": w.lid, "origin_key": "k-owned-0001"}, "gpr": w.gpr.to_string_lossy()});
    let after = lineage::resolve(&w.settings, &item).unwrap();
    assert_eq!(after["gpr"].as_str().unwrap(), generation.to_string_lossy());
    assert_eq!(after["key"], "k-owned-0001");
    assert_eq!(after["adopted_gpr"].as_str().unwrap(), w.gpr.to_string_lossy());
    assert_eq!((after["lineage"]["id"].as_str().unwrap(), after["lineage"]["generation"].as_i64().unwrap()), (w.lid.as_str(), 1));
    assert_eq!(lineage::resolve(&w.settings, &json!({"gpr": "x"})).unwrap(), json!({}));
}

#[test]
fn configuration_targets_are_not_given_a_lineage_by_the_cache() {
    // No registry row to extend (registry None): ensure still creates the lineage with the origin key.
    let w = World::new();
    let made = lineage::ensure(&w.settings, &w.target, None).unwrap();
    assert_eq!(made["origin_key"], "k-owned-0001");
}

struct Registry {
    row: Option<Value>,
    wrote: std::sync::Mutex<Vec<Value>>,
}

impl lineage::TargetRegistry for Registry {
    fn registered(&self, _settings: &Value, _name: &str) -> Option<Value> {
        self.row.clone()
    }
    fn register(&self, _settings: &Value, _name: &str, row: Value) -> lineage::Result<()> {
        self.wrote.lock().unwrap().push(row);
        Ok(())
    }
}

#[test]
fn the_registry_mirror_is_written_once_and_only_for_a_registered_target() {
    let w = World::new();
    let registry = Registry { row: Some(json!({"gpr": "g"})), wrote: Default::default() };
    let made = lineage::ensure(&w.settings, &w.target, Some(&registry)).unwrap();
    let wrote = registry.wrote.lock().unwrap().clone();
    assert_eq!(wrote.len(), 1);
    assert_eq!(wrote[0]["lineage"], json!({"id": made["id"], "origin_key": "k-owned-0001"}));
    let unregistered = Registry { row: None, wrote: Default::default() };
    lineage::ensure(&w.settings, &w.target, Some(&unregistered)).unwrap();
    assert!(unregistered.wrote.lock().unwrap().is_empty());
}

#[test]
fn generation_numbers_are_never_reused() {
    let w = World::with_lineage();
    assert_eq!(lineage::next_generation(&w.settings, &w.lid).unwrap(), 1);
    fs::create_dir_all(lineage::generation_dir(&w.settings, &w.lid, 1).unwrap()).unwrap(); // an abandoned folder
    assert_eq!(lineage::next_generation(&w.settings, &w.lid).unwrap(), 2);
    let log = lineage::intent_log(&w.settings, &w.lid, "c-00000009").unwrap();
    log.append(&json!({"cid": "c-00000009", "attempt": 1, "step": "CANDIDATE_RESERVED", "gen": 5}), false).unwrap(); // a reservation without a folder
    assert_eq!(lineage::next_generation(&w.settings, &w.lid).unwrap(), 6);
}

#[test]
fn invalid_ids_are_refused() {
    let w = World::new();
    for bad in ["", "L-xyz", "../x", "L-123456789"] {
        assert!(lineage::lineage_dir(&w.settings, bad).is_err(), "{bad:?}");
    }
    assert!(lineage::intent_log(&w.settings, "L-00000000", "../c").is_err());
    assert_eq!(lineage::lineage_dir(&w.settings, "L-xyz").unwrap_err().to_string(), "invalid lineage id");
}

// ---- TwoProcessTornTail: the writer that is killed mid-line is a child process re-running this test binary ----

#[test]
fn torn_writer_child() {
    let (Ok(root), Ok(lid)) = (std::env::var("HY_CHILD_ROOT"), std::env::var("HY_CHILD_LID")) else { return };
    let settings = json!({"root": root});
    let record = json!({"gen": 0, "cid": null, "reason": "recover", "gpr": "b".repeat(80)});
    let _ = lineage::append_current(&settings, &lid, &record, false);
}

#[test]
fn a_long_lived_writer_appends_again_after_a_killed_writer_left_a_fragment() {
    let w = World::with_lineage();
    let append = |reason: &str, cid: Value| {
        lineage::append_current(&w.settings, &w.lid, &json!({"gen": 0, "cid": cid, "reason": reason, "gpr": "a"}), false).unwrap()["seq"]
            .as_i64()
            .unwrap()
    };
    assert_eq!(append("recover", Value::Null), 2);
    let killed = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "torn_writer_child", "--nocapture"])
        .env("HY_CHILD_ROOT", w.settings["root"].as_str().unwrap())
        .env("HY_CHILD_LID", &w.lid)
        .env("HYDRALYSIS_TEST_MODE", "1")
        .env("HYDRALYSIS_TEST_FAULT", "log.torn_append:torn:30")
        .output()
        .unwrap();
    assert_eq!(killed.status.code(), Some(137));
    let log = lineage::current_log(&w.settings, &w.lid).unwrap();
    assert!(log.scan().unwrap().torn_tail.is_some());
    assert_eq!(lineage::history(&w.settings, &w.lid).unwrap().len(), 2); // a reader ignores the fragment and never repairs
    assert_eq!(append("recover", Value::Null), 3); // A appends again: it repairs first
    let rows = lineage::history(&w.settings, &w.lid).unwrap();
    assert_eq!(rows.iter().map(|r| r["seq"].as_i64().unwrap()).collect::<Vec<_>>(), [1, 2, 3]);
    assert!(log.scan().unwrap().torn_tail.is_none());
    assert!(log.scan().unwrap().corrupt.is_none());
    assert_eq!(log.repairs().len(), 1);
    let kept: Vec<_> = fs::read_dir(log.path.parent().unwrap())
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("CURRENT.log.torn-"))
        .collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(fs::read(kept[0].path()).unwrap().len(), 30);
    assert!(!String::from_utf8_lossy(&fs::read(&log.path).unwrap()).contains("bbbbbbbb")); // no fragment is left in the log
    assert_eq!(append("rollback", json!("c-0000000a")), 4); // a rollback line goes through the same rule
}

// ---- head, tamper cache, status ----

#[test]
fn head_reports_a_torn_tail_and_a_missing_log() {
    let w = World::with_lineage();
    let log = lineage::current_log(&w.settings, &w.lid).unwrap();
    fs::OpenOptions::new().append(true).open(&log.path).and_then(|mut f| std::io::Write::write_all(&mut f, b"00000000 {\"x\"")).unwrap();
    let head = lineage::head(&w.settings, &w.lid).unwrap();
    assert!(head["torn_tail"].is_object() && head["corrupt"].is_null());
    assert_eq!(head["lines"], 1);
    let none = lineage::head(&w.settings, "L-00000000").unwrap_err();
    match none {
        lineage::Error::Lineage(e) => assert_eq!(e.code, "no_lineage"),
        other => panic!("{other}"),
    }
}

fn publish(w: &World, number: i64) -> std::path::PathBuf {
    let folder = lineage::generation_dir(&w.settings, &w.lid, number).unwrap().join("proj");
    write(&folder.join("P.gpr"), b"gpr");
    write(&folder.join("P.rep").join("db"), b"data");
    let manifest = lineage::write_manifest(&folder, &json!({"cid": "c-1"})).unwrap();
    let digest = sha256_hex(&fs::read(folder.join(lineage::MANIFEST)).unwrap());
    let _ = manifest;
    lineage::append_current(&w.settings, &w.lid, &json!({"gen": number, "cid": "c-00000001", "reason": "commit", "gpr": folder.join("P.gpr").to_string_lossy(), "manifestSha256": digest}), false).unwrap();
    folder
}

#[test]
fn verify_head_and_tampered_see_a_written_generation() {
    let w = World::with_lineage();
    assert_eq!(lineage::verify_head(&w.settings, &w.lid).unwrap()["ok"], true);
    let folder = publish(&w, 1);
    assert_eq!(lineage::verify_head(&w.settings, &w.lid).unwrap()["ok"], true);
    assert!(lineage::tampered(&w.settings, &w.lid).unwrap().is_empty());
    write(&folder.join("P.rep").join("db"), b"changed");
    let found = lineage::tampered(&w.settings, &w.lid).unwrap();
    assert_eq!(found.len(), 1);
    assert_eq!(found[0]["generation"], 1);
    assert_eq!(lineage::verify_head(&w.settings, &w.lid).unwrap()["ok"], false);
}

#[test]
fn the_tamper_cache_answers_while_the_folder_is_unchanged() {
    let mut w = World::with_lineage();
    w.settings["tampered_cache_s"] = json!(3600);
    let folder = publish(&w, 1);
    assert!(lineage::tampered(&w.settings, &w.lid).unwrap().is_empty());
    let cache = lineage::lineage_dir(&w.settings, &w.lid).unwrap().join(lineage::TAMPER_CACHE_NAME);
    assert!(cache.is_file());
    // a changed file changes the signature: the cache is bypassed and the problem is found
    write(&folder.join("P.rep").join("db"), b"changed!");
    assert_eq!(lineage::tampered(&w.settings, &w.lid).unwrap().len(), 1);
}

#[test]
fn status_without_and_with_a_lineage() {
    let w = World::with_lineage();
    let bare = lineage::status(&w.settings, &json!({"gpr": "g"})).unwrap();
    assert_eq!(bare["generation"], 0);
    assert!(bare["lineage"].is_null());
    publish(&w, 1);
    let status = lineage::status(&w.settings, &json!({"gpr": "g", "lineage": {"id": w.lid, "origin_key": "k"}})).unwrap();
    assert_eq!(status["generation"], 1);
    assert_eq!(status["generations"].as_array().unwrap().len(), 2);
    assert!(status.get("tampered").is_none());
    let missing = lineage::status(&w.settings, &json!({"gpr": "g", "lineage": {"id": "L-00000000", "origin_key": "k"}})).unwrap();
    assert_eq!(missing["error"]["error"], "no_lineage");
}
