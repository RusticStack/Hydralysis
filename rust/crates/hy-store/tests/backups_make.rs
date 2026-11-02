//! Port of tests/test_backups.py `Backups` (the client-made backup path, with a fake engine that clones the folder).

#![allow(clippy::result_large_err)]

mod common;

use common::{FakeEngine, World, write};
use hy_core::sealed::sha256_hex;
use hy_store::backups::{self, BackupEngine};
use hy_store::lineage::{self, BackupError, Error};
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};

const REVISION: &str = "3fa9c2d1aa01bb42";

fn make(w: &World, engine: &dyn BackupEngine, confirm: bool) -> Result<Value, Error> {
    backups::make(&w.settings, engine, &w.lid, &w.gpr.to_string_lossy(), "pre-commit", REVISION, 0, confirm, None)
}

fn made(w: &World) -> Value {
    make(w, &FakeEngine::new(), false).unwrap()["backup"].clone()
}

fn folder_of(backup: &Value) -> PathBuf {
    PathBuf::from(backup["folder"].as_str().unwrap())
}

fn read_json(path: &Path) -> Value {
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn code(error: Error) -> (String, String) {
    match error {
        Error::Backup(BackupError { code, message, .. }) => (code, message),
        other => panic!("not a BackupError: {other}"),
    }
}

fn problems(folder: &Path) -> Vec<String> {
    backups::verify(folder).unwrap()["problems"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect()
}

fn rewrite_manifest(folder: &Path, edit: impl FnOnce(&mut Value)) {
    let mut manifest = read_json(&folder.join("backup.json"));
    edit(&mut manifest);
    manifest["selfSha256"] = json!(lineage::self_hash(&manifest));
    fs::write(folder.join("backup.json"), lineage::canonical(&manifest)).unwrap();
}

#[test]
fn a_backup_is_a_verified_sealed_copy_with_backup_json_written_last() {
    let w = World::with_lineage();
    let backup = made(&w);
    let folder = folder_of(&backup);
    let manifest = read_json(&folder.join("backup.json"));
    assert_eq!(
        (&manifest["kind"], &manifest["writer"], &manifest["purpose"], &manifest["format"]),
        (&json!("ghidra-session-backup"), &json!("hydralysis"), &json!("pre-commit"), &json!(1))
    );
    let id = manifest["id"].as_str().unwrap();
    assert!(id.ends_with("-3fa9c2d1-pre-commit") && id.len() == "20260101T000000Z-3fa9c2d1-pre-commit".len() && id.as_bytes()[8] == b'T');
    assert_eq!(folder.file_name().unwrap().to_string_lossy(), id);
    assert_eq!(folder.parent().unwrap().file_name().unwrap().to_string_lossy(), w.lid);
    assert_eq!(
        manifest["source"],
        json!({"gpr": w.gpr.to_string_lossy(), "name": "Owned", "revision": REVISION, "lineage": w.lid, "generation": 0})
    );
    assert_eq!(manifest["verify"]["ok"], true);
    assert_eq!(manifest["copy"]["independent"], false);
    assert_eq!(manifest["selfSha256"].as_str().unwrap(), lineage::self_hash(&manifest));
    assert_eq!(backups::verify(&folder).unwrap()["ok"], true);
    let project = folder.join("project");
    let sidecar = read_json(&project.join("Owned.fork.json"));
    assert_eq!((&sidecar["purpose"], &sidecar["disposable"], &sidecar["state"]), (&json!("backup"), &json!(false), &json!("complete")));
    assert!(project.join("SEALED.json").is_file());
    assert_eq!(lineage::tree_hash(w.gpr.parent().unwrap()).unwrap(), w.master_tree());
}

#[test]
fn the_manifest_lists_what_the_engine_gate_checks_raw_sizes_and_no_sidecar() {
    let w = World::with_lineage();
    let backup = made(&w);
    let folder = folder_of(&backup);
    let rows = backup["manifest"]["files"].as_array().unwrap();
    assert!(!rows.is_empty());
    assert!(rows.iter().all(|r| !r["path"].as_str().unwrap().ends_with(".fork.json")));
    for row in rows {
        assert_eq!(fs::metadata(folder.join(row["path"].as_str().unwrap())).unwrap().len(), row["size"].as_u64().unwrap());
    }
    assert_eq!(backups::verify(&folder).unwrap()["ok"], true);
}

#[test]
fn an_unlisted_sidecar_is_not_an_unlisted_file() {
    let w = World::with_lineage();
    let folder = folder_of(&made(&w));
    let stray = folder.join("project").join("stray.bin");
    write(&stray, b"x");
    assert!(problems(&folder).contains(&"unlisted file project/stray.bin".to_string()));
    fs::remove_file(&stray).unwrap();
    rewrite_manifest(&folder, |m| {
        let rows: Vec<Value> = m["files"].as_array().unwrap().iter().filter(|r| r["path"] != "project/Owned.fork.json").cloned().collect();
        m["filesetSha256"] = json!(lineage::fileset_sha256(&rows));
        m["files"] = Value::Array(rows);
    });
    assert_eq!(backups::verify(&folder).unwrap()["ok"], true, "{:?}", problems(&folder));
}

#[test]
fn the_fork_is_not_writable() {
    let w = World::with_lineage();
    let engine = FakeEngine::new();
    make(&w, &engine, false).unwrap();
    let calls = engine.calls.lock().unwrap().clone();
    let forks: Vec<&Value> = calls.iter().filter(|(n, _)| n == "fork_project").map(|(_, f)| f).collect();
    assert_eq!(forks.iter().map(|f| f["writable"].clone()).collect::<Vec<_>>(), [json!(false)]);
    assert_eq!(calls.iter().filter(|(n, _)| n == "close_project").count(), 1); // nothing is held open
}

#[test]
fn backups_log_records_each_copy() {
    let w = World::with_lineage();
    let backup = made(&w);
    let rows = backups::logged(&w.settings, &w.lid).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        (&rows[0]["id"], &rows[0]["manifestSha256"], &rows[0]["root"]),
        (&backup["id"], &backup["manifestSha256"], &json!(w.root.join("backups").to_string_lossy()))
    );
    assert!(rows[0]["bytes"].as_u64().unwrap() > 0);
    assert_eq!(rows[0]["manifestSha256"].as_str().unwrap(), sha256_hex(&fs::read(folder_of(&backup).join("backup.json")).unwrap()));
}

#[test]
fn a_backup_never_overwrites_and_a_retry_in_the_same_second_gets_its_own_folder() {
    let w = World::with_lineage();
    let first = made(&w);
    let second = made(&w);
    assert_ne!(first["folder"], second["folder"]);
    assert!(second["id"].as_str().unwrap().starts_with(&first["id"].as_str().unwrap()[..8]));
}

#[test]
fn a_copy_that_does_not_match_its_source_writes_no_manifest_and_stays_invisible() {
    let w = World::with_lineage();
    let mut engine = FakeEngine::new();
    engine.after_fork = Some(Box::new(|_src, dest| {
        write(&dest.join("Owned.rep").join("damaged.bin"), b"x");
        write(&dest.join("Owned.gpr"), b"different");
    }));
    let (c, message) = code(make(&w, &engine, false).unwrap_err());
    assert_eq!(c, "backup_failed");
    assert!(message.contains("does not match its source"), "{message}");
    let listed = backups::listing(&w.settings, &w.lid, false).unwrap();
    assert_eq!(listed["backups"], json!([]));
    assert_eq!(listed["invisible"].as_array().unwrap().len(), 1);
    assert!(listed["invisible"][0]["note"].as_str().unwrap().contains("manual removal"));
    assert!(backups::logged(&w.settings, &w.lid).unwrap().is_empty());
}

#[test]
fn a_source_that_changes_while_it_is_copied_makes_no_backup() {
    let w = World::with_lineage();
    let mut engine = FakeEngine::new();
    engine.after_fork = Some(Box::new(|src, _dest| write(&src.join("Owned.rep").join("moved.bin"), b"late")));
    let (_, message) = code(make(&w, &engine, false).unwrap_err());
    assert!(message.contains("source changed"), "{message}");
    assert_eq!(backups::listing(&w.settings, &w.lid, false).unwrap()["backups"], json!([]));
}

#[test]
fn a_folder_without_a_valid_backup_json_is_not_a_usable_backup() {
    let w = World::with_lineage();
    let backup = made(&w);
    fs::write(folder_of(&backup).join("backup.json"), "{}").unwrap();
    assert!(backups::usable(&w.settings, &w.lid, backup["id"].as_str().unwrap(), None).unwrap().is_none());
    assert_eq!(backups::listing(&w.settings, &w.lid, false).unwrap()["invisible"].as_array().unwrap().len(), 1);
}

#[test]
fn verify_rehashes_every_file_and_names_what_changed() {
    let w = World::with_lineage();
    let backup = made(&w);
    let folder = folder_of(&backup);
    fs::write(folder.join("project").join("Owned.gpr"), "tampered").unwrap();
    write(&folder.join("project").join("stray.bin"), b"x");
    let result = backups::verify(&folder).unwrap();
    assert_eq!(result["ok"], false);
    let list = problems(&folder);
    assert!(list.iter().any(|p| p.starts_with("changed file project/Owned.gpr")));
    assert!(list.contains(&"unlisted file project/stray.bin".to_string()));
    assert!(backups::usable(&w.settings, &w.lid, backup["id"].as_str().unwrap(), None).unwrap().is_none());
}

#[test]
fn usable_checks_the_manifest_the_log_names() {
    let w = World::with_lineage();
    let backup = made(&w);
    let id = backup["id"].as_str().unwrap();
    assert!(backups::usable(&w.settings, &w.lid, id, backup["manifestSha256"].as_str()).unwrap().is_some());
    assert!(backups::usable(&w.settings, &w.lid, id, Some(&"0".repeat(64))).unwrap().is_none());
}

#[test]
fn a_replaced_backup_is_detected_by_the_log() {
    let w = World::with_lineage();
    let folder = folder_of(&made(&w));
    rewrite_manifest(&folder, |m| m["createdAt"] = json!("2000-01-01T00:00:00Z"));
    let row = backups::listing(&w.settings, &w.lid, false).unwrap()["backups"][0].clone();
    assert_eq!(row["replaced"], true);
}

#[test]
fn a_deleted_backup_is_reported_as_logged_but_missing() {
    let w = World::with_lineage();
    let backup = made(&w);
    fs::remove_dir_all(folder_of(&backup)).unwrap();
    let listed = backups::listing(&w.settings, &w.lid, false).unwrap();
    assert_eq!(listed["backups"], json!([]));
    assert_eq!(listed["logged_but_missing"], json!([{"id": backup["id"], "root": backup["root"]}]));
}

#[test]
fn a_newer_format_is_refused_not_guessed() {
    let w = World::with_lineage();
    let folder = folder_of(&made(&w));
    rewrite_manifest(&folder, |m| m["format"] = json!(7));
    assert!(problems(&folder).iter().any(|p| p.contains("format_unreadable")));
}

#[test]
fn a_legacy_backup_without_a_seal_is_listed_unsealed_and_verify_adopts_it() {
    let w = World::with_lineage();
    let folder = folder_of(&made(&w));
    fs::remove_file(folder.join("project").join("SEALED.json")).unwrap();
    let row = backups::listing(&w.settings, &w.lid, false).unwrap()["backups"][0].clone();
    assert_eq!(row["sealed"], false);
    assert!(row["note"].as_str().unwrap().contains("client discipline"));
    assert_eq!(backups::adopt_legacy(&folder, None, None).unwrap(), json!({"ok": true, "adopted": true}));
    assert_eq!(backups::listing(&w.settings, &w.lid, false).unwrap()["backups"][0]["sealed"], true);
    assert_eq!(backups::verify(&folder).unwrap()["ok"], true);
}

#[test]
fn a_legacy_backup_that_fails_the_rehash_is_labelled_and_never_adopted() {
    let w = World::with_lineage();
    let folder = folder_of(&made(&w));
    fs::write(folder.join("project").join("Owned.gpr"), "bad").unwrap();
    fs::remove_file(folder.join("project").join("SEALED.json")).unwrap();
    let outcome = backups::adopt_legacy(&folder, None, None).unwrap();
    assert_eq!(outcome["label"], "legacy_unverified");
    assert!(!folder.join("project").join("SEALED.json").exists());
}

#[test]
fn the_default_policy() {
    let w = World::new();
    let wanted = backups::policy(&json!({"root": w.root.join("data").to_string_lossy()})).unwrap();
    assert_eq!(
        (&wanted["backup_min_verified"], &wanted["backup_min_independent"], &wanted["backup_confirm_gb"], &wanted["backup_root_warn_gb"]),
        (&json!(1), &json!(0), &json!(50), &json!(200))
    );
    assert_eq!(wanted["roots"][0]["path"], json!(w.root.join("data").join("backups").to_string_lossy()));
    let mut bad = w.settings.clone();
    bad["backup_roots"] = json!([{"path": "x", "mode": "snapshot"}]);
    assert_eq!(backups::policy(&bad).unwrap_err().to_string(), "backup_roots mode must be auto or copy");
    let mut negative = w.settings.clone();
    negative["backup_min_verified"] = json!(-1);
    assert_eq!(backups::policy(&negative).unwrap_err().to_string(), "backup_min_verified must be a non-negative number");
}

#[test]
fn a_secondary_root_is_always_a_full_copy() {
    let w = World::new();
    let mut s = w.settings.clone();
    s["backup_roots"] = json!([{"path": "a", "mode": "auto"}, {"path": "b", "mode": "auto"}]);
    let wanted = backups::policy(&s).unwrap();
    let roots = wanted["roots"].as_array().unwrap();
    assert_eq!(roots.iter().map(|r| r["mode"].clone()).collect::<Vec<_>>(), [json!("auto"), json!("copy")]);
    assert_eq!(roots.iter().map(|r| r["required"].clone()).collect::<Vec<_>>(), [json!(true), json!(false)]);
}

#[test]
fn two_roots_give_two_verified_copies_and_a_failed_secondary_only_warns() {
    let mut w = World::with_lineage();
    w.settings["backup_roots"] =
        json!([{"path": w.root.join("backups").to_string_lossy()}, {"path": w.root.join("second").to_string_lossy()}]);
    let both = make(&w, &FakeEngine::new(), false).unwrap();
    assert_eq!(both["all"].as_array().unwrap().len(), 2);
    assert_eq!(both["warnings"], json!([]));
    w.settings["backup_roots"] =
        json!([{"path": w.root.join("backups2").to_string_lossy()}, {"path": w.root.join("third").to_string_lossy()}]);
    let mut engine = FakeEngine::new();
    engine.fail_paths = vec!["third".into()];
    let one = make(&w, &engine, false).unwrap();
    assert_eq!(one["all"].as_array().unwrap().len(), 1);
    assert_eq!(one["warnings"][0]["root"], json!(w.root.join("third").to_string_lossy()));
}

#[test]
fn a_failed_primary_aborts_and_so_does_a_failed_secondary_the_policy_needs() {
    let mut w = World::with_lineage();
    w.settings["backup_roots"] =
        json!([{"path": w.root.join("backups").to_string_lossy()}, {"path": w.root.join("second").to_string_lossy()}]);
    let mut engine = FakeEngine::new();
    engine.fail_paths = vec!["backups".into(), "second".into()];
    assert_eq!(code(make(&w, &engine, false).unwrap_err()).0, "backup_failed");
    w.settings["backup_min_verified"] = json!(2);
    w.settings["backup_roots"] = json!([{"path": w.root.join("ok").to_string_lossy()}, {"path": w.root.join("bad").to_string_lossy()}]);
    let mut half = FakeEngine::new();
    half.fail_paths = vec!["bad".into()];
    let (_, message) = code(make(&w, &half, false).unwrap_err());
    assert!(message.contains("backup_min_verified=2"), "{message}");
}

#[test]
fn a_policy_that_wants_an_independent_copy_refuses_a_block_clone() {
    let mut w = World::with_lineage();
    w.settings["backup_min_independent"] = json!(1);
    let (_, message) = code(make(&w, &FakeEngine::new(), false).unwrap_err());
    assert!(message.contains("backup_min_independent=1"), "{message}");
}

#[test]
fn a_large_backup_needs_confirmation_and_states_the_cumulative_cost() {
    let mut w = World::with_lineage();
    made(&w);
    w.settings["backup_confirm_gb"] = json!(1e-10);
    let error = make(&w, &FakeEngine::new(), false).unwrap_err();
    let Error::Backup(error) = error else { panic!("{error}") };
    assert_eq!(error.code, "confirm_large_backup");
    let row = &error.detail["plan"]["roots"][0];
    assert!(row["cumulative_bytes_before"].as_u64().unwrap() > 0); // the first backup counts
    assert_eq!(
        row["cumulative_bytes_after"].as_u64().unwrap(),
        row["cumulative_bytes_before"].as_u64().unwrap() + row["this_backup_bytes"].as_u64().unwrap()
    );
    assert!(!row["free_bytes"].is_null());
    assert!(row["note"].as_str().unwrap().contains("overstates"));
    assert_eq!(backups::listing(&w.settings, &w.lid, false).unwrap()["backups"].as_array().unwrap().len(), 1); // the refusal made nothing
    assert!(make(&w, &FakeEngine::new(), true).unwrap()["backup"]["id"].is_string());
}

#[test]
fn the_doctor_warning_threshold_is_in_the_plan() {
    let mut w = World::with_lineage();
    w.settings["backup_root_warn_gb"] = json!(1e-10);
    let plan = backups::preview(&w.settings, &w.lid, &w.gpr.to_string_lossy()).unwrap();
    assert_eq!(plan["roots"][0]["warn"], true);
}
