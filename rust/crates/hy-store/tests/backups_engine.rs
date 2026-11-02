//! Port of tests/test_backups.py `EngineBackups` (hydra.4: the engine writes the backup, the client re-verifies it).

#![allow(clippy::result_large_err)]

mod common;

use common::{FakeEngine, World};
use hy_store::backups::{self, ENGINE_BACKUP_CAPABILITY};
use hy_store::lineage::{self, BackupError, Error};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;

const REAL_HYDRA4_CAPABILITIES: [&str; 19] = [
    "errorNext",
    "expectAll",
    "idempotency",
    "laneHint",
    "maintLane",
    "queueInfo",
    "cancelWait",
    "forkReport",
    "format",
    "backup",
    "upgradeGate",
    "scriptIsolation",
    "scriptSha256",
    "attemptedChanges",
    "health",
    "identity",
    "seal",
    "forkAtomic",
    "admission",
];

fn engine() -> FakeEngine {
    let mut e = FakeEngine::new();
    e.capabilities = Some(REAL_HYDRA4_CAPABILITIES.iter().map(|c| (*c).to_string()).collect());
    e
}

fn make(w: &World, e: &FakeEngine) -> Result<Value, Error> {
    backups::make(&w.settings, e, &w.lid, &w.gpr.to_string_lossy(), "pre-commit", "3fa9c2d1aa01bb42", 0, false, None)
}

#[test]
fn the_engine_writes_the_backup_with_purpose_backup_and_the_client_reverifies_it() {
    let w = World::with_lineage();
    let e = engine();
    let made = make(&w, &e).unwrap()["backup"].clone();
    let calls = e.calls.lock().unwrap().clone();
    let forks: Vec<&Value> = calls.iter().filter(|(n, _)| n == "fork_project").map(|(_, f)| f).collect();
    assert_eq!(forks.len(), 1);
    assert_eq!((&forks[0]["purpose"], &forks[0]["open"], &forks[0]["verify"]), (&"backup".into(), &false.into(), &"hash".into()));
    assert_eq!(made["manifest"]["writer"], "engine");
    let folder = PathBuf::from(made["folder"].as_str().unwrap());
    assert_eq!(backups::verify(&folder).unwrap()["ok"], true);
    assert_eq!(backups::listing(&w.settings, &w.lid, false).unwrap()["backups"][0]["sealed"], false); // the fake writes no SEALED.json
    assert_eq!(backups::logged(&w.settings, &w.lid).unwrap()[0]["manifestSha256"], made["manifestSha256"]);
    assert_eq!(lineage::tree_hash(w.gpr.parent().unwrap()).unwrap(), w.master_tree());
}

#[test]
fn the_capabilities_a_real_hydra_4_advertises_select_the_engine_backup() {
    assert!(REAL_HYDRA4_CAPABILITIES.contains(&ENGINE_BACKUP_CAPABILITY));
    let w = World::with_lineage();
    assert_eq!(make(&w, &engine()).unwrap()["backup"]["manifest"]["writer"], "engine");
    // without the capability the client's own writer is used
    assert_eq!(make(&w, &FakeEngine::new()).unwrap()["backup"]["manifest"]["writer"], "hydralysis");
}

#[test]
fn an_engine_backup_that_does_not_verify_is_refused_and_stays_invisible_to_use() {
    let w = World::with_lineage();
    let mut e = engine();
    e.after_fork = Some(Box::new(|_src, dest| fs::write(dest.join("Owned.gpr"), "flipped").unwrap()));
    let error = make(&w, &e).unwrap_err().to_string();
    assert!(error.contains("backup_verify_failed") || error.contains("does not verify") || error.contains("failed"), "{error}");
    let listed = backups::listing(&w.settings, &w.lid, true).unwrap();
    let row = &listed["backups"][0];
    assert_eq!(row["verified"], false);
    assert!(backups::usable(&w.settings, &w.lid, row["id"].as_str().unwrap(), None).unwrap().is_none());
}

#[test]
fn an_engine_failure_is_a_backup_failed() {
    let w = World::with_lineage();
    let mut e = engine();
    e.fail_paths = vec!["backups".into()];
    match make(&w, &e).unwrap_err() {
        Error::Backup(BackupError { code, message, .. }) => {
            assert_eq!(code, "backup_failed");
            assert!(message.contains("the engine could not make the backup: disk full"), "{message}");
        }
        other => panic!("{other}"),
    }
}

#[test]
fn legacy_backup_adoption_tells_the_engine_when_it_can_seal() {
    let w = World::with_lineage();
    let e = engine();
    let made = make(&w, &FakeEngine::new()).unwrap()["backup"].clone(); // a client-written backup
    let folder = PathBuf::from(made["folder"].as_str().unwrap());
    fs::remove_file(folder.join("project").join("SEALED.json")).unwrap();
    let outcome = backups::adopt_legacy(&folder, Some(&e), Some(&w.lid)).unwrap();
    assert_eq!(outcome["adopted"], true);
    assert_eq!(outcome["engine_sealed"], true);
    let calls = e.calls.lock().unwrap().clone();
    let seal = calls.iter().find(|(n, _)| n == "seal_project").expect("seal_project called");
    assert_eq!(seal.1["lineage"], w.lid);
}
