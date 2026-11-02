//! Port of tests/test_backups.py `RemoveAndHandler` (the parts below the handler: `remove`, `protected_generations`, `run_op`).

#![allow(clippy::result_large_err)]

mod common;

use common::{FakeEngine, World, write};
use hy_store::backups::{self, BackupEngine};
use hy_store::lineage;
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

fn make(w: &World) -> Value {
    backups::make(&w.settings, &FakeEngine::new(), &w.lid, &w.gpr.to_string_lossy(), "pre-commit", "3fa9c2d1aa01bb42", 0, false, None)
        .unwrap()["backup"]
        .clone()
}

fn publish_three(w: &World) {
    for number in 1..=3 {
        fs::create_dir_all(lineage::generation_dir(&w.settings, &w.lid, number).unwrap()).unwrap();
        lineage::append_current(
            &w.settings,
            &w.lid,
            &json!({"gen": number, "cid": format!("c-{number:08x}"), "reason": "commit", "gpr": format!("g{number}"), "manifestSha256": "m"}),
            false,
        )
        .unwrap();
    }
}

fn remove(w: &World, options: Value) -> Value {
    backups::remove(&w.settings, &w.lid, &options).unwrap()
}

#[test]
fn remove_is_a_dry_run_unless_confirmed_and_never_drops_below_the_policy() {
    let w = World::with_lineage();
    let first = make(&w);
    let id = first["id"].as_str().unwrap();
    let refused = remove(&w, json!({"id": id, "confirm": true}));
    assert_eq!(refused["refused"], "backup_min_verified");
    assert!(PathBuf::from(first["folder"].as_str().unwrap()).is_dir());
    let second = make(&w);
    let dry = remove(&w, json!({"id": id}));
    assert_eq!(dry["dry_run"], true);
    assert_eq!(dry["removed"], false);
    assert!(PathBuf::from(first["folder"].as_str().unwrap()).is_dir());
    assert!(dry["bytes"].as_u64().unwrap() > 0);
    let done = remove(&w, json!({"id": id, "confirm": true}));
    assert_eq!(done["removed"], true);
    assert!(!PathBuf::from(first["folder"].as_str().unwrap()).exists());
    assert!(PathBuf::from(second["folder"].as_str().unwrap()).is_dir());
    assert!(backups::logged(&w.settings, &w.lid).unwrap().iter().any(|r| r.get("removed").is_some_and(|v| v == true)));
    let listing = backups::listing(&w.settings, &w.lid, false).unwrap();
    assert_eq!(listing["backups"].as_array().unwrap().len(), 1);
    assert_eq!(listing["logged_but_missing"], json!([]));
}

#[test]
fn remove_needs_exactly_one_selector_and_a_boolean_confirm() {
    let w = World::with_lineage();
    for bad in [json!({}), json!({"id": "x", "generation": 1}), json!({"id": "x", "confirm": "yes"})] {
        assert!(backups::remove(&w.settings, &w.lid, &bad).is_err(), "{bad}");
    }
}

#[test]
fn remove_refuses_generation_zero_the_head_the_revert_target_and_a_live_views_base() {
    let w = World::with_lineage();
    publish_three(&w);
    let mut reasons = std::collections::BTreeMap::new();
    for number in [0, 3, 2] {
        let reply = remove(&w, json!({"generation": number, "confirm": true}));
        reasons.insert(number, reply["message"].as_str().unwrap().to_string());
        assert_eq!(reply["refused"], "protected_generation");
    }
    assert!(reasons[&0].contains("never removed"));
    assert!(reasons[&3].contains("head"));
    assert!(reasons[&2].contains("revert target"));
    let chain = remove(&w, json!({"generation": 1, "confirm": true}));
    assert_eq!(chain["refused"], "protected_generation");
    assert!(chain["message"].as_str().unwrap().contains("revert chain"));
    // a live view's base protects a generation above the head, which nothing else protects
    fs::create_dir_all(lineage::generation_dir(&w.settings, &w.lid, 4).unwrap()).unwrap();
    let base = PathBuf::from(w.settings["root"].as_str().unwrap()).join("bases").join("origin").join("key");
    write(&base.join("COMPLETE.json"), json!({"gpr": "x", "generation": 4, "lineage": w.lid}).to_string().as_bytes());
    assert_eq!(remove(&w, json!({"generation": 4, "confirm": true}))["message"], "the base of a live view");
    fs::remove_file(base.join("COMPLETE.json")).unwrap();
    let folder = lineage::generation_dir(&w.settings, &w.lid, 4).unwrap();
    write(&folder.join("payload.bin"), &[b'x'; 100]);
    let dry = remove(&w, json!({"generation": 4}));
    assert_eq!((dry["removed"].clone(), dry["dry_run"].clone()), (json!(false), json!(true)));
    assert!(folder.exists());
    assert_eq!(remove(&w, json!({"generation": 4, "confirm": true}))["removed"], true);
    assert!(!folder.exists());
}

#[test]
fn the_revert_chain_stays_protected_after_a_revert_and_a_rolled_back_generation_is_removable() {
    let w = World::with_lineage();
    publish_three(&w);
    lineage::append_current(
        &w.settings,
        &w.lid,
        &json!({"gen": 2, "cid": "c-00000003", "reason": "rollback", "gpr": "g2", "manifestSha256": "m"}),
        false,
    )
    .unwrap();
    let kept = backups::protected_generations(&w.settings, &w.lid).unwrap();
    assert_eq!(kept.keys().copied().collect::<Vec<_>>(), [0, 1, 2]);
    assert!(kept[&1].contains("revert target"));
    assert!(!kept.contains_key(&3));
    assert_eq!(remove(&w, json!({"generation": 3, "confirm": true}))["removed"], true);
    assert_eq!(remove(&w, json!({"generation": 1, "confirm": true}))["refused"], "protected_generation");
}

#[test]
fn list_verify_and_remove_through_run_op() {
    // test_list_verify_and_remove_through_backend_action_backups, below the target lookup that api.py/targets.py own.
    let w = World::with_lineage();
    let backup = make(&w);
    let none = || -> Option<Box<dyn BackupEngine>> { None };
    let listed = backups::run_op(&w.settings, &w.lid, &json!({"op": "list"}), &none).unwrap();
    assert_eq!(listed["backups"].as_array().unwrap().iter().map(|r| r["id"].clone()).collect::<Vec<_>>(), [backup["id"].clone()]);
    assert_eq!(listed["independent_verified"], 0);
    assert_eq!(listed["policy"]["backup_min_verified"], 1);
    let verified = backups::run_op(&w.settings, &w.lid, &json!({"op": "verify", "id": backup["id"]}), &none).unwrap();
    assert_eq!(verified["results"][0]["id"], backup["id"]);
    assert_eq!(verified["results"][0]["ok"], true);
    assert!(backups::run_op(&w.settings, &w.lid, &json!({"op": "verify", "id": "nope"}), &none).is_err());
}
