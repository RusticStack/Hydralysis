//! Port of tests/test_evidence_bundle.py (same cases; see TESTMAP_evidence.md).

mod evsupport;

use evsupport::*;
use hy_store::bundle::{self, BundleError, ExportOptions};
use hy_store::evidence::{self, Claim, EvidenceError, Filter, Verify};
use serde_json::{Map, Value, json};
use std::path::{Path, PathBuf};

fn capture() -> Value {
    json!({"capture_id": "cap_one", "events": [{"seq": 1, "rva": "0x2e3270", "args_hex": "00ff10"}], "dropped_events": 0})
}

/// The POPULATE script of the Python test, with the writer's harness name.
fn populate(db: &Path, extra: &[&str], harness: &str) {
    let c = ctx(harness);
    let mut a = Claim::new("cp", "2.31", "function", "ForceMoveTo", "moves the vehicle", "decompile line 12");
    a.address = "rva:0x1a5f14".into();
    a.subsystem = "vehicles".into();
    evidence::add_claim(db, &a, &c).unwrap();
    let mut b = Claim::new("cp", "2.5", "function", "ForceMoveTo", "moves the vehicle", "decompile line 40");
    b.address = "rva:0x2e3270".into();
    b.subsystem = "vehicles".into();
    b.supersedes = Some(1);
    b.coverage = Some(json!({"status": "partial", "limitations": ["static_only", "indirect_calls_unresolved"]}));
    evidence::add_claim(db, &b, &c).unwrap();
    let mut d = Claim::new("cp", "2.5", "probe", "hit count", "three hits in the fixture", "runtime observe");
    d.address = "rva:0x2e3270".into();
    d.subsystem = "vehicles".into();
    d.authority = Some("controlled-replay".into());
    d.confidence = Some("observed".into());
    d.from_capture = "cap_one".into();
    d.coverage = Some(json!({"status": "complete"}));
    d.parameters = Some(json!({"script_sha256": "ab".repeat(32)}));
    d.limitations = vec![json!("fixture_only")];
    evidence::add_claim(db, &d, &c).unwrap();
    for item in extra {
        let mut e = Claim::new("cp", "2.5", "field", &format!("extra-{item}"), "n", "s");
        e.subsystem = "vehicles".into();
        evidence::add_claim(db, &e, &c).unwrap();
    }
}

struct World {
    dir: tempfile::TempDir,
    db: PathBuf,
    captures: PathBuf,
}

impl World {
    fn new() -> World {
        let dir = work();
        let captures = dir.path().join("captures-in");
        std::fs::create_dir(&captures).unwrap();
        std::fs::write(captures.join("cap_one.json"), capture().to_string()).unwrap();
        let db = dir.path().join("a.db");
        World { dir, db, captures }
    }
    fn root(&self) -> &Path {
        self.dir.path()
    }
    fn options(&self) -> ExportOptions {
        ExportOptions { captures_dir: Some(self.captures.clone()), ctx: ctx("exporter"), ..ExportOptions::default() }
    }
    fn export(&self, name: &str) -> Value {
        self.export_with(name, &self.db, |_| {}).expect("export")
    }
    fn export_with(&self, name: &str, db: &Path, tweak: impl FnOnce(&mut ExportOptions)) -> evidence::Result<Value> {
        let mut options = self.options();
        tweak(&mut options);
        bundle::export_bundle(db, &self.root().join(name), &options)
    }
}

fn mutate(folder: &Path, name: &str, change: impl FnOnce(Vec<u8>) -> Vec<u8>) {
    let file = folder.join(name);
    let data = std::fs::read(&file).unwrap();
    std::fs::write(file, change(data)).unwrap();
}

fn code_of(error: &EvidenceError) -> String {
    error.code().unwrap_or("").to_string()
}

fn bundle_code<T: std::fmt::Debug>(result: evidence::Result<T>) -> String {
    code_of(&result.expect_err("expected a bundle error"))
}

fn sha(data: &[u8]) -> String {
    hy_core::sealed::sha256_hex(data)
}

fn relative_files(folder: &Path) -> Vec<String> {
    fn walk(base: &Path, dir: &Path, out: &mut Vec<String>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.push(p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"));
            }
        }
    }
    let mut out = Vec::new();
    walk(folder, folder, &mut out);
    out.sort();
    out
}

fn set_manifest_entry(folder: &Path, name: &str, data: &[u8]) {
    let path = folder.join("manifest.json");
    let mut manifest: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    manifest["files"][name] = json!({"bytes": data.len(), "sha256": sha(data)});
    std::fs::write(path, manifest.to_string()).unwrap();
}

// ---- ExportAndVerify -------------------------------------------------------------------------------------------------

#[test]
fn a_bundle_exports_and_verifies() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    let result = w.export("bundle");
    assert_eq!((result["records"].as_u64(), result["captures"].as_u64(), &result["missing_captures"]), (Some(3), Some(1), &json!([])));
    let folder = w.root().join("bundle");
    let names = relative_files(&folder);
    assert_eq!(
        names,
        ["captures/cap_one.json", "environment.json", "evidence.jsonl", "limitations.md", "manifest.json", "replay.json", "subjects.json"]
    );
    let verdict = bundle::verify_bundle(&folder).unwrap();
    assert_eq!(verdict["ok"], true, "{verdict}");
    assert_eq!(verdict["bundle_id"], result["bundle_id"]);
    let id = result["bundle_id"].as_str().unwrap();
    assert!(id.starts_with("eb_") && id.len() == 67);
    assert_eq!(verdict["limitations"], json!(["coverage_unknown", "fixture_only", "indirect_calls_unresolved", "static_only"]));
    let manifest: Value = serde_json::from_slice(&std::fs::read(folder.join("manifest.json")).unwrap()).unwrap();
    assert_eq!(manifest["format"], bundle::FORMAT);
    let listed: Vec<&String> = manifest["files"].as_object().unwrap().keys().collect();
    assert_eq!(listed.len(), names.len() - 1);
    let text = std::fs::read_to_string(folder.join("limitations.md")).unwrap();
    assert!(text.contains("`static_only`"));
    assert!(text.contains("(bounds coverage)"));
    let replay: Value = serde_json::from_slice(&std::fs::read(folder.join("replay.json")).unwrap()).unwrap();
    assert_eq!(replay["scenarios"].as_array().unwrap().iter().map(|s| s["name"].clone()).collect::<Vec<_>>(), [json!("hit count")]);
}

#[test]
fn the_selection_filters_and_an_empty_selection_is_refused() {
    let w = World::new();
    populate(&w.db, &["x"], "writer");
    assert_eq!(w.export_with("only-25", &w.db, |o| o.build = "2.5".into()).unwrap()["records"], 3);
    let error = w.export_with("none", &w.db, |o| o.game = "no-such-game".into()).unwrap_err();
    assert_eq!(code_of(&error), "empty_selection");
    assert_eq!(error.to_string(), "no claims match game='no-such-game' subsystem='' build=''");
    assert!(!w.root().join("none").exists());
}

#[test]
fn a_citation_without_its_capture_is_named_not_hidden() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    let empty = w.root().join("no-captures");
    std::fs::create_dir(&empty).unwrap();
    let result = w.export_with("b", &w.db, |o| o.captures_dir = Some(empty.clone())).unwrap();
    assert_eq!(result["missing_captures"], json!(["cap_one"]));
    assert_eq!(bundle::verify_bundle(&w.root().join("b")).unwrap()["missing_captures"], json!(["cap_one"]));
}

#[test]
fn export_replaces_a_bundle_only_when_told_to_and_never_a_foreign_folder() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("bundle");
    let error = w.export_with("bundle", &w.db, |_| {}).unwrap_err();
    assert_eq!(code_of(&error), "bundle_exists");
    assert_eq!(w.export_with("bundle", &w.db, |o| o.overwrite = true).unwrap()["records"], 3);
    let foreign = w.root().join("foreign");
    std::fs::create_dir(&foreign).unwrap();
    std::fs::write(foreign.join("mine.txt"), "keep").unwrap();
    let error = bundle::export_bundle(&w.db, &foreign, &ExportOptions { overwrite: true, ..ExportOptions::default() }).unwrap_err();
    assert_eq!(code_of(&error), "not_a_bundle");
    assert_eq!(std::fs::read_to_string(foreign.join("mine.txt")).unwrap(), "keep");
    let leftovers: Vec<String> = std::fs::read_dir(w.root())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".staging") || n.ends_with(".old"))
        .collect();
    assert!(leftovers.is_empty(), "{leftovers:?}");
}

#[test]
fn an_export_beside_a_busy_writer_is_a_consistent_snapshot() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    let db = w.db.clone();
    let writer = std::thread::spawn(move || {
        for index in 0..150 {
            let mut c = Claim::new("cp", "2.5", "field", &format!("busy-{index}"), "n", "s");
            c.subsystem = "vehicles".into();
            evidence::add_claim(&db, &c, &ctx("writer")).expect("add");
        }
    });
    for index in 0..3 {
        let name = format!("snap{index}");
        w.export_with(&name, &w.db, |o| o.overwrite = true).unwrap();
        assert_eq!(bundle::verify_bundle(&w.root().join(&name)).unwrap()["ok"], true);
    }
    writer.join().unwrap();
}

// ---- Tampering --------------------------------------------------------------------------------------------------------

fn tampered() -> (World, PathBuf) {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("bundle");
    let folder = w.root().join("bundle");
    (w, folder)
}

fn verdict_error(folder: &Path) -> Value {
    bundle::verify_bundle(folder).unwrap()
}

#[test]
fn a_flipped_byte_in_any_file_is_caught() {
    let (_w, folder) = tampered();
    for name in ["evidence.jsonl", "subjects.json", "replay.json", "limitations.md", "environment.json", "captures/cap_one.json"] {
        let pristine = std::fs::read(folder.join(name)).unwrap();
        mutate(&folder, name, |mut data| {
            data[20] ^= 1;
            data
        });
        let verdict = verdict_error(&folder);
        assert_eq!(verdict["ok"], false, "{name}");
        assert_eq!(verdict["error"], "bundle_file_changed", "{name}");
        std::fs::write(folder.join(name), pristine).unwrap();
    }
    assert_eq!(verdict_error(&folder)["ok"], true);
}

#[test]
fn a_record_changed_with_the_manifest_repaired_still_fails_its_evidence_id() {
    let (_w, folder) = tampered();
    let path = folder.join("evidence.jsonl");
    let text = std::fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = text.lines().map(String::from).collect();
    let mut record: Value = serde_json::from_str(&lines[0]).unwrap();
    let note = format!("{}!", record["content"]["note"].as_str().unwrap());
    record["content"]["note"] = json!(note);
    lines[0] = evidence::canonical_json(&record).unwrap();
    let data = format!("{}\n", lines.join("\n")).into_bytes();
    std::fs::write(&path, &data).unwrap();
    set_manifest_entry(&folder, "evidence.jsonl", &data);
    let verdict = verdict_error(&folder);
    assert_eq!((verdict["ok"].clone(), verdict["error"].clone()), (json!(false), json!("evidence_mismatch")));
}

#[test]
fn a_wrong_bundle_id_an_extra_file_a_missing_file_and_a_foreign_path_are_refused() {
    let (w, folder) = tampered();
    let manifest_path = folder.join("manifest.json");
    let pristine = std::fs::read_to_string(&manifest_path).unwrap();
    let mut manifest: Value = serde_json::from_str(&pristine).unwrap();
    manifest["bundle_id"] = json!(format!("eb_{}", "0".repeat(64)));
    std::fs::write(&manifest_path, manifest.to_string()).unwrap();
    assert_eq!(verdict_error(&folder)["error"], "bundle_id_mismatch");
    std::fs::write(&manifest_path, &pristine).unwrap();
    std::fs::write(folder.join("stray.txt"), "x").unwrap();
    assert_eq!(verdict_error(&folder)["error"], "bundle_unlisted_file");
    std::fs::remove_file(folder.join("stray.txt")).unwrap();
    std::fs::remove_file(folder.join("replay.json")).unwrap();
    assert_eq!(verdict_error(&folder)["error"], "bundle_file_missing");
    std::fs::copy(folder.join("limitations.md"), folder.join("replay.json")).unwrap();
    let mut manifest: Value = serde_json::from_str(&pristine).unwrap();
    manifest["files"]["../outside.json"] = json!({"bytes": 1, "sha256": "0".repeat(64)});
    std::fs::write(&manifest_path, manifest.to_string()).unwrap();
    assert_eq!(verdict_error(&folder)["error"], "bundle_path_refused");
    std::fs::write(&manifest_path, "{").unwrap();
    assert_eq!(verdict_error(&folder)["error"], "bundle_manifest_invalid");
    assert_eq!(verdict_error(&w.root().join("nowhere"))["error"], "bundle_missing");
}

#[test]
fn a_derived_file_that_says_something_else_is_refused() {
    let (_w, folder) = tampered();
    let data = b"{\"missing_captures\":[],\"scenarios\":[]}\n".to_vec();
    std::fs::write(folder.join("replay.json"), &data).unwrap();
    set_manifest_entry(&folder, "replay.json", &data);
    assert_eq!(verdict_error(&folder)["error"], "bundle_derived_mismatch");
}

// ---- ForgedRecords ----------------------------------------------------------------------------------------------------

/// Write a bundle whose every hash, derived file and bundle_id is consistent with `records` as given.
fn forge_bundle(folder: &Path, records: &[Value]) {
    let mut records = records.to_vec();
    records.sort_by(|a, b| a["evidence_id"].as_str().cmp(&b["evidence_id"].as_str()));
    let subjects = bundle::subjects_of(&records);
    let replay = bundle::replay_of(&records, &Default::default(), None);
    let limitations = bundle::limitations_of(&records);
    let mut files: std::collections::BTreeMap<String, Vec<u8>> = Default::default();
    files.insert("evidence.jsonl".into(), bundle::jsonl(&records).unwrap());
    files.insert("subjects.json".into(), bundle::json_bytes(&subjects).unwrap());
    files.insert("replay.json".into(), bundle::json_bytes(&replay).unwrap());
    files.insert("environment.json".into(), bundle::json_bytes(&json!({})).unwrap());
    files.insert("limitations.md".into(), bundle::limitations_md(&limitations));
    let table: Map<String, Value> = files.iter().map(|(n, d)| (n.clone(), json!({"bytes": d.len(), "sha256": sha(d)}))).collect();
    let manifest = json!({
        "format": bundle::FORMAT,
        "bundle_id": bundle::bundle_id_of(&records, &subjects, &Default::default(), &replay, &limitations, &Default::default()).unwrap(),
        "records": records.len(), "filter": {"game": "", "subsystem": "", "build": ""}, "files": table,
        "volatile": {"exported_at": "2026-01-01T00:00:00Z", "files": []},
    });
    files.insert("manifest.json".into(), bundle::json_bytes(&manifest).unwrap());
    for (name, data) in files {
        let file = folder.join(&name);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, data).unwrap();
    }
}

/// A record whose evidence_id is the true hash of its (possibly invalid) content.
fn hash_valid_record(changes: &[(&str, Value)]) -> Value {
    let mut claim = Claim::new("cp", "2.5", "field", "forged", "n", "s");
    claim.address = "rva:0x10".into();
    let mut content = evidence::build_content(&claim, &[]).unwrap();
    for (key, value) in changes {
        content[*key] = value.clone();
    }
    json!({"evidence_id": evidence::compute_evidence_id(&content).unwrap(), "content": content, "meta": {}})
}

fn cases() -> Vec<(&'static str, Vec<(&'static str, Value)>)> {
    vec![
        (
            "complete coverage beside a bounding limitation",
            vec![("coverage", json!({"status": "complete"})), ("limitations", json!(["event_ring_overflow"]))],
        ),
        ("an unknown confidence", vec![("confidence", json!("bogus"))]),
        ("an integer address", vec![("address", json!(5))]),
        ("an unknown authority", vec![("authority", json!("trust-me"))]),
        (
            "an unsorted limitation list",
            vec![
                ("coverage", json!({"status": "unknown", "reason": "r"})),
                ("limitations", json!(["coverage_unknown", "coverage_unknown"])),
            ],
        ),
        ("a parameters value that is not an object", vec![("parameters", json!(["x"]))]),
        ("a link that is not an evidence id", vec![("evidence_links", json!(["not-an-id"]))]),
        ("an empty note", vec![("note", json!(""))]),
        ("a boolean where a string belongs", vec![("name", json!(true))]),
    ]
}

#[test]
fn each_hash_valid_but_invalid_record_fails_verify_and_import_and_leaves_the_ledger_empty() {
    let w = World::new();
    for (label, changes) in cases() {
        let record = hash_valid_record(&changes);
        let folder = w.root().join("forged");
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir(&folder).unwrap();
        forge_bundle(&folder, std::slice::from_ref(&record));
        let verdict = verdict_error(&folder);
        assert_eq!(verdict["ok"], false, "{label}: {verdict}");
        assert_eq!(verdict["error"], "evidence_content_invalid", "{label}: {verdict}");
        let target = w.root().join("forged.db");
        let _ = std::fs::remove_file(&target);
        let error = bundle::import_bundle(&folder, &target, &ctx("w")).unwrap_err();
        assert!(matches!(error, EvidenceError::Bundle(_)), "{label}");
        let error = evidence::import_records(&target, std::slice::from_ref(&record), &ctx("w")).unwrap_err();
        assert!(matches!(error, EvidenceError::Integrity(_)), "{label}: the library is guarded on its own too");
        assert!(evidence::query(&target, &Filter::default(), Verify::On).unwrap().is_empty(), "{label}");
        assert_eq!(evidence::verify_ledger(&target).unwrap()["failed"], json!([]), "{label}");
    }
}

#[test]
fn the_forged_bundle_of_the_review_is_refused_and_a_valid_one_still_imports() {
    let w = World::new();
    let good = hash_valid_record(&[]);
    let folder = w.root().join("mixed");
    std::fs::create_dir(&folder).unwrap();
    forge_bundle(&folder, std::slice::from_ref(&good));
    assert_eq!(verdict_error(&folder)["ok"], true);
    let target = w.root().join("mixed.db");
    assert_eq!(bundle::import_bundle(&folder, &target, &ctx("w")).unwrap()["added"], 1);
    let bad = hash_valid_record(&[
        ("name", json!("forged-two")),
        ("address", json!(5)),
        ("confidence", json!("bogus")),
        ("coverage", json!({"status": "complete"})),
        ("limitations", json!(["event_ring_overflow"])),
    ]);
    let folder2 = w.root().join("mixed2");
    std::fs::create_dir(&folder2).unwrap();
    forge_bundle(&folder2, &[good, bad]);
    assert!(matches!(bundle::import_bundle(&folder2, &target, &ctx("w")).unwrap_err(), EvidenceError::Bundle(_)));
    assert_eq!(evidence::query(&target, &Filter::default(), Verify::On).unwrap().len(), 1); // as it was, and still readable
}

#[test]
fn meta_that_is_not_an_object_is_a_bundle_error_with_a_code() {
    let w = World::new();
    for meta in [json!("text"), json!({"provenance": "x"}), json!({"created": 5}), json!({"harness": ["x"]})] {
        let mut record = hash_valid_record(&[]);
        record["meta"] = meta.clone();
        let folder = w.root().join("meta");
        let _ = std::fs::remove_dir_all(&folder);
        std::fs::create_dir(&folder).unwrap();
        forge_bundle(&folder, std::slice::from_ref(&record));
        let verdict = verdict_error(&folder);
        assert_eq!((verdict["ok"].clone(), verdict["error"].clone()), (json!(false), json!("bundle_meta_invalid")), "{meta}: {verdict}");
        let error = evidence::import_records(&w.root().join("meta.db"), std::slice::from_ref(&record), &ctx("w")).unwrap_err();
        assert!(matches!(error, EvidenceError::Integrity(_)), "{meta}");
    }
}

// ---- Compare ---------------------------------------------------------------------------------------------------------

#[test]
fn two_independent_exports_compare_equal_modulo_volatile_fields() {
    let w = World::new();
    let (first, second) = (w.root().join("one.db"), w.root().join("two.db"));
    populate(&first, &[], "client-alpha");
    populate(&second, &[], "client-beta");
    w.export_with("one", &first, |_| {}).unwrap();
    w.export_with("two", &second, |_| {}).unwrap();
    let result = bundle::compare_bundles(&w.root().join("one"), &w.root().join("two")).unwrap();
    assert_eq!(result["status"], "equal", "{result}");
    assert_eq!(result["left_bundle_id"], result["right_bundle_id"]);
    assert_eq!(result["changes"], json!([]));
    assert_eq!(result["summary"]["records_unchanged"], 3);
    assert!(result["volatile_ignored"]["files_differing"].as_array().unwrap().contains(&json!("evidence.jsonl")));
    assert_ne!(std::fs::read(w.root().join("one/evidence.jsonl")).unwrap(), std::fs::read(w.root().join("two/evidence.jsonl")).unwrap());
}

#[test]
fn a_different_bundle_is_classified() {
    let w = World::new();
    let (first, second) = (w.root().join("one.db"), w.root().join("two.db"));
    populate(&first, &[], "writer");
    populate(&second, &["more"], "writer");
    let mut extra = Claim::new("cp", "2.6", "function", "ForceMoveTo", "moved again", "s");
    extra.address = "rva:0x3".into();
    extra.subsystem = "vehicles".into();
    evidence::add_claim(&second, &extra, &ctx("writer")).unwrap();
    w.export_with("one", &first, |_| {}).unwrap();
    w.export_with("two", &second, |_| {}).unwrap();
    let result = bundle::compare_bundles(&w.root().join("one"), &w.root().join("two")).unwrap();
    assert_eq!(result["status"], "different");
    let classes: std::collections::BTreeSet<&str> = result["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|c| c["entity"] == "evidence")
        .map(|c| c["classification"].as_str().unwrap())
        .collect();
    assert_eq!(classes, ["added"].into_iter().collect());
    assert_eq!(result["summary"]["records_added"], 2);
    let reverse = bundle::compare_bundles(&w.root().join("two"), &w.root().join("one")).unwrap();
    assert_eq!(reverse["summary"]["records_removed"], 2);
}

#[test]
fn a_changed_claim_and_a_changed_capture_are_named() {
    let w = World::new();
    let (first, second) = (w.root().join("one.db"), w.root().join("two.db"));
    populate(&first, &[], "writer");
    populate(&second, &[], "writer");
    for (db, note) in [(&first, "four hits"), (&second, "five hits")] {
        let mut c = Claim::new("cp", "2.5", "probe", "hit count", note, "runtime observe");
        c.address = "rva:0x2e3270".into();
        c.subsystem = "vehicles".into();
        evidence::add_claim(db, &c, &ctx("writer")).unwrap();
    }
    w.export_with("one", &first, |_| {}).unwrap();
    let other = w.root().join("captures-two");
    std::fs::create_dir(&other).unwrap();
    let mut changed = capture();
    changed["dropped_events"] = json!(3);
    std::fs::write(other.join("cap_one.json"), changed.to_string()).unwrap();
    w.export_with("two", &second, |o| o.captures_dir = Some(other.clone())).unwrap();
    let result = bundle::compare_bundles(&w.root().join("one"), &w.root().join("two")).unwrap();
    let kinds: Vec<(String, String)> = result["changes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| (c["entity"].as_str().unwrap().into(), c["classification"].as_str().unwrap().into()))
        .collect();
    assert!(kinds.contains(&("evidence".into(), "changed".into())));
    assert!(kinds.contains(&("capture".into(), "changed".into())));
    assert_eq!(result["status"], "different");
}

#[test]
fn compare_refuses_a_bundle_that_does_not_verify() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("one");
    w.export("two");
    mutate(&w.root().join("two"), "subjects.json", |mut d| {
        d.push(b' ');
        d
    });
    assert!(matches!(bundle::compare_bundles(&w.root().join("one"), &w.root().join("two")).unwrap_err(), EvidenceError::Bundle(_)));
}

// ---- Import -----------------------------------------------------------------------------------------------------------

#[test]
fn a_bundle_imports_into_another_ledger_with_its_history() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("bundle");
    let target = w.root().join("c.db");
    let summary = bundle::import_bundle(&w.root().join("bundle"), &target, &ctx("importer")).unwrap();
    assert_eq!(
        (summary["added"].clone(), summary["already_present"].clone(), summary["dangling_links"].clone()),
        (json!(3), json!(0), json!(0))
    );
    let found = evidence::query(&target, &Filter { include_superseded: true, limit: 1_000_000, ..Filter::default() }, Verify::On).unwrap();
    let ids =
        |rows: &[Value]| rows.iter().map(|r| r["evidence_id"].as_str().unwrap().to_string()).collect::<std::collections::BTreeSet<_>>();
    let source = evidence::records_for_bundle(&w.db, "", "", "").unwrap();
    assert_eq!(ids(&found), ids(&source));
    let current = evidence::query(&target, &Filter { game: "cp".into(), ..Filter::default() }, Verify::On).unwrap();
    let mut names: Vec<&str> = current.iter().map(|r| r["name"].as_str().unwrap()).collect();
    names.sort_unstable();
    assert_eq!(names, ["ForceMoveTo", "hit count"]);
    assert_eq!(evidence::verify_ledger(&target).unwrap(), json!({"checked": 3, "failed": []}));
    let old = found.iter().find(|r| r["build"] == "2.31").unwrap();
    assert!(!old["superseded_by"].is_null());
    let original = evidence::query(&w.db, &Filter { include_superseded: true, ..Filter::default() }, Verify::On).unwrap();
    assert_eq!(old["client"], original.iter().find(|r| r["build"] == "2.31").unwrap()["client"]);
    // and the imported ledger exports to an equal bundle
    w.export_with("again", &target, |_| {}).unwrap();
    assert_eq!(bundle::compare_bundles(&w.root().join("bundle"), &w.root().join("again")).unwrap()["status"], "equal");
}

#[test]
fn a_second_import_adds_nothing() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("bundle");
    let target = w.root().join("c.db");
    bundle::import_bundle(&w.root().join("bundle"), &target, &ctx("w")).unwrap();
    let again = bundle::import_bundle(&w.root().join("bundle"), &target, &ctx("w")).unwrap();
    assert_eq!((again["added"].clone(), again["already_present"].clone()), (json!(0), json!(3)));
    assert_eq!(evidence::query(&target, &Filter { include_superseded: true, ..Filter::default() }, Verify::On).unwrap().len(), 3);
}

#[test]
fn a_tampered_bundle_imports_nothing() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("bundle");
    mutate(&w.root().join("bundle"), "evidence.jsonl", |d| String::from_utf8(d).unwrap().replacen("moves", "moveZ", 1).into_bytes());
    let target = w.root().join("c.db");
    assert!(matches!(bundle::import_bundle(&w.root().join("bundle"), &target, &ctx("w")).unwrap_err(), EvidenceError::Bundle(_)));
    assert!(!target.exists());
}

#[test]
fn a_history_that_diverged_is_reported_not_overwritten() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("bundle");
    let target = w.root().join("c.db");
    let mut a = Claim::new("cp", "2.31", "function", "ForceMoveTo", "moves the vehicle", "decompile line 12");
    a.address = "rva:0x1a5f14".into();
    a.subsystem = "vehicles".into();
    evidence::add_claim(&target, &a, &ctx("w")).unwrap();
    let mut b = Claim::new("cp", "9.9", "function", "ForceMoveTo", "local successor", "s");
    b.address = "rva:0x99".into();
    b.subsystem = "vehicles".into();
    b.supersedes = Some(1);
    evidence::add_claim(&target, &b, &ctx("w")).unwrap();
    let summary = bundle::import_bundle(&w.root().join("bundle"), &target, &ctx("w")).unwrap();
    assert_eq!(summary["history_diverged"], 1);
    let rows = evidence::query(&target, &Filter { include_superseded: true, limit: 10, ..Filter::default() }, Verify::On).unwrap();
    assert_eq!(rows.last().unwrap()["superseded_by"], 2);
}

// ---- Payloads ---------------------------------------------------------------------------------------------------------

#[test]
fn no_game_payload_bytes_in_a_claim() {
    let w = World::new();
    type Tweak = Box<dyn Fn(&mut Claim)>;
    let bads: Vec<Tweak> = vec![
        Box::new(|c| c.note = "x ".repeat(9000)),
        Box::new(|c| c.parameters = Some(json!({"dump": "ab".repeat(5000)}))),
        Box::new(|c| c.parameters = Some(json!({"blob": "QUJD".repeat(3000)}))),
    ];
    for (index, bad) in bads.iter().enumerate() {
        let db = w.root().join(format!("p{index}.db"));
        let mut c = Claim::new("cp", "1", "k", "n", "n", "s");
        bad(&mut c);
        evidence::add_claim(&db, &c, &ctx("w")).unwrap();
        let result = bundle::export_bundle(&db, &w.root().join(format!("out{index}")), &ExportOptions::default());
        assert_eq!(bundle_code(result), "payload_refused", "{index}");
    }
}

#[test]
fn bounded_captured_hex_is_allowed_and_a_big_capture_is_not() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    let put = |value: Value| std::fs::write(w.captures.join("cap_one.json"), value.to_string()).unwrap();
    let with = |events: Value| {
        let mut c = capture();
        c["events"] = events;
        c
    };
    put(with(json!([{"bytes_hex": "ab".repeat(4000)}]))); // 8000 characters, under the bound
    assert_eq!(w.export("ok")["captures"], 1);
    put(with(json!([{"bytes_hex": "ab".repeat(5000)}])));
    assert_eq!(bundle_code(w.export_with("big-hex", &w.db, |_| {})), "payload_refused");
    put(with(Value::Array((0..200_000).map(|i| json!({"n": i})).collect())));
    assert_eq!(bundle_code(w.export_with("big-file", &w.db, |_| {})), "payload_refused");
    let mut other = capture();
    other["capture_id"] = json!("someone-else");
    put(other);
    assert_eq!(bundle_code(w.export_with("wrong-id", &w.db, |_| {})), "capture_invalid");
}

#[test]
fn a_bundle_that_carries_a_payload_does_not_verify() {
    let (_w, folder) = tampered();
    let path = folder.join("evidence.jsonl");
    let mut lines: Vec<String> = std::fs::read_to_string(&path).unwrap().lines().map(String::from).collect();
    let mut record: Value = serde_json::from_str(&lines[0]).unwrap();
    record["content"]["parameters"] = json!({"blob": "ab".repeat(6000)});
    record["evidence_id"] = json!(evidence::compute_evidence_id(&record["content"]).unwrap());
    lines[0] = evidence::canonical_json(&record).unwrap();
    lines.sort();
    let data = format!("{}\n", lines.join("\n")).into_bytes();
    std::fs::write(&path, &data).unwrap();
    set_manifest_entry(&folder, "evidence.jsonl", &data);
    let error = verdict_error(&folder)["error"].as_str().unwrap().to_string();
    assert!(["payload_refused", "bundle_not_canonical"].contains(&error.as_str()), "{error}");
}

#[test]
fn the_bundle_of_this_suite_holds_only_fixture_text() {
    let (w, folder) = tampered();
    let mut text = String::new();
    for name in relative_files(&folder) {
        text.push_str(&std::fs::read_to_string(folder.join(name)).unwrap());
    }
    let root = w.root().to_string_lossy().into_owned();
    let bundle_path = folder.to_string_lossy().into_owned();
    assert!(!text.replace(&bundle_path, "").contains(&root), "no local path leaks into a bundle");
}

// ---- Surface ---------------------------------------------------------------------------------------------------------

#[test]
fn the_capability_answers_like_the_python_handler() {
    let w = World::new();
    populate(&w.db, &[], "writer");
    w.export("bundle");
    let resolve = |_: &str| w.db.clone();
    let call =
        |options: Value| -> Value { serde_json::from_str(&bundle::handle(&json!({"options": options}), &resolve, &ctx("w"))).unwrap() };
    let reply = call(json!({"op": "verify", "bundle": w.root().join("bundle").to_string_lossy()}));
    assert_eq!(reply["ok"], true);
    assert_eq!(reply["op"], "verify");
    assert_eq!(call(json!({"op": "verify", "bundle": "bundle"}))["error"], "path_not_absolute");
    assert_eq!(call(json!({"op": "burn"}))["error"], "unknown_op");
    let b = w.root().join("bundle").to_string_lossy().into_owned();
    assert_eq!(call(json!({"op": "compare", "left": b, "right": b}))["status"], "equal");
    let raw = bundle::handle(&json!({"options": {"op": "verify", "bundle": b}}), &resolve, &ctx("w"));
    assert!(raw.starts_with("{\n  \"op\": \"verify\",\n  \"ok\": true"), "{raw}");
}

#[test]
fn a_bundle_error_payload_has_the_python_shape() {
    let error = BundleError::new("bundle_file_missing", "x is missing from the bundle").with("file", json!("x"));
    assert_eq!(error.payload(), json!({"error": "bundle_file_missing", "message": "x is missing from the bundle", "file": "x"}));
}

#[test]
fn the_guard_counts_characters_and_names_the_path() {
    let value = json!({"a": ["x".repeat(16385)]});
    let error = bundle::guard_payload(&value, "claim").unwrap_err().to_string();
    assert_eq!(error, "claim.a[0] is a string of 16385 characters; a bundle carries at most 16384");
    assert!(bundle::guard_payload(&json!("é".repeat(16384)), "v").is_ok());
}

#[test]
fn splitlines_matches_python() {
    assert_eq!(bundle::splitlines("a\nb\r\nc\u{2028}d\n"), ["a", "b", "c", "d"]);
    assert_eq!(bundle::splitlines("a\n\nb"), ["a", "", "b"]);
    assert!(bundle::splitlines("").is_empty());
}
