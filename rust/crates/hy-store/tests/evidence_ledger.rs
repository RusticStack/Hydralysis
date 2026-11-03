//! Ports of tests/test_evidence.py and tests/test_evidence_model.py (same cases; see TESTMAP_evidence.md).

mod evsupport;

use evsupport::*;
use hy_store::evidence::{self, Claim, EvidenceError, Filter, Verify};
use serde_json::{Value, json};

const PINNED_ID: &str = "ev_429247fbd78b7252e2ccd84c4e669781dbe9d812f958e3865d48b43f6ed467ed";

fn pinned() -> Claim {
    let mut c = Claim::new("cp", "2.5", "function", "ForceMoveTo", "moves the vehicle", "decompile line 12");
    c.address = "rva:0x2e3270".into();
    c.subsystem = "vehicles".into();
    c
}

fn err_text<T: std::fmt::Debug>(result: hy_store::evidence::Result<T>) -> String {
    result.expect_err("expected an error").to_string()
}

fn strings(value: &Value) -> Vec<String> {
    value.as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect()
}

// ---- tests/test_evidence.py -----------------------------------------------------------------------------------------

#[test]
fn concurrent_writers_all_land() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let handles: Vec<_> = (0..4)
        .map(|w| {
            let db = db.clone();
            std::thread::spawn(move || {
                for index in 0..40 {
                    let mut claim = Claim::new("cp", "2.5", "function", &format!("w{w}-{index}"), "written concurrently", "test");
                    claim.subsystem = "vehicles".into();
                    evidence::add_claim(&db, &claim, &ctx("writer")).expect("add");
                }
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    let filter = Filter { game: "cp".into(), subsystem: "vehicles".into(), limit: 1000, ..Filter::default() };
    let found = evidence::query(&db, &filter, Verify::On).unwrap();
    assert_eq!(found.len(), 160);
    assert!(found.iter().all(|r| r["harness"] == "writer"));
    let check = rusqlite::Connection::open(&db).unwrap();
    let mode: String = check.query_row("PRAGMA journal_mode", [], |r| r.get(0)).unwrap();
    assert_eq!(mode.to_lowercase(), "wal");
}

#[test]
fn supersession_keeps_the_old_claim_and_filters_it() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let mut first = base();
    first.address = "rva:0x6ab990".into();
    first.subsystem = "animation".into();
    add(&db, first).unwrap();
    let old_id = rows(&db, "cp", false)[0]["id"].as_i64().unwrap();
    let mut second = base();
    second.build = "2.5".into();
    second.address = "rva:0x7c1234".into();
    second.subsystem = "animation".into();
    second.supersedes = Some(old_id);
    add(&db, second).unwrap();
    let by_subsystem = |include| {
        let f = Filter { game: "cp".into(), subsystem: "animation".into(), include_superseded: include, ..Filter::default() };
        evidence::query(&db, &f, Verify::On).unwrap()
    };
    let current = by_subsystem(false);
    assert_eq!(current.iter().map(|r| r["build"].as_str().unwrap()).collect::<Vec<_>>(), ["2.5"]);
    let both = by_subsystem(true);
    assert_eq!(both.len(), 2);
    let old = both.iter().find(|r| r["id"].as_i64() == Some(old_id)).unwrap();
    assert_eq!(old["superseded_by"], current[0]["id"]);
    let mut again = base();
    again.build = "2.5".into();
    again.supersedes = Some(old_id);
    assert!(err_text(add(&db, again)).contains("already superseded"));
    let by = |address: &str, build: &str| {
        let f = Filter { game: "cp".into(), address: address.into(), build: build.into(), ..Filter::default() };
        evidence::query(&db, &f, Verify::On).unwrap().len()
    };
    assert_eq!(by("rva:0x7c1234", ""), 1);
    assert_eq!(by("", "2.31"), 0);
}

#[test]
fn export_lists_current_claims_and_superseded_ones() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let mut a = base();
    a.subsystem = "vehicles".into();
    a.name = "ForceMoveTo".into();
    a.address = "rva:0x1a5f14".into();
    add(&db, a).unwrap();
    let old_id = rows(&db, "cp", false)[0]["id"].as_i64().unwrap();
    let mut b = base();
    b.subsystem = "vehicles".into();
    b.name = "ForceMoveTo".into();
    b.build = "2.5".into();
    b.address = "rva:0x2e3270".into();
    b.supersedes = Some(old_id);
    add(&db, b).unwrap();
    let result = evidence::export(&db, &path(&dir, "vehicles.md"), "cp", "vehicles").unwrap();
    assert_eq!((result["current"].as_u64(), result["superseded"].as_u64()), (Some(1), Some(1)));
    let text = std::fs::read_to_string(result["markdown"].as_str().unwrap()).unwrap();
    assert!(text.contains("rva:0x2e3270"));
    assert!(text.contains("## Superseded"));
    assert_eq!(std::fs::read_to_string(result["jsonl"].as_str().unwrap()).unwrap().lines().count(), 2);
}

fn legacy_schema(db: &std::path::Path, upto_superseded_by: bool) {
    let connection = rusqlite::Connection::open(db).unwrap();
    connection.execute_batch(evidence::SCHEMA).unwrap();
    if upto_superseded_by {
        for column in ["subsystem", "client", "harness", "supersedes", "superseded_by"] {
            let declaration = evidence::COLUMNS.iter().find(|(n, _)| *n == column).unwrap().1;
            connection.execute_batch(&format!("ALTER TABLE claims ADD COLUMN {column} {declaration}")).unwrap();
        }
    }
}

#[test]
fn a_first_release_ledger_is_upgraded_in_place() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    legacy_schema(&db, false);
    raw(&db, "INSERT INTO claims (game, build, kind, name, note, source, created) VALUES ('cp','2.31','k','n','note','src','t')", &[]);
    let mut claim = base();
    claim.subsystem = "new".into();
    add(&db, claim).unwrap();
    let found = rows(&db, "cp", true);
    assert_eq!(found.len(), 2);
    assert_eq!(found.last().unwrap()["subsystem"], "");
}

// ---- tests/test_evidence_model.py: ContentAddressedId ---------------------------------------------------------------

#[test]
fn the_id_is_stable_across_key_order() {
    let mut a = pinned();
    a.parameters = Some(json!({"a": 1, "b": {"x": [1, 2], "y": "z"}}));
    let mut b = pinned();
    b.parameters = Some(serde_json::from_str(r#"{"b": {"y": "z", "x": [1, 2]}, "a": 1}"#).unwrap());
    let ca = evidence::build_content(&a, &[]).unwrap();
    let cb = evidence::build_content(&b, &[]).unwrap();
    assert_eq!(evidence::compute_evidence_id(&ca).unwrap(), evidence::compute_evidence_id(&cb).unwrap());
    // a reversed key order of the content itself
    let reversed: serde_json::Map<String, Value> = ca.as_object().unwrap().iter().rev().map(|(k, v)| (k.clone(), v.clone())).collect();
    assert_eq!(evidence::compute_evidence_id(&ca).unwrap(), evidence::compute_evidence_id(&Value::Object(reversed)).unwrap());
    let id = evidence::compute_evidence_id(&ca).unwrap();
    assert!(id.starts_with("ev_") && id.len() == 67 && evidence::is_evidence_id_str(&id));
}

#[test]
fn the_id_is_pinned_so_that_stored_ids_never_orphan() {
    let content = evidence::build_content(&pinned(), &[]).unwrap();
    assert_eq!(evidence::compute_evidence_id(&content).unwrap(), PINNED_ID);
}

#[test]
fn the_id_is_stable_across_sessions() {
    let dir = work();
    let (one, two) = (path(&dir, "one.db"), path(&dir, "two.db"));
    let mut claim = pinned();
    claim.parameters = Some(json!({"z": 1, "a": {"y": [1, 2], "b": "x"}}));
    claim.coverage = Some(json!({"status": "partial", "limitations": ["static_only"]}));
    let first = evidence::add_claim(&one, &claim, &ctx("writer")).unwrap();
    let second = evidence::add_claim(&two, &claim, &ctx("another-client")).unwrap();
    let ids: Vec<&str> = [&first, &second].iter().map(|m| m.split("evidence_id=").nth(1).unwrap().trim()).collect();
    assert_eq!(ids[0], ids[1]);
    assert!(evidence::is_evidence_id_str(ids[0]));
    let stored = &evidence::query(&one, &Filter::default(), Verify::On).unwrap()[0];
    assert_eq!(stored["evidence_id"], ids[0]);
    assert_eq!(stored["parameters"], json!({"z": 1, "a": {"y": [1, 2], "b": "x"}}));
}

#[test]
fn the_id_commits_the_content_and_not_the_writer() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    add(&db, base()).unwrap();
    let mut other = base();
    other.note = "different".into();
    let message = add(&db, other).unwrap();
    assert_eq!(
        rows(&db, "cp", true)
            .iter()
            .map(|r| r["evidence_id"].as_str().unwrap().to_string())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        2
    );
    assert!(message.contains("stored"));
    let mut claim = pinned();
    claim.coverage = Some(json!({"status": "partial", "limitations": ["static_only"]}));
    evidence::add_claim(&db, &claim, &ctx("writer")).unwrap();
    let again = evidence::add_claim(&db, &claim, &ctx("second")).unwrap();
    assert!(again.contains("already stored"));
}

#[test]
fn the_key_order_of_utf16_not_of_code_points() {
    // U+FFEE is above U+10000 by code point but below it in UTF-16 units.
    let value: Value = serde_json::from_str("{\"\u{10000}\": 1, \"\u{ffee}\": 2}").unwrap();
    assert_eq!(evidence::canonical_json(&value).unwrap(), "{\"\u{10000}\":1,\"\u{ffee}\":2}");
}

#[test]
fn floats_and_big_integers_are_refused() {
    let mut claim = pinned();
    claim.parameters = Some(json!({"x": 1.5}));
    assert!(err_text(evidence::build_content(&claim, &[])).contains("float"));
    claim.parameters = Some(json!({"x": 1u64 << 60}));
    assert!(err_text(evidence::build_content(&claim, &[])).contains("2**53"));
    // a lone surrogate cannot exist in a Rust &str, so that Python case has no counterpart; the database is not created
    let dir = work();
    let db = path(&dir, "evidence.db");
    let mut bad = pinned();
    bad.parameters = Some(json!({"x": 1.5}));
    assert!(evidence::add_claim(&db, &bad, &ctx("w")).is_err());
    assert!(!db.exists());
}

#[test]
fn a_flipped_byte_is_rejected_on_read() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let mut claim = base();
    claim.name = "alpha".into();
    claim.note = "the original note".into();
    add(&db, claim).unwrap();
    assert_eq!(rows(&db, "cp", false).len(), 1);
    raw(&db, "UPDATE claims SET note = ? WHERE name = 'alpha'", &[&"the originbl note"]);
    let filter = Filter { game: "cp".into(), ..Filter::default() };
    let error = evidence::query(&db, &filter, Verify::On).unwrap_err();
    let integrity = error.as_integrity().expect("integrity error");
    assert_eq!(integrity.code, "evidence_mismatch");
    assert_eq!(integrity.row_id, Some(1));
    let listing = evidence::list_claims(&db, "cp", 50, &Filter::default()).unwrap();
    assert!(listing.contains("INTEGRITY FAILED"));
    let report = evidence::verify_ledger(&db).unwrap();
    assert_eq!(report["checked"], 1);
    assert_eq!(report["failed"].as_array().unwrap().iter().map(|f| f["id"].as_i64().unwrap()).collect::<Vec<_>>(), [1]);
    assert!(evidence::export(&db, &path(&dir, "out.md"), "cp", "").is_err());
}

#[test]
fn a_flipped_id_and_a_flipped_coverage_are_rejected_too() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let mut a = base();
    a.name = "alpha".into();
    add(&db, a).unwrap();
    let mut b = base();
    b.name = "beta".into();
    b.coverage = Some(json!("complete"));
    add(&db, b).unwrap();
    let filter = Filter { game: "cp".into(), ..Filter::default() };
    let stored = evidence::query(&db, &filter, Verify::On).unwrap()[0]["evidence_id"].as_str().unwrap().to_string();
    let last = stored.chars().last().unwrap();
    let flipped = format!("{}{}", &stored[..stored.len() - 1], if last != '0' { '0' } else { '1' });
    raw(&db, "UPDATE claims SET evidence_id = ? WHERE evidence_id = ?", &[&flipped, &stored]);
    assert!(evidence::query(&db, &filter, Verify::On).is_err());
    raw(&db, "UPDATE claims SET evidence_id = ? WHERE evidence_id = ?", &[&stored, &flipped]);
    assert_eq!(rows(&db, "cp", true).len(), 2);
    raw(&db, "UPDATE claims SET coverage = ? WHERE name = 'beta'", &[&r#"{"status": "partial", "limitations": ["static_only"]}"#]);
    assert!(evidence::query(&db, &filter, Verify::On).is_err());
    raw(&db, "UPDATE claims SET coverage = ? WHERE name = 'beta'", &[&"{broken"]);
    let error = evidence::query(&db, &filter, Verify::On).unwrap_err();
    assert_eq!(error.as_integrity().unwrap().code, "evidence_unreadable");
}

#[test]
fn restating_a_superseding_claim_is_idempotent_even_after_its_predecessor_is_superseded() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    add(&db, base()).unwrap();
    let mut second = base();
    second.note = "second".into();
    second.supersedes = Some(1);
    assert!(add(&db, second.clone()).unwrap().contains("stored"));
    assert!(add(&db, second).unwrap().contains("already stored"));
    assert_eq!(rows(&db, "cp", true).len(), 2);
    let mut third = base();
    third.note = "third".into();
    third.supersedes = Some(1);
    assert!(err_text(add(&db, third)).contains("already superseded"));
    assert_eq!(rows(&db, "cp", true).len(), 2);
}

#[test]
fn a_claim_stated_twice_is_one_row() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    add(&db, base()).unwrap();
    assert!(add(&db, base()).unwrap().contains("already stored"));
    assert_eq!(rows(&db, "cp", true).len(), 1);
    let mut complete = base();
    complete.coverage = Some(json!({"status": "complete"}));
    add(&db, complete).unwrap();
    assert_eq!(rows(&db, "cp", true).len(), 2);
}

#[test]
fn concurrent_writers_of_one_claim_leave_one_row() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let handles: Vec<_> = (0..6)
        .map(|w| {
            let db = db.clone();
            std::thread::spawn(move || {
                let mut claim = pinned();
                claim.coverage = Some(json!({"status": "partial", "limitations": ["static_only"]}));
                evidence::add_claim(&db, &claim, &ctx(&format!("w{w}"))).expect("add")
            })
        })
        .collect();
    for handle in handles {
        handle.join().unwrap();
    }
    assert_eq!(rows(&db, "cp", true).len(), 1);
}

#[test]
fn supersession_is_an_evidence_link() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let mut old = base();
    old.name = "old".into();
    old.address = "rva:0x1".into();
    add(&db, old).unwrap();
    let old = rows(&db, "cp", false)[0].clone();
    let mut new = base();
    new.name = "old".into();
    new.build = "2.5".into();
    new.address = "rva:0x2".into();
    new.supersedes = old["id"].as_i64();
    add(&db, new).unwrap();
    let new = rows(&db, "cp", false)[0].clone();
    assert_eq!(new["evidence_links"], json!([old["evidence_id"]]));
    let got = evidence::get_claim(&db, old["evidence_id"].as_str().unwrap()).unwrap().unwrap();
    assert_eq!(got["superseded_by"], new["id"]);
    assert!(evidence::get_claim(&db, &format!("ev_{}", "0".repeat(64))).unwrap().is_none());
}

#[test]
fn the_parameters_carry_the_probe_hash() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let digest = "ab".repeat(32);
    let mut claim = base();
    claim.parameters = Some(json!({"script_sha256": digest}));
    claim.authority = Some("controlled-replay".into());
    claim.confidence = Some("observed".into());
    claim.from_capture = "cap_1".into();
    claim.subject_sha256 = "cd".repeat(32);
    add(&db, claim).unwrap();
    let row = rows(&db, "cp", false)[0].clone();
    assert_eq!(row["parameters"], json!({"script_sha256": digest}));
    assert_eq!(
        (row["authority"].as_str(), row["confidence"].as_str(), row["from_capture"].as_str()),
        (Some("controlled-replay"), Some("observed"), Some("cap_1"))
    );
    assert_eq!(row["subject_sha256"], "cd".repeat(32));
    type Tweak = Box<dyn Fn(&mut Claim)>;
    let bads: Vec<Tweak> = vec![
        Box::new(|c| c.from_capture = "../x".into()),
        Box::new(|c| c.subject_sha256 = "xyz".into()),
        Box::new(|c| c.authority = Some("trust-me".into())),
        Box::new(|c| c.confidence = Some("sure".into())),
        Box::new(|c| c.parameters = Some(json!([1]))),
    ];
    for bad in bads {
        let mut claim = base();
        claim.name = "bad".into();
        bad(&mut claim);
        assert!(add(&db, claim).is_err());
    }
}

// ---- CoverageAndLimitations ------------------------------------------------------------------------------------------

#[test]
fn a_claim_that_does_not_say_is_unknown() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    add(&db, base()).unwrap();
    let row = rows(&db, "cp", false)[0].clone();
    assert_eq!(row["coverage"], json!({"status": "unknown", "reason": "coverage_not_reported"}));
    assert_eq!(row["limitations"], json!(["coverage_unknown"]));
}

#[test]
fn the_coverage_and_the_catalog_are_stored_with_the_row() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    let mut a = base();
    a.name = "a".into();
    a.coverage = Some(json!({"status": "partial", "limitations": ["event_ring_overflow", "hit_limit_reached"]}));
    a.limitations = vec![json!("single_run"), json!("fixture_only")];
    add(&db, a).unwrap();
    let mut b = base();
    b.name = "b".into();
    b.coverage = Some(json!({"status": "complete"}));
    b.limitations = vec![json!("static_only")];
    add(&db, b).unwrap();
    let found = rows(&db, "cp", false);
    let get = |name: &str| found.iter().find(|r| r["name"] == name).unwrap().clone();
    assert_eq!(get("a")["coverage"]["status"], "partial");
    assert_eq!(strings(&get("a")["limitations"]), ["event_ring_overflow", "fixture_only", "hit_limit_reached", "single_run"]);
    assert_eq!(strings(&get("b")["limitations"]), ["static_only"]);
    for code in strings(&get("a")["limitations"]).iter().chain(strings(&get("b")["limitations"]).iter()) {
        assert!(evidence::limitation_entry(code).is_some(), "{code}");
    }
    let listing = evidence::list_claims(&db, "cp", 50, &Filter::default()).unwrap();
    assert!(listing.contains("coverage=partial"));
    assert!(listing.contains("limitations=event_ring_overflow"));
}

#[test]
fn a_capped_capture_never_presents_as_complete() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    for code in ["event_ring_overflow", "hit_limit_reached", "payload_clipped", "sampled"] {
        let mut claim = base();
        claim.coverage = Some(json!({"status": "complete"}));
        claim.limitations = vec![json!(code)];
        assert!(err_text(add(&db, claim)).contains("complete"), "{code}");
    }
    let mut claim = base();
    claim.coverage = Some(json!("complete"));
    claim.limitations = vec![json!("z9test:capped")]; // a code of one's own is assumed to bound
    assert!(err_text(add(&db, claim)).contains("complete"));
    assert!(!db.exists());
}

#[test]
fn the_coverage_object_is_strict() {
    let bads = [
        json!({"status": "mostly"}),
        json!({"status": "partial"}),
        json!({"status": "partial", "limitations": []}),
        json!({"status": "unknown", "reason": " "}),
        json!({"status": "complete", "reason": "x"}),
        json!({"status": "complete", "colour": "red"}),
        json!({"status": "partial", "limitations": ["no_such_code"]}),
    ];
    for bad in bads {
        assert!(evidence::normalize_coverage(Some(&bad)).is_err(), "{bad}");
    }
    assert_eq!(evidence::normalize_coverage(Some(&json!("complete"))).unwrap(), json!({"status": "complete"}));
    let partial = evidence::normalize_coverage(Some(&json!({"status": "partial", "limitations": ["sampled"]}))).unwrap();
    assert_eq!(evidence::merge_limitations(&partial, &[json!("z9:custom")]).unwrap(), ["sampled", "z9:custom"]);
    // messages equal Python's
    assert_eq!(
        evidence::normalize_coverage(Some(&json!({"status": "mostly"}))).unwrap_err().to_string(),
        "coverage.status must be one of complete, partial, unknown"
    );
    assert_eq!(
        evidence::check_limitation_code(&json!("Bad Code")).unwrap_err().to_string(),
        "limitation code 'Bad Code' is not a lowercase identifier (optionally `namespace:code`)"
    );
}

#[test]
fn the_states_are_those_of_the_reference() {
    assert_eq!(
        evidence::COVERAGE_STATES.iter().collect::<std::collections::BTreeSet<_>>(),
        ["complete", "partial", "unknown"].iter().collect()
    );
}

// ---- LegacyLedger ----------------------------------------------------------------------------------------------------

fn legacy(db: &std::path::Path) {
    legacy_schema(db, true);
    let sql = "INSERT INTO claims (game, build, kind, name, address, prologue, note, source, created, subsystem, client, harness, supersedes, superseded_by) VALUES ('cp', ?, 'function', ?, ?, '', 'note', 'src', '2026-01-01T00:00:00Z', 'veh', 'old-client:1', 'cli', ?, ?)";
    raw(db, sql, &[&"2.31", &"ForceMoveTo", &"rva:0x1a5f14", &None::<i64>, &2i64]);
    raw(db, sql, &[&"2.5", &"ForceMoveTo", &"rva:0x2e3270", &1i64, &None::<i64>]);
    raw(db, sql, &[&"2.5", &"Other", &"rva:0x10", &None::<i64>, &None::<i64>]);
}

#[test]
fn legacy_rows_are_backfilled_and_verify() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    legacy(&db);
    let found = rows(&db, "cp", true);
    assert_eq!(found.len(), 3);
    assert!(found.iter().all(|r| evidence::is_evidence_id(&r["evidence_id"])));
    let by = |name: &str, build: &str| found.iter().find(|r| r["name"] == name && r["build"] == build).unwrap().clone();
    let (old, new) = (by("ForceMoveTo", "2.31"), by("ForceMoveTo", "2.5"));
    assert_eq!(new["evidence_links"], json!([old["evidence_id"]]));
    assert_eq!(old["coverage"]["status"], "unknown");
    assert_eq!(old["authority"], evidence::DEFAULT_AUTHORITY);
    assert_eq!(evidence::verify_ledger(&db).unwrap(), json!({"checked": 3, "failed": []}));
    assert_eq!(old["client"], "old-client:1"); // attribution survives
}

#[test]
fn a_backfilled_row_has_the_id_of_the_same_claim_stated_today() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    legacy(&db);
    let other = rows(&db, "cp", false).into_iter().find(|r| r["name"] == "Other").unwrap();
    let fresh = path(&dir, "fresh.db");
    let mut claim = Claim::new("cp", "2.5", "function", "Other", "note", "src");
    claim.address = "rva:0x10".into();
    claim.subsystem = "veh".into();
    evidence::add_claim(&fresh, &claim, &ctx("w")).unwrap();
    let got = evidence::query(&fresh, &Filter::default(), Verify::On).unwrap();
    assert_eq!(got[0]["evidence_id"], other["evidence_id"]);
}

#[test]
fn the_backfill_is_not_repeated_and_new_rows_land_beside_it() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    legacy(&db);
    rows(&db, "cp", false);
    let before: Vec<Value> = rows(&db, "cp", true).iter().map(|r| r["evidence_id"].clone()).collect();
    let mut claim = base();
    claim.name = "after".into();
    add(&db, claim).unwrap();
    let after: Vec<Value> = rows(&db, "cp", true).iter().map(|r| r["evidence_id"].clone()).collect();
    assert_eq!(after.len(), 4);
    assert!(before.iter().all(|id| after.contains(id)));
}

#[test]
fn a_row_written_by_an_old_client_after_the_migration_is_backfilled_on_the_next_open() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    add(&db, base()).unwrap();
    raw(&db, "INSERT INTO claims (game, build, kind, name, note, source, created) VALUES ('cp','1','k','n','note','src','t')", &[]);
    let found = rows(&db, "cp", true);
    assert_eq!(found.len(), 2);
    assert!(found.iter().all(|r| evidence::is_evidence_id(&r["evidence_id"])));
}

#[test]
fn four_connections_opening_an_old_ledger_at_once_agree() {
    let dir = work();
    let db = path(&dir, "evidence.db");
    legacy(&db);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let db = db.clone();
            std::thread::spawn(move || {
                let connection = evidence::connect(&db).expect("connect");
                let missing: i64 = connection
                    .query_row("SELECT count(*) FROM claims WHERE evidence_id IS NULL OR evidence_id = ''", [], |r| r.get(0))
                    .unwrap();
                missing
            })
        })
        .collect();
    for handle in handles {
        assert_eq!(handle.join().unwrap(), 0);
    }
    assert_eq!(evidence::verify_ledger(&db).unwrap(), json!({"checked": 3, "failed": []}));
}

// ---- extra checks of the public surface (new in the port) ---------------------------------------------------------------

#[test]
fn integrity_errors_carry_code_and_row() {
    let error: EvidenceError = evidence::verify_content(&json!({}), &json!("nope")).unwrap_err();
    assert_eq!(error.code(), Some("evidence_id_malformed"));
    assert_eq!(error.to_string(), "'nope' is not an evidence id");
}

#[test]
fn the_time_format_matches_strftime() {
    assert_eq!(evidence::format_utc(0), "1970-01-01T00:00:00Z");
    assert_eq!(evidence::format_utc(1_767_225_600), "2026-01-01T00:00:00Z");
    assert_eq!(evidence::format_utc(1_709_209_599), "2024-02-29T12:26:39Z");
}
