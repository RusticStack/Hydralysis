//! Ports of the tests that specify the small leaf modules: test_address_maps, test_hydralysis (the address table),
//! test_integrity (the scan), test_jobowner, test_paths (`forbidden_drives`) and test_localio.

use std::collections::HashSet;
use std::fs;
use std::path::Path;

use hy_engine::address_map::{self, normalise};
use hy_engine::failure::{Failure, Kind};
use hy_engine::{integrity, red4ext, small};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

fn message<T: std::fmt::Debug>(result: Result<T, Failure>) -> String {
    match result {
        Err(Failure::Raise(raise)) => {
            assert_eq!(raise.kind, Kind::ValueError);
            raise.message
        }
        other => panic!("{other:?}"),
    }
}

// ---- address maps -----------------------------------------------------------------------------------------------

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn file(entries: Value, digest: &str, source: &str) -> Vec<u8> {
    json!({"sha256": digest, "source": source, "entries": entries}).to_string().into_bytes()
}

#[test]
fn an_import_is_build_bound_cited_and_normalised() {
    let raw =
        file(json!([{"name": "global", "hash": "0x00AB", "rva": "rva:0x1234", "source": "fixture.map:4"}]), DIGEST, "fixture symbols:12");
    let done = normalise(&raw, DIGEST, r"C:\in\input.json").unwrap();
    assert_eq!(done.entries, 1);
    assert_eq!(done.map_sha256, Sha256::digest(&raw).iter().map(|b| format!("{b:02x}")).collect::<String>());
    let entry = &done.record["entries"][0];
    assert_eq!(*entry, json!({"name": "global", "hash": "0xab", "rva": "0x1234", "source": "fixture.map:4"}));
    let keys: Vec<&str> = done.record.keys().map(String::as_str).collect();
    assert_eq!(keys, ["sha256", "map_sha256", "file", "source", "entries", "record_sha256"]);
    assert_eq!(done.record["record_sha256"], json!(address_map::record_hash(&done.record)));
    // a row without its own source inherits the file's
    let inherit = normalise(&file(json!([{"name": "a", "rva": "0x100"}]), DIGEST, "fixture symbols:12"), DIGEST, "f").unwrap();
    assert_eq!(inherit.record["entries"][0]["source"], json!("fixture symbols:12"));
    assert_eq!(inherit.record["entries"][0]["hash"], json!(""));
}

#[test]
fn a_mismatched_build_a_missing_source_or_a_bad_row_fails_closed() {
    let wrong = file(json!([{"name": "a", "rva": "0x100"}]), &"b".repeat(64), "s");
    assert_eq!(message(normalise(&wrong, DIGEST, "f")), "address map build SHA-256 mismatch");
    let cases = [
        ("", json!({"name": "a", "rva": "0x100"}), "address map requires a cited source"),
        ("   ", json!({"name": "a", "rva": "0x100"}), "address map requires a cited source"),
        ("fixture", json!({"name": "a", "rva": "va:0x100"}), "address map rva must be hexadecimal, e.g. 0x1234"),
        ("fixture", json!({"hash": "not hex", "rva": "0x100"}), "address map hash must be hexadecimal, e.g. 0x1234"),
        ("fixture", json!({"rva": "0x100"}), "address map entry needs a name or hash"),
        ("fixture", json!({"name": "a", "rva": "0x123456789"}), "address map rva must be hexadecimal, e.g. 0x1234"),
        ("fixture", json!({"name": "a", "rva": "0x1", "extra": 1}), "address map entries take name, hash, rva and optional source"),
        ("fixture", json!({"name": 5, "rva": "0x1"}), "address map name must be text of at most 512 characters"),
        ("fixture", json!({"name": "a\u{0}b", "rva": "0x1"}), "address map name must be text of at most 512 characters"),
        ("fixture", json!({"name": "a", "rva": "0x1", "source": " "}), "address map entry requires a cited source"),
    ];
    for (source, row, expected) in cases {
        assert_eq!(message(normalise(&file(json!([row]), DIGEST, source), DIGEST, "f")), expected, "{row}");
    }
}

#[test]
fn the_shape_of_the_file_and_the_row_count_are_bounded() {
    let raw = |text: &str| text.as_bytes().to_vec();
    assert_eq!(message(normalise(&raw("[]"), DIGEST, "f")), "address map takes sha256, source and entries");
    assert_eq!(message(normalise(&raw(r#"{"sha256": "x", "other": 1}"#), DIGEST, "f")), "address map takes sha256, source and entries");
    assert_eq!(message(normalise(&file(json!([]), DIGEST, "s"), DIGEST, "f")), "address map requires 1..100000 entries");
    assert_eq!(message(normalise(&file(json!("rows"), DIGEST, "s"), DIGEST, "f")), "address map requires 1..100000 entries");
    assert_eq!(message(normalise(&[0xff, b'{'], DIGEST, "f")), "address map must be UTF-8 JSON");
    assert_eq!(message(normalise(b"{}", "short", "f")), "address map requires the full build SHA-256");
    assert_eq!(message(normalise(&vec![b' '; address_map::MAX_BYTES + 1], DIGEST, "f")), "address map exceeds 16 MiB");
    let many: Vec<Value> = (0..100_001).map(|i| json!({"name": format!("n{i}"), "rva": "0x1"})).collect();
    assert_eq!(message(normalise(&file(Value::Array(many), DIGEST, "s"), DIGEST, "f")), "address map requires 1..100000 entries");
    // UTF-16 and other encodings Python's json.loads sniffs are the original's to read
    assert!(matches!(normalise(&[0xff, 0xfe, b'{', 0], DIGEST, "f"), Err(Failure::Fallback(_))));
    // a UTF-8 BOM is read as Python reads it
    let mut bom = vec![0xef, 0xbb, 0xbf];
    bom.extend(file(json!([{"name": "a", "rva": "0x1"}]), DIGEST, "s"));
    assert_eq!(normalise(&bom, DIGEST, "f").unwrap().entries, 1);
}

#[test]
fn the_largest_map_normalises() {
    let rows: Vec<Value> = (0..address_map::MAX_ROWS)
        .map(|i| json!({"name": format!("name{i}"), "hash": format!("0x{i:x}"), "rva": format!("0x{:x}", i % 0xffff)}))
        .collect();
    let done = normalise(&file(Value::Array(rows), DIGEST, "s"), DIGEST, "f").unwrap();
    assert_eq!(done.entries, 100_000);
    assert_eq!(done.record["entries"][99_999]["hash"], json!("0x1869f"));
}

#[test]
fn hashes_up_to_thirty_two_digits_and_the_zero_hash_are_normalised() {
    let big = format!("0x{}", "f".repeat(32));
    let done =
        normalise(&file(json!([{"hash": big, "rva": "0x0"}, {"hash": "0x0000", "rva": "rva:0x00ff"}]), DIGEST, "s"), DIGEST, "f").unwrap();
    assert_eq!(done.record["entries"][0]["hash"], json!(big));
    assert_eq!(done.record["entries"][1]["hash"], json!("0x0"));
    assert_eq!(done.record["entries"][1]["rva"], json!("0xff"));
    assert_eq!(
        message(normalise(&file(json!([{"hash": format!("0x{}", "f".repeat(33)), "rva": "0x0"}]), DIGEST, "s"), DIGEST, "f")),
        "address map hash must be hexadecimal, e.g. 0x1234"
    );
}

// ---- the address table ------------------------------------------------------------------------------------------

fn table(dir: &Path, body: &[u8]) -> std::path::PathBuf {
    let path = dir.join("table.json");
    fs::write(&path, body).unwrap();
    path
}

const BODY: &[u8] = b"{\"Code constant offset\": \"1000\"}\n{\"hash\": \"10\", \"symbol\": \"Alpha\", \"offset\": \"0001:00001000\"}\n{\"hash\": \"11\", \"symbol\": \"Beta\", \"offset\": \"0002:00000020\"}\n";

#[test]
fn rows_split_across_chunks_come_out_once_whatever_the_chunk() {
    let dir = tempfile::tempdir().unwrap();
    let path = table(dir.path(), BODY);
    for chunk in [1, 7, 24, 64, 4096, red4ext::CHUNK_SIZE] {
        let mut hashes = Vec::new();
        red4ext::for_each_entry(&path, chunk, |row| {
            hashes.push(row.hash);
            true
        })
        .unwrap();
        assert_eq!(hashes, [10, 11], "chunk {chunk}");
    }
    let found = red4ext::lookup_hashes(&path, &HashSet::from([10]), 24).unwrap();
    assert_eq!(found, ["10 0xa 0001 0x2000 Alpha"]);
}

#[test]
fn the_other_segments_are_not_rvas_and_rvas_are_matched_through_the_constant_offset() {
    let dir = tempfile::tempdir().unwrap();
    let path = table(dir.path(), BODY);
    assert_eq!(red4ext::lookup_hashes(&path, &HashSet::from([11]), 1024).unwrap(), ["11 0xb 0002 0002:20 (not an RVA) Beta"]);
    assert_eq!(red4ext::lookup_rvas(&path, &HashSet::from([0x2000]), 1024).unwrap(), ["10 0xa 0001 0x2000 Alpha"]);
    assert!(red4ext::lookup_rvas(&path, &HashSet::from([0x20]), 1024).unwrap().is_empty(), "segment 2 is never matched by an RVA");
    assert_eq!(red4ext::code_constant_offset(&path).unwrap(), 0x1000);
    let plain = table(dir.path(), b"{\"hash\": \"1\", \"offset\": \"0001:00000010\"}");
    assert_eq!(red4ext::code_constant_offset(&plain).unwrap(), 0x1000, "no stated offset: 0x1000");
    assert_eq!(red4ext::lookup_hashes(&plain, &HashSet::from([1]), 8).unwrap(), ["1 0x1 0001 0x1010 "], "a row without a symbol");
}

#[test]
fn optional_fields_whitespace_and_a_secondary_hash_are_all_rows() {
    let dir = tempfile::tempdir().unwrap();
    let body = b"{\"hash\":  \"5\" , \"secondary hash\": \"ab\", \"symbol\": \"caf\xc3\xa9 \xff\", \"offset\": \"0001:ff\"}";
    let path = table(dir.path(), body);
    // the second spelling has whitespace the pattern does not allow before the comma: not a row
    assert!(red4ext::lookup_hashes(&path, &HashSet::from([5]), 64).unwrap().is_empty());
    let ok =
        table(dir.path(), b"{\"hash\": \"5\",\n \"secondary hash\": \"ab\",  \"symbol\": \"caf\xc3\xa9 \xff\",\t\"offset\":\n\"0001:ff\"}");
    assert_eq!(red4ext::lookup_hashes(&ok, &HashSet::from([5]), 64).unwrap(), ["5 0x5 0001 0x10ff caf\u{e9} \u{fffd}"]);
}

#[test]
fn a_missing_table_is_left_to_the_original_and_a_huge_hash_is_not_modelled() {
    let dir = tempfile::tempdir().unwrap();
    assert!(matches!(red4ext::lookup_hashes(&dir.path().join("none.json"), &HashSet::new(), 64), Err(Failure::Fallback(_))));
    let path = table(dir.path(), format!("{{\"hash\": \"{}\", \"offset\": \"0001:1\"}}", "9".repeat(60)).as_bytes());
    assert!(matches!(red4ext::lookup_hashes(&path, &HashSet::new(), 64), Err(Failure::Fallback(_))));
}

// ---- integrity ----------------------------------------------------------------------------------------------------

fn project(folder: &Path, name: &str, versions: &[u32], bad: &[u32], databases: usize) {
    fs::create_dir_all(folder).unwrap();
    fs::write(folder.join(format!("{name}.gpr")), "gpr").unwrap();
    for index in 0..databases {
        let database = folder.join(format!("{name}.rep")).join("idata").join("00").join(format!("~{index:08x}.db"));
        fs::create_dir_all(&database).unwrap();
        for &number in versions {
            let mut body = if bad.contains(&number) { vec![0u8; 8] } else { integrity::GBF_MAGIC.to_vec() };
            body.extend(vec![number as u8; 64]);
            fs::write(database.join(format!("db.{number}.gbf")), body).unwrap();
        }
    }
}

#[test]
fn a_clean_project_has_no_findings() {
    let dir = tempfile::tempdir().unwrap();
    project(&dir.path().join("clean"), "p", &[1, 2], &[], 3);
    let report = integrity::scan(&dir.path().join("clean")).unwrap();
    assert_eq!((report["ok"].clone(), report["databases"].clone(), report["versions"].clone()), (json!(true), json!(3), json!(6)));
    assert_eq!(report["usable"], json!(true));
    let keys: Vec<&str> = report.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["project", "databases", "versions", "newest_invalid", "empty", "usable", "ok"]);
}

#[test]
fn the_magic_is_the_one_valid_files_begin_with() {
    assert_eq!(integrity::GBF_MAGIC, *b"/01,4),*");
}

#[test]
fn a_zero_header_newest_version_is_found_with_its_fallback() {
    let dir = tempfile::tempdir().unwrap();
    project(&dir.path().join("torn"), "p", &[1, 2], &[2], 1);
    let report = integrity::scan(&dir.path().join("torn")).unwrap();
    assert_eq!(report["ok"], json!(false));
    let found = &report["newest_invalid"][0];
    assert_eq!(
        (found["file"].clone(), found["version"].clone(), found["previous_valid"].clone()),
        (json!("db.2.gbf"), json!(2), json!("db.1.gbf"))
    );
    assert_eq!(report["usable"], json!(true));
}

#[test]
fn only_the_newest_version_counts_and_the_order_is_numeric() {
    let dir = tempfile::tempdir().unwrap();
    project(&dir.path().join("old"), "p", &[1, 2], &[1], 1);
    assert_eq!(integrity::scan(&dir.path().join("old")).unwrap()["ok"], json!(true));
    project(&dir.path().join("many"), "p", &[1, 2, 10], &[10], 2);
    let report = integrity::scan(&dir.path().join("many")).unwrap();
    let versions: Vec<&Value> = report["newest_invalid"].as_array().unwrap().iter().map(|item| &item["version"]).collect();
    assert_eq!(versions, [&json!(10), &json!(10)], "numeric order, not text");
}

#[test]
fn a_short_file_is_invalid_and_a_database_with_no_version_is_empty_not_damaged() {
    let dir = tempfile::tempdir().unwrap();
    project(&dir.path().join("short"), "p", &[1, 2], &[], 1);
    fs::write(dir.path().join("short/p.rep/idata/00/~00000000.db/db.2.gbf"), b"/01").unwrap();
    assert_eq!(integrity::scan(&dir.path().join("short")).unwrap()["ok"], json!(false));
    project(&dir.path().join("new"), "p", &[], &[], 1);
    let report = integrity::scan(&dir.path().join("new")).unwrap();
    assert_eq!((report["ok"].clone(), report["empty"].as_array().unwrap().len()), (json!(true), 1));
}

#[test]
fn nothing_valid_left_makes_the_project_unusable() {
    let dir = tempfile::tempdir().unwrap();
    project(&dir.path().join("dead"), "p", &[1], &[1], 1);
    let report = integrity::scan(&dir.path().join("dead")).unwrap();
    assert_eq!((report["usable"].clone(), report["newest_invalid"][0]["previous_valid"].clone()), (json!(false), Value::Null));
}

// ---- jobowner ----------------------------------------------------------------------------------------------------

fn hash(token: &str) -> String {
    Sha256::digest(token.as_bytes()).iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn only_the_starting_client_cancels() {
    let record = json!({"id": "overlay-1", "owner": {"client": "rusticre:1", "harness": "codex", "token_sha256": hash("secret")}});
    assert!(small::owner_check(&record, "", "secret").is_ok(), "the process that started it remembers the token");
    assert!(small::owner_check(&record, "secret", "").is_ok());
    let denied = small::owner_check(&record, "", "").unwrap_err();
    match denied {
        Failure::Raise(raise) => {
            assert_eq!(raise.kind, Kind::PermissionError);
            assert_eq!(
                raise.message,
                "job overlay-1 belongs to rusticre:1 (codex); every client may read it, cancelling it needs owner, the token its start returned"
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(small::owner_check(&record, "not-the-token", "secret").is_err(), "a supplied token wins over the remembered one");
}

#[test]
fn jobs_from_before_owners_stay_open() {
    assert!(small::owner_check(&json!({"id": "old-job"}), "", "").is_ok());
    assert!(small::owner_check(&json!({"id": "x", "owner": {"client": "c"}}), "", "").is_ok());
    assert!(small::owner_check(&json!({"id": "x", "owner": "text"}), "", "").is_ok());
    let by_job_id = json!({"job_id": "prepare-1", "id": "ignored", "owner": {"token_sha256": hash("t")}});
    match small::owner_check(&by_job_id, "", "") {
        Err(Failure::Raise(raise)) => assert!(raise.message.starts_with("job prepare-1 belongs to None (None);")),
        other => panic!("{other:?}"),
    }
}

// ---- paths ------------------------------------------------------------------------------------------------------

#[test]
fn forbidden_drives_come_from_the_setting_or_the_environment() {
    let drives = |setting: Option<Value>, env: &str| small::forbidden_drives(setting.as_ref(), env);
    assert_eq!(drives(None, "").unwrap(), Vec::<String>::new());
    assert_eq!(drives(None, "c:; d:\\ ,E:/").unwrap(), ["C:", "D:", "E:"]);
    assert_eq!(drives(Some(json!(["c:", " d:\\"])), "X:").unwrap(), ["C:", "D:"]);
    assert_eq!(drives(Some(Value::Null), "f:").unwrap(), ["F:"], "a null setting falls back to the environment");
    assert_eq!(drives(Some(json!("g:")), "X:").unwrap(), ["G:"]);
    for bad in [json!([1]), json!(5), json!({"a": 1})] {
        match drives(Some(bad.clone()), "") {
            Err(Failure::Raise(raise)) => {
                assert_eq!(raise.message, "forbidden_drives must be a list of drive names such as [\"C:\"]", "{bad}")
            }
            other => panic!("{bad}: {other:?}"),
        }
    }
    assert!(small::has_dot_component(r"C:\data\.hydralysis\root"));
    assert!(!small::has_dot_component(r"C:\data\hydra.lysis\root"));
}

// ---- localio ------------------------------------------------------------------------------------------------------

#[test]
fn a_bounded_shared_read() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("metadata.json");
    fs::write(&path, b"abcdef").unwrap();
    assert_eq!(small::read_bytes(&path, 6).unwrap(), b"abcdef");
    assert!(message(small::read_bytes(&path, 5)).starts_with("metadata exceeds 5-byte read budget: "));
    assert_eq!(fs::read(&path).unwrap(), b"abcdef", "a refusal changes nothing");
    assert!(
        matches!(small::read_bytes(&dir.path().join("missing.json"), 6), Err(Failure::Fallback(_))),
        "the native error is the original's"
    );
    assert!(matches!(small::read_bytes(dir.path(), 6), Err(Failure::Fallback(_))));
}

#[test]
fn the_text_writers_agree_with_the_generic_serialiser_on_awkward_text() {
    let control = String::from(char::from(1));
    let delete = String::from(char::from(0x7f));
    let names = [
        "plain".to_string(),
        "café ünï".to_string(),
        "😀 smile".to_string(),
        format!("a{control}b"),
        format!("c{delete}d"),
        format!("q{}uote{}x", char::from(34), char::from(92)),
    ];
    let rows: Vec<Value> = names
        .iter()
        .enumerate()
        .map(|(i, name)| json!({"name": name, "hash": format!("0x{:x}", i * 77), "rva": format!("rva:0x{:x}", i * 4097), "source": format!("{name} src")}))
        .collect();
    let raw = file(Value::Array(rows), DIGEST, "cité 😀");
    let text = address_map::normalise_text(&raw, DIGEST, r"C:\dir\fichier ü.json").unwrap();
    let done = normalise(&raw, DIGEST, r"C:\dir\fichier ü.json").unwrap();
    assert_eq!(text.indent2_bytes, hy_engine::pytext::dumps(&Value::Object(done.record.clone()), hy_engine::pytext::Dumps::Indent2).len());
    assert_eq!(done.record["record_sha256"], json!(address_map::record_hash(&done.record)));
    assert_eq!(done.record["entries"][3]["name"], json!(names[3]));
    assert_eq!(done.record["file"], json!(r"C:\dir\fichier ü.json"));
}

#[test]
fn a_record_past_32_mib_is_refused_at_the_byte() {
    // 100000 rows of twenty emoji (about 11 MB of input, 12 escaped bytes each): past the bound once indented
    let name = "😀".repeat(20);
    let rows: Vec<Value> =
        (0..address_map::MAX_ROWS).map(|i| json!({"name": name, "hash": format!("0x{i:x}"), "rva": "0x10", "source": "s"})).collect();
    let big = normalise(&file(Value::Array(rows), DIGEST, "s"), DIGEST, "f");
    assert_eq!(message(big), "normalized address map exceeds 32 MiB");
    let few: Vec<Value> = (0..10).map(|i| json!({"name": name, "hash": format!("0x{i:x}"), "rva": "0x10", "source": "s"})).collect();
    let text = address_map::normalise_text(&file(Value::Array(few), DIGEST, "s"), DIGEST, "f").unwrap();
    assert!(text.indent2_bytes < address_map::MAX_RECORD_BYTES);
}
