//! Ports of the tests that specify `hydralysis/api.py`'s pure parts (test_contracts, test_hydralysis, test_address_maps'
//! `api` cases) plus its argument checks, which the Python suite exercises only through whole tool calls.

use hy_engine::api::{self, Address, JobKind};
use hy_engine::failure::{Failure, Kind};
use serde_json::{Map, Value, json};

/// The hash of the advertised tool table at catalog epoch 5 (`tests/test_contracts.py` CATALOG_HISTORY).
const EPOCH_5: &str = "7d5fe723148db2813b1cf2555db3a78e056fca48faa786066e0c5b4fb826a9fd";

fn names() -> Vec<String> {
    api::catalog().tool_names.clone()
}

fn refused(result: Result<(), Failure>) -> String {
    match result {
        Err(Failure::Raise(raise)) => {
            assert_eq!(raise.kind, Kind::ValueError);
            raise.message
        }
        other => panic!("{other:?}"),
    }
}

// ---- the catalog -------------------------------------------------------------------------------------------------

#[test]
fn the_table_matches_its_epoch_so_a_change_needs_a_new_epoch() {
    assert_eq!(api::catalog().epoch, 5);
    assert_eq!(api::default_catalog_hash(), EPOCH_5);
    assert_eq!(api::catalog().hash, EPOCH_5, "catalog.json is stale: run tools/gen_mcp_catalog.py");
}

#[test]
fn the_hash_covers_names_descriptions_and_schemas_and_ignores_key_order() {
    let base = api::catalog().tools.clone();
    assert_eq!(api::catalog_hash(&base), EPOCH_5);
    for field in ["name", "description", "inputSchema"] {
        let mut altered = base.clone();
        altered[0][field] = if field == "inputSchema" { json!({"type": "object"}) } else { json!("changed") };
        assert_ne!(api::catalog_hash(&altered), EPOCH_5, "{field}");
    }
    let mut reordered = base.clone();
    let properties = reordered[0]["inputSchema"]["properties"].as_object().unwrap().clone();
    let reversed: Map<String, Value> = properties.into_iter().rev().collect();
    reordered[0]["inputSchema"]["properties"] = Value::Object(reversed);
    assert_eq!(api::catalog_hash(&reordered), EPOCH_5);
    let mut extra = base.clone();
    extra[3]["inputSchema"]["properties"]["added"] = json!({"type": "string"});
    assert_ne!(api::catalog_hash(&extra), EPOCH_5);
}

#[test]
fn the_table_names_the_twenty_one_tools_in_order() {
    let table = api::catalog().tools.as_array().unwrap();
    let advertised: Vec<&str> = table.iter().map(|tool| tool["name"].as_str().unwrap()).collect();
    assert_eq!(advertised.len(), 21);
    assert_eq!(advertised, names().iter().map(String::as_str).collect::<Vec<_>>());
    assert_eq!(advertised.first(), Some(&"fingerprint"));
    assert_eq!(advertised.last(), Some(&"trace"));
    for carrier in ["xrefs", "callers", "callees", "function", "disasm", "bytes", "inspect", "prologue"] {
        let tool = table.iter().find(|t| t["name"] == carrier).unwrap();
        let description = tool["inputSchema"]["properties"]["address"]["description"].as_str().unwrap();
        assert!(description.contains("ambiguous unprefixed addresses are refused"), "{carrier}");
    }
}

#[test]
fn the_instructions_are_the_python_text_for_a_version() {
    let catalog = api::catalog();
    assert_eq!(api::instructions(&catalog.version), catalog.instructions);
}

#[test]
fn not_available_is_a_result_with_the_catalog_and_the_detail_in_place() {
    let detail: Map<String, Value> = serde_json::from_value(json!({"tool": "job", "options": ["a", "b"], "message": "later"})).unwrap();
    let text = api::not_available("jobOptions", "first", &detail, 5, "ab");
    let expected = "{\n  \"not_available\": \"jobOptions\",\n  \"message\": \"later\",\n  \"tool\": \"job\",\n  \"options\": [\n    \"a\",\n    \"b\"\n  ],\n  \"catalog\": {\n    \"epoch\": 5,\n    \"hash\": \"ab\"\n  }\n}";
    assert_eq!(text, expected, "a detail key overrides in place; non-ASCII is escaped");
    let unicode = api::not_available("x", "ação", &Map::new(), 1, "h");
    assert!(unicode.contains("a\\u00e7\\u00e3o"));
}

// ---- the head of call ---------------------------------------------------------------------------------------------

#[test]
fn arguments_must_be_an_object_and_the_tool_must_exist() {
    let ok = |name: Value, args: Value| api::validate_call(&name, &args, &names());
    assert!(ok(json!("fingerprint"), Value::Null).is_ok());
    assert!(ok(json!("sections"), json!({})).is_ok(), "CLI-only commands are tools of the dispatch table");
    assert_eq!(refused(ok(json!("nope"), json!({}))), "unknown tool nope");
    assert_eq!(refused(ok(json!("fingerprint"), json!([]))), "tool arguments must be an object");
    assert_eq!(refused(ok(json!("nope"), json!("x"))), "tool arguments must be an object", "the arguments are checked first");
    assert!(matches!(ok(json!(5), json!({})), Err(Failure::Fallback(_))));
}

#[test]
fn limit_count_and_size_are_bounded() {
    let check = |args: Value| api::validate_call(&json!("imports"), &args, &names());
    assert!(check(json!({"limit": 200, "count": 1, "size": 65536})).is_ok());
    assert_eq!(refused(check(json!({"limit": 201}))), "limit must be 1..200");
    assert_eq!(refused(check(json!({"limit": 0}))), "limit must be 1..200");
    assert_eq!(refused(check(json!({"count": -3}))), "count must be 1..200");
    assert_eq!(refused(check(json!({"size": 65537}))), "size must be 1..65536");
    assert_eq!(refused(check(json!({"limit": true}))), "limit must be 1..200", "a bool is refused before int() sees it");
    // int() semantics: numeric strings and floats are accepted
    assert!(check(json!({"limit": "40"})).is_ok());
    assert!(check(json!({"limit": 40.9})).is_ok());
    assert_eq!(refused(check(json!({"limit": 0.5}))), "limit must be 1..200");
    // the first bad key in limit, count, size order wins
    assert_eq!(refused(check(json!({"size": 0, "limit": 0}))), "limit must be 1..200");
    match check(json!({"limit": "ten"})) {
        Err(Failure::Raise(raise)) => assert_eq!(raise.message, "invalid literal for int() with base 10: 'ten'"),
        other => panic!("{other:?}"),
    }
    match check(json!({"limit": null})) {
        Err(Failure::Raise(raise)) => assert_eq!(raise.kind, Kind::TypeError),
        other => panic!("{other:?}"),
    }
}

// ---- answers --------------------------------------------------------------------------------------------------

#[test]
fn bytes_are_upper_case_hex_separated_by_spaces() {
    assert_eq!(api::hex_bytes_upper_spaced(&[]), "");
    assert_eq!(api::hex_bytes_upper_spaced(&[0x4c]), "4C");
    assert_eq!(api::hex_bytes_upper_spaced(&[0x00, 0xff, 0x0a, 0xb7]), "00 FF 0A B7");
    assert_eq!(api::hex_bytes_upper_spaced(&vec![0xab; 65536]).len(), 65536 * 3 - 1);
}

#[test]
fn the_prologue_arguments_are_checked_before_any_bytes_are_read() {
    assert_eq!(api::prologue_sha256(&json!("A".repeat(64))).unwrap(), "a".repeat(64));
    for bad in [
        json!("a".repeat(63)),
        json!("a".repeat(65)),
        json!(format!("{}g", "a".repeat(63))),
        json!(12),
        Value::Null,
        json!(format!("{}\n", "a".repeat(64))),
    ] {
        match api::prologue_sha256(&bad) {
            Err(Failure::Raise(raise)) => assert_eq!(raise.message, "sha256 must be a full hexadecimal build hash", "{bad}"),
            other => panic!("{bad}: {other:?}"),
        }
    }
    assert_eq!(api::prologue_image_base(&json!("0x140000000")).unwrap(), 0x1_4000_0000);
    assert_eq!(api::prologue_image_base(&json!(5368709120_u64)).unwrap(), 5_368_709_120);
    assert_eq!(api::prologue_image_base(&json!("0b101")).unwrap(), 5);
    match api::prologue_image_base(&json!("base")) {
        Err(Failure::Raise(raise)) => assert_eq!(raise.message, "invalid literal for int() with base 0: 'base'"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_evidence_export_is_an_absolute_md_path() {
    for good in [r"C:\notes\out.md", "C:/notes/out.md", r"D:\a.b\c.md", r"C:\x\.hidden.md", r"C:\x\out.md\"] {
        assert!(api::export_path_ok(good).unwrap(), "{good}");
    }
    for bad in [
        r"notes\out.md",
        "out.md",
        r"\notes\out.md",
        r"C:out.md",
        r"C:\notes\out.txt",
        r"C:\notes\.md",
        r"C:\notes\out.",
        r"C:\",
        r"C:\notes\md",
        "",
    ] {
        assert!(!(api::export_path_ok(bad).unwrap()), "{bad}");
    }
    for odd in [r"\\server\share\x.md", r"\\?\C:\x.md", "C:\\x:y.md", "C:\\caf\u{e9}.md"] {
        assert!(matches!(api::export_path_ok(odd), Err(Failure::Fallback(_))), "{odd}");
    }
}

#[test]
fn job_ids_name_their_store() {
    assert_eq!(api::job_kind("export-1"), JobKind::Export);
    assert_eq!(api::job_kind("decompile-ab"), JobKind::Decompile);
    assert_eq!(api::job_kind("overlay-9"), JobKind::Overlay);
    assert_eq!(api::job_kind("job-0123456789ab"), JobKind::Script);
    assert_eq!(api::job_kind("install-1"), JobKind::Install);
    assert_eq!(api::job_kind(""), JobKind::Install);
    assert!(api::script_job_id_ok("job-0123456789ab"));
    for bad in ["job-0123456789AB", "job-0123456789a", "job-0123456789abc", "job-0123456789ag", "xjob-0123456789ab", "job-0123456789ab\n"] {
        assert!(!api::script_job_id_ok(bad), "{bad}");
    }
}

#[test]
fn the_job_listing_is_newest_first_projected_and_stable() {
    let records = vec![
        json!({"id": "a", "created_at": 1, "extra": 1, "state": "done"}),
        json!({"id": "b", "started_at": 5.5, "kind": "export"}),
        json!({"id": "c"}),
        json!({"id": "d", "created_at": 1, "log_path": "x"}),
        json!({"id": "e", "created_at": 9, "owner": {"client": "me"}}),
    ];
    let text = api::job_listing(&records, 4).unwrap();
    let parsed: Value = serde_json::from_str(&text).unwrap();
    let order: Vec<&str> = parsed["jobs"].as_array().unwrap().iter().map(|j| j["id"].as_str().unwrap()).collect();
    assert_eq!(order, ["e", "b", "a", "d"], "equal keys keep their order");
    assert!(parsed["jobs"][2].get("extra").is_none());
    assert_eq!(parsed["jobs"][3]["log_path"], json!("x"));
    assert_eq!(parsed["detail"], json!("Pass an id to job status for bounded logs and full metadata."));
    assert!(text.starts_with("{\n  \"jobs\": [\n    {\n      \"id\": \"e\""));
    // a key that is null or text cannot be ordered against numbers: the original raises, so this is not modelled
    assert!(api::job_listing(&[json!({"created_at": null}), json!({"id": 1})], 5).is_err());
    assert!(api::job_listing(&[json!({"created_at": "2026"}), json!({"id": 1})], 5).is_err());
}

#[test]
fn list_and_options_helpers() {
    assert_eq!(api::list_of(&Value::Null).unwrap(), Vec::<Value>::new());
    assert_eq!(api::list_of(&json!("a  b\tc\n")).unwrap(), vec![json!("a"), json!("b"), json!("c")]);
    assert_eq!(api::list_of(&json!([1, "x"])).unwrap(), vec![json!(1), json!("x")]);
    assert!(api::list_of(&json!(5)).is_err());
    let bag = |value: Value| api::options_bag(&serde_json::from_value(json!({"options": value})).unwrap());
    assert!(bag(Value::Null).unwrap().is_empty());
    assert_eq!(bag(json!({"op": "list"})).unwrap().len(), 1);
    assert!(bag(json!([])).is_err());
    assert!(api::options_bag(&Map::new()).unwrap().is_empty());
}

#[test]
fn ghidra_run_options_are_validated_before_the_capability_is_asked() {
    assert!(!(api::script_options_dispatch(&Value::Null).unwrap()));
    assert!(!(api::script_options_dispatch(&json!({})).unwrap()));
    assert!(api::script_options_dispatch(&json!({"isolation": "private", "readonly": true})).unwrap());
    assert!(api::script_options_dispatch(&json!({"as": "me"})).unwrap());
    assert!(api::script_options_dispatch(&json!({"isolation": null})).unwrap());
    for (bad, message) in [
        (json!([1]), "options must be an object"),
        (json!({"isolation": "worker"}), "ghidra_run options.isolation must be private, shared or exclusive"),
        (json!({"isolation": 3}), "ghidra_run options.isolation must be private, shared or exclusive"),
        (json!({"readonly": "yes"}), "ghidra_run options.readonly must be a boolean"),
        (json!({"readonly": 1}), "ghidra_run options.readonly must be a boolean"),
    ] {
        match api::script_options_dispatch(&bad) {
            Err(Failure::Raise(raise)) => assert_eq!(raise.message, message, "{bad}"),
            other => panic!("{bad}: {other:?}"),
        }
    }
}

#[test]
fn backups_take_list_verify_or_remove() {
    let op = |value: Value| api::backups_op(&serde_json::from_value(value).unwrap());
    assert_eq!(op(json!({})).unwrap(), "list");
    assert_eq!(op(json!({"op": "verify"})).unwrap(), "verify");
    assert!(op(json!({"op": "delete"})).is_err());
    assert!(op(json!({"op": null})).is_err());
}

// ---- addresses --------------------------------------------------------------------------------------------------

const BASE: u64 = 0x1_4000_0000;

#[test]
fn an_address_is_parsed_the_way_the_python_helper_does() {
    assert_eq!(api::parse_address("name:main", BASE).unwrap(), Address::Mapped);
    assert_eq!(api::parse_address("  hash:0x12 ", BASE).unwrap(), Address::Mapped);
    assert_eq!(api::parse_address("rva:0x1000", BASE).unwrap(), Address::Parsed { rva: 0x1000, bare: None });
    assert_eq!(api::parse_address("va:0x140001000", BASE).unwrap(), Address::Parsed { rva: 0x1000, bare: None });
    assert_eq!(api::parse_address("0x1000", BASE).unwrap(), Address::Parsed { rva: 0x1000, bare: Some(0x1000) });
    assert_eq!(api::parse_address(" 0x140001000 ", BASE).unwrap(), Address::Parsed { rva: 0x1000, bare: Some(0x1_4000_1000) });
    assert_eq!(api::parse_address("4096", BASE).unwrap(), Address::Parsed { rva: 4096, bare: Some(4096) });
    match api::parse_address("seg:0x1", BASE) {
        Err(Failure::Raise(raise)) => assert_eq!(raise.message, "address prefix must be rva: or va:"),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        api::ambiguous_address(" 0x140001000 ", 0x1_4000_1000, 0x1000),
        "ambiguous address 0x140001000: RVA 0x140001000 and VA 0x140001000 (RVA 0x1000) both map to this image; use rva:0x140001000 or va:0x140001000"
    );
}
