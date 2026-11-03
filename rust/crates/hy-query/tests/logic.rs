//! Rust-side cases for decompile.rs and analysis.rs (the Python-vs-Rust fuzz lives in tests/test_rust_parity_logic.py).

use hy_query::analysis::{Invalid, validate_options};
use hy_query::decompile::{coverage, from_error, limitations, merge, py_int0, summarize};
use serde_json::{Value, json};

fn obj(v: Value) -> serde_json::Map<String, Value> {
    v.as_object().unwrap().clone()
}

#[test]
fn python_int_literals() {
    assert_eq!(py_int0("0x10"), Some(16));
    assert_eq!(py_int0(" 1_0 "), Some(10));
    assert_eq!(py_int0("0b11"), Some(3));
    assert_eq!(py_int0("010"), None);
    assert_eq!(py_int0("000"), Some(0));
    assert_eq!(py_int0("1__0"), None);
    assert_eq!(py_int0("1.0"), None);
}

#[test]
fn old_engine_replies_are_unchanged() {
    assert!(summarize(&json!({"ok": true, "truncated": false})).is_empty());
    assert_eq!(
        coverage(&json!({})),
        json!({"status": "unknown", "reason": "the decompile reply carries no truncated/fragments fields"})
    );
}

#[test]
fn truncated_reply_is_partial_with_fragment_totals() {
    let reply = json!({"truncated": true, "bytes_emitted": 10, "reason": "max_result_mb", "fragments": [
        {"start": "0x10", "end": "0x20", "class": "code"}, {"start": "0x20", "end": "0x28", "class": "data"}, {"start": 3, "end": 1, "class": "code"}]});
    let s = summarize(&reply);
    assert_eq!(s["partial"], json!(true));
    assert_eq!(
        s["fragment_bytes"],
        json!({"code": 16, "data": 8, "unknown": 0})
    );
    assert_eq!(
        s["fragments_note"],
        json!("1 malformed fragment(s) dropped")
    );
    assert_eq!(
        limitations(&reply),
        vec!["decompile_truncated", "non_code_fragments"]
    );
    assert_eq!(
        coverage(&reply),
        json!({"status": "partial", "limitations": ["decompile_truncated"]})
    );
}

#[test]
fn paging_and_merge() {
    let reply = json!({"completed": true, "c": "page", "offset": 4, "chars": 99, "next_offset": 8});
    let merged = merge(
        &json!({"ok": true, "c": "whole", "truncated": true}),
        &reply,
    )
    .unwrap();
    assert_eq!(merged["c"], json!("page"));
    assert_eq!(merged["total_characters"], json!(99));
    assert_eq!(merged["truncated"], json!(false));
    assert!(merge(&json!({"ok": true}), &json!({"completed": false})).is_none());
    assert!(from_error("{\"truncated\": true, \"c\": \"x\"}").is_some());
    assert!(from_error("{\"truncated\": true}").is_none());
    assert!(from_error("nope").is_none());
}

#[test]
fn option_validation_bounds_and_fallbacks() {
    let ok = validate_options("decompile", None, false).unwrap();
    assert_eq!(ok, json!({"max_characters": 32000}));
    let err = validate_options("decompile", Some(&obj(json!({"max_characters": 0}))), false);
    assert_eq!(
        err,
        Err(Invalid::Value(
            "max_characters must be an integer in 1..2097152".into()
        ))
    );
    let err = validate_options("function", Some(&obj(json!({"x": 1}))), false);
    assert_eq!(
        err,
        Err(Invalid::Value(
            "options are not supported for function".into()
        ))
    );
    assert_eq!(
        validate_options("diff", None, false),
        Err(Invalid::Fallback)
    );
    assert_eq!(
        validate_options("scan", Some(&obj(json!({"regex": "a"}))), false),
        Err(Invalid::Fallback)
    );
    let t = validate_options(
        "type_edit",
        Some(&obj(
            json!({"kind": "function_delete", "source": "d", "expect": "55 8b"}),
        )),
        false,
    )
    .unwrap();
    assert_eq!(t["expect"], json!("55 8B"));
}
