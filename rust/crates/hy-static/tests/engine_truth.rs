//! Differential check against answers recorded from the real Hydra Engine (`RusticQuery` through
//! `QueryRunner`, benchmarks/static_plane.py harness) on the same fixture project.

use std::path::{Path, PathBuf};

use hy_static::{Error, StaticProgram, answer};
use serde_json::{Value, json};

fn fixtures() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

fn truth(name: &str) -> Value {
    serde_json::from_str(&std::fs::read_to_string(fixtures().join("engine").join(name)).unwrap()).unwrap()
}

fn program() -> StaticProgram {
    StaticProgram::open(&fixtures().join("legacy-12.1.4-analysed"), "/flow_fixture.exe").unwrap()
}

fn request(action: &str, address: &str, limit: u64, cursor: &str, contains: &str) -> Value {
    json!({"id": "t", "action": action, "address": address, "limit": limit, "cursor": cursor,
           "contains": contains, "timeout_s": 30, "options": {}, "expected_sha256": ""})
}

/// Keys the engine answer has that the plane's reply is compared on.
fn same(got: &Value, want: &Value, keys: &[&str]) {
    for key in keys {
        assert_eq!(got.get(*key), want.get(*key), "key {key}");
    }
}

#[test]
fn function_rows_equal_the_engine_or_are_declined() {
    let p = program();
    let rows = truth("function.json");
    let mut equal = 0;
    let mut declined = Vec::new();
    for (address, want) in rows.as_object().unwrap() {
        match answer(&p, &request("function", address, 40, "", "")) {
            Ok(got) => {
                assert_eq!(got["function"], want["function"], "function at {address}");
                same(&got, want, &["program", "sha256", "image_base", "address_kind"]);
                equal += 1;
            }
            Err(Error::Unsupported(why)) => declined.push((address.clone(), why)),
            Err(other) => panic!("{address}: {other}"),
        }
    }
    eprintln!("function: {equal} equal, {} declined", declined.len());
    for d in declined.iter().take(5) {
        eprintln!("  declined {d:?}");
    }
    assert!(equal > 300, "only {equal} of 405 answered natively");
}

#[test]
fn function_inside_a_body_is_the_containing_function() {
    let p = program();
    let rows = truth("function.json");
    let mut checked = 0;
    for (_, want) in rows.as_object().unwrap().iter().take(60) {
        let body = want["function"]["body"][0].as_str().unwrap();
        let max = u64::from_str_radix(body.trim_matches(|c| c == '[' || c == ']').split(", ").nth(1).unwrap(), 16).unwrap();
        if let Ok(got) = answer(&p, &request("function", &format!("va:0x{max:x}"), 40, "", "")) {
            assert_eq!(got["function"], want["function"]);
            checked += 1;
        }
    }
    assert!(checked > 30);
}

#[test]
fn functions_pages_equal_the_engine_or_are_declined() {
    let p = program();
    let pages = truth("functions.json");
    let (mut equal, mut declined) = (0, 0);
    let mut cursor = String::new();
    for page in pages.as_array().unwrap() {
        match answer(&p, &request("functions", "", 200, &cursor, "")) {
            Ok(got) => {
                assert_eq!(got["functions"], page["functions"], "page at cursor {cursor:?}");
                same(&got, page, &["scanned", "truncated", "next_cursor", "program", "sha256"]);
                equal += 1;
            }
            Err(Error::Unsupported(why)) => {
                eprintln!("functions page at {cursor:?} declined: {why}");
                declined += 1;
            }
            Err(other) => panic!("{other}"),
        }
        match page.get("next_cursor") {
            Some(next) if page["truncated"] == json!(true) => cursor = next.as_str().unwrap().to_owned(),
            _ => break,
        }
    }
    eprintln!("functions pages: {equal} equal, {declined} declined");
    assert!(equal >= 1, "no page answered natively");
    // Small pages and the filter: the first page that has no declined function.
    let contains = truth("functions_contains.json");
    match answer(&p, &request("functions", "", 5, "", "fun")) {
        Ok(got) => {
            assert_eq!(got["functions"], contains["functions"]);
            same(&got, &contains, &["scanned", "truncated", "next_cursor"]);
        }
        Err(Error::Unsupported(_)) => {}
        Err(other) => panic!("{other}"),
    }
}
