//! Port of tests/test_lineage.py: SharedVector, CanonicalForm, Manifests.

mod common;

use common::{temp, write};
use hy_core::sealed::sha256_hex;
use hy_store::lineage::{self, MANIFEST, SEAL_MARKER};
use serde_json::{Value, json};
use std::fs;
use std::path::PathBuf;

fn vectors() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../tests/vectors")
}

fn load(name: &str) -> Value {
    serde_json::from_slice(&fs::read(vectors().join(name)).unwrap()).unwrap()
}

const SHARED_VECTOR_SHA256: &str = "a4391e92765682e65d5df8bcd30818b2760190fa467d86ada174ac5971a210eb";

#[test]
fn the_copy_is_byte_identical_to_the_engine_vector() {
    let raw = fs::read(vectors().join("canonical-manifest.json")).unwrap();
    let normalised: Vec<u8> = String::from_utf8(raw).unwrap().replace("\r\n", "\n").into_bytes();
    assert_eq!(sha256_hex(&normalised), SHARED_VECTOR_SHA256);
}

#[test]
fn lineage_reproduces_the_engine_hashes() {
    let vector = load("canonical-manifest.json");
    let manifest = &vector["object"];
    assert!(manifest.get("selfSha256").is_none());
    assert_eq!(lineage::canonical(manifest).len() as u64, vector["canonicalBytes"].as_u64().unwrap());
    assert_eq!(lineage::canonical(&manifest["files"]).len() as u64, vector["canonicalLengthFiles"].as_u64().unwrap());
    assert_eq!(lineage::self_hash(manifest), vector["selfSha256"].as_str().unwrap());
    let files = manifest["files"].as_array().unwrap();
    assert_eq!(lineage::fileset_sha256(files), vector["filesetSha256"].as_str().unwrap());
    let mut with_self = manifest.clone();
    with_self["selfSha256"] = vector["selfSha256"].clone();
    assert_eq!(lineage::self_hash(&with_self), vector["selfSha256"].as_str().unwrap());
}

#[test]
fn the_engine_vector_holds_the_awkward_paths_of_the_spec() {
    let vector = load("canonical-manifest.json");
    let paths: Vec<&str> = vector["object"]["files"].as_array().unwrap().iter().map(|r| r["path"].as_str().unwrap()).collect();
    for needle in ["é", "中", "\u{1F600}", " ", "\u{1}", "\"", "\\"] {
        assert!(paths.iter().any(|p| p.contains(needle)), "{needle:?}");
    }
}

#[test]
fn the_fixed_vector_is_reproduced_byte_for_byte() {
    let vector = load("generation-manifest.json");
    let manifest = &vector["manifest"];
    let mut body = manifest.clone();
    body.as_object_mut().unwrap().remove("selfSha256");
    let canonical = lineage::canonical(&body);
    let hex: String = canonical.iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(hex, vector["canonicalWithoutSelfSha256Utf8Hex"].as_str().unwrap());
    assert_eq!(sha256_hex(&canonical), vector["canonicalWithoutSelfSha256Sha256"].as_str().unwrap());
    assert_eq!(lineage::fileset_sha256(manifest["files"].as_array().unwrap()), vector["filesetSha256"].as_str().unwrap());
    assert_eq!(lineage::self_hash(manifest), vector["selfSha256"].as_str().unwrap());
    assert_eq!(manifest["filesetSha256"], vector["filesetSha256"]);
    assert_eq!(manifest["selfSha256"], vector["selfSha256"]);
}

#[test]
fn the_vector_holds_the_awkward_paths_of_the_spec() {
    let vector = load("generation-manifest.json");
    let paths: Vec<&str> = vector["manifest"]["files"].as_array().unwrap().iter().map(|r| r["path"].as_str().unwrap()).collect();
    for needle in ["é", "日", "\u{1F600}"] {
        assert!(paths.iter().any(|p| p.contains(needle)), "{needle:?}");
    }
    assert!(paths.iter().any(|p| p.contains('\u{2028}') && p.contains('\u{2029}')));
}

#[test]
fn what_is_escaped_and_what_is_not() {
    let text = String::from_utf8(lineage::canonical(&json!({"b": 1, "a": "q\"\\\t\u{1f}<>&'\u{7f} é"}))).unwrap();
    assert_eq!(text, "{\"a\":\"q\\\"\\\\\\t\\u001f<>&'\u{7f} é\",\"b\":1}");
}

#[test]
fn keys_sort_by_code_point_and_there_is_no_whitespace() {
    assert_eq!(
        lineage::canonical(&json!({"b": [1, {"z": 0, "a": 0}], "a": null, "B": true})),
        br#"{"B":true,"a":null,"b":[1,{"a":0,"z":0}]}"#
    );
}

// test_an_unpaired_surrogate_is_refused_in_a_manifest and test_nan_is_refused: a serde_json::Value cannot hold an
// unpaired surrogate (a Rust str is valid Unicode) or NaN (Number::from_f64 refuses it); the PyO3 layer raises when
// converting a Python object.
#[test]
fn nan_cannot_enter_a_value() {
    assert!(serde_json::Number::from_f64(f64::NAN).is_none());
}

// ---- Manifests ----

struct Gen {
    _temp: tempfile::TempDir,
    folder: PathBuf,
}

fn gen_folder() -> Gen {
    let t = temp();
    let folder = t.path().join("gen");
    write(&folder.join("p.rep").join("db.1.gbf"), &b"data".repeat(10));
    write(&folder.join("p.gpr"), b"gpr");
    write(&folder.join("p.fork.json"), json!({"purpose": "generation", "disposable": false, "state": "candidate"}).to_string().as_bytes());
    Gen { _temp: t, folder }
}

fn problems(folder: &std::path::Path) -> Vec<String> {
    lineage::verify_manifest(folder).unwrap()["problems"].as_array().unwrap().iter().map(|p| p.as_str().unwrap().to_string()).collect()
}

#[test]
fn a_written_manifest_verifies_and_hides_nothing() {
    let g = gen_folder();
    let manifest = lineage::write_manifest(&g.folder, &json!({"cid": "c-1"})).unwrap();
    let mut paths: Vec<&str> = manifest["files"].as_array().unwrap().iter().map(|r| r["path"].as_str().unwrap()).collect();
    paths.sort();
    assert_eq!(paths, ["p.fork.json", "p.gpr", "p.rep/db.1.gbf"]);
    assert_eq!(lineage::verify_manifest(&g.folder).unwrap()["ok"], true);
    assert_eq!(manifest["selfSha256"].as_str().unwrap(), lineage::self_hash(&manifest));
    let read = lineage::read_manifest(&g.folder).unwrap();
    assert_eq!(read["filesetSha256"].as_str().unwrap(), lineage::fileset_sha256(manifest["files"].as_array().unwrap()));
}

#[test]
fn sealing_changes_neither_the_sidecar_hash_nor_the_verification() {
    let g = gen_folder();
    lineage::write_manifest(&g.folder, &json!({"cid": "c-1"})).unwrap();
    write(&g.folder.join("p.fork.json"), json!({"purpose": "generation", "disposable": false, "state": "complete"}).to_string().as_bytes());
    write(&g.folder.join(SEAL_MARKER), b"{}");
    write(&g.folder.join("p.lock"), b"x");
    write(&g.folder.join("projectState"), b"x");
    assert_eq!(lineage::verify_manifest(&g.folder).unwrap()["ok"], true);
}

#[test]
fn a_changed_missing_or_added_file_is_tampering() {
    let g = gen_folder();
    lineage::write_manifest(&g.folder, &json!({"cid": "c-1"})).unwrap();
    write(&g.folder.join("p.rep").join("db.1.gbf"), &b"other".repeat(8));
    assert!(problems(&g.folder).contains(&"changed file p.rep/db.1.gbf".to_string()));
    fs::remove_file(g.folder.join("p.gpr")).unwrap();
    assert!(problems(&g.folder).contains(&"missing file p.gpr".to_string()));
    write(&g.folder.join("extra.bin"), b"x");
    assert!(problems(&g.folder).contains(&"unlisted file extra.bin".to_string()));
}

#[test]
fn an_edited_manifest_fails_its_self_hash() {
    let g = gen_folder();
    lineage::write_manifest(&g.folder, &json!({"cid": "c-1"})).unwrap();
    let path = g.folder.join(MANIFEST);
    let text = String::from_utf8(fs::read(&path).unwrap()).unwrap().replace("\"c-1\"", "\"c-2\"");
    fs::write(&path, text).unwrap();
    assert!(problems(&g.folder).contains(&"selfSha256 does not match".to_string()));
}

#[test]
fn a_folder_without_a_manifest_is_invisible() {
    let g = gen_folder();
    assert_eq!(lineage::verify_manifest(&g.folder).unwrap()["ok"], false);
    assert!(lineage::read_manifest(&g.folder).is_none());
}

#[test]
fn a_newer_manifest_format_is_refused_not_guessed() {
    let g = gen_folder();
    let mut manifest = lineage::write_manifest(&g.folder, &json!({"cid": "c-1"})).unwrap();
    manifest["format"] = json!(99);
    let digest = lineage::self_hash(&manifest);
    manifest["selfSha256"] = json!(digest);
    fs::write(g.folder.join(MANIFEST), lineage::canonical(&manifest)).unwrap();
    assert!(problems(&g.folder).iter().any(|p| p.contains("format_unreadable")));
}

#[test]
fn the_tree_hash_ignores_locks_and_the_manifest_but_not_content() {
    let g = gen_folder();
    let before = lineage::tree_hash(&g.folder).unwrap();
    write(&g.folder.join("p.lock"), b"x");
    lineage::write_manifest(&g.folder, &json!({"cid": "c-1"})).unwrap();
    assert_eq!(lineage::tree_hash(&g.folder).unwrap(), before);
    write(&g.folder.join("p.gpr"), b"changed");
    assert_ne!(lineage::tree_hash(&g.folder).unwrap(), before);
}
