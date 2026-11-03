//! Port of tests/test_evidence_parity.py: parity of evidence v2 with the REA reference checkout.
//!
//! The reference is read, never written. With no checkout (CI) or no node the tests return early and print why
//! (Rust has no skip status). Set HYDRALYSIS_REA_REFERENCE to another path.

mod evsupport;

use hy_store::{bundle, evidence};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::process::{Command, Stdio};

const REVISION: &str = "f196ebf80665107aedc16892af25a1e1f9f26f43";

fn reference() -> PathBuf {
    std::env::var_os("HYDRALYSIS_REA_REFERENCE")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"D:\Projects\Hydra\_data\ref-repos\rusticre-rea-reference"))
}

fn reference_revision(root: &std::path::Path) -> String {
    let Ok(head) = std::fs::read_to_string(root.join(".git").join("HEAD")) else { return String::new() };
    let head = head.trim();
    if let Some(reference) = head.strip_prefix("ref:") {
        return std::fs::read_to_string(root.join(".git").join(reference.trim())).map(|s| s.trim().to_string()).unwrap_or_default();
    }
    head.to_string()
}

/// `Some(reason)` when the cases cannot run here.
fn skip_reason() -> Option<String> {
    let root = reference();
    if !root.is_dir() {
        return Some(format!("no reference checkout at {}", root.display()));
    }
    let found = reference_revision(&root);
    if !found.is_empty() && found != REVISION {
        return Some(format!(
            "the reference checkout is at {}, these cases were written against {}",
            &found[..7.min(found.len())],
            &REVISION[..7]
        ));
    }
    None
}

fn node_path() -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).map(|d| d.join(if cfg!(windows) { "node.exe" } else { "node" })).find(|p| p.is_file())
}

macro_rules! guard {
    () => {
        if let Some(reason) = skip_reason() {
            eprintln!("skipped: {reason}");
            return;
        }
    };
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(reference().join(relative)).expect("reference file")
}

/// `re.findall(r'"(<class>+)"', text)` for a lowercase-and-dash class.
fn quoted_words(text: &str, allow_dash: bool) -> Vec<String> {
    let mut out = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find('"') {
        let after = &rest[start + 1..];
        let Some(end) = after.find('"') else { break };
        let word = &after[..end];
        if !word.is_empty() && word.chars().all(|c| c.is_ascii_lowercase() || (allow_dash && c == '-')) {
            out.push(word.to_string());
            rest = &after[end + 1..];
        } else {
            rest = after;
        }
    }
    out
}

/// `^<indent>([a-z_]+):` over the lines of a block.
fn field_names(block: &str, indent: usize) -> std::collections::BTreeSet<String> {
    block
        .lines()
        .filter_map(|line| {
            let body = line.strip_prefix(&" ".repeat(indent))?;
            let name: String = body.chars().take_while(|c| c.is_ascii_lowercase() || *c == '_').collect();
            (!name.is_empty() && body[name.len()..].starts_with(':')).then_some(name)
        })
        .collect()
}

fn schema_fields() -> std::collections::BTreeSet<String> {
    let text = read("src/domain/evidence.ts");
    let start = text.find("const evidenceBaseSchema").unwrap();
    let block = &text[start..];
    let block = &block[..block.find(".strict();").unwrap()];
    field_names(block, 4)
}

#[test]
fn every_reference_field_has_a_counterpart_or_a_stated_gap() {
    guard!();
    let fields = schema_fields();
    assert!(fields.len() >= 16, "the schema parse found too few fields: {fields:?}");
    assert!(fields.contains("evidence_id"));
    let mapped: std::collections::BTreeSet<String> = evidence::REA_FIELD_MAP.iter().map(|(k, _)| k.to_string()).collect();
    let gaps: std::collections::BTreeSet<String> = evidence::REA_FIELD_GAPS.iter().map(|(k, _)| k.to_string()).collect();
    let known: std::collections::BTreeSet<String> = mapped.union(&gaps).cloned().collect();
    assert!(fields.difference(&known).next().is_none(), "reference fields with neither a column nor a documented gap");
    assert!(known.difference(&fields).next().is_none(), "a mapped field the reference no longer has");
    assert!(mapped.intersection(&gaps).next().is_none());
    for (field, counterpart) in evidence::REA_FIELD_MAP {
        for column in counterpart.split(',') {
            assert!(evidence::FIELDS.contains(&column), "{field} maps to {column}, which is not a column");
        }
    }
    for (field, reason) in evidence::REA_FIELD_GAPS {
        assert!(!reason.trim().is_empty(), "{field}");
    }
}

#[test]
fn the_vocabularies_are_the_references() {
    guard!();
    let text = read("src/domain/evidence.ts");
    let authority = &text[text.find("evidenceAuthoritySchema = z.enum([").unwrap()..];
    let authority = &authority[..authority.find(']').unwrap()];
    assert_eq!(quoted_words(authority, true), evidence::AUTHORITIES);
    let marker = "confidence: z.enum([";
    let confidence = &text[text.find(marker).unwrap() + marker.len()..];
    let confidence = &confidence[..confidence.find(']').unwrap()];
    assert_eq!(quoted_words(confidence, false), evidence::CONFIDENCES);
    let coverage = read("src/domain/relationshipCoverage.ts");
    let mut states = std::collections::BTreeSet::new();
    let mut rest = coverage.as_str();
    while let Some(i) = rest.find("status: z.literal(\"") {
        let after = &rest[i + "status: z.literal(\"".len()..];
        let end = after.find('"').unwrap();
        states.insert(after[..end].to_string());
        rest = &after[end..];
    }
    assert_eq!(states, evidence::COVERAGE_STATES.iter().map(|s| s.to_string()).collect());
    assert!(text.contains("prefixedDigestSchema(\"ev\")"));
    assert!(text.contains("`ev_${")); // the id is `ev_` + the digest, as here
}

#[test]
fn the_bundle_fields_have_a_counterpart_or_a_stated_gap() {
    guard!();
    let text = read("src/domain/evidenceBundle.ts");
    let block = &text[text.find("export const evidenceBundleSchema").unwrap()..];
    let block = &block[..block.find("});").unwrap()];
    let fields = field_names(block, 2);
    let expected: std::collections::BTreeSet<String> =
        ["artifacts", "providers", "environments", "scenarios", "captures", "unknowns", "records"].iter().map(|s| s.to_string()).collect();
    assert_eq!(fields, expected);
    let mapped: std::collections::BTreeSet<String> =
        bundle::REA_BUNDLE_MAP.iter().chain(bundle::REA_BUNDLE_GAPS.iter()).map(|(k, _)| k.to_string()).collect();
    assert_eq!(fields, mapped);
    assert!(text.contains("compareUnicodeCodePoints(left.evidence_id, right.evidence_id)")); // records sort by id
    for (_, target) in bundle::REA_BUNDLE_MAP {
        assert!(!target.trim().is_empty());
    }
}

#[test]
fn the_reference_commands_exist_for_every_operation_here() {
    guard!();
    let commands = read("src/cliEvidenceCommands.ts");
    for operation in ["evidenceImport", "evidenceExport", "compare"] {
        assert!(commands.contains(&format!("CLI_COMMANDS.{operation}")), "{operation}");
    }
    // The Python half of this case (`python -m hydralysis.evidence_bundle --help` lists export, verify, compare, import)
    // stays a Python test: the command line is not part of the Rust library.
}

// ---- IdentityVectors (need node) ---------------------------------------------------------------------------------

fn node(source: &str) -> Option<String> {
    let exe = node_path()?;
    let dir = evsupport::work();
    let script = dir.path().join("probe.mjs");
    std::fs::write(&script, source).unwrap();
    let done = Command::new(exe).arg(&script).stdin(Stdio::null()).output().expect("node");
    assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
    Some(String::from_utf8_lossy(&done.stdout).into_owned())
}

fn file_uri(path: &std::path::Path) -> String {
    format!("file:///{}", path.to_string_lossy().replace('\\', "/"))
}

fn reference_digests(values: &Value) -> Option<Vec<String>> {
    let dir = evsupport::work();
    let data = dir.path().join("values.json");
    std::fs::write(&data, values.to_string()).unwrap();
    let module = file_uri(&reference().join("src").join("domain").join("canonicalDigest.ts"));
    let source = format!(
        "import {{ digestCanonicalValue }} from \"{module}\";\nimport {{ readFileSync }} from \"node:fs\";\nconst values = JSON.parse(readFileSync({}, \"utf8\"));\nprocess.stdout.write(JSON.stringify(values.map((value) => digestCanonicalValue(value))));",
        json!(data.to_string_lossy())
    );
    let out = node(&source)?;
    serde_json::from_str(&out).ok()
}

#[test]
fn the_canonical_digest_equals_the_references_on_hard_values() {
    guard!();
    if node_path().is_none() {
        eprintln!("skipped: node is not installed");
        return;
    }
    let mut claim = evidence::Claim::new("cp", "2.5", "function", "ForceMoveTo", "moves the vehicle", "decompile line 12");
    claim.address = "rva:0x2e3270".into();
    claim.subsystem = "vehicles".into();
    let pinned = evidence::build_content(&claim, &[]).unwrap();
    let control: String = (0u8..32).map(char::from).collect::<String>() + "\u{7f}\"\\/";
    let values = json!([
        pinned,
        {"b": [1, "x\u{2028}\u{1}\u{1F600}", null, true, false, -7, 0], "a": {"\u{ffee}": 1, "\u{10000}": 2}},
        {"": "", "z": [], "y": {}, "control": control},
        {"Z": 1, "a": 2, "_": 3, "\u{e9}": 4, "e": 5, "\u{301}": 6, "10": 7, "9": 8},
        [[], [[]], {"nested": {"deeper": {"deepest": [1, 2, {"k": "v"}]}}}],
        "plain string", null, 12345678901234u64, 0
    ]);
    let mine: Vec<String> = values.as_array().unwrap().iter().map(|v| evidence::canonical_digest(v).unwrap()).collect();
    assert_eq!(Some(mine.clone()), reference_digests(&values));
    assert_eq!(format!("ev_{}", mine[0]), "ev_429247fbd78b7252e2ccd84c4e669781dbe9d812f958e3865d48b43f6ed467ed");
}

fn legacy_record() -> Option<Value> {
    let module = file_uri(&reference().join("src").join("domain").join("evidenceLegacy.fixture.ts"));
    let out = node(&format!(
        "import {{ PRE_66_NULL_COVERAGE_EVIDENCE as record }} from \"{module}\";\nprocess.stdout.write(JSON.stringify(record));"
    ))?;
    serde_json::from_str(&out).ok()
}

/// `evidenceSemanticContent` of src/domain/evidence.ts, written out; `legacy` omits relationship_coverage.
fn reference_content(record: &Value, legacy: bool) -> Value {
    let subject = &record["subject"];
    let mut content = json!({
        "subject": if subject.is_null() { Value::Null } else { json!({"digest": subject["digest"], "format": subject["format"], "architecture": subject["architecture"]}) },
        "provider": record["provider"], "analysis_profile": record["analysis_profile"], "predicate_type": record["predicate_type"],
        "operation": record["operation"], "parameters": record["parameters"], "raw_result": record["raw_result"],
        "normalized_result": record["normalized_result"], "confidence": record["confidence"], "authority": record["authority"],
        "environment": record["environment"], "limitations": record["limitations"], "relationship_coverage": record["relationship_coverage"],
        "locations": record["locations"], "evidence_links": record["evidence_links"],
    });
    if legacy {
        content.as_object_mut().unwrap().remove("relationship_coverage");
    }
    content
}

#[test]
fn the_references_published_identity_is_reproduced() {
    guard!();
    let Some(record) = legacy_record() else {
        eprintln!("skipped: node is not installed");
        return;
    };
    let mut keys: std::collections::BTreeSet<String> = record.as_object().unwrap().keys().cloned().collect();
    let mut fields = schema_fields();
    fields.remove("caller_input_path"); // that one is optional
    assert_eq!(std::mem::take(&mut keys), fields);
    let expected = record["evidence_id"].clone();
    assert!(evidence::is_evidence_id(&expected));
    let legacy = format!("ev_{}", evidence::canonical_digest(&reference_content(&record, true)).unwrap());
    assert_eq!(json!(legacy), expected);
    // the current rule commits the explicit null, so the same record has another id today
    let current = format!("ev_{}", evidence::canonical_digest(&reference_content(&record, false)).unwrap());
    assert_ne!(json!(current), expected);
    let theirs = reference_digests(&json!([reference_content(&record, false)])).unwrap();
    assert_eq!(current, format!("ev_{}", theirs[0]));
}

#[test]
fn a_flipped_byte_in_the_reference_vector_is_rejected_the_same_way() {
    guard!();
    let Some(mut record) = legacy_record() else {
        eprintln!("skipped: node is not installed");
        return;
    };
    record["normalized_result"] = json!({"observed": false});
    let tampered = format!("ev_{}", evidence::canonical_digest(&reference_content(&record, true)).unwrap());
    assert_ne!(json!(tampered), record["evidence_id"]);
    // and here: the same flip in a stored claim is refused on read
    let claim = evidence::Claim::new("g", "b", "k", "n", "a", "s");
    let content = evidence::build_content(&claim, &[]).unwrap();
    let identifier = json!(evidence::compute_evidence_id(&content).unwrap());
    evidence::verify_content(&content, &identifier).unwrap();
    let mut flipped = content.clone();
    flipped["note"] = json!("b");
    assert!(evidence::verify_content(&flipped, &identifier).is_err());
}
