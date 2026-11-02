//! Differential test: the Python and Rust evidence implementations given the same inputs must produce the same
//! ledger rows, the same bundle bytes, the same Markdown / JSONL / listing text, and each must read what the other
//! wrote. The Python half is `tests/diff/gen_evidence.py` run with `HY_PYTHON` (default `C:\Python315\python.exe`)
//! and `PYTHONPATH=<repo>/src`. With no Python the test returns early and says so.

mod evsupport;

use evsupport::*;
use hy_store::bundle::{self, ExportOptions};
use hy_store::evidence::{self, Claim, Filter, Verify};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn repo() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..").canonicalize().expect("repo root");
    PathBuf::from(root.to_string_lossy().trim_start_matches(r"\?\"))
}

fn python() -> Option<PathBuf> {
    let candidate = std::env::var_os("HY_PYTHON").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\Python315\python.exe"));
    candidate.is_file().then_some(candidate)
}

fn run_python(exe: &Path, args: &[&Path], mode: &str) {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/diff/gen_evidence.py");
    let done = Command::new(exe)
        .arg(&script)
        .arg(mode)
        .args(args)
        .env("PYTHONPATH", repo().join("src"))
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::null())
        .output()
        .expect("python");
    assert!(done.status.success(), "python {mode} failed:\n{}", String::from_utf8_lossy(&done.stderr));
}

fn str_field(v: &Value, key: &str) -> String {
    v.get(key).and_then(Value::as_str).unwrap_or_default().to_string()
}

fn claim_of(spec: &Value) -> Claim {
    let mut claim = Claim::new(
        &str_field(spec, "game"),
        &str_field(spec, "build"),
        &str_field(spec, "kind"),
        &str_field(spec, "name"),
        &str_field(spec, "note"),
        &str_field(spec, "source"),
    );
    claim.address = str_field(spec, "address");
    claim.prologue = str_field(spec, "prologue");
    claim.subsystem = str_field(spec, "subsystem");
    claim.supersedes = spec.get("supersedes").and_then(Value::as_i64);
    claim.coverage = spec.get("coverage").cloned();
    claim.limitations = spec.get("limitations").and_then(Value::as_array).cloned().unwrap_or_default();
    claim.parameters = spec.get("parameters").cloned();
    claim.confidence = spec.get("confidence").and_then(Value::as_str).map(String::from);
    claim.authority = spec.get("authority").and_then(Value::as_str).map(String::from);
    claim.subject_sha256 = str_field(spec, "subject_sha256");
    claim.from_capture = str_field(spec, "from_capture");
    claim.provenance = spec.get("provenance").cloned();
    claim.from_trace = spec.get("from_trace").cloned();
    claim
}

fn files_of(folder: &Path) -> std::collections::BTreeMap<String, Vec<u8>> {
    fn walk(base: &Path, dir: &Path, out: &mut std::collections::BTreeMap<String, Vec<u8>>) {
        for entry in std::fs::read_dir(dir).unwrap().flatten() {
            let p = entry.path();
            if p.is_dir() {
                walk(base, &p, out);
            } else {
                out.insert(p.strip_prefix(base).unwrap().to_string_lossy().replace('\\', "/"), std::fs::read(&p).unwrap());
            }
        }
    }
    let mut out = Default::default();
    walk(folder, folder, &mut out);
    out
}

fn all_rows(db: &Path) -> Vec<evidence::Row> {
    let filter = Filter { include_superseded: true, limit: 1_000_000, ..Filter::default() };
    let mut rows = evidence::select_rows(db, &filter).unwrap();
    rows.reverse();
    rows
}

#[test]
fn python_and_rust_agree_on_ledger_bundle_and_text() {
    let Some(exe) = python() else {
        eprintln!("skipped: no Python at HY_PYTHON / C:\\Python315\\python.exe");
        return;
    };
    let dir = work();
    let out = dir.path();
    let spec_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/diff/claims.json");
    run_python(&exe, &[out, &spec_path], "gen");

    // ---- the same claims through Rust
    let spec: Vec<Value> = serde_json::from_slice(&std::fs::read(&spec_path).unwrap()).unwrap();
    let diff_ctx = evidence::Ctx { who: Some(("rusticre:1".into(), "diff-harness".into())), now: Some(WHEN.into()) };
    let rust_db = out.join("rust.db");
    let mut messages: Vec<String> = spec.iter().map(|s| evidence::add_claim(&rust_db, &claim_of(s), &diff_ctx).unwrap()).collect();
    messages.push(evidence::add_claim(&rust_db, &claim_of(&spec[0]), &diff_ctx).unwrap());
    assert_eq!(messages.join("\n"), std::fs::read_to_string(out.join("py-messages.txt")).unwrap(), "add_claim messages");

    // ---- ledger rows: every column, as text
    let (py_rows, rust_rows) = (all_rows(&out.join("py.db")), all_rows(&rust_db));
    assert_eq!(py_rows.len(), spec.len());
    assert_eq!(py_rows, rust_rows, "ledger rows differ");

    // ---- bundle bytes
    let environment = json!({"hydralysis": bundle::HYDRALYSIS_VERSION, "python": "3.15.0", "platform": if cfg!(windows) { "win32" } else { "linux" }, "exported_at": WHEN, "exported_by": "diff-harness"});
    let options = ExportOptions {
        captures_dir: Some(out.join("captures")),
        traces_dir: Some(out.join("traces")),
        ctx: diff_ctx.clone(),
        environment: Some(environment),
        ..ExportOptions::default()
    };
    let result = bundle::export_bundle(&rust_db, &out.join("rust-bundle"), &options).unwrap();
    let py_result: Value = serde_json::from_slice(&std::fs::read(out.join("py-export.json")).unwrap()).unwrap();
    for key in ["bundle_id", "records", "captures", "missing_captures", "limitations", "traces", "unreproducible_traces"] {
        assert_eq!(result[key], py_result[key], "export result {key}");
    }
    let (py_files, rust_files) = (files_of(&out.join("py-bundle")), files_of(&out.join("rust-bundle")));
    assert_eq!(py_files.keys().collect::<Vec<_>>(), rust_files.keys().collect::<Vec<_>>());
    for (name, bytes) in &py_files {
        assert_eq!(String::from_utf8_lossy(bytes), String::from_utf8_lossy(&rust_files[name]), "bundle file {name}");
    }

    // ---- Markdown, JSONL, listing
    evidence::export(&rust_db, &out.join("rust.md"), "cp", "").unwrap();
    assert_eq!(std::fs::read(out.join("py.md")).unwrap(), std::fs::read(out.join("rust.md")).unwrap(), "markdown export");
    assert_eq!(std::fs::read(out.join("py.jsonl")).unwrap(), std::fs::read(out.join("rust.jsonl")).unwrap(), "jsonl export");
    let listing = evidence::list_claims(&rust_db, "cp", 50, &Filter { include_superseded: true, ..Filter::default() }).unwrap();
    assert_eq!(listing, std::fs::read_to_string(out.join("py-list.txt")).unwrap(), "list_claims");

    // ---- Rust reads what Python wrote
    let py_verify: Value = serde_json::from_slice(&std::fs::read(out.join("py-verify.json")).unwrap()).unwrap();
    assert_eq!(bundle::verify_bundle(&out.join("py-bundle")).unwrap(), py_verify);
    assert_eq!(py_verify["ok"], true);
    let imported = out.join("imported.db");
    let summary = bundle::import_bundle(&out.join("py-bundle"), &imported, &diff_ctx).unwrap();
    assert_eq!(summary["added"], spec.len());
    assert_eq!(evidence::verify_ledger(&imported).unwrap(), json!({"checked": spec.len(), "failed": []}));
    assert_eq!(
        evidence::records_for_bundle(&imported, "", "", "").unwrap(),
        evidence::records_for_bundle(&out.join("py.db"), "", "", "").unwrap()
    );

    // ---- Python reads what Rust wrote
    run_python(&exe, &[out], "check");
    let check: Value = serde_json::from_slice(&std::fs::read(out.join("py-check.json")).unwrap()).unwrap();
    let rust_query =
        evidence::query(&rust_db, &Filter { include_superseded: true, limit: 1_000_000, ..Filter::default() }, Verify::On).unwrap();
    assert_eq!(check["rows"], Value::Array(rust_query));
    assert_eq!(check["ledger"], json!({"checked": spec.len(), "failed": []}));
    assert_eq!(check["bundle"], bundle::verify_bundle(&out.join("rust-bundle")).unwrap());
    assert_eq!(check["bundle"]["ok"], true);
    assert_eq!(check["compare"]["status"], "equal");
    assert_eq!(check["list"], json!(listing));
}

#[test]
fn rust_and_python_agree_on_the_error_messages_of_refused_claims() {
    let Some(exe) = python() else {
        eprintln!("skipped: no Python");
        return;
    };
    let cases: Vec<(&str, Claim)> = vec![
        ("empty name", Claim::new("cp", "1", "k", " ", "n", "s")),
        ("float", {
            let mut c = Claim::new("cp", "1", "k", "n", "n", "s");
            c.parameters = Some(json!({"x": 1.5}));
            c
        }),
        ("big int", {
            let mut c = Claim::new("cp", "1", "k", "n", "n", "s");
            c.parameters = Some(json!({"x": 1u64 << 60}));
            c
        }),
        ("bad confidence", {
            let mut c = Claim::new("cp", "1", "k", "n", "n", "s");
            c.confidence = Some("sure".into());
            c
        }),
        ("complete + bounding", {
            let mut c = Claim::new("cp", "1", "k", "n", "n", "s");
            c.coverage = Some(json!("complete"));
            c.limitations = vec![json!("sampled")];
            c
        }),
        ("unknown code", {
            let mut c = Claim::new("cp", "1", "k", "n", "n", "s");
            c.limitations = vec![json!("nope")];
            c
        }),
        ("bad trace", {
            let mut c = Claim::new("cp", "1", "k", "n", "n", "s");
            c.from_trace = Some(json!({"session": "s", "events": [], "revision": 1}));
            c
        }),
    ];
    let dir = work();
    let script = dir.path().join("refuse.py");
    std::fs::write(
        &script,
        r#"
import json, sys
from hydralysis import evidence
out = {}
for label, spec in json.loads(sys.stdin.read()).items():
    try:
        evidence.build_content(**spec)
        out[label] = None
    except ValueError as exc:
        out[label] = str(exc)
print(json.dumps(out))
"#,
    )
    .unwrap();
    let specs: serde_json::Map<String, Value> = cases
        .iter()
        .map(|(label, c)| {
            let mut spec = json!({"game": c.game, "build": c.build, "kind": c.kind, "name": c.name, "note": c.note, "source": c.source});
            for (key, value) in
                [("parameters", c.parameters.clone()), ("coverage", c.coverage.clone()), ("from_trace", c.from_trace.clone())]
            {
                if let Some(v) = value {
                    spec[key] = v;
                }
            }
            if let Some(v) = &c.confidence {
                spec["confidence"] = json!(v);
            }
            if !c.limitations.is_empty() {
                spec["limitations"] = json!(c.limitations);
            }
            (label.to_string(), spec)
        })
        .collect();
    use std::io::Write;
    let mut child = Command::new(&exe)
        .arg(&script)
        .env("PYTHONPATH", repo().join("src"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(Value::Object(specs).to_string().as_bytes()).unwrap();
    let done = child.wait_with_output().unwrap();
    assert!(done.status.success(), "{}", String::from_utf8_lossy(&done.stderr));
    let python_says: Value = serde_json::from_slice(&done.stdout).unwrap();
    for (label, claim) in &cases {
        let mine = evidence::build_content(claim, &[]).err().map(|e| e.to_string());
        let theirs = python_says[*label].as_str().map(String::from);
        // The big integer parses as a float in Rust only beyond 64 bits; 2**60 fits, so the messages must match.
        assert_eq!(mine, theirs, "{label}");
    }
}
