//! PyO3 binding of the evidence ledger and bundle (hy-store `evidence`, `bundle`).
//!
//! One dispatcher, `evidence_call(op, args_json) -> result_json`: the Python installer
//! (`hydralysis._rust_evidence`) turns each public function of `evidence.py` / `evidence_bundle.py` into one op.
//! Errors are raised as the Python module's own classes (`EvidenceIntegrityError`, `BundleError`, `ValueError`).

use crate::{convert, parse, text};
use hy_store::bundle::{self, ExportOptions};
use hy_store::evidence::{self, Claim, Ctx, EvidenceError, Filter, Verify};
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyTuple};
use serde_json::{Map, Value, json};
use std::path::PathBuf;

fn raise(py: Python<'_>, error: EvidenceError) -> PyErr {
    match error {
        EvidenceError::Value(m) => PyValueError::new_err(m),
        EvidenceError::Integrity(e) => build(py, "hydralysis.evidence", "EvidenceIntegrityError", &[e.message], |kw| {
            let _ = kw.set_item("code", e.code);
            let _ = kw.set_item("evidence_id", e.evidence_id);
            let _ = kw.set_item("row_id", e.row_id);
        }),
        EvidenceError::Bundle(e) => {
            let detail = Value::Object(e.detail.clone());
            build(py, "hydralysis.evidence_bundle", "BundleError", &[e.code, e.message], |kw| {
                if let Ok(obj) = py.import("json").and_then(|j| j.call_method1("loads", (text(&detail),))) {
                    if let Ok(map) = obj.cast::<PyDict>() {
                        for (k, v) in map.iter() {
                            let _ = kw.set_item(k, v);
                        }
                    }
                }
            })
        }
        EvidenceError::Sqlite(e) => build(py, "sqlite3", "OperationalError", &[e.to_string()], |_| {}),
        EvidenceError::Io(e) => PyErr::from(e),
        EvidenceError::Core(e) => convert(py, e),
    }
}

fn build(py: Python<'_>, module: &str, class: &str, args: &[String], fill: impl FnOnce(&Bound<'_, PyDict>)) -> PyErr {
    let kwargs = PyDict::new(py);
    fill(&kwargs);
    let positional: Vec<Bound<'_, PyAny>> = args.iter().filter_map(|a| a.clone().into_bound_py_any(py).ok()).collect();
    let made =
        PyTuple::new(py, positional).and_then(|tuple| py.import(module)?.getattr(class)?.call(tuple, Some(&kwargs))).map(PyErr::from_value);
    made.unwrap_or_else(|e| e)
}

fn s(args: &Value, key: &str) -> String {
    args.get(key).filter(|v| !v.is_null()).map(evidence::py_str).unwrap_or_default()
}

fn opt<'a>(args: &'a Value, key: &str) -> Option<&'a Value> {
    args.get(key).filter(|v| !v.is_null())
}

fn path(args: &Value, key: &str) -> PathBuf {
    PathBuf::from(s(args, key))
}

fn optional_string(args: &Value, key: &str) -> Option<String> {
    opt(args, key).map(evidence::py_str)
}

fn ctx(args: &Value) -> Ctx {
    let who = args.get("who").and_then(Value::as_array).and_then(|a| match (a.first(), a.get(1)) {
        (Some(c), Some(h)) => Some((evidence::py_str(c), evidence::py_str(h))),
        _ => None,
    });
    Ctx { who, now: optional_string(args, "now") }
}

fn claim(args: &Value) -> Claim {
    Claim {
        game: s(args, "game"),
        build: s(args, "build"),
        kind: s(args, "kind"),
        name: s(args, "name"),
        note: s(args, "note"),
        source: s(args, "source"),
        address: s(args, "address"),
        prologue: s(args, "prologue"),
        subsystem: s(args, "subsystem"),
        supersedes: opt(args, "supersedes").and_then(Value::as_i64),
        coverage: opt(args, "coverage").cloned(),
        limitations: args.get("limitations").and_then(Value::as_array).cloned().unwrap_or_default(),
        parameters: opt(args, "parameters").cloned(),
        confidence: optional_string(args, "confidence"),
        authority: optional_string(args, "authority"),
        subject_sha256: s(args, "subject_sha256"),
        from_capture: s(args, "from_capture"),
        provenance: opt(args, "provenance").cloned(),
        from_trace: opt(args, "from_trace").cloned(),
    }
}

fn filter(args: &Value) -> Filter {
    Filter {
        game: s(args, "game"),
        subsystem: s(args, "subsystem"),
        address: s(args, "address"),
        build: s(args, "build"),
        include_superseded: args.get("include_superseded").is_some_and(evidence::truthy),
        limit: args.get("limit").and_then(Value::as_i64).unwrap_or(50),
        evidence_id: s(args, "evidence_id"),
    }
}

fn verify_mode(args: &Value) -> Verify {
    match args.get("verify") {
        Some(Value::String(m)) if m == "mark" => Verify::Mark,
        Some(v) if !evidence::truthy(v) => Verify::Off,
        _ => Verify::On,
    }
}

fn strings(args: &Value, key: &str) -> Vec<String> {
    args.get(key).and_then(Value::as_array).map(|a| a.iter().map(evidence::py_str).collect()).unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn run(op: &str, a: &Value) -> Result<Value, EvidenceError> {
    Ok(match op {
        "canonical_json" => json!(evidence::canonical_json(&a["value"])?),
        "canonical_digest" => json!(evidence::canonical_digest(&a["value"])?),
        "compute_evidence_id" => json!(evidence::compute_evidence_id(&a["value"])?),
        "check_limitation_code" => json!(evidence::check_limitation_code(&a["value"])?),
        "normalize_coverage" => evidence::normalize_coverage(opt(a, "value"))?,
        "derived_limitations" => json!(evidence::derived_limitations(&a["value"])),
        "merge_limitations" => {
            json!(evidence::merge_limitations(&a["coverage"], a["limitations"].as_array().map_or(&[][..], |v| v.as_slice()))?)
        }
        "check_from_trace" => evidence::check_from_trace(&a["value"])?,
        "build_content" => evidence::build_content(&claim(a), &strings(a, "evidence_links"))?,
        "verify_content" => {
            evidence::verify_content(&a["content"], &a["evidence_id"])?;
            Value::Null
        }
        "check_content" => {
            evidence::check_content(&a["content"], &a["evidence_id"])?;
            Value::Null
        }
        "check_meta" => evidence::check_meta(opt(a, "value"))?,
        "add_claim" => json!(evidence::add_claim(&path(a, "path"), &claim(a), &ctx(a))?),
        "query" => Value::Array(evidence::query(&path(a, "path"), &filter(a), verify_mode(a))?),
        "get_claim" => evidence::get_claim(&path(a, "path"), &s(a, "evidence_id"))?.unwrap_or(Value::Null),
        "verify_ledger" => evidence::verify_ledger(&path(a, "path"))?,
        "records_for_bundle" => {
            Value::Array(evidence::records_for_bundle(&path(a, "path"), &s(a, "game"), &s(a, "subsystem"), &s(a, "build"))?)
        }
        "import_records" => evidence::import_records(&path(a, "path"), a["records"].as_array().map_or(&[][..], |v| v.as_slice()), &ctx(a))?,
        "list_claims" => {
            json!(evidence::list_claims(&path(a, "path"), &s(a, "game"), a.get("limit").and_then(Value::as_i64).unwrap_or(50), &filter(a))?)
        }
        "export" => evidence::export(&path(a, "path"), &path(a, "out"), &s(a, "game"), &s(a, "subsystem"))?,
        "guard_payload" => {
            bundle::guard_payload(&a["value"], &s(a, "where"))?;
            Value::Null
        }
        "check_pin" => bundle::check_pin(&a["pin"], &s(a, "session"))?,
        "stub_pin" => bundle::stub_pin(&s(a, "session"), &a["revision"]),
        "export_bundle" => bundle::export_bundle(
            &path(a, "db_path"),
            &path(a, "out"),
            &ExportOptions {
                game: s(a, "game"),
                subsystem: s(a, "subsystem"),
                build: s(a, "build"),
                captures_dir: opt(a, "captures_dir").map(|_| path(a, "captures_dir")),
                traces_dir: opt(a, "traces_dir").map(|_| path(a, "traces_dir")),
                overwrite: a.get("overwrite").is_some_and(evidence::truthy),
                ctx: ctx(a),
                environment: opt(a, "environment").cloned(),
            },
        )?,
        "load_bundle" => {
            let loaded = bundle::load_bundle(&path(a, "folder"))?;
            let mut value = loaded.to_value();
            let blobs: Map<String, Value> = loaded.capture_blobs.iter().map(|(k, v)| (k.clone(), json!(hex(v)))).collect();
            value["capture_blobs"] = Value::Object(blobs);
            value
        }
        "verify_bundle" => bundle::verify_bundle(&path(a, "folder"))?,
        "compare_bundles" => bundle::compare_bundles(&path(a, "left"), &path(a, "right"))?,
        "import_bundle" => bundle::import_bundle(&path(a, "folder"), &path(a, "db_path"), &ctx(a))?,
        "handle" => {
            let resolved = path(a, "resolved_db");
            json!(bundle::handle(&a["request"], &move |_| resolved.clone(), &ctx(a)))
        }
        other => return Err(EvidenceError::value(format!("unknown evidence op {other}"))),
    })
}

#[pyfunction]
fn evidence_call(py: Python<'_>, op: &str, args: &str) -> PyResult<String> {
    let args = parse(args)?;
    let op = op.to_string();
    match py.detach(|| run(&op, &args)) {
        Ok(value) => Ok(text(&value)),
        Err(error) => Err(raise(py, error)),
    }
}

pub fn register(module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(evidence_call, module)?)?;
    Ok(())
}
