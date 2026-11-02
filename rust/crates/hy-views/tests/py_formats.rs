//! Byte/format compatibility with the Python implementation: files written by one side are read by the other.
//! Skipped when no Python is found (set `HYDRALYSIS_PYTHON` or install C:\Python315).

use std::path::Path;
use std::process::Command;

use hy_views::layout::{Settings, done_path, pending_path};
use hy_views::queue::{self, NoJobs};
use hy_views::records::{self, HolderState};
use serde_json::{Value, json};

fn python() -> Option<String> {
    [
        std::env::var("HYDRALYSIS_PYTHON").unwrap_or_default(),
        r"C:\Python315\python.exe".into(),
    ]
    .into_iter()
    .find(|p| !p.is_empty() && Path::new(p).is_file())
}

fn src() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src")
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
        .trim_start_matches(r"\\?\")
        .to_string()
}

fn run_py(py: &str, code: &str, args: &[&str]) -> String {
    let out = Command::new(py)
        .args(["-c", code])
        .args(args)
        .env("PYTHONPATH", src())
        .env("PYTHONIOENCODING", "utf-8")
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

const L: &str = "L-0000abcd";

#[test]
fn python_view_record_and_changeset_are_read_by_rust() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new().prefix("hv").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = dir.path().to_str().unwrap();
    let code = r#"
import sys, json
from hydralysis import views, durable, lineage
s = {"root": sys.argv[1]}
who = views.identify({"as": "Alice@Host"})
sel = {"key": "k1", "name": "prog", "lineage": {"id": "L-0000abcd", "generation": 2}}
rec = views.claim(s, sel, who, "L-0000abcd")
body = {"format": 1, "csid": "c-0000000000000aaa", "view": who["name"], "records": [{"id": "e1"}], "ids": ["e1"], "sealed_at": "t", "agent": "a"}
durable.write_sealed(views.pending_path(s, "L-0000abcd", "c-0000000000000aaa"), body)
views.write_done(s, "L-0000abcd", "c-0000000000000aaa", {"outcome": "applied", "generation": 4, "build_ms": 7})
print(json.dumps({"name": who["name"], "boot": views.BOOT_ID}))
"#;
    let info: Value = serde_json::from_str(&run_py(&py, code, &[root])).unwrap();
    let s: Settings = json!({"root": root}).as_object().unwrap().clone();
    let name = info["name"].as_str().unwrap();
    let rec = records::read_record(&s, L, name).expect("record readable");
    assert_eq!(rec["format"], 1);
    assert_eq!(rec["agent"], "Alice@Host");
    assert_eq!(rec["id_kind"], "explicit");
    assert_eq!(rec["boot_id"], info["boot"]);
    assert_eq!(rec["base"], json!({"lineage": L, "generation": 2}));
    // the Python process has exited: no holder is alive
    assert_eq!(records::holder_state(&rec, None), HolderState::Orphaned);
    assert_eq!(records::list_records(&s, L).len(), 1);
    assert_eq!(records::view_name("Alice@Host"), name);

    let cs = queue::read_changeset(&s, L, "c-0000000000000aaa").unwrap();
    assert_eq!(cs["view"], name);
    let done = queue::read_done(&s, L, "c-0000000000000aaa")
        .unwrap()
        .unwrap();
    assert_eq!(
        (done["generation"].as_i64(), done["build_ms"].as_i64()),
        (Some(4), Some(7))
    );
    assert!(queue::outstanding(&s, L).unwrap().is_empty());
    assert!(done_path(&s, L, "c-0000000000000aaa").unwrap().is_file());
}

#[test]
fn rust_written_records_are_byte_identical_and_read_by_python() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new().prefix("hv").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = dir.path().to_str().unwrap();
    let s: Settings = json!({"root": root}).as_object().unwrap().clone();
    let body = json!({"format": 1, "csid": "c-0000000000000bbb", "lineage": L, "view": "bob", "ids": ["e1", "\u{e9}"], "records": [{"id": "e1", "after": 1.5}],
                      "sealed_at": "2026-01-01T00:00:00Z", "agent": {"x": null}});
    let path = pending_path(&s, L, "c-0000000000000bbb").unwrap();
    let written = hy_core::sealed::write_sealed(&path, &body, Some(2), None, None).unwrap();
    let rec = json!({"outcome": "conflict", "generation": null})
        .as_object()
        .unwrap()
        .clone();
    queue::write_done(&s, L, "c-0000000000000bbb", &rec).unwrap();

    let code = r#"
import sys, json
from hydralysis import views, durable
s = {"root": sys.argv[1]}
body = json.loads(sys.argv[2])
same = durable.dumps_sealed(body) == open(sys.argv[3], "rb").read()
cs = views.read_changeset(s, "L-0000abcd", "c-0000000000000bbb")
done = views.read_done(s, "L-0000abcd", "c-0000000000000bbb")
print(json.dumps({"same": same, "view": cs["view"], "outcome": done["outcome"], "gen": done["generation"],
                  "queue": views.outstanding(s, "L-0000abcd"), "info": views.pending_info(s, "L-0000abcd", "c-0000000000000bbb")}))
"#;
    let out: Value = serde_json::from_str(&run_py(
        &py,
        code,
        &[root, &body.to_string(), path.to_str().unwrap()],
    ))
    .unwrap();
    assert_eq!(
        out["same"],
        true,
        "Rust sealed bytes differ from durable.dumps_sealed ({} bytes)",
        written.len()
    );
    assert_eq!(out["view"], "bob");
    assert_eq!(out["outcome"], "conflict");
    assert_eq!(out["gen"], Value::Null);
    assert_eq!(out["queue"], json!([]));
    assert_eq!(
        out["info"],
        queue::pending_info(&s, L, "c-0000000000000bbb", None, &NoJobs).unwrap()
    );
}
