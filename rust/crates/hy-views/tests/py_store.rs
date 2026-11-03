//! The view store and the revision rules against the Python implementation: stores written by one side are loaded by the
//! other and must give the same value; pure rules are compared on generated inputs. Skipped when no Python is found.

use std::path::Path;
use std::process::{Command, Stdio};

use hy_views::layout::Settings;
use hy_views::revisions;
use hy_views::store;
use serde_json::{Map, Value, json};

fn python() -> Option<String> {
    [std::env::var("HYDRALYSIS_PYTHON").unwrap_or_default(), r"C:\Python315\python.exe".into()]
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

fn run_py(py: &str, code: &str, stdin: &str, args: &[&str]) -> String {
    use std::io::Write;
    let mut child = Command::new(py)
        .args(["-c", code])
        .args(args)
        .env("PYTHONPATH", src())
        .env("PYTHONIOENCODING", "utf-8")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(stdin.as_bytes()).unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "python failed: {}", String::from_utf8_lossy(&out.stderr));
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn target() -> store::Target {
    json!({"key": "k1", "sha256": "ab".repeat(32), "name": "prog", "lineage": {"id": "L-0000abcd", "generation": 2, "origin_key": "k1"}})
        .as_object()
        .unwrap()
        .clone()
}

fn rec(n: usize) -> Value {
    let id = format!("{n:032x}");
    json!({"id": id, "address": format!("0x{:x}", 0x401000 + n * 16), "options": {"kind": "rename", "source": "test", "name": format!("n\u{e9}{n}")},
           "seq": n, "by": {"client": "c", "harness": "h"}, "at": 1.5 + n as f64,
           "effects": [{"subject": format!("address:0x{:x}", 0x401000 + n * 16), "field": "name", "before": "a", "after": format!("n\u{e9}{n}")}]})
}

const PY_LOAD: &str = r#"
import sys, json
from hydralysis import workcopy
s = {"root": sys.argv[1]}
t = json.loads(sys.argv[2])
print(json.dumps(workcopy.load_store(s, t)))
"#;

#[test]
fn rust_saves_python_loads_and_the_reverse() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new().prefix("hst").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root = dir.path().to_str().unwrap();
    let s: Settings = json!({"root": root}).as_object().unwrap().clone();
    let t = target();
    let t_json = serde_json::to_string(&t).unwrap();

    // Rust writes three mutations (snapshot, then log rows); Python must load exactly what Rust loads.
    let mut st = store::load_store(&s, &t).unwrap();
    for n in 1..=3usize {
        let mut edits = st["edits"].as_array().cloned().unwrap();
        edits.push(rec(n));
        st.insert("edits".into(), json!(edits));
        st.insert("revision".into(), json!(n));
        let journal = revisions::append(
            &st["journal"].as_array().cloned().unwrap(),
            revisions::journal_entry(n as i64, "edit", &["address:0x1".into()], Some(&json!({"client": "c"})), 2.5),
        );
        st.insert("journal".into(), json!(journal));
        store::save_store(&s, &t, &st).unwrap();
    }
    st.insert("commits".into(), json!([{"cid": "c-0001", "ids": [format!("{:032x}", 1)]}]));
    store::save_store(&s, &t, &st).unwrap();
    let ours = Value::Object(store::load_store(&s, &t).unwrap());
    let theirs: Value = serde_json::from_str(&run_py(&py, PY_LOAD, "", &[root, &t_json])).unwrap();
    assert_eq!(ours, theirs);
    assert_eq!(ours["edits"].as_array().unwrap().len(), 3);

    // Python writes a fourth mutation through its own save path; Rust loads the same value.
    let code = r#"
import sys, json
from hydralysis import workcopy
s = {"root": sys.argv[1]}
t = json.loads(sys.argv[2])
st = workcopy.load_store(s, t)
st["edits"].append(json.loads(sys.argv[3]))
st["revision"] = 4
workcopy._save_store(s, t, st)
print(json.dumps(workcopy.load_store(s, t)))
"#;
    let after_py: Value = serde_json::from_str(&run_py(&py, code, "", &[root, &t_json, &rec(4).to_string()])).unwrap();
    let after_rust = Value::Object(store::load_store(&s, &t).unwrap());
    assert_eq!(after_rust, after_py);
    assert_eq!(after_rust["revision"], 4);
    assert_eq!(store::pending_of(&Map::from_iter(after_rust.as_object().unwrap().clone())).len(), 3);
    // the derived marker is byte-identical to Python's
    let want = run_py(
        &py,
        "import sys,json\nfrom hydralysis import workcopy\ns={'root':sys.argv[1]}\nt=json.loads(sys.argv[2])\nprint(workcopy.state_text(workcopy.state_of(workcopy.load_store(s,t))))",
        "",
        &[root, &t_json],
    );
    let got = store::state_text(&store::state_of(&store::load_store(&s, &t).unwrap()));
    assert_eq!(got, want);
}

#[test]
fn revision_rules_match_python_on_generated_cases() {
    let Some(py) = python() else { return };
    let mut x: u64 = 7;
    let mut next = |n: u64| {
        x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (x >> 33) % n
    };
    let kinds = [
        "rename",
        "label",
        "comment",
        "signature",
        "apply",
        "variable",
        "function_create",
        "function_body",
        "function_delete",
        "struct",
        "import_types",
        "batch",
    ];
    let mut subject_cases = Vec::new();
    for _ in 0..300 {
        let kind = kinds[next(12) as usize];
        let address = ["", "0x401000", "401010", "10", "0xdeadbeef"][next(5) as usize];
        let mut options = json!({"kind": kind});
        if next(2) == 0 {
            options["path"] = json!("/a/b");
        }
        if next(2) == 0 {
            options["name"] = json!("nm");
        }
        if kind == "batch" {
            options["edits"] = json!([{"address": "20", "options": {"kind": "rename"}}, {"address": "0x30", "options": {"kind": "function_body", "name": "z"}}]);
        }
        subject_cases.push(json!({"address": address, "options": options}));
    }
    let mut journal_cases = Vec::new();
    for _ in 0..300 {
        let revision = next(8) as i64;
        let mut journal = Vec::new();
        for r in 1..=revision {
            if next(5) != 0 {
                let subj: Vec<&str> = ["a", "b", "c", "*"][..(1 + next(3) as usize)].to_vec();
                journal.push(json!({"revision": r, "op": "e", "subjects": subj, "by": {"c": r}, "at": r as f64}));
            }
        }
        let expected = if next(6) == 0 { Value::Null } else { json!(next(10) as i64) };
        let subjects: Vec<&str> = ["a", "b", "c", "*"][..(1 + next(3) as usize)].to_vec();
        journal_cases.push(json!({"expected": expected, "revision": revision, "journal": journal, "subjects": subjects}));
    }
    let mut dep_cases = Vec::new();
    for _ in 0..200 {
        let n = 2 + next(7) as usize;
        let records: Vec<Value> = (0..n)
            .map(|i| {
                let effects: Vec<Value> = (0..next(3))
                    .map(|_| json!({"subject": format!("s{}", next(3)), "field": field_of(next(3)), "before": null, "after": "x"}))
                    .collect();
                json!({"id": format!("r{i}"), "seq": i + 1, "effects": effects, "address": "0x10", "options": {"kind": "rename"}})
            })
            .collect();
        let selected: Vec<String> = (0..n).filter(|_| next(3) == 0).map(|i| format!("r{i}")).collect();
        let committed: Vec<String> = (0..n).filter(|_| next(5) == 0).map(|i| format!("r{i}")).collect();
        dep_cases.push(json!({"records": records, "selected": selected, "committed": committed}));
    }
    let input = json!({"subjects": subject_cases, "journal": journal_cases, "deps": dep_cases});
    let code = r#"
import sys, json
from hydralysis import revisions
d = json.load(sys.stdin)
print(json.dumps({
  "subjects": [revisions.subjects_of(c["address"], c["options"]) for c in d["subjects"]],
  "fields": [[list(p) for p in revisions.fields_of(c["address"], c["options"])] for c in d["subjects"]],
  "journal": [revisions.reconcile(c["expected"], c["revision"], c["journal"], c["subjects"]) for c in d["journal"]],
  "deps": [revisions.dependents(c["records"], set(c["selected"]), set(c["committed"])) for c in d["deps"]],
}))
"#;
    let want: Value = serde_json::from_str(&run_py(&py, code, &input.to_string(), &[])).unwrap();
    for (i, c) in subject_cases.iter().enumerate() {
        let got = revisions::subjects_of(c["address"].as_str().unwrap(), &c["options"]);
        assert_eq!(json!(got), want["subjects"][i], "subjects case {i}: {c}");
        let fields: Vec<Value> =
            revisions::fields_of(c["address"].as_str().unwrap(), &c["options"]).into_iter().map(|(a, b)| json!([a, b])).collect();
        assert_eq!(Value::Array(fields), want["fields"][i], "fields case {i}: {c}");
    }
    for (i, c) in journal_cases.iter().enumerate() {
        let subjects: Vec<String> = c["subjects"].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
        let got =
            revisions::reconcile(c["expected"].as_i64(), c["revision"].as_i64().unwrap(), c["journal"].as_array().unwrap(), &subjects);
        assert_eq!(got, want["journal"][i], "reconcile case {i}: {c}");
    }
    for (i, c) in dep_cases.iter().enumerate() {
        let set = |k: &str| c[k].as_array().unwrap().iter().map(|s| s.as_str().unwrap().to_string()).collect();
        let got = revisions::dependents(c["records"].as_array().unwrap(), &set("selected"), &set("committed"));
        assert_eq!(json!(got), want["deps"][i], "dependents case {i}: {c}");
    }
}

fn field_of(n: u64) -> &'static str {
    ["name", "report", "type"][n as usize]
}
