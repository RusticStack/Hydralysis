//! `views.seal_changeset` against Python: the same view is sealed by each implementation (lineage creation and target
//! resolution replaced by the same stubs) and the result and the sealed file must be equal. Skipped without Python.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hy_views::layout::Settings;
use hy_views::store::{self, Target};
use hy_views::{gens, queue, views};
use serde_json::{Value, json};

mod common;
use common::{Fake, L, copy_dir, id, normalise, python, rec, run_py, target};

fn settings(root: &Path) -> Settings {
    json!({"root": root.to_str().unwrap()}).as_object().unwrap().clone()
}

fn selected() -> Target {
    store::with_view(&target(), "shared").unwrap()
}

fn world(base: &Path, tweak: &str) -> PathBuf {
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let s = settings(&root);
    let line = json!({"gen": 0, "reason": "origin", "gpr": base.join("g0").join("p.gpr").display().to_string()});
    gens::append_current(&s, L, line.as_object().unwrap(), false).unwrap();
    let mut st = store::load_store(&s, &selected()).unwrap();
    let mut records = vec![rec(1), rec(2), rec(3)];
    if tweak == "unknown" {
        records[2]["before_unknown"] = json!(true);
    }
    let ids: Vec<String> = (1..=3).map(id).collect();
    st.insert("edits".into(), json!(records));
    st.insert("revision".into(), json!(3));
    st.insert("base".into(), json!({"lineage": L, "generation": 0}));
    if tweak == "all_committed" {
        st.insert("commits".into(), json!([{"cid": "c-1", "generation": 0, "ids": ids, "reverted": false}]));
    }
    store::save_store(&s, &selected(), &st).unwrap();
    root
}

const PY: &str = r#"
import sys, json
from hydralysis import views, workcopy
root = sys.argv[1]
options = json.loads(sys.argv[2])
selected = json.loads(sys.argv[3])
workcopy.heal = lambda *a, **k: False
views.ensure_lineage = lambda s, sel: {"id": sys.argv[4]}
views.targets.resolve = lambda s, name: {k: v for k, v in selected.items() if k not in ("view",)}
out = []
for _ in range(int(sys.argv[5])):
    try:
        out.append(views.seal_changeset({"root": root}, selected, options))
    except Exception as e:
        out.append({"raised": str(e)})
print(json.dumps(out))
"#;

/// Everything that differs per run is replaced: the csid, the seal time.
fn mask(v: &mut Value, roots: &[&str]) {
    normalise(v, roots);
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "csid" || k == "sealed_at" {
                    *x = json!("MASKED");
                } else {
                    mask(x, roots);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| mask(x, roots)),
        _ => {}
    }
}

#[test]
fn seal_changeset_matches_python() {
    let Some(py) = python() else { return };
    let ok = json!({"expect_revision": 3, "confirm_one_way_upgrade": true});
    let cases: Vec<(&str, &str, Value, usize)> = vec![
        ("sealed", "", ok.clone(), 1),
        ("reused", "", ok.clone(), 2),
        ("no_confirmation", "", json!({"expect_revision": 3}), 1),
        ("revision_changed", "", json!({"expect_revision": 2, "confirm_one_way_upgrade": true}), 1),
        ("nothing", "all_committed", ok.clone(), 1),
        ("unknown_refused", "unknown", ok.clone(), 1),
        (
            "unknown_allowed",
            "unknown",
            json!({"expect_revision": 3, "confirm_one_way_upgrade": true, "allow_unverified_before": true, "backup": "auto"}),
            1,
        ),
        ("bad_option", "", json!({"expect_revision": 3, "confirm_one_way_upgrade": true, "bogus": 1}), 1),
    ];
    for (name, tweak, options, repeat) in cases {
        let dir = tempfile::Builder::new().prefix("hsl").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let root_a = world(dir.path(), tweak);
        let root_b = dir.path().join("rootb");
        copy_dir(&root_a, &root_b);
        let host = Fake { live: HashMap::new(), no_effects: false, lineage: json!({"id": L}), resolved: selected(), mode: "" };
        let s = settings(&root_a);
        let mut rust_out = Vec::new();
        for _ in 0..repeat {
            rust_out.push(match views::seal_changeset(&host, &s, &selected(), &options) {
                Ok(v) => v,
                Err(e) => json!({"raised": e.to_string()}),
            });
        }
        let out = run_py(
            &py,
            PY,
            &[root_b.to_str().unwrap(), &options.to_string(), &Value::Object(selected()).to_string(), L, &repeat.to_string()],
        );
        let mut rust_out = Value::Array(rust_out);
        let mut py_out: Value = serde_json::from_str(&out).unwrap();
        let roots = [dir.path().to_str().unwrap()];
        mask(&mut rust_out, &roots);
        mask(&mut py_out, &roots);
        assert_eq!(rust_out, py_out, "result of case {name}");
        // The sealed files, read by Rust on both sides (so Python's bytes are checked by Rust's reader).
        let sealed = |root: &Path| -> Vec<Value> {
            let s = settings(root);
            let mut names = queue::outstanding(&s, L).unwrap();
            names.sort();
            names
                .iter()
                .map(|n| {
                    let mut v = Value::Object(queue::read_changeset(&s, L, n).unwrap());
                    mask(&mut v, &[dir.path().to_str().unwrap()]);
                    v
                })
                .collect()
        };
        assert_eq!(sealed(&root_a), sealed(&root_b), "sealed files of case {name}");
        let n = sealed(&root_a).len();
        match name {
            "sealed" | "reused" | "unknown_allowed" => assert_eq!(n, 1, "{name}"),
            _ => assert_eq!(n, 0, "{name}"),
        }
        if name == "reused" {
            assert_eq!(rust_out[1]["reused"], true);
        }
    }
}
