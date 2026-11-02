//! `finalize_changeset`, `settle` and `finalize_commit` against Python: the same initial disk state is finalized by each
//! implementation in its own copy and the resulting stores must be equal (times and pids normalised). Skipped without Python.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use hy_views::gens;
use hy_views::layout::Settings;
use hy_views::settle;
use hy_views::store::{self, Target};
use serde_json::{Map, Value, json};

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
        .stdin(Stdio::null())
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let dest = to.join(e.file_name());
        if e.file_type().unwrap().is_dir() {
            copy_dir(&e.path(), &dest);
        } else {
            std::fs::copy(e.path(), dest).unwrap();
        }
    }
}

fn normalise(v: &mut Value, roots: &[&str]) {
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if k == "at" && x.is_number() {
                    *x = json!(0);
                } else {
                    normalise(x, roots);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| normalise(x, roots)),
        Value::String(s) => {
            for r in roots {
                *s = s.replace(r, "<ROOT>");
            }
            if s.starts_with("rusticre:") {
                *s = "rusticre:PID".into();
            }
        }
        _ => {}
    }
}

const L: &str = "L-0000abcd";

fn target() -> Target {
    json!({"key": "k1", "sha256": "ab".repeat(32), "name": "prog", "lineage": {"id": L, "generation": 3, "origin_key": "k1"}})
        .as_object()
        .unwrap()
        .clone()
}

fn id(n: usize) -> String {
    format!("{n:032x}")
}

fn rec(n: usize) -> Value {
    json!({"id": id(n), "address": format!("0x{:x}", 0x401000 + n * 16), "options": {"kind": "rename", "source": "t", "name": format!("n{n}")}, "seq": n, "by": {"client": "c"}, "at": 1.5,
           "effects": [{"subject": format!("address:0x{:x}", 0x401000 + n * 16), "field": "name", "before": "a", "after": format!("n{n}")}]})
}

/// Builds a root with a lineage whose log has generations 0..=3 (3 by publish of changeset c-...aaa for view key k1),
/// manifests outside the root, and a store with records 1..=4 where record 1 is committed (gen 1) and 2, 3 are decided.
fn world(base: &Path) -> (PathBuf, Vec<String>) {
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let s: Settings = json!({"root": root.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone();
    let gens_dir = base.join("gens");
    let mut gprs = Vec::new();
    for (n, store_facts) in [
        (0, json!({})),
        (1, json!({"ids": [id(1)], "subjects": ["address:0x401010"]})),
        (2, json!({"ids": ["other"], "subjects": ["address:0x999"]})),
        (
            3,
            json!({"ids": [id(2), id(3)], "subjects": ["address:0x401020", "address:0x401030"],
                   "by_changeset": {"c-0000000000000aaa": {"ids": [id(2), id(3)], "snapshot": 7}},
                   "view": "shared", "snapshot": 7, "ids_sha256": store::digest_of(&[id(2), id(3)]), "skipped": []}),
        ),
    ] {
        let folder = gens_dir.join(format!("g{n}"));
        std::fs::create_dir_all(&folder).unwrap();
        let mut manifest = json!({"store": store_facts});
        if n == 3 {
            manifest["cid"] = json!("c-0000000000000bbb");
        }
        std::fs::write(folder.join("MANIFEST.json"), manifest.to_string()).unwrap();
        gprs.push(folder.join("p.gpr").display().to_string());
    }
    let line = |g: i64, reason: &str, extra: Value| {
        let mut m = json!({"gen": g, "reason": reason, "gpr": gprs[g as usize]})
            .as_object()
            .unwrap()
            .clone();
        m.extend(extra.as_object().unwrap().clone());
        m
    };
    gens::append_current(&s, L, &line(0, "origin", json!({})), false).unwrap();
    gens::append_current(&s, L, &line(1, "commit", json!({"cid": "c-1"})), false).unwrap();
    gens::append_current(&s, L, &line(2, "commit", json!({"cid": "c-2"})), false).unwrap();
    gens::append_current(
        &s,
        L,
        &line(3, "commit", json!({"cid": "c-0000000000000bbb", "via": "publish", "changesets": [{"csid": "c-0000000000000aaa", "view_key": "k1", "view": "shared"}]})),
        false,
    )
    .unwrap();
    let t = target();
    let mut st = store::load_store(&s, &t).unwrap();
    st.insert("edits".into(), json!([rec(1), rec(2), rec(3), rec(4)]));
    st.insert("revision".into(), json!(4));
    st.insert("base".into(), json!({"lineage": L, "generation": 1}));
    st.insert(
        "commits".into(),
        json!([{"cid": "c-1", "generation": 1, "ids": [id(1)], "reverted": false}]),
    );
    store::save_store(&s, &t, &st).unwrap();
    (root, gprs)
}

fn load_normalised(root: &Path, base: &Path) -> Value {
    let s: Settings = json!({"root": root.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone();
    let mut v = Value::Object(store::load_store(&s, &target()).unwrap());
    normalise(
        &mut v,
        &[
            root.to_str().unwrap(),
            &root.to_str().unwrap().replace('\\', "\\\\"),
            base.to_str().unwrap(),
        ],
    );
    v
}

const PY_COMMON: &str = r#"
import sys, json
from hydralysis import views, workcopy, commits
root = sys.argv[1]
s = {"root": root}
sel = {"key": "k1", "sha256": "ab"*32, "name": "prog", "lineage": {"id": "L-0000abcd", "generation": 3, "origin_key": "k1"}}
L = "L-0000abcd"
"#;

fn ids(ns: &[usize]) -> Vec<String> {
    ns.iter().map(|n| id(*n)).collect()
}

#[test]
fn finalize_changeset_matches_python_with_and_without_a_generation() {
    let Some(py) = python() else { return };
    for generation in [Some(3i64), None] {
        let dir = tempfile::Builder::new()
            .prefix("hse")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap();
        let (root_a, _) = world(dir.path());
        let root_b = dir.path().join("rootb");
        copy_dir(&root_a, &root_b);
        let subjects = json!(["address:0x401020", "address:0x401030"]);
        let s: Settings = json!({"root": root_a.to_str().unwrap()})
            .as_object()
            .unwrap()
            .clone();
        let wrote = settle::finalize_changeset(
            &s,
            &target(),
            L,
            "c-0000000000000aaa",
            generation,
            &ids(&[2, 3]),
            Some(7),
            None,
            Some(&subjects),
            None,
        )
        .unwrap();
        assert!(wrote);
        // idempotent by csid
        assert!(
            !settle::finalize_changeset(
                &s,
                &target(),
                L,
                "c-0000000000000aaa",
                generation,
                &ids(&[2, 3]),
                Some(7),
                None,
                Some(&subjects),
                None
            )
            .unwrap()
        );
        let code = format!(
            "{PY_COMMON}\nprint(views.finalize_changeset(s, sel, L, 'c-0000000000000aaa', {}, json.loads(sys.argv[2]), 7, subjects=json.loads(sys.argv[3])))",
            generation.map_or("None".to_string(), |g| g.to_string())
        );
        let out = run_py(
            &py,
            &code,
            &[
                root_b.to_str().unwrap(),
                &json!(ids(&[2, 3])).to_string(),
                &subjects.to_string(),
            ],
        );
        assert_eq!(out, "True");
        let (a, b) = (
            load_normalised(&root_a, dir.path()),
            load_normalised(&root_b, dir.path()),
        );
        assert_eq!(a, b, "generation {generation:?}");
        if generation.is_some() {
            // record 4 stays pending and the jump to 3 crosses generation 2: the base stays (the view is stale until rebased)
            assert_eq!(a["base"]["generation"], 1);
            assert_eq!(a["commits"].as_array().unwrap().len(), 1);
            assert_eq!(a["commits"][0]["cid"], "c-0000000000000aaa");
            assert_eq!(a["archived"].as_array().unwrap().len(), 1);
        } else {
            assert_eq!(a["reverted"][0]["reason"], "published:already_in_master");
        }
    }
}

#[test]
fn settle_finalizes_a_publish_the_leader_did_not() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new()
        .prefix("hss")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let (root_a, _) = world(dir.path());
    let root_b = dir.path().join("rootb");
    copy_dir(&root_a, &root_b);
    let s: Settings = json!({"root": root_a.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone();
    assert!(settle::settle(&s, &target(), None).unwrap());
    assert!(!settle::settle(&s, &target(), None).unwrap());
    let out = run_py(
        &py,
        &format!("{PY_COMMON}\nprint(views.settle(s, sel))"),
        &[root_b.to_str().unwrap()],
    );
    assert_eq!(out, "True");
    let (a, b) = (
        load_normalised(&root_a, dir.path()),
        load_normalised(&root_b, dir.path()),
    );
    assert_eq!(a, b);
    assert_eq!(a["changesets"][0]["csid"], "c-0000000000000aaa");
    let mut no_lineage: Map<String, Value> = target();
    no_lineage.remove("lineage");
    assert!(!settle::settle(&s, &no_lineage, None).unwrap());
}

#[test]
fn finalize_commit_matches_python_and_is_idempotent() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new()
        .prefix("hsc")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let (root_a, gprs) = world(dir.path());
    // the generation folder lives at <root>/lineages/<L>/gen/0003 for finalize: copy g3's manifest there
    let place = |root: &Path| {
        let s: Settings = json!({"root": root.to_str().unwrap()})
            .as_object()
            .unwrap()
            .clone();
        let folder = hy_views::layout::generation_dir(&s, L, 3).unwrap();
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::copy(
            Path::new(&gprs[3]).parent().unwrap().join("MANIFEST.json"),
            folder.join("MANIFEST.json"),
        )
        .unwrap();
    };
    place(&root_a);
    let root_b = dir.path().join("rootb");
    copy_dir(&root_a, &root_b);
    let s: Settings = json!({"root": root_a.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone();
    let first =
        settle::finalize_commit(&s, &target(), L, "c-0000000000000bbb", 3, None, false).unwrap();
    assert_eq!(first["already"], false);
    let again =
        settle::finalize_commit(&s, &target(), L, "c-0000000000000bbb", 3, None, false).unwrap();
    assert_eq!(again["already"], true);
    let e = settle::finalize_commit(&s, &target(), L, "c-9999999999999999", 3, None, false)
        .unwrap_err();
    assert_eq!(
        e.to_string(),
        "generation 3 has no manifest for c-9999999999999999"
    );
    let out = run_py(
        &py,
        &format!(
            "{PY_COMMON}\nprint(json.dumps(commits.finalize(s, sel, L, 'c-0000000000000bbb', 3)))"
        ),
        &[root_b.to_str().unwrap()],
    );
    let py_result: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(py_result, first);
    let (a, b) = (
        load_normalised(&root_a, dir.path()),
        load_normalised(&root_b, dir.path()),
    );
    assert_eq!(a, b);
    assert_eq!(a["revision"], 5);
    assert_eq!(
        a["journal"].as_array().unwrap().last().unwrap()["op"],
        "commit"
    );
}
