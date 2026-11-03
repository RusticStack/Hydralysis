//! `views.merge` against Python: the same two views are merged by each implementation (engine calls replaced by the same fake
//! in both); the result and both resulting stores must be equal. Skipped without Python.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hy_views::layout::Settings;
use hy_views::store::{self, Target};
use hy_views::views;
use serde_json::{Value, json};

mod common;
use common::{
    Fake, L, PY_FAKE, copy_dir, id, load, mask_new_ids, normalise, python, rec, run_py, target,
};

fn settings(root: &Path) -> Settings {
    json!({"root": root.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone()
}

fn dest() -> Target {
    store::with_view(&target(), "shared").unwrap()
}

fn source() -> Target {
    store::with_view(&target(), "agent-a").unwrap()
}

/// Source view agent-a holds records 1..=4 (addresses 0x401010..0x401040, `before` "a"); the destination (shared) holds what
/// the tweak says. Both are on generation 3 of the lineage.
fn world(base: &Path, tweak: &str) -> PathBuf {
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let s = settings(&root);
    let base_ref = json!({"lineage": L, "generation": 3});
    let mut mine = store::load_store(&s, &source()).unwrap();
    let mut records = vec![rec(1), rec(2), rec(3), rec(4)];
    if tweak == "unknown" {
        records[3]["before_unknown"] = json!(true);
    }
    mine.insert("edits".into(), json!(records));
    mine.insert("revision".into(), json!(4));
    mine.insert("base".into(), base_ref.clone());
    if tweak == "through" {
        mine.insert("published_through".into(), json!({"shared": 4}));
    }
    store::save_store(&s, &source(), &mine).unwrap();
    let mut theirs = store::load_store(&s, &dest()).unwrap();
    let mut dest_edits = Vec::new();
    if tweak == "pending_dest" {
        dest_edits.push(rec(10));
    }
    if tweak == "already" {
        let mut r = rec(11);
        r["merged_from"] = json!({"view": "agent-a", "id": id(1), "seq": 1});
        dest_edits.push(r);
    }
    theirs.insert("revision".into(), json!(dest_edits.len()));
    theirs.insert("edits".into(), json!(dest_edits));
    theirs.insert("base".into(), base_ref);
    store::save_store(&s, &dest(), &theirs).unwrap();
    root
}

const PY: &str = r#"
root = sys.argv[1]
options = json.loads(sys.argv[3])
source, dest = json.loads(sys.argv[4]), json.loads(sys.argv[6])
s = {"root": root}
try:
    out = views.merge(s, None, source, dest, options)
except Exception as e:
    out = {"raised": str(e)}
print(json.dumps(out))
"#;

type Case = (
    &'static str,
    &'static str,
    Vec<(&'static str, &'static str)>,
    Value,
    bool,
);

#[test]
fn merge_matches_python_across_outcomes() {
    let Some(py) = python() else { return };
    let rev = |n: i64| json!({"expect_revision": n});
    let s2 = "address:0x401020";
    let s3 = "address:0x401030";
    let all_a = vec![
        ("address:0x401010", "a"),
        (s2, "a"),
        (s3, "a"),
        ("address:0x401040", "a"),
    ];
    let mixed = vec![
        ("address:0x401010", "a"),
        (s2, "n2"),
        (s3, "zzz"),
        ("address:0x401040", "a"),
    ];
    let cases: Vec<Case> = vec![
        ("clean", "", all_a.clone(), rev(0), false),
        ("mixed_conflict", "", mixed.clone(), rev(0), false),
        (
            "take_mine",
            "",
            mixed.clone(),
            json!({"expect_revision": 0, "resolve": {s3: "take_mine"}}),
            false,
        ),
        (
            "keep",
            "",
            mixed,
            json!({"expect_revision": 0, "resolve": {s3: "keep"}}),
            false,
        ),
        ("no_effects", "", all_a.clone(), rev(0), true),
        ("pending_dest", "pending_dest", all_a.clone(), rev(1), false),
        ("unknown_refused", "unknown", all_a.clone(), rev(0), false),
        (
            "unknown_allowed",
            "unknown",
            all_a.clone(),
            json!({"expect_revision": 0, "allow_unverified_before": true}),
            false,
        ),
        ("through", "through", all_a.clone(), rev(0), false),
        ("already_merged", "already", all_a.clone(), rev(1), false),
        ("stale_expect", "", all_a, rev(99), false),
    ];
    for (name, tweak, live_pairs, options, no_effects) in cases {
        let dir = tempfile::Builder::new()
            .prefix("hmg")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap();
        let root_a = world(dir.path(), tweak);
        let root_b = dir.path().join("rootb");
        copy_dir(&root_a, &root_b);
        let live: HashMap<String, Value> = live_pairs
            .iter()
            .map(|(s, v)| (format!("{s}|name"), json!(v)))
            .collect();
        let host = Fake {
            live: live.clone(),
            no_effects,
            lineage: json!({"id": L}),
            resolved: target(),
        };
        let opts = options.as_object().unwrap();
        let mut rust_out =
            match views::merge(&host, &settings(&root_a), &source(), &dest(), opts, 30) {
                Ok(v) => v,
                Err(e) => json!({"raised": e.to_string()}),
            };
        let code = format!("{PY_FAKE}{PY}");
        let out = run_py(
            &py,
            &code,
            &[
                root_b.to_str().unwrap(),
                &serde_json::to_string(&live).unwrap(),
                &options.to_string(),
                &Value::Object(source()).to_string(),
                if no_effects { "1" } else { "0" },
                &Value::Object(dest()).to_string(),
            ],
        );
        let mut py_out: Value = serde_json::from_str(&out).unwrap();
        let roots = [dir.path().to_str().unwrap()];
        for v in [&mut rust_out, &mut py_out] {
            normalise(v, &roots);
            mask_new_ids(v);
        }
        assert_eq!(rust_out, py_out, "result of case {name}");
        for (which, t) in [("source", source()), ("destination", dest())] {
            let mut a = load(&root_a, dir.path(), &t);
            let mut b = load(&root_b, dir.path(), &t);
            mask_new_ids(&mut a);
            mask_new_ids(&mut b);
            assert_eq!(a, b, "{which} store of case {name}");
        }
        // The cases must reach the outcomes they are named for, or the equality above proves little.
        let merged = rust_out["merged"].as_i64();
        match name {
            "clean" | "no_effects" | "pending_dest" => assert_eq!(merged, Some(4), "{name}"),
            "take_mine" => assert_eq!(merged, Some(3), "{name}"),
            "keep" => assert_eq!(merged, Some(2), "{name}"),
            "mixed_conflict" => assert_eq!(rust_out["outcome"], "conflict", "{name}"),
            "unknown_refused" | "stale_expect" => {
                assert!(rust_out.get("raised").is_some(), "{name}")
            }
            "through" => assert_eq!(merged, Some(0), "{name}"),
            _ => {}
        }
    }
}
