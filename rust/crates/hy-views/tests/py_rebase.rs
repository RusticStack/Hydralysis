//! `views.rebase` against Python: the same world is rebased by each implementation (engine calls replaced by the same fake
//! in both) and the result and the resulting store must be equal. Skipped without Python.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hy_views::classify::Pair;
use hy_views::error::Result;
use hy_views::gens;
use hy_views::layout::Settings;
use hy_views::store::{self, Store, Target};
use hy_views::views::{self, Host};
use serde_json::{Map, Value, json};

mod common;
use common::{L, copy_dir, id, load, normalise, python, rec, run_py, target};

/// A lineage with generations 0..=3 (3 publishes records 2 and 3) and a view on generation 1 holding record 1 (committed),
/// 2 and 3 (now in the master) and 4 (pending, address 0x401040).
fn world(base: &Path) -> PathBuf {
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let s: Settings = json!({"root": root.to_str().unwrap()}).as_object().unwrap().clone();
    let gens_dir = base.join("gens");
    let mut gprs = Vec::new();
    for (n, facts) in [
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
        let mut manifest = json!({"store": facts});
        if n == 3 {
            manifest["cid"] = json!("c-0000000000000bbb");
        }
        std::fs::write(folder.join("MANIFEST.json"), manifest.to_string()).unwrap();
        gprs.push(folder.join("p.gpr").display().to_string());
    }
    let line = |g: i64, reason: &str, extra: Value| {
        let mut m = json!({"gen": g, "reason": reason, "gpr": gprs[g as usize]}).as_object().unwrap().clone();
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
    st.insert("commits".into(), json!([{"cid": "c-1", "generation": 1, "ids": [id(1)], "reverted": false}]));
    store::save_store(&s, &t, &st).unwrap();
    root
}

/// The engine, as a table of live values keyed `subject|field`; a rebuilt copy (`refresh`) answers nothing, so verification
/// finds no disagreement.
struct Fake {
    live: HashMap<String, Value>,
}

impl Host for Fake {
    fn heal(&self, _: &Settings, _: &Target) -> Result<bool> {
        Ok(false)
    }
    fn ensure_lineage(&self, _: &Settings, _: &Target) -> Result<Value> {
        unreachable!()
    }
    fn resolve_target(&self, _: &Settings, _: &str) -> Result<Target> {
        unreachable!()
    }
    fn open_program(&self, _: &str, _: &str, _: &str, refresh: bool) -> Result<Value> {
        Ok(json!({"fork": refresh}))
    }
    fn probe(&self, program: &Value, pairs: &[Pair]) -> Result<HashMap<Pair, Value>> {
        if program["fork"] == true {
            return Ok(HashMap::new());
        }
        Ok(pairs.iter().filter_map(|p| self.live.get(&format!("{}|{}", p.0, p.1)).map(|v| (p.clone(), v.clone()))).collect())
    }
    fn sync(&self, _: &Settings, _: &Target, _: &Store, _: i64, _: Option<&[Value]>, _: bool) -> Result<Value> {
        Ok(json!({"fork_gpr": "", "effects": []}))
    }
    fn abandon_copy(&self, _: &Settings, _: &Target, _: Option<&Value>) {}
    fn adopt_copy(&self, _: &Settings, _: &Target, _: &Value) -> Result<()> {
        Ok(())
    }
}

const PY: &str = r#"
import sys, json
from hydralysis import views, workcopy, query
root = sys.argv[1]
live = json.loads(sys.argv[2])
options = json.loads(sys.argv[3])
s = {"root": root}
sel = json.loads(sys.argv[4])
workcopy.heal = lambda *a, **k: False
workcopy._sync = lambda *a, **k: {"fork_gpr": "", "effects": []}
def probe(engine, program, pairs):
    if program.get("fork"):
        return {}
    return {p: live[p[0] + "|" + p[1]] for p in pairs if p[0] + "|" + p[1] in live}
workcopy.probe = probe
query.open_program = lambda engine, gpr, program, sha, refresh=False: {"fork": refresh}
views._adopt_copy = lambda *a, **k: None
views._abandon_copy = lambda *a, **k: None
try:
    out = views.rebase(s, None, sel, options)
except Exception as e:
    out = {"raised": str(e)}
print(json.dumps(out))
"#;

#[test]
fn rebase_matches_python_across_conflict_outcomes() {
    let Some(py) = python() else { return };
    let subject = "address:0x401040";
    let cases: Vec<(&str, Option<Value>, Value)> = vec![
        ("clean", Some(json!("a")), json!({"expect_revision": 4})),
        ("converged", Some(json!("n4")), json!({"expect_revision": 4})),
        ("unprobed", None, json!({"expect_revision": 4})),
        ("conflict", Some(json!("zzz")), json!({"expect_revision": 4})),
        ("take_mine", Some(json!("zzz")), json!({"expect_revision": 4, "resolve": {subject: "take_mine"}})),
        ("keep", Some(json!("zzz")), json!({"expect_revision": 4, "resolve": {subject: "keep"}})),
        ("stale_expect", Some(json!("a")), json!({"expect_revision": 99})),
    ];
    for (name, live_value, options) in cases {
        let dir = tempfile::Builder::new().prefix("hrb").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let root_a = world(dir.path());
        let root_b = dir.path().join("rootb");
        copy_dir(&root_a, &root_b);
        let mut live = HashMap::new();
        if let Some(v) = live_value {
            live.insert(format!("{subject}|name"), v);
        }
        let s: Settings = json!({"root": root_a.to_str().unwrap()}).as_object().unwrap().clone();
        let host = Fake { live: live.clone() };
        let mut rust_out = match views::rebase(&host, &s, &target(), &options, 30) {
            Ok(v) => v,
            Err(e) => json!({"raised": e.to_string()}),
        };
        let live_json = Value::Object(live.into_iter().collect::<Map<_, _>>());
        let out = run_py(
            &py,
            PY,
            &[root_b.to_str().unwrap(), &live_json.to_string(), &options.to_string(), &Value::Object(target()).to_string()],
        );
        let mut py_out: Value = serde_json::from_str(&out).unwrap();
        let roots = [dir.path().to_str().unwrap()];
        normalise(&mut rust_out, &roots);
        normalise(&mut py_out, &roots);
        assert_eq!(rust_out, py_out, "result of case {name}");
        let expect = match name {
            "clean" | "converged" | "unprobed" => "resolved_or_dropped",
            "conflict" => "conflict",
            "stale_expect" => "raised",
            _ => "resolved",
        };
        let got = rust_out["outcome"].as_str().unwrap_or("raised");
        match expect {
            "resolved_or_dropped" => assert!(["clean", "dropped"].contains(&got), "{name}: {got}"),
            e => assert_eq!(got, e, "{name}"),
        }
        assert_eq!(load(&root_a, dir.path(), &target()), load(&root_b, dir.path(), &target()), "store of case {name}");
    }
}
