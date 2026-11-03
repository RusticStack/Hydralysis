//! `workcopy.revert`, `edit`, `add_proposals`, `base_master_gpr`, `read_gpr` and the file helpers against Python. The world
//! is built by the same Rust code in two roots, each implementation runs the operation (engine calls replaced by the same
//! fake on both sides), and the result and the resulting store must be equal. Skipped without Python.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use hy_views::generations::{manifest_file_sha256, write_manifest};
use hy_views::layout::{Settings, generation_dir};
use hy_views::store::{self, Target};
use hy_views::{gens, revisions, workcopy};
use serde_json::{Value, json};

mod common;
use common::{Fake, L, copy_dir, id, load, normalise, python, rec, run_py, target};

fn settings(root: &Path) -> Settings {
    json!({"root": root.to_str().unwrap()}).as_object().unwrap().clone()
}

fn selected() -> Target {
    store::with_view(&target(), "shared").unwrap()
}

fn fake() -> Fake {
    Fake { live: HashMap::new(), no_effects: false, lineage: json!({"id": L}), resolved: selected(), mode: "" }
}

/// The records of a case. `plain` is four independent records; the others tweak them.
fn records(tweak: &str) -> Vec<Value> {
    let mut records: Vec<Value> = (1..=4).map(rec).collect();
    match tweak {
        "dependents" => {
            // record 2 edits the same subject and field as record 1, having seen record 1's value
            records[1]["address"] = records[0]["address"].clone();
            records[1]["effects"] = json!([{"subject": format!("address:{}", records[0]["address"].as_str().unwrap()),
                                            "field": "name", "before": "n1", "after": "n2"}]);
        }
        "batch" => {
            records[1]["batch"] = json!("bb");
            records[2]["batch"] = json!("bb");
        }
        _ => {}
    }
    records
}

fn world(base: &Path, tweak: &str) -> PathBuf {
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let s = settings(&root);
    let line = json!({"gen": 0, "reason": "origin", "gpr": base.join("g0").join("p.gpr").display().to_string()});
    gens::append_current(&s, L, line.as_object().unwrap(), false).unwrap();
    let mut st = store::load_store(&s, &selected()).unwrap();
    let records = records(tweak);
    let journal: Vec<Value> = records
        .iter()
        .enumerate()
        .map(|(i, r)| {
            revisions::journal_entry(
                i as i64 + 1,
                "edit",
                &revisions::subjects_of(r["address"].as_str().unwrap(), &r["options"]),
                Some(&json!({"client": "c"})),
                1.5,
            )
        })
        .collect();
    st.insert("edits".into(), json!(records));
    st.insert("revision".into(), json!(4));
    st.insert("journal".into(), json!(journal));
    let generation = if tweak == "stale" { 1 } else { 3 };
    st.insert("base".into(), json!({"lineage": L, "generation": generation}));
    if tweak == "committed" {
        st.insert("commits".into(), json!([{"cid": "c-1", "generation": 3, "ids": [id(1)], "reverted": false}]));
    }
    store::save_store(&s, &selected(), &st).unwrap();
    root
}

/// The shared prelude: the engine-bound seams replaced by the fakes of `common::Fake`.
const PY: &str = r#"
import sys, json
from hydralysis import workcopy
workcopy.heal = lambda *a, **k: False
def sync(settings, target, store, timeout_s, extra=None, **k):
    eff = {}
    for r in extra or []:
        eff[r["id"]] = [{"subject": "address:" + r["address"], "field": "name", "before": "a", "after": r["options"]["name"]}]
    return {"fork_gpr": "", "effects": eff, "last_sync": {"n": len(extra or [])}}
workcopy._sync = sync
root, op, args, selected = sys.argv[1], sys.argv[2], json.loads(sys.argv[3]), json.loads(sys.argv[4])
settings = {"root": root}
try:
    if op == "revert":
        out = workcopy.revert(settings, selected, args["ids"], args.get("expect"), args.get("cascade", False))
    elif op == "edit":
        out = workcopy.edit(settings, None, selected, args["address"], args["options"], 30)
    elif op == "add":
        out = workcopy.add_proposals(settings, None, selected, args["records"], args.get("expect"), 30, args["from"])
    else:
        raise SystemExit("unknown op")
except Exception as e:
    out = {"raised": str(e)}
print(json.dumps(out))
"#;

fn rust_run(op: &str, args: &Value, s: &Settings) -> Value {
    let host = fake();
    let result = match op {
        "revert" => {
            let ids: Vec<String> = args["ids"].as_array().unwrap().iter().map(|v| v.as_str().unwrap().to_string()).collect();
            workcopy::revert(&host, s, &selected(), &ids, args["expect"].as_i64(), args["cascade"].as_bool().unwrap_or(false))
        }
        "edit" => workcopy::edit(&host, s, &selected(), args["address"].as_str().unwrap(), args["options"].clone(), 30),
        "add" => workcopy::add_proposals(&host, s, &selected(), args["records"].as_array().unwrap(), args["expect"].as_i64(), 30, &args["from"]),
        _ => unreachable!(),
    };
    result.unwrap_or_else(|e| json!({"raised": e.to_string()}))
}

/// Replace the random ids a run generates by `NEW<n>`, in both texts, so two runs compare.
fn mask_ids(value: &mut Value, ids: &[String]) {
    let mut text = value.to_string();
    for (n, ident) in ids.iter().enumerate() {
        text = text.replace(ident, &format!("NEW{n}"));
    }
    *value = serde_json::from_str(&text).unwrap();
}

fn new_ids(result: &Value, store: &Value) -> Vec<String> {
    let known: Vec<String> = (1..=4).map(id).collect();
    let mut found: Vec<String> = Vec::new();
    for edit in store["edits"].as_array().into_iter().flatten() {
        let ident = edit["id"].as_str().unwrap().to_string();
        if !known.contains(&ident) {
            found.push(ident);
        }
    }
    if let Some(ident) = result["overlay_id"].as_str() {
        if !found.iter().any(|f| f == ident) {
            found.push(ident.to_string());
        }
    }
    found
}

fn check(py: &str, name: &str, tweak: &str, op: &str, args: Value) {
    let dir = tempfile::Builder::new().prefix("hsw").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let root_a = world(dir.path(), tweak);
    let root_b = dir.path().join("rootb");
    copy_dir(&root_a, &root_b);
    let s = settings(&root_a);
    let mut rust_out = rust_run(op, &args, &s);
    let out = run_py(py, PY, &[root_b.to_str().unwrap(), op, &args.to_string(), &Value::Object(selected()).to_string()]);
    let mut py_out: Value = serde_json::from_str(&out).unwrap();
    let (base, a, b) = (dir.path().to_str().unwrap(), root_a.to_str().unwrap(), root_b.to_str().unwrap());
    let escaped = |t: &str| t.replace('\\', "\\\\");
    let roots = [base, a, b, &escaped(base), &escaped(a), &escaped(b)];
    let mut store_a = load(&root_a, dir.path(), &selected());
    let mut store_b = load(&root_b, dir.path(), &selected());
    let (ids_a, ids_b) = (new_ids(&rust_out, &store_a), new_ids(&py_out, &store_b));
    assert_eq!(ids_a.len(), ids_b.len(), "case {name}: number of new records");
    mask_ids(&mut rust_out, &ids_a);
    mask_ids(&mut py_out, &ids_b);
    mask_ids(&mut store_a, &ids_a);
    mask_ids(&mut store_b, &ids_b);
    normalise(&mut rust_out, &roots);
    normalise(&mut py_out, &roots);
    if std::env::var("WC_SHOW").is_ok() {
        eprintln!("{name}: {}", rust_out.to_string().chars().take(230).collect::<String>());
    }
    assert_eq!(rust_out, py_out, "result of case {name}");
    assert_eq!(store_a, store_b, "store of case {name}");
}

#[test]
fn revert_matches_python() {
    let Some(py) = python() else { return };
    let one = |ids: &[usize], expect: Value, cascade: bool| {
        json!({"ids": ids.iter().map(|i| id(*i)).collect::<Vec<_>>(), "expect": expect, "cascade": cascade})
    };
    check(&py, "single", "plain", "revert", one(&[2], json!(4), false));
    check(&py, "two", "plain", "revert", one(&[1, 3], json!(4), false));
    check(&py, "missing_expect", "plain", "revert", one(&[2], Value::Null, false));
    check(&py, "stale_expect", "plain", "revert", one(&[2], json!(2), false));
    check(&py, "no_match", "plain", "revert", json!({"ids": ["nope", "nada"], "expect": 4}));
    check(&py, "already_committed", "committed", "revert", one(&[1], json!(4), false));
    check(&py, "has_dependents", "dependents", "revert", one(&[1], json!(4), false));
    check(&py, "cascade", "dependents", "revert", one(&[1], json!(4), true));
    check(&py, "batch_by_batch_id", "batch", "revert", json!({"ids": ["bb"], "expect": 4}));
    check(&py, "batch_by_member", "batch", "revert", one(&[2], json!(4), false));
    check(&py, "stale_view", "stale", "revert", one(&[2], json!(4), false));
}

#[test]
fn edit_matches_python() {
    let Some(py) = python() else { return };
    let options = |expect: Value, name: &str| {
        let mut o = json!({"kind": "rename", "source": "t", "name": name});
        if !expect.is_null() {
            o["expect_revision"] = expect;
        }
        o
    };
    check(&py, "ok", "plain", "edit", json!({"address": "0x402000", "options": options(json!(4), "fresh")}));
    check(&py, "missing_expect", "plain", "edit", json!({"address": "0x402000", "options": options(Value::Null, "fresh")}));
    // an older revision whose later edits touched other subjects is rebased; one whose subject moved is a conflict
    check(&py, "rebased", "plain", "edit", json!({"address": "0x402000", "options": options(json!(2), "fresh")}));
    check(&py, "conflict", "plain", "edit", json!({"address": format!("0x{:x}", 0x401000 + 3 * 16), "options": options(json!(2), "fresh")}));
    check(&py, "stale_view", "stale", "edit", json!({"address": "0x402000", "options": options(json!(4), "fresh")}));
    check(&py, "bad_address", "plain", "edit", json!({"address": "zz", "options": options(json!(4), "fresh")}));
    check(&py, "no_address", "plain", "edit", json!({"address": "", "options": options(json!(4), "fresh")}));
}

#[test]
fn add_proposals_matches_python() {
    let Some(py) = python() else { return };
    let records = json!([
        {"id": "a".repeat(32), "address": "0x403000", "options": {"kind": "rename", "source": "t", "name": "p1"}, "source_id": "s1", "source_by": {"client": "x"}, "source_at": 2.5},
        {"id": "b".repeat(32), "address": "0x403010", "options": {"kind": "rename", "source": "t", "name": "p2"}},
    ]);
    let from = json!({"bundle": "bundle-1", "sha256": "ff"});
    check(&py, "ok", "plain", "add", json!({"records": records, "expect": 4, "from": from}));
    check(&py, "missing_expect", "plain", "add", json!({"records": records, "expect": null, "from": from}));
    check(&py, "rebased", "plain", "add", json!({"records": records, "expect": 3, "from": from}));
    check(&py, "stale_view", "stale", "add", json!({"records": records, "expect": 4, "from": from}));
}

// ---- the base generation ---------------------------------------------------------------------------------------

const PY_BASE: &str = r#"
import sys, json
from hydralysis import workcopy
root, selected, mode = sys.argv[1], json.loads(sys.argv[2]), sys.argv[3]
settings = {"root": root}
store = workcopy.load_store(settings, selected)
try:
    out = {"base": workcopy.base_master_gpr(settings, selected, store), "read": workcopy.read_gpr(settings, selected)}
except Exception as e:
    out = {"raised": str(e)}
print(json.dumps(out))
"#;

#[test]
fn base_master_gpr_and_read_gpr_match_python() {
    let Some(py) = python() else { return };
    // (case, store base generation, log lines for the base generation, make the project, make the manifest, tamper)
    let cases = [
        ("head", 3, "none", false, false, false),
        ("behind_ok", 1, "line", true, true, false),
        ("behind_no_line", 1, "none", false, false, false),
        ("behind_project_gone", 1, "line", false, false, false),
        ("behind_no_manifest", 1, "line", true, false, false),
        ("behind_sealed_other", 1, "line", true, true, true),
        ("generation_zero_logged", 0, "zero", true, false, false),
        ("generation_zero_missing", 0, "none", false, false, false),
    ];
    for (name, generation, lines, project, manifest, tamper) in cases {
        let dir = tempfile::Builder::new().prefix("hsb").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let base = dir.path();
        let build = |root: &Path| {
            std::fs::create_dir_all(root).unwrap();
            let s = settings(root);
            let origin = base.join("g0").join("p.gpr");
            gens::append_current(&s, L, json!({"gen": 0, "reason": "origin", "gpr": "G0"}).as_object().unwrap(), false).ok();
            let _ = origin;
            let g1 = generation_dir(&s, L, 1).unwrap();
            let gpr = g1.join("p.gpr");
            let mut line = json!({"gen": 1, "reason": "commit", "gpr": gpr.display().to_string()});
            if project {
                std::fs::create_dir_all(&g1).unwrap();
                std::fs::write(&gpr, b"x").unwrap();
            }
            if manifest {
                write_manifest(&g1, json!({"cid": "c", "via": "publish"}).as_object().unwrap()).unwrap();
                line["manifestSha256"] = json!(if tamper { "0".repeat(64) } else { manifest_file_sha256(&g1).unwrap() });
            }
            if lines == "line" {
                gens::append_current(&s, L, line.as_object().unwrap(), false).unwrap();
            }
            let mut t = selected();
            t.insert("gpr".into(), json!("HEAD.gpr"));
            let mut st = store::load_store(&s, &t).unwrap();
            st.insert("base".into(), json!({"lineage": L, "generation": generation}));
            st.insert("edits".into(), json!([rec(1)]));
            st.insert("revision".into(), json!(1));
            store::save_store(&s, &t, &st).unwrap();
        };
        let (root_a, root_b) = (base.join("ra"), base.join("rb"));
        build(&root_a);
        build(&root_b);
        let mut t = selected();
        t.insert("gpr".into(), json!("HEAD.gpr"));
        let s = settings(&root_a);
        let st = store::load_store(&s, &t).unwrap();
        let mut mine = match workcopy::base_master_gpr(&s, &t, &st) {
            Ok(g) => match workcopy::read_gpr(&s, &t) {
                Ok(r) => json!({"base": g, "read": r}),
                Err(e) => json!({"raised": e.to_string()}),
            },
            Err(e) => json!({"raised": e.to_string()}),
        };
        let out = run_py(&py, PY_BASE, &[root_b.to_str().unwrap(), &Value::Object(t).to_string(), name]);
        let mut theirs: Value = serde_json::from_str(&out).unwrap();
        let (a, b) = (root_a.to_str().unwrap(), root_b.to_str().unwrap());
        let escaped = |t: &str| t.replace('\\', "\\\\");
        let roots = [a, b, &escaped(a), &escaped(b)];
        normalise(&mut mine, &roots);
        normalise(&mut theirs, &roots);
        // Python compares the project path text it read from the log; both log the same path under their own root.
        assert_eq!(mine, theirs, "case {name}");
        if name == "behind_ok" {
            assert!(mine["base"].as_str().unwrap().ends_with("p.gpr"));
        }
    }
}

// ---- helpers on generated input -------------------------------------------------------------------------------------

#[test]
fn prefix_matches_and_base_key_match_python() {
    let Some(py) = python() else { return };
    let code = r#"
import sys, json
from hydralysis import workcopy
cases = json.load(open(sys.argv[1], encoding='utf-8'))
out = []
for c in cases:
    if c["op"] == "prefix":
        out.append(workcopy._prefix_matches(c["records"], c["marker"], c["wanted"]))
    elif c["op"] == "same":
        out.append(workcopy._same_base(c["record"], c["wanted"]))
    elif c["op"] == "key":
        out.append(workcopy.base_key(c["target"], c["binding"], {"revision": c["master"]}, c["release"]))
print(json.dumps(out))
"#;
    let recs: Vec<Value> = (1..=5).map(rec).collect();
    let mut cases: Vec<Value> = Vec::new();
    let mut store = store::empty_store(&"ab".repeat(32));
    store.insert("edits".into(), json!(recs));
    store.insert("revision".into(), json!(5));
    let good = store::state_of(&store);
    let ids: Vec<&str> = recs.iter().map(|r| r["id"].as_str().unwrap()).collect();
    let digest = |n: usize| store::digest_of(&ids[..n]);
    let bases = [json!({"lineage": "", "generation": 0}), json!({"lineage": "L-1", "generation": 2}), json!({"lineage": "", "generation": 1})];
    for n in [0usize, 1, 3, 5, 6] {
        for committed in [json!(store::digest_of::<String>(&[])), json!("x"), Value::Null] {
            for base in std::iter::once(Value::Null).chain(bases.iter().cloned()) {
                let mut marker = json!({"revision": 5, "edits": n, "ids_sha256": digest(n.min(5))});
                if !base.is_null() {
                    marker["base"] = base.clone();
                }
                if !committed.is_null() {
                    marker["committed_sha256"] = committed.clone();
                }
                let mut wanted = good.clone();
                for w in &bases {
                    wanted["base"] = w.clone();
                    cases.push(json!({"op": "prefix", "records": recs, "marker": marker, "wanted": wanted}));
                }
                cases.push(json!({"op": "prefix", "records": recs, "marker": marker, "wanted": null}));
            }
        }
    }
    for odd in [json!(true), json!(1.0), json!("1"), json!(-1)] {
        cases.push(json!({"op": "prefix", "records": recs, "marker": {"edits": odd}, "wanted": null}));
    }
    cases.push(json!({"op": "prefix", "records": recs, "marker": {}, "wanted": good}));
    cases.push(json!({"op": "prefix", "records": recs, "marker": null, "wanted": good}));
    for record in [Value::Null, json!({}), json!({"lineage": "L-1", "generation": 2}), json!({"lineage": "L-1", "generation": 2.0}), json!({"lineage": null, "generation": null})] {
        for wanted in &bases {
            cases.push(json!({"op": "same", "record": record, "wanted": wanted}));
        }
    }
    let t = json!({"key": "k1", "origin_key": "o1"});
    let t2 = json!({"key": "k1"});
    for target in [&t, &t2] {
        for binding in [Value::Null, json!({}), json!({"lineage": "L", "generation": 4})] {
            for release in [Value::Null, json!({"hydraVersion": "1.2", "ghidraVersion": "12.0"})] {
                cases.push(json!({"op": "key", "target": target, "binding": binding, "master": 7, "release": release}));
                cases.push(json!({"op": "key", "target": target, "binding": binding, "master": null, "release": release}));
            }
        }
    }
    let scratch = tempfile::Builder::new().prefix("hsc").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let file = scratch.path().join("cases.json");
    std::fs::write(&file, Value::Array(cases.clone()).to_string()).unwrap();
    let out: Value = serde_json::from_str(&run_py(&py, code, &[file.to_str().unwrap()])).unwrap();
    for (case, theirs) in cases.iter().zip(out.as_array().unwrap()) {
        let mine = match case["op"].as_str().unwrap() {
            "prefix" => {
                let records = case["records"].as_array().unwrap();
                let marker = Some(&case["marker"]).filter(|m| !m.is_null());
                let wanted = Some(&case["wanted"]).filter(|m| !m.is_null());
                json!(workcopy::prefix_matches(records, marker, wanted))
            }
            "same" => json!(workcopy::same_base(Some(&case["record"]).filter(|m| !m.is_null()), &case["wanted"])),
            _ => {
                let binding = Some(&case["binding"]).filter(|m| !m.is_null());
                json!(workcopy::base_key(case["target"].as_object().unwrap(), binding, &case["master"], &case["release"]))
            }
        };
        assert_eq!(&mine, theirs, "case {case}");
    }
}

#[test]
fn file_stores_and_forget_current_match_python() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new().prefix("hsf").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let (a, b) = (dir.path().join("a"), dir.path().join("b"));
    std::fs::create_dir_all(&a).unwrap();
    std::fs::create_dir_all(&b).unwrap();
    let source = dir.path().join("source.bin");
    let payload: Vec<u8> = (0..(9u32 * 1024 * 1024)).map(|i| (i % 251) as u8).collect();
    std::fs::write(&source, &payload).unwrap();
    // working copies on disk for a view, a state file naming some of them
    let t = json!({"key": "k1", "sha256": "x"}).as_object().unwrap().clone();
    for root in [&a, &b] {
        for (folder, name) in [("k1", "w-1"), ("k1", "w-2"), ("k1r", "w-3"), ("k1", "x-4")] {
            let gpr = root.join("working").join(folder).join(name).join("p.gpr");
            std::fs::create_dir_all(gpr.parent().unwrap()).unwrap();
            std::fs::write(&gpr, b"x").unwrap();
        }
        let current = root.join("working").join("k1").join("w-1").join("p.gpr").display().to_string();
        let retired = root.join("working").join("k1").join("w-9").join("p.gpr").display().to_string();
        hy_core::sealed::write_sealed_default(
            &root.join("working").join("k1").join("state.json"),
            &json!({"fork_gpr": current, "state": "{}", "retired": [retired], "last_sync": {"n": 1}}),
        )
        .unwrap();
    }
    let code = r#"
import sys, json
from pathlib import Path
from hydralysis import workcopy
root, source = sys.argv[1], sys.argv[2]
settings = {"root": root}
target = {"key": "k1", "sha256": "x"}
out = {}
out["corpus"] = list(workcopy.store_corpus(settings, source))
out["archive"] = list(workcopy.store_archive(settings, source))
out["forks"] = [str(p) for p in workcopy._forks_on_disk(settings, target)]
cur = str(Path(root) / "working" / "k1" / "w-1" / "p.gpr")
out["superseded"] = workcopy.superseded_forks(settings, target, [cur])
out["superseded_all"] = workcopy.superseded_forks(settings, target, [], [cur.upper()])
workcopy._forget_current(settings, target, [cur.upper()], None)
out["state"] = json.loads((Path(root) / "working" / "k1" / "state.json").read_text())
workcopy._forget_current(settings, target, [], [cur])
out["state2"] = json.loads((Path(root) / "working" / "k1" / "state.json").read_text())
print(json.dumps(out))
"#;
    let theirs: Value = serde_json::from_str(&run_py(&py, code, &[b.to_str().unwrap(), source.to_str().unwrap()])).unwrap();
    let s = settings(&a);
    let state_file = |root: &Path| -> Value {
        let mut v = hy_core::sealed::read_sealed(&root.join("working").join("k1").join("state.json")).unwrap();
        v.as_object_mut().unwrap().remove("seal");
        v
    };
    let mut mine = json!({});
    let (digest, size) = workcopy::store_corpus(&s, &source).unwrap();
    mine["corpus"] = json!([digest, size]);
    let (digest, size) = workcopy::store_archive(&s, &source).unwrap();
    mine["archive"] = json!([digest, size]);
    mine["forks"] = json!(workcopy::forks_on_disk(&s, &t).iter().map(|p| workcopy::shown(p)).collect::<Vec<_>>());
    let cur = workcopy::shown(&a.join("working").join("k1").join("w-1").join("p.gpr"));
    mine["superseded"] = json!(workcopy::superseded_forks(&s, &t, std::slice::from_ref(&cur), &[]).unwrap());
    mine["superseded_all"] = json!(workcopy::superseded_forks(&s, &t, &[], &[cur.to_uppercase()]).unwrap());
    workcopy::forget_current(&s, &t, &[cur.to_uppercase()], None).unwrap();
    mine["state"] = state_file(&a);
    workcopy::forget_current(&s, &t, &[], Some(std::slice::from_ref(&cur))).unwrap();
    mine["state2"] = state_file(&a);
    let (ra, rb) = (a.to_str().unwrap(), b.to_str().unwrap());
    let escaped = |t: &str| t.replace('\\', "\\\\");
    let roots = [ra, rb, &escaped(ra), &escaped(rb)];
    let mut theirs = theirs;
    for state in ["state", "state2"] {
        theirs[state].as_object_mut().unwrap().remove("seal");
    }
    normalise(&mut mine, &roots);
    normalise(&mut theirs, &roots);
    assert_eq!(mine, theirs);
}
