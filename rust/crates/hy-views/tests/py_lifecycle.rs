//! Recovery, revert, heal, in-flight ids and abort requests against Python (`commits.recover`, `revert`, `heal`,
//! `in_flight_ids`, `request_abort`). Each scenario is built on disk by the same Rust code in two roots, run by each
//! implementation, and the result, the log, the intent logs and the store must be equal. Skipped without Python.

use std::path::Path;

use hy_views::commits::{Intent, intent_cids, intent_log};
use hy_views::generations::{manifest_file_sha256, write_manifest};
use hy_views::layout::{Settings, generation_dir, lineage_dir};
use hy_views::locks::LaneLock;
use hy_views::store::{self, Target, digest_of};
use hy_views::{Error, gens, lifecycle};
use serde_json::{Map, Value, json};

mod common;
use common::{L, load, normalise, python, rec, run_py, target};

const CID: &str = "c-0000cafe";

fn settings(root: &Path) -> Settings {
    json!({"root": root.to_str().unwrap()}).as_object().unwrap().clone()
}

fn ids12() -> Vec<String> {
    vec![common::id(1), common::id(2)]
}

/// The target with its lineage link (what `targets.resolve` gives a target that has a lineage).
fn selected(generation: i64, reason: &str) -> Target {
    let mut t = store::with_view(&target(), "shared").unwrap();
    t.insert("lineage".into(), json!({"id": L, "origin_key": "k1", "generation": generation, "cid": CID, "reason": reason}));
    t
}

struct Scenario {
    name: &'static str,
    /// recover | revert | heal | in_flight | abort
    op: &'static str,
    options: Value,
    /// Steps of the commit's intent log, from PREPARE to the last one written (empty: no intent log).
    steps: &'static [&'static str],
    /// The commit's CURRENT.log line exists (and its generation folder with a manifest).
    published: bool,
    /// The store holds the commit (finalized): commits entry and base on generation 1.
    finalized: bool,
    /// Something to do to the world after it is built.
    tweak: &'static str,
    link_reason: &'static str,
    link_generation: i64,
    hold_commit_lock: bool,
}

impl Scenario {
    fn new(name: &'static str, op: &'static str) -> Self {
        Self {
            name,
            op,
            options: json!({}),
            steps: &[],
            published: false,
            finalized: false,
            tweak: "",
            link_reason: "commit",
            link_generation: 1,
            hold_commit_lock: false,
        }
    }
}

const ALL_STEPS: [&str; 12] = [
    "PREPARE",
    "BACKUP_DONE",
    "CANDIDATE_RESERVED",
    "FORKED",
    "APPLIED",
    "FILES_FORCED",
    "MANIFEST",
    "VERIFIED",
    "SEALED",
    "PUBLISHED",
    "FINALIZED",
    "ABORTED",
];

fn steps_to(last: &'static str) -> &'static [&'static str] {
    let end = ALL_STEPS.iter().position(|s| *s == last).unwrap() + 1;
    &ALL_STEPS[..end]
}

fn build(root: &Path, base: &Path, sc: &Scenario) {
    let s = settings(root);
    let ldir = lineage_dir(&s, L).unwrap();
    std::fs::create_dir_all(&ldir).unwrap();
    hy_core::sealed::write_sealed_default(&ldir.join("lineage.json"), &json!({"origin_key": "k1"})).unwrap();
    let g0 = base.join(root.file_name().unwrap()).join("g0");
    std::fs::create_dir_all(&g0).unwrap();
    std::fs::write(g0.join("p.gpr"), b"adopted").unwrap();
    let line = |generation: i64, reason: &str, extra: Value| {
        let mut m = json!({"gen": generation, "reason": reason}).as_object().unwrap().clone();
        m.extend(extra.as_object().unwrap().clone());
        m
    };
    gens::append_current(&s, L, &line(0, "origin", json!({"gpr": g0.join("p.gpr").display().to_string()})), false).unwrap();
    let mut sha = String::new();
    if sc.published || sc.finalized {
        let folder = generation_dir(&s, L, 1).unwrap();
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join("p.gpr"), b"generation 1").unwrap();
        let store_facts = json!({"view": if sc.tweak == "other_view" { "agent-z" } else { "shared" }, "ids": ids12(),
                                  "ids_sha256": digest_of(&ids12()), "snapshot": 3, "skipped": [], "subjects": ["address:0x401010"]});
        let body = json!({"cid": CID, "via": "commit", "base": {"generation": 0}, "store": store_facts});
        write_manifest(&folder, body.as_object().unwrap()).unwrap();
        sha = manifest_file_sha256(&folder).unwrap();
        gens::append_current(
            &s,
            L,
            &line(1, "commit", json!({"cid": CID, "gpr": folder.join("p.gpr").display().to_string(), "manifestSha256": sha})),
            false,
        )
        .unwrap();
        if sc.tweak == "tamper" {
            std::fs::write(folder.join("p.gpr"), b"changed behind the manifest").unwrap();
        }
        if sc.tweak == "later_generation" {
            let f2 = generation_dir(&s, L, 2).unwrap();
            std::fs::create_dir_all(&f2).unwrap();
            std::fs::write(f2.join("p.gpr"), b"generation 2").unwrap();
            gens::append_current(
                &s,
                L,
                &line(2, "commit", json!({"cid": "c-0000beef", "gpr": f2.join("p.gpr").display().to_string()})),
                false,
            )
            .unwrap();
        }
        if sc.tweak == "previous_gone" {
            std::fs::remove_file(g0.join("p.gpr")).unwrap();
        }
    }
    if !sc.steps.is_empty() {
        let intent = Intent::new(&s, L, CID, 1).unwrap();
        for step in sc.steps {
            let mut data = Map::new();
            if *step == "PREPARE" {
                data.insert("ids".into(), json!(ids12()));
            }
            if *step == "PUBLISHED" {
                data.insert("gen".into(), json!(1));
            }
            intent.write(step, data).unwrap();
        }
    }
    let sel = selected(1, "commit");
    let mut st = store::load_store(&s, &sel).unwrap();
    let records = [rec(1), rec(2), rec(3)];
    st.insert("revision".into(), json!(3));
    if sc.tweak == "archived" || sc.tweak == "archive_bad" {
        // The commit's records live in the archive; the view holds only record 3.
        st.insert("edits".into(), json!([records[2].clone()]));
        let archive = hy_views::settle::archive_path(&s, &sel, CID);
        let archived_records = json!([records[0].clone(), records[1].clone()]);
        hy_core::sealed::write_sealed_default(
            &archive,
            &json!({"cid": CID, "ids_sha256": digest_of(&ids12()), "records": archived_records}),
        )
        .unwrap();
        let digest = if sc.tweak == "archive_bad" { "00".repeat(32) } else { digest_of(&ids12()) };
        st.insert(
            "archived".into(),
            json!([{"cid": CID, "generation": 1, "count": 2, "ids_sha256": digest, "archive": archive.display().to_string()}]),
        );
        st.insert("base".into(), json!({"lineage": L, "generation": 1}));
    } else {
        st.insert("edits".into(), json!(records));
    }
    if sc.finalized && sc.tweak != "archived" && sc.tweak != "archive_bad" {
        st.insert(
            "commits".into(),
            json!([{"cid": CID, "generation": 1, "snapshot": 3, "ids": ids12(), "skipped": [], "ids_sha256": digest_of(&ids12()),
                    "bundle_sha256": null, "at": 1.5, "reverted": false}]),
        );
        st.insert("base".into(), json!({"lineage": L, "generation": 1}));
    } else if !st.contains_key("base") || sc.tweak.is_empty() {
        st.insert("base".into(), json!({"lineage": L, "generation": 0}));
    }
    if sc.tweak == "reverted_commit" {
        st["commits"] = json!([{"cid": CID, "generation": 1, "snapshot": 3, "ids": ids12(), "skipped": [],
                                "ids_sha256": digest_of(&ids12()), "at": 1.5, "reverted": true}]);
    }
    store::save_store(&s, &sel, &st).unwrap();
    let _ = sha;
}

const PY: &str = r#"
import sys, json
from hydralysis import commits, lineage
from hydralysis.locks import LaneLock
specs = json.loads(sys.argv[1])
results = {}
for spec in specs:
    op, selected, options, L = spec["op"], spec["selected"], spec["options"], spec["lineage"]
    s = {"root": spec["root"]}
    held = None
    if spec["hold"]:
        held = LaneLock(str(lineage.commit_lock_path(s, L)))
        assert held.acquire()
    try:
        if op == "recover":
            out = commits.recover(s, selected, L)
        elif op == "revert":
            out = commits.revert(s, selected, options)
        elif op == "heal":
            out = commits.heal(s, selected)
        elif op == "in_flight":
            out = commits.in_flight_ids(s, selected)
        else:
            out = commits.request_abort(s, selected, options["cid"])
    except commits.CommitError as e:
        out = {"commit_error": e.payload()}
    except RuntimeError as e:
        out = {"runtime": str(e)}
    except Exception as e:
        out = {"raised": str(e)}
    finally:
        if held is not None:
            held.release()
    results[spec["name"]] = out
print(json.dumps(results))
"#;

fn mask(v: &mut Value, roots: &[&str]) {
    normalise(v, roots);
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if matches!(k.as_str(), "at" | "prevHash" | "sealed_at") {
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

fn snapshot(root: &Path, base: &Path) -> Value {
    let s = settings(root);
    let roots = [root.to_str().unwrap(), base.to_str().unwrap()];
    let mut log = json!(gens::history(&s, L).unwrap());
    mask(&mut log, &roots);
    let mut intents = Map::new();
    for cid in intent_cids(&s, L).unwrap() {
        let mut rows = json!(intent_log(&s, L, &cid).unwrap().scan().records);
        mask(&mut rows, &roots);
        intents.insert(cid, rows);
    }
    let mut st = load(root, base, &selected(1, "commit"));
    mask(&mut st, &roots);
    let flag = lineage_dir(&s, L).unwrap().join("commits").join(format!("{CID}.abort"));
    json!({"log": log, "intents": intents, "store": st, "abort_flag": flag.is_file()})
}

fn as_json(result: Result<Value, Error>) -> Value {
    match result {
        Ok(v) => v,
        Err(Error::View(e)) => json!({"commit_error": e.payload()}),
        Err(Error::Runtime(m)) => json!({"runtime": m}),
        Err(e) => json!({"raised": e.to_string()}),
    }
}

fn first_diff(a: &Value, b: &Value, path: &str) -> String {
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for (k, v) in x {
                match y.get(k) {
                    Some(w) if v != w => return first_diff(v, w, &format!("{path}/{k}")),
                    None => return format!("{path}/{k} only in rust"),
                    _ => {}
                }
            }
            for k in y.keys() {
                if !x.contains_key(k) {
                    return format!("{path}/{k} only in python");
                }
            }
            path.to_string()
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (i, (v, w)) in x.iter().zip(y).enumerate() {
                if v != w {
                    return first_diff(v, w, &format!("{path}[{i}]"));
                }
            }
            path.to_string()
        }
        _ => format!("{path}: rust {a} vs python {b}"),
    }
}

fn scenarios() -> Vec<Scenario> {
    let rev = |n: i64| json!({"kind": "commit_revert", "expect_revision": n});
    let revert = |name| Scenario { published: true, finalized: true, options: rev(3), ..Scenario::new(name, "revert") };
    vec![
        Scenario { steps: steps_to("PUBLISHED"), published: true, ..Scenario::new("recover_roll_forward", "recover") },
        Scenario { steps: steps_to("PUBLISHED"), published: true, tweak: "tamper", ..Scenario::new("recover_roll_back", "recover") },
        Scenario { steps: steps_to("VERIFIED"), ..Scenario::new("recover_unpublished_candidate", "recover") },
        Scenario { steps: steps_to("PREPARE"), ..Scenario::new("recover_after_prepare", "recover") },
        Scenario { steps: steps_to("BACKUP_DONE"), ..Scenario::new("recover_backup_kept", "recover") },
        Scenario { steps: steps_to("FINALIZED"), published: true, finalized: true, ..Scenario::new("recover_nothing_to_do", "recover") },
        revert("revert_ok"),
        Scenario { options: rev(99), ..revert("revert_stale_expect") },
        Scenario { tweak: "later_generation", ..revert("revert_not_latest") },
        Scenario { tweak: "other_view", ..revert("revert_wrong_view") },
        Scenario { tweak: "previous_gone", ..revert("revert_previous_gone") },
        Scenario { tweak: "archived", ..revert("revert_rehydrates") },
        Scenario { tweak: "archive_bad", ..revert("revert_archive_mismatch") },
        Scenario { tweak: "reverted_commit", ..revert("revert_of_a_reverted_commit") },
        Scenario { options: rev(3), ..Scenario::new("revert_nothing", "revert") },
        Scenario { hold_commit_lock: true, ..revert("revert_busy") },
        Scenario { steps: steps_to("PUBLISHED"), published: true, ..Scenario::new("heal_rolls_forward", "heal") },
        Scenario { steps: steps_to("PUBLISHED"), published: true, finalized: true, ..Scenario::new("heal_closes_intent", "heal") },
        Scenario {
            published: true,
            finalized: true,
            link_reason: "rollback",
            link_generation: 0,
            ..Scenario::new("heal_finishes_revert", "heal")
        },
        Scenario { published: true, finalized: true, steps: steps_to("FINALIZED"), ..Scenario::new("heal_nothing", "heal") },
        Scenario { steps: steps_to("PUBLISHED"), published: true, hold_commit_lock: true, ..Scenario::new("heal_busy", "heal") },
        Scenario { steps: steps_to("PREPARE"), ..Scenario::new("in_flight_dead_commit", "in_flight") },
        Scenario { steps: steps_to("PREPARE"), hold_commit_lock: true, ..Scenario::new("in_flight_live_commit", "in_flight") },
        Scenario { steps: steps_to("PUBLISHED"), published: true, ..Scenario::new("in_flight_published", "in_flight") },
        Scenario { steps: steps_to("PUBLISHED"), published: true, finalized: true, ..Scenario::new("in_flight_settled", "in_flight") },
        Scenario { options: json!({"cid": CID}), ..Scenario::new("abort_requested", "abort") },
        Scenario { options: json!({"cid": CID}), published: true, ..Scenario::new("abort_too_late", "abort") },
    ]
}

#[test]
fn lifecycle_matches_python() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new().prefix("hlc").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let mut specs = Vec::new();
    let mut rust_results: Vec<(Scenario, Value)> = Vec::new();
    for sc in scenarios() {
        let root_a = dir.path().join(format!("{}-a", sc.name));
        let root_b = dir.path().join(format!("{}-b", sc.name));
        for r in [&root_a, &root_b] {
            std::fs::create_dir_all(r).unwrap();
            build(r, dir.path(), &sc);
        }
        let sel = selected(sc.link_generation, sc.link_reason);
        let s = settings(&root_a);
        let held = sc.hold_commit_lock.then(|| {
            let mut l = LaneLock::new(lineage_dir(&s, L).unwrap().join(".commit.lock"));
            assert!(l.acquire());
            l
        });
        let out = as_json(match sc.op {
            "recover" => lifecycle::recover(&s, &sel, L).map(Value::from),
            "revert" => lifecycle::revert(&s, &sel, &sc.options),
            "heal" => lifecycle::heal(&s, &sel).map(Value::from),
            "in_flight" => lifecycle::in_flight_ids(&s, &sel).map(|m| json!(m)),
            _ => lifecycle::request_abort(&s, &sel, sc.options["cid"].as_str().unwrap()),
        });
        drop(held);
        specs.push(json!({"name": sc.name, "op": sc.op, "root": root_b.to_str().unwrap(), "selected": sel,
                          "options": sc.options, "lineage": L, "hold": sc.hold_commit_lock}));
        rust_results.push((sc, out));
    }
    let out = run_py(&py, PY, &[&Value::Array(specs).to_string()]);
    let py_all: Value = serde_json::from_str(&out).unwrap();
    for (sc, mut rust_out) in rust_results {
        let root_a = dir.path().join(format!("{}-a", sc.name));
        let root_b = dir.path().join(format!("{}-b", sc.name));
        let mut py_out = py_all[sc.name].clone();
        let roots = [root_b.to_str().unwrap(), root_a.to_str().unwrap(), dir.path().to_str().unwrap()];
        mask(&mut rust_out, &roots);
        mask(&mut py_out, &roots);
        if rust_out != py_out {
            panic!("result of {} differs at {}: rust {rust_out} vs python {py_out}", sc.name, first_diff(&rust_out, &py_out, ""));
        }
        let (a, b) = (snapshot(&root_a, dir.path()), snapshot(&root_b, dir.path()));
        if a != b {
            panic!("disk state of {} differs at {}", sc.name, first_diff(&a, &b, ""));
        }
        // The scenarios must reach the outcomes they are named for.
        let error = rust_out["commit_error"]["error"].as_str().unwrap_or_default();
        match sc.name {
            "recover_roll_forward" => assert_eq!(rust_out[0]["action"], "rolled_forward"),
            "recover_roll_back" => assert_eq!(rust_out[0]["action"], "rolled_back"),
            "recover_unpublished_candidate" => {
                assert_eq!(rust_out[0]["reason"], "unpublished_candidate")
            }
            "recover_nothing_to_do" => assert_eq!(rust_out, json!([])),
            "revert_ok" => assert_eq!(rust_out["pending_again"], 2),
            "revert_stale_expect" => assert_eq!(error, "revision_changed"),
            "revert_not_latest" => assert_eq!(error, "not_latest"),
            "revert_wrong_view" => assert_eq!(error, "wrong_view"),
            "revert_previous_gone" => assert_eq!(error, "revert_failed"),
            "revert_rehydrates" => assert_eq!(rust_out["rehydrated"], 2),
            "revert_archive_mismatch" => assert_eq!(error, "archive_unreadable"),
            "revert_nothing" => assert_eq!(error, "nothing_to_revert"),
            "revert_busy" => assert_eq!(error, "commit_busy"),
            "heal_rolls_forward" | "heal_closes_intent" | "heal_finishes_revert" => {
                assert_eq!(rust_out, json!(true), "{}", sc.name)
            }
            "heal_nothing" => assert_eq!(rust_out, json!(false)),
            "heal_busy" => assert!(rust_out.get("runtime").is_some()),
            "in_flight_live_commit" | "in_flight_published" => {
                assert_eq!(rust_out.as_object().unwrap().len(), 2, "{}", sc.name)
            }
            "in_flight_dead_commit" | "in_flight_settled" => assert_eq!(rust_out, json!({})),
            "abort_requested" => assert_eq!(rust_out["requested"], true),
            "abort_too_late" => assert_eq!(error, "cancel_too_late"),
            _ => {}
        }
    }
}
