//! `views.drain` (the leader) against Python. Two views seal changesets; each implementation drains the same queue with the
//! candidate builder replaced by the same fake (Python `_publish_candidate`, Rust `Host::publish_candidate`). The drain result,
//! every record under the lineage folder, the CURRENT.log lines and both views' stores must be equal. Skipped without Python.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use hy_views::layout::{Settings, lineage_dir};
use hy_views::locks::LaneLock;
use hy_views::store::{self, Target};
use hy_views::{gens, publish, views};
use serde_json::{Value, json};

mod common;
use common::{
    Fake, L, PY_CANDIDATE, PY_FAKE, copy_dir, load, normalise, python, rec, run_py, target,
};

fn settings(root: &Path) -> Settings {
    json!({"root": root.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone()
}

fn view_a() -> Target {
    store::with_view(&target(), "shared").unwrap()
}

fn view_b() -> Target {
    store::with_view(&target(), "agent-b").unwrap()
}

fn fake(live: &HashMap<String, Value>, mode: &'static str) -> Fake {
    Fake {
        live: live.clone(),
        no_effects: false,
        lineage: json!({"id": L}),
        resolved: target(),
        mode,
    }
}

/// Generation 0 and two views with two pending records each, both sealed into the queue (csids are random, so the world is
/// built once and copied for each implementation).
fn world(base: &Path, tweak: &str) -> PathBuf {
    let root = base.join("root");
    std::fs::create_dir_all(&root).unwrap();
    let s = settings(&root);
    let line = json!({"gen": 0, "reason": "origin", "gpr": base.join("g0").join("p.gpr").display().to_string()});
    gens::append_current(&s, L, line.as_object().unwrap(), false).unwrap();
    let host = fake(&HashMap::new(), "");
    for (view, records) in [(view_a(), [rec(1), rec(2)]), (view_b(), [rec(3), rec(4)])] {
        let mut st = store::load_store(&s, &view).unwrap();
        st.insert("edits".into(), json!(records));
        st.insert("revision".into(), json!(2));
        st.insert("base".into(), json!({"lineage": L, "generation": 0}));
        store::save_store(&s, &view, &st).unwrap();
        let options = json!({"expect_revision": 2, "confirm_one_way_upgrade": true});
        views::seal_changeset(&host, &s, &view, &options).unwrap();
        // Changeset ids carry microseconds: keep the two apart and in order.
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    if tweak == "corrupt" {
        let pending = lineage_dir(&s, L).unwrap().join("pending");
        let mut files: Vec<_> = std::fs::read_dir(&pending)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        files.sort();
        std::fs::write(&files[0], b"not a changeset").unwrap();
    }
    root
}

const PY: &str = r#"
root = sys.argv[1]
rounds = int(sys.argv[8])
stop = sys.argv[9] or None
hold = sys.argv[10] == "1"
s = {"root": root}
import json as _j
dest = _j.loads(sys.argv[4])
commits._program_of = lambda engine, gpr, target, **k: {"fork": False}
workcopy.retire_copies = lambda *a, **k: None
views.targets.resolve = lambda settings, name: dest
out = []
for _ in range(rounds):
    try:
        out.append(views.drain(s, sys.argv[6], engine=object(), stop_after=stop))
    except Exception as e:
        out.append({"raised": str(e)})
print(json.dumps(out))
"#;

fn mask(v: &mut Value, roots: &[&str]) {
    normalise(v, roots);
    match v {
        Value::Object(m) => {
            for (k, x) in m.iter_mut() {
                if matches!(
                    k.as_str(),
                    "at" | "sealed_at" | "leader" | "build_ms" | "prevHash"
                ) {
                    *x = json!("MASKED");
                } else if k == "message"
                    && x.as_str().is_some_and(|m| m.starts_with("store_corrupt"))
                {
                    // truncated at 300 characters, and the paths in it differ in length between the two worlds
                    *x = json!("store_corrupt");
                } else {
                    mask(x, roots);
                }
            }
        }
        Value::Array(a) => a.iter_mut().for_each(|x| mask(x, roots)),
        _ => {}
    }
}

/// Every file under the lineage folder, as masked content (sealed records) or a hash (everything else), plus the log.
fn snapshot(root: &Path, base: &Path) -> Value {
    let s = settings(root);
    let dir = lineage_dir(&s, L).unwrap();
    let mut out = BTreeMap::new();
    let mut stack = vec![dir.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).into_iter().flatten().flatten() {
            let p = e.path();
            if p.is_dir() {
                stack.push(p);
                continue;
            }
            let rel = p
                .strip_prefix(&dir)
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/");
            let name = e.file_name().to_string_lossy().into_owned();
            if name.ends_with(".lock")
                || name.ends_with(".bak")
                || name == "publish.leader.json"
                || name == "CURRENT.log"
            {
                continue;
            }
            let sealed = ["pending/", "done/", "declined/", "failures/"]
                .iter()
                .any(|d| rel.starts_with(d));
            let value = if sealed {
                let mut v =
                    hy_core::sealed::read_sealed(&p).unwrap_or_else(|_| json!("UNREADABLE"));
                mask(&mut v, &[root.to_str().unwrap(), base.to_str().unwrap()]);
                v
            } else {
                json!(hy_core::sealed::sha256_hex(&std::fs::read(&p).unwrap()))
            };
            out.insert(rel, value);
        }
    }
    let mut log = json!(gens::history(&s, L).unwrap());
    mask(&mut log, &[root.to_str().unwrap(), base.to_str().unwrap()]);
    let mut stores = serde_json::Map::new();
    for (name, t) in [("a", view_a()), ("b", view_b())] {
        let mut v = load(root, base, &t);
        mask(&mut v, &[root.to_str().unwrap(), base.to_str().unwrap()]);
        stores.insert(name.into(), v);
    }
    json!({"files": out, "log": log, "stores": stores})
}

fn drain_json(d: Result<publish::Drained, hy_views::Error>) -> Value {
    match d {
        Ok(d) => json!({"led": d.led, "built": d.built, "failure": d.failure}),
        Err(e) => json!({"raised": e.to_string()}),
    }
}

struct Case {
    name: &'static str,
    tweak: &'static str,
    mode: &'static str,
    live: Vec<(&'static str, &'static str)>,
    rounds: usize,
    stop: &'static str,
    hold: bool,
}

#[test]
fn drain_matches_python() {
    let Some(py) = python() else { return };
    let subj = [
        "address:0x401010",
        "address:0x401020",
        "address:0x401030",
        "address:0x401040",
    ];
    let clean: Vec<_> = subj.iter().map(|s| (*s, "a")).collect();
    let mut conflict = clean.clone();
    conflict[2].1 = "zzz"; // records 3 and 4 (view b): its whole changeset conflicts
    conflict[3].1 = "zzz";
    let converged: Vec<_> = subj
        .iter()
        .enumerate()
        .map(|(i, s)| (*s, ["n1", "n2", "n3", "n4"][i]))
        .collect();
    let case = |name, tweak, mode, live: &Vec<(&'static str, &'static str)>, rounds| Case {
        name,
        tweak,
        mode,
        live: live.clone(),
        rounds,
        stop: "",
        hold: false,
    };
    let cases = vec![
        case("clean_batch", "", "ok", &clean, 1),
        case("conflict_in_batch", "", "ok", &conflict, 1),
        case("converged_all", "", "ok", &converged, 1),
        case("candidate_fails_until_declined", "", "fail", &clean, 4),
        case("corrupt_changeset", "corrupt", "ok", &clean, 1),
        case("reconcile_after_crash", "crashed", "ok", &clean, 1),
        case("tampered_after_crash", "tampered", "ok", &clean, 1),
        Case {
            hold: true,
            ..case("lock_held", "", "ok", &clean, 1)
        },
    ];
    for c in cases {
        let dir = tempfile::Builder::new()
            .prefix("hdr")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap();
        let live: HashMap<String, Value> = c
            .live
            .iter()
            .map(|(s, v)| (format!("{s}|name"), json!(v)))
            .collect();
        let root_a = world(dir.path(), c.tweak);
        let root_b = dir.path().join("rootb");
        copy_dir(&root_a, &root_b);
        for root in [&root_a, &root_b] {
            if c.tweak == "crashed" || c.tweak == "tampered" {
                // A leader that appended its CURRENT.log line and died before it wrote any result (each world has its own
                // paths in the line, so each is crashed on its own).
                let crashed = drain_json(publish::drain(
                    &fake(&live, "append_only"),
                    &settings(root),
                    L,
                    None,
                    30,
                    None,
                ));
                assert!(crashed.get("raised").is_some(), "{crashed}");
                if c.tweak == "tampered" {
                    let gen1 = hy_views::layout::generation_dir(&settings(root), L, 1).unwrap();
                    std::fs::write(gen1.join("p.gpr"), b"changed behind the manifest").unwrap();
                }
            }
        }
        let held = c.hold.then(|| {
            let mut l =
                LaneLock::new(hy_views::layout::publish_lock_path(&settings(&root_a), L).unwrap());
            assert!(l.acquire());
            l
        });
        let mut rust_out = Vec::new();
        for _ in 0..c.rounds {
            rust_out.push(drain_json(publish::drain(
                &fake(&live, c.mode),
                &settings(&root_a),
                L,
                (!c.stop.is_empty()).then_some(c.stop),
                30,
                None,
            )));
        }
        drop(held);
        let held_b = c.hold.then(|| {
            let mut l =
                LaneLock::new(hy_views::layout::publish_lock_path(&settings(&root_b), L).unwrap());
            assert!(l.acquire());
            l
        });
        let code = format!("{PY_FAKE}{PY_CANDIDATE}{PY}");
        let out = run_py(
            &py,
            &code,
            &[
                root_b.to_str().unwrap(),
                &serde_json::to_string(&live).unwrap(),
                "",
                &Value::Object(view_a()).to_string(),
                "0",
                L,
                c.mode,
                &c.rounds.to_string(),
                c.stop,
                if c.hold { "1" } else { "0" },
            ],
        );
        drop(held_b);
        let mut rust_out = Value::Array(rust_out);
        let mut py_out: Value = serde_json::from_str(&out).unwrap();
        let roots = [
            root_b.to_str().unwrap(),
            root_a.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ];
        mask(&mut rust_out, &roots);
        mask(&mut py_out, &roots);
        assert_eq!(rust_out, py_out, "drain results of case {}", c.name);
        let (a, b) = (snapshot(&root_a, dir.path()), snapshot(&root_b, dir.path()));
        if a != b {
            panic!(
                "lineage state of case {} differs at {}",
                c.name,
                first_diff(&a, &b, "")
            );
        }
        // The cases must reach the outcomes they are named for.
        let files = a["files"].as_object().unwrap();
        let done = files.keys().filter(|k| k.starts_with("done/")).count();
        let declined = files.keys().filter(|k| k.starts_with("declined/")).count();
        match c.name {
            "clean_batch" | "reconcile_after_crash" => {
                assert_eq!((done, declined), (2, 0), "{}", c.name)
            }
            "conflict_in_batch" => assert_eq!((done, declined), (1, 1), "{}", c.name),
            "converged_all" | "corrupt_changeset" => assert!(declined >= 1, "{}", c.name),
            "candidate_fails_until_declined" => assert_eq!(declined, 1, "{}", c.name),
            "lock_held" => assert_eq!(rust_out[0]["led"], false),
            "tampered_after_crash" => assert_eq!(rust_out[0]["failure"]["error"], "tampered"),
            _ => {}
        }
    }
}

const PY_JOB: &str = r#"
root = sys.argv[1]
s = {"root": root, "publish_wait_s": float(sys.argv[8])}
selected = json.loads(sys.argv[4])
dest = json.loads(sys.argv[11])
commits._program_of = lambda engine, gpr, target, **k: {"fork": False}
workcopy.retire_copies = lambda *a, **k: None
views.targets.resolve = lambda settings, name: dest
try:
    out = views.run_publish_job(s, selected, {"csid": sys.argv[9], "lineage": sys.argv[6]}, engine=object())
except views.ViewError as e:
    out = {"view_error": e.payload()}
except Exception as e:
    out = {"raised": str(e)}
print(json.dumps(out))
"#;

/// `views.run_publish_job`: the job of one changeset waits for its decision and leads the queue.
#[test]
fn publish_job_matches_python() {
    let Some(py) = python() else { return };
    let subj = [
        "address:0x401010",
        "address:0x401020",
        "address:0x401030",
        "address:0x401040",
    ];
    let clean: Vec<_> = subj.iter().map(|s| (*s, "a")).collect();
    let mut conflict = clean.clone();
    conflict[2].1 = "zzz";
    conflict[3].1 = "zzz";
    // (name, mode, live, which changeset (0 = view a, 1 = view b), publish_wait_s, hold the lock)
    #[allow(clippy::type_complexity)]
    let cases: Vec<(&str, &str, Vec<(&str, &str)>, usize, f64, bool)> = vec![
        ("published", "ok", clean.clone(), 0, 5.0, false),
        ("published_second", "ok", clean.clone(), 1, 5.0, false),
        ("conflict", "ok", conflict, 1, 5.0, false),
        ("candidate_failed", "fail", clean.clone(), 0, 5.0, false),
        ("wait_expired", "ok", clean, 0, 0.4, true),
    ];
    for (name, mode, live_pairs, which, wait, hold) in cases {
        let dir = tempfile::Builder::new()
            .prefix("hjb")
            .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
            .unwrap();
        let live: HashMap<String, Value> = live_pairs
            .iter()
            .map(|(s, v)| (format!("{s}|name"), json!(v)))
            .collect();
        let root_a = world(dir.path(), "");
        let root_b = dir.path().join("rootb");
        copy_dir(&root_a, &root_b);
        let mut csids: Vec<String> =
            std::fs::read_dir(lineage_dir(&settings(&root_a), L).unwrap().join("pending"))
                .unwrap()
                .map(|e| {
                    e.unwrap()
                        .path()
                        .file_stem()
                        .unwrap()
                        .to_string_lossy()
                        .into_owned()
                })
                .collect();
        csids.sort();
        let csid = csids[which].clone();
        let selected = if which == 0 { view_a() } else { view_b() };
        let mut s_a = settings(&root_a);
        s_a.insert("publish_wait_s".into(), json!(wait));
        let held = hold.then(|| {
            let mut l =
                LaneLock::new(hy_views::layout::publish_lock_path(&settings(&root_a), L).unwrap());
            assert!(l.acquire());
            l
        });
        let options = json!({"csid": csid, "lineage": L});
        let mut rust_out = match publish::run_publish_job(
            &fake(&live, mode),
            &s_a,
            &selected,
            options.as_object().unwrap(),
            30,
            None,
        ) {
            Ok(v) => v,
            Err(hy_views::Error::View(e)) => json!({"view_error": e.payload()}),
            Err(e) => json!({"raised": e.to_string()}),
        };
        drop(held);
        let held_b = hold.then(|| {
            let mut l =
                LaneLock::new(hy_views::layout::publish_lock_path(&settings(&root_b), L).unwrap());
            assert!(l.acquire());
            l
        });
        let code = format!("{PY_FAKE}{PY_CANDIDATE}{PY_JOB}");
        let out = run_py(
            &py,
            &code,
            &[
                root_b.to_str().unwrap(),
                &serde_json::to_string(&live).unwrap(),
                "",
                &Value::Object(selected.clone()).to_string(),
                "0",
                L,
                mode,
                &wait.to_string(),
                &csid,
                "0",
                &Value::Object(target()).to_string(),
            ],
        );
        drop(held_b);
        let mut py_out: Value = serde_json::from_str(&out).unwrap();
        let roots = [
            root_b.to_str().unwrap(),
            root_a.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ];
        mask(&mut rust_out, &roots);
        mask(&mut py_out, &roots);
        if name == "wait_expired" {
            // Python defect: `ViewError(..., csid=csid, **pending_info(...))` passes csid twice and raises a TypeError instead
            // of the structured error. The port raises the structured error; the store and queue must still be equal.
            assert!(
                py_out["raised"]
                    .as_str()
                    .is_some_and(|m| m.contains("multiple values")),
                "{py_out}"
            );
            py_out = rust_out.clone();
        }
        if rust_out != py_out {
            panic!(
                "job result of case {name} differs at {}: {rust_out} vs {py_out}",
                first_diff(&rust_out, &py_out, "")
            );
        }
        let (a, b) = (snapshot(&root_a, dir.path()), snapshot(&root_b, dir.path()));
        if a != b {
            panic!(
                "lineage state of job case {name} differs at {}",
                first_diff(&a, &b, "")
            );
        }
        match name {
            "published" | "published_second" => assert_eq!(rust_out["ok"], true, "{name}"),
            "conflict" => assert_eq!(rust_out["view_error"]["error"], "publish_conflict"),
            "candidate_failed" => assert_eq!(rust_out["view_error"]["error"], "candidate_failed"),
            "wait_expired" => assert_eq!(rust_out["view_error"]["error"], "publish_wait_expired"),
            _ => {}
        }
    }
}

/// The first path at which two JSON values differ, with both sides there.
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
