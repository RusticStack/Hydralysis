//! Commit options, selection, drift and the intent log against Python on generated cases. Skipped without Python.

use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::{Command, Stdio};

use hy_views::commits;
use hy_views::layout::Settings;
use hy_views::store::empty_store;
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
    child
        .stdin
        .take()
        .unwrap()
        .write_all(stdin.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.success(),
        "python failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

struct Rng(u64);
impl Rng {
    fn next(&mut self, n: u64) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (self.0 >> 33) % n
    }
}

const PY: &str = r#"
import sys, json
from hydralysis import commits
d = json.load(sys.stdin)
out = {"validate": [], "select": [], "drift": [], "later": []}
for o in d["validate"]:
    try:
        out["validate"].append({"ok": commits.validate(o)})
    except ValueError as e:
        out["validate"].append({"err": str(e)})
for c in d["select"]:
    store = c["store"]
    try:
        s, added = commits.select(store, c["only"], c["include"])
        out["select"].append({"ids": [r["id"] for r in s], "added": added})
    except commits.CommitError as e:
        out["select"].append({"err": str(e), "code": e.code, "detail": e.detail})
for c in d["drift"]:
    live = {tuple(k.split("\u0001")): v for k, v in c["live"].items()}
    class E: pass
    # drift_check probes through workcopy.probe; reproduce its use of the live map
    from hydralysis import workcopy
    workcopy.probe = lambda engine, program, pairs, timeout_s=60: {p: live.get(p) for p in pairs}
    out["drift"].append(commits.drift_check(None, {}, c["records"]))
    out["later"].append(sorted(commits._later_dependents(c["records"], set(c["drifted"]))))
print(json.dumps(out))
"#;

#[test]
fn commit_rules_match_python_on_generated_cases() {
    let Some(py) = python() else { return };
    let mut rng = Rng(99);
    let keys = [
        "kind",
        "cid",
        "expect_revision",
        "confirm_one_way_upgrade",
        "on_drift",
        "only",
        "include_dependencies",
        "dry_run",
        "backup",
        "snapshot_budget_s",
        "bogus",
    ];
    let mut validate_cases = Vec::new();
    for _ in 0..400 {
        let mut o = serde_json::Map::new();
        o.insert(
            "kind".into(),
            json!(["commit", "commit_revert", "commit_abort", "x"][rng.next(4) as usize]),
        );
        for k in &keys[1..] {
            if rng.next(3) == 0 {
                let v = match *k {
                    "cid" => [json!("c-1a2b3c4d"), json!("c-xyz"), json!(5)][rng.next(3) as usize]
                        .clone(),
                    "expect_revision" => [json!(0), json!(3), json!(-1), json!(true), json!("1")]
                        [rng.next(5) as usize]
                        .clone(),
                    "on_drift" => {
                        [json!("refuse"), json!("skip"), json!("no")][rng.next(3) as usize].clone()
                    }
                    "only" => [
                        json!({"ids": ["a"]}),
                        json!({"authors": null}),
                        json!({"x": 1}),
                        json!({"ids": [1]}),
                        json!(3),
                    ][rng.next(5) as usize]
                        .clone(),
                    "backup" => {
                        [json!("auto"), json!("b-1"), json!(3)][rng.next(3) as usize].clone()
                    }
                    "snapshot_budget_s" => [
                        json!(1),
                        json!(600),
                        json!(0.5),
                        json!(601),
                        json!(true),
                        json!(20.5),
                    ][rng.next(6) as usize]
                        .clone(),
                    "bogus" => json!(1),
                    _ => [json!(true), json!(false), json!(1)][rng.next(3) as usize].clone(),
                };
                o.insert((*k).into(), v);
            }
        }
        if rng.next(2) == 0 {
            o.insert("expect_revision".into(), json!(rng.next(4)));
        }
        validate_cases.push(Value::Object(o));
    }
    let addrs = ["0x10", "0x20", "0x30"];
    let mut select_cases = Vec::new();
    let mut drift_cases = Vec::new();
    for _ in 0..300 {
        let n = 1 + rng.next(6) as usize;
        let mut edits = Vec::new();
        for i in 0..n {
            let mut r = json!({"id": format!("r{i}"), "seq": i + 1, "address": pick(&addrs, rng.next(3)), "options": {"kind": "rename"},
                               "by": {"harness": pick(&["h1", "h2"], rng.next(2))}, "effects": null});
            if rng.next(3) == 0 {
                r["batch"] = json!(["B1", "B2"][rng.next(2) as usize]);
            }
            edits.push(r);
        }
        let commits_list: Vec<Value> = if rng.next(4) == 0 {
            vec![
                json!({"cid": "c-1", "ids": [format!("r{}", rng.next(n as u64))], "reverted": false}),
            ]
        } else {
            vec![]
        };
        let store = json!({"edits": edits, "commits": commits_list});
        let only = match rng.next(5) {
            0 => Value::Null,
            1 => json!({"ids": [format!("r{}", rng.next(n as u64))]}),
            2 => json!({"ids": ["B1"]}),
            3 => json!({"authors": ["h1"]}),
            _ => json!({"ids": ["zzz"]}),
        };
        select_cases.push(json!({"store": store, "only": only, "include": rng.next(2) == 0}));

        let mut records = Vec::new();
        let mut live = serde_json::Map::new();
        for i in 0..n {
            let effects: Vec<Value> = (0..rng.next(3))
                .map(|_| {
                    let s = format!("s{}", rng.next(3));
                    let before = [Value::Null, json!("a"), json!("b")][rng.next(3) as usize].clone();
                    json!({"subject": if rng.next(8) == 0 { "*".to_string() } else { s }, "field": "name", "before": before, "after": pick(&["a", "b", "c"], rng.next(3))})
                })
                .collect();
            records.push(json!({"id": format!("r{i}"), "seq": i + 1, "address": pick(&addrs, rng.next(3)), "options": {"kind": "rename"}, "effects": effects}));
        }
        for s in 0..3 {
            if rng.next(3) != 0 {
                live.insert(
                    format!("s{s}\u{1}name"),
                    json!(["absent", "a", "b", "c"][rng.next(4) as usize]),
                );
            }
        }
        let drifted: Vec<String> = (0..n)
            .filter(|_| rng.next(4) == 0)
            .map(|i| format!("r{i}"))
            .collect();
        drift_cases.push(json!({"records": records, "live": live, "drifted": drifted}));
    }
    let input = json!({"validate": validate_cases, "select": select_cases, "drift": drift_cases});
    let want: Value = serde_json::from_str(&run_py(&py, PY, &input.to_string(), &[])).unwrap();

    let mut accepted = 0;
    for (i, c) in validate_cases.iter().enumerate() {
        match commits::validate(c) {
            Ok(v) => {
                accepted += 1;
                assert_eq!(
                    json!({"ok": v}),
                    want["validate"][i],
                    "validate case {i}: {c}"
                );
            }
            Err(e) => assert_eq!(
                json!({"err": e.to_string()}),
                want["validate"][i],
                "validate case {i}: {c}"
            ),
        }
    }
    assert!(
        accepted > 10,
        "generator must produce accepted options, got {accepted}"
    );

    let mut refused = 0;
    for (i, c) in select_cases.iter().enumerate() {
        let mut store = empty_store("x");
        store.insert("edits".into(), c["store"]["edits"].clone());
        store.insert("commits".into(), c["store"]["commits"].clone());
        let only = (!c["only"].is_null()).then(|| c["only"].clone());
        let got = match commits::select(&store, only.as_ref(), c["include"].as_bool().unwrap()) {
            Ok((s, added)) => {
                json!({"ids": s.iter().map(|r| r["id"].clone()).collect::<Vec<_>>(), "added": added})
            }
            Err(hy_views::Error::View(v)) => {
                refused += 1;
                json!({"err": v.message, "code": v.code, "detail": v.detail})
            }
            Err(other) => panic!("{other}"),
        };
        assert_eq!(got, want["select"][i], "select case {i}: {c}");
    }
    assert!(
        refused > 10,
        "generator must produce refusals, got {refused}"
    );

    for (i, c) in drift_cases.iter().enumerate() {
        let records = c["records"].as_array().unwrap();
        let live: HashMap<(String, String), Value> = c["live"]
            .as_object()
            .unwrap()
            .iter()
            .map(|(k, v)| {
                let (a, b) = k.split_once('\u{1}').unwrap();
                ((a.to_string(), b.to_string()), v.clone())
            })
            .collect();
        // Python probes only the pairs drift_pairs lists; a missing key reads as None
        let probed: HashMap<(String, String), Value> = commits::drift_pairs(records)
            .into_iter()
            .filter_map(|p| live.get(&p).map(|v| (p, v.clone())))
            .collect();
        assert_eq!(
            Value::Array(commits::drift_verdicts(records, &probed)),
            want["drift"][i],
            "drift case {i}: {c}"
        );
        let drifted: BTreeSet<String> = c["drifted"]
            .as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect();
        let later: Vec<String> = commits::later_dependents(records, &drifted)
            .into_iter()
            .collect();
        assert_eq!(json!(later), want["later"][i], "later case {i}");
    }
}

#[test]
fn intent_logs_agree_across_implementations() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new()
        .prefix("hci")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let root = dir.path().to_str().unwrap();
    let s: Settings = json!({"root": root}).as_object().unwrap().clone();
    let l = "L-0000abcd";
    let one = commits::Intent::new(&s, l, "c-1a2b3c4d", 1).unwrap();
    one.write("PREPARE", serde_json::Map::new()).unwrap();
    one.write(
        "CANDIDATE_RESERVED",
        json!({"generation": 5}).as_object().unwrap().clone(),
    )
    .unwrap();
    let code = r#"
import sys, json
from hydralysis import commits
s = {"root": sys.argv[1]}
l = "L-0000abcd"
intent = commits.Intent(s, l, "c-1a2b3c4d", commits.next_attempt(s, l, "c-1a2b3c4d"))
intent.write("PREPARE", note="py")
print(json.dumps({"attempt": intent.attempt, "last": commits.last_steps(s, l, "c-1a2b3c4d"), "cids": commits.intent_cids(s, l)}))
"#;
    let got: Value = serde_json::from_str(&run_py(&py, code, "", &[root])).unwrap();
    assert_eq!(got["attempt"], 2);
    assert_eq!(got["cids"], json!(["c-1a2b3c4d"]));
    // Rust reads the line Python appended, byte-identical framing
    let mine = commits::last_steps(&s, l, "c-1a2b3c4d").unwrap();
    assert_eq!(mine["attempt"], 2);
    assert_eq!(mine["data"], json!({"note": "py"}));
    assert_eq!(mine["rows"], got["last"]["rows"]);
    assert_eq!(commits::next_attempt(&s, l, "c-1a2b3c4d").unwrap(), 3);
}

fn pick(items: &[&'static str], n: u64) -> &'static str {
    items[n as usize]
}
