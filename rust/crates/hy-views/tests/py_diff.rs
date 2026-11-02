//! Differential tests: the Rust classification rule and generation-log helpers against the Python implementation, on
//! generated inputs. Skipped when no Python is found.

use std::collections::HashMap;
use std::path::Path;
use std::process::{Command, Stdio};

use hy_views::classify::{self, Pair};
use hy_views::gens;
use hy_views::layout::Settings;
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

fn case(rng: &mut Rng) -> Value {
    let vals = ["v0", "v1", "v2", "v3", "absent"];
    let subjects = ["s0", "s1", "s2", "*"];
    let fields = ["f0", "f1"];
    let mut records = Vec::new();
    for r in 0..(1 + rng.next(6)) {
        let n = rng.next(4);
        let effects: Vec<Value> = (0..n)
            .map(|_| {
                let v = |rng: &mut Rng| {
                    let x = vals[rng.next(5) as usize];
                    if x == "absent" && rng.next(2) == 0 { Value::Null } else { json!(x) }
                };
                json!({"subject": subjects[rng.next(4) as usize], "field": fields[rng.next(2) as usize], "before": v(rng), "after": v(rng)})
            })
            .collect();
        let mut rec = json!({"id": format!("r{r}"), "effects": effects});
        if rng.next(8) == 0 {
            rec.as_object_mut().unwrap().remove("effects");
        }
        records.push(rec);
    }
    let mut live = Vec::new();
    for s in &subjects[..3] {
        for f in fields {
            if rng.next(3) != 0 {
                let x = vals[rng.next(4) as usize];
                live.push(json!([
                    s,
                    f,
                    if rng.next(5) == 0 {
                        Value::Null
                    } else {
                        json!(x)
                    }
                ]));
            }
        }
    }
    json!({"records": records, "live": live})
}

#[test]
fn classify_matches_python_on_generated_cases() {
    let Some(py) = python() else { return };
    let mut rng = Rng(0x5eed);
    let cases: Vec<Value> = (0..600).map(|_| case(&mut rng)).collect();
    let code = r#"
import sys, json
from hydralysis import views
out = []
for c in json.load(sys.stdin):
    live = {(a, b): v for a, b, v in c["live"] if v is not None}
    live_all = {(a, b): v for a, b, v in c["live"]}
    verdicts, chain = views.classify(c["records"], live_all)
    out.append({"v": verdicts, "chain": sorted([[a, b, v] for (a, b), v in chain.items()]), "pairs": views.probe_pairs(c["records"])})
print(json.dumps(out))
"#;
    let got: Vec<Value> = serde_json::from_str(&run_py(
        &py,
        code,
        &serde_json::to_string(&cases).unwrap(),
        &[],
    ))
    .unwrap();
    let mut conflicts = 0;
    for (i, (c, want)) in cases.iter().zip(&got).enumerate() {
        let live: HashMap<Pair, Value> = c["live"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|t| !t[2].is_null())
            .map(|t| {
                (
                    (t[0].as_str().unwrap().into(), t[1].as_str().unwrap().into()),
                    t[2].clone(),
                )
            })
            .collect();
        let records = c["records"].as_array().unwrap();
        let (verdicts, chain) = classify::classify(records, &live, None);
        assert_eq!(
            Value::Array(verdicts.clone()),
            want["v"],
            "case {i}: {}",
            serde_json::to_string(c).unwrap()
        );
        conflicts += verdicts
            .iter()
            .filter(|v| v["outcome"] == "conflict")
            .count();
        let mut chain: Vec<Value> = chain
            .into_iter()
            .map(|((a, b), v)| json!([a, b, v]))
            .collect();
        chain.sort_by_key(|v| v.to_string());
        let mut wc = want["chain"].as_array().unwrap().clone();
        wc.sort_by_key(|v| v.to_string());
        assert_eq!(chain, wc, "case {i} chain");
        let pairs: Vec<Value> = classify::probe_pairs(records)
            .into_iter()
            .map(|(a, b)| json!([a, b]))
            .collect();
        assert_eq!(Value::Array(pairs), want["pairs"], "case {i} pairs");
    }
    assert!(
        conflicts > 50,
        "generator must exercise conflicts, got {conflicts}"
    );
}

const L: &str = "L-0000abcd";

#[test]
fn current_log_and_master_ids_agree_across_implementations() {
    let Some(py) = python() else { return };
    let dir = tempfile::Builder::new()
        .prefix("hd")
        .tempdir_in(env!("CARGO_TARGET_TMPDIR"))
        .unwrap();
    let root = dir.path();
    let s: Settings = json!({"root": root.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone();
    let mk = |n: u32, store: Value| {
        let f = root.join(format!("g{n}"));
        std::fs::create_dir_all(&f).unwrap();
        std::fs::write(f.join("MANIFEST.json"), json!({"store": store}).to_string()).unwrap();
        f.join("p.gpr").display().to_string()
    };
    let g1 = mk(
        1,
        json!({"ids": ["e1"], "subjects": ["s1"], "view": "alice"}),
    );
    let g2 = mk(
        2,
        json!({"ids": ["e2"], "merged_from_ids": ["m9"], "subjects": ["s2"]}),
    );
    // Rust appends two lines, Python a third; both read back all.
    gens::append_current(
        &s,
        L,
        json!({"gen": 0, "reason": "origin", "gpr": "x/p.gpr"})
            .as_object()
            .unwrap(),
        false,
    )
    .unwrap();
    gens::append_current(&s, L, json!({"gen": 1, "reason": "commit", "gpr": g1, "cid": "c-0001", "changesets": [{"csid": "c-0000000000000aaa", "view": "alice"}]}).as_object().unwrap(), false).unwrap();
    let code = r#"
import sys, json
from hydralysis import lineage, views
s = {"root": sys.argv[1]}
lineage.append_current(s, "L-0000abcd", {"gen": 2, "reason": "commit", "gpr": sys.argv[2], "cid": "c-0002"})
head = lineage.head(s, "L-0000abcd")
print(json.dumps({"head": head, "ids": sorted(views.master_ids(s, "L-0000abcd")), "ids1": sorted(views.master_ids(s, "L-0000abcd", 1)),
                  "editors": views.editors_since(s, "L-0000abcd", 0), "live": [r["gen"] for r in views.live_generations(s, "L-0000abcd")]}))
"#;
    let want: Value =
        serde_json::from_str(&run_py(&py, code, "", &[root.to_str().unwrap(), &g2])).unwrap();
    let head = gens::head(&s, L).unwrap();
    assert_eq!(Value::Object(head), want["head"]);
    let ids: Vec<String> = gens::master_ids(&s, L, 0).unwrap().into_iter().collect();
    assert_eq!(json!(ids), want["ids"]);
    let ids1: Vec<String> = gens::master_ids(&s, L, 1).unwrap().into_iter().collect();
    assert_eq!(json!(ids1), want["ids1"]);
    assert_eq!(
        Value::Array(gens::editors_since(&s, L, 0, None).unwrap()),
        want["editors"]
    );
    let live: Vec<i64> = gens::live_generations(&s, L)
        .unwrap()
        .iter()
        .map(|r| r["gen"].as_i64().unwrap())
        .collect();
    assert_eq!(json!(live), want["live"]);
}
