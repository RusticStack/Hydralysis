//! Helpers shared by the cross-implementation tests (Python 3.15 is needed; tests skip without it).
#![allow(dead_code)]

use std::path::Path;
use std::process::{Command, Stdio};

use hy_views::layout::Settings;
use hy_views::store::{self, Target};
use serde_json::{Value, json};

pub fn python() -> Option<String> {
    [
        std::env::var("HYDRALYSIS_PYTHON").unwrap_or_default(),
        r"C:\Python315\python.exe".into(),
    ]
    .into_iter()
    .find(|p| !p.is_empty() && Path::new(p).is_file())
}

pub fn src() -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../../src")
        .canonicalize()
        .unwrap()
        .display()
        .to_string()
        .trim_start_matches(r"\\?\")
        .to_string()
}

pub fn run_py(py: &str, code: &str, args: &[&str]) -> String {
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

pub fn copy_dir(from: &Path, to: &Path) {
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

pub fn normalise(v: &mut Value, roots: &[&str]) {
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

pub const L: &str = "L-0000abcd";

pub fn target() -> Target {
    json!({"key": "k1", "sha256": "ab".repeat(32), "name": "prog", "gpr": "x.gpr", "program": "prog", "lineage": {"id": L, "generation": 3, "origin_key": "k1"}})
        .as_object()
        .unwrap()
        .clone()
}

pub fn id(n: usize) -> String {
    format!("{n:032x}")
}

pub fn rec(n: usize) -> Value {
    json!({"id": id(n), "address": format!("0x{:x}", 0x401000 + n * 16), "options": {"kind": "rename", "source": "t", "name": format!("n{n}")}, "seq": n, "by": {"client": "c"}, "at": 1.5,
           "effects": [{"subject": format!("address:0x{:x}", 0x401000 + n * 16), "field": "name", "before": "a", "after": format!("n{n}")}]})
}

pub fn load(root: &Path, base: &Path, target: &Target) -> Value {
    let s: Settings = json!({"root": root.to_str().unwrap()})
        .as_object()
        .unwrap()
        .clone();
    let mut v = Value::Object(store::load_store(&s, target).unwrap());
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

/// Replace the random ids a merge generates by `new-<source id>` (in a store) or `new` (in a result), so two runs compare.
pub fn mask_new_ids(v: &mut Value) {
    if let Some(edits) = v.get_mut("edits").and_then(Value::as_array_mut) {
        for e in edits {
            if let Some(from) = e.get("merged_from").and_then(|m| m["id"].as_str()) {
                let name = format!("new-{from}");
                e["id"] = json!(name);
            }
        }
    }
    if let Some(ids) = v.get_mut("ids").and_then(Value::as_array_mut) {
        ids.iter_mut().for_each(|x| *x = json!("new"));
    }
}

/// The engine, as a table of live values keyed `subject|field`; a rebuilt copy (`fork` programs) answers nothing.
pub struct Fake {
    pub live: std::collections::HashMap<String, Value>,
    pub no_effects: bool,
    pub lineage: Value,
    pub resolved: Target,
}

impl hy_views::views::Host for Fake {
    fn heal(&self, _: &Settings, _: &Target) -> hy_views::Result<bool> {
        Ok(false)
    }
    fn ensure_lineage(&self, _: &Settings, _: &Target) -> hy_views::Result<Value> {
        Ok(self.lineage.clone())
    }
    fn resolve_target(&self, _: &Settings, _: &str) -> hy_views::Result<Target> {
        Ok(self.resolved.clone())
    }
    fn open_program(&self, _: &str, _: &str, _: &str, refresh: bool) -> hy_views::Result<Value> {
        Ok(json!({"fork": refresh}))
    }
    fn probe(
        &self,
        program: &Value,
        pairs: &[hy_views::classify::Pair],
    ) -> hy_views::Result<std::collections::HashMap<hy_views::classify::Pair, Value>> {
        if program["fork"] == true {
            return Ok(Default::default());
        }
        Ok(pairs
            .iter()
            .filter_map(|p| {
                self.live
                    .get(&format!("{}|{}", p.0, p.1))
                    .map(|v| (p.clone(), v.clone()))
            })
            .collect())
    }
    fn sync(
        &self,
        _: &Settings,
        _: &Target,
        _: &store::Store,
        _: i64,
        extra: Option<&[Value]>,
        _: bool,
    ) -> hy_views::Result<Value> {
        let mut effects = serde_json::Map::new();
        if !self.no_effects {
            for r in extra.unwrap_or_default() {
                let address = r["address"].as_str().unwrap_or_default();
                effects.insert(
                    r["id"].as_str().unwrap_or_default().to_string(),
                    json!([{"subject": format!("address:{address}"), "field": "name", "before": "a", "after": r["options"]["name"]}]),
                );
            }
        }
        Ok(
            json!({"fork_gpr": "", "effects": effects, "last_sync": {"n": extra.map_or(0, <[Value]>::len)}}),
        )
    }
    fn abandon_copy(&self, _: &Settings, _: &Target, _: Option<&Value>) {}
    fn adopt_copy(&self, _: &Settings, _: &Target, _: &Value) -> hy_views::Result<()> {
        Ok(())
    }
}

/// The same fake for Python, as a prelude: `live` and `noeffects` come from argv.
pub const PY_FAKE: &str = r#"
import sys, json
from hydralysis import views, workcopy, query
live = json.loads(sys.argv[2])
noeffects = sys.argv[5] == "1"
workcopy.heal = lambda *a, **k: False
def sync(settings, target, store, timeout_s, extra=None, **k):
    eff = {}
    if not noeffects:
        for r in extra or []:
            eff[r["id"]] = [{"subject": "address:" + r["address"], "field": "name", "before": "a", "after": r["options"]["name"]}]
    return {"fork_gpr": "", "effects": eff, "last_sync": {"n": len(extra or [])}}
workcopy._sync = sync
def probe(engine, program, pairs):
    if program.get("fork"):
        return {}
    return {p: live[p[0] + "|" + p[1]] for p in pairs if p[0] + "|" + p[1] in live}
workcopy.probe = probe
query.open_program = lambda engine, gpr, program, sha, refresh=False: {"fork": refresh}
"#;
