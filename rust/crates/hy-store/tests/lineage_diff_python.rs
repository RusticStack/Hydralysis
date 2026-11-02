//! Differential tests against the Python implementation (`src/hydralysis`) for lineage / backups / runtime_events:
//! the same inputs go through both and the results / on-disk bytes are compared. Skipped (with a note) when
//! `C:\Python315\python.exe` (or HY_PYTHON) is absent.

mod common;

use common::{FakeEngine, World, temp, write};
use hy_store::{backups, events, lineage};
use serde_json::{Map, Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn python() -> Option<PathBuf> {
    let candidate = std::env::var("HY_PYTHON").map_or_else(|_| PathBuf::from(r"C:\Python315\python.exe"), PathBuf::from);
    candidate.is_file().then_some(candidate)
}

fn src() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../src").canonicalize().unwrap()
}

fn strip(path: &Path) -> String {
    path.to_string_lossy().trim_start_matches(r"\\?\").to_string()
}

/// Run one Python storage operation (tests/py/diff.py) and parse its JSON answer.
fn py(op: &str, args: &Value) -> Option<Value> {
    let exe = python()?;
    let helper = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/py/diff.py");
    let file = tempfile::Builder::new().suffix(".json").tempfile_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    fs::write(file.path(), args.to_string()).unwrap();
    let output = Command::new(exe)
        .arg(helper)
        .arg(strip(&src()))
        .arg(op)
        .arg(format!("@{}", file.path().display()))
        .env("PYTHONIOENCODING", "utf-8")
        .env_remove("HYDRALYSIS_TEST_FAULT")
        .output()
        .unwrap();
    assert!(output.status.success(), "python {op} failed: {}", String::from_utf8_lossy(&output.stderr));
    Some(serde_json::from_slice(&output.stdout).unwrap_or_else(|e| panic!("{op}: {e}: {}", String::from_utf8_lossy(&output.stdout))))
}

/// xorshift64*: deterministic, no dependency.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn string(&mut self) -> String {
        let len = self.below(12);
        (0..len)
            .map(|_| match self.below(5) {
                0 => char::from_u32(self.below(0x80) as u32).unwrap(),
                1 => char::from_u32(0xA0 + self.below(0x500) as u32).unwrap(),
                2 => char::from_u32(0x2000 + self.below(0x100) as u32).unwrap(),
                3 => char::from_u32(0x1F300 + self.below(0x300) as u32).unwrap(),
                _ => ['"', '\\', '/', '\n', '\t', '\u{7f}', '\u{1f}', '<'][self.below(8) as usize],
            })
            .collect()
    }

    fn value(&mut self, depth: u32) -> Value {
        match self.below(if depth > 3 { 6 } else { 8 }) {
            0 => Value::Null,
            1 => json!(self.below(2) == 1),
            2 => json!((self.next() as i64) >> self.below(60)),
            3 => {
                let f = f64::from_bits(self.next());
                if f.is_finite() { json!(f) } else { json!(0.25) }
            }
            4 => json!(self.below(1_000_000) as f64 / 8.0),
            5 => Value::String(self.string()),
            6 => Value::Array((0..self.below(4)).map(|_| self.value(depth + 1)).collect()),
            _ => {
                let mut map = Map::new();
                for _ in 0..self.below(4) {
                    map.insert(self.string(), self.value(depth + 1));
                }
                Value::Object(map)
            }
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn canonical_frame_and_record_hash_match_python_on_random_values() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let values: Vec<Value> = (0..400).map(|_| rng.value(0)).collect();
    let objects: Vec<Value> = values.iter().map(|v| json!({"v": v, "n": 1})).collect();
    let Some(canon) = py("canonical_many", &json!({"values": values})) else { return eprintln!("python not found: skipped") };
    for (value, theirs) in values.iter().zip(canon.as_array().unwrap()) {
        assert_eq!(hex(&lineage::canonical(value)), theirs.as_str().unwrap(), "canonical of {value}");
    }
    let frames = py("frame_many", &json!({"values": objects})).unwrap();
    for (value, theirs) in objects.iter().zip(frames.as_array().unwrap()) {
        assert_eq!(hex(&events::frame(value)), theirs.as_str().unwrap(), "frame of {value}");
    }
    let hashes = py("hash_many", &json!({"values": objects})).unwrap();
    for (value, theirs) in objects.iter().zip(hashes.as_array().unwrap()) {
        assert_eq!(events::record_hash(value), theirs.as_str().unwrap(), "hash of {value}");
    }
}

fn awkward_tree(folder: &Path) {
    write(&folder.join("a.gpr"), b"gpr");
    write(&folder.join("P.rep/db.1.gbf"), &b"data".repeat(2000));
    write(&folder.join("P.rep/idata/~index.dat"), b"");
    write(&folder.join("caf\u{e9}/\u{65e5}\u{672c}.bin"), b"x");
    write(&folder.join("sp ace/Upper.TXT"), b"y");
    write(&folder.join("Zed.fork.json"), br#"{"purpose": "generation", "state": "candidate", "n": 1.5}"#);
    write(&folder.join("a.lock"), b"excluded");
    write(&folder.join("projectState"), b"excluded");
    write(&folder.join("projectState2/inner.bin"), b"included");
    write(&folder.join("big.bin"), &vec![7u8; 3 * 1024 * 1024 + 5]);
}

#[test]
fn tree_files_tree_hash_and_manifest_bytes_match_python() {
    let t = temp();
    let (a, b) = (t.path().join("a"), t.path().join("b"));
    awkward_tree(&a);
    awkward_tree(&b);
    let ours = Value::Array(lineage::tree_files(&a).unwrap());
    let Some(theirs) = py("tree_files", &json!({"folder": a.to_string_lossy()})) else { return eprintln!("python not found: skipped") };
    assert_eq!(ours, theirs);
    assert_eq!(json!(lineage::tree_hash(&a).unwrap()), py("tree_hash", &json!({"folder": a.to_string_lossy()})).unwrap());
    let body = json!({"cid": "c-1", "note": "caf\u{e9}", "n": 2});
    lineage::write_manifest(&a, &body).unwrap();
    py("write_manifest", &json!({"folder": b.to_string_lossy(), "body": body})).unwrap();
    assert_eq!(fs::read(a.join("MANIFEST.json")).unwrap(), fs::read(b.join("MANIFEST.json")).unwrap(), "MANIFEST.json bytes");
    assert_eq!(py("verify_manifest", &json!({"folder": a.to_string_lossy()})).unwrap()["ok"], true);
    assert_eq!(lineage::verify_manifest(&b).unwrap()["ok"], true);
    write(&a.join("a.gpr"), b"tampered");
    let theirs = py("verify_manifest", &json!({"folder": a.to_string_lossy()})).unwrap();
    assert_eq!(lineage::verify_manifest(&a).unwrap(), theirs);
}

#[test]
fn current_log_is_readable_and_appendable_by_both() {
    let w = World::new();
    let Some(theirs) = py("ensure", &json!({"settings": w.settings, "target": w.target})) else {
        return eprintln!("python not found: skipped");
    };
    let lid = theirs["id"].as_str().unwrap().to_string();
    let ours = lineage::ensure(&w.settings, &w.target, None).unwrap();
    assert_eq!(ours["id"], json!(lid));
    assert_eq!(Value::Object(ours), theirs);
    for (i, side) in ["rust", "python", "rust", "python"].iter().enumerate() {
        let record = json!({"gen": i + 1, "cid": format!("c-{i:08x}"), "reason": "commit", "gpr": "g\u{e9}", "manifestSha256": "m"});
        if *side == "rust" {
            lineage::append_current(&w.settings, &lid, &record, false).unwrap();
        } else {
            py("append", &json!({"settings": w.settings, "lid": lid, "record": record})).unwrap();
        }
    }
    let rows = lineage::history(&w.settings, &lid).unwrap();
    assert_eq!(rows.iter().map(|r| r["seq"].as_i64().unwrap()).collect::<Vec<_>>(), [1, 2, 3, 4, 5]);
    assert_eq!(Value::Array(rows), py("history", &json!({"settings": w.settings, "lid": lid})).unwrap());
    assert_eq!(Value::Object(lineage::head(&w.settings, &lid).unwrap()), py("head", &json!({"settings": w.settings, "lid": lid})).unwrap());
}

#[test]
fn event_logs_cross_verify_and_counters_match() {
    let t = temp();
    let session = "c".repeat(32);
    let (rust_dir, py_dir) = (t.path().join("rust"), t.path().join("py"));
    let log = events::EventLog::new(&rust_dir, &session);
    for index in 0..30 {
        let message = json!({"type": "send", "payload": {"event": "enter", "hit": index, "text": "caf\u{e9} \u{1F600}", "f": 0.5 * f64::from(index)}});
        log.count_message("hook", &message, false);
        log.record("hook", &message);
    }
    log.marker("capture_start", &json!({"capture": "c1"}));
    log.close();
    let Some(theirs) = py("events_write", &json!({"dir": py_dir.to_string_lossy(), "session": session, "count": 30})) else {
        return eprintln!("python not found: skipped");
    };
    assert_eq!(py("events_verify", &json!({"dir": rust_dir.to_string_lossy(), "session": session})).unwrap()["ok"], true);
    assert_eq!(events::verify_log(&py_dir, &session, None, &BTreeMap::new())["ok"], true);
    assert_eq!(log.counters_copy(), theirs["counters"]);
    let strip_time = |dir: &Path| -> Vec<Value> {
        events::iter_records(&dir.join(events::LOG_NAME))
            .map(|r| {
                let mut r = Value::Object(r.unwrap());
                for key in ["t", "prev", "hash"] {
                    r.as_object_mut().unwrap().remove(key);
                }
                r
            })
            .collect()
    };
    assert_eq!(strip_time(&rust_dir), strip_time(&py_dir));
    let first = |dir: &Path| {
        fs::read_to_string(dir.join(events::LOG_NAME)).unwrap().lines().next().unwrap()[9..].split("\"t\":").next().unwrap().to_string()
    };
    assert_eq!(first(&rust_dir), first(&py_dir));
}

#[test]
fn a_rust_backup_verifies_in_python_and_lists_the_same() {
    let w = World::with_lineage();
    let made =
        backups::make(&w.settings, &FakeEngine::new(), &w.lid, &w.gpr.to_string_lossy(), "pre-commit", "3fa9c2d1aa01bb42", 0, false, None)
            .unwrap();
    let folder = made["backup"]["folder"].as_str().unwrap().to_string();
    let Some(theirs) = py("backup_verify", &json!({"folder": folder})) else { return eprintln!("python not found: skipped") };
    assert_eq!(theirs["ok"], true, "{theirs}");
    assert_eq!(backups::verify(Path::new(&folder)).unwrap(), theirs);
    assert_eq!(
        backups::listing(&w.settings, &w.lid, true).unwrap(),
        py("listing", &json!({"settings": w.settings, "lid": w.lid, "verify_all": true})).unwrap()
    );
    assert_eq!(backups::policy(&w.settings).unwrap(), py("policy", &json!({"settings": w.settings})).unwrap());
}
