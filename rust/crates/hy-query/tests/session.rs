//! Ports of the engine-facing tests of tests/test_query.py (ClientCap, ProgramsInUse) and
//! tests/test_decompile_e2e.py (Fallback), tests/test_decompile_partial.py (engine_decompile) against a fake engine.

#![allow(clippy::result_large_err)]

use hy_query::session::{
    Engine, EngineError, OpenError, OpenOptions, Registry, accepted, engine_decompile, public,
    reader_lanes, run_script, windows_path,
};
use serde_json::{Map, Value, json};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

const SHA: &str = "abababababababababababababababababababababababababababababababab";

fn busy(resource: &str) -> EngineError {
    let mut d = Map::new();
    d.insert("reason".into(), json!("capacity"));
    d.insert("resource".into(), json!(resource));
    EngineError::new("busy", "held", d, "open_program")
}

/// `CappedEngine` of tests/test_query.py.
struct Capped {
    key: String,
    cap: usize,
    open: Mutex<Vec<String>>,
    calls: Mutex<Vec<(String, Map<String, Value>)>>,
    /// A gate every `open_program` waits on and a refusal it then raises (the threads tests).
    gate: Option<Gate>,
}

struct Gate {
    entered: (Mutex<bool>, Condvar),
    release: (Mutex<bool>, Condvar),
    refuse: bool,
}

impl Gate {
    fn new(refuse: bool) -> Self {
        Self {
            entered: (Mutex::new(false), Condvar::new()),
            release: (Mutex::new(false), Condvar::new()),
            refuse,
        }
    }
    fn set(pair: &(Mutex<bool>, Condvar)) {
        *pair.0.lock().unwrap() = true;
        pair.1.notify_all();
    }
    fn wait(pair: &(Mutex<bool>, Condvar)) -> bool {
        let g = pair.0.lock().unwrap();
        let (g, _) = pair
            .1
            .wait_timeout_while(g, Duration::from_secs(10), |v| !*v)
            .unwrap();
        *g
    }
}

impl Capped {
    fn new() -> Self {
        Self {
            key: "capped|query".into(),
            cap: 4,
            open: Mutex::new(vec![]),
            calls: Mutex::new(vec![]),
            gate: None,
        }
    }
    fn opens(&self) -> usize {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .filter(|c| c.0 == "open_program")
            .count()
    }
    fn closed(&self, program: &str) -> bool {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .any(|(c, f)| c == "close_program" && f.get("program") == Some(&json!(program)))
    }
    fn open_list(&self) -> Vec<String> {
        self.open.lock().unwrap().clone()
    }
}

impl Engine for Capped {
    fn key(&self) -> &str {
        &self.key
    }
    fn call(&self, command: &str, fields: &Map<String, Value>) -> Result<Value, EngineError> {
        self.calls
            .lock()
            .unwrap()
            .push((command.to_string(), fields.clone()));
        let s = |k: &str| fields[k].as_str().unwrap().to_string();
        match command {
            "open_project" => {
                let path = s("path");
                let stem = path
                    .rsplit('/')
                    .next()
                    .unwrap()
                    .trim_end_matches(".gpr")
                    .to_string();
                Ok(json!({"id": format!("p-{stem}"), "gpr": path, "revision": "r"}))
            }
            "open_program" => {
                if let Some(gate) = &self.gate {
                    Gate::set(&gate.entered);
                    Gate::wait(&gate.release);
                    if gate.refuse {
                        return Err(busy("heap"));
                    }
                }
                let key = format!("{}:{}", s("project"), s("path"));
                let mut open = self.open.lock().unwrap();
                if !open.contains(&key) {
                    if open.len() >= self.cap {
                        let mut d = Map::new();
                        d.insert("reason".into(), json!("capacity"));
                        d.insert("resource".into(), json!("client_cap"));
                        return Err(EngineError::new(
                            "busy",
                            "this client has too many programs open",
                            d,
                            "open_program",
                        ));
                    }
                    open.push(key.clone());
                }
                Ok(
                    json!({"key": key, "sha256": SHA, "revision": "r", "functions": 1, "analyzed": true}),
                )
            }
            "close_program" => {
                let mut open = self.open.lock().unwrap();
                let p = s("program");
                match open.iter().position(|k| *k == p) {
                    None => Err(EngineError::new(
                        "no_program",
                        "not open",
                        Map::new(),
                        "close_program",
                    )),
                    Some(i) => {
                        open.remove(i);
                        Ok(json!({"closed": true}))
                    }
                }
            }
            other => panic!("unexpected command {other}"),
        }
    }
}

fn open(
    reg: &Registry,
    engine: &dyn Engine,
    name: &str,
    writable: bool,
) -> Result<hy_query::session::Row, OpenError> {
    reg.open_program(
        engine,
        &format!("C:/views/{name}/{name}.gpr"),
        "/fixture.exe",
        SHA,
        &OpenOptions {
            writable,
            ..Default::default()
        },
    )
}

fn key_of(name: &str) -> String {
    format!("p-{name}:/fixture.exe")
}

// ---- ClientCap ---------------------------------------------------------------------------------------------------

#[test]
fn a_fifth_view_closes_the_least_recently_used_read_only_program() {
    let (reg, engine) = (Registry::new(), Capped::new());
    for n in ["a", "b", "c", "d"] {
        open(&reg, &engine, n, false).unwrap();
    }
    open(&reg, &engine, "a", false).unwrap(); // a cache hit makes "a" the most recently used
    let fifth = open(&reg, &engine, "e", false).unwrap();
    assert_eq!(fifth.key, key_of("e"));
    assert_eq!(engine.open_list(), ["a", "c", "d", "e"].map(key_of));
    assert!(engine.closed(&key_of("b")));
    let mut cached: Vec<String> = reg.rows(&engine.key).into_iter().map(|r| r.key).collect();
    cached.sort();
    let mut want = engine.open_list();
    want.sort();
    assert_eq!(cached, want);
    // the evicted view opens again (and evicts the next oldest), it is not answered from a stale key
    assert_eq!(open(&reg, &engine, "b", false).unwrap().key, key_of("b"));
    assert!(!engine.open_list().contains(&key_of("c")));
}

#[test]
fn a_writable_program_is_never_closed_and_the_refusal_stands_when_nothing_read_only_is_left() {
    let (reg, engine) = (Registry::new(), Capped::new());
    for n in ["w1", "w2", "w3", "w4"] {
        open(&reg, &engine, n, true).unwrap();
    }
    let err = open(&reg, &engine, "r", false).unwrap_err();
    match err {
        OpenError::Engine(e) => assert!(e.at_client_cap() && e.code == "busy"),
        other => panic!("{other:?}"),
    }
    assert!(
        !engine
            .calls
            .lock()
            .unwrap()
            .iter()
            .any(|c| c.0 == "close_program")
    );
    assert_eq!(engine.open_list().len(), 4);
}

#[test]
fn another_busy_is_not_taken_for_the_cap() {
    let reg = Registry::new();
    struct Heap(Capped);
    impl Engine for Heap {
        fn key(&self) -> &str {
            self.0.key()
        }
        fn call(&self, command: &str, fields: &Map<String, Value>) -> Result<Value, EngineError> {
            if command == "open_program" && fields["project"].as_str().unwrap().contains("held") {
                return Err(busy("heap"));
            }
            self.0.call(command, fields)
        }
    }
    let engine = Heap(Capped::new());
    open(&reg, &engine, "a", false).unwrap();
    let err = open(&reg, &engine, "held", false).unwrap_err();
    match err {
        OpenError::Engine(e) => assert_eq!(e.details["resource"], json!("heap")),
        other => panic!("{other:?}"),
    }
    assert_eq!(engine.0.open_list(), [key_of("a")]);
}

// ---- ProgramsInUse -----------------------------------------------------------------------------------------------

/// A read on another thread that holds NAMES until the returned flag is set.
fn read_elsewhere(
    reg: &Arc<Registry>,
    engine: &Arc<Capped>,
    names: &[&'static str],
) -> (std::thread::JoinHandle<()>, Arc<AtomicBool>) {
    let done = Arc::new(AtomicBool::new(false));
    let held = Arc::new(AtomicBool::new(false));
    let (r, e, d, h) = (reg.clone(), engine.clone(), done.clone(), held.clone());
    let names = names.to_vec();
    let t = std::thread::spawn(move || {
        let _hold = r.holding();
        for n in names {
            open(&r, &*e, n, false).unwrap();
        }
        h.store(true, Ordering::SeqCst);
        for _ in 0..2000 {
            if d.load(Ordering::SeqCst) {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    });
    assert!(hy_query::session::wait_until(
        Duration::from_secs(10),
        || held.load(Ordering::SeqCst)
    ));
    (t, done)
}

#[test]
fn a_program_a_read_is_using_is_not_closed_for_the_cap() {
    let (reg, engine) = (Arc::new(Registry::new()), Arc::new(Capped::new()));
    let (t, done) = read_elsewhere(&reg, &engine, &["a"]);
    for n in ["b", "c", "d"] {
        open(&reg, &*engine, n, false).unwrap();
    }
    assert_eq!(open(&reg, &*engine, "e", false).unwrap().key, key_of("e"));
    assert!(
        engine.open_list().contains(&key_of("a")),
        "the oldest row, but a read is running on it"
    );
    assert!(engine.closed(&key_of("b")));
    done.store(true, Ordering::SeqCst);
    t.join().unwrap();
}

#[test]
fn the_marks_end_with_the_read() {
    let (reg, engine) = (Registry::new(), Capped::new());
    {
        let _hold = reg.holding();
        open(&reg, &engine, "a", false).unwrap();
        open(&reg, &engine, "a", false).unwrap();
        assert_eq!(reg.in_use(), vec![(engine.key.clone(), key_of("a"), 2)]);
    }
    assert!(reg.in_use().is_empty());
}

#[test]
fn when_every_read_only_program_is_in_use_the_least_recently_used_is_closed_as_before() {
    let (reg, engine) = (Arc::new(Registry::new()), Arc::new(Capped::new()));
    let (t, done) = read_elsewhere(&reg, &engine, &["a", "b", "c", "d"]);
    assert_eq!(
        open(&reg, &*engine, "e", false).unwrap().key,
        key_of("e"),
        "the open is served, not refused"
    );
    assert!(engine.closed(&key_of("a")));
    done.store(true, Ordering::SeqCst);
    t.join().unwrap();
}

#[test]
fn a_read_holds_its_program_from_the_moment_the_open_hands_it_out() {
    let (reg, engine) = (Arc::new(Registry::new()), Arc::new(Capped::new()));
    for n in ["b", "c", "d"] {
        open(&reg, &*engine, n, false).unwrap();
    }
    let (t, done) = read_elsewhere(&reg, &engine, &["b", "c", "d"]);
    {
        let _hold = reg.holding();
        open(&reg, &*engine, "a", false).unwrap(); // a fresh open; another thread's open comes before this read sends its script
        let (r, e) = (reg.clone(), engine.clone());
        std::thread::spawn(move || open(&r, &*e, "e", false).unwrap())
            .join()
            .unwrap();
        assert!(
            engine.open_list().contains(&key_of("a")),
            "the read's own program was closed under it"
        );
    }
    assert!(engine.closed(&key_of("b")));
    done.store(true, Ordering::SeqCst);
    t.join().unwrap();
}

fn four_threads(refuse: bool) -> (Arc<Registry>, Arc<Capped>, Vec<Result<String, OpenError>>) {
    let reg = Arc::new(Registry::new());
    let mut engine = Capped::new();
    engine.gate = Some(Gate::new(refuse));
    let engine = Arc::new(engine);
    let handles: Vec<_> = (0..4)
        .map(|_| {
            let (r, e) = (reg.clone(), engine.clone());
            std::thread::spawn(move || open(&r, &*e, "a", false).map(|row| row.key))
        })
        .collect();
    let gate = engine.gate.as_ref().unwrap();
    assert!(Gate::wait(&gate.entered));
    std::thread::sleep(Duration::from_millis(200)); // the other three reach the gate of the open in flight
    Gate::set(&gate.release);
    let results = handles.into_iter().map(|h| h.join().unwrap()).collect();
    (reg, engine, results)
}

#[test]
fn threads_opening_one_program_send_one_open() {
    let (_reg, engine, results) = four_threads(false);
    let keys: Vec<String> = results.into_iter().map(Result::unwrap).collect();
    assert_eq!(keys, vec![key_of("a"); 4]);
    assert_eq!(engine.opens(), 1);
}

#[test]
fn threads_waiting_on_a_refused_open_take_its_refusal_instead_of_waiting_again() {
    let (reg, engine, results) = four_threads(true);
    let resources: Vec<String> = results
        .into_iter()
        .map(|r| match r.unwrap_err() {
            OpenError::Engine(e) => e.details["resource"].as_str().unwrap().to_string(),
            other => panic!("{other:?}"),
        })
        .collect();
    assert_eq!(resources, vec!["heap"; 4]);
    assert_eq!(engine.opens(), 1);
    assert_eq!(
        reg.opening(),
        0,
        "the open in flight is forgotten once it ends"
    );
}

#[test]
fn a_refresh_opens_again_after_the_gate() {
    let (reg, engine) = (Registry::new(), Capped::new());
    open(&reg, &engine, "a", false).unwrap();
    reg.open_program(
        &engine,
        "C:/views/a/a.gpr",
        "/fixture.exe",
        SHA,
        &OpenOptions {
            refresh: true,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(engine.opens(), 2);
}

// ---- open_program edges (no Python test; quirks of the original) --------------------------------------------------

#[test]
fn a_wrong_build_is_refused_with_the_original_message() {
    let (reg, engine) = (Registry::new(), Capped::new());
    let err = reg
        .open_program(
            &engine,
            "C:/v/a/a.gpr",
            "/fixture.exe",
            &"cd".repeat(32),
            &OpenOptions::default(),
        )
        .unwrap_err();
    assert_eq!(
        err.to_string(),
        format!(
            "/fixture.exe in C:/v/a/a.gpr reports SHA-256 {SHA}, not the target build {}; nothing was answered",
            "cd".repeat(32)
        )
    );
    assert!(
        reg.rows(&engine.key).is_empty(),
        "nothing is cached for a wrong build"
    );
}

#[test]
fn the_cache_key_is_the_lowercased_windows_spelling_of_the_project() {
    let (reg, engine) = (Registry::new(), Capped::new());
    reg.open_program(
        &engine,
        "C:/Views/A/a.gpr",
        "/fixture.exe",
        SHA,
        &OpenOptions::default(),
    )
    .unwrap();
    reg.open_program(
        &engine,
        "c:\\views\\a\\.\\a.gpr",
        "/fixture.exe",
        SHA,
        &OpenOptions::default(),
    )
    .unwrap();
    assert_eq!(engine.opens(), 1);
    assert_eq!(windows_path("C:/a//b/./c/"), "C:\\a\\b\\c");
    assert_eq!(windows_path(""), ".");
    assert_eq!(windows_path("//srv/share/x"), "\\\\srv\\share\\x");
    assert_eq!(windows_path("rel/x"), "rel\\x");
}

#[test]
fn forget_and_drop_program_remove_rows_of_one_connection() {
    let (reg, engine) = (Registry::new(), Capped::new());
    open(&reg, &engine, "a", false).unwrap();
    open(&reg, &engine, "b", false).unwrap();
    reg.drop_program(&engine.key, &key_of("a"));
    assert_eq!(reg.rows(&engine.key).len(), 1);
    reg.forget("other");
    assert_eq!(reg.rows(&engine.key).len(), 1);
    reg.forget(&engine.key);
    assert!(reg.rows(&engine.key).is_empty());
    open(&reg, &engine, "a", false).unwrap();
    reg.forget_role("cap");
    assert_eq!(
        reg.rows(&engine.key).len(),
        1,
        "a role prefix needs the `|`"
    );
    reg.forget_role("capped");
    assert!(reg.rows(&engine.key).is_empty());
}

#[test]
fn rows_under_a_folder_are_dropped() {
    let dir = std::env::temp_dir().join(format!("hyq-rows-{}", std::process::id()));
    std::fs::create_dir_all(dir.join("keep")).unwrap();
    std::fs::create_dir_all(dir.join("gone")).unwrap();
    let (reg, engine) = (Registry::new(), Capped::new());
    for n in ["keep", "gone"] {
        let gpr = format!("{}/{n}/{n}.gpr", dir.to_string_lossy().replace('\\', "/"));
        reg.open_program(&engine, &gpr, "/fixture.exe", SHA, &OpenOptions::default())
            .unwrap();
    }
    reg.drop_rows_under(&engine.key, &[&dir.join("gone").to_string_lossy()]);
    let left: Vec<String> = reg
        .rows(&engine.key)
        .into_iter()
        .map(|r| r.project.as_str().unwrap().to_string())
        .collect();
    assert_eq!(left, vec!["p-keep"]);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn reader_lanes_and_readers() {
    assert_eq!(reader_lanes(&json!({})), 1);
    assert_eq!(reader_lanes(&json!({"readerLanes": 4})), 4);
    assert_eq!(reader_lanes(&json!({"reader_lanes": 64})), 64);
    assert_eq!(reader_lanes(&json!({"readerLanes": 65})), 1);
    assert_eq!(reader_lanes(&json!({"readerLanes": 0})), 1);
    assert_eq!(reader_lanes(&json!({"readerLanes": true})), 1);
    assert_eq!(reader_lanes(&json!({"readerLanes": 2.0})), 1);
    let reg = Registry::new();
    reg.add_lane("s", 1, "s");
    reg.add_lane("s", 2, "s|lane2");
    assert_eq!(reg.readers("s"), vec!["s", "s|lane2"]);
    assert_eq!(reg.readers("z"), vec!["z"]);
}

// ---- accepted / public ------------------------------------------------------------------------------------------

#[test]
fn credentials_never_enter_a_refusal() {
    let refused = json!({"ok": false, "error": "no", "token": "t", "nested": [{"ipc": 1, "x": 2}], "secret": 3});
    let err = accepted("xrefs", &refused).unwrap_err();
    assert_eq!(err, r#"{"ok": false, "error": "no", "nested": [{"x": 2}]}"#);
    assert_eq!(
        public(&json!({"a": {"token": 1, "b": 2}})),
        json!({"a": {"b": 2}})
    );
}

#[test]
fn an_ok_reply_passes_and_a_decompile_gains_its_summary() {
    let ok = json!({"ok": true, "c": "x"});
    assert_eq!(accepted("xrefs", &ok).unwrap(), ok);
    let d = accepted("decompile", &ok).unwrap();
    assert_eq!(d["c"], json!("x"));
}

// ---- engine_decompile --------------------------------------------------------------------------------------------

struct One {
    calls: Mutex<Vec<(String, Map<String, Value>)>>,
    reply: Result<Value, EngineError>,
}

impl One {
    fn new(reply: Result<Value, EngineError>) -> Self {
        Self {
            calls: Mutex::new(vec![]),
            reply,
        }
    }
}

impl Engine for One {
    fn key(&self) -> &str {
        "one"
    }
    fn call(&self, command: &str, fields: &Map<String, Value>) -> Result<Value, EngineError> {
        self.calls
            .lock()
            .unwrap()
            .push((command.into(), fields.clone()));
        self.reply.clone()
    }
}

fn pieces() -> Value {
    json!({"completed": true, "name": "entry", "entry": "0x140001000", "signature": "int entry(void);", "chars": 5, "c": "int x;",
           "truncated": false, "partial": true, "reason": "non_contiguous_body",
           "fragments": [{"start": "0x140001000", "end": "0x140001038", "class": "code", "decompiled": true},
                         {"start": "0x140001200", "end": "0x14000121f", "class": "data", "decompiled": false}]})
}

const NO_PCODE: &str = "No pcode could be generated at 0x143020480";

fn request() -> Value {
    json!({"action": "decompile", "address": "0x141f6f9b0", "options": {"max_characters": 1000}})
}

#[test]
fn a_script_failure_is_deferred_to_a_job_unless_inline() {
    let engine = One::new(Ok(pieces()));
    let failed = json!({"ok": false, "error": NO_PCODE});
    let err = engine_decompile(&engine, "k", &request(), 30, &failed, false).unwrap_err();
    assert!(err.reason().unwrap().contains("No pcode"));
    assert!(engine.calls.lock().unwrap().is_empty());
}

#[test]
fn inline_the_engine_command_runs_with_a_long_timeout_and_is_labelled() {
    let engine = One::new(Ok(pieces()));
    let failed = json!({"ok": false, "error": NO_PCODE});
    let merged = engine_decompile(&engine, "k", &request(), 30, &failed, true).unwrap();
    let calls = engine.calls.lock().unwrap();
    let (command, fields) = &calls[0];
    assert_eq!(command, "decompile");
    assert_eq!(fields["timeout"], json!(3600));
    assert_eq!(fields["maxChars"], json!(1000));
    assert!(!fields.contains_key("maxResultMb"));
    assert_eq!(merged["ok"], json!(true));
    assert_eq!(merged["fallback"]["via"], json!("engine_decompile"));
    assert!(
        merged["fallback"]["reason"]
            .as_str()
            .unwrap()
            .contains("No pcode")
    );
    assert_eq!(merged["reason"], json!("non_contiguous_body"));
    assert_eq!(merged["fragments"].as_array().unwrap().len(), 2);
}

#[test]
fn explicit_options_reach_the_engine_and_a_slow_answer_defers() {
    let page = json!({"name": "f", "entry": "0x1", "completed": true, "c": "page", "offset": 0, "chars": 9000, "next_offset": 4, "truncated": false});
    let req = json!({"action": "decompile", "address": "0x1",
                     "options": {"max_characters": 10, "max_result_kb": 7, "max_result_mb": 3, "offset": 20}});
    let good = json!({"ok": true, "c": "t"});
    let engine = One::new(Ok(page));
    engine_decompile(&engine, "k", &req, 30, &good, false).unwrap();
    let fields = engine.calls.lock().unwrap()[0].1.clone();
    assert_eq!(
        (
            &fields["maxResultKb"],
            &fields["maxResultMb"],
            &fields["offset"],
            &fields["timeout"]
        ),
        (&json!(7), &json!(3), &json!(20), &json!(35))
    );
    let slow = One::new(Err(EngineError::new(
        "timeout",
        "decompile timed out",
        Map::new(),
        "",
    )));
    assert!(engine_decompile(&slow, "k", &req, 30, &good, false).is_err());
    assert_eq!(
        engine_decompile(&slow, "k", &req, 30, &good, true).unwrap(),
        good
    );
}

#[test]
fn the_command_is_asked_only_when_needed_and_a_refusal_keeps_the_script_answer() {
    let engine = One::new(Ok(pieces()));
    let good = json!({"ok": true, "c": "t"});
    let plain = json!({"action": "decompile", "address": "0x1", "options": {}});
    assert_eq!(
        engine_decompile(&engine, "k", &plain, 5, &good, false).unwrap(),
        good
    );
    let other = json!({"action": "xrefs", "address": "0x1", "options": {"max_result_mb": 1}});
    assert_eq!(
        engine_decompile(&engine, "k", &other, 5, &good, false).unwrap(),
        good
    );
    assert!(engine.calls.lock().unwrap().is_empty());
    let mb2 = json!({"action": "decompile", "address": "0x1", "options": {"max_result_mb": 2}});
    let merged = engine_decompile(&engine, "k", &mb2, 5, &good, false).unwrap();
    assert_eq!(engine.calls.lock().unwrap()[0].1["maxResultMb"], json!(2));
    assert_eq!(merged["reason"], json!("non_contiguous_body"));
    let refuse = One::new(Err(EngineError::new("bad_request", "no", Map::new(), "")));
    assert_eq!(
        engine_decompile(&refuse, "k", &mb2, 5, &good, false).unwrap(),
        good
    );
}

// ---- run_script --------------------------------------------------------------------------------------------------

struct Script {
    output: Value,
    seen: Mutex<Option<Map<String, Value>>>,
    lane: bool,
}

impl Engine for Script {
    fn key(&self) -> &str {
        "s"
    }
    fn supports(&self, name: &str) -> bool {
        self.lane && name == "laneHint"
    }
    fn call(&self, _command: &str, fields: &Map<String, Value>) -> Result<Value, EngineError> {
        *self.seen.lock().unwrap() = Some(fields.clone());
        Ok(self.output.clone())
    }
}

#[test]
fn run_script_takes_the_last_json_line_and_sends_the_quick_lane() {
    let engine = Script {
        output: json!({"output": "noise\n{\"a\": 1}\nmore\n{\"ok\": true}\ntail"}),
        seen: Mutex::new(None),
        lane: true,
    };
    let (answer, raw) = run_script(
        &engine,
        "k",
        &json!({"action": "x"}),
        30,
        None,
        0,
        Some(1.5),
    )
    .unwrap();
    assert_eq!(answer, json!({"ok": true}));
    assert!(raw.get("output").is_some());
    let seen = engine.seen.lock().unwrap().clone().unwrap();
    assert_eq!(seen["lane"], json!("quick"));
    assert_eq!(seen["timeout"], json!(35));
    assert_eq!(seen["wait"], json!(180_000));
    assert_eq!(seen["maxChars"], json!(16_000_000));
    assert_eq!(seen["deadline"], json!(1.5));
    assert_eq!(seen["args"], json!(["{\"action\": \"x\"}"]));
}

#[test]
fn run_script_refuses_an_incomplete_answer_and_a_large_request_without_a_directory() {
    let truncated = Script {
        output: json!({"output": "{\"ok\": true}", "truncated": true}),
        seen: Mutex::new(None),
        lane: false,
    };
    let err = run_script(&truncated, "k", &json!({}), 5, None, 7, None).unwrap_err();
    assert!(
        err.to_string()
            .starts_with("RusticQuery returned no complete answer (truncated=True): ")
    );
    assert_eq!(
        truncated.seen.lock().unwrap().as_ref().unwrap()["wait"],
        json!(7)
    );
    let none = Script {
        output: json!({"output": "no json"}),
        seen: Mutex::new(None),
        lane: false,
    };
    let err = run_script(&none, "k", &json!({}), 5, None, 0, None).unwrap_err();
    assert!(err.to_string().contains("(truncated=None)"));
    let big = json!({"pad": "x".repeat(300_000)});
    assert_eq!(
        run_script(&none, "k", &big, 5, None, 0, None)
            .unwrap_err()
            .to_string(),
        "request too large to send inline"
    );
}

#[test]
fn a_large_request_travels_as_a_file_that_is_removed_after() {
    let dir = std::env::temp_dir().join(format!("hyq-req-{}", std::process::id()));
    let engine = Script {
        output: json!({"output": "{\"ok\": true}"}),
        seen: Mutex::new(None),
        lane: false,
    };
    let big = json!({"pad": "x".repeat(300_000)});
    run_script(&engine, "k", &big, 5, Some(&dir), 0, None).unwrap();
    let arg = engine.seen.lock().unwrap().clone().unwrap()["args"][0]
        .as_str()
        .unwrap()
        .to_string();
    assert!(arg.starts_with('@') && arg.contains("request-"));
    assert_eq!(std::fs::read_dir(&dir).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn splitlines_matches_python_str_splitlines() {
    use hy_query::session::py_splitlines;
    assert_eq!(py_splitlines(""), Vec::<&str>::new());
    assert_eq!(py_splitlines("a\nb\r\nc\rd"), ["a", "b", "c", "d"]);
    assert_eq!(py_splitlines("a\n"), ["a"]);
    assert_eq!(py_splitlines("a\n\nb"), ["a", "", "b"]);
    assert_eq!(
        py_splitlines("x\u{2028}y\u{85}z\x0b\x0c\x1c\x1d\x1e"),
        ["x", "y", "z", "", "", "", ""]
    );
    assert_eq!(py_splitlines("\r\n"), [""]);
    assert_eq!(py_splitlines("\r\r\n"), ["", ""]);
}

#[test]
fn max_characters_is_converted_like_python_int() {
    use hy_query::session::{DecompileError, py_int};
    assert_eq!(py_int(&json!(7)).unwrap(), 7);
    assert_eq!(py_int(&json!(1.9)).unwrap(), 1);
    assert_eq!(py_int(&json!(-1.9)).unwrap(), -1);
    assert_eq!(py_int(&json!(true)).unwrap(), 1);
    assert_eq!(py_int(&json!(" 1_0 ")).unwrap(), 10);
    assert_eq!(py_int(&json!("-3")).unwrap(), -3);
    assert!(
        matches!(py_int(&json!(null)), Err(DecompileError::Type(m)) if m.ends_with("not 'NoneType'"))
    );
    assert!(
        matches!(py_int(&json!([])), Err(DecompileError::Type(m)) if m.ends_with("not 'list'"))
    );
    assert!(
        matches!(py_int(&json!({})), Err(DecompileError::Type(m)) if m.ends_with("not 'dict'"))
    );
    assert!(
        matches!(py_int(&json!("0x10")), Err(DecompileError::Value(m)) if m == "invalid literal for int() with base 10: '0x10'")
    );
    assert!(matches!(
        py_int(&json!("1__0")),
        Err(DecompileError::Value(_))
    ));
    assert!(matches!(py_int(&json!("")), Err(DecompileError::Value(_))));
    assert!(matches!(
        py_int(&json!(u64::MAX)),
        Err(DecompileError::Unsupported(_))
    ));
}
