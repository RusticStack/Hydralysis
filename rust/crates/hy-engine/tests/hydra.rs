//! Ports of the tests that specify `hydralysis/hydra.py`'s pure parts (test_client, test_deadline, test_query,
//! test_supervisor, test_trace, test_concurrency) plus the cases the Python suite leaves to the differential tests.

use std::fs;
use std::io::Write;
use std::path::Path;

use hy_engine::failure::{Failure, Kind};
use hy_engine::hydra::{self, ErrorParts, Pins};
use serde_json::{Map, Value, json};

fn pins() -> Pins {
    Pins { release: "12.3-hydra.6".into(), protocol: 3, protocol_min: 2, client_version: "1.1.0".into() }
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        other => panic!("not an object: {other}"),
    }
}

// ---- retry classification (test_client.test_which_commands_are_idempotent, test_trace) -------------------------

#[test]
fn which_commands_are_idempotent() {
    for command in ["hello", "health", "status", "open_project", "open_program", "info", "list", "project", "functions", "decompile"] {
        assert!(hydra::idempotent_command(command), "{command}");
    }
    for command in ["save", "import", "fork_project", "edit", "rename", "comment", "cancel", "analyze", "frobnicate"] {
        assert!(!hydra::idempotent_command(command), "{command}");
    }
}

#[test]
fn trace_reads_may_be_sent_again_and_writes_may_not() {
    for command in ["trace_list", "trace_info", "trace_query", "trace_explain", "trace_diff", "trace_check", "trace_bundle"] {
        assert!(hydra::idempotent_command(command), "{command}");
    }
    for command in [
        "trace_open",
        "trace_append",
        "trace_mark",
        "trace_export",
        "trace_close",
        "trace_resymbolize",
        "trace_reprocess",
        "trace_relations",
        "trace_artifact",
        "trace_evict",
    ] {
        assert!(!hydra::idempotent_command(command), "{command}");
    }
}

#[test]
fn a_script_is_idempotent_only_for_a_read_action() {
    let action = |body: &str| hydra::script_action(body).unwrap();
    assert!(hydra::read_action(&action(&json!({"action": "decompile"}).to_string()).unwrap()));
    assert!(hydra::read_action(&action(&json!({"action": "overlay_state"}).to_string()).unwrap()));
    for name in ["apply_overlays", "type_edit", "anything_new"] {
        assert!(!hydra::read_action(&action(&json!({"action": name}).to_string()).unwrap()), "{name}");
    }
    // no action, a non-string action, a list, a bare string: not an action
    assert_eq!(action("{}"), None);
    assert_eq!(action(&json!({"action": null}).to_string()), None);
    assert_eq!(action(&json!({"action": 4}).to_string()), None);
    assert_eq!(action("[1]"), None);
    assert_eq!(action("\"decompile\""), None);
}

#[test]
fn a_request_file_names_the_action_and_a_missing_one_is_not_an_action() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("request.json");
    fs::write(&file, json!({"action": "decompile"}).to_string()).unwrap();
    let body = format!("@{}", file.display());
    assert_eq!(hydra::script_action(&body).unwrap().as_deref(), Some("decompile"));
    fs::write(&file, json!({"action": "apply_overlays"}).to_string()).unwrap();
    assert_eq!(hydra::script_action(&body).unwrap().as_deref(), Some("apply_overlays"));
    let missing = format!("@{}", dir.path().join("missing.json").display());
    assert_eq!(hydra::script_action(&missing).unwrap(), None);
    // invalid UTF-8 in the file is a ValueError in Python, which the original swallows
    fs::write(&file, [0xff, 0xfe, 0x00]).unwrap();
    assert_eq!(hydra::script_action(&body).unwrap(), None);
}

#[test]
fn json_python_reads_but_serde_does_not_is_left_to_the_original() {
    for body in ["{\"action\": NaN}", "{\"action\": \"x\", \"q\": Infinity}", "{\"action\": \"x\", \"q\": 1e999}"] {
        assert!(matches!(hydra::script_action(body), Err(Failure::Fallback(_))), "{body}");
    }
}

#[test]
fn a_huge_integer_does_not_matter_to_the_action_but_it_does_to_exactness() {
    // the action is read from the same body whatever the integers next to it are
    let body = "{\"action\": \"decompile\", \"n\": 123456789012345678901234567890}";
    assert_eq!(hydra::script_action(body).unwrap().as_deref(), Some("decompile"));
    assert!(hy_engine::pytext::parse_json("{\"n\": 123456789012345678901234567890}").is_err());
    assert!(
        hy_engine::pytext::parse_json("{\"n\": 18446744073709551615, \"m\": -9223372036854775808, \"s\": \"99999999999999999999999\"}")
            .is_ok()
    );
    assert!(hy_engine::pytext::parse_json("[\"a\\\"b\", 99999999999999999999]").is_err());
}

// ---- the engine error text --------------------------------------------------------------------------------------

fn text_of(
    code: &str,
    message: &str,
    details: Value,
    command: &str,
    retry: Option<Value>,
    next: Option<Value>,
    queue: Option<Value>,
) -> String {
    let details = object(details);
    let queue = queue.or_else(|| details.get("queue").cloned());
    hydra::engine_error_text(&ErrorParts {
        code,
        message,
        details: &details,
        command,
        retry_after_ms: retry.as_ref(),
        next: next.as_ref(),
        queue: queue.as_ref(),
    })
    .unwrap()
}

#[test]
fn a_busy_answer_carries_the_holder_the_hold_time_and_the_retry() {
    let text = text_of(
        "busy",
        "locked",
        json!({"holderInfo": {"client": "a", "heldMs": 4200}, "reason": "pool_full", "running": 7}),
        "open_program",
        Some(json!(2500)),
        None,
        None,
    );
    assert_eq!(
        text,
        r#"{"engine_error": "busy", "message": "locked", "command": "open_program", "holderInfo": {"client": "a", "heldMs": 4200}, "reason": "pool_full", "running": 7, "heldMs": 4200, "retryAfterMs": 2500}"#
    );
}

#[test]
fn lists_are_cut_to_five_and_the_cut_is_counted_but_next_and_retry_are_not_cut() {
    let long: Vec<i32> = (0..9).collect();
    let text = text_of(
        "failed",
        "m",
        json!({"alternatives": long, "suggest": {"deep": long}}),
        "script",
        Some(json!(1)),
        Some(json!({"cmd": "x", "args": long})),
        None,
    );
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["alternatives"], json!([0, 1, 2, 3, 4]));
    assert_eq!(parsed["suggest"]["deep"], json!([0, 1, 2, 3, 4]));
    assert_eq!(parsed["more"], json!({"alternatives": 4, "suggest.deep": 4}));
    assert_eq!(parsed["next"]["args"].as_array().unwrap().len(), 9);
}

#[test]
fn the_queue_keeps_sixty_four_entries_and_says_how_many_were_left_out() {
    let waiting: Vec<i32> = (0..70).collect();
    let text = text_of("busy", "m", json!({}), "c", None, None, Some(json!({"waiting": waiting, "position": 3})));
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["queue"]["waiting"].as_array().unwrap().len(), 64);
    assert_eq!(parsed["more"], json!({"queue.waiting": 6}));
}

#[test]
fn a_failed_script_shows_the_tail_of_its_output_and_text_stays_unicode() {
    let output: String = "é".repeat(2500);
    let text = text_of("failed", "ação", json!({"output": output}), "script", None, None, None);
    let parsed: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(parsed["output_tail"].as_str().unwrap().chars().count(), 2000);
    assert!(text.contains("ação"), "ensure_ascii is False");
    // only a `failed` error has the tail
    let other = text_of("busy", "m", json!({"output": "x"}), "c", None, None, None);
    assert!(!other.contains("output_tail"));
    // an output that is not text has a `str()` this port does not model
    let details = object(json!({"output": {"a": 1}}));
    let parts = ErrorParts { code: "failed", message: "m", details: &details, command: "c", retry_after_ms: None, next: None, queue: None };
    assert!(matches!(hydra::engine_error_text(&parts), Err(Failure::Fallback(_))));
}

#[test]
fn held_ms_comes_from_details_then_from_the_holder() {
    let direct = text_of("busy", "m", json!({"heldMs": 5, "holderInfo": {"heldMs": 9}}), "c", None, None, None);
    assert!(direct.contains("\"heldMs\": 5"));
    let nested = text_of("busy", "m", json!({"holderInfo": {"heldMs": 9}}), "c", None, None, None);
    assert!(nested.contains("\"heldMs\": 9"));
    let neither = text_of("busy", "m", json!({"holderInfo": "text"}), "c", None, None, None);
    assert!(!neither.contains("heldMs"));
}

// ---- engine inspection -------------------------------------------------------------------------------------------

/// A jar with `hydra.properties`, as the engine ships it.
fn write_jar(path: &Path, text: &str) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let mut writer = zip::ZipWriter::new(fs::File::create(path).unwrap());
    writer.start_file("hydra.properties", zip::write::SimpleFileOptions::default()).unwrap();
    writer.write_all(text.as_bytes()).unwrap();
    writer.finish().unwrap();
}

fn install(root: &Path, release: Option<&str>, decompiler: bool, application: &str) {
    let ghidra = root.join("Ghidra");
    fs::create_dir_all(&ghidra).unwrap();
    fs::write(ghidra.join("application.properties"), application).unwrap();
    if let Some(release) = release {
        write_jar(
            &ghidra.join("Features").join("HeadlessSession").join("lib").join("HeadlessSession.jar"),
            &format!("hydra.version={release}\n"),
        );
    }
    if decompiler {
        let os = ghidra.join("Features").join("Decompiler").join("os").join("win_x86_64");
        fs::create_dir_all(&os).unwrap();
        fs::write(os.join("decompile.exe"), b"x").unwrap();
    }
}

const APPLICATION: &str = "application.version=12.3\napplication.java.min=21\napplication.java.max=25\n";

#[test]
fn a_pinned_engine_is_ready() {
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), Some("12.3-hydra.6"), true, APPLICATION);
    let report = hydra::inspect_engine(dir.path(), false, &pins()).unwrap();
    assert_eq!(report["ready"], json!(true));
    assert_eq!(report["pinned"], json!(true));
    assert_eq!(report["hydra_release"], json!("12.3-hydra.6"));
    assert_eq!((report["java_min"].clone(), report["java_max"].clone()), (json!(21), json!(25)));
    let keys: Vec<&str> = report.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["component", "path", "ready", "ghidra_version", "hydra_release", "java_min", "java_max", "pinned"]);
}

#[test]
fn not_a_ghidra_install_a_stock_ghidra_another_release_and_a_missing_decompiler_are_refused_by_name() {
    let dir = tempfile::tempdir().unwrap();
    let report = hydra::inspect_engine(dir.path(), false, &pins()).unwrap();
    assert_eq!(report["reason"], json!("not a Ghidra/Hydra install (no Ghidra/application.properties)"));
    assert_eq!(report["ready"], json!(false));
    assert!(report.get("ghidra_version").is_none());

    let stock = tempfile::tempdir().unwrap();
    install(stock.path(), None, true, APPLICATION);
    let report = hydra::inspect_engine(stock.path(), false, &pins()).unwrap();
    assert!(report["reason"].as_str().unwrap().starts_with("a stock Ghidra without Hydra's HeadlessSession module"));
    assert_eq!(report["hydra_release"], Value::Null);

    let older = tempfile::tempdir().unwrap();
    install(older.path(), Some("12.3-hydra.3"), true, APPLICATION);
    let report = hydra::inspect_engine(older.path(), false, &pins()).unwrap();
    assert_eq!(
        report["reason"],
        json!("Hydra Engine 12.3-hydra.3; this Hydralysis pins 12.3-hydra.6 (set hydra_allow_unpinned to try it)")
    );
    let report = hydra::inspect_engine(older.path(), true, &pins()).unwrap();
    assert_eq!((report["ready"].clone(), report["pinned"].clone()), (json!(true), json!(false)));

    let bare = tempfile::tempdir().unwrap();
    install(bare.path(), Some("12.3-hydra.6"), false, APPLICATION);
    let report = hydra::inspect_engine(bare.path(), false, &pins()).unwrap();
    let native = bare.path().join("Ghidra").join("Features").join("Decompiler").join("os");
    assert_eq!(report["reason"], json!(format!("native decompiler missing under {}", native.display())));
}

#[test]
fn java_limits_default_and_a_malformed_one_is_the_original_value_error() {
    let dir = tempfile::tempdir().unwrap();
    install(dir.path(), Some("12.3-hydra.6"), true, "application.version=12.3\n");
    let report = hydra::inspect_engine(dir.path(), false, &pins()).unwrap();
    assert_eq!((report["java_min"].clone(), report["java_max"].clone()), (json!(21), Value::Null));
    let broken = tempfile::tempdir().unwrap();
    install(broken.path(), Some("12.3-hydra.6"), true, "application.version=12.3\napplication.java.min=twenty\n");
    match hydra::inspect_engine(broken.path(), false, &pins()) {
        Err(Failure::Raise(raise)) => {
            assert_eq!(raise.kind, Kind::ValueError);
            assert_eq!(raise.message, "invalid literal for int() with base 10: 'twenty'");
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn the_release_is_read_from_the_jar_and_a_damaged_jar_is_no_release() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(hydra::engine_release(dir.path()), None);
    let jar = dir.path().join("Ghidra/Features/HeadlessSession/lib/HeadlessSession.jar");
    write_jar(&jar, "# comment\nhydra.version=12.3-hydra.6 \nother=1\n");
    assert_eq!(hydra::engine_release(dir.path()).as_deref(), Some("12.3-hydra.6"));
    write_jar(&jar, "x.hydra.version=12.3\n hydra.version=12.3\nhydra.version=\n");
    assert_eq!(hydra::engine_release(dir.path()), None, "an anchored match only, with at least one character");
    fs::write(&jar, b"not a zip").unwrap();
    assert_eq!(hydra::engine_release(dir.path()), None);
}

#[test]
fn properties_keep_quotes_and_skip_comments() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("p.properties");
    fs::write(&file, "a = \"quoted\"\n  # c=1\n#d=2\nno-equals\nb=x=y\na=last\n").unwrap();
    assert_eq!(hydra::properties(&file), vec![("a".to_string(), "last".to_string()), ("b".to_string(), "x=y".to_string())]);
}

// ---- the client library (test_deadline.Negotiation) -------------------------------------------------------------

fn library(protocol: &str, release: &str) -> String {
    format!("PROTOCOL = {protocol}\nCLIENT_VERSION = \"1.1.0\"\nHYDRA_RELEASE = \"{release}\"\n")
}

fn refused(result: Result<hydra::Stamps, Failure>) -> String {
    match result {
        Err(Failure::Raise(raise)) => {
            assert_eq!(raise.kind, Kind::ValueError);
            raise.message
        }
        other => panic!("{other:?}"),
    }
}

#[test]
fn a_pinned_client_must_speak_the_pinned_protocol() {
    assert!(hydra::check_client_text("p", &library("3", "12.3-hydra.6"), false, &pins()).is_ok());
    let message = refused(hydra::check_client_text("p", &library("2", "12.3-hydra.6"), false, &pins()));
    assert_eq!(message, "Hydra client p speaks protocol 2; Hydralysis needs 3");
}

#[test]
fn an_unpinned_client_of_protocol_2_is_accepted_and_protocol_1_is_not() {
    assert!(hydra::check_client_text("p", &library("2", "12.3-hydra.3"), true, &pins()).is_ok());
    assert!(hydra::check_client_text("p", &library("3", "12.3-hydra.4x"), true, &pins()).is_ok());
    let message = refused(hydra::check_client_text("p", &library("1", "12.3-hydra.1"), true, &pins()));
    assert_eq!(message, "Hydra client p speaks protocol 1; Hydralysis needs 2 to 3");
}

#[test]
fn a_pinned_client_must_also_be_the_pinned_release_and_client_version() {
    let message = refused(hydra::check_client_text("p", &library("3", "12.3-hydra.5"), false, &pins()));
    assert_eq!(message, "Hydra client p is release 12.3-hydra.5 / client 1.1.0; this Hydralysis pins 12.3-hydra.6 / 1.1.0");
    let message = refused(hydra::check_client_text("p", "PROTOCOL = 3\n", false, &pins()));
    assert_eq!(message, "Hydra client p is release None / client None; this Hydralysis pins 12.3-hydra.6 / 1.1.0");
}

#[test]
fn a_missing_or_malformed_protocol_stamp_prints_what_was_found() {
    assert_eq!(refused(hydra::check_client_text("p", "", false, &pins())), "Hydra client p speaks protocol None; Hydralysis needs 3");
    assert_eq!(
        refused(hydra::check_client_text("p", "PROTOCOL = x3\n", false, &pins())),
        "Hydra client p speaks protocol x3; Hydralysis needs 3"
    );
    // leading zeros are digits; a number far past every range is refused, not parsed
    assert!(hydra::check_client_text("p", &library("003", "12.3-hydra.6"), false, &pins()).is_ok());
    let huge = "9".repeat(40);
    assert!(refused(hydra::check_client_text("p", &library(&huge, "12.3-hydra.6"), false, &pins())).contains(&huge));
    assert!(matches!(hydra::check_client_text("p", "PROTOCOL = ٣\n", false, &pins()), Err(Failure::Fallback(_))));
}

#[test]
fn stamps_survive_crlf_and_quotes_and_prefixed_names_do_not_match() {
    let text = "PROTOCOL_MIN = 2\r\nPROTOCOL=\"3\"\r\nCLIENT_VERSION = '1.1.0'\r\nHYDRA_RELEASE=12.3-hydra.6\r\n";
    let stamps = hydra::check_client_text("p", text, false, &pins());
    // CLIENT_VERSION is single-quoted, so the quote is part of the value: the pin check refuses it
    assert!(refused(stamps).contains("client '1.1.0'"));
    let plain = "PROTOCOL = 3\r\nCLIENT_VERSION = \"1.1.0\"\r\nHYDRA_RELEASE = \"12.3-hydra.6\"\r\n";
    let stamps = hydra::check_client_text("p", plain, false, &pins()).unwrap();
    assert_eq!(stamps.protocol.as_deref(), Some("3"));
    assert_eq!(stamps.client_version.as_deref(), Some("1.1.0"));
}

// ---- the daemon config (test_query.LaunchConfiguration) ---------------------------------------------------------

fn config(settings: Value) -> Result<Value, Failure> {
    hydra::daemon_config(&object(settings), Path::new(r"C:\data\root"))
}

#[test]
fn defaults_follow_sixteen_expected_agents() {
    let c = config(json!({"root": "r"})).unwrap();
    assert_eq!((c["maxLong"].clone(), c["maxQuick"].clone()), (json!(24), json!(32)));
    assert_eq!(c["idleTimeout"], json!(7200));
    assert_eq!(c["keepWarm"], json!(3600));
}

#[test]
fn the_caps_scale_with_expected_agents_and_never_fall_below_the_floor() {
    let small = config(json!({"expected_agents": 2})).unwrap();
    let large = config(json!({"expected_agents": 40})).unwrap();
    assert_eq!((small["maxLong"].clone(), small["maxQuick"].clone()), (json!(8), json!(16)));
    assert_eq!((large["maxLong"].clone(), large["maxQuick"].clone()), (json!(60), json!(80)));
    // 10 agents: ceil(30 / 2) = 15 and 20 (the launch test)
    let ten = config(json!({"expected_agents": 10})).unwrap();
    assert_eq!((ten["maxLong"].clone(), ten["maxQuick"].clone()), (json!(15), json!(20)));
    // an odd count rounds up: ceil(33 / 2) = 17
    assert_eq!(config(json!({"expected_agents": 11})).unwrap()["maxLong"], json!(17));
}

#[test]
fn an_explicit_hydra_setting_wins_and_keeps_its_place() {
    let c = config(json!({"expected_agents": 16, "hydra": {"maxLong": 5, "maxQuick": 7, "maxImports": 3, "other": 1}})).unwrap();
    assert_eq!((c["maxLong"].clone(), c["maxQuick"].clone(), c["maxImports"].clone()), (json!(5), json!(7), json!(3)));
    assert!(c.get("other").is_none());
    let keys: Vec<&str> = c.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["scriptPath", "tmpdir", "idleTimeout", "keepWarm", "vmargs", "maxLong", "maxQuick", "maxImports"]);
}

#[test]
fn a_bad_count_is_refused() {
    for bad in [json!(0), json!(257), json!(-1), json!(true), json!("16"), json!(1.5)] {
        match config(json!({"expected_agents": bad})) {
            Err(Failure::Raise(raise)) => {
                assert_eq!((raise.kind, raise.message.as_str()), (Kind::ValueError, "expected_agents must be an integer 1..256"), "{bad}");
            }
            other => panic!("{bad}: {other:?}"),
        }
    }
}

#[test]
fn paths_java_and_heap_follow_the_settings() {
    let c = config(json!({"java_home": "C:\\jdk", "hydra_max_heap": "8G", "hydra_idle_s": "60", "hydra_keep_warm_s": 5.9})).unwrap();
    assert_eq!(c["scriptPath"], json!([r"C:\data\root\hydra\scripts", r"C:\data\root\hydra\user-scripts"]));
    assert_eq!(c["tmpdir"], json!(r"C:\data\root\hydra\tmp"));
    assert_eq!(c["java"], json!("C:\\jdk"));
    assert_eq!(c["maxHeap"], json!("8G"));
    assert_eq!((c["idleTimeout"].clone(), c["keepWarm"].clone()), (json!(60), json!(5)));
    assert_eq!(
        c["vmargs"],
        json!([r"-Dapplication.settingsdir=C:\data\root\hydra\ghidra-settings", r"-Dapplication.cachedir=C:\data\root\hydra\ghidra-cache"])
    );
    let keys: Vec<&str> = c.as_object().unwrap().keys().map(String::as_str).collect();
    assert_eq!(keys, ["scriptPath", "tmpdir", "idleTimeout", "keepWarm", "java", "vmargs", "maxHeap", "maxLong", "maxQuick"]);
    // an empty java_home is not set; a number has a str() this port leaves to the original
    assert!(config(json!({"java_home": ""})).unwrap().get("java").is_none());
    assert!(matches!(config(json!({"java_home": 7})), Err(Failure::Fallback(_))));
    // int(None) is a TypeError, the error order is idle, keep-warm, then the agent count
    match config(json!({"hydra_idle_s": null, "expected_agents": 0})) {
        Err(Failure::Raise(raise)) => assert_eq!(raise.kind, Kind::TypeError),
        other => panic!("{other:?}"),
    }
}

// ---- the supervisor's signals -----------------------------------------------------------------------------------

#[test]
fn each_wedge_signal_counts_as_a_miss() {
    let signal = |reply: Value| hydra::wedge_signal(Some(&reply), 30_000).unwrap();
    assert_eq!(signal(json!({"state": "suspect"})), Some("suspect"));
    assert_eq!(signal(json!({"tick": {"ageMs": 31_000}, "watchdogStallMs": 30_000})), Some("tick_stalled"));
    assert_eq!(signal(json!({"schedulerLockOk": false})), Some("scheduler_lock"));
    assert_eq!(signal(json!({"state": "ok", "tick": {"ageMs": 5}, "schedulerLockOk": true})), None);
    assert_eq!(hydra::wedge_signal(None, 30_000).unwrap(), Some("no_answer"));
}

#[test]
fn the_tick_age_is_measured_against_the_replys_own_stall_and_then_the_default() {
    assert_eq!(hydra::wedge_signal(Some(&json!({"tick": {"ageMs": 31_000}})), 30_000).unwrap(), Some("tick_stalled"));
    assert_eq!(hydra::wedge_signal(Some(&json!({"tick": {"ageMs": 30_000}})), 30_000).unwrap(), None, "equal is not stalled");
    assert_eq!(hydra::wedge_signal(Some(&json!({"tick": {"ageMs": 31_000}, "watchdogStallMs": 60_000})), 30_000).unwrap(), None);
    assert_eq!(hydra::wedge_signal(Some(&json!({"tick": {"ageMs": 40_000.5}})), 30_000).unwrap(), Some("tick_stalled"));
    // a boolean is an int in Python, so `True > 0` stalls; a string age is not a number at all
    assert_eq!(hydra::wedge_signal(Some(&json!({"tick": {"ageMs": true}, "watchdogStallMs": 0})), 30_000).unwrap(), Some("tick_stalled"));
    assert_eq!(hydra::wedge_signal(Some(&json!({"tick": {"ageMs": "5"}})), 30_000).unwrap(), None);
    assert_eq!(hydra::wedge_signal(Some(&json!({"tick": 5})), 30_000).unwrap(), None);
    assert!(hydra::wedge_signal(Some(&json!([1])), 30_000).is_err());
}

#[test]
fn patience_is_the_default_or_the_twenty_five_second_budget() {
    assert_eq!(hydra::patience_ms(180_000, false), 180_000);
    assert_eq!(hydra::patience_ms(180_000, true), 25_000);
    assert_eq!(hydra::patience_ms(10_000, true), 10_000);
}
