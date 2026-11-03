//! The pure parts of `hydralysis/hydra.py`: the engine error text, retry classification, engine install inspection,
//! the daemon config, the client-library stamp check and the supervisor's wedge signal.
//!
//! The pins (`RELEASE`, `PROTOCOL`, `PROTOCOL_MIN`, `CLIENT_VERSION`) are arguments, not constants here: `tools/bump_hydra.py`
//! rewrites them in `hydra.py`, and that file stays their only home. The connection, pool, entry and supervisor loop
//! (threads, sockets, the daemon process) are not ported.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};

use crate::failure::{Failure, Res};
use crate::pytext::{py_int_value, py_splitlines, py_str_tail, py_strip};

/// Lists in an error stay this short (`hydra.LIST_CAP`).
pub const LIST_CAP: usize = 5;
/// The lists of `queue` keep this many entries (`hydra.QUEUE_CAP`).
pub const QUEUE_CAP: usize = 64;
/// What an error never shortens (`hydra.UNCAPPED`).
pub const UNCAPPED: [&str; 2] = ["next", "retryAfterMs"];

/// Commands that may be sent again after a lost reply (`hydra.IDEMPOTENT_COMMANDS`).
pub const IDEMPOTENT_COMMANDS: &[&str] = &[
    "ping",
    "hello",
    "health",
    "status",
    "projects",
    "programs",
    "overlays",
    "journal",
    "open_project",
    "open_program",
    "switch",
    "close_project",
    "close_program",
    "refresh",
    "reopen",
    "project",
    "list",
    "info",
    "functions",
    "decompile",
    "trace_list",
    "trace_info",
    "trace_query",
    "trace_explain",
    "trace_diff",
    "trace_check",
    "trace_bundle",
];

/// RusticQuery actions that do not change the program (`hydra.READ_ACTIONS`).
pub const READ_ACTIONS: &[&str] = &[
    "overlay_state",
    "decompile",
    "function",
    "functions",
    "xrefs",
    "types",
    "type",
    "data",
    "scan",
    "variables",
    "dossier",
    "blocks",
    "pcode",
    "trace",
    "vcalls",
    "vtables",
    "writes",
    "orphans",
    "fingerprints",
];

/// The pins of the Python module, handed in by the caller.
#[derive(Clone, Debug)]
pub struct Pins {
    pub release: String,
    pub protocol: i64,
    pub protocol_min: i64,
    pub client_version: String,
}

// ---- EngineError ------------------------------------------------------------------------------------------------

/// `hydra._capped`: lists stay short, `more` records how many entries were left out (a later list of the same name
/// overwrites an earlier count, as the Python dict assignment does).
fn capped(value: &Value, name: &str, more: &mut Map<String, Value>, cap: usize) -> Value {
    match value {
        Value::Array(items) => {
            if items.len() > cap {
                more.insert(name.to_string(), Value::from(items.len() - cap));
            }
            Value::Array(items.iter().take(cap).map(|item| capped(item, name, more, cap)).collect())
        }
        Value::Object(map) => {
            let mut out = Map::new();
            for (key, item) in map {
                let inner = if name.is_empty() { key.clone() } else { format!("{name}.{key}") };
                out.insert(key.clone(), capped(item, &inner, more, cap));
            }
            Value::Object(out)
        }
        other => other.clone(),
    }
}

/// The parts of an `ok:false` answer `EngineError.__init__` builds its text from.
pub struct ErrorParts<'a> {
    pub code: &'a str,
    pub message: &'a str,
    pub details: &'a Map<String, Value>,
    pub command: &'a str,
    pub retry_after_ms: Option<&'a Value>,
    pub next: Option<&'a Value>,
    /// The `queue` argument, else `details["queue"]` (the caller resolves which, as the constructor does).
    pub queue: Option<&'a Value>,
}

/// `str(EngineError(...))`: the JSON an agent can act on, `json.dumps(payload, ensure_ascii=False)`.
pub fn engine_error_text(parts: &ErrorParts<'_>) -> Res<String> {
    let details = parts.details;
    let mut payload = Map::new();
    payload.insert("engine_error".into(), Value::String(parts.code.into()));
    payload.insert("message".into(), Value::String(parts.message.into()));
    payload.insert("command".into(), Value::String(parts.command.into()));
    if let (Some(output), "failed") = (details.get("output"), parts.code) {
        // `str(output)[-2000:]`: only a string has a `str()` this port knows
        let Value::String(text) = output else {
            return Err(Failure::fallback("details.output is not a string"));
        };
        payload.insert("output_tail".into(), Value::String(py_str_tail(text, 2000)));
    }
    for key in
        ["holder", "holderInfo", "suggest", "suggestion", "alternatives", "reason", "program", "project", "current", "running", "ambiguous"]
    {
        if let Some(value) = details.get(key) {
            payload.insert(key.into(), value.clone());
        }
    }
    // held = details.get("heldMs"); if None and holderInfo is a dict: holderInfo.get("heldMs")
    let mut held = details.get("heldMs").filter(|v| !v.is_null());
    if held.is_none()
        && let Some(Value::Object(info)) = details.get("holderInfo")
    {
        held = info.get("heldMs").filter(|v| !v.is_null());
    }
    if let Some(held) = held {
        payload.insert("heldMs".into(), held.clone());
    }
    if let Some(queue) = parts.queue.filter(|v| !v.is_null()) {
        payload.insert("queue".into(), queue.clone());
    }
    if let Some(retry) = parts.retry_after_ms.filter(|v| !v.is_null()) {
        payload.insert("retryAfterMs".into(), retry.clone());
    }
    if let Some(next) = parts.next.filter(|v| !v.is_null()) {
        payload.insert("next".into(), next.clone());
    }
    let mut more = Map::new();
    let mut shaped = Map::new();
    for (key, item) in &payload {
        let value = if UNCAPPED.contains(&key.as_str()) {
            item.clone()
        } else {
            capped(item, key, &mut more, if key == "queue" { QUEUE_CAP } else { LIST_CAP })
        };
        shaped.insert(key.clone(), value);
    }
    if !more.is_empty() {
        shaped.insert("more".into(), Value::Object(more));
    }
    Ok(crate::pytext::dumps(&Value::Object(shaped), crate::pytext::Dumps::Spaced))
}

// ---- retry classification ---------------------------------------------------------------------------------------

/// `command in IDEMPOTENT_COMMANDS` for every command but `script`.
pub fn idempotent_command(command: &str) -> bool {
    IDEMPOTENT_COMMANDS.contains(&command)
}

/// Whether a RusticQuery action only reads (`action in READ_ACTIONS`).
pub fn read_action(action: &str) -> bool {
    READ_ACTIONS.contains(&action)
}

/// `hydra._script_action` for a `script` call of `RusticQuery.java`, given `str(args[0])`: the `action` of its request
/// body. `@path` names a file holding the body. `Ok(None)` is the original's "not an action" (every `IndexError`,
/// `OSError`, `ValueError` and `AttributeError` it swallows).
pub fn script_action(first_argument: &str) -> Res<Option<String>> {
    let text = match first_argument.strip_prefix('@') {
        Some(path) => match fs::read(path) {
            // `Path.read_text(encoding="utf-8")` translates newlines; JSON whitespace outside strings is unaffected and a raw
            // newline inside a string is invalid either way
            Ok(bytes) => match String::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => return Ok(None),
            },
            Err(_) => return Ok(None),
        },
        None => first_argument.to_string(),
    };
    // Python's json accepts NaN/Infinity, lone surrogates and any integer size: whatever serde refuses is the original's to say
    let Ok(value) = serde_json::from_str::<Value>(&text) else {
        return Err(Failure::fallback("json not parsed by serde"));
    };
    Ok(match value.get("action") {
        Some(Value::String(action)) => Some(action.clone()),
        _ => None,
    })
}

// ---- engine install inspection ----------------------------------------------------------------------------------

/// `Ghidra/Features/HeadlessSession`, relative to an engine install (`hydra.SESSION_MODULE`).
const SESSION_MODULE: [&str; 3] = ["Ghidra", "Features", "HeadlessSession"];

fn join_all(base: &Path, parts: &[&str]) -> PathBuf {
    parts.iter().fold(base.to_path_buf(), |path, part| path.join(part))
}

/// `hydra.engine_release`: the Hydra release an engine install was built as, from `hydra.properties` in its own jar.
pub fn engine_release(directory: &Path) -> Option<String> {
    let mut jar = join_all(directory, &SESSION_MODULE);
    jar.push("lib");
    jar.push("HeadlessSession.jar");
    if !jar.is_file() {
        return None;
    }
    let file = fs::File::open(&jar).ok()?;
    let mut archive = zip::ZipArchive::new(file).ok()?;
    let mut entry = archive.by_name("hydra.properties").ok()?;
    let mut raw = Vec::new();
    std::io::Read::read_to_end(&mut entry, &mut raw).ok()?;
    let text = String::from_utf8_lossy(&raw);
    version_in(&text)
}

/// `re.search(r"^hydra\.version=(\S+)", text, re.M)`: `^` after `\n` only, `\S` as Python's `str` means it
/// (the ASCII separators U+001C to U+001F are whitespace there).
fn version_in(text: &str) -> Option<String> {
    static VERSION: OnceLock<Regex> = OnceLock::new();
    let re = VERSION.get_or_init(|| Regex::new(r"(?m)^hydra\.version=([^\s\x1c-\x1f]+)").expect("regex"));
    re.captures(text).map(|found| found[1].to_string())
}

/// `hydra._properties`: `key=value` lines of a Java properties file (no quote stripping, unlike `backends`).
pub fn properties(path: &Path) -> Vec<(String, String)> {
    let mut result: Vec<(String, String)> = Vec::new();
    if !path.is_file() {
        return result;
    }
    let Ok(raw) = fs::read(path) else {
        return result;
    };
    let text = String::from_utf8_lossy(&raw);
    for line in py_splitlines(&text) {
        if let Some((key, value)) = line.split_once('=')
            && !crate::pytext::py_lstrip(line).starts_with('#')
        {
            let (key, value) = (py_strip(key).to_string(), py_strip(value).to_string());
            match result.iter_mut().find(|(k, _)| *k == key) {
                Some(existing) => existing.1 = value,
                None => result.push((key, value)),
            }
        }
    }
    result
}

fn property<'a>(properties: &'a [(String, String)], name: &str) -> Option<&'a str> {
    properties.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str())
}

/// `Path.glob("*/decompile*")` is non-empty (case-insensitive on Windows).
fn has_decompiler(native: &Path) -> bool {
    let Ok(dirs) = fs::read_dir(native) else {
        return false;
    };
    dirs.flatten().filter(|dir| dir.path().is_dir()).any(|dir| {
        fs::read_dir(dir.path()).is_ok_and(|inner| {
            inner.flatten().any(|item| {
                let name = item.file_name().to_string_lossy().to_lowercase();
                name.starts_with("decompile")
            })
        })
    })
}

/// `hydra.inspect_engine` for the already resolved install directory `path`: the report dict (key order kept).
pub fn inspect_engine(path: &Path, allow_unpinned: bool, pins: &Pins) -> Res<Value> {
    let application = properties(&path.join("Ghidra").join("application.properties"));
    let mut report = Map::new();
    report.insert("component".into(), "analysis".into());
    report.insert("path".into(), Value::String(path.to_string_lossy().into_owned()));
    report.insert("ready".into(), false.into());
    let with = |report: &Map<String, Value>, extra: Vec<(&str, Value)>| {
        let mut out = report.clone();
        for (key, value) in extra {
            out.insert(key.into(), value);
        }
        Value::Object(out)
    };
    let Some(version) = property(&application, "application.version").filter(|v| !v.is_empty()) else {
        return Ok(with(&report, vec![("reason", "not a Ghidra/Hydra install (no Ghidra/application.properties)".into())]));
    };
    let release = engine_release(path);
    // `int(application.get("application.java.min") or 21)`
    let java_min = match property(&application, "application.java.min").filter(|v| !v.is_empty()) {
        Some(text) => py_int_value(&Value::String(text.into()))?,
        None => 21,
    };
    let java_max = match property(&application, "application.java.max").filter(|v| !v.is_empty()) {
        Some(text) => Value::from(py_int_value(&Value::String(text.into()))?),
        None => Value::Null,
    };
    report.insert("ghidra_version".into(), Value::String(version.into()));
    report.insert("hydra_release".into(), release.clone().map_or(Value::Null, Value::String));
    report.insert("java_min".into(), Value::from(java_min));
    report.insert("java_max".into(), java_max);
    let Some(found) = release else {
        let reason = format!(
            "a stock Ghidra without Hydra's HeadlessSession module; Hydralysis drives Hydra Engine {} (backend install); a stock Ghidra is never used",
            pins.release
        );
        return Ok(with(&report, vec![("reason", reason.into())]));
    };
    if found != pins.release && !allow_unpinned {
        let reason = format!("Hydra Engine {found}; this Hydralysis pins {} (set hydra_allow_unpinned to try it)", pins.release);
        return Ok(with(&report, vec![("reason", reason.into())]));
    }
    let native = join_all(path, &["Ghidra", "Features", "Decompiler", "os"]);
    if !has_decompiler(&native) {
        let reason = format!("native decompiler missing under {}", native.to_string_lossy());
        return Ok(with(&report, vec![("reason", reason.into())]));
    }
    Ok(with(&report, vec![("ready", true.into()), ("pinned", (found == pins.release).into())]))
}

// ---- the client library ------------------------------------------------------------------------------------------

/// The three stamps `load_client` reads from `ghidra_session.py`: `PROTOCOL`, `CLIENT_VERSION`, `HYDRA_RELEASE`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamps {
    pub protocol: Option<String>,
    pub client_version: Option<String>,
    pub hydra_release: Option<String>,
}

/// `re.search(r'^NAME\s*=\s*"?([^"\n]+)"?', text, re.M)` for the stamp NAME, on text read with universal newlines.
fn stamp(text: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"(?m)^{name}[\s\x1c-\x1f]*=[\s\x1c-\x1f]*"?([^"\n]+)"?"#)).expect("regex");
    re.captures(text).map(|found| found[1].to_string())
}

/// `str.isdigit` for the ASCII subset; anything else is `None` (not modelled).
fn ascii_digits(text: &str) -> Option<bool> {
    if text.is_empty() {
        return Some(false);
    }
    if !text.is_ascii() {
        return None;
    }
    Some(text.bytes().all(|b| b.is_ascii_digit()))
}

/// The stamps of the client library TEXT (as `Path.read_text` returns it: newlines already `\n`).
pub fn client_stamps(text: &str) -> Stamps {
    Stamps { protocol: stamp(text, "PROTOCOL"), client_version: stamp(text, "CLIENT_VERSION"), hydra_release: stamp(text, "HYDRA_RELEASE") }
}

/// Translate newlines as text-mode reading does (`\r\n` and `\r` become `\n`).
pub fn universal_newlines(text: &str) -> String {
    if !text.contains('\r') {
        return text.to_string();
    }
    text.replace("\r\n", "\n").replace('\r', "\n")
}

/// The pin checks of `hydra.load_client` on the library file at PATH (`shown` is `str(path)` as the messages print it):
/// protocol range, then (pinned) release and client version. `Raise ValueError` carries the original's message; any
/// failure to read the file is a fallback so the original raises its own `OSError`.
pub fn check_client_file(path: &Path, shown: &str, allow_unpinned: bool, pins: &Pins) -> Res<Stamps> {
    let raw = fs::read(path).map_err(|e| Failure::fallback(format!("cannot read client library: {e}")))?;
    check_client_text(shown, &String::from_utf8_lossy(&raw), allow_unpinned, pins)
}

/// [`check_client_file`] on text that has not had its newlines translated yet.
pub fn check_client_text(shown_path: &str, text: &str, allow_unpinned: bool, pins: &Pins) -> Res<Stamps> {
    let stamps = client_stamps(&universal_newlines(text));
    let shown = |value: &Option<String>| value.clone().unwrap_or_else(|| "None".to_string());
    let low = if allow_unpinned { pins.protocol_min } else { pins.protocol };
    let protocol_ok = match stamps.protocol.as_deref().map(|value| (value, ascii_digits(value))) {
        None | Some((_, Some(false))) => false,
        Some((_, None)) => return Err(Failure::fallback("non-ASCII protocol stamp")),
        Some((value, Some(true))) => {
            let significant = value.trim_start_matches('0');
            // more digits than an i64 holds is a number far outside every accepted range
            significant.len() <= 18
                && significant.parse::<i64>().map_or(low <= 0 && significant.is_empty(), |n| (low..=pins.protocol).contains(&n))
        }
    };
    if !protocol_ok {
        let needs = if allow_unpinned { format!("{} to {}", pins.protocol_min, pins.protocol) } else { pins.protocol.to_string() };
        return Err(Failure::value(format!(
            "Hydra client {shown_path} speaks protocol {}; Hydralysis needs {needs}",
            shown(&stamps.protocol)
        )));
    }
    if !allow_unpinned
        && (stamps.hydra_release.as_deref() != Some(pins.release.as_str())
            || stamps.client_version.as_deref() != Some(pins.client_version.as_str()))
    {
        return Err(Failure::value(format!(
            "Hydra client {shown_path} is release {} / client {}; this Hydralysis pins {} / {}",
            shown(&stamps.hydra_release),
            shown(&stamps.client_version),
            pins.release,
            pins.client_version
        )));
    }
    Ok(stamps)
}

// ---- the daemon config -------------------------------------------------------------------------------------------

/// The default number of agents expected at once (`hydra.DEFAULT_EXPECTED_AGENTS`).
pub const DEFAULT_EXPECTED_AGENTS: i64 = 16;

/// `hydra.expected_agents`: an integer in 1..=256, default 16.
pub fn expected_agents(settings: &Map<String, Value>) -> Res<i64> {
    match settings.get("expected_agents") {
        None => Ok(DEFAULT_EXPECTED_AGENTS),
        Some(Value::Number(n)) => match n.as_i64() {
            Some(value) if (1..=256).contains(&value) => Ok(value),
            _ => Err(Failure::value("expected_agents must be an integer 1..256")),
        },
        Some(_) => Err(Failure::value("expected_agents must be an integer 1..256")),
    }
}

/// `hydra.daemon_config` for the resolved data ROOT.
pub fn daemon_config(settings: &Map<String, Value>, root: &Path) -> Res<Value> {
    let text = |path: PathBuf| Value::String(path.to_string_lossy().into_owned());
    let hydra = root.join("hydra");
    let mut config = Map::new();
    config.insert("scriptPath".into(), Value::Array(vec![text(hydra.join("scripts")), text(hydra.join("user-scripts"))]));
    config.insert("tmpdir".into(), text(hydra.join("tmp")));
    let number = |key: &str, default: i64| -> Res<i64> {
        match settings.get(key) {
            None => Ok(default),
            Some(value) => py_int_value(value),
        }
    };
    config.insert("idleTimeout".into(), number("hydra_idle_s", 7200)?.into());
    config.insert("keepWarm".into(), number("hydra_keep_warm_s", 3600)?.into());
    // `if settings.get("java_home")`: only a non-empty string has a `str()` this port models
    match settings.get("java_home") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::String(s)) if s.is_empty() => {}
        Some(Value::String(s)) => {
            config.insert("java".into(), Value::String(s.clone()));
        }
        Some(_) => return Err(Failure::fallback("java_home is not a string")),
    }
    config.insert(
        "vmargs".into(),
        Value::Array(vec![
            Value::String(format!("-Dapplication.settingsdir={}", hydra.join("ghidra-settings").to_string_lossy())),
            Value::String(format!("-Dapplication.cachedir={}", hydra.join("ghidra-cache").to_string_lossy())),
        ]),
    );
    match settings.get("hydra_max_heap") {
        None | Some(Value::Null) | Some(Value::Bool(false)) => {}
        Some(Value::String(s)) if s.is_empty() => {}
        Some(Value::String(s)) => {
            config.insert("maxHeap".into(), Value::String(s.clone()));
        }
        Some(_) => return Err(Failure::fallback("hydra_max_heap is not a string")),
    }
    let agents = expected_agents(settings)?;
    config.insert("maxLong".into(), 8.max((agents * 3 + 1) / 2).into());
    config.insert("maxQuick".into(), 16.max(agents * 2).into());
    match settings.get("hydra") {
        None | Some(Value::Null) => {}
        Some(Value::Object(overrides)) => {
            for key in ["maxImports", "maxQuick", "maxLong", "forkCopyLimitMb"] {
                if let Some(value) = overrides.get(key) {
                    config.insert(key.into(), value.clone());
                }
            }
        }
        Some(_) => return Err(Failure::fallback("settings.hydra is not an object")),
    }
    Ok(Value::Object(config))
}

// ---- the supervisor ----------------------------------------------------------------------------------------------

/// `hydra.wedge_signal`: why one probe counts as a miss. `health` is the reply (`None` for no answer).
pub fn wedge_signal(health: Option<&Value>, stall_ms: i64) -> Res<Option<&'static str>> {
    let Some(health) = health else {
        return Ok(Some("no_answer"));
    };
    let Value::Object(health) = health else {
        return Err(Failure::fallback("health reply is not an object"));
    };
    if health.get("state").and_then(Value::as_str) == Some("suspect") {
        return Ok(Some("suspect"));
    }
    // `stall = health.get("watchdogStallMs", stall_ms)`: compared with `>`, so it must be a number
    let stall = match health.get("watchdogStallMs") {
        None => Num::Int(stall_ms),
        Some(value) => Num::of(value).ok_or_else(|| Failure::fallback("watchdogStallMs is not a number"))?,
    };
    // `tick = health.get("tick") or {}`; only a dict is read, so a falsy or foreign value changes nothing
    if let Some(Value::Object(tick)) = health.get("tick")
        && let Some(age) = tick.get("ageMs").and_then(Num::of)
        && age.greater(&stall)?
    {
        return Ok(Some("tick_stalled"));
    }
    if health.get("schedulerLockOk") == Some(&Value::Bool(false)) {
        return Ok(Some("scheduler_lock"));
    }
    Ok(None)
}

/// A Python `int`/`float`/`bool` as the comparison `>` sees it.
#[derive(Clone, Copy)]
enum Num {
    Int(i64),
    Float(f64),
}

impl Num {
    fn of(value: &Value) -> Option<Num> {
        match value {
            Value::Bool(b) => Some(Num::Int(i64::from(*b))),
            Value::Number(n) => n.as_i64().map(Num::Int).or_else(|| n.as_f64().map(Num::Float)),
            _ => None,
        }
    }

    /// `self > other` with Python's exact int/float comparison, within the range where `f64` is exact.
    fn greater(&self, other: &Num) -> Res<bool> {
        const EXACT: i64 = 1 << 53;
        let fits = |n: &Num| !matches!(n, Num::Int(i) if i.abs() > EXACT);
        if !fits(self) || !fits(other) {
            return Err(Failure::fallback("integer beyond exact float range"));
        }
        let float = |n: &Num| match n {
            Num::Int(i) => *i as f64,
            Num::Float(f) => *f,
        };
        Ok(float(self) > float(other))
    }
}

/// `hydra.patience_ms`: DEFAULT_MS, or the 25 s patience budget once the engine reports queue information.
pub fn patience_ms(default_ms: i64, queue_info: bool) -> i64 {
    const PATIENCE_S: f64 = 25.0;
    if queue_info { default_ms.min((PATIENCE_S * 1000.0) as i64) } else { default_ms }
}
