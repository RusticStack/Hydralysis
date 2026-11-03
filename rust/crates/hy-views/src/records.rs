//! View records: who holds a view and its lease (`views.py` section "agent identity and view records", RECORD_FORMAT=1).
//!
//! One sealed JSON file per view, `lineages/<id>/views/<name>.json`, written under `<name>.lock`. A holder is live while
//! its lease holds and its process exists; a view with no live holder is `orphaned`.

use std::path::PathBuf;
use std::sync::RwLock;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result, ViewError};
use crate::layout::{BOOT_ID, Settings, dir, env, is_view_name, lineage_dir, now_f64};
use crate::proc;
use hy_core::sealed::{self, ReadOptions};

pub const RESERVED_VIEWS: [&str; 2] = ["shared", "master"];
/// `viewLeaseS`: a holder that makes no call for this long no longer owns the view.
pub const LEASE_S: f64 = 600.0;
/// The lease is rewritten when this much of it is gone, not on every call.
pub const LEASE_REFRESH_S: f64 = 60.0;
pub const RECORD_FORMAT: i64 = 1;
pub const RECORD_LOCK_S: f64 = 10.0;
const AGENT_MAX: usize = 128;
const RECORD_MAX_BYTES: u64 = 65536;

static HARNESS: RwLock<Option<String>> = RwLock::new(None);

/// `hydra.set_harness`: the MCP client name (`clientInfo.name`), sanitised the way Python does.
pub fn set_harness(name: &str) {
    let cleaned: String =
        name.chars().map(|c| if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ' ' | '-') { c } else { '-' }).take(64).collect();
    *HARNESS.write().unwrap() = Some(cleaned);
}

/// The MCP client name, else `HYDRALYSIS_HARNESS`, else `cli`.
pub fn agent_name() -> String {
    HARNESS.read().unwrap().clone().or_else(|| env("HARNESS")).unwrap_or_else(|| "cli".into())
}

/// How a call's agent id was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Default,
    Stable,
    Explicit,
}

impl Kind {
    pub fn as_str(self) -> &'static str {
        match self {
            Kind::Default => "default",
            Kind::Stable => "stable",
            Kind::Explicit => "explicit",
        }
    }
}

/// Who a call is (`views.identify`).
#[derive(Debug, Clone, PartialEq)]
pub struct Who {
    pub agent: String,
    pub kind: Kind,
    pub name: String,
    pub shared: bool,
}

pub fn clean_agent_id(value: &Value, what: &str) -> Result<String> {
    let bad = || Error::value(format!("{what} must be a string of 1..{AGENT_MAX} printable characters"));
    let Value::String(s) = value else {
        return Err(bad());
    };
    if s.trim().is_empty() || s.chars().count() > AGENT_MAX || s.chars().any(|c| (c as u32) < 32) {
        return Err(bad());
    }
    Ok(s.trim().to_string())
}

/// `HYDRALYSIS_AGENT_ID` (stable across restarts), else `<client name>@<boot id>`.
pub fn default_agent_id() -> Result<(String, Kind)> {
    if let Some(fixed) = env("AGENT_ID") {
        return Ok((clean_agent_id(&Value::String(fixed), "HYDRALYSIS_AGENT_ID")?, Kind::Stable));
    }
    Ok((format!("{}@{}", agent_name(), *BOOT_ID), Kind::Default))
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// The view name of an agent id: the id itself when it is already a lower-case view name, else a slug plus a
/// 10-digit digest of the exact spelling, so two ids never share a (case-insensitive) file name.
pub fn view_name(agent_id: &str) -> String {
    if is_view_name(agent_id) && !RESERVED_VIEWS.contains(&agent_id) && agent_id == agent_id.to_lowercase() {
        return agent_id.to_string();
    }
    let replaced = agent_id.replace('@', ".at.");
    let mut slug = String::new();
    let mut in_run = false;
    for c in replaced.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-') {
            slug.push(c);
            in_run = false;
        } else if !in_run {
            slug.push('-');
            in_run = true;
        }
    }
    let trimmed = slug.trim_matches(|c| matches!(c, '-' | '.' | '_'));
    let mut slug: String = trimmed.chars().take(48).collect::<String>().to_lowercase();
    if slug.is_empty() {
        slug = "agent".into();
    }
    format!("{slug}.{}", &sha256_hex(agent_id)[..10])
}

/// Who a call is. Pops `as` from `options`.
pub fn identify(options: &mut Map<String, Value>) -> Result<Who> {
    let given = options.remove("as").filter(|v| !v.is_null());
    let (agent, kind) = match given {
        None => default_agent_id()?,
        Some(v) => (clean_agent_id(&v, "options.as")?, Kind::Explicit),
    };
    if agent == "shared" {
        return Ok(Who { agent, kind, name: "shared".into(), shared: true });
    }
    if agent == "master" {
        return Err(Error::value("options.as 'master' is reserved: it labels reads of the sealed master"));
    }
    let name = view_name(&agent);
    Ok(Who { agent, kind, name, shared: false })
}

pub fn views_dir(settings: &Settings, lineage_id: &str) -> Result<PathBuf> {
    dir(settings, lineage_id, "views")
}

pub fn record_path(settings: &Settings, lineage_id: &str, name: &str) -> Result<PathBuf> {
    if !is_view_name(name) {
        return Err(Error::value("invalid view name"));
    }
    Ok(views_dir(settings, lineage_id)?.join(format!("{name}.json")))
}

fn record_lock(settings: &Settings, lineage_id: &str, name: &str) -> Result<hy_core::lock::LockGuard> {
    Ok(hy_core::lock::lock(&views_dir(settings, lineage_id)?.join(format!("{name}.lock")), RECORD_LOCK_S, "view record")?)
}

/// The view record, or `None` when there is none or it cannot be read (a record is metadata: the store is the truth).
pub fn read_record(settings: &Settings, lineage_id: &str, name: &str) -> Option<Map<String, Value>> {
    let path = record_path(settings, lineage_id, name).ok()?;
    let options = ReadOptions { max_bytes: Some(RECORD_MAX_BYTES), require_seal: false };
    match sealed::read_sealed_info(&path, &options, Some(Value::Null)) {
        Ok((Value::Object(map), _)) => Some(map),
        _ => None,
    }
}

pub fn list_records(settings: &Settings, lineage_id: &str) -> Vec<Map<String, Value>> {
    let Ok(folder) = views_dir(settings, lineage_id) else {
        return Vec::new();
    };
    let Ok(entries) = std::fs::read_dir(&folder) else {
        return Vec::new();
    };
    let mut stems: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter_map(|n| n.strip_suffix(".json").map(str::to_string))
        .collect();
    stems.sort();
    stems
        .into_iter()
        .filter_map(|stem| {
            read_record(settings, lineage_id, &stem).filter(|r| r.get("view").and_then(Value::as_str) == Some(stem.as_str()))
        })
        .collect()
}

fn num(value: Option<&Value>) -> f64 {
    value.and_then(Value::as_f64).unwrap_or(0.0)
}

fn holder_live(holder: &Value, now: f64) -> bool {
    if num(holder.get("lease_until")) < now {
        return false;
    }
    let pid = holder.get("pid").and_then(Value::as_i64).unwrap_or(0);
    let started = holder.get("pid_started_ms").and_then(Value::as_i64).unwrap_or(0);
    proc::identity(pid, started)
}

/// The live holders of a record, by boot id.
pub fn live_holders(record: &Map<String, Value>, now: Option<f64>) -> Map<String, Value> {
    let now = now.unwrap_or_else(now_f64);
    record
        .get("holders")
        .and_then(Value::as_object)
        .map(|h| h.iter().filter(|(_, v)| holder_live(v, now)).map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HolderState {
    /// This process holds it.
    Mine,
    /// Another process does.
    Live,
    /// No holder is alive.
    Orphaned,
}

impl HolderState {
    pub fn as_str(self) -> &'static str {
        match self {
            HolderState::Mine => "mine",
            HolderState::Live => "live",
            HolderState::Orphaned => "orphaned",
        }
    }
}

pub fn holder_state(record: &Map<String, Value>, now: Option<f64>) -> HolderState {
    let holders = live_holders(record, now);
    if holders.contains_key(BOOT_ID.as_str()) {
        HolderState::Mine
    } else if holders.is_empty() {
        HolderState::Orphaned
    } else {
        HolderState::Live
    }
}

/// What `claim` needs of the selected target.
#[derive(Debug, Clone)]
pub struct Selected<'a> {
    pub key: &'a str,
    pub name: &'a str,
    /// `workcopy.lineage_binding(selected)`: `{lineage, generation}` or null.
    pub binding: Value,
}

/// Take (create, refresh or adopt) the record of the view `who` names, under the record's lock (`views.claim`).
///
/// A process default id belongs to the process that made it: another process that names it with `as` while a holder is
/// live is refused with `view_in_use`. Explicit and stable ids are shared by every caller that presents them (D59).
/// With `create` false a missing record is not made.
pub fn claim(
    settings: &Settings,
    selected: &Selected<'_>,
    who: &Who,
    lineage_id: &str,
    lease_s: f64,
    create: bool,
) -> Result<Option<Map<String, Value>>> {
    let name = who.name.as_str();
    let path = record_path(settings, lineage_id, name)?;
    let now = now_f64();
    let boot = BOOT_ID.as_str();
    let pid = i64::from(std::process::id());
    let started = proc::own_started_ms();

    // Most calls find this process's own fresh lease: the record as it is is the answer, without the record lock.
    if let Some(current) = read_record(settings, lineage_id, name)
        && (who.kind == Kind::Default || current.get("id_kind").and_then(Value::as_str) != Some("default"))
        && let Some(mine) = current.get("holders").and_then(|h| h.get(boot))
        && mine.get("pid").and_then(Value::as_i64) == Some(pid)
        && mine.get("pid_started_ms").and_then(Value::as_i64) == Some(started)
        && mine.get("lease_until").and_then(Value::as_f64).is_some_and(|l| l - now > lease_s - LEASE_REFRESH_S)
    {
        return Ok(Some(current));
    }
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let _guard = record_lock(settings, lineage_id, name)?;
    let record = read_record(settings, lineage_id, name);
    if record.is_none() && !create {
        return Ok(None);
    }
    let mut holders: Map<String, Value> = Map::new();
    if let Some(record) = &record {
        if let Some(old) = record.get("holders").and_then(Value::as_object) {
            holders = old.iter().filter(|(_, v)| holder_live(v, now)).map(|(k, v)| (k.clone(), v.clone())).collect();
        }
        let others: Vec<&String> = holders.keys().filter(|b| b.as_str() != boot).collect();
        if let Some(first) = others.first()
            && record.get("id_kind").and_then(Value::as_str) == Some("default")
            && who.kind != Kind::Default
        {
            let owner = &holders[first.as_str()];
            return Err(ViewError::new(
                "view_in_use",
                format!(
                    "view {} is held by a live process of the same agent ({}, pid {}); it can be adopted when its lease ends or its process exits",
                    who.agent,
                    py_str(owner.get("agent_name")),
                    py_str(owner.get("pid"))
                ),
            )
            .with("view", json!(name))
            .with("agent", json!(who.agent))
            .with(
                "owner",
                json!({"boot_id": first, "pid": owner.get("pid"), "agent_name": owner.get("agent_name"), "lease_until": owner.get("lease_until")}),
            )
            .into());
        }
    }
    if let (Some(mine), Some(_)) = (holders.get(boot), &record)
        && num(mine.get("lease_until")) - now > lease_s - LEASE_REFRESH_S
    {
        return Ok(record);
    }
    holders
        .insert(boot.to_string(), json!({"pid": pid, "pid_started_ms": started, "lease_until": now + lease_s, "agent_name": agent_name()}));
    let empty = Map::new();
    let rec = record.as_ref().unwrap_or(&empty);
    let adopted = if record.is_some()
        && rec.get("boot_id").and_then(Value::as_str) != Some(boot)
        && !rec.get("holders").and_then(Value::as_object).is_some_and(|h| h.contains_key(boot))
    {
        Some(json!({"boot_id": rec.get("boot_id"), "pid": rec.get("pid"), "agent_name": rec.get("agent_name"), "at": now}))
    } else {
        None
    };
    let previous = rec.get("adopted_from").filter(|v| truthy(v)).cloned();
    let id_kind = rec.get("id_kind").filter(|v| truthy(v)).cloned().unwrap_or_else(|| json!(who.kind.as_str()));
    let base = rec.get("base").filter(|v| truthy(v)).cloned().unwrap_or_else(|| selected.binding.clone());
    let mut body = Map::new();
    body.insert("format".into(), json!(RECORD_FORMAT));
    body.insert("view".into(), json!(name));
    body.insert("agent".into(), json!(who.agent));
    body.insert("id_kind".into(), id_kind);
    body.insert("agent_name".into(), json!(agent_name()));
    body.insert("boot_id".into(), json!(boot));
    body.insert("pid".into(), json!(pid));
    body.insert("pid_started_ms".into(), json!(started));
    body.insert("lease_until".into(), json!(now + lease_s));
    body.insert("holders".into(), Value::Object(holders));
    body.insert("key".into(), json!(selected.key));
    body.insert("target".into(), json!(selected.name));
    body.insert("base".into(), base);
    body.insert("state".into(), json!("open"));
    body.insert("created".into(), rec.get("created").cloned().unwrap_or_else(|| json!(now)));
    body.insert("last_seen".into(), json!(now));
    if let Some(a) = adopted.or(previous) {
        body.insert("adopted_from".into(), a);
    }
    let value = Value::Object(body);
    sealed::write_sealed(&path, &value, Some(2), Some(65536), None)?;
    let Value::Object(body) = value else { unreachable!() };
    Ok(Some(body))
}

/// Python truthiness of a JSON value.
pub fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

/// `str()` of a JSON value as Python prints it in a message.
pub fn py_str(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".into(),
        Some(Value::String(s)) => s.clone(),
        Some(Value::Bool(b)) => if *b { "True" } else { "False" }.into(),
        Some(other) => other.to_string(),
    }
}

/// Record that the view's fork is `evicted`, `deleted` or `open` again. Best effort (every failure is swallowed).
pub fn mark_state(settings: &Settings, lineage_id: &str, name: &str, state: &str, fields: Map<String, Value>) {
    let _ = (|| -> Result<()> {
        let _guard = record_lock(settings, lineage_id, name)?;
        if let Some(mut record) = read_record(settings, lineage_id, name) {
            record.insert("state".into(), json!(state));
            record.extend(fields);
            sealed::write_sealed(&record_path(settings, lineage_id, name)?, &Value::Object(record), Some(2), Some(65536), None)?;
        }
        Ok(())
    })();
}

/// One row of `status show=views`. `pending`/`base` come from the view's store (`None`/the record's own base when the store
/// cannot be read); the working-copy side that computes them is ported with `workcopy`.
pub fn describe(record: &Map<String, Value>, pending: Option<usize>, store_base: Option<Value>, now: Option<f64>) -> Value {
    let now = now.unwrap_or_else(now_f64);
    let base = store_base.or_else(|| record.get("base").cloned()).unwrap_or(Value::Null);
    let last_seen = record.get("last_seen").and_then(Value::as_f64).unwrap_or(now);
    let mut row = Map::new();
    row.insert("view".into(), record["view"].clone());
    row.insert("agent".into(), record["agent"].clone());
    row.insert("id_kind".into(), record.get("id_kind").cloned().unwrap_or(Value::Null));
    row.insert("agent_name".into(), record.get("agent_name").cloned().unwrap_or(Value::Null));
    row.insert("state".into(), json!(holder_state(record, Some(now)).as_str()));
    row.insert("fork".into(), record.get("state").cloned().unwrap_or(Value::Null));
    row.insert("pending".into(), pending.map_or(Value::Null, |p| json!(p)));
    row.insert("base".into(), base);
    row.insert("boot_id".into(), record.get("boot_id").cloned().unwrap_or(Value::Null));
    row.insert("pid".into(), record.get("pid").cloned().unwrap_or(Value::Null));
    row.insert("lease_until".into(), record.get("lease_until").cloned().unwrap_or(Value::Null));
    row.insert("idle_s".into(), json!(((now - last_seen) * 10.0).round() / 10.0));
    if let Some(a) = record.get("adopted_from").filter(|v| truthy(v)) {
        row.insert("adopted_from".into(), a.clone());
    }
    Value::Object(row)
}

/// The lineage folder a record belongs to (kept for callers that build sibling paths).
pub fn lineage_folder(settings: &Settings, lineage_id: &str) -> Result<PathBuf> {
    lineage_dir(settings, lineage_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(root: &std::path::Path) -> Settings {
        json!({"root": root.to_str().unwrap()}).as_object().unwrap().clone()
    }

    #[test]
    fn view_names_match_the_python_rule() {
        assert_eq!(view_name("alice"), "alice");
        assert_eq!(view_name("shared"), format!("shared.{}", &sha256_hex("shared")[..10]));
        assert_eq!(view_name("Alice"), format!("alice.{}", &sha256_hex("Alice")[..10]));
        assert_eq!(view_name("claude-code@1f2e"), format!("claude-code.at.1f2e.{}", &sha256_hex("claude-code@1f2e")[..10]));
        assert_eq!(view_name("  !! "), format!("agent.{}", &sha256_hex("  !! ")[..10]));
    }

    #[test]
    fn identify_pops_as_and_refuses_master() {
        let mut o = json!({"as": "shared", "x": 1}).as_object().unwrap().clone();
        let w = identify(&mut o).unwrap();
        assert!(w.shared && w.name == "shared" && w.kind == Kind::Explicit);
        assert!(!o.contains_key("as"));
        let mut o = json!({"as": "master"}).as_object().unwrap().clone();
        assert_eq!(identify(&mut o).unwrap_err().to_string(), "options.as 'master' is reserved: it labels reads of the sealed master");
        let mut o = json!({"as": ""}).as_object().unwrap().clone();
        assert_eq!(identify(&mut o).unwrap_err().to_string(), "options.as must be a string of 1..128 printable characters");
        let mut o = Map::new();
        assert_eq!(identify(&mut o).unwrap().kind, Kind::Default);
    }

    #[test]
    fn claim_creates_refreshes_and_lists_a_record() {
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path());
        let sel = Selected { key: "k1", name: "prog", binding: json!({"lineage": "L-00000001", "generation": 0}) };
        let mut o = json!({"as": "alice"}).as_object().unwrap().clone();
        let who = identify(&mut o).unwrap();
        assert!(claim(&s, &sel, &who, "L-00000001", LEASE_S, false).unwrap().is_none());
        let rec = claim(&s, &sel, &who, "L-00000001", LEASE_S, true).unwrap().unwrap();
        assert_eq!(rec["view"], "alice");
        assert_eq!(rec["format"], 1);
        assert_eq!(rec["id_kind"], "explicit");
        assert_eq!(rec["base"]["generation"], 0);
        assert_eq!(rec["boot_id"], BOOT_ID.as_str());
        // a second call within the lease returns the same record without rewriting it
        let again = claim(&s, &sel, &who, "L-00000001", LEASE_S, true).unwrap().unwrap();
        assert_eq!(again["lease_until"], rec["lease_until"]);
        let rows = list_records(&s, "L-00000001");
        assert_eq!(rows.len(), 1);
        assert_eq!(holder_state(&rows[0], None), HolderState::Mine);
        mark_state(&s, "L-00000001", "alice", "evicted", Map::new());
        assert_eq!(read_record(&s, "L-00000001", "alice").unwrap()["state"], "evicted");
        let d = describe(&rows[0], Some(3), None, None);
        assert_eq!(d["state"], "mine");
        assert_eq!(d["pending"], 3);
    }

    #[test]
    fn a_default_view_held_by_another_live_process_is_refused_to_an_explicit_claim() {
        let dir = tempfile::tempdir().unwrap();
        let s = settings(dir.path());
        let sel = Selected { key: "k1", name: "prog", binding: Value::Null };
        // forge a record whose default-kind holder is a different, live process (the parent of this test is not
        // guaranteed, so use this process under another boot id)
        let name = "bob";
        let path = record_path(&s, "L-00000001", name).unwrap();
        let holder = json!({"pid": std::process::id(), "pid_started_ms": proc::own_started_ms(), "lease_until": now_f64() + 600.0, "agent_name": "x"});
        let rec = json!({"format": 1, "view": name, "agent": "bob", "id_kind": "default", "agent_name": "x", "boot_id": "ffff",
                         "holders": {"ffff": holder}, "key": "k1", "target": "prog", "state": "open", "created": 1.0, "last_seen": 1.0});
        sealed::write_sealed(&path, &rec, Some(2), None, None).unwrap();
        let who = Who { agent: "bob".into(), kind: Kind::Explicit, name: name.into(), shared: false };
        let err = claim(&s, &sel, &who, "L-00000001", LEASE_S, true).unwrap_err();
        match err {
            Error::View(v) => {
                assert_eq!(v.code, "view_in_use");
                assert!(v.message.starts_with("view bob is held by a live process of the same agent (x, pid "));
            }
            other => panic!("{other}"),
        }
    }
}
