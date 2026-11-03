//! The view store: `overlays/<key>.json` (version 3, sealed snapshot plus append log) and what is derived from it
//! (`workcopy.py` lines 420-860: `load_store`, `_save_store`, `pending_of`, `state_of`, `summary`, `changes`).
//!
//! The snapshot-plus-log mechanics are `hy_store::storelog` (storage lane). Not ported here: the in-process parsed-store
//! cache (`_LOADED`; a CPU optimisation, answers are identical) and `analysis.validate_options` (see [`set_validator`]).

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::layout::{Settings, root_path};
use crate::queue::MAX_HISTORY_BYTES;
use crate::records::truthy;
use crate::revisions;
use hy_core::sealed::{self, Kind, ReadOptions};

pub const STORE_VERSION: i64 = 3;
pub const MAX_OVERLAYS: usize = 4096;
pub const MAX_CHANGESETS: usize = 200;

/// A store in its version-3 shape (a JSON object with the keys of `_empty_store`).
pub type Store = Map<String, Value>;
/// A target (`targets.resolve` result): at least `key`, `sha256`, optionally `lineage`, `view`.
pub type Target = Map<String, Value>;

/// `analysis.validate_options("type_edit", options, _record=True)`: normalises a record's options. Injected by the host
/// that owns `analysis`; the default accepts an object unchanged (a clean stored record is a fixed point of it).
pub type Validator = fn(&Value) -> Result<Value>;

fn default_validator(options: &Value) -> Result<Value> {
    match options {
        Value::Object(_) => Ok(options.clone()),
        Value::Null => Ok(json!({})),
        _ => Err(Error::value("options must be an object")),
    }
}

static VALIDATOR: RwLock<Validator> = RwLock::new(default_validator);

pub fn set_validator(v: Validator) {
    *VALIDATOR.write().unwrap() = v;
}

pub fn default_base() -> Value {
    json!({"lineage": "", "generation": 0})
}

fn tstr<'a>(target: &'a Target, key: &str) -> &'a str {
    target.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// `{lineage, generation}` the head generation gives a view, or `None` for a target with no lineage.
pub fn lineage_binding(target: &Target) -> Option<Value> {
    let link = target.get("lineage").filter(|l| truthy(l))?;
    Some(json!({"lineage": link.get("id"), "generation": link.get("generation")}))
}

pub fn store_path(settings: &Settings, target: &Target) -> Result<PathBuf> {
    let key = tstr(target, "key");
    let ok = !key.is_empty() && key.len() <= 128 && key.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-');
    if !ok {
        return Err(Error::value("invalid overlay target key"));
    }
    Ok(root_path(settings).join("overlays").join(format!("{key}.json")))
}

fn file_name(p: &Path) -> String {
    p.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// The sealed store record, or `None` when no store was ever written. A version-3 file whose seal was stripped is
/// `store_corrupt`, not a pre-seal record.
pub fn store_record(path: &Path) -> Result<Option<Value>> {
    let limit = MAX_HISTORY_BYTES + 4096;
    let (kind, value, _) = sealed::inspect_file(path, Some(limit), false)?;
    match (kind, value) {
        (Kind::Sealed, Some(v)) => Ok(Some(v)),
        (Kind::Unsealed, Some(v)) => {
            if matches!(v.get("version").and_then(Value::as_i64), Some(1 | 2)) {
                return Ok(Some(v));
            }
            let backup = sealed::backup_path(path);
            Err(hy_core::Error::store_corrupt(
                path,
                &backup,
                vec![(file_name(path), "no seal (a version-3 store is always sealed)".into()), (file_name(&backup), "not tried".into())],
            )
            .into())
        }
        _ => {
            let options = ReadOptions { max_bytes: Some(limit), require_seal: false };
            let (v, _) = sealed::read_sealed_info(path, &options, Some(Value::Null))?;
            Ok(if v.is_null() { None } else { Some(v) })
        }
    }
}

fn is_hex32(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// `analysis._edit`: `{id, address, options}` of a record, validated.
pub fn edit_of(value: &Map<String, Value>) -> Result<Map<String, Value>> {
    if value.keys().any(|k| !matches!(k.as_str(), "id" | "address" | "options")) {
        return Err(Error::value("overlay edit accepts id, address and options"));
    }
    edit_fields(value)
}

/// [`edit_of`] for a map that may hold other keys (a stored record): only `id`, `address` and `options` are read.
fn edit_fields(value: &Map<String, Value>) -> Result<Map<String, Value>> {
    let validate = *VALIDATOR.read().unwrap();
    let options = validate(value.get("options").unwrap_or(&Value::Null))?;
    let address = match value.get("address") {
        None => "",
        Some(Value::String(s)) if s.chars().count() <= 128 && !s.contains('\0') => s.as_str(),
        _ => {
            return Err(Error::value("overlay address must be text of at most 128 characters"));
        }
    };
    if !address.is_empty() {
        let digits = address.strip_prefix("0x").unwrap_or(address);
        if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::value("overlay address must be a numeric Ghidra VA"));
        }
    }
    let kind = options.get("kind").and_then(Value::as_str).unwrap_or_default();
    if !["struct", "batch", "import_types", "import_archive"].contains(&kind) && address.is_empty() {
        return Err(Error::value("this type edit requires a Ghidra VA"));
    }
    let id = match value.get("id") {
        Some(v) if truthy(v) => v.as_str().filter(|s| is_hex32(s)).map(str::to_string),
        _ => {
            let mut b = [0u8; 16];
            getrandom::fill(&mut b).expect("OS randomness");
            Some(hex::encode(b))
        }
    };
    let Some(id) = id else {
        return Err(Error::value("overlay id must be 32 lowercase hexadecimal characters"));
    };
    let mut out = Map::new();
    out.insert("id".into(), json!(id));
    out.insert("address".into(), json!(address));
    out.insert("options".into(), options);
    Ok(out)
}

/// One stored record as a v3 record. A record without effects (v1, v2) keeps `effects: null` and `before_unknown`.
pub fn clean_record(item: &Value, position: usize, previous_seq: i64) -> Result<Value> {
    let Value::Object(item) = item else {
        return Err(Error::value("overlay history holds a record that is not an object"));
    };
    let mut clean = edit_fields(item)?;
    for key in ["by", "at", "batch"] {
        if let Some(v) = item.get(key) {
            clean.insert(key.into(), v.clone());
        }
    }
    let seq = match item.get("seq") {
        None => Some(position as i64 + 1),
        Some(Value::Number(n)) => n.as_i64(),
        _ => None,
    };
    let id = clean["id"].as_str().unwrap_or_default().to_string();
    let Some(seq) = seq.filter(|s| *s > previous_seq) else {
        return Err(Error::value(format!("overlay record {id} has a sequence number out of order")));
    };
    clean.insert("seq".into(), json!(seq));
    let effects = revisions::clean_effects(item.get("effects"))?;
    let unknown = effects.is_none() || item.get("before_unknown").is_some_and(truthy);
    clean.insert("effects".into(), effects.map_or(Value::Null, Value::Array));
    if unknown {
        clean.insert("before_unknown".into(), json!(true));
    }
    for key in ["imported_from", "merged_from"] {
        if let Some(v) = item.get(key) {
            clean.insert(key.into(), v.clone());
        }
    }
    Ok(Value::Object(clean))
}

pub fn digest_of<S: AsRef<str>>(ids: &[S]) -> String {
    let joined: Vec<&str> = ids.iter().map(AsRef::as_ref).collect();
    hex::encode(Sha256::digest(joined.join("\n").as_bytes()))
}

/// The committed-id set (D32): one entry per cid, `ids` authoritative, `ids_sha256` over the sorted ids.
pub fn clean_commits(raw: Option<&Value>) -> Result<Vec<Value>> {
    let list = match raw {
        None | Some(Value::Null) => return Ok(Vec::new()),
        Some(Value::Array(a)) => a,
        Some(_) => return Err(Error::value("overlay commits must be a list")),
    };
    let mut seen = std::collections::BTreeSet::new();
    let mut clean = Vec::new();
    for entry in list {
        let cid = entry.get("cid").and_then(Value::as_str);
        let ids = entry.get("ids").and_then(Value::as_array).filter(|a| a.iter().all(Value::is_string));
        let (Some(cid), Some(ids)) = (cid, ids) else {
            return Err(Error::value("an overlay commit entry needs a cid and a list of ids"));
        };
        if !seen.insert(cid.to_string()) {
            return Err(Error::value(format!("overlay commits repeat cid {cid}")));
        }
        let mut sorted: Vec<&str> = ids.iter().filter_map(Value::as_str).collect();
        sorted.sort_unstable();
        let digest = digest_of(&sorted);
        if entry.get("ids_sha256").is_some_and(|d| d.as_str() != Some(digest.as_str())) {
            return Err(Error::value(format!("overlay commit {cid} does not match its ids_sha256")));
        }
        let mut merged = entry.as_object().cloned().unwrap_or_default();
        merged.insert("ids_sha256".into(), json!(digest));
        merged.insert("reverted".into(), json!(entry.get("reverted").is_some_and(truthy)));
        clean.push(Value::Object(merged));
    }
    Ok(clean)
}

/// `published_through` (4.8): destination view -> the highest `seq` of this view's records already merged there.
pub fn clean_through(raw: Option<&Value>) -> Value {
    let Some(map) = raw.and_then(Value::as_object) else {
        return json!({});
    };
    Value::Object(
        map.iter().filter(|(_, v)| v.is_i64() && v.as_i64().is_some_and(|n| n >= 0)).map(|(k, v)| (k.clone(), v.clone())).collect(),
    )
}

/// The publish queue's bookkeeping in this view (4.10): one entry per changeset settled here.
pub fn clean_changesets(raw: Option<&Value>) -> Vec<Value> {
    let mut kept: Vec<Value> =
        raw.and_then(Value::as_array).into_iter().flatten().filter(|i| i.get("csid").is_some_and(Value::is_string)).cloned().collect();
    let skip = kept.len().saturating_sub(MAX_CHANGESETS);
    kept.split_off(skip)
}

pub fn empty_store(sha256: &str) -> Store {
    let v = json!({"version": STORE_VERSION, "sha256": sha256, "revision": 0, "base": default_base(), "edits": [], "reverted": [],
                   "journal": [], "commits": [], "archived": [], "stale": null, "published_through": {}, "changesets": []});
    let Value::Object(m) = v else { unreachable!() };
    m
}

fn reread_closure(path: PathBuf) -> impl Fn() -> hy_core::Result<Option<Value>> {
    move || {
        store_record(&path).map_err(|e| match e {
            Error::Core(c) => c,
            Error::View(v) => hy_core::Error::value(v.message),
            Error::Runtime(m) => hy_core::Error::value(m),
        })
    }
}

/// The store in its version-3 shape. A v1 or v2 file upgrades in memory (its `version` still says what was read) and on disk
/// at its first write.
pub fn load_store(settings: &Settings, target: &Target) -> Result<Store> {
    let path = store_path(settings, target)?;
    if path.is_file() && std::fs::metadata(&path)?.len() > MAX_HISTORY_BYTES {
        return Err(Error::value("overlay history exceeds 20 MiB; preserved for review"));
    }
    let snapshot = store_record(&path)?;
    let reread = reread_closure(path.clone());
    let record = hy_store::storelog::read(&path, snapshot, Some(&reread))?;
    let sha = tstr(target, "sha256");
    let binding = lineage_binding(target);
    let Some(mut record) = record else {
        let mut fresh = empty_store(sha);
        if let Some(b) = binding {
            fresh.insert("base".into(), b); // a view created after a commit starts on the head generation
        }
        return Ok(fresh);
    };
    let version = record.get("version").and_then(Value::as_i64);
    if !matches!(version, Some(1..=3)) || record.get("sha256").and_then(Value::as_str) != Some(sha) {
        return Err(Error::value(format!(
            "overlays at {} belong to another build or format; preserve them and use a new target",
            path.display()
        )));
    }
    let too_many = || Error::value(format!("overlay history must contain at most {MAX_OVERLAYS} records"));
    // The stored records are consumed as they are cleaned, so the two copies of a big history are never alive together.
    let items = match record.get_mut("edits") {
        Some(Value::Array(items)) if items.len() <= MAX_OVERLAYS => std::mem::take(items),
        _ => return Err(too_many()),
    };
    let mut clean = Vec::with_capacity(items.len());
    let mut previous = 0;
    for (position, item) in items.into_iter().enumerate() {
        let c = clean_record(&item, position, previous)?;
        previous = c["seq"].as_i64().unwrap_or(previous);
        clean.push(c);
    }
    let ids: std::collections::BTreeSet<&str> = clean.iter().filter_map(|e| e["id"].as_str()).collect();
    if ids.len() != clean.len() {
        return Err(Error::value("overlay history has duplicate edit identities"));
    }
    let mut base = record.get("base").filter(|b| b.is_object()).cloned().unwrap_or_else(default_base);
    if let Some(b) = binding
        && clean.is_empty()
        && !record.get("commits").is_some_and(truthy)
        && base.get("generation") != b.get("generation")
    {
        base = b; // a view with no records follows the head (it has nothing to rebase)
    }
    let revision = match record.get("revision") {
        Some(Value::Number(n)) => n.as_i64().unwrap_or(0),
        Some(Value::String(s)) => s.trim().parse().map_err(|_| Error::value(format!("invalid literal for int() with base 10: '{s}'")))?,
        _ => clean.len() as i64,
    };
    let mut out = Store::new();
    out.insert("version".into(), record["version"].clone());
    out.insert("sha256".into(), json!(sha));
    out.insert("revision".into(), json!(revision));
    out.insert("base".into(), base);
    out.insert("edits".into(), Value::Array(clean));
    out.insert("reverted".into(), record.get("reverted").cloned().unwrap_or_else(|| json!([])));
    out.insert("journal".into(), Value::Array(revisions::clean_journal(record.get("journal"))));
    out.insert("commits".into(), Value::Array(clean_commits(record.get("commits"))?));
    out.insert("archived".into(), record.get("archived").filter(|a| a.is_array()).cloned().unwrap_or_else(|| json!([])));
    out.insert("stale".into(), record.get("stale").filter(|s| s.is_string()).cloned().unwrap_or(Value::Null));
    out.insert("published_through".into(), clean_through(record.get("published_through")));
    out.insert("changesets".into(), Value::Array(clean_changesets(record.get("changesets"))));
    Ok(out)
}

fn stored_version(path: &Path) -> Option<i64> {
    use std::io::Read;
    let mut head = Vec::new();
    std::fs::File::open(path).ok()?.take(8192).read_to_end(&mut head).ok()?;
    // `"version"\s*:\s*(\d+)` anywhere in the first 8 KiB
    let needle = b"\"version\"";
    let mut from = 0;
    while let Some(at) = head[from..].windows(needle.len()).position(|w| w == needle) {
        let mut i = from + at + needle.len();
        while head.get(i).is_some_and(u8::is_ascii_whitespace) {
            i += 1;
        }
        if head.get(i) == Some(&b':') {
            i += 1;
            while head.get(i).is_some_and(u8::is_ascii_whitespace) {
                i += 1;
            }
            let digits: String = head[i..].iter().take_while(|b| b.is_ascii_digit()).map(|b| *b as char).collect();
            if let Ok(n) = digits.parse() {
                return Some(n);
            }
        }
        from += at + needle.len();
    }
    let (_, value, _) = sealed::inspect_file(path, Some(MAX_HISTORY_BYTES + 4096), false).ok()?;
    value?.get("version").and_then(Value::as_i64)
}

/// Migration: the first write over a v1 or v2 file keeps it, once, as `<file>.v<N>.bak`.
fn keep_old_format(path: &Path) -> Result<()> {
    if !path.is_file() {
        return Ok(());
    }
    if let Some(old @ (1 | 2)) = stored_version(path) {
        let backup = path.with_file_name(format!("{}.v{old}.bak", file_name(path)));
        if !backup.exists() {
            hy_core::fsio::atomic_write_point(&backup, &std::fs::read(path)?, &format!("v{old}_backup"), true)?;
        }
    }
    Ok(())
}

/// The record to write: the store in its v3 form, whatever shape the caller holds. `known` are the records of the store on
/// disk, already clean: an equal record at its position is taken as it is.
pub fn v3(store: &Store, target: &Target, known: &[Value]) -> Result<Value> {
    let mut edits = Vec::new();
    let mut previous = 0;
    for (position, item) in store.get("edits").and_then(Value::as_array).into_iter().flatten().enumerate() {
        let same = known.get(position).is_some_and(|k| k == item && k.get("seq").and_then(Value::as_i64).is_some_and(|s| s > previous));
        let edit = if same { item.clone() } else { clean_record(item, position, previous)? };
        previous = edit["seq"].as_i64().unwrap_or(previous);
        edits.push(edit);
    }
    assemble(store, target, edits)
}

/// [`v3`] for a store the caller gives up: its records are moved, not copied. `same[i]` says record `i` equals the clean
/// record known at its position (see `hy_store::storelog::known_edits_equal`).
pub fn v3_owned(mut store: Store, target: &Target, same: &[bool]) -> Result<Value> {
    let items = match store.remove("edits") {
        Some(Value::Array(items)) => items,
        _ => Vec::new(),
    };
    let mut edits = Vec::with_capacity(items.len());
    let mut previous = 0;
    for (position, item) in items.into_iter().enumerate() {
        let known = same.get(position).copied().unwrap_or(false) && item.get("seq").and_then(Value::as_i64).is_some_and(|s| s > previous);
        let edit = if known { item } else { clean_record(&item, position, previous)? };
        previous = edit["seq"].as_i64().unwrap_or(previous);
        edits.push(edit);
    }
    assemble(&store, target, edits)
}

fn assemble(store: &Store, target: &Target, edits: Vec<Value>) -> Result<Value> {
    let base = store.get("base").filter(|b| b.is_object()).cloned().unwrap_or_else(default_base);
    let or_empty = |k: &str| store.get(k).filter(|v| truthy(v)).cloned().unwrap_or_else(|| json!([]));
    let sha = store.get("sha256").cloned().unwrap_or_else(|| json!(tstr(target, "sha256")));
    Ok(json!({
        "version": STORE_VERSION, "sha256": sha, "revision": store["revision"], "base": base, "edits": edits,
        "reverted": or_empty("reverted"), "journal": or_empty("journal"), "commits": clean_commits(store.get("commits"))?,
        "archived": or_empty("archived"), "stale": store.get("stale").cloned().unwrap_or(Value::Null),
        "published_through": clean_through(store.get("published_through")), "changesets": clean_changesets(store.get("changesets")),
    }))
}

/// Version 3, sealed snapshot plus an fsynced append log row per mutation (storelog); a v1 or v2 file is kept once first.
pub fn save_store(settings: &Settings, target: &Target, store: &Store) -> Result<()> {
    let path = store_path(settings, target)?;
    let known = hy_store::storelog::known_edits(&path);
    let known: &[Value] = known.as_ref().and_then(Value::as_array).map_or(&[], Vec::as_slice);
    let record = v3(store, target, known)?;
    write_record(&path, &record)
}

/// [`save_store`] for a store the caller gives up: no copy of its records is made on the way to the log.
pub fn save_store_owned(settings: &Settings, target: &Target, store: Store) -> Result<()> {
    let path = store_path(settings, target)?;
    let same = match store.get("edits") {
        Some(Value::Array(items)) => hy_store::storelog::known_edits_equal(&path, items),
        _ => Vec::new(),
    };
    let record = v3_owned(store, target, &same)?;
    keep_old_format(&path)?;
    hy_store::storelog::save_owned(&path, record, Some(MAX_HISTORY_BYTES as usize), Some(HISTORY_TOO_LARGE))?;
    Ok(())
}

/// The clean `edits` of the store at PATH as this process last wrote or read them (its cache), `Null` when unknown.
pub fn known_edits(path: &Path) -> Value {
    hy_store::storelog::known_edits(path).unwrap_or(Value::Null)
}

const HISTORY_TOO_LARGE: &str = "overlay history would exceed 20 MiB; existing history preserved";

fn write_record(path: &Path, record: &Value) -> Result<()> {
    keep_old_format(path)?;
    hy_store::storelog::save(path, record, Some(MAX_HISTORY_BYTES as usize), Some(HISTORY_TOO_LARGE))?;
    Ok(())
}

/// Ids of the records in a live commit (D32). Reverted commits do not count.
pub fn committed_ids(store: &Store) -> std::collections::BTreeSet<String> {
    let mut found = std::collections::BTreeSet::new();
    for entry in store.get("commits").and_then(Value::as_array).into_iter().flatten() {
        if !entry.get("reverted").is_some_and(truthy) {
            found.extend(entry.get("ids").and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string));
        }
    }
    found
}

/// The records the working copy replays: every record not in a live commit, in `seq` (store) order.
pub fn pending_of(store: &Store) -> Vec<Value> {
    let committed = committed_ids(store);
    store
        .get("edits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|e| !committed.contains(e["id"].as_str().unwrap_or_default()))
        .cloned()
        .collect()
}

/// The overlay marker of 4.2: the pending list plus the base and the committed set it was built on.
pub fn state_of(store: &Store) -> Value {
    let ids: Vec<String> = pending_of(store).iter().map(|e| e["id"].as_str().unwrap_or_default().to_string()).collect();
    let base = store.get("base").filter(|b| truthy(b)).cloned().unwrap_or_else(default_base);
    let committed: Vec<String> = committed_ids(store).into_iter().collect();
    json!({
        "revision": store["revision"], "edits": ids.len(), "ids_sha256": digest_of(&ids),
        "base": {"lineage": base.get("lineage").cloned().unwrap_or_else(|| json!("")), "generation": base.get("generation").cloned().unwrap_or_else(|| json!(0))},
        "committed_sha256": digest_of(&committed),
    })
}

/// Byte-identical to Gson's rendering of the same object in RusticQuery.java: compact, key order as built.
pub fn state_text(state: &Value) -> String {
    String::from_utf8_lossy(&hy_core::json::dumps(state, hy_core::json::FRAME)).into_owned()
}

pub fn has_overlays(settings: &Settings, target: &Target) -> Result<bool> {
    Ok(sealed::exists(&store_path(settings, target)?) && !pending_of(&load_store(settings, target)?).is_empty())
}

pub fn expected_state(settings: &Settings, target: &Target) -> Result<Option<String>> {
    if !sealed::exists(&store_path(settings, target)?) {
        return Ok(None);
    }
    let store = load_store(settings, target)?;
    Ok(if pending_of(&store).is_empty() { None } else { Some(state_text(&state_of(&store))) })
}

/// `working/<key>`: the view's working-copy directory.
pub fn directory(settings: &Settings, target: &Target) -> PathBuf {
    root_path(settings).join("working").join(tstr(target, "key"))
}

/// `backends.read_json(working/<key>/state.json)`: `{}` when missing or unreadable.
pub fn working_state(settings: &Settings, target: &Target) -> Result<Map<String, Value>> {
    let path = directory(settings, target).join("state.json");
    match sealed::read_sealed_info(&path, &ReadOptions::default(), Some(json!({})))?.0 {
        Value::Object(m) => Ok(m),
        _ => Ok(Map::new()),
    }
}

/// A short summary of a store for a reply. `store` is the copy the caller already loaded.
pub fn summary(settings: &Settings, target: &Target, store: Option<Store>) -> Result<Value> {
    let store = match store {
        Some(s) => s,
        None => load_store(settings, target)?,
    };
    let state = working_state(settings, target)?;
    let journal = store["journal"].as_array().cloned().unwrap_or_default();
    let latest = journal.iter().max_by_key(|e| e["revision"].as_i64().unwrap_or(0));
    let pending = pending_of(&store);
    let edits = store["edits"].as_array().cloned().unwrap_or_default();
    let recent: Vec<Value> = edits
        .iter()
        .skip(edits.len().saturating_sub(10))
        .map(|e| json!({"id": e["id"], "address": e["address"], "kind": e["options"].get("kind"), "by": e.get("by"), "at": e.get("at")}))
        .collect();
    let in_sync = !state.is_empty() && state.get("state").and_then(Value::as_str) == Some(state_text(&state_of(&store)).as_str());
    Ok(json!({
        "revision": store["revision"], "view_revision": store["revision"], "edits": edits.len(), "pending": pending.len(),
        "committed": edits.len() - pending.len(),
        "latest_editor": latest.map_or(Value::Null, |l| json!({"by": l["by"], "at": l["at"]})),
        "reverted": store["reverted"].as_array().map_or(0, Vec::len),
        "working_copy": state.get("fork_gpr"), "working_state": state.get("state"), "in_sync": in_sync,
        "last_sync": state.get("last_sync"), "recent": recent,
    }))
}

/// The view's records after revision `since` (by `seq`), each with its effects and whether a live commit holds it.
pub fn changes(settings: &Settings, target: &Target, since: i64, state: &str, limit: usize) -> Result<Value> {
    let store = load_store(settings, target)?;
    let committed = committed_ids(&store);
    let mut rows = Vec::new();
    for edit in store["edits"].as_array().into_iter().flatten() {
        let mine = if committed.contains(edit["id"].as_str().unwrap_or_default()) { "committed" } else { "pending" };
        if edit["seq"].as_i64().unwrap_or(0) <= since || !(state == "all" || state == mine) {
            continue;
        }
        let mut row = json!({
            "seq": edit["seq"], "id": edit["id"], "address": edit["address"], "kind": edit["options"].get("kind"),
            "source": edit["options"].get("source"), "by": edit.get("by"), "at": edit.get("at"), "state": mine, "effects": edit["effects"],
        });
        if edit.get("before_unknown").is_some_and(truthy) {
            row["before_unknown"] = json!(true);
        }
        rows.push(row);
    }
    let truncated = rows.len() > limit;
    let next_since = rows.get(limit.wrapping_sub(1)).filter(|_| truncated).map(|r| r["seq"].clone());
    rows.truncate(limit);
    let mut out = json!({"view_revision": store["revision"], "since": since, "state": state, "changes": rows, "truncated": truncated});
    if let Some(n) = next_since {
        out["next_since"] = n;
    }
    out["archived_commits"] = json!(store.get("archived").and_then(Value::as_array).map_or(0, Vec::len));
    Ok(out)
}

/// `master_generation_changed` when the view holds records on a generation that is no longer the head (4.7).
pub fn stale_reason(store: &Store, target: &Target) -> Option<&'static str> {
    let binding = lineage_binding(target)?;
    let has_work = store.get("edits").is_some_and(truthy) || store.get("commits").is_some_and(truthy);
    let base_generation = store.get("base").and_then(|b| b.get("generation")).and_then(Value::as_i64).unwrap_or(0);
    (has_work && Some(base_generation) != binding["generation"].as_i64()).then_some("master_generation_changed")
}

/// The `rebase` call that settles a stale view.
pub fn rebase_next(store: &Store) -> Value {
    json!({"tool": "ghidra_query", "action": "type_edit", "options": {"kind": "rebase", "expect_revision": store["revision"]}})
}

/// Select a durable annotation namespace without changing the analysed target (`workcopy.with_view`).
pub fn with_view(target: &Target, view: &str) -> Result<Target> {
    if !view.is_empty() && !crate::layout::is_view_name(view) {
        return Err(Error::value("view must be a name of 1..64 letters, digits, dots, dashes or underscores"));
    }
    let origin = target.get("origin_key").filter(|v| truthy(v)).or_else(|| target.get("key").filter(|v| truthy(v))).cloned();
    let mut out = target.clone();
    if view.is_empty() || view == "shared" {
        out.insert("view".into(), json!("shared"));
    } else {
        let key = hex::encode(Sha256::digest(format!("{}\nview:{view}", tstr(target, "key")).as_bytes()));
        out.insert("key".into(), json!(&key[..16]));
        out.insert("view".into(), json!(view));
    }
    if let Some(o) = origin {
        out.insert("origin_key".into(), o);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(root: &Path) -> Settings {
        json!({"root": root.to_str().unwrap()}).as_object().unwrap().clone()
    }

    fn target(lineage: Option<(&str, i64)>) -> Target {
        let mut t = json!({"key": "k1", "sha256": "ab".repeat(32), "name": "prog"}).as_object().unwrap().clone();
        if let Some((id, g)) = lineage {
            t.insert("lineage".into(), json!({"id": id, "generation": g, "origin_key": "k1"}));
        }
        t
    }

    fn edit(id: &str, seq: i64, address: &str, name: &str) -> Value {
        json!({"id": id, "address": address, "options": {"kind": "rename", "name": name}, "seq": seq, "by": {"client": "c"}, "at": 1.5,
               "effects": [{"subject": format!("address:{address}"), "field": "name", "before": "a", "after": name}]})
    }

    #[test]
    fn empty_store_save_load_roundtrip_and_pending() {
        let d = tempfile::Builder::new().prefix("hs").tempdir().unwrap();
        let s = settings(d.path());
        let t = target(Some(("L-0000abcd", 2)));
        let fresh = load_store(&s, &t).unwrap();
        assert_eq!(fresh["base"], json!({"lineage": "L-0000abcd", "generation": 2}));
        assert_eq!(fresh["revision"], 0);
        let mut store = fresh;
        let id1 = "1".repeat(32);
        let id2 = "2".repeat(32);
        store.insert("edits".into(), json!([edit(&id1, 1, "0x401000", "x"), edit(&id2, 2, "0x401010", "y")]));
        store.insert("revision".into(), json!(2));
        store.insert("commits".into(), json!([{"cid": "c-0001", "ids": [id1]}]));
        save_store(&s, &t, &store).unwrap();
        let back = load_store(&s, &t).unwrap();
        assert_eq!(back["edits"].as_array().unwrap().len(), 2);
        assert_eq!(back["commits"][0]["ids_sha256"], digest_of(std::slice::from_ref(&id1)));
        assert_eq!(back["commits"][0]["reverted"], false);
        assert_eq!(pending_of(&back).len(), 1);
        assert_eq!(pending_of(&back)[0]["id"], id2);
        let st = state_of(&back);
        assert_eq!(st["edits"], 1);
        assert_eq!(
            state_text(&st),
            format!(
                "{{\"revision\":2,\"edits\":1,\"ids_sha256\":\"{}\",\"base\":{{\"lineage\":\"L-0000abcd\",\"generation\":2}},\"committed_sha256\":\"{}\"}}",
                digest_of(std::slice::from_ref(&id2)),
                digest_of(std::slice::from_ref(&id1))
            )
        );
        assert!(has_overlays(&s, &t).unwrap());
        let ch = changes(&s, &t, 0, "pending", 40).unwrap();
        assert_eq!(ch["changes"].as_array().unwrap().len(), 1);
        assert_eq!(summary(&s, &t, None).unwrap()["pending"], 1);
    }

    #[test]
    fn refusals_carry_python_messages() {
        let d = tempfile::Builder::new().prefix("hs").tempdir().unwrap();
        let s = settings(d.path());
        let t = target(None);
        let mut store = load_store(&s, &t).unwrap();
        let mut e = edit(&"3".repeat(32), 1, "0x10", "x");
        e["seq"] = json!(0);
        store.insert("edits".into(), json!([e]));
        assert_eq!(
            save_store(&s, &t, &store).unwrap_err().to_string(),
            format!("overlay record {} has a sequence number out of order", "3".repeat(32))
        );
        let bad = json!({"id": "XYZ", "address": "0x10", "options": {"kind": "rename"}});
        assert_eq!(clean_record(&bad, 0, 0).unwrap_err().to_string(), "overlay id must be 32 lowercase hexadecimal characters");
        let none = json!({"id": "4".repeat(32), "options": {"kind": "rename"}});
        assert_eq!(clean_record(&none, 0, 0).unwrap_err().to_string(), "this type edit requires a Ghidra VA");
        let other = json!({"version": 3, "sha256": "ff", "revision": 0, "edits": []});
        let mut wrong = target(None);
        wrong.insert("sha256".into(), json!("00"));
        let _ = other;
        store.insert("edits".into(), json!([edit(&"5".repeat(32), 1, "0x10", "x")]));
        save_store(&s, &t, &store).unwrap();
        assert!(load_store(&s, &wrong).unwrap_err().to_string().contains("belong to another build or format"));
        let mut bad_key = target(None);
        bad_key.insert("key".into(), json!("../x"));
        assert_eq!(store_path(&s, &bad_key).unwrap_err().to_string(), "invalid overlay target key");
    }

    #[test]
    fn view_selection_and_stale_reason() {
        let t = target(Some(("L-0000abcd", 3)));
        let v = with_view(&t, "alice").unwrap();
        assert_eq!(v["view"], "alice");
        assert_eq!(v["key"].as_str().unwrap().len(), 16);
        assert_eq!(v["origin_key"], "k1");
        assert_eq!(with_view(&t, "shared").unwrap()["key"], "k1");
        assert_eq!(
            with_view(&t, "bad name").unwrap_err().to_string(),
            "view must be a name of 1..64 letters, digits, dots, dashes or underscores"
        );
        let mut store = empty_store("x");
        assert_eq!(stale_reason(&store, &t), None);
        store.insert("edits".into(), json!([{}]));
        store.insert("base".into(), json!({"lineage": "L-0000abcd", "generation": 1}));
        assert_eq!(stale_reason(&store, &t), Some("master_generation_changed"));
        assert_eq!(rebase_next(&store)["options"]["kind"], "rebase");
    }
}
