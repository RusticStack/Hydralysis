//! The parts of `hydralysis.workcopy` that do not drive the engine: the working-copy folders and their state file, the
//! shared-base identity, the corpus and type-archive stores, the base-generation lookup, and the mutations of the view
//! store (`revert`, `edit`, `add_proposals`). The store itself (`load_store`, `_save_store`, `summary`, ...) is
//! [`crate::store`]; the conflict rules are [`crate::views`] and [`crate::revisions`].
//!
//! Engine-bound functions stay in Python and are reached through [`Host`]: `heal` and `_sync` (and `_attribution`, which
//! names the calling client). Not ported: `release`, `retire_copies`, `close_superseded_readers`, `discard_forks`,
//! `_apply`, `probe`, `_fork`, `_build_base`, `_base`, `warm_base`, `_marker`, `_sync`, `reader`, `repair`, `refresh`,
//! `rebuilding`, `engine_release`. See `PORTING.md`.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::layout::{Settings, now_f64, root_path};
use crate::records::truthy;
use crate::revisions;
use crate::settle::{py_dumps, view_lock};
use crate::store::{
    self, MAX_OVERLAYS, Store, Target, committed_ids, default_base, digest_of, load_store, rebase_next, save_store, stale_reason,
    store_path, working_state,
};
use crate::views::{Host, rebase_report, reconcile, refuse_stale};
use hy_core::sealed;

/// The bound on a type archive or corpus (`analysis.MAX_CORPUS_BYTES`).
pub const MAX_CORPUS_BYTES: u64 = 1024 * 1024 * 1024;
/// The read block of the hashing loops (`1 << 22`).
const BLOCK: usize = 1 << 22;

/// `str(path)` as Python's `WindowsPath` shows it: backslashes, no trailing separator.
pub fn shown(path: &Path) -> String {
    let text = path.display().to_string();
    if !cfg!(windows) {
        return text;
    }
    let text = text.replace('/', "\\");
    let keep = if text.len() > 3 { text.trim_end_matches('\\') } else { text.as_str() };
    keep.to_string()
}

/// `str(paths.resolved(gpr)).lower()`: the identity under which two spellings of one project path compare equal.
pub fn norm(path: &str) -> String {
    let resolved = std::fs::canonicalize(path)
        .map(|p| {
            let text = p.display().to_string();
            text.strip_prefix(r"\\?\").map_or(text.clone(), str::to_string)
        })
        .unwrap_or_else(|_| std::path::absolute(path).map_or_else(|_| path.to_string(), |p| p.display().to_string()));
    resolved.replace('/', "\\").to_lowercase()
}

fn tstr<'a>(target: &'a Target, key: &str) -> &'a str {
    target.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn view_of(target: &Target) -> &str {
    target.get("view").and_then(Value::as_str).unwrap_or("shared")
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value.and_then(Value::as_array).into_iter().flatten().filter_map(Value::as_str).map(str::to_string).collect()
}

// ---- targets and folders -----------------------------------------------------------------------------------------

fn origin_of(target: &Target) -> Option<Value> {
    target.get("origin_key").filter(|v| truthy(v)).or_else(|| target.get("key").filter(|v| truthy(v))).cloned()
}

/// `workcopy.master_target`: the sealed master as a read target (no overlays, no working copy, no store; D43).
pub fn master_target(target: &Target) -> Target {
    let mut out = target.clone();
    out.insert("view".into(), json!("master"));
    out.insert("master_read".into(), json!(true));
    if let Some(origin) = origin_of(target) {
        out.insert("origin_key".into(), origin);
    }
    out
}

/// `workcopy.view_exists`: does the view of `target` have a store? (A view is created lazily, by its first edit.)
pub fn view_exists(settings: &Settings, target: &Target) -> Result<bool> {
    Ok(sealed::exists(&store_path(settings, target)?))
}

/// `workcopy.view_folders`: the folders that hold the view's working copies: its own and the one its rebases build in.
pub fn view_folders(settings: &Settings, target: &Target) -> Vec<PathBuf> {
    let own = store::directory(settings, target);
    let name = own.file_name().map(|n| format!("{}r", n.to_string_lossy())).unwrap_or_default();
    let rebase = own.with_file_name(name);
    vec![own, rebase]
}

fn state_path(settings: &Settings, target: &Target) -> PathBuf {
    store::directory(settings, target).join("state.json")
}

// ---- the rebase lane ---------------------------------------------------------------------------------------------

thread_local! {
    /// The rebase folders whose lane this thread holds (`workcopy._REBASING`).
    static REBASING: std::cell::RefCell<BTreeSet<String>> = const { std::cell::RefCell::new(BTreeSet::new()) };
}

/// The rebase lane of a view (`workcopy.rebase_lane`): the `.view.lock` of its rebase folder, held for the whole rebase
/// and marked as this thread's, so the switch's own sweep still lists the copies in that folder.
pub struct RebaseLane {
    folder: String,
    _lock: hy_core::lock::LockGuard,
}

impl Drop for RebaseLane {
    fn drop(&mut self) {
        REBASING.with(|set| set.borrow_mut().remove(&self.folder));
    }
}

pub fn rebase_lane(settings: &Settings, target: &Target) -> Result<RebaseLane> {
    let mut shadow = target.clone();
    shadow.insert("key".into(), json!(format!("{}r", tstr(target, "key"))));
    let folder = norm(&store::directory(settings, &shadow).display().to_string());
    let lock = view_lock(settings, &shadow, None)?;
    REBASING.with(|set| set.borrow_mut().insert(folder.clone()));
    Ok(RebaseLane { folder, _lock: lock })
}

/// `workcopy._rebase_building`: `folder` is a rebase folder whose lane another rebase holds, so the copy in it is being
/// built and a sweep of the view must not close it.
fn rebase_building(folder: &Path) -> bool {
    if REBASING.with(|set| set.borrow().contains(&norm(&folder.display().to_string()))) {
        return false;
    }
    hy_core::lock::held(&folder.join(".view.lock"))
}

fn glob_match(name: &str, prefix: &str, suffix: &str) -> bool {
    if cfg!(windows) {
        let lower = name.to_lowercase();
        lower.starts_with(prefix) && lower.ends_with(suffix) && lower.len() >= prefix.len() + suffix.len()
    } else {
        name.starts_with(prefix) && name.ends_with(suffix) && name.len() >= prefix.len() + suffix.len()
    }
}

/// `workcopy._forks_on_disk`: every working copy of the view that is on disk (`w-*/*.gpr` in the view's folders),
/// referenced or not. The rebase folder is left out while another rebase of the view holds its lane.
pub fn forks_on_disk(settings: &Settings, target: &Target) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for (index, folder) in view_folders(settings, target).into_iter().enumerate() {
        if !folder.is_dir() || (index > 0 && rebase_building(&folder)) {
            continue;
        }
        let mut here: Vec<(String, String, PathBuf)> = Vec::new();
        let Ok(entries) = std::fs::read_dir(&folder) else { continue };
        for entry in entries.flatten() {
            let directory = entry.file_name().to_string_lossy().into_owned();
            if !glob_match(&directory, "w-", "") || !entry.path().is_dir() {
                continue;
            }
            let Ok(inner) = std::fs::read_dir(entry.path()) else { continue };
            for file in inner.flatten() {
                let name = file.file_name().to_string_lossy().into_owned();
                if glob_match(&name, "", ".gpr") && file.path().is_file() {
                    here.push((directory.to_lowercase(), name.to_lowercase(), file.path()));
                }
            }
        }
        here.sort();
        found.extend(here.into_iter().map(|(_, _, path)| path));
    }
    found
}

/// `workcopy.superseded_forks`: the view's working copies other than `keep`: the ones its state names (current and
/// retired), `also`, and every other copy on disk. The view lock must be held.
pub fn superseded_forks(settings: &Settings, target: &Target, keep: &[String], also: &[String]) -> Result<Vec<String>> {
    let kept: BTreeSet<String> = keep.iter().filter(|k| !k.is_empty()).map(|k| norm(k)).collect();
    let state = working_state(settings, target)?;
    let mut candidates: Vec<String> = Vec::new();
    candidates.extend(state.get("fork_gpr").and_then(Value::as_str).map(str::to_string));
    candidates.extend(strings(state.get("retired")));
    candidates.extend(also.iter().cloned());
    candidates.extend(forks_on_disk(settings, target).iter().map(|p| shown(p)));
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for gpr in candidates {
        if gpr.is_empty() {
            continue;
        }
        let key = norm(&gpr);
        if !kept.contains(&key) && seen.insert(key) {
            out.push(gpr);
        }
    }
    Ok(out)
}

/// `workcopy._forget_current`: after a discard, the state file stops naming a copy that was discarded as the view's
/// current one, so the next use forks a new copy instead of reusing it. `retired`, when given, replaces the retired list.
pub fn forget_current(settings: &Settings, target: &Target, discarded: &[String], retired: Option<&[String]>) -> Result<()> {
    let state = working_state(settings, target)?;
    if state.is_empty() {
        return Ok(());
    }
    let gone: BTreeSet<String> = discarded.iter().filter(|g| !g.is_empty()).map(|g| norm(g)).collect();
    let current = state.get("fork_gpr").filter(|v| truthy(v)).cloned();
    let mut changed = state.clone();
    if let Some(retired) = retired {
        changed.insert("retired".into(), json!(retired));
    }
    if let Some(current) = current.as_ref().and_then(Value::as_str)
        && gone.contains(&norm(current))
    {
        changed.shift_remove("fork_gpr");
        changed.shift_remove("state");
        let held = strings(changed.get("retired"));
        if !held.iter().any(|g| g == current) && Path::new(current).exists() {
            let mut list = held;
            list.push(current.to_string());
            changed.insert("retired".into(), json!(list));
        }
    }
    if changed != state {
        sealed::write_sealed_default(&state_path(settings, target), &Value::Object(changed))?;
    }
    Ok(())
}

/// `workcopy._retire`: remove old working copies the engine no longer has open and keep the rest for a later sync.
///
/// `open_now` is the engine's open project paths, or `None` when `status` failed (then nothing is removed).
pub fn retire(gprs: &[String], open_now: Option<&[String]>) -> Vec<String> {
    if gprs.is_empty() {
        return Vec::new();
    }
    let Some(open_now) = open_now else { return gprs.to_vec() };
    let open: BTreeSet<String> = open_now.iter().map(|g| norm(g)).collect();
    let mut kept = Vec::new();
    for gpr in gprs {
        let parent = Path::new(gpr).parent().unwrap_or(Path::new(""));
        if open.contains(&norm(gpr)) {
            kept.push(gpr.clone());
            continue;
        }
        let _ = std::fs::remove_dir_all(parent);
        if parent.exists() {
            kept.push(gpr.clone());
        }
    }
    kept
}

// ---- the shared base ---------------------------------------------------------------------------------------------

/// `workcopy.base_key`: one key per (master origin, lineage generation, master revision, engine release).
pub fn base_key(target: &Target, binding: Option<&Value>, master_revision: &Value, release: &Value) -> String {
    let default = default_base();
    let binding = binding.filter(|b| truthy(b)).unwrap_or(&default);
    let origin = target.get("origin_key").or_else(|| target.get("key")).cloned().unwrap_or(Value::Null);
    let material = json!({
        "origin": origin,
        "lineage": binding.get("lineage").cloned().unwrap_or_else(|| json!("")),
        "generation": binding.get("generation").cloned().unwrap_or_else(|| json!(0)),
        "master_revision": master_revision,
        "release": release,
    });
    let text = hy_core::json::dumps(
        &material,
        hy_core::json::Options { layout: hy_core::json::Layout::Compact, sort_keys: true, ensure_ascii: true },
    );
    hex::encode(Sha256::digest(&text))[..20].to_string()
}

/// `workcopy.bases_root`: `bases/` (every master) or, with a target, `bases/<origin key>/`.
pub fn bases_root(settings: &Settings, target: Option<&Target>) -> PathBuf {
    let root = root_path(settings).join("bases");
    match target {
        Some(t) => root.join(origin_of(t).and_then(|o| o.as_str().map(str::to_string)).unwrap_or_default()),
        None => root,
    }
}

fn py_eq(a: &Value, b: &Value) -> bool {
    match (a.as_f64(), b.as_f64()) {
        (Some(x), Some(y)) if a.is_number() && b.is_number() => x == y,
        _ => a == b,
    }
}

/// `workcopy._prefix_matches`: how many leading pending records the program already holds, or `None` if it diverged.
///
/// `wanted` is the marker the store asks for (`state_of`): the program must also have been built on the same base and the
/// same committed set. A marker without `base` is a v2 marker: it matches only generation 0 with an empty committed set.
pub fn prefix_matches(records: &[Value], marker: Option<&Value>, wanted: Option<&Value>) -> Option<usize> {
    let marker = match marker {
        Some(m) if truthy(m) => m,
        _ => return Some(0),
    };
    let empty = digest_of::<String>(&[]);
    if let Some(wanted) = wanted {
        match marker.get("base").filter(|b| !b.is_null()) {
            None => {
                if wanted["base"] != default_base() || wanted["committed_sha256"] != json!(empty) {
                    return None;
                }
            }
            Some(base) if *base != wanted["base"] => return None,
            Some(_) => {}
        }
        if marker.get("committed_sha256").unwrap_or(&json!(empty)) != &wanted["committed_sha256"] {
            return None;
        }
    }
    let count = marker.get("edits").map_or(Some(-1), |v| if v.is_boolean() { None } else { v.as_i64() })?;
    let count = usize::try_from(count).ok().filter(|c| *c <= records.len())?;
    let ids: Vec<&str> = records[..count].iter().map(|r| r["id"].as_str().unwrap_or_default()).collect();
    (marker.get("ids_sha256") == Some(&json!(digest_of(&ids)))).then_some(count)
}

/// `workcopy._same_base`: was the base record of a state file built on the (lineage, generation) `wanted` names?
pub fn same_base(record: Option<&Value>, wanted: &Value) -> bool {
    let pick = |v: Option<&Value>, key: &str, fallback: Value| -> Value {
        v.and_then(|r| r.get(key)).filter(|x| truthy(x)).cloned().unwrap_or(fallback)
    };
    py_eq(&pick(record, "lineage", json!("")), &pick(Some(wanted), "lineage", json!("")))
        && py_eq(&pick(record, "generation", json!(0)), &pick(Some(wanted), "generation", json!(0)))
}

// ---- corpora and type archives ---------------------------------------------------------------------------------

pub fn corpus_path(settings: &Settings, digest: &str) -> PathBuf {
    root_path(settings).join("corpora").join(format!("{digest}.jsonl"))
}

pub fn archive_path(settings: &Settings, digest: &str) -> PathBuf {
    root_path(settings).join("archives").join(format!("{digest}.gdt"))
}

fn random_hex() -> String {
    let mut bytes = [0u8; 16];
    getrandom::fill(&mut bytes).expect("OS randomness");
    hex::encode(bytes)
}

/// SHA-256 of a file read in `BLOCK` pieces.
fn hash_file(path: &Path) -> std::io::Result<(String, u64)> {
    let mut file = std::fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut block = vec![0u8; BLOCK];
    let mut size = 0u64;
    loop {
        let n = file.read(&mut block)?;
        if n == 0 {
            break;
        }
        digest.update(&block[..n]);
        size += n as u64;
    }
    Ok((hex::encode(digest.finalize()), size))
}

/// `workcopy.store_corpus`: copy a corpus under its SHA-256 once; overlay replay never rereads the caller's file.
pub fn store_corpus(settings: &Settings, source: &Path) -> Result<(String, u64)> {
    let (value, _) = hash_file(source)?;
    let destination = corpus_path(settings, &value);
    if !destination.is_file() {
        if let Some(parent) = destination.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let name = destination.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        let temporary = destination.with_file_name(format!("{name}.{}.tmp", random_hex()));
        std::fs::copy(source, &temporary)?;
        hy_core::fsio::replace_file(&temporary, &destination)?;
    }
    Ok((value, std::fs::metadata(&destination)?.len()))
}

/// `workcopy.verify_archive`
pub fn verify_archive(path: &Path, digest: &str, size: u64) -> Result<()> {
    if std::fs::metadata(path)?.len() != size {
        return Err(Error::value(format!("stored type archive has the wrong size: {}", shown(path))));
    }
    if hash_file(path)?.0 != digest {
        return Err(Error::value(format!("stored type archive does not match its SHA-256: {}", shown(path))));
    }
    Ok(())
}

/// `workcopy.store_archive`: snapshot exactly the hashed bytes, bounded and independent of the original file.
pub fn store_archive(settings: &Settings, source: &Path) -> Result<(String, u64)> {
    let mtime = |m: &std::fs::Metadata| m.modified().ok();
    let before = std::fs::metadata(source)?;
    let directory = root_path(settings).join("archives");
    std::fs::create_dir_all(&directory)?;
    let temporary = directory.join(format!("{}.tmp", random_hex()));
    let outcome = (|| -> Result<(String, u64)> {
        let mut input = std::fs::File::open(source)?;
        let mut output = std::fs::OpenOptions::new().write(true).create_new(true).open(&temporary)?;
        let mut digest = Sha256::new();
        let mut size = 0u64;
        let mut block = vec![0u8; BLOCK];
        loop {
            let n = input.read(&mut block)?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > MAX_CORPUS_BYTES {
                return Err(Error::value("archive exceeds 1 GiB"));
            }
            digest.update(&block[..n]);
            std::io::Write::write_all(&mut output, &block[..n])?;
        }
        drop(output);
        let after = std::fs::metadata(source)?;
        if size < 1 || (before.len(), mtime(&before)) != (after.len(), mtime(&after)) {
            return Err(Error::value("archive changed while copying or is empty"));
        }
        let value = hex::encode(digest.finalize());
        let destination = archive_path(settings, &value);
        let _guard = hy_core::lock::lock(&destination.with_extension("lock"), 5.0, "type archive")?;
        if destination.exists() {
            verify_archive(&destination, &value, size)?;
        } else {
            hy_core::fsio::replace_file(&temporary, &destination)?;
        }
        Ok((value, size))
    })();
    let _ = std::fs::remove_file(&temporary);
    outcome
}

/// `workcopy._replayable`: what RusticQuery needs to replay one record; bulk records get their files.
pub fn replayable(settings: &Settings, target: &Target, record: &Value) -> Result<Value> {
    let mut options = record["options"].as_object().cloned().unwrap_or_default();
    let directory = store::directory(settings, target);
    let kind = options.get("kind").and_then(Value::as_str).unwrap_or_default().to_string();
    let id = record["id"].as_str().unwrap_or_default();
    if kind == "import_types" {
        let digest = options.get("corpus_sha256").and_then(Value::as_str).unwrap_or_default().to_string();
        let corpus = corpus_path(settings, &digest);
        if !corpus.is_file() {
            return Err(Error::value(format!(
                "corpus {} of overlay {id} is missing from {}; preserved overlays cannot be replayed",
                digest.chars().take(12).collect::<String>(),
                shown(corpus.parent().unwrap_or(Path::new("")))
            )));
        }
        options.insert("corpus_file".into(), json!(shown(&corpus)));
        options.insert("report_file".into(), json!(shown(&directory.join(format!("import-{id}.json")))));
    }
    if kind == "import_archive" {
        let digest = options.get("archive_sha256").and_then(Value::as_str).unwrap_or_default().to_string();
        let archive = archive_path(settings, &digest);
        let size = options.get("archive_bytes").and_then(Value::as_u64).unwrap_or_default();
        verify_archive(&archive, &digest, size)?;
        options.insert("archive_file".into(), json!(shown(&archive)));
        options.insert("report_file".into(), json!(shown(&directory.join(format!("import-{id}.json")))));
    }
    Ok(json!({"id": record["id"], "address": record["address"], "options": options}))
}

// ---- the base generation of a view -------------------------------------------------------------------------------

/// `workcopy.base_master_gpr`: the project of the generation `store` is based on: the head (`target["gpr"]`) only for a
/// view on the head generation; a view behind it is built from its own generation's sealed project. A generation whose
/// project is gone is refused with `base_unavailable`, naming the rebase.
pub fn base_master_gpr(settings: &Settings, target: &Target, store: &Store) -> Result<String> {
    let Some(binding) = store::lineage_binding(target) else {
        return Ok(tstr(target, "gpr").to_string());
    };
    let base = store.get("base").filter(|b| truthy(b)).cloned().unwrap_or_else(default_base);
    let generation = base.get("generation").filter(|g| truthy(g)).and_then(Value::as_i64).unwrap_or(0);
    if Some(generation) == binding["generation"].as_i64() {
        return Ok(tstr(target, "gpr").to_string());
    }
    let lineage_id = base
        .get("lineage")
        .and_then(Value::as_str)
        .filter(|l| !l.is_empty())
        .map_or_else(|| binding["lineage"].as_str().unwrap_or_default().to_string(), str::to_string);
    let settings_value = Value::Object(settings.clone());
    let mut problem: Option<String> = None;
    let rows: Vec<Value> = match hy_store::lineage::history(&settings_value, &lineage_id) {
        Ok(all) => all.into_iter().filter(|r| r.get("gen").and_then(Value::as_i64) == Some(generation) && truthy(&r["gpr"])).collect(),
        Err(error) => {
            problem = Some(format!("the lineage log could not be read: {error}"));
            Vec::new()
        }
    };
    let mut gpr: Option<String> = rows.last().and_then(|r| r["gpr"].as_str()).map(str::to_string);
    if generation == 0 && gpr.is_none() && problem.is_none() {
        gpr = hy_store::lineage::load(&settings_value, &lineage_id)
            .ok()
            .and_then(|record| record.get("origin_gpr").and_then(Value::as_str).map(str::to_string))
            .filter(|g| !g.is_empty());
    }
    if problem.is_none() && gpr.as_deref().is_none_or(str::is_empty) {
        problem = Some(format!("the lineage log names no project for generation {generation}"));
    } else if problem.is_none() && !Path::new(gpr.as_deref().unwrap_or_default()).is_file() {
        problem = Some(format!("the project of generation {generation} is gone ({})", gpr.as_deref().unwrap_or_default()));
    } else if problem.is_none() && generation > 0 {
        // A published generation is a sealed folder: its manifest must still be the one its log line names.
        let named = rows.iter().find_map(|r| r.get("manifestSha256").and_then(Value::as_str).filter(|s| !s.is_empty()));
        let folder = hy_store::lineage::project_folder_of(gpr.as_deref().unwrap_or_default());
        if hy_store::lineage::read_manifest(&folder).is_none() {
            problem = Some(format!("the folder of generation {generation} has no manifest"));
        } else if named.is_some_and(|n| hy_store::lineage::manifest_file_sha256(&folder).as_deref() != Some(n)) {
            problem = Some(format!("the folder of generation {generation} is not the sealed one its log line names"));
        }
    }
    let Some(problem) = problem else { return Ok(gpr.unwrap_or_default()) };
    Err(Error::Runtime(py_dumps(&json!({
        "error": "base_unavailable", "view": view_of(target), "base": base, "head": binding, "detail": problem,
        "next": rebase_next(store),
        "suggest": "the generation this view is based on is no longer available, so its working copy cannot be rebuilt and Hydralysis does not answer from the head instead. Rebase the view onto the head with ghidra_query action=type_edit options.kind=rebase (the call in `next`); its records are kept in the store",
    }))))
}

/// `workcopy.read_gpr`: the project a read of a view without pending records opens: its base generation. A view that has
/// no store, or none behind the head, reads the head.
pub fn read_gpr(settings: &Settings, target: &Target) -> Result<String> {
    if !target.get("lineage").is_some_and(truthy) || !sealed::exists(&store_path(settings, target)?) {
        return Ok(tstr(target, "gpr").to_string());
    }
    let store = load_store(settings, target)?;
    if stale_reason(&store, target).is_some() { base_master_gpr(settings, target, &store) } else { Ok(tstr(target, "gpr").to_string()) }
}

// ---- mutations of the store ---------------------------------------------------------------------------------------

/// `workcopy.require_revision`: `expect_revision` is mandatory for every mutation on every view; the error carries the
/// current one.
pub fn require_revision(settings: &Settings, target: &Target, expect: Option<i64>, what: &str) -> Result<i64> {
    match expect {
        Some(e) => Ok(e),
        None => {
            let current = load_store(settings, target)?["revision"].as_i64().unwrap_or(0);
            Err(Error::Runtime(py_dumps(&revisions::missing_payload(current, view_of(target), what))))
        }
    }
}

/// `workcopy._selected`: the records whose id, or whose batch, is in `ids`.
pub fn selected(store: &Store, ids: &[String]) -> Vec<Value> {
    let wanted: BTreeSet<&str> = ids.iter().map(String::as_str).collect();
    store
        .get("edits")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter(|e| {
            e["id"].as_str().is_some_and(|i| wanted.contains(i))
                || e.get("batch").and_then(Value::as_str).is_some_and(|b| wanted.contains(b))
        })
        .cloned()
        .collect()
}

fn id_of(edit: &Value) -> &str {
    edit["id"].as_str().unwrap_or_default()
}

fn subjects_of_all(edits: &[Value]) -> Vec<String> {
    let set: BTreeSet<String> =
        edits.iter().flat_map(|e| revisions::subjects_of(e["address"].as_str().unwrap_or_default(), &e["options"])).collect();
    set.into_iter().collect()
}

/// `workcopy.revert`: undo records in one step. The working copy is rebuilt from the master on next use.
///
/// A record a live commit holds is refused (`already_committed`); a record whose removal would leave a later pending record
/// on the same (subject, field) with a stale `before` is refused (`has_dependents`) unless `cascade`.
pub fn revert(host: &dyn Host, settings: &Settings, target: &Target, ids: &[String], expect: Option<i64>, cascade: bool) -> Result<Value> {
    host.heal(settings, target)?;
    let expect = require_revision(settings, target, expect, "revert")?;
    let _lock = view_lock(settings, target, None)?;
    let mut store = load_store(settings, target)?;
    refuse_stale(&store, target, "revert", Some(settings))?;
    let mut dropped = selected(&store, ids);
    if dropped.is_empty() {
        return Err(Error::value(format!("no overlay record or batch matches {}", ids.join(", "))));
    }
    let committed = committed_ids(&store);
    let current = store["revision"].clone();
    let held: Vec<&str> = dropped.iter().map(id_of).filter(|i| committed.contains(*i)).collect();
    if !held.is_empty() {
        return Err(Error::Runtime(py_dumps(&json!({
            "error": "already_committed", "ids": held, "current_revision": current,
            "suggest": "a committed record is history: undo it with a new inverse edit, or revert the commit",
        }))));
    }
    let edits: Vec<Value> = store["edits"].as_array().cloned().unwrap_or_default();
    let dropped_set: BTreeSet<String> = dropped.iter().map(|e| id_of(e).to_string()).collect();
    let later = revisions::dependents(&edits, &dropped_set, &committed);
    if !later.is_empty() && !cascade {
        return Err(Error::Runtime(py_dumps(&json!({
            "error": "has_dependents", "ids": later, "reverting": dropped.iter().map(id_of).collect::<Vec<_>>(),
            "current_revision": current,
            "suggest": "later records of the same subject and field rest on these; revert them first, or pass cascade:true to revert the whole chain",
        }))));
    }
    if !later.is_empty() {
        let later_set: BTreeSet<&str> = later.iter().map(String::as_str).collect();
        dropped.extend(edits.iter().filter(|e| later_set.contains(id_of(e))).cloned());
        // A batch always goes whole.
        let batches: Vec<String> = dropped.iter().filter_map(|e| e.get("batch").and_then(Value::as_str)).map(str::to_string).collect();
        let more: Vec<Value> = selected(&store, &batches).into_iter().filter(|e| !dropped.contains(e)).collect();
        dropped.extend(more);
    }
    let dropped_ids: BTreeSet<String> = dropped.iter().map(|e| id_of(e).to_string()).collect();
    // A commit that has written its PREPARE line still needs its selected records in the store when it finalizes.
    let flying: BTreeMap<String, String> = crate::lifecycle::in_flight_ids(settings, target)?;
    let busy: Vec<&String> = dropped_ids.iter().filter(|i| flying.contains_key(*i)).collect();
    if let Some(first) = busy.first() {
        return Err(Error::Runtime(py_dumps(&json!({
            "error": "commit_in_flight", "ids": busy, "cid": flying[*first], "current_revision": current, "retryAfterMs": 2000,
            "suggest": "a commit is working on these records; retry when it finishes, or commit_abort it first",
        }))));
    }
    let kept: Vec<Value> = edits.iter().filter(|e| !dropped_ids.contains(id_of(e))).cloned().collect();
    let removed: Vec<String> = edits.iter().map(id_of).filter(|i| dropped_ids.contains(*i)).map(str::to_string).collect();
    let subjects = subjects_of_all(&dropped);
    let decision = reconcile(&store, expect, &subjects)?;
    let who = host.attribution();
    let now = now_f64();
    store.insert("edits".into(), Value::Array(kept));
    store.insert("revision".into(), json!(expect_plus_one(&store)));
    let mut reverted = store.get("reverted").and_then(Value::as_array).cloned().unwrap_or_default();
    reverted.push(json!({"ids": removed, "by": who, "at": now}));
    store.insert("reverted".into(), Value::Array(reverted));
    let journal = store["journal"].as_array().cloned().unwrap_or_default();
    let revision = store["revision"].as_i64().unwrap_or(0);
    store.insert(
        "journal".into(),
        Value::Array(revisions::append(&journal, revisions::journal_entry(revision, "revert", &subjects, Some(&who), now))),
    );
    save_store(settings, target, &store)?;
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert("reverted".into(), json!(removed.len()));
    out.insert("revision".into(), json!(revision));
    out.insert("view_revision".into(), json!(revision));
    if !later.is_empty() {
        let later_set: BTreeSet<&str> = later.iter().map(String::as_str).collect();
        out.insert("cascaded".into(), json!(removed.iter().filter(|i| later_set.contains(i.as_str())).collect::<Vec<_>>()));
    }
    out.extend(rebase_report(expect, &decision));
    out.insert("note".into(), json!("the working copy is rebuilt from the unchanged master on the next query"));
    Ok(Value::Object(out))
}

fn expect_plus_one(store: &Store) -> i64 {
    store["revision"].as_i64().unwrap_or(0) + 1
}

/// `workcopy._summary`: the import report's counts; the full report stays in its file.
pub fn summarise_import(report: &Value) -> Value {
    const KEYS: [&str; 17] = [
        "records",
        "archive_types",
        "already_present",
        "archive_sha256",
        "by_kind",
        "fields",
        "embedded_parents",
        "flattened_parents",
        "inherited_fields",
        "functions_typed_this",
        "functions_thiscall_kept",
        "functions_renamed",
        "unresolved_type_names",
        "conflicts_total",
        "failures_total",
        "category",
        "unresolved_top",
    ];
    let mut out = Map::new();
    for key in &KEYS[..16] {
        out.insert((*key).into(), report.get(*key).cloned().unwrap_or(Value::Null));
    }
    let top: Vec<Value> =
        report.get("unresolved").and_then(Value::as_array).map(|a| a.iter().take(10).cloned().collect()).unwrap_or_default();
    out.insert("unresolved_top".into(), Value::Array(top));
    Value::Object(out)
}

fn next_seq(store: &Store, revision: i64) -> i64 {
    let top = store["edits"].as_array().into_iter().flatten().filter_map(|e| e["seq"].as_i64()).max().unwrap_or(0);
    revision.max(top + 1)
}

fn effects_for(state: &Value, id: &str) -> Result<Option<Vec<Value>>> {
    revisions::clean_effects(state.get("effects").and_then(|e| e.get(id)))
}

/// `workcopy.edit`: validate, apply and record one cited edit (or batch) with an optimistic revision check.
///
/// `options` is consumed the way Python's `options.pop(...)` consumes the caller's dict: `expect_revision`, `corpus` and
/// `archive` are removed from it.
pub fn edit(host: &dyn Host, settings: &Settings, target: &Target, address: &str, options: Value, timeout_s: i64) -> Result<Value> {
    let mut options = options.as_object().cloned().ok_or_else(|| Error::value("options must be an object"))?;
    let expect = options.shift_remove("expect_revision").and_then(|v| v.as_i64());
    host.heal(settings, target)?;
    let expect = require_revision(settings, target, expect, "type_edit")?;
    let kind = options.get("kind").and_then(Value::as_str).unwrap_or_default().to_string();
    if kind == "import_types" {
        let source =
            options.shift_remove("corpus").and_then(|v| v.as_str().map(str::to_string)).ok_or_else(|| Error::Runtime("'corpus'".into()))?;
        let (digest, size) = store_corpus(settings, Path::new(&source))?;
        options.insert("corpus_sha256".into(), json!(digest));
        options.insert("corpus_bytes".into(), json!(size));
    }
    if kind == "import_archive" {
        let source = options
            .shift_remove("archive")
            .and_then(|v| v.as_str().map(str::to_string))
            .ok_or_else(|| Error::Runtime("'archive'".into()))?;
        let (digest, size) = store_archive(settings, Path::new(&source))?;
        options.insert("archive_sha256".into(), json!(digest));
        options.insert("archive_bytes".into(), json!(size));
    }
    let mut record = Map::new();
    record.insert("id".into(), json!(random_hex()));
    record.insert("address".into(), json!(address));
    record.insert("options".into(), Value::Object(options.clone()));
    let mut clean = store::edit_of(&record)?;
    clean.insert("by".into(), host.attribution());
    clean.insert("at".into(), json!(now_f64()));
    let _lock = view_lock(settings, target, None)?;
    let mut store = load_store(settings, target)?;
    refuse_stale(&store, target, "type_edit", Some(settings))?;
    let subjects = revisions::subjects_of(address, &clean["options"]);
    let decision = reconcile(&store, expect, &subjects)?;
    if store["edits"].as_array().map_or(0, Vec::len) >= MAX_OVERLAYS {
        return Err(Error::value("overlay history limit reached; export/review it before adding more edits"));
    }
    let state = host.sync(settings, target, &store, timeout_s, Some(&[Value::Object(clean.clone())]), true)?;
    // The subject record: what this edit changed and what was there before. An engine whose script does not report effects
    // leaves the record without them (`before_unknown`): it still replays, it cannot be drift-checked.
    let id = clean["id"].as_str().unwrap_or_default().to_string();
    let effects = effects_for(&state, &id)?;
    clean.insert("effects".into(), effects.as_ref().map_or(Value::Null, |e| json!(e)));
    if effects.is_none() {
        clean.insert("before_unknown".into(), json!(true));
    }
    let revision = store["revision"].as_i64().unwrap_or(0) + 1;
    store.insert("revision".into(), json!(revision));
    clean.insert("seq".into(), json!(next_seq(&store, revision)));
    let mut edits = store["edits"].as_array().cloned().unwrap_or_default();
    edits.push(Value::Object(clean.clone()));
    store.insert("edits".into(), Value::Array(edits));
    let journal = store["journal"].as_array().cloned().unwrap_or_default();
    store.insert(
        "journal".into(),
        Value::Array(revisions::append(
            &journal,
            revisions::journal_entry(revision, "edit", &subjects, clean.get("by"), clean["at"].as_f64().unwrap_or(0.0)),
        )),
    );
    save_store(settings, target, &store)?;
    let report = state.get("last_sync").filter(|l| truthy(l)).and_then(|l| l.get("import_report")).filter(|r| truthy(r));
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert("overlay_id".into(), clean["id"].clone());
    out.insert("revision".into(), json!(revision));
    out.insert("view_revision".into(), json!(revision));
    out.extend(rebase_report(expect, &decision));
    out.insert("by".into(), clean["by"].clone());
    if let Some(report) = report {
        out.insert("import_report".into(), summarise_import(report));
    }
    let applied = if kind == "batch" { options.get("edits").and_then(Value::as_array).map_or(0, Vec::len) } else { 1 };
    out.insert("edits_applied".into(), json!(applied));
    out.insert("working_copy".into(), state.get("fork_gpr").cloned().ok_or_else(|| Error::Runtime("'fork_gpr'".into()))?);
    out.insert("sync".into(), state.get("last_sync").cloned().unwrap_or(Value::Null));
    out.insert("seq".into(), clean["seq"].clone());
    match effects {
        Some(_) => out.insert("effects".into(), clean["effects"].clone()),
        None => out.insert("before_unknown".into(), json!(true)),
    };
    out.insert("persistence".into(), json!("cited, build-bound overlay applied to the working copy; the canonical project is unchanged"));
    Ok(Value::Object(out))
}

/// `workcopy.add_proposals`: add `records` (id, address, options, optional effects) to a view as pending proposals,
/// atomically: the engine applies them all first (a record it refuses leaves the view unchanged), then the store takes
/// them, one revision and one journal entry each, with the effects of this view's program. Used by bundle import.
pub fn add_proposals(
    host: &dyn Host,
    settings: &Settings,
    target: &Target,
    records: &[Value],
    expect: Option<i64>,
    timeout_s: i64,
    imported_from: &Value,
) -> Result<Value> {
    host.heal(settings, target)?;
    let expect = require_revision(settings, target, expect, "import_bundle")?;
    let mut clean: Vec<Map<String, Value>> = Vec::new();
    for record in records {
        let mut slim = Map::new();
        for key in ["id", "address", "options"] {
            if let Some(v) = record.get(key) {
                slim.insert(key.into(), v.clone());
            }
        }
        let mut item = store::edit_of(&slim)?;
        item.insert("by".into(), host.attribution());
        item.insert("at".into(), json!(now_f64()));
        let mut from = imported_from.as_object().cloned().unwrap_or_default();
        from.insert("id".into(), record.get("source_id").cloned().unwrap_or_else(|| record["id"].clone()));
        from.insert("by".into(), record.get("source_by").cloned().unwrap_or(Value::Null));
        from.insert("at".into(), record.get("source_at").cloned().unwrap_or(Value::Null));
        item.insert("imported_from".into(), Value::Object(from));
        clean.push(item);
    }
    let subjects: Vec<String> = clean
        .iter()
        .flat_map(|i| revisions::subjects_of(i["address"].as_str().unwrap_or_default(), &i["options"]))
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let _lock = view_lock(settings, target, None)?;
    let mut store = load_store(settings, target)?;
    refuse_stale(&store, target, "import_bundle", Some(settings))?;
    let decision = reconcile(&store, expect, &subjects)?;
    if store["edits"].as_array().map_or(0, Vec::len) + clean.len() > MAX_OVERLAYS {
        return Err(Error::value("overlay history limit reached; export/review it before adding more edits"));
    }
    let extra: Vec<Value> = clean.iter().cloned().map(Value::Object).collect();
    let state = host.sync(settings, target, &store, timeout_s, Some(&extra), true)?;
    for item in &mut clean {
        let id = item["id"].as_str().unwrap_or_default().to_string();
        let effects = effects_for(&state, &id)?;
        item.insert("effects".into(), effects.as_ref().map_or(Value::Null, |e| json!(e)));
        if effects.is_none() {
            item.insert("before_unknown".into(), json!(true));
        }
        let revision = store["revision"].as_i64().unwrap_or(0) + 1;
        store.insert("revision".into(), json!(revision));
        item.insert("seq".into(), json!(next_seq(&store, revision)));
        let mut edits = store["edits"].as_array().cloned().unwrap_or_default();
        edits.push(Value::Object(item.clone()));
        store.insert("edits".into(), Value::Array(edits));
        let own = revisions::subjects_of(item["address"].as_str().unwrap_or_default(), &item["options"]);
        let journal = store["journal"].as_array().cloned().unwrap_or_default();
        store.insert(
            "journal".into(),
            Value::Array(revisions::append(
                &journal,
                revisions::journal_entry(revision, "edit", &own, item.get("by"), item["at"].as_f64().unwrap_or(0.0)),
            )),
        );
    }
    save_store(settings, target, &store)?;
    let revision = store["revision"].clone();
    let mut out = Map::new();
    out.insert("ok".into(), json!(true));
    out.insert("added".into(), json!(clean.iter().map(|i| i["id"].clone()).collect::<Vec<_>>()));
    out.insert("revision".into(), revision.clone());
    out.insert("view_revision".into(), revision);
    out.extend(rebase_report(expect, &decision));
    out.insert("working_copy".into(), state.get("fork_gpr").cloned().ok_or_else(|| Error::Runtime("'fork_gpr'".into()))?);
    out.insert("sync".into(), state.get("last_sync").cloned().unwrap_or(Value::Null));
    Ok(Value::Object(out))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::{empty_store, pending_of, state_of};

    fn records(n: usize) -> Vec<Value> {
        (1..=n)
            .map(|i| {
                json!({"id": format!("{i:032x}"), "address": format!("0x{:x}", 0x1000 + i),
                       "options": {"kind": "rename", "name": format!("n{i}")}, "seq": i})
            })
            .collect()
    }

    fn base_store(n: usize) -> Store {
        let mut s = empty_store(&"ab".repeat(32));
        s.insert("revision".into(), json!(n));
        s.insert("edits".into(), json!(records(n)));
        s
    }

    fn commit(ids: &[&Value], reverted: bool) -> Value {
        json!([{"cid": "c-1", "ids": ids, "reverted": reverted}])
    }

    fn settings(d: &tempfile::TempDir) -> Settings {
        json!({"root": d.path().to_str().unwrap()}).as_object().unwrap().clone()
    }

    // tests/test_store_v3.py: test_the_marker_of_a_program_built_before_the_commit_no_longer_matches
    #[test]
    fn the_marker_of_a_program_built_before_the_commit_no_longer_matches() {
        let before = base_store(3);
        let marker = state_of(&before);
        assert_eq!(prefix_matches(&pending_of(&before), Some(&marker), Some(&state_of(&before))), Some(3));
        let recs = records(3);
        let mut after = before.clone();
        after.insert("commits".into(), commit(&[&recs[0]["id"], &recs[1]["id"]], false));
        let wanted = state_of(&after);
        assert_eq!(wanted["edits"], 1);
        assert_eq!(prefix_matches(&pending_of(&after), Some(&marker), Some(&wanted)), None);
        let mut rebuilt = after.clone();
        rebuilt.insert("revision".into(), json!(3));
        let built = state_of(&rebuilt);
        assert_eq!(prefix_matches(&pending_of(&after), Some(&built), Some(&wanted)), Some(1));
        let mut moved = after.clone();
        moved.insert("base".into(), json!({"lineage": "L-1", "generation": 2}));
        assert_eq!(prefix_matches(&pending_of(&moved), Some(&built), Some(&state_of(&moved))), None);
    }

    // tests/test_store_v3.py: test_a_v2_style_marker_matches_only_generation_zero_with_an_empty_committed_set
    #[test]
    fn a_v2_style_marker_matches_only_generation_zero_with_an_empty_committed_set() {
        let store = base_store(2);
        let full = state_of(&store);
        let v2 = json!({"revision": full["revision"], "edits": full["edits"], "ids_sha256": full["ids_sha256"]});
        assert_eq!(prefix_matches(&records(2), Some(&v2), Some(&full)), Some(2));
        let recs = records(2);
        let mut with_commit = store.clone();
        with_commit.insert("commits".into(), commit(&[&recs[0]["id"]], false));
        assert_eq!(prefix_matches(&pending_of(&with_commit), Some(&v2), Some(&state_of(&with_commit))), None);
        let mut later = store.clone();
        later.insert("base".into(), json!({"lineage": "L-1", "generation": 1}));
        assert_eq!(prefix_matches(&records(2), Some(&v2), Some(&state_of(&later))), None);
    }

    #[test]
    fn prefix_matching_rejects_every_malformed_marker() {
        let recs = records(2);
        assert_eq!(prefix_matches(&recs, None, None), Some(0));
        assert_eq!(prefix_matches(&recs, Some(&json!({})), None), Some(0));
        for count in [json!(true), json!(3), json!(-1), json!(1.0), json!("1")] {
            assert_eq!(prefix_matches(&recs, Some(&json!({"x": 1, "edits": count})), None), None, "{count}");
        }
        assert_eq!(prefix_matches(&recs, Some(&json!({"x": 1})), None), None);
        let one = digest_of(&[recs[0]["id"].as_str().unwrap()]);
        assert_eq!(prefix_matches(&recs, Some(&json!({"edits": 1, "ids_sha256": one})), None), Some(1));
        assert_eq!(prefix_matches(&recs, Some(&json!({"edits": 1, "ids_sha256": "0"})), None), None);
    }

    #[test]
    fn a_state_file_base_is_the_same_only_for_the_same_lineage_and_generation() {
        let wanted = json!({"lineage": "L-1", "generation": 2});
        assert!(same_base(Some(&json!({"lineage": "L-1", "generation": 2})), &wanted));
        assert!(!same_base(Some(&json!({"lineage": "L-1", "generation": 3})), &wanted));
        assert!(!same_base(None, &wanted));
        assert!(same_base(None, &json!({"lineage": "", "generation": 0})));
        assert!(same_base(Some(&json!({"lineage": null, "generation": null})), &json!({})));
    }

    // tests/test_archive_import.py: test_snapshot_is_hashed_and_verified_on_every_replay
    #[test]
    fn a_snapshot_is_hashed_and_verified_on_every_replay() {
        let d = tempfile::Builder::new().prefix("wc").tempdir().unwrap();
        let s = settings(&d);
        let source = d.path().join("source.gdt");
        std::fs::write(&source, b"archive fixture bytes").unwrap();
        let (digest, size) = store_archive(&s, &source).unwrap();
        assert_eq!(digest, hex::encode(Sha256::digest(b"archive fixture bytes")));
        let record = json!({"id": "a".repeat(32), "address": "", "options": {"kind": "import_archive",
            "source": "fixture.gdt:types", "archive_sha256": digest, "archive_bytes": size}});
        std::fs::write(&source, b"changed original").unwrap();
        let target = json!({"key": "target"}).as_object().unwrap().clone();
        let result = replayable(&s, &target, &record).unwrap();
        let stored = PathBuf::from(result["options"]["archive_file"].as_str().unwrap());
        assert_eq!(std::fs::read(&stored).unwrap(), b"archive fixture bytes");
        std::fs::write(&stored, b"archive fixture byteX").unwrap();
        assert!(replayable(&s, &target, &record).unwrap_err().to_string().contains("SHA-256"));
    }

    // tests/test_archive_import.py: test_snapshot_conflicting_existing_content_is_not_replaced
    #[test]
    fn a_conflicting_existing_snapshot_is_not_replaced() {
        let d = tempfile::Builder::new().prefix("wc").tempdir().unwrap();
        let s = settings(&d);
        let source = d.path().join("source.gdt");
        std::fs::write(&source, b"archive fixture bytes").unwrap();
        let (digest, _) = store_archive(&s, &source).unwrap();
        let stored = archive_path(&s, &digest);
        std::fs::write(&stored, b"archive fixture byteX").unwrap();
        assert!(store_archive(&s, &source).unwrap_err().to_string().contains("SHA-256"));
        assert_eq!(std::fs::read(&stored).unwrap(), b"archive fixture byteX");
        let leftovers =
            std::fs::read_dir(stored.parent().unwrap()).unwrap().flatten().filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"));
        assert_eq!(leftovers.count(), 0, "no temporary file is left behind");
    }

    #[test]
    fn empty_archives_are_refused_and_corpora_are_stored_once() {
        let d = tempfile::Builder::new().prefix("wc").tempdir().unwrap();
        let s = settings(&d);
        let empty = d.path().join("empty.gdt");
        std::fs::write(&empty, b"").unwrap();
        assert_eq!(store_archive(&s, &empty).unwrap_err().to_string(), "archive changed while copying or is empty");
        let corpus = d.path().join("c.jsonl");
        std::fs::write(&corpus, b"{}\n").unwrap();
        let (digest, size) = store_corpus(&s, &corpus).unwrap();
        assert_eq!((digest.len(), size), (64, 3));
        std::fs::write(&corpus, b"changed").unwrap();
        assert_eq!(store_corpus(&s, &corpus).unwrap().0.len(), 64);
        assert_eq!(std::fs::read(corpus_path(&s, &digest)).unwrap(), b"{}\n");
        let missing = json!({"id": "b".repeat(32), "address": "", "options": {"kind": "import_types", "corpus_sha256": "f".repeat(64)}});
        let target = json!({"key": "t"}).as_object().unwrap().clone();
        let error = replayable(&s, &target, &missing).unwrap_err().to_string();
        assert!(error.starts_with(&format!("corpus {} of overlay {} is missing from ", "f".repeat(12), "b".repeat(32))), "{error}");
    }

    #[test]
    fn views_masters_and_bases() {
        let t = json!({"key": "k1", "sha256": "x", "name": "p"}).as_object().unwrap().clone();
        let m = master_target(&t);
        assert_eq!((m["view"].as_str(), m["master_read"].as_bool(), m["origin_key"].as_str()), (Some("master"), Some(true), Some("k1")));
        let d = tempfile::Builder::new().prefix("wc").tempdir().unwrap();
        let s = settings(&d);
        assert_eq!(view_folders(&s, &t)[1].file_name().unwrap().to_string_lossy(), "k1r");
        assert!(!view_exists(&s, &t).unwrap());
        assert_eq!(bases_root(&s, Some(&t)), root_path(&s).join("bases").join("k1"));
        let release = json!({"hydraVersion": "1"});
        let a = base_key(&t, None, &json!(3), &release);
        assert_eq!(a.len(), 20);
        assert_eq!(a, base_key(&t, Some(&default_base()), &json!(3), &release));
        assert_ne!(a, base_key(&t, None, &json!(4), &release));
        assert_ne!(a, base_key(&t, Some(&json!({"lineage": "L", "generation": 1})), &json!(3), &release));
    }

    #[test]
    fn retire_removes_closed_copies_and_keeps_open_ones() {
        let d = tempfile::Builder::new().prefix("wc").tempdir().unwrap();
        let mk = |n: &str| {
            let dir = d.path().join(n);
            std::fs::create_dir_all(&dir).unwrap();
            let gpr = dir.join("p.gpr");
            std::fs::write(&gpr, b"x").unwrap();
            gpr.display().to_string()
        };
        let (a, b) = (mk("w-a"), mk("w-b"));
        assert!(retire(&[], None).is_empty());
        assert_eq!(retire(&[a.clone(), b.clone()], None), vec![a.clone(), b.clone()]);
        assert_eq!(retire(&[a.clone(), b.clone()], Some(&[b.to_uppercase()])), vec![b.clone()]);
        assert!(!Path::new(&a).exists() && Path::new(&b).exists());
    }

    #[test]
    fn a_forgotten_current_copy_is_dropped_from_the_state_and_remembered_as_retired() {
        let d = tempfile::Builder::new().prefix("wc").tempdir().unwrap();
        let s = settings(&d);
        let t = json!({"key": "k1", "sha256": "x"}).as_object().unwrap().clone();
        let copy = d.path().join("working").join("k1").join("w-1").join("p.gpr");
        std::fs::create_dir_all(copy.parent().unwrap()).unwrap();
        std::fs::write(&copy, b"x").unwrap();
        let gpr = copy.display().to_string();
        let path = store::directory(&s, &t).join("state.json");
        // no state file: nothing is written
        forget_current(&s, &t, std::slice::from_ref(&gpr), None).unwrap();
        assert!(!path.exists());
        sealed::write_sealed_default(&path, &json!({"fork_gpr": gpr, "state": "{}", "retired": [], "keep": 1})).unwrap();
        forget_current(&s, &t, &[gpr.to_uppercase()], None).unwrap();
        let now = working_state(&s, &t).unwrap();
        assert_eq!((now.get("fork_gpr"), now.get("state"), now["keep"].as_i64()), (None, None, Some(1)));
        assert_eq!(now["retired"], json!([gpr]));
        assert_eq!(superseded_forks(&s, &t, &[], &[]).unwrap(), vec![gpr.clone()]);
        assert!(superseded_forks(&s, &t, std::slice::from_ref(&gpr), &[]).unwrap().is_empty());
        assert_eq!(forks_on_disk(&s, &t), vec![copy]);
    }
}
