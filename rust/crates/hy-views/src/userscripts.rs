//! `ghidra_run` option handling and script staging (`hydralysis.userscripts`).
//!
//! Ported: [`check_options`], [`choose`], [`stage`], [`list_scripts`]. Not ported (they drive the engine through
//! `hydra.Engine` / `QueryRunner`): `run`, `_save_view`, `_level`, `handle` (the contextvar hand-over to `run`).

use std::path::{Path, PathBuf};

use serde_json::{Map, Value, json};

use crate::error::{Error, Result};
use hy_core::sealed::{self, ReadOptions};

/// The isolation values a caller may ask for. `shared` never (D47); `worker` is chosen for a view, not asked for.
pub const ASKABLE: [&str; 2] = ["private", "exclusive"];
pub const OPTION_KEYS: [&str; 2] = ["isolation", "readonly"];
/// The engine's `scriptIsolation` version from which `isolation:"worker"` exists (E7 advertises 2).
pub const WORKER_VERSION: i64 = 2;

/// Why [`choose`] did not pick an isolation.
#[derive(Debug, thiserror::Error)]
pub enum Refusal {
    /// `userscripts.NotAvailable`: the engine lacks the capability; answered `not_available`, nothing is run.
    #[error("{message}")]
    NotAvailable { capability: &'static str, message: String },
    /// A Python `ValueError`.
    #[error("{0}")]
    Value(String),
}

/// The validated `ghidra_run` options: only `isolation` (private, exclusive) and `readonly` (a boolean).
///
/// `None` (Python `None`) and JSON `null` give an empty set; anything but an object is refused.
pub fn check_options(options: Option<&Value>) -> std::result::Result<Map<String, Value>, String> {
    let options = match options {
        None | Some(Value::Null) => return Ok(Map::new()),
        Some(Value::Object(map)) => map,
        Some(_) => return Err("options must be an object".into()),
    };
    let mut unknown: Vec<&str> = options.keys().map(String::as_str).filter(|k| !OPTION_KEYS.contains(k)).collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return Err(format!("ghidra_run options take isolation and readonly (and as); not {}", unknown.join(", ")));
    }
    // `options.get("isolation")` is None for a missing key and for an explicit null alike.
    match options.get("isolation") {
        None | Some(Value::Null) => {}
        Some(Value::String(s)) if s == "shared" => {
            return Err("a user ghidra_run never runs shared (its changes would be visible to other readers while it \
                        runs); omit isolation to get private, worker or exclusive, or ask for private or exclusive"
                .into());
        }
        Some(Value::String(s)) if ASKABLE.contains(&s.as_str()) => {}
        Some(_) => return Err("ghidra_run options.isolation must be private or exclusive".into()),
    }
    if options.get("readonly").is_some_and(|v| !v.is_boolean()) {
        return Err("ghidra_run options.readonly must be a boolean".into());
    }
    Ok(options.clone())
}

/// The isolation of one run (7.4); `Ok(None)` is today's contained mode (an engine without the capability).
///
/// `level` is the engine's `scriptIsolation` version (0: none), `on_view` whether the program is a view's working copy,
/// `changed` whether it has unsaved edits (`info.changed`), `asked` the caller's `options.isolation`.
pub fn choose(level: i64, on_view: bool, changed: bool, asked: Option<&str>) -> std::result::Result<Option<String>, Refusal> {
    if let Some(asked) = asked {
        if level == 0 {
            return Err(Refusal::NotAvailable {
                capability: "scriptIsolation",
                message: "this engine has no script isolation (hydra.2/3); the script was not run. Call ghidra_run \
                          without options for today's contained mode"
                    .into(),
            });
        }
        if asked == "private" && changed {
            return Err(Refusal::Value(
                "isolation private reads the stored file, and this program has unsaved edits it would not see; omit \
                 isolation (a view is saved first and the script runs in a worker) or ask for exclusive"
                    .into(),
            ));
        }
        return Ok(Some(asked.to_string()));
    }
    if level == 0 {
        return Ok(None);
    }
    if on_view && level >= WORKER_VERSION {
        return Ok(Some("worker".into()));
    }
    Ok(Some(if changed { "exclusive" } else { "private" }.into()))
}

/// Python `str.isspace` for one character (`char::is_whitespace` plus the four information separators).
fn py_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

fn py_strip(text: &str) -> &str {
    text.trim_matches(py_space)
}

/// `str.splitlines()`: the line boundaries Python knows (`\n \r \r\n \v \f \x1c-\x1e \x85 \u2028 \u2029`).
fn splitlines(text: &str) -> Vec<&str> {
    let mut lines = Vec::new();
    let mut start = 0;
    let mut chars = text.char_indices().peekable();
    while let Some((at, c)) = chars.next() {
        if matches!(c, '\n' | '\r' | '\u{b}' | '\u{c}' | '\u{1c}' | '\u{1d}' | '\u{1e}' | '\u{85}' | '\u{2028}' | '\u{2029}') {
            lines.push(&text[start..at]);
            let mut end = at + c.len_utf8();
            if c == '\r' && chars.peek().is_some_and(|&(_, next)| next == '\n') {
                chars.next();
                end += 1;
            }
            start = end;
        }
    }
    if start < text.len() {
        lines.push(&text[start..]);
    }
    lines
}

/// The `usage` line of a script: the first of its first 40 lines that starts, after stripping `/`, `#`, blanks, with "usage".
fn usage_of(text: &str) -> String {
    for line in splitlines(text).into_iter().take(40) {
        let stripped = py_strip(py_strip(line).trim_start_matches(['/', '#', ' ']));
        if stripped.to_lowercase().starts_with("usage") {
            return stripped.to_string();
        }
    }
    String::new()
}

/// Python `Path` ordering on Windows: component-wise on the lower-cased text.
fn sort_key(name: &str) -> String {
    if cfg!(windows) { name.to_lowercase() } else { name.to_string() }
}

/// `PurePath.suffix`: from the last dot, empty for a dotfile or a trailing dot.
fn py_suffix(name: &str) -> &str {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() => &name[i..],
        _ => "",
    }
}

/// `userscripts.list_scripts` after the target is resolved: `folder` is `selected.get("scripts")` (empty or `None`: unset).
///
/// `shown` is `str(Path(folder))`, which the caller (Python) normalises; it is only used in the "no scripts" text.
pub fn list_scripts(target: &str, folder: Option<&str>, shown: &str, name_filter: &str) -> Result<String> {
    let folder = folder.filter(|f| !f.is_empty());
    let dir = folder.map(PathBuf::from).filter(|p| p.is_dir());
    let Some(dir) = dir else {
        return Err(Error::value(format!("target {target} has no scripts directory")));
    };
    let mut names: Vec<String> = std::fs::read_dir(&dir)?
        .map(|entry| entry.map(|e| e.file_name().to_string_lossy().into_owned()))
        .collect::<std::io::Result<_>>()?;
    names.sort_by_key(|n| sort_key(n));
    let wanted = name_filter.to_lowercase();
    let mut rows = Vec::new();
    for name in names {
        if !matches!(py_suffix(&name), ".java" | ".py") {
            continue;
        }
        if !name_filter.is_empty() && !name.to_lowercase().contains(&wanted) {
            continue;
        }
        let bytes = std::fs::read(dir.join(&name))?;
        let usage = usage_of(&String::from_utf8_lossy(&bytes));
        rows.push(format!("{name}  {usage}"));
    }
    Ok(if rows.is_empty() { format!("no scripts in {shown}") } else { rows.join("\n") })
}

/// `str(path.resolve())` without the `\\?\` prefix `canonicalize` adds on Windows.
fn resolved(path: &Path) -> Result<String> {
    let full = std::fs::canonicalize(path)?.display().to_string();
    Ok(full.strip_prefix(r"\\?\").map_or(full.clone(), str::to_string))
}

/// `userscripts._stage`: copy `source` into the user-scripts folder `staged_dir` and record who owns the name.
///
/// `own_dir` is Hydralysis's own `scripts` folder: a name that exists there is refused. Returns the staged file name.
pub fn stage(own_dir: &Path, staged_dir: &Path, source: &Path) -> Result<String> {
    let name = source.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if own_dir.join(&name).exists() {
        return Err(Error::value(format!("{name} is the name of one of Hydralysis's own scripts; rename yours")));
    }
    std::fs::create_dir_all(staged_dir)?;
    let staged = staged_dir.join(&name);
    let data = std::fs::read(source)?;
    let owners_path = staged_dir.join("owners.json");
    let read_owners = || -> Result<Map<String, Value>> {
        let record = sealed::read_sealed_info(&owners_path, &ReadOptions::default(), Some(json!({})))?.0;
        Ok(record.as_object().cloned().unwrap_or_default())
    };
    let current = if staged.is_file() { Some(std::fs::read(&staged)?) } else { None };
    let differs = current.as_ref().is_none_or(|c| *c != data);
    if current.is_some() && differs {
        let owner = read_owners()?.get(&name).and_then(Value::as_str).filter(|o| !o.is_empty()).map(str::to_string);
        if let Some(owner) = owner
            && owner != resolved(source)?
        {
            return Err(Error::value(format!("a different {name} from {owner} is staged already; rename one of them")));
        }
    }
    if differs {
        let temporary = staged_dir.join(format!("{name}.tmp"));
        std::fs::write(&temporary, &data)?;
        hy_core::fsio::replace_file(&temporary, &staged)?;
    }
    let mut owners = read_owners()?;
    owners.insert(name.clone(), Value::String(resolved(source)?));
    sealed::write_sealed_default(&owners_path, &Value::Object(owners))?;
    Ok(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn opts(v: Value) -> std::result::Result<Map<String, Value>, String> {
        check_options(Some(&v))
    }

    #[test]
    fn options_are_validated_like_python() {
        assert_eq!(check_options(None).unwrap(), Map::new());
        assert_eq!(opts(Value::Null).unwrap(), Map::new());
        assert_eq!(opts(json!([])).unwrap_err(), "options must be an object");
        assert_eq!(opts(json!({"isolation": "private", "readonly": true})).unwrap().len(), 2);
        assert_eq!(opts(json!({"isolation": null})).unwrap().len(), 1);
        assert_eq!(
            opts(json!({"zeta": 1, "alpha": 2})).unwrap_err(),
            "ghidra_run options take isolation and readonly (and as); not alpha, zeta"
        );
        assert!(opts(json!({"isolation": "shared"})).unwrap_err().starts_with("a user ghidra_run never runs shared"));
        assert_eq!(opts(json!({"isolation": "worker"})).unwrap_err(), "ghidra_run options.isolation must be private or exclusive");
        assert_eq!(opts(json!({"isolation": 5})).unwrap_err(), "ghidra_run options.isolation must be private or exclusive");
        assert_eq!(opts(json!({"readonly": 1})).unwrap_err(), "ghidra_run options.readonly must be a boolean");
        assert_eq!(opts(json!({"readonly": null})).unwrap_err(), "ghidra_run options.readonly must be a boolean");
    }

    #[test]
    fn isolation_choice_table() {
        assert_eq!(choose(0, false, false, None).unwrap(), None);
        assert_eq!(choose(1, true, false, None).unwrap().as_deref(), Some("private"));
        assert_eq!(choose(1, true, true, None).unwrap().as_deref(), Some("exclusive"));
        assert_eq!(choose(2, true, true, None).unwrap().as_deref(), Some("worker"));
        assert_eq!(choose(2, false, false, None).unwrap().as_deref(), Some("private"));
        assert_eq!(choose(2, false, true, Some("exclusive")).unwrap().as_deref(), Some("exclusive"));
        assert!(matches!(choose(0, false, false, Some("private")), Err(Refusal::NotAvailable { capability: "scriptIsolation", .. })));
        let Err(Refusal::Value(m)) = choose(2, true, true, Some("private")) else { panic!("expected a refusal") };
        assert!(m.starts_with("isolation private reads the stored file"));
    }

    #[test]
    fn splitlines_matches_python() {
        assert_eq!(splitlines("a\nb\r\nc\rd"), vec!["a", "b", "c", "d"]);
        assert_eq!(splitlines("a\n"), vec!["a"]);
        assert_eq!(splitlines("\n\n"), vec!["", ""]);
        assert_eq!(splitlines("a\u{2028}b\u{85}c\u{c}d"), vec!["a", "b", "c", "d"]);
        assert!(splitlines("").is_empty());
    }

    #[test]
    fn scripts_are_listed_with_their_usage_and_filtered() {
        let d = tempfile::Builder::new().prefix("us").tempdir().unwrap();
        std::fs::write(d.path().join("B.java"), "// Usage: B <addr>\nclass B {}").unwrap();
        std::fs::write(d.path().join("a.py"), "# nothing\n#   usage - a\n").unwrap();
        std::fs::write(d.path().join("notes.txt"), "usage: no").unwrap();
        let folder = d.path().to_str().unwrap();
        let text = list_scripts("t", Some(folder), folder, "").unwrap();
        assert_eq!(text, "a.py  usage - a\nB.java  Usage: B <addr>");
        assert_eq!(list_scripts("t", Some(folder), folder, "B").unwrap(), "B.java  Usage: B <addr>");
        assert_eq!(list_scripts("t", Some(folder), folder, "zzz").unwrap(), format!("no scripts in {folder}"));
        assert_eq!(list_scripts("t", None, "", "").unwrap_err().to_string(), "target t has no scripts directory");
        assert_eq!(list_scripts("t", Some("Z:/definitely/not/here"), "", "").unwrap_err().to_string(), "target t has no scripts directory");
    }

    #[test]
    fn staging_refuses_own_names_and_a_different_script_of_the_same_name() {
        let d = tempfile::Builder::new().prefix("us").tempdir().unwrap();
        let (own, staged, one, two) = (d.path().join("own"), d.path().join("staged"), d.path().join("one"), d.path().join("two"));
        for p in [&own, &one, &two] {
            std::fs::create_dir_all(p).unwrap();
        }
        std::fs::write(own.join("Mine.java"), "x").unwrap();
        std::fs::write(one.join("Mine.java"), "x").unwrap();
        std::fs::write(one.join("S.java"), "first").unwrap();
        std::fs::write(two.join("S.java"), "second").unwrap();
        assert_eq!(
            stage(&own, &staged, &one.join("Mine.java")).unwrap_err().to_string(),
            "Mine.java is the name of one of Hydralysis's own scripts; rename yours"
        );
        assert_eq!(stage(&own, &staged, &one.join("S.java")).unwrap(), "S.java");
        assert_eq!(std::fs::read_to_string(staged.join("S.java")).unwrap(), "first");
        assert_eq!(stage(&own, &staged, &one.join("S.java")).unwrap(), "S.java");
        let error = stage(&own, &staged, &two.join("S.java")).unwrap_err().to_string();
        assert!(error.starts_with("a different S.java from ") && error.ends_with(" is staged already; rename one of them"), "{error}");
        let owners = sealed::read_sealed(&staged.join("owners.json")).unwrap();
        assert!(owners["S.java"].as_str().unwrap().ends_with("S.java"));
    }
}
