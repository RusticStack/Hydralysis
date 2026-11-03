//! Where a program's database file is inside a Ghidra project folder.
//!
//! A project is `<name>.gpr` beside `<name>.rep/`. The repository keeps `idata/~index.dat` (the folder and item
//! list), and for each item `idata/<bucket>/<id>.prp` (properties) and `idata/<bucket>/~<id>.db/db.<N>.gbf` (the
//! database; the highest `N` is the current version). Anything else in that folder (a journal, a temporary file of
//! a save in progress) means the file may be changing, and the plane declines.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::error::{Error, Result};

/// Size and modification time of the database file, compared before and after a read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Stamp {
    /// File length.
    pub len: u64,
    /// Last write time.
    pub modified: Option<SystemTime>,
}

/// A program found in a project.
#[derive(Debug, Clone)]
pub struct Located {
    /// The current `db.<N>.gbf`.
    pub gbf: PathBuf,
    /// `N` of that file.
    pub version: u32,
    /// Path of the program in the project (`/name.exe`).
    pub program_path: String,
    /// The domain file name (`name.exe`): what `currentProgram.getName()` answers.
    pub name: String,
    /// The repository file id from the index.
    pub file_id: String,
    /// The stamp of the file when it was found.
    pub stamp: Stamp,
    /// Every path whose state decides what was found: the database, the index and its journal (absent), the
    /// properties file, the folder holding the database versions and `idata` itself. A change in any of them
    /// (new version, journal or save file appearing, replaced index) changes its [`Mark`].
    pub watch: Vec<PathBuf>,
}

/// What `stat` says about a path: length and write time, `None` for both when it does not exist. For a folder the
/// write time changes when an entry is added, removed or renamed in it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mark {
    len: Option<u64>,
    modified: Option<SystemTime>,
}

/// The [`Mark`] of `path` now. One `stat`; it opens no handle that outlives the call.
pub fn mark_of(path: &Path) -> Mark {
    match fs::metadata(path) {
        Ok(meta) => Mark { len: Some(meta.len()), modified: meta.modified().ok() },
        Err(_) => Mark { len: None, modified: None },
    }
}

/// The marks of `paths`, in order.
pub fn marks_of(paths: &[PathBuf]) -> Vec<Mark> {
    paths.iter().map(|p| mark_of(p)).collect()
}

impl Located {
    /// The stamp of the file now.
    pub fn stamp_now(&self) -> Result<Stamp> {
        stamp_of(&self.gbf)
    }
}

fn stamp_of(path: &Path) -> Result<Stamp> {
    let meta = fs::metadata(path)?;
    Ok(Stamp { len: meta.len(), modified: meta.modified().ok() })
}

/// The `<name>.rep` folder of a project given as the `.gpr` file, the project folder, or the `.rep` folder.
fn repository(project: &Path) -> Result<PathBuf> {
    if project.is_file() {
        let is_gpr = project.extension().is_some_and(|e| e.eq_ignore_ascii_case("gpr"));
        if !is_gpr {
            return Err(Error::unsupported("the project path is a file but not a .gpr"));
        }
        let rep = project.with_extension("rep");
        return if rep.is_dir() { Ok(rep) } else { Err(Error::unsupported("the project has no .rep folder beside its .gpr")) };
    }
    if !project.is_dir() {
        return Err(Error::unsupported("the project path does not exist"));
    }
    if project.join("idata").is_dir() {
        return Ok(project.to_path_buf());
    }
    let mut found = Vec::new();
    for entry in fs::read_dir(project)? {
        let path = entry?.path();
        if path.extension().is_some_and(|e| e.eq_ignore_ascii_case("rep")) && path.is_dir() {
            found.push(path);
        }
    }
    match found.len() {
        1 => Ok(found.remove(0)),
        0 => Err(Error::unsupported("the folder holds no project (.rep)")),
        _ => Err(Error::unsupported("the folder holds more than one project")),
    }
}

/// One item of `~index.dat`.
struct Item {
    id: String,
    folder: String,
    name: String,
    file_id: String,
}

fn parse_index(text: &str) -> Result<Vec<Item>> {
    let mut folder = String::new();
    let mut items = Vec::new();
    let mut lines = text.lines();
    match lines.next() {
        Some("VERSION=1") => {}
        _ => return Err(Error::unsupported("~index.dat is not version 1")),
    }
    for line in lines {
        if line.starts_with('/') {
            folder = line.to_owned();
        } else if let Some(item) = line.strip_prefix("  ") {
            let (Some(first), Some(last)) = (item.find(':'), item.rfind(':')) else {
                return Err(Error::failed("malformed item line in ~index.dat"));
            };
            if first == last {
                return Err(Error::failed("malformed item line in ~index.dat"));
            }
            items.push(Item {
                id: item[..first].to_owned(),
                folder: folder.clone(),
                name: item[first + 1..last].to_owned(),
                file_id: item[last + 1..].to_owned(),
            });
        }
    }
    Ok(items)
}

/// The folder holding `~<id>.db` and `<id>.prp`: the first two characters of the id name the bucket, with the last
/// two and a scan of every bucket as fallbacks.
fn storage_dir(idata: &Path, id: &str) -> Result<PathBuf> {
    let wanted = format!("~{id}.db");
    let mut guesses = Vec::new();
    if id.len() >= 2 && id.is_ascii() {
        guesses.push(id[..2].to_owned());
        guesses.push(id[id.len() - 2..].to_owned());
    }
    for guess in guesses {
        let dir = idata.join(guess);
        if dir.join(&wanted).is_dir() {
            return Ok(dir);
        }
    }
    for entry in fs::read_dir(idata)? {
        let dir = entry?.path();
        if dir.is_dir() && dir.join(&wanted).is_dir() {
            return Ok(dir);
        }
    }
    Err(Error::failed("the item has no storage folder"))
}

fn content_type(prp: &str) -> Option<&str> {
    let at = prp.find("NAME=\"CONTENT_TYPE\"")?;
    let rest = &prp[at..];
    let value = rest.find("VALUE=\"")? + "VALUE=\"".len();
    let end = rest[value..].find('"')?;
    Some(&rest[value..value + end])
}

/// Find `program` (`/name.exe` or `name.exe`) in `project`.
///
/// # Errors
///
/// `Unsupported` for a layout this resolver does not read (a journal, unknown files beside the database, several
/// programs with the name), `Failed` for files that are missing or malformed.
pub fn locate(project: &Path, program: &str) -> Result<Located> {
    let rep = repository(project)?;
    let idata = rep.join("idata");
    if idata.join("~index.jrn").exists() {
        return Err(Error::unsupported("the project index has an unrecovered journal"));
    }
    let wanted = if program.starts_with('/') { program.to_owned() } else { format!("/{program}") };
    let index = fs::read_to_string(idata.join("~index.dat")).map_err(|e| Error::unsupported(format!("no readable ~index.dat: {e}")))?;
    let mut hits = Vec::new();
    for item in parse_index(&index)? {
        let path = if item.folder == "/" { format!("/{}", item.name) } else { format!("{}/{}", item.folder, item.name) };
        if path == wanted {
            hits.push((item, path));
        }
    }
    let (item, program_path) = match hits.len() {
        1 => hits.remove(0),
        0 => return Err(Error::unsupported("the program is not in the project index")),
        _ => return Err(Error::unsupported("the program name is ambiguous in the index")),
    };
    let id = item.id;
    let dir = storage_dir(&idata, &id)?;
    let prp = fs::read_to_string(dir.join(format!("{id}.prp"))).map_err(|e| Error::unsupported(format!("no readable {id}.prp: {e}")))?;
    if content_type(&prp) != Some("Program") {
        return Err(Error::unsupported("the item is not a Program"));
    }
    let db_dir = dir.join(format!("~{id}.db"));
    let mut newest: Option<u32> = None;
    for entry in fs::read_dir(&db_dir)? {
        let file = entry?.file_name().to_string_lossy().into_owned();
        let version = file.strip_prefix("db.").and_then(|r| r.strip_suffix(".gbf")).and_then(|n| n.parse::<u32>().ok());
        match version {
            Some(n) => newest = Some(newest.map_or(n, |m| m.max(n))),
            None if file.strip_prefix("db.").is_some_and(|r| r.ends_with(".cp")) => {}
            None => {
                return Err(Error::unsupported(format!("unexpected file {file} beside the database (a save may be in progress)")));
            }
        }
    }
    let version = newest.ok_or_else(|| Error::unsupported("the item has no database version"))?;
    let gbf = db_dir.join(format!("db.{version}.gbf"));
    let stamp = stamp_of(&gbf)?;
    let watch =
        vec![gbf.clone(), idata.join("~index.jrn"), idata.join("~index.dat"), dir.join(format!("{id}.prp")), db_dir.clone(), idata.clone()];
    Ok(Located { gbf, version, program_path, name: item.name, file_id: item.file_id, stamp, watch })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_lines_keep_folder_and_colons_in_names() {
        let text = "VERSION=1\n/\n  00000000:a.exe:111\n/sub\n  00000001:b:c.exe:222\nNEXT-ID:2\nMD5:x\n";
        let items = parse_index(text).unwrap();
        assert_eq!(items.len(), 2);
        assert_eq!((items[0].id.as_str(), items[0].folder.as_str(), items[0].name.as_str()), ("00000000", "/", "a.exe"));
        assert_eq!((items[1].folder.as_str(), items[1].name.as_str(), items[1].file_id.as_str()), ("/sub", "b:c.exe", "222"));
    }

    #[test]
    fn a_foreign_index_version_is_declined() {
        assert!(matches!(parse_index("VERSION=2\n/\n"), Err(Error::Unsupported(_))));
    }

    #[test]
    fn content_type_reads_the_property_state() {
        let prp = "<STATE NAME=\"CONTENT_TYPE\" TYPE=\"string\" VALUE=\"Program\" />";
        assert_eq!(content_type(prp), Some("Program"));
        assert_eq!(content_type("<x/>"), None);
    }
}
