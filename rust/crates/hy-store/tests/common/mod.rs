//! Shared fixtures for the lineage / backups / events tests (the port of tests/test_commit.py `World` and
//! tests/fakehydra.py `FakeEngine`, reduced to what the storage layer touches).
#![allow(dead_code)]

use hy_store::backups::{BackupEngine, EngineFailure};
use hy_store::lineage;
use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub fn temp() -> tempfile::TempDir {
    std::fs::create_dir_all(env!("CARGO_TARGET_TMPDIR")).unwrap();
    tempfile::Builder::new().prefix("hy-store-").tempdir_in(env!("CARGO_TARGET_TMPDIR")).expect("tempdir")
}

pub fn write(path: &Path, data: &[u8]) {
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, data).unwrap();
}

pub struct World {
    pub temp: tempfile::TempDir,
    pub root: PathBuf,
    pub gpr: PathBuf,
    pub settings: Value,
    pub lid: String,
    pub target: Value,
}

impl World {
    /// An analysed project `analysed/Owned/Owned.gpr` with a `.rep` tree, settings with one backup root, no lineage yet.
    pub fn new() -> World {
        let temp = temp();
        let root = hy_store::config::resolved(temp.path());
        let gpr = root.join("analysed").join("Owned").join("Owned.gpr");
        write(&gpr, b"gpr");
        write(&gpr.parent().unwrap().join("Owned.rep").join("db.1.gbf"), &b"data".repeat(64));
        write(&gpr.parent().unwrap().join("Owned.rep").join("idata").join("~index.dat"), b"index");
        let settings =
            json!({"root": root.join("data").to_string_lossy(), "backup_roots": [{"path": root.join("backups").to_string_lossy()}]});
        let target = json!({"name": "owned", "key": "k-owned-0001", "gpr": gpr.to_string_lossy(), "program": "/owned.exe", "sha256": "ab".repeat(32)});
        World { temp, root, gpr, settings, lid: String::new(), target }
    }

    pub fn with_lineage() -> World {
        let mut w = World::new();
        let made = lineage::ensure(&w.settings, &w.target, None).unwrap();
        w.lid = made["id"].as_str().unwrap().to_string();
        w
    }

    pub fn master_tree(&self) -> String {
        lineage::tree_hash(self.gpr.parent().unwrap()).unwrap()
    }
}

type Hook = Box<dyn Fn(&Path, &Path) + Send + Sync>;

/// `fakehydra.FakeEngine` reduced to `fork_project` / `close_project`: copies the project folder like a clone and writes a sidecar.
pub struct FakeEngine {
    pub calls: Mutex<Vec<(String, Value)>>,
    pub fail_paths: Vec<String>,
    pub after_fork: Option<Hook>,
    pub capabilities: Option<Vec<String>>,
}

impl FakeEngine {
    pub fn new() -> FakeEngine {
        FakeEngine { calls: Mutex::new(Vec::new()), fail_paths: Vec::new(), after_fork: None, capabilities: None }
    }

    pub fn names(&self) -> Vec<String> {
        self.calls.lock().unwrap().iter().map(|(n, _)| n.clone()).collect()
    }
}

fn copy_tree(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for entry in fs::read_dir(from).unwrap().flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if matches!(name.as_str(), "SEALED.json" | "backup.json" | "MANIFEST.json")
            || name.ends_with(".lock")
            || name.ends_with(".lock~")
            || name.ends_with(".fork.json")
        {
            continue;
        }
        let target = to.join(&name);
        if entry.file_type().unwrap().is_dir() {
            copy_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).unwrap();
        }
    }
}

impl BackupEngine for FakeEngine {
    fn call(&self, command: &str, fields: Value) -> Result<Value, EngineFailure> {
        self.calls.lock().unwrap().push((command.to_string(), fields.clone()));
        match command {
            "fork_project" => {
                let source = PathBuf::from(fields["project"].as_str().unwrap());
                let destination = PathBuf::from(fields["path"].as_str().unwrap());
                let text = destination.to_string_lossy().into_owned();
                if self.fail_paths.iter().any(|p| text.contains(p.as_str())) {
                    return Err(EngineFailure { code: "io".into(), message: "disk full".into() });
                }
                let name = source.file_stem().unwrap().to_string_lossy().into_owned();
                copy_tree(source.parent().unwrap(), &destination);
                let sidecar = json!({"format": 1, "purpose": fields.get("purpose").cloned().unwrap_or(json!("fork")), "disposable": true,
                                     "source": source.to_string_lossy()});
                fs::write(destination.join(format!("{name}.fork.json")), sidecar.to_string()).unwrap();
                if fields["purpose"] == "backup" {
                    // The manifest an engine writes (writer "engine"), last and never changed; the sidecar is complete.
                    let sidecar = json!({"format": 1, "purpose": "backup", "disposable": false, "state": "complete"});
                    fs::write(destination.join(format!("{name}.fork.json")), sidecar.to_string()).unwrap();
                    let all = lineage::tree_files(&destination).unwrap();
                    let files = hy_store::backups::manifest_files(&all);
                    let mut manifest = json!({"format": 1, "kind": "ghidra-session-backup", "writer": "engine", "id": "20261029T000000Z-00000001-manual",
                        "purpose": "manual", "createdAt": "2026-10-29T00:00:00Z", "createdBy": {"client": "hydralysis", "harness": "fake"},
                        "source": {"gpr": source.to_string_lossy(), "name": name}, "files": files,
                        "filesetSha256": lineage::fileset_sha256(&hy_store::backups::manifest_files(&all)),
                        "copy": {"method": "clone", "sameVolume": true, "independent": false, "ms": 1},
                        "verify": {"level": "hash", "ok": true, "at": "2026-10-29T00:00:01Z"}});
                    manifest["selfSha256"] = json!(lineage::self_hash(&manifest));
                    fs::write(destination.join("backup.json"), lineage::canonical(&manifest)).unwrap();
                }
                if let Some(hook) = &self.after_fork {
                    hook(source.parent().unwrap(), &destination);
                }
                Ok(
                    json!({"project": "p1", "gpr": destination.join(format!("{name}.gpr")).to_string_lossy(), "method": "clone", "cloned": true, "bytes": 1}),
                )
            }
            "close_project" => Ok(json!({})),
            other => Ok(json!({"command": other})),
        }
    }

    fn capabilities(&self) -> Result<Vec<String>, EngineFailure> {
        self.capabilities.clone().ok_or(EngineFailure { code: "unsupported".into(), message: "no capabilities".into() })
    }

    fn hello(&self) -> Value {
        json!({"protocol": 2, "hydraVersion": "hydra.3", "ghidraVersion": "12.3", "installId": "fake"})
    }

    fn identity(&self) -> Value {
        json!({"client": "tests", "pid": 1})
    }
}
