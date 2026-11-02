//! The `hydralysis/environment` metadata of the initialize reply.
//!
//! mcp.py computes it at launch (`environment.describe()`: configuration, data root, engine release, file system). The
//! report is read-only and starts no JVM, but it needs the Python modules, so the host asks the worker once and keeps the
//! answer for a few minutes in the temp directory (key: the HYDRALYSIS_*/RUSTICRE_* environment, the working directory,
//! the Python and the catalog version). A later launch with the same key starts no Python at all. Set
//! `HYDRALYSIS_MCP_ENV_TTL_S=0` to always ask.

use crate::worker::Worker;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub struct EnvSlot {
    value: Mutex<Option<Value>>,
    ready: Condvar,
}

impl EnvSlot {
    pub fn new() -> Arc<EnvSlot> {
        Arc::new(EnvSlot {
            value: Mutex::new(None),
            ready: Condvar::new(),
        })
    }

    fn set(&self, value: Value) {
        *self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(value);
        self.ready.notify_all();
    }

    /// The report once it is known (it always is within `timeout`).
    pub fn get(&self, timeout: Duration, version: &str) -> Value {
        let guard = self
            .value
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let (guard, _) = self
            .ready
            .wait_timeout_while(guard, timeout, |value| value.is_none())
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard
            .clone()
            .unwrap_or_else(|| unavailable(version, "the environment report was not ready in time"))
    }
}

fn unavailable(version: &str, why: &str) -> Value {
    json!({
        "version": version, "root": null, "root_source": null, "config": null, "config_source": "none",
        "engine_release": null, "engine_dir": null, "filesystem": {"fs": null, "cow": null, "drive": null},
        "warnings": [], "error": why
    })
}

fn cache_path(version: &str) -> std::path::PathBuf {
    let mut hasher = Sha256::new();
    let mut vars: Vec<(String, String)> = std::env::vars()
        .filter(|(name, _)| {
            let upper = name.to_uppercase();
            let host_only =
                upper.starts_with("HYDRALYSIS_MCP") || upper.starts_with("HYDRALYSIS_WORKER");
            !host_only
                && (upper.starts_with("HYDRALYSIS_")
                    || upper.starts_with("RUSTICRE_")
                    || upper.starts_with("PYTHON")
                    || matches!(
                        upper.as_str(),
                        "APPDATA"
                            | "LOCALAPPDATA"
                            | "USERPROFILE"
                            | "HOME"
                            | "XDG_CONFIG_HOME"
                            | "XDG_DATA_HOME"
                            | "SYSTEMDRIVE"
                    ))
        })
        .collect();
    vars.sort();
    for (name, value) in vars {
        hasher.update(format!("{name}={value}\n"));
    }
    hasher.update(format!(
        "cwd={}\nversion={version}\n",
        std::env::current_dir()
            .map(|dir| dir.display().to_string())
            .unwrap_or_default()
    ));
    let digest = hasher.finalize();
    let key: String = digest
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    std::env::temp_dir().join(format!("hydralysis-mcp-env-{key}.json"))
}

fn ttl() -> u64 {
    std::env::var("HYDRALYSIS_MCP_ENV_TTL_S")
        .ok()
        .and_then(|text| text.parse().ok())
        .unwrap_or(300)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// Resolve the report in the background; `announce` (the stderr banner) is written as soon as it is known.
pub fn resolve(slot: Arc<EnvSlot>, worker: Arc<Worker>, version: String) {
    let _ = std::thread::Builder::new()
        .name("environment".into())
        .spawn(move || {
            let path = cache_path(&version);
            let ttl = ttl();
            if ttl > 0 {
                let cached = std::fs::read_to_string(&path)
                    .ok()
                    .and_then(|text| serde_json::from_str::<Value>(&text).ok());
                if let Some(cached) = cached {
                    let fresh = cached["at"]
                        .as_u64()
                        .is_some_and(|at| now().saturating_sub(at) < ttl);
                    if fresh && cached["environment"].is_object() {
                        announce(cached["announce"].as_str().unwrap_or(""));
                        slot.set(cached["environment"].clone());
                        return;
                    }
                }
            }
            match worker.environment() {
                Ok((environment, banner)) => {
                    announce(&banner);
                    if ttl > 0 {
                        let record =
                            json!({"at": now(), "environment": environment, "announce": banner});
                        let temporary = path.with_extension("tmp");
                        if std::fs::write(&temporary, record.to_string()).is_ok() {
                            let _ = std::fs::rename(&temporary, &path);
                        }
                    }
                    slot.set(environment);
                }
                Err(why) => {
                    eprintln!("hydralysis: the environment report is unavailable: {why}");
                    slot.set(unavailable(&version, &why));
                }
            }
        });
}

fn announce(text: &str) {
    if !text.is_empty() {
        eprint!("{text}");
    }
}
