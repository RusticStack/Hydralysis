//! Durable file IO (`durable.atomic_write` / `replace_file`, `localio.read_bytes`).
//!
//! `atomic_write` writes a sibling temporary file, fsyncs it and replaces the target (MoveFileExW with write-through
//! on Windows; rename plus a directory fsync elsewhere). A permission or sharing error (an antivirus scan or an
//! indexer holding the target) is retried with backoff.

use crate::error::{Error, Result};
use crate::fault::{die, fault};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

pub const RETRY_FIRST_S: f64 = 0.05;
pub const RETRY_MAX_DELAY_S: f64 = 0.5;
pub const RETRY_TOTAL_S: f64 = 10.0;
pub const DEFAULT_MAX_BYTES: u64 = 32 * 1024 * 1024;

/// `os.path.abspath` for a path that may not exist (no symlink resolution, no `\\?\` prefix added).
pub fn abspath(path: &Path) -> PathBuf {
    std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf())
}

/// Windows extended-length form for paths of 240 characters or more.
#[cfg(windows)]
fn extended(path: &Path) -> Vec<u16> {
    use std::os::windows::ffi::OsStrExt;
    let abs = abspath(path);
    let mut wide: Vec<u16> = abs.as_os_str().encode_wide().collect();
    let verbatim: Vec<u16> = "\\\\?\\".encode_utf16().collect();
    if wide.len() >= 240 && !wide.starts_with(&verbatim) {
        let unc: Vec<u16> = "\\\\".encode_utf16().collect();
        wide = if wide.starts_with(&unc) {
            let mut v: Vec<u16> = "\\\\?\\UNC\\".encode_utf16().collect();
            v.extend_from_slice(&wide[2..]);
            v
        } else {
            let mut v = verbatim;
            v.extend_from_slice(&wide);
            v
        };
    }
    wide.push(0);
    wide
}

#[cfg(windows)]
fn replace_once(source: &Path, destination: &Path) -> std::io::Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH, MoveFileExW};
    let (from, to) = (extended(source), extended(destination));
    // SAFETY: both buffers are NUL-terminated UTF-16 that outlive the call.
    let ok = unsafe { MoveFileExW(from.as_ptr(), to.as_ptr(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH) };
    if ok == 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
}

#[cfg(not(windows))]
fn replace_once(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)?;
    if let Some(parent) = destination.parent() {
        fsync_directory(parent);
    }
    Ok(())
}

/// Directory entries cannot be forced on Windows; every state self-validates.
pub fn fsync_directory(directory: &Path) {
    #[cfg(not(windows))]
    if let Ok(handle) = File::open(directory) {
        let _ = handle.sync_all();
    }
    #[cfg(windows)]
    let _ = directory;
}

/// Python maps ERROR_ACCESS_DENIED and ERROR_SHARING_VIOLATION (and lock violation) to PermissionError.
pub fn is_permission_error(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::PermissionDenied || matches!(error.raw_os_error(), Some(5 | 32 | 33))
}

/// Replace `destination` with `source`, retrying a permission error with backoff.
pub fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    let (mut delay, mut waited) = (RETRY_FIRST_S, 0.0);
    loop {
        match replace_once(source, destination) {
            Ok(()) => return Ok(()),
            Err(error) if is_permission_error(&error) => {
                if waited + delay > RETRY_TOTAL_S {
                    return Err(error.into());
                }
                std::thread::sleep(Duration::from_secs_f64(delay));
                waited += delay;
                delay = (delay * 2.0).min(RETRY_MAX_DELAY_S);
            }
            Err(error) => return Err(error.into()),
        }
    }
}

fn write_new(path: &Path, data: &[u8], sync: bool) -> std::io::Result<()> {
    let mut handle = OpenOptions::new().write(true).create_new(true).open(path)?;
    handle.write_all(data)?;
    if sync {
        handle.sync_all()?;
    }
    Ok(())
}

fn name_of(path: &Path) -> String {
    path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
}

/// `path.with_name(path.name + suffix)`.
pub fn with_suffix(path: &Path, suffix: &str) -> PathBuf {
    path.with_file_name(format!("{}{}", name_of(path), suffix))
}

pub fn create_parent(path: &Path) -> std::io::Result<()> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => fs::create_dir_all(parent),
        _ => Ok(()),
    }
}

/// Write bytes so that a reader sees the old file or the new one, never a mixture. `sync = false` skips the fsync of
/// the new bytes: only for a copy that is never the sole valid version (the `.bak` of `write_sealed`).
pub fn atomic_write_point(path: &Path, data: &[u8], point: &str, sync: bool) -> Result<()> {
    create_parent(path)?;
    let temporary = with_suffix(path, &format!(".{}.tmp", uuid::Uuid::new_v4().simple()));
    let outcome = (|| -> Result<()> {
        if let Some(torn) = fault(&format!("{point}.torn"))? {
            // A non-atomic writer killed halfway: n bytes land in the file itself.
            let mut handle = File::create(path)?;
            handle.write_all(&data[..torn.min(data.len())])?;
            handle.sync_all()?;
            die();
        }
        write_new(&temporary, data, sync)?;
        fault(&format!("{point}.before_replace"))?;
        replace_file(&temporary, path)?;
        fault(&format!("{point}.after_replace"))?;
        Ok(())
    })();
    if outcome.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    outcome
}

pub fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    atomic_write_point(path, data, "atomic", true)
}

/// `localio.read_bytes`: shared read (read/write/delete sharing is std's default on Windows) within a budget.
pub fn read_bytes_max(path: &Path, max_bytes: u64) -> Result<Vec<u8>> {
    if max_bytes == 0 || max_bytes > DEFAULT_MAX_BYTES {
        return Err(Error::value(format!("metadata read budget must be 1..{DEFAULT_MAX_BYTES} bytes")));
    }
    let mut handle = File::open(path)?;
    let size = handle.metadata().map(|m| m.len()).unwrap_or(0);
    let over = || Error::value(format!("metadata exceeds {max_bytes}-byte read budget: {}", path.display()));
    if size > max_bytes {
        return Err(over());
    }
    let mut data = Vec::with_capacity(size as usize);
    (&mut handle).take(max_bytes + 1).read_to_end(&mut data)?;
    if data.len() as u64 > max_bytes {
        return Err(over());
    }
    Ok(data)
}

pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    read_bytes_max(path, DEFAULT_MAX_BYTES)
}

/// `Ok(None)` when the file does not exist.
pub fn read_optional(path: &Path, max_bytes: Option<u64>) -> Result<Option<Vec<u8>>> {
    match read_bytes_max(path, max_bytes.unwrap_or(DEFAULT_MAX_BYTES)) {
        Ok(data) => Ok(Some(data)),
        Err(error) if error.is_not_found() => Ok(None),
        Err(error) => Err(error),
    }
}

