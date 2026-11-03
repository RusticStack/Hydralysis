//! Durable file IO (`durable.atomic_write` / `replace_file`, `localio.read_bytes`).
//!
//! `atomic_write` writes a sibling temporary file, fsyncs it and replaces the target (a POSIX-semantics rename on
//! Windows, so readers holding the target open do not block it; rename plus a directory fsync elsewhere). A permission or sharing error (an antivirus scan or an
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

/// Replace with POSIX semantics (`std::fs::rename`: FileRenameInfoEx with FILE_RENAME_FLAG_POSIX_SEMANTICS, which Rust's
/// std falls back from on a file system or Windows build that lacks it). `MoveFileExW(MOVEFILE_REPLACE_EXISTING)` is refused
/// with ERROR_ACCESS_DENIED for as long as any reader holds the destination open, even one that shares delete; with readers
/// that always have it open (a slow disk, a scanner) a writer then fails after the whole retry budget. The POSIX rename
/// unlinks the old file under its readers, who keep reading the version they opened. The bytes were fsynced before this
/// call; the destination is flushed once more afterwards, as MOVEFILE_WRITE_THROUGH did, best effort.
#[cfg(windows)]
fn replace_once(source: &Path, destination: &Path) -> std::io::Result<()> {
    fs::rename(source, destination)?;
    if let Ok(handle) = OpenOptions::new().write(true).open(destination) {
        let _ = handle.sync_all();
    }
    Ok(())
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

/// The retry delays of `replace_file`: 50 ms doubling to a 500 ms cap, while the total wait stays within 10 s.
pub fn retry_delays() -> Vec<f64> {
    let (mut delay, mut waited, mut out) = (RETRY_FIRST_S, 0.0, Vec::new());
    while waited + delay <= RETRY_TOTAL_S {
        out.push(delay);
        waited += delay;
        delay = (delay * 2.0).min(RETRY_MAX_DELAY_S);
    }
    out
}

/// Replace `destination` with `source`, retrying a permission error with backoff.
pub fn replace_file(source: &Path, destination: &Path) -> Result<()> {
    let mut delays = retry_delays().into_iter();
    loop {
        match replace_once(source, destination) {
            Ok(()) => return Ok(()),
            Err(error) if is_permission_error(&error) => match delays.next() {
                Some(delay) => std::thread::sleep(Duration::from_secs_f64(delay)),
                None => return Err(error.into()),
            },
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

/// `(file id, mtime in ns, size)`.
pub type FileIdentity = (u64, i128, u64);

/// `(file id, mtime in ns, size)` of a file, the identity `os.stat` gives Python (`st_ino`, `st_mtime_ns`,
/// `st_size`); `None` when it does not exist.
pub fn file_identity(path: &Path) -> Option<FileIdentity> {
    let meta = fs::metadata(path).ok()?;
    let mtime = meta.modified().ok().map_or(0, system_time_ns);
    Some((file_id(path, &meta), mtime, meta.len()))
}

pub fn system_time_ns(time: std::time::SystemTime) -> i128 {
    match time.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => d.as_nanos() as i128,
        Err(e) => -(e.duration().as_nanos() as i128),
    }
}

#[cfg(unix)]
fn file_id(_path: &Path, meta: &fs::Metadata) -> u64 {
    std::os::unix::fs::MetadataExt::ino(meta)
}

#[cfg(windows)]
fn file_id(path: &Path, _meta: &fs::Metadata) -> u64 {
    use windows_sys::Win32::Storage::FileSystem::{BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle};
    // Open without access rights so a locked file still answers; a failure yields 0 (identity then rests on mtime and size).
    let Ok(handle) = fs::OpenOptions::new().access_mode(0).open(path) else { return 0 };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // SAFETY: the handle is open for the duration of the call and info is a valid out-structure.
    let ok = unsafe { GetFileInformationByHandle(std::os::windows::io::AsRawHandle::as_raw_handle(&handle) as _, &mut info) };
    if ok == 0 { 0 } else { (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow) }
}

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
