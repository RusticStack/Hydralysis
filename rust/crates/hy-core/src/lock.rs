//! Cross-process exclusive file locks (`hydralysis.locks`), released by the OS if the holder dies.
//!
//! The locked range is byte 0, length 1, the range `msvcrt.locking` takes in Python's `LaneLock`, so Python and Rust
//! processes exclude each other. On Windows a waiter queues in the kernel (`LockFileEx` without
//! `LOCKFILE_FAIL_IMMEDIATELY` on an overlapped handle) and is served in arrival order; the wait is bounded and the
//! request is cancelled on timeout. Elsewhere the lock is polled every 50 ms.

use crate::error::{Error, Result};
use std::path::Path;
use std::time::{Duration, Instant};

/// A held lock; dropping it releases it.
pub struct LockGuard {
    _inner: imp::Held,
}

impl std::fmt::Debug for LockGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LockGuard")
    }
}

/// Wait up to `timeout_s` for the exclusive lock at `path` (`locks.locked`). `what` names it in `LockBusy`.
pub fn lock(path: &Path, timeout_s: f64, what: &str) -> Result<LockGuard> {
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(timeout_s.max(0.0));
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        match imp::acquire(path, remaining) {
            Ok(Some(inner)) => return Ok(LockGuard { _inner: inner }),
            Ok(None) => return Err(Error::lock_busy(what, path, started.elapsed().as_secs_f64())),
            Err(error) => {
                // Could not queue (the file is being replaced or deleted): retry until the deadline.
                if Instant::now() >= deadline {
                    return Err(if matches!(error, Error::Io(_)) {
                        Error::lock_busy(what, path, started.elapsed().as_secs_f64())
                    } else {
                        error
                    });
                }
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// True when another holder owns the lock at `path` (`locks.held`).
pub fn held(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    matches!(imp::acquire(path, Duration::ZERO), Ok(None))
}

fn seed(path: &Path) -> std::io::Result<()> {
    // Byte 0 must exist before it is locked, or a probe cannot write it.
    if std::fs::metadata(path).map(|m| m.len() == 0).unwrap_or(true) {
        use std::io::Write;
        std::fs::OpenOptions::new().append(true).create(true).open(path)?.write_all(b"0")?;
    }
    Ok(())
}

#[cfg(windows)]
mod imp {
    use super::*;
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE, INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LockFileEx,
        OPEN_ALWAYS, UnlockFileEx,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{CreateEventW, WaitForSingleObject};

    pub struct Held {
        handle: HANDLE,
    }

    // SAFETY: a file HANDLE may be used and closed from any thread.
    unsafe impl Send for Held {}

    impl Drop for Held {
        fn drop(&mut self) {
            let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
            // Unlock explicitly: on close alone the OS releases the range "when resources allow", not at once.
            // SAFETY: handle is the locked file; overlapped is a valid zeroed structure.
            unsafe {
                UnlockFileEx(self.handle, 0, 1, 0, &mut overlapped);
                CloseHandle(self.handle);
            }
        }
    }

    /// `Ok(Some)` held, `Ok(None)` timed out (or busy for a zero timeout).
    pub fn acquire(path: &Path, timeout: Duration) -> Result<Option<Held>> {
        seed(path)?;
        let mut wide: Vec<u16> = std::path::absolute(path).unwrap_or_else(|_| path.to_path_buf()).as_os_str().encode_wide().collect();
        wide.push(0);
        // SAFETY: wide is NUL-terminated; other arguments are plain values.
        let handle = unsafe {
            CreateFileW(
                wide.as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_ALWAYS,
                FILE_FLAG_OVERLAPPED,
                std::ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: manual-reset, initially non-signalled, unnamed event.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            let error = std::io::Error::last_os_error();
            // SAFETY: handle was opened above.
            unsafe { CloseHandle(handle) };
            return Err(error.into());
        }
        // SAFETY: zeroed OVERLAPPED is a valid initial value; it outlives the request (we always wait for completion).
        let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
        overlapped.hEvent = event;
        let mut done: u32 = 0;
        let mut result: Result<Option<()>> = Ok(Some(()));
        // SAFETY: handle/overlapped valid for the whole request.
        unsafe {
            if LockFileEx(handle, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &mut overlapped) == 0 {
                let code = GetLastError();
                if code != ERROR_IO_PENDING {
                    result = Err(std::io::Error::from_raw_os_error(code as i32).into());
                } else {
                    let ms = timeout.as_millis().min(0xFFFF_FFFE) as u32;
                    let signalled = WaitForSingleObject(event, ms);
                    let cancelled = signalled != WAIT_OBJECT_0;
                    if cancelled {
                        CancelIoEx(handle, &overlapped);
                    }
                    // Always wait for the request to finish; a grant that raced the cancel still counts as held.
                    if GetOverlappedResult(handle, &overlapped, &mut done, 1) == 0 {
                        let error = std::io::Error::last_os_error();
                        result = if cancelled { Ok(None) } else { Err(error.into()) };
                    }
                }
            }
            CloseHandle(event);
            match result {
                Ok(Some(())) => Ok(Some(Held { handle })),
                Ok(None) => {
                    CloseHandle(handle);
                    Ok(None)
                }
                Err(error) => {
                    CloseHandle(handle);
                    Err(error)
                }
            }
        }
    }
}

#[cfg(not(windows))]
mod imp {
    use super::*;
    use std::fs::{File, OpenOptions, TryLockError};

    pub struct Held {
        _file: File,
    }

    pub fn acquire(path: &Path, timeout: Duration) -> Result<Option<Held>> {
        seed(path)?;
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        let deadline = Instant::now() + timeout;
        loop {
            match file.try_lock() {
                Ok(()) => return Ok(Some(Held { _file: file })),
                Err(TryLockError::WouldBlock) => {
                    if Instant::now() >= deadline {
                        return Ok(None);
                    }
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(TryLockError::Error(error)) => return Err(error.into()),
            }
        }
    }
}
