//! Cross-process OS file locks, released by the OS if the holder dies (`hydralysis.locks`).
//!
//! The lock is one exclusive byte-range lock on byte 0 (length 1) of the lock file, the same range the Python
//! `msvcrt.locking` takes, so Rust and Python holders exclude each other. On Windows a bounded wait queues in the
//! kernel (`LockFileEx` on an overlapped handle) and is served in arrival order; elsewhere it polls every 50 ms.

use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// A bounded wait for an OS lock ran out (PROTOCOL-3.md 4.10, D44).
#[derive(Debug, Clone, thiserror::Error)]
#[error("{what} is busy ({name}); retry shortly")]
pub struct LockBusy {
    pub what: String,
    pub path: PathBuf,
    pub waited_s: f64,
    pub retry_after_ms: u64,
    name: String,
}

impl LockBusy {
    pub fn new(what: &str, path: &Path, waited_s: f64) -> Self {
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        Self {
            what: what.into(),
            path: path.into(),
            waited_s: (waited_s * 1000.0).round() / 1000.0,
            retry_after_ms: 1000,
            name,
        }
    }

    /// The structured `busy` reply (same keys and text as Python `LockBusy.payload`).
    pub fn payload(&self) -> serde_json::Value {
        serde_json::json!({
            "error": "busy", "what": self.what, "lock": self.name, "waited_s": self.waited_s,
            "retryAfterMs": self.retry_after_ms,
            "suggest": "another client holds this lock; retry after retryAfterMs, nothing was changed",
        })
    }
}

fn seed(path: &Path) -> std::io::Result<()> {
    let empty = std::fs::metadata(path)
        .map(|m| m.len() == 0)
        .unwrap_or(true);
    if empty {
        // byte 0 must exist before it is locked, as LaneLock does
        OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)?
            .write_all(b"0")?;
    }
    Ok(())
}

#[cfg(windows)]
mod sys {
    use std::os::windows::ffi::OsStrExt;
    use std::path::Path;
    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_IO_PENDING, GENERIC_READ, GENERIC_WRITE, GetLastError, HANDLE,
        INVALID_HANDLE_VALUE, WAIT_OBJECT_0,
    };
    use windows_sys::Win32::Storage::FileSystem::{
        CreateFileW, FILE_FLAG_OVERLAPPED, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY, LockFileEx, OPEN_ALWAYS, UnlockFileEx,
    };
    use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
    use windows_sys::Win32::System::Threading::{
        CreateEventW, WaitForMultipleObjects, WaitForSingleObject,
    };

    pub struct Handle(pub HANDLE);
    // SAFETY: a Win32 file handle may be used and closed from any thread.
    unsafe impl Send for Handle {}

    impl Drop for Handle {
        fn drop(&mut self) {
            // SAFETY: owned, valid handle closed once.
            unsafe { CloseHandle(self.0) };
        }
    }

    pub fn wide(path: &Path) -> Vec<u16> {
        path.as_os_str().encode_wide().chain(Some(0)).collect()
    }

    fn open(path: &Path, flags: u32) -> std::io::Result<Handle> {
        // SAFETY: valid NUL-terminated wide string; other arguments are plain values.
        let h = unsafe {
            CreateFileW(
                wide(path).as_ptr(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                std::ptr::null(),
                OPEN_ALWAYS,
                flags,
                std::ptr::null_mut(),
            )
        };
        if h == INVALID_HANDLE_VALUE {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(Handle(h))
        }
    }

    fn zeroed() -> OVERLAPPED {
        // SAFETY: OVERLAPPED is plain data; all-zero is its documented initial state.
        unsafe { std::mem::zeroed() }
    }

    /// Non-blocking exclusive lock of byte 0 (LaneLock).
    pub fn try_lock(path: &Path) -> std::io::Result<Option<Handle>> {
        let h = open(path, 0)?;
        let mut ov = zeroed();
        // SAFETY: handle is valid, ov outlives the synchronous call.
        let ok = unsafe {
            LockFileEx(
                h.0,
                LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
                0,
                1,
                0,
                &mut ov,
            )
        };
        Ok(if ok != 0 { Some(h) } else { None })
    }

    pub fn unlock(h: &Handle) {
        let mut ov = zeroed();
        // SAFETY: valid handle; explicit unlock because close alone releases "when resources allow".
        unsafe { UnlockFileEx(h.0, 0, 1, 0, &mut ov) };
    }

    /// Queue in the kernel for the lock. `Ok(None)` on timeout or when a `wake` handle signalled first.
    pub fn queued(
        path: &Path,
        timeout_ms: u32,
        wake: &[HANDLE],
    ) -> std::io::Result<Option<Handle>> {
        let h = open(path, FILE_FLAG_OVERLAPPED)?;
        // SAFETY: manual-reset, initially unsignalled, unnamed event.
        let event = unsafe { CreateEventW(std::ptr::null(), 1, 0, std::ptr::null()) };
        if event.is_null() {
            return Err(std::io::Error::last_os_error());
        }
        let event = Handle(event);
        let mut ov = zeroed();
        ov.hEvent = event.0;
        // SAFETY: handle valid; `ov` and its event live until the request completed (we always wait below).
        if unsafe { LockFileEx(h.0, LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &mut ov) } != 0 {
            return Ok(Some(h));
        }
        // SAFETY: trivial.
        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(std::io::Error::from_raw_os_error(err as i32));
        }
        let signalled = if wake.is_empty() {
            // SAFETY: valid event handle.
            unsafe { WaitForSingleObject(event.0, timeout_ms) }
        } else {
            let mut all = vec![event.0];
            all.extend_from_slice(wake);
            // SAFETY: `all` holds valid handles.
            unsafe { WaitForMultipleObjects(all.len() as u32, all.as_ptr(), 0, timeout_ms) }
        };
        let cancelled = signalled != WAIT_OBJECT_0;
        if cancelled {
            // SAFETY: withdraw the pending request on this handle.
            unsafe { CancelIoEx(h.0, &ov) };
        }
        let mut done = 0u32;
        // SAFETY: wait for the request to finish so OVERLAPPED may be freed; a grant that raced the cancel counts.
        let ok = unsafe { GetOverlappedResult(h.0, &ov, &mut done, 1) };
        if ok == 0 {
            if cancelled {
                return Ok(None);
            }
            return Err(std::io::Error::last_os_error());
        }
        Ok(Some(h))
    }

    /// Wait until one of `handles` is signalled (true) or the timeout passes (false).
    pub fn wait_handles(handles: &[HANDLE], timeout_ms: u32) -> bool {
        if handles.is_empty() {
            std::thread::sleep(std::time::Duration::from_millis(u64::from(timeout_ms)));
            return false;
        }
        // SAFETY: caller passes valid handles.
        unsafe {
            WaitForMultipleObjects(handles.len() as u32, handles.as_ptr(), 0, timeout_ms)
                == WAIT_OBJECT_0
        }
    }

    pub mod watch {
        use super::wide;
        use std::path::Path;
        use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_NOTIFY_CHANGE_FILE_NAME, FindCloseChangeNotification,
            FindFirstChangeNotificationW, FindNextChangeNotification,
        };

        pub fn first(folder: &Path) -> Option<HANDLE> {
            // SAFETY: valid wide string.
            let h = unsafe {
                FindFirstChangeNotificationW(wide(folder).as_ptr(), 0, FILE_NOTIFY_CHANGE_FILE_NAME)
            };
            (!h.is_null() && h != INVALID_HANDLE_VALUE).then_some(h)
        }
        pub fn next(h: HANDLE) {
            // SAFETY: valid notification handle.
            unsafe { FindNextChangeNotification(h) };
        }
        pub fn close(h: HANDLE) {
            // SAFETY: valid notification handle closed once.
            unsafe { FindCloseChangeNotification(h) };
        }
    }
}

#[cfg(windows)]
pub type RawHandle = windows_sys::Win32::Foundation::HANDLE;

/// Non-queued exclusive lock (Python `LaneLock`).
pub struct LaneLock {
    path: PathBuf,
    #[cfg(windows)]
    handle: Option<sys::Handle>,
    #[cfg(not(windows))]
    handle: Option<std::fs::File>,
}

impl LaneLock {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self {
            path: path.into(),
            handle: None,
        }
    }

    pub fn acquire(&mut self) -> bool {
        if self.handle.is_some() {
            return true;
        }
        if seed(&self.path).is_err() {
            return false;
        }
        #[cfg(windows)]
        {
            if let Ok(Some(h)) = sys::try_lock(&self.path) {
                self.handle = Some(h);
                return true;
            }
            false
        }
        #[cfg(not(windows))]
        {
            let Ok(f) = OpenOptions::new().read(true).write(true).open(&self.path) else {
                return false;
            };
            if f.try_lock().is_ok() {
                self.handle = Some(f);
                return true;
            }
            false
        }
    }

    pub fn release(&mut self) {
        if let Some(h) = self.handle.take() {
            #[cfg(windows)]
            sys::unlock(&h);
            drop(h);
        }
    }
}

impl LaneLock {
    /// Python `_QueuedLock.wait`: queue in the kernel for the lock; `None` when `timeout_s` ran out or one of the `wake`
    /// handles (a [`FolderWatch`]) signalled first. Windows only.
    #[cfg(windows)]
    pub fn queued(
        path: impl Into<PathBuf>,
        timeout_s: f64,
        wake: &[RawHandle],
    ) -> std::io::Result<Option<LaneLock>> {
        let path = path.into();
        seed(&path)?;
        let ms = (timeout_s.max(0.0) * 1000.0).min(4_294_967_294.0) as u32;
        Ok(sys::queued(&path, ms, wake)?.map(|handle| LaneLock {
            path,
            handle: Some(handle),
        }))
    }
}

impl Drop for LaneLock {
    fn drop(&mut self) {
        self.release();
    }
}

/// Is the lock at `path` held by someone? (A missing file is not held.)
pub fn held(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let mut probe = LaneLock::new(path);
    if probe.acquire() {
        probe.release();
        false
    } else {
        true
    }
}

/// Held guard from [`locked`]; releases on drop.
pub struct Guard {
    #[cfg(windows)]
    handle: Option<sys::Handle>,
    #[cfg(not(windows))]
    lane: LaneLock,
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(h) = self.handle.take() {
            sys::unlock(&h);
        }
        #[cfg(not(windows))]
        self.lane.release();
    }
}

/// Wait a bounded time for an exclusive lock; never queue forever (Python `locks.locked`).
pub fn locked(path: &Path, timeout_s: f64, what: &str) -> Result<Guard, LockBusy> {
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let started = Instant::now();
    let deadline = started + Duration::from_secs_f64(timeout_s.max(0.0));
    #[cfg(not(windows))]
    let mut lane = LaneLock::new(path);
    loop {
        #[cfg(windows)]
        {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let attempt = seed(path).and_then(|()| {
                sys::queued(path, remaining.as_millis().min(0xFFFF_FFFE) as u32, &[])
            });
            match attempt {
                Ok(Some(handle)) => {
                    return Ok(Guard {
                        handle: Some(handle),
                    });
                }
                Ok(None) => return Err(LockBusy::new(what, path, started.elapsed().as_secs_f64())),
                Err(_) => {} // could not queue (file being replaced or deleted): retry until the deadline
            }
        }
        #[cfg(not(windows))]
        if lane.acquire() {
            return Ok(Guard { lane });
        }
        if Instant::now() >= deadline {
            return Err(LockBusy::new(what, path, started.elapsed().as_secs_f64()));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// Wait until one of the waitable kernel `handles` is signalled (true) or `timeout_s` passes (false). Windows only.
#[cfg(windows)]
pub fn wait_handles(handles: &[RawHandle], timeout_s: f64) -> bool {
    sys::wait_handles(
        handles,
        (timeout_s.max(0.0) * 1000.0).min(4_294_967_294.0) as u32,
    )
}

/// Signalled when a file is created, renamed or removed in one of the folders (not recursive); `rearm` after each wake.
#[cfg(windows)]
pub struct FolderWatch {
    pub handles: Vec<RawHandle>,
}

#[cfg(windows)]
impl FolderWatch {
    pub fn new<P: AsRef<Path>>(folders: impl IntoIterator<Item = P>) -> Self {
        Self {
            handles: folders
                .into_iter()
                .filter_map(|f| sys::watch::first(f.as_ref()))
                .collect(),
        }
    }
    pub fn rearm(&self) {
        self.handles.iter().for_each(|h| sys::watch::next(*h));
    }
}

#[cfg(windows)]
impl Drop for FolderWatch {
    fn drop(&mut self) {
        self.handles.drain(..).for_each(sys::watch::close);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[test]
    fn lane_lock_excludes_and_held_probes() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("a.lock");
        assert!(!held(&p));
        let mut a = LaneLock::new(&p);
        assert!(a.acquire());
        assert!(held(&p));
        let mut b = LaneLock::new(&p);
        assert!(!b.acquire());
        a.release();
        assert!(!held(&p));
        assert!(b.acquire());
    }

    #[test]
    fn locked_times_out_with_busy_payload_and_frees_on_drop() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("sub").join("b.lock");
        let g = locked(&p, 1.0, "registry").unwrap();
        let e = locked(&p, 0.2, "registry").err().expect("busy");
        assert_eq!(e.to_string(), "registry is busy (b.lock); retry shortly");
        let v = e.payload();
        assert_eq!(v["error"], "busy");
        assert_eq!(v["retryAfterMs"], 1000);
        assert!(e.waited_s >= 0.15);
        drop(g);
        locked(&p, 1.0, "registry").unwrap();
    }

    #[test]
    fn contending_waiters_are_all_served() {
        let dir = tempfile::tempdir().unwrap();
        let p = Arc::new(dir.path().join("c.lock"));
        let n = Arc::new(AtomicUsize::new(0));
        let ts: Vec<_> = (0..8)
            .map(|_| {
                let (p, n) = (p.clone(), n.clone());
                std::thread::spawn(move || {
                    for _ in 0..5 {
                        let _g = locked(&p, 10.0, "t").unwrap();
                        n.fetch_add(1, Ordering::SeqCst);
                    }
                })
            })
            .collect();
        ts.into_iter().for_each(|t| t.join().unwrap());
        assert_eq!(n.load(Ordering::SeqCst), 40);
    }
}
