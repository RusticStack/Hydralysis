//! Process identity: creation time as the OS reports it, so a recycled PID is never mistaken for the holder
//! (`hydralysis.proc.identity`, `hydralysis.preparation.process_start_ms`).

/// Milliseconds since the Unix epoch at which `pid` was created, or 0 when it is not running / cannot be read.
#[cfg(windows)]
pub fn process_start_ms(pid: u32) -> i64 {
    use windows_sys::Win32::Foundation::{CloseHandle, FILETIME};
    use windows_sys::Win32::System::Threading::{
        GetExitCodeProcess, GetProcessTimes, OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION,
    };

    const STILL_ACTIVE: u32 = 259;
    // SAFETY: plain OpenProcess; the handle is closed below.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        return 0;
    }
    let mut code = 0u32;
    let zero = FILETIME {
        dwLowDateTime: 0,
        dwHighDateTime: 0,
    };
    let (mut created, mut exited, mut kernel, mut user) = (zero, zero, zero, zero);
    // SAFETY: valid handle and out-pointers for the duration of the calls.
    let ms = unsafe {
        if GetExitCodeProcess(handle, &mut code) == 0
            || code != STILL_ACTIVE
            || GetProcessTimes(handle, &mut created, &mut exited, &mut kernel, &mut user) == 0
        {
            0
        } else {
            let ticks =
                (u64::from(created.dwHighDateTime) << 32) | u64::from(created.dwLowDateTime);
            (ticks / 10_000) as i64 - 11_644_473_600_000
        }
    };
    // SAFETY: owned handle closed once.
    unsafe { CloseHandle(handle) };
    ms
}

#[cfg(not(windows))]
pub fn process_start_ms(pid: u32) -> i64 {
    // TODO: /proc/<pid>/stat starttime on Linux, sysctl on macOS (Windows x64 is the supported target).
    let _ = pid;
    0
}

/// Is `pid` a live process that was started at `started_ms` (within 2 ms)? Do not adopt or kill a recycled PID.
pub fn identity(pid: i64, started_ms: i64) -> bool {
    if pid <= 0 || started_ms == 0 {
        return false;
    }
    let actual = process_start_ms(pid as u32);
    actual != 0 && (actual - started_ms).abs() <= 2
}

/// This process's own start time, read once.
pub fn own_started_ms() -> i64 {
    static STARTED: std::sync::LazyLock<i64> =
        std::sync::LazyLock::new(|| process_start_ms(std::process::id()));
    *STARTED
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(windows)]
    fn own_process_is_live_and_a_wrong_start_is_not() {
        let started = own_started_ms();
        assert!(started > 1_600_000_000_000);
        assert!(identity(i64::from(std::process::id()), started));
        assert!(!identity(i64::from(std::process::id()), started + 5000));
        assert!(!identity(0, started));
        assert!(!identity(i64::from(std::process::id()), 0));
    }
}
