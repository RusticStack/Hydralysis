//! Port of `hydralysis/proc.py`: children never inherit the server's stdin, owned workers are identified by
//! (pid, creation time) so a recycled PID is never adopted or killed.
//!
//! The Python reaper thread has no counterpart here: `std::process::Child` handles are owned by the caller and a
//! dropped `Child` does not leave a zombie on Windows.

use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

#[cfg(windows)]
mod win {
    use std::ffi::c_void;

    pub type Handle = *mut c_void;
    #[repr(C)]
    #[derive(Default, Clone, Copy)]
    pub struct FileTime {
        pub low: u32,
        pub high: u32,
    }
    unsafe extern "system" {
        pub fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        pub fn GetExitCodeProcess(h: Handle, code: *mut u32) -> i32;
        pub fn GetProcessTimes(h: Handle, c: *mut FileTime, e: *mut FileTime, k: *mut FileTime, u: *mut FileTime) -> i32;
        pub fn CloseHandle(h: Handle) -> i32;
    }
}

/// `CREATE_NO_WINDOW`.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// Apply the Hydralysis child defaults: stdin is the null device, and on Windows no console window appears.
pub fn configure(cmd: &mut Command) -> &mut Command {
    cmd.stdin(Stdio::null());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }
    cmd
}

/// `proc.run`: run to completion with captured output.
pub fn run(program: &str, args: &[&str]) -> std::io::Result<Output> {
    let mut cmd = Command::new(program);
    cmd.args(args);
    configure(&mut cmd);
    cmd.output()
}

/// `proc.identity`: is `pid` alive with the creation time `started_ms` (Unix milliseconds)?
pub fn identity(pid: u32, started_ms: i64) -> bool {
    if pid == 0 || started_ms == 0 {
        return false;
    }
    identity_os(pid, started_ms)
}

#[cfg(windows)]
#[allow(unsafe_code)]
fn identity_os(pid: u32, started_ms: i64) -> bool {
    use win::*;
    // PROCESS_QUERY_LIMITED_INFORMATION
    // SAFETY: plain Win32 calls on a handle this function opens and closes; all out-pointers are locals.
    unsafe {
        let handle = OpenProcess(0x1000, 0, pid);
        if handle.is_null() {
            return false;
        }
        let mut code = 0u32;
        let alive = GetExitCodeProcess(handle, &mut code) != 0 && code == 259; // STILL_ACTIVE
        let mut times = [FileTime::default(); 4];
        let [c, e, k, u] = &mut times;
        let got = alive && GetProcessTimes(handle, c, e, k, u) != 0;
        CloseHandle(handle);
        if !got {
            return false;
        }
        let ticks = (u64::from(times[0].high) << 32) | u64::from(times[0].low);
        let actual_ms = (ticks / 10_000) as i64 - 11_644_473_600_000;
        (actual_ms - started_ms).abs() <= 2
    }
}

#[cfg(not(windows))]
fn identity_os(pid: u32, started_ms: i64) -> bool {
    let read = |p: String| std::fs::read_to_string(p).ok();
    let Some(stat) = read(format!("/proc/{pid}/stat")) else {
        return false;
    };
    let Some((_, rest)) = stat.rsplit_once(')') else {
        return false;
    };
    let fields: Vec<&str> = rest.split_whitespace().collect();
    if fields.first() == Some(&"Z") || fields.len() < 20 {
        return false;
    }
    let Some(boot) =
        read("/proc/stat".into()).and_then(|s| s.lines().find_map(|l| l.strip_prefix("btime ").and_then(|v| v.trim().parse::<f64>().ok())))
    else {
        return false;
    };
    let Ok(start_ticks) = fields[19].parse::<f64>() else {
        return false;
    };
    let actual_ms = (boot + start_ticks / 100.0) * 1000.0;
    (actual_ms - started_ms as f64).abs() <= 1000.0
}

/// `proc.terminate_tree` and the kill half of `proc.stop`: end a process and everything it started.
fn kill_tree(pid: u32) -> Result<(), String> {
    #[cfg(windows)]
    {
        let out = run("taskkill.exe", &["/PID", &pid.to_string(), "/T", "/F"]).map_err(|e| e.to_string())?;
        if out.status.success() {
            Ok(())
        } else {
            let text = String::from_utf8_lossy(if out.stderr.is_empty() { &out.stdout } else { &out.stderr }).trim().to_string();
            Err(text)
        }
    }
    #[cfg(not(windows))]
    {
        let out = Command::new("kill").args(["-KILL", &format!("-{pid}")]).output().map_err(|e| e.to_string())?;
        if out.status.success() { Ok(()) } else { Err(String::from_utf8_lossy(&out.stderr).trim().to_string()) }
    }
}

/// `proc.terminate_tree`.
pub fn terminate_tree(pid: u32) -> Result<(), String> {
    kill_tree(pid).map_err(|e| format!("owned process tree cleanup failed: {e}"))
}

/// `proc.stop`: stop an owned worker whose identity still matches; a worker that is already gone is not an error.
pub fn stop(pid: u32, started_ms: i64) -> Result<(), String> {
    if !identity(pid, started_ms) {
        return Ok(());
    }
    if let Err(e) = kill_tree(pid)
        && identity(pid, started_ms)
    {
        return Err(format!("could not stop owned worker {pid}: {e}"));
    }
    let deadline = Instant::now() + Duration::from_secs(10);
    while identity(pid, started_ms) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    if identity(pid, started_ms) {
        return Err(format!("owned worker {pid} has not exited"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_pid_or_start_is_never_an_identity() {
        assert!(!identity(0, 5));
        assert!(!identity(4242, 0));
    }

    #[cfg(windows)]
    #[test]
    fn a_child_matches_its_own_creation_time_and_stop_ends_it() {
        let mut cmd = Command::new("ping.exe");
        cmd.args(["-n", "30", "127.0.0.1"]).stdout(Stdio::null());
        configure(&mut cmd);
        let mut child = cmd.spawn().unwrap();
        let pid = child.id();
        // learn the creation time through the same API surface, then check tolerance and mismatch
        let now_ms = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64;
        let found = (now_ms - 20_000..=now_ms + 1000).step_by(1).find(|ms| identity(pid, *ms));
        let started = found.expect("creation time within 20 s of now");
        assert!(identity(pid, started + 2));
        assert!(!identity(pid, started + 5000));
        stop(pid, started).unwrap();
        let _ = child.wait();
        assert!(!identity(pid, started));
        stop(pid, started).unwrap(); // already gone: fine
    }
}
