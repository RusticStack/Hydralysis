//! PID identity: a pid alone can be reused, so every action on a running target re-checks
//! (pid, creation time, image path) captured when the target was first seen.
use std::io;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Threading::*;
const SYNCHRONIZE: u32 = 0x0010_0000;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcessIdentity {
    pub pid: u32,
    /// FILETIME (100 ns units since 1601) from GetProcessTimes.
    pub created: u64,
    pub image: String,
}

#[derive(Debug)]
pub enum IdentityError {
    /// The process has exited or the pid does not exist.
    Gone,
    /// The pid now names a different process (different creation time).
    Reused {
        was: u64,
        now: u64,
    },
    /// Same creation time but another image: refuse.
    ImageChanged {
        was: String,
        now: String,
    },
    Os(io::Error),
}

impl std::fmt::Display for IdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IdentityError::Gone => write!(f, "the target process is gone"),
            IdentityError::Reused { was, now } => {
                write!(f, "pid was reused (created {was} then {now})")
            }
            IdentityError::ImageChanged { was, now } => {
                write!(f, "process image changed from {was} to {now}")
            }
            IdentityError::Os(e) => write!(f, "{e}"),
        }
    }
}
impl std::error::Error for IdentityError {}

struct Owned(HANDLE);
impl Drop for Owned {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn query(pid: u32) -> Result<(u64, String, bool), IdentityError> {
    unsafe {
        let h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | SYNCHRONIZE, 0, pid);
        if h.is_null() {
            let e = io::Error::last_os_error();
            // 87 = ERROR_INVALID_PARAMETER: no such pid. Access denied stays an error, not "gone".
            return Err(if e.raw_os_error() == Some(87) { IdentityError::Gone } else { IdentityError::Os(e) });
        }
        let h = Owned(h);
        let alive = WaitForSingleObject(h.0, 0) == WAIT_TIMEOUT;
        if !alive {
            return Ok((0, String::new(), false));
        }
        let (mut c, mut x, mut k, mut u) = (core::mem::zeroed(), core::mem::zeroed(), core::mem::zeroed(), core::mem::zeroed());
        if GetProcessTimes(h.0, &mut c, &mut x, &mut k, &mut u) == 0 {
            return Err(IdentityError::Os(io::Error::last_os_error()));
        }
        let created = ((c.dwHighDateTime as u64) << 32) | c.dwLowDateTime as u64;
        let mut buf = vec![0u16; 32768];
        let mut n = buf.len() as u32;
        if QueryFullProcessImageNameW(h.0, 0, buf.as_mut_ptr(), &mut n) == 0 {
            return Err(IdentityError::Os(io::Error::last_os_error()));
        }
        Ok((created, String::from_utf16_lossy(&buf[..n as usize]), alive))
    }
}

impl ProcessIdentity {
    pub fn capture(pid: u32) -> Result<ProcessIdentity, IdentityError> {
        let (created, image, alive) = query(pid)?;
        if !alive {
            return Err(IdentityError::Gone);
        }
        Ok(ProcessIdentity { pid, created, image })
    }

    /// Ok when the pid still names the same live process. Any doubt other than a confirmed exit is an error, never
    /// "gone".
    pub fn verify(&self) -> Result<(), IdentityError> {
        let (created, image, alive) = query(self.pid)?;
        if !alive {
            return Err(IdentityError::Gone);
        }
        if created != self.created {
            return Err(IdentityError::Reused { was: self.created, now: created });
        }
        if !image.eq_ignore_ascii_case(&self.image) {
            return Err(IdentityError::ImageChanged { was: self.image.clone(), now: image });
        }
        if !alive {
            return Err(IdentityError::Gone);
        }
        Ok(())
    }

    /// True only when the process is confirmed absent or the pid was reused.
    pub fn is_gone(&self) -> bool {
        matches!(self.verify(), Err(IdentityError::Gone) | Err(IdentityError::Reused { .. }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn own_process_verifies() {
        let id = ProcessIdentity::capture(std::process::id()).unwrap();
        assert!(id.image.to_lowercase().ends_with(".exe"));
        id.verify().unwrap();
        assert!(!id.is_gone());
    }

    #[test]
    fn detects_exit_and_reuse() {
        let mut c = std::process::Command::new("cmd.exe").args(["/c", "exit", "0"]).spawn().unwrap();
        let id = ProcessIdentity::capture(c.id()).unwrap_or_else(|e| match e {
            IdentityError::Gone => ProcessIdentity { pid: c.id(), created: 0, image: String::new() },
            e => panic!("{e}"),
        });
        c.wait().unwrap();
        // The pid is now exited (handle closed after wait): either absent or, rarely, reused.
        assert!(id.is_gone() || id.created == 0);
        // A forged creation time must read as reuse.
        let mine = ProcessIdentity::capture(std::process::id()).unwrap();
        let forged = ProcessIdentity { created: mine.created + 1, ..mine };
        assert!(matches!(forged.verify(), Err(IdentityError::Reused { .. })));
        assert!(forged.is_gone());
    }
}
