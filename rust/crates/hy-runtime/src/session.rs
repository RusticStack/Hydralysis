//! A spawned, instrumented target: suspended create, section, injection, drain.
use crate::{inject, pe_exports};
use hy_agent_proto as proto;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;

pub struct Site {
    pub rva: u64,
    pub expect: Vec<u8>,
}

pub struct Session {
    pub process: HANDLE,
    pub thread: HANDLE,
    pub pid: u32,
    view: *mut u8,
    section: HANDLE,
    tails: Vec<u32>,
}

impl Session {
    /// Spawn `exe args` suspended with the shared section ready; sites are requested but not yet installed.
    pub fn spawn(exe: &Path, args: &[String], sites: &[Site]) -> io::Result<Session> {
        unsafe {
            let mut cmd = format!("\"{}\"", exe.display());
            for a in args {
                cmd.push(' ');
                cmd.push_str(a);
            }
            let mut cmdw: Vec<u16> = cmd.encode_utf16().chain(Some(0)).collect();
            let mut si: STARTUPINFOW = core::mem::zeroed();
            si.cb = core::mem::size_of::<STARTUPINFOW>() as u32;
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
            let exew: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
            if CreateProcessW(
                exew.as_ptr(),
                cmdw.as_mut_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                0,
                CREATE_SUSPENDED,
                core::ptr::null(),
                core::ptr::null(),
                &si,
                &mut pi,
            ) == 0
            {
                return Err(io::Error::last_os_error());
            }
            let name: Vec<u16> = format!("Local\\hy_agent_{}\0", pi.dwProcessId)
                .encode_utf16()
                .collect();
            let section = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                core::ptr::null(),
                PAGE_READWRITE,
                0,
                proto::SECTION_SIZE as u32,
                name.as_ptr(),
            );
            if section.is_null() {
                TerminateProcess(pi.hProcess, 1);
                return Err(io::Error::last_os_error());
            }
            let view = MapViewOfFile(section, FILE_MAP_ALL_ACCESS, 0, 0, proto::SECTION_SIZE).Value
                as *mut u8;
            (view as *mut u64).write(proto::MAGIC);
            (view.add(proto::H_NSITES) as *mut u32).write(sites.len() as u32);
            for (i, s) in sites.iter().enumerate() {
                let r = view.add(proto::H_SITES + i * proto::SITE_REQ_SIZE);
                (r as *mut u64).write_unaligned(s.rva);
                (r.add(8) as *mut u32).write_unaligned(s.expect.len().min(16) as u32);
                core::ptr::copy_nonoverlapping(
                    s.expect.as_ptr(),
                    view.add(proto::H_EXPECT + i * 16),
                    s.expect.len().min(16),
                );
            }
            Ok(Session {
                process: pi.hProcess,
                thread: pi.hThread,
                pid: pi.dwProcessId,
                view,
                section,
                tails: vec![0; proto::MAX_RINGS],
            })
        }
    }

    /// Inject the agent and run its init; fails with the agent's error code if a guard refused.
    pub fn inject(&self, dll: &Path) -> io::Result<()> {
        unsafe {
            let image = std::fs::read(dll)?;
            let (rva, _) = pe_exports::find_export(&image, "hy_agent_init")
                .ok_or_else(|| io::Error::other("agent has no hy_agent_init"))?;
            let base = inject::load_library(self.process, self.pid, dll)?;
            let code =
                inject::run_remote(self.process, base + rva as usize, core::ptr::null(), 10_000)?;
            let status = (self.view.add(proto::H_STATUS) as *const u32).read_volatile();
            if code != 0 || status != 1 {
                return Err(io::Error::other(format!(
                    "agent init failed: code {code}, status {status}"
                )));
            }
            Ok(())
        }
    }

    pub fn resume(&self) {
        unsafe { ResumeThread(self.thread) };
    }

    pub fn running(&self) -> bool {
        unsafe { WaitForSingleObject(self.process, 0) == WAIT_TIMEOUT }
    }

    /// Drain every ring; returns records read. `f` sees each decoded record.
    pub fn drain(&mut self, mut f: impl FnMut(&proto::Rec)) -> u64 {
        let mut n = 0;
        unsafe {
            let claimed = ((self.view.add(proto::H_NEXT_RING) as *const u32).read_volatile()
                as usize)
                .min(proto::MAX_RINGS);
            for i in 0..claimed {
                let r = self.view.add(proto::ring_offset(i));
                let head = (r as *const u32).read_volatile();
                core::sync::atomic::fence(core::sync::atomic::Ordering::Acquire);
                let mut t = self.tails[i];
                while t != head {
                    let slot = r.add(
                        proto::RING_HDR + (t as usize & (proto::RING_RECS - 1)) * proto::REC_SIZE,
                    );
                    let mut b = [0u8; proto::REC_SIZE];
                    core::ptr::copy_nonoverlapping(slot, b.as_mut_ptr(), proto::REC_SIZE);
                    f(&proto::Rec::decode(&b));
                    t = t.wrapping_add(1);
                    n += 1;
                }
                self.tails[i] = t;
                (r.add(64) as *mut u32).write_volatile(t);
            }
        }
        n
    }

    pub fn dropped(&self) -> u64 {
        unsafe {
            let claimed = ((self.view.add(proto::H_NEXT_RING) as *const u32).read_volatile()
                as usize)
                .min(proto::MAX_RINGS);
            (0..claimed)
                .map(|i| {
                    (self.view.add(proto::ring_offset(i) + 8) as *const u32).read_volatile() as u64
                })
                .sum()
        }
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.view.cast(),
            });
            CloseHandle(self.section);
            CloseHandle(self.thread);
            CloseHandle(self.process);
        }
    }
}
