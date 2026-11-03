//! A spawned (or attached) instrumented target: section, injection, control channel, drain, breakpoints.
use crate::clock::Clock;
use crate::identity::{IdentityError, ProcessIdentity};
use crate::{inject, pe_exports};
use hy_agent_proto as proto;
use proto::Hit;
use std::collections::HashMap;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::*;
use windows_sys::Win32::Security::Cryptography::{BCRYPT_USE_SYSTEM_PREFERRED_RNG, BCryptGenRandom};
use windows_sys::Win32::System::Diagnostics::Debug::{ReadProcessMemory, WriteProcessMemory};
use windows_sys::Win32::System::Diagnostics::ToolHelp::*;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::*;
const SYNCHRONIZE: u32 = 0x0010_0000;

/// What to hook and what to record. Mirrors the probe parameters of the Frida template.
#[derive(Clone, Debug)]
pub struct SiteSpec {
    /// Module file name; empty means the main module.
    pub module: String,
    /// Expected load address of the module (0 = unchecked). A mismatch refuses the probe.
    pub module_base: u64,
    pub rva: u64,
    /// Export name the file's export table gave for `rva`; the live export must agree.
    pub export: Option<String>,
    /// 5..=32 bytes the live code must equal before any byte is written.
    pub expect: Vec<u8>,
    pub flags: u32,
    pub nargs: u32,
    /// Keep one hit in `stride` per thread (1 = every hit).
    pub stride: u32,
    pub buf_ptr_arg: i32,
    pub buf_len_arg: i32,
    pub buf_fixed: u32,
    pub buf_max: u32,
    pub stack_depth: u32,
}

impl SiteSpec {
    pub fn new(rva: u64, expect: Vec<u8>) -> SiteSpec {
        SiteSpec {
            module: String::new(),
            module_base: 0,
            rva,
            export: None,
            expect,
            flags: 0,
            nargs: 0,
            stride: 1,
            buf_ptr_arg: -1,
            buf_len_arg: -1,
            buf_fixed: 0,
            buf_max: 0,
            stack_depth: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SiteCounters {
    pub hits: u64,
    pub kept: u64,
}

impl SiteCounters {
    /// Hits the sampling policy skipped: exact, never estimated.
    pub fn skipped(&self) -> u64 {
        self.hits - self.kept
    }
}

#[derive(Clone, Debug, Default)]
pub struct Counters {
    pub sites: Vec<SiteCounters>,
    pub attempted: u64,
    pub dropped: u64,
    pub read_failed: u64,
    pub unreturned: u64,
    pub stalls: u64,
    /// Time hits spent waiting for a full ring, in the record clock's ticks.
    pub stall_ticks: u64,
    pub no_ring: u64,
    pub bad_records: u64,
    pub events_lost: u64,
}

#[derive(Clone, Debug)]
pub struct Event {
    pub kind: u16,
    pub site: u16,
    pub tid: u32,
    pub slot: u32,
    pub tsc: u64,
    pub data: [u64; 5],
}

#[derive(Clone, Debug)]
pub struct Paused {
    pub slot: usize,
    pub tid: u32,
    pub site: u32,
    pub parked_for: Duration,
    pub frame: [u64; proto::P_FRAME_WORDS],
}

#[derive(Clone, Debug)]
pub struct ModuleInfo {
    pub name: String,
    pub path: String,
    pub base: u64,
    pub size: u32,
}

/// Options for `Session::spawn_opts`.
#[derive(Clone, Debug, Default)]
pub struct SpawnOpts {
    pub stdout: Option<std::path::PathBuf>,
    pub cwd: Option<std::path::PathBuf>,
    pub env: Option<Vec<(String, String)>>,
}

pub struct Session {
    pub process: HANDLE,
    pub thread: HANDLE,
    pub pid: u32,
    /// Random per-session tag that names every kernel object of the session and is handed to the agent.
    tag: u64,
    pub identity: ProcessIdentity,
    pub clock: Clock,
    pub(crate) view: *mut u8,
    section: HANDLE,
    cmd_ev: HANDLE,
    rsp_ev: HANDLE,
    bp_ev: Vec<HANDLE>,
    tails: Vec<u32>,
    counters: Counters,
    next_event: u32,
    first_seen: HashMap<(usize, u64), Instant>,
    seq: u32,
    pub(crate) watch: crate::watch::WatchState,
    pub(crate) memory: crate::memory::MemoryState,
}

// The raw handles and the view are owned by the session and only used through &mut self.
unsafe impl Send for Session {}

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(Some(0)).collect()
}

/// Largest single `read_memory` request.
pub const MAX_READ: usize = 16 << 20;

/// A zeroed buffer of `len` bytes, refusing sizes above [`MAX_READ`] and reporting allocation failure as an error.
fn zeroed_buffer(len: usize) -> io::Result<Vec<u8>> {
    if len > MAX_READ {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, format!("read of {len} bytes exceeds the {MAX_READ} byte limit")));
    }
    let mut buf = Vec::new();
    buf.try_reserve_exact(len).map_err(|e| io::Error::new(io::ErrorKind::OutOfMemory, e.to_string()))?;
    buf.resize(len, 0);
    Ok(buf)
}

/// A kernel handle closed on drop, so every early return in session setup releases what was created so far.
struct OwnedHandle(HANDLE);

impl OwnedHandle {
    fn into_raw(self) -> HANDLE {
        let h = self.0;
        core::mem::forget(self);
        h
    }
}

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        // SAFETY: the handle is owned and closed exactly once.
        unsafe { CloseHandle(self.0) };
    }
}

/// A mapped view unmapped on drop.
struct OwnedView(*mut u8);

impl OwnedView {
    fn into_raw(self) -> *mut u8 {
        let v = self.0;
        core::mem::forget(self);
        v
    }
}

impl Drop for OwnedView {
    fn drop(&mut self) {
        // SAFETY: the view was returned by MapViewOfFile and is unmapped exactly once.
        unsafe { UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: self.0.cast() }) };
    }
}

/// Create a session event. An event that already exists is refused: the name is squatted or the tag collided.
fn named_event(name: &str, manual: bool) -> io::Result<OwnedHandle> {
    // SAFETY: plain Win32 call with a NUL-terminated name.
    let h = unsafe { CreateEventW(core::ptr::null(), manual as i32, 0, wide(name).as_ptr()) };
    if h.is_null() {
        return Err(io::Error::last_os_error());
    }
    let h = OwnedHandle(h);
    // SAFETY: reads the thread's last-error value set by CreateEventW above.
    if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, format!("kernel object {name} already exists")));
    }
    Ok(h)
}

/// 64 random bits from the system RNG; never zero (the agent treats zero as "no tag").
fn random_tag() -> io::Result<u64> {
    loop {
        let mut bytes = [0u8; 8];
        // SAFETY: the buffer is 8 writable bytes; a null algorithm handle with the flag selects the system RNG.
        let status =
            unsafe { BCryptGenRandom(core::ptr::null_mut(), bytes.as_mut_ptr(), bytes.len() as u32, BCRYPT_USE_SYSTEM_PREFERRED_RNG) };
        if status != 0 {
            return Err(io::Error::other(format!("system RNG failed: {status:#x}")));
        }
        let tag = u64::from_le_bytes(bytes);
        if tag != 0 {
            return Ok(tag);
        }
    }
}

/// Quote one argument by the MSVCRT / `CommandLineToArgvW` rules, so the child sees exactly `arg` as one argv entry.
fn push_quoted(out: &mut String, arg: &str) {
    if !arg.is_empty() && !arg.contains([' ', '\t', '\n', '\x0b', '"']) {
        out.push_str(arg);
        return;
    }
    out.push('"');
    let mut backslashes = 0usize;
    for c in arg.chars() {
        match c {
            '\\' => backslashes += 1,
            '"' => {
                // Backslashes before a quote are doubled, then the quote itself is escaped.
                out.extend(core::iter::repeat_n('\\', backslashes * 2 + 1));
                out.push('"');
                backslashes = 0;
            }
            _ => {
                out.extend(core::iter::repeat_n('\\', backslashes));
                out.push(c);
                backslashes = 0;
            }
        }
    }
    // Trailing backslashes would escape the closing quote.
    out.extend(core::iter::repeat_n('\\', backslashes * 2));
    out.push('"');
}

/// The child's command line: the executable (always quoted) followed by each argument as one argv entry.
fn command_line(exe: &str, args: &[String]) -> String {
    let mut cmd = format!("\"{exe}\"");
    for a in args {
        cmd.push(' ');
        push_quoted(&mut cmd, a);
    }
    cmd
}

unsafe fn put_site(view: *mut u8, i: usize, s: &SiteSpec) {
    unsafe {
        let c = view.add(proto::site_offset(i));
        core::ptr::write_bytes(c, 0, proto::SITE_SIZE);
        (c.add(proto::S_RVA) as *mut u64).write(s.rva);
        (c.add(proto::S_BASE) as *mut u64).write(s.module_base);
        let n = s.expect.len().min(32);
        (c.add(proto::S_EXPECT_LEN) as *mut u32).write(n as u32);
        core::ptr::copy_nonoverlapping(s.expect.as_ptr(), c.add(proto::S_EXPECT), n);
        (c.add(proto::S_FLAGS) as *mut u32).write(s.flags);
        (c.add(proto::S_NARGS) as *mut u32).write(s.nargs.min(proto::MAX_ARGS as u32));
        (c.add(proto::S_MASK) as *mut u32).write(s.stride.max(1) - 1);
        (c.add(proto::S_BUF_PTR_ARG) as *mut i32).write(s.buf_ptr_arg);
        (c.add(proto::S_BUF_LEN_ARG) as *mut i32).write(s.buf_len_arg);
        (c.add(proto::S_BUF_FIXED) as *mut u32).write(s.buf_fixed);
        (c.add(proto::S_BUF_MAX) as *mut u32).write(s.buf_max.min(proto::BUF_MAX as u32));
        (c.add(proto::S_STACK_DEPTH) as *mut u32).write(s.stack_depth.min(proto::MAX_STACK as u32));
        let m = s.module.as_bytes();
        core::ptr::copy_nonoverlapping(m.as_ptr(), c.add(proto::S_MODULE), m.len().min(63));
        if let Some(e) = &s.export {
            let e = e.as_bytes();
            core::ptr::copy_nonoverlapping(e.as_ptr(), c.add(proto::S_EXPORT), e.len().min(63));
        }
        (c.add(proto::S_STATE) as *mut u32).write_volatile(proto::SITE_UNUSED);
    }
}

impl Session {
    /// Create the section and events. On error nothing created here leaks; the caller keeps ownership of
    /// `process` and `thread` (they are stored in the session only on success).
    fn build(process: HANDLE, thread: HANDLE, pid: u32, sites: &[SiteSpec]) -> io::Result<Session> {
        unsafe {
            let identity = ProcessIdentity::capture(pid).map_err(|e| io::Error::other(e.to_string()))?;
            let tag = random_tag()?;
            let sec_name = wide(&proto::object_name("agent", pid, tag));
            let section = CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                core::ptr::null(),
                PAGE_READWRITE,
                0,
                proto::SECTION_SIZE as u32,
                sec_name.as_ptr(),
            );
            if section.is_null() {
                return Err(io::Error::last_os_error());
            }
            let section_error = GetLastError();
            let section = OwnedHandle(section);
            if section_error == ERROR_ALREADY_EXISTS {
                // Someone else created this name first: its contents are not ours to trust.
                return Err(io::Error::new(io::ErrorKind::AlreadyExists, "the agent section name already exists"));
            }
            let view = MapViewOfFile(section.0, FILE_MAP_ALL_ACCESS, 0, 0, proto::SECTION_SIZE).Value as *mut u8;
            if view.is_null() {
                return Err(io::Error::last_os_error());
            }
            let view = OwnedView(view);
            (view.0 as *mut u64).write(proto::MAGIC);
            (view.0.add(proto::H_NSITES) as *mut u32).write(sites.len().min(proto::MAX_SITES) as u32);
            for (i, s) in sites.iter().enumerate().take(proto::MAX_SITES) {
                put_site(view.0, i, s);
            }
            let cmd_ev = named_event(&proto::object_name("cmd", pid, tag), false)?;
            let rsp_ev = named_event(&proto::object_name("rsp", pid, tag), false)?;
            let bp_ev = (0..proto::MAX_PAUSE)
                .map(|i| named_event(&proto::object_name(&format!("bp_{i}"), pid, tag), true))
                .collect::<io::Result<Vec<_>>>()?;
            Ok(Session {
                process,
                thread,
                pid,
                tag,
                identity,
                clock: Clock::new(false, 0, 0, 0),
                view: view.into_raw(),
                section: section.into_raw(),
                cmd_ev: cmd_ev.into_raw(),
                rsp_ev: rsp_ev.into_raw(),
                bp_ev: bp_ev.into_iter().map(OwnedHandle::into_raw).collect(),
                tails: vec![0; proto::MAX_RINGS],
                counters: Counters { sites: vec![SiteCounters::default(); proto::MAX_SITES], ..Default::default() },
                next_event: 0,
                first_seen: HashMap::new(),
                seq: 0,
                watch: crate::watch::WatchState::default(),
                memory: crate::memory::MemoryState::default(),
            })
        }
    }

    /// Spawn `exe args` suspended with the section ready; sites are requested but not yet installed.
    pub fn spawn(exe: &Path, args: &[String], sites: &[SiteSpec]) -> io::Result<Session> {
        Session::spawn_with(exe, args, sites, None)
    }

    /// As `spawn`, with the child's stdout and stderr redirected to `stdout` (created or truncated) when given.
    pub fn spawn_with(exe: &Path, args: &[String], sites: &[SiteSpec], stdout: Option<&Path>) -> io::Result<Session> {
        let opts = SpawnOpts { stdout: stdout.map(Path::to_path_buf), ..Default::default() };
        Session::spawn_opts(exe, args, sites, &opts)
    }

    /// Spawn suspended with a working directory and an environment block when given (the environment replaces the
    /// parent's, as Frida's `envp` does).
    pub fn spawn_opts(exe: &Path, args: &[String], sites: &[SiteSpec], opts: &SpawnOpts) -> io::Result<Session> {
        use windows_sys::Win32::Storage::FileSystem::CreateFileW;
        let stdout = opts.stdout.as_deref();
        unsafe {
            // Each argument reaches the child as exactly one argv entry (spaces and quotes are escaped).
            let mut cmdw = wide(&command_line(&exe.display().to_string(), args));
            let mut si: STARTUPINFOEXW = core::mem::zeroed();
            si.StartupInfo.cb = core::mem::size_of::<STARTUPINFOEXW>() as u32;
            let mut pi: PROCESS_INFORMATION = core::mem::zeroed();
            let exew: Vec<u16> = exe.as_os_str().encode_wide().chain(Some(0)).collect();
            // Handles the child inherits: exactly these two, through an explicit list, never "every inheritable
            // handle of the host" (which would pin other sessions' log files in a multi-session host).
            let mut inherited: Vec<OwnedHandle> = Vec::new();
            let mut attr_buf: Vec<usize> = Vec::new();
            let mut inherit = 0;
            if let Some(path) = stdout {
                let sa = windows_sys::Win32::Security::SECURITY_ATTRIBUTES {
                    nLength: core::mem::size_of::<windows_sys::Win32::Security::SECURITY_ATTRIBUTES>() as u32,
                    lpSecurityDescriptor: core::ptr::null_mut(),
                    bInheritHandle: 1,
                };
                let pw: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
                let out_handle = CreateFileW(pw.as_ptr(), 0x4000_0000, 3, &sa, 2, 0x80, core::ptr::null_mut());
                if out_handle == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                inherited.push(OwnedHandle(out_handle));
                let nul: Vec<u16> = wide("NUL");
                let stdin = CreateFileW(nul.as_ptr(), 0x8000_0000, 3, &sa, 3, 0x80, core::ptr::null_mut());
                if stdin == INVALID_HANDLE_VALUE {
                    return Err(io::Error::last_os_error());
                }
                inherited.push(OwnedHandle(stdin));
                si.StartupInfo.dwFlags = 0x100; // STARTF_USESTDHANDLES
                si.StartupInfo.hStdOutput = out_handle;
                si.StartupInfo.hStdError = out_handle;
                si.StartupInfo.hStdInput = stdin;
                let list: [HANDLE; 2] = [out_handle, stdin];
                let mut bytes = 0usize;
                // Sizing call: fails with ERROR_INSUFFICIENT_BUFFER by design and reports the size.
                InitializeProcThreadAttributeList(core::ptr::null_mut(), 1, 0, &mut bytes);
                attr_buf.resize(bytes.div_ceil(core::mem::size_of::<usize>()).max(1), 0);
                let attrs: LPPROC_THREAD_ATTRIBUTE_LIST = attr_buf.as_mut_ptr().cast();
                if InitializeProcThreadAttributeList(attrs, 1, 0, &mut bytes) == 0 {
                    return Err(io::Error::last_os_error());
                }
                if UpdateProcThreadAttribute(
                    attrs,
                    0,
                    PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                    list.as_ptr().cast(),
                    core::mem::size_of_val(&list),
                    core::ptr::null_mut(),
                    core::ptr::null(),
                ) == 0
                {
                    let e = io::Error::last_os_error();
                    DeleteProcThreadAttributeList(attrs);
                    return Err(e);
                }
                si.lpAttributeList = attrs;
                inherit = 1;
            }
            let env_block: Option<Vec<u16>> = opts.env.as_ref().map(|vars| {
                let mut b: Vec<u16> = Vec::new();
                for (k, v) in vars {
                    b.extend(format!("{k}={v}").encode_utf16());
                    b.push(0);
                }
                b.push(0);
                if vars.is_empty() {
                    b.push(0);
                }
                b
            });
            let cwdw: Option<Vec<u16>> = opts.cwd.as_ref().map(|c| c.as_os_str().encode_wide().chain(Some(0)).collect());
            let flags = CREATE_SUSPENDED
                | if env_block.is_some() { 0x400 } else { 0 }
                | if inherit != 0 { EXTENDED_STARTUPINFO_PRESENT } else { 0 };
            let created = CreateProcessW(
                exew.as_ptr(),
                cmdw.as_mut_ptr(),
                core::ptr::null(),
                core::ptr::null(),
                inherit,
                flags,
                env_block.as_ref().map_or(core::ptr::null(), |b| b.as_ptr() as *const _),
                cwdw.as_ref().map_or(core::ptr::null(), |c| c.as_ptr()),
                &si.StartupInfo,
                &mut pi,
            );
            let create_error = (created == 0).then(io::Error::last_os_error);
            if inherit != 0 {
                DeleteProcThreadAttributeList(si.lpAttributeList);
            }
            drop(inherited);
            if let Some(e) = create_error {
                return Err(e);
            }
            match Session::build(pi.hProcess, pi.hThread, pi.dwProcessId, sites) {
                Ok(s) => Ok(s),
                Err(e) => {
                    TerminateProcess(pi.hProcess, 1);
                    CloseHandle(pi.hThread);
                    CloseHandle(pi.hProcess);
                    Err(e)
                }
            }
        }
    }

    /// Attach to a running process of the same bitness. The caller has authority over `pid`; identity is captured now.
    pub fn attach(pid: u32, sites: &[SiteSpec]) -> io::Result<Session> {
        unsafe {
            let access = PROCESS_CREATE_THREAD
                | PROCESS_QUERY_INFORMATION
                | PROCESS_VM_OPERATION
                | PROCESS_VM_READ
                | PROCESS_VM_WRITE
                | PROCESS_SUSPEND_RESUME
                | SYNCHRONIZE
                | PROCESS_TERMINATE;
            let h = OpenProcess(access, 0, pid);
            if h.is_null() {
                return Err(io::Error::last_os_error());
            }
            Session::build(h, core::ptr::null_mut(), pid, sites).inspect_err(|_| {
                CloseHandle(h);
            })
        }
    }

    pub(crate) fn rd32(&self, off: usize) -> u32 {
        unsafe { (self.view.add(off) as *const u32).read_volatile() }
    }
    pub(crate) fn wr32(&self, off: usize, v: u32) {
        unsafe { (self.view.add(off) as *mut u32).write_volatile(v) }
    }
    fn rd64(&self, off: usize) -> u64 {
        unsafe { (self.view.add(off) as *const u64).read_volatile() }
    }
    /// Inject the agent and run its init. Per-site failures are in `site_status`; this fails only when the agent
    /// itself could not start.
    pub fn inject(&mut self, dll: &Path) -> io::Result<()> {
        fn ctx(stage: &str, e: io::Error) -> io::Error {
            io::Error::new(e.kind(), format!("{stage}: {e}"))
        }
        unsafe {
            let image = std::fs::read(dll).map_err(|e| ctx("reading the agent", e))?;
            let (rva, _) =
                pe_exports::find_export(&image, "hy_agent_init").ok_or_else(|| io::Error::other("agent has no hy_agent_init"))?;
            // A process resumed a moment ago may still be starting up; CreateRemoteThread then reports access denied
            // (5) or not-enough-memory (8). Retry for a short, bounded time. A process we spawned suspended never
            // needs this.
            let retry = |e: &io::Error, tries: u32| tries < 200 && matches!(e.raw_os_error(), Some(5) | Some(8));
            let mut tries = 0;
            let base = loop {
                match inject::load_library(self.process, self.pid, dll) {
                    Ok(b) => break b,
                    Err(e) if retry(&e, tries) => {
                        tries += 1;
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => return Err(ctx("loading the agent", e)),
                }
            };
            tries = 0;
            let code = loop {
                match inject::run_remote(self.process, base + rva as usize, self.tag as usize as *const core::ffi::c_void, 20_000) {
                    Ok(c) => break c,
                    Err(e) if retry(&e, tries) => {
                        tries += 1;
                        std::thread::sleep(Duration::from_millis(50));
                    }
                    Err(e) => return Err(ctx("running hy_agent_init", e)),
                }
            };
            if code != 0 || self.rd32(proto::H_STATUS) != 1 {
                return Err(io::Error::other(format!("agent init failed: code {code}, status {}", self.rd32(proto::H_STATUS))));
            }
            self.clock = Clock::new(
                self.rd32(proto::H_USE_QPC) != 0,
                self.rd64(proto::H_TSC0),
                self.rd64(proto::H_QPC0),
                self.rd64(proto::H_QPC_FREQ),
            );
            self.refine_clock();
            Ok(())
        }
    }

    fn refine_clock(&mut self) {
        let (mut q, t) = (0i64, unsafe { core::arch::x86_64::_rdtsc() });
        unsafe { windows_sys::Win32::System::Performance::QueryPerformanceCounter(&mut q) };
        self.clock.refine(t, q as u64);
    }

    pub fn resume(&self) {
        if !self.thread.is_null() {
            unsafe { ResumeThread(self.thread) };
        }
    }

    pub fn running(&self) -> bool {
        unsafe { WaitForSingleObject(self.process, 0) == WAIT_TIMEOUT }
    }

    /// The target's exit code once it has exited.
    pub fn exit_code(&self) -> Option<u32> {
        if self.running() {
            return None;
        }
        let mut code = 0u32;
        (unsafe { GetExitCodeProcess(self.process, &mut code) } != 0).then_some(code)
    }

    /// Rings ever claimed (the high-water mark; rings are reused after their thread exits).
    pub fn ring_count(&self) -> u32 {
        self.rd32(proto::H_NRINGS)
    }

    pub fn verify_identity(&self) -> Result<(), IdentityError> {
        self.identity.verify()
    }

    /// `(state, error)` of a site as the agent last wrote it.
    pub fn site_status(&self, i: usize) -> (u32, u32) {
        let c = proto::site_offset(i);
        (self.rd32(c + proto::S_STATE), self.rd32(c + proto::S_ERR))
    }

    /// One mailbox round trip. Returns the agent's result code (0 = ok).
    pub fn control(&mut self, cmd: u32, arg0: u64, timeout: Duration) -> io::Result<u32> {
        unsafe {
            let mb = self.view.add(proto::MAILBOX_OFF);
            (mb.add(proto::MB_CMD) as *mut u32).write_volatile(cmd);
            (mb.add(proto::MB_ARGS) as *mut u64).write_volatile(arg0);
            self.seq += 1;
            let seq = self.seq;
            (mb.add(proto::MB_SEQ) as *mut u32).write_volatile(seq);
            SetEvent(self.cmd_ev);
            let deadline = Instant::now() + timeout;
            loop {
                let left = deadline.saturating_duration_since(Instant::now());
                WaitForSingleObject(self.rsp_ev, left.as_millis().min(u32::MAX as u128) as u32);
                if (mb.add(proto::MB_RSEQ) as *const u32).read_volatile() == seq {
                    return Ok((mb.add(proto::MB_RESULT) as *const u32).read_volatile());
                }
                if Instant::now() >= deadline {
                    return Err(io::Error::new(io::ErrorKind::TimedOut, "agent did not answer"));
                }
            }
        }
    }

    pub fn ping(&mut self) -> io::Result<()> {
        match self.control(proto::CMD_PING, 0, Duration::from_secs(5))? {
            0 => Ok(()),
            c => Err(io::Error::other(format!("ping answered {c}"))),
        }
    }

    /// Arm a site while the target runs (threads are stopped inside the agent for the patch only).
    /// Returns the agent's error code on refusal.
    pub fn arm_site(&mut self, idx: usize, spec: &SiteSpec) -> io::Result<Result<(), u32>> {
        if idx >= proto::MAX_SITES {
            return Ok(Err(proto::ERR_BAD_SITE));
        }
        self.identity.verify().map_err(|e| io::Error::other(e.to_string()))?;
        unsafe { put_site(self.view, idx, spec) };
        Ok(match self.control(proto::CMD_ARM_SITE, idx as u64, Duration::from_secs(30))? {
            0 => Ok(()),
            c => Err(c),
        })
    }

    pub fn retire_site(&mut self, idx: usize) -> io::Result<Result<(), u32>> {
        Ok(match self.control(proto::CMD_RETIRE_SITE, idx as u64, Duration::from_secs(30))? {
            0 => Ok(()),
            c => Err(c),
        })
    }

    /// Restore every patched site (agent stays loaded, recording stops).
    pub fn detach_sites(&mut self) -> io::Result<()> {
        match self.control(proto::CMD_DETACH, 0, Duration::from_secs(30))? {
            0 => Ok(()),
            c => Err(io::Error::other(format!("detach answered {c}"))),
        }
    }

    /// Change the sampling stride of a site at any time (1 = keep every hit).
    pub fn set_stride(&self, idx: usize, stride: u32) {
        self.wr32(proto::site_offset(idx) + proto::S_MASK, stride.max(1) - 1);
    }

    /// Run one step of the sampling policy: read the counters, let `sampler` decide, apply the new strides.
    pub fn sampling_tick(&mut self, sampler: &mut crate::sampling::Sampler) {
        let c = self.counters();
        let hits: Vec<u64> = c.sites.iter().map(|s| s.hits).collect();
        for (site, stride) in sampler.step(Instant::now(), &hits, c.dropped) {
            self.set_stride(site, stride);
        }
    }

    /// Read every ring to its head. Each decoded hit is passed to `f`.
    pub fn drain_with(&mut self, mut f: impl FnMut(Hit)) -> u64 {
        use std::sync::atomic::Ordering;
        self.refine_clock();
        let mut n = 0;
        unsafe {
            let claimed = (self.rd32(proto::H_NRINGS) as usize).min(proto::MAX_RINGS);
            for i in 0..claimed {
                let r = self.view.add(proto::ring_offset(i));
                let head_a = &*(r.add(proto::R_HEAD) as *const std::sync::atomic::AtomicU32);
                let state_a = &*(r.add(proto::R_STATE) as *const std::sync::atomic::AtomicU32);
                let state = state_a.load(Ordering::Acquire);
                let head = head_a.load(Ordering::Acquire);
                let mut t = self.tails[i];
                while t != head {
                    let off = t as usize & (proto::RING_DATA - 1);
                    let avail = (head.wrapping_sub(t) as usize).min(proto::RING_DATA - off);
                    let slice = core::slice::from_raw_parts(r.add(proto::RING_HDR + off), avail);
                    match proto::decode_record(slice) {
                        Some((size, hit)) => {
                            if let Some(h) = hit {
                                f(h);
                                n += 1;
                            }
                            t = t.wrapping_add(size as u32);
                        }
                        None => {
                            self.counters.bad_records += 1;
                            t = head;
                        }
                    }
                }
                self.tails[i] = t;
                (r.add(proto::R_TAIL) as *mut u32).write_volatile(t);
                if state == proto::RING_RETIRED && t == head {
                    // The owner is gone and everything it wrote is read: hand the ring back.
                    let _ = state_a.compare_exchange(proto::RING_RETIRED, proto::RING_FREE, Ordering::AcqRel, Ordering::Relaxed);
                }
            }
        }
        n
    }

    pub fn drain(&mut self) -> Vec<Hit> {
        let mut out = Vec::new();
        self.drain_with(|h| out.push(h));
        out
    }

    /// Totals over all rings; hit/kept counters are monotonic per ring and never reset when a ring is reused.
    pub fn counters(&mut self) -> Counters {
        let mut c = Counters {
            sites: vec![SiteCounters::default(); proto::MAX_SITES],
            bad_records: self.counters.bad_records,
            events_lost: self.counters.events_lost,
            ..Default::default()
        };
        unsafe {
            let claimed = (self.rd32(proto::H_NRINGS) as usize).min(proto::MAX_RINGS);
            for i in 0..claimed {
                let r = self.view.add(proto::ring_offset(i));
                let u = |o: usize| (r.add(o) as *const u32).read_volatile() as u64;
                c.dropped += u(proto::R_DROPPED);
                c.read_failed += u(proto::R_READ_FAILED);
                c.unreturned += u(proto::R_UNRETURNED);
                c.stalls += u(proto::R_STALLS);
                c.stall_ticks += (r.add(proto::R_STALL_TICKS) as *const u64).read_volatile();
                for s in 0..proto::MAX_SITES {
                    let p = r.add(proto::RING_CTR + s * proto::CTR_SIZE) as *const u64;
                    c.sites[s].hits += p.read_volatile();
                    c.sites[s].kept += p.add(1).read_volatile();
                }
            }
        }
        c.attempted = c.sites.iter().map(|s| s.hits).sum();
        c.no_ring = self.rd32(proto::H_NO_RING) as u64;
        c
    }

    /// Per ring: `(ring, attempted, dropped, read_failed)` as the agent counts them. `attempted` is the ring's
    /// sequence counter, which every attempted record advances, dropped or not.
    pub fn ring_rows(&self) -> Vec<(u32, u64, u64, u64)> {
        let claimed = (self.rd32(proto::H_NRINGS) as usize).min(proto::MAX_RINGS);
        (0..claimed)
            .map(|i| unsafe {
                let r = self.view.add(proto::ring_offset(i));
                let u = |o: usize| (r.add(o) as *const u32).read_volatile() as u64;
                (i as u32, u(proto::R_SEQ), u(proto::R_DROPPED), u(proto::R_READ_FAILED))
            })
            .collect()
    }

    /// Out-of-band events (breakpoint hits, watch hits, auto-continues) since the last call.
    pub fn events(&mut self) -> Vec<Event> {
        self.refine_clock();
        let head = self.rd32(proto::H_EVENT_HEAD);
        let mut out = Vec::new();
        let backlog = head.wrapping_sub(self.next_event) as usize;
        if backlog > proto::EVENT_SLOTS {
            self.counters.events_lost += (backlog - proto::EVENT_SLOTS) as u64;
            self.next_event = head.wrapping_sub(proto::EVENT_SLOTS as u32);
        }
        while self.next_event != head {
            let idx = self.next_event as usize;
            let off = proto::event_offset(idx);
            if self.rd32(off + proto::E_SEQ) != self.next_event.wrapping_add(1) {
                break; // claimed but not yet published
            }
            unsafe {
                let e = self.view.add(off);
                let mut data = [0u64; 5];
                for (k, d) in data.iter_mut().enumerate() {
                    *d = (e.add(proto::E_DATA + 8 * k) as *const u64).read_volatile();
                }
                out.push(Event {
                    kind: (e.add(proto::E_KIND) as *const u16).read_volatile(),
                    site: (e.add(proto::E_SITE) as *const u16).read_volatile(),
                    tid: (e.add(proto::E_TID) as *const u32).read_volatile(),
                    slot: (e.add(proto::E_SLOT) as *const u32).read_volatile(),
                    tsc: (e.add(proto::E_TSC) as *const u64).read_volatile(),
                    data,
                });
            }
            self.next_event = self.next_event.wrapping_add(1);
        }
        out
    }

    /// Threads currently parked at a breakpoint.
    pub fn paused(&mut self) -> Vec<Paused> {
        let mut out = Vec::new();
        let now = Instant::now();
        for i in 0..proto::MAX_PAUSE {
            let off = proto::pause_offset(i);
            if self.rd32(off + proto::P_STATE) != 1 {
                continue;
            }
            let tsc = self.rd64(off + proto::P_TSC);
            let first = *self.first_seen.entry((i, tsc)).or_insert(now);
            let mut frame = [0u64; proto::P_FRAME_WORDS];
            for (k, w) in frame.iter_mut().enumerate() {
                *w = self.rd64(off + proto::P_FRAME + 8 * k);
            }
            out.push(Paused {
                slot: i,
                tid: self.rd32(off + proto::P_TID),
                site: self.rd32(off + proto::P_SITE),
                parked_for: now - first,
                frame,
            });
        }
        let view = self.view;
        let rd = |off: usize| unsafe { (view.add(off) as *const u64).read_volatile() };
        self.first_seen.retain(|(slot, tsc), _| {
            let off = proto::pause_offset(*slot);
            rd(off + proto::P_STATE) as u32 == 1 && rd(off + proto::P_TSC) == *tsc
        });
        out
    }

    /// Let the parked thread in `slot` run. `auto` marks a watchdog release.
    pub fn continue_breakpoint(&mut self, slot: usize, auto: bool) -> bool {
        if slot >= proto::MAX_PAUSE || self.rd32(proto::pause_offset(slot) + proto::P_STATE) != 1 {
            return false;
        }
        self.wr32(proto::pause_offset(slot) + proto::P_ACTION, if auto { 2 } else { 1 });
        unsafe { SetEvent(self.bp_ev[slot]) };
        true
    }

    /// The breakpoint watchdog: continue every thread parked longer than `limit` (30 s by default in the product).
    /// Returns the slots released.
    pub fn watchdog(&mut self, limit: Duration) -> Vec<usize> {
        let late: Vec<usize> = self.paused().into_iter().filter(|p| p.parked_for >= limit).map(|p| p.slot).collect();
        late.into_iter().filter(|&s| self.continue_breakpoint(s, true)).collect()
    }

    fn thread_ids(&self) -> Vec<u32> {
        let mut ids = Vec::new();
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
            if snap == INVALID_HANDLE_VALUE {
                return ids;
            }
            let mut e: THREADENTRY32 = core::mem::zeroed();
            e.dwSize = core::mem::size_of::<THREADENTRY32>() as u32;
            let mut ok = Thread32First(snap, &mut e);
            while ok != 0 {
                if e.th32OwnerProcessID == self.pid {
                    ids.push(e.th32ThreadID);
                }
                ok = Thread32Next(snap, &mut e);
            }
            CloseHandle(snap);
        }
        ids
    }

    pub fn threads(&self) -> Vec<u32> {
        self.thread_ids()
    }

    /// Suspend every thread of the target (process-wide pause). Returns the handles; `resume_all` releases them.
    pub fn suspend_all(&self) -> Vec<HANDLE> {
        let mut hs = Vec::new();
        for tid in self.thread_ids() {
            unsafe {
                let h = OpenThread(THREAD_SUSPEND_RESUME, 0, tid);
                if h.is_null() {
                    continue;
                }
                if SuspendThread(h) == u32::MAX {
                    CloseHandle(h);
                    continue;
                }
                hs.push(h);
            }
        }
        hs
    }

    pub fn resume_all(&self, handles: Vec<HANDLE>) {
        for h in handles {
            unsafe {
                ResumeThread(h);
                CloseHandle(h);
            }
        }
    }

    /// Loaded modules of the target.
    pub fn modules(&self) -> io::Result<Vec<ModuleInfo>> {
        unsafe {
            let snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid);
            if snap == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let mut e: MODULEENTRY32W = core::mem::zeroed();
            e.dwSize = core::mem::size_of::<MODULEENTRY32W>() as u32;
            let mut out = Vec::new();
            let mut ok = Module32FirstW(snap, &mut e);
            let s = |w: &[u16]| String::from_utf16_lossy(&w[..w.iter().position(|&c| c == 0).unwrap_or(w.len())]);
            while ok != 0 {
                out.push(ModuleInfo { name: s(&e.szModule), path: s(&e.szExePath), base: e.modBaseAddr as u64, size: e.modBaseSize });
                ok = Module32NextW(snap, &mut e);
            }
            CloseHandle(snap);
            Ok(out)
        }
    }

    /// Kernel-checked read: an unreadable range fails with an error code, no fault is raised in the target.
    ///
    /// # Errors
    /// `InvalidInput` when `len` exceeds [`MAX_READ`] (the length comes from the caller's request and must not be
    /// able to abort the host on allocation failure); `OutOfMemory` when the buffer cannot be reserved.
    pub fn read_memory(&self, address: u64, len: usize) -> io::Result<Vec<u8>> {
        let mut buf = zeroed_buffer(len)?;
        let mut got = 0usize;
        let ok = unsafe { ReadProcessMemory(self.process, address as *const _, buf.as_mut_ptr().cast(), len, &mut got) };
        if ok == 0 || got != len {
            return Err(io::Error::last_os_error());
        }
        Ok(buf)
    }

    pub(crate) fn write_raw(&self, address: u64, bytes: &[u8]) -> io::Result<()> {
        let mut put = 0usize;
        let ok = unsafe { WriteProcessMemory(self.process, address as *const _, bytes.as_ptr().cast(), bytes.len(), &mut put) };
        if ok == 0 || put != bytes.len() {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Memory protection of the page holding `address`: `(base, size, protect)`.
    pub fn query(&self, address: u64) -> io::Result<(u64, u64, u32)> {
        unsafe {
            let mut mbi: MEMORY_BASIC_INFORMATION = core::mem::zeroed();
            if VirtualQueryEx(self.process, address as *const _, &mut mbi, core::mem::size_of::<MEMORY_BASIC_INFORMATION>()) == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok((mbi.BaseAddress as u64, mbi.RegionSize as u64, if mbi.State == MEM_COMMIT { mbi.Protect } else { 0 }))
        }
    }

    pub fn terminate(&self) {
        unsafe { TerminateProcess(self.process, 1) };
    }

    /// Stop the agent's control thread. Sites stay as they are unless `detach_sites` ran first.
    pub fn shutdown_agent(&self) {
        self.wr32(proto::H_SHUTDOWN, 1);
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe {
            self.wr32(proto::H_SHUTDOWN, 1);
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS { Value: self.view.cast() });
            CloseHandle(self.section);
            for h in [self.cmd_ev, self.rsp_ev] {
                CloseHandle(h);
            }
            for h in &self.bp_ev {
                CloseHandle(*h);
            }
            if !self.thread.is_null() {
                CloseHandle(self.thread);
            }
            CloseHandle(self.process);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(args: &[&str]) -> String {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        command_line(r"C:\x\a b.exe", &args)
    }

    #[test]
    fn plain_arguments_stay_bare_and_the_exe_is_quoted() {
        assert_eq!(line(&["info", "--n=3"]), r#""C:\x\a b.exe" info --n=3"#);
    }

    #[test]
    fn spaces_quotes_and_empty_arguments_are_one_argv_entry() {
        assert_eq!(line(&["a b"]), r#""C:\x\a b.exe" "a b""#);
        assert_eq!(line(&[""]), r#""C:\x\a b.exe" """#);
        assert_eq!(line(&[r#"say "hi""#]), r#""C:\x\a b.exe" "say \"hi\"""#);
    }

    #[test]
    fn backslashes_double_only_before_a_quote_or_the_closing_quote() {
        assert_eq!(line(&[r"C:\dir\"]), r#""C:\x\a b.exe" C:\dir\"#);
        assert_eq!(line(&[r"C:\my dir\"]), r#""C:\x\a b.exe" "C:\my dir\\""#);
        assert_eq!(line(&[r#"a\"b"#]), r#""C:\x\a b.exe" "a\\\"b""#);
    }

    #[test]
    fn read_size_is_capped_before_allocating() {
        assert_eq!(zeroed_buffer(MAX_READ + 1).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(zeroed_buffer(usize::MAX).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(zeroed_buffer(16).unwrap(), vec![0u8; 16]);
    }

    #[test]
    fn session_tags_are_random_and_nonzero() {
        let a = random_tag().unwrap();
        let b = random_tag().unwrap();
        assert!(a != 0 && b != 0 && a != b);
    }
}
