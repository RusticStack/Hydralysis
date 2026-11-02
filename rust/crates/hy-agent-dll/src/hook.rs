//! x86-64 inline hooks: a 5-byte `jmp rel32` at the site into a per-site stub that saves the argument registers,
//! calls `on_hit`, restores, runs the relocated stolen prologue and jumps back.
//!
//! Return capture: `on_hit` swaps the return address on the stack for the shared return trampoline and keeps the
//! entry data (and the real return address) on a per-thread shadow stack; `on_return` completes the record.
use crate::ring::{self, Entry};
use crate::{pause, threads};
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicUsize, Ordering};
use hy_agent_proto as p;
use iced_x86::code_asm::*;
use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use windows_sys::Win32::System::Diagnostics::Debug::*;
use windows_sys::Win32::System::Memory::*;

pub static RET_STUB: AtomicUsize = AtomicUsize::new(0);

/// Immutable per-site data the stub passes to `on_hit` (leaked; stubs live for the process).
#[repr(C)]
pub struct Hook {
    pub site: u16,
    pub cfg: *mut u8,
    pub addr: usize,
}

/// Everything prepared before the other threads are suspended.
pub struct Prepared {
    pub addr: usize,
    pub len: usize,
    pub orig: [u8; 16],
    pub patch: [u8; 16],
}

fn enc<T, E>(r: Result<T, E>) -> Result<T, u32> {
    r.map_err(|_| p::ERR_ENCODE)
}

fn alloc_near(site: usize, size: usize) -> Option<usize> {
    let lo = site.saturating_sub(0x6000_0000) & !0xFFFF;
    let hi = site + 0x6000_0000;
    let mut a = site & !0xFFFF;
    // Search outward from the site: nearest free region first.
    let mut step = 0usize;
    while step < 0x6000_0000 {
        for cand in [a.wrapping_sub(step), a + step] {
            if cand < lo || cand > hi {
                continue;
            }
            let ptr = unsafe {
                VirtualAlloc(
                    cand as *const _,
                    size,
                    MEM_RESERVE | MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE,
                )
            };
            if !ptr.is_null() {
                return Some(ptr as usize);
            }
        }
        step += 0x10000;
        a = site & !0xFFFF;
    }
    None
}

/// Decode, relocate and assemble the stub for `addr`. Does not touch the site.
pub unsafe fn prepare(site: u16, cfg: *mut u8, addr: usize) -> Result<Prepared, u32> {
    unsafe {
        let flags = (cfg.add(p::S_FLAGS) as *const u32).read_unaligned();
        let code = core::slice::from_raw_parts(addr as *const u8, 32);
        let mut dec = Decoder::with_ip(64, code, addr as u64, DecoderOptions::NONE);
        let mut stolen: Vec<Instruction> = Vec::new();
        let mut len = 0usize;
        while len < 5 {
            let i = dec.decode();
            if i.is_invalid() {
                return Err(p::ERR_DECODE);
            }
            len += i.len();
            stolen.push(i);
        }
        for i in &stolen {
            if matches!(
                i.flow_control(),
                FlowControl::ConditionalBranch | FlowControl::UnconditionalBranch
            ) {
                let t = i.near_branch_target() as usize;
                if t > addr && t < addr + len {
                    return Err(p::ERR_DECODE);
                }
            }
        }
        let mem = alloc_near(addr, 4096).ok_or(p::ERR_NO_STUB_ROOM)?;
        let hook = Box::leak(Box::new(Hook { site, cfg, addr })) as *const Hook as u64;
        let stack = flags & p::F_STACK != 0;
        let extra: i32 = if stack { 64 } else { 0 };

        let tls = ring::TLS_IDX.load(Ordering::Relaxed);
        let mut a = enc(CodeAssembler::new(64))?;
        let mut tail = a.create_label();
        let mut main_counted = a.create_label();
        let mut main_plain = a.create_label();
        if tls < 64 {
            // Inline gate (no call, no xmm save): count the hit in this thread's ring and skip it when the sampling
            // policy says so. Only a kept hit, or a thread with no ring yet, takes the full path below.
            let ctr = (p::RING_CTR + site as usize * p::CTR_SIZE) as i32;
            let mut keep = a.create_label();
            let mut slow = a.create_label();
            enc(a.pushfq())?;
            enc(a.push(r10))?;
            enc(a.push(r11))?;
            enc(a.mov(r10, qword_ptr(0x1480u64 + 8 * tls as u64).gs()))?;
            enc(a.test(r10, r10))?;
            enc(a.jz(slow))?;
            enc(a.inc(qword_ptr(r10 + ctr)))?;
            enc(a.mov(r11, qword_ptr(r10 + ctr + 16)))?;
            enc(a.test(r11, r11))?;
            enc(a.jz(keep))?;
            enc(a.dec(r11))?;
            enc(a.mov(qword_ptr(r10 + ctr + 16), r11))?;
            enc(a.pop(r11))?;
            enc(a.pop(r10))?;
            enc(a.popfq())?;
            enc(a.jmp(tail))?;
            enc(a.set_label(&mut keep))?;
            enc(a.pop(r11))?;
            enc(a.pop(r10))?;
            enc(a.popfq())?;
            enc(a.jmp(main_counted))?;
            enc(a.set_label(&mut slow))?;
            enc(a.pop(r11))?;
            enc(a.pop(r10))?;
            enc(a.popfq())?;
        } else {
            enc(a.jmp(main_plain))?;
        }
        enc(a.set_label(&mut main_plain))?;
        emit_main(&mut a, hook, stack, extra, false)?;
        enc(a.jmp(tail))?;
        enc(a.set_label(&mut main_counted))?;
        emit_main(&mut a, hook, stack, extra, true)?;
        enc(a.set_label(&mut tail))?;
        for i in stolen {
            enc(a.add_instruction(i))?;
        }
        enc(a.jmp((addr + len) as u64))?;
        let code = enc(a.assemble(mem as u64))?;
        core::ptr::copy_nonoverlapping(code.as_ptr(), mem as *mut u8, code.len());
        FlushInstructionCache(-1isize as _, mem as *const _, code.len());

        let rel = i32::try_from(mem as i64 - (addr as i64 + 5)).map_err(|_| p::ERR_NO_STUB_ROOM)?;
        let mut orig = [0u8; 16];
        core::ptr::copy_nonoverlapping(addr as *const u8, orig.as_mut_ptr(), 16);
        let mut patch = orig;
        patch[0] = 0xE9;
        patch[1..5].copy_from_slice(&rel.to_le_bytes());
        for b in patch.iter_mut().take(len).skip(5) {
            *b = 0x90;
        }
        Ok(Prepared {
            addr,
            len,
            orig,
            patch,
        })
    }
}

/// Write `bytes[..len]` over the site. The caller has the other threads suspended. When the first 8 bytes sit in one
/// cache line the patch is a single atomic 8-byte store, so a thread that was not stopped (a thread created in the
/// window) sees either the old or the new bytes.
pub unsafe fn write_site(addr: usize, bytes: &[u8; 16], len: usize) -> Result<(), u32> {
    unsafe {
        let mut old = 0u32;
        if VirtualProtect(addr as *const _, 16, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return Err(p::ERR_PROTECT);
        }
        if (addr & 63) <= 56 && len <= 8 {
            let cur = (addr as *const u64).read_unaligned();
            let mut word = cur.to_le_bytes();
            word[..len].copy_from_slice(&bytes[..len]);
            let a = &*(addr as *const core::sync::atomic::AtomicU64);
            a.store(u64::from_le_bytes(word), Ordering::SeqCst);
        } else {
            core::ptr::copy_nonoverlapping(bytes.as_ptr(), addr as *mut u8, len);
        }
        VirtualProtect(addr as *const _, 16, old, &mut old);
        FlushInstructionCache(-1isize as _, addr as *const _, 16);
        Ok(())
    }
}

/// Install a prepared hook with every other thread stopped and none of them inside the stolen bytes.
pub unsafe fn commit(pr: &Prepared) -> Result<(), u32> {
    unsafe {
        let mut result = Err(p::ERR_THREAD_IN_SITE);
        for _ in 0..200 {
            let stopped = threads::suspend_others().map_err(|_| p::ERR_SUSPEND)?;
            if !stopped.any_in(pr.addr, pr.addr + pr.len) {
                result = write_site(pr.addr, &pr.patch, pr.len);
                drop(stopped);
                break;
            }
            drop(stopped);
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        result
    }
}

/// Put the original bytes back. A thread already inside the stub finishes it and returns to the (restored) site.
pub unsafe fn retire(pr: &Prepared) -> Result<(), u32> {
    unsafe {
        let stopped = threads::suspend_others().map_err(|_| p::ERR_SUSPEND)?;
        let r = write_site(pr.addr, &pr.orig, pr.len);
        drop(stopped);
        r
    }
}

/// The full save / call / restore sequence. `counted`: the inline gate already counted the hit and decided to keep it.
fn emit_main(
    a: &mut CodeAssembler,
    hook: u64,
    stack: bool,
    extra: i32,
    counted: bool,
) -> Result<(), u32> {
    enc(a.pushfq())?;
    for r in [rax, rcx, rdx, r8, r9, r10, r11] {
        enc(a.push(r))?;
    }
    if stack {
        for r in [rbx, rbp, rsi, rdi, r12, r13, r14, r15] {
            enc(a.push(r))?;
        }
    }
    enc(a.sub(rsp, 104))?;
    let xs = [xmm0, xmm1, xmm2, xmm3];
    for (n, x) in xs.iter().enumerate() {
        enc(a.movups(xmmword_ptr(rsp + 40 + 16 * n as i32), *x))?;
    }
    enc(a.mov(rcx, hook))?;
    enc(a.lea(rdx, qword_ptr(rsp + 104 + extra)))?;
    if stack {
        enc(a.lea(r8, qword_ptr(rsp + 104)))?;
    } else {
        enc(a.xor(r8d, r8d))?;
    }
    enc(a.mov(r9d, u32::from(counted)))?;
    enc(a.mov(rax, on_hit as *const () as usize as u64))?;
    enc(a.call(rax))?;
    for (n, x) in xs.iter().enumerate() {
        enc(a.movups(*x, xmmword_ptr(rsp + 40 + 16 * n as i32)))?;
    }
    enc(a.add(rsp, 104))?;
    if stack {
        for r in [r15, r14, r13, r12, rdi, rsi, rbp, rbx] {
            enc(a.pop(r))?;
        }
    }
    for r in [r11, r10, r9, r8, rdx, rcx, rax] {
        enc(a.pop(r))?;
    }
    enc(a.popfq())?;
    Ok(())
}

pub unsafe fn make_return_stub() -> Result<usize, u32> {
    unsafe {
        let mut a = enc(CodeAssembler::new(64))?;
        enc(a.sub(rsp, 8))?;
        enc(a.push(rax))?;
        enc(a.push(rdx))?;
        enc(a.sub(rsp, 56))?;
        enc(a.movups(xmmword_ptr(rsp + 32), xmm0))?;
        enc(a.lea(rcx, qword_ptr(rsp + 56)))?;
        enc(a.mov(rax, on_return as *const () as usize as u64))?;
        enc(a.call(rax))?;
        enc(a.movups(xmm0, xmmword_ptr(rsp + 32)))?;
        enc(a.add(rsp, 56))?;
        enc(a.pop(rdx))?;
        enc(a.pop(rax))?;
        enc(a.ret())?;
        let mem = VirtualAlloc(
            core::ptr::null(),
            4096,
            MEM_RESERVE | MEM_COMMIT,
            PAGE_EXECUTE_READWRITE,
        ) as usize;
        if mem == 0 {
            return Err(p::ERR_NO_STUB_ROOM);
        }
        let bytes = enc(a.assemble(mem as u64))?;
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), mem as *mut u8, bytes.len());
        FlushInstructionCache(-1isize as _, mem as *const _, bytes.len());
        Ok(mem)
    }
}

#[inline(always)]
unsafe fn arg(fr: *const u64, i: usize) -> u64 {
    unsafe {
        if i < 4 {
            *fr.add(5 - i)
        } else {
            *fr.add(9 + i)
        }
    }
}

#[inline(always)]
unsafe fn read_buf(dst: *mut MaybeUninit<u8>, src: u64, n: usize) -> bool {
    unsafe {
        if src == 0 || n == 0 {
            return n == 0;
        }
        let mut got = 0usize;
        let ok = ReadProcessMemory(-1isize as _, src as *const _, dst as *mut _, n, &mut got);
        ok != 0 && got == n
    }
}

/// Called by the stub with the saved registers. `fr[5]` rcx, `fr[4]` rdx, `fr[3]` r8, `fr[2]` r9, `fr[8]` return address.
unsafe extern "system" fn on_hit(h: *const Hook, fr: *const u64, saved: *const u64, counted: u64) {
    unsafe {
        let h = &*h;
        let cfg = h.cfg;
        let ring = ring::my_ring();
        if ring.is_null() {
            return;
        }
        let c = ring::ctr(ring, h.site as usize);
        let next = c.add(2);
        if counted == 0 {
            c.write_volatile(c.read_volatile() + 1); // hits
            let skip = next.read_volatile();
            if skip != 0 {
                next.write_volatile(skip - 1);
                return;
            }
        }
        c.add(1).write_volatile(c.add(1).read_volatile() + 1); // kept
        next.write_volatile((cfg.add(p::S_MASK) as *const u32).read_volatile() as u64);

        let flags = (cfg.add(p::S_FLAGS) as *const u32).read();
        let want_return = flags & p::F_RETURN != 0;
        let slot = fr.add(8) as *mut u64;

        // The entry lives in the shadow stack when a return record is wanted, else on this frame.
        let mut local = MaybeUninit::<Entry>::uninit();
        let mut shadow_entry: *mut Entry = core::ptr::null_mut();
        if want_return {
            ring::SHADOW.with(|s| {
                let s = &mut *s.get();
                // Entries whose frame was unwound without returning (exception, longjmp) are stale.
                while s.depth > 0 && s.ents[s.depth - 1].slot <= slot as usize {
                    s.depth -= 1;
                    ring::bump32(ring, p::R_UNRETURNED);
                }
                if s.depth < p::SHADOW_DEPTH {
                    shadow_entry = &mut s.ents[s.depth] as *mut Entry;
                    s.depth += 1;
                }
            });
        }
        let e: &mut Entry = if shadow_entry.is_null() {
            &mut *local.as_mut_ptr()
        } else {
            &mut *shadow_entry
        };
        // Only the scalar fields are written eagerly; the arrays are filled up to their used length.
        e.site = h.site;
        e.rec_flags = 0;
        e.tid = ring::teb_tid();
        e.ret_addr = *slot;
        e.slot = slot as usize;
        e.buflen = 0;
        e.buf_addr = 0;
        e.buf_on_return = false;
        if want_return {
            e.rec_flags |= p::RF_HAS_RETURN;
            if shadow_entry.is_null() {
                e.rec_flags |= p::RF_NO_SHADOW;
            }
        }
        let nargs = ((cfg.add(p::S_NARGS) as *const u32).read() as usize).min(p::MAX_ARGS);
        e.nargs = nargs as u8;
        for i in 0..nargs {
            e.args[i] = MaybeUninit::new(arg(fr, i));
        }
        // Buffer capture.
        let buf_arg = (cfg.add(p::S_BUF_PTR_ARG) as *const i32).read();
        if (0..16).contains(&buf_arg) {
            let ptr = arg(fr, buf_arg as usize);
            let len_arg = (cfg.add(p::S_BUF_LEN_ARG) as *const i32).read();
            let want = if len_arg >= 0 {
                arg(fr, len_arg as usize) as u32 as usize
            } else {
                (cfg.add(p::S_BUF_FIXED) as *const u32).read() as usize
            };
            let nbuf = want
                .min((cfg.add(p::S_BUF_MAX) as *const u32).read() as usize)
                .min(p::BUF_MAX);
            e.buf_addr = ptr;
            e.buf_ptr = ptr;
            e.buf_len = nbuf as u32;
            if flags & p::F_BUF_ON_RETURN != 0 && want_return && !shadow_entry.is_null() {
                e.buf_on_return = true;
            } else if read_buf(e.buf.as_mut_ptr(), ptr, nbuf) {
                e.buflen = nbuf as u16;
            } else {
                e.rec_flags |= p::RF_BUF_FAILED;
                ring::bump32(ring, p::R_READ_FAILED);
            }
        }
        e.nstack = 0;
        if flags & p::F_STACK != 0 {
            let depth =
                ((cfg.add(p::S_STACK_DEPTH) as *const u32).read() as usize).min(p::MAX_STACK);
            e.nstack = walk(h.addr, slot, saved, depth, e.stack.as_mut_ptr() as *mut u64) as u8;
        }
        e.tsc = ring::now();

        if !shadow_entry.is_null() {
            *slot = RET_STUB.load(Ordering::Relaxed) as u64;
        } else {
            ring::emit(ring, e, false, 0, 0, 0);
        }
        if flags & p::F_PAUSE != 0 {
            pause::park(h.site, fr);
        }
    }
}

/// Collect up to `depth` return addresses starting with the one at `slot` (the hooked function's caller).
unsafe fn walk(
    site_addr: usize,
    slot: *mut u64,
    saved: *const u64,
    depth: usize,
    out: *mut u64,
) -> usize {
    unsafe {
        #[repr(C, align(16))]
        struct Ctx(CONTEXT);
        let mut c: Ctx = core::mem::zeroed();
        let ctx = &mut c.0;
        ctx.Rip = site_addr as u64;
        ctx.Rsp = slot as u64;
        if !saved.is_null() {
            // push order rbx rbp rsi rdi r12 r13 r14 r15 -> ascending memory r15 .. rbx
            ctx.R15 = *saved;
            ctx.R14 = *saved.add(1);
            ctx.R13 = *saved.add(2);
            ctx.R12 = *saved.add(3);
            ctx.Rdi = *saved.add(4);
            ctx.Rsi = *saved.add(5);
            ctx.Rbp = *saved.add(6);
            ctx.Rbx = *saved.add(7);
        }
        let mut n = 0;
        while n < depth {
            let mut image = 0u64;
            let rf = RtlLookupFunctionEntry(ctx.Rip, &mut image, core::ptr::null_mut());
            if rf.is_null() {
                ctx.Rip = *(ctx.Rsp as *const u64);
                ctx.Rsp += 8;
            } else {
                let mut handler = core::ptr::null_mut();
                let mut frame = 0u64;
                RtlVirtualUnwind(
                    0,
                    image,
                    ctx.Rip,
                    rf,
                    ctx,
                    &mut handler,
                    &mut frame,
                    core::ptr::null_mut(),
                );
            }
            if ctx.Rip == 0 {
                break;
            }
            out.add(n).write(ctx.Rip);
            n += 1;
        }
        n
    }
}

/// Reached by `ret` from a hooked function whose return address was swapped. `frame[0]` rdx, `[1]` rax, `[2]` the slot
/// that the final `ret` of the trampoline pops: we write the real return address there.
unsafe extern "system" fn on_return(frame: *mut u64) {
    unsafe {
        let tsc_end = ring::now();
        let last_error = ring::teb_last_error();
        let placeholder = frame.add(2) as usize;
        let retval = *frame.add(1);
        let ring = ring::my_ring();
        let mut orig = 0u64;
        ring::SHADOW.with(|s| {
            let s = &mut *s.get();
            while s.depth > 0 && s.ents[s.depth - 1].slot < placeholder {
                s.depth -= 1;
                if !ring.is_null() {
                    ring::bump32(ring, p::R_UNRETURNED);
                }
            }
            if s.depth == 0 || s.ents[s.depth - 1].slot != placeholder {
                // Cannot happen unless the stack was corrupted; there is no safe place to return to.
                core::arch::asm!("ud2");
            }
            s.depth -= 1;
            let e = &mut s.ents[s.depth];
            orig = e.ret_addr;
            if e.buf_on_return {
                let n = e.buf_len as usize;
                if read_buf(e.buf.as_mut_ptr(), e.buf_ptr, n) {
                    e.buflen = n as u16;
                } else {
                    e.rec_flags |= p::RF_BUF_FAILED;
                    if !ring.is_null() {
                        ring::bump32(ring, p::R_READ_FAILED);
                    }
                }
            }
            if !ring.is_null() {
                ring::emit(ring, e, true, tsc_end, retval, last_error);
            }
        });
        *frame.add(2) = orig;
    }
}
