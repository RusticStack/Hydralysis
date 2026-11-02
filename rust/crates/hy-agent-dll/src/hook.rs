//! x86-64 inline hook: a 5-byte `jmp rel32` at the site into a stub that saves the argument registers, calls
//! the recorder, restores, runs the relocated stolen prologue and jumps back. Installed with every other thread
//! quiescent (init runs while the target's threads are suspended or not yet started).
use crate::ring;
use iced_x86::code_asm::*;
use iced_x86::{
    BlockEncoder, BlockEncoderOptions, Code, Decoder, DecoderOptions, FlowControl, Instruction,
    InstructionBlock,
};
use windows_sys::Win32::System::Diagnostics::Debug::FlushInstructionCache;
use windows_sys::Win32::System::Memory::*;
use windows_sys::Win32::System::Threading::GetCurrentProcess;

pub const ERR_BYTES_MISMATCH: u32 = 10;
pub const ERR_DECODE: u32 = 11;
pub const ERR_NO_STUB_ROOM: u32 = 12;
pub const ERR_ENCODE: u32 = 13;
pub const ERR_PROTECT: u32 = 14;

#[repr(C)]
pub struct Hook {
    site: u16,
}

/// Called by the stub. `fr[0]` is r11 ... `fr[5]` rcx, `fr[8]` the return address (see stub layout).
unsafe extern "system" fn on_hit(h: *const Hook, fr: *const u64) {
    unsafe { ring::record((*h).site, *fr.add(5), *fr.add(8)) }
}

fn alloc_near(site: usize, size: usize) -> Option<usize> {
    let mut a = (site.saturating_sub(0x4000_0000)) & !0xFFFF;
    let hi = site + 0x4000_0000;
    while a < hi {
        let p = unsafe {
            VirtualAlloc(
                a as *const _,
                size,
                MEM_RESERVE | MEM_COMMIT,
                PAGE_EXECUTE_READWRITE,
            )
        };
        if !p.is_null() {
            return Some(p as usize);
        }
        a += 0x10000;
    }
    None
}

pub unsafe fn install(site_id: u16, site: usize, expect: &[u8]) -> Result<(), u32> {
    unsafe {
        let code = core::slice::from_raw_parts(site as *const u8, 32);
        if !expect.is_empty() && &code[..expect.len()] != expect {
            return Err(ERR_BYTES_MISMATCH);
        }
        // Steal whole instructions covering >= 5 bytes; refuse a branch that lands inside the stolen range.
        let mut dec = Decoder::with_ip(64, code, site as u64, DecoderOptions::NONE);
        let mut stolen: Vec<Instruction> = Vec::new();
        let mut len = 0usize;
        while len < 5 {
            let i = dec.decode();
            if i.is_invalid() {
                return Err(ERR_DECODE);
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
                if t > site && t < site + len {
                    return Err(ERR_DECODE);
                }
            }
        }
        let mem = alloc_near(site, 4096).ok_or(ERR_NO_STUB_ROOM)?;
        let hook = Box::leak(Box::new(Hook { site: site_id })) as *const Hook as u64;

        let mut a = CodeAssembler::new(64).map_err(|_| ERR_ENCODE)?;
        a.pushfq().map_err(|_| ERR_ENCODE)?;
        for r in [rax, rcx, rdx, r8, r9, r10, r11] {
            a.push(r).map_err(|_| ERR_ENCODE)?;
        }
        a.sub(rsp, 104).map_err(|_| ERR_ENCODE)?;
        let xs = [xmm0, xmm1, xmm2, xmm3];
        for (n, x) in xs.iter().enumerate() {
            a.movups(xmmword_ptr(rsp + 40 + 16 * n as i32), *x)
                .map_err(|_| ERR_ENCODE)?;
        }
        a.mov(rcx, hook).map_err(|_| ERR_ENCODE)?;
        a.lea(rdx, qword_ptr(rsp + 104)).map_err(|_| ERR_ENCODE)?;
        a.mov(rax, on_hit as *const () as usize as u64)
            .map_err(|_| ERR_ENCODE)?;
        a.call(rax).map_err(|_| ERR_ENCODE)?;
        for (n, x) in xs.iter().enumerate() {
            a.movups(*x, xmmword_ptr(rsp + 40 + 16 * n as i32))
                .map_err(|_| ERR_ENCODE)?;
        }
        a.add(rsp, 104).map_err(|_| ERR_ENCODE)?;
        for r in [r11, r10, r9, r8, rdx, rcx, rax] {
            a.pop(r).map_err(|_| ERR_ENCODE)?;
        }
        a.popfq().map_err(|_| ERR_ENCODE)?;
        let mut instrs: Vec<Instruction> = a.instructions().to_vec();
        instrs.extend(stolen);
        instrs.push(
            Instruction::with_branch(Code::Jmp_rel32_64, (site + len) as u64)
                .map_err(|_| ERR_ENCODE)?,
        );
        let enc = BlockEncoder::encode(
            64,
            InstructionBlock::new(&instrs, mem as u64),
            BlockEncoderOptions::NONE,
        )
        .map_err(|_| ERR_ENCODE)?;
        core::ptr::copy_nonoverlapping(
            enc.code_buffer.as_ptr(),
            mem as *mut u8,
            enc.code_buffer.len(),
        );

        let rel = (mem as i64) - (site as i64 + 5);
        let rel32 = i32::try_from(rel).map_err(|_| ERR_NO_STUB_ROOM)?;
        let mut old = 0u32;
        if VirtualProtect(site as *const _, 8, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return Err(ERR_PROTECT);
        }
        let p = site as *mut u8;
        p.write(0xE9);
        (p.add(1) as *mut i32).write_unaligned(rel32);
        for k in 5..len {
            p.add(k).write(0x90);
        }
        VirtualProtect(site as *const _, 8, old, &mut old);
        FlushInstructionCache(GetCurrentProcess(), site as *const _, len);
        FlushInstructionCache(GetCurrentProcess(), mem as *const _, enc.code_buffer.len());
        Ok(())
    }
}
