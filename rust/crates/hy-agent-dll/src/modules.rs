//! Module load and unload notifications. The loader tells the agent (`LdrRegisterDllNotification`) the moment a module is
//! mapped or unmapped; each notification becomes one event in the shared event ring: `[base, size, name x 3]` where the
//! name is the first 24 characters of the module's base name (ASCII; anything else becomes `?`). The host resolves the
//! full path. The callback runs under the loader's notification lock on whatever thread loaded the module, so it only
//! does what `push_event` does: a few atomic stores.
use crate::ring;
use core::ffi::c_void;
use core::sync::atomic::Ordering;
use hy_agent_proto as p;

#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum: u16,
    buffer: *const u16,
}

/// `LDR_DLL_LOADED_NOTIFICATION_DATA` and `LDR_DLL_UNLOADED_NOTIFICATION_DATA` share this prefix.
#[repr(C)]
struct Notification {
    flags: u32,
    full_name: *const UnicodeString,
    base_name: *const UnicodeString,
    dll_base: *mut c_void,
    size_of_image: u32,
}

const REASON_LOADED: u32 = 1;
const REASON_UNLOADED: u32 = 2;

type Callback = unsafe extern "system" fn(u32, *const Notification, *mut c_void);

#[link(name = "ntdll", kind = "raw-dylib")]
unsafe extern "system" {
    fn LdrRegisterDllNotification(flags: u32, callback: Callback, context: *mut c_void, cookie: *mut *mut c_void) -> i32;
}

/// Pack up to 24 characters of a UTF-16 name into three little-endian words, NUL padded.
pub fn pack_name(name: &[u16]) -> [u64; 3] {
    let mut bytes = [0u8; 24];
    for (slot, &c) in bytes.iter_mut().zip(name) {
        *slot = if (1..0x80).contains(&c) { c as u8 } else { b'?' };
    }
    let word = |i: usize| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap());
    [word(0), word(1), word(2)]
}

unsafe extern "system" fn on_notification(reason: u32, data: *const Notification, _ctx: *mut c_void) {
    unsafe {
        let kind = match reason {
            REASON_LOADED => p::EV_MODULE_LOAD,
            REASON_UNLOADED => p::EV_MODULE_UNLOAD,
            _ => return,
        };
        let sec = ring::section();
        if data.is_null() || sec.is_null() {
            return;
        }
        let shutdown = &*(sec.add(p::H_SHUTDOWN) as *const core::sync::atomic::AtomicU32);
        if shutdown.load(Ordering::Acquire) != 0 {
            return;
        }
        let d = &*data;
        let name = if d.base_name.is_null() || (*d.base_name).buffer.is_null() {
            [0; 3]
        } else {
            let n = (*d.base_name).length as usize / 2;
            pack_name(core::slice::from_raw_parts((*d.base_name).buffer, n.min(24)))
        };
        ring::push_event(kind, 0, 0, [d.dll_base as u64, u64::from(d.size_of_image), name[0], name[1], name[2]]);
    }
}

/// Start reporting. Modules already mapped are not reported (the host lists them itself).
pub unsafe fn register() {
    unsafe {
        let mut cookie: *mut c_void = core::ptr::null_mut();
        LdrRegisterDllNotification(0, on_notification, core::ptr::null_mut(), &mut cookie);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_pack_into_three_words_and_truncate() {
        let w = pack_name(&"trace_plugin.dll".encode_utf16().collect::<Vec<_>>());
        let mut bytes = Vec::new();
        for x in w {
            bytes.extend_from_slice(&x.to_le_bytes());
        }
        assert_eq!(&bytes[..16], b"trace_plugin.dll");
        assert!(bytes[16..].iter().all(|&b| b == 0));
        let long = pack_name(&[b'a' as u16; 40]);
        assert_eq!(long, [u64::from_le_bytes(*b"aaaaaaaa"); 3]);
        assert_eq!(pack_name(&[0x4e2d, b'x' as u16])[0], u64::from_le_bytes(*b"?x\0\0\0\0\0\0"));
    }
}
