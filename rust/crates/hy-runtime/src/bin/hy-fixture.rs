//! A small Rust target the live tests drive. Modes (first argument):
//!   info              print the RVA and first bytes of `fx_hit` and the RVA of the data cell
//!   churn N           N short-lived threads, each calling `fx_hit` three times (thread-exit ring reuse)
//!   pause             call `fx_hit(7)` once on the main thread (breakpoint tests)
//!   watch             print ADDR, wait, write the cell five times, then once from a late thread
//!   write             print ADDR, wait until the cell reads 0x3333 (compare-and-swap write tests)
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "system" fn fx_hit(x: u64) -> u64 {
    std::hint::black_box(x.wrapping_mul(0x9E37_79B9_7F4A_7C15).rotate_left(13) ^ x)
}

static CELL: AtomicU64 = AtomicU64::new(0x1111);

fn base() -> usize {
    unsafe {
        windows_sys::Win32::System::LibraryLoader::GetModuleHandleW(core::ptr::null()) as usize
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(String::as_str).unwrap_or("info");
    match mode {
        "info" => {
            let f = fx_hit as *const () as usize;
            let bytes: Vec<String> = (0..32)
                .map(|i| format!("{:02x}", unsafe { *(f as *const u8).add(i) }))
                .collect();
            println!(
                "RVA={:x} BYTES={} CELL={:x}",
                f - base(),
                bytes.join(""),
                &CELL as *const AtomicU64 as usize - base()
            );
        }
        "churn" => {
            let n: u64 = args[2].parse().unwrap();
            for i in 0..n {
                std::thread::spawn(move || {
                    for k in 0..3 {
                        fx_hit(i * 3 + k);
                    }
                })
                .join()
                .unwrap();
                std::thread::sleep(Duration::from_millis(1));
            }
            println!("DONE");
        }
        "pause" => {
            fx_hit(7);
            println!("AFTER");
        }
        "watch" => {
            println!("ADDR={:x}", &CELL as *const AtomicU64 as usize);
            std::thread::sleep(Duration::from_millis(600));
            for v in 1..=5u64 {
                CELL.store(v, Ordering::SeqCst);
                std::thread::sleep(Duration::from_millis(5));
            }
            std::thread::spawn(|| {
                std::thread::sleep(Duration::from_millis(400));
                CELL.store(99, Ordering::SeqCst);
            })
            .join()
            .unwrap();
            std::thread::sleep(Duration::from_millis(50));
            println!("DONE");
        }
        "write" => {
            println!(
                "ADDR={:x} BASE={:x}",
                &CELL as *const AtomicU64 as usize,
                base()
            );
            for _ in 0..20_000 {
                if CELL.load(Ordering::SeqCst) == 0x3333 {
                    println!("SAW");
                    return;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            println!("TIMEOUT");
            std::process::exit(2);
        }
        other => {
            eprintln!("unknown mode {other}");
            std::process::exit(64);
        }
    }
}
