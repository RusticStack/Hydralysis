//! A sealed or atomic write must never expose an empty or partial file to a reader.
//!
//! Writer threads replace one path again and again (`atomic_write` of a self-checking blob; `write_sealed` of a
//! COMPLETE.json-like record) while reader threads read it in a loop. A reader may see the version before or after a
//! replace, never a zero-length file, a torn one, or a sealed record that needs its `.bak`. Environment:
//! `HY_STRESS_SECS` (default 3), `HY_STRESS_DIR` (default the temp dir; point it at D: or E: to compare disks),
//! `HY_STRESS_NOISE` (threads that fsync large files in the same folder to make the disk slow; default 0, the noisy
//! test uses 3 when unset), `HY_STRESS_WRITERS` / `HY_STRESS_READERS` (defaults 4 and 4).

use hy_core::fsio::{atomic_write, read_bytes};
use hy_core::sealed::{ReadOptions, Source, read_sealed_info, write_sealed_default};
use serde_json::json;
use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

fn number(name: &str, default: u64) -> u64 {
    std::env::var(name).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

fn folder(case: &str) -> PathBuf {
    let base = std::env::var_os("HY_STRESS_DIR").map(PathBuf::from).unwrap_or_else(std::env::temp_dir);
    let dir = base.join(format!("hy-stress-{case}-{}", uuid::Uuid::new_v4().simple()));
    fs::create_dir_all(&dir).unwrap();
    dir
}

/// `[length: u32 LE][byte][length x byte]`: any prefix, any empty file and any mixture of two versions fails the check.
fn blob(seed: u64) -> Vec<u8> {
    let length = 1 + ((seed.wrapping_mul(2654435761)) % 70_000) as usize;
    let byte = (seed % 251) as u8 + 1;
    let mut out = Vec::with_capacity(length + 5);
    out.extend_from_slice(&(length as u32).to_le_bytes());
    out.push(byte);
    out.resize(length + 5, byte);
    out
}

fn blob_ok(data: &[u8]) -> Result<(), String> {
    if data.len() < 5 {
        return Err(format!("{} bytes", data.len()));
    }
    let length = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
    if data.len() != length + 5 {
        return Err(format!("declares {length} body bytes, file has {}", data.len() - 5));
    }
    if data[5..].iter().any(|b| *b != data[4]) {
        return Err("mixed bytes".into());
    }
    Ok(())
}

#[derive(Default)]
struct Tally {
    reads: AtomicU64,
    writes: AtomicU64,
    transient: AtomicU64,
    bad: Mutex<Vec<String>>,
}

impl Tally {
    fn bad(&self, what: String) {
        let mut bad = self.bad.lock().unwrap();
        if bad.len() < 10 {
            bad.push(what);
        }
    }
}

fn noise(dir: &Path, stop: &Arc<AtomicBool>, threads: u64) -> Vec<std::thread::JoinHandle<()>> {
    (0..threads)
        .map(|index| {
            let (stop, path) = (stop.clone(), dir.join(format!("noise-{index}.bin")));
            std::thread::spawn(move || {
                let block = vec![0xA5u8; 4 * 1024 * 1024];
                while !stop.load(Ordering::Relaxed) {
                    if let Ok(mut file) = File::create(&path) {
                        let _ = file.write_all(&block);
                        let _ = file.sync_all();
                    }
                }
                let _ = fs::remove_file(&path);
            })
        })
        .collect()
}

/// Run `write`/`read` on writer and reader threads for the configured time and return the tally.
fn stress(
    case: &str,
    noisy: u64,
    seed: impl Fn(&Path),
    write: impl Fn(&Path, u64) + Send + Sync + 'static,
    read: impl Fn(&Path, &Tally) + Send + Sync + 'static,
) -> Arc<Tally> {
    let dir = folder(case);
    let target = dir.join("COMPLETE.json");
    seed(&target);
    let (stop, tally) = (Arc::new(AtomicBool::new(false)), Arc::new(Tally::default()));
    let (write, read) = (Arc::new(write), Arc::new(read));
    let mut handles = noise(&dir, &stop, noisy);
    for index in 0..number("HY_STRESS_WRITERS", 4) {
        let (stop, tally, write, target) = (stop.clone(), tally.clone(), write.clone(), target.clone());
        handles.push(std::thread::spawn(move || {
            let mut n = index * 1_000_000;
            while !stop.load(Ordering::Relaxed) {
                n += 1;
                write(&target, n);
                tally.writes.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    for _ in 0..number("HY_STRESS_READERS", 4) {
        let (stop, tally, read, target) = (stop.clone(), tally.clone(), read.clone(), target.clone());
        handles.push(std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                read(&target, &tally);
                tally.reads.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(number("HY_STRESS_SECS", 3)) {
        std::thread::sleep(Duration::from_millis(50));
    }
    stop.store(true, Ordering::Relaxed);
    for handle in handles {
        handle.join().unwrap();
    }
    println!(
        "{case}: {} writes, {} reads, {} transient read errors in {:?} on {}",
        tally.writes.load(Ordering::Relaxed),
        tally.reads.load(Ordering::Relaxed),
        tally.transient.load(Ordering::Relaxed),
        started.elapsed(),
        dir.display()
    );
    let _ = fs::remove_dir_all(&dir);
    tally
}

fn atomic_case(case: &str, noisy: u64) {
    let tally = stress(
        case,
        noisy,
        |path| atomic_write(path, &blob(0)).unwrap(),
        |path, n| atomic_write(path, &blob(n)).unwrap(),
        |path, tally| match read_bytes(path) {
            Ok(data) => {
                if let Err(why) = blob_ok(&data) {
                    tally.bad(format!("torn atomic_write blob: {why}"));
                }
            }
            Err(error) => {
                // A read racing the replace may be refused; that is not a torn file, but it is counted and reported.
                tally.transient.fetch_add(1, Ordering::Relaxed);
                if error.is_not_found() {
                    tally.bad(format!("the file vanished during a replace: {error}"));
                }
            }
        },
    );
    assert!(tally.bad.lock().unwrap().is_empty(), "{:?}", tally.bad.lock().unwrap());
    assert!(tally.writes.load(Ordering::Relaxed) > 0 && tally.reads.load(Ordering::Relaxed) > 0);
}

fn record(n: u64) -> serde_json::Value {
    json!({"gpr": format!("E:/work/base-{n}/x.gpr"), "key": "74fe83b1ebc73fc946a0", "generation": n, "built_at": 1.5,
           "pad": "p".repeat((n % 5000) as usize)})
}

fn sealed_case(case: &str, noisy: u64) {
    let tally = stress(
        case,
        noisy,
        |path| {
            write_sealed_default(path, &record(0)).unwrap();
        },
        |path, n| {
            write_sealed_default(path, &record(n)).unwrap();
        },
        |path, tally| match read_sealed_info(path, &ReadOptions::default(), None) {
            Ok((value, Source::File)) => {
                let n = value["generation"].as_u64().unwrap_or(u64::MAX);
                if value != record(n) {
                    tally.bad(format!("a record that is not any version written: generation {n}"));
                }
            }
            Ok((_, source)) => tally.bad(format!("the reader needed {source:?} (the file was not a valid version)")),
            Err(error) => {
                if error.to_string().contains("zero-length") || error.to_string().contains("store_corrupt") {
                    tally.bad(format!("StoreCorrupt for a reader: {error}"));
                } else {
                    tally.transient.fetch_add(1, Ordering::Relaxed);
                }
            }
        },
    );
    assert!(tally.bad.lock().unwrap().is_empty(), "{:?}", tally.bad.lock().unwrap());
    assert!(tally.writes.load(Ordering::Relaxed) > 0 && tally.reads.load(Ordering::Relaxed) > 0);
}

/// Readers that keep the file open for a while (a slow disk, a scanner): the replace must still go through.
#[test]
fn atomic_write_while_readers_hold_the_file_open() {
    let tally = stress(
        "atomic-hold",
        0,
        |path| atomic_write(path, &blob(0)).unwrap(),
        |path, n| atomic_write(path, &blob(n)).unwrap(),
        |path, tally| {
            use std::io::Read;
            let Ok(mut file) = File::open(path) else {
                tally.transient.fetch_add(1, Ordering::Relaxed);
                return;
            };
            std::thread::sleep(Duration::from_millis(20));
            let mut data = Vec::new();
            if file.read_to_end(&mut data).is_ok()
                && let Err(why) = blob_ok(&data)
            {
                tally.bad(format!("torn atomic_write blob: {why}"));
            }
        },
    );
    assert!(tally.bad.lock().unwrap().is_empty(), "{:?}", tally.bad.lock().unwrap());
    assert!(tally.writes.load(Ordering::Relaxed) > 0);
}

#[test]
fn atomic_write_is_never_seen_empty_or_torn() {
    atomic_case("atomic", number("HY_STRESS_NOISE", 0));
}

#[test]
fn write_sealed_is_never_seen_empty_or_torn() {
    sealed_case("sealed", number("HY_STRESS_NOISE", 0));
}

#[test]
fn atomic_write_on_a_slow_disk() {
    atomic_case("atomic-noisy", number("HY_STRESS_NOISE", 3));
}

#[test]
fn write_sealed_on_a_slow_disk() {
    sealed_case("sealed-noisy", number("HY_STRESS_NOISE", 3));
}
