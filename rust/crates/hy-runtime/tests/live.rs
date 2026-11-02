//! Live tests: real processes (the repo's frameloop fixture and the Rust `hy-fixture` target), the real agent DLL.
//! These are the Rust counterparts of the e2e cases in tests/test_trace_e2e.py, test_runtime*.py and test_watch*.py
//! (see TESTMAP.md). Fixtures come from HY_FIXTURES (default E:\Projects\Hydra\_logs\r\hy-runtime\fx).
#![cfg(windows)]

use hy_runtime::authorize::{Authorization, normalize};
use hy_runtime::identity::{IdentityError, ProcessIdentity};
use hy_runtime::memory::{Gate, MemError};
use hy_runtime::pe_exports;
use hy_runtime::proto::{self, Hit};
use hy_runtime::session::{Session, SiteSpec};
use hy_runtime::watch::{Kind, Phase};
use serde_json::json;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------- helpers

fn agent_dll() -> PathBuf {
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT
        .get_or_init(|| {
            let exe = std::env::current_exe().unwrap();
            let dir = exe.parent().unwrap().parent().unwrap().to_path_buf();
            let mut cmd = std::process::Command::new(
                std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()),
            );
            cmd.args(["build", "-p", "hy-agent-dll"])
                .current_dir(env!("CARGO_MANIFEST_DIR"));
            if !cfg!(debug_assertions) {
                cmd.arg("--release");
            }
            assert!(cmd.status().unwrap().success(), "building the agent failed");
            let dll = dir.join("hy_agent_dll.dll");
            assert!(dll.is_file(), "{} missing", dll.display());
            dll
        })
        .clone()
}

fn fixtures() -> PathBuf {
    std::env::var_os("HY_FIXTURES")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(r"E:\Projects\Hydra\_logs\r\hy-runtime\fx"))
}

fn work(name: &str) -> PathBuf {
    let d = std::env::temp_dir()
        .join("hy-runtime-tests")
        .join(format!("{name}-{}", std::process::id()));
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn map_rva(map: &str, name: &str) -> u64 {
    let base = map
        .lines()
        .find_map(|l| l.trim().strip_prefix("Preferred load address is "))
        .map(|h| u64::from_str_radix(h.trim(), 16).unwrap())
        .expect("preferred base in map");
    let line = map
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(name))
        .unwrap_or_else(|| panic!("{name} not in map"));
    u64::from_str_radix(line.split_whitespace().nth(2).unwrap(), 16).unwrap() - base
}

struct Frameloop {
    exe: PathBuf,
    image: Vec<u8>,
    map: String,
}

impl Frameloop {
    fn new() -> Frameloop {
        let dir = fixtures();
        let exe = dir.join("frameloop.exe");
        Frameloop {
            image: std::fs::read(&exe).expect("frameloop.exe fixture"),
            map: std::fs::read_to_string(dir.join("frameloop.map")).unwrap(),
            exe,
        }
    }
    fn site(&self, name: &str, flags: u32, nargs: u32) -> SiteSpec {
        let rva = map_rva(&self.map, name);
        let mut s = SiteSpec::new(
            rva,
            pe_exports::bytes_at_rva(&self.image, rva as u32, 16)
                .unwrap()
                .to_vec(),
        );
        s.flags = flags;
        s.nargs = nargs;
        s
    }
}

fn wait_exit(s: &mut Session, timeout: Duration, mut tick: impl FnMut(&mut Session)) {
    let end = Instant::now() + timeout;
    while s.running() {
        assert!(Instant::now() < end, "target did not exit in {timeout:?}");
        tick(s);
        std::thread::sleep(Duration::from_millis(2));
    }
    tick(s);
}

fn run_collect(s: &mut Session, timeout: Duration) -> Vec<Hit> {
    let mut hits = Vec::new();
    wait_exit(s, timeout, |s| hits.extend(s.drain()));
    hits
}

fn spawn_armed(exe: &Path, args: &[&str], sites: &[SiteSpec], out: &Path) -> Session {
    let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
    let mut s = Session::spawn_with(exe, &args, sites, Some(out)).expect("spawn");
    s.inject(&agent_dll()).expect("inject");
    s
}

fn text(p: &Path) -> String {
    std::fs::read_to_string(p).unwrap_or_default()
}

fn kv(out: &str, key: &str) -> String {
    out.split_whitespace()
        .find_map(|w| w.strip_prefix(key))
        .map(str::to_string)
        .unwrap_or_else(|| panic!("{key} not in {out:?}"))
}

fn hy_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_hy-fixture"))
}

fn fixture_info() -> (u64, Vec<u8>, u64) {
    let out = work("info").join("out.txt");
    let mut s = Session::spawn_with(&hy_fixture(), &["info".into()], &[], Some(&out)).unwrap();
    s.resume();
    wait_exit(&mut s, Duration::from_secs(20), |_| {});
    let t = text(&out);
    let bytes = (0..16)
        .map(|i| u8::from_str_radix(&kv(&t, "BYTES=")[2 * i..2 * i + 2], 16).unwrap())
        .collect();
    (
        u64::from_str_radix(&kv(&t, "RVA="), 16).unwrap(),
        bytes,
        u64::from_str_radix(&kv(&t, "CELL="), 16).unwrap(),
    )
}

fn wait_for(path: &Path, needle: &str, timeout: Duration) -> String {
    let end = Instant::now() + timeout;
    loop {
        let t = text(path);
        if t.contains(needle) {
            return t;
        }
        assert!(Instant::now() < end, "{needle} never appeared in {t:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

// ---------------------------------------------------------------- capture / probe parity (frameloop)

#[test]
fn args_and_return_capture() {
    let fl = Frameloop::new();
    let out = work("args").join("out.txt");
    let mut s = spawn_armed(
        &fl.exe,
        &["--frames=300"],
        &[fl.site("fx_job_callback", proto::F_RETURN, 1)],
        &out,
    );
    assert_eq!(s.site_status(0), (proto::SITE_ARMED, 0));
    s.resume();
    let hits = run_collect(&mut s, Duration::from_secs(30));
    assert_eq!(hits.len(), 300);
    assert_eq!(s.exit_code(), Some(0));
    for (i, h) in hits.iter().enumerate() {
        assert_eq!(h.args, vec![i as u64], "hit {i}");
        assert_eq!(h.retval, i as u64);
        assert_ne!(h.flags & proto::RF_RETURNED, 0);
        assert!(h.tsc_end >= h.tsc && h.tsc > 0);
        assert_ne!(h.ret_addr, 0);
    }
    assert!(
        hits.windows(2).all(|w| w[1].ring_seq == w[0].ring_seq + 1),
        "ring_seq is contiguous"
    );
    let c = s.counters();
    assert_eq!(
        (c.sites[0].hits, c.sites[0].kept, c.dropped, c.unreturned),
        (300, 300, 0, 0)
    );
    assert!(text(&out).contains("callback_sum=44850"), "{}", text(&out));
}

#[test]
fn sampling_counts_every_skip_exactly() {
    let fl = Frameloop::new();
    let mut site = fl.site("fx_frame_begin", 0, 1);
    site.stride = 4;
    let out = work("sample").join("out.txt");
    let mut s = spawn_armed(&fl.exe, &["--frames=200"], &[site], &out);
    s.resume();
    let hits = run_collect(&mut s, Duration::from_secs(30));
    let c = s.counters();
    assert_eq!(
        (c.sites[0].hits, c.sites[0].kept, c.sites[0].skipped()),
        (200, 50, 150)
    );
    assert_eq!(hits.len(), 50);
    assert_eq!(
        hits.iter().map(|h| h.args[0]).collect::<Vec<_>>(),
        (0..200).step_by(4).collect::<Vec<u64>>()
    );
}

#[test]
fn stack_walk_reports_the_caller() {
    let fl = Frameloop::new();
    let out = work("stack").join("out.txt");
    let mut site = fl.site("fx_job_callback", proto::F_STACK, 1);
    site.stack_depth = 4;
    let mut s = spawn_armed(&fl.exe, &["--frames=20"], &[site], &out);
    let main = s
        .modules()
        .unwrap()
        .into_iter()
        .find(|m| m.name.eq_ignore_ascii_case("frameloop.exe"))
        .unwrap();
    s.resume();
    let hits = run_collect(&mut s, Duration::from_secs(30));
    assert_eq!(hits.len(), 20);
    for h in &hits {
        assert!(h.stack.len() >= 2, "{:x?}", h.stack);
        assert_eq!(h.stack[0], h.ret_addr);
        assert!(h.stack[0] >= main.base && h.stack[0] < main.base + main.size as u64);
    }
    assert_eq!(s.exit_code(), Some(0));
}

#[test]
fn export_hook_with_buffer_capture() {
    let dll = PathBuf::from(r"C:\Windows\System32\KernelBase.dll");
    let image = std::fs::read(&dll).unwrap();
    let (rva, _) = pe_exports::find_export(&image, "WriteFile").expect("WriteFile export");
    let expect = pe_exports::bytes_at_rva(&image, rva, 16).unwrap().to_vec();
    let fl = Frameloop::new();
    let dir = work("export");
    let times = dir.join("times.bin");
    let mut site = SiteSpec::new(rva as u64, expect);
    site.module = "kernelbase.dll".into();
    site.export = Some("WriteFile".into());
    site.nargs = 3;
    site.flags = proto::F_RETURN;
    site.buf_ptr_arg = 1;
    site.buf_len_arg = 2;
    site.buf_max = 256;
    let times_arg = format!("--times={}", times.display());
    let mut s = spawn_armed(
        &fl.exe,
        &["--frames=40", &times_arg],
        &[site],
        &dir.join("out.txt"),
    );
    assert_eq!(
        s.site_status(0),
        (proto::SITE_ARMED, 0),
        "export hook must arm"
    );
    s.resume();
    let hits = run_collect(&mut s, Duration::from_secs(30));
    assert_eq!(s.exit_code(), Some(0));
    let file = std::fs::read(&times).unwrap();
    assert_eq!(file.len(), 320);
    let h = hits
        .iter()
        .find(|h| h.args.get(2) == Some(&320))
        .unwrap_or_else(|| panic!("no 320-byte WriteFile in {} hits", hits.len()));
    assert_eq!(h.buf, file[..256], "buffer captured at the call");
    assert_eq!(h.retval & 0xFFFF_FFFF, 1, "WriteFile returned TRUE");
}

#[test]
fn guards_refuse_before_any_byte_is_written() {
    let image = std::fs::read(r"C:\Windows\System32\KernelBase.dll").unwrap();
    let (rva, _) = pe_exports::find_export(&image, "WriteFile").unwrap();
    let good = pe_exports::bytes_at_rva(&image, rva, 16).unwrap().to_vec();
    let mk = |f: &dyn Fn(&mut SiteSpec)| {
        let mut s = SiteSpec::new(rva as u64, good.clone());
        s.module = "kernelbase.dll".into();
        s.export = Some("WriteFile".into());
        s.nargs = 1;
        f(&mut s);
        s
    };
    let sites = [
        mk(&|s| s.expect[3] ^= 0xFF),                  // 0: prologue differs
        mk(&|s| s.export = Some("ReadFile".into())),   // 1: export names another address
        mk(&|s| s.module_base = 0x1234_0000),          // 2: module mapped elsewhere
        mk(&|s| s.module = "nosuchmodule.dll".into()), // 3: module not loaded
        mk(&|s| s.expect.truncate(4)),                 // 4: too few bytes to prove the site
        mk(&|_| ()),                                   // 5: the good one
    ];
    let fl = Frameloop::new();
    let out = work("guards").join("out.txt");
    let mut s = spawn_armed(&fl.exe, &["--frames=30"], &sites, &out);
    let want = [
        proto::ERR_BYTES_MISMATCH,
        proto::ERR_EXPORT_MISMATCH,
        proto::ERR_MODULE_BASE,
        proto::ERR_NO_MODULE,
        proto::ERR_BAD_SITE,
    ];
    for (i, code) in want.iter().enumerate() {
        assert_eq!(s.site_status(i), (proto::SITE_FAILED, *code), "site {i}");
    }
    assert_eq!(s.site_status(5), (proto::SITE_ARMED, 0));
    s.resume();
    let hits = run_collect(&mut s, Duration::from_secs(30));
    assert!(
        hits.iter().all(|h| h.site == 5),
        "only the proven site records"
    );
    assert_eq!(s.exit_code(), Some(0));
}

#[test]
fn arm_and_retire_while_threads_run() {
    let fl = Frameloop::new();
    let dir = work("live-arm");
    let out = dir.join("out.txt");
    let mut s = Session::spawn_with(
        &fl.exe,
        &["--frames=3000".into(), "--sleep-ms=1".into()],
        &[],
        Some(&out),
    )
    .unwrap();
    s.resume();
    std::thread::sleep(Duration::from_millis(150));
    s.inject(&agent_dll()).unwrap();
    s.ping().unwrap();
    let mut hits = s.drain();
    assert!(hits.is_empty());
    assert_eq!(
        s.arm_site(0, &fl.site("fx_job_callback", proto::F_RETURN, 1))
            .unwrap(),
        Ok(())
    );
    let t0 = Instant::now();
    while hits.len() < 100 {
        hits.extend(s.drain());
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "no hits after a live arm"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(s.retire_site(0).unwrap(), Ok(()));
    hits.extend(s.drain());
    let after_retire = hits.len();
    std::thread::sleep(Duration::from_millis(150));
    hits.extend(s.drain());
    assert!(
        hits.len() <= after_retire + 1,
        "a retired site stops recording ({} -> {})",
        after_retire,
        hits.len()
    );
    wait_exit(&mut s, Duration::from_secs(60), |s| hits.extend(s.drain()));
    assert_eq!(s.exit_code(), Some(0));
    assert!(hits.len() < 3000 && hits.len() >= 100);
    assert!(
        hits.windows(2).all(|w| w[1].args[0] == w[0].args[0] + 1),
        "no hit lost or duplicated between arm and retire"
    );
    assert!(
        text(&out).contains("callback_sum=4498500"),
        "{}",
        text(&out)
    ); // 3000*2999/2: the hooked code computed correctly
}

// ---------------------------------------------------------------- rings, breakpoints

#[test]
fn thread_exit_frees_the_ring_for_reuse() {
    let (rva, bytes, _) = fixture_info();
    let out = work("churn").join("out.txt");
    let mut site = SiteSpec::new(rva, bytes);
    site.nargs = 1;
    let mut s = spawn_armed(&hy_fixture(), &["churn", "300"], &[site], &out);
    assert_eq!(s.site_status(0), (proto::SITE_ARMED, 0));
    s.resume();
    let hits = run_collect(&mut s, Duration::from_secs(60));
    assert_eq!(s.exit_code(), Some(0));
    let c = s.counters();
    assert_eq!(hits.len(), 900);
    assert_eq!((c.dropped, c.no_ring), (0, 0));
    assert!(
        s.ring_count() < 64,
        "300 threads shared {} rings",
        s.ring_count()
    );
    assert!(text(&out).contains("DONE"));
}

#[test]
fn breakpoint_parks_until_continued() {
    let (rva, bytes, _) = fixture_info();
    let out = work("bp").join("out.txt");
    let mut site = SiteSpec::new(rva, bytes);
    site.nargs = 1;
    site.flags = proto::F_PAUSE;
    let mut s = spawn_armed(&hy_fixture(), &["pause"], &[site], &out);
    s.resume();
    let t0 = Instant::now();
    let p = loop {
        if let Some(p) = s.paused().into_iter().next() {
            break p;
        }
        assert!(t0.elapsed() < Duration::from_secs(20), "never parked");
        std::thread::sleep(Duration::from_millis(5));
    };
    assert_eq!(p.frame[5], 7, "rcx of the hit is in the parked frame");
    assert_ne!(p.tid, 0);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        s.running() && !text(&out).contains("AFTER"),
        "the thread is held"
    );
    assert!(
        s.events()
            .iter()
            .any(|e| e.kind == proto::EV_BREAKPOINT && e.slot as usize == p.slot)
    );
    assert!(s.continue_breakpoint(p.slot, false));
    wait_exit(&mut s, Duration::from_secs(20), |_| {});
    assert!(text(&out).contains("AFTER"));
    assert_eq!(s.exit_code(), Some(0));
}

#[test]
fn watchdog_releases_a_parked_thread() {
    let (rva, bytes, _) = fixture_info();
    let out = work("wd").join("out.txt");
    let mut site = SiteSpec::new(rva, bytes);
    site.flags = proto::F_PAUSE;
    let mut s = spawn_armed(&hy_fixture(), &["pause"], &[site], &out);
    s.resume();
    let mut released = Vec::new();
    let t0 = Instant::now();
    while s.running() {
        assert!(t0.elapsed() < Duration::from_secs(20));
        released.extend(s.watchdog(Duration::from_millis(250)));
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(released.len(), 1, "exactly one auto-continue");
    assert!(t0.elapsed() >= Duration::from_millis(250));
    assert!(text(&out).contains("AFTER"));
    assert_eq!(s.exit_code(), Some(0));
}

// ---------------------------------------------------------------- memory write and watch

fn auth_for(module: &str, rva_start: u64, rva_end: u64, actions: &[&str]) -> Authorization {
    normalize(
        &json!({"sha256": "0".repeat(64), "actions": actions, "max_size": 8,
        "ranges": [{"module": module, "rva_start": rva_start, "rva_end": rva_end}]}),
    )
    .unwrap()
}

#[test]
fn cas_write_undo_and_refusals() {
    let (rva, _bytes, cell_rva) = fixture_info();
    let out = work("write").join("out.txt");
    let mut s = Session::spawn_with(&hy_fixture(), &["write".into()], &[], Some(&out)).unwrap();
    s.resume();
    let t = wait_for(&out, "BASE=", Duration::from_secs(20));
    let addr = u64::from_str_radix(&kv(&t, "ADDR="), 16).unwrap();
    let base = u64::from_str_radix(&kv(&t, "BASE="), 16).unwrap();
    let v = |x: u64| x.to_le_bytes().to_vec();
    let gate = Gate::Fixture;

    // refusals leave memory alone
    assert!(matches!(
        s.write_cas(&gate, addr, &v(0x9999), &v(1), "a good enough reason"),
        Err(MemError::CasMismatch { .. })
    ));
    assert!(matches!(
        s.write_cas(&gate, addr, &v(0x1111), &v(1), "short"),
        Err(MemError::BadRequest(_))
    ));
    assert!(matches!(
        s.write_cas(
            &gate,
            base + rva,
            &[0u8; 8],
            &v(1),
            "patching code is refused"
        ),
        Err(MemError::ExecutableRange(_))
    ));
    assert_eq!(s.read_memory(addr, 8).unwrap(), v(0x1111));

    // owner authorization: the module+rva range of the cell, then a range that misses it
    let exe_name = hy_fixture()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    let outside = Gate::Authorized(auth_for(
        &exe_name,
        cell_rva + 0x100,
        cell_rva + 0x200,
        &["write"],
    ));
    match s.write_cas(
        &outside,
        addr,
        &v(0x1111),
        &v(0x2222),
        "outside the declared range",
    ) {
        Err(MemError::Refused(r)) => assert_eq!(r.code, "outside_authorized_range"),
        other => panic!("{other:?}"),
    }
    let watch_only = Gate::Authorized(auth_for(&exe_name, cell_rva, cell_rva + 8, &["watch"]));
    assert!(
        matches!(s.write_cas(&watch_only, addr, &v(0x1111), &v(0x2222), "watch only build"), Err(MemError::Refused(r)) if r.code == "action_not_authorized")
    );
    let inside = Gate::Authorized(auth_for(&exe_name, cell_rva, cell_rva + 8, &["write"]));
    let id = s
        .write_cas(
            &inside,
            addr,
            &v(0x1111),
            &v(0x2222),
            "authorized write inside range",
        )
        .unwrap();
    assert_eq!(s.read_memory(addr, 8).unwrap(), v(0x2222));
    assert_eq!(s.undo_log()[0].mode, "authorized");
    s.undo_write(&inside, id).unwrap();
    assert_eq!(s.read_memory(addr, 8).unwrap(), v(0x1111));

    // DIVERGED: something else changed the cell after our write
    let id2 = s
        .write_cas(
            &gate,
            addr,
            &v(0x1111),
            &v(0x2222),
            "first write of the pair",
        )
        .unwrap();
    s.write_cas(&gate, addr, &v(0x2222), &v(0x4444), "someone else's write")
        .unwrap();
    match s.undo_write(&gate, id2) {
        Err(MemError::Diverged { found }) => assert_eq!(found, v(0x4444)),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        s.read_memory(addr, 8).unwrap(),
        v(0x4444),
        "diverged undo writes nothing"
    );

    s.write_cas(&gate, addr, &v(0x4444), &v(0x3333), "let the target finish")
        .unwrap();
    wait_exit(&mut s, Duration::from_secs(20), |_| {});
    assert!(text(&out).contains("SAW"));
    assert_eq!(s.exit_code(), Some(0));
}

#[test]
fn watch_records_writes_from_old_and_new_threads_and_disarms_clean() {
    let (_, _, _) = fixture_info();
    let out = work("watch").join("out.txt");
    let mut s = Session::spawn_with(&hy_fixture(), &["watch".into()], &[], Some(&out)).unwrap();
    s.resume();
    s.inject(&agent_dll()).unwrap();
    let t = wait_for(&out, "ADDR=", Duration::from_secs(20));
    let addr = u64::from_str_radix(&kv(&t, "ADDR="), 16).unwrap();
    // misuse is refused before anything is armed
    assert!(matches!(
        s.arm_watch(&Gate::Fixture, addr + 1, 8, Kind::Write, 100),
        Err(MemError::BadRequest(_))
    ));
    let slot = s
        .arm_watch(&Gate::Fixture, addr, 8, Kind::Write, 100)
        .unwrap();
    let mut events = Vec::new();
    let mut hits_seen = 0;
    wait_exit(&mut s, Duration::from_secs(60), |s| {
        s.sync_watch_threads();
        events.extend(s.events());
        hits_seen = s.watch_hits(slot);
    });
    events.extend(s.events());
    let watch_events: Vec<_> = events
        .iter()
        .filter(|e| e.kind == proto::EV_WATCH_HIT)
        .collect();
    assert_eq!(
        s.exit_code(),
        Some(0),
        "no 0x80000004: the handler absorbed every trap"
    );
    assert_eq!(
        hits_seen.max(s.watch_hits(slot)),
        6,
        "five writes from the main thread, one from the late thread"
    );
    assert_eq!(watch_events.len(), 6);
    assert!(
        watch_events
            .iter()
            .all(|e| e.data[2] == addr && e.data[3] & 1 != 0)
    );
    let tids: std::collections::HashSet<u32> = watch_events.iter().map(|e| e.tid).collect();
    assert_eq!(
        tids.len(),
        2,
        "the late thread was covered by sync_watch_threads"
    );
}

#[test]
fn disarm_reads_back_every_thread_and_clears() {
    let out = work("disarm").join("out.txt");
    let mut s = Session::spawn_with(&hy_fixture(), &["write".into()], &[], Some(&out)).unwrap();
    s.resume();
    s.inject(&agent_dll()).unwrap();
    let t = wait_for(&out, "ADDR=", Duration::from_secs(20));
    let addr = u64::from_str_radix(&kv(&t, "ADDR="), 16).unwrap();
    let slot = s
        .arm_watch(&Gate::Fixture, addr, 8, Kind::ReadWrite, 10)
        .unwrap();
    assert!(!s.watch_tainted());
    assert_eq!(s.disarm_watch(slot).unwrap(), Phase::Clear);
    assert!(
        matches!(s.disarm_watch(slot), Err(MemError::BadRequest(_))),
        "clear is final"
    );
    // the slot is reusable after a clear
    let again = s
        .arm_watch(&Gate::Fixture, addr, 4, Kind::Write, 10)
        .unwrap();
    assert_eq!(s.disarm_watch(again).unwrap(), Phase::Clear);
    s.write_cas(
        &Gate::Fixture,
        addr,
        &0x1111u64.to_le_bytes(),
        &0x3333u64.to_le_bytes(),
        "let the target finish",
    )
    .unwrap();
    wait_exit(&mut s, Duration::from_secs(20), |_| {});
    assert_eq!(s.exit_code(), Some(0));
}

// ---------------------------------------------------------------- identity

#[test]
fn identity_follows_the_process() {
    let out = work("ident").join("out.txt");
    let mut s = Session::spawn_with(&hy_fixture(), &["write".into()], &[], Some(&out)).unwrap();
    s.resume();
    s.verify_identity().unwrap();
    let id = ProcessIdentity::capture(s.pid).unwrap();
    assert!(id.image.to_lowercase().ends_with("hy-fixture.exe"));
    s.terminate();
    wait_exit(&mut s, Duration::from_secs(10), |_| {});
    assert!(matches!(
        s.verify_identity(),
        Err(IdentityError::Gone) | Err(IdentityError::Reused { .. })
    ));
    assert!(id.is_gone());
}
