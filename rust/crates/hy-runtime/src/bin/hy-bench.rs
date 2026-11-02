//! Rust counterpart of benchmarks/trace_overhead.py for the recorder alone (no TRACE-1 encoder, no Python worker):
//! frameloop with capture off versus capture on, interleaved rounds, the fixture timing its own frames.
//!
//!   hy-bench <agent.dll> <fixtures-dir> [--rounds N] [--workloads tight,paced] [--hooks N]
//!
//! The "on" run spawns the fixture suspended, injects the agent, arms the nine baseline-style hooks (one argument
//! captured each, exact counting, no sampling) and drains the rings every 2 ms while it runs.
use hy_runtime::pe_exports;
use hy_runtime::sampling::{Mode, Policy, Sampler};
use hy_runtime::session::{Session, SiteSpec};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const HOOKS: [&str; 11] = [
    "fx_frame_begin",
    "fx_frame_end",
    "fx_phase_begin",
    "fx_stage_input",
    "fx_job_callback",
    "fx_job_physics",
    "fx_consume",
    "fx_ours_write",
    "fx_host_overwrite",
    "fx_stage_update",
    "fx_stage_render",
];
const FREQ: f64 = 10_000_000.0;

fn map_rva(map: &str, name: &str) -> u64 {
    let base = map
        .lines()
        .find_map(|l| l.trim().strip_prefix("Preferred load address is "))
        .map(|h| u64::from_str_radix(h.trim(), 16).unwrap())
        .unwrap();
    let line = map
        .lines()
        .find(|l| l.split_whitespace().nth(1) == Some(name))
        .unwrap();
    u64::from_str_radix(line.split_whitespace().nth(2).unwrap(), 16).unwrap() - base
}

fn pct(v: &[f64], p: f64) -> f64 {
    v[((v.len() as f64 - 1.0) * p) as usize]
}

struct Run {
    p50: f64,
    mean: f64,
    p99: f64,
    wall: f64,
    hits: u64,
    dropped: u64,
    frames: usize,
    offered: u64,
}

fn read_times(path: &Path, wall: f64, hits: u64, dropped: u64) -> Run {
    let d = std::fs::read(path).expect("times file");
    let mut us: Vec<f64> = d
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c) as f64 / FREQ * 1e6)
        .collect();
    us.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Run {
        p50: pct(&us, 0.5),
        mean: us.iter().sum::<f64>() / us.len() as f64,
        p99: pct(&us, 0.99),
        wall,
        hits,
        dropped,
        frames: us.len(),
        offered: 0,
    }
}

fn run(exe: &Path, args: &[String], sites: &[SiteSpec], dll: Option<&Path>, times: &Path) -> Run {
    let _ = std::fs::remove_file(times);
    let mut a = args.to_vec();
    a.push(format!("--times={}", times.display()));
    let mut s =
        Session::spawn_with(exe, &a, sites, Some(&times.with_extension("txt"))).expect("spawn");
    if let Some(dll) = dll {
        s.inject(dll).expect("inject");
        for i in 0..sites.len() {
            assert_eq!(
                s.site_status(i).0,
                hy_runtime::proto::SITE_ARMED,
                "site {i} refused: {:?}",
                s.site_status(i)
            );
        }
    }
    let mut sampler = Sampler::new(
        Policy {
            mode: if std::env::var("HY_SAMPLING").is_ok_and(|v| v == "exact") {
                Mode::Exact
            } else {
                Mode::Adaptive
            },
            ..Policy::default()
        },
        sites.len(),
    );
    let t0 = Instant::now();
    s.resume();
    let mut hits = 0u64;
    let every: u64 = std::env::var("HY_DRAIN_MS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1);
    while s.running() {
        if dll.is_some() && every > 0 {
            hits += s.drain_with(|_| {});
            s.sampling_tick(&mut sampler);
        }
        std::thread::sleep(Duration::from_millis(every.max(1)));
    }
    let wall = t0.elapsed().as_secs_f64();
    let (mut dropped, mut offered) = (0, 0u64);
    if dll.is_some() {
        hits += s.drain_with(|_| {});
        let c = s.counters();
        dropped = c.dropped;
        offered = c.sites.iter().map(|x| x.hits).sum();
    }
    assert_eq!(s.exit_code(), Some(0));
    let mut r = read_times(times, wall, hits, dropped);
    r.offered = offered;
    r
}

fn median(mut v: Vec<f64>) -> f64 {
    v.sort_by(|a, b| a.partial_cmp(b).unwrap());
    v[v.len() / 2]
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let dll = PathBuf::from(&a[1]);
    let fx = PathBuf::from(&a[2]);
    let mut rounds = 5;
    let mut workloads = "tight,paced".to_string();
    let mut nhooks = HOOKS.len();
    let mut i = 3;
    while i < a.len() {
        match a[i].as_str() {
            "--rounds" => rounds = a[i + 1].parse().unwrap(),
            "--workloads" => workloads = a[i + 1].clone(),
            "--hooks" => nhooks = a[i + 1].parse().unwrap(),
            _ => panic!("unknown option {}", a[i]),
        }
        i += 2;
    }
    let exe = fx.join("frameloop.exe");
    let image = std::fs::read(&exe).unwrap();
    let map = std::fs::read_to_string(fx.join("frameloop.map")).unwrap();
    let sites: Vec<SiteSpec> = HOOKS[..nhooks]
        .iter()
        .map(|n| {
            let rva = map_rva(&map, n);
            let mut s = SiteSpec::new(
                rva,
                pe_exports::bytes_at_rva(&image, rva as u32, 16)
                    .unwrap()
                    .to_vec(),
            );
            s.nargs = 1;
            s
        })
        .collect();
    let work = std::env::temp_dir().join("hy-bench");
    std::fs::create_dir_all(&work).unwrap();
    let times = work.join("times.bin");
    println!("hooks={} rounds={rounds}", sites.len());
    for w in workloads.split(',') {
        let args: Vec<String> = match w {
            "tight" => vec!["--frames=20000".into()],
            "paced" => vec!["--frames=20000".into(), "--spin-us=200".into()],
            "frame16" => vec!["--frames=600".into(), "--spin-us=16000".into()],
            other => panic!("unknown workload {other}"),
        };
        let (mut off, mut on) = (Vec::new(), Vec::new());
        for r in 0..rounds {
            off.push(run(&exe, &args, &[], None, &times));
            on.push(run(&exe, &args, &sites, Some(&dll), &times));
            println!(
                "{w} round {r}: off p50 {:.2} us  on p50 {:.2} us  hits {} dropped {}",
                off[r].p50, on[r].p50, on[r].hits, on[r].dropped
            );
        }
        let ov = |f: &dyn Fn(&Run) -> f64| {
            median(
                (0..rounds)
                    .map(|i| (f(&on[i]) - f(&off[i])) / f(&off[i]))
                    .collect(),
            )
        };
        println!("== {w} ({rounds} rounds) ==");
        println!(
            "frame p50 {:.2} -> {:.2} us  mean {:.2} -> {:.2} us  p99 {:.2} -> {:.2} us",
            median(off.iter().map(|r| r.p50).collect()),
            median(on.iter().map(|r| r.p50).collect()),
            median(off.iter().map(|r| r.mean).collect()),
            median(on.iter().map(|r| r.mean).collect()),
            median(off.iter().map(|r| r.p99).collect()),
            median(on.iter().map(|r| r.p99).collect())
        );
        println!(
            "overhead (median of rounds): p50 {:.1}%  mean {:.1}%  p99 {:.1}%  wall {:.1}%",
            100.0 * ov(&|r| r.p50),
            100.0 * ov(&|r| r.mean),
            100.0 * ov(&|r| r.p99),
            100.0 * ov(&|r| r.wall)
        );
        println!(
            "offered/frame {:.1}  kept/frame {:.1}  dropped {}",
            on[0].offered as f64 / on[0].frames as f64,
            on[0].hits as f64 / on[0].frames as f64,
            on.iter().map(|r| r.dropped).sum::<u64>()
        );
    }
}
