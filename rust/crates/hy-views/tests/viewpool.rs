//! `hydralysis.viewpool` against the stub worker of `tests/test_viewpool.py`: one Rust test per original test of the
//! `Reuse`, `Failure` and `Idle` classes. (`StartJob`, `RunJobLifecycle` and `RealWorker` are about `views.start_job` and the
//! real Python worker; they stay black-box tests of the Python modules and run under `HYDRALYSIS_IMPL=rust` too.)
//! Skipped without Python.

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use hy_views::viewpool::{Config, Pool};

mod common;
use common::python;

const STUB: &str = r#"
import json, os, sys, time
from pathlib import Path
PREFIX = b"@hydralysis-viewpool "
def say(**message):
    sys.stdout.buffer.write(PREFIX + json.dumps(message).encode("ascii") + b"\n")
    sys.stdout.buffer.flush()
log = Path(sys.argv[1])
release = log.parent / "release"
mode = sys.argv[2] if len(sys.argv) > 2 else "normal"
if mode == "die-before-hello":
    sys.exit(9)
say(ready=True, pid=os.getpid())
for line in sys.stdin.buffer:
    message = json.loads(line)
    if message.get("stop"):
        break
    job = message.get("job")
    if not job:
        continue
    with log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps({"pid": os.getpid(), "job": job}) + "\n")
    if mode == "hold":
        while not release.exists():
            time.sleep(0.02)
    if mode == "die-mid-job":
        os._exit(7)
    say(done=True)
"#;

struct World {
    _dir: tempfile::TempDir,
    root: PathBuf,
    log: PathBuf,
    python: String,
    pools: Vec<Pool>,
}

impl World {
    fn new() -> Option<Self> {
        let python = python()?;
        let dir = tempfile::Builder::new().prefix("vp").tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
        let root = dir.path().to_path_buf();
        std::fs::write(root.join("stub.py"), STUB).unwrap();
        Some(Self { log: root.join("jobs.jsonl"), root, _dir: dir, python, pools: Vec::new() })
    }

    fn pool(&mut self, config: Config) -> Pool {
        let pool = Pool::new(config);
        self.pools.push(pool.clone());
        pool
    }

    fn command(&self, mode: &str) -> Vec<String> {
        vec![self.python.clone(), self.root.join("stub.py").display().to_string(), self.log.display().to_string(), mode.to_string()]
    }

    fn env() -> Vec<(String, String)> {
        std::env::vars().collect()
    }

    fn send(&self, pool: &Pool, name: &str, mode: &str, max_workers: usize) -> bool {
        let path = self.root.join(name);
        std::fs::write(&path, "{}").unwrap();
        pool.send(&path.display().to_string(), &self.command(mode), &Self::env(), max_workers)
    }

    fn jobs(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(&self.log)
            .map(|text| text.lines().filter(|l| !l.trim().is_empty()).map(|l| serde_json::from_str(l).unwrap()).collect())
            .unwrap_or_default()
    }

    fn release(&self) {
        std::fs::write(self.root.join("release"), "go").unwrap();
    }
}

impl Drop for World {
    fn drop(&mut self) {
        self.release();
        for pool in &self.pools {
            pool.close_all();
            wait_for(|| pool.workers().is_empty(), 5.0);
            pool.kill_all();
            pool.shutdown();
        }
    }
}

fn wait_for(mut predicate: impl FnMut() -> bool, seconds: f64) -> bool {
    let deadline = Instant::now() + Duration::from_secs_f64(seconds);
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    predicate()
}

fn pids(world: &World) -> std::collections::BTreeSet<u64> {
    world.jobs().iter().map(|row| row["pid"].as_u64().unwrap()).collect()
}

// Reuse.test_a_second_job_reuses_the_warm_worker
#[test]
fn a_second_job_reuses_the_warm_worker() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    assert!(world.send(&pool, "one.json", "normal", 8));
    assert!(wait_for(|| world.jobs().len() == 1, 15.0));
    assert!(wait_for(|| pool.workers().first().is_some_and(|w| !w.busy), 15.0));
    assert!(world.send(&pool, "two.json", "normal", 8));
    assert!(wait_for(|| world.jobs().len() == 2, 15.0));
    assert_eq!(pids(&world).len(), 1, "the second job needed a second process");
    assert_eq!(pool.workers().len(), 1);
}

// Reuse.test_two_jobs_at_once_use_two_workers_and_never_share_one
#[test]
fn two_jobs_at_once_use_two_workers_and_never_share_one() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    assert!(world.send(&pool, "one.json", "hold", 8));
    assert!(world.send(&pool, "two.json", "hold", 8));
    assert!(wait_for(|| world.jobs().len() == 2, 15.0));
    assert_eq!(pids(&world).len(), 2);
    let workers = pool.workers();
    assert_eq!((workers.len(), workers.iter().filter(|w| w.busy).count()), (2, 2));
    world.release();
    assert!(wait_for(|| pool.workers().iter().all(|w| !w.busy), 15.0));
}

// Reuse.test_the_cap_sends_the_overflow_to_the_one_shot_path
#[test]
fn the_cap_sends_the_overflow_to_the_one_shot_path() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    assert!(world.send(&pool, "one.json", "hold", 1));
    assert!(!world.send(&pool, "two.json", "hold", 1));
    assert!(wait_for(|| world.jobs().len() == 1, 15.0));
    world.release();
}

// Failure.test_a_worker_that_dies_before_its_hello_is_not_delivered_and_the_pool_is_disabled
#[test]
fn a_worker_that_dies_before_its_hello_is_not_delivered_and_the_pool_is_broken() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    assert!(!world.send(&pool, "one.json", "die-before-hello", 8));
    assert!(pool.broken());
    assert!(world.jobs().is_empty());
}

// Failure.test_a_worker_killed_mid_job_does_not_touch_the_caller_or_the_job_file_and_the_pool_drops_it
#[test]
fn a_worker_killed_mid_job_does_not_touch_the_job_file_and_the_pool_drops_it() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    assert!(world.send(&pool, "one.json", "hold", 8));
    assert!(wait_for(|| world.jobs().len() == 1, 15.0));
    let record = std::fs::read_to_string(world.root.join("one.json")).unwrap();
    pool.kill_all();
    assert!(wait_for(|| pool.workers().is_empty(), 15.0));
    assert_eq!(std::fs::read_to_string(world.root.join("one.json")).unwrap(), record);
    assert!(world.send(&pool, "two.json", "hold", 8), "the pool did not survive a killed worker");
    assert!(wait_for(|| world.jobs().len() == 2, 15.0));
    assert_eq!(pids(&world).len(), 2);
}

// Failure.test_a_failing_job_is_never_a_failing_publish (a spawn that fails)
#[test]
fn a_spawn_that_fails_is_a_fallback_not_a_failed_publish() {
    let Some(world) = World::new() else { return };
    let pool = Pool::new(Config::default());
    let path = world.root.join("job.json");
    std::fs::write(&path, "{}").unwrap();
    let missing = vec![world.root.join("no-such-program.exe").display().to_string()];
    assert!(!pool.send(&path.display().to_string(), &missing, &World::env(), 8));
    assert!(pool.broken());
    assert!(!pool.send(&path.display().to_string(), &world.command("normal"), &World::env(), 8), "a broken pool takes nothing");
}

// Idle.test_one_idle_worker_is_kept_and_an_idle_one_is_stopped_after_the_timeout
#[test]
fn one_idle_worker_is_kept_and_an_idle_one_is_stopped_after_the_timeout() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config { idle: Duration::from_millis(300), ..Config::default() });
    assert!(world.send(&pool, "one.json", "normal", 8));
    assert!(wait_for(|| world.jobs().len() == 1, 15.0));
    assert!(wait_for(|| pool.workers().first().is_some_and(|w| !w.busy), 15.0));
    assert!(world.send(&pool, "two.json", "normal", 8));
    assert!(wait_for(|| world.jobs().len() == 2, 15.0));
    assert!(wait_for(|| pool.workers().is_empty(), 5.0), "the idle worker was not stopped");
}

// (new) the pool keeps one idle worker when two jobs end, and stops the extra one at once
#[test]
fn a_second_idle_worker_is_stopped_as_soon_as_its_job_ends() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    assert!(world.send(&pool, "one.json", "hold", 8));
    assert!(world.send(&pool, "two.json", "hold", 8));
    assert!(wait_for(|| world.jobs().len() == 2, 15.0));
    world.release();
    assert!(wait_for(|| pool.workers().len() == 1, 15.0), "workers: {:?}", pool.workers());
    assert!(!pool.workers()[0].busy);
}

// (new) another environment's package is not this pool's
#[test]
fn a_send_from_another_package_is_refused() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    let mut env = World::env();
    env.retain(|(k, _)| k != "PYTHONPATH");
    env.push(("PYTHONPATH".into(), "A".into()));
    let path = world.root.join("job.json");
    std::fs::write(&path, "{}").unwrap();
    assert!(pool.send(&path.display().to_string(), &world.command("normal"), &env, 8));
    env.retain(|(k, _)| k != "PYTHONPATH");
    env.push(("PYTHONPATH".into(), "B".into()));
    assert!(!pool.send(&path.display().to_string(), &world.command("normal"), &env, 8));
    let _: &Path = &path;
}

// (new) close_all stops idle workers and refuses new jobs
#[test]
fn a_closed_pool_stops_its_idle_workers_and_takes_no_job() {
    let Some(mut world) = World::new() else { return };
    let pool = world.pool(Config::default());
    assert!(world.send(&pool, "one.json", "normal", 8));
    assert!(wait_for(|| world.jobs().len() == 1 && pool.workers().iter().all(|w| !w.busy), 15.0));
    pool.close_all();
    assert!(wait_for(|| pool.workers().is_empty(), 5.0));
    assert!(!world.send(&pool, "two.json", "normal", 8));
}
