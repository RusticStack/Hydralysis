//! Warm workers for publish jobs (`hydralysis.viewpool`): a publish hands its job file to an already imported process
//! instead of spawning one.
//!
//! A worker is a child process that speaks two control lines on its stdout, each prefixed [`PREFIX`]: `{"ready":true,"pid":n}`
//! once it is ready to read a job, and `{"done":true}` after each job. A job is handed over as `{"job": "<path>"}` on its
//! stdin; closing the stdin tells it to exit. Anything else it writes is drained and dropped.
//!
//! What the pool guarantees, as in Python: one job per worker at a time; never more than `max_workers` workers; at most
//! [`Config::keep_idle`] idle workers kept (a second one is stopped as soon as its job ends); an idle worker is stopped after
//! [`Config::idle`]; a job line is handed only to a live worker, and it is reported "not delivered" (so the caller runs the
//! one-shot path) only when the write failed or the worker died before its hello. A spawn failure, or a worker this pool
//! spawned that died before its hello, marks the pool broken: it takes no more jobs.
//!
//! The command, the environment and `max_workers` come with each call (Python decides them: `viewpool.command()` is a seam).

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use serde_json::Value;

/// The prefix of a control line on the worker's stdout.
pub const PREFIX: &[u8] = b"@hydralysis-viewpool ";

/// The pool's limits (the constants of `viewpool.py`).
#[derive(Clone)]
pub struct Config {
    /// The first hello of a worker; a worker that is alive but slower still runs its job.
    pub ready_timeout: Duration,
    /// An idle worker is stopped after this long.
    pub idle: Duration,
    /// Idle workers kept; a worker whose job ends while another is idle is stopped at once.
    pub keep_idle: usize,
    /// An idle worker that does not exit when its stdin closes is killed after this long.
    pub stop_grace: Duration,
    /// How a worker that must be killed is ended (its whole process tree, in the host). The default only kills the child.
    pub terminate: Arc<dyn Fn(u32) + Send + Sync>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ready_timeout: Duration::from_secs(10),
            idle: Duration::from_secs(2),
            keep_idle: 1,
            stop_grace: Duration::from_secs(5),
            terminate: Arc::new(|_| {}),
        }
    }
}

/// What a caller can see of a worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerInfo {
    pub pid: u32,
    pub busy: bool,
    pub alive: bool,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

#[derive(Default)]
struct Hello {
    ready: bool,
    gone: bool,
}

struct Worker {
    pid: AtomicU32,
    child: Mutex<Child>,
    stdin: Mutex<Option<ChildStdin>>,
    hello: Mutex<Hello>,
    hello_changed: Condvar,
    busy: AtomicBool,
    dead: AtomicBool,
    last_used: Mutex<Instant>,
}

impl Worker {
    /// `_Worker.alive`: not retired and the process has not exited.
    fn alive(&self) -> bool {
        !self.dead.load(Ordering::SeqCst) && matches!(lock(&self.child).try_wait(), Ok(None))
    }

    fn busy(&self) -> bool {
        self.busy.load(Ordering::SeqCst)
    }

    fn close_stdin(&self) {
        lock(&self.stdin).take();
    }

    fn kill(&self) {
        let _ = lock(&self.child).kill();
    }
}

#[derive(Default)]
struct State {
    workers: Vec<Arc<Worker>>,
    stopping: Vec<(Arc<Worker>, Instant)>,
    sweeper: bool,
    closed: bool,
    broken: bool,
    /// The environment of the first send: every worker is spawned with it; a send with another package or harness is refused.
    env: Option<Vec<(String, String)>>,
}

struct Shared {
    state: Mutex<State>,
    wake: Condvar,
    config: Config,
}

/// The warm workers of one process.
#[derive(Clone)]
pub struct Pool {
    shared: Arc<Shared>,
}

fn env_key(env: &[(String, String)]) -> (Option<&str>, Option<&str>) {
    let get = |name: &str| env.iter().find(|(k, _)| k == name).map(|(_, v)| v.as_str());
    (get("PYTHONPATH"), get("HYDRALYSIS_HARNESS"))
}

fn control(line: &[u8]) -> Option<Value> {
    let body = line.strip_prefix(PREFIX)?;
    serde_json::from_slice::<Value>(body).ok().filter(Value::is_object)
}

impl Pool {
    pub fn new(config: Config) -> Self {
        Self { shared: Arc::new(Shared { state: Mutex::new(State::default()), wake: Condvar::new(), config }) }
    }

    /// True once the pool has refused to work in this environment (a spawn failed, or a fresh worker died before its hello).
    pub fn broken(&self) -> bool {
        lock(&self.shared.state).broken
    }

    pub fn workers(&self) -> Vec<WorkerInfo> {
        lock(&self.shared.state)
            .workers
            .iter()
            .map(|w| WorkerInfo { pid: w.pid.load(Ordering::SeqCst), busy: w.busy(), alive: w.alive() })
            .collect()
    }

    /// Hand the job at `path` to a warm worker. `false`: the caller spawns the one-shot worker (the pool is closed, broken,
    /// another environment's, full, or the job was not delivered).
    pub fn send(&self, path: &str, command: &[String], env: &[(String, String)], max_workers: usize) -> bool {
        let (worker, fresh) = {
            let mut state = lock(&self.shared.state);
            if state.closed || state.broken {
                return false;
            }
            match &state.env {
                None => state.env = Some(env.to_vec()),
                // Another package or another harness names the same worker's import and engine labels: not this pool.
                Some(first) if env_key(first) != env_key(env) => return false,
                Some(_) => {}
            }
            state.workers.retain(|w| w.alive());
            let idle = state.workers.iter().filter(|w| !w.busy() && w.alive()).max_by_key(|w| *lock(&w.last_used)).cloned();
            if let Some(worker) = idle {
                worker.busy.store(true, Ordering::SeqCst);
                (worker, false)
            } else if state.workers.len() < max_workers.max(1) {
                match self.spawn(command, state.env.as_deref().unwrap_or(&[])) {
                    Some(worker) => {
                        worker.busy.store(true, Ordering::SeqCst);
                        state.workers.push(worker.clone());
                        (worker, true)
                    }
                    None => {
                        state.broken = true;
                        return false;
                    }
                }
            } else {
                return false; // every worker is busy: this publish takes the one-shot path, exactly as before
            }
        };
        let delivered = self.hand(&worker, path);
        if !delivered && fresh {
            // A worker spawned by this call died before its hello: this environment cannot run the pool.
            lock(&self.shared.state).broken = true;
        }
        delivered
    }

    fn hand(&self, worker: &Arc<Worker>, path: &str) -> bool {
        let line = hy_core::json::dumps(
            &serde_json::json!({ "job": path }),
            hy_core::json::Options { layout: hy_core::json::Layout::Spaced, sort_keys: false, ensure_ascii: true },
        );
        let written = {
            let mut stdin = lock(&worker.stdin);
            match stdin.as_mut() {
                Some(pipe) => pipe.write_all(&line).and_then(|()| pipe.write_all(b"\n")).and_then(|()| pipe.flush()).is_ok(),
                None => false,
            }
        };
        if !written {
            // The worker's read end was gone before the line arrived: no job ran, so the caller may use the one-shot path.
            self.retire(worker);
            return false;
        }
        // No hello yet. A worker writes it before it reads any job line, so a dead worker here never read this job; an alive
        // one is still importing and will read it.
        let deadline = Instant::now() + self.shared.config.ready_timeout;
        let mut hello = lock(&worker.hello);
        while !hello.ready && !hello.gone && worker.alive() && Instant::now() < deadline {
            let slice = Duration::from_millis(50).min(deadline.saturating_duration_since(Instant::now()));
            hello = worker.hello_changed.wait_timeout(hello, slice).unwrap_or_else(PoisonError::into_inner).0;
        }
        hello.ready || worker.alive()
    }

    fn spawn(&self, command: &[String], env: &[(String, String)]) -> Option<Arc<Worker>> {
        let (program, arguments) = command.split_first()?;
        let mut builder = Command::new(program);
        builder
            .args(arguments)
            .env_clear()
            .envs(env.iter().map(|(k, v)| (k, v)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());
        #[cfg(windows)]
        std::os::windows::process::CommandExt::creation_flags(&mut builder, 0x0800_0000); // CREATE_NO_WINDOW
        let mut child = builder.spawn().ok()?;
        let (stdin, stdout) = (child.stdin.take(), child.stdout.take());
        let (Some(stdin), Some(stdout)) = (stdin, stdout) else {
            let _ = child.kill(); // a child this process cannot speak to must not linger
            return None;
        };
        let worker = Arc::new(Worker {
            pid: AtomicU32::new(child.id()),
            child: Mutex::new(child),
            stdin: Mutex::new(Some(stdin)),
            hello: Mutex::new(Hello::default()),
            hello_changed: Condvar::new(),
            busy: AtomicBool::new(false),
            dead: AtomicBool::new(false),
            last_used: Mutex::new(Instant::now()),
        });
        let (pool, reader) = (self.clone(), worker.clone());
        std::thread::Builder::new()
            .name("hydralysis-viewpool-reader".into())
            .spawn(move || pool.read(&reader, BufReader::new(stdout)))
            .ok()?;
        Some(worker)
    }

    /// The reader thread of one worker: its control lines until its stdout ends.
    fn read(&self, worker: &Arc<Worker>, mut stdout: BufReader<std::process::ChildStdout>) {
        let mut line = Vec::new();
        loop {
            line.clear();
            match stdout.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let trimmed = line.strip_suffix(b"\n").unwrap_or(&line);
            let trimmed = trimmed.strip_suffix(b"\r").unwrap_or(trimmed);
            let Some(message) = control(trimmed) else { continue }; // a job's own output goes nowhere
            if message.get("ready").is_some_and(truthy) {
                if let Some(pid) = message.get("pid").and_then(Value::as_u64).filter(|p| *p > 0) {
                    worker.pid.store(u32::try_from(pid).unwrap_or(0), Ordering::SeqCst);
                }
                lock(&worker.hello).ready = true;
                worker.hello_changed.notify_all();
            } else if message.get("done").is_some_and(truthy) {
                self.finished(worker);
            }
        }
        self.died(worker);
    }

    fn retire(&self, worker: &Arc<Worker>) {
        let mut state = lock(&self.shared.state);
        worker.dead.store(true, Ordering::SeqCst);
        state.workers.retain(|w| !Arc::ptr_eq(w, worker));
        drop(state);
        worker.close_stdin();
    }

    /// The worker ran its job: it is idle again, and the pool keeps at most `keep_idle` idle workers.
    fn finished(&self, worker: &Arc<Worker>) {
        let mut state = lock(&self.shared.state);
        if worker.dead.load(Ordering::SeqCst) || !state.workers.iter().any(|w| Arc::ptr_eq(w, worker)) {
            return;
        }
        worker.busy.store(false, Ordering::SeqCst);
        *lock(&worker.last_used) = Instant::now();
        let mut idle: Vec<Arc<Worker>> = state.workers.iter().filter(|w| !w.busy() && w.alive()).cloned().collect();
        idle.sort_by_key(|w| *lock(&w.last_used));
        // `idle[:-KEEP_IDLE]` (and, as in Python, nothing at all for a keep of 0)
        let excess = if state.closed {
            idle
        } else if self.shared.config.keep_idle == 0 {
            Vec::new()
        } else {
            let keep_from = idle.len().saturating_sub(self.shared.config.keep_idle);
            idle.truncate(keep_from);
            idle
        };
        for extra in excess {
            self.stop(&mut state, &extra);
        }
        self.ensure_sweeper(&mut state);
    }

    /// The worker's stdout ended: it is gone. Its job, if it was running one, is as it left it.
    fn died(&self, worker: &Arc<Worker>) {
        {
            let mut state = lock(&self.shared.state);
            worker.dead.store(true, Ordering::SeqCst);
            state.workers.retain(|w| !Arc::ptr_eq(w, worker));
        }
        worker.close_stdin();
        lock(&worker.hello).gone = true;
        worker.hello_changed.notify_all();
        self.shared.wake.notify_all();
    }

    /// Ask an idle worker to exit by closing its stdin (its next read sees the end); the sweeper kills one that does not.
    fn stop(&self, state: &mut State, worker: &Arc<Worker>) {
        worker.dead.store(true, Ordering::SeqCst);
        state.workers.retain(|w| !Arc::ptr_eq(w, worker));
        worker.close_stdin();
        state.stopping.push((worker.clone(), Instant::now() + self.shared.config.stop_grace));
        self.shared.wake.notify_all();
    }

    fn ensure_sweeper(&self, state: &mut State) {
        if state.sweeper {
            return;
        }
        state.sweeper = true;
        let pool = self.clone();
        if std::thread::Builder::new().name("hydralysis-viewpool-sweeper".into()).spawn(move || pool.sweep()).is_err() {
            state.sweeper = false;
        }
    }

    /// The sweeper: stops idle workers after `idle`, and forgets (or kills) the ones that were asked to stop. It sleeps until
    /// the next deadline instead of ticking, and ends when the pool holds no worker.
    fn sweep(&self) {
        let config = &self.shared.config;
        let mut state = lock(&self.shared.state);
        loop {
            let now = Instant::now();
            let idle: Vec<Arc<Worker>> = state.workers.iter().filter(|w| !w.busy() && w.alive()).cloned().collect();
            for worker in idle {
                if state.closed || now.saturating_duration_since(*lock(&worker.last_used)) >= config.idle {
                    self.stop(&mut state, &worker);
                }
            }
            let mut kill: Vec<Arc<Worker>> = Vec::new();
            state.stopping.retain(|(worker, deadline)| {
                // As in Python, a worker that was asked to stop is `dead` and so never `alive`: it leaves the list at the next
                // sweep, and the kill below is reached only for a worker that was never marked dead.
                if !worker.alive() {
                    false
                } else if now >= *deadline {
                    kill.push(worker.clone());
                    false
                } else {
                    true
                }
            });
            if state.workers.is_empty() && state.stopping.is_empty() {
                state.sweeper = false;
                return;
            }
            let next = state
                .workers
                .iter()
                .filter(|w| !w.busy() && w.alive())
                .map(|w| *lock(&w.last_used) + config.idle)
                .chain(state.stopping.iter().map(|(_, deadline)| *deadline))
                .min();
            drop(state);
            for worker in kill {
                // outside the lock: a kill may take a while, and dispatches must not wait for it
                (config.terminate)(worker.pid.load(Ordering::SeqCst));
                worker.kill();
            }
            state = lock(&self.shared.state);
            state = match next {
                Some(at) => {
                    let wait = at.saturating_duration_since(Instant::now()).max(Duration::from_millis(1));
                    self.shared.wake.wait_timeout(state, wait).unwrap_or_else(PoisonError::into_inner).0
                }
                None => self.shared.wake.wait(state).unwrap_or_else(PoisonError::into_inner),
            };
        }
    }

    /// Stop every idle worker now; busy workers are left to finish their job (and are stopped when it ends).
    pub fn close_all(&self) {
        let mut state = lock(&self.shared.state);
        state.closed = true;
        let idle: Vec<Arc<Worker>> = state.workers.iter().filter(|w| !w.busy()).cloned().collect();
        for worker in idle {
            self.stop(&mut state, &worker);
        }
        self.ensure_sweeper(&mut state);
    }

    /// At interpreter exit: idle workers get their stop; a busy worker finishes its job and then sees its stdin end.
    pub fn shutdown(&self) {
        let mut state = lock(&self.shared.state);
        state.closed = true;
        let idle: Vec<Arc<Worker>> = state.workers.iter().filter(|w| !w.busy()).cloned().collect();
        for worker in idle {
            self.stop(&mut state, &worker);
        }
    }

    /// Kill every worker's process now (tests; a host that must not leave workers behind).
    pub fn kill_all(&self) {
        let workers: Vec<Arc<Worker>> = {
            let state = lock(&self.shared.state);
            state.workers.iter().chain(state.stopping.iter().map(|(w, _)| w)).cloned().collect()
        };
        for worker in workers {
            worker.kill();
        }
    }
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64().is_some_and(|f| f != 0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}
