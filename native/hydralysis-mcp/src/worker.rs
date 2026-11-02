//! The bridge to the Python worker (`python -m hydralysis.worker`): spawned on the first delegated call, closed after an
//! idle period, restarted on the next call. The protocol is one JSON object per line (see hydralysis/worker.py).

use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, Sender};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

type Pending = Arc<Mutex<HashMap<u64, Sender<Value>>>>;

/// What the server knows about one accepted tool call: cancelled by the client, and where it runs in the worker.
#[derive(Default)]
pub struct CallState {
    pub cancelled: AtomicBool,
    pub worker_id: AtomicU64,
    pub reason: Mutex<String>,
}

struct Proc {
    child: Child,
    stdin: ChildStdin,
    pending: Pending,
    alive: Arc<AtomicBool>,
    last: Instant,
}

struct Inner {
    proc: Option<Proc>,
    harness: Option<Value>,
}

pub struct Worker {
    inner: Mutex<Inner>,
    python: String,
    idle: Duration,
    next_id: AtomicU64,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Worker {
    pub fn new() -> Arc<Worker> {
        let python = std::env::var("HYDRALYSIS_PYTHON")
            .ok()
            .filter(|text| !text.is_empty())
            .unwrap_or_else(|| "python".to_string());
        let idle = std::env::var("HYDRALYSIS_WORKER_IDLE_S")
            .ok()
            .and_then(|text| text.parse::<f64>().ok())
            .filter(|seconds| *seconds >= 0.0)
            .unwrap_or(30.0);
        let worker = Arc::new(Worker {
            inner: Mutex::new(Inner {
                proc: None,
                harness: None,
            }),
            python,
            idle: Duration::from_secs_f64(idle),
            next_id: AtomicU64::new(1),
        });
        let weak = Arc::downgrade(&worker);
        std::thread::Builder::new()
            .name("worker-reaper".into())
            .spawn(move || {
                let tick = Duration::from_millis(250);
                loop {
                    std::thread::sleep(tick);
                    let Some(worker) = weak.upgrade() else { return };
                    worker.reap();
                }
            })
            .ok();
        worker
    }

    fn spawn(&self, harness: Option<&Value>) -> Result<Proc, String> {
        let mut command = Command::new(&self.python);
        command
            .args(["-X", "utf8", "-P", "-m", "hydralysis.worker"])
            .env("PYTHONUTF8", "1")
            .env("HYDRALYSIS_MCP_WORKER", "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit());
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x0800_0000);
        }
        let mut child = command
            .spawn()
            .map_err(|error| format!("cannot start the Python worker ({}): {error}; set HYDRALYSIS_PYTHON to a Python with hydralysis installed", self.python))?;
        let stdin = child.stdin.take().ok_or("worker has no stdin")?;
        let stdout = child.stdout.take().ok_or("worker has no stdout")?;
        let pending: Pending = Arc::new(Mutex::new(HashMap::new()));
        let alive = Arc::new(AtomicBool::new(true));
        {
            let pending = Arc::clone(&pending);
            let alive = Arc::clone(&alive);
            std::thread::Builder::new()
                .name("worker-reader".into())
                .spawn(move || {
                    let mut lines = BufReader::new(stdout);
                    let mut line = String::new();
                    loop {
                        line.clear();
                        match lines.read_line(&mut line) {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                        let Ok(message) = serde_json::from_str::<Value>(line.trim()) else {
                            continue;
                        };
                        let Some(id) = message.get("id").and_then(Value::as_u64) else {
                            continue;
                        };
                        if let Some(sender) = lock(&pending).remove(&id) {
                            let _ = sender.send(message);
                        }
                    }
                    alive.store(false, Ordering::SeqCst);
                    for (_, sender) in lock(&pending).drain() {
                        let _ = sender
                            .send(json!({"dead": "the Python worker exited before it answered"}));
                    }
                })
                .map_err(|error| error.to_string())?;
        }
        let mut proc = Proc {
            child,
            stdin,
            pending,
            alive,
            last: Instant::now(),
        };
        if let Some(name) = harness {
            let _ = writeln!(proc.stdin, "{}", json!({"op": "harness", "name": name}));
        }
        Ok(proc)
    }

    /// Send one request and wait for its reply. `build` gets the request id.
    fn roundtrip(
        &self,
        build: impl FnOnce(u64) -> Value,
        state: Option<&CallState>,
    ) -> Result<Value, String> {
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        let (sender, receiver) = channel();
        {
            let mut inner = lock(&self.inner);
            let stale = inner
                .proc
                .as_ref()
                .is_some_and(|proc| !proc.alive.load(Ordering::SeqCst));
            if stale {
                if let Some(mut dead) = inner.proc.take() {
                    let _ = dead.child.kill();
                    let _ = dead.child.wait();
                }
            }
            if inner.proc.is_none() {
                let harness = inner.harness.clone();
                inner.proc = Some(self.spawn(harness.as_ref())?);
            }
            let proc = inner.proc.as_mut().ok_or("worker missing")?;
            lock(&proc.pending).insert(id, sender);
            if let Some(state) = state {
                state.worker_id.store(id, Ordering::SeqCst);
            }
            let line = serde_json::to_string(&build(id)).map_err(|error| error.to_string())?;
            let wrote = writeln!(proc.stdin, "{line}").and_then(|()| proc.stdin.flush());
            if let Err(error) = wrote {
                lock(&proc.pending).remove(&id);
                return Err(format!(
                    "the Python worker is not accepting requests: {error}"
                ));
            }
            proc.last = Instant::now();
            if state.is_some_and(|state| state.cancelled.load(Ordering::SeqCst)) {
                let _ = writeln!(
                    proc.stdin,
                    "{}",
                    json!({"op": "cancel", "id": id, "reason": "cancelled by the client"})
                );
            }
        }
        let reply = receiver
            .recv()
            .map_err(|_| "the Python worker closed".to_string());
        if let Some(proc) = lock(&self.inner).proc.as_mut() {
            proc.last = Instant::now();
        }
        let reply = reply?;
        if let Some(reason) = reply.get("dead").and_then(Value::as_str) {
            return Err(reason.to_string());
        }
        Ok(reply)
    }

    /// Run one `tools/call` in the worker. The reply is `{"id", "result"}` or `{"id", "error"}`.
    pub fn call(&self, params: &Value, state: &CallState) -> Result<Value, String> {
        self.roundtrip(
            |id| json!({"op": "call", "id": id, "params": params}),
            Some(state),
        )
    }

    /// `environment.describe()` of the worker's Python, and the launch banner text for stderr.
    pub fn environment(&self) -> Result<(Value, String), String> {
        let reply = self.roundtrip(|id| json!({"op": "environment", "id": id}), None)?;
        let environment = reply
            .get("environment")
            .cloned()
            .ok_or_else(|| "the worker returned no environment".to_string())?;
        let banner = reply
            .get("announce")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        Ok((environment, banner))
    }

    /// The client's name (initialize `clientInfo.name`): handed to the worker now and after every restart.
    pub fn set_harness(&self, name: Value) {
        let mut inner = lock(&self.inner);
        if let Some(proc) = inner.proc.as_mut() {
            let _ = writeln!(proc.stdin, "{}", json!({"op": "harness", "name": name}));
        }
        inner.harness = Some(name);
    }

    /// Forward a client cancellation of the call at `state.worker_id`.
    pub fn cancel(&self, state: &CallState) {
        let id = state.worker_id.load(Ordering::SeqCst);
        if id == 0 {
            return;
        }
        let reason = lock(&state.reason).clone();
        let mut inner = lock(&self.inner);
        if let Some(proc) = inner.proc.as_mut() {
            let _ = writeln!(
                proc.stdin,
                "{}",
                json!({"op": "cancel", "id": id, "reason": reason})
            );
        }
    }

    /// Close the worker when it has been idle for the idle period and nothing is pending.
    fn reap(&self) {
        let taken = {
            let mut inner = lock(&self.inner);
            let due = inner.proc.as_ref().is_some_and(|proc| {
                !proc.alive.load(Ordering::SeqCst)
                    || (lock(&proc.pending).is_empty() && proc.last.elapsed() >= self.idle)
            });
            if due {
                inner.proc.take()
            } else {
                None
            }
        };
        if let Some(proc) = taken {
            close(proc);
        }
    }

    /// Close the worker now (the host is exiting).
    pub fn shutdown(&self) {
        let taken = lock(&self.inner).proc.take();
        if let Some(proc) = taken {
            close(proc);
        }
    }
}

fn close(mut proc: Proc) {
    let _ = writeln!(proc.stdin, "{}", json!({"op": "exit"}));
    drop(proc.stdin);
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        match proc.child.try_wait() {
            Ok(Some(_)) | Err(_) => return,
            Ok(None) if Instant::now() >= deadline => break,
            Ok(None) => std::thread::sleep(Duration::from_millis(20)),
        }
    }
    let _ = proc.child.kill();
    let _ = proc.child.wait();
}
