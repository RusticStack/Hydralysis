//! `hydralysis_rt`: the Python-facing runtime session. It is a thin layer: every behaviour lives in `hy-runtime`.
//!
//! Blocking calls release the GIL, including the wait for the session mutex. Errors become
//! `RuntimeError`/`OSError`/`ValueError`; nothing here panics on input (PyO3 would turn a panic into `PanicException`,
//! not end the process).

mod convert;
mod decode;
mod snapshot;

use hy_runtime::memory::{Gate, MemError};
use hy_runtime::proto;
use hy_runtime::sampling::{Mode, Policy, Sampler};
use hy_runtime::session::{Session, SiteSpec, SpawnOpts};
use hy_runtime::watch::Kind;
use pyo3::exceptions::{PyOSError, PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict, PyList};
use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use windows_sys::Win32::System::Performance::QueryPerformanceCounter;
use windows_sys::Win32::System::Threading::WaitForSingleObject;

type SamplingRow = (usize, u64, u64, u64, u32, f64);
type SamplingReport = (u32, f64, Vec<SamplingRow>);
type Dr7Rows = (Vec<(u32, u64)>, Vec<u32>);

fn os(e: std::io::Error) -> PyErr {
    PyOSError::new_err(e.to_string())
}

fn mem(e: MemError) -> PyErr {
    PyRuntimeError::new_err(e.to_string())
}

fn gate_of(authorization: Option<&str>) -> PyResult<Gate> {
    match authorization {
        None => Ok(Gate::Fixture),
        Some(text) => {
            let v: serde_json::Value = serde_json::from_str(text).map_err(|e| PyValueError::new_err(e.to_string()))?;
            let a = hy_runtime::authorize::normalize(&v).map_err(PyValueError::new_err)?;
            Ok(Gate::Authorized(a))
        }
    }
}

// Wire flags of the batch contract (trace_wire.py).
const W_RET: u8 = 1;
const W_FAILED: u8 = 2;
const W_TRUNC: u8 = 4;
const W_WIDE: u8 = 8;
const W_BUF: u8 = 16;
const W_SAMPLED: u8 = 32;

const MAGIC: u32 = 0x3142_5448;

/// Sites at or above this index belong to the observe/break probes of the script surface; the trace recorder owns the
/// ones below (it takes at most 48). Both drain the same rings, so each leaves the other's hits where it finds them.
const OBSERVE_BASE: u16 = 48;

/// Hits drained from the rings and not yet handed to their consumer.
#[derive(Default)]
struct Stash {
    trace: Vec<proto::Hit>,
    observe: Vec<proto::Hit>,
}

#[pyclass(module = "hydralysis_rt")]
struct RtSession {
    inner: Mutex<Option<Session>>,
    sampler: Mutex<Option<Sampler>>,
    /// Trace records that came back with their return (the recorder's `left`).
    returned: AtomicU64,
    stash: Mutex<Stash>,
    #[pyo3(get)]
    pid: u32,
    #[pyo3(get)]
    created: u64,
    #[pyo3(get)]
    image: String,
}

impl RtSession {
    /// Run `f` on the session with the GIL released while waiting for the session mutex and while `f` runs. Other
    /// methods hold the mutex across a mailbox round trip of up to 30 s; waiting for it with the GIL held would
    /// freeze every Python thread of the process.
    fn with<T: Send>(&self, py: Python<'_>, f: impl FnOnce(&mut Session) -> PyResult<T> + Send) -> PyResult<T> {
        py.detach(|| self.with_locked(f))
    }

    fn with_locked<T>(&self, f: impl FnOnce(&mut Session) -> PyResult<T>) -> PyResult<T> {
        let mut g = self.inner.lock().map_err(|_| PyRuntimeError::new_err("session lock poisoned"))?;
        match g.as_mut() {
            Some(s) => f(s),
            None => Err(PyRuntimeError::new_err("session is closed")),
        }
    }

    /// The body of `sampling_report`, run with the GIL released (it holds the sampler mutex across the session call).
    fn sampling_report_locked(&self) -> PyResult<SamplingReport> {
        let g = self.sampler.lock().map_err(|_| PyRuntimeError::new_err("sampler lock poisoned"))?;
        let c = self.with_locked(|s| Ok(s.counters()))?;
        let (changes, effective) = g.as_ref().map_or((0, 0.0), |x| (x.changes, x.effective));
        let rows = c
            .sites
            .iter()
            .enumerate()
            .map(|(i, x)| {
                let (skipped, stride, rate) = match g.as_ref() {
                    Some(y) if i < usize::from(OBSERVE_BASE) => (y.reported_skipped(i, x.hits, x.kept), y.stride(i), y.rate(i)),
                    _ => (0, 1, 0.0),
                };
                (i, x.hits, x.kept, skipped, stride, rate)
            })
            .collect();
        Ok((changes, effective, rows))
    }

    fn wrap(s: Session) -> RtSession {
        RtSession {
            pid: s.pid,
            created: s.identity.created,
            image: s.identity.image.clone(),
            inner: Mutex::new(Some(s)),
            sampler: Mutex::new(None),
            returned: AtomicU64::new(0),
            stash: Mutex::new(Stash::default()),
        }
    }

    /// Drain the rings once and sort what came out between the two consumers.
    fn pull(&self, s: &mut Session) -> PyResult<()> {
        let hits = s.drain();
        if hits.is_empty() {
            return Ok(());
        }
        let mut stash = self.stash.lock().map_err(|_| PyRuntimeError::new_err("stash lock poisoned"))?;
        for h in hits {
            if h.site >= OBSERVE_BASE {
                stash.observe.push(h);
            } else {
                if h.flags & proto::RF_RETURNED != 0 {
                    self.returned.fetch_add(1, Ordering::Relaxed);
                }
                stash.trace.push(h);
            }
        }
        Ok(())
    }
}

fn opt<'py, T: for<'a> FromPyObject<'a, 'py, Error = PyErr>>(d: &Bound<'py, PyDict>, k: &str) -> PyResult<Option<T>> {
    match d.get_item(k)? {
        Some(v) if !v.is_none() => Ok(Some(v.extract::<T>()?)),
        _ => Ok(None),
    }
}

fn site_spec(d: &Bound<'_, PyDict>) -> PyResult<SiteSpec> {
    let rva: u64 = opt(d, "rva")?.ok_or_else(|| PyValueError::new_err("rva is required"))?;
    let expect: Vec<u8> = opt(d, "expect")?.unwrap_or_default();
    let mut s = SiteSpec::new(rva, expect);
    s.module = opt::<String>(d, "module")?.unwrap_or_default();
    s.module_base = opt(d, "base")?.unwrap_or(0);
    s.export = opt(d, "export")?;
    s.nargs = opt(d, "nargs")?.unwrap_or(0);
    s.stride = opt(d, "stride")?.unwrap_or(1);
    s.stack_depth = opt(d, "stack")?.unwrap_or(0);
    let mut flags = 0;
    if opt::<bool>(d, "with_leave")?.unwrap_or(false) {
        flags |= proto::F_RETURN;
    }
    if s.stack_depth > 1 {
        flags |= proto::F_STACK;
    }
    if opt::<bool>(d, "pause")?.unwrap_or(false) {
        flags |= proto::F_PAUSE;
    }
    if let Some(b) = d.get_item("buf")?.filter(|b| !b.is_none()) {
        let b = b.cast::<PyDict>().map_err(|e| PyValueError::new_err(e.to_string()))?;
        s.buf_ptr_arg = opt::<i32>(b, "ptr_arg")?.unwrap_or(-1);
        s.buf_len_arg = opt::<i32>(b, "len_arg")?.unwrap_or(-1);
        s.buf_fixed = opt(b, "fixed")?.unwrap_or(0);
        s.buf_max = opt(b, "max")?.unwrap_or(64);
        if opt::<bool>(b, "wide")?.unwrap_or(false) {
            flags |= proto::F_BUF_WIDE;
        }
        if opt::<bool>(b, "cstr")?.unwrap_or(false) {
            flags |= proto::F_BUF_CSTR;
        }
        if opt::<bool>(b, "on_return")?.unwrap_or(false) {
            flags |= proto::F_BUF_ON_RETURN;
        }
    }
    s.flags = flags;
    Ok(s)
}

fn code(r: Result<(), u32>) -> (bool, u32) {
    match r {
        Ok(()) => (true, 0),
        Err(c) => (false, c),
    }
}

#[pymethods]
impl RtSession {
    /// Spawn suspended. The agent is not injected yet.
    #[staticmethod]
    #[pyo3(signature = (exe, argv=Vec::new(), cwd=None, env=None, stdout=None))]
    fn spawn(
        py: Python<'_>,
        exe: String,
        argv: Vec<String>,
        cwd: Option<String>,
        env: Option<Vec<(String, String)>>,
        stdout: Option<String>,
    ) -> PyResult<RtSession> {
        let opts = SpawnOpts { stdout: stdout.map(PathBuf::from), cwd: cwd.map(PathBuf::from), env };
        let s = py.detach(|| Session::spawn_opts(std::path::Path::new(&exe), &argv, &[], &opts)).map_err(os)?;
        Ok(RtSession::wrap(s))
    }

    #[staticmethod]
    fn attach(py: Python<'_>, pid: u32) -> PyResult<RtSession> {
        Ok(RtSession::wrap(py.detach(|| Session::attach(pid, &[])).map_err(os)?))
    }

    /// Inject the agent library and start it.
    fn inject(&self, py: Python<'_>, dll: String) -> PyResult<()> {
        py.detach(|| self.with_locked(|s| s.inject(std::path::Path::new(&dll)).map_err(os)))
    }

    fn resume(&self, py: Python<'_>) -> PyResult<()> {
        self.with(py, |s| {
            s.resume();
            Ok(())
        })
    }

    fn running(&self, py: Python<'_>) -> PyResult<bool> {
        self.with(py, |s| Ok(s.running()))
    }

    fn exit_code(&self, py: Python<'_>) -> PyResult<Option<u32>> {
        self.with(py, |s| Ok(s.exit_code()))
    }

    /// Wait up to `ms` for the process to exit; true when it has. The session lock is not held while waiting.
    fn wait_exit(&self, py: Python<'_>, ms: u32) -> PyResult<bool> {
        let h = self.with(py, |s| Ok(s.process as usize))?;
        Ok(py.detach(|| unsafe { WaitForSingleObject(h as _, ms) == 0 }))
    }

    fn verify_identity(&self, py: Python<'_>) -> PyResult<()> {
        self.with(py, |s| s.verify_identity().map_err(|e| PyRuntimeError::new_err(e.to_string())))
    }

    /// Arm site `idx` from a spec dict. Returns `(ok, error_code)`.
    fn arm_site(&self, py: Python<'_>, idx: usize, spec: &Bound<'_, PyDict>) -> PyResult<(bool, u32)> {
        if idx >= proto::MAX_SITES {
            return Err(PyValueError::new_err("site index out of range"));
        }
        let spec = site_spec(spec)?;
        let r = py.detach(|| self.with_locked(|s| s.arm_site(idx, &spec).map_err(os)))?;
        Ok(code(r))
    }

    fn retire_site(&self, py: Python<'_>, idx: usize) -> PyResult<(bool, u32)> {
        let r = py.detach(|| self.with_locked(|s| s.retire_site(idx).map_err(os)))?;
        Ok(code(r))
    }

    fn detach_sites(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| self.with_locked(|s| s.detach_sites().map_err(os)))
    }

    fn set_stride(&self, py: Python<'_>, idx: usize, stride: u32) -> PyResult<()> {
        if idx >= proto::MAX_SITES {
            return Err(PyValueError::new_err("site index out of range"));
        }
        self.with(py, |s| {
            s.set_stride(idx, stride);
            Ok(())
        })
    }

    /// `(state, error)` of a site as the agent last wrote it.
    fn site_status(&self, py: Python<'_>, idx: usize) -> PyResult<(u32, u32)> {
        if idx >= proto::MAX_SITES {
            return Err(PyValueError::new_err("site index out of range"));
        }
        self.with(py, |s| Ok(s.site_status(idx)))
    }

    /// Drain the rings into batches in the wire format of `trace_wire.py`, each at most `max_bytes` of records,
    /// numbered from `first_seq`. Empty when nothing was pending. Every header carries the cumulative counters.
    fn drain_wire<'py>(&self, py: Python<'py>, producer_gen: u32, first_seq: u32, max_bytes: usize) -> PyResult<Vec<Bound<'py, PyBytes>>> {
        let batches = py.detach(|| {
            self.with_locked(|s| {
                self.pull(s)?;
                let hits = std::mem::take(&mut self.stash.lock().map_err(|_| PyRuntimeError::new_err("stash lock poisoned"))?.trace);
                if hits.is_empty() {
                    return Ok(Vec::new());
                }
                let clock = s.clock;
                let c = s.counters();
                let cap = max_bytes.clamp(4096, 1 << 24);
                let mut out: Vec<Vec<u8>> = Vec::new();
                let mut body: Vec<u8> = Vec::new();
                let mut n = 0u32;
                let mut seq = first_seq;
                let mut flush = |body: &mut Vec<u8>, n: &mut u32, seq: &mut u32| {
                    if *n == 0 {
                        return;
                    }
                    let mut b = Vec::with_capacity(64 + body.len());
                    b.extend_from_slice(&MAGIC.to_le_bytes());
                    b.extend_from_slice(&1u16.to_le_bytes());
                    b.extend_from_slice(&64u16.to_le_bytes());
                    b.extend_from_slice(&producer_gen.to_le_bytes());
                    b.extend_from_slice(&seq.to_le_bytes());
                    b.extend_from_slice(&qpc_now().to_le_bytes());
                    b.extend_from_slice(&n.to_le_bytes());
                    b.extend_from_slice(&(body.len() as u32).to_le_bytes());
                    b.extend_from_slice(&c.attempted.to_le_bytes());
                    b.extend_from_slice(&c.dropped.to_le_bytes());
                    b.extend_from_slice(&c.read_failed.to_le_bytes());
                    b.extend_from_slice(&c.no_ring.to_le_bytes());
                    b.extend_from_slice(body);
                    out.push(b);
                    body.clear();
                    *n = 0;
                    *seq = seq.wrapping_add(1);
                };
                for h in &hits {
                    let times = (clock.to_qpc(h.tsc), if h.tsc_end == 0 { 0 } else { clock.to_qpc(h.tsc_end) });
                    let rec = wire_record(times, h);
                    if !body.is_empty() && body.len() + rec.len() > cap {
                        flush(&mut body, &mut n, &mut seq);
                    }
                    body.extend_from_slice(&rec);
                    n += 1;
                }
                flush(&mut body, &mut n, &mut seq);
                Ok(out)
            })
        })?;
        Ok(batches.iter().map(|b| PyBytes::new(py, b)).collect())
    }

    /// Hits of the observe/break sites (index 48 and up) since the last call, oldest first, as dicts:
    /// `site tid args stack ret_addr retval last_error returned buf buf_addr buf_failed t` (`t` in QPC ticks).
    fn drain_hits<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let hits = py.detach(|| {
            self.with_locked(|s| {
                self.pull(s)?;
                let clock = s.clock;
                let taken = std::mem::take(&mut self.stash.lock().map_err(|_| PyRuntimeError::new_err("stash lock poisoned"))?.observe);
                Ok(taken
                    .into_iter()
                    .map(|h| {
                        let t = clock.to_qpc(h.tsc);
                        (h, t)
                    })
                    .collect::<Vec<_>>())
            })
        })?;
        hits.into_iter()
            .map(|(h, t)| {
                let d = PyDict::new(py);
                d.set_item("site", h.site)?;
                d.set_item("tid", h.tid)?;
                d.set_item("args", h.args)?;
                d.set_item("stack", h.stack)?;
                d.set_item("ret_addr", h.ret_addr)?;
                d.set_item("retval", h.retval)?;
                d.set_item("last_error", h.last_error)?;
                d.set_item("returned", h.flags & proto::RF_RETURNED != 0)?;
                d.set_item("buf", PyBytes::new(py, &h.buf))?;
                d.set_item("buf_addr", h.buf_addr)?;
                d.set_item("buf_failed", h.flags & proto::RF_BUF_FAILED != 0)?;
                d.set_item("t", t)?;
                Ok(d)
            })
            .collect()
    }

    /// Choose the sampling policy: `mode` is "adaptive", "exact" or "fixed" (with `stride`); `exact_sites` are site
    /// indexes never thinned.
    #[pyo3(signature = (mode, rate_budget, stride, interval_ms, exact_sites=Vec::new()))]
    fn configure_sampling(
        &self,
        py: Python<'_>,
        mode: &str,
        rate_budget: f64,
        stride: u32,
        interval_ms: u64,
        exact_sites: Vec<usize>,
    ) -> PyResult<()> {
        let mode = match mode {
            "adaptive" => Mode::Adaptive,
            "exact" => Mode::Exact,
            "fixed" => Mode::Fixed(stride.max(1)),
            other => {
                return Err(PyValueError::new_err(format!("unknown sampling mode {other:?}")));
            }
        };
        let policy = Policy {
            mode,
            rate_budget,
            interval: Duration::from_millis(interval_ms.max(1)),
            exact_sites: exact_sites.into_iter().collect::<HashSet<_>>(),
        };
        // Every std lock is taken with the GIL released (see `locked_sampler`).
        py.detach(|| {
            *self.sampler.lock().map_err(|_| PyRuntimeError::new_err("sampler lock poisoned"))? =
                Some(Sampler::new(policy, usize::from(OBSERVE_BASE)));
            Ok(())
        })
    }

    /// One step of the sampling policy (a no-op until configured). New strides are applied to the agent's sites.
    ///
    /// The sampler mutex is held across the session call, so the whole step runs with the GIL released: a guard held
    /// while this thread waits to take the GIL back would deadlock against any thread that holds the GIL and waits for
    /// that mutex (`configure_sampling`, `sampling_report`). Lock order is sampler, then session, everywhere.
    fn sampling_tick(&self, py: Python<'_>) -> PyResult<()> {
        py.detach(|| {
            let mut g = self.sampler.lock().map_err(|_| PyRuntimeError::new_err("sampler lock poisoned"))?;
            let Some(sampler) = g.as_mut() else {
                return Ok(());
            };
            self.with_locked(|s| {
                s.sampling_tick(sampler);
                Ok(())
            })
        })
    }

    /// `(policy_changes, effective_budget, [(site, hits, kept, skipped, stride, rate_per_s)])` for every site slot (the
    /// caller picks the armed ones). Sites from `OBSERVE_BASE` up are not the sampler's: stride 1, rate 0.
    fn sampling_report(&self, py: Python<'_>) -> PyResult<SamplingReport> {
        py.detach(|| self.sampling_report_locked())
    }

    /// Cumulative counters, per-site `(hits, kept)` and per-ring rows.
    fn counters<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let (c, rows, clock) = self.with(py, |s| Ok((s.counters(), s.ring_rows(), s.clock)))?;
        let freq = clock.freq;
        let d = PyDict::new(py);
        d.set_item("attempted", c.attempted)?;
        d.set_item("dropped", c.dropped)?;
        d.set_item("read_failed", c.read_failed)?;
        d.set_item("no_ring", c.no_ring)?;
        d.set_item("unreturned", c.unreturned)?;
        d.set_item("stalls", c.stalls)?;
        d.set_item("stall_ticks", clock.span_to_qpc(c.stall_ticks))?;
        d.set_item("bad_records", c.bad_records)?;
        d.set_item("qpc_freq", freq)?;
        d.set_item("returned", self.returned.load(Ordering::Relaxed))?;
        let sites = PyList::empty(py);
        for x in &c.sites {
            sites.append((x.hits, x.kept))?;
        }
        d.set_item("sites", sites)?;
        let rr = PyList::empty(py);
        for (ring, attempted, dropped, failed) in rows {
            let r = PyDict::new(py);
            r.set_item("ring", ring)?;
            r.set_item("attempted", attempted)?;
            r.set_item("dropped", dropped)?;
            r.set_item("read_failed", failed)?;
            rr.append(r)?;
        }
        d.set_item("rings", rr)?;
        Ok(d)
    }

    fn ring_count(&self, py: Python<'_>) -> PyResult<u32> {
        self.with(py, |s| Ok(s.ring_count()))
    }

    /// Out-of-band events: `(kind, site, tid, slot, data, qpc)`.
    #[allow(clippy::type_complexity)]
    fn events(&self, py: Python<'_>) -> PyResult<Vec<(u16, u16, u32, u32, Vec<u64>, u64)>> {
        self.with(py, |s| {
            let clock = s.clock;
            Ok(s.events().into_iter().map(|e| (e.kind, e.site, e.tid, e.slot, e.data.to_vec(), clock.to_qpc(e.tsc))).collect())
        })
    }

    /// Parked threads: `(slot, tid, site, parked_seconds)`.
    fn paused(&self, py: Python<'_>) -> PyResult<Vec<(usize, u32, u32, f64)>> {
        self.with(py, |s| Ok(s.paused().into_iter().map(|p| (p.slot, p.tid, p.site, p.parked_for.as_secs_f64())).collect()))
    }

    #[pyo3(signature = (slot, auto=false))]
    fn continue_breakpoint(&self, py: Python<'_>, slot: usize, auto: bool) -> PyResult<bool> {
        self.with(py, |s| Ok(s.continue_breakpoint(slot, auto)))
    }

    /// Release every thread parked longer than `limit_s`; returns the slots released.
    fn watchdog(&self, py: Python<'_>, limit_s: f64) -> PyResult<Vec<usize>> {
        self.with(py, |s| Ok(s.watchdog(Duration::from_secs_f64(limit_s.max(0.0)))))
    }

    fn modules<'py>(&self, py: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let list = self.with(py, |s| s.modules().map_err(os))?;
        list.into_iter()
            .map(|m| {
                let d = PyDict::new(py);
                d.set_item("name", m.name)?;
                d.set_item("path", m.path)?;
                d.set_item("base", m.base)?;
                d.set_item("size", m.size)?;
                Ok(d)
            })
            .collect()
    }

    fn threads(&self, py: Python<'_>) -> PyResult<Vec<u32>> {
        self.with(py, |s| Ok(s.threads()))
    }

    /// Every thread as `(tid, state, {register: value})`; the state is Frida's name, the registers are empty for a
    /// thread that could not be stopped for the read.
    #[allow(clippy::type_complexity)]
    fn thread_report<'py>(&self, py: Python<'py>) -> PyResult<Vec<(u32, &'static str, Bound<'py, PyDict>)>> {
        let report = py.detach(|| self.with_locked(|s| Ok(s.thread_report())))?;
        report
            .into_iter()
            .map(|t| {
                let regs = PyDict::new(py);
                for (name, value) in t.regs {
                    regs.set_item(name, value)?;
                }
                Ok((t.tid, t.state.as_str(), regs))
            })
            .collect()
    }

    fn read_memory<'py>(&self, py: Python<'py>, address: u64, size: usize) -> PyResult<Bound<'py, PyBytes>> {
        let v = py.detach(|| self.with_locked(|s| s.read_memory(address, size).map_err(os)))?;
        Ok(PyBytes::new(py, &v))
    }

    /// `(base, size, protect)` of the region holding `address`.
    fn query(&self, py: Python<'_>, address: u64) -> PyResult<(u64, u64, u32)> {
        self.with(py, |s| s.query(address).map_err(os))
    }

    /// Compare-and-swap with the policy gate. `authorization` is the JSON of the build's entry, or None for the
    /// fixture gate. Returns the undo id.
    #[pyo3(signature = (address, expect, value, reason, authorization=None))]
    fn write_cas(
        &self,
        py: Python<'_>,
        address: u64,
        expect: Vec<u8>,
        value: Vec<u8>,
        reason: String,
        authorization: Option<String>,
    ) -> PyResult<u32> {
        let gate = gate_of(authorization.as_deref())?;
        self.with(py, |s| s.write_cas(&gate, address, &expect, &value, &reason).map_err(mem))
    }

    #[pyo3(signature = (id, authorization=None))]
    fn undo_write(&self, py: Python<'_>, id: u32, authorization: Option<String>) -> PyResult<()> {
        let gate = gate_of(authorization.as_deref())?;
        self.with(py, |s| s.undo_write(&gate, id).map_err(mem))
    }

    /// Arm a hardware watch (`kind` is "write" or "rw"); returns the slot.
    #[pyo3(signature = (address, size, kind, limit, authorization=None))]
    fn arm_watch(&self, py: Python<'_>, address: u64, size: u32, kind: &str, limit: u32, authorization: Option<String>) -> PyResult<usize> {
        let gate = gate_of(authorization.as_deref())?;
        let kind = match kind {
            "write" => Kind::Write,
            "rw" | "readwrite" => Kind::ReadWrite,
            other => {
                return Err(PyValueError::new_err(format!("unknown watch kind {other:?}")));
            }
        };
        self.with(py, |s| s.arm_watch(&gate, address, size, kind, limit).map_err(mem))
    }

    /// Disarm and read back; returns the phase name ("clear" or "tainted").
    fn disarm_watch(&self, py: Python<'_>, slot: usize) -> PyResult<&'static str> {
        use hy_runtime::watch::Phase::*;
        self.with(py, |s| {
            Ok(match s.disarm_watch(slot).map_err(mem)? {
                Arming => "arming",
                Armed => "armed",
                Disarming => "disarming",
                Clear => "clear",
                Tainted => "tainted",
            })
        })
    }

    /// DR7 of every thread, read now: `([(tid, dr7)], [tid that could not be read])`.
    fn read_dr7(&self, py: Python<'_>) -> PyResult<Dr7Rows> {
        py.detach(|| self.with_locked(|s| Ok(s.read_dr7())))
    }

    /// The threads a watch slot has been programmed into.
    fn watch_threads(&self, py: Python<'_>, slot: usize) -> PyResult<Vec<u32>> {
        self.with(py, |s| Ok(s.watch_threads(slot)))
    }

    fn watch_hits(&self, py: Python<'_>, slot: usize) -> PyResult<u32> {
        self.with(py, |s| Ok(s.watch_hits(slot)))
    }

    fn sync_watch_threads(&self, py: Python<'_>) -> PyResult<()> {
        self.with(py, |s| {
            s.sync_watch_threads();
            Ok(())
        })
    }

    fn watch_tainted(&self, py: Python<'_>) -> PyResult<bool> {
        self.with(py, |s| Ok(s.watch_tainted()))
    }

    fn terminate(&self, py: Python<'_>) -> PyResult<()> {
        self.with(py, |s| {
            s.terminate();
            Ok(())
        })
    }

    /// Ask the agent to stop and drop the session (unmaps the section, closes handles).
    fn close(&self, py: Python<'_>) {
        py.detach(|| {
            if let Ok(mut g) = self.inner.lock()
                && let Some(s) = g.take()
            {
                s.shutdown_agent();
            }
        });
    }
}

fn qpc_now() -> u64 {
    let mut v = 0i64;
    unsafe { QueryPerformanceCounter(&mut v) };
    v as u64
}

fn wire_record(times: (u64, u64), h: &proto::Hit) -> Vec<u8> {
    let mut flags = 0u8;
    if h.flags & proto::RF_RETURNED != 0 {
        flags |= W_RET;
    }
    if h.flags & proto::RF_BUF_FAILED != 0 {
        flags |= W_FAILED | W_BUF;
    }
    if h.flags & proto::RF_BUF_TRUNC != 0 {
        flags |= W_TRUNC;
    }
    if h.flags & proto::RF_BUF_WIDE != 0 {
        flags |= W_WIDE;
    }
    if !h.buf.is_empty() {
        flags |= W_BUF;
    }
    if h.flags & proto::RF_SAMPLED != 0 {
        flags |= W_SAMPLED;
    }
    let nstack = h.stack.len().min(15);
    let padded = h.buf.len().div_ceil(8) * 8;
    let size = 64 + 8 * h.args.len() + 8 * nstack + padded;
    let mut o = Vec::with_capacity(size);
    o.extend_from_slice(&(size as u16).to_le_bytes());
    o.push(1 | ((nstack as u8) << 4));
    o.push(flags);
    // Site ids on the wire are 1-based (the Python plan numbers its probes from 1).
    o.extend_from_slice(&(h.site + 1).to_le_bytes());
    o.extend_from_slice(&h.ring.to_le_bytes());
    o.extend_from_slice(&times.0.to_le_bytes());
    o.extend_from_slice(&h.tid.to_le_bytes());
    o.extend_from_slice(&h.ring_seq.to_le_bytes());
    o.extend_from_slice(&h.ret_addr.to_le_bytes());
    o.extend_from_slice(&times.1.to_le_bytes());
    o.extend_from_slice(&h.retval.to_le_bytes());
    o.extend_from_slice(&h.last_error.to_le_bytes());
    o.extend_from_slice(&(h.args.len() as u16).to_le_bytes());
    o.extend_from_slice(&(h.buf.len() as u16).to_le_bytes());
    o.extend_from_slice(&h.buf_addr.to_le_bytes());
    for a in &h.args {
        o.extend_from_slice(&a.to_le_bytes());
    }
    for a in h.stack.iter().take(nstack) {
        o.extend_from_slice(&a.to_le_bytes());
    }
    o.extend_from_slice(&h.buf);
    o.resize(size, 0);
    o
}

#[pyfunction]
fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

#[pymodule]
fn hydralysis_rt(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<RtSession>()?;
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add("Unmodelled", m.py().get_type::<convert::Unmodelled>())?;
    m.add_function(wrap_pyfunction!(decode::decode_normalize, m)?)?;
    m.add_function(wrap_pyfunction!(decode::decode_value, m)?)?;
    m.add_function(wrap_pyfunction!(decode::decode_event, m)?)?;
    m.add_function(wrap_pyfunction!(decode::decode_layout_values, m)?)?;
    m.add_function(wrap_pyfunction!(snapshot::snapshot_stable_sha256, m)?)?;
    m.add_function(wrap_pyfunction!(snapshot::snapshot_compare, m)?)?;
    Ok(())
}
