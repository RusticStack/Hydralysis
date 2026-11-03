//! Which views stay open in this process, and which are let go (`hydralysis.viewgov`; Y5, D43, D61,
//! PROTOCOL-3.md 3.11 and 4.10).
//!
//! LRU and `max_views`, idle eviction with a keep-warm exemption, and the pin-or-evict step: "no running request" and
//! "closing" are decided in one step under one lock, so a view is never closed under a running request.
//! `delete_idle_folders` (needs the views store and working copies) is not ported yet; see TESTMAP.md.

use std::collections::HashMap;
use std::sync::{Arc, Condvar, LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

/// Seconds between folder-delete sweeps per lineage.
pub const DELETE_SWEEP_S: f64 = 600.0;
/// The most a process's exit waits for its views to be closed.
pub const SESSION_END_S: f64 = 30.0;

/// The governor's limits.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Limits {
    pub max_views: f64,
    pub idle_evict_s: f64,
    pub keep_warm_records: f64,
    pub idle_delete_s: f64,
    pub wait_s: f64,
}

impl Default for Limits {
    fn default() -> Self {
        Self { max_views: 24.0, idle_evict_s: 600.0, keep_warm_records: 1000.0, idle_delete_s: 86400.0, wait_s: 30.0 }
    }
}

/// The limits from the settings (camelCase or snake_case names), falling back to defaults for a missing or invalid value.
pub fn limits(settings: Option<&Map<String, Value>>) -> Limits {
    let mut found = Limits::default();
    let pick = |names: [&str; 2], minimum: f64| -> Option<f64> {
        let s = settings?;
        for name in names {
            if let Some(Value::Number(n)) = s.get(name)
                && let Some(v) = n.as_f64().filter(|v| *v >= minimum)
            {
                return Some(v);
            }
        }
        None
    };
    if let Some(v) = pick(["maxViews", "max_views"], 1.0) {
        found.max_views = v;
    }
    if let Some(v) = pick(["viewIdleEvictS", "view_idle_evict_s"], 0.0) {
        found.idle_evict_s = v;
    }
    if let Some(v) = pick(["viewKeepWarmRecords", "view_keep_warm_records"], 0.0) {
        found.keep_warm_records = v;
    }
    if let Some(v) = pick(["viewIdleDeleteS", "view_idle_delete_s"], 0.0) {
        found.idle_delete_s = v;
    }
    found
}

/// Every open view of this process is running a request: nothing can be closed to make room.
#[derive(Debug, Clone, thiserror::Error)]
#[error("this process holds {open_views} views open (max_views {max_views}) and every one is running a request")]
pub struct Capacity {
    pub open_views: usize,
    pub max_views: f64,
    pub retry_after_ms: u64,
}

/// Lifecycle of a governed view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Open,
    Evicting,
    Evicted,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            State::Open => "open",
            State::Evicting => "evicting",
            State::Evicted => "evicted",
        }
    }
}

/// What a release callback is told about the view it closes.
#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub key: String,
    pub name: String,
    pub target: Value,
}

/// Closes a view (discard, keep the folder). An `Err` puts the view back to `open` and is never raised to the caller.
pub type Release = Arc<dyn Fn(&EntryInfo) -> Result<(), String> + Send + Sync>;

struct Entry {
    key: String,
    name: String,
    target: Value,
    last_used: f64,
    running: u32,
    pending: u64,
    state: State,
    closed: u64,
    error: String,
    release: Option<Release>,
}

impl Entry {
    fn info(&self) -> EntryInfo {
        EntryInfo { key: self.key.clone(), name: self.name.clone(), target: self.target.clone() }
    }

    fn row(&self, now: f64) -> Value {
        let mut row = json!({
            "view": self.name, "key": self.key, "state": self.state.as_str(), "running": self.running,
            "pending": self.pending, "idle_s": ((now - self.last_used) * 10.0).round() / 10.0, "closed": self.closed,
        });
        if !self.error.is_empty() {
            row["error"] = json!(self.error);
        }
        row
    }
}

/// A request's hold on a view. `rebuilt` is true when the view was closed since its last use (the reply says so once).
#[derive(Debug)]
pub struct Pin {
    key: String,
    pub rebuilt: bool,
    pub started: Instant,
}

#[derive(Default)]
struct Inner {
    entries: HashMap<String, Entry>,
    swept: HashMap<String, f64>,
}

impl Inner {
    fn open_count(&self) -> usize {
        self.entries.values().filter(|e| e.state == State::Open).count()
    }

    fn victim(&self, exclude: Option<&str>) -> Option<String> {
        self.entries
            .values()
            .filter(|e| e.state == State::Open && e.running == 0 && Some(e.key.as_str()) != exclude)
            .min_by(|a, b| a.last_used.total_cmp(&b.last_used))
            .map(|e| e.key.clone())
    }
}

/// The per-process view governor.
pub struct Governor {
    clock: Arc<dyn Fn() -> f64 + Send + Sync>,
    inner: Mutex<Inner>,
    cond: Condvar,
}

fn monotonic() -> f64 {
    static START: LazyLock<Instant> = LazyLock::new(Instant::now);
    START.elapsed().as_secs_f64() + 1.0
}

impl Default for Governor {
    fn default() -> Self {
        Self::new(Arc::new(monotonic))
    }
}

impl Governor {
    pub fn new(clock: Arc<dyn Fn() -> f64 + Send + Sync>) -> Self {
        Self { clock, inner: Mutex::new(Inner::default()), cond: Condvar::new() }
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// Hold the view of `selected` (`key`, `view`, plus `name/program/sha256/gpr`) for a request. Waits (bounded) while the
    /// view is being closed; makes room first when the view is new and the process is at `max_views`.
    pub fn pin(
        &self,
        selected: &Map<String, Value>,
        settings: Option<&Map<String, Value>>,
        release: Option<Release>,
        pending: Option<u64>,
    ) -> Result<Pin, Capacity> {
        let limit = limits(settings);
        let deadline = self.now() + limit.wait_s;
        let key = selected.get("key").and_then(Value::as_str).unwrap_or_default().to_string();
        let mut guard = self.inner.lock().unwrap();
        loop {
            if guard.entries.get(&key).is_some_and(|e| e.state == State::Evicting) {
                if self.now() >= deadline {
                    return Err(Capacity { open_views: guard.open_count(), max_views: limit.max_views, retry_after_ms: 1000 });
                }
                guard = self.cond.wait_timeout(guard, Duration::from_millis(50)).unwrap().0;
                continue;
            }
            break;
        }
        let now = self.now();
        let created = !guard.entries.contains_key(&key);
        let mut rebuilt = false;
        if created {
            let mut target = Map::new();
            for k in ["name", "program", "sha256", "gpr", "key", "view"] {
                target.insert(k.into(), selected.get(k).cloned().unwrap_or(Value::Null));
            }
            let name = selected.get("view").and_then(Value::as_str).unwrap_or_default().to_string();
            guard.entries.insert(
                key.clone(),
                Entry {
                    key: key.clone(),
                    name,
                    target: Value::Object(target),
                    last_used: now,
                    running: 0,
                    pending: 0,
                    state: State::Open,
                    closed: 0,
                    error: String::new(),
                    release: None,
                },
            );
        } else if let Some(e) = guard.entries.get_mut(&key).filter(|e| e.state == State::Evicted) {
            rebuilt = true;
            e.state = State::Open;
        }
        {
            let e = guard.entries.get_mut(&key).unwrap();
            e.running += 1; // pin first: from here on this view cannot be chosen as a victim
            e.last_used = now;
            if release.is_some() {
                e.release.clone_from(&release);
            }
            if let Some(p) = pending {
                e.pending = p;
            }
        }
        let mut victims: Vec<String> = Vec::new();
        while guard.open_count() as f64 > limit.max_views {
            let Some(victim) = guard.victim(Some(&key)) else {
                let held = guard.open_count();
                for chosen in &victims {
                    if let Some(e) = guard.entries.get_mut(chosen) {
                        e.state = State::Open;
                    }
                }
                guard.entries.get_mut(&key).unwrap().running -= 1;
                if created {
                    guard.entries.remove(&key);
                }
                self.cond.notify_all();
                return Err(Capacity { open_views: held.saturating_sub(1), max_views: limit.max_views, retry_after_ms: 2000 });
            };
            guard.entries.get_mut(&victim).unwrap().state = State::Evicting; // no longer counted as open
            victims.push(victim);
        }
        drop(guard);
        self.close(&victims, release.as_ref());
        Ok(Pin { key, rebuilt, started: Instant::now() })
    }

    pub fn unpin(&self, pin: &Pin) {
        let mut guard = self.inner.lock().unwrap();
        let now = self.now();
        if let Some(e) = guard.entries.get_mut(&pin.key).filter(|e| e.running > 0) {
            e.running -= 1;
            e.last_used = now;
        }
        self.cond.notify_all();
    }

    /// Run `f` holding the view; unpins afterwards, also on panic.
    pub fn hold<T>(
        &self,
        selected: &Map<String, Value>,
        settings: Option<&Map<String, Value>>,
        release: Option<Release>,
        pending: Option<u64>,
        f: impl FnOnce(&Pin) -> T,
    ) -> Result<T, Capacity> {
        struct Unpin<'a>(&'a Governor, &'a Pin);
        impl Drop for Unpin<'_> {
            fn drop(&mut self) {
                self.0.unpin(self.1);
            }
        }
        let pin = self.pin(selected, settings, release, pending)?;
        let _u = Unpin(self, &pin);
        Ok(f(&pin))
    }

    /// Record the pending-record count of a view.
    pub fn note(&self, key: &str, pending: u64) {
        if let Some(e) = self.inner.lock().unwrap().entries.get_mut(key) {
            e.pending = pending;
        }
    }

    /// Close each victim (already marked `evicting`). A failing close puts the view back to `open`; it is not raised.
    fn close(&self, victims: &[String], release: Option<&Release>) -> Vec<String> {
        let mut closed = Vec::new();
        for key in victims {
            let info = {
                let g = self.inner.lock().unwrap();
                g.entries.get(key).map(Entry::info)
            };
            let Some(info) = info else { continue };
            let result = match release {
                Some(r) => std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| r(&info)))
                    .unwrap_or_else(|_| Err("panic: release panicked".into())),
                None => Ok(()),
            };
            let mut g = self.inner.lock().unwrap();
            if let Some(e) = g.entries.get_mut(key) {
                match result {
                    Ok(()) => {
                        e.state = State::Evicted;
                        e.closed += 1;
                        closed.push(e.name.clone());
                    }
                    Err(message) => {
                        e.error = message;
                        e.state = State::Open;
                    }
                }
            }
            self.cond.notify_all();
        }
        closed
    }

    /// Close every view idle for `viewIdleEvictS`, except a keep-warm view (pending >= `viewKeepWarmRecords`).
    pub fn sweep(&self, settings: Option<&Map<String, Value>>, release: Option<&Release>) -> Vec<String> {
        let limit = limits(settings);
        let mut victims = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            let now = self.now();
            for e in g.entries.values_mut() {
                if e.state == State::Open
                    && e.running == 0
                    && now - e.last_used >= limit.idle_evict_s
                    && (e.pending as f64) < limit.keep_warm_records
                {
                    e.state = State::Evicting;
                    victims.push(e.key.clone());
                }
            }
        }
        self.close(&victims, release)
    }

    /// Close one view now if it has no running request. False when it is running or not open.
    pub fn evict(&self, key: &str, release: Option<&Release>) -> bool {
        {
            let mut g = self.inner.lock().unwrap();
            match g.entries.get_mut(key) {
                Some(e) if e.state == State::Open && e.running == 0 => e.state = State::Evicting,
                _ => return false,
            }
        }
        !self.close(&[key.to_string()], release).is_empty()
    }

    /// Close the least recently used idle view (the engine said `capacity`). The name, or `None` when every view is running.
    pub fn evict_lru(&self, release: Option<&Release>, exclude: Option<&str>) -> Option<String> {
        let key = {
            let mut g = self.inner.lock().unwrap();
            let key = g.victim(exclude)?;
            g.entries.get_mut(&key).unwrap().state = State::Evicting;
            key
        };
        self.close(&[key], release).into_iter().next()
    }

    /// The process is ending: close every view it still holds, each with the callback of the request that last pinned it.
    /// A view with a running request, or one kept warm, is left open.
    pub fn end_session(&self, settings: Option<&Map<String, Value>>) -> Vec<String> {
        let limit = limits(settings);
        let mut victims: Vec<(String, Release)> = Vec::new();
        {
            let mut g = self.inner.lock().unwrap();
            for e in g.entries.values_mut() {
                if e.state == State::Open
                    && e.running == 0
                    && (e.pending as f64) < limit.keep_warm_records
                    && let Some(r) = e.release.clone()
                {
                    e.state = State::Evicting;
                    victims.push((e.key.clone(), r));
                }
            }
        }
        let mut closed = Vec::new();
        for (key, release) in victims {
            closed.extend(self.close(&[key], Some(&release)));
        }
        closed
    }

    pub fn forget(&self, key: &str) {
        self.inner.lock().unwrap().entries.remove(key);
    }

    /// Rows for every governed view, least recently used first.
    pub fn snapshot(&self) -> Vec<Value> {
        let g = self.inner.lock().unwrap();
        let now = self.now();
        let mut rows: Vec<&Entry> = g.entries.values().collect();
        rows.sort_by(|a, b| a.last_used.total_cmp(&b.last_used));
        rows.into_iter().map(|e| e.row(now)).collect()
    }

    pub fn reset(&self) {
        let mut g = self.inner.lock().unwrap();
        g.entries.clear();
        g.swept.clear();
    }

    /// True at most once per `DELETE_SWEEP_S` per lineage.
    pub fn due_for_delete_sweep(&self, lineage_id: &str) -> bool {
        let mut g = self.inner.lock().unwrap();
        let now = self.now();
        if now - g.swept.get(lineage_id).copied().unwrap_or(-DELETE_SWEEP_S) < DELETE_SWEEP_S {
            return false;
        }
        g.swept.insert(lineage_id.into(), now);
        true
    }
}

/// The process-wide governor.
pub static GOVERNOR: LazyLock<Governor> = LazyLock::new(Governor::default);

thread_local! {
    static ENDING: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// True on the thread that closes the views at the end of the session: it starts no daemon.
pub fn session_ending() -> bool {
    ENDING.with(std::cell::Cell::get)
}

/// Close this process's views now, on a worker thread joined for at most `timeout_s` (default [`SESSION_END_S`]).
pub fn end_session(settings: Option<Map<String, Value>>, timeout_s: Option<f64>) -> Vec<String> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::Builder::new()
        .name("hydralysis-session-end".into())
        .spawn(move || {
            ENDING.with(|c| c.set(true));
            let _ = tx.send(GOVERNOR.end_session(settings.as_ref()));
        })
        .ok();
    rx.recv_timeout(Duration::from_secs_f64(timeout_s.unwrap_or(SESSION_END_S))).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn sel(name: &str) -> Map<String, Value> {
        json!({"key": format!("k-{name}"), "view": name, "name": "p", "program": "x"}).as_object().unwrap().clone()
    }

    fn settings(v: Value) -> Map<String, Value> {
        v.as_object().unwrap().clone()
    }

    fn fake() -> (Governor, Arc<AtomicU64>) {
        let t = Arc::new(AtomicU64::new(1000));
        let c = t.clone();
        (Governor::new(Arc::new(move || c.load(Ordering::SeqCst) as f64)), t)
    }

    fn recorder() -> (Release, Arc<Mutex<Vec<String>>>) {
        let log = Arc::new(Mutex::new(Vec::new()));
        let l = log.clone();
        (
            Arc::new(move |e: &EntryInfo| {
                l.lock().unwrap().push(e.name.clone());
                Ok(())
            }),
            log,
        )
    }

    #[test]
    fn limits_accept_both_spellings_and_reject_invalid() {
        assert_eq!(limits(None), Limits::default());
        let l = limits(Some(&settings(json!({"maxViews": 3, "view_idle_evict_s": 5, "viewKeepWarmRecords": true, "viewIdleDeleteS": -1}))));
        assert_eq!(l.max_views, 3.0);
        assert_eq!(l.idle_evict_s, 5.0);
        assert_eq!(l.keep_warm_records, 1000.0);
        assert_eq!(l.idle_delete_s, 86400.0);
        assert_eq!(limits(Some(&settings(json!({"maxViews": 0})))).max_views, 24.0);
    }

    #[test]
    fn lru_eviction_at_max_views_and_rebuilt_flag() {
        let (g, t) = fake();
        let (rel, log) = recorder();
        let s = settings(json!({"maxViews": 2}));
        for n in ["a", "b"] {
            t.fetch_add(1, Ordering::SeqCst);
            g.hold(&sel(n), Some(&s), Some(rel.clone()), None, |_| ()).unwrap();
        }
        t.fetch_add(1, Ordering::SeqCst);
        g.hold(&sel("c"), Some(&s), Some(rel.clone()), None, |_| ()).unwrap();
        assert_eq!(*log.lock().unwrap(), vec!["a"]);
        t.fetch_add(1, Ordering::SeqCst);
        let pin = g.pin(&sel("a"), Some(&s), Some(rel.clone()), None).unwrap();
        assert!(pin.rebuilt);
        g.unpin(&pin);
        assert_eq!(log.lock().unwrap().as_slice(), ["a", "b"]);
    }

    #[test]
    fn capacity_when_every_view_is_running_and_nothing_leaks() {
        let (g, _) = fake();
        let s = settings(json!({"maxViews": 1}));
        let p = g.pin(&sel("a"), Some(&s), None, None).unwrap();
        let e = g.pin(&sel("b"), Some(&s), None, None).unwrap_err();
        assert_eq!((e.open_views, e.retry_after_ms), (1, 2000));
        assert_eq!(g.snapshot().len(), 1);
        g.unpin(&p);
    }

    #[test]
    fn sweep_evicts_idle_but_keeps_warm_and_running() {
        let (g, t) = fake();
        let (rel, log) = recorder();
        let s = settings(json!({"viewIdleEvictS": 10, "viewKeepWarmRecords": 5}));
        g.hold(&sel("idle"), Some(&s), None, Some(0), |_| ()).unwrap();
        g.hold(&sel("warm"), Some(&s), None, Some(5), |_| ()).unwrap();
        let busy = g.pin(&sel("busy"), Some(&s), None, None).unwrap();
        t.fetch_add(11, Ordering::SeqCst);
        assert_eq!(g.sweep(Some(&s), Some(&rel)), vec!["idle"]);
        assert_eq!(*log.lock().unwrap(), vec!["idle"]);
        g.unpin(&busy);
    }

    #[test]
    fn failing_release_returns_to_open_with_error() {
        let (g, _) = fake();
        g.hold(&sel("a"), None, None, None, |_| ()).unwrap();
        let bad: Release = Arc::new(|_| Err("RuntimeError: nope".into()));
        assert!(!g.evict("k-a", Some(&bad)));
        let rows = g.snapshot();
        assert_eq!(rows[0]["state"], "open");
        assert_eq!(rows[0]["error"], "RuntimeError: nope");
    }

    #[test]
    fn end_session_closes_unpinned_cold_views_only() {
        let (g, _) = fake();
        let (rel, log) = recorder();
        g.hold(&sel("a"), None, Some(rel.clone()), None, |_| ()).unwrap();
        g.hold(&sel("warm"), None, Some(rel.clone()), Some(2000), |_| ()).unwrap();
        g.hold(&sel("norelease"), None, None, None, |_| ()).unwrap();
        assert_eq!(g.end_session(None), vec!["a"]);
        assert_eq!(*log.lock().unwrap(), vec!["a"]);
    }

    #[test]
    fn delete_sweep_is_rate_limited_per_lineage() {
        let (g, t) = fake();
        assert!(g.due_for_delete_sweep("L"));
        assert!(!g.due_for_delete_sweep("L"));
        assert!(g.due_for_delete_sweep("M"));
        t.fetch_add(601, Ordering::SeqCst);
        assert!(g.due_for_delete_sweep("L"));
    }

    #[test]
    fn pin_waits_for_a_closing_view_then_reopens_it() {
        let g = Arc::new(Governor::default());
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let gc = gate.clone();
        let slow: Release = Arc::new(move |_| {
            let (m, c) = &*gc;
            let mut open = m.lock().unwrap();
            while !*open {
                open = c.wait(open).unwrap();
            }
            Ok(())
        });
        g.hold(&sel("a"), None, None, None, |_| ()).unwrap();
        let g2 = g.clone();
        let evictor = std::thread::spawn(move || g2.evict("k-a", Some(&slow)));
        while g.snapshot()[0]["state"] != "evicting" {
            std::thread::yield_now();
        }
        let g3 = g.clone();
        let pinner = std::thread::spawn(move || g3.pin(&sel("a"), None, None, None).unwrap().rebuilt);
        std::thread::sleep(Duration::from_millis(120));
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        assert!(evictor.join().unwrap());
        assert!(pinner.join().unwrap());
    }
}
