/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
//! The connection: an endpoint, a JSON-lines channel, and request/response matching.
//!
//! Ported from `ghidra_session._Base` and `SocketSession`. A reader thread owns the read half
//! and routes every answer to the waiter registered for its `id` (or keeps it until the caller
//! waits), so several threads may call at once, as the Python client allows. A reply line is
//! delivered whole, and, when [`ConnectOptions::keep_raw`] is set, byte for byte beside its
//! parsed value; that is what the differential harness compares.

use std::collections::{HashMap, HashSet};
use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{Shutdown, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{RecvTimeoutError, Sender, channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::error::{Error, Result, SessionError};
use crate::version::{CLIENT_VERSION, PROTOCOL, check_compatible};

/// How long the reader thread waits in one read before it looks at `closed`.
const READ_SLICE: Duration = Duration::from_millis(500);

/// How long a `hello` may take at most (Python's `HELLO_DEADLINE_S`).
pub const HELLO_DEADLINE_S: f64 = 5.0;

/// The daemon's endpoint file: `{"host", "port", "token", ...}`.
#[derive(Debug, Clone)]
pub struct Endpoint {
    /// The address the daemon listens on (`"127.0.0.1"`).
    pub host: String,
    /// The port it listens on.
    pub port: u16,
    /// The token its `hello` requires.
    pub token: String,
    /// The whole file, for the protocol and install checks.
    pub value: Value,
}

impl Endpoint {
    /// Reads `<state>/<instance>.json`, the file `Daemon` writes and reads.
    ///
    /// # Errors
    /// [`code::IO`] when the file cannot be read; [`code::BAD_ENDPOINT`] when it is not JSON.
    pub fn read_file(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)?;
        let value: Value = serde_json::from_str(&text)?;
        Self::from_value(value)
    }

    /// Reads `<state>/<instance>.json`.
    ///
    /// # Errors
    /// As [`Endpoint::read_file`].
    pub fn from_state(state: &Path, instance: &str) -> Result<Self> {
        Self::read_file(&state.join(format!("{instance}.json")))
    }

    /// Builds one from an endpoint object.
    ///
    /// # Errors
    /// [`code::BAD_ENDPOINT`] when `host`, `port` or `token` is missing or unusable. The Python
    /// client raises `KeyError`/`ValueError` there.
    pub fn from_value(value: Value) -> Result<Self> {
        let host = value
            .get("host")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Endpoint("the endpoint has no host".to_owned()))?
            .to_owned();
        let port = value
            .get("port")
            .and_then(Value::as_u64)
            .and_then(|p| u16::try_from(p).ok())
            .filter(|p| *p != 0)
            .ok_or_else(|| Error::Endpoint("the endpoint has no usable port".to_owned()))?;
        let token = value
            .get("token")
            .and_then(Value::as_str)
            .ok_or_else(|| Error::Endpoint("the endpoint has no token".to_owned()))?
            .to_owned();
        Ok(Self {
            host,
            port,
            token,
            value,
        })
    }

    fn socket_address(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// What a connection calls itself, and how it behaves.
#[derive(Debug, Clone)]
pub struct ConnectOptions {
    /// The `client` label of the connection (`hello.client`).
    pub client: String,
    /// The `harness` label (`hello.harness`).
    pub harness: String,
    /// Run [`check_compatible`] on the answer; the Python `SocketSession` default.
    pub check: bool,
    /// Limit the `hello` wait, in seconds; `None` waits without a limit, as Python does.
    pub hello_deadline: Option<f64>,
    /// Keep each answer's raw line beside its parsed value (`call_raw`/the `call` command).
    pub keep_raw: bool,
}

impl Default for ConnectOptions {
    fn default() -> Self {
        Self {
            client: String::new(),
            harness: String::new(),
            check: true,
            hello_deadline: None,
            keep_raw: false,
        }
    }
}

impl ConnectOptions {
    /// Options for one connection, checked, with no hello deadline.
    #[must_use]
    pub fn new(client: impl Into<String>, harness: impl Into<String>) -> Self {
        Self {
            client: client.into(),
            harness: harness.into(),
            ..Self::default()
        }
    }
}

/// One whole answer: the parsed object and, when asked for, its exact line.
#[derive(Debug, Clone)]
pub struct Reply {
    /// The parsed response object.
    pub value: Value,
    /// The line exactly as the engine wrote it, including its `\n`, when `keep_raw` is set.
    pub raw: Option<String>,
}

struct Arrival {
    raw: String,
}

struct State {
    arrived: HashMap<u64, Arrival>,
    waiters: HashMap<u64, Sender<Arrival>>,
    abandoned: HashSet<u64>,
    event_lines: Vec<String>,
    closed: bool,
    /// A reply line that could not be read as the protocol promises; ends the session.
    protocol_error: Option<String>,
}

/// The callback every progress event is handed to.
type EventHandler = Arc<dyn Fn(&Value) + Send + Sync>;

/// The callback every progress event's raw line is handed to.
type RawEventHandler = Arc<dyn Fn(&str) + Send + Sync>;

struct Inner {
    stream: Mutex<TcpStream>,
    state: Mutex<State>,
    next_id: AtomicU64,
    on_event: Mutex<Option<EventHandler>>,
    on_event_raw: Mutex<Option<RawEventHandler>>,
}

/// Locks a mutex, ignoring a poison: a panic in one caller must not end the session for the
/// others (the Python client's locks have no poison either).
fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Whether a request's answer is still wanted (`Tracked`) or must be dropped (`Abandoned`,
/// used for the `cancel` a deadline sends).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendMode {
    Tracked,
    Abandoned,
}

/// A connected session: `hello` done, protocol known, requests correlated by `id`.
pub struct Session {
    inner: Arc<Inner>,
    reader: Option<JoinHandle<()>>,
    hello: Value,
    hello_raw: String,
    protocol: i64,
    endpoint: Endpoint,
    options: ConnectOptions,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session")
            .field("client", &self.options.client)
            .field("harness", &self.options.harness)
            .field("protocol", &self.protocol)
            .field("endpoint", &self.endpoint.socket_address())
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
    }
}

impl Session {
    /// Dials the endpoint, sends `hello` and checks the answer.
    ///
    /// On a socket `hello` must be the first request, with the endpoint's token; it asks for
    /// protocol [`PROTOCOL`] and the answer fixes what the connection speaks
    /// ([`Session::protocol`]), exactly as `SocketSession.__init__` does.
    ///
    /// # Errors
    /// [`code::IO`] when the connection fails, [`code::INCOMPATIBLE`] when the engine refuses,
    /// or a [`SessionError`] with the engine's code for an `ok:false` answer.
    pub fn connect(endpoint: Endpoint, options: &ConnectOptions) -> Result<Self> {
        let stream = TcpStream::connect(endpoint.socket_address())?;
        stream.set_nodelay(true)?;
        let read_stream = stream.try_clone()?;
        let inner = Arc::new(Inner {
            stream: Mutex::new(stream),
            state: Mutex::new(State {
                arrived: HashMap::new(),
                waiters: HashMap::new(),
                abandoned: HashSet::new(),
                event_lines: Vec::new(),
                closed: false,
                protocol_error: None,
            }),
            next_id: AtomicU64::new(0),
            on_event: Mutex::new(None),
            on_event_raw: Mutex::new(None),
        });
        let reader_inner = Arc::clone(&inner);
        let reader = thread::Builder::new()
            .name("hydra-client-reader".to_owned())
            .spawn(move || reader_loop(&reader_inner, read_stream))?;
        let mut session = Self {
            inner,
            reader: Some(reader),
            hello: Value::Null,
            hello_raw: String::new(),
            protocol: 0,
            endpoint,
            options: options.clone(),
        };
        let reply = match session.call_raw(
            "hello",
            fields([
                ("token", Value::String(session.endpoint.token.clone())),
                ("client", Value::String(options.client.clone())),
                ("harness", Value::String(options.harness.clone())),
                ("clientVersion", Value::String(CLIENT_VERSION.to_owned())),
                ("protocol", Value::from(PROTOCOL)),
            ]),
            options.hello_deadline,
        ) {
            Ok(reply) => reply,
            Err(e) => {
                session.close_ref();
                return Err(e);
            }
        };
        let hello = if reply.value.get("ok") == Some(&Value::Bool(true)) {
            reply.value.get("result").cloned().unwrap_or(Value::Null)
        } else {
            session.close_ref();
            return Err(answer_error(&reply.value));
        };
        if options.check
            && let Err(e) = check_compatible(&hello, CLIENT_VERSION, None, None)
        {
            session.close_ref();
            return Err(e);
        }
        session.protocol = hello
            .get("protocol")
            .and_then(Value::as_i64)
            .filter(|p| *p == 2 || *p == 3)
            .unwrap_or(PROTOCOL);
        session.hello = hello;
        session.hello_raw = reply.raw.unwrap_or_default();
        Ok(session)
    }

    /// The `hello` answer.
    #[must_use]
    pub fn hello(&self) -> &Value {
        &self.hello
    }

    /// The whole `hello` answer line as the engine wrote it .
    #[must_use]
    pub fn hello_raw(&self) -> &str {
        &self.hello_raw
    }

    /// The protocol this connection runs at: 2 or 3, from the `hello` answer.
    #[must_use]
    pub fn protocol(&self) -> i64 {
        self.protocol
    }

    /// The endpoint this session dialled.
    #[must_use]
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// The labels this connection sent.
    #[must_use]
    pub fn options(&self) -> &ConnectOptions {
        &self.options
    }

    /// The progress events received so far (Python's `events`), oldest first.
    #[must_use]
    pub fn events(&self) -> Vec<Value> {
        let state = lock(&self.inner.state);
        state
            .event_lines
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// Removes and returns the events received so far.
    pub fn take_events(&self) -> Vec<Value> {
        let mut state = lock(&self.inner.state);
        let lines = std::mem::take(&mut state.event_lines);
        lines
            .iter()
            .filter_map(|line| serde_json::from_str(line).ok())
            .collect()
    }

    /// Installs the callback every future event is handed to (Python's `on_event`).
    pub fn set_event_handler(&self, handler: impl Fn(&Value) + Send + Sync + 'static) {
        *lock(&self.inner.on_event) = Some(Arc::new(handler));
    }

    /// Installs the callback every future event's raw line is handed to; it runs on the reader thread.
    pub fn set_raw_event_handler(&self, handler: impl Fn(&str) + Send + Sync + 'static) {
        *lock(&self.inner.on_event_raw) = Some(Arc::new(handler));
    }

    /// The raw lines of the events received so far, oldest first.
    #[must_use]
    pub fn event_lines(&self) -> Vec<String> {
        lock(&self.inner.state).event_lines.clone()
    }

    /// True once the connection has ended.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        lock(&self.inner.state).closed
    }

    /// Sends one request and returns its id, without waiting.
    ///
    /// # Errors
    /// [`code::IO`] when the line cannot be written.
    pub fn send(&self, cmd: &str, fields: Map<String, Value>) -> Result<u64> {
        self.send_inner(cmd, fields, SendMode::Tracked)
    }

    /// Sends a request line the caller builds from the request id (no trailing newline); with `abandon` the
    /// answer is dropped when it arrives (`_send_request(abandon=True)`).
    ///
    /// # Errors
    /// [`code::IO`] when the line cannot be written.
    pub fn send_with(&self, abandon: bool, build: impl FnOnce(u64) -> String) -> Result<u64> {
        let rid = self.inner.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        if abandon {
            lock(&self.inner.state).abandoned.insert(rid);
        }
        let mut line = build(rid);
        line.push(char::from(b'\n'));
        let mut stream = lock(&self.inner.stream);
        stream.write_all(line.as_bytes())?;
        stream.flush()?;
        Ok(rid)
    }

    fn send_inner(&self, cmd: &str, fields: Map<String, Value>, mode: SendMode) -> Result<u64> {
        let rid = self.inner.next_id.fetch_add(1, Ordering::SeqCst) + 1;
        let mut request = Map::new();
        request.insert("id".to_owned(), Value::from(rid));
        request.insert("cmd".to_owned(), Value::String(cmd.to_owned()));
        request.extend(fields);
        if mode == SendMode::Abandoned {
            lock(&self.inner.state).abandoned.insert(rid);
        }
        let mut line = serde_json::to_string(&Value::Object(request))?;
        line.push('\n');
        let mut stream = lock(&self.inner.stream);
        stream.write_all(line.as_bytes())?;
        stream.flush()?;
        Ok(rid)
    }

    /// Waits for one request's answer and returns the whole response object.
    ///
    /// `deadline` is seconds, client side only (it is never sent). When it passes, `cancel
    /// target=<rid> parallel=true` is sent, the late answer is dropped and
    /// `SessionError("deadline_exceeded")` is raised; the connection stays usable.
    ///
    /// # Errors
    /// [`code::CLOSED`], [`code::DEADLINE_EXCEEDED`], an engine `ok:false` code, or
    /// [`code::BAD_REPLY`] when a line could not be read as the protocol promises.
    ///
    pub fn wait(&self, rid: u64, deadline: Option<f64>) -> Result<Value> {
        self.wait_reply(rid, deadline).map(|reply| reply.value)
    }

    /// [`Session::wait`] keeping the raw line.
    ///
    /// # Errors
    /// As [`Session::wait`].
    ///
    pub fn wait_reply(&self, rid: u64, deadline: Option<f64>) -> Result<Reply> {
        let raw = self.wait_line(rid, deadline)?;
        let value = serde_json::from_str(&raw)?;
        Ok(Reply {
            value,
            raw: Some(raw),
        })
    }

    /// [`Session::wait`] returning the answer's line as the engine wrote it, unparsed: the caller's JSON parser reads it
    /// (so a string with a lone surrogate escape, which Python accepts and `serde_json` does not, is not refused here).
    ///
    /// # Errors
    /// As [`Session::wait`].
    pub fn wait_line(&self, rid: u64, deadline: Option<f64>) -> Result<String> {
        let end = match deadline {
            Some(seconds) if seconds.is_finite() && seconds > 0.0 => {
                Some(Instant::now() + Duration::from_secs_f64(seconds))
            }
            Some(seconds) => {
                return Err(Error::Invalid(format!(
                    "deadline must be a positive number of seconds, not {seconds}"
                )));
            }
            None => None,
        };
        let state = Arc::clone(&self.inner);
        let rx = {
            let mut st = lock(&self.inner.state);
            if let Some(arrival) = st.arrived.remove(&rid) {
                return Ok(arrival.raw);
            }
            if let Some(problem) = st.protocol_error.clone() {
                return Err(Error::BadReply(problem));
            }
            if st.closed {
                return Err(Error::closed());
            }
            let (tx, rx) = channel();
            st.waiters.insert(rid, tx);
            rx
        };
        // One wait: the channel wakes on an answer, on close (the sender is dropped) and on the
        // deadline. A registered waiter is removed under the state lock before a cancel, which
        // is what keeps a late answer from being delivered after the deadline error.
        let received = match end {
            None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            Some(end) => {
                let left = end.saturating_duration_since(Instant::now());
                if left.is_zero() {
                    Err(RecvTimeoutError::Timeout)
                } else {
                    rx.recv_timeout(left)
                }
            }
        };
        match received {
            Ok(arrival) => Ok(arrival.raw),
            Err(RecvTimeoutError::Disconnected) => {
                let mut st = lock(&state.state);
                if let Some(arrival) = st.arrived.remove(&rid) {
                    return Ok(arrival.raw);
                }
                if let Some(problem) = st.protocol_error.clone() {
                    return Err(Error::BadReply(problem));
                }
                Err(Error::closed())
            }
            Err(RecvTimeoutError::Timeout) => {
                let deadline_s = deadline.unwrap_or(0.0);
                let mut st = lock(&state.state);
                if let Some(arrival) = st.arrived.remove(&rid) {
                    return Ok(arrival.raw);
                }
                if st.closed {
                    return Err(Error::closed());
                }
                // Still registered: take the waiter out and, still under the lock, look once
                // more, so an answer routed just now is not lost to the timeout.
                st.waiters.remove(&rid);
                if let Ok(arrival) = rx.try_recv() {
                    return Ok(arrival.raw);
                }
                st.abandoned.insert(rid);
                drop(st);
                let cancel = self
                    .send_inner(
                        "cancel",
                        fields([
                            ("target", Value::from(rid)),
                            ("parallel", Value::Bool(true)),
                        ]),
                        SendMode::Abandoned,
                    )
                    .ok();
                Err(Error::deadline_exceeded(deadline_s, rid, cancel))
            }
        }
    }

    /// Sends one request, waits for its answer and returns `result`.
    ///
    /// # Errors
    /// As [`Session::wait`], plus [`code::BAD_REPLY`] for an `ok:true` answer with no `result`.
    ///
    pub fn call(
        &self,
        cmd: &str,
        fields: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Value> {
        check_deadline(deadline)?;
        let rid = self.send(cmd, fields)?;
        let response = self.wait(rid, deadline)?;
        if response.get("ok") == Some(&Value::Bool(true)) {
            response.get("result").cloned().ok_or_else(|| {
                Error::BadReply(format!("the answer to request {rid} has no result"))
            })
        } else {
            Err(answer_error(&response))
        }
    }

    /// Like [`Session::call`] but returns the whole response: `result` plus `stale`,
    /// `refreshed`, `ms` and the rest.
    ///
    /// # Errors
    /// As [`Session::call`].
    ///
    pub fn call_raw(
        &self,
        cmd: &str,
        fields: Map<String, Value>,
        deadline: Option<f64>,
    ) -> Result<Reply> {
        check_deadline(deadline)?;
        let rid = self.send(cmd, fields)?;
        self.wait_reply(rid, deadline)
    }

    /// Re-dials a fresh endpoint: the daemon may have restarted between the two, so the caller
    /// re-reads the endpoint file. This client's ids start again at 1 on the new connection,
    /// as a new `SocketSession` does.
    ///
    /// # Errors
    /// As [`Session::connect`].
    pub fn reconnect(self, endpoint: Endpoint, options: &ConnectOptions) -> Result<Self> {
        drop(self);
        Self::connect(endpoint, options)
    }

    /// Shuts the connection down and waits for the reader thread.
    pub fn close(mut self) {
        self.shutdown();
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }

    /// Shuts the connection down through a shared reference; the reader thread ends by itself.
    pub fn close_ref(&self) {
        self.shutdown();
    }

    fn shutdown(&self) {
        let _ = self
            .inner
            .stream
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .shutdown(Shutdown::Both);
        let mut state = lock(&self.inner.state);
        state.closed = true;
        state.waiters.clear();
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        // The reader may be waiting for the interpreter lock this thread holds (an event handler), so it is not joined.
        self.shutdown();
    }
}

/// Validates a client-side deadline the way `_check_deadline` does, before anything is sent.
fn check_deadline(deadline: Option<f64>) -> Result<()> {
    match deadline {
        Some(seconds) if seconds.is_finite() && seconds > 0.0 => Ok(()),
        Some(seconds) => Err(Error::Invalid(format!(
            "deadline must be a positive number of seconds, not {seconds}"
        ))),
        None => Ok(()),
    }
}

/// A request's field map from pairs; a tiny helper so call sites read like the Python kwargs.
#[must_use]
pub fn fields(pairs: impl IntoIterator<Item = (&'static str, Value)>) -> Map<String, Value> {
    pairs
        .into_iter()
        .map(|(key, value)| (key.to_owned(), value))
        .collect()
}

fn answer_error(response: &Value) -> Error {
    let error = response.get("error").cloned().unwrap_or(Value::Null);
    Error::Session(SessionError::from_error_object(&error))
}

fn reader_loop(inner: &Arc<Inner>, stream: TcpStream) {
    // A read that finds nothing for READ_SLICE looks at `closed` and goes on: a peer that never answers a shutdown (a
    // wedged daemon) must not keep this thread, and the socket, alive for good. Bytes of an unfinished line stay in `line`.
    let _ = stream.set_read_timeout(Some(READ_SLICE));
    let mut reader = BufReader::new(stream);
    let mut line = Vec::new();
    loop {
        match reader.read_until(b'\n', &mut line) {
            Ok(0) => break,
            Err(e)
                if matches!(
                    e.kind(),
                    ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted
                ) =>
            {
                if lock(&inner.state).closed {
                    break;
                }
            }
            Err(_) => break,
            Ok(_) => {
                let text = String::from_utf8_lossy(&line);
                let handled = handle_line(inner, text.as_ref());
                line.clear();
                if let Err(problem) = handled {
                    let mut state = lock(&inner.state);
                    state.protocol_error = Some(problem);
                    break;
                }
            }
        }
    }
    close_state(inner);
}

fn handle_line(inner: &Arc<Inner>, line: &str) -> std::result::Result<(), String> {
    let trimmed = line.trim_start();
    if trimmed.is_empty() || !trimmed.starts_with('{') {
        // Not protocol (a JVM message on stdout); ignore, as the Python client does.
        return Ok(());
    }
    let top = scan_top(trimmed)
        .ok_or_else(|| format!("a reply line is not a JSON object: {}", line.trim()))?;
    if top.event && !top.ok {
        let mut state = lock(&inner.state);
        state.event_lines.push(line.to_owned());
        drop(state);
        let handler = lock(&inner.on_event).clone();
        if let Some(handler) = handler
            && let Ok(value) = serde_json::from_str::<Value>(line)
        {
            handler(&value);
        }
        let handler = lock(&inner.on_event_raw).clone();
        if let Some(handler) = handler {
            handler(line);
        }
        return Ok(());
    }
    let Some(id) = top.id else {
        // The Python client keeps such a line under `_pending[None]`, where it can never be
        // matched; ignoring it is the same from every caller's point of view.
        return Ok(());
    };
    let mut state = lock(&inner.state);
    if state.abandoned.remove(&id) {
        return Ok(());
    }
    let arrival = Arrival {
        raw: line.to_owned(),
    };
    if let Some(waiter) = state.waiters.remove(&id) {
        drop(state);
        if waiter.send(arrival).is_err() {
            // The waiter gave up between its last check and this line; the answer is unwanted.
        }
        return Ok(());
    }
    state.arrived.insert(id, arrival);
    Ok(())
}

/// The three top-level members a reply is routed by.
struct Top {
    id: Option<u64>,
    event: bool,
    ok: bool,
}

/// Reads the top-level members of one JSON object line without building it: `id` (when a non-negative integer), and whether
/// `event` and `ok` are present. Nested values and strings are skipped, whatever they hold (a lone surrogate escape,
/// which `json.loads` accepts); `None` when the line is not an object.
fn scan_top(line: &str) -> Option<Top> {
    let bytes = line.as_bytes();
    let mut at = 0;
    let skip_space = |at: &mut usize| {
        while *at < bytes.len() && matches!(bytes[*at], b' ' | b'\t' | b'\r' | b'\n') {
            *at += 1;
        }
    };
    skip_space(&mut at);
    if bytes.get(at) != Some(&b'{') {
        return None;
    }
    at += 1;
    let mut top = Top {
        id: None,
        event: false,
        ok: false,
    };
    skip_space(&mut at);
    if bytes.get(at) == Some(&b'}') {
        return Some(top);
    }
    loop {
        skip_space(&mut at);
        let key_start = at + 1;
        at = skip_string(bytes, at)?;
        let key = &bytes[key_start..at - 1];
        skip_space(&mut at);
        if bytes.get(at) != Some(&b':') {
            return None;
        }
        at += 1;
        skip_space(&mut at);
        match key {
            b"event" => top.event = true,
            b"ok" => top.ok = true,
            b"id" => {
                let digits = bytes[at..]
                    .iter()
                    .take_while(|b| b.is_ascii_digit())
                    .count();
                let after = bytes.get(at + digits).copied();
                if digits > 0 && !matches!(after, Some(b'.' | b'e' | b'E')) {
                    top.id = line[at..at + digits].parse().ok();
                }
            }
            _ => {}
        }
        at = skip_value(bytes, at)?;
        skip_space(&mut at);
        match bytes.get(at)? {
            b',' => at += 1,
            b'}' => return Some(top),
            _ => return None,
        }
    }
}

/// The offset just past the string that starts at `at` (a quote).
fn skip_string(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'"') {
        return None;
    }
    let mut i = at + 1;
    while let Some(&b) = bytes.get(i) {
        match b {
            b'"' => return Some(i + 1),
            b'\\' => i += 2,
            _ => i += 1,
        }
    }
    None
}

/// The offset just past the value that starts at `at`: a string, a nested object or array (by bracket depth, strings
/// skipped), or a bare literal or number up to the next `,` or `}`.
fn skip_value(bytes: &[u8], at: usize) -> Option<usize> {
    match bytes.get(at)? {
        b'"' => skip_string(bytes, at),
        b'{' | b'[' => {
            let mut depth = 0usize;
            let mut i = at;
            while let Some(&b) = bytes.get(i) {
                match b {
                    b'"' => {
                        i = skip_string(bytes, i)?;
                        continue;
                    }
                    b'{' | b'[' => depth += 1,
                    b'}' | b']' => {
                        depth = depth.checked_sub(1)?;
                        if depth == 0 {
                            return Some(i + 1);
                        }
                    }
                    _ => {}
                }
                i += 1;
            }
            None
        }
        _ => {
            let mut i = at;
            while let Some(&b) = bytes.get(i) {
                if matches!(b, b',' | b'}' | b']' | b' ' | b'\t' | b'\r' | b'\n') {
                    break;
                }
                i += 1;
            }
            (i > at).then_some(i)
        }
    }
}

fn close_state(inner: &Arc<Inner>) {
    let mut state = lock(&inner.state);
    state.closed = true;
    state.waiters.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn endpoint_requires_host_port_token() {
        let e = Endpoint::from_value(json!({"host": "127.0.0.1", "port": 1, "token": "t"}))
            .expect("a complete endpoint");
        assert_eq!(e.socket_address(), "127.0.0.1:1");
        for bad in [
            json!({"port": 1, "token": "t"}),
            json!({"host": "h", "token": "t"}),
            json!({"host": "h", "port": 1}),
            json!({"host": "h", "port": 70000, "token": "t"}),
            json!({"host": "h", "port": 0, "token": "t"}),
        ] {
            assert!(Endpoint::from_value(bad.clone()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_top_level_scan_finds_id_event_and_ok_and_skips_the_rest() {
        let top = scan_top(r#" {"x": {"id": 9, "a": [1, "}", {"b": "\\"}]}, "id": 12, "ok": true, "s": "a\ud800b"}"#).expect("an object");
        assert_eq!((top.id, top.event, top.ok), (Some(12), false, true));
        let top = scan_top(r#"{"event":"progress","message":"m"}"#).expect("an object");
        assert_eq!((top.id, top.event, top.ok), (None, true, false));
        let top = scan_top(r#"{"id": 1.5, "ok": false}"#).expect("an object");
        assert_eq!(top.id, None);
        assert!(
            scan_top("[1]").is_none()
                && scan_top(r#"{"id": 1"#).is_none()
                && scan_top("{").is_none()
        );
        assert!(scan_top("{}").is_some());
    }

    #[test]
    fn fields_helper_builds_a_json_object() {
        let f = fields([("a", Value::from(1)), ("b", Value::Bool(true))]);
        assert_eq!(Value::Object(f), json!({"a": 1, "b": true}));
    }
}
