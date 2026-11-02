//! The MCP server: mcp.py's `Server.handle` and `Server.serve` (JSON-RPC over stdio, three lanes, cancellation, output
//! cap), with the native tools answered here and the rest delegated to the Python worker.

use crate::catalog::{granted_cpus, lane_sizes, Catalog, Lane, LaneSize};
use crate::env::{self, EnvSlot};
use crate::tools;
use crate::worker::{CallState, Worker};
use crate::{pyjson, wire};
use serde_json::{json, Map, Value};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

#[derive(Clone, PartialEq, Eq, Hash)]
enum Key {
    Int(i64),
    Text(String),
}

/// mcp.py `_request_key`: 1 and "1" are different ids; booleans and floats are not cancellable.
fn request_key(id: &Value) -> Option<Key> {
    match id {
        Value::String(text) => Some(Key::Text(text.clone())),
        Value::Number(number) if !number.is_f64() => number.as_i64().map(Key::Int),
        _ => None,
    }
}

pub struct Server {
    catalog: Catalog,
    sizes: [LaneSize; 3],
    out: Mutex<Box<dyn Write + Send>>,
    worker: Arc<Worker>,
    inflight: Mutex<HashMap<Key, Arc<CallState>>>,
    admitted: [AtomicUsize; 3],
    running_fast: (Mutex<usize>, Condvar),
    accepted: (Mutex<usize>, Condvar),
    environment: Arc<EnvSlot>,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn ok(id: &Value, result: Value) -> String {
    pyjson::dumps(&json!({"jsonrpc": "2.0", "id": id, "result": result}))
}

fn error(id: &Value, code: i64, message: &str) -> String {
    pyjson::dumps(&json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}))
}

/// `bytes.decode("utf-8", errors="ignore")`.
fn decode_ignore(mut bytes: &[u8]) -> String {
    let mut out = String::new();
    loop {
        match std::str::from_utf8(bytes) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(failure) => {
                let (valid, rest) = bytes.split_at(failure.valid_up_to());
                out.push_str(std::str::from_utf8(valid).unwrap_or(""));
                let skip = failure.error_len().unwrap_or(rest.len());
                bytes = &rest[skip..];
            }
        }
    }
}

/// mcp.py `_tool_result`: the cap on the reply, head and tail kept, the marker between them, and `isError` set.
pub fn tool_result(
    text: &str,
    mut is_error: bool,
    structured: Option<Value>,
    max_output: usize,
) -> Value {
    let encoded = text.as_bytes();
    let text = if encoded.len() > max_output {
        let marker = format!(
            "\n[OUTPUT TRUNCATED: original {} UTF-8 bytes; only the head and tail are shown within a {} -byte limit. Middle output was discarded. Narrow the query or use a smaller page.]\n",
            encoded.len(),
            max_output
        )
        .replace(" -byte", "-byte");
        let budget = max_output - marker.len();
        let head = decode_ignore(&encoded[..budget / 2]);
        let tail = decode_ignore(&encoded[encoded.len() - (budget - budget / 2)..]);
        is_error = true;
        format!("{head}{marker}{tail}")
    } else {
        text.to_string()
    };
    let mut result = Map::new();
    result.insert("content".into(), json!([{"type": "text", "text": text}]));
    result.insert("isError".into(), json!(is_error));
    if let Some(structured) = structured {
        result.insert("structuredContent".into(), structured);
    }
    Value::Object(result)
}

impl Server {
    pub fn new(out: Box<dyn Write + Send>, worker: Arc<Worker>) -> Arc<Server> {
        let catalog = Catalog::load();
        let sizes = lane_sizes(&catalog, granted_cpus());
        let environment = EnvSlot::new();
        env::resolve(
            Arc::clone(&environment),
            Arc::clone(&worker),
            catalog.version.clone(),
        );
        Arc::new(Server {
            catalog,
            sizes,
            out: Mutex::new(out),
            worker,
            inflight: Mutex::new(HashMap::new()),
            admitted: [
                AtomicUsize::new(0),
                AtomicUsize::new(0),
                AtomicUsize::new(0),
            ],
            running_fast: (Mutex::new(0), Condvar::new()),
            accepted: (Mutex::new(0), Condvar::new()),
            environment,
        })
    }

    fn write(&self, payload: &str, framed: bool) {
        let bytes = wire::encode(payload, framed);
        let mut out = lock(&self.out);
        if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
            // The client closed the pipe: nothing more can be answered.
            std::process::exit(0);
        }
    }

    fn result_of(&self, text: &str, is_error: bool, structured: Option<Value>) -> Value {
        tool_result(text, is_error, structured, self.catalog.max_output_bytes)
    }

    /// Everything but `tools/call`, which runs on a lane.
    fn handle(&self, message: &Map<String, Value>) -> Option<String> {
        let method = message.get("method").and_then(Value::as_str).unwrap_or("");
        let id = message.get("id").cloned().unwrap_or(Value::Null);
        let params = match message.get("params") {
            Some(Value::Object(map)) => map.clone(),
            _ => Map::new(),
        };
        match method {
            "initialize" => {
                let wanted = params.get("protocolVersion").and_then(Value::as_str);
                let protocol = wanted
                    .filter(|wanted| {
                        self.catalog
                            .protocol_versions
                            .iter()
                            .any(|known| known == wanted)
                    })
                    .unwrap_or(&self.catalog.protocol_versions[0])
                    .to_string();
                let client = params.get("clientInfo").and_then(Value::as_object);
                if let Some(name) = client.and_then(|client| client.get("name")) {
                    let truthy = match name {
                        Value::Null | Value::Bool(false) => false,
                        Value::String(text) => !text.is_empty(),
                        Value::Number(number) => number.as_f64() != Some(0.0),
                        Value::Array(items) => !items.is_empty(),
                        Value::Object(map) => !map.is_empty(),
                        Value::Bool(true) => true,
                    };
                    let preset = ["HYDRALYSIS_HARNESS", "RUSTICRE_HARNESS"]
                        .iter()
                        .any(|key| std::env::var(key).is_ok_and(|value| !value.is_empty()));
                    if truthy && !preset {
                        self.worker.set_harness(name.clone());
                    }
                }
                let environment = self
                    .environment
                    .get(Duration::from_secs(60), &self.catalog.version);
                Some(ok(
                    &id,
                    json!({
                        "protocolVersion": protocol,
                        "capabilities": {"tools": {"listChanged": false}},
                        "serverInfo": {"name": "hydralysis", "version": self.catalog.version},
                        "instructions": self.catalog.instructions,
                        "_meta": {"hydralysis/catalog": self.catalog.meta(), "hydralysis/environment": environment},
                    }),
                ))
            }
            "notifications/initialized" | "notifications/cancelled" => None,
            "ping" => Some(ok(&id, json!({}))),
            "tools/list" => Some(ok(&id, json!({"tools": self.catalog.tools}))),
            "resources/list" => Some(ok(&id, json!({"resources": []}))),
            "resources/templates/list" => Some(ok(&id, json!({"resourceTemplates": []}))),
            "prompts/list" => Some(ok(&id, json!({"prompts": []}))),
            _ if id.is_null() => None,
            _ => Some(error(&id, -32601, &format!("method not found: {method}"))),
        }
    }

    /// One `tools/call`: the native tool, or the worker's answer.
    fn tool_call(&self, id: &Value, params: &Map<String, Value>, state: &CallState) -> String {
        if let Some(Value::String(name)) = params.get("name") {
            if !self.catalog.tool_names.contains(name) {
                return ok(
                    id,
                    self.result_of(&format!("ValueError: unknown tool {name}"), true, None),
                );
            }
            // A panic in a native read is a bug in this host, not in the call: the worker answers it instead.
            let attempt =
                std::panic::catch_unwind(|| tools::native_call(name, params.get("arguments")));
            if let Ok(Some(text)) = attempt {
                return ok(id, self.result_of(&text, false, None));
            }
        }
        match self.worker.call(&Value::Object(params.clone()), state) {
            Ok(reply) => {
                if let Some(result) = reply.get("result") {
                    ok(id, result.clone())
                } else if let Some(failure) = reply.get("error") {
                    error(
                        id,
                        failure["code"].as_i64().unwrap_or(-32603),
                        failure["message"].as_str().unwrap_or("internal error"),
                    )
                } else {
                    error(id, -32603, "internal error")
                }
            }
            Err(why) => ok(
                id,
                self.result_of(&format!("RuntimeError: {why}"), true, None),
            ),
        }
    }

    fn admit(&self, lane: Lane) -> bool {
        let limit = self.sizes[lane.index()].outstanding;
        self.admitted[lane.index()]
            .try_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < limit).then_some(count + 1)
            })
            .is_ok()
    }

    fn run_call(
        self: Arc<Self>,
        message: Map<String, Value>,
        framed: bool,
        lane: Lane,
        state: Arc<CallState>,
        key: Option<Key>,
    ) {
        if lane == Lane::Fast {
            let (counter, signal) = &self.running_fast;
            let mut running = lock(counter);
            while *running >= self.sizes[0].workers {
                running = signal
                    .wait(running)
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
            }
            *running += 1;
        }
        if !state.cancelled.load(Ordering::SeqCst) {
            let id = message.get("id").cloned().unwrap_or(Value::Null);
            let params = match message.get("params") {
                Some(Value::Object(map)) => map.clone(),
                _ => Map::new(),
            };
            let response = self.tool_call(&id, &params, &state);
            // MCP: no response for a cancelled request.
            if !state.cancelled.load(Ordering::SeqCst) {
                self.write(&response, framed);
            }
        }
        if lane == Lane::Fast {
            let (counter, signal) = &self.running_fast;
            *lock(counter) -= 1;
            signal.notify_one();
        }
        if let Some(key) = key {
            let mut inflight = lock(&self.inflight);
            if inflight
                .get(&key)
                .is_some_and(|known| Arc::ptr_eq(known, &state))
            {
                inflight.remove(&key);
            }
        }
        self.admitted[lane.index()].fetch_sub(1, Ordering::SeqCst);
        let (count, signal) = &self.accepted;
        *lock(count) -= 1;
        signal.notify_all();
    }

    fn cancelled(&self, params: Option<&Value>) {
        let Some(params) = params.and_then(Value::as_object) else {
            return;
        };
        let Some(key) = params.get("requestId").and_then(request_key) else {
            return;
        };
        let state = lock(&self.inflight).get(&key).cloned();
        if let Some(state) = state {
            let reason = params
                .get("reason")
                .and_then(Value::as_str)
                .unwrap_or("cancelled by the client")
                .to_string();
            *lock(&state.reason) = reason;
            state.cancelled.store(true, Ordering::SeqCst);
            self.worker.cancel(&state);
        }
    }

    /// Read messages until end of input, then answer every accepted call before returning.
    pub fn serve<R: BufRead>(self: &Arc<Self>, input: &mut R) {
        loop {
            let (message, framed) = match wire::read_envelope(input) {
                Ok(Some(pair)) => pair,
                Ok(None) => break,
                Err(failure) => {
                    self.write(
                        &error(
                            &Value::Null,
                            -32700,
                            &format!("parse error: {}", failure.detail),
                        ),
                        failure.framed,
                    );
                    continue;
                }
            };
            let Value::Object(message) = message else {
                self.write(&error(&Value::Null, -32600, "invalid request"), framed);
                continue;
            };
            let Some(method) = message
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                self.write(&error(&Value::Null, -32600, "invalid request"), framed);
                continue;
            };
            if message
                .get("params")
                .is_some_and(|params| !params.is_object())
            {
                self.write(
                    &error(
                        message.get("id").unwrap_or(&Value::Null),
                        -32602,
                        "params must be an object",
                    ),
                    framed,
                );
                continue;
            }
            if !message.contains_key("id") {
                // Notifications never receive replies or consume a tool slot.
                if method == "notifications/cancelled" {
                    self.cancelled(message.get("params"));
                }
                continue;
            }
            if method != "tools/call" {
                if let Some(response) = self.handle(&message) {
                    self.write(&response, framed);
                }
                continue;
            }
            let params = message.get("params").and_then(Value::as_object);
            let name = params
                .and_then(|params| params.get("name"))
                .and_then(Value::as_str);
            let lane = self
                .catalog
                .lane_of(name, params.and_then(|params| params.get("arguments")));
            if !self.admit(lane) {
                let outstanding = self.sizes[lane.index()].outstanding;
                let retry = self.catalog.retry_after_ms;
                let text = format!(
                    "Server busy: {outstanding} {} tool calls are outstanding. Retry this call in about {retry} ms (retryAfterMs={retry}), or after a result arrives.",
                    lane.name()
                );
                let structured = json!({"error": "busy", "lane": lane.name(), "outstanding": outstanding, "retryAfterMs": retry});
                let id = message.get("id").unwrap_or(&Value::Null);
                self.write(
                    &ok(id, self.result_of(&text, true, Some(structured))),
                    framed,
                );
                continue;
            }
            let state = Arc::new(CallState::default());
            let key = message.get("id").and_then(request_key);
            if let Some(key) = &key {
                lock(&self.inflight).insert(key.clone(), Arc::clone(&state));
            }
            *lock(&self.accepted.0) += 1;
            let server = Arc::clone(self);
            let spawned = std::thread::Builder::new()
                .name(format!("call-{}", lane.name()))
                .spawn(move || server.run_call(message, framed, lane, state, key));
            if spawned.is_err() {
                // Out of threads: undo the admission and say so.
                self.admitted[lane.index()].fetch_sub(1, Ordering::SeqCst);
                *lock(&self.accepted.0) -= 1;
            }
        }
        let (count, signal) = &self.accepted;
        let mut open = lock(count);
        while *open > 0 {
            open = signal
                .wait(open)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        drop(open);
        self.worker.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_text_is_untouched_and_long_text_keeps_head_and_tail() {
        let short = tool_result("hello", false, None, 128);
        assert_eq!(short["content"][0]["text"], "hello");
        assert_eq!(short["isError"], false);
        let long = "a".repeat(100) + &"é".repeat(100) + &"z".repeat(100);
        let cut = tool_result(&long, false, None, 200);
        let text = cut["content"][0]["text"].as_str().unwrap().to_string();
        assert!(text.len() <= 200);
        assert!(text.contains("[OUTPUT TRUNCATED: original 400 UTF-8 bytes; only the head and tail are shown within a 200-byte limit."));
        assert_eq!(cut["isError"], true);
    }

    #[test]
    fn decode_ignore_drops_split_characters() {
        assert_eq!(decode_ignore(&"aé".as_bytes()[..2]), "a");
        assert_eq!(decode_ignore(&"éa".as_bytes()[1..]), "a");
    }
}
