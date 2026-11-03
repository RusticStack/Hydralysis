//! Port of `hydralysis/client.py`: the in-process facade over the tool dispatch (`api.call`).
//!
//! The dispatch is a trait so the MCP host, the Python bridge or a test double can plug in. The facade keeps the
//! Python contract: `None` arguments are dropped, JSON-looking answers come back parsed, a refusal (ValueError,
//! OSError, KeyError, RuntimeError from the dispatch) becomes a [`ClientError::Rustic`] whose `result` is the
//! structured answer when the message was a JSON object.

use serde_json::{Map, Value, json};

pub const TABLE_ROWS: usize = 200;

/// A failure of the dispatch itself.
pub struct DispatchError {
    /// The Python exception class name (`ValueError`, `OSError`, `KeyError`, `RuntimeError`, or anything else).
    pub kind: String,
    pub message: String,
    /// True for the classes `Client.call` turns into `RusticError`; anything else propagates untouched.
    pub caught: bool,
    /// The original error object of a host language (a `PyErr`), handed back to the caller of the facade.
    pub fatal: Option<Box<dyn std::any::Any + Send>>,
}

impl DispatchError {
    pub fn caught(kind: &str, message: impl Into<String>) -> Self {
        Self {
            kind: kind.to_string(),
            message: message.into(),
            caught: true,
            fatal: None,
        }
    }
}

pub trait Dispatch {
    /// One tool call: `args` is a JSON object in call order.
    fn call(&self, tool: &str, args: &Value) -> Result<String, DispatchError>;
}

pub struct Rustic {
    /// `"<Kind>: <message>"`.
    pub message: String,
    pub result: Option<Value>,
    /// `str(exc.__cause__)`: the dispatch error's own message.
    pub cause: String,
    /// The dispatch's original error object (a `PyErr`), the `__cause__` of the refusal.
    pub source: Option<Box<dyn std::any::Any + Send>>,
}

pub enum ClientError {
    Rustic(Box<Rustic>),
    /// An error of the host language to re-raise as is.
    Fatal(Box<dyn std::any::Any + Send>),
    /// A plain Python-class error the facade itself raises (`ValueError`, `IndexError`).
    Plain {
        kind: &'static str,
        message: String,
    },
}

impl std::fmt::Debug for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::Rustic(r) => write!(f, "Rustic({})", r.message),
            ClientError::Fatal(_) => write!(f, "Fatal"),
            ClientError::Plain { kind, message } => write!(f, "{kind}({message})"),
        }
    }
}

/// A tool answer as data: JSON when it is JSON, else the text.
#[derive(Debug, Clone, PartialEq)]
pub enum Answer {
    Json(Value),
    Text(String),
}

/// `parse`.
pub fn parse(text: &str) -> Answer {
    let stripped = text.trim_start();
    if (stripped.starts_with('{') || stripped.starts_with('['))
        && let Ok(v) = serde_json::from_str::<Value>(text)
    {
        return Answer::Json(v);
    }
    Answer::Text(text.to_string())
}

impl Answer {
    pub fn into_value(self) -> Value {
        match self {
            Answer::Json(v) => v,
            Answer::Text(t) => Value::String(t),
        }
    }
}

pub struct Client<D: Dispatch> {
    dispatch: D,
}

type Res<T> = Result<T, ClientError>;

impl<D: Dispatch> Client<D> {
    pub fn new(dispatch: D) -> Self {
        Self { dispatch }
    }

    /// `call(tool, **args)`: None (`null`) arguments are dropped.
    pub fn call(&self, tool: &str, args: &Map<String, Value>) -> Res<Answer> {
        let kept: Map<String, Value> = args
            .iter()
            .filter(|(_, v)| !v.is_null())
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        match self.dispatch.call(tool, &Value::Object(kept)) {
            Ok(text) => Ok(parse(&text)),
            Err(e) if e.caught => {
                let answer = parse(&e.message);
                Err(ClientError::Rustic(Box::new(Rustic {
                    message: format!("{}: {}", e.kind, e.message),
                    result: match answer {
                        Answer::Json(v @ Value::Object(_)) => Some(v),
                        _ => None,
                    },
                    cause: e.message,
                    source: e.fatal,
                })))
            }
            Err(e) => Err(match e.fatal {
                Some(f) => ClientError::Fatal(f),
                None => ClientError::Plain {
                    kind: "RuntimeError",
                    message: e.message,
                },
            }),
        }
    }

    fn text_call(&self, tool: &str, args: Map<String, Value>) -> Res<String> {
        Ok(match self.call(tool, &args)? {
            Answer::Text(t) => t,
            Answer::Json(v) => v.to_string(),
        })
    }

    /// `try_query`: None when the engine answers not_found.
    pub fn try_query(
        &self,
        target: &str,
        action: &str,
        address: &str,
        options: Map<String, Value>,
    ) -> Res<Option<Value>> {
        match self.query(target, action, address, options) {
            Ok(v) => Ok(Some(v)),
            Err(ClientError::Rustic(r))
                if r.result.as_ref().and_then(|v| v.get("error_kind"))
                    == Some(&json!("not_found")) =>
            {
                Ok(None)
            }
            Err(e) => Err(e),
        }
    }

    /// `fingerprint(exe)`: the JSON object after the header lines.
    pub fn fingerprint(&self, exe: &str) -> Res<Value> {
        let text = self.text_call("fingerprint", obj(&[("exe", json!(exe))]))?;
        let at = text.find("\n{").ok_or_else(|| ClientError::Plain {
            kind: "ValueError",
            message: "substring not found".into(),
        })?;
        serde_json::from_str(&text[at + 1..]).map_err(|e| ClientError::Plain {
            kind: "ValueError",
            message: e.to_string(),
        })
    }

    /// `read(exe, address, size)`: file bytes (the last line of the answer is hex).
    pub fn read(&self, exe: &str, address: &str, size: i64) -> Res<Vec<u8>> {
        let text = self.text_call(
            "bytes",
            obj(&[
                ("exe", json!(exe)),
                ("address", json!(address)),
                ("size", json!(size)),
            ]),
        )?;
        let Some((_, last)) = text.rsplit_once('\n') else {
            return Err(ClientError::Plain {
                kind: "IndexError",
                message: "list index out of range".into(),
            });
        };
        let bytes = last.as_bytes();
        let bad = |at: usize| ClientError::Plain {
            kind: "ValueError",
            message: format!("non-hexadecimal number found in fromhex() arg at position {at}"),
        };
        let mut out = Vec::new();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_whitespace() {
                i += 1;
                continue;
            }
            if !bytes[i].is_ascii_hexdigit() {
                return Err(bad(i));
            }
            let Some(&lo) = bytes.get(i + 1) else {
                return Err(bad(bytes.len()));
            };
            if !lo.is_ascii_hexdigit() {
                return Err(bad(i + 1));
            }
            out.push(
                u8::from_str_radix(std::str::from_utf8(&bytes[i..i + 2]).unwrap_or("0"), 16)
                    .unwrap_or(0),
            );
            i += 2;
        }
        Ok(out)
    }

    /// `check_prologues`: rows checked in pages of 200 and merged.
    pub fn check_prologues(&self, exe: &str, rows: &[Value], sha256: Option<&str>) -> Res<Value> {
        if rows.is_empty() {
            return Err(ClientError::Rustic(Box::new(Rustic {
                message: "ValueError: no rows to check".into(),
                result: None,
                cause: String::new(),
                source: None,
            })));
        }
        let mut merged: Option<Value> = None;
        for page in rows.chunks(TABLE_ROWS) {
            let result = self.table(exe, page, sha256)?;
            match merged.as_mut() {
                None => merged = Some(result),
                Some(m) => {
                    if let (Some(rows), Some(extra)) =
                        (m["rows"].as_array().cloned(), result["rows"].as_array())
                    {
                        let mut all = rows;
                        all.extend(extra.iter().cloned());
                        m["rows"] = Value::Array(all);
                    }
                    for key in ["checked", "matched", "failed"] {
                        let sum = m["summary"][key].as_i64().unwrap_or(0)
                            + result["summary"][key].as_i64().unwrap_or(0);
                        m["summary"][key] = json!(sum);
                    }
                    let both = m["matched"].as_bool().unwrap_or(false)
                        && result["matched"].as_bool().unwrap_or(false);
                    m["matched"] = json!(both);
                }
            }
        }
        Ok(merged.unwrap_or(Value::Null))
    }

    fn table(&self, exe: &str, rows: &[Value], sha256: Option<&str>) -> Res<Value> {
        let args = obj(&[
            ("exe", json!(exe)),
            ("checks", Value::Array(rows.to_vec())),
            ("sha256", sha256.map_or(Value::Null, |s| json!(s))),
        ]);
        match self.call("prologue", &args) {
            Ok(a) => Ok(a.into_value()),
            Err(ClientError::Rustic(r)) => {
                match r.cause.strip_prefix("PROLOGUE TABLE MISMATCH\n") {
                    Some(rest) => serde_json::from_str(rest).map_err(|e| ClientError::Plain {
                        kind: "ValueError",
                        message: e.to_string(),
                    }),
                    None => Err(ClientError::Rustic(r)),
                }
            }
            Err(e) => Err(e),
        }
    }

    pub fn disasm(&self, exe: &str, address: &str, count: i64) -> Res<Value> {
        Ok(self
            .call(
                "disasm",
                &obj(&[
                    ("exe", json!(exe)),
                    ("address", json!(address)),
                    ("count", json!(count)),
                ]),
            )?
            .into_value())
    }

    pub fn inspect(&self, exe: &str, address: &str) -> Res<Value> {
        Ok(self
            .call(
                "inspect",
                &obj(&[("exe", json!(exe)), ("address", json!(address))]),
            )?
            .into_value())
    }

    pub fn sigscan(&self, exe: &str, pattern: &str, limit: i64) -> Res<Value> {
        Ok(self
            .call(
                "sigscan",
                &obj(&[
                    ("exe", json!(exe)),
                    ("pattern", json!(pattern)),
                    ("limit", json!(limit)),
                ]),
            )?
            .into_value())
    }

    /// `query`: `limit`, `cursor`, `contains` and `timeout_s` are top level (an export keeps only `timeout_s` there).
    pub fn query(
        &self,
        target: &str,
        action: &str,
        address: &str,
        mut options: Map<String, Value>,
    ) -> Res<Value> {
        let lifted: &[&str] = if action == "export" {
            &["timeout_s"]
        } else {
            &["limit", "cursor", "contains", "timeout_s"]
        };
        let mut top = Vec::new();
        for key in lifted {
            if let Some(v) = options.shift_remove(*key) {
                top.push((*key, v));
            }
        }
        let mut args = obj(&[
            ("target", json!(target)),
            ("action", json!(action)),
            ("address", json!(address)),
            (
                "options",
                if options.is_empty() {
                    Value::Null
                } else {
                    Value::Object(options)
                },
            ),
        ]);
        for (k, v) in top {
            args.insert(k.to_string(), v);
        }
        Ok(self.call("ghidra_query", &args)?.into_value())
    }

    pub fn runtime(&self, action: &str, options: Value) -> Res<Value> {
        Ok(self
            .call(
                "runtime",
                &obj(&[("action", json!(action)), ("options", options)]),
            )?
            .into_value())
    }

    pub fn evidence(&self, args: &Map<String, Value>) -> Res<Value> {
        Ok(self.call("evidence_list", args)?.into_value())
    }
}

fn obj(pairs: &[(&str, Value)]) -> Map<String, Value> {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_string(), v.clone()))
        .collect()
}
