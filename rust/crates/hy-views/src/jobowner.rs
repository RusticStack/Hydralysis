//! Who may cancel a durable job: the client that started it (`hydralysis.jobowner`).
//!
//! Starting a job returns an owner token; the record keeps only its SHA-256 hex. Every client can read a job,
//! cancelling needs the token (a process remembers the tokens of jobs it started).

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};

use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

static TOKENS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(Default::default);

/// The caller's identity (`hydra.identity()` in Python): supplied by the host.
#[derive(Debug, Clone)]
pub struct Identity {
    pub client: String,
    pub harness: String,
}

/// Mirrors Python's `PermissionError` with the exact message.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct PermissionDenied(pub String);

fn record_id(record: &Map<String, Value>) -> String {
    for key in ["job_id", "id"] {
        match record.get(key) {
            Some(Value::String(s)) if !s.is_empty() => return s.clone(),
            Some(Value::Null) | Some(Value::Bool(false)) | None => {}
            Some(Value::String(_)) => {}
            Some(other) => return other.to_string(),
        }
    }
    String::new()
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// Make `who` the owner of a new job record (before it is written); returns the token.
pub fn issue(record: &mut Map<String, Value>, who: &Identity) -> String {
    let mut raw = [0u8; 16];
    getrandom::fill(&mut raw).expect("OS randomness");
    let token = hex::encode(raw);
    record.insert("owner".into(), json!({"client": who.client, "harness": who.harness, "token_sha256": sha256_hex(&token)}));
    TOKENS.lock().unwrap().insert(record_id(record), token.clone());
    token
}

fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Null) | None => "None".into(),
        Some(other) => other.to_string(),
    }
}

/// Refuse a cancel by anyone but the job's owner. Jobs made before owners existed are open.
pub fn check(record: &Map<String, Value>, token: &str) -> Result<(), PermissionDenied> {
    let Some(owner) = record.get("owner").and_then(Value::as_object) else {
        return Ok(());
    };
    let Some(stored) = owner.get("token_sha256").and_then(Value::as_str).filter(|s| !s.is_empty()) else {
        return Ok(());
    };
    let id = record_id(record);
    let supplied = if token.is_empty() { TOKENS.lock().unwrap().get(&id).cloned().unwrap_or_default() } else { token.to_string() };
    if !supplied.is_empty() && constant_time_eq(sha256_hex(&supplied).as_bytes(), stored.as_bytes()) {
        return Ok(());
    }
    Err(PermissionDenied(format!(
        "job {id} belongs to {} ({}); every client may read it, cancelling it needs owner, the token its start returned",
        text(owner.get("client")),
        text(owner.get("harness")),
    )))
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// A job as every client sees it: the owner's identity, never the token's hash.
pub fn public(record: &Map<String, Value>) -> Map<String, Value> {
    let mut out = record.clone();
    if let Some(Value::Object(owner)) = record.get("owner")
        && owner.contains_key("token_sha256")
    {
        let kept: Map<String, Value> = owner.iter().filter(|(k, _)| *k != "token_sha256").map(|(k, v)| (k.clone(), v.clone())).collect();
        out.insert("owner".into(), Value::Object(kept));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn who() -> Identity {
        Identity { client: "c1".into(), harness: "h1".into() }
    }

    fn rec(id: &str) -> Map<String, Value> {
        json!({"job_id": id}).as_object().unwrap().clone()
    }

    #[test]
    fn owner_can_cancel_with_remembered_or_explicit_token() {
        let mut r = rec("j-own");
        let token = issue(&mut r, &who());
        assert!(check(&r, "").is_ok());
        assert!(check(&r, &token).is_ok());
    }

    #[test]
    fn stranger_is_refused_with_python_message() {
        let mut r = rec("j-str");
        issue(&mut r, &who());
        let e = check(&r, "nope").unwrap_err();
        assert_eq!(e.0, "job j-str belongs to c1 (h1); every client may read it, cancelling it needs owner, the token its start returned");
    }

    #[test]
    fn legacy_jobs_are_open_and_public_hides_hash() {
        assert!(check(&rec("old"), "").is_ok());
        let mut r = rec("j-pub");
        issue(&mut r, &who());
        let p = public(&r);
        assert!(p["owner"].get("token_sha256").is_none());
        assert_eq!(p["owner"]["client"], "c1");
        assert!(r["owner"].get("token_sha256").is_some());
    }
}
