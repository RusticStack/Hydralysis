//! The stdio transport of mcp.py: newline-delimited JSON, with `Content-Length` framed input answered in kind.

use serde_json::Value;
use std::io::{BufRead, Read};

/// A message that could not be parsed. `framed` says how to answer it.
#[derive(Debug)]
pub struct ParseError {
    pub detail: String,
    pub framed: bool,
}

/// The next message and whether it arrived framed; `Ok(None)` at end of input.
pub fn read_envelope<R: BufRead>(input: &mut R) -> Result<Option<(Value, bool)>, ParseError> {
    let mut first = Vec::new();
    loop {
        first.clear();
        match input.read_until(b'\n', &mut first) {
            Ok(0) | Err(_) => return Ok(None),
            Ok(_) => {}
        }
        if !first.iter().all(u8::is_ascii_whitespace) {
            break;
        }
    }
    let framed = first.len() >= 15 && first[..15].eq_ignore_ascii_case(b"content-length:");
    let fail = |detail: String| ParseError { detail, framed };
    let body: Vec<u8> = if framed {
        let value = String::from_utf8_lossy(&first[15..]).trim().to_string();
        let length: i64 = value.parse().map_err(|_| {
            fail(format!(
                "invalid literal for int() with base 10: b'{value}'"
            ))
        })?;
        if length < 0 {
            return Err(fail("negative Content-Length".to_string()));
        }
        loop {
            let mut line = Vec::new();
            match input.read_until(b'\n', &mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    if line == b"\r\n" || line == b"\n" {
                        break;
                    }
                }
            }
        }
        let mut body = Vec::new();
        let _ = input.by_ref().take(length as u64).read_to_end(&mut body);
        if body.len() as i64 != length {
            return Err(fail("incomplete Content-Length body".to_string()));
        }
        body
    } else {
        first.trim_ascii().to_vec()
    };
    match serde_json::from_slice::<Value>(&body) {
        // JSON null is not EOF; let the request validator reject it.
        Ok(Value::Null) => Ok(Some((Value::Array(Vec::new()), framed))),
        Ok(message) => Ok(Some((message, framed))),
        Err(error) => {
            let text = error.to_string();
            let what = if text.starts_with("expected value") || text.starts_with("EOF") {
                "Expecting value".to_string()
            } else if text.starts_with("trailing characters") {
                "Extra data".to_string()
            } else {
                text.split(" at line").next().unwrap_or(&text).to_string()
            };
            let column = error.column().max(1);
            Err(fail(format!(
                "{what}: line {} column {column} (char {})",
                error.line(),
                column - 1
            )))
        }
    }
}

/// The bytes written for one response: a line, or `Content-Length` framed.
pub fn encode(payload: &str, framed: bool) -> Vec<u8> {
    if framed {
        let mut out = format!("Content-Length: {}\r\n\r\n", payload.len()).into_bytes();
        out.extend_from_slice(payload.as_bytes());
        out
    } else {
        let mut out = payload.as_bytes().to_vec();
        out.push(b'\n');
        out
    }
}
