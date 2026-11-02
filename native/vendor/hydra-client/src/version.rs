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
//! Protocol constants, negotiation and compatibility, ported from `ghidra_session.py` 1.1.0
//! (`PROTOCOL`, `check_compatible`, `engine_protocols`, `Daemon._check_install`) and, for the
//! server side of the decision, from `Client.requestedProtocol` (Java).

use std::path::Path;

use serde_json::Value;

use crate::error::{Error, SessionError, code};

/// The protocol this client asks for: 3, the highest it speaks.
pub const PROTOCOL: i64 = 3;
/// The lowest protocol this client speaks; an engine at 2 is accepted and answered as 2.
pub const PROTOCOL_MIN: i64 = 2;
/// The `ghidra_session.py` version this port identifies as. The engine echoes it in `status`
/// and compares it with its `minClient`, so it must not be bumped without the Python client.
pub const CLIENT_VERSION: &str = "1.1.0";

/// The protocol range one client accepts.
///
/// `protocol` alone (no `protocol_min`) is exactly that one protocol, which is the form the
/// 1.0.0 client's `check_compatible(protocol=...)` used; both absent is `PROTOCOL_MIN..PROTOCOL`.
#[must_use]
pub fn client_range(protocol: Option<i64>, protocol_min: Option<i64>) -> (i64, i64) {
    let hi = protocol.unwrap_or(PROTOCOL);
    let lo = match protocol_min {
        Some(lo) => lo,
        None if protocol.is_none() => PROTOCOL_MIN.min(hi),
        None => hi,
    };
    (lo, hi)
}

/// `"2"` for a single protocol, `"2..3"` for a range.
#[must_use]
pub fn span(lo: i64, hi: i64) -> String {
    if lo == hi {
        lo.to_string()
    } else {
        format!("{lo}..{hi}")
    }
}

/// True for a JSON integer: a bool, a string or a float is not a protocol number
/// (`_is_protocol`).
#[must_use]
pub fn is_protocol(v: Option<&Value>) -> bool {
    matches!(v, Some(Value::Number(n)) if n.is_i64() || n.is_u64())
}

fn protocol_i64(v: &Value) -> Option<i64> {
    if !is_protocol(Some(v)) {
        return None;
    }
    v.as_i64()
        .or_else(|| v.as_u64().and_then(|u| i64::try_from(u).ok()))
}

/// The protocols an engine says it serves, from a `hello` answer, a `ready` event or an
/// endpoint file: `protocolMin`..`protocolMax` when it sends them, else the single
/// `protocol`. `None` when there is no usable integer (`engine_protocols`).
#[must_use]
pub fn engine_protocols(info: &Value) -> Option<(i64, i64)> {
    let p = info.get("protocol");
    let lo = info.get("protocolMin").or(p);
    let hi = info.get("protocolMax").or(p);
    Some((protocol_i64(lo?)?, protocol_i64(hi?)?))
}

/// The protocol a `hello` asks for, as the engine answers it (`Client.requestedProtocol` in
/// Java): the requested value when it lies in `PROTOCOL_MIN..PROTOCOL_MAX`, `PROTOCOL_MAX` when
/// it is larger, and `PROTOCOL_MIN` when the field is absent, smaller, or not a JSON integer.
///
/// This is the server's rule; a client only needs it to predict an answer or to build a fake
/// engine in tests.
#[must_use]
pub fn requested_protocol(hello: &Value) -> i64 {
    const MAX: i64 = 3;
    let Some(v) = hello.get("protocol") else {
        return PROTOCOL_MIN;
    };
    let Some(n) = v.as_number() else {
        return PROTOCOL_MIN;
    };
    // Java reads the primitive's text and requires -?[0-9]+ before parsing a BigInteger.
    let text = n.to_string();
    if !is_decimal_integer(&text) {
        return PROTOCOL_MIN;
    }
    let Ok(value) = text.parse::<i128>() else {
        // A magnitude beyond i128 is still "larger than MAX" or "smaller than MIN" by its sign.
        return if text.starts_with('-') {
            PROTOCOL_MIN
        } else {
            MAX
        };
    };
    if value >= i128::from(MAX) {
        MAX
    } else if value <= i128::from(PROTOCOL_MIN) {
        PROTOCOL_MIN
    } else {
        i64::try_from(value).unwrap_or(PROTOCOL_MIN)
    }
}

fn is_decimal_integer(text: &str) -> bool {
    let digits = text.strip_prefix('-').unwrap_or(text);
    !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_digit())
}

/// Python's `repr` of a JSON scalar, for the messages below (`None`, `True`, `'3'`, `2.0`).
fn python_repr(v: Option<&Value>) -> String {
    match v {
        None | Some(Value::Null) => "None".to_owned(),
        Some(Value::Bool(true)) => "True".to_owned(),
        Some(Value::Bool(false)) => "False".to_owned(),
        Some(Value::String(s)) => format!("'{}'", s.replace('\\', "\\\\").replace('\'', "\\'")),
        Some(Value::Number(n)) => n.to_string(),
        Some(other) => other.to_string(),
    }
}

/// The engine's identity, as `check_compatible` prints it.
fn who(info: &Value) -> String {
    let hydra = info
        .get("hydraVersion")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("?");
    let ghidra = info
        .get("ghidraVersion")
        .or_else(|| info.get("ghidra"))
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .unwrap_or("?");
    format!("Hydra Engine {hydra} (Ghidra {ghidra})")
}

/// `check_compatible`: a `hello` answer, a `ready` event or an endpoint against this client.
///
/// The answer's `protocol` must lie in `PROTOCOL_MIN..PROTOCOL` (`protocol` alone, when given
/// without `protocol_min`, means exactly that protocol) and, when the engine advertises
/// `protocolMin` and `protocolMax`, that range must overlap the client's and contain the
/// answer. A session that reports no `minClient` is accepted when the protocol fits.
///
/// # Errors
/// [`code::INCOMPATIBLE`] with both versions named, exactly as the Python client words it.
pub fn check_compatible(
    info: &Value,
    client_version: &str,
    protocol: Option<i64>,
    protocol_min: Option<i64>,
) -> Result<(), Error> {
    let theirs = info.get("protocol");
    let (lo, hi) = client_range(protocol, protocol_min);
    let who = who(info);
    let mine = format!(
        "this client (ghidra_session.py {client_version}) speaks {}",
        span(lo, hi)
    );
    let advertised = engine_protocols(info);
    let mut said = format!("protocol {}", python_repr(theirs));
    if let Some((alo, ahi)) = advertised
        && (protocol_i64(theirs.unwrap_or(&Value::Null)) != Some(alo) || alo != ahi)
    {
        said.push_str(" (advertises ");
        said.push_str(&span(alo, ahi));
        said.push(')');
    }
    let incompatible =
        |message: String| Error::Session(SessionError::new(code::INCOMPATIBLE, message));
    let fits = theirs
        .and_then(protocol_i64)
        .is_some_and(|t| lo <= t && t <= hi);
    if !fits {
        return Err(incompatible(format!(
            "{who} speaks {said}, {mine}: use the client of the same release as the engine"
        )));
    }
    let Some((alo, ahi)) = advertised else {
        return Err(incompatible(format!(
            "{who} reports an unreadable protocolMin or protocolMax"
        )));
    };
    let t = theirs.and_then(protocol_i64).unwrap_or(lo);
    if ahi < lo || alo > hi || !(alo <= t && t <= ahi) {
        return Err(incompatible(format!(
            "{who} speaks {said} but its range does not fit, {mine}: use the client of the \
             same release as the engine"
        )));
    }
    if let Some(need) = info.get("minClient").and_then(Value::as_str)
        && !need.is_empty()
    {
        let need_v = parse_version(need).ok_or_else(|| {
            incompatible(format!(
                "{who} reports an unreadable minClient: not a dotted version: {need:?}"
            ))
        })?;
        let mine_v = parse_version(client_version).ok_or_else(|| {
            incompatible(format!(
                "{who} reports an unreadable minClient: not a dotted version: {client_version:?}"
            ))
        })?;
        if mine_v < need_v {
            return Err(incompatible(format!(
                "{who} requires a client of at least {need}, this is ghidra_session.py \
                 {client_version}: upgrade the client to the one released with the engine"
            )));
        }
    }
    Ok(())
}

/// `"1.2.3"` as `(1, 2, 3)`; anything else is `None` (Python raises `ValueError`), so callers
/// can keep `check_compatible`'s message.
#[must_use]
pub fn parse_version(text: &str) -> Option<Vec<u64>> {
    let parts: Vec<&str> = text.trim().split('.').collect();
    if parts.is_empty()
        || !parts
            .iter()
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    parts.iter().map(|p| p.parse().ok()).collect()
}

/// The endpoint half of `Daemon._check_install`: the daemon must serve a protocol that overlaps
/// this client's range, and, when it names an install, that install must be the one given.
///
/// # Errors
/// [`code::INCOMPATIBLE`] for the protocol, [`code::BAD_ENDPOINT`] for another install, with the
/// Python client's wording.
pub fn check_endpoint(
    endpoint: &Value,
    instance: &str,
    install_dir: Option<&Path>,
) -> Result<(), Error> {
    if let (Some(their), Some(ours)) =
        (endpoint.get("install").and_then(Value::as_str), install_dir)
    {
        let their_path = Path::new(their);
        let same = their_path
            .canonicalize()
            .ok()
            .zip(ours.canonicalize().ok())
            .is_some_and(|(a, b)| paths_equal(&a, &b));
        if !same {
            return Err(Error::Endpoint(format!(
                "the {instance:?} daemon runs {their} (Ghidra {}), not {}; stop it, or use \
                 another --instance",
                endpoint
                    .get("ghidra")
                    .and_then(Value::as_str)
                    .unwrap_or("?"),
                ours.display()
            )));
        }
    }
    let (lo, hi) = client_range(None, None);
    let served = engine_protocols(endpoint);
    let ok = served.is_some_and(|(alo, ahi)| ahi >= lo && alo <= hi);
    if !ok {
        let speaks = served.map_or_else(
            || python_repr(endpoint.get("protocol")),
            |(alo, ahi)| span(alo, ahi),
        );
        return Err(Error::Session(SessionError::new(
            code::INCOMPATIBLE,
            format!(
                "the {instance:?} daemon speaks protocol {speaks}, this client \
                 (ghidra_session.py {CLIENT_VERSION}) speaks {}; stop it first",
                span(lo, hi)
            ),
        )));
    }
    Ok(())
}

/// Windows compares paths case-insensitively; `std::path::Path` does not.
fn paths_equal(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.to_string_lossy()
            .eq_ignore_ascii_case(&b.to_string_lossy())
    } else {
        a == b
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Ported from examples/client_compat_tests.py `t_check_compatible` (the ok/bad tables).
    #[test]
    fn check_compatible_table_of_accepted_answers() {
        let ok = [
            json!({"protocol": 2}),
            json!({"protocol": 3}),
            json!({"protocol": 2, "minClient": "1.0.0"}),
            json!({"protocol": 3, "minClient": CLIENT_VERSION}),
            json!({"protocol": 3, "protocolMin": 2, "protocolMax": 3}),
            json!({"protocol": 2, "protocolMin": 2, "protocolMax": 3}),
            json!({"protocol": 3, "protocolMin": 2, "protocolMax": 9}),
        ];
        for info in ok {
            check_compatible(&info, CLIENT_VERSION, None, None)
                .unwrap_or_else(|e| panic!("{info} should be accepted: {e}"));
        }
    }

    #[test]
    fn check_compatible_table_of_refused_answers() {
        let bad = [
            json!({}),
            json!({"protocol": 1}),
            json!({"protocol": 4}),
            json!({"protocol": null}),
            json!({"protocol": true}),
            json!({"protocol": "3"}),
            json!({"protocol": 2.0}),
            json!({"protocol": 2, "protocolMax": 1}),
            json!({"protocol": 3, "protocolMin": 4, "protocolMax": 5}),
            json!({"protocol": 3, "protocolMin": 2, "protocolMax": 2}),
            json!({"protocol": 2, "protocolMax": "x"}),
            json!({"protocol": 2, "protocolMin": 3, "protocolMax": 3}),
            json!({"protocol": 3, "minClient": "99.0.0"}),
            json!({"protocol": 2, "minClient": "x"}),
        ];
        for info in bad {
            let e = check_compatible(&info, CLIENT_VERSION, None, None)
                .expect_err(&format!("{info} should be refused"));
            assert_eq!(e.code(), code::INCOMPATIBLE, "{info}");
        }
    }

    #[test]
    fn check_compatible_exact_protocol_form_is_one_protocol() {
        check_compatible(&json!({"protocol": 2}), CLIENT_VERSION, Some(2), None).unwrap();
        assert!(check_compatible(&json!({"protocol": 3}), CLIENT_VERSION, Some(2), None).is_err());
        assert!(check_compatible(&json!({"protocol": 2}), CLIENT_VERSION, Some(3), None).is_err());
        check_compatible(&json!({"protocol": 2}), CLIENT_VERSION, Some(3), Some(2)).unwrap();
    }

    #[test]
    fn an_unknown_version_answer_names_both_sides() {
        let e = check_compatible(
            &json!({"protocol": 4, "hydraVersion": "9.9-hydra.1", "ghidraVersion": "9.9"}),
            CLIENT_VERSION,
            None,
            None,
        )
        .expect_err("protocol 4");
        let msg = e.to_string();
        for part in [
            "9.9-hydra.1",
            "speaks protocol 4",
            "speaks 2..3",
            CLIENT_VERSION,
        ] {
            assert!(msg.contains(part), "message lacks {part:?}: {msg}");
        }
    }

    // Ported from `t_protocol_below_range`.
    #[test]
    fn a_contradictory_engine_is_refused_with_both_versions_named() {
        let answers = [
            json!({"protocol": 1, "protocolMin": 1, "protocolMax": 1}),
            json!({"protocol": 2, "protocolMin": 1, "protocolMax": 1}),
            json!({"protocol": 3, "protocolMax": 1}),
        ];
        for extra in answers {
            let mut info = json!({"protocol": 2, "minClient": "1.0.0",
                                  "hydraVersion": "9.9-hydra.1", "ghidraVersion": "12.3"});
            if let (Some(dst), Some(src)) = (info.as_object_mut(), extra.as_object()) {
                dst.extend(src.clone());
            }
            let e = check_compatible(&info, CLIENT_VERSION, None, None)
                .expect_err("below range should be refused");
            let msg = e.to_string();
            assert!(msg.contains("9.9-hydra.1"), "{msg}");
            assert!(
                msg.contains(&format!("ghidra_session.py {CLIENT_VERSION}")),
                "{msg}"
            );
            assert!(msg.contains("speaks protocol"), "{msg}");
            assert!(msg.contains("2..3"), "{msg}");
        }
    }

    // Ported from `t_endpoint_overlap` (the protocol and install checks, without the daemon).
    #[test]
    fn endpoint_overlap_accepts_any_overlap_of_the_range() {
        let ok = [
            json!({"protocol": 2}),
            json!({"protocol": 3}),
            json!({"protocol": 2, "protocolMin": 2, "protocolMax": 3}),
            json!({"protocol": 3, "protocolMin": 3, "protocolMax": 4}),
            json!({"protocol": 1, "protocolMin": 1, "protocolMax": 2}),
            json!({"protocol": 2, "protocolMin": 2, "protocolMax": 9}),
        ];
        for ep in ok {
            check_endpoint(&ep, "cc", None)
                .unwrap_or_else(|e| panic!("{ep} should be accepted: {e}"));
        }
        let bad = [
            json!({}),
            json!({"protocol": 1}),
            json!({"protocol": 4}),
            json!({"protocol": "2"}),
            json!({"protocol": true}),
            json!({"protocol": 2, "protocolMax": 1}),
            json!({"protocol": 4, "protocolMin": 4, "protocolMax": 5}),
        ];
        for ep in bad {
            let e = check_endpoint(&ep, "cc", None).expect_err(&format!("{ep} should be refused"));
            assert!(
                matches!(e.code(), code::INCOMPATIBLE | code::BAD_ENDPOINT),
                "{ep}: {e}"
            );
        }
    }

    // Ported from `t_fake_v2_server` / `t_fake_v3_server`'s server side.
    #[test]
    fn requested_protocol_matches_the_engine_rule() {
        assert_eq!(requested_protocol(&json!({})), 2);
        assert_eq!(requested_protocol(&json!({"protocol": 3})), 3);
        assert_eq!(requested_protocol(&json!({"protocol": 2})), 2);
        assert_eq!(requested_protocol(&json!({"protocol": 1})), 2);
        assert_eq!(requested_protocol(&json!({"protocol": 99})), 3);
        assert_eq!(requested_protocol(&json!({"protocol": null})), 2);
        assert_eq!(requested_protocol(&json!({"protocol": true})), 2);
        assert_eq!(requested_protocol(&json!({"protocol": "3"})), 2);
        assert_eq!(requested_protocol(&json!({"protocol": 2.0})), 2);
        // A magnitude beyond i64 is still larger than MAX by its text; serde_json refuses to
        // hold such a literal at all, which the Java engine accepts (see PORTING.md).
        assert_eq!(requested_protocol(&json!({"protocol": i64::MAX})), 3);
    }

    #[test]
    fn version_parsing_rejects_non_dotted_text() {
        assert_eq!(parse_version("1.2.3"), Some(vec![1, 2, 3]));
        assert_eq!(parse_version(""), None);
        assert_eq!(parse_version("1..2"), None);
        assert_eq!(parse_version("1.2.x"), None);
    }

    #[test]
    fn spans_and_ranges_match_python() {
        assert_eq!(span(2, 2), "2");
        assert_eq!(span(2, 3), "2..3");
        assert_eq!(client_range(None, None), (2, 3));
        assert_eq!(client_range(Some(2), None), (2, 2));
        assert_eq!(client_range(Some(3), Some(2)), (2, 3));
    }
}
