//! The options of `type_edit kind=rebase|merge|publish`, checked (`views.validate`).

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::layout::is_view_name;

pub const RESOLUTIONS: [&str; 2] = ["take_mine", "keep"];
pub const FORMAT: i64 = 1;

fn allowed(kind: &str) -> Option<&'static [&'static str]> {
    const COMMON: [&str; 3] = ["kind", "expect_revision", "resolve"];
    match kind {
        "rebase" => Some(&["kind", "expect_revision", "resolve"]),
        "merge" => Some(&[
            "kind",
            "expect_revision",
            "resolve",
            "from",
            "allow_unverified_before",
        ]),
        "publish" => Some(&[
            "kind",
            "expect_revision",
            "resolve",
            "to",
            "confirm_one_way_upgrade",
            "allow_unverified_before",
            "backup",
            "confirm_large",
        ]),
        _ => {
            let _ = COMMON;
            None
        }
    }
}

fn is_int(v: &Value) -> Option<i64> {
    match v {
        Value::Number(n) => n.as_i64(),
        _ => None,
    }
}

/// Check `options`; unknown keys are refused. Returns a copy.
pub fn validate(options: &Value) -> Result<Map<String, Value>> {
    let Value::Object(options) = options else {
        return Err(Error::value("options must be an object"));
    };
    let kind = options.get("kind").and_then(Value::as_str).unwrap_or("");
    let Some(keys) = allowed(kind) else {
        return Err(Error::value("kind must be rebase, merge or publish"));
    };
    let mut extra: Vec<&str> = options
        .keys()
        .map(String::as_str)
        .filter(|k| !keys.contains(k))
        .collect();
    if !extra.is_empty() {
        extra.sort_unstable();
        return Err(Error::value(format!(
            "options do not belong to {kind}: {}",
            extra.join(", ")
        )));
    }
    let out = options.clone();
    if !out
        .get("expect_revision")
        .and_then(is_int)
        .is_some_and(|r| r >= 0)
    {
        let who = if kind == "merge" || out.get("to").is_some_and(crate::records::truthy) {
            "destination view"
        } else {
            "view"
        };
        return Err(Error::value(format!(
            "expect_revision is required (the revision of the {who} you read)"
        )));
    }
    if kind == "merge" && !out.get("from").is_some_and(crate::records::truthy) {
        return Err(Error::value(
            "merge needs from: the view whose records are merged into this one",
        ));
    }
    for name in ["from", "to"] {
        if let Some(v) = out.get(name)
            && !v.as_str().is_some_and(|s| s == "shared" || is_view_name(s))
        {
            return Err(Error::value(format!("{name} must be a view name")));
        }
    }
    for name in [
        "confirm_one_way_upgrade",
        "allow_unverified_before",
        "confirm_large",
    ] {
        if out.get(name).is_some_and(|v| !v.is_boolean()) {
            return Err(Error::value(format!("{name} must be a boolean")));
        }
    }
    match out.get("resolve") {
        None | Some(Value::Null) => {}
        Some(Value::Object(map))
            if map
                .values()
                .all(|v| v.as_str().is_some_and(|s| RESOLUTIONS.contains(&s))) => {}
        _ => return Err(Error::value("resolve is {<subject>: take_mine | keep}")),
    }
    if out.get("backup").is_some_and(|v| !v.is_string()) {
        return Err(Error::value(
            "backup must be auto or the id of a verified backup",
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn msg(v: Value) -> String {
        validate(&v).unwrap_err().to_string()
    }

    #[test]
    fn refusals_carry_the_python_messages() {
        assert_eq!(msg(json!([])), "options must be an object");
        assert_eq!(
            msg(json!({"kind": "x"})),
            "kind must be rebase, merge or publish"
        );
        assert_eq!(
            msg(json!({"kind": "rebase", "expect_revision": 1, "zeta": 1, "alpha": 2})),
            "options do not belong to rebase: alpha, zeta"
        );
        assert_eq!(
            msg(json!({"kind": "rebase"})),
            "expect_revision is required (the revision of the view you read)"
        );
        assert_eq!(
            msg(json!({"kind": "rebase", "expect_revision": true})),
            "expect_revision is required (the revision of the view you read)"
        );
        assert_eq!(
            msg(json!({"kind": "merge", "expect_revision": 0})),
            "merge needs from: the view whose records are merged into this one"
        );
        assert_eq!(
            msg(json!({"kind": "publish", "to": "x", "expect_revision": -1})),
            "expect_revision is required (the revision of the destination view you read)"
        );
        assert_eq!(
            msg(json!({"kind": "merge", "expect_revision": 0, "from": ".bad"})),
            "from must be a view name"
        );
        assert_eq!(
            msg(json!({"kind": "publish", "expect_revision": 0, "confirm_large": 1})),
            "confirm_large must be a boolean"
        );
        assert_eq!(
            msg(json!({"kind": "rebase", "expect_revision": 0, "resolve": {"a": "nope"}})),
            "resolve is {<subject>: take_mine | keep}"
        );
        assert_eq!(
            msg(json!({"kind": "publish", "expect_revision": 0, "backup": 3})),
            "backup must be auto or the id of a verified backup"
        );
    }

    #[test]
    fn a_valid_option_set_passes_unchanged() {
        let o = json!({"kind": "merge", "expect_revision": 2, "from": "shared", "resolve": {"s": "keep"}, "allow_unverified_before": true});
        assert_eq!(Value::Object(validate(&o).unwrap()), o);
    }
}
