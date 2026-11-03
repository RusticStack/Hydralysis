//! Owner-authorized runtime memory mode: the allow-list, its range check and the per-build stamp.
//! Port of `runtime_authorize.py`; the refusal codes and the validation rules are the same.
use serde_json::Value;

pub const MAX_RANGE: u64 = 1 << 20;
pub const MAX_SIZE: u64 = 64;
pub const MAX_WATCH_SIZE: u64 = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    Write,
    Watch,
}

impl Action {
    pub fn name(self) -> &'static str {
        match self {
            Action::Write => "write",
            Action::Watch => "watch",
        }
    }
}

/// A refusal with a machine-readable code; `Display` is `[code] detail`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refusal {
    pub code: &'static str,
    pub detail: String,
}

impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.code, self.detail)
    }
}
impl std::error::Error for Refusal {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Range {
    /// Lower-cased module name, or `None` for an absolute VA range.
    pub module: Option<String>,
    pub start: u64,
    pub end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Authorization {
    pub sha256: String,
    pub actions: Vec<Action>,
    pub max_size: u64,
    pub ranges: Vec<Range>,
    pub note: String,
}

/// The module a span is resolved against: name and load address.
#[derive(Clone, Debug)]
pub struct ModuleRef {
    pub name: String,
    pub base: u64,
}

fn num(v: Option<&Value>, what: &str) -> Result<u64, String> {
    let parse = |s: &str| -> Option<u64> {
        let s = s.trim();
        if let Some(h) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) { u64::from_str_radix(h, 16).ok() } else { s.parse().ok() }
    };
    match v {
        Some(Value::Number(n)) => n.as_u64().ok_or_else(|| format!("{what} is negative or not an integer")),
        Some(Value::String(s)) => parse(s).ok_or_else(|| format!("{what} is not a number: {s:?}")),
        other => Err(format!("{what} is not a number: {other:?}")),
    }
}

/// One validated entry. The error says what is wrong.
pub fn normalize(entry: &Value) -> Result<Authorization, String> {
    let obj = entry.as_object().ok_or("an authorization is an object")?;
    let sha = obj.get("sha256").and_then(Value::as_str).unwrap_or("").to_lowercase();
    if sha.len() != 64 || !sha.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)) {
        return Err("sha256 must be 64 hex characters (the exact build)".into());
    }
    let listed = obj
        .get("actions")
        .and_then(Value::as_array)
        .filter(|a| !a.is_empty())
        .ok_or("actions must be a non-empty list of write and/or watch")?;
    let mut actions = Vec::new();
    for a in listed {
        let act = match a.as_str() {
            Some("write") => Action::Write,
            Some("watch") => Action::Watch,
            _ => return Err("actions must be a non-empty list of write and/or watch".into()),
        };
        if !actions.contains(&act) {
            actions.push(act);
        }
    }
    actions.sort_by_key(|a| a.name());
    let max_size = match obj.get("max_size") {
        Some(Value::Number(n)) if n.as_u64().is_some_and(|v| (1..=MAX_SIZE).contains(&v)) => n.as_u64().unwrap(),
        _ => return Err(format!("max_size must be an integer 1..{MAX_SIZE}")),
    };
    let ranges_in =
        obj.get("ranges").and_then(Value::as_array).filter(|r| !r.is_empty()).ok_or("ranges must declare at least one bounded range")?;
    let mut ranges = Vec::new();
    for item in ranges_in {
        let r = item.as_object().ok_or("a range is an object")?;
        let (module, start, end) = if let Some(m) = r.get("module") {
            let module = m.as_str().unwrap_or("").trim().to_string();
            if module.is_empty() || r.contains_key("va_start") {
                return Err("a range is module+rva_start+rva_end or va_start+va_end".into());
            }
            (Some(module.to_lowercase()), num(r.get("rva_start"), "rva_start")?, num(r.get("rva_end"), "rva_end")?)
        } else {
            (None, num(r.get("va_start"), "va_start")?, num(r.get("va_end"), "va_end")?)
        };
        if end <= start || end - start > MAX_RANGE {
            return Err(format!("a range must be 1..{MAX_RANGE} bytes (start < end)"));
        }
        ranges.push(Range { module, start, end });
    }
    let note: String = obj.get("note").and_then(Value::as_str).unwrap_or("").chars().take(200).collect();
    Ok(Authorization { sha256: sha, actions, max_size, ranges, note })
}

/// The entry for the build, or why there is none. An invalid entry for this build is reported, never trusted.
pub fn lookup(settings: &Value, digest: &str) -> Result<Authorization, String> {
    let listed = match settings.get("runtime_authorized_targets") {
        None | Some(Value::Null) => {
            return Err("the setting runtime_authorized_targets is empty or missing".into());
        }
        Some(Value::Array(a)) if a.is_empty() => {
            return Err("the setting runtime_authorized_targets is empty or missing".into());
        }
        Some(Value::Array(a)) => a,
        Some(_) => return Err("runtime_authorized_targets must be a list".into()),
    };
    let mut problem = String::new();
    for item in listed {
        let sha = item.get("sha256").and_then(Value::as_str).unwrap_or("").to_lowercase();
        if digest.is_empty() || sha != digest {
            continue;
        }
        match normalize(item) {
            Ok(a) => return Ok(a),
            Err(e) => problem = format!("the entry for this build is invalid: {e}"),
        }
    }
    Err(if problem.is_empty() { "this build's SHA-256 is not in runtime_authorized_targets".into() } else { problem })
}

impl Authorization {
    /// Refuse unless the action, the size and the whole span are inside a declared range.
    pub fn check(&self, action: Action, address: u64, size: u64, module: Option<&ModuleRef>) -> Result<(), Refusal> {
        if !self.actions.contains(&action) {
            return Err(Refusal {
                code: "action_not_authorized",
                detail: format!(
                    "{} is not in this build's authorized actions {:?}",
                    action.name(),
                    self.actions.iter().map(|a| a.name()).collect::<Vec<_>>()
                ),
            });
        }
        let cap = if action == Action::Watch { self.max_size.min(MAX_WATCH_SIZE) } else { self.max_size };
        if size > cap {
            return Err(Refusal {
                code: "size_exceeds_authorization",
                detail: format!("{size} bytes exceeds the authorized {cap} for {}", action.name()),
            });
        }
        let name = module.map(|m| m.name.to_lowercase());
        for r in &self.ranges {
            let (lo, hi) = match (&r.module, module) {
                (None, _) => (r.start, r.end),
                (Some(m), Some(mr)) if name.as_deref() == Some(m.as_str()) => (mr.base + r.start, mr.base + r.end),
                _ => continue,
            };
            if lo <= address && address + size <= hi {
                return Ok(());
            }
        }
        Err(Refusal {
            code: "outside_authorized_range",
            detail: format!("span {address:#x}+{size} is not inside any declared range of this build"),
        })
    }
}

/// 'x64', 'x86' or '' from the PE header at the start of a file.
pub fn pe_arch(head: &[u8]) -> &'static str {
    let le32 = |o: usize| head.get(o..o + 4).map(|b| u32::from_le_bytes(b.try_into().unwrap()));
    let Some(off) = le32(0x3c).map(|v| v as usize) else {
        return "";
    };
    if head.get(..2) != Some(b"MZ") || head.get(off..off + 4) != Some(b"PE\0\0") {
        return "";
    }
    match head.get(off + 4..off + 6).map(|b| u16::from_le_bytes(b.try_into().unwrap())) {
        Some(0x8664) => "x64",
        Some(0x14c) => "x86",
        _ => "",
    }
}

/// A conformance stamp passes only for this build, architecture, pinned tool version and iteration count.
pub fn valid_stamp(stamp: &Value, digest: &str, arch: &str, tool: &str, iterations: u64) -> bool {
    stamp.get("result").and_then(Value::as_str) == Some("pass")
        && stamp.get("target_sha256").and_then(Value::as_str) == Some(digest)
        && stamp.get("arch").and_then(Value::as_str) == Some(arch)
        && stamp.get("frida").and_then(Value::as_str).or_else(|| stamp.get("agent").and_then(Value::as_str)) == Some(tool)
        && stamp.get("iterations").and_then(Value::as_u64).unwrap_or(0) >= iterations
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SHA: &str = "d36e74c47592e9c656ae250078cb40b2be63c782af5bfbeff2280d43e653fab4";

    fn entry() -> Value {
        json!({"sha256": SHA, "actions": ["write", "watch"], "max_size": 8,
               "ranges": [{"module": "Game.exe", "rva_start": "0x1F0000", "rva_end": "0x1F4000"},
                          {"va_start": "0x7FF600200000", "va_end": "0x7FF600200100"}], "note": "why"})
    }

    #[test]
    fn normalizes_and_checks() {
        let a = normalize(&entry()).unwrap();
        let m = ModuleRef { name: "game.exe".into(), base: 0x7ff6_0000_0000 };
        a.check(Action::Write, 0x7ff6_001f_0000, 8, Some(&m)).unwrap();
        a.check(Action::Watch, 0x7ff6_0020_0000, 8, None).unwrap();
        assert_eq!(a.check(Action::Write, 0x7ff6_001f_0000, 9, Some(&m)).unwrap_err().code, "size_exceeds_authorization");
        assert_eq!(a.check(Action::Write, 0x7ff6_001f_3ffd, 8, Some(&m)).unwrap_err().code, "outside_authorized_range");
        assert_eq!(a.check(Action::Write, 0x7ff6_001f_0000, 8, None).unwrap_err().code, "outside_authorized_range");
    }

    #[test]
    fn watch_is_capped_at_the_hardware() {
        let mut e = entry();
        e["max_size"] = json!(64);
        let a = normalize(&e).unwrap();
        assert_eq!(a.check(Action::Watch, 0x7ff6_0020_0000, 16, None).unwrap_err().code, "size_exceeds_authorization");
        a.check(Action::Write, 0x7ff6_0020_0000, 16, None).unwrap();
    }

    #[test]
    fn action_not_listed() {
        let mut e = entry();
        e["actions"] = json!(["write"]);
        let a = normalize(&e).unwrap();
        assert_eq!(a.check(Action::Watch, 0x7ff6_0020_0000, 4, None).unwrap_err().code, "action_not_authorized");
    }

    #[test]
    fn invalid_entries() {
        for (k, v) in [
            ("sha256", json!("abc")),
            ("actions", json!([])),
            ("actions", json!(["exec"])),
            ("max_size", json!(65)),
            ("max_size", json!(true)),
            ("ranges", json!([])),
            ("ranges", json!([{"va_start": 1, "va_end": 1 + MAX_RANGE + 1}])),
            ("ranges", json!([{"module": "a.exe", "va_start": 1, "rva_start": 1, "rva_end": 2}])),
        ] {
            let mut e = entry();
            e[k] = v;
            assert!(normalize(&e).is_err(), "{k}");
        }
    }

    #[test]
    fn lookup_reports_why() {
        assert!(lookup(&json!({}), SHA).unwrap_err().contains("empty or missing"));
        assert!(lookup(&json!({"runtime_authorized_targets": 3}), SHA).unwrap_err().contains("must be a list"));
        assert!(lookup(&json!({"runtime_authorized_targets": [entry()]}), &"0".repeat(64)).unwrap_err().contains("not in"));
        let mut bad = entry();
        bad["max_size"] = json!(0);
        assert!(lookup(&json!({"runtime_authorized_targets": [bad]}), SHA).unwrap_err().contains("is invalid"));
        assert_eq!(lookup(&json!({"runtime_authorized_targets": [entry()]}), SHA).unwrap().max_size, 8);
    }

    #[test]
    fn stamp_and_arch() {
        let s = json!({"result": "pass", "target_sha256": SHA, "arch": "x64", "agent": "hy-1", "iterations": 100});
        assert!(valid_stamp(&s, SHA, "x64", "hy-1", 100));
        assert!(!valid_stamp(&s, SHA, "x86", "hy-1", 100));
        assert!(!valid_stamp(&s, SHA, "x64", "hy-1", 101));
        let mut h = vec![0u8; 0x100];
        h[..2].copy_from_slice(b"MZ");
        h[0x3c] = 0x80;
        h[0x80..0x84].copy_from_slice(b"PE\0\0");
        h[0x84] = 0x64;
        h[0x85] = 0x86;
        assert_eq!(pe_arch(&h), "x64");
        assert_eq!(pe_arch(b"nope"), "");
    }
}
