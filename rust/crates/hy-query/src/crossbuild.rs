//! Port of `hydralysis/crossbuild.py::match`: the whole-program function matching between two builds.
//!
//! Phases and tie rules are the Python ones, including dict insertion order (an `IndexMap` stands in for each dict),
//! so the pairs come out in the same order with the same methods.

use std::collections::{HashMap, HashSet};

use indexmap::IndexMap;
use serde_json::Value;

pub const FINGERPRINT_INSTRUCTION_LIMIT: i64 = 20000;

/// One function fingerprint row. Fields are the ones `match` reads.
#[derive(Debug, Clone)]
pub struct Row {
    pub bytes: Value,
    pub shape: Value,
    pub size: i64,
    pub instructions: i64,
    pub strings: Vec<Value>,
    pub imports: Vec<Value>,
    pub constants: Vec<Value>,
    pub callees: Vec<String>,
    pub heads: Vec<Value>,
}

fn truthy(v: &Value) -> bool {
    match v {
        Value::Null => false,
        Value::Bool(b) => *b,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}

impl Row {
    /// None when a field `match` needs is missing or has another type (Python would raise; the caller falls back).
    pub fn from_json(v: &Value) -> Option<Row> {
        let o = v.as_object()?;
        let int = |k: &str| o.get(k).and_then(Value::as_i64);
        let list = |k: &str| o.get(k).and_then(Value::as_array).cloned();
        let callees = o.get("callees")?.as_array()?.iter().map(|c| c.as_str().map(String::from)).collect::<Option<Vec<_>>>()?;
        let heads = match o.get("heads") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(a)) => a.clone(),
            Some(_) => return None,
        };
        Some(Row {
            bytes: o.get("bytes")?.clone(),
            shape: o.get("shape")?.clone(),
            size: int("size")?,
            instructions: int("instructions")?,
            strings: list("strings")?,
            imports: list("imports")?,
            constants: list("constants")?,
            callees,
            heads,
        })
    }

    fn complete(&self) -> bool {
        self.instructions <= FINGERPRINT_INSTRUCTION_LIMIT
    }
}

fn similar(a: &Row, b: &Row, ratio: f64) -> bool {
    let (small, large) = if a.size <= b.size { (a.size, b.size) } else { (b.size, a.size) };
    large == 0 || (large - small) as f64 / large as f64 <= ratio
}

type Rows = IndexMap<String, Row>;
type Pairs = IndexMap<String, (String, &'static str)>;

/// `_unique`: key -> rva for keys that occur once among the rows not excluded.
fn unique(rows: &Rows, key: &dyn Fn(&Row) -> Option<String>, excluded: &dyn Fn(&str) -> bool) -> IndexMap<String, String> {
    let mut seen: IndexMap<String, Option<String>> = IndexMap::new();
    for (rva, row) in rows {
        if excluded(rva) {
            continue;
        }
        if let Some(value) = key(row) {
            match seen.get_mut(&value) {
                Some(slot) => *slot = None,
                None => {
                    seen.insert(value, Some(rva.clone()));
                }
            }
        }
    }
    seen.into_iter().filter_map(|(k, v)| v.map(|r| (k, r))).collect()
}

fn tup(values: &[&[Value]]) -> String {
    Value::Array(values.iter().map(|v| Value::Array(v.to_vec())).collect()).to_string()
}

fn floor_div(a: i64, b: i64) -> i64 {
    a.div_euclid(b)
}

/// `match(source, destination)`: source RVA -> (destination RVA, method), in Python's insertion order.
pub fn match_builds(source: &Rows, destination: &Rows) -> Pairs {
    let mut pairs: Pairs = IndexMap::new();
    let mut taken: HashSet<String> = HashSet::new();

    // The same code for every phase: `check` compares the two rows of one candidate pair.
    #[allow(clippy::type_complexity, clippy::too_many_arguments)] // mirrors the Python closure `phase`
    fn phase(
        method: &'static str,
        source: &Rows,
        destination: &Rows,
        pairs: &mut Pairs,
        taken: &mut HashSet<String>,
        key: &dyn Fn(&Row, &Pairs) -> Option<String>,
        right_key: Option<&dyn Fn(&Row, &Pairs) -> Option<String>>,
        check: Option<&dyn Fn(&Row, &Row) -> bool>,
    ) {
        let a = {
            let p: &Pairs = pairs;
            unique(source, &|r| key(r, p), &|rva| p.contains_key(rva))
        };
        let b = {
            let p: &Pairs = pairs;
            let t: &HashSet<String> = taken;
            let rk = right_key.unwrap_or(key);
            unique(destination, &|r| rk(r, p), &|rva| t.contains(rva))
        };
        for (value, rva) in &a {
            if let Some(other) = b.get(value)
                && !other.is_empty()
                && check.is_none_or(|c| c(&source[rva], &destination[other]))
            {
                pairs.insert(rva.clone(), (other.clone(), method));
                taken.insert(other.clone());
            }
        }
    }

    let s = |v: &Value| v.clone();
    let k_exact1 = |r: &Row, _: &Pairs| (r.size >= 24 && r.complete() && truthy(&r.bytes)).then(|| r.bytes.to_string());
    let k_exact2 = |r: &Row, _: &Pairs| {
        (r.size >= 8 && r.complete() && (!r.strings.is_empty() || !r.imports.is_empty()))
            .then(|| Value::Array(vec![s(&r.bytes), Value::Array(r.strings.clone()), Value::Array(r.imports.clone())]).to_string())
    };
    let k_shape1 = |r: &Row, _: &Pairs| {
        (r.instructions >= 6 && r.complete()).then(|| Value::Array(vec![s(&r.shape), Value::from(r.size)]).to_string())
    };
    let k_anchor1 = |r: &Row, _: &Pairs| (!r.strings.is_empty() || r.imports.len() >= 2).then(|| tup(&[&r.strings, &r.imports]));
    let k_anchor2 = |r: &Row, _: &Pairs| {
        (r.constants.len() >= 2)
            .then(|| Value::Array(vec![Value::Array(r.constants.clone()), Value::from(floor_div(r.instructions, 4))]).to_string())
    };
    let k_shape2 = |r: &Row, _: &Pairs| (r.instructions >= 12 && r.complete() && truthy(&r.shape)).then(|| r.shape.to_string());
    let k_heads = |r: &Row, _: &Pairs| (!r.heads.is_empty()).then(|| Value::Array(r.heads.clone()).to_string());
    let sim = |a: &Row, b: &Row| similar(a, b, 0.3);
    let sim9 = |a: &Row, b: &Row| similar(a, b, 0.9);

    phase("exact", source, destination, &mut pairs, &mut taken, &k_exact1, None, None);
    phase("exact", source, destination, &mut pairs, &mut taken, &k_exact2, None, None);
    phase("shape", source, destination, &mut pairs, &mut taken, &k_shape1, None, None);
    phase("anchors", source, destination, &mut pairs, &mut taken, &k_anchor1, None, Some(&sim));
    phase("anchors", source, destination, &mut pairs, &mut taken, &k_anchor2, None, Some(&sim));
    phase("shape", source, destination, &mut pairs, &mut taken, &k_shape2, None, Some(&sim));
    phase("strings", source, destination, &mut pairs, &mut taken, &k_heads, None, Some(&sim9));

    // Call graph: the k-th callee of a matched pair, when both are unmatched and alike.
    for _ in 0..8 {
        let mut added = 0;
        let snapshot: Vec<(String, String)> = pairs.iter().map(|(k, v)| (k.clone(), v.0.clone())).collect();
        for (rva, other) in snapshot {
            let (left, right) = (&source[&rva].callees, &destination[&other].callees);
            if left.len() != right.len() {
                continue;
            }
            for (callee, counterpart) in left.iter().zip(right) {
                if pairs.contains_key(callee)
                    || taken.contains(counterpart)
                    || !source.contains_key(callee)
                    || !destination.contains_key(counterpart)
                {
                    continue;
                }
                if similar(&source[callee], &destination[counterpart], 0.25) {
                    pairs.insert(callee.clone(), (counterpart.clone(), "callgraph"));
                    taken.insert(counterpart.clone());
                    added += 1;
                }
            }
        }
        if added == 0 {
            break;
        }
    }

    // Callees: two or more direct callees, all matched, map to exactly the callees of one unmatched destination function.
    for _ in 0..4 {
        let before = pairs.len();
        let translated = |r: &Row, p: &Pairs| {
            let set: HashSet<&String> = r.callees.iter().collect();
            if set.len() >= 2 && r.callees.iter().all(|c| p.contains_key(c)) {
                let mut v: Vec<&String> = set.iter().map(|c| &p[*c].0).collect();
                v.sort();
                Some(serde_json::to_string(&v).unwrap())
            } else {
                None
            }
        };
        let own = |r: &Row, _: &Pairs| {
            let set: HashSet<&String> = r.callees.iter().collect();
            (set.len() >= 2).then(|| {
                let mut v: Vec<&String> = set.into_iter().collect();
                v.sort();
                serde_json::to_string(&v).unwrap()
            })
        };
        let sim5 = |a: &Row, b: &Row| similar(a, b, 0.5);
        phase("callees", source, destination, &mut pairs, &mut taken, &translated, Some(&own), Some(&sim5));
        if pairs.len() == before {
            break;
        }
    }

    // Callers: a function's matched callers narrow its candidates to their unmatched callees; exactly one alike candidate wins.
    let mut callers_of: HashMap<&String, HashSet<&String>> = HashMap::new();
    for (rva, row) in source {
        for callee in &row.callees {
            callers_of.entry(callee).or_default().insert(rva);
        }
    }
    for _ in 0..4 {
        let mut proposals: IndexMap<String, Vec<String>> = IndexMap::new();
        for (rva, row) in source {
            if pairs.contains_key(rva) {
                continue;
            }
            let known: Vec<&String> = callers_of
                .get(rva)
                .map(|set| set.iter().filter(|c| pairs.contains_key(**c)).map(|c| &pairs[*c].0).collect())
                .unwrap_or_default();
            if known.is_empty() {
                continue;
            }
            let mut candidates: Option<HashSet<&String>> = None;
            for caller in known {
                let options: HashSet<&String> = destination[caller]
                    .callees
                    .iter()
                    .filter(|c| destination.contains_key(*c) && !taken.contains(*c) && similar(row, &destination[*c], 0.35))
                    .collect();
                candidates = Some(match candidates {
                    None => options,
                    Some(prev) => prev.intersection(&options).copied().collect(),
                });
            }
            if let Some(c) = candidates
                && c.len() == 1
            {
                let only = c.into_iter().next().unwrap().clone();
                proposals.entry(only).or_default().push(rva.clone());
            }
        }
        let mut added = 0;
        for (other, claimants) in proposals {
            if claimants.len() == 1 {
                pairs.insert(claimants[0].clone(), (other.clone(), "callers"));
                taken.insert(other);
                added += 1;
            }
        }
        if added == 0 {
            break;
        }
    }
    pairs
}

/// Parse a JSON object of rva -> row; None when any row is not in the shape `match` reads.
pub fn rows_from_json(v: &Value) -> Option<Rows> {
    let o = v.as_object()?;
    o.iter().map(|(k, r)| Row::from_json(r).map(|row| (k.clone(), row))).collect()
}
