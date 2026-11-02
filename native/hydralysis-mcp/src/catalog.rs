//! The advertised catalog, generated from api.py and mcp.py by tools/gen_mcp_catalog.py (catalog.json).

use serde_json::Value;
use std::collections::HashSet;

const RAW: &str = include_str!("../catalog.json");

pub struct Catalog {
    pub version: String,
    pub epoch: Value,
    pub hash: String,
    pub instructions: String,
    pub tool_names: HashSet<String>,
    pub engine_tools: HashSet<String>,
    pub long_tools: HashSet<String>,
    pub long_trace_actions: HashSet<String>,
    pub protocol_versions: Vec<String>,
    pub max_output_bytes: usize,
    pub retry_after_ms: u64,
    pub engine_parallel_max: usize,
    pub long_slots: usize,
    pub engine_slots_min: usize,
    pub engine_slots_max: usize,
    /// The tool table; serialised with the Python separators it is the `tools/list` result.
    pub tools: Value,
}

fn strings(value: &Value, key: &str) -> Vec<String> {
    value[key]
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

impl Catalog {
    pub fn load() -> Catalog {
        let value: Value = serde_json::from_str(RAW).expect("catalog.json is valid JSON");
        let count = |key: &str| value[key].as_u64().unwrap_or(0) as usize;
        Catalog {
            version: value["version"].as_str().unwrap_or("").to_string(),
            epoch: value["epoch"].clone(),
            hash: value["hash"].as_str().unwrap_or("").to_string(),
            instructions: value["instructions"].as_str().unwrap_or("").to_string(),
            tool_names: strings(&value, "tool_names").into_iter().collect(),
            engine_tools: strings(&value, "engine_tools").into_iter().collect(),
            long_tools: strings(&value, "long_tools").into_iter().collect(),
            long_trace_actions: strings(&value, "long_trace_actions").into_iter().collect(),
            protocol_versions: strings(&value, "protocol_versions"),
            max_output_bytes: count("max_output_bytes"),
            retry_after_ms: value["retry_after_ms"].as_u64().unwrap_or(2000),
            engine_parallel_max: count("engine_parallel_max"),
            long_slots: count("long_slots"),
            engine_slots_min: count("engine_slots_min"),
            engine_slots_max: count("engine_slots_max"),
            tools: value["tools"].clone(),
        }
    }

    /// `{"epoch": N, "hash": "..."}`, the `hydralysis/catalog` metadata.
    pub fn meta(&self) -> Value {
        serde_json::json!({"epoch": self.epoch, "hash": self.hash})
    }

    /// Which lane a tool call runs on (mcp.py `lane_of`).
    pub fn lane_of(&self, name: Option<&str>, arguments: Option<&Value>) -> Lane {
        let Some(name) = name else { return Lane::Fast };
        if !self.engine_tools.contains(name) {
            return Lane::Fast;
        }
        if name == "trace" {
            let action = arguments
                .and_then(|value| value.get("action"))
                .and_then(Value::as_str);
            return if action.is_some_and(|action| self.long_trace_actions.contains(action)) {
                Lane::Long
            } else {
                Lane::Engine
            };
        }
        if self.long_tools.contains(name) {
            Lane::Long
        } else {
            Lane::Engine
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub enum Lane {
    Fast,
    Engine,
    Long,
}

impl Lane {
    pub fn name(self) -> &'static str {
        match self {
            Lane::Fast => "fast",
            Lane::Engine => "engine",
            Lane::Long => "long",
        }
    }

    pub fn index(self) -> usize {
        self as usize
    }
}

/// A lane's `workers` (calls that run at once) and `outstanding` (calls accepted before `Server busy`).
#[derive(Clone, Copy, Debug)]
pub struct LaneSize {
    pub workers: usize,
    pub outstanding: usize,
}

/// mcp.py `lane_sizes`, indexed by `Lane::index`.
pub fn lane_sizes(catalog: &Catalog, cpus: usize) -> [LaneSize; 3] {
    let cpus = cpus.max(1);
    let fast = cpus.clamp(4, 16);
    let engine = catalog
        .engine_slots_max
        .min((2 * cpus).max(catalog.engine_slots_min))
        .min(catalog.engine_parallel_max - catalog.long_slots);
    [
        LaneSize {
            workers: fast,
            outstanding: (2 * fast).max(8),
        },
        LaneSize {
            workers: engine,
            outstanding: engine,
        },
        LaneSize {
            workers: catalog.long_slots,
            outstanding: catalog.long_slots,
        },
    ]
}

/// The CPUs this process may use (`PYTHON_CPU_COUNT` wins, like mcp.py `granted_cpus`).
pub fn granted_cpus() -> usize {
    if let Some(count) = std::env::var("PYTHON_CPU_COUNT")
        .ok()
        .and_then(|text| text.parse::<usize>().ok())
        .filter(|count| *count > 0)
    {
        return count;
    }
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lane_sizes_match_the_python_budgets() {
        let catalog = Catalog::load();
        let sizes = lane_sizes(&catalog, 24);
        assert_eq!((sizes[0].workers, sizes[0].outstanding), (16, 32));
        assert_eq!((sizes[1].workers, sizes[1].outstanding), (24, 24));
        assert_eq!((sizes[2].workers, sizes[2].outstanding), (8, 8));
        let small = lane_sizes(&catalog, 1);
        assert_eq!((small[0].workers, small[0].outstanding), (4, 8));
        assert_eq!(small[1].workers, 8);
    }

    #[test]
    fn lanes_follow_the_tool_names() {
        let catalog = Catalog::load();
        assert_eq!(catalog.lane_of(Some("function"), None), Lane::Fast);
        assert_eq!(catalog.lane_of(Some("ghidra_query"), None), Lane::Engine);
        assert_eq!(catalog.lane_of(Some("prepare"), None), Lane::Long);
        let export = serde_json::json!({"action": "export"});
        assert_eq!(catalog.lane_of(Some("trace"), Some(&export)), Lane::Long);
        assert_eq!(catalog.lane_of(None, None), Lane::Fast);
    }
}
