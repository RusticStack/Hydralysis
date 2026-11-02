# Test map: old (Python / fakefrida) -> new (Rust)

Stage 1 only. Nothing below is ported yet; the entries record the intended target.

| Old test / tool | Kind | New home |
| --- | --- | --- |
| tests/test_runtime*.py (fakefrida) | white-box, Frida double | hy-runtime tests against a trait-based test double of `Session` (stage 4) |
| tests/test_trace_capture.py | white-box | hy-runtime `capture` unit tests + double |
| tests/test_trace_e2e.py, test_trace_g2_live.py | black-box, real fixtures | unchanged, run with `HYDRALYSIS_IMPL=rust` via PyO3 (stage 2+) |
| tests/test_trace_gates*.py, test_trace_extras.py | gates | unchanged, differential |
| tests/test_agent_cost.py, benchmarks/trace_overhead.py | overhead | run against the Rust agent (stage 2) |
| tests/test_watch*.py, tools/watch_conformance.py | watch | stage 3 |
| tests/test_runtime_authorized.py | authorization | stage 3 |
| (new) hy-agent-proto rec_roundtrip | unit | hy-agent-proto/src/lib.rs |
| (new) spike on frameloop | manual spike | hy-runtime/src/bin/spike.rs |
