# Trace pump: Python to Rust porting notes

What moved into `hydralysis_native` (`native/src/trace/`), what stayed in Python, and how equality is checked.

| Python (the specification) | Rust twin | Use |
|---|---|---|
| `trace_capture.TraceSource` writer half (decode, redact, encode, chain, append, head sidecar, artifacts) | `pump.rs` `TracePump` | batch write with the GIL released; fsync batched on a background thread |
| `trace_pump.SegmentTail` chain walk (CRC, numbering, back link, record hash) | `segment.rs` `scan_chain` | fast path; stops in front of any line it cannot vouch for |
| `trace_capture.verify_segment` | `segment.rs` `verify_segment_file` | whole-file check |
| `trace_keys.annotate` (frame, phase, role keys) | `keys.rs` `annotate_events` | `annotate` tries it, `annotate_python` is the fallback |

## Behaviour rules

- Python stays the specification. Native is used only when `hydralysis_native` imports and `HYDRALYSIS_NATIVE` is not `0`.
- The native scan never rejects: on anything unusual (bad hash, odd shape, unknown role resolver) it stops or refuses and the Python code
  decides, so accepted and rejected input are unchanged.
- Same observable output: segment bytes, record hashes and head, key ordering, report contents.
- Lock, transport counters and the Frida callbacks stay in Python.

## Where equality is tested

- `tests/test_trace_keys_native.py`: native vs `annotate_python` on hand-made and randomized streams.
- `tests/test_trace_capture.py`: segment bytes/hashes written by the native pump vs the Python writer, tail and verify paths.
- Run each suite three ways: new `.pyd`, the previous `.pyd`, and no `.pyd` (all must pass).

## Measuring

`python benchmarks/trace_pump_bench.py --label NAME --out FILE` (synthetic batches through `TraceSource.on_batch`, no Frida).
Set `HYDRALYSIS_NATIVE=0` for the pure-Python twin.

## Known limits

Windows x64 only. The native crate has no Rust unit tests; equality is proven from Python against the Python twin.
