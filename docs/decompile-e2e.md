# Decompile end to end through Hydralysis

`ghidra-query --action decompile` (CLI) and `ghidra_query` (MCP) ask the RusticQuery script first (seconds). The script has its
own limits: a body in several pieces ends in "No pcode could be generated", and a huge function runs past the script's timeout. In
those cases Hydralysis retries with the engine's own `decompile` command (engine PROTOCOL-3 section 8.21), which classifies the
pieces, returns partial C on overflow, sizes its response budget itself and pages.

## Fallback and job

* The retry is labelled in the reply: `fallback: {via: "engine_decompile", reason: <the script's error>, engine_s, timeout_s, job}`.
* The engine call can take minutes, so it runs as a decompile job (`decompile-<12 hex>`, `hydralysis.decompile_job`, a worker
  process like the export worker). `ghidra_query` returns the job at once (`state`, `stage`, `elapsed_s`, `log_tail`); `job` with
  the id reports progress and, once `state` is `done`, the `result` (the normal decompile reply). The same call arriving while the
  job runs finds the same job (`reused`).
* The CLI follows the job itself: progress lines on stderr, the result on stdout. `--wait SECONDS` (default 3600) bounds the wait;
  `--wait 0` prints the job and returns. The engine timeout of the retry is 3600 s.
* The same path serves `max_result_mb`, `max_result_kb` and `offset`: the script cannot honour them, so the engine is asked too;
  if it does not answer within the call's `timeout_s`, the call becomes a job.

## Options (decompile)

| option | range | meaning |
|---|---|---|
| `max_characters` | 1..2097152, default 32000 | clips the C text of the reply |
| `max_result_mb` | 1..1024 | hard ceiling on the engine's whole reply; omitted means the engine's adaptive budget |
| `max_result_kb` | 1..1048576 | like MB, in KiB; wins when both are given |
| `offset` | >= 0 | characters; the reply is the page from `offset`, at most `max_characters` long |

## Reply fields

`partial`, `reason` (`response_buffer`, `non_contiguous_body`, ...), `truncated`, `bytes_emitted`, `fragments`, `cut` (what the
overflow left), `budget` (`mode` auto or ceiling), `offset`, `next_offset`, all summarised in `decompile`. A reply cut by the cap
has the recovered front of the C text in `c` when the cut fell inside the C markup.

Evidence coverage and export limitation codes: `decompile_truncated` (cut by a cap the caller named), `decompile_budget_limited`
(cut by the engine's auto budget), `decompile_paged` (a page, `next_offset` follows), `non_code_fragments`.

## Real target (Cyberpunk2077.exe 2.5, a copy of the analysed project, read only)

See the CHANGELOG entry and `E:\Projects\Hydra\_logs\hyd-e2e-*` for the runs; timings are in the lane report.
