# Cyberpunk 2.5: saved-project and value-flow check

> Historical record: written when this project was called RusticRE (command `rusticre`, variables `RUSTICRE_*`, tool prefix `mcp__rusticre__*`). It is kept as written; the names are `hydralysis`, `HYDRALYSIS_*` and `mcp__hydralysis__*` now.

This is a record of a bounded check on an existing user-owned project, not a
game-specific feature or a claim that every acceptance gate has passed. The
[requested checks](https://github.com/RusticStack/RusticRE/pull/6#issuecomment-6397988372)
include adoption, type import, cross-build transfer, tracing, and live work.

On 2026-10-27, a separate source snapshot at RusticRE commit
[`f38488e050158a0921fe3d1e43c96fa72055521b`](https://github.com/RusticStack/RusticRE/commit/f38488e050158a0921fe3d1e43c96fa72055521b)
was exercised over its stdio MCP server with the pinned Hydra 12.3-hydra.2
release. The game executable was read, never launched or imported. The
analysed project was `F:/dev-cache/ghidra-2.5/NCT-2.5/NCT-2.5.gpr`; its
program's SHA-256 and the executable's SHA-256 were both
`d36e74c47592e9c656ae250078cb40b2be63c782af5bfbeff2280d43e653fab4`.
The executable was Cyberpunk 2.5, version 3.0.88.46235. All RusticRE and
Hydra state used an isolated root under
`F:/dev-cache/rusticre/nct-readonly-20261027/`.

The `prepare` call with `action=adopt`, `path=<project>`, `exe=<executable>`
and `target=cyberpunk-2.5` registered the existing program with
`copied=false`, `imported=false`, image base `0x140000000` and 243,855
functions. Cold adoption took 32.72 seconds wall time; Hydra reported 30.75
seconds opening the older database through its read-only, in-memory upgrade
path. A bounded `ghidra_query` with `action=decompile`,
`address=0x14125946c` and `timeout_s=120` answered in 6.06 seconds wall
time. This was one function, not a program export.

The memory-flow request used `action=trace`, `address=0x1412594ac`,
`timeout_s=120`, and `options={"argument":1,"brief":true,"depth":12,
"functions":1,"nodes":200}`. It returned `0x6` in the low bytes of a
`PIECE` at `0x14125949a`, reaching the argument through a `stack_pointee`
edge before the call. The result also reported an after-use occurrence at
`0x141259746`. The request took 0.292 seconds wall time; the reported query
time was 0.271 seconds. It was **truncated at 200 operations**, so the output
is evidence of the cited path, not a complete flow or proof of runtime
reachability. This reproduces the specific static scope-six observation
documented in the [earlier trace change](https://github.com/RusticStack/RusticRE/commit/0efd4e6f7c04d4513f690f7991e857e0671278e9).
These single-run times describe this machine and workload, not general
performance guarantees.

Before and after the test, the nine project files had the same relative names,
sizes, and modification times; this check did not hash every project file. The
engine log identifies the opened project as a read-only view. Its background
upgrade-cache build was cancelled when the isolated daemon stopped, so another
cold open may incur the upgrade cost again. Full MCP replies, the recorded
timings and the engine log are in the isolated root above.

The remaining 2.5 gates were not established by this check:

- The existing live reflection snapshot at
  `F:/dev-cache/nct-baseline/2.5/rtti-live/` identifies the same executable
  hash and reports 16,602 classes and 125,713 properties. Its project-specific
  `classes.jsonl` and `props.jsonl` records are not RusticRE's generic
  `kind`-tagged [type corpus](type-corpus.md); no ready converted corpus or
  converter was found in the checked project tools and cache paths. No import
  was attempted, and no claim of named fields from a 2.5 import is made.
- Both saved baseline address inventories exist under
  `F:/dev-cache/nct-baseline/{2.31,2.5}/snapshot/addresses.json`. The NCT
  address specification contains 44 entries, including 39 with `expect`
  patterns. NCT's [state record](https://github.com/KelpHect/NightCityTogether/blob/458490756e7ea080d3bf09ce0a2e6c8867f7ce24/STATE.md)
  reports its own live self-test; the existence of those records is
  not a verification that RusticRE mapped 44 functions correctly. No cached
  RusticRE fingerprint pair for the two builds was found in the checked
  RusticRE cache, and the referenced local 2.31 project path was absent in the
  checked NCT worktree. Producing a new whole-program fingerprint sweep was
  outside this bounded check, so no 44/44 transfer claim is made.
- Live process reads and observation on a detoured function were not run. No
  game process was launched and no hook was installed.
