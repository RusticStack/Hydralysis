# Verification on fixtures with known answers

> Historical record: written when this project was called RusticRE (command `rusticre`, variables `RUSTICRE_*`, tool prefix `mcp__rusticre__*`). It is kept as written; the names are `hydralysis`, `HYDRALYSIS_*` and `mcp__hydralysis__*` now.

The capabilities RusticRE promises (the sixteen items of the "only RE server" work, PR #6)
are checked here on small programs whose answers are known exactly, for both x64 and
32-bit x86, instead of on one game's data. Each fixture is built by MSVC without a PDB,
so the analysis sees what it sees in a shipped program; the linker map of each build is the
ground truth for every address. Builds are reproducible (`/Brepro`).

| Fixture | What is known |
| --- | --- |
| `tests/fixtures/flow_fixture.c` | `fx_flow` stores `0x2A` into `Config.limit` two calls away (`fx_relay` -> `fx_store`) and reads it back with `fx_read`; exactly `fx_store`, `fx_reset` and `fx_clamp` write `Config.limit`; at start the program writes a `jmp` from `fx_hooked` to `fx_detour`; `fx_tick(Config *, float dt)` runs once per ~50 ms frame with `dt` in {0.25, 0.375, 0.5, 0.625}. |
| `tests/fixtures/vcall_fixture.cpp` | `Shape` and `Gadget` both have a virtual method in slot 1; calls through it with receivers known by construction (a global object, a factory's result, a parameter). |
| `tests/fixtures/diff_fixture.c` | Two builds (`-DV2`): identical functions (some moved), two changed ones (`df_limit`, `df_banner`), one added (`df_added`), one removed (`df_removed`); build 2 also inserts a `Record` field that shifts what `df_decode_amount` reads. |

The semantic-trace fixtures (`trace_app`, `interleave`, `layouts`, `frameloop`, `veh_freeze`, `replica_a/b`, `fnv_names`, `minivm`, `persist`, `deadlock`, `ioctl_client`, plus extensions of `vcall_fixture` and `diff_fixture`) are described in `docs/trace-fixtures.md`.

The linker folds identical code (`/OPT:ICF`), as it does in shipped games: on x86
`fx_pair` shares `fx_store`'s bytes, and `fx_sides_of`/`fx_gadget_run` are one
`jmp [rcx+8]`. The checks expect that.

## Running

```text
python tests/fixtures/build_fixtures.py <build-dir>
python tests/fixtures/prepare_fixtures.py <build-dir>
python tests/fixtures/verify_fixtures.py <build-dir> [check ...]
```

`build` needs the MSVC build tools (found with `vswhere`). `prepare` registers each build
as a target named `fx-<arch>-<name>-<sha8>` (one analysis per build, never re-imported).
`verify` prints PASS or FAIL with its evidence per check and architecture; the runtime
checks spawn the fixture under a RusticRE session and stop it through a stop file.

## Results (2026-10-27, Hydra 12.3-hydra.2, Frida 17.24.3)

| Item | Check | x64 | x86 |
| --- | --- | --- | --- |
| 3 Memory-aware value flow | `value_flow`: tracing `fx_read`'s value back reaches only `0x2A`, via argument_binding, argument_binding, field_store; other constants are reported as address provenance | PASS | PASS |
| 13 Who writes this field | `writers`: of the static store sites at `Config.limit`'s offset, the ones that wrote the live `g_config` are `fx_store`, `fx_reset`, `fx_clamp` (and on x86 `fx_pair`, folded into `fx_store`) | PASS | PASS |
| 4 Probing hooked functions | `hooked`: `patches` flags `fx_hooked` and decodes the detour to `fx_detour`; unpatched functions are clean (on relocated x86 code too); static `prologue`/`sigscan` read the file's original bytes; a probe with `accept_patch` works past the detour | PASS | PASS |
| 2, 7 Cross-build diff and transfer | `diff`: every `df_` function has the right status and partner; the re-addressed prologue table places the 10 surviving functions and leaves only `df_removed` unplaced | PASS | PASS |
| 10 Indirect calls through vtables | `vcalls`: `Square::sides` is slot 1 of `Square::vftable`; the implementation is named; `receiver_global` verifies only the call through `g_square`, `receiver_from` only the one through `fx_make_shape`; the folded tail call is listed with its receiver a parameter | PASS | PASS |
| 12 Sampled observation | `sample`: a sampled probe on `dt` (xmm1 on x64, a stack argument on x86) reports ~16 calls/s and exactly 0.25..0.625, one summary per window, no per-call events | PASS | PASS |
| 5, 14 Runtime over MCP, typed live reads | `mcp_typed_read`: over the stdio MCP transport, a corpus type for `Config` is imported, the fixture spawned and `g_config` read through the type (mode 2, limit in range, speed growing) | PASS | PASS |
| 9 Evidence ledger | `ledger`: `df_limit`'s threshold claimed on build 1 (100) is superseded by its re-derivation on build 2 (250, found through the diff); the subsystem export lists the current claim with its source and the old one as superseded | PASS | (x64 only) |

Items checked elsewhere:

- 1 (bulk types) and 6 (adoption): on the analysed Cyberpunk 2.31 and 2.5 projects (adopted
  in place; a 2.31 RTTI corpus import makes `0x3878F4` decompile with named fields).
- 8 (bulk naming): a 174-name transfer applied as one job and undone in one step.
- 11 (argument decoding): live on Cyberpunk 2.5, a probe on the archive mount loop decoded
  58 archive paths in load order.
- 16 (library API): NCT's `hashcheck.py` and the address part of `baseline.py`, rewritten on
  `rusticre.client`, give identical results on the 2.5 table.
- 32-bit games: KotOR 1, Fallout 3 and Empire at War were prepared through RusticRE; a missed
  function found by `orphans` was created, decompiled and reverted on KotOR 1; `thiscall`
  argument mapping and register captures were checked live on KotOR 1.

## Several harnesses at once (item 15)

Three agents ran as separate harnesses against one data root at the same time,
each through the CLI with its own `RUSTICRE_HARNESS`, while the coordinator owned a runtime
session on the flow fixture:

- Overlays: two harnesses renamed the same function, both having read revision 1; one edit
  was applied (revision 2), the other got `{"conflict": "overlay revision changed",
  "last_edit_by": {"harness": "harness-c"}}`. Nothing was overwritten silently.
- Evidence: six claims from three harnesses in one ledger, each attributed to its client
  and harness.
- Runtime: an attach by a harness was refused while the coordinator's session drove the
  program; arming a probe in that session without its owner token was refused; reading its
  status was allowed.
- Jobs: every job appeared in one list with its owner; cancelling another harness's export
  was refused naming the owner; the owner cancelled its own with its token.
- No re-import: preparing an already analysed build answered `configured`, `started: false`;
  the preparation job count stayed the same.
- Fair sharing: while a Fallout 3 decompile export ran (56,280 functions), 20 short queries
  from another client took 17 ms median (12 ms in the engine).

The first run found that every export died at once with `No module named 'capstone'`; the
export worker now gets RusticRE's dependencies on its path, and the engine integration test
runs a real export.

## Not covered

- Hardware data watchpoints on a build that is neither a fixture nor owner-authorized
  (`runtime_authorized_targets`, see runtime-memory-policy.md): refused; item 13 uses the
  static write sites plus probes on them, and states what that does not cover.
- A probe over a call instruction is refused: in testing it could not be released again.
- `receiver_type` verification of virtual calls needs a typed receiver (an imported type
  on the parameter); the fixtures check the global and factory forms.
