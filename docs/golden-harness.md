# Golden decompile diff harness

`tools/golden.py` records what a decompiler says about every function of an analysed program and
compares two such records. It is the evidence gate for anything that can change decompiler
output: a Hydra Engine release, an upstream Ghidra merge (the decompiler's C++ and the type
system change there), a RusticQuery change. The question it answers is not "does it build" but
"did the C that agents read change, and did any function stop decompiling".

Stock Ghidra is **not** a dependency of Hydralysis or Hydra. The harness can also run a stock
Ghidra install, only so that a baseline from the old engine can be compared with the new one.

## What it records

A capture is a directory:

| File | Holds |
| --- | --- |
| `rows.jsonl` | Line 1, a header; then one row per function. |
| `c.jsonl.gz` | `{entry, c}` for every function that decompiled (the C text, needed to normalise again and to show a diff). |
| `header.json` | The header again, for reading. |

The header names the engine (Ghidra version and build date, Hydra release, revision), the SHA-256
of the native `decompile.exe` and of `Decompiler.jar`, the program's SHA-256, the function count
and its breakdown, the decompile path, the decompiler options (and their SHA-256), the date given
on the command line, and the SHA-256 of the harness code that made it. Each row is
`{entry, name, size, status, ms, c_sha256, normalized_c_sha256, error}`; the production path
adds `engine_ms` (time inside the engine, without the request round trip).

`status` is `ok`, `failed` (the decompiler refused), `timeout` or `error` (the request itself
failed). Entries are canonical lower-case hex (`0x401000`), so captures from different drivers
line up.

### Two decompile paths, labelled separately

| `--path` | What runs | Why it exists |
| --- | --- | --- |
| `production` | One `RusticQuery.java` `decompile` request per function through the same `query.run_script` the MCP tools and the export job use. Since 0.5.0 `RusticQuery` calls `DecompileOptions.grabFromProgram` (through one helper, before `openProgram`), so it decompiles on the program's own options (`DecompileOptions.grabFromProgram`). Before 0.5.0 it opened `DecompInterface` without `setOptions` and ran on the native defaults, so a capture made then is not comparable with one made now. Hydra only. | This is what agents get. |
| `explicit` | `tools/golden/GoldenExport.java`, one script run for the whole program, with `DecompileOptions` set explicitly. `--options-mode fixed` (default) sets a documented list and reads nothing from the program; `--options-mode program` also calls `grabFromProgram`, which is `DecompileOptions.grabFromProgram`. The header carries every option value and a hash of them. | The same source runs under Hydra's `script` command and under stock `analyzeHeadless`, so two engines are compared with one driver and identical options. |

The options change the output (calling conventions printed on the signature, `in_ECX` versus a
`this` parameter, constants in read-only memory folded or left as `DAT_` names). `production` and
`explicit --options-mode program` use the same options and produce the same C (see
[Parity](#parity-of-the-production-path-with-decompileoptionsgrabfromprogram)); `explicit` with the default
`--options-mode fixed` reads nothing from the program and differs from both. Never diff captures
of different options for a gate; `diff` refuses unless `--allow-mismatch`. Compare like with like.

## Running it

```text
set JAVA_HOME=C:\Program Files\Eclipse Adoptium\jdk-25.0.4.101-hotspot
set ENG=D:\Projects\Hydra\_engines\hydra-2\extracted\ghidra_12.3_DEV
set CLIENT=D:\Projects\Hydra\_engines\hydra-2\client\hydra-client-12.3-hydra.2\ghidra_session.py

rem A COPY of the analysed project, proven identical, source proven untouched:
python tools/golden.py project-copy F:\...\kotor D:\Projects\Hydra\_golden\kotor-src-copy

python tools/golden.py capture --engine %ENG% --client %CLIENT% --project <copy>\kotor.gpr ^
    --path production --label hydra-2 --date 2026-10-27 --out <baselines>\hydra-2\kotor\production
python tools/golden.py capture --engine %ENG% --client %CLIENT% --project <copy>\kotor.gpr ^
    --path explicit  --label hydra-2 --date 2026-10-27 --out <baselines>\hydra-2\kotor\explicit

rem the other engine, same driver, stock Ghidra (explicit path only):
python tools/golden.py capture --stock F:\...\ghidra_12.1.4_PUBLIC --project <second copy>\kotor.gpr ^
    --program-name swkotor.exe --label ghidra-12.1.4 --out <baselines>\ghidra-12.1.4\kotor\explicit

python tools/golden.py diff <baselines>\hydra-2\kotor\explicit <new>\kotor\explicit ^
    --profile corpus --report report.json
python tools/golden.py timing <baselines>\hydra-2\kotor\production
```

`capture` starts its own Hydra daemon with a fresh state directory under
`D:/Projects/Hydra/_golden/state` (`--state-root` to change it), never joins another one, and
stops it afterwards. It sets `GHIDRA_SESSION_UPGRADE_CACHE=off` unless `--upgrade-cache` is
given, so a project saved by an older Ghidra is upgraded in memory and timings do not compete
with the cache's background copy. Always capture from a **copy** of the project: open the original
with an older engine only, never with the one under test, and check with `treehash` that it did
not change.

`--sample N` decompiles a deterministic sample of N functions, stratified by size bucket
(`--seed`). Both captures of a comparison must cover the same sample; `diff` warns when they do not.

### Reading a diff

Every function present in either capture lands in exactly one class:

| Class | Meaning |
| --- | --- |
| `identical` | Same C text (`c_sha256`). |
| `identical_after_normalisation` | Different text, same after the normaliser below. |
| `changed` | Different after normalisation. The report keeps a bounded list with a unified diff. |
| `failed_only_in_B` | Decompiled in A, not in B. The regression that matters most. |
| `failed_only_in_A` | The opposite (a fix). |
| `failed_in_both` | |
| `missing_in_B` / `missing_in_A` | The function set differs (analysis changed, or a different sample). |

### The normaliser

`identical_after_normalisation` is a passing class, so the normaliser must never hide a real
change. Every rule is a formatting rule or an alpha-renaming:

- **whitespace**: line endings, trailing blanks, runs of blank lines, leading and trailing blank lines.
- **standard** (the default) adds: standalone comment lines and blocks (banners) are dropped,
  except `/* WARNING ... */`, which are kept with their `0x...` addresses masked; temporaries
  (`iVar3`, `pcVar2`, any `...Var<n>`) and stack names (`local_10`, `uStack_8`,
  `in_stack_ffffffc8`, `local_res4`) are renumbered by first appearance, per family, outside
  string and character literals.

It does not touch: `DAT_`, `FUN_`, `LAB_`, `PTR_` names and every other address, types, casts,
operators, statement order, parameter names (`param_1`), function names, end-of-line comments,
or the text of a WARNING (so "could not recover jumptable" appearing is a change). Use
`--level whitespace` for a stricter pass, `--level raw` for none.

### The gate

`diff` exits 0 when the gate passes, 1 when it fails (2 on usage errors). Defaults:

| Profile | `failed_only_in_B` | identical or normalised, of the functions that decompiled in A |
| --- | --- | --- |
| `corpus` (default) | 0 | at least 98% |
| `fixtures` | 0 | 100% |

`--min-match-pct` and `--max-failed-only-in-b` override them. A different program SHA-256 or
decompile path between the two captures fails the gate (`--allow-mismatch` makes it a warning).
The thresholds are a starting proposal: tune them after the first real merge gate, and write down
why.

## Parity of the production path with `DecompileOptions.grabFromProgram`

`RusticQuery` used to open its decompiler without `setOptions`. The first baselines (2026-10-27,
Hydra 12.3-hydra.2) showed what that cost, and the comparison that shows it is the easy one to
get wrong: `explicit` in its default `fixed` mode reads nothing from the program, so it loses the
calling conventions (`in_ECX` locals instead of `this`) and is the wrong oracle for the program's own options.
The right one is `explicit --options-mode program`.

Counts only; the C text of a game stays local. KotOR 1 (8,616 functions), hydra-2 engine:

| A | B | identical | changed | failed only in B |
| --- | --- | ---: | ---: | ---: |
| `explicit --options-mode program` | `production`, before the change (native defaults) | 7,253 | 1,363 | 0 |
| `explicit --options-mode program` | `production`, after the change (`grabFromProgram`) | 8,616 | 0 | 0 |
| `production` before | `production` after | 7,253 | 1,363 | 0 |

All eight public MSVC fixtures (x86 and x64, 3,959 functions in all): after the change `production` and
`explicit --options-mode program` are identical on every function (the `fixtures` gate passes at 100%).

What the 1,363 changes are: a function whose C read a constant or string from read-only memory.
Respecting the read-only flag is one of the program's options, off on the native defaults and on in the
program. On the public fixture it is `df_scale`: `param_1 * DAT_004161c4 - DAT_004161c0` becomes
`param_1 * 1.5 - 0.25`. The same change turns a copy from a read-only string into
`builtin_strncpy(...)`, turns array locals that were several 4-byte pieces into one array, and the
`Globals starting with '_' overlap smaller symbols` warning goes away where the constant is folded.
The signatures also change: 318 more `__thiscall` and 132 more `__fastcall` signatures (3,055 to 3,373 and 2,238 to
2,370; the option behind each one was not isolated). Decompile time is unchanged (median 20.0 ms before, 21.3 ms after on this machine's one
sequential run each; the distributions overlap and a one-off run is not a benchmark).

An engine integration test keeps it so: `tests/test_engine_options.py` decompiles a fixture function
whose float constants live in `.rdata` and asserts the values are shown, and that a `thiscall` method
keeps its convention and its `this` parameter. It needs the fixtures built
(`HYDRALYSIS_INTEGRATION_FIXTURES`), so it skips elsewhere.

## Tiers

1. **Public fixtures, anywhere.** The MSVC fixtures (`tests/fixtures`, see
   [verification-fixtures.md](verification-fixtures.md)) are built reproducibly (`/Brepro`) from
   source in this repository, so their captures contain nothing proprietary. `golden.py prepare`
   imports and analyses them through Hydralysis's own preparation path and writes a set file;
   `capture-set` captures every program of a set; gate with `--profile fixtures`. Needs an
   engine and MSVC, so it is run by whoever has them (a self-hosted runner, a release
   checklist), not by the unit-test CI.
2. **A real game, local only.** A large analysed project (KotOR 1, about 9,000 functions) catches
   what small fixtures cannot: the corpus gate. Its captures hold C text derived from a binary
   you do not own the rights to publish, so they stay on the machine, outside any repository
   (`D:/Projects/Hydra/_golden`). Do not commit them, attach them to an issue or paste excerpts of
   them into a pull request; share counts and hashes. `diff --no-text` writes a report with no C.

CI runs only `tests/test_golden.py` (the normaliser, diff and gate on invented captures).

## Timing

Each row's `ms` is wall time. On the production path it includes the request round trip
(`engine_ms` is the time inside the engine); on the explicit path it is the decompile call alone.
`golden.py timing <capture>` prints min, median, p95 and max per size bucket (1-byte, small 2-64
bytes, medium 65-512, large over 512). A decompile time is a function of the function's size:
quote it per bucket, not as one number.

## Files

- `tools/golden.py`: capture, capture-set, diff, timing, treehash, project-copy, prepare.
- `tools/golden/GoldenExport.java`: the explicit-options driver (plain GhidraScript, runs under
  stock `analyzeHeadless` and under Hydra's `script`).
- `tests/test_golden.py`: normaliser, diff and gate tests.
