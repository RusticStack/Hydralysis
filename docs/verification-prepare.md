# Prepare, adopt and scripts on a real engine (package Z5)

Hydralysis prepares a new executable (a fresh import and analysis), adopts a project that is already analysed, and runs
a user's own Java scripts (`ghidra_run`). Before this package those paths were proven on `whoami.exe` and by hand. The
tests below put them on a real Hydra engine and measure what they claim instead of echoing a literal.

Everything here is local evidence on Windows 11, Python 3.15, JDK 25.0.4, the project and every scratch folder on an NTFS
volume (D:). The machine was shared with other agents' builds, daemons and tests while these ran, so seconds are
observations under load, not benchmarks. CI does not run these classes (it has no MSVC fixtures, no game build and no
12.1.4 fixture); `tests/test_engine_prepare.py` and `tests/test_engine_scripts.py` skip themselves without their variables.

## Rows covered

| Row | Ask | Test | Result |
| --- | --- | --- | --- |
| C1-14 | adopt opens the project in place: no copy, no import | `AdoptMeasured.test_adopt_leaves_the_tree_and_the_daemon_untouched`, `...test_a_wrong_build_hash_registers_nothing_and_writes_nothing`, `...test_the_measurement_can_see_a_writable_open` (negative control), `LegacyAdopt`, `KotorLocal.test_adopt_of_the_analysed_project_copy_changes_nothing_and_matches_the_build` | pass |
| C1-21 | prepare of a fresh executable | `PrepareMatrix` (whoami plus the 8 MSVC fixtures, `maxImports` 2), `CancelMidImport`, `KilledWorker`, `KotorLocal.test_a_fresh_prepare_on_a_copy_...` | pass |
| C1-23 | `RusticQuery.java` and script migration | `ScriptStaging` (staged after daemon start, changed text, collision, compile error, old-style script), `StageUnit` (`_stage` and `owners.json`, no engine) | pass |
| C1-37 | fresh import and analysis of a new executable (P0 restatement of C1-21) | as C1-21 | pass |
| C1-39 | script migration (P0 restatement of C1-23) | as C1-23 | pass, with the `.py` decision below |
| C2-14 | Java `scriptPath` | `ScriptStaging` | pass |

## What "the daemon command log" is

The engine keeps no per-command log (protocol 2 and 3). The record is made from two sides, and the tests use both:

- **What was asked.** Every request this process sends goes through `hydra.Engine.call` or `.send`. `CommandLog` wraps both
  and records `(command, fields)`. For adopt it must contain only `open_project`, `list` and `open_program`, never
  `import`, `analyze`, `fork_project`, `save`, `rename`, `edit`, `script` and the other writers, and no `open_project` or
  `open_program` with `writable`. A request sent by another process (a prepare worker) is not in this log.
- **What the engine did.** `status` and `programs` are read back afterwards: every project has `writable: false`, every
  program has `mode: read_only`, no `writer` and `unsavedEdits` 0, and `imports.history.count` (the number of imports the
  daemon ever took) did not move during the adopt.
- **What the disk shows.** `lineage.tree_hash` of the project folder (files, sizes and SHA-256; it skips locks,
  `projectState` and manifests) before and after. For the KotOR copy the owner's own hash (SHA-256 over the sorted
  `path<TAB>size<TAB>sha256` lines of every file) is checked as well, and equals the value recorded for the original.

**The instruments were shown to see.** `test_the_measurement_can_see_a_writable_open` opens a copy of a prepared project
writable on purpose: `CommandLog.writable_opens()` reports both opens, the daemon reports a non-read-only program, and the
tree hash of the copy changes (`tree_changed_by_a_writable_open: true`). So a tree hash that does not move during adopt
means something.

## Results

Engine under test: the published 12.3-hydra.3 (protocol 2), and 12.3-hydra.2. Same tests, same outcome on both
(24 tests, `KotorLocal` skipped on hydra.2 because it is a local run).

### Prepare, concurrent, against `maxImports`

whoami and the 8 fixtures (x64 and x86 of flow, vcall, diff1, diff2) were all started at once against a daemon with
`maxImports` 2. A sampler read `status.imports` every 0.4 s (147 samples).

| Observation | Value |
| --- | --- |
| most imports running at once | 2 (= `maxImports`, never more) |
| most imports waiting at once | 7 |
| imports the daemon took | 9, one per build; gate empty at the end |
| wall time for all nine | 63 s (hydra.3, one run) |
| every job | `done`, analysed, hash equal to the manifest's, one target each |
| first query on each | a decompile at a manifest function address answers |

Per build (hydra.3): function counts 341 (whoami), 472 / 484 / 571 / 571 (x64 flow, vcall, diff1, diff2) and
542 / 557 / 650 / 650 (x86). Import 1.2 to 3.9 s (whoami 10.3 s), analysis 25 to 45 s.

**Defect found by this matrix, and fixed.** In the first full run one of the nine workers failed at once with
`backend setup is already running`: `backends.ensure` took `.backend.lock` without waiting even when the engine was
installed and nothing had to be set up, so workers that started together failed each other. This is the opposite of the
owner objective, and the matrix is where it shows. `BackendEnsureRace` reproduces it without an engine (six overlapping
workers: five failed; red log `_logs/Z5/red-ensure.log`). `ensure` now waits up to 30 s for the holder, honours
cancellation, and re-reads the backend state once it has the lock (the holder may have finished the install). The same
tests are green (`_logs/Z5/green-ensure.log`) and so is the full matrix.

### Cancel and a killed worker

Both start a prepare of `diff1.exe` (x64), wait until the daemon reports the import running, then interrupt it.

| | cancel through the job | worker killed (`TerminateProcess`) |
| --- | --- | --- |
| job state | `cancelled` | `interrupted` |
| import gate | drained | drained |
| daemon | alive | alive |
| target registered | none | none |
| program held by the daemon | none | none |
| program in the job's project | none (opened read-only and listed) | none |
| prepare again | new job, `done`, 571 functions | new job, `done`, 571 functions |

### Adopt, measured

On a project the test prepared itself (whoami, 341 functions): commands sent `open_project, list, open_program, list`;
tree hash identical before and after; `copied`, `imported` and `written` all false (derived by observation in
`targets.adopt`, not asserted); the daemon holds the program read-only; its import count did not move (1 before, 1 after).
A wrong build hash registers nothing and writes nothing.

### Legacy 12.1.4 project

The fixture (`examples/fixtures/legacy-12.1.4` of the engine repository, on E2's branch; a copy is made first) is a
database-version-32 project made from the public flow fixture. Its program was imported but never analysed (311
functions, `analyzed: false`), so adopt correctly refuses it (`is not analysed; prepare a fresh analysis instead`). What
the test pins: nothing is registered, no writable open, the engine still reads the old database read-only (a function
listing answers), the engine's upgrade cache builds in its own state folder (`building` at adopt, `ready` later), and the
project folder's tree hash is the same before the adopt, after the reads and after the cache build finished. The fixture
cannot show an adopt that is accepted; that needs an analysed 12.1.4 project, which the KotOR run below is.

### KotOR (local evidence, counts, seconds and hashes only)

Both the 4,042,752-byte game executable and the analysed project were copied to scratch before any engine saw them. The
original project was only hashed; its owner hash is
`6d8ced789b9f0945ee2ade42e75cf6db0a92c97ea4e65b8a353fd624860240df` before and after. Nothing derived from the game is
stored (no decompile, no export), and none of it is committed.

| | Value (hydra.3, one run) |
| --- | --- |
| executable SHA-256 | `0290889e0cea6ebc00021c1bdb945704fc4c45afaf7fcebabb0e82ba674437e6` |
| fresh prepare, wall | 186 s (an earlier run took 241 s; the foreign load was not controlled) |
| import / analysis | 11.2 s / 158.0 s (first run 10.5 s / 212.1 s) |
| functions after a fresh analysis | 8,956 |
| first query (function list plus one decompile) | 0.58 s (first run 0.75 s) |
| adopt of the analysed copy | 0.78 s (first run 1.34 s); 8,966 functions; its recorded SHA-256 equals the executable's |
| commands during adopt | `open_project, list, open_program, list` |
| tree hash of the project copy before and after adopt | `4089f7f72a83298d949b2e408e9432b1e4de55bf24c518ca12157f589f07c3ba`, unchanged; the owner hash also unchanged |

The fresh analysis finds 8,956 functions and the older project holds 8,966. The difference of 10 is reported, not
explained: the two analyses ran on different engines and options.

### Scripts

`userscripts.run` on a prepared program, one daemon, the scripts written by the tests.

- **Staged after the daemon started.** The daemon is running (pid recorded) before the script exists; the script is staged
  into `<root>/hydra/user-scripts`, runs, and the pid is unchanged.
- **Changed text, same name.** The second run prints the new text, not the old.
- **Collision.** A different script of the same name from another folder is refused with `a different X.java from <owner>`;
  the staged file is unchanged and `owners.json` still names the first owner. The same text from another folder is not a
  collision. A script named like one of Hydralysis's own is refused. These rules are also tested with no engine
  (`StageUnit`).
- **Compile error.** The error reaches the caller with the compiler's own line (`Broken.java:3: error: incompatible
  types`), the job record is `failed` with that text, and the daemon takes the next script.
- **Old-style script.** A GhidraMCP/REA-era script ported to headless use (arguments from `getScriptArgs()`, the listing
  walked with `getFirstFunction`/`getFunctionAfter`, a `// Usage:` header) runs, is listed with its usage line, and prints
  the engine's own count of non-external functions.
- **Mutating script on a copy.** A script that renames a function runs on a copy of the prepared project in
  `mode=contained`; it reports the new name, then the copy's tree hash and the original's are both unchanged, and the next
  script sees the old name.

### The `.py` decision

`userscripts.py` accepts `.py` in its name check, stages the file and sends it. The engine answers
`script did not load: Ghidra was not started with PyGhidra. Python is not available` on both installs. So a Python script
cannot run on this engine, and nothing in the repository starts it with PyGhidra.

**Decision: `.py` is not supported; it is dropped, not proven.** What this package does: the test
`test_a_py_script_never_runs_and_changes_nothing` pins the outcome that matters (the script never runs, the job ends
`failed`, the project is not touched, the next Java script runs) and accepts either a typed engine failure (today) or a
refusal of the name up front (after the change below). What it does not do: `userscripts.py` belongs to Y4e (W6), so the
change itself is left to Y4e: restrict `_SCRIPT` to `\.java`, refuse `.py` before staging with a message that names
PyGhidra, and list only `.java` files in `list_scripts`. Until then `list_scripts` still shows `.py` files.

## Limits

- One run per configuration; timings are under a shared load and move by tens of percent between runs (the two KotOR
  prepares above differ by 55 s). Counts, hashes and states are the findings; seconds are context.
- `maxImports` was set to 2 for the matrix. The daemon's default (this machine: 4) is not what was measured.
- The cancel and kill tests interrupt a prepare of one build; a kill during the final registration step, or a kill of the
  daemon itself, is not covered here.
- The engine under test has no per-command log; the "command log" is the client side plus the daemon's own status, as
  described above. An engine that sends a request this process did not make cannot be seen by `CommandLog`.
- Not covered by this package: protocol-3 engines (none of these installs speaks it), `ghidra_run` isolation modes (Y4e),
  and ReFS behaviour (all of this ran on NTFS).
