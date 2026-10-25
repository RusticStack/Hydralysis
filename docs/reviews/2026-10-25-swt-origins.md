# RusticRE on SWTOR-origins: native-hook verification and a warm function dossier

**Project:** SWTOR-origins (private-server reconstruction from a user-owned retail client)
**Date:** 2026-10-25
**Target:** `D:\Games\Star Wars - The Old Republic\swtor\retailclient\swtor.exe`
**SHA-256:** `0f32b9d9562dafce89be662014615e0cc288f042a3fcfbbd8c38271abcd690f5` (build 25812320, x64)
**Ghidra project:** `F:\dev-cache\ghidra-projects\SWTOR-origins\client` (read-only; RusticRE copied its own snapshot)
**Boundary:** user-owned binary, read-only project, no hooks installed, no imports, no saved edits.

## 1. Tasks and exact workflows

I did not use a synthetic sample. Both tasks come from current work: a launcher-owned native capture kit that hooks 21 engine functions, and an opcode corpus whose two largest bodies are still undocumented.

### Setup (one-time)

```
git clone --depth 1 https://github.com/RusticStack/RusticRE F:\dev-cache\rusticre-self-20261025
$env:PYTHONPATH="F:\dev-cache\rusticre-self-20261025\src"
# rusticre.local.json (not committed): root on F:, ghidra_12.1.4_PUBLIC, JDK 25,
# targets.swtor = {dir: .../client, name: client, program: swtor.exe, exe: ...}
```

First attempt used `dir: F:/dev-cache/ghidra-projects/SWTOR-origins` and failed with
`analysed project is missing client.gpr or client.rep under ...`; the field wants the directory
that **contains** `client.gpr`. After that correction, `ghidra-query --action status`
returned `{"alive": false, ...}` in 182 ms.

### Task A — verify the capture hook table (real work)

The kit pins 16-byte prologues for 21 RVAs in `tools/capture/native-hooks.json`. If any prologue
moves, the kit must refuse to attach. I checked three sites with RusticRE:

```
python -m rusticre prologue --exe <swtor.exe> --expect "48 8B C4 48 89 48 08 56 57 41 54 41 56 41 57 48" rva:0x43cf20
python -m rusticre prologue --exe <swtor.exe> --expect "48 8B C4 55 41 54 41 55 41 56 41 57 48 8D A8 58" rva:0x43bb70
python -m rusticre prologue --exe <swtor.exe> --expect "48 8B C4 48 89 50 10 56 57 41 56 48 83 EC 60 48" rva:0x43b460
python -m rusticre inspect --exe <swtor.exe> rva:0x43cf20
```

All three returned `PROLOGUE MATCH`. `inspect` reported the router as
`0x43cf20-0x43d37f size 0x45f`, a prologue dump, the first instructions, and one call candidate
from `0x43bdd5`. It also printed `instruction boundaries unverified; limit 12`, which is an
honest statement that the caller list is a byte-pattern heuristic, not a Ghidra xref.

Measurements: 171–196 ms per prologue call (dominated by process start), 385 ms for `inspect`.
Each call re-opened and re-hashed the 30,680,576-byte image.

### Task B — warm decompilation and references for the router

`FUN_14043cf20` is the inbound message router registered in our catalogue. The function is
already analysed, so this is exactly the repeated query the project does all day.

```
python -m rusticre ghidra-query --target swtor --action decompile 0x14043cf20 --timeout 120
python -m rusticre ghidra-query --target swtor --action decompile 0x14043bb70 --timeout 120
python -m rusticre ghidra-query --target swtor --action xrefs 0x14043cf20 --limit 20 --timeout 120
```

Observed:

* cold decompile: **5,998 ms**, 7,475-byte JSON (metadata + C), `function.body` `[0x14043cf20, 0x14043d37e]`, `body_truncated: false`, `sha256` echoed;
* warm decompile of a second function: **294 ms**, 5,423 bytes;
* warm xrefs: **236 ms** total, `query_s: 0.051`, three references — two `DATA` (`0x14206d0ac`, `0x14184f2a0`) and one `UNCONDITIONAL_CALL` from `0x14043bdd5`, `truncated: false`.

The Ghidra xref agrees with the `inspect` caller candidate. The signature and decompiler text are
the same as our Ghidra headless output, as expected: RusticRE drives the same engine.

## 2. Better, equal, worse than our REA + Ghidra workflow

**Better.** The warm path is the difference that matters here. Our Ghidra batch lane returned the
same router decompilation in **5.9 s wall** (6,438 bytes) on a warm machine, because every call
launches a headless JVM and opens the project. RusticRE returned the equivalent in **0.29 s** warm,
with structured metadata (`address_kind: VA`, hash, function bounds, truncation flag, worker log
path) that our script wraps by hand. Across a 30-function sweep that is ~3 minutes versus ~25 s.

**Equal.** Decompiler quality is identical — same Ghidra version, same project snapshot. Both
report the same `FUN_14043cf20` signature. `inspect` (PE only) works without a JVM and without a
prepared project, which is useful because our capture kit only needs bytes.

**Worse.** RusticRE has no basic blocks, p-code, value flow or bounded def-use tracing; REA's
dossier remains the only one-call answer for "where does this field come from". RusticRE also has
no saved type/symbol/comment edits, no interactive type recovery, and no import/analyse-once job
for a new binary (merged PR #2 documents that). For our GOM field-writer questions, REA is still
the tool.

## 3. What failed or was clumsy

1. **Prologue format mismatch.** Our table stores contiguous hex (`488bc448...`). `prologue --expect`
   accepts space-separated bytes only and rejected the contiguous form with
   `ValueError: prologue byte out of range`. I had to reformat by hand; a 21-hook verification
   otherwise means parsing and reformatting our JSON outside the tool.
2. **Address-intent inconsistency.** PE tools require/accept explicit `rva:`/`va:` (PR #2), but
   `ghidra-query` rejected `va:0x14043cf20` with `ValueError: use a numeric Ghidra VA, not a symbol
   name`; bare `0x14043cf20` worked. The same session therefore uses two address conventions.
3. **Config `dir` semantics.** The error names the missing file, but the field is the project
   directory itself, not its parent. One failed cold start per target is easy to avoid.
4. **Inspect caller semantics.** The heuristic caller list can differ from Ghidra xrefs (it found
   only the call, while xrefs also found two data references). The warning is present but easy to
   miss; callers and data references should not look like the same claim.
5. **Our own trap, not RusticRE's:** the Ghidra headless call with the RVA `0x43cf20` exited 0 and
   printed `no function at 0x43cf20`. RusticRE's explicit `address_kind` would have caught this
   class of mistake if it also accepted prefixed VAs.

## 4. What I would change

**Extend existing tools (preferred).**

* `prologue`: accept contiguous hex and `--expect-file`, and add `--table <hooks.json>` so one call
  verifies all 21 pinned sites and emits one JSON line per site plus a summary count. This is a
  repeated task in our project, not a new concept.
* `prologue`/`inspect`: accept `rva:`/`va:` consistently with `ghidra-query`; make `--expect`
  normalization shared across CLI and MCP.
* `inspect`: emit `call_candidates` and `data_refs` as separate keys, with the existing
  "unverified boundaries" note attached to the former.
* `ghidra-query`: accept prefixed addresses and echo `address_kind` (already in the JSON) from the
  request side too.
* Config loader: if `dir` contains no `.gpr` but a single child directory does, name that child in
  the error or resolve it.

**New tools that earn their place.**

* A bounded **function dossier** action (`ghidra-query --action dossier`) returning, in one call:
  bounds, signature, decompile (capped), callers/callees, data refs, referenced strings, and basic
  block count/edges (no p-code). This replaces the four-to-six calls we make per function and is
  the closest honest substitute for REA's dossier. Output goes to a file above a size threshold,
  with counts/hash inline.
* A **batch table** job for hook tables (same lifecycle as `ghidra-run`: id, async, bounded log) so
  100–200 sites can be checked without 200 process starts.

**Not add.** No per-game tools; no second decompiler; no REA-style unbounded p-code dump; no
filesystem sandbox claims for custom scripts.

## 5. If REA and the Ghidra MCP were removed

RusticRE would need to absorb these shapes, in priority order:

1. **Batch verification** (`prologue --table`, async job, JSONL result, exit nonzero on mismatch).
   This is cheap and fully replaceable today.
2. **Function dossier** (one call, bounded C + callers/callees/xrefs/strings + block edges; full
   text to a file, ≤8 KB inline; cursor for later pages). This replaces most of our REA use.
3. **Bounded def-use / value-flow** for a field offset inside a function (source line, instruction,
   register chain, stop conditions, max depth). Hard; if not implemented, this is the one question
   that still needs REA.
4. **Preparation lifecycle** (`prepare`/`job` with hash, analysed flag, project snapshot) so a new
   capture build does not require manual Ghidra import. PR #2 lists this as a known gap.
5. **Working-copy writes** for names/types in a lane, applied with prologue checks — not in the
   master. Without this, symbol work still needs Ghidra.

What cannot be replaced: interactive type recovery, saved type/symbol edits, and p-code-level
reasoning. Ghidra headless remaining is a different, larger problem than removing the MCP.

## 6. Work that stays outside RusticRE

* Dynamic work: the native capture kit, live GOM dumps, Frida sessions, movement/death validation
  against a running client. RusticRE is static by design.
* Interactive type recovery and data-type editing for GOM classes (thousands of fields).
* Non-PE targets: none in this project today, but the server tooling and capture kits are not PE.

## 7. Evidence boundary

Every command above ran against the user-owned retail client read-only. The Ghidra master was
never written: RusticRE copied its own snapshot under `F:\dev-cache\rusticre-self-20261025\work`
and used `-process -noanalysis -readOnly`. No hooks were installed, no imports were added, no
symbols or comments were saved, and the capture kit was not running. The local config, snapshots,
worker logs and evidence database are uncommitted. Counts and addresses are from the tool output;
no large decompiled body is reproduced here.
