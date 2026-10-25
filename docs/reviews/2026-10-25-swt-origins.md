# RusticRE on SWTOR-origins — usage review

Status: **documentation only.** No code changes are included in this pull request. The findings
come from using RusticRE's CLI and MCP surface against a user-owned retail SWTOR client while
answering two questions that come up in normal preservation work. The protocol findings stay in
the SWTOR-origins project; this document records tool behaviour only, with no game assets or
decompiled program text.

## Target

| field | value |
|---|---|
| executable | `swtor.exe`, build 25812320 |
| SHA-256 | `0f32b9d9562dafce89be662014615e0cc288f042a3fcfbbd8c38271abcd690f5` |
| format | PE32+, x64, image base `0x140000000`, 30,680,576 bytes |
| Ghidra project | `client.gpr` / `client.rep`, previously imported and analysed, opened read-only from a RusticRE snapshot |

## What was run

The two questions were: "are the 21 hook prologues in our native capture kit still true?", and
"what does the inbound message router do with a frame?". Both are static questions against a
project that is already analysed.

PE tools, without starting a JVM:

* `prologue` at `rva:0x43cf20` (router), `rva:0x43bb70` (frame decoder) and `rva:0x43b460`
  (frame queue) with the pinned 16-byte sequence from our hook table. All three returned
  `PROLOGUE MATCH` in 171–196 ms per call.
* `inspect` at `rva:0x43cf20` returned the function bounds `0x43cf20–0x43d37f` (`0x45f`), the
  prologue, the first instructions and one call candidate from `0x43bdd5`. It also printed
  `instruction boundaries unverified; limit 12`, which correctly marks the caller list as a
  heuristic.
* `fingerprint` identified the image and hash before anything else, which is the check our kit
  depends on.

Ghidra path, with the prepared project:

* `ghidra-query --action decompile 0x14043cf20` returned the router with body
  `[0x14043cf20,0x14043d37e]`, `body_truncated: false`, the program SHA-256 and `address_kind: VA`.
  Cold call: 5,998 ms; 7,475 bytes.
* A second decompile (`0x14043bb70`) took 294 ms warm, 5,423 bytes.
* `ghidra-query --action xrefs 0x14043cf20` took 236 ms in total (`query_s: 0.051`) and returned
  three references: two `DATA` (`0x14206d0ac`, `0x14184f2a0`) and one `UNCONDITIONAL_CALL` from
  `0x14043bdd5`. That call matches the `inspect` candidate.

For comparison, our own Ghidra headless lane returned the same decompilation in 5.9 s wall with
the same signature, because it starts a JVM for every request.

The practical result: RusticRE verified the hook table with PE tools and returned the analysed
router with a warm worker. The address, hash and function bounds were explicit in every reply.

## What worked well

* Warm queries are the difference that matters for this project. 0.29 s versus 5.9 s per
  decompilation is roughly twenty times cheaper across an opcode sweep, and the response already
  carries the hash, address space and function bounds that our scripts otherwise reconstruct.
* The PE tools work before any Ghidra setup and are enough for prologue and hash checks.
* `rva:`/`va:` input on the PE side, and the ambiguity error, make the intended address space
  explicit.
* The small catalog stays out of the way. There is no need to reach for a 200-tool server to
  answer one function question.
* `inspect` bounds were exact for this PE32+ image, and its caller candidate agreed with the
  Ghidra xref.

## What failed or was clumsy

### 1. Contiguous-hex prologues are rejected

Our hook table stores the pinned bytes as one lowercase string:

```text
488bc448894808565741544156415748
```

`prologue --expect` splits on whitespace, so the whole string is read as one number and the call
fails with:

```text
ValueError: prologue byte out of range: 488bc448894808565741544156415748
```

Space-separated bytes work. Reformatting a 21-row table outside the tool is exactly the friction a
batch mode should remove, especially because our table is the natural input.

### 2. `ghidra-query` rejects the `va:` prefix that the PE tools require

`ghidra-query --action decompile va:0x14043cf20` returns:

```text
ValueError: use a numeric Ghidra VA, not a symbol name
```

Bare `0x14043cf20` works. In one session I therefore used two address conventions: explicit
prefixes for PE tools and a bare number for the query tool. This is the same address-space
ambiguity that PR #2 fixed on the PE side; the query path did not get the same treatment.

### 3. The target `dir` must be the directory containing the `.gpr`

I first supplied the parent of `client.gpr` and got:

```text
ValueError: analysed project is missing client.gpr or client.rep under F:\...\SWTOR-origins
```

The message is truthful, but the field is the project directory itself, one level below what I
passed. A resolver that accepts a single child directory, or an error naming the exact expected
path, would remove one cold-start retry per target.

### 4. `inspect` caller candidates and Ghidra xrefs are different claims

`inspect` found one call candidate. `xrefs` found the same call plus two `DATA` references. Both
are correct for their semantics, but they are printed in a similar shape, and the only warning is
a trailing note (`instruction boundaries unverified; limit 12`). A reader can easily treat the
shorter list as "all references". Splitting the two keys would make the distinction structural
rather than textual.

### 5. Our own trap, and the contrast worth keeping

When I passed the RVA to our Ghidra headless script, it exited **0** and printed
`no function at 0x43cf20`. That is our bug, not RusticRE's, but it shows why the explicit
`address_kind` in RusticRE's reply matters. The safer default is to make every tool reject an
address whose space is not stated, rather than to rely on the caller to remember.

## Proposed follow-ups

These are proposals only; none is implemented here.

### A. Make `prologue` a table tool

This is the highest-frequency change for this project.

* Accept contiguous hex (and `0x`-prefixed or comma-separated bytes) in `--expect`, in addition
  to the current space-separated form.
* Add `--expect-file` for one site and `--table <hooks.json>` for many. Our table is a list of
  `{offset, names, prologue}` rows.
* Open and hash the image once, then emit one JSON line per row:
  `{name, rva, expect, actual, match}` with a `{checked, matched, failed}` summary.
* Exit non-zero on any mismatch.
* Add a test that a contiguous 16-byte value matches, a wrong byte fails, and the 21-row table
  produces 21 results from one process.

This is an extension of an existing tool, not a new concept, and it turns a scripted loop into
one command.

### B. Accept `rva:`/`va:` in `ghidra-query`

* Parse the same explicit prefixes the PE tools accept and reject ambiguous bare addresses.
* Keep unambiguous bare VAs working, as PR #2 did for PE tools.
* Echo the interpretation in `address_kind` (already present).
* Add a test that both prefixed forms reach the same function and that an ambiguous bare value is
  refused.

### C. Split `inspect` call candidates from data references

* Emit `call_candidates` and `data_refs` as separate keys.
* Keep the "unverified boundaries" note attached to the call candidates only.
* Add a test where a function has one call site and two data references, and assert the counts
  remain separate.

### D. Add a bounded function dossier

The router question cost two calls here; adding callers, callees and referenced strings would
cost five or six. That per-function overhead is the dominant cost in a 79-opcode backlog.

* `ghidra-query --action dossier <VA> --out func.json --inline-bytes 8192 --max-refs 100`.
* Return bounds, signature, capped decompiler text, callers, callees, data references, short
  referenced strings, block count and edges, `truncated`, and a cursor.
* Above the inline cap, write the full text to a file and return its path, byte count and SHA-256.
* Add a test for the cap, a later cursor page, and an explicit error for a missing function.

This is the closest honest substitute for a one-call REA dossier. It should not try to reproduce
p-code or value flow.

### E. Resolve the target directory, or name it exactly

* If `dir` contains no `.gpr`, look for a single child directory that does; otherwise fail with
  the exact path it expects.
* Add a unit test for both the resolved and the ambiguous case.

### F. Leave the rest alone

Do not add per-game tools, a second decompiler, or unbounded listings. Do not move initial
analysis, interactive type recovery or saved symbol/type edits into RusticRE. Those are the parts
that should keep using Ghidra.

## When I would still use REA

RusticRE does not implement basic blocks, p-code, value-flow or bounded def-use tracing. For our
next question after "what does this handler do" — "where does this GOM field value come from" —
REA remains the right call. That is an analysis gap, not a tool-count problem, and it should not
be filled by copying REA's surface into RusticRE piece by piece.

## When I would still use Ghidra

RusticRE opens an already analysed copy and never imports. Initial analysis, interactive type
recovery, and persisted renames, types and comments still belong to Ghidra. This project's client
was prepared separately; RusticRE was fast because that work already existed. A make-once
preparation job in RusticRE would be welcome, but it is a separate decision from warm queries.

## Where RusticRE fits

For this project, RusticRE is the first call for build fingerprints, hook-byte and prologue
checks, bounded decompilation of an already-analysed function, and reference lookups. It keeps
the context small and the build hash explicit. REA remains the deeper analysis tool, and Ghidra
remains the initial-analysis and authoring environment.

## Evidence boundary

* The executable is user-owned and was not modified.
* No game, hook or Ghidra import was launched for this review.
* RusticRE copied its own project snapshot; the master was opened read-only and no saved symbols
  or comments changed.
* This PR contains no game assets, saves, extracted data or decompiled program text.
* The protocol and capture findings remain in the SWTOR-origins project.

## Conclusion

The warm-query workflow is useful and should stay small. Two changes are worth doing first:
**A** (a prologue table mode, because hook verification is a recurring loop) and **B** (consistent
address intent between PE and query tools, because one session should not use two conventions).
**C** and **E** are small clarity fixes. **D** is the one larger addition that would pay for itself
across a 79-opcode backlog; p-code and value flow should stay with REA.
