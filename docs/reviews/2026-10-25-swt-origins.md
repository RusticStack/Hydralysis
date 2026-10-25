# RusticRE against a 30 MB game client: SWTOR-origins evaluation

Evaluator notes from real work in `F:\projects\SWTOR-origins` on 2026-10-25.
RusticRE 0.2.0 at `main` (`6ea3358`, after PRs #1 and #2). Timings are single
wall-clock samples that include process start; each observation is stated next
to its command. No claim here rests on an unrecorded run.

Target: `D:\Games\Star Wars - The Old Republic\swtor\retailclient\swtor.exe`,
SHA-256 `0F32B9D9562DAFCE89BE662014615E0CC288F042A3FCFBBD8C38271ABCD690F5`,
version 3.2.2.0, timestamp `0x6ac6a73e`, image base `0x140000000`, entry RVA
`0xfd7a80`, 30,680,576 bytes (29.3 MiB, not the 50 MB in the brief). The saved
Ghidra project was copied to `client-rusticre-eval`; RusticRE then copied that
copy into `F:\dev-cache\rusticre-swtoreval-work`.

## 1. Tasks and exact workflows

### 1.1 Hook-site verification (`frameDecoder` 0x43bb70, `router` 0x43cf20)

Compared against `tools/capture/native-hooks.json`, which pins 16 prologue
bytes per hook.

RusticRE, PE path, no JVM:

```
rusticre inspect --exe <swtor.exe> rva:0x43bb70
rusticre prologue --exe <swtor.exe> --expect "48 8B C4 55 41 54 41 55 41 56 41 57 48 8D A8 58" rva:0x43bb70
rusticre inspect --exe <swtor.exe> rva:0x43cf20
rusticre prologue --exe <swtor.exe> --expect "48 8B C4 48 89 48 08 56 57 41 54 41 56 41 57 48" rva:0x43cf20
rusticre sigscan --exe <swtor.exe> --limit 8 -- "48 8B C4 55 41 54 41 55 41 56 41 57 48 8D A8 58"
```

Results. `inspect` reported unwind bounds `0x43bb70-0x43be91` (size 0x321) and
`0x43cf20-0x43d37f` (size 0x45f), the pinned prologues, and three and one byte
call candidates. `prologue` printed `PROLOGUE MATCH` for both. `sigscan`
returned three hits for the frameDecoder pattern (`0x3548f0`, `0x355350`,
`0x43bb70`) — the pattern is not unique, so the pinned RVA, not the scan, is
what disambiguates. Five calls total, each 175–425 ms, 251–1,399 bytes each.

Ghidra headless, through the existing read-only batch lane (one JVM per call):
`Disasm.java 14043bb70 14043bb90` (5.46 s), `Disasm.java 14043cf20 14043cf40`
(5.23 s), `FnRange.java 14043bb70 14043d380 20` (5.58 s). Prologues agree byte
for byte, and Ghidra's function sizes 801 and 1119 equal 0x321 and 0x45f. All
three static sources agree on bytes and bounds; the cost differs by ~25×.

REA was attempted and did not get there. `rea.open_binary` on the same path
answered in 4.66 s with the correct SHA-256 and format `pe`, then
`rea.analyze_function({procedure: "0x14043bb70"})` returned
`provider_timeout`, `timeout_ms: 600000`, `failure_message: "Ghidra startup
deadline elapsed"`. Its diagnostics show why: the provider binds
`import_mode: "ephemeral-source-immutable"` and re-analyses the artifact in a
temperature directory instead of opening the analysed project. No prologue
bytes came back. The reused-project patch in our `re-rea` skill is not active
here, so "REA first" would have cost a full import.

### 1.2 Undocumented body: inbound 0x23B61278 / outbound 0xF96DCDA6

Registry and catalogue first. `data/protocol/registry.json` lists both as
`layout.status: "unknown"` ("body layout not decoded"). 0x23B61278 is inbound,
handler `0x140133890`, dispatcher `0x140143850`; 0xF96DCDA6 is outbound,
handler `0x1403E27C0` (static candidate). Ghidra headless
`FindOpcode.java 0x23B61278 0xF96DCDA6` (6.44 s) found the immediate twice per
direction: `0x1401443c4` in `FUN_140143850` and `0x14053499b` in
`FUN_1405348c0`; `0x1403e2908`/`0x1403e2953` both inside the sender.

The vtable "handler" is not a parser: `0x140133890` is a loop over 0x28-byte
records calling a guard-dispatched function per record, and all four of its
references are data, not code. The real reader is the dispatcher's case body,
which for `0x23B61278` calls `FUN_140141b60` and then checks the frame was
consumed.

`FUN_140141b60` (RusticRE, 366 ms, 5,238 characters) reads a `u32` at the
reader cursor, grows a vector to that many 0x28-byte entries, and per entry
calls `FUN_1403fb260` to read a `u32` length and points the entry at
`cursor`/`length`. `FUN_1403fb260` (301 ms) refuses a length outside the
caller's bounds ("Element has length that is below the minimum" / "…above the
maximum"). The writer, `FUN_1403fad30` (228 ms), writes a frame's `u32` size at
+0x10 and memcpys its +0x18 buffer — the length prefix, in code.

The capture agrees exactly. In `F:\dev-cache\capture-audit\cap2254-decoded.jsonl`
(41,745 records, 57 opcodes) all 2,554 inbound bodies parse as `u32 count` then
`count × (u32 length + bytes)` with zero bytes left over, and all 2,508 outbound
bodies parse as `u32 length + bytes`. The inbound records carry 3,107 entries
of 18–2,856 bytes (mode 77, 1,922 of them), up to 11 per message.

Proved: the container framing, at both code and byte level. Proved: every one
of those 3,107 entries and 2,508 payloads starts with the same 10-byte run
`cf ef e1 98 01 0c e8 3b 4d cf`. Not proved: what it is. It also sits at offset
4 or 8 in five further opcodes (7 opcodes, 7,058 records), it is absent as a
literal from the image (`sigscan` for the 10 bytes and for
`cfefe198`/`010ce83b`/`04d9d3ad` returned zero hits), and the functions above
do not write it. The inner field alphabet is also undecoded: some outbound
blobs hold one-byte-length ASCII (`Windows 8`, `en-us`) and IEEE-754 floats
(1.0, 1.25, 1.0 at offsets 30/34/38 of the 77-byte body), consistent with a
typed field stream, but no field ids or types are claimed.

### 1.3 Bounded function inventory (0x140130000–0x140140000)

RusticRE has no range filter, so I paged `--action functions` with
`--contains FUN_14013` (address-derived names act as a crude range filter),
followed `next_cursor`, then ran `inspect` per address: 284 calls, 48,121 bytes
of pages for 279 entries plus a 110.3 s loop, ending in
`F:\dev-cache\rusticre-swtoreval-work\fn-inventory-14013.csv` (30,988 bytes:
address, name, fragments, pdata bounds, size, prologue16).

Comparisons. Ghidra headless `FnRange.java 140130000 140140000 400` returned
280 functions with sizes in one 10.9 s call and 10,464 bytes — 37 bytes per
function against RusticRE's 172, whose JSON repeats signature and body arrays
and still lacks the two fields I wanted. 99 of 279 (35%) have no `.pdata`
entry: `inspect` prints "no pdata function contains …" with no bounds or
prologue, and exits 0. 17 functions have several fragments (max 36, the area
reply dispatcher), so "size" is ambiguous — Ghidra's `size` is the inclusive
extent, summing fragments is exact for 136 of 180 and off by small padding
amounts for 44, and end-minus-start subtraction is off by one for all 180.

Full-program enumeration is worse than it looks: 60 pages of 200 entries,
12,000 functions, 1,947,698 bytes and 16.4 s, and the cursor had not reached
the end. There is no total count and no way to ask for one range.

### 1.4 MCP surface

Spoke newline JSON to `rusticre mcp` directly. `initialize` 123 ms / 801 bytes;
`instructions` 601 bytes; `tools/list` 6,479 bytes, 20 tools, largest schema
624 bytes. `inspect` 245 ms / 1,498 bytes, `prologue` 26 ms / 350 bytes,
`ghidra_query` 83 ms / 1,229 bytes — it reused the worker the CLI started (same
session path and PID) — `status` 3 ms. `evidence_add` stored a prologue claim
and `evidence_list` returned it with its source; the server exited 0.

## 2. Better, equal, worse than the REA + Ghidra workflow

Better, clearly: the PE path. Hook bytes and bounds in 0.2–0.4 s per call with
no JVM, against 5.2–5.6 s per Ghidra headless call here, and against a REA
attempt that could not finish startup within 600 s. A cold `ghidra-query` cost
5.1 s (4.8 s of it snapshot copy/startup, 0.10 s query); warm decompiles were
0.36–1.32 s. That is the difference between a check you run and one you avoid.

Equal: decompiler text. For `FUN_140141b60` the RusticRE text and the
`DecompFn.java` text are identical after whitespace normalisation — 164
non-blank lines, no differences in the C body (both Ghidra 12.1.4).

Worse: questions that need more than one address. No range query, a hard cap
of 200 results per page, no bulk prologue export, a 32,000-character decompile
cap (the area dispatcher is 46,087 characters, so it came back `truncated: true`
with `total_characters` set — honest, and still a second strategy), and no
basic blocks, p-code, value flow or def-use. Empty pages are the practical
cost: a search that matches nothing still costs a call and 536 bytes.

## 3. Failures and clumsiness (exact)

1. Default worker root broke Ghidra. With `root` under `.rusticre`, the first
   `ghidra-query` failed in 2.46 s: `RuntimeError: Ghidra exited 1 before ready`,
   log `Path element starting with '.' is not permitted`. The shipped
   `.gitignore` invites exactly that layout; a non-dot root fixed it, and the
   README does not mention the restriction.
2. Contiguous hex is rejected. `--expect 488bc4…` and the same string in
   `sigscan` both died with `ValueError: prologue byte out of range:
   488bc455…` (74 bytes, exit 1). Space-separated tokens work. Our
   `native-hooks.json` stores contiguous hex, so every check needs a
   re-formatting step.
3. `--limit 400` on `--action functions`: `ValueError: limit must be 1..200`.
   The README says a page examines at most 2,000 entries but never states the
   200-result cap, and an empty page (`functions: []`, `truncated: true`,
   exit 0) is indistinguishable from failure without reading counts.
4. `inspect` on a function without unwind data exits 0 and prints
   `no pdata function contains 0x130240`, then disassembles anyway. Scripts have
   to parse prose to tell "no bounds" from "found".
5. Address spaces in one session: `sigscan` answers in RVAs (`0x43bb70`),
   `inspect` prints `0x0043bb70`, `xrefs` and `ghidra-query` answer in VAs
   (`0x140133890`). `rva:`/`va:` fixed ambiguity on input (PR #2), but nothing
   converts or labels the output, and no command takes an RVA and asks Ghidra.
6. REA's error payload is 37,461 bytes of Ghidra startup log plus 1,744 of
   stderr, inline in the JSON — diagnosable and unreadable in a tool result.
7. `evidence-add` needs `--target --build --kind --name --note --source`; the
   README's one-line example implies only a claim and a source. First attempt
   exited 2 on usage.
8. `--action function` gives body fragments and no size; on the 36-fragment
   dispatcher a consumer must know the inclusive-end convention to compute one.

## 4. Changes I would make

To existing tools: reject or rewrite a dot-leading `root` at startup (one-line
check; the failure should name the config key); accept contiguous hex in
`--expect`/`--pattern`; print the 200 cap in the help; give `functions`
`--start/--end` and `--out FILE` so an inventory never crosses the model
context; add `size` and `prologue` to `--action function` (free from PE plus
body range); give `inspect` a machine-readable "no bounds" status; label
`address_kind` in `sigscan` output as `ghidra-query` already does; allow an RVA
with `--target` so one command can hop from PE offset to decompiler; make
`evidence-add` derive `build`/`kind`/`name` when omitted.

Genuinely new: a bounded inventory op (`inventory --range A-B --out f.jsonl`)
merging saved-analysis bounds with PE prologues and returning counts plus a
path. That is the one shape missing for subsystem work, and it is small. The
fresh-binary preparation lifecycle PR #2 documents as missing is the other real
gap, but it is a milestone.

Do not add: opcode/registry tooling for one game (our registry stays in our
repo); p-code, basic blocks or value flow (that is REA's remaining reason to
exist); automatic import on a query (the current refusal is correct);
decompiler output above the cap by default; a second address syntax.

## 5. What RusticRE must absorb if REA and the Ghidra MCP disappear

Ghidra headless survives, so the vacuum is the interactive layer, not the
analysis. To replace REA's dossier and the MCP's ad-hoc scripts:
- One function, one answer: address in, bounds + prologue + instructions +
  callers + callees + xrefs + decompiled C out, with coverage stated per facet
  and truncation flagged. The pieces exist; they are separate commands today,
  one process each.
- Bounded paging everywhere: functions and xrefs page; strings, callers and
  callees do not. Every list needs a cursor, a cap in the schema and a
  `truncated` flag.
- Async: one warm worker per target with a request lock is right; what is
  missing is a job handle for long work (`ghidra-run` is synchronous
  JVM-per-call). A `--wait/--job` pair with a durable log path would cover it.
- Working-copy writes: snapshots are copied and opened read-only, so a rename or
  a comment needs the interactive Ghidra UI. A lane that copies, lets a script
  edit and records the diff would absorb the MCP's most-used feature without
  touching the master.
- Context budgets and file outputs: 172 bytes per inventory entry and 32,000
  characters per decompile are the numbers that decide whether an agent can
  work. `--out FILE` (JSONL, one object per function, build hash in each
  record) for anything over ~20 KB, plus a summary line, would cut most of our
  call cost.

Cannot be replaced by this: p-code, value-flow/def-use, typed basic blocks,
interactive type recovery, non-PE formats, and anything runtime (see §6).

## 6. Still needs dynamic, interactive or non-PE tooling

The 10-byte run at the head of every blob in §1.2 is the concrete example: two
decompiled functions and 5,062 records bound it but do not explain it. Settling
it needs a second capture from another session (to separate a session constant
from a message constant) or a live breakpoint on the frame encoder — our native
hook lane, not a static query. Type recovery for the field stream (float
triples, length-prefixed strings, field ids) is interactive Ghidra work. Our
other lanes — SCPT containers, `.tor` assets, the .NET launcher — are outside a
PE-only server by construction. Hook verification also stops at static bytes:
RusticRE can say the prologue matches, never that the JVM installed the hook
safely; that stays with `tools/capture`.

## 7. Evidence boundary

The binary is user-owned and was read only; SHA-256 was identical before and
after (`0F32B9…690F5`), file mtime 2026-10-19. The master project at
`F:\dev-cache\ghidra-projects\SWTOR-origins\client` was never opened in place —
its `.gbf` mtime is still 2026-10-18 — and every Ghidra call used the existing
batch lane or RusticRE's own copy at `client-rusticre-eval`. No import, no
saved edit, no hook, no attach, no port. Work products (config, snapshots,
logs, CSV) live under `F:\dev-cache\rusticre-swtoreval-work` and the clone;
none of it is committed. Capture statistics are counts and structure only.
