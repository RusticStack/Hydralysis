# Saved-analysis capabilities and upstream research

Inspected upstream through `gh` and local reference checkouts outside Hydralysis.
REA revision: `f196ebf80665107aedc16892af25a1e1f9f26f43`.
GhidraMCP revision: `1e980252087b2479a21b9ca6d82d5829538651a7`.
No upstream implementation was copied into this repository or installed as a
runtime dependency. Both projects ultimately call Ghidra's analysis APIs; a
small independent adapter can expose those APIs without loading either MCP.

## What the source established

REA's
[type inspection](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/bridge/ghidra/ReaGhidraBridge.java#L1170-L1258)
reads category-path type identities and typed program data, with explicit
limitations on source authority. This is materially different from guessing
an object's layout from a function name. Hydralysis now exposes bounded `types`
and `type` query actions, including fields, offsets, lengths, enum values,
pointees, arrays and typedef bases. `variables` reports the decompiler's
recovered local/parameter types and storage, marked as recovered rather than
original source types.

REA's
[function analysis and high p-code](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/bridge/ghidra/ReaGhidraBridge.java#L1553-L1828)
derive a function dossier, operations, input/output varnodes and def-use links
from Ghidra's `HighFunction`. Its
[trace service](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/src/application/native/NativeValueTrace.ts#L24-L130)
limits attempted decompilations and preserves partial observations when a
non-seed callee refuses. These sources justify bounded flow queries, not
registering one MCP tool for every intermediate representation.

GhidraMCP's
[variable and function type operations](https://github.com/LaurieWired/GhidraMCP/blob/1e980252087b2479a21b9ca6d82d5829538651a7/extension/src/main/java/com/lauriewired/ghidramcp/core/GhidraAnalysisService.java#L544-L603)
use `HighFunctionDBUtil`, a C signature parser and Ghidra commands. Its
[transaction wrapper](https://github.com/LaurieWired/GhidraMCP/blob/1e980252087b2479a21b9ca6d82d5829538651a7/extension/src/main/java/com/lauriewired/ghidramcp/core/GhidraAnalysisService.java#L684-L709)
commits only a successful action. Hydralysis uses those public Ghidra APIs with
its own validation and a different persistence model: cited overlays outside
the canonical project.

API signatures were checked against the installed Ghidra 12.1.4 source/Javadoc
archives, including `HighFunction`, `PcodeOpAST`, `VarnodeAST`,
`HighFunctionDBUtil`, `DataTypeManager`, `BasicBlockModel`, `DataUtilities` and
`ApplyFunctionSignatureCmd`. Runtime validation belongs to the coordinator's
small owned fixture; no game-wide analysis was launched by this investigation.

## Query protocol

The query worker now serves a private authenticated socket bound to IPv4
`127.0.0.1` on an ephemeral port. Its random 256-bit token is retained only in
local startup metadata and is removed from public status/MCP output. Each
connection carries one four-byte big-endian-length UTF-8 JSON request and one
response, bounded to 32 MiB and 16 MiB respectively. Request IDs are exactly
32 lowercase hexadecimal characters. Authentication is constant-time; malformed
frames or unauthenticated peers do not execute a query or extend idle lifetime.

This replaces both shared-file and immutable per-request JSON mailboxes, after
real ReFS integration runs still produced permission failures in the file
transport. Per-call request/response files are no longer written or polled.
The client enforces one absolute RPC deadline; the Java listener has a finite
frame-admission deadline and idle lifetime. Source snapshots, startup state and
diagnostic logs remain durable files. Filesystem errors there remain visible;
no permission changes, error suppression or polling retries mask them. The
Java worker and shared transport module hashes both invalidate stale workers.

These operations share `ghidra_query`; they do not add a catalog of separate
type/p-code tools:

| Action | Selection and result |
| --- | --- |
| `types` | Bounded type page; optional `contains`; hexadecimal row `cursor` |
| `type` | `options.path` exact/category type identity or typed-data `address` |
| `data` | Containing typed data/string/components and references; optional raw pointer table |
| `scan` | Paged listing instructions between VAs, with literal mnemonic/operand filters |
| `variables` | Function VA; recovered symbols, types and storage |
| `dossier` | Function VA; bounded instructions, entry callers, calls, data/string references, blocks and C |
| `blocks` | Function VA; listing-derived basic blocks and outgoing flows |
| `pcode` | Function VA; high p-code, SSA varnodes and def-use edges; paged |
| `trace` | Function VA; optional operation/varnode `seed`, direction and budgets |
| `type_edit` | Cited structure, prototype, local type, typed data, name or comment overlay |

`trace` accepts `options.direction` (`backward` or `forward`), `depth` (1–32),
`nodes` (1–200), and `functions` (1–8). Omit `seed` to start from the selected
instruction and the seed function's returns. To select a particular value,
copy an operation or varnode ID from `pcode`. IDs cite the function VA,
instruction VA, operation sequence, or SSA varnode identity. Every reply also
retains the program's full executable SHA-256.

The worker captures at most 4,096 operations per function and 12,000 total,
with a finite deadline. Returned nodes and edges have smaller bounds. Direct
call argument/return bindings may cross up to the selected function budget;
indirect targets, memory aliases, call side effects and feasible runtime paths
are explicitly unknown. Recovered call prototypes are analysis evidence,
not proof of the original ABI or runtime behavior. A refused child decompile
is an unknown in the partial trace; a refused seed remains an error.

Missing functions and invalid request selections are typed recoverable errors.
They do not retire a healthy worker. Decompiler failures, replay failures and
other backend exceptions remain nonrecoverable; their partial in-memory state
is not a successful query result.

A dossier scans at most 2,000 decoded instructions and 8,000 outgoing
references. Its instruction preview is at most 40 rows, and its explicit
`instructions_truncated` flag distinguishes that preview from the full scanned
count (`total_instructions_scanned`). Entry caller references have a separate
2,000-reference scan bound and an exact-entry scope label. Calls, data
references, defined-string previews, blocks and C each report their own
truncation. Data/string rows cite their `from`/`to` VAs, reference type and
bounded saved-data value. One string preview retains its first observed site;
this is not whole-body incoming-reference enumeration. Aggregate payload
trimming also marks the affected components incomplete.

## Cited type overlays

`type_edit` requires a nonempty `options.source` on every edit. Every edit and
every revert, on every view (the shared one included), also requires
`options.expect_revision`: the `view_revision` that `ghidra_query status`
reports. Edits are user assertions,
not silently promoted to binary ground truth. Accepted kinds are:

- `struct`: explicit category `path`, byte `size` and at most 64 fields with
  offsets, type identities and names. Overlapping components are refused.
- `signature`: C `prototype` for the selected function VA.
- `variable`: recovered `variable` name and new `type`, with optional `name`.
- `apply`: explicit data `type` at a VA, refusing conflicting code/data.
- `rename` / `label` / `comment`: a cited function name, a name for a mapped
  address (data included), or a comment, for the selected address.
- `function_create`, `function_body`, `function_delete`: explicit definition
  corrections with matching exact entry bytes. Create/body edits require at
  most 64 inclusive `ranges` of numeric VAs and optionally a name. The entry
  and range boundaries must already be decoded instruction boundaries, all
  ranges must be initialized executable memory, and another function may not
  overlap the body. No disassembly or boundary guessing occurs. Deletion
  targets an exact entry, rather than whichever function contains a guess.
- `batch`: one atomic group of 1–200 non-batch edits, supplied as an inline
  `edits` array or a `file` containing that JSON array (at most 256 KiB).
  Entries contain `address` and `options`; an omitted child source inherits
  the common batch `source`. All children are validated before dispatch.
  File input is normalized into embedded records with its full input-file
  SHA-256, byte size and original path, so replay never rereads a changed or
  missing file. Nested batches are refused. Java wraps all children in one
  outer transaction and returns an applied count, without dumping every edit.
- `import_types`: a whole type corpus (JSONL) applied as one cited, revertible
  overlay job; see [type-corpus.md](type-corpus.md).
- `import_archive`: types from a `.gdt` type archive, whole or selected by exact
  `paths`, as one cited overlay job; see [type-archives.md](type-archives.md).
- `revert`: `ids` of overlays to remove in one step; the working copy is rebuilt
  from the master. It adds no assertion, so it takes no new `source`, but it
  still needs `expect_revision`.

An edit executes within a transaction in the worker's memory. Its decompiler
cache is disposed after the change. Only an `ok` backend response permits the
Python caller to append the edit to
`<root>/overlays/<target-key>.json`. That history is bounded to 4,096 top-level
records and 20 MiB of serialized data, atomically written, and tied to the full
binary hash. A batch is one history record containing its embedded children.
A changed build refuses old overlays instead of guessing their applicability.

`data` accepts `options.table=true` to return consecutive 4/8-byte pointer
candidates with mapping and exact known-function identities. Its pointer table
continuation is a numeric VA in `next_cursor`. It does not infer a vtable's
extent or runtime objects from plausible words. Large defined values are not
fully materialized. `scan` accepts optional `end`, `mnemonic` and `operand`
literal filters and visits at most 2,000 listing instructions per page; it
returns progress and a VA cursor even for a page with no matching instruction.
Neither action disassembles new code. `scan` also accepts a bounded regular
expression over the decoded mnemonic and operands.

`decompile` retains its 32,000-character interactive default. A reviewed file
export may explicitly request `options.max_characters` up to 2,097,152. The
reply always reports the actual limit, total character count and truncation;
this remains bounded and does not promise an unbounded export. Function
summaries retain up to 200 disjoint body ranges with explicit truncation.

Every later worker receives the saved overlay IDs and replays only edits not
yet applied in that worker. This preserves type work across a worker restart
while canonical `.gpr`/`.rep` files remain unchanged. It does not claim a
saved master edit. Sources, offsets and layouts can be reviewed independently
of the Ghidra cache. Hook installation is a separate runtime operation with
its own actual-byte gate.

Replay attempts every saved record; it never silently truncates annotations to
fit a query. A deadline or failed edit reports incomplete/pending replay and
refuses to execute the query. A failed batch rolls back the entire batch in
memory, and the caller persists no batch record unless the backend reports
success. Callers may explicitly choose a longer query deadline for reviewed
large batches. The default remains bounded.

Sixteen focused Python tests validate budgets, source requirements, field
validation, normalized file batches, 4,096-record scale and byte limits,
identity-preserving persistence, build mismatch refusal and read-only history
loading. They do not establish Java integration success;
the coordinator's compile and real fixture checks supply that evidence.
