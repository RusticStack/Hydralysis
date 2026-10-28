# Evidence behind the workflow changes

Research date: 2026-10-24. This report distinguishes repository documentation,
retained local call records, and new Hydralysis checks. Historical timings below
are measurements reported by those projects, not a new benchmark or a claim of
Hydralysis speedup. Private transcripts and proprietary binary/decompiler output
are not included in this repository.

## Night City Together

Inspected the local checkout at
`C:\Users\KellHect\orca\projects\CoopCyberpunk` and used `gh` to verify
`KelpHect/NightCityTogether`, its main branch, and commit
`1364117365c51720db26e5d88272e7cf0d7bbb33`. Read its agent policy, RE helper
documentation, relevant engine maps, gotchas, and retained Claude Code logs for
the `CoopCyberpunk-scoter` workspace. The project explicitly requires build
fingerprints, evidence for addresses, and checked prologue bytes before a name
enters its hook table. See its
[ground-truth policy](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/CLAUDE.md#L13-L22).

The retained log corpus contained 1,478 JSONL files (1,882,708,456 stored bytes).
Parsing assistant `tool_use` records and deduplicating by `tool_use.id` found 135
Ghidra MCP calls across eight operations:

| Operation | Unique calls |
| --- | ---: |
| disassemble | 68 |
| decompile_function | 15 |
| list_xrefs | 14 |
| read_bytes | 12 |
| search_symbols_by_name | 10 |
| search_code | 8 |
| list_project_binaries | 5 |
| search_strings | 3 |

Reproduction scope: recursively parse `*.jsonl` beneath
`C:\Users\KellHect\.claude\projects\C--Users-KellHect-orca-workspaces-CoopCyberpunk-scoter`,
read `message.content` list entries with `type == "tool_use"`, deduplicate their
`id`, then count names prefixed `mcp__ghidra__` or `mcp__rea`. Workflow transcript
copies repeat call IDs, so counting files or messages overstates use. This scope
contained no direct `mcp__rea` calls. That is not evidence that REA was never used:
the project documents its CLI wrapper and retained shell records invoke RE
helpers. Shell mentions were not counted as executed commands, since comments,
documentation edits, pipelines, loops, and copied commands make that inference
unreliable.

### Failures change the design

| Evidence | Consequence for Hydralysis |
| --- | --- |
| The project's [REA integration notes](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/re/README.md#L105-L147) report a 1,278 s import/analysis query, patched to open an analysed project with `-process`, `-noanalysis`, and `-readOnly`. | A query must reuse saved analysis. Initial import is a separate operation, never an implicit fallback. |
| The same source reports function queries taking 14–26 s per CLI launch versus 1.3 s in one MCP session; decompile 12–14 s versus 1.8 s; address references 0.2 s within the session. These are historical measurements on one game build and machine. | Keep a query worker warm; measure startup separately from repeated requests. |
| `find_xrefs_to_name`/`list_names` fails after 30–40 s and later requests fail until close/open, according to the [same notes](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/re/README.md#L141-L147). | Resolve addresses directly and bound enumeration. A timed-out worker must be recoverable without poisoning the MCP server. |
| Local log `e61e704a-10b4-4c24-a6d5-115b8645f242/subagents/agent-a0ec6bf1de0021e1b.jsonl`, lines 98–99: `list_xrefs` for `ISerializable::OnSerialize` produced 555,014 characters and exceeded the host's output limit. | Bound returned rows and provide continuation; a correct unbounded result can still be unusable. |
| That log's lines 72–73: an address query was rejected as ambiguous because two labels named the same address. Decompile repeated the failure in another lane. | Numeric addresses must bypass a whole-name search and must not become ambiguous merely because one address has aliases. |
| The [project setup notes](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/re/README.md#L55-L73) describe 6–10 GB analysis memory and a 12G heap configuration; [REA notes](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/re/README.md#L124-L147) require one process per project copy and report roughly 1 GB RAM per concurrent REA process. | Heap and concurrency are explicit configuration. One owner holds each copied project's lock; do not launch competing workers or copy analysis per function. |
| [The shell client](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/re/README.md#L77-L103) exists because workflow agents lacked an MCP connection. | CLI and MCP need the same short, discoverable operations. A decompile should not require hand-writing a Ghidra script. |

The original helper list also explains why a small PE surface earns its place:
[instructions, callers, strings, raw bytes, function bounds, signatures, and
checked names](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/re/README.md#L25-L50).
Its [gotchas G88–G91](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/docs/gotchas.md#L702-L717)
record wildcard prologue failures, data references mistaken for function
pointers, decompiler argument omissions, and a helper silently limited to 40
callers. Matching bytes is a gate, disassembly remains accessible beside a
decompile, and an incomplete page must say it is incomplete.

## SWTOR preservation

Inspected `F:\Projects\SWTOR-origins` and verified its remote
`KelpHect/SWTOR-origins`, commit
`11ea4e93ff0069ed56590f01d935e98accac087b`. Its
[Ghidra setup notes](https://github.com/KelpHect/SWTOR-origins/blob/11ea4e93ff0069ed56590f01d935e98accac087b/docs/ghidra-setup.md#L3-L17)
record the 30 MB client's roughly 20-minute analysis, a default 2G heap, a 12G
configuration, and a 600,000 ms REA startup deadline. The document attributes
swapping to the smaller heap; this investigation did not reproduce or isolate
that attribution. Its
[lane policy](https://github.com/KelpHect/SWTOR-origins/blob/11ea4e93ff0069ed56590f01d935e98accac087b/docs/ghidra-setup.md#L35-L53)
requires project copies, per-instance CPU limits, and reuse of saved analysis.
The [startup explanation](https://github.com/KelpHect/SWTOR-origins/blob/11ea4e93ff0069ed56590f01d935e98accac087b/docs/ghidra-setup.md#L71-L77)
distinguishes a slow healthy launch from a dead worker. Hydralysis needs separate
startup and per-query deadlines, rather than one short global deadline.

The
[client audit method](https://github.com/KelpHect/SWTOR-origins/blob/11ea4e93ff0069ed56590f01d935e98accac087b/docs/auth-head-audit-client.md#L17-L22)
records GhidraMCP `BACKEND_UNAVAILABLE`, followed by three successful direct
headless passes against a saved analysed lane with `-process`, `-noanalysis`, and
`-readOnly`. This is concrete evidence of agents routing around an unavailable
MCP. A short Hydralysis CLI query must reach the same persistent analysis path as
MCP, and errors must identify whether setup, startup, or the query failed. A
backend failure must never silently turn a query into another import.

## KotOR remaster

Inspected `E:\Projects\kotor-remaster\kotor-remaster` and verified its remote
`KelpHect/kotor-remaster`, commit
`28e5806f5b4b468d7c28d6bda28252cce7c660ea`. Its
[artifact record](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/01_ARTIFACTS.md#L10-L35)
distinguishes the current 4,042,752-byte PE32 executable, SHA-256
`0290889e0cea6ebc00021c1bdb945704fc4c45afaf7fcebabb0e82ba674437e6`, from an
earlier wrapped `.bind` executable, SHA-256
`34e6d971c034222a417995d8e1e8fdd9f8781795c9c289bd86c499a439f34c88`.
The earlier project's analysis was discarded as the wrong build. Therefore
"KotOR is packed" is not a safe project-wide assumption: inspect the supplied
artifact, surface packing indicators, and reject a saved project's binary hash
mismatch before returning its decompiler text. Packing indicators are a triage
warning, not proof of a particular packer or permission to unpack anything.

The
[v4 export record](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/14_P0_FUNCTION_CLASSIFICATION.md#L51-L78)
reports a read-only pass on a project copy, before/after tree hashes, 10,849
internal functions, and body ranges that can be disjoint. It supports analysed
project reuse and exact function ranges; PE64 unwind bounds alone do not cover
this PE32 workflow.

Its
[discovery record](https://github.com/KelpHect/kotor-remaster/blob/28e5806f5b4b468d7c28d6bda28252cce7c660ea/docs/recon/14_P0_FUNCTION_CLASSIFICATION.md#L86-L96)
describes label-only callers, pointer/vtable scans, and four decompile timeouts
that emitted 23–171 KB when allowed 300 seconds. Those are expensive individual
decompiles, not JVM startup measurements. Keep a bounded long-running script
escape hatch for such deliberate batch work; do not make every interactive
query inherit that budget or return that much text.

## Loaded does not mean used

The observed eight-operation Ghidra set is evidence for a focused default, not
proof that all other tools were unnecessary. Retained logs do not preserve every
client's complete negotiated tool catalog, deleted sessions, or tasks performed
elsewhere. Read-only inspection of
`C:\Users\KellHect\.qoder\settings.json` and its `.bak-20261023` backup
corroborated simultaneous `rea`, `ghidra`, and `ghidra-headless` registrations;
the current file also registers `hydralysis`. No client settings were changed.
Registration proves configuration, not successful negotiation or actual use.
The user's reports of roughly 200 REA tools, the approximately 15 KB schema
failure, and a registered smaller server being bypassed remain task-supplied
requirements unless corroborated by a particular retained failure. They are not
measured token savings.

Android, browser, firmware, and similar unrelated adapters have no observed need
in this native PE workflow. They should not enter the default server merely
because REA exposes them. A short operation name, actionable setup error, CLI
equivalent, and working example matter as much as protocol correctness: a server
that agents route around has not replaced the old workflow.

### Protocol compatibility is part of adoption

The initial Hydralysis implementation accepted newline-delimited input but always
wrote `Content-Length` frames. The
[MCP stdio transport specification](https://modelcontextprotocol.io/specification/2025-06-18/basic/transports#stdio)
requires newline-delimited JSON-RPC messages. A server that looks healthy in a
custom framing test can therefore fail in an ordinary client before any useful
call. Validate a real subprocess exchange with newline-delimited initialize,
tools/list, and tools/call messages; schema size alone does not establish client
compatibility.

## Where REA or Ghidra still earns a call

REA remains useful when a whole-function dossier needs basic blocks, p-code,
value flow, or bounded def-use tracing that Hydralysis does not implement. The
[historical workflow](https://github.com/KelpHect/NightCityTogether/blob/1364117365c51720db26e5d88272e7cf0d7bbb33/tools/re/README.md#L141-L147)
explicitly distinguishes those questions from cheap PE disassembly and callers.

Use Ghidra directly for initial import/analysis, interactive type recovery,
renaming, comments, and other deliberate writes to the master project. Hydralysis's
read-only query path should not pretend those edits were saved to the master.
Live process state, engine reflection, and runtime hook installation remain
separate tasks: an offline byte match proves a particular site's bytes, not the
correct thread, lifetime, calling convention, or safe hook teardown.

## SWTOR local call-site supplement

Read the local OpenCode database at
`C:\Users\KellHect\.local\share\opencode\opencode.db` through SQLite's
`file:.../opencode.db?mode=ro` URI. The scope was the 227 retained `session_v2`
rows whose `lower(directory) LIKE '%swtor%'`, joined to their
`session_message` rows with `type='assistant'`. The extraction inspected only
message `content` entries with `type='tool'` and `name='execute'`, then searched
their recorded `state.input` code for `tools.rea.<method>(` call sites. It did
not count prose mentions, reasoning, tool schemas, or unrelated projects.

These are **recorded code call sites, not counts of executed REA calls or
successful answers**. A loop may invoke a site many times; an earlier failure
may prevent a later site from running. The retained execution wrappers include
these sites:

| REA method | Recorded code call sites |
| --- | ---: |
| `analyze_function` | 42 |
| `list_documents` | 18 |
| `search_strings`, `xrefs` | 16 each |
| `open_binary` | 15 |
| `binary_overview`, `binary_session` | 14 each |
| `get_navigation_context` | 9 |
| `start_frida_session`, `load_frida_script`, `frida_session_status`, `close_frida_session` | 7 each |
| `read_bytes`, `procedure_pseudo_code`, `address_to_file_offset` | 2 each |
| `procedure_assembly`, `resolve_containing_procedure` | 1 each |

No Android, browser, or firmware method call sites were found by that scoped
extraction. This does not establish their negotiated tool count, their use in
another client, or the necessity of a new runtime tool: Frida lifecycle sites
alone do not prove that live target inspection succeeded. The common native
questions support focused function, string, xref, and byte operations.

The same corpus preserves a concrete filesystem admission failure. Session
`ses_eae6aa667ffeweKOlwTs8iUcRa`, message
`msg_15195b7d50015cFNeIIiUQ4lwS`, records an execution wrapper requesting
`open_binary` on `F:\dev-cache\swtor-token-probe\PlatformInfo.dll`, followed by
`binary_overview`. Its result is `execution_failure`, with
`ERR_REA_WINDOWS_NATIVE`, `failure_kind=start`, and the diagnostic
"Backing volume must be NTFS with persistent ACLs" for that F: path
(Win32 50). F: is this machine's ReFS Dev Drive. The wrapper's recorded
`time.ran` to `time.completed` interval is 3.12 seconds; it is not an isolated
Ghidra startup or analysis measurement. The result is a backend filesystem
incompatibility, not an empty search. Hydralysis must preserve that distinction
and work on its configured storage rather than hiding the failure behind a
retry or another import.

No retained `execute` wrapper containing `tools.rea.` in this scoped extraction
had a recorded duration above 600 seconds. Therefore this database extraction
does not independently establish the user's approximately 20-minute failed
client call. The repository's analysis notes and the user's incident report
remain separately identified sources for that history. These local records
are private, may not exist on another machine, and are not redistributed here;
the row identifiers and extraction method make the finding auditable locally.
