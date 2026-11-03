# Register the server

The command is the console script of the virtual environment you installed into:

```text
<checkout>\.venv\Scripts\hydralysis.exe mcp
```

Set `HYDRALYSIS_ROOT` to a dot-free directory on your development drive for private engines, prepared projects, evidence and logs. Existing target configuration is optional: `prepare` registers a fresh executable after its explicit one-time analysis. `HYDRALYSIS_CONFIG` can still select a JSON file for existing projects.

Use a Hydralysis-only profile for the covered workflow: setup, initial preparation, saved analysis, cited overlays, bounded flow and verified runtime evidence. Keeping REA and two Ghidra servers enabled still loads their catalogs; adding a small server does not remove that cost. No client settings are changed by Hydralysis. Review [capability limits](../README.md#evidence-and-limits) before removing a fallback you still need.

The server is named `hydralysis`, so a harness that prefixes tool names with the server name shows `mcp__hydralysis__prepare`, `mcp__hydralysis__ghidra_query` and so on. The earlier name was `rusticre` (`mcp__rusticre__*`); re-register the server under the new name and update any allow-list, hook matcher or prompt that spells the old prefix. The `rusticre` command is kept for one release, so an old registration that runs `rusticre mcp` still starts, but it now announces itself as `hydralysis`. `RUSTICRE_*` variables are still read for that release (see the README).

For a client that accepts the common `mcpServers` configuration shape:

```json
{
  "mcpServers": {
    "hydralysis": {
      "command": "<checkout>/.venv/Scripts/hydralysis.exe",
      "args": ["mcp"],
      "env": {"HYDRALYSIS_ROOT": "<data root>"}
    }
  }
}
```

The server speaks newline-delimited UTF-8 JSON on stdio; legacy framed input gets a framed reply. Diagnostics stay off stdout. Tool errors do not close the session, and control messages remain responsive during bounded tool work. Oversized answers explicitly report truncation; narrow the query or page it.

In a client with no MCP connection, use the same operations from its terminal:

```text
hydralysis ghidra-query --target sample 0x140001000
hydralysis inspect --exe F:/binaries/sample.exe rva:0x1000
hydralysis prepare --exe F:/binaries/sample.exe --target sample --plan
hydralysis prepare --exe F:/binaries/sample.exe --target sample
hydralysis job <prepare-id>
```

Install or reference this repository's `skills/hydralysis/SKILL.md` in that client's agent guidance so the short command is discoverable. Prefer `ghidra-query` over hand-written headless Ghidra runs: CLI, MCP and scripts share one warm engine. Use `--options-file` for trace/edit/runtime JSON and bulk work. In Qoder, explicit preparation/export commands can run later without changing the MCP catalog or importing per query. `sections`, `exports`, `ghidra-scripts` and `ghidra-jobs` are CLI aliases; use fingerprint detail and `job` in MCP.

Restart the client after the edit. A session that is already open keeps the tool list it started with.

## From scripts

Python tools import the same operations instead of reimplementing PE reading or prologue checks. `hydralysis.client.Client` calls the dispatch the MCP server uses, so names, arguments, bounds and refusals are the MCP contract; JSON answers come back parsed and a refusal raises `RusticError`.

```python
from hydralysis.client import Client

re = Client()                       # Client(config="<data root>/config.json") selects targets
build = re.fingerprint(exe)         # {"sha256": ..., "image_base": ..., ...}
head = re.read(exe, "rva:0x5d53a0", 32)
table = re.check_prologues(exe, rows, sha256=build["sha256"])   # rows: [{address, expect | [alternatives], name?}]
table["matched"], [row["name"] for row in table["rows"] if not row["match"]]
re.query("cp25", "decompile", "rva:0x5d53a0")
re.call("xrefs", exe=exe, address="rva:0x5d53a0", limit=20)     # any tool by its MCP name
```

`check_prologues` returns a mismatching table rather than raising, and pages tables longer than the tool's 200 rows. PowerShell and other languages use the JSON command, which prints one envelope and exits 0 or 1:

```text
hydralysis call prologue --args-file checks.json
{"ok": true, "result": {"fingerprint": {...}, "rows": [...], "matched": true}}
{"ok": false, "error": "ValueError: prologue table build SHA-256 mismatch; no rows verified"}
```

```powershell
$answer = hydralysis call bytes --args '{"exe": "D:/Game/bin/x64/Game.exe", "address": "rva:0x1000", "size": 16}' | ConvertFrom-Json
if (-not $answer.ok) { throw $answer.error }
```

## Native MCP host (optional)

`native/hydralysis-mcp` is a Rust build of this server's transport. It speaks the same stdio MCP (initialize, `tools/list`,
`tools/call`, ping, cancellation, the fast/engine/long lanes, the 128 KiB output cap and the error envelopes of
`hydralysis/mcp.py`), advertises the same catalog (epoch, hash and bytes come from `native/hydralysis-mcp/catalog.json`,
which `tools/gen_mcp_catalog.py` writes from `api.py`), and answers `fingerprint`, `imports`, `function`, `bytes`,
`strings`, `sigscan`, `callers` and `xrefs` itself for well-formed PE images. Everything else (the engine tools,
`disasm`/`inspect`/`callees`, the evidence store, `trace`, `runtime`) is run by `python -m hydralysis.worker`, a Python
process the host starts on the first such call and closes after `HYDRALYSIS_WORKER_IDLE_S` (default 30) idle seconds. A
call the native code is not certain about (an argument of an unusual type, a PE pefile might read differently, any error)
is also handed to the worker, so the reply and the error text are always the Python ones.

Build it with `python tools/build_mcp_host.py` (needs a Rust toolchain; it copies the binary to `src/hydralysis/bin/`,
which the wheel ships). `hydralysis mcp` then starts the binary and keeps the Python server as the fallback when it is
missing; `HYDRALYSIS_MCP=python` forces the Python server and `HYDRALYSIS_MCP=native` requires the binary. For the
smallest resident footprint register the binary itself (`<checkout>/src/hydralysis/bin/hydralysis-mcp.exe`, with
`HYDRALYSIS_PYTHON` set to the venv's `python.exe`); `hydralysis mcp` and `python -m hydralysis.mcp_launch` keep a small
Python launcher process alive beside it. The `rusticre` command starts the same host.

| Variable | Meaning |
| --- | --- |
| `HYDRALYSIS_MCP` | `python`, `native` or unset (auto) |
| `HYDRALYSIS_MCP_BIN` | the binary to start |
| `HYDRALYSIS_PYTHON` | the interpreter of the worker (set by `hydralysis mcp`; default `python`) |
| `HYDRALYSIS_WORKER_IDLE_S` | seconds of idleness before the worker is closed (default 30) |
| `HYDRALYSIS_MCP_ENV_TTL_S` | seconds the launch environment report is cached in the temp folder (default 300; 0 = off) |
