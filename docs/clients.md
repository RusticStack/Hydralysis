# Register the server

The command on this machine is:

```text
F:\Projects\RusticRE\.venv\Scripts\rusticre.exe mcp
```

Set `RUSTICRE_ROOT` to a dot-free directory on your development drive for private engines, prepared projects, evidence and logs. Existing target configuration is optional: `prepare` registers a fresh executable after its explicit one-time analysis. `RUSTICRE_CONFIG` can still select a JSON file for existing projects.

Use a RusticRE-only profile for the covered workflow: setup, initial preparation, saved analysis, cited overlays, bounded flow and verified runtime evidence. Keeping REA and two Ghidra servers enabled still loads their catalogs; adding a small server does not remove that cost. No client settings are changed by RusticRE. Review [capability limits](../README.md#evidence-and-limits) before removing a fallback you still need.

For a client that accepts the common `mcpServers` configuration shape:

```json
{
  "mcpServers": {
    "rusticre": {
      "command": "F:/Projects/RusticRE/.venv/Scripts/rusticre.exe",
      "args": ["mcp"],
      "env": {"RUSTICRE_ROOT": "F:/dev-cache/rusticre"}
    }
  }
}
```

The server speaks newline-delimited UTF-8 JSON on stdio; legacy framed input gets a framed reply. Diagnostics stay off stdout. Tool errors do not close the session, and control messages remain responsive during bounded tool work. Oversized answers explicitly report truncation; narrow the query or page it.

In a client with no MCP connection, use the same operations from its terminal:

```text
rusticre ghidra-query --target sample 0x140001000
rusticre inspect --exe F:/binaries/sample.exe rva:0x1000
rusticre prepare --exe F:/binaries/sample.exe --target sample --plan
rusticre prepare --exe F:/binaries/sample.exe --target sample
rusticre job <prepare-id>
```

Install or reference this repository's `skills/rusticre/SKILL.md` in that client's agent guidance so the short command is discoverable. Prefer `ghidra-query` over hand-written headless Ghidra runs: CLI, MCP and scripts share one warm engine. Use `--options-file` for trace/edit/runtime JSON and bulk work. In Qoder, explicit preparation/export commands can run later without changing the MCP catalog or importing per query. `sections`, `exports`, `ghidra-scripts` and `ghidra-jobs` are CLI aliases; use fingerprint detail and `job` in MCP.

Restart the client after the edit. A session that is already open keeps the tool list it started with.

## From scripts

Python tools import the same operations instead of reimplementing PE reading or prologue checks. `rusticre.client.Client` calls the dispatch the MCP server uses, so names, arguments, bounds and refusals are the MCP contract; JSON answers come back parsed and a refusal raises `RusticError`.

```python
from rusticre.client import Client

re = Client()                       # Client(config="F:/dev-cache/rusticre/config.json") selects targets
build = re.fingerprint(exe)         # {"sha256": ..., "image_base": ..., ...}
head = re.read(exe, "rva:0x5d53a0", 32)
table = re.check_prologues(exe, rows, sha256=build["sha256"])   # rows: [{address, expect | [alternatives], name?}]
table["matched"], [row["name"] for row in table["rows"] if not row["match"]]
re.query("cp25", "decompile", "rva:0x5d53a0")
re.call("xrefs", exe=exe, address="rva:0x5d53a0", limit=20)     # any tool by its MCP name
```

`check_prologues` returns a mismatching table rather than raising, and pages tables longer than the tool's 200 rows. PowerShell and other languages use the JSON command, which prints one envelope and exits 0 or 1:

```text
rusticre call prologue --args-file checks.json
{"ok": true, "result": {"fingerprint": {...}, "rows": [...], "matched": true}}
{"ok": false, "error": "ValueError: prologue table build SHA-256 mismatch; no rows verified"}
```

```powershell
$answer = rusticre call bytes --args '{"exe": "D:/Game/bin/x64/Game.exe", "address": "rva:0x1000", "size": 16}' | ConvertFrom-Json
if (-not $answer.ok) { throw $answer.error }
```
