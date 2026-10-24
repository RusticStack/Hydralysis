# Register the server

The command on this machine is:

```text
F:\Projects\RusticRE\.venv\Scripts\rusticre.exe mcp
```

Set `RUSTICRE_CONFIG` to `F:\Projects\RusticRE\rusticre.local.json` when a Ghidra target is configured. The PE tools do not need it.

Use a RusticRE-only profile for ordinary PE inspection and saved-project queries. Keeping REA and two Ghidra servers enabled still loads their catalogs; adding a small server does not remove that cost. Keep a separate optional profile for REA value-flow/basic-block dossiers or Ghidra editing. No client settings are changed by RusticRE.

For a client that accepts the common `mcpServers` configuration shape:

```json
{
  "mcpServers": {
    "rusticre": {
      "command": "F:/Projects/RusticRE/.venv/Scripts/rusticre.exe",
      "args": ["mcp"],
      "env": {"RUSTICRE_CONFIG": "F:/Projects/RusticRE/rusticre.local.json"}
    }
  }
}
```

The server speaks newline-delimited UTF-8 JSON on stdio; legacy framed input gets a framed reply. Diagnostics stay off stdout. Tool errors do not close the session, and control messages remain responsive during bounded tool work. Oversized answers explicitly report truncation; narrow the query or page it.

In a client with no MCP connection, use the same operations from its terminal:

```text
rusticre ghidra-query --target sample 0x140001000
rusticre inspect --exe F:/binaries/sample.exe 0x1000
```

Install or reference this repository's `skills/rusticre/SKILL.md` in that client's agent guidance so the short command is discoverable. Prefer `ghidra-query` over hand-written `analyzeHeadless`: both CLI and MCP use the same warm worker. `ghidra-lanes` was removed from the default catalog; use query `status` and the job log instead.

Restart the client after the edit. A session that is already open keeps the tool list it started with.
