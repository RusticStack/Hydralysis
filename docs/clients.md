# Register the server

The command on this machine is:

```text
F:\Projects\RusticRE\.venv\Scripts\rusticre.exe mcp
```

Set `RUSTICRE_CONFIG` to `F:\Projects\RusticRE\rusticre.local.json` when a Ghidra target is configured. The PE tools do not need it.

Add this server next to REA and GhidraMCP. Leave those in place until an agent has used both and said which call still needs the old server. A model with a small tool budget will still fail if REA stays enabled, because REA registers its whole surface.

Restart the client after the edit. A session that is already open keeps the tool list it started with.
