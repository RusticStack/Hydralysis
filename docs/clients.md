# Register the server, then drop the other two

Add RusticRE. After one real `fingerprint` and, where you use Ghidra, one real `ghidra-run`, remove the `rea` server and LaurieWired's `ghidra` / `ghidra-headless` servers from that client. Leave a session that is already running alone until it finishes. OpenCode keeps the tool list from the moment it started.

The command is the installed console script, or `python -m rusticre mcp` with `PYTHONPATH` set to this repo's `src` while developing.

## Claude Code

`.mcp.json` in the game repo:

```json
{
  "mcpServers": {
    "rusticre": {
      "command": "rusticre",
      "args": ["mcp"]
    }
  }
}
```

Night City Together today points `ghidra` at `http://127.0.0.1:8765/mcp` (pyghidra-mcp). Keep that process until `ghidra-run` on the same analysed project returns a script body. Then the HTTP server is optional.

## OpenCode

In `opencode.json`, next to the existing servers:

```json
"rusticre": {
  "type": "local",
  "command": ["rusticre", "mcp"],
  "environment": {
    "RUSTICRE_CONFIG": "F:/Projects/RusticRE/rusticre.local.json"
  },
  "timeout": {
    "startup": 10000,
    "execution": 900000
  }
}
```

SWTOR currently loads `rea-agents@6.5.0` and `ghidra_batch`. `ghidra_batch` is the unversioned copy of the lane runner this package replaces. After `Recv.java` succeeds through `rusticre`, remove both.

## Qoder

`settings.json` on this machine registers `rea`, `ghidra` (LaurieWired against port 8080), and `ghidra-headless` (a second copy pointed at `swkotor.exe`). Replace those three entries with one:

```json
"rusticre": {
  "command": "rusticre",
  "args": ["mcp"],
  "env": {
    "RUSTICRE_CONFIG": "F:/Projects/RusticRE/rusticre.local.json"
  }
}
```

That is the change that lets a model with a small tool budget continue. The eighteen tools are the ones the session logs actually called.
