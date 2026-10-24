# RusticRE

Twenty reverse-engineering tools for any PE you own. One command, `rusticre`. One MCP server.

The list is the operations agents actually called, under generic names. REA's function dossier is `inspect` and does not start a JVM. A decompile is `ghidra-run` on a project you have already analysed. A hook site is `sigscan`, then `prologue`. Android, browser, firmware, Hopper and the rest of REA are not registered.

| Tool | Operation |
| --- | --- |
| `fingerprint`, `sections`, `imports`, `exports` | What this binary is |
| `inspect` | Bounds, prologue, instructions, direct callers |
| `disasm`, `xrefs`, `callers`, `callees`, `function`, `bytes`, `strings` | One question each |
| `sigscan`, `prologue` | Find a hook site, then check the bytes before hooking |
| `evidence-add` | Store a claim only if it has a source |
| `ghidra-run` | One script, read-only, on a copy of an analysed project |

`target` is a name you pick in the config for a Ghidra project. It is not a list of games.

## Setup

```text
uv venv --python 3.14 .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\rusticre.exe tools
```

Copy `config.example.json` to `rusticre.local.json` or set `RUSTICRE_CONFIG` when you want `ghidra-run`. The PE tools need only `--exe`.

`ghidra-run` copies the master project into `<root>/lanes` and opens the copy with `-noanalysis -readOnly`. Close the master first. Eight copies can run at once.

## Why these twenty

Session logs from the machines that drove REA, GhidraMCP and headless Ghidra were counted. The calls that did the work were disassembly, cross-references, callers, function bounds, raw bytes, strings, imports, a decompile against an analysed project, and a prologue check before a name was trusted. `inspect` is those first facts in one answer, which is what REA's `function` tool was used for. `sigscan` is the hook search those sessions did by hand.

`src/rusticre/red4ext.py` parses one vendor's address-table JSON. It is not an MCP tool. A format that belongs to one program stays out of the server until a second program needs the same parser.

## Tests

```text
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
```

The tests do not launch Ghidra or a game.
