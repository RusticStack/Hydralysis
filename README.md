# RusticRE

A reverse-engineering toolkit for three games you own: Cyberpunk 2077 (Night City Together), Knights of the Old Republic, and The Old Republic. One Python package. One command, `rusticre`. One MCP server with eighteen tools.

It exists so a model with a small tool limit can do the work, and so the next machine does not depend on a PowerShell version or on a 200-tool server.

## Tools

| Command | Question |
| --- | --- |
| `fingerprint` | Which build is this exe? |
| `disasm` | What instructions are at this address? |
| `xrefs` | Who points at this address? |
| `callers` | Which direct calls land here? |
| `funcof` | Which pdata function contains this address, and what are its first bytes? |
| `bytes` / `prologue` | Do those bytes still match the stored prologue? |
| `strings` | Where is this text in the exe? |
| `hash` / `addr` | RED4ext address-table hash to RVA, and back. Segment 0001 only. |
| `evidence-add` | Store a claim with the line that proves it. |
| `ghidra-run` | Run one script on a read-only copy of an analysed project. |
| `systems` | Which co-op systems and mods are the targets? |

`rusticre tools` prints the MCP names. `rusticre mcp` is the server.

A 64-bit exe (Cyberpunk, SWTOR) uses rip-relative references. `swkotor.exe` is 32-bit; references are the absolute address, and disassembly uses 32-bit mode.

## Setup

```text
uv venv
uv pip install -e .
rusticre tools
```

Ghidra is optional and is not downloaded by this package. Copy `config.example.json` to `rusticre.local.json` or set `RUSTICRE_CONFIG`. Fill in the Ghidra install and, per game, the analysed project, the program name, and the script directory. `ghidra-run` copies that project into `<root>/lanes` and opens the copy with `-noanalysis -readOnly`.

The master project must be closed before the first copy. Eight lanes can run at once. A lane held by another process, or by Ghidra's own `.lock` file, is skipped.

## Clients

Point Claude Code, OpenCode, or Qoder at `rusticre mcp` and disconnect REA and LaurieWired's GhidraMCP. The snippets are in `docs/clients.md`. Do this when no session is mid-task. An OpenCode process keeps the tool list it started with.

## Where the game work stays

This repo does not become the coop mod, the KotOR engine, or the SWTOR server.

- Night City Together keeps the plugin, the scripts, and the harness. `rusticre systems --game cyberpunk` is the list of systems that library has to own: the body, the animgraph, movement, the world around each player, a shared new game, quests, scenes, vehicles, NPCs, combat. It also lists RED4ext (keep), and redscript, Codeware, TweakXL, ArchiveXL, and CET (do not require them; still load when both players have the same build).
- kotor-remaster keeps the format parsers and its ledger. Use this package for the exe and for Ghidra.
- SWTOR-origins keeps the protocol decoders and the shard. Point `ghidra-run` at the analysed client and the existing scripts, including `Recv.java`.

A claim without a source is refused. Decompiler text is a reading aid. The evidence row is the record.

## Tests

```text
set PYTHONPATH=src
python -m unittest discover -s tests -v
```

On PowerShell that environment assignment is `$env:PYTHONPATH = "src"`. The tests do not launch Ghidra or a game.
