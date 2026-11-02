# Tool mapping (skeleton)

How the Hydralysis surface relates to the two tools it replaced in agent sessions. This is a skeleton (`status` is `skeleton` in [data/tool-surfaces.json](data/tool-surfaces.json)): rows I could derive from this repository's docs, skills and source are filled in; everything else says **to verify**. No row has been checked by running the other tool.

## Counts, and where each comes from

The counts below are written by `tools/count_surfaces.py` into `docs/data/tool-surfaces.json`, and `tests/test_tool_mapping.py` checks this page against it and against `api.TOOL_NAMES`. Only the Hydralysis count is reproduced from this repository; the other two are third-party figures, listed with the date and the label "not reproduced" [below](#owner-reported-third-party-figures-2026-10-28).

| Surface | Count | Source | Status |
| --- | --- | --- | --- |
| Hydralysis (formerly RusticRE) MCP tools | 21 | `TOOL_NAMES` in `src/hydralysis/api.py`. The CLI also has four aliases that are not MCP tools (`sections`, `exports`, `ghidra_scripts`, `ghidra_jobs`). | Counted in this repo. |
| GhidraMCP bridge | 30 `@mcp.tool` functions | `src/ghidra_mcp/server.py` of the bridge at pinned revision `1e98025` (the owner's measured figure was 28). | 30 counted from that file. 28 is plausibly 30 minus the two GUI-only tools (`get_current_address`, `get_current_function`), which is **to verify**. |
| REA (`reverse-engineer-anything`) | 207 | The `tool_count` field in that skill's metadata only. | Not enumerated from a live `tools/list`; treat as the skill's own claim, **to verify**. |

Counts are not capability. REA's surface includes Android, JADX, ADB, apktool, JEB, firmware, browser, Electron, JavaScript, EVM, Hopper, Frida, Objective-C and Swift tooling that Hydralysis deliberately does not register (see [THIRD_PARTY.md](../THIRD_PARTY.md)).

## Hydralysis tools (21)

| Tool | Purpose |
| --- | --- |
| `fingerprint`, `imports` | Identity, packing triage, tables; fingerprint `detail=sections\|exports` |
| `inspect`, `disasm`, `function`, `bytes`, `strings`, `xrefs`, `callers`, `callees` | Cheap PE evidence, no engine |
| `sigscan`, `prologue` | Locate hook candidates and verify bytes |
| `evidence_add`, `evidence_list` | Claims with mandatory sources |
| `backend`, `prepare`, `job` | Setup, adoption, one-time analysis, progress |
| `ghidra_query`, `ghidra_run` | Saved analysis (decompile, xrefs, types, trace, edits, export, diff) and deliberate scripts |
| `runtime` | Controlled local runtime sessions |
| `trace` | Semantic traces: cited, bounded answers about what a program did (query, diff, explain, check, export); capture is `runtime` |

## GhidraMCP (30) to Hydralysis

"Partial" means the nearest operation answers a narrower or different question. Rows marked **to verify** are inferred from the docs, not tested side by side.

| GhidraMCP tool | Hydralysis equivalent | Status |
| --- | --- | --- |
| `get_program_info` | `fingerprint` (PE identity); `ghidra_query` replies carry the image base and full executable hash | Partial; to verify |
| `list_functions` | `ghidra_query --action functions` (paged, `--cursor`) | Covered |
| `list_methods` | `ghidra_query --action functions` | To verify |
| `search_functions_by_name` | `ghidra_query --action functions --contains <text>` | Covered |
| `list_classes` | None found; `types` and `vtables` are related, not the same | Gap; to verify |
| `list_namespaces` | None found | Gap; to verify |
| `list_segments` | `fingerprint detail=sections` (PE sections, CLI `sections`); not Ghidra memory blocks | Partial; to verify |
| `list_imports` | `imports` | Covered |
| `list_exports` | `fingerprint detail=exports` (CLI `exports`) | Covered |
| `list_data_items` | `ghidra_query --action data` | Partial; to verify |
| `list_strings` | `strings` | Covered |
| `get_function_by_address` | `function`, `ghidra_query --action function` | Covered |
| `get_current_address` | None: GUI-only | Out of scope |
| `get_current_function` | None: GUI-only | Out of scope |
| `decompile_function` (by name) | `ghidra_query` by address; names resolve only through an imported address map (`name:<name>`) | Partial |
| `decompile_function_by_address` | `ghidra_query <address>` | Covered |
| `disassemble_function` | `disasm`, `inspect` | Covered |
| `get_xrefs_to` | `xrefs`, `ghidra_query --action xrefs` | Covered |
| `get_xrefs_from` | `ghidra_query --action dossier` (references, callers, callees) | To verify |
| `get_function_xrefs` | `ghidra_query --action xrefs`, `dossier` | To verify |
| `get_function_calls` | `callers`, `callees`, `ghidra_query --action dossier` | Covered |
| `read_memory` | `bytes` reads the PE file; `runtime` reads live memory. Ghidra's own memory (BSS, overlays, relocated bytes) is not read by `ghidra_query` | Partial; to verify |
| `rename_function_by_address`, `rename_function` | `type_edit` kind `rename` (cited overlay in a working copy) | Different semantics: not written into the analysed project |
| `rename_data` | `type_edit` kind `label` | Different semantics |
| `rename_variable` | `type_edit` kind `variable` (`variable`, `name`) | Different semantics; to verify |
| `set_function_prototype` | `type_edit` kind `signature` | Different semantics |
| `set_local_variable_type` | `type_edit` kind `variable` (`variable`, `type`) | Different semantics |
| `set_decompiler_comment`, `set_disassembly_comment` | `type_edit` kind `comment` | To verify whether the two comment kinds are distinguished |

Hydralysis operations with no GhidraMCP counterpart: `trace`, `pcode`, `vtables`, `vcalls`, `writes`, `orphans`, `diff`, `import_types`, `import_archive`, `export`, `sigscan`, `prologue`, `evidence_add`, `runtime`.

## REA (207) to Hydralysis

Not mapped. The 207 figure is skill metadata, and no tool list was enumerated for this repository; a row-by-row table is **to verify** and not yet written.

## Known open questions

- Which of the 30 GhidraMCP tools were exercised in real sessions, and how often: **to verify** against session logs.
- Whether the two GUI-only tools account for the owner's 28: **to verify**.
- Whether REA's 207 matches a live `tools/list`: **to verify**.

## Owner-reported third-party figures, 2026-10-28

Figures that came from the owner or from a third party's own metadata. None was reproduced by running the other tool; each row says where it comes from and what this repository counted instead. A figure here is context, not evidence.

| Figure | Reported by | Counted here | Status |
| --- | --- | --- | --- |
| 28 GhidraMCP tools | the owner | 30 `@mcp.tool` functions at bridge revision `1e98025` (recorded in `docs/data/tool-surfaces.json`) | not reproduced |
| 207 tools in `reverse-engineer-anything` | the skill's `tool_count` metadata | no live `tools/list` was enumerated | not reproduced |
| 7.0-7.8 s for the same question through the upstream command-line launcher (Ghidra 12.1.4) | the owner | no upstream launcher is used or run by this repository | not reproduced |

The Hydralysis figure next to them is reproduced: 21 tools, counted from `tool_table()` by `tools/count_surfaces.py`.
