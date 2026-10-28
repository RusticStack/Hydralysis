# What was taken, and what was left out

The server registers twenty operations. They are the ones session logs showed agents using, under names that do not belong to one program. The upstream trees were not vendored.

## The analysis engine

Hydralysis analyses with **Hydra Engine**, a fork of Ghidra (12.3 DEV, [RusticStack/hydra-engine](https://github.com/RusticStack/hydra-engine), Apache-2.0) with a headless session daemon. The pinned release is downloaded as a release asset with its SHA-256 checked and installed privately under the Hydralysis data root; it is not vendored here. Hydralysis is built on Ghidra's analysis and decompiler. It is not independent of Ghidra; it simply does not use or need a separate Ghidra install.

- No stock Ghidra is used or needed. An engine without Hydra's session module is refused. The old `ghidra_dir` setting and `GHIDRA_INSTALL_DIR` variable are ignored, and `backend inspect` reports them under `ignored`. A unit test fails if the shipped source or skills name them anywhere else.
- There is no GUI. Hydra Engine is headless only; projects it writes cannot be opened by Ghidra 12.2 or 12.1.4.

## Other components and sources

| Source | Licence | What this repo keeps | What it leaves |
| --- | --- | --- | --- |
| [RusticStack/hydra-engine](https://github.com/RusticStack/hydra-engine), a fork of [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | Apache-2.0 | The engine it drives: the pinned headless release (12.3-hydra.2) and its Python client, installed by `backend install` or named by `hydra_dir` and `hydra_client`. Ghidra's analysers and decompiler do the analysis. | Any stock Ghidra install and launcher, and any decompiler output checked into git. Neither the engine nor Ghidra is shipped in this repository. |
| Eclipse Temurin JDK 25 | GPL-2.0 with Classpath Exception | A full JDK, found or installed privately from a pinned archive with a SHA-256 check. | The installer, PATH edits, administrator operations. |
| `pefile`, `capstone`; optional pinned Frida backend | their own licences | Offline PE parsing and disassembly; the optional runtime engine, installed only on request. | Everything else of their trees. |
| [morluto/rea](https://github.com/morluto/rea) `rea-agents` | MIT | One evidence-shaped answer per question. Open an analysed Ghidra project read-only. Never re-import the exe on each call. Store a prologue with every name. | The 207-tool server (the skill's own `tool_count`, not reproduced): Android, JADX, ADB, apktool, JEB, firmware, browser, Electron, JavaScript, EVM, Hopper, Frida, Objective-C, Swift. |
| [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Apache-2.0 | The questions that sessions actually asked: program identity, disassembly, decompile-by-script, xrefs, callers, raw bytes. See [the tool mapping](docs/tool-mapping.md). | The tools that depend on an interactive "current address", and the Ghidra extension plugin. Renames and retypes are cited overlays in a working copy, not written into the analysed project. |
| `ghidra-batch` (local, written for SWTOR-origins, 2026-10-20) | MIT, this machine | An OS file lock that dies with the process, and the filter that keeps script output and drops the Ghidra log. | The SWTOR-only config, the eighteen copied `run-*.ps1` wrappers, and the unversioned tree under `F:\dev-cache\ghidra-batch`. |
| [cranebeaker/coop-anything](https://github.com/cranebeaker/coop-anything) | MIT | The method: map the systems co-op has to share, record a byte signature for the build, prove sync with a checker before asking a person to look. | Their playbook text, the contribution queue, console and Switch skills, and their instruction to install REA. |

NightCoop is not a source. It is closed. Watch what the puppet does. Re-derive the inputs from the game exe.

CyberpunkMP is not a source. Study the behaviour. Re-derive every address.
