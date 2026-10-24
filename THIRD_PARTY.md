# What was taken, and what was left out

The server registers twenty operations. They are the ones session logs showed agents using, under names that do not belong to one program. The upstream trees were not vendored.

| Source | Licence | What this repo keeps | What it leaves |
| --- | --- | --- | --- |
| [morluto/rea](https://github.com/morluto/rea) `rea-agents` | MIT | One evidence-shaped answer per question. Open an analysed Ghidra project read-only. Never re-import the exe on each call. Store a prologue with every name. | The 200-tool server: Android, JADX, ADB, apktool, JEB, firmware, browser, Electron, JavaScript, EVM, Hopper, Frida, Objective-C, Swift. |
| [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra) | Apache-2.0 | `analyzeHeadless -process -noanalysis -readOnly` against a project you already analysed. Ghidra itself is installed separately and is not shipped. | The Ghidra distribution, the GUI, and any decompiler output checked into git. |
| [LaurieWired/GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Apache-2.0 | The questions that sessions actually asked: program identity, disassembly, decompile-by-script, xrefs, callers, raw bytes. | The GUI "current address" tools, rename, retype, and the Ghidra extension plugin. Names are stored in the evidence ledger, not written into the project copy. |
| `ghidra-batch` (local, written for SWTOR-origins, 2026-10-20) | MIT, this machine | A copy of the analysed project per concurrent run, an OS file lock that dies with the process, Ghidra's own `.lock` file as a second check, and the filter that keeps script output and drops the Ghidra log. | The SWTOR-only config, the eighteen copied `run-*.ps1` wrappers, and the unversioned tree under `F:\dev-cache\ghidra-batch`. |
| [cranebeaker/coop-anything](https://github.com/cranebeaker/coop-anything) | MIT | The method: map the systems co-op has to share, record a byte signature for the build, prove sync with a checker before asking a person to look. | Their playbook text, the contribution queue, console and Switch skills, and their instruction to install REA. |

NightCoop is not a source. It is closed. Watch what the puppet does. Re-derive the inputs from the game exe.

CyberpunkMP is not a source. Study the behaviour. Re-derive every address.
