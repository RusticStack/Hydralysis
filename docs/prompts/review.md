# Prompt

Paste this as it is.

```text
I made RusticRE to replace the REA and Ghidra MCPs. I use those today while
building Night City Together, the SWTOR preservation project, and the KotOR
remaster. REA loads on the order of 200 tools, Android and browser and
firmware included, and smaller models die before they do any real work. I
want one small server I can point at any program I own later, not a toolkit
hardcoded for these three.

Repo: https://github.com/RusticStack/RusticRE
Checkout: F:\Projects\RusticRE
Branch: main

The three projects are on this machine and on GitHub. Night City Together is
the Cyberpunk co-op mod. SWTOR-origins is the preservation and private-server
work. kotor-remaster is the KotOR reverse engineering and the new engine.
Use gh, and read them locally if you need to see how an agent actually
struggled. Do not turn RusticRE into a feature of any of them.

The failures matter as much as the calls that worked. These are the ones I
already hit, and I want you to treat a timeout or a dead session as a reason
to change a tool:

REA re-imports and re-analyses the binary on every call. On the 30 MB SWTOR
client that ran about 20 minutes and then timed out. The same decompile
against the already analysed project was a few seconds. After that, agents
stopped calling REA and typed analyzeHeadless by hand, which is the slow
path again. A Ghidra question that lists every xref to a name, or every
function, hangs for tens of seconds on a large program and then the rest of
that session fails too. Two agents opening one Ghidra project die on its
lock. The default 2 GB heap swaps. Starting a JVM for one CLI call costs
14 to 26 seconds before an answer, and REA's startup deadline aborted healthy
launches of big binaries. The tool list itself failed models before any call:
too many tools, or one schema over about 15 KB, and Qoder had REA plus two
Ghidra servers at once. A smaller server I did register was still unused,
because the old command was easier to type. KotOR's exe is packed, so a
decompiler that does not notice that spends its time on noise.

The objective: make RusticRE the tool you would trust if you were the agent
doing that work tomorrow. Research what REA and Ghidra were actually used
for, what timed out or killed the session, and what was loaded and never
touched. Use RusticRE yourself. Where a call is clumsy, slow, or missing,
change it and open a pull request against main. A tool that is correct but
times out, or that agents will not reach for, is not done.

Keep my bar. The server stays small. A tool earns its place because an agent
needed it, not because another project has it. No tool per game, engine, or
mod loader. Do not copy REA, Ghidra, or GhidraMCP into this repo. A hook is
not installed on a guess: the bytes have to match. A claim without a source
is not a claim. Decompiler text comes from a project that was already
analysed, opened read-only, not from importing the binary again.

In the pull request, say what you looked at, what you changed, and where you
would still rather call REA or Ghidra and why. Commits as
KelpHect <kellhect@gmail.com>.
```
