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

The objective: make RusticRE the tool you would trust if you were the agent
doing that work tomorrow. Research what REA and Ghidra were actually used
for, and what was loaded and never touched. Use RusticRE yourself. Where a
call is clumsy, or something you needed is missing, change it and open a
pull request against main.

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
