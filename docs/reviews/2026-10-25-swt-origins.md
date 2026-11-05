# RusticRE on SWTOR-origins — what using it was actually like

This is a documentation-only report. No code changed, no game data included.

I came to RusticRE in the middle of a normal week of work: our native capture kit hooks 21
functions in the retail client, and I was about to re-check that its pinned prologues were still
correct before another session. The other question on my desk was the inbound router — a function
I keep citing but had never sat down and read end to end. Both are static questions against a
Ghidra project that already exists. That felt like a fair test of whether this tool fits the way I
work.

What follows is my experience, not a benchmark report. The numbers are real, but they are here
because they are what changed my mind, not because they are the point.

## The target I used

| field | value |
|---|---|
| executable | `swtor.exe`, build 25812320 |
| SHA-256 | `0f32b9d9562dafce89be662014615e0cc288f042a3fcfbbd8c38271abcd690f5` |
| format | PE32+, x64, image base `0x140000000` |
| Ghidra project | `client.gpr` / `client.rep`, already analysed, opened read-only from a snapshot |

## Getting started: two small stumbles before anything worked

The first thing I did was point the config at our project. I gave it the folder I think of as "the
project" — the one above `client.gpr` — and got:

```text
ValueError: analysed project is missing client.gpr or client.rep under F:\...\SWTOR-origins
```

It is a fair error. The file really was missing from where I pointed. But it took me a second to
realise the tool wanted the directory *containing* the project file, not its parent. After the
correction, `ghidra-query --action status` answered in 182 ms with `{"alive": false, ...}`, which
I liked: it did not start a JVM just to say hello.

Then I went to check the hook table. Our table stores each prologue as one lowercase string:

```text
488bc448894808565741544156415748
```

I pasted it into `--expect` and got:

```text
ValueError: prologue byte out of range: 488bc448894808565741544156415748
```

The parser splits on whitespace, so it read the whole thing as one enormous byte. Space-separated
bytes work. I reformatted by hand, checked three sites, and all three returned `PROLOGUE MATCH`.

That was the moment I stopped thinking of this as a tool I was evaluating and started thinking of
it as a tool I would have to wrap. Our whole reason for having a table is that it gets re-checked
as a table; a tool that only takes one byte string at a time is not shaped for the loop I actually
run.

## The moment it clicked

The router was different.

```text
python -m rusticre ghidra-query --target swtor --action decompile 0x14043cf20 --timeout 120
```

Cold, that took **5,998 ms** and returned 7,475 bytes: the function body `[0x14043cf20,
0x14043d37e]`, `body_truncated: false`, the program SHA-256 and `address_kind: VA`.

The second decompile — a different function — took **294 ms**.

Our own Ghidra headless lane took **5.9 s** for the same router, every time, because it starts a
JVM and opens the project for each question. So the warm path is not a marginal improvement; it is
the difference between "I'll batch these questions and come back" and "I'll just look now". I
found myself reading the router, then immediately asking for xrefs (236 ms, `query_s: 0.051`),
because the cost of another question had dropped below the cost of deciding whether to ask it.

That is the part I want to keep. It changed how I worked, not just how long a command took.

## What I trusted, and what I did not

I trusted the replies that carried the hash, the address space and the function bounds. When the
tool tells me `address_kind: VA`, the program SHA-256, and that the body was not truncated, I do
not have to open a second terminal to check which project or which address space I am in. That
matters more than it sounds in a project with several lanes and a history of RVA/VA mistakes.

I did **not** trust the `inspect` caller list at first. It printed one call candidate from
`0x43bdd5`, with a trailing note: `instruction boundaries unverified; limit 12`. It looked like a
cross-reference and did not behave like one. When the Ghidra `xrefs` call returned the same call
*plus* two data references, I relaxed: the heuristic was right about the call, just narrower than
the real reference set. But I had to learn that by cross-checking. The warning is there; it is
buried in a way I nearly missed.

This is also where I made my own mistake. I passed the RVA to our Ghidra headless script and it
exited **0** and printed `no function at 0x43cf20`. Our script did the wrong thing quietly.
RusticRE's explicit `address_kind` is the right instinct, and it is the reason I would rather see
every tool refuse an unlabelled address than trust the caller to remember which space they are in.

## What was clumsy, in the order I hit it

1. **The prologue format.** Contiguous hex is normal in tables; the tool takes only spaced bytes.
   Reformatting 21 rows outside the tool is exactly the friction a batch mode should remove.
2. **Two address conventions in one session.** `ghidra-query` rejects `va:0x14043cf20` with
   `use a numeric Ghidra VA, not a symbol name`, while the PE tools require or accept the prefix.
   I kept switching mental gears, and that is how the RVA mistake above happened.
3. **The project directory.** One cold-start retry per target because the field is the project
   directory itself, not its parent.
4. **Caller candidates look like xrefs.** The distinction is textual, not structural.
5. **No batch mode.** Three prologue checks were three processes. A 21-row table, which is what we
   actually maintain, has no single command.

None of these are deep design problems. All of them are the kind of thing that makes a tool feel
foreign to a workflow that is otherwise a good fit.

## What I need from Codex

These are ordered by how much they would change my week, not by implementation size.

### A. Let `prologue` take a table

This is the one I want most. Hook verification is a loop over a committed JSON file, and right now
the tool cannot consume that file. Accept contiguous hex; add `--expect-file` and
`--table <hooks.json>`; open and hash the image once; emit one JSON line per row and a summary;
exit non-zero on any mismatch.

The feeling I am chasing: one command I can put in CI, not a script I maintain to call the tool.

### B. One address convention

Accept `rva:` and `va:` in `ghidra-query` the way the PE tools do, keep unambiguous bare VAs
working, and echo the interpretation. I lost time to this, and I made a real mistake because of it.

### C. Separate call candidates from data references

`inspect` should emit `call_candidates` and `data_refs` as different keys, with the "unverified
boundaries" note attached only to the former. I should not have to cross-check to learn what a
list means.

### D. Give me a function dossier

Two calls for the router is fine; five or six for the next opcode is not. One bounded call that
returns bounds, signature, capped decompiler text, callers, callees, data references, short
strings, block count and edges, with a cursor and a file for the full text, would change the
79-opcode backlog from a project into an afternoon. I would rather have this than a wider catalog.

### E. Resolve the project directory

Accept a parent with a single project child, or fail naming the exact path. Small, but it is the
first thing every new user will hit.

### F. Don't grow the surface

Do not add per-game tools, a second decompiler, or unbounded listings. The small catalog is why I
could keep the whole tool in my head.

## What I still need REA for

The question after "what does this handler do" is always "where does this value come from". I did
not try to answer that here because I know RusticRE does not do value flow or bounded def-use. REA
does, and I will keep using it for that. This is not a complaint: a tool that tried to do
everything would be harder to trust for the parts it does well.

## What I still need Ghidra for

The first import and analysis, interactive type recovery, and saved renames, types and comments.
RusticRE opens a copy and never writes; that is the right boundary for it. Our client was already
analysed, which is the only reason the warm path was available to me at all.

## How I would describe it to a colleague

"Use it when the project is already analysed and you need a fact now." That is the sentence I
would say. It is smaller than REA and much faster than starting a JVM, and it tells you which
build and address space you are looking at. It is not the place to go for value flow, and it is
not a batch tool yet. With A, B and D it would be the first thing I open every morning.

## Evidence boundary

I used the user-owned retail client read-only. No game, hook or import was launched. RusticRE
copied its own snapshot; the master project was never written, and no symbols or comments were
saved. The config and snapshots are local and uncommitted. Nothing from another project's review is
included here; the findings are from the commands above.
