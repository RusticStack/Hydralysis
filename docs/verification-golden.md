# 12.1.4 against 12.3 decompile comparison (Z7)

This page reports how the C text that Ghidra 12.1.4 produces differs from the C text of 12.3
(Hydra Engine 12.3-hydra.3). It is **reported, never gated** (owner decision): nothing in the
repository's tests, CI or release steps fails on these numbers. It holds **counts only**. No
decompiled C, function name or address of any game is in this repository; the captures stay under
`D:/Projects/Hydra/_golden`, outside the repository, as the harness rule requires.

The capture and diff harness is `tools/golden.py` (frozen, see [golden-harness.md](golden-harness.md)).
The classification is `tools/golden_classify.py`, a separate tool that only reads captures.

## What was compared

| | A | B |
| --- | --- | --- |
| engine | stock Ghidra 12.1.4 PUBLIC | Hydra Engine 12.3-hydra.3 (Ghidra 12.3 DEV) |
| decompile path | `explicit`, `--options-mode fixed` | the same |
| program | one KotOR executable, 8,616 comparable functions, SHA-256 `0290889e...437e6` (the same project copy lineage for both) | the same program |
| fixtures | the 8 generated fixture programs, imported and analysed by stock 12.1.4 | the same 8 programs, in two modes below |

The two modes for the fixtures answer "fresh against upgraded analysis":

* **upgraded**: B opens the project that stock 12.1.4 analysed, so 12.3 upgrades it in memory and
  decompiles what 12.1.4 found.
* **fresh**: B opens a project that 12.3 imported and analysed itself.

## The `maxBadData` option held equal

12.3 added the decompiler option `maxBadData` (upstream change GP-6945, default 4): after that many
bad-data exceptions in one function the decompiler stops with an error. 12.1.4 has no such option and
no limit. The earlier reading of the 77.124% figure was that this option confounded it.

Holding the options equal was done without editing the frozen harness:

* The harness script `GoldenExport.java` was copied to a scratch directory under `_logs` together with
  `golden.py`, and one line was added to the copy: `options.setMaxBadData(1000000)`. The repository
  copy is untouched. Because 12.1.4 has no limit, a very large value is the closest equal setting.
* Both B captures were made: pinned (`maxBadData` 1000000) and unpinned (12.3's default 4).
* `golden_classify.py` excludes `maxBadData` when it compares the two option sets and lists any
  other differing option by name. The result for every capture pair below: **no other option
  differs** (`equal_apart_from_pinned` true).

Result, counted on the KotOR capture:

| | functions |
| --- | ---: |
| with bad-data text in 12.1.4 (A) | 0 |
| with bad-data text in 12.3 (B, pinned) | 0 |
| with bad-data text in 12.3 (B, default 4) | 0 |
| changed against A, B pinned | 1,971 |
| changed against A, B default | 1,971 |
| changed only when pinned / only when default | 0 / 0 |
| B pinned against B default, any difference | 0 |

So on this program the option changes nothing: pinning it leaves exactly the same 6,645 of 8,616
identical (77.124%) and the same 1,971 changed functions. **The statement that the figure is
"confounded by `maxBadData` 4" is not supported by this measurement** and should not be repeated
in other documents; the difference has other causes (next section).

## KotOR: the 1,971 changed functions by cause

6,645 of 8,616 functions are identical or identical after normalisation (77.124%); 1,971 are
changed; none failed or is missing on either side. Each changed function gets one primary cause,
the first rule that matches its changed lines (rule order is the table order). The rules are
heuristic text rules over the normalised line diff, not a proof of equivalence.

| primary cause | functions | policy |
| --- | ---: | --- |
| bad instruction handling (`maxBadData`) | 0 | accepted |
| unimplemented instruction | 0 | open |
| switch or jump table | 8 | open |
| WARNING comment text only | 2 | accepted |
| calling convention or register notation | 47 | open |
| same statements, different order | 54 | accepted |
| same conditions, flipped polarity or swapped operands | 744 | accepted |
| different branch, loop or goto count | 236 | open |
| stack variables split, merged or resized | 401 | open |
| declared types of locals | 129 | open |
| types or pointer casts | 59 | open |
| constants or data references | 167 | open |
| variable naming only | 21 | accepted |
| no rule matched | 103 | open |
| **accepted / open** | **821 / 1,150** | |

`by_signal` (every rule that matches, not only the first) is in the tool's JSON output; a function
can have several causes, so those counts add up to more than 1,971.

## Accepted-difference policy

* **accepted** means: the mechanism is named, the difference is reported, and no action is required.
  The accepted classes are presentation differences (statement order, condition polarity, comment
  text, naming). They are accepted **by class**; no individual function was checked for semantic
  equivalence, so "accepted" is a statement about the class rule, not a proof for each function.
* **open** means: not attributed to a documented upstream change. Open is not a failure and nothing
  is gated on it; it is the list a person would look at first if a decompiler difference mattered.
* The table lives in `POLICY` in `tools/golden_classify.py`. The `bad-data-limit` entry is accepted
  because the mechanism is documented upstream, even though no function in the measured programs
  hits it.
* A stricter or looser policy changes only the accepted/open split, never an exit status: the tool
  exits 0 whenever it produced a report.

## Fixtures: stock 12.1.4 baselines

Stock 12.1.4 baselines exist for all 8 fixtures (x64 and x86; flow, vcall, diff1, diff2). The
fixtures contain no game data, so their counts are shown per fixture.

Upgraded mode (12.3 reads the 12.1.4 analysis), 3,965 functions compared, 3,127 identical (78.9%), 838 changed:

| fixture | compared | identical | changed | match % |
| --- | ---: | ---: | ---: | ---: |
| fx-x64-flow | 405 | 321 | 84 | 79.259 |
| fx-x64-vcall | 418 | 335 | 83 | 80.144 |
| fx-x64-diff1 | 506 | 397 | 109 | 78.458 |
| fx-x64-diff2 | 506 | 397 | 109 | 78.458 |
| fx-x86-flow | 473 | 376 | 97 | 79.493 |
| fx-x86-vcall | 489 | 393 | 96 | 80.368 |
| fx-x86-diff1 | 584 | 454 | 130 | 77.740 |
| fx-x86-diff2 | 584 | 454 | 130 | 77.740 |

Fresh mode (12.3 analyses the program itself), 3,965 functions compared, 3,049 identical (76.9%), 910 changed:

| fixture | compared | identical | changed | match % |
| --- | ---: | ---: | ---: | ---: |
| fx-x64-flow | 405 | 315 | 90 | 77.778 |
| fx-x64-vcall | 418 | 329 | 89 | 78.708 |
| fx-x64-diff1 | 506 | 391 | 115 | 77.273 |
| fx-x64-diff2 | 506 | 391 | 115 | 77.273 |
| fx-x86-flow | 473 | 365 | 107 | 77.167 |
| fx-x86-vcall | 489 | 382 | 106 | 78.119 |
| fx-x86-diff1 | 584 | 438 | 144 | 75.000 |
| fx-x86-diff2 | 584 | 438 | 144 | 75.000 |

Reading: the identical share on generated fixtures (75 to 80%) is close to KotOR's 77%, so the
difference is a property of the decompiler version, not of the game program. Fresh analysis changes
a few more functions than upgraded (72 more over the eight fixtures), and in fresh mode the x86
fixtures have 1 or 2 functions that only one side found (missing in B). Every fixture pair has
equal options apart from `maxBadData`. `fx-*-diff1` and `fx-*-diff2` give identical counts.

## Reproduce

All paths below are on the owner's machine, outside the repository.

```text
python tools/golden_classify.py classify <A explicit capture> <B explicit capture> ^
    [--unpinned <B capture with the engine default>] --json out.json --markdown out.md
python tools/golden_classify.py fixtures <root A> <root B> --json out.json --markdown out.md
```

Captures: `_golden/baselines/ghidra-12.1.4/kotor/explicit` (the existing stock baseline),
`_golden/baselines/hydra-3-released/kotor/explicit-pinned` and `explicit-default`,
`_golden/baselines/ghidra-12.1.4/fixtures/<name>/explicit`,
`_golden/baselines/hydra-3-released-upgraded/fixtures/<name>/explicit` and
`hydra-3-released-fresh/fixtures/<name>/explicit`. Reports: `_golden/after/z7/`. The project copies
used by the engine captures are in `_golden/copies-z7` (each proven identical to its source by
`project-copy`); the KotOR original was never opened by an engine.

The pinned captures used a harness copy whose `GoldenExport.java` differs from the repository's by
the single `setMaxBadData` line; their headers record that script's SHA-256. The unpinned and the
stock captures used the repository copy.

## What this page does not claim

* It does not say 12.3 is better or worse than 12.1.4; it counts where the text differs.
* "Accepted" is by class, not verified per function (see the policy above).
* The 98% gate of the old harness is **reported, not enforced**: at 77.124% it would fail, and by
  the owner's decision it does not.
* The timing of the captures was taken while other agents used the machine; no timing claim is made.
