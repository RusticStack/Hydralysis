# Resumable saved-analysis exports

`ghidra_query` action `export` starts a durable background file job. It does
not return thousands of C bodies through MCP, start an import, or modify the
canonical Ghidra project. A target must already have valid saved analysis.

For example, save these options as `F:/work/export-options.json`:

```json
{"mode":"decompile","limit":10849,"timeout_s":60}
```

Then use the same CLI/MCP path:

```text
hydralysis ghidra-query --target sample --action export --options-file F:/work/export-options.json
hydralysis job export-0123456789ab
hydralysis job export-0123456789ab --action cancel --owner <owner_token>
```

The Python API is `exporting.start(settings, target, options)`;
`exporting.status(settings, id)` and `exporting.cancel(settings, id)` operate
on the returned `export-...` identity. Modes are `decompile`, `functions` and
`types`. Options accept `limit` (1–100,000 records, default 100,000), optional
literal name/path `contains` or `regex`, inclusive function VA `start`/`end`,
an absolute `.jsonl` output path `out`, per-query `timeout_s` (1–300, default 30),
and `resume`. By default records stream under `<root>/exports/<id>/<mode>.jsonl`,
alongside `imports.json`, `job.json` and a durable worker log. A custom `out`
must have an existing parent and cannot be inside a Ghidra project. Identical active/completed requests reuse the
existing job instead of launching duplicate exports.

## Progress and truthful completion

Status returns counters for completed keys, successes, individual failures and
truncated results, plus the current enumeration cursor, source provenance,
paths, byte count, error and bounded log tail. `state=done` means the requested
export run ended; inspect `complete` and `limited` as well. A count cap, failed
function or truncated body/type means `complete=false`. Reaching the end of the
selected enumeration without those losses is required for a complete export.
A filtered export is complete only for that filter; a whole-program inventory
also requires an empty `contains` filter.
The caller's limit is an explicit upper bound, not proof that the program has
that many functions.

Each completed record includes a build SHA-256 and the saved-project,
implementation and type-overlay identity used to produce it. An export of C
uses the query's explicit 2,097,152-character per-function cap; larger functions
retain `truncated=true`. Nested recovered-type truncation is also counted.
Per-function decompiler timeouts/refusals produce failed rows and do not discard
other results. Backend/session failures pause the job with its progress intact;
a busy backend gets one bounded retry. Status makes a dead worker `interrupted`
rather than leaving it permanently `running`.

`imports.json` contains observed PE import names/ordinals/IAT addresses from the
configured executable, tied to its full build digest. A target with only a
saved-project hash or an unsupported non-PE binary records import availability
as unknown/unavailable; it does not invent an import list.

## Hashes and their scope

- `c_sha256` hashes the exact exported UTF-8 C text. It remains a partial-text
  hash when `truncated=true`.
- `body_sha256` hashes ordered file-backed body bytes with an explicit domain
  tag and little-endian RVA/length pairs. It is a build-bound byte-layout hash,
  not a normalized assembly or semantic-equivalence hash. Body hashing uses at
  most 16 MiB per function, with an explicitly reported unavailable reason for
  missing/truncated/non-file-backed ranges. A configured PE larger than the
  512 MiB in-memory body-hash budget likewise records that limitation.
- The completed run records output/import file digests. It does not claim an
  assembly artifact/hash when no assembly text was exported.

## Resume and cancellation

Resume by giving the original id, for example:

```json
{"resume":"export-0123456789ab"}
```

Use that object with the same target and `--action export`. Resume validates
the full binary digest, saved source metadata, backend application metadata,
query/export implementation and type-overlay identity. It cannot change the
recorded mode, filter, count cap or timeout, and does not accept a user-supplied
cursor or completed-address list. A completed valid export returns its existing
artifact instead of repeating work. Changed source/code/overlays require a new
export, leaving the old one intact.

Every JSONL append is flushed and fsynced before updating progress. Resume
replays completed keys from validated output, so a worker dying after a durable
row but before its checkpoint does not duplicate that row or skip the following
one. Duplicate keys, changed provenance, a missing recorded output, a torn tail
or an invalid JSON row cause explicit refusal with the original file preserved.
The reader has a 16 MiB row and 1 GiB total replay/output budget; hitting a budget
pauses or refuses explicitly rather than silently truncating or rewriting data.

An OS run lock prevents two workers from appending to one export; a separate
control lock serializes launch/resume. Cancellation is checked before backend
work and between functions. It waits for the current bounded query to finish;
it does not kill another client's shared query worker. Cancelled exports retain
their rows and can be resumed after validation.

The regression suite uses a fake `QueryRunner` and fixture source metadata to
exercise streaming, caps, nested truncation, busy/refused calls, cancellation,
worker interruption, crash-after-append recovery, duplicate starts, provenance
changes and torn tails. Real integration is intentionally a small owned fixture
export. A full game or 10,849-function decompilation is not part of automated
development verification and should be launched only when the user requests it.
