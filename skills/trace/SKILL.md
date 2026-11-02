---
name: trace
description: Ask what a program did, from a recorded or live semantic trace: bounded, cited answers with revision and coverage gaps. Capture itself is runtime.
---

# Trace

`trace` answers from the engine's store of semantic events. It never replaces `runtime` (which controls the target) and never
returns raw traces: replies hold counts, groups, a few representative events, event ids as citations, the `revision` they were
read at, the coverage revision and the gaps that matter, and what was cut.

1. Record: `trace action=start options={profile, images, scenario, launch:{action:"spawn", ...runtime options}}`. A build-bound
   profile is verified against the exact images first; a required hook that does not match refuses the session, an optional one
   is recorded as a coverage limitation. `trace action=stop session=<id>` ends capture and detaches. Or `action=import` a JSONL
   file (a damaged file imports its valid prefix and says where it stopped).
2. Look: `query` (kinds, filter, group_by, cursor, revision), then `explain` (options.event_id, depth, direction) to walk what
   led to an event, `mark` to label a moment, `status` for sessions and capture health.
3. Compare: `diff` (options.against, group_by). Output classes are `only_a`, `only_b`, `different_under_matched_coverage` and
   `not_comparable`. Absence in one run is not unreachability.
4. Assert: `check` returns pass, fail or unknown. Zero eligible cases, a missing observer or an overlapping gap is `unknown`.
5. Keep: `export`, `resymbolize` and `import` are jobs (`job` follows them). Cite a finding with `evidence_add` and
   `from_trace={session, events, revision}`; an evidence bundle then carries `traces/<session>.json` with the pinned revision
   and authorized artifact ranges, or lists what cannot be reproduced.

Read gaps before conclusions. A zero-loss counter with no active observer is not coverage, and a replay that cannot be
reproduced is said so. With no daemon, `options.offline=true` runs `op` verify, import, rebuild or export on files.
