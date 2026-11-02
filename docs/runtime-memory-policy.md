# Runtime memory write and watchpoints: the policy

Answers GitHub issue #7. The policy is explicit, not a tool gap: **`runtime write` and `runtime watch` are fixture-only
by default, and an owner can authorize one named build with a declared, bounded range.** A build with no entry has the
static + probe fallback and nothing else.

## Three cases

| Target | `write` / `watch` | What to use |
|---|---|---|
| A verification fixture (SHA-256 in `runtime_fixture_sha256`, file carries `HYDRALYSIS_FIXTURE_ONLY`) | allowed (the default mode, unchanged) | as before |
| An application you own, listed in `runtime_authorized_targets` | allowed inside the declared ranges, after the checks below | owner-authorized mode |
| Anything else (no entry, a different build, an invalid entry) | refused: `[not_authorized] ...` | static `writes` action plus a live store probe |

The fallback for an unverified build is the one the Sprint 0/1 audit used: the static `writes` scan to find the store
sites, then `runtime` probes on them. It counts hits and records what it cannot see (finite sites, no data-flow to a
consumer); it is not a hardware watchpoint and does not say which write survived. That limit is the price of not
arming debug registers in a process nobody verified.

## Owner-authorized mode

Add an entry to the local `config.json`. The caller's options, the target's file and the target itself cannot turn it on.

```json
"runtime_authorized_targets": [{
  "sha256": "d36e74c47592e9c656ae250078cb40b2be63c782af5bfbeff2280d43e653fab4",
  "actions": ["write", "watch"],
  "max_size": 8,
  "ranges": [
    {"module": "Game.exe", "rva_start": "0x1F0000", "rva_end": "0x1F4000"},
    {"va_start": "0x7FF600200000", "va_end": "0x7FF600200100"}
  ],
  "note": "field table of the world state; owner: <name>"
}]
```

* `sha256`: the exact build. Another build of the same application is a different target.
* `actions`: `write`, `watch` or both.
* `max_size`: bytes per write, 1..64; a watch is also capped at 8 (the hardware).
* `ranges`: at least one, each at most 1 MiB. `module` + `rva_start`/`rva_end` follows the module's load address
  (ASLR-safe); `va_start`/`va_end` is an absolute range. The whole span of a request must lie inside one range.
* An invalid entry is ignored for that build and the refusal says why.

What stays exactly as in fixture mode:

* a write is a compare-and-swap (`expect` must match) with a required reason, and goes in the undo log; undo reports
  `DIVERGED` instead of overwriting what changed since. Undo is range-checked too;
* executable ranges are refused for both actions, even when a declared range covers one (`EXECUTABLE RANGE`);
* a watch is the state machine `arming -> armed -> disarming -> clear | tainted`; it reaches `clear` only through a
  debug-register readback of every thread, and a tainted session refuses to detach unless the owner forces it;
* every write and watch records `mode: authorized` in its log entry.

What is added: a **per-build conformance stamp** before any watch is armed. With `runtime setup` done, run:

```
python tools/watch_conformance.py <fixtures out dir> --bind-build <path to the authorized exe>
```

The tool runs the same real-process matrix (proof watch, CAS write/undo/DIVERGED, 100-iteration teardown race loop) on the
fixtures of the exe's architecture, and on a pass writes `<root>/watch-stamps/authorized/<sha256>.json`. A watch
on an authorized build needs a stamp that passes, names that build's SHA-256 and architecture, the pinned Frida
version and at least 100 iterations; otherwise it is refused with `[conformance_stamp_missing]`. The stamp does **not**
prove that the application tolerates debug registers (an anti-debug check, or its own use of them): the matrix never
runs on the application. That judgement stays with the owner, who is the only one who can edit the allow-list.

## Refusal codes

A refusal is a `PermissionError` whose message starts with a code in brackets (the `AuthorizationRefused` exception also
carries `.code` and `.detail`):

| Code | Meaning |
|---|---|
| `not_authorized` | neither a fixture nor an authorized build; the message names both settings and the fallback |
| `fixture_marker_missing` | listed as a fixture but the file has no marker, and no authorization applies |
| `action_not_authorized` | `write` or `watch` is not in the entry's `actions` |
| `size_exceeds_authorization` | larger than `max_size` (or 8 for a watch) |
| `outside_authorized_range` | the span is not inside a declared range |
| `conformance_stamp_missing` | no passing per-build stamp for this build, architecture and Frida |

Executable-range, alignment, slot, reason and CAS errors keep their existing messages.
