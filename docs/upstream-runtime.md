# Native runtime observations and debugging

The reference inspected was `morluto/rea` at
`f196ebf80665107aedc16892af25a1e1f9f26f43`, using `gh` and the external
reference checkout `F:\dev-cache\ref-repos\rusticre-rea-reference`. No REA
implementation, MCP process or package is a RusticRE runtime dependency.

The upstream [Frida workflow](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/docs/frida-instrumentation.md)
loads an optional native binding, enumerates processes, attaches or spawns a
paused target, loads authored scripts, captures bounded messages and detaches.
Its [tool contracts](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/src/contracts/fridaToolContracts.ts)
expose eight lifecycle tools. The [session manager](https://github.com/morluto/rea/blob/f196ebf80665107aedc16892af25a1e1f9f26f43/src/frida/FridaInstrumentationManager.ts#L299-L407)
tracks the selected process, paused spawn and acquired provider resources.
Those are useful semantics, not a reason to register eight more MCP tools.

RusticRE implements one generic `runtime` operation family in its own Python
worker. The optional backend is the pinned Frida Python package, installed
under the configured development root. Setup reads the official pinned-version
[PyPI metadata](https://pypi.org/pypi/frida/17.24.3/json), records wheel hashes,
requires pip hash verification and imports the resulting version before
reporting readiness. No global Python, PATH, permissions, security controls or
MCP registration are changed. An incomplete installation is preserved and
reported rather than silently deleted or replaced.

The [Frida JavaScript API](https://frida.re/docs/javascript-api/) is the primary
API reference for module enumeration, readable memory ranges, `Interceptor`,
CPU contexts, backtraces and typed `send`/`recv` communication. The implementation
was written independently against that API; it is not a copy of REA.

## Small runtime protocol

The Python entry point is `runtime(action, options, settings)`, also shared by
CLI and MCP dispatch. Backend inspection is `inspect(settings)` and explicit
installation is `setup(settings)`.

| Action | Required selection / behavior |
| --- | --- |
| `processes` | Local bounded process discovery. No target attaches. |
| `spawn` | Exact `exe`, optional `argv` and expected `sha256`. Returns a paused owned spawn and runtime `session`. |
| `attach` | Explicit `pid` and exact `exe`; OS process path is checked before injection. |
| `status` | `session`, optional `after` event sequence and `limit`. Includes dropped-event counts and continuation. |
| `modules`, `threads` | `session`; bounded loaded-module facts or observed thread CPU contexts. |
| `read` | `session`, bounded `size`, and either module+RVA or explicit absolute `address`. Reads remain within one readable mapping; heap/stack reads retain target identity and range provenance. |
| `observe` | `session`, exact module `sha256`, `module`, `rva`, 5–64 concrete `expect` bytes and bounded event `limit`. |
| `break` | The same checked site as `observe`, capturing context before waiting for explicit continue. |
| `continue` | `session`, optional `hook_id`; releases the stopped callback thread. A 30-second watchdog also releases it. |
| `unload` | `session` and an owned `hook_id` or `script_id`; releases the probe/script. |
| `resume` | Resumes only the paused spawn owned by this session. It is separate from breakpoint continuation. |
| `detach` | Releases owned probes/scripts, detaches and resumes a still-paused owned spawn after instrumentation release. Never kills the target. |

The target process and runtime worker are distinct. Every worker has its own
OS request lock, local IPC channel, process creation identity, durable log and
bounded request deadline. A failed native request cannot block the MCP control
reader. Requests use one authenticated loopback TCP connection per call,
bound strictly to `127.0.0.1` on an ephemeral port. Four-byte big-endian lengths
frame UTF-8 JSON, capped at 256 KiB in both directions. Full request UUIDs,
constant-time comparison of a 256-bit token and one monotonic deadline across
connect/send/header/body reads bound admission and transport. The token lives
only in the private local readiness record; public tool metadata omits it.
No caller supplies a remote address. Structured agent errors leave the session
available; a native request that fails its deadline is cleaned up and retired.
Durable readiness, state and logs remain on disk; filesystem access errors
propagate with errno, native error when available, and the exact path.
Evidence records the generated probe's SHA-256.
Messages retain at most 1,000 events / 256 KiB, and an individual oversized
payload is explicitly clipped. Event pagination cannot recover already evicted
events; `dropped_events` discloses that loss.

## Verification before changing target code

Built-in probes check the selected module backing file's full SHA-256 against
the expected build, verify live bytes, and repeat the live-byte and module-base
checks inside the injected script immediately before `Interceptor.attach`.
Wildcards cannot validate a runtime probe. A mismatch does not install one.
These checks establish the selected site's bytes at installation; they do not
prove a calling convention or that the function is semantically the intended
one. The backing-file digest is not a hash of the complete live relocated image.
Live reads and the final pre-hook snapshot use
[`NativePointer.readVolatile`](https://frida.re/docs/javascript-api/#nativepointer),
which avoids native exceptions when a running target changes a mapping. A null
or short snapshot is refused before byte comparison or hook installation;
the readable-range and target-pointer-width bounds still apply.

The generic probe captures observed CPU context, up to eight raw argument
slots, return register value, return address, thread id and a bounded backtrace.
Raw slots and pointer values are not asserted to be typed source-language
arguments. `break` stops the callback's target thread; it is not a stop-the-world
debugger. On unload/detach the callback is continued before instrumentation is
released. Failed cleanup retains owned handles and reports the error; a target
is not claimed dead or successfully resumed without an observed operation.

Arbitrary target-side scripts are deliberately not exposed: they could bypass
the required byte-verification gate through an unchecked hook. The generated
control/probe scripts are internal implementation details. Host-side project
code can decode the bounded observations and pointer reads without installing
another MCP server.

This replaces the needed local process lifecycle and register/probe observation
use cases. It does not relabel Frida as a portable instruction-step debugger;
CPU single-step and unrestricted authored Frida scripts are not advertised.

`tests/test_runtime.py` exercises byte/hash refusal before injection, JavaScript
error propagation, context/break source generation, event bounds, explicit
continuation, detach-before-resume ordering, cleanup failure ownership, PID
reuse refusal and isolated backend installation. Real runtime verification uses
the coordinator's compiled owned fixture; it must not launch or inject games
merely to establish generic runtime behavior.

## Real owned-fixture verification

The coordinator's `runtime_fixture.exe` was exercised through `RuntimeRunner`
with the optional backend installed under
`F:\dev-cache\rusticre\complete-20261024`. The successful bounded harness
log is `runtime-integration-smoke-v5-ipc.log`; full observations and fixture SHA-256
are in `runtime-integration-results.json`. It verified paused spawn, explicit
PID attach, module bytes, mismatch refusal, observed arguments/registers/return
and backtrace, removal restoring original bytes, a verified breakpoint,
absolute `Sample` memory read while stopped, explicit continue and matching
return, detach leaving the target alive, and graceful stopfile exits. No game
was launched, attached, imported or decompiled.

The real calls found defects not established by mocks: Windows paused-spawn
`Process.mainModule` selected an unrelated module, so startup now resolves the
requested exact loaded path; Frida CPU context properties are non-enumerable,
so register capture explicitly selects the architecture's documented register
names; and readiness must preserve worker PID/creation identity separately
from the target PID. Their failed logs remain alongside the successful run,
and regression tests cover the corrected contracts. This is instrumentation
and single-thread probe/breakpoint validation, not full native debugger parity.

An independent x86 build of the same source has PE machine `0x14c`, a 32-bit
optional header and Frida `ia32` / four-byte pointers. Its build and full smoke
evidence is under `fixture-x86/build.log`,
`runtime-x86-integration-smoke-v4-ipc.log` and
`runtime-x86-integration-results.json` in the same external evidence root.
The x86 fixture SHA-256 is
`f98a1d50309926fa8864adfbb81f06a475ac1a6e6ace2e2f1c93eccdfa16949a`.
Both architectures passed the lifecycle, bytes, context, breakpoint, pointer
read, restoration and graceful-exit checks above with IPC and volatile reads.

The earlier x86 file-mailbox attempts failed with reported access errors,
including on an immutable request filename (`errno=13`, native error
unavailable through Python's CRT). Their logs and partial reports are retained.
Cleanup detached and released probes; no permissions or security settings were
changed. This failure prompted the loopback transport change, rather than a
longer timeout or suppression of permission errors. The final x64 and x86
runs both use the replacement transport.
