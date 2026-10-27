# Hardware watchpoints and stepping: safety research

RusticRE does not yet provide hardware data watchpoints or CPU instruction
stepping. Its existing cooperative `break` action pauses in an instrumentation
callback; it is not an operating-system debugger and must not be described as
single-step support.

## What the fixture showed

On Windows x64 with Frida 17.24.3, an agent-created fixture exported a 4-byte
integer and incremented it in a loop. The fixture and test scripts were kept
outside the game installations, at
`F:/dev-cache/rusticre/watchpoint-fixture/`. The most recent x64 binary used
for the unrelated-exception and disconnect tests had SHA-256
`a472292851f1735446486b8f39f1b53ec9da07a8e2271ad66fbf0096e3b9c486`.

- A watchpoint using debug-register slot 0 was installed, then its Frida
  exception-handler script was unloaded without first clearing the slot. The
  next fixture write terminated it with `0x80000004` (`STATUS_SINGLE_STEP`).
  An explicit unload therefore cannot simply discard an armed handler.
- A separate prototype cleared the slot and its status bit in the native
  exception context. A matching write produced an event with the post-write
  trap PC and the fixture continued to exit 0. The trap PC is not claimed to
  be the address of the store instruction.
- A synthetic unrelated single-step exception had no matching DR6 slot bit and
  was passed to the fixture's own handler; a later actual watchpoint produced
  the expected slot bit and was handled. An already occupied slot was refused
  rather than overwritten.
- Registering `Script.bindWeak` cleanup let the x64 fixture survive a normal
  script unload and forced termination of a separate attached controller.
  Controller termination was also tested at several timings, including while
  the selected thread was suspended and after programming the slot but before
  resuming it. These are individual fixture runs, not proof against every
  timing or teardown failure.
- A manual 32-bit Windows context prototype hung twice and its agent-owned
  fixture/controller had to be stopped. A different prototype using Frida's
  built-in per-thread hardware-watchpoint operation caught a write in a 32-bit
  fixture and exited 0. That prototype did not establish safe slot ownership
  or disconnect cleanup. The x86 fixture binary SHA-256 was
  `c592c2aa8d51c9e677905e14ff0306a188c294d98a91096d5a3e7ecfb481fcbd`.

The local research scripts include `smoke.py`, `disconnect_test.py`,
`occupied_test.py`, and `frida32_probe.py` in the directory above. They are
experiments for disposable owned fixtures, not RusticRE's supported interface.
In particular, the deliberately unsafe unload test must never be run on a game.

## Requirements before exposing the capability

The backend needs to preserve the existing runtime session ownership and
target/build checks. A watchpoint should specify an exact address, size,
operation and thread, report its limited coverage, and avoid implying that a
post-instruction trap PC is the writer instruction. Its slot must be checked
and programmed without overwriting another debugger's state; the implementation
must retain a stable thread handle and account for thread exit and ID reuse.

The exception handler must recognize only its own slot and preserve or forward
unrelated exceptions. It must disarm on hit, cancellation, timeout, detach,
worker disconnect and partial setup failure. A failed disarm must not destroy
the handler while the hardware trap remains active. In particular, the
current runtime worker can be retired after an IPC timeout, so a design must
prove cleanup under controller death as well as orderly requests. Repeated
races and injected cleanup failures need coverage on each supported
architecture; the successful x64 disconnect samples above are insufficient
for that claim. Safe handling of stale or changed debug registers also needs
explicit tests before shipping.

True stepping additionally requires ownership of a real paused thread and
native single-step state, distinguishing its trap from watchpoints and other
debuggers, and restoring the thread's prior state on every exit path. A
tracing approximation or a cooperative function breakpoint is not a CPU step.

A separate native Windows debugger controller is another possible design:
[`DebugActiveProcess`](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-debugactiveprocess)
attaches to a process, and
[`WaitForDebugEvent`](https://learn.microsoft.com/en-us/windows/win32/api/debugapi/nf-debugapi-waitfordebugevent)
receives debug events. Its failure semantics need deliberate testing:
Windows documents that the debuggee is terminated by default when its debugger
exits, while
[`DebugSetProcessKillOnExit(FALSE)`](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-debugsetprocesskillonexit)
requests detachment instead. That setting alone does not establish that a
previously programmed hardware slot is cleared when the controller dies; the
linked documentation does not make that guarantee. Coexistence with RusticRE's
Frida session, target-owned exception handling, cancellation and both x86 and
x64 also require fixture tests before choosing that backend.

Frida documents its [per-thread hardware watchpoints and process exception
handler](https://frida.re/docs/javascript-api/) and describes their
[one-shot use](https://frida.re/news/2024/09/06/frida-16-5-0-released/).
Microsoft documents the [x64 Windows `CONTEXT` structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context).
