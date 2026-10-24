---
name: rusticre-hooks
description: Find a function worth hooking and prove the bytes still match. Use when attaching a detour, a vtable slot, or an import hook in a binary you own.
---

# Hooks

1. `imports` if the hook is on a DLL symbol. `strings` if you have a log message. `sigscan` if you have a byte pattern from the last build.
2. `inspect` the hit. Record the prologue bytes from that output.
3. `prologue --expect` those bytes. `PROLOGUE MISMATCH` means the site moved. Do not hook.
4. `evidence-add --kind hook` with the address, the expect bytes, and the source line.
5. On the next build of the same file, repeat `prologue` before installing the hook.

A hook is one site. A scan of every function is not a hook list.
