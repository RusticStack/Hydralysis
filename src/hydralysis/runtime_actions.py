"""The action handlers of a runtime session's worker: reads, patches, probes, breakpoints, unload.

A mixin of `runtime_worker.RuntimeAgent`. The module-file helpers (`file_bytes`, `_call_in_span`, ...) stay in
`runtime_worker` and are reached through `self._w()`: tests patch them there.
"""

from __future__ import annotations

import hashlib
import re
import sys
import uuid
from pathlib import Path

from hydralysis.runtime_agents import _expect, _probe_source


class ActionsMixin:
    def _w(self):
        """The module that defines the agent class: `hydralysis.runtime_worker`, or `__main__` when the worker runs
        as `python -m hydralysis.runtime_worker` (it is then not importable under its own name without a second copy)."""
        return sys.modules[type(self).__module__]

    def _module(self, args: dict) -> dict:
        name = str(args.get("module") or "")
        if not name:
            raise ValueError("select one loaded module by exact name or path")
        module = self.control.exports_sync.module(name)
        path = Path(module["path"])
        module["file_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
        expected = str(args.get("sha256") or "").lower()
        if expected and expected != module["file_sha256"]:
            raise ValueError("loaded module's backing file SHA256 differs from expected build")
        return module

    def _export(self, module: dict, args: dict) -> dict | None:
        """The export an observe/break names (`export`), looked up in the module FILE's export table; None when
        the request names an RVA. Naming both is allowed only when they agree."""
        if args.get("export") is None:
            return None
        from hydralysis.runtime_exports import export_table, resolve_export
        row = resolve_export(export_table(self._w()._image(module["path"])), str(args["export"]))
        if args.get("rva") not in (None, "") and int(str(args["rva"]), 0) != row["rva"]:
            raise ValueError("export %s is at rva %#x in the module's file, not %s" % (args["export"], row["rva"], args["rva"]))
        return row

    def _site(self, args: dict, hook: bool = False, with_export: bool = False):
        module = self._module(args)
        export = self._export(module, args) if hook else None
        rva = export["rva"] if export else int(str(args.get("rva", "")), 0)
        if not 0 <= rva < module["size"]:
            raise ValueError("RVA is outside selected module")
        if hook and not re.fullmatch("[0-9a-f]{64}", str(args.get("sha256") or "").lower()):
            raise ValueError("live probes require options.sha256: the full SHA-256 of the selected module's file "
                             "(for the main executable, the same hash as spawn/attach)")
        site = (module, rva, hex(int(module["base"], 16) + rva))
        return (*site, export) if with_export else site

    def _patcher(self, address: int) -> dict | None:
        """Follow a live detour (through a relay page if needed) to the module that installed it."""
        data = bytes(self.control.exports_sync.read(hex(address), 16))
        detour = self._w().decode_detour(data, address)
        hops = []
        for _ in range(3):
            if detour is None:
                break
            located = self.control.exports_sync.locate(hex(detour["target"]))
            hop = {**detour, "target": hex(detour["target"]), "module": (located.get("module") or {}).get("name"),
                   "module_path": (located.get("module") or {}).get("path")}
            if located.get("module"):
                hop["target_rva"] = hex(detour["target"] - int(located["module"]["base"], 16))
            hops.append(hop)
            if located.get("module") or not located.get("range"):
                break
            # A trampoline relay outside any module (MinHook-style): read where it jumps.
            detour = self._w().decode_detour(bytes(self.control.exports_sync.read(hex(detour["target"]), 16)), detour["target"])
        if not hops:
            return None
        return {"jump": hops[0]["kind"], "hops": hops, "patcher_module": hops[-1].get("module"),
                "patcher_path": hops[-1].get("module_path"), "detour": hops[-1]["target"]}

    def patches(self, args: dict) -> dict:
        rows = args.get("rows")
        if not isinstance(rows, list) or not 1 <= len(rows) <= 200:
            raise ValueError("patches needs rows=[{module, rva, size?}], 1..200")
        results, patched = [], 0
        for row in rows:
            module, rva, address = self._site({**row, "sha256": row.get("sha256", args.get("sha256"))})
            size = int(row.get("size", 16))
            if not 1 <= size <= 64 or rva + size > module["size"]:
                raise ValueError("patch check size must be 1..64 bytes inside the module")
            live = bytes(self.control.exports_sync.read(address, size))
            # The loader's base relocations are not patches: compare with the bytes as loaded.
            original = self._w().file_bytes(module["path"], rva, size, int(module["base"], 16))
            item = {"name": row.get("name", ""), "module": module["name"], "rva": hex(rva), "address": address,
                    "file_bytes": original.hex(" ").upper(), "live_bytes": live.hex(" ").upper(), "patched": live != original}
            if item["patched"]:
                patched += 1
                item["patch"] = self._patcher(int(address, 16))
            results.append(item)
        return {"rows": results, "checked": len(results), "patched": patched,
                "provenance": "file bytes from the module's file on disk; live bytes read now; detours decoded, not executed"}

    def _autostop_capture(self) -> None:
        """A detach ends an open capture while its probes can still answer for their counters."""
        if getattr(self, "open_capture", None) is None:
            return
        try:
            self._capture_stop(None)
        except Exception as exc:  # the detach goes on; the capture stays open and says so when read
            print("capture could not be sealed at detach:", repr(exc), flush=True)

    def _continue(self, hook_id: str):
        entry = self.scripts.get(hook_id)
        if entry is not None:
            entry["handle"].post({"type": "continue:" + hook_id})
        self.pauses.pop(hook_id, None)

    def handle(self, action: str, args: dict) -> dict:
        if action == "status":
            limit = int(args.get("limit", 40))
            after = int(args.get("after", 0))
            if not 1 <= limit <= 200 or after < 0:
                raise ValueError("status limit must be 1..200; after must be nonnegative")
            with self.lock:
                matching = [item for item, _ in self.events if item["sequence"] > after]
                events = matching[:limit]
                return {**self.snapshot(), "worker_alive": True, "events": events,
                        "truncated": len(matching) > limit, "next_after": events[-1]["sequence"] if events else after}
        if action == "detach":
            self._autostop_capture()
            return self.cleanup()
        if self.detached:
            raise RuntimeError("target session is detached")
        if action == "resume":
            if not self.paused_spawn:
                raise ValueError("resume is only for this session's paused spawn; use continue for a breakpoint")
            self.device.resume(self.pid)
            self.paused_spawn = False
            self.state = "running"
            self.publish()
            return {"state": self.state, "pid": self.pid}
        if action == "continue":
            hook_id = str(args.get("hook_id") or "")
            if hook_id and hook_id not in self.pauses:
                raise ValueError("hook is not currently paused")
            for item in [hook_id] if hook_id else list(self.pauses):
                self._continue(item)
            self.publish()
            return {"continued": hook_id or "all", "state": self.state}
        if action == "modules":
            limit = int(args.get("limit", 40))
            if not 1 <= limit <= 200:
                raise ValueError("limit must be 1..200")
            return self.control.exports_sync.modules(limit)
        if action == "threads":
            limit = int(args.get("limit", 40))
            if not 1 <= limit <= 200:
                raise ValueError("limit must be 1..200")
            return self.control.exports_sync.threads(limit)
        if action == "read":
            size = int(args.get("size", 64))
            if not 1 <= size <= 4096:
                raise ValueError("read size must be 1..4096")
            if args.get("address"):
                if args.get("module") or "rva" in args:
                    raise ValueError("read requires address or module+rva, not both")
                value = int(str(args["address"]).removeprefix("va:"), 0)
                info = self.control.exports_sync.info()
                maximum = 1 << (int(info["pointer_size"]) * 8)
                if not 0 < value < maximum or value + size > maximum:
                    raise ValueError("absolute read address overflows the target pointer width")
                address = hex(value)
                provenance = self.control.exports_sync.locate(address)
                module = provenance.get("module")
                rva = value - int(module["base"], 16) if module else None
            else:
                module, rva, address = self._site(args)
                if rva + size > module["size"]:
                    raise ValueError("read must remain inside selected module")
                provenance = self.control.exports_sync.locate(address)
            data = self.control.exports_sync.read(address, size)
            layout = args.get("layout")
            typed = None
            if layout is not None:
                from hydralysis.runtime_decode import layout_values
                if not isinstance(layout, list) or len(layout) > 512:
                    raise ValueError("layout is a list of at most 512 {name, offset, type, size?} fields")
                typed = layout_values(layout, bytes(data))
            return {"module": module, "rva": hex(rva) if rva is not None else None, "address": address,
                    **({"fields": typed, "type": args.get("type_name")} if typed is not None else {}),
                    **({"layout_source": args["layout_source"]} if args.get("layout_source") else {}),
                    "range": provenance.get("range"), "target": {"pid": self.pid, "created_ms": self.target_created_ms,
                    "exe": self.target_exe, "exe_sha256": self.target_sha256},
                    "bytes": " ".join("%02X" % x for x in data)}
        if action in ("observe", "break"):
            module, rva, address, export = self._site(args, hook=True, with_export=True)
            expect_source = "caller"
            if export and not args.get("expect"):
                # A hook by export name may leave expect out: it is then the file's own bytes as the loader leaves
                # them, so the live site is still checked against the build the hash names.
                expect_source = "file"
                args = {**args, "expect": " ".join("%02X" % b for b in self._w().file_bytes(
                    module["path"], rva, 8, int(module["base"], 16)))}
            expected = _expect(str(args.get("expect") or ""))
            if rva + len(expected) > module["size"]:
                raise ValueError("expected bytes extend outside selected module")
            actual = self.control.exports_sync.read(address, len(expected))
            patch = None
            # expect is the file's bytes; a relocated module holds them with the loader's fixups.
            if list(actual) != expected and self._w()._relocated(module, rva, expected, list(actual)):
                expected = list(actual)
            if list(actual) != expected:
                patch = self._patcher(int(address, 16))
                # accept_patch: expect is the original prologue; the live bytes may differ only by a
                # detour another tool wrote, and the module's file must still hold expect exactly.
                if not args.get("accept_patch") or patch is None:
                    raise ValueError("PROLOGUE MISMATCH; hook refused: got " + " ".join("%02X" % x for x in actual)
                                     + ("; live detour %s to %s (%s); pass accept_patch=true with the original prologue to probe past it"
                                        % (patch["jump"], patch["detour"], patch["patcher_module"] or "no module") if patch else ""))
                original = list(self._w().file_bytes(module["path"], rva, len(expected)))
                if original != expected:
                    raise ValueError("accept_patch needs expect to be the module file's original prologue; the file holds "
                                     + " ".join("%02X" % x for x in original))
                expected = list(actual)
            limit = int(args.get("limit", 20))
            if not 1 <= limit <= 200:
                raise ValueError("probe limit must be 1..200")
            from hydralysis.runtime_decode import SCALARS, normalize
            captures = normalize(args.get("capture"))
            sample = args.get("sample")
            if sample is not None:
                if action != "observe" or not isinstance(sample, dict) or set(sample) - {"window_s", "capture"}:
                    raise ValueError("sample is for observe: {window_s 1..300, capture: index of a numeric capture}")
                window, index = int(sample.get("window_s", 10)), int(sample.get("capture", 0))
                if not 1 <= window <= 300 or not 0 <= index < len(captures) or captures[index]["as"] not in SCALARS:
                    raise ValueError("sample needs window_s 1..300 and a capture index whose decoder is a number")
                sample = {"window_s": window, "capture": index, "as": captures[index]["as"]}
            convention = str(args.get("convention") or "native")
            if convention not in ("native", "thiscall", "fastcall"):
                raise ValueError("convention is native, thiscall or fastcall (the last two for 32-bit x86)")
            call = self._w()._call_in_span(module["path"], rva)
            if call:
                raise ValueError("probe refused: the bytes it would overwrite hold a call (%s), which the instrumentation "
                                 "cannot release again; probe the call's target, or an instruction after the call" % call)
            # A probe inside a function (a store, a call site) must not hook the return: say so with
            # instruction=true; on x64 a site that is not the start of a pdata function is one.
            instruction = bool(args.get("instruction"))
            if not instruction:
                instruction = self._w()._inside_function(module["path"], rva)
            hook_id = uuid.uuid4().hex
            source = _probe_source(module, rva, expected, hook_id, limit, action == "break", captures, sample, convention,
                                   instruction, export["name"] if export and export["name"] else None)
            handle = self._load(hook_id, source, {"kind": action, "module": module, "rva": hex(rva), "expected_bytes": expected,
                                                  "captures": captures, "sample": sample, "limit": limit,
                                                  "convention": convention,
                                                  **({"export": export} if export else {})})
            return {"hook_id": hook_id, "verified": True, "module": module, "rva": hex(rva), "instruction": instruction,
                    "address": address, "script_sha256": handle["source_sha256"], "pause_deadline_s": 30 if action == "break" else None,
                    "expect_source": expect_source,
                    **({"export": {"name": export["name"], "ordinal": export["ordinal"], "rva": hex(export["rva"]),
                                   "checked_against": "the module file's export table (build hash %s)"
                                                      % module["file_sha256"][:16]}} if export else {}),
                    **({"past_patch": patch} if patch else {})}
        if action == "patches":
            return self.patches(args)
        if action == "capture":
            return self.capture(args)
        if action == "snapshot":
            return self.snapshot_take(args)
        if action == "unload":
            script_id = str(args.get("script_id") or args.get("hook_id") or "")
            if script_id not in self.scripts:
                raise ValueError("script_id/hook_id is not owned by this session")
            self._unload(script_id)
            self.publish()
            return {"unloaded": script_id}
        raise ValueError("unsupported runtime action; use guarded observe/break or bounded read; arbitrary scripts are not accepted")

    def _load(self, script_id: str, source: str, metadata: dict) -> dict:
        script = self.session.create_script(source)
        script.on("message", lambda message, data: self.message(script_id, message, data))
        entry = {**metadata, "handle": script, "source_sha256": hashlib.sha256(source.encode()).hexdigest()}
        self.scripts[script_id] = entry
        try:
            script.load()
            if entry.get("script_error"):
                raise RuntimeError("runtime script failed: " + entry["script_error"])
            if metadata.get("kind") in ("observe", "break") and not script.exports_sync.status().get("installed"):
                raise RuntimeError("runtime probe did not confirm installation")
        except Exception as original:
            try:
                script.unload()
                self.scripts.pop(script_id)
            except Exception as cleanup:
                # Retain ownership for explicit cleanup retry.
                entry["cleanup_pending"] = True
                error_type = PermissionError if isinstance(original, PermissionError) or isinstance(cleanup, PermissionError) else RuntimeError
                raise error_type("runtime script %s failed to load (%s); cleanup failed (%s); "
                                 "script retained for unload retry" % (script_id, original, cleanup)) from original
            raise
        self.publish()
        return entry

    def _unload(self, script_id: str):
        entry = self.scripts[script_id]
        self._retire_hook(script_id)
        if script_id in self.pauses:
            self._continue(script_id)
        try:
            entry["handle"].unload()
        except Exception as exc:
            # A script the target's exit (or the session's end) destroyed is already gone.
            if "destroyed" not in str(exc):
                raise
        self.scripts.pop(script_id)
