"""A stand-in for the frida binding, for transport tests only.

It starts real processes (so a child that inherits the server's stdin would
still hang), and simulates the device, sessions and scripts the runtime worker
drives: module lists, reads backed by the module's file, probes and breakpoints.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

__version__ = "17.24.3"

BASE = 0x140000000
_spawned: dict[int, subprocess.Popen] = {}


class _Exports:
    def __init__(self, script):
        self._script = script

    def __getattr__(self, name):
        handler = getattr(self._script, "rpc_" + name, None)
        if handler is None:
            raise AttributeError(name)
        return handler


class Script:
    def __init__(self, session, source: str):
        self.session = session
        self.source = source
        self.handlers = []
        self.loaded = False
        self.exports_sync = _Exports(self)
        match = re.search(r"const p=(\{.*?\});", source)
        self.parameters = json.loads(match.group(1)) if match else None
        self.seen = 0

    def on(self, event, callback):
        if event == "message":
            self.handlers.append(callback)

    def _send(self, payload):
        for handler in self.handlers:
            handler({"type": "send", "payload": payload}, None)

    def load(self):
        if self.parameters is not None:
            got = self.session.read(BASE + self.parameters["rva"], len(self.parameters["expect"]))
            if got != self.parameters["expect"]:
                raise RuntimeError("PROLOGUE MISMATCH; probe refused")
            export = self.parameters.get("export")
            if export is not None:
                # What the probe script checks against the live module's own export table.
                from hydralysis.runtime_exports import module_export
                if module_export(self.session.exe, export)["rva"] != self.parameters["rva"]:
                    raise RuntimeError("EXPORT MISMATCH; probe refused")
            self._send({"event": "probe_installed", "hook_id": self.parameters["id"], "verified_bytes": got})
            # One simulated hit, so status, continue and unload have something to act on.
            # HYDRALYSIS_FAKE_HITS=N: the probe fires N times; it sends at most `limit` events, as the real one does,
            # and its counters() say N.
            hits = int(os.environ.get("HYDRALYSIS_FAKE_HITS", "1"))
            if self.parameters.get("sample"):
                self.seen = 120
                self._send({"event": "sample", "hook_id": self.parameters["id"], "window_s": self.parameters["sample"]["window_s"],
                            "count": 120, "rate": 12.0, "min": 0.5, "max": 4.0, "last": 3.5})
            else:
                # A hit whose first capture points at "ABC": what the probe copies, decoded by the worker.
                captures = [{"pointer": hex(BASE), "hex": ("414243" + "00" * c["size"])[:c["size"] * 2]}
                            for c in self.parameters.get("captures", [])]
                self.seen = hits
                for hit in range(1, min(hits, self.parameters["limit"]) + 1):
                    self._send({"event": "break" if self.parameters["pause"] else "enter", "hook_id": self.parameters["id"],
                                "hit": hit, "thread": 1, "address": hex(BASE + self.parameters["rva"]),
                                "arguments": ["0x0"] * 8, "backtrace": [], "captures": captures})
        self.loaded = True

    def unload(self):
        self.loaded = False

    def post(self, message):
        pass

    # control script
    def rpc_info(self, selected=None):
        main = self.session.main(selected)
        return {"pid": self.session.pid, "arch": "x64", "pointer_size": 8, "selected_module_found": True, "main": main}

    def rpc_modules(self, limit):
        return {"total": 1, "truncated": False, "modules": [self.session.main()]}

    def rpc_threads(self, limit):
        return {"total": 1, "truncated": False, "threads": [{"id": 1, "state": "waiting", "context": {"pc": hex(BASE)}}]}

    def rpc_module(self, name):
        main = self.session.main()
        if name not in (main["name"], main["path"]):
            raise RuntimeError("module must match exactly one loaded path/name")
        return main

    def rpc_locate(self, address):
        main = self.session.main()
        return {"range": {"base": main["base"], "size": main["size"], "protection": "r-x"}, "module": main}

    def rpc_read(self, address, size):
        return self.session.read(int(address, 16), size)

    # probe script
    def rpc_status(self):
        return {"installed": self.loaded}

    def rpc_counters(self):
        if os.environ.get("HYDRALYSIS_FAKE_NO_COUNTERS"):
            raise RuntimeError("script has no exported counters")
        limit = (self.parameters or {}).get("limit", 0)
        return {"seen": self.seen, "hits": min(self.seen, limit), "limit": limit}

    def rpc_release(self):
        self.loaded = False


class Session:
    def __init__(self, pid: int, exe: str):
        self.pid = pid
        self.exe = exe
        self.callbacks = []

    def main(self, selected=None):
        path = self.exe
        return {"name": Path(path).name, "path": path, "base": hex(BASE), "size": Path(path).stat().st_size}

    def read(self, address: int, size: int) -> list[int]:
        # The module as loaded: RVAs map through the PE section table, like the real loader.
        from hydralysis.pe import Image
        rva = address - BASE
        try:
            chunk = bytearray(Image(Path(self.exe)).read_rva(rva, size))
        except Exception:
            chunk = bytearray(Path(self.exe).read_bytes()[rva:rva + size])
        # HYDRALYSIS_FAKE_PATCH="0x1000=E9 FB FF FF FF": a detour another tool wrote, live only (RVA).
        patch = os.environ.get("HYDRALYSIS_FAKE_PATCH", "")
        if patch:
            offset, text = patch.split("=", 1)
            data = bytes.fromhex(text)
            for index, value in enumerate(data):
                position = int(offset, 16) + index - rva
                if 0 <= position < len(chunk):
                    chunk[position] = value
        return list(bytes(chunk).ljust(size, b"\0"))

    def on(self, event, callback):
        self.callbacks.append(callback)

    def create_script(self, source):
        return Script(self, source)

    def detach(self):
        pass


class Device:
    def enumerate_processes(self):
        return [SimpleNamespace(pid=os.getpid(), name=Path(sys.executable).name)]

    def spawn(self, argv, envp=None, cwd=None, **options):
        process = subprocess.Popen(list(argv), env=envp, cwd=cwd, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        _spawned[process.pid] = process
        return process.pid

    def resume(self, pid):
        pass

    def attach(self, pid):
        # In the worker process the module is `__main__`; importing it under its own name would load a second copy
        # and hide a handler that looks its helpers up by that name (the real binding imports nothing of ours).
        process_path = getattr(sys.modules.get("__main__"), "_process_path", None)
        if process_path is None:
            from hydralysis.runtime_worker import _process_path as process_path
        return Session(pid, process_path(pid))


def get_local_device():
    return Device()
