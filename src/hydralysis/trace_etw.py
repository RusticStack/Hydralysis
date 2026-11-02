"""Launch and supervise the ``hydra-etw`` consumer for a trace session; report what it could not cover.

The consumer writes its own segment (``etw.seg``) and health (``etw.health.json``) beside the agent's. Not being
elevated is not an error of the session: it is missing coverage, recorded as the limitation ``etw-not-elevated``.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

from . import proc

EXIT_OK, EXIT_FAILED, EXIT_REFUSED = 0, 2, 3
LIMITATION_NOT_ELEVATED = "etw-not-elevated"


def find_binary() -> Path | None:
    """``HYDRA_ETW`` first, then next to the engine install, then PATH."""
    env = os.environ.get("HYDRA_ETW")
    if env and Path(env).is_file():
        return Path(env)
    found = shutil.which("hydra-etw")
    return Path(found) if found else None


class EtwConsumer:
    def __init__(self, trace_dir: Path, session_id: str, pids: list[int], key_file: Path,
                 generation: int = 1, binary: Path | None = None, providers: list[str] | None = None) -> None:
        self.dir = Path(trace_dir)
        self.session_id = session_id
        self.pids = list(pids)
        self.key_file = Path(key_file)
        self.generation = generation
        self.binary = binary or find_binary()
        self.providers = providers
        self.proc: subprocess.Popen | None = None
        self.stop_file = self.dir / "etw.stop"

    @property
    def segment_id(self) -> str:
        return f"{self.session_id}/etw/{self.generation}"

    def start(self) -> dict:
        """Start the consumer. The result says whether it is running or why not (never raises for a missing tool)."""
        if self.binary is None:
            return {"state": "unavailable", "limitation": "etw-binary-missing"}
        self.dir.mkdir(parents=True, exist_ok=True)
        self.stop_file.unlink(missing_ok=True)
        cmd = [str(self.binary), "--dir", str(self.dir), "--session", self.session_id, "--key-file", str(self.key_file),
               "--gen", str(self.generation), "--stop-file", str(self.stop_file)]
        for pid in self.pids:
            cmd += ["--pid", str(pid)]
        if self.providers:
            cmd += ["--providers", ",".join(self.providers)]
        self.proc = proc.popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            code = self.proc.poll()
            if code is not None:
                return self._exited(code)
            health = self.health()
            if health.get("state") == "active":
                return {"state": "running", "health": health}
            time.sleep(0.05)
        return {"state": "starting"}

    def _exited(self, code: int) -> dict:
        if code == EXIT_REFUSED:
            return {"state": "refused", "limitation": LIMITATION_NOT_ELEVATED}
        err = ""
        if self.proc and self.proc.stderr:
            err = self.proc.stderr.read().decode("utf-8", "replace")[:500]
            self.proc.stderr.close()
        return {"state": "failed", "exit": code, "stderr": err}

    def health(self) -> dict:
        try:
            return json.loads((self.dir / "etw.health.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def stop(self, timeout: float = 30.0) -> dict:
        if self.proc is None:
            return {"state": "not-started"}
        if self.proc.poll() is None:
            self.stop_file.touch()   # a signal, not a record
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
                return {"state": "killed", "limitation": "etw-consumer-killed"}
        code = self.proc.returncode
        if code == EXIT_OK and self.proc.stderr:
            self.proc.stderr.close()
        return self._exited(code) if code != EXIT_OK else {"state": "stopped", "health": self.health()}

    def coverage(self) -> dict:
        """What the source could and could not see, for the session's health claims."""
        h = self.health()
        limits: list[str] = []
        if h.get("limitation"):
            limits.append(h["limitation"])
        producer, transport = h.get("producer", {}), h.get("transport", {})
        if producer.get("events_lost") or producer.get("buffers_lost") or producer.get("real_time_buffers_lost"):
            limits.append("etw-events-lost")
        if transport.get("queue_dropped"):
            limits.append("etw-queue-dropped")
        if transport.get("partial_decode"):
            limits.append("etw-partial-decode")
        if producer.get("provider_enable_failures"):
            limits.append("etw-provider-not-enabled")
        return {"complete": not limits and h.get("state") in ("active", "stopped"), "limitations": sorted(set(limits)), "health": h}
