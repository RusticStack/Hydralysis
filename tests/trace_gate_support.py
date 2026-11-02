"""Support for the acceptance-gate tests (tests/test_trace_gates.py): real fixtures, live capture, the real engine.

* `fixtures_dir()` builds the trace fixtures once (HYDRA_TRACE_FX names a persistent build directory to reuse).
* `GateProfile` writes a fixtures-only profile for ANY fixture function: the prologue is read from the built image, so the
  hook verifies by construction, and each hook names the payload fields (corr, key, object, ...) the engine's relation and
  identity builders consume. Nothing here ships: the shipped fixture baseline is src/hydralysis/profiles/baseline_fixtures.toml.
* `capture()` runs a fixture under the real Frida recorder and returns its events (TRACE-1 envelopes, ready to import).
* `Engine` is a private real daemon (own data root) and the `trace` tool in front of it.
"""

from __future__ import annotations

import json
import os
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))
sys.path.insert(0, str(HERE.parent / "src"))

import trace_fixtures as tf  # noqa: E402
from support import workdir  # noqa: E402

ENGINE = os.environ.get("HYDRALYSIS_INTEGRATION_ENGINE") or os.environ.get("RUSTICRE_INTEGRATION_ENGINE")
CLIENT = os.environ.get("HYDRALYSIS_INTEGRATION_CLIENT") or os.environ.get("RUSTICRE_INTEGRATION_CLIENT")
TOOL = os.environ.get("HYDRA_TRACE_EXE", "")
HAVE_ENGINE = bool(ENGINE and CLIENT and TOOL and Path(TOOL).is_file())
try:
    import frida  # noqa: F401
    HAVE_LIVE = os.name == "nt" and tf.msvc_available()
except ImportError:
    HAVE_LIVE = False

_BUILT: dict = {}


def fixtures_dir() -> Path:
    """The x64 build directory of every trace fixture (built once per process, or reused from HYDRA_TRACE_FX)."""
    if "dir" not in _BUILT:
        import build_fixtures
        persistent = os.environ.get("HYDRA_TRACE_FX")
        root = Path(persistent) if persistent else Path(workdir("trace-gate-fx").name)
        for group in build_fixtures.TRACE_GROUPS:
            tf.build_group(group, root, ("x64",))
        _BUILT["dir"] = root / "x64"
    return _BUILT["dir"]


# ---- profiles ------------------------------------------------------------------------------------------------------------
def _toml_value(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, (list, tuple)):
        return "[" + ", ".join(_toml_value(v) for v in value) + "]"
    if isinstance(value, dict):
        return "{ " + ", ".join("%s = %s" % (k, _toml_value(v)) for k, v in value.items()) + " }"
    raise TypeError(value)


class GateProfile:
    """A fixtures-only profile built from hook dicts: {id, event, module, symbol, nargs, capture, ...}."""

    def __init__(self, fx: Path, profile_id: str, modules: list[str], hooks: list[dict], *, kinds: list[str] | None = None,
                 extra: str = ""):
        self.fx = Path(fx)
        self.id = profile_id
        self.modules = list(dict.fromkeys(list(modules) + [h["module"] for h in hooks]))
        self.hooks = hooks
        self.kinds = kinds or sorted({h["event"] for h in hooks if not h["event"].startswith("core.")})
        self.extra = extra

    def image(self, module: str):
        from hydralysis.pe import Image
        local = self.fx / module
        return Image(local if local.is_file() else Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32" / module)

    def prologue(self, module: str, symbol: str, size: int = 12) -> str:
        from hydralysis.profiles.verify import _export_rva, _map_rva
        image = self.image(module)
        rva = _map_rva(image, symbol)
        if rva is None:
            rva = _export_rva(image, symbol, True)
        if rva is None:
            raise KeyError("%s is not in the map of %s" % (symbol, module))
        return " ".join("%02X" % b for b in image.read_rva(rva, size))

    def text(self) -> str:
        out = ["[profile]", 'id = %s' % json.dumps(self.id), 'domain = "app"', 'description = "gate test profile"', "",
               "[target]", "bitness = 64", "modules = %s" % _toml_value(self.modules), "fixtures_only = true", "",
               "[host]", 'os = "windows-x64"', 'fault_policy = "tolerant"', "record_handler_chain = true", ""]
        for kind in self.kinds:
            base = "core.marker"
            out += ["[[event_kinds]]", "name = %s" % json.dumps(kind), "extends = %s" % json.dumps(base),
                    'description = "gate event"', "[event_kinds.payload]", "op = \"u64\"", ""]
        for hook in self.hooks:
            row = dict(hook)
            symbol = row["symbol"]
            row.setdefault("required", True)
            row["prologue"] = [self.prologue(row["module"], symbol, row.pop("prologue_bytes", 12))]
            out.append("[[hooks]]")
            for key, value in row.items():
                out.append("%s = %s" % (key, _toml_value(value)))
            out.append("")
        out.append(self.extra)
        return "\n".join(out)

    def load(self, directory: Path):
        from hydralysis import profiles
        path = Path(directory) / (self.id.replace("/", "_") + ".toml")
        path.write_text(self.text(), encoding="utf-8")
        return profiles.load_file(path)

    def specs(self, directory: Path, exe_names: list[str] | None = None) -> list[dict]:
        from hydralysis import profiles
        profile = self.load(directory)
        names = exe_names or self.modules
        images = {name: self.image(name) for name in names}
        verification = profiles.verify_profile(profile, images)
        profiles.require(verification)
        return [s for s in profiles.probe_specs(profile, verification) if s["module"] in names]


# ---- live capture --------------------------------------------------------------------------------------------------------
class Captured:
    def __init__(self, live, stopped, events):
        self.live, self.stopped, self.events = live, stopped, events
        self.health = stopped["trace"]["health"]

    def lines(self) -> list[dict]:
        """Events in the form `trace_append` takes."""
        from hydralysis import trace_capture as tc
        lines, _omitted = tc.export_jsonl(self.live.segment, self.live.segment_id, for_import=True)
        return [json.loads(line) for line in lines]


def capture(runs: Path, exe: str, args: list[str], specs: list[dict], *, linger_ms: int = 600, env: dict | None = None,
            cwd: str | None = None, wait: float = 90.0, **trace) -> Captured:
    """Spawn EXE paused under the recorder, arm SPECS, resume, wait for exit, stop. Returns the events read back."""
    import trace_live
    from hydralysis import trace_capture as tc
    live = trace_live.Live(Path(runs), fixtures_dir() / exe, args, linger_ms=linger_ms, env=env, cwd=cwd)
    try:
        live.start(specs, **trace)
        live.resume()
        if not live.wait_exit(wait):
            raise AssertionError("%s did not exit" % exe)
        time.sleep(0.3)
        stopped = live.stop()
        events = tc.read_events(live.segment, live.segment_id)
        return Captured(live, stopped, events)
    finally:
        live.close()


# ---- the real engine -----------------------------------------------------------------------------------------------------
class Engine:
    """A private daemon (own data root) and the `trace` tool in front of it."""

    def __init__(self, tag: str = "gate"):
        from unittest.mock import patch
        from hydralysis import hydra
        self.work = workdir("trace-" + tag)
        self.root = Path(self.work.name)
        self.settings = {"root": str(self.root / "data"), "hydra_dir": ENGINE, "hydra_client": CLIENT, "hydra_idle_s": 600}
        if os.environ.get("HYDRALYSIS_INTEGRATION_UNPINNED"):
            self.settings["hydra_allow_unpinned"] = True
        self.env = patch.dict(os.environ, {"HYDRALYSIS_ROOT": self.settings["root"]})
        self.env.start()
        self.patch = patch("hydralysis.api._settings", return_value=self.settings)
        self.patch.start()
        self.hydra = hydra
        self.engine = hydra.Engine(self.settings)
        self.caps: dict[str, str] = {}

    def close(self):
        try:
            try:
                self.engine.stop(force=True)
            finally:
                daemon = self.engine.module().Daemon(str(self.engine.engine_dir), str(self.hydra.state_dir(self.settings)),
                                                     self.hydra.INSTANCE)
                if daemon.jvm_alive() or daemon.read_endpoint():
                    daemon.kill()
        finally:
            self.patch.stop()
            self.env.stop()
            self.work.cleanup()

    # the same entry point as the MCP tool
    def tool(self, action: str, session: str | None = None, **options) -> dict:
        from hydralysis import api
        args = {"action": action, "options": options}
        if session is not None:
            args["session"] = session
        return json.loads(api.call("trace", args))

    def client(self):
        from hydralysis import trace
        return trace.TraceClient(trace._engine(self.settings))

    def open(self, session: str, **options) -> dict:
        started = self.tool("start", session, **options)
        if "error" in started:
            raise AssertionError(started)
        self.caps[session] = started["cap"]
        return started

    def append(self, session: str, events: list[dict], batch: int = 200) -> int:
        client = self.client()
        total = 0
        for start in range(0, len(events), batch):
            reply = client.append(session, events[start:start + batch], cap=self.caps[session])
            if reply.get("rejected"):
                raise AssertionError(reply["rejected"][:3])
            total += int(reply["accepted"])
        return total

    def load(self, session: str, events: list[dict], *, close: bool = False, **options) -> dict:
        """Open SESSION, append EVENTS, optionally close the writer."""
        opened = self.open(session, **options)
        self.append(session, events)
        if close:
            self.client().close(session, cap=self.caps[session])
        return opened

    def rows(self, session: str, **options) -> list[dict]:
        """Every row of a query (raw engine rows, paged on one snapshot)."""
        client, out, after, up_to = self.client(), [], None, None
        while True:
            reply = client.query(session, limit=1000, after=after, up_to=up_to, **options)
            for row in reply.get("rows") or []:
                if isinstance(row.get("payload"), str):
                    row["p"] = json.loads(row["payload"])
                out.append(row)
            after, up_to = reply.get("next"), reply.get("up_to")
            if not after:
                return out

    def prepare(self, exe: Path, target: str, timeout: float = 600) -> dict:
        """Import and analyse EXE in the engine so a trace can symbolize against it."""
        from hydralysis import preparation
        job = preparation.prepare(self.settings, str(exe), target)
        deadline = time.monotonic() + timeout
        while True:
            status = preparation.status(self.settings, job["job_id"])
            if status["state"] not in preparation.ACTIVE:
                return status
            if time.monotonic() > deadline:
                raise AssertionError("prepare %s still %s" % (target, status["state"]))
            time.sleep(0.5)


def unique(prefix: str) -> str:
    return "%s_%s" % (prefix, uuid.uuid4().hex[:8])
