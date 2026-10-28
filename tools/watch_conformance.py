"""Hardware-watchpoint conformance on the verification fixtures (Z12), per architecture.

usage: python tools/watch_conformance.py <fixtures out dir> [--arch x64|x86|both] [--iterations 100]

<fixtures out dir> is build_fixtures.py's output (manifest.json). HYDRALYSIS_CONFIG / HYDRALYSIS_ROOT select the
runtime backend (`runtime setup` done). Per architecture it runs, against a real fixture process only:

  1. the proof: a watch on g_watched is hit, then disarmed; the debug registers of every thread read back clear;
  2. a compare-and-swap write on g_config.mode, its undo, and an undo that reports DIVERGED;
  3. the teardown race loop (`--iterations`, at least 100): attach, arm, a random delay, then a disarm / a detach while
     armed / an immediate disarm, in rotation, against the fixture's second thread that stores the watched variable
     about every millisecond; after the detach the fixture must still be running, and when stopped it must exit 0,
     never 0x80000004 (STATUS_SINGLE_STEP: a debug register outlived its handler).

A passing architecture gets its stamp in <root>/watch-stamps/<arch>.json; the runtime's `watch arm` refuses without
the stamp for the target's architecture, the fixture build and the pinned Frida. The exit status is 0 only when every
architecture asked for passed; 2 when the backend or the fixtures are not there (nothing is stamped then).
Never run against anything but the fixtures: write and watch also refuse any build not listed in the setting
`runtime_fixture_sha256`, which this tool adds for the fixture it built and nothing else.
"""

from __future__ import annotations

import json
import random
import subprocess
import sys
import time
from pathlib import Path

ARCHES = ("x64", "x86")
MIN_ITERATIONS = 100
STATUS_SINGLE_STEP = 0x80000004
STAMP_VERSION = 1


def exit_code_verdict(code) -> str:
    """'' for a clean exit; otherwise what the exit code means."""
    if code == 0:
        return ""
    value = code & 0xFFFFFFFF if isinstance(code, int) else code
    if value == STATUS_SINGLE_STEP:
        return "exit 0x80000004 (STATUS_SINGLE_STEP: a debug register outlived its handler)"
    return "exit %s" % (hex(value) if isinstance(value, int) and value > 255 else value)


def make_stamp(arch: str, fixture_sha256: str, frida: str, iterations: int, failures: list) -> dict:
    passed = not failures and iterations >= MIN_ITERATIONS
    return {"version": STAMP_VERSION, "result": "pass" if passed else "fail", "arch": arch,
            "fixture_sha256": fixture_sha256, "frida": frida, "iterations": iterations,
            "failures": failures[:20], "at": time.strftime("%Y-%m-%dT%H:%M:%S")}


def exit_status(stamps: dict, wanted=ARCHES) -> int:
    """0 only when every wanted architecture has a passing stamp."""
    return 0 if all((stamps.get(arch) or {}).get("result") == "pass" for arch in wanted) else 1


class Fixture:
    """A fixture process this tool started (so it owns the exit code) under a runtime session."""

    def __init__(self, runner, build: dict):
        self.runner, self.build = runner, build
        self.stop = Path(build["path"]).with_suffix(".conf.stop")
        self.stop.unlink(missing_ok=True)
        self.process = subprocess.Popen([build["path"], str(self.stop)], cwd=str(Path(build["path"]).parent),
                                        stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.detached = False
        started = runner.call("attach", {"exe": build["path"], "sha256": build["sha256"], "pid": self.process.pid})
        self.session, self.owner = started["session"], started["owner"]
        modules = self.call("modules", limit=50)["modules"]
        main = next(m for m in modules if m["name"].lower() == Path(build["path"]).name.lower())
        self.delta = int(main["base"], 16) - int(build["image_base"], 16)

    def live(self, name: str) -> str:
        return hex(int(self.build["globals"][name], 16) + self.delta)

    def call(self, action: str, **options):
        return self.runner.call(action, {"session": self.session, "owner": self.owner, **options})

    def detach(self, **options):
        result = self.call("detach", **options)
        self.detached = True
        return result

    def alive(self) -> bool:
        return self.process.poll() is None

    def finish(self) -> int:
        """Stop the fixture and return its exit code."""
        if not self.detached:
            try:
                self.detach(force_tainted=True)
            except Exception:
                pass
        self.stop.write_text("stop")
        try:
            return self.process.wait(timeout=15)
        except subprocess.TimeoutExpired:
            self.process.kill()
            return -1


def hits(fixture: Fixture, wait_s: float = 3.0) -> int:
    """Watch hits in the session's events, waiting up to wait_s for the first."""
    deadline, after, count = time.monotonic() + wait_s, 0, 0
    while True:
        status = fixture.call("status", limit=200, after=after)
        for event in status.get("events", []):
            payload = (event.get("message") or {}).get("payload") or {}
            count += payload.get("event") == "watch_hit"
        after = status.get("next_after", after)
        if count or time.monotonic() > deadline:
            return count
        time.sleep(0.1)


def proof(runner, build: dict) -> list[str]:
    """Steps 1 and 2: one watch round trip with readback, and write / undo / DIVERGED."""
    failures = []
    fixture = Fixture(runner, build)
    try:
        watch = fixture.call("watch", op="arm", address=fixture.live("g_watched"), size=4, access="write",
                             reason="conformance: watch the fixture's stored variable")["watch"]
        seen = hits(fixture)
        if not seen:
            failures.append("no watch hit in 3 s")
        done = fixture.call("watch", op="disarm", watch=watch["id"])
        verified = done["watch"].get("verified") or {}
        if done["state"] != "clear" or verified.get("still_enabled") or not verified.get("threads_read"):
            failures.append("disarm not verified clear: %s" % json.dumps(done)[:300])
        mode = fixture.live("g_config")
        first = fixture.call("write", address=mode, expect="02 00 00 00", bytes="07 00 00 00",
                             reason="conformance: change the fixture mode")["entry"]
        fixture.call("write", address=mode, expect="07 00 00 00", bytes="09 00 00 00", reason="conformance: change it again")
        diverged = fixture.call("write", op="undo", id=first["id"])
        if diverged.get("status") != "DIVERGED":
            failures.append("undo after a later write did not report DIVERGED: %s" % json.dumps(diverged)[:300])
        undone = fixture.call("write", op="undo")
        if not undone.get("undone"):
            failures.append("undo of the latest write failed: %s" % json.dumps(undone)[:300])
        try:
            fixture.call("write", address=hex(int(build["functions"]["fx_flow"], 16) + fixture.delta), expect="00", bytes="01",
                reason="conformance: must be refused in code")
            failures.append("a write into the code range was not refused")
        except ValueError as refusal:
            if "EXECUTABLE RANGE" not in str(refusal):
                failures.append("code-range write refused for another reason: %s" % str(refusal)[:200])
    except Exception as error:
        failures.append("proof: %s" % str(error)[:400])
    finally:
        code = fixture.finish()
        if exit_code_verdict(code):
            failures.append("proof: " + exit_code_verdict(code))
    return failures


def race_iteration(runner, build: dict, index: int) -> str:
    """One teardown race; '' when it passed, else why not."""
    fixture = Fixture(runner, build)
    why = ""
    try:
        fixture.call("watch", op="arm", address=fixture.live("g_watched"), size=4, access="write",
                     reason="conformance: race loop %d" % index)
        variant = index % 3
        if variant != 2:
            time.sleep(random.uniform(0.0, 0.03))
        watch = fixture.call("watch", op="list")["watches"][0]
        if variant == 1:
            result = fixture.detach()                      # the worker disarms and proves clear before it lets go
            if result.get("tainted"):
                why = "detach while armed left the session tainted"
        else:
            done = fixture.call("watch", op="disarm", watch=watch["id"])
            if done["state"] != "clear":
                why = "disarm not clear: %s %s" % (done.get("error"), json.dumps((done.get("watch") or {}).get("verified")))
            fixture.detach()
        time.sleep(0.25)                                   # the fixture stores the variable about every millisecond
        if not fixture.alive():
            why = why or "fixture died after the detach: %s" % exit_code_verdict(fixture.process.returncode)
    except Exception as error:
        why = why or "error: %s" % str(error)[:300]
    code = fixture.finish()
    if exit_code_verdict(code):
        why = why or exit_code_verdict(code)
    return "%s [fixture %s]" % (why, exit_code_verdict(code) or "exit 0") if why else why


def conform(runner, build: dict, arch: str, iterations: int) -> dict:
    failures = ["%s: %s" % (arch, f) for f in proof(runner, build)]
    done = 0
    for index in range(iterations):
        why = race_iteration(runner, build, index)
        done += 1
        if why:
            failures.append("%s iteration %d: %s" % (arch, index, why))
            print("FAIL", arch, "iteration", index, why, flush=True)
            if len(failures) >= 5:
                break
        elif index % 10 == 0:
            print("ok", arch, "iteration", index, flush=True)
    from hydralysis.runtime import FRIDA_VERSION
    return make_stamp(arch, build["sha256"], FRIDA_VERSION, done, failures)


def main(argv: list[str]) -> int:
    import argparse
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("fixtures")
    parser.add_argument("--arch", default="both", choices=("x64", "x86", "both"))
    parser.add_argument("--iterations", type=int, default=MIN_ITERATIONS)
    options = parser.parse_args(argv)
    from hydralysis import config, runtime
    manifest_path = Path(options.fixtures) / "manifest.json"
    if not manifest_path.is_file():
        print("no manifest.json in", options.fixtures, "(run tests/fixtures/build_fixtures.py)")
        return 2
    manifest = json.loads(manifest_path.read_text())
    wanted = ARCHES if options.arch == "both" else (options.arch,)
    settings = config.load()
    builds = {arch: manifest.get(arch + "/flow_fixture.exe") for arch in wanted}
    if not all(builds.values()):
        print("the manifest has no flow_fixture.exe for", [a for a, b in builds.items() if not b])
        return 2
    settings["runtime_fixture_sha256"] = sorted({b["sha256"] for b in builds.values()})
    settings["runtime_watch_conformance_run"] = True      # this run is what produces the stamp
    missing = runtime._missing(settings)
    if missing:
        print(missing)
        return 2
    runner = runtime.RuntimeRunner(settings)
    stamps = {}
    for arch in wanted:
        print("== conformance", arch, "iterations", options.iterations, flush=True)
        stamp = conform(runner, builds[arch], arch, options.iterations)
        stamps[arch] = stamp
        target = runtime._root(settings) / "watch-stamps" / (arch + ".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        runtime._write(target, stamp)
        print(arch, stamp["result"].upper(), "iterations", stamp["iterations"], "failures", len(stamp["failures"]))
        for failure in stamp["failures"]:
            print("  ", failure)
    status = exit_status(stamps, wanted)
    print("conformance", "PASS" if status == 0 else "FAIL", {a: s["result"] for a, s in stamps.items()})
    return status


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
