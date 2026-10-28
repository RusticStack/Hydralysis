"""Z5 (PROTOCOL-3.md section 8): the real-engine matrix for prepare and adopt.

Runs only against a real Hydra install, like tests/test_engine_integration.py (HYDRALYSIS_INTEGRATION_ENGINE and
HYDRALYSIS_INTEGRATION_CLIENT, optionally HYDRALYSIS_INTEGRATION_JAVA, HYDRALYSIS_INTEGRATION_UNPINNED for an engine that is
not the pinned release). Every class has its own data root and its own daemon, which it stops at the end.

Further variables, each gating only the classes that need it:

  HYDRALYSIS_INTEGRATION_FIXTURES  the build directory of tests/fixtures/build_fixtures.py (x64/, x86/, manifest.json).
  HYDRALYSIS_INTEGRATION_BINARY    a small PE (default: Windows' whoami.exe), the same as test_engine_integration.py.
  HYDRALYSIS_INTEGRATION_LEGACY    the folder of a Ghidra 12.1.4 project (examples/fixtures/legacy-12.1.4 of the engine
                                   repository on E2's branch). It is copied first and never opened in place.
  HYDRALYSIS_INTEGRATION_KOTOR_EXE / HYDRALYSIS_INTEGRATION_KOTOR_PROJECT
                                   a local game build and its analysed project. LOCAL EVIDENCE ONLY: both are copied to
                                   the test's own scratch before any engine sees them, and the test records counts,
                                   seconds and hashes, never a decompile or an export (nothing game-derived is stored).
  HYDRALYSIS_INTEGRATION_EVIDENCE  a folder where each class writes a small JSON of what it measured.

What "the daemon command log" means here. The engine (protocol 2/3) keeps no per-command log. The record is made on two
sides: every request this process sends goes through hydra.Engine.call or .send, and CommandLog records them there; the
daemon's own view is read back with `status` (`projects[].writable`, `programs[].mode`, `programs[].writer`, and
`imports.history.count`, the number of imports the daemon ever took). Together they say what was asked and what the engine
did. A request sent by another process (a prepare worker) is not in CommandLog; those tests use the daemon's view.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from support import workdir
from test_engine_integration import BINARY, CLIENT, ENGINE, _env, _release

FIXTURES = _env("INTEGRATION_FIXTURES")
LEGACY = _env("INTEGRATION_LEGACY")
KOTOR_EXE = _env("INTEGRATION_KOTOR_EXE")
KOTOR_PROJECT = _env("INTEGRATION_KOTOR_PROJECT")
EVIDENCE = _env("INTEGRATION_EVIDENCE")
JAVA_HOME = _env("INTEGRATION_JAVA")

HAVE_ENGINE = bool(ENGINE and CLIENT)
HAVE_BINARY = bool(HAVE_ENGINE and BINARY and Path(BINARY).is_file())
HAVE_FIXTURES = bool(HAVE_ENGINE and FIXTURES and (Path(FIXTURES) / "manifest.json").is_file())
HAVE_LEGACY = bool(HAVE_ENGINE and LEGACY and (Path(LEGACY) / "legacy.gpr").is_file())
HAVE_KOTOR = bool(HAVE_ENGINE and KOTOR_EXE and Path(KOTOR_EXE).is_file() and KOTOR_PROJECT
                  and (Path(KOTOR_PROJECT) / "kotor.gpr").is_file())

# What adopt may send. An adopt that sent one of the FORBIDDEN commands imported, analysed, forked or wrote something.
ALLOWED_FOR_ADOPT = {"open_project", "list", "open_program", "hello", "status", "ping", "projects", "programs", "info"}
FORBIDDEN_FOR_ADOPT = {"import", "analyze", "fork_project", "save", "rename", "edit", "comment", "discard_edits",
                       "promote_overlay", "script", "seal_project", "refresh", "reopen"}


def evidence(name: str, record: dict) -> None:
    """Counts, seconds and hashes only (nothing derived from a game): the local record of one measured run."""
    if EVIDENCE:
        folder = Path(EVIDENCE)
        folder.mkdir(parents=True, exist_ok=True)
        (folder / (name + ".json")).write_text(json.dumps(record, indent=1, sort_keys=True), encoding="utf-8")


def golden_tree_sha256(folder: Path) -> str:
    """The owner's tree hash of a project folder (the one recorded for the KotOR original): sha256 of the sorted
    `path<TAB>size<TAB>sha256` lines of every file. Not the same function as lineage.tree_hash (which skips locks)."""
    import hashlib
    rows = []
    for path in sorted(item for item in Path(folder).rglob("*") if item.is_file()):
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1 << 20), b""):
                digest.update(block)
        rows.append("%s\t%d\t%s" % (path.relative_to(folder).as_posix(), path.stat().st_size, digest.hexdigest()))
    return hashlib.sha256("\n".join(rows).encode()).hexdigest()


class CommandLog:
    """Records every request this process sends to the engine while it is active."""

    def __init__(self):
        self.entries: list[tuple[str, dict]] = []
        self._patches = []

    def __enter__(self):
        from hydralysis import hydra
        original_call, original_send = hydra.Engine.call, hydra.Engine.send
        log = self

        def call(engine, command, raw=False, **fields):
            log.entries.append((command, dict(fields)))
            return original_call(engine, command, raw=raw, **fields)

        def send(engine, command, **fields):
            log.entries.append((command, dict(fields)))
            return original_send(engine, command, **fields)

        self._patches = [patch.object(hydra.Engine, "call", call), patch.object(hydra.Engine, "send", send)]
        for item in self._patches:
            item.start()
        return self

    def __exit__(self, *exc):
        for item in reversed(self._patches):
            item.stop()

    def commands(self) -> list[str]:
        return [command for command, _ in self.entries]

    def writable_opens(self) -> list[tuple[str, dict]]:
        return [(command, fields) for command, fields in self.entries
                if command in ("open_project", "open_program") and fields.get("writable")]

    def forbidden(self, names=FORBIDDEN_FOR_ADOPT) -> list[str]:
        return [command for command in self.commands() if command in names]


def start_root(cls, label: str, hydra_options: dict | None = None) -> None:
    """A fresh data root, settings and environment patch on CLS (the daemon starts on the first request)."""
    from hydralysis import query
    cls.work = workdir(label)
    cls.root = Path(cls.work.name)
    cls.settings = {"root": str(cls.root / "data"), "hydra_dir": ENGINE, "hydra_client": CLIENT, "hydra_idle_s": 900}
    if _env("INTEGRATION_UNPINNED"):
        cls.settings["hydra_allow_unpinned"] = True
    if JAVA_HOME:
        cls.settings["java_home"] = JAVA_HOME
    if hydra_options:
        cls.settings["hydra"] = dict(hydra_options)
    query._keys.clear()
    cls.env = patch.dict(os.environ, {"HYDRALYSIS_ROOT": cls.settings["root"],
                                      "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")})
    cls.env.start()


def wait_job(settings: dict, job_id: str, timeout_s: float = 900, states=None) -> dict:
    """Poll a preparation job until it leaves ACTIVE (or STATES contains its state)."""
    from hydralysis import preparation
    deadline = time.monotonic() + timeout_s
    while True:
        status = preparation.status(settings, job_id)
        if (status["state"] in states) if states else (status["state"] not in preparation.ACTIVE):
            return status
        if time.monotonic() > deadline:
            raise AssertionError("job %s still %s after %s s: %s" % (job_id, status["state"], timeout_s,
                                                                    json.dumps(status)[:2000]))
        time.sleep(0.5)


def daemon_status(settings: dict) -> dict:
    """The daemon's own status, joined without starting one."""
    from hydralysis import hydra
    return hydra.Engine(settings, start=False).call("status")


def daemon_programs(settings: dict) -> list:
    """The daemon's `programs` listing: mode, writer, unsaved edits, sha256 of every program it holds."""
    from hydralysis import hydra
    return hydra.Engine(settings, start=False).call("programs").get("programs") or []


def daemon_alive(settings: dict) -> bool:
    from hydralysis import hydra
    try:
        return bool(hydra.Engine(settings, start=False).call("ping").get("pong"))
    except Exception:  # noqa: BLE001 - any failure to reach the daemon is "not alive"
        return False


def gate(settings: dict) -> dict:
    return daemon_status(settings)["imports"]


def import_count(settings: dict) -> int:
    return int(gate(settings).get("history", {}).get("count", 0))


def read_only_everywhere(case: unittest.TestCase, settings: dict) -> dict:
    """The daemon's view: no project is open writable and no program has a writer."""
    status = daemon_status(settings)
    projects = status.get("projects") or []
    programs = daemon_programs(settings)
    case.assertTrue(programs, "the daemon holds no program: nothing was opened")
    for project in projects:
        case.assertFalse(project.get("writable"), project)
    for program in programs:
        case.assertEqual(program.get("mode"), "read_only", program)
        case.assertFalse(program.get("writer"), program)
        case.assertEqual(program.get("unsavedEdits"), 0, program)
    return {"projects": projects, "programs": programs}


def registry_names(settings: dict) -> set:
    from hydralysis import targets
    return set(targets.registry(settings))


# ---- 0. found by the matrix below: workers that start together must not fail each other ------------------------------


class BackendEnsureRace(unittest.TestCase):
    """The matrix started nine prepare workers at once and one failed with `backend setup is already running`: ensure()
    took .backend.lock without waiting, even when the engine was already installed and nothing needed setting up. Several
    agents preparing at the same time must not fail each other (owner objective). No engine is needed: the report is faked
    ready and the write that follows the lock is slowed so the workers overlap."""

    def test_workers_that_overlap_on_a_ready_backend_all_succeed(self):
        from hydralysis import backends
        work = workdir("ensure-race")
        self.addCleanup(work.cleanup)
        root = Path(work.name)
        report = {"root": str(root), "ready": True, "engine": {"path": "e"}, "client": {"path": "c"}, "jdk": {"path": "j"}}
        original_write = backends.write_json

        def slow_write(path, value):
            time.sleep(0.4)
            original_write(path, value)

        outcomes, lock = [], threading.Lock()

        def worker():
            try:
                backends.ensure({"root": str(root)})
                result = "ok"
            except Exception as exc:  # noqa: BLE001 - the outcome is the assertion
                result = "%s: %s" % (type(exc).__name__, exc)
            with lock:
                outcomes.append(result)

        with patch.object(backends, "inspect", lambda settings: dict(report)), \
                patch.object(backends, "write_json", slow_write):
            threads = [threading.Thread(target=worker) for _ in range(6)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(60)
        self.assertEqual(outcomes, ["ok"] * 6, outcomes)

    def test_a_worker_that_waits_for_an_installer_sees_the_finished_install(self):
        from hydralysis import backends
        from hydralysis.locks import LaneLock
        work = workdir("ensure-wait")
        self.addCleanup(work.cleanup)
        root = Path(work.name)
        ready = {"root": str(root), "ready": True, "engine": {"path": "e"}, "client": {"path": "c"}, "jdk": {"path": "j"}}
        missing = {"root": str(root), "ready": False, "engine": None, "client": None, "jdk": None}
        state = {"installed": False}
        holder = LaneLock(str(root / ".backend.lock"))
        self.assertTrue(holder.acquire())

        def finish_install():
            time.sleep(0.5)
            state["installed"] = True
            holder.release()

        installer = threading.Thread(target=finish_install)
        installer.start()
        try:
            # without install=True a worker that found nothing would fail; it must re-read once the installer is done
            with patch.object(backends, "inspect", lambda settings: dict(ready if state["installed"] else missing)):
                result = backends.ensure({"root": str(root)})
        finally:
            installer.join(10)
        self.assertEqual(result["hydra_dir"], "e")


# ---- 1. whoami and the eight MSVC fixtures, imported two at a time -----------------------------------------------


def _fixture_set() -> list[tuple[str, Path, dict | None]]:
    """(target, exe, manifest entry) for whoami and the eight fixtures."""
    rows = [("who", Path(BINARY), None)]
    manifest = json.loads((Path(FIXTURES) / "manifest.json").read_text(encoding="utf-8"))
    for key in sorted(manifest):
        entry = manifest[key]
        arch, exe = key.split("/")
        path = Path(FIXTURES) / arch / exe
        rows.append(("fx-%s-%s" % (arch, exe.replace(".exe", "").replace("_", "")), path, entry))
    return rows


@unittest.skipUnless(HAVE_BINARY and HAVE_FIXTURES, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT/FIXTURES")
class PrepareMatrix(unittest.TestCase):
    """whoami plus the 8 MSVC fixtures (x64 and x86 of flow, vcall, diff1, diff2), all started together against a
    daemon whose maxImports is 2: the import gate must hold the other seven back, every job must finish, and each
    prepared build must answer a first query."""

    MAX_IMPORTS = 2

    @classmethod
    def setUpClass(cls):
        from hydralysis import preparation, query
        start_root(cls, "prep-matrix", {"maxImports": cls.MAX_IMPORTS})
        cls.rows = _fixture_set()
        cls.samples: list[tuple[int, int]] = []
        cls.started = time.monotonic()
        cls.jobs = {}
        for target, exe, _ in cls.rows:
            cls.jobs[target] = preparation.prepare(cls.settings, str(exe), target)["job_id"]
        stop = threading.Event()

        def sample():
            while not stop.is_set():
                try:
                    now = gate(cls.settings)
                    cls.samples.append((len(now.get("running") or []), len(now.get("queue") or [])))
                except Exception:  # noqa: BLE001 - the daemon may not be up yet
                    pass
                stop.wait(0.4)

        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        try:
            cls.results = {target: wait_job(cls.settings, job_id, 1500) for target, job_id in cls.jobs.items()}
        finally:
            stop.set()
            sampler.join(10)
        cls.wall_s = round(time.monotonic() - cls.started, 1)
        cls.runner = query.QueryRunner(cls.settings)

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def test_every_job_finishes_and_names_its_build(self):
        for target, exe, entry in self.rows:
            with self.subTest(target=target):
                result = self.results[target]
                self.assertEqual(result["state"], "done", result)
                self.assertTrue(result["verification"]["analyzed"])
                self.assertGreater(result["verification"]["functions"], 0)
                if entry:
                    self.assertEqual(result["sha256"], entry["sha256"])
        self.assertEqual(registry_names(self.settings), {target for target, _, _ in self.rows})

    def test_the_import_gate_held_the_others_back(self):
        self.assertGreater(len(self.samples), 5, "the sampler saw too few points: %s" % self.samples)
        running = [r for r, _ in self.samples]
        queued = [q for _, q in self.samples]
        self.assertLessEqual(max(running), self.MAX_IMPORTS, "more imports ran than maxImports allows")
        self.assertEqual(max(running), self.MAX_IMPORTS, "the gate never ran two at once: %s" % self.samples)
        self.assertGreater(max(queued), 0, "nothing ever waited at the gate: %s" % self.samples)
        status = gate(self.settings)
        self.assertEqual(status["maxImports"], self.MAX_IMPORTS)
        self.assertEqual(status["history"]["count"], len(self.rows), "the daemon took one import per build")
        self.assertEqual((status["running"], status["queue"]), ([], []))
        evidence("prepare-matrix", {
            "binaries": len(self.rows), "maxImports": self.MAX_IMPORTS, "wall_s": self.wall_s,
            "max_running": max(running), "max_queued": max(queued), "samples": len(self.samples),
            "jobs": {target: {"functions": self.results[target]["verification"]["functions"],
                              "import_s": self.results[target].get("import_seconds"),
                              "analysis_s": (self.results[target].get("analysis") or {}).get("seconds"),
                              "sha256": self.results[target]["sha256"]} for target, _, _ in self.rows}})

    def test_each_prepared_build_answers_a_first_query(self):
        for target, _, entry in self.rows:
            with self.subTest(target=target):
                if entry:
                    address = sorted(entry["functions"].values())[0]
                else:
                    address = json.loads(self.runner.query(target, "functions", "", limit=5))["functions"][0]["address"]
                answer = json.loads(self.runner.query(target, "decompile", address))
                self.assertTrue(answer["ok"], answer)
                self.assertTrue(answer.get("c"))


# ---- 2. cancel and a killed worker -------------------------------------------------------------------------------


def _slow_exe() -> Path:
    """A build whose import and analysis last long enough to be interrupted (about 30 s on this machine)."""
    return Path(FIXTURES) / "x64" / "diff1.exe"


class _Interrupt(unittest.TestCase):
    """Shared steps of the two interruption classes: run a prepare to the middle of the import, interrupt it, and check
    that nothing is registered, the gate drains, the daemon survives and the build can be prepared again."""

    TARGET = "interrupted"

    @classmethod
    def setUpClass(cls):
        start_root(cls, "prep-interrupt")

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def mid_import(self) -> dict:
        """Start the prepare and wait until the daemon is running its import."""
        from hydralysis import preparation
        job = preparation.prepare(self.settings, str(_slow_exe()), self.TARGET)
        deadline = time.monotonic() + 300
        while time.monotonic() < deadline:
            status = preparation.status(self.settings, job["job_id"])
            self.assertNotIn(status["state"], ("done", "failed", "blocked"), status)
            if status.get("engine_request"):
                try:
                    if gate(self.settings)["running"]:
                        return {**status, "owner_token": job["owner_token"]}
                except Exception:  # noqa: BLE001 - the daemon is still starting
                    pass
            time.sleep(0.3)
        self.fail("the import never started: %s" % json.dumps(preparation.status(self.settings, job["job_id"]))[:1500])

    def drained(self, timeout_s: float = 60) -> dict:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            now = gate(self.settings)
            if not now["running"] and not now["queue"]:
                return now
            time.sleep(0.5)
        self.fail("the import gate did not drain: %s" % json.dumps(gate(self.settings))[:1500])

    def assert_nothing_registered(self, job: dict) -> None:
        from hydralysis import hydra
        self.assertEqual(registry_names(self.settings), set())
        self.assertEqual([program for program in daemon_programs(self.settings)
                          if str(program.get("sha256", "")).lower() == job["sha256"]], [],
                         "the daemon still holds the interrupted program")
        # The project the job made holds no program: opened read-only, listed, and closed again.
        gpr = Path(job["project_dir"]) / "project" / "analysis.gpr"
        if gpr.is_file():
            engine = hydra.Engine(self.settings)
            opened = engine.call("open_project", path=str(gpr))
            try:
                listing = engine.call("list", project=opened["id"], programsOnly=True, limit=50)
                self.assertEqual([entry for entry in listing.get("entries", []) if entry.get("program")], [])
            finally:
                engine.call("close_project", project=opened["id"])

    def prepare_again(self, first_job: str) -> dict:
        from hydralysis import preparation
        again = preparation.prepare(self.settings, str(_slow_exe()), self.TARGET)
        self.assertNotEqual(again["job_id"], first_job, "the interrupted job must not be reused")
        self.assertFalse(again.get("reused"), again)
        result = wait_job(self.settings, again["job_id"], 900)
        self.assertEqual(result["state"], "done", result)
        self.assertEqual(registry_names(self.settings), {self.TARGET})
        return result


@unittest.skipUnless(HAVE_FIXTURES, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT/FIXTURES")
class CancelMidImport(_Interrupt):
    def test_cancel_mid_import_registers_no_program_and_no_target(self):
        from hydralysis import preparation
        job = self.mid_import()
        preparation.cancel(self.settings, job["job_id"], owner=job["owner_token"])
        result = wait_job(self.settings, job["job_id"], 180)
        self.assertEqual(result["state"], "cancelled", result)
        self.drained()
        self.assert_nothing_registered(job)
        self.assertTrue(daemon_alive(self.settings))
        again = self.prepare_again(job["job_id"])
        evidence("prepare-cancel", {"cancelled_state": result["state"], "re_prepare_state": again["state"],
                                    "functions": again["verification"]["functions"]})


@unittest.skipUnless(HAVE_FIXTURES, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT/FIXTURES")
class KilledWorker(_Interrupt):
    def test_a_killed_worker_leaves_no_program_no_target_and_a_live_daemon(self):
        job = self.mid_import()
        pid = int(job["worker_pid"])
        os.kill(pid, signal.SIGTERM)  # on Windows this is TerminateProcess: the worker gets no chance to clean up
        result = wait_job(self.settings, job["job_id"], 120)
        self.assertEqual(result["state"], "interrupted", result)
        self.assertIn("worker exited", result["error"])
        self.drained()
        self.assertTrue(daemon_alive(self.settings), "the daemon must survive a client that died mid-import")
        self.assert_nothing_registered(job)
        again = self.prepare_again(job["job_id"])
        evidence("prepare-killed-worker", {"state_after_kill": result["state"], "re_prepare_state": again["state"],
                                           "functions": again["verification"]["functions"]})


# ---- 3. adopt, measured ------------------------------------------------------------------------------------------


@unittest.skipUnless(HAVE_BINARY, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")
class AdoptMeasured(unittest.TestCase):
    """adopt of an analysed project, measured instead of echoed: the project's tree hash before and after, the
    commands this process sent, and what the daemon reports about the project and the program afterwards."""

    @classmethod
    def setUpClass(cls):
        from hydralysis import preparation, query
        start_root(cls, "adopt-measured")
        shutil.copy2(BINARY, cls.root / "fixture.exe")
        job = preparation.prepare(cls.settings, str(cls.root / "fixture.exe"), "prepared")
        cls.prepared = wait_job(cls.settings, job["job_id"], 900)
        if cls.prepared["state"] != "done":
            raise AssertionError("prepare did not finish: %s" % json.dumps(cls.prepared)[:3000])
        cls.folder = Path(cls.prepared["project"]["gpr"]).parent
        cls.sha = cls.prepared["sha256"]
        cls.runner = query.QueryRunner(cls.settings)

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def adopt(self, path, **kwargs):
        from hydralysis import preparation
        return preparation.adopt(self.settings, str(path), **kwargs)

    def test_adopt_leaves_the_tree_and_the_daemon_untouched(self):
        from hydralysis import lineage
        before = lineage.tree_hash(self.folder)
        imports_before = import_count(self.settings)
        with CommandLog() as log:
            result = self.adopt(self.folder, sha256_value=self.sha, target="adopted")
        self.assertTrue(result["registered"], result)
        self.assertEqual((result["copied"], result["imported"], result["written"]), (False, False, False), result)
        self.assertEqual(lineage.tree_hash(self.folder), before, "adopt changed the project's tree")
        self.assertEqual(log.forbidden(), [], "adopt sent %s" % log.commands())
        self.assertEqual(set(log.commands()) - ALLOWED_FOR_ADOPT, set(), log.commands())
        self.assertEqual(log.writable_opens(), [])
        self.assertIn("open_program", log.commands())
        read_only_everywhere(self, self.settings)
        self.assertEqual(import_count(self.settings), imports_before, "the daemon took an import during adopt")
        # and the adopted target answers, still without changing the tree
        listed = json.loads(self.runner.query("adopted", "functions", "", limit=3))
        self.assertTrue(listed["functions"])
        self.assertEqual(lineage.tree_hash(self.folder), before)
        evidence("adopt-measured", {"tree_sha256": before, "commands": log.commands(), "functions": result["functions"],
                                    "imports_before": imports_before, "imports_after": import_count(self.settings)})

    def test_a_wrong_build_hash_registers_nothing_and_writes_nothing(self):
        from hydralysis import lineage
        before = lineage.tree_hash(self.folder)
        with CommandLog() as log:
            result = self.adopt(self.folder, sha256_value="0" * 64, target="wrong")
        self.assertFalse(result["registered"], result)
        self.assertEqual(result["state"], "no_match")
        self.assertNotIn("wrong", registry_names(self.settings))
        self.assertEqual(log.forbidden(), [])
        self.assertEqual(lineage.tree_hash(self.folder), before)

    def test_the_measurement_can_see_a_writable_open(self):
        """Negative control on a COPY: the same instruments must flag a writable open, or the zeros above prove nothing."""
        from hydralysis import hydra, lineage
        copy = self.root / "control-copy"
        shutil.copytree(self.folder, copy)
        before = lineage.tree_hash(copy)
        gpr = next(copy.glob("*.gpr"))
        with CommandLog() as log:
            engine = hydra.Engine(self.settings)
            opened = engine.call("open_project", path=str(gpr), writable=True)
            try:
                listing = engine.call("list", project=opened["id"], programsOnly=True, limit=5)
                entry = next(item for item in listing["entries"] if item.get("program"))
                engine.call("open_program", path=entry["path"], project=opened["id"], writable=True)
                writable = [program for program in daemon_programs(self.settings)
                            if program.get("project") == opened["id"]]
                engine.call("close_program", program=writable[0]["key"])
            finally:
                engine.call("close_project", project=opened["id"])
        self.assertEqual(len(log.writable_opens()), 2, log.entries)
        self.assertTrue(any(program.get("mode") != "read_only" or program.get("writer") for program in writable), writable)
        evidence("adopt-control", {"tree_changed_by_a_writable_open": lineage.tree_hash(copy) != before})


@unittest.skipUnless(HAVE_LEGACY and HAVE_FIXTURES, "set HYDRALYSIS_INTEGRATION_LEGACY (and the other variables)")
class LegacyAdopt(unittest.TestCase):
    """A Ghidra 12.1.4 project (database version 32) made from the public flow fixture. It holds a program that was
    imported but never analysed, so adopt must refuse it, read-only and without touching the folder, and the engine must
    still read it."""

    @classmethod
    def setUpClass(cls):
        start_root(cls, "adopt-legacy")
        cls.folder = cls.root / "legacy-12.1.4"
        shutil.copytree(LEGACY, cls.folder)
        cls.sha = json.loads((Path(FIXTURES) / "manifest.json").read_text(encoding="utf-8"))["x64/flow_fixture.exe"]["sha256"]

    @classmethod
    def tearDownClass(cls):
        _release(cls)

    def test_a_12_1_4_project_is_read_but_not_adopted_and_stays_byte_identical(self):
        from hydralysis import hydra, lineage, preparation
        before = lineage.tree_hash(self.folder)
        with CommandLog() as log:
            with self.assertRaises(ValueError) as caught:
                preparation.adopt(self.settings, str(self.folder), sha256_value=self.sha, target="legacy")
        self.assertIn("not analysed", str(caught.exception))
        self.assertEqual(registry_names(self.settings), set())
        self.assertEqual(log.forbidden(), [])
        self.assertEqual(log.writable_opens(), [])
        self.assertEqual(lineage.tree_hash(self.folder), before)
        status = read_only_everywhere(self, self.settings)
        program = status["programs"][0]
        self.assertEqual(program["sha256"], self.sha)
        self.assertFalse(program["analyzed"])
        # the engine reads the old database without upgrading the folder
        functions = hydra.Engine(self.settings).call("functions", program=program["key"], limit=5)
        self.assertTrue(functions["functions"])
        self.assertEqual(lineage.tree_hash(self.folder), before)
        # the engine builds its upgrade cache in its own state folder: wait for it, then the project is still unchanged
        deadline = time.monotonic() + 240
        final = program
        while time.monotonic() < deadline:
            final = next(item for item in daemon_programs(self.settings) if item["key"] == program["key"])
            if final.get("cacheBuild") not in ("building", "queued", "pending"):
                break
            time.sleep(2)
        self.assertEqual(lineage.tree_hash(self.folder), before, "the upgrade cache build changed the project folder")
        evidence("adopt-legacy-12.1.4", {"tree_sha256": before, "refused": str(caught.exception)[:160],
                                         "functions": program["functions"], "analyzed": program["analyzed"],
                                         "cacheBuild_at_adopt": program.get("cacheBuild"),
                                         "cacheBuild_final": final.get("cacheBuild"),
                                         "cachedUpgrade_final": final.get("cachedUpgrade")})


# ---- 4. a local KotOR run, on copies ---------------------------------------------------------------------------


@unittest.skipUnless(HAVE_KOTOR, "set HYDRALYSIS_INTEGRATION_KOTOR_EXE/KOTOR_PROJECT (local evidence)")
class KotorLocal(unittest.TestCase):
    """LOCAL EVIDENCE: a fresh prepare of the 32-bit game build and an adopt of its analysed project, both on copies.
    The original project is only read (hashed) and never opened by an engine; nothing derived from the game is kept."""

    @classmethod
    def setUpClass(cls):
        start_root(cls, "kotor-local")
        cls.original = Path(KOTOR_PROJECT)
        cls.source_hash_before = golden_tree_sha256(cls.original)
        cls.exe = cls.root / "kotor-copy.exe"
        shutil.copy2(KOTOR_EXE, cls.exe)
        cls.project = cls.root / "kotor-project-copy"
        shutil.copytree(cls.original, cls.project)

    @classmethod
    def tearDownClass(cls):
        try:
            _release(cls)
        finally:
            after = golden_tree_sha256(cls.original)
            evidence("kotor-source-unchanged", {"before": cls.source_hash_before, "after": after,
                                                "unchanged": after == cls.source_hash_before})

    def test_a_fresh_prepare_on_a_copy_records_seconds_functions_and_the_first_query(self):
        from hydralysis import preparation, query
        started = time.monotonic()
        job = preparation.prepare(self.settings, str(self.exe), "kotor-fresh", timeout_s=3600)
        result = wait_job(self.settings, job["job_id"], 3600)
        wall = round(time.monotonic() - started, 1)
        self.assertEqual(result["state"], "done", result)
        runner = query.QueryRunner(self.settings)
        first = time.monotonic()
        listed = json.loads(runner.query("kotor-fresh", "functions", "", limit=5))
        address = listed["functions"][0]["address"]
        answer = json.loads(runner.query("kotor-fresh", "decompile", address))
        first_s = round(time.monotonic() - first, 2)
        self.assertTrue(answer["ok"], "first decompile failed")
        evidence("kotor-fresh-prepare", {
            "exe_sha256": result["sha256"], "wall_s": wall, "import_s": result.get("import_seconds"),
            "analysis_s": (result.get("analysis") or {}).get("seconds"), "functions": result["verification"]["functions"],
            "first_query_s": first_s})
        self.assertGreater(result["verification"]["functions"], 1000)

    def test_adopt_of_the_analysed_project_copy_changes_nothing_and_matches_the_build(self):
        from hydralysis import lineage, preparation
        self.assertEqual(self.source_hash_before, "6d8ced789b9f0945ee2ade42e75cf6db0a92c97ea4e65b8a353fd624860240df",
                         "the original is not the one the owner hashed")
        self.assertEqual(golden_tree_sha256(self.project), self.source_hash_before, "the copy differs from the original")
        before = lineage.tree_hash(self.project)
        imports_before = import_count(self.settings) if daemon_alive(self.settings) else 0
        started = time.monotonic()
        with CommandLog() as log:
            result = preparation.adopt(self.settings, str(self.project), exe=str(self.exe), target="kotor-adopted")
        seconds = round(time.monotonic() - started, 2)
        self.assertTrue(result["registered"], result)
        self.assertEqual((result["copied"], result["imported"], result["written"]), (False, False, False), result)
        self.assertEqual(lineage.tree_hash(self.project), before)
        self.assertEqual(golden_tree_sha256(self.project), self.source_hash_before, "adopt changed the copy")
        self.assertEqual(log.forbidden(), [], log.commands())
        self.assertEqual(log.writable_opens(), [])
        read_only_everywhere(self, self.settings)
        self.assertEqual(import_count(self.settings), imports_before)
        evidence("kotor-adopt", {"seconds": seconds, "functions": result["functions"], "commands": log.commands(),
                                 "tree_sha256_before_after": before, "owner_hash_before_after": self.source_hash_before,
                                 "sha256": result["sha256"]})


if __name__ == "__main__":
    unittest.main()
