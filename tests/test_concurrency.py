"""Concurrency regression guard (PROTOCOL-3.md 8, package Z1).

It pins the behaviour on the path agents use, before Y1 and Y2 rewrite it. Nothing here asserts a duration.

Always run (no engine):
  * the source guard: `query.py` and `hydra.py` never import `LaneLock` or name `.request.lock` (the saved-analysis
    path takes no request lock, so concurrent queries are never serialized or refused by Hydralysis itself);
  * the store-level cases, with the engine step of an edit (`workcopy._sync`) replaced by a stub that reports the
    edit's effect: `SameAddressRace` (threads and processes), `TwoWriters`, the two-author journal, and a process
    killed while it holds the view's lock in the middle of an edit.

Run only against a real Hydra engine (HYDRALYSIS_INTEGRATION_ENGINE and HYDRALYSIS_INTEGRATION_CLIENT, as for
test_engine_integration.py): the same store cases through `QueryRunner.query`, Barrier-started parallel queries at
N = 2, 3 and `maxLong` + 1, and the two known issues below.

Known issues (red by design until Y2): the multithread `_sync` test (4 and 12 threads building 4 and 12 views in one
process; the measured `no_project` error, BP20) and the single-base test (N concurrent first-view builds must make
one base, BP19). They are marked `expectedFailure`, so the suite is green while the defect exists and turns red
("unexpected success") the day it is fixed: Y2 then deletes the `@known_issue` line. To see them fail as ordinary
tests set HYDRALYSIS_KNOWN_ISSUES=run.
"""

from __future__ import annotations

import ast
import functools
import json
import os
import subprocess
import sys
import threading
import time
import unittest
import uuid
from pathlib import Path
from unittest.mock import patch

SRC = Path(__file__).resolve().parent.parent / "src"
HARNESS_B = "z1-client-b"
# A hung child or worker fails its test instead of blocking the suite. These are watchdogs, not timing assertions.
WATCHDOG_S = 240


def _env(name):
    """HYDRALYSIS_<name>, else the old RUSTICRE_<name> (the same rule as test_engine_integration.py)."""
    return os.environ.get("HYDRALYSIS_" + name) or os.environ.get("RUSTICRE_" + name)


ENGINE = _env("INTEGRATION_ENGINE")
CLIENT = _env("INTEGRATION_CLIENT")
BINARY = _env("INTEGRATION_BINARY") or (
    os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "System32", "whoami.exe") if os.name == "nt" else "")
HAVE_ENGINE = bool(ENGINE and CLIENT and BINARY and Path(BINARY).is_file())
NEEDS_ENGINE = unittest.skipUnless(HAVE_ENGINE, "set HYDRALYSIS_INTEGRATION_ENGINE/CLIENT")


def known_issue(test):
    """Red by design until Y2 (PROTOCOL-3.md 4.11, BP19/BP20): an expected failure.

    Only a failed assertion counts as the known defect. Any other exception (a broken harness, a missing
    engine) is reported as a real failure of the test, which `expectedFailure` alone would hide.
    HYDRALYSIS_KNOWN_ISSUES=run turns the marker off so the test runs, and fails, like any other.
    """
    if _env("KNOWN_ISSUES") == "run":
        return test

    @functools.wraps(test)
    def wrapper(self):
        try:
            test(self)
        except (AssertionError, unittest.SkipTest):
            raise
        except BaseException as exc:  # noqa: BLE001
            self.addCleanup(self.fail, "the known-issue test broke with %s instead of failing an assertion: %s"
                            % (type(exc).__name__, str(exc)[:500]))
            raise
    return unittest.expectedFailure(wrapper)


def run_threads(count, work):
    """COUNT threads, started together by a Barrier. Returns [(index, value, exception)] in index order."""
    barrier = threading.Barrier(count)
    found = [None] * count

    def body(index):
        try:
            barrier.wait(WATCHDOG_S)
            found[index] = (index, work(index), None)
        except BaseException as exc:  # noqa: BLE001 - the test reports whatever a thread raised
            found[index] = (index, None, exc)

    threads = [threading.Thread(target=body, args=(index,), daemon=True) for index in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(WATCHDOG_S)
    hung = [index for index, thread in enumerate(threads) if thread.is_alive()]
    if hung:
        raise AssertionError("threads %s did not finish within %d s" % (hung, WATCHDOG_S))
    return found


# ---------------------------------------------------------------------------------------------------------------
# The engine step of an edit, stubbed for the engine-free cases.

STUB_TARGET = {"key": "z1" + "0" * 14, "sha256": "a" * 64, "name": "z1stub", "gpr": "stub.gpr", "program": "/stub.exe",
               "view": "shared"}
STUB_ADDRESSES = ("0x140001000", "0x140002000", "0x140003000")


def stub_sync(settings, target, store, timeout_s, extra=None):
    """What `workcopy._sync` reports for the records it was given, without an engine."""
    from hydralysis import revisions
    effects = {}
    for item in extra or []:
        subject = revisions.subjects_of(item["address"], item["options"])[0]
        effects[item["id"]] = [{"subject": subject, "field": "name", "before": None, "after": item["options"]["name"]}]
    return {"fork_gpr": "stub.gpr", "last_sync": {"stub": True}, "effects": effects}


def perform_edit(settings, mode, view, address, name, expect):
    """One cited rename of ADDRESS in VIEW, naming the revision it read. Raises RuntimeError on a conflict."""
    from hydralysis import query, workcopy
    options = {"kind": "rename", "name": name, "source": "z1 concurrency test", "expect_revision": expect}
    if mode == "stub":
        return workcopy.edit(settings, None, workcopy.with_view(STUB_TARGET, view), address, options, 30)
    options["view"] = view
    return json.loads(query.QueryRunner(settings).query("fixture", "type_edit", address, timeout_s=300, options=options))


def is_conflict(exc):
    """Whether EXC is the optimistic-revision conflict an agent receives (revisions.conflict_payload)."""
    if not isinstance(exc, RuntimeError):
        return False
    try:
        return json.loads(str(exc)).get("conflict") == "overlay revision changed"
    except ValueError:
        return False


# ---------------------------------------------------------------------------------------------------------------
# Child processes: this file, run as a script. A second client of the same data root.

def child_main(spec):
    sys.path.insert(0, str(SRC))
    from hydralysis import workcopy
    mode = spec["mode"]
    if mode == "stub":
        workcopy._sync = stub_sync
    if spec.get("hold"):
        # Hold the view's lock inside an edit: `_sync` runs only with it held. Tell the parent, then never return.
        def hold(*args, **kwargs):
            Path(spec["held"]).write_text("held", encoding="utf-8")
            time.sleep(3600)
        workcopy._sync = hold
    bases = []
    if spec.get("count_bases"):
        from hydralysis import hydra
        original = hydra.Engine.call

        def counting(engine, command, *args, **fields):
            if command == "fork_project" and os.path.basename(str(fields.get("path", ""))).startswith("base-"):
                bases.append(str(fields["path"]))
            return original(engine, command, *args, **fields)
        hydra.Engine.call = counting
    Path(spec["ready"]).write_text("ready", encoding="utf-8")
    deadline = time.monotonic() + WATCHDOG_S
    while not Path(spec["go"]).exists():
        if time.monotonic() > deadline:
            print(json.dumps({"error": "no go signal"}))
            return 3
        time.sleep(0.01)
    try:
        answer = perform_edit(spec["settings"], mode, spec["view"], spec["address"], spec["name"], spec["expect"])
        out = {"ok": True, "revision": answer["revision"], "by": answer["by"], "overlay_id": answer["overlay_id"]}
    except RuntimeError as exc:
        out = {"ok": False, "conflict": is_conflict(exc), "error": str(exc)[:2000]}
    if spec.get("count_bases"):
        out["bases"] = bases
    if spec.get("names") and out["ok"]:
        from hydralysis import query
        runner = query.QueryRunner(spec["settings"])
        out["names"] = {address: json.loads(runner.query("fixture", "decompile", address, options={"view": spec["view"]}))
                        ["function"]["name"] for address in spec["names"]}
    print(json.dumps(out))
    return 0


class Child:
    """A started second client. `wait_ready` then `go`, then `result`."""

    def __init__(self, case, **spec):
        self.dir = Path(case.work.name) / ("child-" + uuid.uuid4().hex[:8])
        self.dir.mkdir()
        self.spec = {"mode": case.MODE, "settings": case.settings, "ready": str(self.dir / "ready"), "go": str(self.dir / "go"),
                     "held": str(self.dir / "held"), **spec}
        harness = self.spec.pop("harness", None)
        env = dict(os.environ, PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
        env.pop("HYDRALYSIS_TEST_FAULT", None)
        if harness:
            env["HYDRALYSIS_HARNESS"] = harness
        self.process = subprocess.Popen([sys.executable, str(Path(__file__).resolve()), "--child", json.dumps(self.spec)],
                                        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        case.addCleanup(self.kill)

    def kill(self):
        if self.process.poll() is None:
            self.process.kill()
        self.process.communicate()

    def wait_for(self, name, what):
        path = self.dir / name
        deadline = time.monotonic() + WATCHDOG_S
        while not path.exists():
            if self.process.poll() is not None:
                raise AssertionError("the child ended before %s: %s" % (what, self.process.communicate()[1][-3000:]))
            if time.monotonic() > deadline:
                raise AssertionError("the child did not reach %s in %d s" % (what, WATCHDOG_S))
            time.sleep(0.01)

    def wait_ready(self):
        self.wait_for("ready", "its start line")

    def go(self):
        (self.dir / "go").write_text("go", encoding="utf-8")

    def result(self):
        try:
            out, err = self.process.communicate(timeout=WATCHDOG_S)
        except subprocess.TimeoutExpired:
            self.kill()
            raise AssertionError("the child did not finish within %d s" % WATCHDOG_S)
        lines = [line for line in out.splitlines() if line.startswith("{")]
        if self.process.returncode != 0 or not lines:
            raise AssertionError("the child failed (exit %s): %s %s" % (self.process.returncode, out[-1500:], err[-3000:]))
        return json.loads(lines[-1])


# ---------------------------------------------------------------------------------------------------------------
# 1. The source guard.

def lane_lock_uses(source, filename="<source>"):
    """Where SOURCE imports or names `LaneLock`, or names a `.request.lock` file."""
    found = []
    for node in ast.walk(ast.parse(source, filename)):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            if any(alias.name.split(".")[-1] == "LaneLock" for alias in node.names):
                found.append((node.lineno, "imports LaneLock"))
        elif isinstance(node, ast.Name) and node.id == "LaneLock":
            found.append((node.lineno, "uses LaneLock"))
        elif isinstance(node, ast.Attribute) and node.attr == "LaneLock":
            found.append((node.lineno, "uses .LaneLock"))
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) and "request.lock" in node.value:
            found.append((node.lineno, "names a request.lock file"))
    return found


class SourceGuard(unittest.TestCase):
    """The saved-analysis path (query.py) and the engine client (hydra.py) hold no request lock of their own."""

    def test_query_and_hydra_never_import_lanelock_or_create_a_request_lock(self):
        for name in ("query.py", "hydra.py"):
            path = SRC / "hydralysis" / name
            with self.subTest(file=name):
                self.assertEqual(lane_lock_uses(path.read_text(encoding="utf-8"), str(path)), [])

    def test_the_guard_sees_each_form_of_the_violation(self):
        for source in ("from hydralysis.locks import LaneLock\n", "from hydralysis.locks import locked, LaneLock as L\n",
                       "from hydralysis import locks\nx = locks.LaneLock(p)\n", "lease = LaneLock(p)\n",
                       "path = d / '.request.lock'\n", "import hydralysis.locks.LaneLock\n"):
            with self.subTest(source=source):
                self.assertTrue(lane_lock_uses(source))
        self.assertEqual(lane_lock_uses("from hydralysis.locks import locked\nwith locked(p):\n    pass\n"), [])

    def test_the_guard_is_not_vacuous_on_the_runtime_module(self):
        # runtime.py keeps its own per-session request lock, and the guard finds it.
        self.assertTrue(lane_lock_uses((SRC / "hydralysis" / "runtime.py").read_text(encoding="utf-8")))


# ---------------------------------------------------------------------------------------------------------------
# 2. The store-level cases, shared by the engine-free class and the real-engine class.

class StoreCases:
    """Needs MODE ('stub' or 'real'), `settings`, `addresses` (two or more) and `target`."""

    MODE = "stub"

    def new_view(self):
        return "z1-" + uuid.uuid4().hex[:10]

    def store(self, view):
        from hydralysis import workcopy
        return workcopy.load_store(self.settings, workcopy.with_view(self.target, view))

    def edit(self, view, address, name, expect):
        return perform_edit(self.settings, self.MODE, view, address, name, expect)

    def visible_names(self, view, addresses):
        """The function names a query answers with in VIEW (real engine only)."""
        return {}

    def assert_one_winner(self, outcomes, view, before_revision, before_journal):
        """OUTCOMES: [(value, exception)]. Exactly one ok, the others conflicts, one record and one journal entry."""
        wins = [value for value, exc in outcomes if exc is None]
        others = [exc for _, exc in outcomes if exc is not None]
        self.assertEqual(len(wins), 1, "wins=%r errors=%r" % (wins, [str(exc)[:300] for exc in others]))
        self.assertTrue(all(is_conflict(exc) for exc in others), [str(exc)[:300] for exc in others])
        self.assertEqual(len(others), len(outcomes) - 1)
        store = self.store(view)
        self.assertEqual(store["revision"], before_revision + 1)
        self.assertEqual(len(store["journal"]), before_journal + 1)
        self.assertEqual(len(store["edits"]), before_revision + 1)
        self.assertEqual(store["edits"][-1]["id"], wins[0]["overlay_id"])
        return wins[0]

    def test_same_address_race_between_threads_has_one_winner(self):
        address = self.addresses[0]
        for count in (2, 8):
            with self.subTest(threads=count):
                view = self.new_view()
                found = run_threads(count, lambda index: self.edit(view, address, "race_%d_%d" % (count, index), 0))
                self.assert_one_winner([(value, exc) for _, value, exc in found], view, 0, 0)

    def test_same_address_race_between_processes_has_one_winner(self):
        address, view = self.addresses[0], self.new_view()
        children = [Child(self, view=view, address=address, name="proc_race_%d" % number, expect=0) for number in range(3)]
        for child in children:
            child.wait_ready()
        for child in children:
            child.go()
        answers = [child.result() for child in children]
        self.assertEqual(sorted(answer["ok"] for answer in answers), [False, False, True], answers)
        self.assertTrue(all(answer["conflict"] for answer in answers if not answer["ok"]), answers)
        store = self.store(view)
        self.assertEqual((store["revision"], len(store["journal"]), len(store["edits"])), (1, 1, 1))
        (winner,) = [answer for answer in answers if answer["ok"]]
        self.assertEqual(store["edits"][0]["id"], winner["overlay_id"])

    def test_a_different_address_after_a_stale_revision_is_rebased_not_refused(self):
        # The same race on two addresses: both succeed, the second is rebased (subject-aware, not a global lock).
        view = self.new_view()
        found = run_threads(2, lambda index: self.edit(view, self.addresses[index], "rebase_%d" % index, 0))
        self.assertEqual([exc for _, _, exc in found], [None, None])
        store = self.store(view)
        self.assertEqual((store["revision"], len(store["journal"])), (2, 2))
        self.assertEqual(sorted(value["rebased"] for _, value, _ in found), [False, True])

    def test_two_writers_see_each_others_edit_at_once(self):
        view = self.new_view()
        first, second = self.addresses[0], self.addresses[1]
        mine = self.edit(view, first, "writer_a", 0)
        self.assertEqual(mine["revision"], 1)
        # Client B is another process: it names the revision it reads (1) and sees A's record immediately.
        theirs = Child(self, view=view, address=second, name="writer_b", expect=1, harness=HARNESS_B,
                       names=[first, second] if self.MODE == "real" else [])
        theirs.wait_ready()
        theirs.go()
        answer = theirs.result()
        self.assertTrue(answer["ok"], answer)
        self.assertEqual(answer["revision"], 2)
        if self.MODE == "real":
            self.assertEqual(answer["names"], {first: "writer_a", second: "writer_b"})
        # And A sees B's edit at once, with no refresh step.
        from hydralysis import workcopy
        changes = workcopy.changes(self.settings, workcopy.with_view(self.target, view), 0, "all", 40)
        self.assertEqual([row["id"] for row in changes["changes"]], [mine["overlay_id"], answer["overlay_id"]])
        self.assertEqual(changes["view_revision"], 2)
        self.assertEqual(self.store(view)["revision"], 2)
        if self.MODE == "real":
            self.assertEqual(self.visible_names(view, [first, second]), {first: "writer_a", second: "writer_b"})

    def test_the_journal_names_both_authors(self):
        from hydralysis import hydra
        view = self.new_view()
        mine = self.edit(view, self.addresses[0], "author_a", 0)
        child = Child(self, view=view, address=self.addresses[1], name="author_b", expect=1, harness=HARNESS_B)
        child.wait_ready()
        child.go()
        theirs = child.result()
        self.assertTrue(theirs["ok"], theirs)
        journal = self.store(view)["journal"]
        self.assertEqual([entry["revision"] for entry in journal], [1, 2])
        self.assertEqual([entry["op"] for entry in journal], ["edit", "edit"])
        self.assertEqual(journal[0]["by"], mine["by"])
        self.assertEqual(journal[1]["by"], theirs["by"])
        self.assertEqual(journal[0]["by"]["client"], hydra.identity()["client"])
        self.assertNotEqual(journal[0]["by"]["client"], journal[1]["by"]["client"])
        self.assertEqual(journal[1]["by"]["harness"], HARNESS_B)
        self.assertNotEqual(journal[0]["by"]["harness"], journal[1]["by"]["harness"])
        # The records carry the same authors as the journal.
        self.assertEqual([edit["by"] for edit in self.store(view)["edits"]], [entry["by"] for entry in journal])

    def test_a_process_killed_holding_the_views_lock_mid_edit_does_not_block_the_next_edit(self):
        view, address = self.new_view(), self.addresses[0]
        child = Child(self, view=view, address=address, name="doomed", expect=0, hold=True)
        child.wait_ready()
        child.go()
        child.wait_for("held", "the middle of its edit (inside the engine step, with the view's lock held)")
        child.kill()
        self.assertNotEqual(child.process.returncode, 0)
        # The killed edit recorded nothing.
        self.assertEqual((self.store(view)["revision"], self.store(view)["edits"]), (0, []))
        outcome = {}

        def next_edit():
            try:
                outcome["answer"] = self.edit(view, address, "survivor", 0)
            except BaseException as exc:  # noqa: BLE001
                outcome["error"] = exc
        worker = threading.Thread(target=next_edit, daemon=True)
        worker.start()
        worker.join(WATCHDOG_S)
        self.assertFalse(worker.is_alive(), "the next edit is still waiting for a lock whose holder was killed")
        self.assertNotIn("error", outcome, outcome.get("error"))
        self.assertEqual(outcome["answer"]["revision"], 1)
        self.assertEqual([edit["id"] for edit in self.store(view)["edits"]], [outcome["answer"]["overlay_id"]])


class StoreConcurrency(StoreCases, unittest.TestCase):
    """No engine: `workcopy._sync` is replaced by `stub_sync`; the lock, the revision check and the store are real."""

    MODE = "stub"

    @classmethod
    def setUpClass(cls):
        from support import workdir
        cls.work = workdir("z1stub")
        cls.settings = {"root": str(Path(cls.work.name) / "data")}
        cls.target = {**STUB_TARGET}
        cls.addresses = STUB_ADDRESSES
        cls.patcher = patch("hydralysis.workcopy._sync", stub_sync)
        cls.patcher.start()

    @classmethod
    def tearDownClass(cls):
        cls.patcher.stop()
        cls.work.cleanup()


# ---------------------------------------------------------------------------------------------------------------
# 3. The real engine.

def prepared(cls, label):
    """A prepared fixture under its own data root and daemon (test_engine_integration's helper)."""
    import test_engine_integration as integration
    integration._prepare(cls, BINARY, label, "fixture")


def release(cls):
    import test_engine_integration as integration
    integration._release(cls)


@NEEDS_ENGINE
class EngineConcurrency(StoreCases, unittest.TestCase):
    """The same store cases through QueryRunner.query on the real engine, and parallel queries."""

    MODE = "real"

    @classmethod
    def setUpClass(cls):
        prepared(cls, "z1conc")
        listed = json.loads(cls.runner.query("fixture", "functions", "", limit=5))["functions"]
        cls.addresses = tuple(item["address"] for item in listed[:3])
        cls.target = cls.runner.target("fixture")
        if len(cls.addresses) < 2:
            release(cls)
            raise AssertionError("the fixture has fewer than two functions")

    @classmethod
    def tearDownClass(cls):
        release(cls)

    def visible_names(self, view, addresses):
        return {address: json.loads(self.runner.query("fixture", "decompile", address, options={"view": view}))["function"]["name"]
                for address in addresses}

    def long_slots(self):
        from hydralysis import hydra
        scheduler = hydra.Engine(self.settings).call("status").get("scheduler") or {}
        return int((scheduler.get("long") or {}).get("slots") or 6)

    def test_parallel_queries_through_the_runner_are_all_answered(self):
        # Every RusticQuery run is a `script` call in the engine's long lane; N = maxLong + 1 is one more than it has slots.
        address = self.addresses[0]
        self.runner.query("fixture", "decompile", address)
        for count in (2, 3, self.long_slots() + 1):
            with self.subTest(threads=count):
                def ask(index):
                    answers = []
                    for round_number in range(3):
                        action = ("decompile", "function", "xrefs")[(index + round_number) % 3]
                        answers.append(json.loads(self.runner.query("fixture", action, address)))
                    return answers
                found = run_threads(count, ask)
                errors = [(index, type(exc).__name__, str(exc)[:300]) for index, _, exc in found if exc is not None]
                self.assertEqual(errors, [])
                for _, answers, _ in found:
                    for answer in answers:
                        self.assertTrue(answer["ok"], answer)
                        self.assertNotIn("busy", json.dumps(answer))

    def test_a_query_while_an_edit_is_in_flight_is_answered_not_refused(self):
        view = self.new_view()
        address = self.addresses[0]

        def work(index):
            if index == 0:
                return self.edit(view, address, "inflight_name", 0)
            return json.loads(self.runner.query("fixture", "decompile", address, options={"view": view}))
        found = run_threads(4, work)
        self.assertEqual([(index, str(exc)[:300]) for index, _, exc in found if exc is not None], [])
        # A reader sees the program before or after the edit, never an error.
        for _, value, _ in found[1:]:
            self.assertTrue(value["ok"], value)


class Overlap:
    """Forces the schedule that the measurement (BP20) hit by chance, at the engine-call level.

    Every thread's sync reaches its `apply_overlays` script call (so each holds a program opened on the process's
    writer connection), then one thread finishes its whole edit, which ends with its sync disconnecting the writer,
    and only then do the others make their call. Hooks `hydra.Engine.call` (the protocol, not Hydralysis internals),
    so it keeps working when `_sync` is rewritten; a barrier that cannot fill (a design that serializes syncs)
    is given up after `GIVE_UP_S` and the call goes ahead, so the test then simply runs the threads."""

    GIVE_UP_S = 20

    def __init__(self, count):
        self.barrier = threading.Barrier(count)
        self.guard = threading.Lock()
        self.arrived = 0
        self.leader_done = threading.Event()
        self.local = threading.local()
        self.forced = True

    def finished(self):
        """The calling thread's edit has returned."""
        if getattr(self.local, "leader", False):
            self.leader_done.set()

    def patch(self):
        from hydralysis import hydra
        original = hydra.Engine.call
        overlap = self

        def call(engine, command, *args, **fields):
            if command == "script" and hydra._script_action(fields) == "apply_overlays" and not hasattr(overlap.local, "gated"):
                overlap.local.gated = True
                try:
                    overlap.barrier.wait(overlap.GIVE_UP_S)
                except threading.BrokenBarrierError:
                    overlap.forced = False
                else:
                    with overlap.guard:
                        overlap.local.leader = overlap.arrived == 0
                        overlap.arrived += 1
                    if not overlap.local.leader:
                        overlap.leader_done.wait(overlap.GIVE_UP_S * 3)
            return original(engine, command, *args, **fields)
        return patch.object(hydra.Engine, "call", call)


@NEEDS_ENGINE
class SyncThreadSafety(unittest.TestCase):
    """BP20: `workcopy._sync` shares one writer connection per process, so one sync's disconnect closes the
    projects another sync is using (`no_project`). Red by design until Y2 gives each sync its own, or a
    reference-counted, connection.

    The schedule is forced (see Overlap): left to chance, 4 threads passed in one of two measured runs."""

    @classmethod
    def setUpClass(cls):
        prepared(cls, "z1sync")
        listed = json.loads(cls.runner.query("fixture", "functions", "", limit=5))["functions"]
        cls.address = listed[0]["address"]

    @classmethod
    def tearDownClass(cls):
        release(cls)

    def build_views(self, count):
        tag, overlap = uuid.uuid4().hex[:6], Overlap(count)

        def build(index):
            try:
                return json.loads(self.runner.query("fixture", "type_edit", self.address, timeout_s=300, options={
                    "kind": "rename", "name": "sync_%d" % index, "source": "z1 test", "view": "sync-%s-%d" % (tag, index),
                    "expect_revision": 0}))
            finally:
                overlap.finished()
        with overlap.patch():
            found = run_threads(count, build)
        errors = ["view %d: %s: %s" % (index, type(exc).__name__, str(exc)[:240]) for index, _, exc in found if exc is not None]
        self.assertEqual(errors, [], "%d of %d views failed" % (len(errors), count))
        self.assertEqual([value["revision"] for _, value, _ in found], [1] * count)

    @known_issue
    def test_4_threads_build_4_views_in_one_process(self):
        self.build_views(4)

    @known_issue
    def test_12_threads_build_12_views_in_one_process(self):
        self.build_views(12)


@NEEDS_ENGINE
class SingleBase(unittest.TestCase):
    """BP19: the base (the master in the engine's database format) is built once per master revision. Today every
    view builds its own, so N concurrent first views make N bases. Red by design until Y2.

    The count is the `fork_project` calls whose destination is a `base-*` folder, as each client sees them."""

    MODE = "real"

    @classmethod
    def setUpClass(cls):
        prepared(cls, "z1base")
        listed = json.loads(cls.runner.query("fixture", "functions", "", limit=5))["functions"]
        cls.address = listed[0]["address"]

    @classmethod
    def tearDownClass(cls):
        release(cls)

    @known_issue
    def test_concurrent_first_view_builds_make_one_base(self):
        # Four clients (processes, so that the writer-connection defect of SyncThreadSafety is not in the way),
        # each building the first version of its own view of the same master at the same moment.
        count, tag = 4, uuid.uuid4().hex[:6]
        children = [Child(self, view="base-%s-%d" % (tag, number), address=self.address, name="base_%d" % number,
                          expect=0, count_bases=True) for number in range(count)]
        for child in children:
            child.wait_ready()
        for child in children:
            child.go()
        answers = [child.result() for child in children]
        self.assertEqual([answer["ok"] for answer in answers], [True] * count, answers)
        bases = [path for answer in answers for path in answer["bases"]]
        self.assertEqual(len(bases), 1, "%d base builds for %d first views: %s" % (len(bases), count, bases))


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--child":
        sys.exit(child_main(json.loads(sys.argv[2])))
    unittest.main()
