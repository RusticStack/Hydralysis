"""No stock Ghidra, proved end to end (PROTOCOL-3.md 8, package Z4; audit C2).

`NoStockEndToEnd` is one sequential class. It scrubs `os.environ` and `PATH` itself, plants a decoy "stock install"
(a canary directory named by the stock hook variable and put on `PATH`, whose launchers would leave a marker if
anything ran them), and then runs the whole journey with the public tool dispatch (`hydralysis.api.call`, the one
the MCP server uses):

  1. `backend inspect`: not ready (no engine, no client), the decoy hook reported as ignored, the decoy never probed;
  2. `backend install`: a durable job that unpacks the pinned Hydra release from archives it re-hashes;
  3. `backend inspect`: ready, from the pinned engine under the private root;
  4. `prepare`: a durable job that imports and analyses a small PE;
  5. `prepare` with `action=adopt`: the prepared project registered in place under a second target;
  6. `ghidra_query` (decompile, function listing) on both targets, and a small `ghidra_run` script;
  7. a process audit: every process that belongs to this run is Hydra Engine from the private root, none names a
     stock launcher or the canary, and the canary directory is byte-for-byte unchanged and its marker never written.

Gate: Windows, a JDK 25 (HYDRALYSIS_INTEGRATION_JAVA), a small PE (HYDRALYSIS_INTEGRATION_BINARY, default
whoami.exe) and the two pinned archives. The archives come from HYDRALYSIS_NOSTOCK_ARCHIVES, else from the
`downloads` folder beside the engine named by HYDRALYSIS_INTEGRATION_ENGINE (where CI's `ci_engine.py install` leaves
them). Nothing is downloaded: a missing archive skips the class.

`AuditHarnessTool` always runs (no engine). It shows that `tools/audit_harness.py` is not vacuous: it fails on a
planted stock server, a planted stock name in a skill, and a catalog that advertises one, and passes on clean input.

Run:  PYTHONPATH=src python -m unittest tests/test_engine_nostock.py   (or discover)
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from support import workdir

REPOSITORY = Path(__file__).resolve().parent.parent
SRC = REPOSITORY / "src"
AUDIT = REPOSITORY / "tools" / "audit_harness.py"

# Built from parts: the repository's text scan for the stock names covers tools/ and docs/, not tests/, but a test
# that plants these names should still not spell them in one piece.
HOOK = "GHIDRA" + "_INSTALL_DIR"
LAUNCHERS = ("analyze" + "Headless", "ghidra" + "Run")
STOCK = re.compile("|".join((HOOK, *LAUNCHERS, "ghidra" + "_dir")), re.IGNORECASE)


def _env(name):
    return os.environ.get("HYDRALYSIS_" + name) or os.environ.get("RUSTICRE_" + name)


LOG = _env("NOSTOCK_LOG")   # read before the run scrubs the environment
JAVA = _env("INTEGRATION_JAVA")
BINARY = _env("INTEGRATION_BINARY") or (
    os.path.join(os.environ.get("SystemRoot", "C:/Windows"), "System32", "whoami.exe") if os.name == "nt" else "")


def _archives() -> Path | None:
    candidates = [_env("NOSTOCK_ARCHIVES")]
    if _env("INTEGRATION_ENGINE"):
        candidates.append(Path(_env("INTEGRATION_ENGINE")).resolve().parents[1] / "downloads")
    sys.path.insert(0, str(SRC))
    from hydralysis import hydra
    names = [asset["url"].rsplit("/", 1)[-1] for asset in (hydra.ASSETS["engine"], hydra.ASSETS["client"])]
    for candidate in candidates:
        if candidate and all((Path(candidate) / name).is_file() for name in names):
            return Path(candidate)
    return None


ARCHIVES = _archives() if os.name == "nt" else None
RUNNABLE = bool(os.name == "nt" and ARCHIVES and JAVA and (Path(JAVA) / "bin" / "javac.exe").is_file()
                and BINARY and Path(BINARY).is_file())


def tree_fingerprint(directory: Path) -> dict:
    result = {}
    for path in sorted(directory.rglob("*")):
        relative = path.relative_to(directory).as_posix()
        if path.is_dir():
            result[relative + "/"] = None
        else:
            stat = path.stat()
            result[relative] = (stat.st_size, stat.st_mtime_ns, hashlib.sha256(path.read_bytes()).hexdigest())
    return result


def make_canary(root: Path) -> Path:
    """A decoy stock install. Anything that runs one of its launchers writes RAN.txt."""
    canary = root / "decoy-stock-install"
    (canary / "support").mkdir(parents=True)
    (canary / "Ghidra").mkdir()
    marker = canary / "RAN.txt"
    script = "@echo off\r\necho ran %~nx0 > \"{}\"\r\n".format(marker)
    for relative in ("support/" + LAUNCHERS[0] + ".bat", "support/launch.bat", LAUNCHERS[1] + ".bat"):
        (canary / relative).write_text(script, encoding="ascii")
    (canary / "Ghidra" / "application.properties").write_text("application.name=decoy\n", encoding="ascii")
    return canary


def scrubbed_environment(root: Path, canary: Path) -> dict:
    system = os.environ["SystemRoot"]
    keep = ("SystemRoot", "windir", "COMSPEC", "PATHEXT", "USERPROFILE", "APPDATA", "LOCALAPPDATA", "ProgramData",
            "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE",
            "HOMEDRIVE", "HOMEPATH", "USERNAME", "COMPUTERNAME", "OS")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    temp = root / "tmp"
    temp.mkdir(exist_ok=True)
    env.update(TEMP=str(temp), TMP=str(temp), JAVA_HOME=JAVA, HYDRALYSIS_ROOT=str(root / "data"), PYTHONDONTWRITEBYTECODE="1",
               PYTHONPATH=str(SRC), PYTHONIOENCODING="utf-8")
    system32 = Path(system) / "System32"
    # The decoy goes first on PATH and is also named by the stock hook: if anything honoured either, it would find it.
    env["PATH"] = os.pathsep.join([str(canary / "support"), str(canary), str(system32), system,
                                   str(system32 / "Wbem"), str(system32 / "WindowsPowerShell" / "v1.0")])
    env[HOOK] = str(canary)
    return env


def processes() -> list[dict]:
    command = ("Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine "
               "| ConvertTo-Json -Compress")
    shell = Path(os.environ.get("SystemRoot", "C:/Windows")) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    done = subprocess.run([str(shell), "-NoProfile", "-NonInteractive", "-Command", command],
                          capture_output=True, text=True, timeout=120)
    if done.returncode:
        raise AssertionError("process listing failed (%d): %s" % (done.returncode, done.stderr[-500:]))
    data = json.loads(done.stdout)
    return data if isinstance(data, list) else [data]


@unittest.skipUnless(RUNNABLE, "needs Windows, HYDRALYSIS_INTEGRATION_JAVA (JDK 25), a small PE and the pinned archives "
                               "(HYDRALYSIS_NOSTOCK_ARCHIVES or HYDRALYSIS_INTEGRATION_ENGINE)")
class NoStockEndToEnd(unittest.TestCase):
    steps: set

    @classmethod
    def setUpClass(cls):
        from hydralysis import hydra
        cls.work = workdir("nostock")
        cls.root = Path(cls.work.name)
        cls.canary = make_canary(cls.root)
        cls.canary_before = tree_fingerprint(cls.canary)
        (cls.root / "data" / "downloads").mkdir(parents=True)
        for asset in (hydra.ASSETS["engine"], hydra.ASSETS["client"]):
            name = asset["url"].rsplit("/", 1)[-1]
            shutil.copy2(ARCHIVES / name, cls.root / "data" / "downloads" / name)
        cls.binary = cls.root / "fixture.exe"
        shutil.copy2(BINARY, cls.binary)
        cls.env = patch.dict(os.environ, scrubbed_environment(cls.root, cls.canary), clear=True)
        cls.env.start()
        cls.steps = set()
        cls.snapshots = []
        cls.state = {}

    @classmethod
    def tearDownClass(cls):
        from hydralysis import api
        try:
            api.call("backend", {"action": "stop", "force": True})
        except Exception as error:            # the engine may never have started
            print("engine stop: %s" % error, file=sys.stderr)
        try:
            from hydralysis import hydra
            from hydralysis.config import load
            settings = load()
            if settings.get("hydra_dir"):
                engine = hydra.Engine(settings)
                daemon = engine.module().Daemon(str(engine.engine_dir), str(hydra.state_dir(settings)), hydra.INSTANCE)
                if daemon.jvm_alive() or daemon.read_endpoint():
                    daemon.kill()          # a daemon that ignored the stop must not outlive the test
        except Exception as error:
            print("engine kill check: %s" % error, file=sys.stderr)
        cls.env.stop()
        time.sleep(1)
        cls.work.cleanup()

    # -- helpers ---------------------------------------------------------------------------------------------
    def need(self, step):
        if step not in self.steps:
            self.skipTest("earlier step %r did not pass" % step)

    def call(self, name, **args):
        from hydralysis import api
        return api.call(name, args)

    def json(self, name, **args):
        return json.loads(self.call(name, **args))

    def wait(self, job_id, seconds):
        deadline = time.monotonic() + seconds
        while True:
            record = self.json("job", id=job_id)
            if record["state"] not in ("queued", "running") or time.monotonic() > deadline:
                return record
            time.sleep(1)

    def snapshot(self, label):
        """Record every process that belongs to this run (its command line holds the private root)."""
        root = str(self.root).lower().replace("\\", "/")
        mine = []
        for item in processes():
            line = (item.get("CommandLine") or "").lower().replace("\\", "/")
            path = (item.get("ExecutablePath") or "").lower().replace("\\", "/")
            if root in line or root in path:
                mine.append(item)
        for item in mine:
            for name in re.findall(r"@(\S+\.args)", item.get("CommandLine") or ""):
                if Path(name).is_file():
                    item["ArgumentFile"] = Path(name).read_text(encoding="utf-8", errors="replace")
        self.snapshots.append((label, mine))
        if LOG:      # evidence for a report: the full command lines of this run's processes
            with open(LOG, "a", encoding="utf-8") as log:
                log.write(json.dumps({"label": label, "processes": mine}, indent=1) + "\n")

    # -- the journey -----------------------------------------------------------------------------------------
    def test_01_before_install_the_engine_is_missing_and_the_decoy_is_ignored(self):
        from hydralysis import hydra
        report = self.json("backend", action="inspect")
        self.assertFalse(report["ready"], report)
        self.assertIsNone(report["engine"])
        self.assertIsNone(report["client"])
        self.assertEqual([item["setting"] for item in report["ignored"]], [HOOK])
        self.assertEqual(report["pinned_release"], hydra.RELEASE)
        self.assertNotIn(str(self.canary).lower(), json.dumps(report["checks"]).lower(), "discovery probed the decoy")
        self.steps.add("inspect-before")

    def test_02_install_is_a_job_that_unpacks_the_pinned_release(self):
        self.need("inspect-before")
        started = self.json("backend", action="install")
        self.assertEqual(started["kind"], "install")
        self.assertTrue(started["job_id"].startswith("setup-"), started)
        record = self.wait(started["job_id"], 1200)
        self.assertEqual(record["state"], "done", json.dumps(record)[:3000])
        self.steps.add("install")

    def test_03_after_install_the_pinned_engine_is_ready_and_the_decoy_still_ignored(self):
        self.need("install")
        from hydralysis import hydra
        report = self.json("backend", action="inspect")
        self.assertTrue(report["ready"], json.dumps(report)[:3000])
        self.assertEqual(report["engine"]["hydra_release"], hydra.RELEASE)
        self.assertTrue(report["engine"]["pinned"])
        self.assertEqual(Path(report["engine"]["path"]).parent, (self.root / "data" / "backends").resolve())
        self.assertEqual([item["setting"] for item in report["ignored"]], [HOOK])
        self.state["engine_dir"] = str(Path(report["engine"]["path"]).resolve())
        self.assertNotIn(str(self.canary).lower(), json.dumps({k: v for k, v in report.items() if k != "ignored"}).lower())
        self.steps.add("inspect-after")

    def test_04_prepare_imports_and_analyses_as_a_job(self):
        self.need("inspect-after")
        started = self.json("prepare", exe=str(self.binary), target="nostock-main")
        self.assertEqual(started["kind"], "prepare", started)
        record = self.wait(started["job_id"], 900)
        self.assertEqual(record["state"], "done", json.dumps(record)[:3000])
        self.assertTrue(Path(record["project"]["gpr"]).is_file())
        self.state["prepared"] = record
        self.snapshot("after prepare")
        self.steps.add("prepare")

    def test_05_adopt_registers_the_prepared_project_in_place(self):
        self.need("prepare")
        prepared = self.state["prepared"]
        adopted = self.json("prepare", action="adopt", path=str(Path(prepared["project"]["gpr"]).parent),
                            sha256=prepared["sha256"], target="nostock-adopted")
        self.assertTrue(adopted["registered"], adopted)
        self.assertFalse(adopted["copied"])
        self.steps.add("adopt")

    def test_06_queries_and_a_small_script_run_on_the_engine(self):
        self.need("adopt")
        for target in ("nostock-main", "nostock-adopted"):
            listed = self.json("ghidra_query", target=target, action="functions", limit=5)
            self.assertTrue(listed["functions"], target)
            address = listed["functions"][0]["address"]
            decompiled = self.json("ghidra_query", target=target, action="decompile", address=address)
            self.assertTrue(decompiled["ok"], target)
            self.assertEqual(decompiled["engine"]["mode"], "contained")
        scripts = self.root / "scripts"
        scripts.mkdir()
        (scripts / "NostockProbe.java").write_text(
            "import ghidra.app.script.GhidraScript;\n"
            "public class NostockProbe extends GhidraScript {\n"
            "    @Override protected void run() throws Exception {\n"
            "        println(\"nostock-probe functions=\" + currentProgram.getFunctionManager().getFunctionCount());\n"
            "    }\n}\n", encoding="utf-8")
        config = self.root / "scripted.json"
        config.write_text(json.dumps({"targets": {"nostock-scripted": {
            **{k: v for k, v in self.state["prepared"]["project"].items() if k in ("gpr", "program", "dir", "name")},
            "sha256": self.state["prepared"]["sha256"], "scripts": str(scripts)}}}), encoding="utf-8")
        with patch.dict(os.environ, {"HYDRALYSIS_CONFIG": str(config)}):
            ran = self.call("ghidra_run", target="nostock-scripted", script="NostockProbe")
        self.assertIn("state=done", ran)
        self.assertRegex(ran, r"nostock-probe functions=\d+")
        self.snapshot("after queries")
        self.steps.add("queries")

    def test_07_process_audit_and_canary(self):
        self.need("queries")
        engine_dir = re.sub(r"[\\/]+", "/", self.state["engine_dir"].lower())
        seen_engine = False
        for label, mine in self.snapshots:
            self.assertTrue(mine, "no process of this run was visible %s" % label)
            for item in mine:
                line = item.get("CommandLine") or ""
                self.assertIsNone(STOCK.search(line), "%s: a process names a stock-install setting: %s" % (label, line[:300]))
                self.assertNotIn(str(self.canary).lower(), line.lower(), "%s: a process uses the decoy: %s" % (label, line[:300]))
                if (item.get("Name") or "").lower().startswith("java"):
                    # The engine's class path travels in an @argument file under the private root.
                    text = line.lower()
                    arguments = item.get("ArgumentFile") or ""
                    self.assertIsNone(STOCK.search(arguments), "%s: the class-path file names a stock install" % label)
                    text = re.sub(r"[\\/]+", "/", text + arguments.lower())   # the file escapes its backslashes
                    if engine_dir in text:
                        seen_engine = True
        self.assertTrue(seen_engine, "no java process was seen running from the pinned engine under the private root: %s" % [
            (label, [(i.get("Name"), (i.get("CommandLine") or "")[:160]) for i in mine]) for label, mine in self.snapshots])
        self.assertFalse((self.canary / "RAN.txt").exists(), "a decoy launcher was executed")
        self.assertEqual(tree_fingerprint(self.canary), self.canary_before, "the decoy install was touched")
        self.assertEqual(os.environ[HOOK], str(self.canary), "the scrubbed environment was changed during the run")


def pid_alive(pid):
    if os.name == "nt":
        done = subprocess.run(["tasklist", "/FI", "PID eq %d" % pid, "/NH", "/FO", "CSV"], capture_output=True)
        return ('"%d"' % pid).encode() in done.stdout
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def kill_pid(pid):
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        os.kill(pid, 9)


class AuditHarnessTool(unittest.TestCase):
    """tools/audit_harness.py fails on planted stock names and passes on clean input."""

    def setUp(self):
        self.work = workdir("audit")
        self.root = Path(self.work.name)

    def tearDown(self):
        self.work.cleanup()

    def audit(self, *args):
        env = {key: value for key, value in os.environ.items() if key.upper() != HOOK}
        done = subprocess.run([sys.executable, "-I", str(AUDIT), "--json", *args], capture_output=True, text=True,
                              timeout=180, env=env, cwd=self.root)
        try:
            report = json.loads(done.stdout)
        except ValueError:
            self.fail("audit printed no JSON (exit %d): %s %s" % (done.returncode, done.stdout[-500:], done.stderr[-500:]))
        return done.returncode, report

    def write(self, name, document):
        path = self.root / name
        path.write_text(json.dumps(document), encoding="utf-8")
        return path

    def fake_server(self, description="Query saved analysis."):
        path = self.root / "fake_hydralysis_server.py"
        path.write_text(
            "import json, sys\n"
            "for raw in sys.stdin:\n"
            "    m = json.loads(raw)\n"
            "    if m.get('method') == 'initialize':\n"
            "        r = {'protocolVersion': '2025-06-18', 'serverInfo': {'name': 'hydralysis', 'version': '0'}, 'instructions': ''}\n"
            "    elif m.get('method') == 'tools/list':\n"
            "        r = {'tools': [{'name': 'ghidra_query', 'description': %r, 'inputSchema': {'type': 'object'}}]}\n"
            "    else:\n"
            "        continue\n"
            "    print(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': r}), flush=True)\n" % description, encoding="utf-8")
        return path

    def skill(self, text, name="re-sample"):
        directory = self.root / "skills" / name
        directory.mkdir(parents=True)
        (directory / "SKILL.md").write_text("---\nname: %s\ndescription: x\n---\n%s\n" % (name, text), encoding="utf-8")
        return self.root / "skills"

    def test_clean_servers_and_skills_pass(self):
        server = self.fake_server()
        config = self.write("clean.json", {"mcpServers": {"hydralysis": {"command": sys.executable, "args": [str(server)]}}})
        code, report = self.audit("--config", str(config), "--skills", str(self.skill("Use hydralysis for everything.")))
        self.assertEqual(code, 0, report["findings"])
        catalog = report["configs"][0]["servers"][0]["catalog"]
        self.assertTrue(catalog["launched"])
        self.assertEqual(catalog["tool_count"], 1)

    def test_a_server_that_leaves_a_helper_running_is_ended_and_its_directory_released(self):
        """The helper inherits the server's working directory; a bare terminate() of the server leaves it running."""
        pidfile = self.root / "helper.pid"
        server = self.root / "helper_server.py"
        server.write_text(
            "import json, subprocess, sys\n"
            "helper = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(120)'])\n"
            "open(%r, 'w').write(str(helper.pid))\n"
            "for raw in sys.stdin:\n"
            "    m = json.loads(raw)\n"
            "    if m.get('method') == 'initialize':\n"
            "        r = {'protocolVersion': '2025-06-18', 'serverInfo': {'name': 'hydralysis', 'version': '0'}, 'instructions': ''}\n"
            "    elif m.get('method') == 'tools/list':\n"
            "        r = {'tools': []}\n"
            "    else:\n"
            "        continue\n"
            "    print(json.dumps({'jsonrpc': '2.0', 'id': m['id'], 'result': r}), flush=True)\n" % str(pidfile), encoding="utf-8")
        config = self.write("helper.json", {"mcpServers": {"hydralysis": {"command": sys.executable, "args": [str(server)]}}})
        code, report = self.audit("--config", str(config), "--skills", str(self.skill("fine")))
        self.assertTrue(pidfile.exists(), "the helper was never started")
        pid = int(pidfile.read_text())
        deadline = time.time() + 10
        while time.time() < deadline and pid_alive(pid):
            time.sleep(0.1)
        alive = pid_alive(pid)
        if alive:
            kill_pid(pid)
        self.assertFalse(alive, "the helper of the audited server is still running after the audit")

    def test_a_stock_server_in_a_configuration_fails(self):
        config = self.write("stock.json", {"mcpServers": {"ghidra-mcp": {"command": "python", "args": ["bridge.py"]}}})
        code, report = self.audit("--config", str(config), "--skills", str(self.skill("fine")), "--no-launch")
        self.assertEqual(code, 1)
        self.assertTrue(any("stock Ghidra" in item["message"] for item in report["findings"]), report["findings"])

    def test_a_stock_variable_in_a_server_environment_fails_without_printing_its_value(self):
        config = self.write("env.json", {"mcpServers": {"x": {"command": "x", "env": {HOOK: "C:/secret-looking-path"}}}})
        code, report = self.audit("--config", str(config), "--skills", str(self.skill("fine")), "--no-launch")
        self.assertEqual(code, 1)
        self.assertNotIn("secret-looking-path", json.dumps(report))

    def test_a_catalog_that_advertises_a_stock_name_fails(self):
        server = self.fake_server("Run %s first." % LAUNCHERS[0])
        config = self.write("catalog.json", {"mcpServers": {"hydralysis": {"command": sys.executable, "args": [str(server)]}}})
        code, report = self.audit("--config", str(config), "--skills", str(self.skill("fine")))
        self.assertEqual(code, 1)
        self.assertTrue(any("advertises" in item["message"] for item in report["findings"]), report["findings"])

    def test_a_skill_naming_the_stock_install_fails_unless_the_line_says_ignored(self):
        code, report = self.audit("--no-launch", "--skills", str(self.skill("Set %s before you start." % HOOK)))
        self.assertEqual(code, 1)
        shutil.rmtree(self.root / "skills")
        code, report = self.audit("--no-launch", "--skills", str(self.skill("A %s setting is ignored here." % HOOK)))
        self.assertEqual(code, 0, report["findings"])

    def test_a_skill_whose_front_matter_name_differs_from_its_directory_fails_in_this_repository_only(self):
        skills = self.skill("fine")
        (skills / "re-sample" / "SKILL.md").write_text("---\nname: other\n---\nfine\n", encoding="utf-8")
        code, report = self.audit("--no-launch", "--skills", str(skills))
        self.assertEqual(code, 0)       # outside this repository a mismatch is only a warning
        self.assertTrue(any(item["level"] == "warn" and "front matter" in item["message"] for item in report["findings"]))

    def test_the_own_server_of_this_checkout_passes_the_audit(self):
        code, report = self.audit("--self", "--config", str(self.write("empty.json", {})), "--skills", str(REPOSITORY / "skills"))
        self.assertEqual(code, 0, report["findings"])
        catalog = report["configs"][-1]["servers"][0]["catalog"]
        self.assertTrue(catalog["launched"], catalog)
        self.assertEqual(catalog["server_info"]["name"], "hydralysis")
        self.assertEqual(catalog["tool_count"], 20)

    def test_this_repository_skills_have_matching_names_and_no_stock_names(self):
        code, report = self.audit("--no-launch", "--skills", str(REPOSITORY / "skills"))
        self.assertEqual(code, 0, report["findings"])
        self.assertGreaterEqual(report["skills"][0]["files_scanned"], 4)


if __name__ == "__main__":
    unittest.main()
