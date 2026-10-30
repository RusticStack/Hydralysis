"""Z3: environment, configuration and the early doctor slice (PROTOCOL-3.md, package Z3).

Unit and process-level tests run everywhere. The tests that need a real engine run only when
HYDRALYSIS_INTEGRATION_ENGINE and HYDRALYSIS_INTEGRATION_CLIENT (and, for a JDK outside PATH,
HYDRALYSIS_INTEGRATION_JAVA) are set, like test_engine_integration.py. Each owns its data root and its daemon.
"""

from __future__ import annotations

import io
import json
import os
import queue
import subprocess
import sys
import threading
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from support import REPOSITORY, workdir

from hydralysis import api, compat, config, environment, paths

SRC = os.environ.get("HYDRALYSIS_TEST_SRC") or str(REPOSITORY / "src")
ENGINE = os.environ.get("HYDRALYSIS_INTEGRATION_ENGINE")
CLIENT = os.environ.get("HYDRALYSIS_INTEGRATION_CLIENT")
JAVA = os.environ.get("HYDRALYSIS_INTEGRATION_JAVA")
needs_engine = unittest.skipUnless(ENGINE and CLIENT and os.name == "nt", "needs HYDRALYSIS_INTEGRATION_ENGINE/CLIENT on Windows")


def scrubbed(home: Path, **extra) -> dict:
    """A minimal environment: no HYDRALYSIS_*, no RUSTICRE_*, no JAVA_HOME; a private home so nothing else is read."""
    keep = {key: os.environ[key] for key in ("SystemRoot", "SYSTEMROOT", "SystemDrive", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP", "APPDATA", "PYTHONUSERBASE")
            if key in os.environ}
    keep.update(USERPROFILE=str(home), HOME=str(home), LOCALAPPDATA=str(home / "Local"), XDG_DATA_HOME=str(home / "xdg"),
                PYTHONPATH=SRC, PYTHONIOENCODING="utf-8")
    keep.update(extra)
    return keep


def run_module(args: list[str], cwd: Path, env: dict, stdin: bytes = b"") -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-m"] + args, cwd=str(cwd), env=env, input=stdin, capture_output=True, timeout=60)


def java_pids(marker: str) -> set[int]:
    """Process ids of java.exe whose command line mentions MARKER."""
    script = ("Get-CimInstance Win32_Process -Filter \"name='java.exe'\" | "
              "Select-Object ProcessId,CommandLine | ConvertTo-Json -Compress")
    out = subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", script], capture_output=True, timeout=60)
    text = out.stdout.decode("utf-8", "replace").strip()
    if out.returncode != 0:
        raise RuntimeError("cannot list java.exe: %s" % out.stderr.decode("utf-8", "replace"))
    if not text:
        return set()
    rows = json.loads(text)
    rows = [rows] if isinstance(rows, dict) else rows
    needle = marker.lower().replace("/", "\\")
    return {int(row["ProcessId"]) for row in rows if needle in (row.get("CommandLine") or "").lower().replace("/", "\\")}


class McpProcess:
    """One `python -m hydralysis mcp` server process driven over newline JSON."""

    def __init__(self, cwd: Path, env: dict):
        self.process = subprocess.Popen([sys.executable, "-m", "hydralysis", "mcp"], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=subprocess.PIPE, cwd=str(cwd), env=env)
        self.replies: queue.Queue = queue.Queue()
        self.stderr = io.BytesIO()
        threading.Thread(target=self._read, daemon=True).start()
        threading.Thread(target=self._drain, daemon=True).start()
        self.ident = 0

    def _read(self):
        for line in self.process.stdout:
            self.replies.put(json.loads(line))

    def _drain(self):
        for line in self.process.stderr:
            self.stderr.write(line)

    def request(self, method: str, params: dict, timeout: float = 120):
        self.ident += 1
        message = {"jsonrpc": "2.0", "id": self.ident, "method": method, "params": params}
        self.process.stdin.write((json.dumps(message) + "\n").encode())
        self.process.stdin.flush()
        return self.replies.get(timeout=timeout)

    def tool(self, name: str, arguments: dict) -> dict:
        reply = self.request("tools/call", {"name": name, "arguments": arguments})
        return json.loads(reply["result"]["content"][0]["text"])

    def close(self) -> str:
        try:
            self.process.stdin.close()
            self.process.wait(timeout=20)
        except Exception:
            self.process.kill()
        for stream in (self.process.stdout, self.process.stderr):
            try:
                stream.close()
            except Exception:
                pass
        return self.stderr.getvalue().decode("utf-8", "replace")


class SameEnvironmentEverywhere(unittest.TestCase):
    """The same root and configuration from any working directory, with a scrubbed environment."""

    def test_default_root_and_config_do_not_depend_on_the_working_directory(self):
        with workdir("env-cwd") as name:
            base = Path(name)
            home = base / "home"
            home.mkdir()
            one, two = base / "one", base / "two"
            one.mkdir()
            two.mkdir()
            # A configuration in a working directory is NOT read: it would give each harness its own root.
            (two / "hydralysis.local.json").write_text(json.dumps({"root": str(base / "elsewhere")}), encoding="utf-8")
            reports = []
            for folder in (one, two, base):
                done = run_module(["hydralysis.environment", "describe"], folder, scrubbed(home))
                self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace"))
                reports.append(json.loads(done.stdout))
            for report in reports:
                self.assertEqual((report["root"], report["root_source"], report["config"], report["config_source"]),
                                 (reports[0]["root"], reports[0]["root_source"], reports[0]["config"], reports[0]["config_source"]))
            self.assertEqual(reports[0]["config_source"], "none")
            self.assertTrue(Path(reports[0]["root"]).is_relative_to(home), reports[0]["root"])
            # The ignored file is reported, from the directory that holds it.
            ignored = [item["id"] for item in json.loads(run_module(["hydralysis.environment", "describe"], two, scrubbed(home)).stdout)["warnings"]]
            self.assertIn("config_in_cwd_ignored", ignored)

    def test_the_per_user_configuration_applies_from_every_directory(self):
        with workdir("env-user") as name:
            base = Path(name)
            home = base / "home"
            data = base / "data"
            user = home / "Local" / "Hydralysis" if os.name == "nt" else home / "xdg" / "hydralysis"
            user.mkdir(parents=True)
            (user / "hydralysis.local.json").write_text(json.dumps({"root": str(data)}), encoding="utf-8")
            seen = set()
            for folder in (base, home, user):
                report = json.loads(run_module(["hydralysis.environment", "describe"], folder, scrubbed(home)).stdout)
                seen.add((report["root"], report["root_source"], report["config"], report["config_source"]))
            self.assertEqual(len(seen), 1, seen)
            root, source, path, config_source = seen.pop()
            self.assertEqual(Path(root), data.resolve())
            self.assertEqual((source, config_source), ("config", "user"))
            self.assertEqual(Path(path), user / "hydralysis.local.json")

    def test_environment_variables_win_and_are_named(self):
        with workdir("env-vars") as name:
            base = Path(name)
            explicit = base / "explicit.json"
            explicit.write_text(json.dumps({"root": str(base / "from-config")}), encoding="utf-8")
            env = scrubbed(base / "home", HYDRALYSIS_CONFIG=str(explicit))
            report = json.loads(run_module(["hydralysis.environment", "describe"], base, env).stdout)
            self.assertEqual((report["config_source"], report["root_source"]), ("env", "config"))
            env["HYDRALYSIS_ROOT"] = str(base / "from-env")
            report = json.loads(run_module(["hydralysis.environment", "describe"], base, env).stdout)
            self.assertEqual(Path(report["root"]), (base / "from-env").resolve())
            self.assertEqual(report["root_source"], "env")

    def test_a_broken_configuration_is_a_finding_not_a_crash(self):
        with workdir("env-broken") as name:
            base = Path(name)
            bad = base / "bad.json"
            bad.write_text("{not json", encoding="utf-8")
            done = run_module(["hydralysis.environment", "doctor"], base, scrubbed(base / "home", HYDRALYSIS_CONFIG=str(bad)))
            self.assertEqual(done.returncode, 1, done.stderr.decode("utf-8", "replace"))
            self.assertEqual([item["id"] for item in json.loads(done.stdout)["findings"]], ["config_invalid"])


class Warnings(unittest.TestCase):
    def _describe(self, root: Path, fs: str, platform: str = "win32", system_drive: str = "C:") -> dict:
        with patch.dict(os.environ, {"HYDRALYSIS_ROOT": str(root)}, clear=False), \
                patch("hydralysis.config.config_source", return_value=(None, "none")), \
                patch("hydralysis.config.read_settings", return_value={}):
            return environment.describe(volume_probe=lambda _path: fs, platform=platform,
                                        environ={"SystemDrive": system_drive, "HYDRALYSIS_ROOT": str(root)})

    def test_a_non_copy_on_write_volume_is_warned_and_refs_is_not(self):
        with workdir("env-cow") as name:
            ids = [item["id"] for item in self._describe(Path(name), "NTFS")["warnings"]]
            self.assertIn("root_not_cow", ids)
            report = self._describe(Path(name), "ReFS")
            self.assertNotIn("root_not_cow", [item["id"] for item in report["warnings"]])
            self.assertEqual((report["filesystem"]["fs"], report["filesystem"]["cow"]), ("ReFS", True))

    @unittest.skipUnless(os.name == "nt", "drive letters")
    def test_a_root_on_the_system_drive_is_warned(self):
        with workdir("env-sys") as name:
            drive = Path(name).resolve().drive
            on = self._describe(Path(name), "ReFS", system_drive=drive)
            self.assertIn("root_on_system_drive", [item["id"] for item in on["warnings"]])
            off = self._describe(Path(name), "ReFS", system_drive="Q:")
            self.assertNotIn("root_on_system_drive", [item["id"] for item in off["warnings"]])

    def test_an_unreadable_file_system_is_reported_as_unknown_not_as_an_error(self):
        with workdir("env-unk") as name:
            def broken(_path):
                raise OSError("no volume information")
            with patch.dict(os.environ, {"HYDRALYSIS_ROOT": name}), patch("hydralysis.config.read_settings", return_value={}):
                report = environment.describe(volume_probe=broken)
            self.assertEqual(report["filesystem"]["fs"], None)
            self.assertIn("root_fs_unknown", [item["id"] for item in report["warnings"]])

    def test_volume_info_classifies_known_file_systems(self):
        for name, cow in (("ReFS", True), ("btrfs", True), ("NTFS", False), ("ext4", False), ("exFAT", False)):
            self.assertEqual(paths.volume_info(Path.cwd(), probe=lambda _p, n=name: n)["cow"], cow, name)


class Banner(unittest.TestCase):
    def test_the_banner_names_root_source_configuration_source_engine_and_file_system(self):
        report = {"version": "9.9", "root": "R:/data", "root_source": "env", "config": "R:/c.json", "config_source": "user",
                  "engine_release": "12.3-hydra.2", "filesystem": {"fs": "ReFS", "cow": True, "drive": "R:"},
                  "warnings": [{"level": "warn"}, {"level": "info"}]}
        text = environment.banner(report)
        for part in ("R:/data", "source: env", "R:/c.json", "source: user", "12.3-hydra.2", "ReFS", "warnings=1"):
            self.assertIn(part, text)

    def test_a_server_started_from_a_foreign_directory_reports_the_same_environment(self):
        with workdir("env-server") as name:
            base = Path(name)
            home, foreign, data = base / "home", base / "foreign", base / "data"
            foreign.mkdir()
            (foreign / "hydralysis.local.json").write_text(json.dumps({"root": str(base / "wrong")}), encoding="utf-8")
            env = scrubbed(home, HYDRALYSIS_ROOT=str(data))
            server = McpProcess(foreign, env)
            try:
                reply = server.request("initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "env-test"}})
                meta = reply["result"]["_meta"]["hydralysis/environment"]
                self.assertEqual(Path(meta["root"]), data.resolve())
                self.assertEqual(meta["root_source"], "env")
                self.assertEqual(meta["config_source"], "none")
                self.assertIn("filesystem", meta)
                self.assertIn("engine_release", meta)
                self.assertIn("config_in_cwd_ignored", [item["id"] for item in meta["warnings"]])
            finally:
                err = server.close()
            first = err.splitlines()[0]
            self.assertTrue(first.startswith("hydralysis "), err)
            for part in (str(data.resolve()), "source: env", "source: none", "engine=", "filesystem="):
                self.assertIn(part, first)

    def test_the_banner_goes_to_stderr_and_stdout_stays_protocol_only(self):
        with workdir("env-stdout") as name:
            base = Path(name)
            payload = (json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}) + "\n").encode()
            done = run_module(["hydralysis", "mcp"], base, scrubbed(base / "home", HYDRALYSIS_ROOT=str(base / "data")), payload)
            self.assertEqual(done.returncode, 0)
            self.assertEqual([json.loads(line)["id"] for line in done.stdout.splitlines()], [1])
            self.assertIn(b"hydralysis ", done.stderr.splitlines()[0])


class Init(unittest.TestCase):
    def test_init_pins_the_root_is_idempotent_and_never_overwrites_without_force(self):
        with workdir("env-init") as name:
            base = Path(name)
            env = scrubbed(base / "home")
            first = json.loads(run_module(["hydralysis.environment", "init", "--root", str(base / "data")], base, env).stdout)
            self.assertTrue(first["written"])
            self.assertTrue((base / "data").is_dir())
            written = Path(first["config"])
            self.assertEqual(json.loads(written.read_text(encoding="utf-8"))["root"], str((base / "data").resolve()))
            second = json.loads(run_module(["hydralysis.environment", "init", "--root", str(base / "other")], base, env).stdout)
            self.assertFalse(second["written"])
            self.assertEqual(json.loads(written.read_text(encoding="utf-8"))["root"], str((base / "data").resolve()))
            # After init, every directory sees the pinned root.
            for folder in (base, base / "data"):
                report = json.loads(run_module(["hydralysis.environment", "describe"], folder, env).stdout)
                self.assertEqual((Path(report["root"]), report["config_source"], report["root_source"]),
                                 ((base / "data").resolve(), "user", "config"))
            forced = json.loads(run_module(["hydralysis.environment", "init", "--root", str(base / "other"), "--force"], base, env).stdout)
            self.assertTrue(forced["written"])

    def test_init_refuses_a_dot_prefixed_root(self):
        with workdir("env-dot") as name:
            base = Path(name)
            done = run_module(["hydralysis.environment", "init", "--root", str(base / ".hidden" / "data")], base, scrubbed(base / "home"))
            self.assertEqual(done.returncode, 2)
            self.assertIn("dot-prefixed", done.stderr.decode("utf-8", "replace"))
            self.assertFalse((base / "home").exists() and any((base / "home").rglob("hydralysis.local.json")))


class StatusSpawnsNothing(unittest.TestCase):
    def test_status_is_handled_by_the_environment_module_and_joins_without_starting(self):
        self.assertEqual(api.HANDLER_MODULES["environment"], "hydralysis.environment")
        engine = Mock()
        engine.call.side_effect = RuntimeError("Hydra engine did not start: no 'default' daemon is running (state x)")
        with patch("hydralysis.api._settings", return_value={}), patch("hydralysis.api.load", return_value={}), \
                patch("hydralysis.hydra.Engine", return_value=engine) as constructor:
            status = json.loads(api.call("backend", {"action": "status"}))
        self.assertIs(constructor.call_args.kwargs.get("start"), False)
        self.assertEqual((status["daemon"], status["started"]), ("not_running", False))
        self.assertIn("no 'default' daemon", status["reason"])
        self.assertIn("root", status["environment"])
        self.assertIn("catalog", status)

    @unittest.skipUnless(os.name == "nt", "the WMI fallback of platform.uname() is Windows-only")
    def test_the_backend_report_starts_no_process_when_wmi_fails(self):
        # platform.uname() falls back to `cmd /c ver` when its WMI query fails; the report must not go through it.
        import platform
        from hydralysis import backends
        with workdir("env-nowmi") as name, patch.object(platform, "_uname_cache", None),                 patch.object(platform, "_wmi_query", side_effect=OSError("WMI not available")),                 patch("subprocess.Popen", side_effect=AssertionError("the backend report started a process")) as popen:
            report = backends.inspect({"root": str(Path(name) / "data")})
        popen.assert_not_called()
        self.assertEqual(report["portable_install_supported"],
                         (os.environ.get("PROCESSOR_ARCHITEW6432") or os.environ.get("PROCESSOR_ARCHITECTURE", "")).lower()
                         in ("amd64", "x86_64"))

    def test_status_with_no_engine_installed_is_a_result_not_an_error(self):
        with patch("hydralysis.api._settings", side_effect=ValueError("no ready Hydra engine")), patch("hydralysis.api.load", return_value={}):
            status = json.loads(api.call("backend", {"action": "status"}))
        self.assertEqual(status["daemon"], "not_running")
        self.assertIn("no ready Hydra engine", status["reason"])

    def test_stop_still_uses_the_engine(self):
        engine = Mock()
        engine.stop.return_value = {"stopped": False}
        with patch("hydralysis.api._settings", return_value={}), patch("hydralysis.api.load", return_value={}), \
                patch("hydralysis.hydra.Engine", return_value=engine):
            self.assertEqual(json.loads(api.call("backend", {"action": "stop"})), {"stopped": False})

    def test_status_of_the_runtime_component_is_still_refused(self):
        with patch("hydralysis.api.load", return_value={}):
            with self.assertRaises(ValueError):
                api.call("backend", {"action": "status", "component": "runtime"})


def engine_settings(base: Path) -> dict:
    root = base / "data"
    root.mkdir(parents=True, exist_ok=True)
    settings = {"root": str(root), "hydra_dir": ENGINE, "hydra_client": CLIENT, "hydra_allow_unpinned": True, "hydra_idle_s": 600}
    if JAVA:
        settings["java_home"] = JAVA
    (root / "backend.json").write_text(json.dumps(settings), encoding="utf-8")
    return settings


@needs_engine
class RealEngine(unittest.TestCase):
    def test_backend_status_with_no_daemon_spawns_no_process_and_no_java(self):
        with workdir("env-nodaemon") as name:
            base = Path(name)
            settings = engine_settings(base)
            env = scrubbed(base / "home", HYDRALYSIS_ROOT=settings["root"])
            before = java_pids(settings["root"])
            with patch.dict(os.environ, {"HYDRALYSIS_ROOT": settings["root"]}), \
                    patch("subprocess.Popen", side_effect=AssertionError("backend status started a process")) as popen:
                status = json.loads(api.call("backend", {"action": "status"}))
            popen.assert_not_called()
            self.assertEqual((status["daemon"], status["started"]), ("not_running", False))
            self.assertIsNotNone(status["environment"]["engine_release"])
            # The same through the real command line, from a foreign directory.
            done = run_module(["hydralysis", "backend", "--action", "status"], base, env)
            self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace"))
            self.assertEqual(json.loads(done.stdout)["daemon"], "not_running")
            self.assertEqual(java_pids(settings["root"]), before)
            self.assertEqual(before, set())

    def test_backend_doctor_leaves_the_java_list_unchanged(self):
        with workdir("env-doctor") as name:
            base = Path(name)
            settings = engine_settings(base)
            env = scrubbed(base / "home", HYDRALYSIS_ROOT=settings["root"])
            before = java_pids(settings["root"])
            done = run_module(["hydralysis", "backend", "--action", "doctor"], base, env)
            self.assertEqual(done.returncode, 0, done.stderr.decode("utf-8", "replace"))
            self.assertEqual(java_pids(settings["root"]), before)
            self.assertEqual(before, set())

    def test_eight_server_processes_share_one_root_and_exactly_one_java(self):
        with workdir("env-eight") as name:
            base = Path(name)
            settings = engine_settings(base)
            env = scrubbed(base / "home", HYDRALYSIS_ROOT=settings["root"])
            servers = [McpProcess(base, env) for _ in range(8)]
            try:
                roots = set()
                for index, server in enumerate(servers):
                    reply = server.request("initialize", {"protocolVersion": "2025-06-18", "clientInfo": {"name": "env-%d" % index}})
                    roots.add(reply["result"]["_meta"]["hydralysis/environment"]["root"])
                self.assertEqual(len(roots), 1, roots)
                # Eight idle servers and eight status calls start no JVM.
                for server in servers:
                    self.assertEqual(server.tool("backend", {"action": "status"})["daemon"], "not_running")
                self.assertEqual(java_pids(settings["root"]), set())
                # The first engine call of every server process, all at once: one launcher wins, the rest join it.
                code = ("import sys; from hydralysis import api, hydra; "
                        "e = hydra.Engine(api._settings()); print(e.call('status')['installId'])")
                callers = [subprocess.Popen([sys.executable, "-c", code], env=env, cwd=str(base), stdout=subprocess.PIPE,
                                            stderr=subprocess.PIPE) for _ in range(8)]
                outputs = [caller.communicate(timeout=300) for caller in callers]
                for caller, (out, err) in zip(callers, outputs):
                    self.assertEqual(caller.returncode, 0, err.decode("utf-8", "replace"))
                self.assertEqual(len({out.strip() for out, _ in outputs}), 1)
                self.assertEqual(len(java_pids(settings["root"])), 1)
                # Every server now sees that one daemon.
                seen = {(item["daemon"], item["installId"], item["pid"]) for item in
                        (server.tool("backend", {"action": "status"}) for server in servers)}
                self.assertEqual(len(seen), 1, seen)
                self.assertEqual(next(iter(seen))[0], "running")
                self.assertEqual(len(java_pids(settings["root"])), 1)
            finally:
                for server in servers:
                    server.close()
                from hydralysis import hydra
                try:
                    hydra.Engine({**settings, "root": settings["root"]}).stop(force=True)
                except Exception:
                    pass
            self.assertEqual(java_pids(settings["root"]), set())


if __name__ == "__main__":
    unittest.main()
