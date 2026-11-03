"""Rust vs Python for the pure logic of hydra.py, api.py and the small leaf modules (rust/crates/hy-engine).

Each test runs the Python original and the Rust twin (`hydralysis_native.engine_*_rs`) on the same inputs and compares the
value, or the exception's type and message. An input Rust declines (it answers `None`: the original must run) is counted;
every test asserts that most of its inputs were answered by Rust, so a binding that declines everything cannot pass.
"""

import json
import os
import random
import string
import tempfile
import unittest
import zipfile
from pathlib import Path

try:
    import hydralysis_native as native
except ImportError:
    native = None

from hydralysis import address_maps, api, hydra, integrity, jobowner, localio, red4ext

ABSENT = object()


def original(function):
    """The Python function behind a wrapper installed by `HYDRALYSIS_IMPL=rust`."""
    return getattr(function, "python_function", function)


def python(function, *args, **kwargs):
    try:
        return ("ok", original(function)(*args, **kwargs))
    except Exception as exc:  # noqa: BLE001 - the type and message are the comparison
        return ("err", type(exc).__name__, str(exc))


def rust(name, *args):
    """("ok", value), ("err", type, message) or ("fallback",)."""
    try:
        reply = native.engine_call_rs(name, json.dumps(args))
    except Exception as exc:  # noqa: BLE001
        return ("err", type(exc).__name__, str(exc))
    return ("fallback",) if reply is None else ("ok", json.loads(reply))


class Parity(unittest.TestCase):
    """Base: counts the inputs Rust answered, and compares."""

    answered = 0
    declined = 0

    def same(self, want, got, label=""):
        if got == ("fallback",):
            self.declined += 1
            return
        self.answered += 1
        self.assertEqual(got, want, label)

    def check(self, python_function, rust_name, python_args, rust_args=None, label="", finish=None):
        want = python(python_function, *python_args)
        got = rust(rust_name, *(python_args if rust_args is None else rust_args))
        if finish is not None and got[0] == "ok":
            got = ("ok", finish(got[1]))
        self.same(want, got, label or repr(python_args)[:200])

    def tearDown(self):
        total = self.answered + self.declined
        if total:
            self.assertGreaterEqual(self.answered, total * 0.6, "Rust declined too many inputs: %d of %d" % (self.declined, total))


def skip_unbuilt(cls):
    return unittest.skipIf(native is None or not hasattr(native, "engine_call_rs"), "native extension not built")(cls)


# ---- hydra --------------------------------------------------------------------------------------------------------

WORDS = ["busy", "failed", "closed", "not_found", "cancelled", "ação", "ünï", "x" * 40, "a\"b", "tab\t", "emoji \U0001F600", ""]


def random_json(rng, depth=0):
    kind = rng.randrange(9 if depth < 3 else 6)
    if kind == 0:
        return rng.choice(WORDS)
    if kind == 1:
        return rng.randrange(-5, 10**6)
    if kind == 2:
        return rng.choice([0.5, 1.0, 1e22, -2.25, 3.14159, 1e-7, 123456789.123])
    if kind == 3:
        return rng.choice([True, False, None])
    if kind == 4:
        return rng.choice(WORDS)
    if kind == 5:
        return rng.randrange(0, 5)
    if kind in (6, 7):
        return [random_json(rng, depth + 1) for _ in range(rng.choice([0, 1, 3, 5, 6, 9, 70]))]
    return {rng.choice(WORDS + ["k1", "k2", "queue", "waiting"]): random_json(rng, depth + 1) for _ in range(rng.randrange(0, 4))}


@skip_unbuilt
class EngineErrorParity(Parity):
    def test_the_error_text_of_random_answers(self):
        rng = random.Random(7)
        keys = ["holder", "holderInfo", "suggest", "suggestion", "alternatives", "reason", "program", "project", "current",
                "running", "ambiguous", "heldMs", "queue", "output", "other"]
        for index in range(1500):
            details = {rng.choice(keys): random_json(rng) for _ in range(rng.randrange(0, 7))}
            if rng.random() < 0.3:
                details["output"] = "é" * rng.choice([5, 2000, 2600]) + "tail"
            queue = rng.choice([None, details.get("queue"), {"waiting": list(range(rng.choice([3, 64, 70]))), "position": 1}])
            held = details.get("heldMs")
            if held is None and isinstance(details.get("holderInfo"), dict):
                held = details["holderInfo"].get("heldMs")
            args = (rng.choice(WORDS), rng.choice(WORDS), details, rng.choice(["script", "", "open_program"]), queue, held,
                    rng.choice([None, 2000, 1.5]), rng.choice([None, {"cmd": "x", "args": list(range(9))}]))
            want = python(hydra._error_text, *args)
            got = rust("engine_error_text", args[0], args[1], details, args[3], args[6], args[7], queue)
            self.same(want, got, "case %d: %r" % (index, args))

    def test_the_text_of_a_real_engine_error_is_the_same_object_either_way(self):
        error = hydra.EngineError("busy", "locked", {"holderInfo": {"heldMs": 7}, "reason": "pool_full"}, "open_program", retry_after_ms=2500)
        self.assertEqual(json.loads(str(error))["heldMs"], 7)
        self.assertEqual(error.held_ms, 7)


@skip_unbuilt
class RetryParity(Parity):
    def test_script_actions_in_bodies_and_files(self):
        folder = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, folder, True)
        file = folder / "request.json"
        bodies = [json.dumps({"action": "decompile"}), json.dumps({"action": "apply_overlays"}), json.dumps({"action": 4}), "{}", "[1]",
                  "\"x\"", "not json", "", "{\"action\": \"x\",", json.dumps({"action": "caf\u00e9"}), "  {\"action\":\"scan\"}\n",
                  "{\"action\": \"decompile\", \"action\": \"types\"}", "{\"action\": NaN}", "{\"n\": 1e999, \"action\": \"data\"}",
                  "{\"action\": \"fingerprints\", \"big\": 123456789012345678901234567890}", "\ufeff{\"action\":\"data\"}"]
        for body in bodies:
            fields = {"script": "RusticQuery.java", "args": [body]}
            self.check(hydra._script_action, "script_action", (fields,), (body,), label=repr(body))
            file.write_text(body, encoding="utf-8", newline="")
            fields = {"script": "RusticQuery.java", "args": ["@" + str(file)]}
            self.check(hydra._script_action, "script_action", (fields,), ("@" + str(file),), label="file " + repr(body))
        file.write_bytes(b"\xff\xfe{")
        fields = {"script": "RusticQuery.java", "args": ["@" + str(file)]}
        self.check(hydra._script_action, "script_action", (fields,), ("@" + str(file),))
        missing = "@" + str(folder / "nothing.json")
        self.check(hydra._script_action, "script_action", ({"script": "RusticQuery.java", "args": [missing]},), (missing,))

    def test_the_command_lists(self):
        for command in ("ping", "hello", "health", "status", "decompile", "trace_bundle", "trace_open", "save", "script", "", "frobnicate"):
            self.assertEqual(hydra.idempotent(command), command in ("ping", "hello", "health", "status", "decompile", "trace_bundle"))

    def test_the_wedge_signal_of_random_replies(self):
        rng = random.Random(11)
        cases = [None, {}, {"state": "suspect"}, {"state": "ok"}, {"schedulerLockOk": False}, {"schedulerLockOk": True}, {"schedulerLockOk": 0},
                 {"tick": {"ageMs": 31_000}}, {"tick": {"ageMs": 30_000}}, {"tick": {"ageMs": 30_000.5}}, {"tick": {"ageMs": True}, "watchdogStallMs": 0},
                 {"tick": {"ageMs": "5"}}, {"tick": []}, {"tick": 0}, {"tick": {"ageMs": 5}, "watchdogStallMs": "x"}, {"watchdogStallMs": "x"},
                 {"tick": {"ageMs": 10**15}, "watchdogStallMs": 10**15 + 1}, {"tick": {"ageMs": None}}]
        for _ in range(300):
            reply = {rng.choice(["state", "tick", "watchdogStallMs", "schedulerLockOk", "x"]): rng.choice(
                ["suspect", {"ageMs": rng.choice([0, 29_999, 30_000, 30_001, 1e5, -1])}, rng.choice([0, 5000, 60_000]), True, False, None, "s"])
                for _ in range(rng.randrange(1, 4))}
            cases.append(reply)
        for reply in cases:
            for stall in (30_000, 1, 0):
                self.check(hydra.wedge_signal, "wedge_signal", (reply, stall), label="%r %r" % (reply, stall))


def jar(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("hydra.properties", text)


def engine_install(folder, release, application, decompiler=True, other_entry=False):
    (folder / "Ghidra").mkdir(parents=True, exist_ok=True)
    if application is not None:
        (folder / "Ghidra" / "application.properties").write_text(application, encoding="utf-8")
    if release is not None:
        text = "other=1\nhydra.version=%s\n" % release
        path = folder / "Ghidra" / "Features" / "HeadlessSession" / "lib" / "HeadlessSession.jar"
        if other_entry:
            path.parent.mkdir(parents=True, exist_ok=True)
            with zipfile.ZipFile(path, "w") as archive:
                archive.writestr("other.txt", text)
        else:
            jar(path, text)
    if decompiler:
        (folder / "Ghidra" / "Features" / "Decompiler" / "os" / "win_x86_64").mkdir(parents=True, exist_ok=True)
        (folder / "Ghidra" / "Features" / "Decompiler" / "os" / "win_x86_64" / "decompile.exe").write_bytes(b"x")


@skip_unbuilt
class EngineInstallParity(Parity):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.folder, True)

    def pins(self):
        return (hydra.RELEASE, hydra.PROTOCOL, hydra.PROTOCOL_MIN, hydra.CLIENT_VERSION)

    def test_inspection_of_many_installs(self):
        good = "application.version=12.3\napplication.java.min=21\napplication.java.max=25\n"
        variants = [
            (hydra.RELEASE, good, True), (hydra.RELEASE, good, False), (None, good, True), ("12.3-hydra.3", good, True),
            (hydra.RELEASE, "application.version=\n", True), (hydra.RELEASE, "# nothing\n", True), (hydra.RELEASE, None, True),
            (hydra.RELEASE, "application.version=12\napplication.java.min=x\n", True),
            (hydra.RELEASE, "application.version=12\napplication.java.min= 17 \napplication.java.max=\n", True),
            (hydra.RELEASE, "application.version=12\r\napplication.java.max=\"25\"\r\n", True),
            (hydra.RELEASE, "application.version = 12.3 # c\nignored\n#k=v\n", True),
            ("12.3-hydra.4x", good, True),
        ]
        for index, (release, application, decompiler) in enumerate(variants):
            for allow in (False, True):
                folder = self.folder / ("i%d" % index)
                if not folder.exists():
                    engine_install(folder, release, application, decompiler)
                want = python(hydra.inspect_engine, str(folder), allow)
                got = rust("inspect_engine", str(folder.resolve()), allow, *self.pins())
                if want[0] == "ok":
                    want = ("ok", {**want[1], "path": str(folder.resolve())}) if False else want
                self.same(want, got, "variant %d allow=%s" % (index, allow))
        empty = self.folder / "empty"
        empty.mkdir()
        self.same(python(hydra.inspect_engine, str(empty)), rust("inspect_engine", str(empty.resolve()), False, *self.pins()))

    def test_release_of_odd_jars(self):
        for index, text in enumerate(["hydra.version=1\n", "x\nhydra.version=2 \nhydra.version=3", "  hydra.version=4", "hydra.version=\n",
                                      "hydra.version=a b\n", "\r\nhydra.version=5\r\n", "hydra.version=6\x1d7\n", "caf\u00e9\nhydra.version=7\u00a08\n",
                                      "hydra.version=\u00e98\n", "Hydra.Version=9\n", ""]):
            folder = self.folder / ("j%d" % index)
            jar(folder / "Ghidra" / "Features" / "HeadlessSession" / "lib" / "HeadlessSession.jar", text)
            self.check(hydra.engine_release, "engine_release", (folder,), (str(folder),), label=repr(text))
        broken = self.folder / "broken"
        target = broken / "Ghidra" / "Features" / "HeadlessSession" / "lib"
        target.mkdir(parents=True)
        (target / "HeadlessSession.jar").write_bytes(b"PK\x03\x04 not really")
        self.check(hydra.engine_release, "engine_release", (broken,), (str(broken),))
        other = self.folder / "other"
        engine_install(other, "12.3", "application.version=1\n", other_entry=True)
        self.check(hydra.engine_release, "engine_release", (other,), (str(other),))
        self.check(hydra.engine_release, "engine_release", (self.folder / "nowhere",), (str(self.folder / "nowhere"),))

    def test_client_stamps(self):
        rng = random.Random(3)
        pieces = ["PROTOCOL = %s\n", "PROTOCOL=\"%s\"\n", "PROTOCOL_MIN = %s\n", "  PROTOCOL = %s\n", "PROTOCOL\t=\t%s\r\n", "PROTOCOL %s\n",
                  "# PROTOCOL = %s\n", "PROTOCOL = '%s'\n"]
        values = ["3", "2", "1", "03", "x", "", "3 ", "\u0663", "9" * 40, "3.0", "-3", "+3", "\u00b2"]
        releases = [hydra.RELEASE, "12.3-hydra.5", "", hydra.RELEASE + " "]
        versions = [hydra.CLIENT_VERSION, "1.0.0", "", "'1.1.0'"]
        cases = 0
        for _ in range(400):
            text = ""
            for _ in range(rng.randrange(0, 4)):
                text += rng.choice(pieces) % rng.choice(values)
            if rng.random() < 0.8:
                text += "CLIENT_VERSION = \"%s\"\n" % rng.choice(versions)
            if rng.random() < 0.8:
                text += rng.choice(["HYDRA_RELEASE = \"%s\"\n", "HYDRA_RELEASE=%s\r\n", "HYDRA_RELEASE = '%s'\n"]) % rng.choice(releases)
            for allow in (False, True):
                file = self.folder / ("lib%d.py" % cases)
                cases += 1
                file.write_bytes(text.encode("utf-8"))
                self.check(hydra._client_stamps, "client_stamps", (file, allow), (str(file), str(file), allow, *self.pins()), label=repr(text))
        broken = self.folder / "broken.py"
        broken.write_bytes(b"PROTOCOL = 3\nCLIENT_VERSION = \"\xff\"\nHYDRA_RELEASE = \"" + hydra.RELEASE.encode() + b"\"\n")
        self.check(hydra._client_stamps, "client_stamps", (broken, False), (str(broken), str(broken), False, *self.pins()))

    def test_daemon_config_of_random_settings(self):
        rng = random.Random(5)
        root = Path(self.folder) / "root"
        for index in range(500):
            settings = {"root": str(root)}
            for key, choices in (("hydra_idle_s", [None, 60, "90", 5.5, True, "x", 10**30, -1, []]),
                                 ("hydra_keep_warm_s", [None, 5, "7", 1.9, "", {}]),
                                 ("java_home", [None, "C:\\jdk", "", 7, 0, False, "ação"]),
                                 ("hydra_max_heap", [None, "8G", "", 8, False]),
                                 ("expected_agents", [None, 1, 2, 10, 11, 16, 40, 256, 257, 0, -1, True, "16", 1.5, [], 10**30]),
                                 ("hydra", [None, {}, {"maxLong": 5, "maxQuick": 7, "other": 1}, {"maxImports": 3, "forkCopyLimitMb": 9}, [], "x", {"maxLong": None}])):
                if rng.random() < 0.5:
                    value = rng.choice(choices)
                    if value is not None or rng.random() < 0.3:
                        settings[key] = value
            want = python(hydra.daemon_config, settings)
            got = rust("daemon_config", settings, str(hydra.root_path(settings)))
            self.same(want, got, "case %d: %r" % (index, settings))
            if want[0] == "ok" and got[0] == "ok":
                self.assertEqual(list(got[1]), list(want[1]), "key order")


# ---- api --------------------------------------------------------------------------------------------------------

@skip_unbuilt
class CatalogParity(Parity):
    def test_hash_table_instructions_and_not_available(self):
        original_hash = original(api.catalog_hash)
        original_table = original(api.tool_table)
        self.assertEqual(native.engine_catalog_hash_rs(), original_hash())
        self.assertEqual(json.loads(native.engine_tool_table_rs()), original_table())
        self.assertEqual(list(json.loads(native.engine_tool_table_rs())[0]["inputSchema"]["properties"]),
                         list(original_table()[0]["inputSchema"]["properties"]), "property order")
        self.assertEqual(native.engine_instructions_rs(api.__version__), original(api.instructions)())
        for detail in ({}, {"tool": "job", "options": ["a", "b"]}, {"op": "list", "later": "now", "catalog": 1}, {"text": "a\u00e7\u00e3o \U0001F600"}):
            for message in ("m", "a\u00e7\u00e3o", ""):
                want = python(api.not_available, "doctor", message, **detail)
                got = rust("not_available", "doctor", message, detail, api.CATALOG_EPOCH, original_hash())
                self.same(want, got, repr(detail))
        self.assertEqual(api.catalog_hash(), original_hash())

    def test_every_tool_table_the_python_hash_accepts_hashes_the_same(self):
        table = original(api.tool_table)()
        rng = random.Random(1)
        for _ in range(20):
            altered = json.loads(json.dumps(table))
            altered[rng.randrange(len(altered))]["description"] = rng.choice(WORDS) + str(rng.random())
            self.assertNotEqual(original(api.catalog_hash)(altered), original(api.catalog_hash)(table))


@skip_unbuilt
class CallParity(Parity):
    def test_the_checks_before_a_tool_runs(self):
        rng = random.Random(9)
        names = list(api.TOOL_NAMES) + list(api.CLI_ONLY) + ["nope", "", "Fingerprint"]
        values = [None, 0, 1, 40, 200, 201, 65536, 65537, -1, True, False, 1.9, 0.5, "7", "x", "", " 8 ", [], {}, "1_0", 10**30, 2.5e30]
        for index in range(1500):
            args = rng.choice([None, {}, [], "x", 3] + [{key: rng.choice(values) for key in rng.sample(["limit", "count", "size", "other"], rng.randrange(0, 4))}
                                                       for _ in range(6)])
            name = rng.choice(names)
            want = python(api._check_call, name, args)
            sub = {key: args[key] for key in ("limit", "count", "size") if key in args} if isinstance(args, dict) else args
            got = rust("validate_call", name, sub)
            if got[0] == "ok":
                got = ("ok", args or {})
            self.same(want, got, "case %d: %r %r" % (index, name, args))
        self.assertEqual(python(api._check_call, 5, {}), ("err", "ValueError", "unknown tool 5"))
        self.assertEqual(rust("validate_call", 5, {}), ("fallback",))

    def test_hex_bytes(self):
        rng = random.Random(2)
        for size in (0, 1, 2, 3, 31, 32, 255, 4096, 65536):
            data = bytes(rng.randrange(256) for _ in range(size))
            self.assertEqual(native.engine_hex_bytes_rs(data), original(api._hex)(data))

    def test_job_listing(self):
        rng = random.Random(4)
        for index in range(300):
            records = []
            for _ in range(rng.randrange(0, 30)):
                record = {}
                for key in ("id", "job_id", "kind", "state", "created_at", "started_at", "owner", "log_path", "extra", "elapsed_s", "complete"):
                    if rng.random() < 0.5:
                        if key in ("created_at", "started_at"):
                            record[key] = rng.choice([1, 2, 3, 1.5, 2.5, 3, 1_700_000_000.25, True, 0])
                        else:
                            record[key] = rng.choice(WORDS + [1, None, {"client": "c"}, [1, 2]])
                records.append(record)
            limit = rng.choice([1, 5, 20, 100])
            want = python(api._job_listing, [dict(r) for r in records], limit)
            got = rust("job_listing", records, limit)
            self.same(want, got, "case %d" % index)
        odd = [{"created_at": None}, {"id": 1}]
        self.same(python(api._job_listing, odd, 5), rust("job_listing", odd, 5))
        mixed = [{"created_at": "2026"}, {"id": 1}]
        self.same(python(api._job_listing, mixed, 5), rust("job_listing", mixed, 5))

    def test_prologue_arguments_and_the_export_path(self):
        for value in ("a" * 64, "A" * 64, "g" * 64, "a" * 63, "a" * 65, "", None, 5, "a" * 64 + "\n", "\u0661" * 64, "aB" * 32):
            self.same(python(api._sha256_arg, value), rust("prologue_sha256", value), repr(value))
        for value in ("0x140000000", "5368709120", " 0x10 ", "0b101", "0o17", "1_000", "0x", "", "base", "0x_ff", "00", "012", -5, 7, "1.5", "-0x10",
                      "\u0663", "it's", "a\\b"):
            want = python(api._image_base_arg, value)
            got = rust("prologue_image_base", value)
            if got[0] == "ok":
                got = ("ok", int(got[1]))
            self.same(want, got, repr(value))
        for path in ("C:\\a\\b.md", "C:/a/b.md", "C:\\a\\b.MD", "C:\\a\\.md", "C:\\a\\b.", "C:\\a\\b", "C:\\", "C:", "C:b.md", "\\a\\b.md", "a\\b.md",
                     "b.md", "", "C:\\a\\b.md\\", "C:\\a\\.\\b.md", "C:\\a\\..\\b.md", "C:\\a.b\\c", "D:\\x\\y.tar.md", "C:\\a\\b..md", "C:\\a\\.hidden.md",
                     "c:/A/B.md", "C:\\a b\\c d.md", "C:\\a\\b.md ", "C:\\a\\b.md.", "C:\\a\\md", "\\\\srv\\share\\x.md", "//srv/share/x.md", "C:\\a:b.md"):
            self.same(python(api._md_path, path), rust("export_path_ok", path), repr(path))

    def test_the_small_helpers(self):
        for job in ("export-1", "decompile-1", "overlay-1", "job-0123456789ab", "job-0123456789AB", "job-0123456789a", "job-0123456789ab\n", "x", "", "job-"):
            self.assertEqual(rust("script_job_id_ok", job)[1], bool(__import__("re").fullmatch(r"job-[0-9a-f]{12}", job)), repr(job))
        for value in (None, "a b\tc", " ", "", ["x", 1], {"a": 1}, 5, "a\x1cb", "caf\u00e9\u00a0x"):
            self.same(python(api._list, value), rust("list_of", value), repr(value))
        for args in ({}, {"options": None}, {"options": {"a": 1}}, {"options": []}, {"options": "x"}, {"options": {}}):
            self.same(python(api._options_bag, args), rust("options_bag", args), repr(args))
        for options in (None, {}, {"isolation": "private"}, {"isolation": "x"}, {"isolation": 3}, {"isolation": None}, {"readonly": True},
                        {"readonly": 1}, {"readonly": "yes"}, [1], "x", {"as": "me"}, {"isolation": [], "readonly": 5}):
            want = python(api._script_options, options)
            validation = want[0] == "err" and want[1] == "ValueError" and want[2].startswith(
                ("options must be", "ghidra_run options.isolation", "ghidra_run options.readonly"))
            if validation:
                expected = want
            else:
                # empty options run the script as before; anything else reaches the capability dispatch
                # (a registered handler may answer with an empty string, so the options themselves say whether it was reached)
                expected = ("ok", bool(options))
            self.same(expected, rust("script_options", options), repr(options))
        for options in ({}, {"op": "list"}, {"op": "verify"}, {"op": "remove"}, {"op": "x"}, {"op": None}, {"op": 3}):
            want = python(api._backend_action, "doctor", {}, {}) if False else None
            got = rust("backups_op", options)
            expected = options.get("op", "list")
            if expected in ("list", "verify", "remove"):
                self.assertEqual(got, ("ok", expected))
            else:
                self.assertEqual(got, ("err", "ValueError", "backups options.op must be list, verify or remove"))


# ---- the small leaf modules ---------------------------------------------------------------------------------------

DIGEST = "a" * 64


def address_map_text(rng, digest=DIGEST):
    if rng.random() < 0.5:  # a mostly valid map with a single oddity, so the accepted path is exercised too
        rows = [{"name": "n%d" % i, "hash": rng.choice(["0x%x" % (i * 3), "0X%X" % i]), "rva": rng.choice(["0x%x" % (i + 1), "rva:0x%x" % (i + 1)]),
                 "source": rng.choice(["s", "t"])} for i in range(rng.randrange(1, 6))]
        document = {"sha256": digest, "source": "fixture:%d" % rng.randrange(9), "entries": rows}
        if rng.random() < 0.3:
            rng.choice(rows)[rng.choice(["name", "hash", "rva", "source"])] = rng.choice(["", 5, "x" * 600, "0x", "caf" + chr(233), None, chr(0x1F600) * 3, "a" + chr(1) + "b", "d" + chr(127) + "e", "q" + chr(34) + "b" + chr(92) + "s"])
        return json.dumps(document, ensure_ascii=rng.random() < 0.5)
    rows = []
    for _ in range(rng.randrange(0, 6)):
        row = {}
        if rng.random() < 0.8:
            row["name"] = rng.choice(["a", "caf\u00e9", "n" * 512, "n" * 513, "", 5, "a\x00b"])
        if rng.random() < 0.6:
            row["hash"] = rng.choice(["0x00AB", "0xab", "", "0x" + "f" * 32, "0x" + "f" * 33, "0X1", "ab", "0x", 5, "0x1g", "0x0"])
        if rng.random() < 0.95:
            row["rva"] = rng.choice(["0x1234", "rva:0x1234", "va:0x1234", "0x123456789", "0x00ff", "1234", "rva:0x", 5, "0xABCDEF01"])
        if rng.random() < 0.3:
            row["source"] = rng.choice(["s", "", "  ", "x" * 4096, "x" * 4097, 3])
        if rng.random() < 0.05:
            row["extra"] = 1
        rows.append(row)
    document = {"sha256": rng.choice([digest, digest.upper(), "b" * 64, 5]), "source": rng.choice(["fixture:1", "", "   ", "x" * 4097, None, 3]),
                "entries": rows if rng.random() < 0.9 else rng.choice([[], "x", None, {}])}
    for key in list(document):
        if rng.random() < 0.05:
            del document[key]
    if rng.random() < 0.05:
        document["extra"] = 1
    return json.dumps(document, ensure_ascii=rng.random() < 0.5)


@skip_unbuilt
class LeafParity(Parity):
    def setUp(self):
        self.folder = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.folder, True)

    def test_address_map_normalisation(self):
        rng = random.Random(8)
        source = self.folder / "in.json"
        valid = 0
        for index in range(1500):
            text = address_map_text(rng)
            raw = text.encode("utf-8")
            if index % 50 == 0:
                raw = rng.choice([b"\xef\xbb\xbf" + raw, b"\xff\xfe" + raw, raw[: len(raw) // 2], b"", b"[]", b"null", b"{\"sha256\": NaN}"])
            want = python(address_maps._normalize, raw, DIGEST, source)
            if want[0] == "ok":
                valid += 1
                content_hash, count, make = want[1]
                want = ("ok", [content_hash, count, make()])
            found = None
            try:
                found = native.engine_address_map_rs(raw, DIGEST, str(source.resolve()))
                got = ("fallback",) if found is None else ("ok", [found[0], found[1], json.loads(found[2])])
            except Exception as exc:  # noqa: BLE001
                got = ("err", type(exc).__name__, str(exc))
            if want[0] == "ok" and got[0] == "ok":
                self.assertEqual(list(got[1][2]), list(want[1][2]), "record key order")
            self.same(want, got, "case %d: %r" % (index, text[:300]))
        self.assertGreater(valid, 30, "the generator must produce some valid maps")

    def test_a_record_past_32_mib_is_refused_the_same_way(self):
        name = chr(0x1F600) * 20
        rows = [{"name": name, "hash": "0x%x" % i, "rva": "0x10", "source": "s"} for i in range(address_maps.MAX_ROWS)]
        raw = json.dumps({"sha256": DIGEST, "source": "bulk", "entries": rows}, ensure_ascii=False).encode()
        self.assertLess(len(raw), address_maps.MAX_BYTES)
        source = self.folder / "emoji.json"
        want = python(address_maps._normalize, raw, DIGEST, source)
        try:
            found = native.engine_address_map_rs(raw, DIGEST, str(source.resolve()))
            got = ("fallback",) if found is None else ("ok", found)
        except Exception as exc:  # noqa: BLE001
            got = ("err", type(exc).__name__, str(exc))
        self.assertEqual(want, ("err", "ValueError", "normalized address map exceeds 32 MiB"))
        self.assertEqual(got, want)

    def test_a_large_map_normalises_to_the_same_record(self):
        rows = [{"name": "n%d" % i, "hash": "0x%x" % (i * 7), "rva": "rva:0x%x" % (i % 65535), "source": "s%d" % (i % 9)} for i in range(20000)]
        raw = json.dumps({"sha256": DIGEST, "source": "bulk", "entries": rows}).encode()
        source = self.folder / "big.json"
        content_hash, count, make = original(address_maps._normalize)(raw, DIGEST, source)
        found = native.engine_address_map_rs(raw, DIGEST, str(source.resolve()))
        self.assertEqual((found[0], found[1]), (content_hash, count))
        self.assertEqual(json.loads(found[2]), make())

    def test_red4ext_lookups(self):
        rng = random.Random(6)
        for index in range(60):
            lines = []
            if rng.random() < 0.7:
                lines.append('{"Code constant offset": "%x"}' % rng.choice([0x1000, 0x2000, 0]))
            for _ in range(rng.randrange(0, 40)):
                row = '{"hash": "%d"%s, "symbol": "%s", "offset": "%s:%x"}' % (
                    rng.randrange(0, 50), rng.choice(['', ', "secondary hash": "ab12"', ',\n "secondary hash": "ab"']),
                    rng.choice(["Alpha", "caf\u00e9", "", "q"]), rng.choice(["0001", "0002", "00ff"]), rng.randrange(0, 0x10000))
                if rng.random() < 0.15:
                    row = row.replace('"symbol": "%s", ' % "Alpha", "")
                if rng.random() < 0.1:
                    row = row.replace('"hash":', '"hash" :')
                if rng.random() < 0.3:  # a random edit: the hand-written row scanner must agree with the original's pattern on damaged rows
                    spot = rng.randrange(len(row))
                    row = rng.choice([row[:spot] + row[spot + 1:], row[:spot] + rng.choice([" ", "\t", "\n", "\x0b", "\x0c", '"', "{", "}", ":", ",", "a", "G", "9"]) + row[spot:]])
                lines.append(row)
            body = rng.choice(["\n", ",\n", " "]).join(lines).encode("utf-8")
            path = self.folder / ("t%d.json" % index)
            path.write_bytes(body)
            for chunk in (1, 5, 24, 100, 4096, 4 * 1024 * 1024):
                wanted = {rng.randrange(0, 50) for _ in range(5)}
                rvas = {rng.randrange(0x1000, 0x12000) for _ in range(40)}
                self.same(python(red4ext.lookup_hashes, path, wanted, chunk_size=chunk),
                          _red4ext("hash", path, wanted, chunk), "hashes %d chunk %d" % (index, chunk))
                self.same(python(red4ext.lookup_rvas, path, rvas, chunk_size=chunk), _red4ext("rva", path, rvas, chunk), "rvas")

    def test_integrity_scan(self):
        rng = random.Random(10)
        for index in range(40):
            project = self.folder / ("p%d" % index)
            project.mkdir()
            (project / "p.gpr").write_text("gpr")
            for rep in rng.sample(["a.rep", "B.rep", "c.REP", "d.repx", "e"], rng.randrange(0, 4)):
                for group in rng.sample(["idata", "user"], rng.randrange(0, 3)):
                    for bucket in rng.sample(["00", "01", "ff"], rng.randrange(0, 3)):
                        for number in rng.sample(range(0, 4), rng.randrange(0, 3)):
                            database = project / rep / group / bucket / ("~%08x.db" % number)
                            database.mkdir(parents=True, exist_ok=True)
                            for version in rng.sample([1, 2, 3, 10, 11, 100], rng.randrange(0, 4)):
                                data = rng.choice([integrity.GBF_MAGIC, b"\x00" * 8, b"/01", b"", integrity.GBF_MAGIC + b"x"])
                                (database / ("db.%d.gbf" % version)).write_bytes(data)
                            if rng.random() < 0.2:
                                (database / "db.1.gbf.tmp").write_bytes(b"x")
                            if rng.random() < 0.2:
                                (database / "db.007.gbf").write_bytes(integrity.GBF_MAGIC)
                        if rng.random() < 0.1:
                            (project / rep / group / bucket).mkdir(parents=True, exist_ok=True)
                            (project / rep / group / bucket / "~stray.db").write_bytes(b"x")
            want = python(integrity.scan, project / "p.gpr")
            got = rust("integrity_scan", str(project))
            self.same(want, got, "project %d" % index)

    def test_job_owner_check(self):
        def token_hash(token):
            import hashlib
            return hashlib.sha256(token.encode()).hexdigest()
        records = [{"id": "overlay-1"}, {"id": "x", "owner": {"client": "c", "harness": "h", "token_sha256": token_hash("t")}},
                   {"job_id": "j", "id": "i", "owner": {"token_sha256": token_hash("t")}}, {"owner": {"token_sha256": token_hash("t")}},
                   {"id": "x", "owner": {"token_sha256": ""}}, {"id": "x", "owner": "text"}, {"id": "x", "owner": {"client": 5, "token_sha256": "ab"}},
                   {"id": 7, "owner": {"token_sha256": "ab"}}, {"id": "x", "owner": {"token_sha256": "\u00e9"}}, {"id": "x", "owner": {"token_sha256": 5}}]
        for record in records:
            for token in ("", "t", "u"):
                for remembered in ("", "t", "u"):
                    jobowner._TOKENS.clear()
                    if remembered:
                        jobowner._TOKENS[jobowner._id(record)] = remembered
                    want = python(jobowner.check, record, token)
                    got = rust("owner_check", record, token, remembered)
                    if got[0] == "ok":
                        got = ("ok", None)
                    self.same(want, got, "%r %r %r" % (record, token, remembered))
        jobowner._TOKENS.clear()

    def test_forbidden_drives_and_dot_components(self):
        from hydralysis import compat, paths
        for setting in (ABSENT, None, "", "c:", "c:;d:\\ , e:/", ["c:", " d:\\"], [], ["c:", 1], 5, {"a": 1}, "  ", ",,;", ["", " "], ["\u00e9:"]):
            for env in ("", "x:;y:", " "):
                settings = {} if setting is ABSENT else {"forbidden_drives": setting}
                os.environ["HYDRALYSIS_FORBIDDEN_DRIVES"] = env
                try:
                    want = python(paths.forbidden_drives, settings)
                finally:
                    del os.environ["HYDRALYSIS_FORBIDDEN_DRIVES"]
                self.same(want, rust("forbidden_drives", None if setting is ABSENT else setting, env), "%r %r" % (setting, env))
        for path in ("C:\\a\\b", "C:\\a\\.b\\c", "C:\\.hidden", "\\\\srv\\share\\.x", "C:/a/.b", "C:\\a.b\\c"):
            parts = Path(path).parts
            self.assertEqual(rust("dot_component", path)[1], any(part.startswith(".") for part in parts), path)
        self.assertTrue(compat is not None)

    def test_bounded_shared_reads(self):
        target = self.folder / "metadata.bin"
        for size in (0, 1, 5, 6, 100):
            target.write_bytes(b"x" * size)
            for budget in (1, 5, 6, 100, 101, localio.DEFAULT_MAX_BYTES):
                want = python(localio.read_bytes, target, max_bytes=budget)
                try:
                    data = native.engine_read_bytes_rs(str(target), budget)
                    got = ("fallback",) if data is None else ("ok", data)
                except Exception as exc:  # noqa: BLE001
                    got = ("err", type(exc).__name__, str(exc))
                self.same(want, got, "size %d budget %d" % (size, budget))
        self.assertIsNone(native.engine_read_bytes_rs(str(self.folder / "missing"), 10))


def _red4ext(kind, path, wanted, chunk):
    try:
        found = native.engine_red4ext_rs(kind, str(path), [str(item) for item in wanted], chunk)
    except Exception as exc:  # noqa: BLE001
        return ("err", type(exc).__name__, str(exc))
    return ("fallback",) if found is None else ("ok", found)


@skip_unbuilt
class AddressParity(Parity):
    def test_parse_address(self):
        base = 0x140000000
        from hydralysis import pe
        for text in ("name:main", " hash:0x12 ", "rva:0x1000", "va:0x140001000", "va:0x1000", "0x1000", "0x140001000", " 4096 ", "seg:1", "", ":",
                     "rva:", "rva:-1", "-5", "0x", "1_000", "0b11", "0o7", "0x_1", "RVA:0X10", "Va:0x140000010", "1e3", "\u0663"):
            want = python(pe.parse_rva, text.strip(), base) if not text.strip().startswith(("name:", "hash:")) else ("mapped",)
            got = rust("parse_address", text, base)
            if got[0] == "fallback":
                self.declined += 1
                continue
            if want == ("mapped",):
                self.assertEqual(got, ("ok", {"mapped": True}))
            elif want[0] == "ok":
                self.assertEqual(got[0], "ok", text)
                self.assertEqual(got[1]["rva"], want[1])
                if ":" not in text.strip():
                    self.assertEqual(int(got[1]["bare"]), int(text.strip(), 0))
                else:
                    self.assertIsNone(got[1]["bare"])
            else:
                self.assertEqual(got, want, text)
            self.answered += 1


if __name__ == "__main__":
    unittest.main()
