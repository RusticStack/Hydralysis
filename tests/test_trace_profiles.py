"""The trace profile SDK: loading, validation, build-bound hook verification and query modules."""

import hashlib
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "fixtures"))
from support import workdir
from test_pe import image as make_image

from hydralysis import profiles
from hydralysis.profiles import HookRefused, ProfileError

TEXT = b"\x55\x8b\xec\x83\xec\x10" + b"\x90" * 10 + b"\x40\x53\x48\x83\xec\x20" + b"\x90" * 9 + b"\xc3"


def pe(text=TEXT, exports=None):
    img = make_image(text)
    img.export_rva = lambda symbol: (exports or {}).get(symbol)
    return img


def manifest(sha, *, extra="", optional_prologue="55 8B EC 83 EC 10", required_prologue="55 8B EC 83 EC ??"):
    return f"""
[profile]
id = "test-app/1"
[target]
bitness = 32
modules = ["main.exe"]
[[target.builds]]
module = "main.exe"
image_sha256 = "{sha}"
[[event_kinds]]
name = "app.feature"
extends = "core.state.write"
[event_kinds.payload]
feature = "key"
on = "bool?"
[[hooks]]
id = "gate"
event = "app.feature"
symbol = "Gate"
required = true
prologue = "{required_prologue}"
[[hooks]]
id = "open"
event = "core.resource.open"
rva = "0x1000"
required = false
prologue = "{optional_prologue}"
[[hooks]]
id = "sig"
event = "core.function.enter"
signature = "40 53 48"
required = false
prologue = "40 53 48 83 EC ??"
[diff]
group_by = ["kind", "function"]
{extra}
"""


def sha_of(img):
    return img.fingerprint()["sha256"]


class Loading(unittest.TestCase):
    def test_baseline_loads_and_records_its_hash(self):
        profile = profiles.load_baseline()
        self.assertEqual(profile.id, "fixtures-baseline/1")
        self.assertTrue(profile.data["target"]["fixtures_only"])
        self.assertEqual(len(profile.sha256), 64)
        self.assertEqual(list(profile.files), ["baseline_fixtures.toml"])
        self.assertEqual(profile.sha256, profiles.load_baseline().sha256)
        self.assertIn("app.feature", profile.kind_names())
        self.assertEqual(profile.session_record()["fixtures_only"], True)

    def test_a_changed_byte_changes_the_session_hash(self):
        text = profiles.BASELINE.read_text("utf-8")
        other = profiles.load_text(text.replace("limit = 50", "limit = 51"), directory=None)
        self.assertNotEqual(other.sha256, profiles.load_baseline().sha256)

    def test_a_profile_without_builds_is_refused_unless_fixtures_only(self):
        text = profiles.BASELINE.read_text("utf-8").replace("fixtures_only = true", "fixtures_only = false")
        with self.assertRaises(ProfileError) as caught:
            profiles.load_text(text)
        self.assertTrue(any("build-bound" in e for e in caught.exception.errors))

    def test_every_problem_is_listed_not_just_the_first(self):
        text = """
[profile]
id = "Bad Id"
[target]
bitness = 16
modules = []
[[hooks]]
id = "h"
event = "nope.kind"
symbol = "a"
rva = "0x10"
prologue = "ZZ"
[diff]
group_by = ["colour"]
"""
        with self.assertRaises(ProfileError) as caught:
            profiles.load_text(text)
        joined = " | ".join(caught.exception.errors)
        for word in ("profile.id", "target.bitness", "target.modules", "hooks[0].event", "exactly one of", "hooks[0].prologue", "diff.group_by"):
            self.assertIn(word, joined)

    def test_unknown_keys_and_sections_are_refused(self):
        with self.assertRaises(ProfileError):
            profiles.load_text(profiles.BASELINE.read_text("utf-8") + "\n[surprise]\nx = 1\n")
        with self.assertRaises(ProfileError):
            profiles.load_text(profiles.BASELINE.read_text("utf-8").replace('kind = "frame"', 'kind = "frame"\ncolour = "red"'))

    def test_references_must_resolve(self):
        text = profiles.BASELINE.read_text("utf-8").replace('value = "frame-begin"', 'value = "no-such-hook"')
        with self.assertRaises(ProfileError) as caught:
            profiles.load_text(text)
        self.assertTrue(any("roles[0].value" in e for e in caught.exception.errors))
        text = profiles.BASELINE.read_text("utf-8").replace('state = "profile_object_offset"', 'state = "mystery"')
        with self.assertRaises(ProfileError):
            profiles.load_text(text)

    def test_an_rva_hook_needs_a_listed_build(self):
        text = """
[profile]
id = "x/1"
[target]
bitness = 64
modules = ["a.exe"]
fixtures_only = true
[[hooks]]
id = "h"
event = "core.marker"
rva = "0x1000"
prologue = "55"
"""
        with self.assertRaises(ProfileError) as caught:
            profiles.load_text(text)
        self.assertTrue(any("build-bound" in e for e in caught.exception.errors))

    def test_not_toml_is_its_own_error(self):
        with self.assertRaises(ProfileError) as caught:
            profiles.load_text("[[[")
        self.assertEqual(caught.exception.code, "profile_unreadable")


class Codecs(unittest.TestCase):
    def codec(self, vectors):
        return profiles.load_text(profiles.BASELINE.read_text("utf-8") + f"""
[[codecs]]
id = "names64"
base = "fnv1a"
bits = 64
vectors = {vectors}
applies_to = ["app.feature.payload.feature"]
""")

    def test_a_codec_is_accepted_only_with_vectors_it_reproduces(self):
        ok = self.codec('[{input = "a", output = "0xaf63dc4c8601ec8c"}]')
        self.assertEqual(ok.data["codecs"][0]["id"], "names64")
        with self.assertRaises(ProfileError) as caught:
            self.codec('[{input = "a", output = "0x1"}]')
        self.assertIn("hashes to", " ".join(caught.exception.errors))
        with self.assertRaises(ProfileError):
            self.codec("[]")

    def test_a_layout_codec_records_a_schema_hash(self):
        profile = profiles.load_text(profiles.BASELINE.read_text("utf-8") + """
[[codecs]]
id = "msg"
base = "layout"
fields = [{name = "id", offset = 0, type = "u32"}, {name = "len", offset = 4, type = "u32"}]
""")
        self.assertEqual(len(profile.data["codecs"][0]["schema_sha256"]), 64)


class Verification(unittest.TestCase):
    def verify(self, img, **kwargs):
        profile = profiles.load_text(manifest(sha_of(img), **kwargs))
        return profile, profiles.verify_profile(profile, {"main.exe": img})

    def test_a_matching_build_verifies_every_hook(self):
        img = pe(exports={"Gate": 0x1000})
        profile, result = self.verify(img)
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["counts"], {"verified": 3, "refused_required": 0, "refused_optional": 0})
        self.assertEqual({row["hook"]: row["rva"] for row in result["hooks"]},
                         {"gate": "rva:0x1000", "open": "rva:0x1000", "sig": "rva:0x1010"})
        profiles.require(result)

    def test_a_tampered_required_prologue_is_refused(self):
        tampered = bytearray(TEXT)
        tampered[3] = 0x84  # the bytes are no longer the profile's prologue
        img = pe(bytes(tampered), exports={"Gate": 0x1000})
        profile = profiles.load_text(manifest(sha_of(img)))
        result = profiles.verify_profile(profile, {"main.exe": img})
        self.assertFalse(result["ok"])
        self.assertEqual([r["hook"] for r in result["refusals"]], ["gate"])
        self.assertEqual(result["refusals"][0]["reason"], "prologue-mismatch")
        gate = next(row for row in result["hooks"] if row["hook"] == "gate")
        self.assertEqual((gate["status"], gate["actual"][:11]), ("refused", "55 8B EC 84"))
        self.assertNotIn("gate", result["enabled"])
        with self.assertRaises(HookRefused) as caught:
            profiles.require(result)
        self.assertEqual(caught.exception.code, "required_hook_refused")
        self.assertEqual(caught.exception.payload()["refusals"][0]["hook"], "gate")

    def test_an_optional_refusal_is_a_coverage_limitation_not_a_failure(self):
        img = pe(exports={"Gate": 0x1000})
        profile, result = self.verify(img, optional_prologue="55 8B EC 83 EC 11")
        self.assertTrue(result["ok"])
        self.assertEqual(result["limitations"], [{"code": "optional-hook-refused", "hook": "open",
                                                  "event": "core.resource.open", "reason": "prologue-mismatch"}])
        self.assertEqual(result["counts"]["refused_optional"], 1)
        open_row = next(row for row in result["hooks"] if row["hook"] == "open")
        self.assertEqual(open_row["status"], "refused")
        self.assertNotIn("open", result["enabled"])

    def test_the_limitation_code_is_a_trace_limitation(self):
        from hydralysis import trace
        self.assertIn("optional-hook-refused", trace.LIMITATIONS)

    def test_another_build_refuses_everything_bound_to_the_first(self):
        img = pe(exports={"Gate": 0x1000})
        profile = profiles.load_text(manifest("0" * 64))
        result = profiles.verify_profile(profile, {"main.exe": img})
        self.assertFalse(result["ok"])
        self.assertEqual({r["reason"] for r in result["refusals"]}, {"build-not-listed"})
        self.assertEqual({lim["reason"] for lim in result["limitations"]}, {"build-not-listed"})
        self.assertEqual(result["enabled"], [])

    def test_wrong_bitness_and_missing_module(self):
        img = pe(exports={"Gate": 0x1000})
        profile = profiles.load_text(manifest(sha_of(img)))
        img.bits = 64
        self.assertEqual(profiles.verify_profile(profile, {"main.exe": img})["refusals"][0]["reason"], "bitness-mismatch")
        self.assertEqual(profiles.verify_profile(profile, {})["refusals"][0]["reason"], "module-unknown")

    def test_symbol_and_signature_failures_have_their_own_reasons(self):
        img = pe(exports={})
        result = profiles.verify_profile(profiles.load_text(manifest(sha_of(img))), {"main.exe": img})
        self.assertEqual(result["refusals"][0]["reason"], "symbol-not-found")
        twice = pe(TEXT[:16] + TEXT[16:22] + TEXT[16:22] + b"\x90" * 10, exports={"Gate": 0x1000})
        profile = profiles.load_text(manifest(sha_of(twice)))
        sig = next(row for row in profiles.verify_profile(profile, {"main.exe": twice})["hooks"] if row["hook"] == "sig")
        self.assertEqual((sig["status"], sig["reason"]), ("refused", "signature-ambiguous"))
        gone = pe(b"\x90" * 32, exports={"Gate": 0x1000})
        again = profiles.verify_profile(profiles.load_text(manifest(sha_of(gone))), {"main.exe": gone})
        sig = next(row for row in again["hooks"] if row["hook"] == "sig")
        self.assertEqual(sig["reason"], "signature-not-found")


class Queries(unittest.TestCase):
    def test_a_declarative_query_compiles_to_an_engine_request(self):
        profile = profiles.load_baseline()
        request = profiles.compile_query(profile, "app.registry.consumers", session="s1")
        self.assertEqual(request, {"session": "s1", "kinds": ["core.resource.open"], "filter": {},
                                   "group_by": ["resource.key", "function"], "limit": 50})
        self.assertEqual(profiles.compile_query(profile, "app.registry.consumers", session="s1", limit=500)["limit"], 200)
        with self.assertRaises(profiles.QueryModuleError):
            profiles.compile_query(profile, "nope", session="s1")

    def module_profile(self, folder, source, digest=None):
        directory = Path(folder)
        (directory / "q.py").write_bytes(source.encode("utf-8"))
        sha = digest or hashlib.sha256(source.encode()).hexdigest()
        (directory / "profile.toml").write_text(profiles.BASELINE.read_text("utf-8") + f"""
[[queries]]
id = "app.top"
module = "q.py"
sha256 = "{sha}"
""", "utf-8")
        return profiles.load_file(directory / "profile.toml")

    def test_a_pinned_module_runs_contained_over_rows(self):
        with workdir("prof-q") as folder:
            profile = self.module_profile(folder, "def query(rows, params):\n    return {'n': len(rows), 'top': params.get('k')}\n")
            self.assertIn("q.py", profile.files)
            self.assertEqual(profiles.run_module(profile, "app.top", [{"a": 1}, {"a": 2}], {"k": "x"}), {"n": 2, "top": "x"})

    def test_a_changed_module_is_not_run(self):
        with workdir("prof-q") as folder:
            profile = self.module_profile(folder, "def query(rows, params):\n    return {}\n")
            (Path(folder) / "q.py").write_text("def query(rows, params):\n    return {'evil': 1}\n", "utf-8")
            with self.assertRaises(profiles.QueryModuleError) as caught:
                profiles.run_module(profile, "app.top", [])
            self.assertEqual(caught.exception.code, "module_changed")

    def test_a_wrong_pin_refuses_the_profile(self):
        with workdir("prof-q") as folder:
            with self.assertRaises(ProfileError):
                self.module_profile(folder, "def query(rows, params):\n    return {}\n", digest="0" * 64)

    def test_a_module_that_fails_or_hangs_or_floods_is_stopped(self):
        cases = (("def query(rows, params):\n    raise RuntimeError('boom')\n", {}, "module_failed"),
                 ("import time\ndef query(rows, params):\n    time.sleep(30)\n", {"timeout_s": 1}, "module_timeout"),
                 ("def query(rows, params):\n    return {'x': 'a' * 2000000}\n", {}, "output_too_large"))
        for source, kwargs, code in cases:
            with workdir("prof-q") as folder:
                profile = self.module_profile(folder, source)
                with self.assertRaises(profiles.QueryModuleError) as caught:
                    profiles.run_module(profile, "app.top", [], **kwargs)
                self.assertEqual(caught.exception.code, code)

    def test_a_module_cannot_escape_the_profile_folder(self):
        with workdir("prof-q") as folder:
            (Path(folder) / "profile.toml").write_text(profiles.BASELINE.read_text("utf-8") + """
[[queries]]
id = "app.out"
module = "../q.py"
sha256 = "%s"
""" % ("0" * 64), "utf-8")
            with self.assertRaises(ProfileError):
                profiles.load_file(Path(folder) / "profile.toml")

    def test_a_manifest_text_cannot_carry_modules(self):
        text = profiles.BASELINE.read_text("utf-8") + '\n[[queries]]\nid = "a.b"\nmodule = "q.py"\nsha256 = "%s"\n' % ("0" * 64)
        with self.assertRaises(ProfileError):
            profiles.load_text(text)


FIXTURE_GROUPS = ("trace_app", "frameloop", "interleave", "veh_freeze", "deadlock", "persist")


class BaselineAgainstTheRealFixtures(unittest.TestCase):
    """The shipped baseline names real functions and real prologues of the built fixture images (not stand-ins)."""

    @classmethod
    def setUpClass(cls):
        import trace_fixtures
        if not trace_fixtures.msvc_available():
            raise unittest.SkipTest("MSVC build tools are not installed")
        cls.dirs = workdir("baseline-fx")
        cls.root = Path(cls.dirs.__enter__())
        cls.manifest = {}
        for group in FIXTURE_GROUPS:
            built = trace_fixtures.build_group(group, cls.root, ("x64",))["x64"]
            cls.manifest.update(built["manifest"])
        cls.dir = cls.root / "x64"

    @classmethod
    def tearDownClass(cls):
        cls.dirs.__exit__(None, None, None)

    def images(self, folder=None):
        from hydralysis.pe import Image
        folder = Path(folder or self.dir)
        return {name: Image(folder / name) for name in ("trace_app.exe", "frameloop.exe", "interleave.exe", "veh_freeze.exe",
                                                        "deadlock.exe", "persist.exe")}

    def test_every_hook_names_a_real_function_and_verifies(self):
        profile = profiles.load_baseline()
        result = profiles.verify_profile(profile, self.images())
        self.assertTrue(result["ok"], result["refusals"])
        self.assertEqual(result["counts"]["verified"], len(profile.data["hooks"]))
        self.assertEqual(result["limitations"], [])
        for hook in profile.data["hooks"]:
            self.assertIn(hook["symbol"], self.manifest[hook["module"]]["functions"], hook["id"])

    def test_the_fixture_functions_are_internal_not_exports(self):
        # which is why a fixtures-only profile reads the linker map: the images export none of the hooked functions
        from hydralysis.pe import Image, pefile
        image = Image(self.dir / "frameloop.exe")
        image.pe.parse_data_directories(directories=[pefile().DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        exported = {item.name.decode() for item in image.pe.DIRECTORY_ENTRY_EXPORT.symbols if item.name}
        self.assertEqual(exported, {"g_entity"})

    def test_a_run_supplies_only_its_images_and_the_other_sections_are_not_applicable(self):
        images = {"frameloop.exe": self.images()["frameloop.exe"]}
        result = profiles.verify_profile(profiles.load_baseline(), images)
        self.assertTrue(result["ok"])
        states = {row["hook"]: row["status"] for row in result["hooks"]}
        self.assertEqual(states["frame-begin"], "verified")
        self.assertEqual(states["file-write"], "not-applicable")
        self.assertEqual(result["limitations"], [])

    def tampered(self, name, symbol, new_byte=0x90):
        import shutil
        folder = self.root / ("tampered-" + symbol)
        folder.mkdir(exist_ok=True)
        for suffix in (".exe", ".map"):
            shutil.copy2(self.dir / (name[:-4] + suffix), folder / (name[:-4] + suffix))
        from hydralysis.pe import Image
        image = Image(folder / name)
        rva = profiles.verify_profile(profiles.load_baseline(), {name: image})
        site = next(row["rva"] for row in rva["hooks"] if row.get("status") == "verified" and symbol in (
            profiles.load_baseline().hook(row["hook"]) or {}).get("symbol", ""))
        offset = image.rva_to_offset(int(site.removeprefix("rva:"), 16))
        data = bytearray((folder / name).read_bytes())
        data[offset] = new_byte
        (folder / name).write_bytes(bytes(data))
        return folder

    def test_a_tampered_prologue_of_a_required_hook_is_refused(self):
        folder = self.tampered("frameloop.exe", "fx_frame_begin")
        from hydralysis.pe import Image
        result = profiles.verify_profile(profiles.load_baseline(), {"frameloop.exe": Image(folder / "frameloop.exe")})
        self.assertFalse(result["ok"])
        self.assertEqual([(r["hook"], r["reason"]) for r in result["refusals"]], [("frame-begin", "prologue-mismatch")])
        with self.assertRaises(HookRefused):
            profiles.require(result)

    def test_a_tampered_optional_hook_is_a_coverage_limitation_not_a_failure(self):
        folder = self.tampered("frameloop.exe", "fx_job_callback")
        from hydralysis.pe import Image
        result = profiles.verify_profile(profiles.load_baseline(), {"frameloop.exe": Image(folder / "frameloop.exe")})
        self.assertTrue(result["ok"])
        self.assertEqual([(l["code"], l["hook"], l["reason"]) for l in result["limitations"]],
                         [("optional-hook-refused", "job-callback", "prologue-mismatch")])
        self.assertNotIn("job-callback", result["enabled"])

    def test_without_the_map_a_fixtures_hook_has_no_site(self):
        import shutil
        folder = self.root / "nomap"
        folder.mkdir(exist_ok=True)
        shutil.copy2(self.dir / "frameloop.exe", folder / "frameloop.exe")
        from hydralysis.pe import Image
        result = profiles.verify_profile(profiles.load_baseline(), {"frameloop.exe": Image(folder / "frameloop.exe")})
        self.assertEqual({r["reason"] for r in result["refusals"]}, {"symbol-not-found"})

    def test_a_non_fixtures_profile_never_reads_a_map(self):
        text = profiles.BASELINE.read_text("utf-8").replace("fixtures_only = true", "fixtures_only = false")
        builds = '[[target.builds]]\nmodule = "frameloop.exe"\nimage_sha256 = "%s"\n\n[[hooks]]' % ("0" * 64)
        text = text.replace("[[hooks]]", builds, 1)
        profile = profiles.load_text(text)
        result = profiles.verify_profile(profile, {"frameloop.exe": self.images()["frameloop.exe"]})
        self.assertIn("build-not-listed", {r["reason"] for r in result["refusals"]} | {r.get("reason") for r in result["hooks"]})


if __name__ == "__main__":
    unittest.main()
