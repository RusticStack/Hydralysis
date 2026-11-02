"""Smoke tests of the semantic-trace fixtures (12.3-hydra.6, docs/trace-fixtures.md).

Each fixture is built with MSVC for x64 and x86 (tests/fixtures/build_fixtures.py), run, and compared with the parts of its
expected-answer file (tests/fixtures/expected/<name>.json) that need no tracing: exit codes, stdout lines, files produced,
and that the functions and data the file names exist in the linker map. The tests skip only when MSVC is truly absent;
a build or run that fails with MSVC present is a failure. No tracing code is involved.
"""

from __future__ import annotations

import struct
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE / "fixtures"))

import gen_fnv_names  # noqa: E402
import trace_fixtures as tf  # noqa: E402
from support import workdir  # noqa: E402

MSVC = tf.msvc_available()


@unittest.skipUnless(MSVC, "MSVC build tools (vswhere) are not installed")
class FixtureCase(unittest.TestCase):
    """Builds one fixture group per class; subclasses name it in GROUP."""

    GROUP = ""

    @classmethod
    def setUpClass(cls):
        cls._build_root = workdir("trace-fx-" + cls.GROUP)
        cls.built = tf.build_group(cls.GROUP, Path(cls._build_root.name))
        cls.expected = tf.load_expected(cls.GROUP)

    @classmethod
    def tearDownClass(cls):
        cls._build_root.cleanup()

    def test_programs_match_expected_answers(self):
        """Every entry of the expected file on each architecture; a sequence shares one work dir."""
        for arch, built in self.built.items():
            shared = workdir("trace-run-" + self.GROUP) if "sequence" in self.expected else None
            for run in tf.runs_of(self.expected):
                with self.subTest(arch=arch, run=run["id"]):
                    if shared:
                        problems = tf.execute(run, built["dir"], Path(shared.name))
                    else:
                        with workdir("trace-run-" + self.GROUP) as name:
                            problems = tf.execute(run, built["dir"], Path(name))
                    self.assertEqual(problems, [])
            if shared:
                shared.cleanup()

    def test_named_functions_and_data_exist_in_the_map(self):
        for arch, built in self.built.items():
            functions, data = tf.functions_of(built)
            for role, name in self.expected.get("functions", {}).items():
                with self.subTest(arch=arch, role=role):
                    self.assertIn(name, functions)
            for role, name in self.expected.get("data", {}).items():
                with self.subTest(arch=arch, data=role):
                    self.assertIn(name, data)

    def test_expected_file_is_well_formed(self):
        self.assertEqual(self.expected["fixture"], self.GROUP)
        self.assertTrue(self.expected["answers"])
        for run in tf.runs_of(self.expected):
            for key in ("id", "program", "args", "max_seconds", "exit_code", "stdout_lines"):
                self.assertIn(key, run)


class TraceApp(FixtureCase):
    GROUP = "trace_app"

    def test_two_configs_differ_where_the_answers_say(self):
        outputs = {}
        for config in ("A", "B"):
            run = next(r for r in self.expected["runs"] if r["id"] == "config_" + config)
            with workdir("trace-app") as name:
                self.assertEqual(tf.execute(run, self.built["x64"]["dir"], Path(name)), [])
                outputs[config] = {p.name: p.read_bytes() for p in Path(name).iterdir() if p.is_file()}
        self.assertNotEqual(outputs["A"]["trace_app.cfg"], outputs["B"]["trace_app.cfg"])
        self.assertEqual(outputs["A"]["trace_app.data"], outputs["B"]["trace_app.data"])
        self.assertNotIn("trace_app.extra", outputs["A"])
        self.assertIn("trace_app.extra", outputs["B"])


class Interleave(FixtureCase):
    GROUP = "interleave"

    def test_answers_name_every_op_once(self):
        pools = self.expected["answers"]["pools"]
        ops = pools["P"]["ops"] + pools["Q"]["ops"]
        self.assertEqual(len(ops), len(set(ops)))
        self.assertEqual(self.expected["answers"]["missing_link"]["op"], 9999)


class Layouts(FixtureCase):
    GROUP = "layouts"

    def test_stream_decodes_with_an_independent_reader(self):
        answers = self.expected["answers"]
        stream = bytes.fromhex(answers["stream_hex"])
        offset, layout, seen = 0, 1, []
        while offset < len(stream):
            kind, length = struct.unpack_from("<HH", stream, offset)
            seen.append((kind, offset, length))
            if kind == 0xF0:
                layout = struct.unpack_from("<H", stream, offset + 4)[0]
            offset += length
        self.assertEqual(offset, len(stream))
        self.assertEqual(layout, 2)
        self.assertEqual([k for k, _o, _l in seen], [1, 1, 1, 0xF0, 2, 2, 2])
        self.assertEqual([m["offset"] for m in answers["messages"]], [o for _k, o, _l in seen])


class Frameloop(FixtureCase):
    GROUP = "frameloop"

    def test_longer_run_of_the_overhead_benchmark_shape(self):
        out = subprocess.run([str(self.built["x64"]["dir"] / "frameloop.exe"), "--frames=2000"], capture_output=True, text=True,
                             timeout=60).stdout.splitlines()
        self.assertIn("FX frames=2000", out)
        self.assertIn("FX verdicts survived=200 overwritten=1800 read_before_write=0", out)


class VehFreeze(FixtureCase):
    GROUP = "veh_freeze"


class VcallFixture(FixtureCase):
    GROUP = "vcall_fixture"

    def test_the_two_overloads_are_distinct_functions(self):
        for arch, built in self.built.items():
            functions = built["manifest"]["vcall_fixture.exe"]["functions"]
            self.assertNotEqual(functions["Counter::put"], functions["Counter::put!direct"], arch)


class Replica(FixtureCase):
    GROUP = "replica"

    def test_logs_show_the_delay_the_outage_and_the_owner_only_object(self):
        answers = self.expected["answers"]
        for arch, built in self.built.items():
            with self.subTest(arch=arch), workdir("trace-replica") as name:
                work = Path(name)
                self.assertEqual(tf.execute(self.expected["runs"][0], built["dir"], work), [])
                owner, replica = tf.read_jsonl(work / "owner.jsonl"), tf.read_jsonl(work / "replica.jsonl")
                # clock calibration from the three sync markers
                syncs = [r for r in replica if r["kind"] == "sync"]
                self.assertEqual(len(syncs), answers["clock"]["markers"])
                offsets = sorted(s["t_ms"] - s["owner_sent_ms"] for s in syncs)
                low, high = answers["clock"]["offset_range_ms"]
                self.assertTrue(low <= offsets[len(offsets) // 2] <= high, offsets)
                offset = offsets[0]
                # mirrors: exactly the sent ticks, each lagging its owner publication by about the injected delay
                mirrors = [r for r in replica if r["kind"] == "mirror"]
                self.assertEqual([m["seq"] for m in mirrors], answers["mirror_seqs_expected"])
                truth = {r["seq"]: r for r in owner if r["kind"] == "truth" and r["obj"] == 1}
                self.assertEqual(len(truth), 200)
                lags = sorted(m["t_ms"] - offset - truth[m["seq"]]["t_ms"] for m in mirrors)
                low, high = answers["delay_tolerance_ms"]
                self.assertTrue(low - 10 <= lags[len(lags) // 2] <= high + 40, lags[len(lags) // 2])
                for m in mirrors:
                    self.assertEqual(m["value"], truth[m["seq"]]["value"])
                # outage: no mirror for the outage ticks, extrapolated ticks cover it
                self.assertFalse([m for m in mirrors if 60 <= m["seq"] < 160])
                self.assertGreaterEqual(len([r for r in replica if r["kind"] == "extrapolated"]), answers["extrapolated_ticks_min"])
                # owner-only object
                self.assertEqual([r["obj"] for r in owner if r["kind"] == "create"], [2])
                self.assertFalse([r for r in replica if r.get("obj") == 2])


class FnvNames(FixtureCase):
    GROUP = "fnv_names"

    def test_hashes_in_the_answers_are_fnv1a64_and_the_pair_collides(self):
        answers = self.expected["answers"]
        for text, value in answers["algorithm"]["test_vector"].items():
            self.assertEqual("0x%016x" % gen_fnv_names.fnv1a64(text), value)
        hashes = set()
        for row in answers["records"]:
            self.assertEqual(int(row["hash"], 16), gen_fnv_names.fnv1a64(row["name"]))
            hashes.add(row["hash"])
        self.assertEqual(len(hashes), 64)
        a, b = answers["collision"]["names"]
        self.assertNotEqual(a, b)
        self.assertEqual(gen_fnv_names.fnv1a64(a), gen_fnv_names.fnv1a64(b))
        self.assertNotIn(answers["collision"]["hash"], hashes)

    def test_the_hash_constants_are_in_the_binary(self):
        for arch, built in self.built.items():
            data = (built["dir"] / "fnv_names.exe").read_bytes()
            for row in self.expected["answers"]["records"][:5] + [self.expected["answers"]["collision"]]:
                value = int(row["hash"], 16)
                if arch == "x64":
                    self.assertIn(struct.pack("<Q", value), data, (arch, row))
                else:
                    self.assertIn(struct.pack("<I", value & 0xFFFFFFFF), data, (arch, row))


class Minivm(FixtureCase):
    GROUP = "minivm"

    def test_twelve_natives_ten_from_the_table(self):
        natives = self.expected["answers"]["natives"]
        self.assertEqual(len(natives), 12)
        self.assertEqual(sum(n["registered_by"] == "table" for n in natives), 10)
        for arch, built in self.built.items():
            functions, _data = tf.functions_of(built)
            for native in natives:
                self.assertIn(native["native"], functions, arch)


class Persist(FixtureCase):
    GROUP = "persist"

    def test_the_intervention_changes_only_one_value(self):
        steps = {s["id"]: s for s in self.expected["sequence"]}
        before = bytes.fromhex(steps["save_with_intervention"]["files"]["persist_before.dat"]["hex"])
        after = bytes.fromhex(steps["save_with_intervention"]["files"]["persist_save.dat"]["hex"])
        changed = [i for i in range(len(before)) if before[i] != after[i]]
        self.assertEqual(changed, [self.expected["answers"]["intervention"]["record"]["byte_offset_of_value"]])


class Deadlock(FixtureCase):
    GROUP = "deadlock"


class DiffFixture(FixtureCase):
    GROUP = "diff_fixture"

    def test_builds_differ_by_the_documented_changes(self):
        for arch, built in self.built.items():
            one, two = built["manifest"]["diff1.exe"], built["manifest"]["diff2.exe"]
            self.assertNotEqual(one["sha256"], two["sha256"])
            self.assertIn("df_removed", one["functions"])
            self.assertNotIn("df_removed", two["functions"])
            self.assertIn("df_added", two["functions"])
            self.assertNotIn("df_added", one["functions"])
            for name in ("df_render", "df_mix", "df_decode_amount"):
                self.assertIn(name, one["functions"])
                self.assertIn(name, two["functions"])


class IoctlClient(FixtureCase):
    GROUP = "ioctl_client"


# The base class is abstract; keep unittest from collecting it as a test of its own.
del FixtureCase

if __name__ == "__main__":
    unittest.main()
