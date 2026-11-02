"""Python vs Rust on the export worker's pure parts and crossbuild.match (HYDRALYSIS_IMPL switch, same inputs)."""

import hashlib
import json
import os
import random
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import crossbuild, export_worker as ew

try:
    import hydralysis_native
    HAVE_NATIVE = hasattr(hydralysis_native, "crossbuild_match_rs")
except ImportError:
    HAVE_NATIVE = False


def outcome(function, *args, impl):
    with patch.dict(os.environ, {"HYDRALYSIS_IMPL": impl}):
        try:
            return ("ok", function(*args))
        except Exception as error:  # noqa: BLE001
            return (type(error).__name__, str(error))


BUILD = "b" * 64
PROV = {"sha256": BUILD, "version": 2, "gpr": "x"}


def row(key, **extra):
    c = extra.pop("c", "int f(){}")
    value = {"job": "export-0123456789ab", "build_sha256": BUILD, "mode": "decompile", "provenance": PROV, "key": key,
             "state": "done", "result": {"c": c}, "c_sha256": hashlib.sha256(c.encode()).hexdigest()}
    value.update(extra)
    return value


def lines(*rows):
    return b"".join(json.dumps(r).encode() + b"\n" for r in rows)


@unittest.skipUnless(HAVE_NATIVE, "native module not built")
class ExportReplay(unittest.TestCase):
    def check(self, content, completed_before=0, max_row=None):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            job = base / "job.json"
            out = base / "decompile.jsonl"
            if content is not None:
                out.write_bytes(content)
            (base / "imports.json").write_text(json.dumps({"build_sha256": BUILD, "state": "done", "imports": []}))
            record = {"id": "export-0123456789ab", "options": {"mode": "decompile"}, "output_path": str(out),
                      "provenance": PROV, "completed": completed_before}
            with patch.object(ew, "MAX_ROW_BYTES", max_row or ew.MAX_ROW_BYTES):
                python = outcome(ew.replay, job, record, impl="python")
                rust = outcome(ew.replay, job, record, impl="rust")
            self.assertEqual(python, rust, content)
            return python

    def test_cases(self):
        good = lines(row("a"), row("b", state="failed", result={"error": "x"}, c_sha256=hashlib.sha256(b"").hexdigest()),
                     row("c", truncated=True))
        cases = [
            None, b"", good, good + b'{"torn"', b"not json\n", b"[1]\n", lines(row("a"), row("a")),
            lines(row("a", job="other")), lines(row("a", build_sha256="c" * 64)), lines(row("a", mode="functions")),
            lines(row("a", provenance={"sha256": BUILD})), lines(row(1)), lines({**row("a"), "key": None}),
            lines(row("a", state="odd")), lines(row("a", result=None)), lines(row("a", c_sha256="0" * 64)),
            lines(row("a", c_sha256="Z")), lines({k: v for k, v in row("a").items() if k != "c_sha256"}),
            lines(row("a", state="failed", result={"error": "e"}, truncated=0)),
            lines(row("a", state="failed", result=None)), lines(row("a", c="é€𐍈 text")),
            lines(row("a", state="failed", result={"error": "e"}, c_sha256="x")),
        ]
        for content in cases:
            self.check(content)
        self.check(None, completed_before=3)
        self.check(good, max_row=20)
        self.check(good + b"x" * 30, max_row=20)

    def test_many_rows_parallel(self):
        rows = [row("k%d" % i, c="int f%d(){}" % i) for i in range(3000)]
        content = lines(*rows)
        result = self.check(content)
        self.assertEqual(result[1]["completed"], 3000)
        self.check(content[:-1])
        broken = list(rows)
        broken[2500] = dict(broken[2500], c_sha256="0" * 64)
        broken[100] = dict(broken[100], key="k5")
        self.assertIn("line 101", self.check(lines(*broken))[1])


class FakeImage:
    pass


@unittest.skipUnless(HAVE_NATIVE, "native module not built")
class ExportHelpers(unittest.TestCase):
    def test_pure_helpers(self):
        rng = random.Random(5)
        responses = [{}, {"truncated": True}, {"a": [{"b": {"body_truncated": True}}]}, {"a": [1, {"truncated": False}]},
                     {"fragments": [{"start": 0, "end": 4, "class": "data"}], "truncated": True, "c": "x"}, {"partial": True},
                     {"truncated": "yes"}]
        for response in responses:
            for function in (ew.partial, ew.decompile_row):
                self.assertEqual(outcome(function, response, impl="python"), outcome(function, response, impl="rust"), response)
        keys = ["a", "b", "é"]
        for sample in (keys, [], ["x"], [1, 2]):
            self.assertEqual(outcome(ew.keys_sha256, sample, impl="python"), outcome(ew.keys_sha256, sample, impl="rust"))
        for _ in range(100):
            listed = ["k%d" % i for i in range(rng.randint(0, 8))]
            snapshot = {"keys": listed, "count": len(listed), "engine_function_total": rng.choice([None, 12, True, 5.5])}
            progress = {"keys": set(rng.sample(listed + ["z1", "z2"], rng.randint(0, len(listed) + 2)) if listed else ["z1"]),
                        "succeeded": rng.randint(0, 5), "failed": rng.randint(0, 3)}
            selected = {"limit": rng.randint(1, 10)}
            self.assertEqual(outcome(ew.parity, snapshot, selected, progress, impl="python"),
                             outcome(ew.parity, snapshot, selected, progress, impl="rust"), (snapshot, progress, selected))

    def test_body_hash(self):
        from tests.test_pe import image
        pe = image(b"\x90" * 31 + b"\xc3")
        base = "0x400000"
        cases = [
            {"function": {"body": ["[401000, 40101f]"]}, "image_base": base}, {"function": {"body": ["[401000,40101f]"]}, "image_base": base},
            {"function": {"body": ["[401000, 40101f]", "[402000,402003]"]}, "image_base": base},
            {"function": {"body": ["[401000, 401020]"]}, "image_base": base}, {"function": {"body": ["[400000, 400010]"]}, "image_base": base},
            {"function": {"body": ["[401010, 401000]"]}, "image_base": base}, {"function": {"body": ["nope"]}, "image_base": base},
            {"function": {"body": ["[401000, 40101f]"]}}, {"function": {"body": ["[401000, 40101f]"]}, "image_base": "zz"},
            {"function": {"body": ["[401000, 40101f]"]}, "image_base": " 0x400000 "}, {"function": {"body": []}, "image_base": base},
            {"function": {"body_truncated": True, "body": ["[401000, 40101f]"]}, "image_base": base}, {"image_base": base},
            {"function": {"body": ["[401000, 7fffffff]"]}, "image_base": base},
        ]
        for response in cases:
            for target in (pe, None):
                self.assertEqual(outcome(ew.body_hash, response, target, impl="python"),
                                 outcome(ew.body_hash, response, target, impl="rust"), (response, target is None))


def fingerprint(rng, index, pool):
    shape = rng.choice(pool["shapes"])
    callees = rng.sample(pool["rvas"], rng.randint(0, 4)) if rng.random() < 0.7 else []
    return {"rva": pool["rvas"][index], "bytes": rng.choice(pool["bytes"]), "shape": shape, "size": rng.choice([0, 4, 10, 30, 64, 100, 200]),
            "instructions": rng.choice([1, 6, 12, 40, 30000]), "strings": rng.sample(pool["strings"], rng.randint(0, 2)),
            "imports": rng.sample(pool["imports"], rng.randint(0, 3)), "constants": rng.sample(pool["constants"], rng.randint(0, 3)),
            "callees": callees, "heads": rng.sample(pool["heads"], rng.randint(0, 2)), "name": "FUN_x", "source": "ANALYSIS"}


@unittest.skipUnless(HAVE_NATIVE, "native module not built")
class CrossbuildMatch(unittest.TestCase):
    def test_random_builds(self):
        for seed in range(60):
            rng = random.Random(seed)
            count = rng.randint(5, 80)
            pool = {"rvas": ["0x%x" % (0x1000 + 16 * i) for i in range(count)], "shapes": ["s%d" % i for i in range(max(3, count // 3))],
                    "bytes": ["aa%02x" % i for i in range(max(3, count // 2))], "strings": ["a", "b", "c", "d", "e"],
                    "imports": ["i1", "i2", "i3", "i4"], "constants": [1, 2, 3, 4, 5, 255], "heads": ["h%d" % i for i in range(6)]}
            source = {pool["rvas"][i]: fingerprint(rng, i, pool) for i in range(count)}
            shift = rng.randint(0, 3)
            dest_rvas = ["0x%x" % (0x2000 + 16 * i) for i in range(count + shift)]
            pool2 = dict(pool, rvas=dest_rvas)
            destination = {}
            for i in range(count + shift):
                base = source.get(pool["rvas"][i - shift]) if 0 <= i - shift < count and rng.random() < 0.8 else None
                if base is None:
                    destination[dest_rvas[i]] = fingerprint(rng, i, pool2)
                else:
                    twin = dict(base, rva=dest_rvas[i])
                    twin["callees"] = [dest_rvas[min(count + shift - 1, pool["rvas"].index(c) + shift)] for c in base["callees"]]
                    if rng.random() < 0.3:
                        twin["size"] += rng.randint(0, 20)
                    destination[dest_rvas[i]] = twin
            python = outcome(lambda a, b: list(crossbuild.match(a, b).items()), source, destination, impl="python")
            rust = outcome(lambda a, b: list(crossbuild.match(a, b).items()), source, destination, impl="rust")
            self.assertEqual(python, rust, seed)
            self.assertGreater(len(python[1]), 0) if seed == 0 else None


if __name__ == "__main__":
    unittest.main()
