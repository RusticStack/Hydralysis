"""Rust vs Python parity for the filesystem leaves of backends.py and doctor.py."""

import json
import os
import tempfile
import unittest
from pathlib import Path

try:
    import hydralysis_native as native
except ImportError:
    native = None

from hydralysis import backends, doctor


@unittest.skipIf(native is None or not hasattr(native, "system_properties_rs"), "native extension not built")
class SystemParity(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.addCleanup(__import__("shutil").rmtree, self.dir, True)

    def test_properties(self):
        text = 'A=1\n# c=2\n  #d=3\nB = "x y" \nnoeq\nC=a=b\r\nD="q"\rE=\x0bF=9\u2028G=1\n'
        path = self.dir / "release"
        path.write_bytes(text.encode("utf-8") + b"\xff\xfeH=z\n")
        want = backends._python_properties(path)
        self.assertEqual(dict(native.system_properties_rs(str(path))), want)
        self.assertEqual(native.system_properties_rs(str(self.dir / "none")), [])

    def test_children(self):
        for name in ("jdk-21", "JDK-25.0.1", "jdk-25", "hydra-12", "hydra-x", "Hydra-9", "other"):
            (self.dir / name).mkdir()
        (self.dir / "jdkfile").write_text("x")
        for pattern in ("jdk*", "hydra-[0-9]*"):
            want = [str(p) for p in backends._python_children(self.dir, pattern)]
            self.assertEqual(native.system_children_rs(str(self.dir), pattern), want)
        self.assertEqual(native.system_children_rs(str(self.dir / "none"), "jdk*"), [])

    def test_native_compatible(self):
        good = bytearray(b"MZ" + bytes(62) + bytes(64))
        good[60:64] = (64).to_bytes(4, "little")
        good[64:70] = b"PE\0\0\x64\x86"
        cases = {"good": bytes(good), "arm": bytes(good).replace(b"\x64\x86", b"\x64\xaa"), "short": b"MZ",
                 "empty": b"", "elf": b"\x7fELF\x02" + bytes(30), "macho": b"\xcf\xfa\xed\xfe" + bytes(8),
                 "far": b"MZ" + bytes(58) + (10**6).to_bytes(4, "little")}
        for name, data in cases.items():
            path = self.dir / name
            path.write_bytes(data)
            self.assertEqual(native.system_native_compatible_rs(str(path)), backends._python_native_compatible(path), name)
        self.assertFalse(native.system_native_compatible_rs(str(self.dir)))

    def test_machine(self):
        self.assertEqual(native.system_machine_rs() or backends._python_machine(), backends._python_machine())

    def test_read_json_and_instances(self):
        (self.dir / "ok.json").write_text('{"a": 1}', encoding="utf-8")
        (self.dir / "list.json").write_text("[1]", encoding="utf-8")
        (self.dir / "bad.json").write_text("{", encoding="utf-8")
        (self.dir / "bom.json").write_bytes(b'\xef\xbb\xbf{"a":1}')
        for name in ("ok", "list", "a.launch", "x.supervisor", "supervisor", "B", ".json"[:0] + "z.y"):
            (self.dir / (name + ".json")).write_text("{}")
            (self.dir / (name + ".lock")).write_text("")
        for name in ("ok", "list", "bad", "bom", "missing", "B"):
            path = self.dir / (name + ".json")
            self.assertEqual(json.loads(native.system_read_json_object_rs(str(path))), doctor._python_read_json(path), name)
        self.assertEqual(native.system_instances_rs(str(self.dir)), doctor._python_instances(self.dir))
        self.assertEqual(native.system_instances_rs(str(self.dir / "none")), [])

    def test_dir_size_and_count_key(self):
        (self.dir / "a" / "b").mkdir(parents=True)
        (self.dir / "a" / "x").write_bytes(b"1" * 10)
        (self.dir / "a" / "b" / "y").write_bytes(b"2" * 7)
        self.assertEqual(native.system_dir_size_rs(str(self.dir)), doctor._python_dir_size(self.dir))
        self.assertEqual(native.system_dir_size_rs(str(self.dir / "none")), 0)
        value = {"k": 1, "a": [{"k": 0}, {"k": "x", "n": {"k": [1]}}, {"k": []}, {"k": None}], "b": {"k": True}}
        self.assertEqual(native.system_count_key_rs(json.dumps(value), "k"), doctor._python_count_key(value, "k"))
        self.assertEqual(native.system_count_key_rs("5", "k"), 0)


if __name__ == "__main__":
    unittest.main()
