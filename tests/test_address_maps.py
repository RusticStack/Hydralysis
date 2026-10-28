import json
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hydralysis import address_maps, api
from support import workdir


class AddressMaps(unittest.TestCase):
    def setUp(self):
        self.work = workdir("address-maps")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.settings = {"root": str(self.root)}
        self.digest = "a" * 64

    def file(self, entries, digest=None, source="fixture symbols:12"):
        path = self.root / "input.json"
        path.write_text(json.dumps({"sha256": digest or self.digest, "source": source, "entries": entries}), encoding="utf-8")
        return str(path)

    def test_import_and_resolve_are_build_bound_and_cited(self):
        path = self.file([{"name": "global", "hash": "0x00AB", "rva": "rva:0x1234", "source": "fixture.map:4"}])
        imported = address_maps.import_map(self.settings, self.digest, path)
        for selector in ("name:global", "hash:0xab"):
            result = address_maps.resolve(self.settings, self.digest, selector)
            self.assertEqual(result["rva"], "0x1234")
            self.assertEqual(result["evidence"][0]["source"], "fixture.map:4")
            self.assertEqual(result["evidence"][0]["map_sha256"], imported["map_sha256"])
        with self.assertRaisesRegex(ValueError, "no address map"):
            address_maps.resolve(self.settings, "b" * 64, "name:global")

    def test_mismatch_missing_source_bad_rva_and_ambiguous_names_fail_closed(self):
        for path in (self.file([{"name": "a", "rva": "0x100"}], "b" * 64),):
            with self.assertRaisesRegex(ValueError, "SHA-256 mismatch"):
                address_maps.import_map(self.settings, self.digest, path)
        for source, row in (("", {"name": "a", "rva": "0x100"}),
                            ("fixture", {"name": "a", "rva": "va:0x100"}),
                            ("fixture", {"hash": "not hex", "rva": "0x100"})):
            with self.subTest(row=row), self.assertRaises(ValueError):
                address_maps.import_map(self.settings, self.digest, self.file([row], source=source))
        address_maps.import_map(self.settings, self.digest, self.file([{"name": "a", "rva": "0x100"}]))
        address_maps.import_map(self.settings, self.digest, self.file([{"name": "a", "rva": "0x200"}]))
        with self.assertRaisesRegex(ValueError, "ambiguous"):
            address_maps.resolve(self.settings, self.digest, "name:a")

    def test_changed_stored_map_is_rejected(self):
        result = address_maps.import_map(self.settings, self.digest, self.file([{"name": "a", "rva": "0x100"}]))
        path = Path(result["path"])
        record = json.loads(path.read_text(encoding="utf-8"))
        record.pop("seal", None)  # a hand edit that also strips the seal; a stale seal is store_corrupt (test_durable)
        record["entries"][0]["rva"] = "0x200"
        path.write_text(json.dumps(record), encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "provenance"):
            address_maps.resolve(self.settings, self.digest, "name:a")

    def test_ghidra_query_resolves_map_and_returns_evidence(self):
        path = self.file([{"name": "a", "rva": "0x100"}])
        runner = MagicMock()
        runner.target.return_value = {"sha256": self.digest}
        runner.query.return_value = json.dumps({"ok": True})
        with patch.object(api, "_settings", return_value=self.settings), patch.object(api, "QueryRunner", return_value=runner):
            api.call("ghidra_query", {"target": "fixture", "action": "address_map", "options": {"path": path}})
            answer = json.loads(api.call("ghidra_query", {"target": "fixture", "action": "decompile", "address": "name:a"}))
        self.assertEqual(runner.query.call_args.args[2], "rva:0x100")
        self.assertEqual(answer["address_resolution"]["evidence"][0]["source"], "fixture symbols:12")


if __name__ == "__main__":
    unittest.main()
