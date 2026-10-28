import hashlib
import unittest
from pathlib import Path

from hydralysis import analysis, workcopy
from support import workdir


class ArchiveImport(unittest.TestCase):
    def setUp(self):
        self.work = workdir("archive-import")
        self.addCleanup(self.work.cleanup)
        self.root = Path(self.work.name)
        self.settings = {"root": str(self.root)}
        self.source = self.root / "source.gdt"
        self.source.write_bytes(b"archive fixture bytes")

    def test_validation_requires_source_absolute_gdt_and_existing_file(self):
        options = {"kind": "import_archive", "archive": str(self.source), "source": "fixture.gdt:types"}
        self.assertEqual(analysis.validate_options("type_edit", options), options)
        for override in ({"source": ""}, {"archive": "relative.gdt"}, {"archive": str(self.root / "missing.gdt")},
                         {"archive_sha256": "a" * 64}):
            with self.subTest(override=override), self.assertRaises((ValueError, FileNotFoundError)):
                analysis.validate_options("type_edit", {**options, **override})

    def test_snapshot_is_hashed_and_verified_on_every_replay(self):
        digest, size = workcopy.store_archive(self.settings, str(self.source))
        self.assertEqual(digest, hashlib.sha256(b"archive fixture bytes").hexdigest())
        record = {"id": "a" * 32, "address": "", "options": {"kind": "import_archive", "source": "fixture.gdt:types",
                  "archive_sha256": digest, "archive_bytes": size}}
        clean = analysis._edit(record)
        self.source.write_bytes(b"changed original")
        result = workcopy._replayable(self.settings, {"key": "target"}, clean)
        stored = Path(result["options"]["archive_file"])
        self.assertEqual(stored.read_bytes(), b"archive fixture bytes")
        stored.write_bytes(b"archive fixture byteX")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            workcopy._replayable(self.settings, {"key": "target"}, clean)

    def test_snapshot_conflicting_existing_content_is_not_replaced(self):
        digest, size = workcopy.store_archive(self.settings, str(self.source))
        stored = workcopy.archive_path(self.settings, digest)
        stored.write_bytes(b"archive fixture byteX")
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            workcopy.store_archive(self.settings, str(self.source))
        self.assertEqual(stored.read_bytes(), b"archive fixture byteX")

    def test_scoped_type_paths_survive_recording_and_reject_invalid_selections(self):
        options = {"kind": "import_archive", "archive": str(self.source), "source": "archive row", "paths": ["/u4"]}
        self.assertEqual(analysis.validate_options("type_edit", options)["paths"], ["/u4"])
        digest, size = workcopy.store_archive(self.settings, str(self.source))
        record = analysis._edit({"id": "a" * 32, "address": "", "options": {"kind": "import_archive", "source": "archive row",
                    "archive_sha256": digest, "archive_bytes": size, "paths": ["/u4"]}})
        self.assertEqual(record["options"]["paths"], ["/u4"])
        for paths in ([], ["relative"], ["/u4", "/u4"], ["/u4"] * 201):
            with self.subTest(paths=paths[:3]), self.assertRaises(ValueError):
                analysis.validate_options("type_edit", {**options, "paths": paths})


if __name__ == "__main__":
    unittest.main()
