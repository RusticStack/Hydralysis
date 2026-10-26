import ctypes
import json
import os
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

from rusticre import localio
from rusticre.backends import read_json

from support import workdir


class LocalMetadataReadTests(unittest.TestCase):
    def setUp(self):
        self.temp = workdir()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_binary_and_strict_utf8_text_reads(self):
        filename = self.root / "metadata.json"
        content = json.dumps({"name": "ação"}, ensure_ascii=False).encode("utf-8")
        filename.write_bytes(content)
        self.assertEqual(localio.read_bytes(filename), content)
        self.assertEqual(json.loads(localio.read_text(filename)), {"name": "ação"})
        filename.write_bytes(b"\xff")
        with self.assertRaises(UnicodeDecodeError):
            localio.read_text(filename)

    def test_size_limit_refuses_without_changing_the_file(self):
        filename = self.root / "metadata.json"
        filename.write_bytes(b"abcdef")
        with self.assertRaisesRegex(ValueError, "read budget"):
            localio.read_bytes(filename, max_bytes=5)
        self.assertEqual(filename.read_bytes(), b"abcdef")
        self.assertEqual(localio.read_bytes(filename, max_bytes=6), b"abcdef")

    def test_invalid_budgets_and_null_filenames_are_rejected(self):
        for budget in (True, 0, -1, localio.DEFAULT_MAX_BYTES + 1, 1.5):
            with self.subTest(budget=budget), self.assertRaisesRegex(ValueError, "budget"):
                localio.read_bytes(self.root / "not-opened", max_bytes=budget)
        with self.assertRaisesRegex(ValueError, "null character"):
            localio.read_bytes("not\0a-file")

    def test_missing_file_is_distinct_from_invalid_metadata(self):
        filename = self.root / "missing.json"
        with self.assertRaises(FileNotFoundError) as caught:
            localio.read_bytes(filename)
        self.assertEqual(caught.exception.filename, str(filename))
        self.assertEqual(read_json(filename), {})
        filename.write_text("[]", encoding="utf-8")
        with self.assertRaisesRegex(ValueError, "JSON object"):
            read_json(filename)

    @unittest.skipUnless(os.name == "nt", "Windows native shared-read contract")
    def test_public_native_read_closes_its_handle_before_caller_replaces_file(self):
        filename = self.root / "metadata.json"
        replacement = self.root / "new-metadata.tmp"
        filename.write_bytes(b"old metadata")
        replacement.write_bytes(b"new metadata")
        kernel = localio._kernel()
        with patch.object(kernel, "CloseHandle", wraps=kernel.CloseHandle) as close:
            self.assertEqual(localio.read_bytes(filename), b"old metadata")
            close.assert_called_once()
        # This is the shipped operation pattern: the reader has returned and
        # closed its handle before the caller publishes a replacement.
        replacement.replace(filename)
        self.assertEqual(localio.read_bytes(filename), b"new metadata")

    @unittest.skipUnless(os.name == "nt", "Windows native error preservation")
    def test_access_denied_keeps_native_code_and_filename_without_retry(self):
        filename = self.root / "denied.json"
        kernel = Mock()
        kernel.CreateFileW.return_value = ctypes.c_void_p(-1).value
        with patch("rusticre.localio._kernel", return_value=kernel), patch("ctypes.get_last_error", return_value=5):
            with self.assertRaises(PermissionError) as caught:
                read_json(filename)
        self.assertEqual(caught.exception.winerror, 5)
        self.assertEqual(caught.exception.filename, str(filename))
        kernel.CreateFileW.assert_called_once_with(str(filename), 0x80000000, 7, None, 3, 0x80, None)
        kernel.CloseHandle.assert_not_called()

    @unittest.skipUnless(os.name == "nt", "Windows native error preservation")
    def test_missing_native_code_is_preserved(self):
        filename = self.root / "missing-native.json"
        with self.assertRaises(FileNotFoundError) as caught:
            localio.read_bytes(filename)
        self.assertEqual(caught.exception.winerror, 2)
        self.assertEqual(caught.exception.filename, str(filename))


if __name__ == "__main__":
    unittest.main()
