import ctypes
import unittest
from unittest.mock import Mock, patch

from hydralysis import darwin_process, preparation, proc, runtime_worker


class DarwinProcess(unittest.TestCase):
    def library(self, *, pid=42, status=2, sec=1700000000, usec=123456, length=None):
        lib = Mock()
        def info(requested, flavor, arg, pointer, size):
            self.assertEqual((requested, flavor, arg), (42, 3, 0))
            data = ctypes.cast(pointer, ctypes.POINTER(darwin_process._BsdInfo)).contents
            data.pid, data.status, data.start_sec, data.start_usec = pid, status, sec, usec
            return size if length is None else length
        def path(requested, buffer, size):
            self.assertEqual((requested, size), (42, 4096))
            value = b"/Applications/Owned.app/Contents/MacOS/Owned"
            ctypes.memmove(buffer, value + b"\0", len(value) + 1)
            return len(value)
        lib.proc_pidinfo.side_effect = info
        lib.proc_pidpath.side_effect = path
        return lib

    def test_apple_struct_layout_and_process_information(self):
        self.assertEqual(ctypes.sizeof(darwin_process._BsdInfo), 136)
        with patch("hydralysis.darwin_process._library", return_value=self.library()):
            self.assertEqual(darwin_process.created_ms(42), 1700000000123)
            self.assertEqual(darwin_process.process_path(42), "/Applications/Owned.app/Contents/MacOS/Owned")

    def test_rejects_partial_stale_zombie_or_invalid_information(self):
        for changes in ({"length": 20}, {"pid": 43}, {"status": 5}, {"sec": 0}, {"usec": 1000000}):
            with self.subTest(changes=changes), patch("hydralysis.darwin_process._library", return_value=self.library(**changes)):
                with self.assertRaises(OSError):
                    darwin_process.created_ms(42)
        with self.assertRaises(ValueError):
            darwin_process.created_ms(0)

    def test_path_failure_does_not_return_an_unverified_path(self):
        lib = self.library()
        lib.proc_pidpath.side_effect = lambda *_: 0
        with patch("hydralysis.darwin_process._library", return_value=lib), \
             patch("ctypes.get_errno", return_value=13):
            with self.assertRaises(PermissionError):
                darwin_process.process_path(42)

    def test_darwin_dispatch_rejects_recycled_or_unavailable_identity(self):
        with patch("os.name", "posix"), patch("sys.platform", "darwin"), \
             patch("hydralysis.darwin_process.created_ms", return_value=1700000000123), \
             patch("hydralysis.darwin_process.process_path", return_value="/owned"):
            self.assertTrue(proc.identity(42, 1700000000123))
            self.assertFalse(proc.identity(42, 1700000000124))
            self.assertEqual(preparation.process_start_ms(42), 1700000000123)
            self.assertEqual(runtime_worker._created_ms(42), 1700000000123)
            self.assertEqual(runtime_worker._process_path(42), "/owned")
        with patch("os.name", "posix"), patch("sys.platform", "darwin"), \
             patch("hydralysis.darwin_process.created_ms", side_effect=PermissionError("denied")):
            with self.assertRaises(PermissionError):
                proc.identity(42, 1700000000123)
            with self.assertRaises(PermissionError):
                preparation.process_start_ms(42)
            with self.assertRaises(PermissionError):
                runtime_worker._created_ms(42)


if __name__ == "__main__":
    unittest.main()
