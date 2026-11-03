"""Differential test: the Rust PE tools (hy-pe / hy-disasm / hy-query via hydralysis_native) against the Python reference.

Skipped when the native module is not built (or is an older build without NativeImage). Every tool is run through both
implementations on real system PEs (x64 and 32-bit) and on the synthetic image from test_pe, and the text (or the
exception type and message) must be identical.
"""

import json
import os
import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis import pe, prologue

try:
    import hydralysis_native
    HAVE_NATIVE = hasattr(hydralysis_native, "NativeImage")
except ImportError:
    HAVE_NATIVE = False

ROOT = Path(os.environ.get("SystemRoot", "C:/Windows"))
CORPUS = [
    ROOT / "System32" / "whoami.exe",
    ROOT / "System32" / "notepad.exe",
    ROOT / "System32" / "kernel32.dll",
    ROOT / "System32" / "ntdll.dll",
    ROOT / "System32" / "advapi32.dll",
    ROOT / "SysWOW64" / "cmd.exe",
    ROOT / "SysWOW64" / "kernel32.dll",
    Path(os.environ.get("HYDRALYSIS_PARITY_EXTRA", "D:/Projects/Hydra/_data/scratch/jvmfix-di/diff1.exe")),
]


def run(image, impl, method, *args, **kwargs):
    with patch.dict(os.environ, {"HYDRALYSIS_IMPL": impl}):
        try:
            value = getattr(image, method)(*args, **kwargs)
            return ("ok", value)
        except Exception as error:  # noqa: BLE001 - the type and text are the comparison
            return (type(error).__name__, str(error))


def interesting_rvas(image):
    rvas = {image.pe.OPTIONAL_HEADER.AddressOfEntryPoint, image.text.VirtualAddress,
            image.text.VirtualAddress + 0x37, image.sections[-1].VirtualAddress + 3, 0x10, 0x7FFFFFFF}
    raw = image._section_data(image.text)
    index = raw.find(b"\xe8", 0x100)
    if index >= 0:
        rel = int.from_bytes(raw[index + 1:index + 5], "little", signed=True)
        rvas.add(image.text.VirtualAddress + index + 5 + rel)
    try:
        image.pe.parse_data_directories(directories=[3])
        directory = image.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if directory.VirtualAddress and directory.Size >= 12:
            blob = image.read_rva(directory.VirtualAddress, min(directory.Size, 12 * 40))
            for at in range(0, len(blob) - 11, 12 * 7):
                rvas.add(struct.unpack_from("<I", blob, at)[0])
                rvas.add(struct.unpack_from("<I", blob, at)[0] + 4)
    except Exception:  # noqa: BLE001
        pass
    return sorted(rvas)


@unittest.skipUnless(HAVE_NATIVE, "hydralysis_native with NativeImage is not built")
class RustPeParity(unittest.TestCase):
    def compare(self, image, label, method, *args, **kwargs):
        python = run(image, "python", method, *args, **kwargs)
        rust = run(image, "rust", method, *args, **kwargs)
        self.assertEqual(python, rust, "%s %s%r%r" % (label, method, args, kwargs))

    def check_image(self, image, label):
        self.compare(image, label, "header")
        self.assertEqual(run(image, "python", "fingerprint"), run(image, "rust", "fingerprint"), label)
        self.compare(image, label, "sections_text")
        self.compare(image, label, "imports_text", 100000)
        self.compare(image, label, "imports_text", 7, "file|Heap")
        self.compare(image, label, "exports_text", 100000)
        self.compare(image, label, "exports_text", 3)
        for pattern, limit in (("Windows|error", 25), ("^[A-Z]{6,}", 5), ("zzzzqqq", 5)):
            self.compare(image, label, "find_strings", pattern, limit)
        for sig in ("48 89 5C 24 ??", "55 8B EC", "CC CC CC", "E8 ?? ?? ?? ??"):
            self.compare(image, label, "sigscan", sig, 12)
        for rva in interesting_rvas(image):
            for method in ("disasm", "callees", "inspect", "function_of", "string_at", "rva_to_offset", "_available"):
                self.compare(image, label, method, rva)
            self.compare(image, label, "disasm", rva, 60)
            self.compare(image, label, "callers", rva, 5)
            self.compare(image, label, "xrefs", rva, 5)
            self.compare(image, label, "read_rva", rva, 33)
            self.compare(image, label, "loaded_bytes", rva, 64, image.base + 0x10000)

    def test_system_images(self):
        seen = 0
        for path in CORPUS:
            if not path.is_file():
                continue
            seen += 1
            with self.subTest(path=str(path)):
                with patch.dict(os.environ, {"HYDRALYSIS_IMPL": "python"}):
                    image = pe.Image(path)
                self.check_image(image, path.name)
        if not seen:
            self.skipTest("no PE corpus present")

    def test_synthetic_images_and_errors(self):
        from test_pe import image as make
        for kwargs in ({}, {"machine": 0x1C4}, {"machine": 0x8664}):
            image = make(**kwargs)
            with self.subTest(kwargs=kwargs):
                self.check_image(image, "synthetic")
                for rva, size in ((0x101F, 2), (0x1020, 4), (0x1000, -1), (-1, 4), (0x2000, 4)):
                    self.compare(image, "synthetic", "read_rva", rva, size)
                self.compare(image, "synthetic", "disasm", 0x1000, 0)
                self.compare(image, "synthetic", "disasm", 0x101F)
        image = make(b"\0prefixSuffix\0\0" + "Wide".encode("utf-16le") + b"\0\0")
        self.compare(image, "synthetic", "find_strings", "Suffix|Wide", 10)

    def test_prologue_helpers(self):
        for text in ("48 89 5C 24 ??", "0x48,0x89", "\\x55\\x8b\\xec", "?? ??", "", "4889zz", "488", "48??89", "0x"):
            python = _capture(prologue.parse_expect, text)
            rust = _capture(lambda t: hydralysis_native.parse_expect_rs(t), text)
            self.assertEqual(python, rust, text)
        haystack = bytes(range(256)) * 4 + b"\x48\x89\x5c\x24\x08" * 3
        for pattern in ([0x48, 0x89, None, 0x24], [None, 0x89, 0x5C], [0x00, 0x01], [0xFF, 0x00, None, 0x02]):
            for limit in (1, 3, 100):
                self.assertEqual(prologue.find_pattern(haystack, pattern, limit),
                                 hydralysis_native.find_pattern_rs(haystack, pattern, limit), (pattern, limit))
        for text in ("rva:0x10", "va:0x140000010", "0x140000010", "0x10", "va:0x10", "zz:1", "-3", "rva:abc", "12"):
            python = _capture(pe.parse_rva, text, 0x140000000)
            rust = _capture(hydralysis_native.parse_rva_rs, text, 0x140000000)
            self.assertEqual(python, rust, text)


def _capture(function, *args):
    try:
        return ("ok", function(*args))
    except Exception as error:  # noqa: BLE001
        return (type(error).__name__ if not isinstance(error, ValueError) else "ValueError", str(error))


if __name__ == "__main__":
    unittest.main()
