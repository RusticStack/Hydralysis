"""`Image.loaded_bytes` with a real base relocation directory in the file, under whichever implementation is selected
(HYDRALYSIS_IMPL unset or `rust`): test_writers patches `Image._relocations` with a fabricated table, which only the Python
method asks; this reads the table from the file's bytes, which is what the Rust image does."""

import struct
import unittest
from pathlib import Path
from unittest.mock import patch

from hydralysis.pe import Image


def image_with_a_relocation_table() -> Image:
    """A 32-bit image at 0x400000 whose .reloc section (RVA 0x3000, file offset 0x400: file aligned, as pefile reads
    directory data) holds one HIGHLOW fixup at RVA 0x1001."""
    data = bytearray(0x420)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, 0x14C, 3, 0, 0, 0, 224, 0x102)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, 0x4000, 0x200)
    struct.pack_into("<I", data, opt + 92, 16)
    struct.pack_into("<II", data, opt + 96 + 5 * 8, 0x3000, 12)
    for index, (label, vsize, rva, raw_size, raw_offset, flags) in enumerate((
        (b".text", 0x100, 0x1000, 0x20, 0x200, 0x60000020),
        (b".data", 0x20, 0x2000, 0x20, 0x220, 0xC0000040),
        (b".reloc", 0x20, 0x3000, 0x20, 0x400, 0x42000040),
    )):
        struct.pack_into("<8sIIIIIIHHI", data, opt + 224 + index * 40, label, vsize, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)
    data[0x200:0x208] = b"\x68\x00\x60\x41\x00\xe8\x30\xfe"
    struct.pack_into("<II", data, 0x400, 0x1000, 12)
    struct.pack_into("<HH", data, 0x408, (3 << 12) | 1, 0)
    with patch.object(Path, "read_bytes", return_value=bytes(data)):
        return Image(Path("fixture.exe"))


class LoadedBytesFromTheFile(unittest.TestCase):
    def test_a_relocation_table_in_the_file_is_applied_for_the_load_delta(self):
        pe = image_with_a_relocation_table()
        self.assertEqual(pe.loaded_bytes(0x1000, 8, pe.base), pe.read_rva(0x1000, 8))
        moved = pe.loaded_bytes(0x1000, 8, pe.base + 0x500000)
        self.assertEqual(moved[:5], b"\x68" + struct.pack("<I", 0x416000 + 0x500000))
        self.assertEqual(moved[5:], pe.read_rva(0x1005, 3))
        # A window that starts inside the relocated word gets its upper bytes fixed too.
        self.assertEqual(pe.loaded_bytes(0x1003, 2, pe.base + 0x500000), moved[3:5])


if __name__ == "__main__":
    unittest.main()
