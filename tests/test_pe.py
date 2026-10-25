import hashlib
import struct
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from rusticre.pe import Image, _file_version
from rusticre.prologue import compare, find_pattern, matches, parse_expect


def image(text=b"\x90" * 31 + b"\xc3", *, name=b".text", machine=0x14C, virtual_size=0x100):
    """A two-section PE whose virtual .text tail would alias .data on disk."""
    data = bytearray(0x240)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<HHIIIHH", data, 0x84, machine, 2, 0, 0, 0, 224, 0x102)
    opt = 0x98
    struct.pack_into("<H", data, opt, 0x10B)
    struct.pack_into("<I", data, opt + 16, 0x1000)
    struct.pack_into("<I", data, opt + 28, 0x400000)
    struct.pack_into("<II", data, opt + 32, 0x1000, 0x200)
    struct.pack_into("<II", data, opt + 56, 0x3000, 0x200)
    struct.pack_into("<I", data, opt + 92, 16)
    for index, (label, vsize, rva, raw_size, raw_offset, flags) in enumerate((
        (name, virtual_size, 0x1000, 0x20, 0x200, 0x60000020),
        (b".data", 0x20, 0x2000, 0x20, 0x220, 0xC0000040),
    )):
        struct.pack_into("<8sIIIIIIHHI", data, opt + 224 + index * 40,
                         label, vsize, rva, raw_size, raw_offset, 0, 0, 0, 0, flags)
    data[0x200:0x220] = text.ljust(0x20, b"\x90")[:0x20]
    data[0x220:0x240] = b"DATA" * 8
    with patch.object(Path, "read_bytes", return_value=bytes(data)):
        return Image(Path("fixture.exe"))


class FileBackedReads(unittest.TestCase):
    def test_string_search_returns_full_string_start_and_wide_text(self):
        pe = image(b"\0prefixSuffix\0\0" + "Wide".encode("utf-16le") + b"\0\0")
        result = pe.find_strings("Suffix|Wide", 10)
        self.assertIn("0x1001 ascii prefixSuffix", result)
        self.assertIn("0x100f utf-16le Wide", result)
        self.assertNotIn("0x1007 ascii Suffix", result)

    def test_virtual_tail_does_not_alias_next_section(self):
        pe = image()
        self.assertIsNone(pe.rva_to_offset(0x1020))
        with self.assertRaisesRegex(ValueError, "not in a section"):
            pe.read_rva(0x1020, 4)
        with self.assertRaisesRegex(ValueError, "file-backed"):
            pe.read_rva(0x101F, 2)
        self.assertEqual(pe.read_rva(0x2000, 4), b"DATA")

    def test_truncated_file_and_negative_reads_are_refused(self):
        pe = image()
        pe.data = pe.data[:0x221]
        with self.assertRaisesRegex(ValueError, "file-backed"):
            pe.read_rva(0x2000, 2)
        with self.assertRaisesRegex(ValueError, "non-negative"):
            pe.read_rva(0x1000, -1)

    def test_disassembly_at_section_end_uses_available_bytes(self):
        self.assertIn("ret", image().disasm(0x101F))

    def test_other_pe_architecture_is_not_silently_decoded_as_x64(self):
        with self.assertRaisesRegex(ValueError, "x86/x64 only"):
            image(machine=0x1C4).disasm(0x1000)


class ProvenanceAndCandidates(unittest.TestCase):
    def test_header_keeps_full_build_hash(self):
        pe = image()
        self.assertIn(hashlib.sha256(pe.data).hexdigest(), pe.header())

    def test_pefile_nested_resource_groups_supply_file_version(self):
        table = SimpleNamespace(entries={b"ProductVersion": b"product", b"FileVersion": b"1.2.3.4"})
        pe = SimpleNamespace(FileInfo=[[SimpleNamespace(StringTable=[table])]], parse_data_directories=lambda **kwargs: None)
        self.assertEqual(_file_version(pe), "1.2.3.4")

    def test_wrapper_indicator_is_a_warning_not_a_packed_verdict(self):
        pe = image(name=b".bind")
        self.assertIn(".bind", " ".join(pe.fingerprint()["analysis_warnings"]))
        self.assertIn("not proof", pe.fingerprint()["packing_status"])
        self.assertIn("executable SHA-256", pe.header())
        self.assertEqual(image().fingerprint()["analysis_warnings"], [])
        self.assertIn("not proof", image().fingerprint()["packing_status"])

    def test_callees_does_not_decode_e8_inside_an_immediate(self):
        # mov eax,0x909090e8; nop; ret -- its E8 byte is not a call opcode.
        pe = image(bytes.fromhex("B8 E8 90 90 90 90 C3"))
        self.assertIn("0 decoded direct call(s)", pe.callees(0x1000))

    def test_last_possible_call_site_is_included_and_labelled_candidate(self):
        # The final five bytes are a call from 0x101b to 0x1000.
        pe = image(b"\x90" * 27 + b"\xe8" + struct.pack("<i", -32))
        callers = pe.callers(0x1000)
        self.assertIn("rva:0x101b E8 call candidate -> rva:0x1000", callers)
        self.assertIn("instruction boundaries unverified", callers)
        self.assertIn("rva:0x101b call rva:0x1000", pe.callees(0x1000))


class SignatureVerification(unittest.TestCase):
    def test_all_wildcards_cannot_validate_a_hook(self):
        with self.assertRaisesRegex(ValueError, "concrete byte"):
            compare(b"\x90\x90", "?? ??")
        with self.assertRaisesRegex(ValueError, "concrete byte"):
            find_pattern(b"abc", [None, None], 10)
        self.assertFalse(matches(b"abc", [None, None]))
        self.assertFalse(matches(b"abc", []))

    def test_anchored_search_handles_edges_overlap_and_limits(self):
        self.assertEqual(find_pattern(b"aaa", parse_expect("61 61"), 10), [0, 1])
        self.assertEqual(find_pattern(b"aXbaYb", parse_expect("61 ?? 62"), 10), [0, 3])
        self.assertEqual(find_pattern(b"XaYa", parse_expect("?? 61"), 1), [0])
        self.assertEqual(find_pattern(b"aXb", parse_expect("61 ?? 62 ??"), 10), [])
        self.assertEqual(find_pattern(b"XaYb", parse_expect("?? 61 ?? 62"), 10), [0])


if __name__ == "__main__":
    unittest.main()
