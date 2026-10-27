import struct
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from test_pe import image

from rusticre import runtime
from rusticre.runtime_decode import normalize
from rusticre.runtime_worker import _probe_source


class LoadedBytes(unittest.TestCase):
    def test_base_relocations_are_applied_for_the_load_delta(self):
        pe = image(b"\x68\x00\x60\x41\x00\xe8\x30\xfe" + b"\x90" * 24)
        with patch.object(type(pe), "_relocations", return_value=[(0x1001, 4)]):
            self.assertEqual(pe.loaded_bytes(0x1000, 8, pe.base), pe.read_rva(0x1000, 8))
            moved = pe.loaded_bytes(0x1000, 8, pe.base + 0x500000)
            self.assertEqual(moved[:5], b"\x68" + struct.pack("<I", 0x416000 + 0x500000))
            # A window that starts inside the relocated word gets its upper bytes fixed too.
            self.assertEqual(pe.loaded_bytes(0x1003, 2, pe.base + 0x500000), moved[3:5])


class BaseArguments(unittest.TestCase):
    def decoded(self, code, bits):
        pe = image(code.ljust(32, b"\xcc"), machine=0x8664 if bits == 64 else 0x14C)
        pe.bits = bits
        return pe

    def test_an_untouched_argument_register_or_a_loaded_stack_argument(self):
        x64 = self.decoded(b"\x89\x51\x04\xc3", 64)           # mov [rcx+4], edx; ret
        self.assertEqual(runtime._base_argument(x64, 0x1000, 0x1000, "rcx"), ("reg", "rcx"))
        x86 = self.decoded(b"\x8b\x44\x24\x04\x8b\x4c\x24\x08\x89\x48\x04\xc3", 32)  # mov eax,[esp+4]; ...
        self.assertEqual(runtime._base_argument(x86, 0x1000, 0x1008, "eax"), ("stack", 0))
        computed = self.decoded(b"\x48\x8b\x41\x08\x89\x50\x04\xc3", 64)  # mov rax,[rcx+8]; mov [rax+4],edx
        self.assertIsNone(runtime._base_argument(computed, 0x1000, 0x1004, "rax"))

    def test_the_argument_is_recovered_at_the_return_site(self):
        lea = [{"address": "0x1400011f4", "mnemonic": "LEA", "operands": "RCX, [0x14001a000]"},
               {"address": "0x1400011fb", "mnemonic": "CALL", "operands": "0x140001000"},
               {"address": "0x140001200", "mnemonic": "MOV", "operands": "EDX, EBX"}]
        self.assertEqual(runtime._argument_at_return(lea, 0x1400011fb, ("reg", "rcx"), 64), ("static", 0x14001a000))
        kept = [{"address": "0x10", "mnemonic": "MOV", "operands": "RCX, RBX"}, {"address": "0x13", "mnemonic": "CALL", "operands": "0x1"}]
        self.assertEqual(runtime._argument_at_return(kept, 0x13, ("reg", "rcx"), 64), ("reg", "rbx"))
        volatile = [{"address": "0x10", "mnemonic": "MOV", "operands": "RCX, RAX"}, {"address": "0x13", "mnemonic": "CALL", "operands": "0x1"}]
        self.assertIsNone(runtime._argument_at_return(volatile, 0x13, ("reg", "rcx"), 64))
        pushed = [{"address": "0x4011bb", "mnemonic": "PUSH", "operands": "ECX"},
                  {"address": "0x4011bc", "mnemonic": "PUSH", "operands": "0x416000"},
                  {"address": "0x4011c1", "mnemonic": "CALL", "operands": "0x401090"}]
        self.assertEqual(runtime._argument_at_return(pushed, 0x4011c1, ("stack", 0), 32), ("static", 0x416000))
        cleaned = [{"address": "0x10", "mnemonic": "PUSH", "operands": "dword ptr [EAX + 0x4]"},
                   {"address": "0x13", "mnemonic": "CALL", "operands": "0x1"}, {"address": "0x18", "mnemonic": "ADD", "operands": "ESP, 0x8"}]
        self.assertEqual(runtime._argument_at_return(cleaned, 0x13, ("stack", 0), 32), ("stack", 0))


class ProbeForms(unittest.TestCase):
    def source(self, instruction):
        return _probe_source({"path": "x.exe", "base": "0x400000"}, 0x1000, [0x55, 0x8B, 0xEC, 0x83, 0xEC], "a" * 32, 5, False,
                             normalize([{"reg": "rcx", "as": "pointer"}]), None, "native", instruction)

    def test_an_instruction_probe_is_a_callback_without_a_return_hook(self):
        self.assertIn('"instruction": true', self.source(True))
        self.assertIn("p.instruction?Interceptor.attach(site,enter)", self.source(True))

    def test_a_call_inside_the_probed_bytes_is_found(self):
        from rusticre import runtime_worker
        pe = image(b"\x48\x8d\x0d\x00\x00\x00\x00\xe8\x00\x00\x00\x00\xc3", machine=0x8664)
        pe.bits = 64
        with patch.object(runtime_worker, "_image", return_value=pe):
            self.assertIsNone(runtime_worker._call_in_span("x.exe", 0x1000))       # LEA covers the 5 bytes
            self.assertIn("call", runtime_worker._call_in_span("x.exe", 0x1007))


class WritersRequest(unittest.TestCase):
    def test_rows_object_and_target_are_required(self):
        runner = runtime.RuntimeRunner({"root": "unused"})
        owner = {"exe": "x.exe"}
        for bad in ({"rows": [], "target": "t"}, {"rows": [{}], "target": ""},
                    {"rows": [{"site": "0x1"}], "target": "t", "offset": "0x4"}):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                runner._writers("a" * 32, dict(bad), "token", owner)


if __name__ == "__main__":
    unittest.main()
