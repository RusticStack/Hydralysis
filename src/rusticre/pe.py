"""Reads for any PE you own. 32-bit and 64-bit.

The header line is the build. Quote it with every address.
Nothing in here knows which game the file came from.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

import capstone
import pefile

_PRINTABLE = set(range(32, 127))


class Image:
    def __init__(self, path: Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        self.pe = pefile.PE(data=self.data, fast_load=True)
        self.base = int(self.pe.OPTIONAL_HEADER.ImageBase)
        self.machine = int(self.pe.FILE_HEADER.Machine)
        self.bits = 32 if self.machine == 0x14C else 64
        self.sections = []
        for section in self.pe.sections:
            name = section.Name.rstrip(b"\0").decode("utf-8", "replace")
            self.sections.append(section)
            if name == ".text":
                self.text = section
        if not hasattr(self, "text"):
            self.text = self.pe.sections[0]

    def fingerprint(self) -> dict:
        info = {
            "exe": self.path.name,
            "size": len(self.data),
            "timeDateStamp": hex(self.pe.FILE_HEADER.TimeDateStamp),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "image_base": hex(self.base),
        }
        version = _file_version(self.pe)
        if version:
            info["file_version"] = version
        return info

    def header(self) -> str:
        info = self.fingerprint()
        extra = ""
        if "file_version" in info:
            extra += " version " + info["file_version"]
        return "# exe %s size %d tds %s sha256 %s%s" % (
            info["exe"],
            info["size"],
            info["timeDateStamp"],
            info["sha256"][:16],
            extra,
        )

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            start = section.VirtualAddress
            size = max(section.Misc_VirtualSize, section.SizeOfRawData)
            if start <= rva < start + size:
                return rva - start + section.PointerToRawData
        return None

    def read_rva(self, rva: int, size: int) -> bytes:
        offset = self.rva_to_offset(rva)
        if offset is None:
            raise ValueError("rva %#x is not in a section of %s" % (rva, self.path.name))
        return self.data[offset : offset + size]

    def string_at(self, rva: int, limit: int = 80) -> str | None:
        try:
            raw = self.read_rva(rva, limit)
        except ValueError:
            return None
        end = raw.find(b"\0")
        if end < 4:
            return None
        text = raw[:end]
        if any(byte not in _PRINTABLE for byte in text):
            return None
        return text.decode("ascii")

    def disasm(self, rva: int, count: int = 40) -> str:
        mode = capstone.CS_MODE_32 if self.bits == 32 else capstone.CS_MODE_64
        md = capstone.Cs(capstone.CS_ARCH_X86, mode)
        blob = self.read_rva(rva, count * 16)
        lines = [self.header()]
        shown = 0
        for insn in md.disasm(blob, rva):
            note = _rip_note(self, insn)
            lines.append("%#010x: %s %s%s" % (insn.address, insn.mnemonic, insn.op_str, note))
            shown += 1
            if shown >= count:
                break
        if shown == 0:
            lines.append("(no instructions at %#x)" % rva)
        return "\n".join(lines)

    def callers(self, target: int, limit: int = 50) -> str:
        """Direct E8/E9 call and jump sites whose displacement lands on `target`."""
        hits = []
        section = self.text
        start = section.PointerToRawData
        raw = self.data[start : start + section.SizeOfRawData]
        base = section.VirtualAddress
        for index in range(0, max(0, len(raw) - 5)):
            opcode = raw[index]
            if opcode not in (0xE8, 0xE9):
                continue
            rel = int.from_bytes(raw[index + 1 : index + 5], "little", signed=True)
            site = base + index
            dest = site + 5 + rel
            if dest == target:
                kind = "call" if opcode == 0xE8 else "jmp"
                hits.append("%#x %s %#x" % (site, kind, dest))
                if len(hits) >= limit:
                    break
        lines = [self.header(), "%d direct site(s) -> %#x" % (len(hits), target)]
        lines.extend(hits)
        return "\n".join(lines)

    def xrefs(self, target: int, limit: int = 40) -> str:
        """References to `target`.

        64-bit: rip-relative LEA and MOV. 32-bit: the absolute address stored
        little-endian in an executable section (KotOR's swkotor.exe).
        """
        if self.bits == 32:
            return self._xrefs_abs(target, limit)
        hits = []
        for section in self.sections:
            if not (section.Characteristics & 0x20000000):
                continue
            start = section.PointerToRawData
            raw = self.data[start : start + section.SizeOfRawData]
            base = section.VirtualAddress
            index = 0
            while index + 7 <= len(raw) and len(hits) < limit:
                if raw[index] in (0x48, 0x4C) and raw[index + 1] in (0x8D, 0x8B) and (raw[index + 2] & 0xC7) == 0x05:
                    disp = int.from_bytes(raw[index + 3 : index + 7], "little", signed=True)
                    site = base + index
                    dest = site + 7 + disp
                    if dest == target:
                        hits.append("%#x -> %#x" % (site, dest))
                    index += 7
                    continue
                index += 1
        text = self.string_at(target) or ""
        lines = [self.header(), "%d rip-relative ref(s) -> %#x %s" % (len(hits), target, text)]
        lines.extend(hits)
        return "\n".join(lines)

    def _xrefs_abs(self, target: int, limit: int) -> str:
        needle = (self.base + target).to_bytes(4, "little")
        hits = []
        for section in self.sections:
            if not (section.Characteristics & 0x20000000):
                continue
            raw = self.data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]
            start = 0
            while len(hits) < limit:
                found = raw.find(needle, start)
                if found < 0:
                    break
                hits.append("%#x -> %#x" % (section.VirtualAddress + found, target))
                start = found + 1
        lines = [self.header(), "%d absolute ref(s) -> %#x" % (len(hits), target)]
        lines.extend(hits)
        return "\n".join(lines)

    def find_strings(self, pattern: str, limit: int = 30) -> str:
        regex = re.compile(pattern.encode("utf-8"))
        lines = [self.header()]
        count = 0
        for section in self.sections:
            raw = self.data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]
            for match in regex.finditer(raw):
                rva = section.VirtualAddress + match.start()
                lines.append("%#x %s" % (rva, match.group().decode("utf-8", "replace")))
                count += 1
                if count >= limit:
                    return "\n".join(lines)
        if count == 0:
            lines.append("(no match)")
        return "\n".join(lines)

    def _executable(self):
        found = [section for section in self.sections if section.Characteristics & 0x20000000]
        return found or list(self.sections[:1])

    def sections_text(self) -> str:
        lines = [self.header(), "bits %d" % self.bits]
        for section in self.sections:
            name = section.Name.rstrip(b"\0").decode("utf-8", "replace")
            marks = ""
            if section.Characteristics & 0x20000000:
                marks += "x"
            if section.Characteristics & 0x40000000:
                marks += "r"
            if section.Characteristics & 0x80000000:
                marks += "w"
            lines.append(
                "%-8s rva=%#x vsize=%#x raw=%#x %s"
                % (name, section.VirtualAddress, section.Misc_VirtualSize, section.SizeOfRawData, marks)
            )
        return "\n".join(lines)

    def imports_text(self, limit: int = 80) -> str:
        self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
        lines = [self.header()]
        count = 0
        for entry in getattr(self.pe, "DIRECTORY_ENTRY_IMPORT", []) or []:
            dll = entry.dll.decode("utf-8", "replace") if isinstance(entry.dll, bytes) else str(entry.dll)
            for item in entry.imports:
                if item.name:
                    label = item.name.decode("utf-8", "replace") if isinstance(item.name, bytes) else str(item.name)
                else:
                    label = "ord:%s" % item.ordinal
                lines.append("%s %s" % (dll, label))
                count += 1
                if count >= limit:
                    return "\n".join(lines)
        if count == 0:
            lines.append("(no imports)")
        return "\n".join(lines)

    def exports_text(self, limit: int = 80) -> str:
        self.pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
        lines = [self.header()]
        symbols = getattr(self.pe, "DIRECTORY_ENTRY_EXPORT", None)
        if symbols is None:
            lines.append("(no exports)")
            return "\n".join(lines)
        count = 0
        for item in symbols.symbols:
            name = item.name.decode("utf-8", "replace") if item.name else "ord:%s" % item.ordinal
            lines.append("%#x %s" % (item.address, name))
            count += 1
            if count >= limit:
                break
        if count == 0:
            lines.append("(no exports)")
        return "\n".join(lines)

    def sigscan(self, pattern: str, limit: int = 20) -> str:
        from rusticre.prologue import find_pattern, parse_expect

        expect = parse_expect(pattern)
        hits = []
        for section in self._executable():
            raw = self.data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]
            for offset in find_pattern(raw, expect, limit - len(hits)):
                hits.append("%#x" % (section.VirtualAddress + offset))
                if len(hits) >= limit:
                    break
            if len(hits) >= limit:
                break
        lines = [self.header(), "%d hit(s) for %s" % (len(hits), pattern)]
        lines.extend(hits)
        return "\n".join(lines)

    def callees(self, rva: int, limit: int = 30) -> str:
        bounds = self._bounds(rva)
        if bounds is None:
            begin, end = rva, rva + 0x200
            scope = "no pdata; scanned 0x200 bytes from %#x" % rva
        else:
            begin, end = bounds
            scope = "function %#x-%#x" % bounds
        blob = self.read_rva(begin, max(0, end - begin))
        hits = []
        for index in range(0, max(0, len(blob) - 5)):
            if blob[index] != 0xE8:
                continue
            rel = int.from_bytes(blob[index + 1 : index + 5], "little", signed=True)
            site = begin + index
            hits.append("%#x call %#x" % (site, site + 5 + rel))
            if len(hits) >= limit:
                break
        lines = [self.header(), scope, "%d direct call(s)" % len(hits)]
        lines.extend(hits)
        return "\n".join(lines)

    def inspect(self, rva: int) -> str:
        """One picture of a function: bounds, prologue, instructions, direct callers.

        This is the local stand-in for REA's function dossier. It does not
        start Ghidra. Ask ghidra_run when you need decompiler text.
        """
        return "\n".join((
            self.function_of(rva) if self._bounds(rva) else self.header() + "\nno pdata function contains %#x" % rva,
            self.disasm(rva, 16),
            self.callers(rva, 12),
        ))

    def _bounds(self, rva: int) -> tuple[int, int] | None:
        directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
        if directory.VirtualAddress == 0 or directory.Size < 12:
            return None
        blob = self.read_rva(directory.VirtualAddress, directory.Size)
        count = len(blob) // 12
        lo = 0
        hi = count
        while lo < hi:
            mid = (lo + hi) // 2
            begin, end, _unwind = _runtime_function(blob, mid)
            if rva < begin:
                hi = mid
            elif rva >= end:
                lo = mid + 1
            else:
                return begin, end
        return None

    def function_of(self, rva: int) -> str:
        """The pdata function that contains `rva`, plus its first 32 bytes."""
        found = self._bounds(rva)
        lines = [self.header()]
        if found is None:
            directory = self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[3]
            if directory.VirtualAddress == 0 or directory.Size < 12:
                raise ValueError("this exe has no exception directory; function bounds need pdata")
            lines.append("no pdata function contains %#x" % rva)
            return "\n".join(lines)
        begin, end = found
        first = self.read_rva(begin, 32)
        lines.append("function %#x-%#x size %#x" % (begin, end, end - begin))
        lines.append("prologue %s" % " ".join("%02X" % byte for byte in first))
        return "\n".join(lines)


def _runtime_function(blob: bytes, index: int) -> tuple[int, int, int]:
    offset = index * 12
    begin = int.from_bytes(blob[offset : offset + 4], "little")
    end = int.from_bytes(blob[offset + 4 : offset + 8], "little")
    unwind = int.from_bytes(blob[offset + 8 : offset + 12], "little")
    return begin, end, unwind


def _rip_note(image: Image, insn) -> str:
    if "rip" not in insn.op_str:
        return ""
    try:
        disp_text = insn.op_str.split("rip", 1)[1].split("]", 1)[0].replace(" ", "")
        disp = int(disp_text, 16)
    except (IndexError, ValueError):
        return ""
    dest = insn.address + insn.size + disp
    text = image.string_at(dest)
    note = "  ; -> %#x" % dest
    if text:
        note += ' "%s"' % text
    return note


def _file_version(pe) -> str:
    try:
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_RESOURCE"]])
    except Exception:
        return ""
    if not hasattr(pe, "FileInfo"):
        return ""
    for entry in pe.FileInfo or []:
        for item in getattr(entry, "StringTable", []) or []:
            for key, value in item.entries.items():
                if key.decode("utf-8", "replace").lower() in ("fileversion", "productversion"):
                    return value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    return ""


def parse_rva(text: str, image_base: int = 0x140000000) -> int:
    value = int(str(text), 0)
    if value >= image_base:
        return value - image_base
    return value
