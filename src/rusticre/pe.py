"""Reads for any PE you own. 32-bit and 64-bit.

The header line is the build. Quote it with every address.
Nothing in here knows which game the file came from.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
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
        self.bits = 32 if self.pe.OPTIONAL_HEADER.Magic == 0x10B else 64
        self._fingerprint = None
        self.sections = []
        for section in self.pe.sections:
            name = section.Name.rstrip(b"\0").decode("utf-8", "replace")
            self.sections.append(section)
            if name == ".text":
                self.text = section
        if not self.sections:
            raise ValueError("PE has no sections")
        if not hasattr(self, "text"):
            self.text = self.pe.sections[0]

    def fingerprint(self) -> dict:
        if self._fingerprint is not None:
            return dict(self._fingerprint)
        info = {
            "exe": self.path.name,
            "size": len(self.data),
            "timeDateStamp": hex(self.pe.FILE_HEADER.TimeDateStamp),
            "sha256": hashlib.sha256(self.data).hexdigest(),
            "image_base": hex(self.base),
            "machine": hex(self.machine),
            "bits": self.bits,
            "entry_point_rva": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
        }
        version = _file_version(self.pe)
        if version:
            info["file_version"] = version
        warnings = []
        entry = self.pe.OPTIONAL_HEADER.AddressOfEntryPoint
        entry_section = None
        for section in self.sections:
            name = section.Name.rstrip(b"\0").decode("utf-8", "replace")
            if section.VirtualAddress <= entry < section.VirtualAddress + max(section.Misc_VirtualSize, section.SizeOfRawData):
                entry_section = section
                info["entry_point_section"] = name
            if name.lower() in (".bind", "upx0", "upx1", "upx2", ".aspack", ".adata", ".vmp0", ".vmp1", ".themida"):
                warnings.append("section %s is a known wrapper/packer indicator" % name)
        if entry_section is None:
            warnings.append("entry point is outside the section table")
        else:
            if not entry_section.Characteristics & 0x20000000:
                warnings.append("entry point is in a non-executable section")
            raw = self._section_data(entry_section)[:65536]
            if raw:
                entropy = -sum((count / len(raw)) * math.log2(count / len(raw)) for count in Counter(raw).values())
                if entropy >= 7.5:
                    warnings.append("entry section entropy %.2f bits/byte in first %d raw bytes; compressed/encrypted data is possible" % (entropy, len(raw)))
        info["analysis_warnings"] = warnings
        info["packing_status"] = "suspected; indicators are not proof" if warnings else "no obvious indicators; not proof of unpacked code"
        self._fingerprint = info
        return dict(info)

    def header(self) -> str:
        info = self.fingerprint()
        extra = ""
        if "file_version" in info:
            extra += " version " + info["file_version"]
        line = "# exe %s size %d tds %s sha256 %s%s" % (
            info["exe"],
            info["size"],
            info["timeDateStamp"],
            info["sha256"],
            extra,
        )
        line += "\n# bits %d image_base %s entry_rva %s" % (info["bits"], info["image_base"], info["entry_point_rva"])
        if info["analysis_warnings"]:
            line += "\n# CAUTION: possible packed/wrapped or unusual image: " + "; ".join(info["analysis_warnings"])
            line += ". Verify the analysed project's executable SHA-256 before trusting decompiler text."
        return line

    def rva_to_offset(self, rva: int) -> int | None:
        for section in self.sections:
            start = section.VirtualAddress
            size = section.SizeOfRawData
            if start <= rva < start + size:
                offset = rva - start + section.PointerToRawData
                return offset if 0 <= offset < len(self.data) else None
        return None

    def _available(self, rva: int) -> int:
        for section in self.sections:
            relative = rva - section.VirtualAddress
            if 0 <= relative < section.SizeOfRawData:
                return max(0, min(section.SizeOfRawData - relative, len(self.data) - section.PointerToRawData - relative))
        return 0

    def _section_data(self, section) -> bytes:
        start = section.PointerToRawData
        return self.data[start : start + section.SizeOfRawData]

    def _decoder(self):
        if self.machine not in (0x14C, 0x8664):
            raise ValueError("instruction decoding supports x86/x64 only; PE machine is %#x" % self.machine)
        mode = capstone.CS_MODE_32 if self.bits == 32 else capstone.CS_MODE_64
        return capstone.Cs(capstone.CS_ARCH_X86, mode)

    def read_rva(self, rva: int, size: int) -> bytes:
        if rva < 0 or size < 0:
            raise ValueError("RVA and size must be non-negative")
        offset = self.rva_to_offset(rva)
        if offset is None:
            raise ValueError("rva %#x is not in a section of %s" % (rva, self.path.name))
        if size > self._available(rva):
            raise ValueError("read at rva %#x size %#x crosses the file-backed section boundary" % (rva, size))
        return self.data[offset : offset + size]

    def string_at(self, rva: int, limit: int = 80) -> str | None:
        try:
            raw = self.read_rva(rva, min(limit, self._available(rva)))
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
        md = self._decoder()
        if count <= 0:
            raise ValueError("instruction count must be positive")
        blob = self.read_rva(rva, min(count * 16, self._available(rva)))
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
        """Byte candidates, not verified instruction boundaries or a complete call graph."""
        self._decoder()
        hits = []
        for section in self._executable():
            raw = self._section_data(section)
            for match in re.finditer(b"[\xe8\xe9]", raw):
                index = match.start()
                if index + 5 > len(raw):
                    continue
                rel = int.from_bytes(raw[index + 1 : index + 5], "little", signed=True)
                site = section.VirtualAddress + index
                dest = site + 5 + rel
                if dest == target:
                    kind = "E8 call candidate" if raw[index] == 0xE8 else "E9 jump candidate"
                    hits.append("%#x %s -> %#x" % (site, kind, dest))
                    if len(hits) >= limit:
                        break
            if len(hits) >= limit:
                break
        lines = [self.header(), "%d byte candidate(s) -> %#x; instruction boundaries unverified; limit %d" % (len(hits), target, limit)]
        lines.extend(hits)
        if len(hits) >= limit:
            lines.append("[limit reached; results may be incomplete]")
        return "\n".join(lines)

    def xrefs(self, target: int, limit: int = 40) -> str:
        """References to `target`.

        64-bit: rip-relative LEA and MOV. 32-bit: the absolute address stored
        little-endian in an executable section. These are byte candidates.
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
            for match in re.finditer(b"[\x48\x4c][\x8d\x8b]", raw):
                index = match.start()
                if index + 7 <= len(raw) and (raw[index + 2] & 0xC7) == 0x05:
                    disp = int.from_bytes(raw[index + 3 : index + 7], "little", signed=True)
                    site = base + index
                    dest = site + 7 + disp
                    if dest == target:
                        hits.append("%#x -> %#x" % (site, dest))
                    if len(hits) >= limit:
                        break
            if len(hits) >= limit:
                break
        text = self.string_at(target) or ""
        lines = [self.header(), "%d RIP-relative byte candidate(s) -> %#x %s; instruction boundaries unverified; limit %d" % (len(hits), target, text, limit)]
        lines.extend(hits)
        if len(hits) >= limit:
            lines.append("[limit reached; results may be incomplete]")
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
        lines = [self.header(), "%d absolute byte candidate(s) -> %#x; instruction boundaries unverified; limit %d" % (len(hits), target, limit)]
        lines.extend(hits)
        if len(hits) >= limit:
            lines.append("[limit reached; results may be incomplete]")
        return "\n".join(lines)

    def find_strings(self, pattern: str, limit: int = 30) -> str:
        regex = re.compile(pattern)
        lines = [self.header()]
        count = 0
        for section in self.sections:
            raw = self.data[section.PointerToRawData : section.PointerToRawData + section.SizeOfRawData]
            for encoding, printable in (("ascii", rb"[\x20-\x7e]{4,}"),
                                        ("utf-16le", rb"(?:[\x20-\x7e]\x00){4,}")):
                for match in re.finditer(printable, raw):
                    text = match.group().decode(encoding)
                    if not regex.search(text):
                        continue
                    # Return the whole string's start, not the matching substring:
                    # xrefs point to the string start even when a suffix matched.
                    rva = section.VirtualAddress + match.start()
                    clipped = text[:512] + (" [text truncated]" if len(text) > 512 else "")
                    lines.append("%#x %s %s" % (rva, encoding, clipped))
                    count += 1
                    if count >= limit:
                        lines.append("[limit reached; results may be incomplete]")
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
                    lines.append("[limit reached; results may be incomplete]")
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
        if count >= limit:
            lines.append("[limit reached; results may be incomplete]")
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
        if len(hits) >= limit:
            lines.append("[limit reached; results may be incomplete]")
        return "\n".join(lines)

    def callees(self, rva: int, limit: int = 30) -> str:
        md = self._decoder()
        md.detail = True
        bounds = self._bounds(rva)
        if bounds is None:
            begin, end = rva, rva + min(0x200, self._available(rva))
            scope = "no pdata; linear decode from caller-supplied start %#x (unverified), at most 0x200 bytes" % rva
        else:
            begin, end = bounds
            scope = "function %#x-%#x" % bounds
        blob = self.read_rva(begin, max(0, end - begin))
        hits = []
        for insn in md.disasm(blob, begin):
            if insn.id == capstone.x86.X86_INS_CALL and insn.operands and insn.operands[0].type == capstone.x86.X86_OP_IMM:
                hits.append("%#x call %#x" % (insn.address, insn.operands[0].imm))
                if len(hits) >= limit:
                    break
        lines = [self.header(), scope, "%d decoded direct call(s); linear decode is not a complete control-flow graph; limit %d" % (len(hits), limit)]
        lines.extend(hits)
        if len(hits) >= limit:
            lines.append("[limit reached; results may be incomplete]")
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
        if self.machine != 0x8664:
            return None
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
        first = self.read_rva(begin, min(32, end - begin))
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
    versions = {}
    for group in pe.FileInfo or []:
        for entry in group if isinstance(group, (list, tuple)) else (group,):
            for item in getattr(entry, "StringTable", []) or []:
                for key, value in item.entries.items():
                    name = key.decode("utf-8", "replace") if isinstance(key, bytes) else str(key)
                    if name.lower() in ("fileversion", "productversion"):
                        versions[name.lower()] = value.decode("utf-8", "replace") if isinstance(value, bytes) else str(value)
    if versions:
        return versions.get("fileversion", versions.get("productversion", ""))
    return ""


def parse_rva(text: str, image_base: int = 0x140000000) -> int:
    text = str(text).strip().lower()
    prefix = ""
    if ":" in text:
        prefix, text = text.split(":", 1)
        if prefix not in ("rva", "va"):
            raise ValueError("address prefix must be rva: or va:")
    value = int(text, 0)
    if value < 0:
        raise ValueError("address must be non-negative")
    if prefix == "rva":
        return value
    if prefix == "va":
        if value < image_base:
            raise ValueError("VA is below this image's base")
        return value - image_base
    if value >= image_base:
        return value - image_base
    return value
