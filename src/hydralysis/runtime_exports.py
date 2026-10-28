"""A module's export table, read from its file on disk, for hooks named by export instead of by RVA.

The table is the file's, not the running process's: the worker checks the name against the file the build hash
names, then the probe checks again that the live module's own export of that name is the same address.
"""

from __future__ import annotations

import re
from pathlib import Path

_NAME = re.compile(r"^[\x21-\x7e]{1,256}$")


def export_table(image) -> list[dict]:
    """Every export of a parsed `pe.Image`: name (None for an ordinal-only one), ordinal, rva, forwarder (or None)."""
    import pefile
    pe = image.pe
    pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    directory = getattr(pe, "DIRECTORY_ENTRY_EXPORT", None)
    if directory is None:
        return []
    rows = []
    for symbol in directory.symbols:
        rows.append({"name": symbol.name.decode("latin-1") if symbol.name else None, "ordinal": int(symbol.ordinal),
                     "rva": int(symbol.address),
                     "forwarder": symbol.forwarder.decode("latin-1") if symbol.forwarder else None})
    return rows


def resolve_export(table: list[dict], name: str) -> dict:
    """The one export called `name` (or `#<ordinal>`), refusing an absent, ambiguous or forwarded one."""
    if not isinstance(name, str) or not _NAME.match(name):
        raise ValueError("export must be an export name (printable ASCII, at most 256) or #<ordinal>")
    if name.startswith("#"):
        if not re.fullmatch(r"#[0-9]{1,5}", name):
            raise ValueError("an export ordinal is written #<number>")
        matches = [row for row in table if row["ordinal"] == int(name[1:])]
    else:
        matches = [row for row in table if row["name"] == name]
    if not matches:
        named = sorted(row["name"] for row in table if row["name"])
        close = [item for item in named if name.lower() in item.lower()][:8]
        raise ValueError("the module's export table has no export %s (%d exports%s)"
                         % (name, len(table), "; similar: " + ", ".join(close) if close else ""))
    if len(matches) > 1:
        raise ValueError("export %s is listed %d times in the module's export table; use its ordinal" % (name, len(matches)))
    row = matches[0]
    if row["forwarder"]:
        raise ValueError("export %s is a forward to %s, not code in this module; hook it in the module that defines it"
                         % (name, row["forwarder"]))
    return row


def module_export(path: str, name: str, image=None) -> dict:
    """Resolve `name` in the export table of the module file at `path`."""
    if image is None:
        from hydralysis.pe import Image
        image = Image(Path(path))
    return resolve_export(export_table(image), name)
