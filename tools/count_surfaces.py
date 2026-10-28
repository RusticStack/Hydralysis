"""Write the three tool-surface counts of docs/data/tool-surfaces.json.

  python tools/count_surfaces.py                 write the file (Hydralysis count from tool_table())
  python tools/count_surfaces.py --check         exit 1 when the file differs from what would be written
  python tools/count_surfaces.py --ghidramcp PATH/server.py   recount the bridge's @mcp.tool functions
  python tools/count_surfaces.py --rea-metadata PATH.json     take the REA tool_count from skill metadata

Only the Hydralysis count can be reproduced here. Without the two options the recorded third-party
counts are kept as they are, and the file still says they are not reproduced.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SURFACES = ROOT / "docs" / "data" / "tool-surfaces.json"


def hydralysis_count() -> int:
    sys.path.insert(0, str(ROOT / "src"))
    try:
        from hydralysis.api import TOOL_NAMES, tool_table
    finally:
        sys.path.pop(0)
    table = tool_table()
    if [tool["name"] for tool in table] != list(TOOL_NAMES):
        raise SystemExit("tool_table() and TOOL_NAMES disagree")
    return len(table)


def ghidramcp_count(server: Path) -> int:
    return len(re.findall(r"^\s*@mcp\.tool\(", server.read_text(encoding="utf-8"), re.MULTILINE))


def rea_count(metadata: Path) -> int:
    return int(json.loads(metadata.read_text(encoding="utf-8"))["tool_count"])


def compute(current: dict, ghidramcp: Path | None = None, rea: Path | None = None) -> dict:
    result = json.loads(json.dumps(current))
    counts = {"hydralysis": hydralysis_count()}
    if ghidramcp is not None:
        counts["ghidramcp"] = ghidramcp_count(ghidramcp)
    if rea is not None:
        counts["rea"] = rea_count(rea)
    for surface in result["surfaces"]:
        if surface["id"] in counts:
            surface["count"] = counts[surface["id"]]
    return result


def render(data: dict) -> str:
    return json.dumps(data, indent=2) + "\n"


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--ghidramcp", type=Path)
    parser.add_argument("--rea-metadata", type=Path)
    parser.add_argument("--output", type=Path, default=SURFACES)
    args = parser.parse_args(argv)
    current = json.loads(SURFACES.read_text(encoding="utf-8"))
    wanted = render(compute(current, args.ghidramcp, args.rea_metadata))
    for surface in json.loads(wanted)["surfaces"]:
        print("%s: %d" % (surface["id"], surface["count"]))
    if args.check:
        same = args.output.is_file() and args.output.read_text(encoding="utf-8") == wanted
        if not same:
            print("docs/data/tool-surfaces.json is out of date", file=sys.stderr)
        return 0 if same else 1
    args.output.write_text(wanted, encoding="utf-8", newline="\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
