"""Write native/hydralysis-mcp/catalog.json from api.py and mcp.py.

The native MCP host answers initialize and tools/list from this file, so the advertised table, its epoch and hash, the
instructions text and the lane constants are exactly the Python server's. Run it whenever api.py's tool table, the
instructions, CATALOG_EPOCH, the version or the mcp.py lane constants change; tests/test_mcp_native.py fails when the
checked-in file is stale.

    python tools/gen_mcp_catalog.py [--check]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

TARGET = ROOT / "native" / "hydralysis-mcp" / "catalog.json"


def build() -> dict:
    from hydralysis import __version__, api, mcp
    return {
        "version": __version__,
        "epoch": api.CATALOG_EPOCH,
        "hash": api.catalog_hash(),
        "instructions": api.instructions(),
        "tool_names": list(api.TOOL_NAMES),
        "engine_tools": sorted(mcp.ENGINE_TOOLS),
        "long_tools": sorted(mcp.LONG_TOOLS),
        "long_trace_actions": sorted(mcp.LONG_TRACE_ACTIONS),
        "protocol_versions": list(mcp.PROTOCOL_VERSIONS),
        "max_output_bytes": mcp.MAX_OUTPUT_BYTES,
        "retry_after_ms": mcp.RETRY_AFTER_MS,
        "engine_parallel_max": mcp.ENGINE_PARALLEL_MAX,
        "long_slots": mcp.LONG_SLOTS,
        "engine_slots_min": mcp.ENGINE_SLOTS_MIN,
        "engine_slots_max": mcp.ENGINE_SLOTS_MAX,
        "tools": api.tool_table(),
    }


def render() -> str:
    return json.dumps(build(), ensure_ascii=True, separators=(",", ":")) + "\n"


def main(argv: list[str]) -> int:
    text = render()
    if "--check" in argv:
        current = TARGET.read_text(encoding="utf-8") if TARGET.is_file() else ""
        if current != text:
            print("%s is stale; run python tools/gen_mcp_catalog.py" % TARGET, file=sys.stderr)
            return 1
        return 0
    TARGET.write_text(text, encoding="utf-8", newline="\n")
    print("wrote %s (%d bytes)" % (TARGET, len(text)))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
