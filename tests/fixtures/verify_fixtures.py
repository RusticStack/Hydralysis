"""Run the verification checks against the prepared fixtures (docs/verification-fixtures.md).

usage: python tests/fixtures/verify_fixtures.py <fixtures out dir> [check ...]
Each check prints PASS/FAIL with its evidence; the exit status is the number of failures.
RUSTICRE_CONFIG selects the data root the fixtures were prepared in (prepare_fixtures.py).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rusticre.client import Client

re = Client()
ARCHES = ("x64", "x86")


def load(out_dir: str) -> dict:
    return json.loads((Path(out_dir) / "manifest.json").read_text())


def target(arch: str, exe: str) -> str:
    return "fx-%s-%s" % (arch, exe.removesuffix(".exe").replace("_fixture", ""))


def last_load(name: str, address: str) -> str:
    operations = re.query(name, "pcode", address, nodes=200)["operations"]
    loads = [op for op in operations if op["opcode"] == "LOAD"]
    return loads[-1]["id"]


def check_value_flow(manifest: dict) -> list[str]:
    """Item 3: fx_read's value traced back through fx_relay -> fx_store is the constant 0x2A."""
    failures = []
    for arch in ARCHES:
        name, functions = target(arch, "flow_fixture.exe"), manifest[arch + "/flow_fixture.exe"]["functions"]
        trace = re.query(name, "trace", functions["fx_read"], timeout_s=120, seed=last_load(name, functions["fx_read"]),
                         direction="backward", depth=12, functions=4, callers=2, brief=True)
        values = [c for c in trace["constants"] if c.get("role") == "value"]
        found = [c["value"] for c in values]
        via = [hop.get("via") for hop in values[0]["path_to_seed"]] if values else []
        ok = found == ["0x2a"] and "field_store" in via
        print("%s value_flow %s: value constants %s via %s" % ("PASS" if ok else "FAIL", arch, found, via))
        if not ok:
            failures.append("value_flow " + arch)
    return failures


CHECKS = {"value_flow": check_value_flow}


def main(argv: list[str]) -> int:
    manifest = load(argv[0])
    selected = argv[1:] or list(CHECKS)
    failures = []
    for name in selected:
        failures += CHECKS[name](manifest)
    print("%d check(s) failed: %s" % (len(failures), failures) if failures else "all checks passed")
    return len(failures)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
