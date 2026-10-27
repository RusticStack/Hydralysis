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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_fixtures import target_name  # noqa: E402

re = Client()
ARCHES = ("x64", "x86")


MANIFEST: dict = {}


def load(out_dir: str) -> dict:
    MANIFEST.update(json.loads((Path(out_dir) / "manifest.json").read_text()))
    return MANIFEST


def target(arch: str, exe: str) -> str:
    return target_name(arch + "/" + exe, MANIFEST[arch + "/" + exe])


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


class Running:
    """A fixture process under a RusticRE runtime session; stopped through its stop file."""

    def __init__(self, arch: str, exe: str):
        build = MANIFEST[arch + "/" + exe]
        self.build, self.stop_file = build, Path(build["path"]).with_suffix(".stop")
        self.stop_file.unlink(missing_ok=True)
        started = re.runtime("spawn", exe=build["path"], sha256=build["sha256"], argv=[str(self.stop_file)],
                             cwd=str(Path(build["path"]).parent))
        self.session, self.owner = started["session"], started["owner"]
        re.runtime("resume", session=self.session, owner=self.owner)
        modules = re.runtime("modules", session=self.session, limit=50)
        main = next(m for m in modules["modules"] if m["name"].lower() == Path(build["path"]).name.lower())
        self.delta = int(main["base"], 16) - int(build["image_base"], 16)

    def live(self, name: str) -> int:
        """A global's address in the running process (the map's VA moved by the load base)."""
        return int(self.build["globals"][name], 16) + self.delta

    def call(self, action: str, **options):
        return re.runtime(action, session=self.session, owner=self.owner, **options)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        try:
            re.runtime("detach", session=self.session, owner=self.owner)
        except Exception as error:  # still report the check
            print("  detach:", error)
        self.stop_file.write_text("stop")


def check_writers(manifest: dict) -> list[str]:
    """Item 13: of the static store sites at Config.limit's offset, the live ones writing g_config
    are exactly those of fx_store, fx_reset and fx_clamp (x86 folds fx_pair into fx_store)."""
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        name, functions = target(arch, "flow_fixture.exe"), build["functions"]
        names = {}
        for function, address in functions.items():
            names.setdefault(int(address, 16), []).append(function)
        rows = re.query(name, "writes", limit=32, timeout_s=120, offset="0x4")["writes"]
        expected = {"fx_store", "fx_reset", "fx_clamp"}
        with Running(arch, "flow_fixture.exe") as running:
            answer = running.call("writers", target=name, rows=rows, object=hex(running.live("g_config")), offset="0x4",
                                  size=4, window_s=3)
        writers = set()
        for site in answer["writers"]:
            writers.update(names.get(int(site["site"], 16) - 0, []) or names.get(_entry(name, site["site"]), [site["site"]]))
        refused = [s for s in answer["sites"] if not s.get("probed")]
        shared = [s for s in answer["writers"] if s.get("other_objects")]
        ok = expected <= writers and not (writers - expected - {"fx_pair"})
        print("%s writers %s: %s; %d of %d sites probed; sites that also wrote other objects: %s"
              % ("PASS" if ok else "FAIL", arch, sorted(writers), len(answer["sites"]) - len(refused), len(answer["sites"]),
                 [(s["site"], s["other_objects"]) for s in shared]))
        for site in refused[:3]:
            print("   not probed", site["site"], site["reason"][:120])
        if not ok:
            failures.append("writers " + arch)
    return failures


def _entry(name: str, site: str) -> int:
    function = re.try_query(name, "function", site)
    return int(function["function"]["address"], 16) if function else 0


CHECKS = {"value_flow": check_value_flow, "writers": check_writers}


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
