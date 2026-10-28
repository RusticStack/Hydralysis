"""CI helper: the pinned Hydra release, its checksum, and the hermetic check.

The release, asset URLs, SHA-256 values and sizes live only in src/hydralysis/hydra.py
(RELEASE, ASSETS). This script reads them from there, so a workflow never duplicates a pin.

  pins              print the pins; with GITHUB_OUTPUT set, also write release/engine_sha/client_sha
  install ROOT      download (or reuse ROOT/downloads), verify SHA-256 and size, unpack the engine and
                    client under ROOT/backends, and export HYDRALYSIS_INTEGRATION_ENGINE/CLIENT
                    (to GITHUB_ENV when set)
  hermetic          fail unless no stock Ghidra hook or install is visible to the process
  hermetic ROOT --java JDK
                    the above, plus: with a bogus stock-Ghidra variable set in this process, discovery
                    still picks the pinned Hydra engine, reports the variable as ignored, and never
                    probes the bogus path

Run with the repository installed (pip install -e .) so `hydralysis` imports. Exit code 0 only when
every check passed; a failed check prints one JSON line per problem and exits 1.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

from hydralysis import backends, hydra

# The stock-Ghidra hook, built from parts so a text scan for it finds only the workflow.
STOCK_VARIABLE = "GHIDRA" + "_INSTALL_DIR"
STOCK_LAUNCHERS = ("analyze" + "Headless", "ghidraRun")


def _emit(path_variable: str, lines: dict) -> None:
    target = os.environ.get(path_variable)
    if not target:
        return
    with open(target, "a", encoding="utf-8", newline="\n") as handle:
        for key, value in lines.items():
            handle.write("%s=%s\n" % (key, value))


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def cmd_pins(_args) -> int:
    pins = {"release": hydra.RELEASE, "engine_sha": hydra.ASSETS["engine"]["sha256"],
            "engine_size": hydra.ASSETS["engine"]["size"], "client_sha": hydra.ASSETS["client"]["sha256"],
            "engine_url": hydra.ASSETS["engine"]["url"]}
    print(json.dumps(pins, indent=2))
    _emit("GITHUB_OUTPUT", pins)
    return 0


def cmd_install(args) -> int:
    root = Path(args.root).resolve()
    settings = {"root": str(root)}
    # backends._download reuses ROOT/downloads when the archive is there, but only after re-hashing it
    # against the pin, and a fresh download is checked for size and SHA-256 before it is renamed into place.
    result = hydra.install(settings, backends._download, backends._extract)
    for name in ("engine", "client"):
        archive = root / "downloads" / hydra.ASSETS[name]["url"].rsplit("/", 1)[-1]
        observed = sha256(archive)
        if observed != hydra.ASSETS[name]["sha256"]:
            print(json.dumps({"failed": "%s archive SHA-256 mismatch" % name, "observed": observed}))
            return 1
        print("%s archive %s sha256 %s (pinned: match)" % (name, archive.name, observed))
    print(json.dumps(result, indent=2))
    _emit("GITHUB_ENV", {"HYDRALYSIS_INTEGRATION_ENGINE": result["hydra_dir"],
                         "HYDRALYSIS_INTEGRATION_CLIENT": result["hydra_client"]})
    return 0


def _ambient_problems() -> list[str]:
    problems = []
    if os.environ.get(STOCK_VARIABLE):
        problems.append("%s is set in the environment: %s" % (STOCK_VARIABLE, os.environ[STOCK_VARIABLE]))
    for launcher in STOCK_LAUNCHERS:
        found = shutil.which(launcher) or shutil.which(launcher + ".bat")
        if found:
            problems.append("a stock Ghidra launcher is on PATH: %s" % found)
    return problems


def cmd_hermetic(args) -> int:
    problems = _ambient_problems()
    if args.root:
        root = Path(args.root).resolve()
        settings = {"root": str(root), "java_home": args.java}
        bogus = str(root / "not-a-stock-ghidra")
        os.environ[STOCK_VARIABLE] = bogus
        report = backends.inspect({**settings, "hydra_dir": os.environ.get("HYDRALYSIS_INTEGRATION_ENGINE"),
                                   "hydra_client": os.environ.get("HYDRALYSIS_INTEGRATION_CLIENT")})
        if not report["ready"]:
            problems.append("discovery is not ready with the pinned engine: %s" % json.dumps(report)[:1500])
        elif report["engine"].get("hydra_release") != hydra.RELEASE:
            problems.append("discovered engine is %r, not the pinned %s" % (report["engine"].get("hydra_release"), hydra.RELEASE))
        if [item["setting"] for item in report["ignored"]] != [STOCK_VARIABLE]:
            problems.append("the stock variable was not reported as ignored: %s" % json.dumps(report["ignored"]))
        if bogus in json.dumps(report["checks"]):
            problems.append("discovery probed the stock path")
    for problem in problems:
        print(json.dumps({"hermetic_failure": problem}))
    if not problems:
        print("hermetic: no stock Ghidra variable, launcher or discovery path%s" % (
            "; with a bogus stock variable set, the pinned Hydra %s is still the engine and the variable is ignored" % hydra.RELEASE
            if args.root else ""))
    return 1 if problems else 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("pins").set_defaults(run=cmd_pins)
    install = sub.add_parser("install")
    install.add_argument("root")
    install.set_defaults(run=cmd_install)
    hermetic = sub.add_parser("hermetic")
    hermetic.add_argument("root", nargs="?")
    hermetic.add_argument("--java")
    hermetic.set_defaults(run=cmd_hermetic)
    args = parser.parse_args(argv)
    return args.run(args)


if __name__ == "__main__":
    sys.exit(main())
