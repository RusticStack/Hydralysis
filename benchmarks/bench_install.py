"""Backend install from a pre-downloaded archive cache (row C1-13: about 18 s). Never fails on download time.

    python benchmarks/bench_install.py --cached-archives <dir with the engine zip and the client zip> --out <logs>

Runs the install code path (`hydralysis.hydra.install` with the installer's own verify and unpack) in a fresh root after
copying the two archives into its download cache, so the network is out of the figure: the time is verify SHA-256,
unpack and validate. The archive names and hashes are the ones pinned in `hydralysis.hydra.ASSETS`; an archive that
is missing or does not match is reported, not downloaded. This is a measurement, not a gate: the exit code is 0.
"""

from __future__ import annotations

import argparse
import json
import shutil
import time
from pathlib import Path

import bench_common as common


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--cached-archives", required=True)
    parser.add_argument("--out")
    parser.add_argument("--root")
    parser.add_argument("--runs", type=int, default=3)
    args = parser.parse_args(argv)
    from hydralysis import backends, hydra
    out = common.output_dir(args.out)
    cache = Path(args.cached_archives)
    report = {"script": "bench_install", "rows": ["C1-13"], "machine": common.machine(), "load_before": common.foreign_load(),
              "pinned_release": hydra.RELEASE, "archives": {}, "runs": [], "measured": False}
    for kind, asset in hydra.ASSETS.items():
        name = asset["url"].rsplit("/", 1)[-1]
        found = cache / name
        report["archives"][kind] = {"expected_name": name, "expected_sha256": asset["sha256"],
                                    "found": str(found) if found.is_file() else None,
                                    "sha256_ok": found.is_file() and common.sha256_of(found) == asset["sha256"]}
    if not all(item["sha256_ok"] for item in report["archives"].values()):
        report["note"] = "pre-downloaded archives are missing or do not match the pinned hashes; nothing was installed or downloaded"
    else:
        for _ in range(args.runs):
            root = common.fresh_root(args, "install")
            started = time.perf_counter()
            try:
                downloads = root / "data" / "downloads"
                downloads.mkdir(parents=True)
                for item in report["archives"].values():
                    shutil.copy2(item["found"], downloads / Path(item["found"]).name)
                started = time.perf_counter()
                hydra.install({"root": str(root / "data")}, backends._download, backends._extract)
                report["runs"].append({"seconds": round(time.perf_counter() - started, 3), "file_system": common.file_system(root)})
            except Exception as exc:
                report["runs"].append({"seconds": round(time.perf_counter() - started, 3),
                                       "error": "%s: %s" % (type(exc).__name__, str(exc)[:400])})
            finally:
                common.cleanup(root)
        good = [r["seconds"] for r in report["runs"] if "error" not in r]
        report["measured"] = bool(good)
        report["seconds"] = common.summarize(good)
        report["budget"] = common.judge("bench_install.seconds.median", report["seconds"]["median"])
    report["load_after"] = common.foreign_load()
    path = common.write_report(out, "bench_install", report)
    print(json.dumps({"report": str(path), "measured": report["measured"], "note": report.get("note"),
                      "seconds": report.get("seconds")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
