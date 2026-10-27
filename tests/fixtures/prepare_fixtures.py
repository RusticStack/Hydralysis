"""Prepare every built fixture as an analysis target (fx-<arch>-<name>-<sha8>) and wait for the jobs.

A target name belongs to one build, so a changed fixture gets a new name rather than replacing one.

usage: python tests/fixtures/prepare_fixtures.py <fixtures out dir>   (HYDRALYSIS_CONFIG selects the root)
"""

from __future__ import annotations

import json
import sys
import time
from pathlib import Path

from hydralysis.client import Client


def target_name(key: str, build: dict) -> str:
    arch, exe = key.split("/")
    return "fx-%s-%s-%s" % (arch, exe.removesuffix(".exe").replace("_fixture", ""), build["sha256"][:8])


def main(out_dir: str) -> int:
    manifest = json.loads((Path(out_dir) / "manifest.json").read_text())
    re = Client()
    jobs = {}
    for key, build in manifest.items():
        target = target_name(key, build)
        started = re.call("prepare", exe=build["path"], target=target)
        jobs[target] = started.get("job_id")
        print(target, started.get("state"), started.get("job_id"))
    failed = 0
    for target, job in jobs.items():
        if not job:
            continue
        while True:
            status = re.call("job", id=job)
            if status["state"] not in ("queued", "running"):
                break
            time.sleep(3)
        verification = status.get("verification") or {}
        print(target, status["state"], verification.get("functions"), status.get("error", ""))
        failed += status["state"] != "done"
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
