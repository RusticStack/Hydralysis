"""Persists a working copy's committed overlay changes, off the edit path.

Saving a large program writes its database whole (about 35 s for a 1.5 GB
project), so edits return once committed in the engine and this process saves
after edits pause. One saver per target (an OS lock). Losing an unsaved change is
safe: the overlay store is the record, and the next sync replays what the
program's marker shows it lost.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

from rusticre import hydra, targets
from rusticre.backends import read_json, write_json
from rusticre.locks import LaneLock, locked

MAX_RUN_S = 4 * 3600


def run(directory: Path, name: str) -> int:
    lease = LaneLock(str(directory / ".saver.lock"))
    if not lease.acquire():
        return 0
    try:
        settings = read_json(directory / "saver-settings.json")
        # Saving only shortens a restart (the store is the record; lost changes are replayed),
        # and it holds the program for minutes on a large project, so it waits for a quiet time.
        debounce = float(settings.get("overlay_save_debounce_s", 600))
        target = targets.resolve(settings, name)
        started = time.monotonic()
        while time.monotonic() - started < MAX_RUN_S:
            state = read_json(directory / "state.json")
            quiet = time.time() - float(state.get("updated_at", 0))
            if state.get("saved_at") and state["saved_at"] >= state.get("updated_at", 0):
                return 0
            if quiet < debounce:
                time.sleep(min(debounce - quiet, debounce) + 0.1)
                continue
            from rusticre.query import forget, open_program
            engine = hydra.Engine(settings, role="saver")
            try:
                program = open_program(engine, state["fork_gpr"], target["program"], target["sha256"],
                                       writable=True, upgrade=True, refresh=True)
                began = time.time()
                info = engine.call("info", program=program["key"])
                if info.get("changed"):
                    print(time.strftime("%H:%M:%S"), "saving", program["key"], flush=True)
                    saved = engine.call("save", program=program["key"], comment="RusticRE overlays", wait=600000)
                    print(time.strftime("%H:%M:%S"), "saved revision", saved.get("revision"), "in %.1fs" % (time.time() - began), flush=True)
                with locked(directory / ".sync.lock", 120, "working copy"):
                    latest = read_json(directory / "state.json")
                    if latest.get("updated_at", 0) <= began and latest.get("fork_gpr") == state["fork_gpr"]:
                        latest["saved_at"] = time.time()
                        write_json(directory / "state.json", latest)
                        return 0
            finally:
                engine.reset()
                forget(engine)
        return 0
    finally:
        lease.release()


if __name__ == "__main__":
    raise SystemExit(run(Path(sys.argv[1]).resolve(), sys.argv[2]))
