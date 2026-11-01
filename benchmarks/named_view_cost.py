"""Named-view build cost per phase, shared base against rebuilt base, and the replay run (rows C2-08, C2-57, D61).

    python benchmarks/named_view_cost.py --engine <dir> --client <ghidra_session.py> --root <fresh folder on the file system to
        measure> --out bench-out --runs 5 --views 1,4,12

Two runs of the same script, one with --root on NTFS and one on ReFS, give both file systems.

Named-view run: for each of 1, 4 and 12 simultaneous NEW views and each of the modes `shared` (the base of the master
is already built) and `rebuilt` (the base folder is removed first, so the views pay the base), N runs; every view makes
its first edit, which builds its working copy. The phases are the engine-side `last_sync.phases_ms` of that edit
(master_open, fork, copy, base_upgrade, open, replay, total), with the fork details (method, bytes, copyMs). One
fork is the whole `fork` figure of that view; with a shared base a view pays one fork (the working copy), and a
rebuilt base adds a second (the base) for the builder only, so the old "95.6 ms" can be read as one or two forks.

Replay run (--replay 1,100,1000,4096): a view holding that many pending records (added in one batch) loses its working
copy, as after an idle eviction (D61), and the first call afterwards replays the whole store onto a fresh fork of
the shared base. That wall time is compared with the 5 s per-call threshold; `viewKeepWarmRecords` (placeholder 1000)
is the store size from which the view is kept warm instead, so the verdict says which record counts are over it.

Exit status: 0 when every requested measurement was recorded, 1 when any replay record errored (for example a binary
with fewer label addresses than the requested count, such as the system whoami.exe fixture at 4,096) or a run failed.
"""

from __future__ import annotations

import argparse
import json
import shutil
import threading
import time
import uuid
from pathlib import Path

import mcp_latency as common

PER_CALL_THRESHOLD_S = 5.0
KEEP_WARM_RECORDS_PLACEHOLDER = 1000
PHASE_NAMES = ("master_open", "fork", "copy", "base_upgrade", "open", "replay", "total", "unattributed")


def with_unattributed(phases: dict | None) -> dict | None:
    """Add `unattributed`: total minus the timed phases (`copy` is inside `fork`). It is the writer connection,
    the state write and the retire pass, the part of the old 1.4 s that no phase names."""
    if not phases or "total" not in phases:
        return phases
    timed = sum(phases.get(name, 0) for name in ("master_open", "fork", "base_upgrade", "open", "replay"))
    return {**phases, "unattributed": phases["total"] - timed}


def _functions(runner, target: str, want: int) -> list[str]:
    listed = json.loads(runner.query(target, "functions", limit=max(want, 5)))["functions"]
    return [item["address"] for item in listed]


def _first_edit(runner, target: str, view: str, address: str, name: str) -> dict:
    started = time.monotonic()
    edited = json.loads(runner.query(target, "type_edit", address, timeout_s=300, options={
        "kind": "rename", "name": name, "source": "named_view_cost", "view": view, "expect_revision": 0}))
    sync = edited.get("sync") or {}
    return {"view": view, "wall_s": round(time.monotonic() - started, 3), "phases_ms": with_unattributed(sync.get("phases_ms")),
            "rebuilt": sync.get("rebuilt"), "fork": sync.get("fork"), "seconds": sync.get("seconds")}


def named_run(runner, settings: dict, target: str, addresses: list[str], count: int, mode: str, run: int) -> dict:
    from hydralysis import workcopy
    if mode == "rebuilt":
        shutil.rmtree(workcopy.bases_root(settings, runner.target(target)), ignore_errors=True)
    results: list = [None] * count
    errors: list = []
    barrier = threading.Barrier(count)

    def work(index: int) -> None:
        view = "nv-%s-%d-%d-%s" % (mode, count, run, index)
        try:
            barrier.wait(30)
            results[index] = _first_edit(runner, target, view, addresses[index % len(addresses)], "nv_%d_%d_%d" % (count, run, index))
        except Exception as exc:  # recorded, never hidden
            errors.append("%s: %s" % (type(exc).__name__, str(exc)[:500]))

    started = time.monotonic()
    threads = [threading.Thread(target=work, args=(i,)) for i in range(count)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    done = [r for r in results if r]
    return {"views": count, "mode": mode, "run": run, "wall_s": round(time.monotonic() - started, 3),
            "per_view": done, "errors": errors}


def aggregate(runs: list[dict]) -> dict:
    """Per phase: median/p95/max over every view of every run of one (views, mode) cell, in ms."""
    cell = {}
    for phase in PHASE_NAMES:
        values = [view["phases_ms"][phase] for run in runs for view in run["per_view"] if view.get("phases_ms") and phase in view["phases_ms"]]
        cell[phase] = common.summarize([float(v) for v in values])
    cell["wall_s"] = common.summarize([run["wall_s"] for run in runs])
    cell["views_that_rebuilt_the_base"] = sum(1 for run in runs for v in run["per_view"] if (v.get("phases_ms") or {}).get("base_upgrade"))
    cell["errors"] = [e for run in runs for e in run["errors"]]
    return cell


def labels(runner, binary: Path, wanted: int) -> list[str]:
    """WANTED distinct byte addresses inside file-backed, non-executable sections (label records)."""
    from hydralysis.pe import Image
    image = Image(binary)
    out: list[str] = []
    for section in image.sections:
        if section.Characteristics & 0x20000000 or not section.SizeOfRawData:
            continue
        for offset in range(0, min(section.SizeOfRawData, section.Misc_VirtualSize or section.SizeOfRawData)):
            out.append(hex(image.base + section.VirtualAddress + offset))
            if len(out) >= wanted:
                return out
    return out


def replay_run(runner, settings: dict, target: str, binary: Path, count: int, entry: str) -> dict:
    from hydralysis import workcopy
    view = "replay-%d-%s" % (count, int(time.time()))
    selected = workcopy.with_view(runner.target(target), view)
    addresses = labels(runner, binary, count)
    if len(addresses) < count:
        return {"records": count, "error": "the fixture has only %d label addresses; use a larger --binary" % len(addresses)}
    records = [{"id": uuid.uuid4().hex, "address": address, "options": {"kind": "label", "name": "rp_%d" % i, "source": "named_view_cost"}}
               for i, address in enumerate(addresses)]
    writer = workcopy.writer_for(settings, selected)
    started = time.monotonic()
    try:
        workcopy.add_proposals(settings, writer, selected, records, 0, 3600, {"bundle": "named_view_cost"})
    except Exception as exc:
        return {"records": count, "error": "%s: %s" % (type(exc).__name__, str(exc)[:600]), "fill_s": round(time.monotonic() - started, 3)}
    fill = time.monotonic() - started
    store = workcopy.load_store(settings, selected)
    # An idle eviction: the working copy is gone, the store and the shared base remain.
    directory = workcopy._directory(settings, selected)
    state = workcopy._state(settings, selected)
    close_error = None
    try:
        workcopy.writer_for(settings, selected).call("close_project", project=state.get("fork_gpr", ""), discard=True)
    except Exception as exc:  # a failed discard can leave a stale fork: the record says so and the run is not trusted
        close_error = "%s: %s" % (type(exc).__name__, str(exc)[:300])
    for child in directory.glob("w-*"):
        shutil.rmtree(child, ignore_errors=True)
    (directory / "state.json").unlink(missing_ok=True)
    begin = time.monotonic()
    answered = json.loads(runner.query(target, "decompile", entry, timeout_s=300, options={"view": view}))
    first_call = time.monotonic() - begin
    after = workcopy._state(settings, selected)
    sync = (after.get("last_sync") or {})
    begin = time.monotonic()
    runner.query(target, "decompile", entry, timeout_s=300, options={"view": view})
    warm_call = time.monotonic() - begin
    return {"records": count, "pending_in_store": len(workcopy.pending_of(store)), "fill_s": round(fill, 3),
            "first_call_after_eviction_s": round(first_call, 3), "warm_call_s": round(warm_call, 3),
            "phases_ms": with_unattributed(sync.get("phases_ms")), "applied_now": sync.get("applied_now"), "answered": bool(answered),
            "close_project_error": close_error,
            "over_5s_threshold": first_call > PER_CALL_THRESHOLD_S,
            "at_or_over_keep_warm_placeholder": count >= KEEP_WARM_RECORDS_PLACEHOLDER}


def publish_latency() -> dict:
    """SP7 publish latency at 1, 4 and 12 publishers. It needs Y3's `hydralysis.publish`; without it the figure is pending."""
    import importlib.util
    if importlib.util.find_spec("hydralysis.publish") is None:
        return {"status": "pending", "publishers": [1, 4, 12],
                "reason": "hydralysis.publish (Y3) is not in this tree; measure it when Y3 is merged, with the same 1, 4 and 12 publishers"}
    return {"status": "pending", "publishers": [1, 4, 12],
            "reason": "hydralysis.publish exists but this harness has no verified publish call yet; wire it to Y3's final surface"}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    common.common_arguments(parser)
    parser.add_argument("--runs", type=int, default=5, help="runs per cell (at least 5 for a recorded figure)")
    parser.add_argument("--views", default="1,4,12")
    parser.add_argument("--modes", default="shared,rebuilt")
    parser.add_argument("--replay", default="", help="record counts, for example 1,100,1000,4096")
    parser.add_argument("--keep-root", action="store_true")
    args = parser.parse_args(argv)
    common.require_engine(args)
    binary = common.default_binary(args.binary)
    root = common.fresh_root(args, "nvc")
    out = common.output_dir(args.out)
    settings = common.settings_of(args, root)
    scratch = root / "fixture.exe"
    shutil.copy2(binary, scratch)
    report = {"script": "named_view_cost", "rows": ["C2-08", "C2-57"], "engine": common.engine_facts(args),
              "machine": common.machine(), "program_sha256": common.sha256_of(scratch), "program": binary.name,
              "file_system": common.file_system(root), "root": str(root), "runs": args.runs,
              "load_before": common.foreign_load(), "named": {}, "replay": []}
    runner = None
    failed = False
    try:
        runner, status = common.prepare(settings, scratch, "fixture")
        report["prepare_state"] = status["state"]
        target = "fixture"
        addresses = _functions(runner, target, 12)
        report["functions_available"] = len(addresses)
        for count in [int(x) for x in args.views.split(",") if x]:
            for mode in [m for m in args.modes.split(",") if m]:
                cells = []
                if mode == "shared":
                    # Build the shared base once, outside the measurement, through a throw-away view.
                    _first_edit(runner, target, "warm-%d" % count, addresses[0], "warm_%d" % count)
                for run in range(args.runs):
                    cells.append(named_run(runner, settings, target, addresses, count, mode, run))
                report["named"]["%s/%d" % (mode, count)] = {"aggregate": aggregate(cells), "runs": cells}
        for count in [int(x) for x in args.replay.split(",") if x]:
            report["replay"].append(replay_run(runner, settings, target, scratch, count, addresses[0]))
        errored = [r["records"] for r in report["replay"] if r.get("error")]
        report["keep_warm_decision"] = {
            "viewKeepWarmRecords_placeholder": KEEP_WARM_RECORDS_PLACEHOLDER, "per_call_threshold_s": PER_CALL_THRESHOLD_S,
            "first_count_over_threshold": next((r["records"] for r in report["replay"] if r.get("over_5s_threshold")), None),
            "incomplete": bool(errored), "counts_with_errors": errored,
            "note": "fixture only; decided on the KotOR run. The placeholder stands when no count below it is over the "
                    "threshold; otherwise lower it to the last count under it. When incomplete is true (a replay "
                    "record errored) there is no verdict for the errored counts."}
        failed = bool(errored)
        report["publish_latency"] = publish_latency()
        budgets = common.load_budgets()
        judged = []
        for key, cell in report["named"].items():
            for phase in ("total", "fork", "base_upgrade"):
                judged.append(common.judge("named_view_cost.%s.%s.%s.median_ms" % (report["file_system"], key, phase), cell["aggregate"][phase]["median"], budgets))
        for item in report["replay"]:
            if item.get("first_call_after_eviction_s") is not None:
                judged.append(common.judge("named_view_cost.%s.replay.%d.first_call_s" % (report["file_system"], item["records"]), item["first_call_after_eviction_s"], budgets))
        report["budget_report"] = judged
    finally:
        report["load_after"] = common.foreign_load()
        try:
            common.stop_engine(settings)
        except Exception as exc:
            report["stop_error"] = str(exc)[:300]
        path = common.write_report(out, "named_view_cost-%s" % (report.get("file_system") or "fs"), report)
        print(json.dumps({"report": str(path), "named_cells": sorted(report["named"]), "replay": [
            {k: r.get(k) for k in ("records", "first_call_after_eviction_s", "error")} for r in report["replay"]]}, indent=2))
        time.sleep(1)
        if not args.keep_root:
            common.cleanup(root)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
