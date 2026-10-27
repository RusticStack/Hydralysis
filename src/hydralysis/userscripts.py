"""ghidra_run: one of your own Ghidra scripts on a target's saved analysis.

The engine only loads Java scripts from its script path, so the script is copied
into Hydralysis's user-scripts folder first (never over one of Hydralysis's own, and
never over a different script of the same name). It runs contained: the engine
rolls back an outer transaction, so it cannot change the project or what other
clients read. Nothing is imported and no project is copied.
"""

from __future__ import annotations

import json
import re
import time
import uuid
from pathlib import Path

from hydralysis import hydra, targets, workcopy
from hydralysis.backends import read_json, write_json
from hydralysis.paths import root_path

_SCRIPT = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]*\.(?:java|py)")


def _stage(settings: dict, source: Path) -> str:
    own = Path(__file__).with_name("scripts")
    if (own / source.name).exists():
        raise ValueError("%s is the name of one of Hydralysis's own scripts; rename yours" % source.name)
    folder = hydra.script_dirs(settings)[1]
    folder.mkdir(parents=True, exist_ok=True)
    staged = folder / source.name
    data = source.read_bytes()
    if staged.is_file() and staged.read_bytes() != data:
        owner = read_json(folder / "owners.json").get(source.name)
        if owner and owner != str(source.resolve()):
            raise ValueError("a different %s from %s is staged already; rename one of them" % (source.name, owner))
    if not staged.is_file() or staged.read_bytes() != data:
        temporary = staged.with_name(staged.name + ".tmp")
        temporary.write_bytes(data)
        temporary.replace(staged)
    owners = read_json(folder / "owners.json")
    owners[source.name] = str(source.resolve())
    write_json(folder / "owners.json", owners)
    return source.name


def run(settings: dict, target: str, script: str, args: list[str], timeout_s: int = 600, view: str = "") -> str:
    from hydralysis.query import QueryRunner
    selected = workcopy.with_view(targets.resolve(settings, target), view)
    name = script if script.endswith((".java", ".py")) else script + ".java"
    if not _SCRIPT.fullmatch(name):
        raise ValueError("script must be a simple .java or .py file name")
    folder = Path(selected.get("scripts") or "")
    if not selected.get("scripts") or not (folder / name).is_file():
        raise ValueError("script %s is not in target %s's scripts directory (%s)" % (name, target, folder or "not set"))
    if not 1 <= timeout_s <= 14400:
        raise ValueError("timeout_s must be 1..14400")
    if len(args) > 64 or any(not isinstance(item, str) or len(item) > 32768 for item in args):
        raise ValueError("script arguments must be at most 64 strings")
    staged = _stage(settings, folder / name)
    runner = QueryRunner(settings)
    program = runner.program_for(selected)
    job_id = "job-%s" % uuid.uuid4().hex[:12]
    started = time.time()
    record = {"job_id": job_id, "kind": "script", "target": target, "view": selected["view"], "script": name, "args": args,
              "started_at": started, "created_at": started, "program": program["key"], "state": "running"}
    jobs = root_path(settings) / "jobs"
    write_json(jobs / (job_id + ".json"), record)
    try:
        result = runner.engine.call("script", script=staged, program=program["key"], args=args,
                                    timeout=timeout_s, maxChars=1_000_000, wait=30000)
        record.update(state="done", output=result.get("output", ""), truncated=result.get("truncated"),
                      mode=result.get("mode"), changed=result.get("changed"))
    except hydra.EngineError as error:
        record.update(state="failed", error=str(error))
    record.update(finished_at=time.time(), duration_s=round(time.time() - started, 2))
    write_json(jobs / (job_id + ".json"), record)
    if record["state"] != "done":
        raise RuntimeError("script job %s failed: %s" % (job_id, record["error"]))
    return ("job=%s target=%s view=%s script=%s mode=%s state=done duration=%ss%s\n--- script output ---\n%s"
            % (job_id, target, selected["view"], name, record["mode"], record["duration_s"],
               " (output truncated)" if record.get("truncated") else "", record["output"] or "(no script output)"))


def list_scripts(settings: dict, target: str, name_filter: str = "") -> str:
    selected = targets.resolve(settings, target)
    folder = Path(selected.get("scripts") or "")
    if not selected.get("scripts") or not folder.is_dir():
        raise ValueError("target %s has no scripts directory" % target)
    rows = []
    for path in sorted(folder.iterdir()):
        if path.suffix in (".java", ".py") and (not name_filter or name_filter.lower() in path.name.lower()):
            usage = ""
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines()[:40]:
                stripped = line.strip().lstrip("/# ").strip()
                if stripped.lower().startswith("usage"):
                    usage = stripped
                    break
            rows.append("%s  %s" % (path.name, usage))
    return "\n".join(rows) if rows else "no scripts in %s" % folder
