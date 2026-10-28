"""File export worker. Queries saved analysis; never imports or edits a master."""

from __future__ import annotations

import hashlib
import json
import os
import re
import struct
import sys
import time
from pathlib import Path

from hydralysis import targets, workcopy
from hydralysis.backends import read_json, write_json
from hydralysis.exporting import MAX_OUTPUT_BYTES, MAX_ROW_BYTES, code_sha256, master_revision, provenance, update
from hydralysis.locks import LaneLock
from hydralysis.pe import Image
from hydralysis.preparation import process_start_ms
from hydralysis.query import QueryRunner


class Paused(RuntimeError):
    pass


def output_path(path: Path, record: dict) -> Path:
    """The job's own file, or the caller's absolute path recorded when the job started."""
    chosen = record["options"].get("out")
    expected = Path(chosen) if chosen else path.parent / (record["options"]["mode"] + ".jsonl")
    if Path(record["output_path"]).resolve() != expected.resolve():
        raise ValueError("export output path differs from the path recorded for this job")
    return expected


def validate_imports(path: Path, record: dict, *, required: bool = False) -> Path:
    destination = path.parent / "imports.json"
    if Path(record.get("imports_path", str(destination))).resolve() != destination.resolve():
        raise ValueError("export imports path differs from the owned job path")
    if not destination.is_file():
        if required:
            raise ValueError("recorded export imports metadata is missing; files preserved")
        return destination
    if destination.stat().st_size > MAX_ROW_BYTES:
        raise ValueError("export imports metadata exceeds the 16 MiB validation budget; file preserved")
    saved = read_json(destination)
    if saved.get("build_sha256") != record["provenance"]["sha256"]:
        raise ValueError("export imports metadata is from another build; file preserved")
    if saved.get("state") not in ("done", "unavailable") or not isinstance(saved.get("imports"), list):
        raise ValueError("export imports metadata has an invalid state/import list; file preserved")
    return destination


def replay(path: Path, record: dict) -> dict:
    output = output_path(path, record)
    result = {"keys": set(), "completed": 0, "succeeded": 0, "failed": 0, "truncated": 0}
    if not output.exists():
        if record.get("completed", 0):
            raise ValueError("recorded export output is missing; refusing to overwrite or skip completed work")
        validate_imports(path, record)
        return result
    if output.stat().st_size > MAX_OUTPUT_BYTES:
        raise ValueError("export output exceeds the 1 GiB replay budget")
    with output.open("rb") as handle:
        number = 0
        while True:
            line = handle.readline(MAX_ROW_BYTES + 1)
            if not line:
                break
            number += 1
            if len(line) > MAX_ROW_BYTES:
                raise ValueError("export JSONL row exceeds the 16 MiB replay budget; output preserved")
            if not line.endswith(b"\n"):
                raise ValueError("torn export JSONL tail at line %d; output preserved for recovery" % number)
            try:
                row = json.loads(line)
            except ValueError as exc:
                raise ValueError("invalid export JSONL line %d; output preserved" % number) from exc
            if not isinstance(row, dict):
                raise ValueError("export JSONL line %d is not an object; output preserved" % number)
            if (row.get("job") != record["id"] or row.get("build_sha256") != record["provenance"]["sha256"]
                    or row.get("mode") != record["options"]["mode"] or row.get("provenance") != record["provenance"]):
                raise ValueError("export JSONL provenance mismatch at line %d" % number)
            key = row.get("key")
            if not isinstance(key, str) or key in result["keys"]:
                raise ValueError("duplicate or missing export key at line %d; output preserved" % number)
            state = row.get("state")
            if state not in ("done", "failed"):
                raise ValueError("invalid export row state at line %d; output preserved" % number)
            response = row.get("result")
            if state == "done" and not isinstance(response, dict):
                raise ValueError("completed export row lacks a result at line %d; output preserved" % number)
            has_c = isinstance(response, dict) and "c" in response
            if has_c or "c_sha256" in row or (state == "done" and record["options"]["mode"] == "decompile"):
                c = response.get("c") if isinstance(response, dict) else None
                expected = row.get("c_sha256")
                if (not isinstance(c, str) or not isinstance(expected, str)
                        or not re.fullmatch(r"[0-9a-f]{64}", expected)
                        or hashlib.sha256(c.encode("utf-8")).hexdigest() != expected):
                    raise ValueError("export C SHA-256 mismatch at line %d; output preserved" % number)
            result["keys"].add(key)
            result["completed"] += 1
            result["succeeded" if row.get("state") == "done" else "failed"] += 1
            result["truncated"] += bool(row.get("truncated"))
    validate_imports(path, record, required=result["completed"] > 0)
    return result


def validate_completed(path: Path, record: dict) -> None:
    """Reusing a completed artifact must verify its recorded file digests."""
    replay(path, record)
    imports_file = validate_imports(path, record, required=True)
    for label, filename, key in (("output", output_path(path, record), "output_sha256"),
                                 ("imports", imports_file, "imports_sha256")):
        expected = record.get(key)
        if not isinstance(expected, str) or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise ValueError("completed export %s SHA-256 is missing/invalid; files preserved" % label)
        if not filename.is_file() or _sha(filename) != expected:
            raise ValueError("completed export %s SHA-256 mismatch; files preserved" % label)


def frozen(record: dict):
    settings, target, identity = record["settings"], record["target"], record["provenance"]
    project = settings["targets"][target]
    if code_sha256() != identity["code_sha256"]:
        raise Paused("query/export implementation changed during export; old output preserved")
    selected = workcopy.with_view(targets.resolve(settings, target), record["options"].get("view", ""))
    if master_revision(settings, selected) != identity["master_revision"]:
        raise Paused("master project was saved during export; old output preserved")
    if workcopy.expected_state(settings, selected) != identity["overlay_state"]:
        raise Paused("type overlays changed during export; old output preserved")
    if project.get("exe"):
        stat = Path(project["exe"]).stat()
        if {"size": stat.st_size, "mtime_ns": stat.st_mtime_ns} != identity.get("exe_stat"):
            raise Paused("binary changed during export; old output preserved")


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def imports(path: Path, record: dict):
    destination = path.parent / "imports.json"
    if destination.exists():
        validate_imports(path, record, required=True)
        return
    project = record["settings"]["targets"][record["target"]]
    result = {"build_sha256": record["provenance"]["sha256"], "source": "configured binary import directory", "imports": []}
    if not project.get("exe"):
        result.update(state="unavailable", reason="target has no configured exe; saved project metadata cannot supply PE imports here")
    else:
        import pefile
        try:
            pe = pefile.PE(project["exe"], fast_load=True)
            try:
                pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
                for library in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []):
                    for symbol in library.imports:
                        result["imports"].append({"library": library.dll.decode("utf-8", "replace"),
                                                  "name": symbol.name.decode("utf-8", "replace") if symbol.name else None,
                                                  "ordinal": symbol.ordinal, "iat_va": hex(symbol.address)})
                result.update(state="done", count=len(result["imports"]))
            finally:
                pe.close()
        except pefile.PEFormatError as exc:
            result.update(state="unavailable", reason="configured binary is not a supported PE: " + str(exc))
    write_json(destination, result)


def body_hash(response: dict, image: Image | None) -> dict:
    function = response.get("function") or {}
    if image is None:
        return {"body_sha256": None, "body_hash_reason": "no configured PE below the 512 MiB hashing budget"}
    if function.get("body_truncated"):
        return {"body_sha256": None, "body_hash_reason": "function body ranges were truncated"}
    ranges = function.get("body") or []
    if not ranges:
        return {"body_sha256": None, "body_hash_reason": "no analysed function body ranges"}
    digest, total = hashlib.sha256(), 0
    digest.update(b"rusticre-body-ranges-v1\0")
    try:
        base = int(response["image_base"], 16)
        for item in ranges:
            match = re.fullmatch(r"\[([0-9a-fA-F]+),\s*([0-9a-fA-F]+)\]", item)
            if not match:
                raise ValueError("unsupported body range representation")
            start, end = (int(value, 16) for value in match.groups())
            size = end - start + 1
            total += size
            if size <= 0 or total > 16 * 1024 * 1024:
                raise ValueError("body exceeds the 16 MiB per-function hashing budget")
            data = image.read_rva(start - base, size)
            digest.update(struct.pack("<QQ", start - base, len(data)))
            digest.update(data)
    except (ValueError, KeyError, OverflowError) as exc:
        return {"body_sha256": None, "body_hash_reason": str(exc)}
    return {"body_sha256": digest.hexdigest(), "body_bytes": total,
            "body_hash_method": "SHA256(domain tag; ordered RVA/length little-endian uint64 pairs; raw file-backed body bytes)"}


def _query(runner, record, action, **kwargs):
    view = record["options"].get("view", "")
    if view:
        kwargs["options"] = {**kwargs.get("options", {}), "view": view}
    for attempt in range(2):
        try:
            response = json.loads(runner.query(record["target"], action, **kwargs))
            if response.get("ok") is False:
                raise RuntimeError(str(response.get("error") or "query returned failure"))
            if response.get("sha256") != record["provenance"]["sha256"]:
                raise Paused("query returned another program build")
            return response
        except (RuntimeError, ValueError) as exc:
            if not any(word in str(exc).lower() for word in ("busy", "another worker is starting", "anotherworkerisstarting")):
                raise
            if attempt:
                raise Paused("backend remained busy after one retry: " + str(exc)) from exc
            time.sleep(0.5)


def partial(response: dict) -> bool:
    """Nested recovered-type limits are incompleteness too, not just C caps."""
    pending = [response]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            if value.get("truncated") is True or value.get("body_truncated") is True:
                return True
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
    return False


def run(path: Path, generation: str, runner_factory=QueryRunner):
    lease = LaneLock(str(path.parent / ".run.lock"))
    if not lease.acquire():
        return
    started = time.monotonic()
    def finish(**changes):
        return update(path, finished_at=time.time(), elapsed_run_s=round(time.monotonic() - started, 3), **changes)
    try:
        record = read_json(path)
        if generation != record.get("generation"):
            return
        if record.get("cancel_requested"):
            finish(state="cancelled", stage="cancelled before backend queries", complete=False)
            return
        update(path, state="running", stage="validating saved analysis", worker_pid=os.getpid(), worker_started_ms=process_start_ms(os.getpid()))
        _, observed = provenance(record["settings"], record["target"], record["options"].get("view", ""))
        if observed != record["provenance"]:
            raise Paused("export source/build/code/overlays changed before worker startup")
        if read_json(path).get("cancel_requested"):
            finish(state="cancelled", stage="cancelled before backend queries", complete=False)
            return
        progress = replay(path, record)
        progress_fields = lambda: {name: progress[name] for name in ("completed", "succeeded", "failed", "truncated")}
        update(path, **progress_fields())
        imports(path, record)
        project = record["settings"]["targets"][record["target"]]
        image = None
        if project.get("exe") and Path(project["exe"]).stat().st_size <= 512 * 1024 * 1024:
            try:
                image = Image(Path(project["exe"]))
            except Exception as exc:
                print("PE body hash unavailable:", repr(exc), flush=True)
        # The binary was fully hashed above and its stat is checked between
        # rows. Avoid rereading a 100 MB exe for every one of 10,000 functions.
        query_settings = json.loads(json.dumps(record["settings"]))
        query_project = query_settings["targets"][record["target"]]
        query_project.pop("exe", None)
        query_project["sha256"] = record["provenance"]["sha256"]
        runner = runner_factory(query_settings)
        selected = record["options"]
        cursor = str(record.get("cursor") or selected.get("start") or "")
        pattern = re.compile(selected["regex"]) if selected.get("regex") else None
        end = int(selected["end"], 16) if selected.get("end") else None
        output = output_path(path, record)
        exhausted = False
        with output.open("a", encoding="utf-8", newline="\n") as handle:
            while progress["completed"] < selected["limit"]:
                if read_json(path).get("cancel_requested"):
                    finish(state="cancelled", stage="cancelled between bounded queries", complete=False, **progress_fields())
                    return
                frozen(record)
                page_action = "types" if selected["mode"] == "types" else "functions"
                page = _query(runner, record, page_action, limit=100, cursor=cursor,
                              contains=selected["contains"], timeout_s=selected["timeout_s"])
                items = page.get("types" if page_action == "types" else "functions")
                if not isinstance(items, list):
                    raise Paused("query returned no enumeration rows")
                if end is not None and page_action == "functions":
                    beyond = [item for item in items if int(str(item.get("address", "0")), 16) > end]
                    if beyond:
                        items = [item for item in items if item not in beyond]
                        page = {**page, "truncated": False}
                if pattern is not None:
                    items = [item for item in items
                             if pattern.search(str(item.get("path") if selected["mode"] == "types" else item.get("name") or ""))]
                for item in items:
                    key = str(item.get("path") if selected["mode"] == "types" else item.get("address") or "")
                    if not key:
                        raise Paused("enumeration returned a row with no address/path key")
                    if key in progress["keys"]:
                        continue
                    if progress["completed"] >= selected["limit"]:
                        break
                    if read_json(path).get("cancel_requested"):
                        finish(state="cancelled", stage="cancelled between bounded queries", complete=False, **progress_fields())
                        return
                    frozen(record)
                    row = {"version": 1, "job": record["id"], "target": record["target"], "mode": selected["mode"],
                           "key": key, "build_sha256": record["provenance"]["sha256"], "provenance": record["provenance"]}
                    try:
                        if selected["mode"] == "functions":
                            response = {name: page[name] for name in ("program", "sha256", "image_base") if name in page}
                            response["function"] = item
                        elif selected["mode"] == "types":
                            response = _query(runner, record, "type", options={"path": key}, limit=200, timeout_s=selected["timeout_s"])
                        else:
                            response = _query(runner, record, "decompile", address=key, options={"max_characters": 2097152}, timeout_s=selected["timeout_s"])
                        row.update(state="done", result=response, truncated=partial(response))
                        if "c" in response:
                            row["c_sha256"] = hashlib.sha256(response["c"].encode("utf-8")).hexdigest()
                            row["c_hash_scope"] = "exact exported UTF-8 C text; inspect truncated before claiming a complete body"
                        if selected["mode"] != "types":
                            row.update(body_hash(response, image))
                    except (RuntimeError, ValueError, TimeoutError) as exc:
                        if isinstance(exc, Paused):
                            raise
                        expected_failure = isinstance(exc, TimeoutError) or any(word in str(exc).lower() for word in ("decompile refused", "no analysed function", "unknown type", "no type"))
                        if not expected_failure:
                            raise Paused("backend query failed; output preserved: " + str(exc)) from exc
                        row.update(state="failed", error=str(exc)[:4000], truncated=False)
                    frozen(record)
                    encoded = json.dumps(row, ensure_ascii=False) + "\n"
                    if len(encoded.encode("utf-8")) > MAX_ROW_BYTES:
                        raise Paused("export record exceeds the 16 MiB row/replay budget; preceding rows preserved")
                    if output.stat().st_size + len(encoded.encode("utf-8")) > MAX_OUTPUT_BYTES:
                        raise Paused("export reached the 1 GiB output/replay budget; existing rows preserved")
                    handle.write(encoded)
                    handle.flush()
                    os.fsync(handle.fileno())
                    progress["keys"].add(key)
                    progress["completed"] += 1
                    progress["succeeded" if row["state"] == "done" else "failed"] += 1
                    progress["truncated"] += bool(row["truncated"])
                    update(path, stage="exporting " + key, current=key, output_bytes=output.stat().st_size, **progress_fields())
                pending_in_page = any(str(item.get("path") if selected["mode"] == "types" else item.get("address") or "") not in progress["keys"] for item in items)
                if pending_in_page:
                    # A requested count cap may stop in the middle of a page.
                    # Do not advance past entries that were never exported.
                    break
                next_cursor = str(page.get("next_cursor") or "")
                if not page.get("truncated"):
                    exhausted = True
                    break
                if not next_cursor or next_cursor == cursor:
                    raise Paused("enumeration made no cursor progress; export paused")
                cursor = next_cursor
                update(path, cursor=cursor)
        limited = not exhausted and progress["completed"] >= selected["limit"]
        finish(state="done", stage="finished", limited=limited,
               complete=exhausted and progress["failed"] == 0 and progress["truncated"] == 0,
               output_sha256=_sha(output), imports_sha256=_sha(path.parent / "imports.json"), **progress_fields())
    except Paused as exc:
        finish(state="paused", stage="paused", error=str(exc)[:4000], complete=False)
        print("EXPORT PAUSED:", str(exc), flush=True)
    except Exception as exc:
        finish(state="failed", stage="failed", error="%s: %s" % (type(exc).__name__, exc), complete=False)
        print("EXPORT FAILED:", repr(exc), flush=True)
    finally:
        lease.release()


if __name__ == "__main__":
    run(Path(sys.argv[1]).resolve(), sys.argv[2])
