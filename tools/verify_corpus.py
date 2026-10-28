"""Read-only PE compatibility checks; never imports, decompiles or launches targets."""

import argparse
import hashlib
import json
import os
import time
from pathlib import Path

from hydralysis.api import call
from hydralysis.config import load
from hydralysis.pe import Image
from hydralysis.preparation import plan


def verify(path: Path, settings: dict) -> dict:
    image = Image(path)
    identity = image.fingerprint()
    before = path.stat()
    result = {"path": str(path), "identity": identity, "checks": {}, "errors": []}
    proposal = plan(settings, str(path))
    result["preflight"] = {key: proposal[key] for key in ("state", "started", "would_import", "reason", "preflight")}

    def check(name, arguments):
        try:
            text = call(name, {"exe": str(path), **arguments})
            result["checks"][name] = {"ok": True, "output_sha256": hashlib.sha256(text.encode()).hexdigest(), "characters": len(text)}
            return text
        except Exception as error:
            result["errors"].append({"tool": name, "error": "%s: %s" % (type(error).__name__, error)})
            return ""

    check("fingerprint", {})
    check("sections", {})
    check("imports", {"limit": 8})
    check("exports", {"limit": 8})
    check("strings", {"pattern": "(?i)save|render|player", "limit": 3})
    if proposal["state"] == "blocked":
        result["code_checks"] = "skipped: known wrapper/packer indicators; no game-code claim"
    elif image.machine not in (0x14C, 0x8664):
        result["code_checks"] = "unsupported PE instruction architecture"
    else:
        entry = int(image.pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        address = "rva:%#x" % entry
        raw = image.read_rva(entry, min(16, image._available(entry)))
        if not raw:
            result["errors"].append({"tool": "bytes", "error": "entry is not file backed"})
        else:
            byte_text = check("bytes", {"address": address, "size": len(raw)})
            assert byte_text.splitlines()[-1] == raw.hex(" ").upper(), "byte mismatch"
            check("disasm", {"address": address, "count": 4})
            check("inspect", {"address": address})
            check("callers", {"address": address, "limit": 3})
            check("callees", {"address": address, "limit": 3})
            check("xrefs", {"address": address, "limit": 3})
            check("sigscan", {"pattern": raw.hex(" "), "limit": 3})
            check("prologue", {"address": address, "expect": raw.hex(" ")})
            mismatched = bytes([raw[0] ^ 0xFF]) + raw[1:]
            try:
                call("prologue", {"exe": str(path), "address": address, "expect": mismatched.hex(" ")})
                result["errors"].append({"tool": "prologue", "error": "mismatch was accepted"})
            except ValueError as error:
                assert "PROLOGUE MISMATCH" in str(error), str(error)
                result["checks"]["prologue_mismatch"] = {"ok": True, "refused": True}
    after = path.stat()
    result["input_unchanged"] = (before.st_size, before.st_mtime_ns) == (after.st_size, after.st_mtime_ns)
    result["ok"] = not result["errors"] and result["input_unchanged"]
    return result


def golden_c_hashes(path: Path) -> dict:
    """entry -> c_sha256 from a golden capture's rows.jsonl (hashes only; the capture's C text is not read)."""
    result = {}
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            row = json.loads(line)
            if row.get("type") == "function" and row.get("status") == "ok":
                result[hex(int(row["entry"], 16))] = row.get("c_sha256")
    return result


def export_corpus(settings: dict, target: str, args) -> dict:
    """Run (or resume) a full decompile export of TARGET, then report parity, timing and, optionally, golden agreement.

    The report holds counts, digests and timings only: no function bodies and no game text."""
    from hydralysis import exporting
    from hydralysis.backends import read_json

    started = time.monotonic()
    options = {"resume": args.resume} if args.resume else {"mode": args.mode, "timeout_s": args.timeout_s}
    job = exporting.start(settings, target, options)
    while job["state"] in exporting.ACTIVE:
        time.sleep(args.poll_s)
        job = exporting.status(settings, job["id"])
        print(job["state"], job.get("completed"), flush=True)
    record = read_json(exporting.job_path(settings, job["id"]))
    output = Path(record["output_path"])
    report = {"job": record["id"], "target": target, "state": record["state"], "build_sha256": record["provenance"]["sha256"],
              "pin_sha256": args.pin, "pin_matches": args.pin is None or record["provenance"]["sha256"] == args.pin,
              "parity": record.get("parity"), "all_succeeded": record.get("all_succeeded"), "complete": record.get("complete"),
              "completed": record.get("completed"), "succeeded": record.get("succeeded"), "failed": record.get("failed"),
              "truncated": record.get("truncated"), "elapsed_run_s": record.get("elapsed_run_s"),
              "wall_s": round(time.monotonic() - started, 1), "output_bytes": output.stat().st_size if output.is_file() else 0,
              "output_sha256": record.get("output_sha256"), "error": record.get("error", "")}
    if record.get("elapsed_run_s") and record.get("completed"):
        report["rows_per_s"] = round(record["completed"] / record["elapsed_run_s"], 2)
    if args.golden:
        golden = golden_c_hashes(Path(args.golden))
        seen, same, different = set(), 0, []
        with output.open(encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                key = hex(int(row["key"], 16))
                seen.add(key)
                if row.get("state") == "done" and golden.get(key) == row.get("c_sha256"):
                    same += 1
                else:
                    different.append(key)
        report["golden"] = {"rows": len(golden), "same_c_sha256": same, "different": len(different),
                            "missing_from_export": len(set(golden) - seen), "not_in_golden": len(seen - set(golden)),
                            "different_sample": different[:20]}
    report["ok"] = bool(record["state"] == "done" and report["pin_matches"] and (record.get("parity") or {}).get("ok")
                        and (not args.require_all_succeeded or record.get("all_succeeded")))
    return report


def export_main(argv) -> int:
    parser = argparse.ArgumentParser(prog="verify_corpus.py export", description=export_corpus.__doc__)
    parser.add_argument("--target", required=True, help="a target already analysed and registered (use a COPY of a game project)")
    parser.add_argument("--output", required=True, type=Path, help="report JSON (counts and digests only)")
    parser.add_argument("--mode", default="decompile", choices=("decompile", "functions", "types"))
    parser.add_argument("--timeout-s", type=int, default=120)
    parser.add_argument("--poll-s", type=float, default=5.0)
    parser.add_argument("--resume", default="", help="resume this export job id instead of starting one")
    parser.add_argument("--pin", help="expected build SHA-256 of the target; the run fails if the export's build differs")
    parser.add_argument("--golden", help="a golden capture's rows.jsonl: compare each row's c_sha256 with it")
    parser.add_argument("--require-all-succeeded", action="store_true",
                        help="also fail when a row failed or was truncated (parity alone does not)")
    args = parser.parse_args(argv)
    report = export_corpus(load(), args.target, args)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2))
    print(json.dumps({key: value for key, value in report.items() if key != "golden"}), flush=True)
    return 0 if report["ok"] else 1


def main():
    import sys
    if sys.argv[1:2] == ["export"]:
        return export_main(sys.argv[2:])
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    directory, output = args.directory.resolve(), args.output.resolve()
    if not directory.is_dir() or output.is_relative_to(directory):
        parser.error("choose an existing input directory and an output outside it")
    settings = load()
    jobs = Path(settings["root"]) / "preparation" / "jobs"
    jobs_before = set(jobs.glob("*/job.json"))
    files = []
    for folder, children, names in os.walk(directory, followlinks=False):
        children[:] = [name for name in children if not Path(folder, name).is_symlink()]
        files.extend(Path(folder, name) for name in names if name.lower().endswith(".exe") and not Path(folder, name).is_symlink())
    records = []
    for path in sorted(files):
        try:
            record = verify(path, settings)
        except Exception as error:
            record = {"path": str(path), "ok": False, "errors": [{"error": "%s: %s" % (type(error).__name__, error)}]}
        record["install"] = path.relative_to(directory).parts[0]
        records.append(record)
        print(record["install"], path.name, "PASS" if record["ok"] else "FAIL", flush=True)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps({"root": str(directory), "records": records}, indent=2))
    assert jobs_before == set(jobs.glob("*/job.json")), "read-only planning unexpectedly started a job"
    summary = {"root": str(directory), "executables": len(records), "installs": sorted({r["install"] for r in records}),
               "passed": sum(r["ok"] for r in records), "failed": sum(not r["ok"] for r in records),
               "analyses_started": 0, "programs_launched": 0, "records": records}
    output.write_text(json.dumps(summary, indent=2))
    print(json.dumps({key: value for key, value in summary.items() if key != "records"}), flush=True)
    return int(bool(summary["failed"]))


if __name__ == "__main__":
    raise SystemExit(main())
