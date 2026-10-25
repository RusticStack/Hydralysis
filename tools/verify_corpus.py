"""Read-only PE compatibility checks; never imports, decompiles or launches targets."""

import argparse
import hashlib
import json
import os
from pathlib import Path

from rusticre.api import call
from rusticre.config import load
from rusticre.pe import Image
from rusticre.preparation import plan


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


def main():
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
