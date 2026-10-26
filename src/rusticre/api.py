"""One dispatch table for the CLI and the MCP server."""

from __future__ import annotations

import json
from pathlib import Path

from rusticre import __version__
from rusticre.config import evidence_path, load
from rusticre.evidence import add_claim, list_claims
from rusticre.pe import Image, parse_rva
from rusticre.prologue import compare
from rusticre.query import QueryRunner

# Chosen from what agents actually called, mapped onto generic operations.
# REA's function dossier -> inspect. Ghidra decompile/xrefs/bytes -> the
# matching tools plus ghidra_run. Hook work -> sigscan and prologue.
# Android, browser, firmware and the rest of REA are not registered.
TOOL_NAMES = (
    "fingerprint",
    "imports",
    "disasm",
    "inspect",
    "xrefs",
    "callers",
    "callees",
    "function",
    "bytes",
    "strings",
    "sigscan",
    "prologue",
    "evidence_add",
    "evidence_list",
    "ghidra_run",
    "ghidra_query",
    "backend",
    "prepare",
    "job",
    "runtime",
)

# Backward-compatible terminal commands; these are not extra MCP tools.
CLI_ONLY = ("sections", "exports", "ghidra_scripts", "ghidra_jobs")

# Names that must never appear. They are the REA surface this server exists to avoid.
REJECTED = (
    "adb",
    "android",
    "apk",
    "browser",
    "electron",
    "firmware",
    "frida",
    "hopper",
    "jeb",
    "objc",
    "swift",
)


def tool_table() -> list[dict]:
    def tool(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
        schema: dict = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return {"name": name, "description": description, "inputSchema": schema}

    string = {"type": "string"}
    integer = {"type": "integer"}
    pe_address = {"type": "string", "description": "Use rva:0x... or va:0x...; ambiguous unprefixed addresses are refused."}
    return [
        tool("fingerprint", "PE build identity and packing triage. detail=sections/exports returns those tables.", {"exe": string, "detail": {"type": "string", "enum": ["header", "sections", "exports"]}}, ["exe"]),
        tool("imports", "Imported DLL symbols.", {"exe": string, "limit": integer}, ["exe"]),
        tool("disasm", "Disassemble at an RVA or VA. 64-bit rip-relative operands show their target.", {
            "exe": string, "address": pe_address, "count": integer,
        }, ["exe", "address"]),
        tool("inspect", "Cheap PE inspection: x64 pdata bounds, instructions, candidate callers. For analysed bounds/decompile use ghidra_query.", {
            "exe": string, "address": pe_address,
        }, ["exe", "address"]),
        tool("xrefs", "References to an address. 64-bit rip-relative LEA/MOV, 32-bit absolute.", {
            "exe": string, "address": pe_address, "limit": integer,
        }, ["exe", "address"]),
        tool("callers", "Direct E8/E9 sites in executable code that land on an address.", {
            "exe": string, "address": pe_address, "limit": integer,
        }, ["exe", "address"]),
        tool("callees", "Direct E8 calls made from the function that contains an address.", {
            "exe": string, "address": pe_address, "limit": integer,
        }, ["exe", "address"]),
        tool("function", "The pdata function that contains an address, and its first 32 bytes.", {
            "exe": string, "address": pe_address,
        }, ["exe", "address"]),
        tool("bytes", "Raw bytes at an address.", {"exe": string, "address": pe_address, "size": integer}, ["exe", "address"]),
        tool("strings", "Printable strings matching a regular expression.", {
            "exe": string, "pattern": string, "limit": integer,
        }, ["exe", "pattern"]),
        tool("sigscan", "Find a byte pattern in executable sections. ?? is a wildcard. Use this to locate a hook site.", {
            "exe": string, "pattern": string, "limit": integer,
        }, ["exe", "pattern"]),
        tool("prologue", "Verify one prologue or checks[{address,expect,name?}] against one PE build. Any mismatch fails; no hook is installed.", {
            "exe": string, "address": pe_address, "expect": string,
            "checks": {"type": "array", "items": {"type": "object"}},
            "sha256": string, "image_base": string,
        }, ["exe"]),
        tool("evidence_add", "Store one proved claim. note and source are required. target is any name you give this binary.", {
            "target": string, "build": string, "kind": string, "name": string,
            "note": string, "source": string, "address": string, "prologue": string, "db": string,
        }, ["target", "build", "kind", "name", "note", "source"]),
        tool("evidence_list", "List stored claims, newest first.", {"target": string, "limit": integer, "db": string}),
        tool("ghidra_run", "Run one of your Ghidra scripts on a target's saved analysis, contained (rolled back). No import, no copy.", {
            "target": string, "script": string,
            "args": {"type": "array", "items": string},
            "timeout_s": integer,
        }, ["target", "script"]),
        tool("ghidra_query", "Query saved analysis through the shared warm engine. Numeric VA/rva:/va: addresses; bounded pages via next_cursor. export starts a durable file job. Use backend help for options.", {
            "target": string,
            "action": {"type": "string", "enum": ["decompile", "function", "functions", "xrefs", "types", "type", "data", "scan", "variables", "dossier", "blocks", "pcode", "trace", "type_edit", "export", "status", "stop"]},
            "address": string, "limit": integer, "cursor": string, "contains": string, "timeout_s": integer,
            "options": {"type": "object"},
        }, ["target"]),
        tool("backend", "Discover/install private analysis or runtime engines, never other MCPs. install returns a durable job. status/stop the shared engine. help gives operation options.", {
            "action": {"type": "string", "enum": ["inspect", "install", "status", "stop", "help"]},
            "component": {"type": "string", "enum": ["analysis", "runtime"]},
        }),
        tool("prepare", "Register a build: adopt an analysed project in place (path=.gpr or folder; hash-checked, no copy), or start a one-time import/analysis job. plan is read-only.", {
            "exe": string, "target": string, "timeout_s": integer, "install": {"type": "boolean"},
            "action": {"type": "string", "enum": ["plan", "start", "adopt"]},
            "path": string, "sha256": string, "program": string,
        }),
        tool("job", "Durable setup/analysis job status, bounded logs or cancellation. An empty id lists recent jobs.", {
            "action": {"type": "string", "enum": ["status", "cancel"]}, "id": string, "limit": integer,
        }),
        tool("runtime", "Own-process debugging/instrumentation sessions: spawn/attach, modules, memory, verified probes/breakpoints, registers, continue and detach. Use backend help for options.", {
            "action": string, "options": {"type": "object"},
        }, ["action"]),
    ]


def call(name: str, args: dict | None) -> str:
    if args is not None and not isinstance(args, dict):
        raise ValueError("tool arguments must be an object")
    args = args or {}
    if name not in TOOL_NAMES + CLI_ONLY:
        raise ValueError("unknown tool %s" % name)
    for key, maximum in (("limit", 200), ("count", 200), ("size", 65536)):
        if key in args and (isinstance(args[key], bool) or not 1 <= int(args[key]) <= maximum):
            raise ValueError("%s must be 1..%d" % (key, maximum))
    if name == "fingerprint":
        image = _image(args)
        detail = args.get("detail", "header")
        if detail == "sections":
            return image.sections_text()
        if detail == "exports":
            return image.exports_text(200)
        if detail != "header":
            raise ValueError("fingerprint detail must be header, sections or exports")
        return image.header() + "\n" + json.dumps(image.fingerprint(), indent=2)
    if name in ("backend", "prepare", "job", "runtime"):
        return _workflow(name, args)
    if name == "sections":
        return _image(args).sections_text()
    if name == "imports":
        return _image(args).imports_text(int(args.get("limit") or 80))
    if name == "exports":
        return _image(args).exports_text(int(args.get("limit") or 80))
    if name == "disasm":
        image = _image(args)
        return image.disasm(_addr(image, args), int(args.get("count") or 40))
    if name == "inspect":
        image = _image(args)
        return image.inspect(_addr(image, args))
    if name == "xrefs":
        image = _image(args)
        return image.xrefs(_addr(image, args), int(args.get("limit") or 40))
    if name == "callers":
        image = _image(args)
        return image.callers(_addr(image, args), int(args.get("limit") or 50))
    if name == "callees":
        image = _image(args)
        return image.callees(_addr(image, args), int(args.get("limit") or 30))
    if name == "function":
        image = _image(args)
        return image.function_of(_addr(image, args))
    if name == "bytes":
        image = _image(args)
        data = image.read_rva(_addr(image, args), int(args.get("size") or 32))
        return image.header() + "\n" + " ".join("%02X" % byte for byte in data)
    if name == "strings":
        return _image(args).find_strings(str(args.get("pattern") or ""), int(args.get("limit") or 30))
    if name == "sigscan":
        return _image(args).sigscan(str(args.get("pattern") or ""), int(args.get("limit") or 20))
    if name == "prologue":
        from rusticre.prologue import compare_table, parse_expect
        image = _image(args)
        if "sha256" in args:
            import re
            expected_hash = args["sha256"]
            if not isinstance(expected_hash, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", expected_hash):
                raise ValueError("sha256 must be a full hexadecimal build hash")
            if expected_hash.lower() != image.fingerprint()["sha256"]:
                raise ValueError("prologue table build SHA-256 mismatch; no rows verified")
        if "image_base" in args and int(str(args["image_base"]), 0) != image.base:
            raise ValueError("prologue table image base mismatch; no rows verified")
        if "checks" in args:
            if "address" in args or "expect" in args:
                raise ValueError("use checks or a single address/expect pair")
            result = compare_table(image, args["checks"], lambda text: _addr(image, {"address": text}))
            if not result["matched"]:
                raise ValueError("PROLOGUE TABLE MISMATCH\n" + json.dumps(result, indent=2))
            return json.dumps(result, indent=2)
        if not args.get("expect"):
            raise ValueError("expect is required for a single prologue")
        expected = parse_expect(str(args["expect"]))
        if len(expected) > 4096:
            raise ValueError("expect must be at most 4096 bytes")
        data = image.read_rva(_addr(image, args), len(expected))
        result = image.header() + "\n" + compare(data, str(args["expect"]))
        if "PROLOGUE MISMATCH" in result:
            raise ValueError(result)
        return result
    if name == "evidence_add":
        return add_claim(
            evidence_path(str(args.get("db") or "")),
            game=str(args.get("target") or args.get("game") or ""),
            build=str(args.get("build") or ""),
            kind=str(args.get("kind") or ""),
            name=str(args.get("name") or ""),
            note=str(args.get("note") or ""),
            source=str(args.get("source") or ""),
            address=str(args.get("address") or ""),
            prologue=str(args.get("prologue") or ""),
        )
    if name == "evidence_list":
        return list_claims(
            evidence_path(str(args.get("db") or "")),
            str(args.get("target") or args.get("game") or ""),
            int(args.get("limit") or 50),
        )
    target = str(args.get("target") or args.get("game") or "")
    if name == "ghidra_query":
        if args.get("action") == "export":
            from rusticre.exporting import start
            return json.dumps(start(_settings(), target, args.get("options")), indent=2)
        return QueryRunner(_settings()).query(
            target, str(args.get("action") or "decompile"), str(args.get("address") or ""),
            int(args.get("limit", 40)), str(args.get("cursor") or ""), str(args.get("contains") or ""),
            int(args.get("timeout_s", 30)),
            args.get("options"),
        )
    if name == "ghidra_run":
        from rusticre.userscripts import run
        return run(_settings(), target, str(args.get("script") or ""),
                   [str(item) for item in _list(args.get("args"))], int(args.get("timeout_s") or 600))
    if name == "ghidra_scripts":
        from rusticre.userscripts import list_scripts
        return list_scripts(load(), target, str(args.get("filter") or ""))
    if name == "ghidra_jobs":
        return _workflow("job", {"limit": int(args.get("limit") or 20)})
    raise ValueError("unknown tool %s" % name)


def instructions() -> str:
    return (
        "RusticRE %s. Twenty tools for any PE you own. prepare imports/analyses "
        "a new executable exactly once as a durable job and registers its build; "
        "backend discovers/installs the engines, never their MCPs. job reports progress. "
        "runtime manages verified debugging/instrumentation sessions. inspect is the function "
        "picture (bounds, prologue, instructions, callers) and does not start a JVM. "
        "sigscan and prologue are how a hook site is found and checked. ghidra_run "
        "executes one script on a read-only copy of a project you already analysed. "
        "Prefer ghidra_query for bounded address-based decompilation and references; "
        "its JVM stays warm across CLI and MCP calls; export writes bulk artifacts as a job. "
        "Addresses there are VAs or explicit rva:/va:. "
        "For PE addresses use rva:0x... or va:0x... when the interpretation is ambiguous. "
        "Do not re-import the binary. evidence_add stores a claim only with a source."
        % __version__
    )


def _workflow(name: str, args: dict) -> str:
    settings = load()
    if name == "backend":
        action, component = args.get("action", "inspect"), args.get("component", "analysis")
        if component not in ("analysis", "runtime"):
            raise ValueError("component must be analysis or runtime")
        if action == "help":
            from rusticre.workflow_help import operation_help
            return json.dumps(operation_help(component), indent=2)
        if action == "install":
            from rusticre.preparation import start_install
            return json.dumps(start_install(settings, component), indent=2)
        if action in ("status", "stop"):
            if component != "analysis":
                raise ValueError("status/stop apply to the shared analysis engine")
            from rusticre import hydra
            engine = hydra.Engine(_settings())
            if action == "stop":
                return json.dumps(engine.stop(force=bool(args.get("force"))), indent=2)
            status = engine.call("status")
            keep = ("protocol", "hydraVersion", "ghidraVersion", "installId", "pid", "startedAt", "memory", "youAre")
            summary = {key: status.get(key) for key in keep if key in status}
            summary["projects"] = [{key: item.get(key) for key in ("id", "name", "gpr", "writable", "revision", "stale", "users")}
                                   for item in status.get("projects", [])][:20]
            summary["programs"] = [{key: item.get(key) for key in ("key", "mode", "owner", "users", "busy")}
                                   for item in status.get("programs", [])][:40]
            summary["clients"] = [{key: item.get(key) for key in ("id", "name", "harness")}
                                  for item in status.get("clients", [])][:40]
            summary["imports"] = status.get("imports")
            return json.dumps(summary, indent=2, default=str)
        if action != "inspect":
            raise ValueError("backend action must be inspect, install, status, stop or help")
        if component == "runtime":
            from rusticre.runtime import inspect
        else:
            from rusticre.backends import inspect
        return json.dumps(inspect(settings), indent=2)
    if name == "prepare":
        from rusticre.preparation import adopt, plan, prepare
        action = args.get("action", "start")
        if action not in ("plan", "start", "adopt"):
            raise ValueError("prepare action must be plan, start or adopt")
        if action == "adopt":
            return json.dumps(adopt(settings, str(args.get("path") or ""), str(args.get("exe") or ""),
                                    str(args.get("sha256") or ""), str(args.get("program") or ""),
                                    str(args.get("target") or "")), indent=2)
        if not args.get("exe"):
            raise ValueError("prepare %s requires exe" % action)
        install = args.get("install", False)
        if not isinstance(install, bool):
            raise ValueError("install must be a boolean")
        operation = plan if action == "plan" else prepare
        return json.dumps(operation(settings, str(args.get("exe") or ""), str(args.get("target") or ""),
                                  int(args.get("timeout_s", 3600)), install), indent=2)
    if name == "job":
        from rusticre.preparation import cancel, status
        job_id = str(args.get("id") or "")
        action = args.get("action", "status")
        if action == "cancel":
            if not job_id:
                raise ValueError("job id is required for cancellation")
            if job_id.startswith("export-"):
                from rusticre.exporting import cancel as cancel_export
                return json.dumps(cancel_export(settings, job_id), indent=2)
            return json.dumps(cancel(settings, job_id), indent=2)
        if action != "status":
            raise ValueError("job action must be status or cancel")
        if not job_id:
            from rusticre.backends import read_json
            from rusticre.exporting import status as export_status
            limit = int(args.get("limit", 20))
            if not 1 <= limit <= 100:
                raise ValueError("job limit must be 1..100")
            records = status(settings, limit=limit)["jobs"]
            paths = sorted((Path(settings["root"]) / "exports").glob("export-*/job.json"),
                           key=lambda item: item.stat().st_mtime_ns, reverse=True)[:limit]
            records.extend(export_status(settings, item.parent.name) for item in paths)
            scripts = sorted((Path(settings["root"]) / "jobs").glob("job-*.json"),
                             key=lambda item: item.stat().st_mtime_ns, reverse=True)[:limit]
            records.extend(read_json(item) for item in scripts)
            records.sort(key=lambda item: item.get("created_at", item.get("started_at", 0)), reverse=True)
            fields = ("id", "job_id", "kind", "component", "state", "stage", "target", "game", "script",
                      "created_at", "started_at", "elapsed_s", "duration_s", "completed", "failed", "complete", "log_path")
            return json.dumps({"jobs": [{key: item[key] for key in fields if key in item} for item in records[:limit]],
                               "detail": "Pass an id to job status for bounded logs and full metadata."}, indent=2)
        if job_id.startswith("export-"):
            from rusticre.exporting import status as export_status
            return json.dumps(export_status(settings, job_id), indent=2)
        if job_id.startswith("job-"):
            import re
            if not re.fullmatch(r"job-[0-9a-f]{12}", job_id):
                raise ValueError("invalid script job id")
            from rusticre.backends import read_json
            record = read_json(Path(settings["root"]) / "jobs" / (job_id + ".json"))
            if not record:
                raise ValueError("no script job %s" % job_id)
            return json.dumps(record, indent=2)
        return json.dumps(status(settings, job_id, int(args.get("limit", 20))), indent=2)
    if args.get("action") == "setup":
        from rusticre.preparation import start_install
        return json.dumps(start_install(settings, "runtime"), indent=2)
    from rusticre.runtime import runtime
    return runtime(str(args.get("action") or ""), args.get("options") or {}, settings)


def _image(args: dict) -> Image:
    exe = args.get("exe") or os_exe()
    if not exe:
        raise ValueError("exe is required")
    path = Path(str(exe))
    if not path.is_file():
        raise ValueError("exe not found: %s" % path)
    return Image(path)


def os_exe() -> str:
    import os
    return os.environ.get("RUSTICRE_EXE", "")


def _addr(image: Image, args: dict) -> int:
    if "address" not in args:
        raise ValueError("address is required")
    text = str(args["address"]).strip()
    rva = parse_rva(text, image.base)
    if ":" not in text:
        value = int(text, 0)
        if value >= image.base:
            raw_mapped = image.rva_to_offset(value) is not None
            va_mapped = image.rva_to_offset(rva) is not None
            if raw_mapped and va_mapped:
                raise ValueError("ambiguous address %s: RVA %#x and VA %#x (RVA %#x) both map to this image; use rva:%s or va:%s"
                                 % (text, value, value, rva, text, text))
            if raw_mapped:
                return value
    return rva


def _list(value) -> list:
    if value is None:
        return []
    if isinstance(value, str):
        return value.split()
    return list(value)


def _settings() -> dict:
    from rusticre.backends import resolved
    return resolved(load())
