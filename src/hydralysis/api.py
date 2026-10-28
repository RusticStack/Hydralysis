"""One dispatch table for the CLI and the MCP server."""

from __future__ import annotations

import hashlib
import importlib
import json
from pathlib import Path

from hydralysis import __version__
from hydralysis.config import evidence_path, load
from hydralysis.evidence import add_claim, list_claims
from hydralysis.pe import Image, parse_rva
from hydralysis.prologue import compare
from hydralysis.query import QueryRunner

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


# The advertised tool table is cached by running MCP sessions (listChanged is False), so it may
# change only through a catalog epoch: bump CATALOG_EPOCH together with an entry in
# tests/test_contracts.py CATALOG_HISTORY, and tell users a harness restart is needed once.
# Epoch 2 brought back the refusal clause of the pe_address description ("ambiguous unprefixed addresses are
# refused", epoch 0), which epoch 1 had weakened to "(bare values may be refused)". It is NOT the epoch-0 text:
# epoch 0 said "Use rva:0x... or va:0x...; ..." and the "0x..." examples stay dropped, because the eight tools that
# carry the description would then cost 104 bytes more (8276 against 8172 advertised bytes, json.dumps with default
# separators), over the 8192 budget of tests/test_contracts.py test_catalog_stays_small_in_bytes_as_well_as_count.
# Where the catalog is reported: backend status, backend help and backend inspect (api.py), and the
# MCP initialize result under _meta (mcp.py). ghidra_query status is built in query.py and does not carry it.
# Everything added after epoch 1 rides the free-form `options` objects (see OPTION_BAGS).
CATALOG_EPOCH = 2

# Which `options` bag carries which feature (PROTOCOL-3.md 7.7). The bags are free-form objects
# in the schema, so a later package changes a handler, never the schema.
OPTION_BAGS = {
    "ghidra_query": "type_edit options.kind (commit, commit_revert, rebase, publish, merge, export_bundle, "
                    "import_bundle, plus today's kinds), options.view, options.expect_revision, options.as (the agent "
                    "identity of the call, D59); status options.show (changes, views, lineage, queue, health)",
    "backend": "action=backups options.op (list, verify, remove: remove is a dry run unless confirm:true) and "
               "selectors; action=doctor options (sections, verbose)",
    "ghidra_run": "options.isolation (private, shared, exclusive), options.readonly, options.as (the agent identity "
                  "of the call, D59)",
    "job": "status/cancel filters (kind, cid) for commit and backup jobs",
    "runtime": "per-action options (exists)",
}

# The handler registry (PROTOCOL-3.md 8.2, D34). A capability name maps to the module that implements it. The module is
# imported lazily, at call time, so a test can patch this table and a later package registers its handler by creating
# its module, never by editing this file. A module that does not exist yet, or that has no `handle`, answers
# `not_available` (a result, not an error). `handle(capability, request)` returns the reply text; `request` carries
# `tool`, `action`, `options`, `args` and `settings`.
HANDLER_MODULES = {
    "backups": "hydralysis.backups",
    "doctor": "hydralysis.doctor",
    "jobOptions": "hydralysis.commits",
    "scriptIsolation": "hydralysis.userscripts",
    "views": "hydralysis.views",
    "publish": "hydralysis.publish",
    "environment": "hydralysis.environment",
    "evidenceBundle": "hydralysis.evidence_bundle",
}


def handler(capability: str):
    """The module registered for CAPABILITY, or None while it does not exist (or has no `handle`)."""
    name = HANDLER_MODULES.get(capability)
    if not name:
        return None
    try:
        module = importlib.import_module(name)
    except ModuleNotFoundError as exc:
        if exc.name and (name == exc.name or name.startswith(exc.name + ".")):
            return None
        raise
    return module if callable(getattr(module, "handle", None)) else None


def dispatch(capability: str, message: str, request: dict, **detail) -> str:
    """Hand REQUEST to the registered handler; `not_available` with MESSAGE when there is none."""
    module = handler(capability)
    if module is None:
        return not_available(capability, message, **detail)
    return module.handle(capability, request)


def catalog_hash(table: list[dict] | None = None) -> str:
    """SHA-256 over the canonical JSON of the advertised tools (names, descriptions, schemas)."""
    canonical = json.dumps(tool_table() if table is None else table, sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("ascii")).hexdigest()


def catalog() -> dict:
    return {"epoch": CATALOG_EPOCH, "hash": catalog_hash()}


def not_available(capability: str, message: str, **detail) -> str:
    """The reply of a carrier whose engine or Hydralysis capability is not there yet (a result, not an error)."""
    return json.dumps({"not_available": capability, "message": message, **detail, "catalog": catalog()}, indent=2)


def tool_table() -> list[dict]:
    def tool(name: str, description: str, properties: dict, required: list[str] | None = None) -> dict:
        schema: dict = {"type": "object", "properties": properties}
        if required:
            schema["required"] = required
        return {"name": name, "description": description, "inputSchema": schema}

    string = {"type": "string"}
    integer = {"type": "integer"}
    pe_address = {"type": "string", "description": "Use rva:/va:; ambiguous unprefixed addresses are refused."}
    options = {"type": "object"}
    return [
        tool("fingerprint", "PE build identity and packing triage. detail=sections/exports returns those tables.", {"exe": string, "detail": {"type": "string", "enum": ["header", "sections", "exports"]}}, ["exe"]),
        tool("imports", "Imported symbols and IAT slots (xrefs on a slot: its callers); pattern filters.", {"exe": string, "limit": integer, "pattern": string}, ["exe"]),
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
        tool("prologue", "Verify one prologue or checks[{address,expect (or a list),name?}] against a PE build's file bytes; with session, live bytes and who patched them. Any mismatch fails.", {
            "exe": string, "address": pe_address, "expect": string,
            "checks": {"type": "array", "items": {"type": "object"}},
            "sha256": string, "image_base": string, "session": string,
        }, ["exe"]),
        tool("evidence_add", "Store one proved claim (note and source required), attributed to this client; subsystem groups it; supersedes=<id> replaces an older claim, keeping it.", {
            "target": string, "build": string, "kind": string, "name": string,
            "note": string, "source": string, "address": string, "prologue": string, "db": string,
            "subsystem": string, "supersedes": integer,
        }, ["target", "build", "kind", "name", "note", "source"]),
        tool("evidence_list", "Claims, newest first, by target/subsystem/address/build; superseded ones on request. export=<path.md> writes a subsystem (and .jsonl).", {
            "target": string, "limit": integer, "db": string, "subsystem": string, "address": string, "build": string,
            "include_superseded": {"type": "boolean"}, "export": string}),
        tool("ghidra_run", "Run your Ghidra script on saved analysis; contained and rolled back.", {
            "target": string, "script": string, "view": string,
            "args": {"type": "array", "items": string},
            "timeout_s": integer, "options": options,
        }, ["target", "script"]),
        tool("ghidra_query", "Query saved analysis; pages use next_cursor. address_map imports cited name/hash maps; export starts a job. See backend help.", {
            "target": string,
            "action": {"type": "string", "enum": ["decompile", "function", "functions", "xrefs", "types", "type", "data", "scan", "variables", "dossier", "blocks", "pcode", "trace", "type_edit", "diff", "vcalls", "vtables", "writes", "orphans", "export", "address_map", "status", "stop"]},
            "address": string, "limit": integer, "cursor": string, "contains": string, "timeout_s": integer,
            "options": options,
        }, ["target"]),
        tool("backend", "Discover/install private analysis or runtime engines, never other MCPs. install returns a durable job. status/stop the shared engine. doctor and backups take options. help gives operation options.", {
            "action": {"type": "string", "enum": ["inspect", "install", "status", "stop", "help", "doctor", "backups"]},
            "component": {"type": "string", "enum": ["analysis", "runtime"]}, "options": options,
        }),
        tool("prepare", "Register a build: adopt an analysed project in place (path=.gpr or folder; hash-checked, no copy), or start a one-time import/analysis job. plan is read-only.", {
            "exe": string, "target": string, "timeout_s": integer, "install": {"type": "boolean"},
            "action": {"type": "string", "enum": ["plan", "start", "adopt"]},
            "path": string, "sha256": string, "program": string,
        }),
        tool("job", "Job status, bounded logs or cancel (needs owner, its start's owner_token). No id lists every client's jobs.", {
            "action": {"type": "string", "enum": ["status", "cancel"]}, "id": string, "limit": integer, "owner": string,
            "options": options,
        }),
        tool("runtime", "Own-process debugging/instrumentation sessions: spawn/attach, modules, memory, verified probes/breakpoints, registers, continue and detach. Use backend help for options.", {
            "action": string, "options": options,
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
        return _image(args).imports_text(int(args.get("limit") or 80), str(args.get("pattern") or ""))
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
        from hydralysis.prologue import compare_table, parse_expect
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
            if args.get("session"):
                _live(result, args, image)
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
            subsystem=str(args.get("subsystem") or ""),
            supersedes=int(args["supersedes"]) if args.get("supersedes") is not None else None,
        )
    if name == "evidence_list":
        path = evidence_path(str(args.get("db") or ""))
        target = str(args.get("target") or args.get("game") or "")
        if args.get("export"):
            from hydralysis.evidence import export
            out = Path(str(args["export"]))
            if not out.is_absolute() or out.suffix != ".md":
                raise ValueError("export must be an absolute path ending in .md")
            return json.dumps(export(path, out, target, str(args.get("subsystem") or "")), indent=2)
        return list_claims(path, target, int(args.get("limit") or 50), subsystem=str(args.get("subsystem") or ""),
                           address=str(args.get("address") or ""), build=str(args.get("build") or ""),
                           include_superseded=bool(args.get("include_superseded")))
    target = str(args.get("target") or args.get("game") or "")
    if name == "ghidra_query":
        settings = _settings()
        if args.get("action") == "export":
            from hydralysis.exporting import start
            return json.dumps(start(settings, target, args.get("options")), indent=2)
        runner = QueryRunner(settings)
        if args.get("action") == "address_map":
            from hydralysis.address_maps import import_map
            options = args.get("options")
            if not isinstance(options, dict) or set(options) != {"path"} or not isinstance(options["path"], str):
                raise ValueError("address_map requires options.path to a cited JSON map")
            return json.dumps(import_map(settings, runner.target(target)["sha256"], options["path"]), indent=2)
        address = str(args.get("address") or "")
        resolution = None
        if address.startswith(("name:", "hash:")):
            from hydralysis.address_maps import resolve
            resolution = resolve(settings, runner.target(target)["sha256"], address)
            address = "rva:" + resolution["rva"]
        result = runner.query(
            target, str(args.get("action") or "decompile"), address,
            int(args.get("limit", 40)), str(args.get("cursor") or ""), str(args.get("contains") or ""),
            int(args.get("timeout_s", 30)),
            args.get("options"),
        )
        if resolution:
            decoded = json.loads(result)
            decoded["address_resolution"] = resolution
            return json.dumps(decoded, ensure_ascii=False)
        return result
    if name == "ghidra_run":
        options = args.get("options")
        if options is not None and not isinstance(options, dict):
            raise ValueError("options must be an object")
        options = dict(options or {})
        from hydralysis import views
        who = views.identify(options)  # `options.as` rides this bag too (D59); it is not an option of the script itself
        stub = _script_options(options)
        if stub:
            return stub
        from hydralysis.userscripts import run
        return run(_settings(), target, str(args.get("script") or ""),
                   [str(item) for item in _list(args.get("args"))], int(args.get("timeout_s") or 600),
                   args.get("view", ""), who=who)
    if name == "ghidra_scripts":
        from hydralysis.userscripts import list_scripts
        return list_scripts(load(), target, str(args.get("filter") or ""))
    if name == "ghidra_jobs":
        return _workflow("job", {"limit": int(args.get("limit") or 20)})
    raise ValueError("unknown tool %s" % name)


def instructions() -> str:
    return (
        "Hydralysis %s. Twenty tools for any PE you own. prepare adopts an analysed project in place, "
        "or imports/analyses a new executable exactly once as a durable job, and registers its build; "
        "backend discovers/installs the engines, never their MCPs. job reports progress. "
        "runtime manages verified debugging/instrumentation sessions. inspect is the function "
        "picture (bounds, prologue, instructions, callers) and does not start a JVM. "
        "sigscan and prologue are how a hook site is found and checked. ghidra_run "
        "runs one of your scripts contained, so it cannot change the project. "
        "Prefer ghidra_query for bounded address-based decompilation and references; "
        "one warm engine serves CLI, MCP and script clients; export writes bulk artifacts as a job. "
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
        options = _options_bag(args)
        if action in ("doctor", "backups"):
            return _backend_action(action, options, args)
        if action == "help":
            from hydralysis.workflow_help import operation_help
            return json.dumps({**operation_help(component), "catalog": catalog(), "option_bags": OPTION_BAGS}, indent=2)
        if action == "install":
            from hydralysis.preparation import start_install
            return json.dumps(start_install(settings, component), indent=2)
        if action in ("status", "stop"):
            if component != "analysis":
                raise ValueError("status/stop apply to the shared analysis engine")
            from hydralysis import hydra
            engine = hydra.Engine(_settings())
            if action == "stop":
                return json.dumps(engine.stop(force=bool(args.get("force"))), indent=2)
            status = engine.call("status")
            keep = ("protocol", "hydraVersion", "ghidraVersion", "installId", "pid", "startedAt", "memory", "youAre")
            summary = {key: status.get(key) for key in keep if key in status}
            summary["catalog"] = catalog()
            summary["projects"] = [{key: item.get(key) for key in ("id", "name", "gpr", "writable", "revision", "stale", "users")}
                                   for item in status.get("projects", [])][:20]
            summary["programs"] = [{key: item.get(key) for key in ("key", "mode", "owner", "users", "busy")}
                                   for item in status.get("programs", [])][:40]
            summary["clients"] = [{key: item.get(key) for key in ("id", "name", "harness")}
                                  for item in status.get("clients", [])][:40]
            summary["imports"] = status.get("imports")
            return json.dumps(summary, indent=2, default=str)
        if action != "inspect":
            raise ValueError("backend action must be inspect, install, status, stop, help, doctor or backups")
        if component == "runtime":
            from hydralysis.runtime import inspect
        else:
            from hydralysis.backends import inspect
        report = {**inspect(settings), "catalog": catalog()}
        from hydralysis import compat
        if compat.deprecations():
            # Names inherited from RusticRE that this process still honoured (one release).
            report = {**report, "deprecated": compat.deprecations()}
        return json.dumps(report, indent=2)
    if name == "prepare":
        from hydralysis.preparation import adopt, plan, prepare
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
        options = _options_bag(args)
        if options:
            return dispatch("jobOptions", "job options are not implemented in this release; call job without options",
                            {"tool": "job", "action": args.get("action", "status"), "options": options, "args": args,
                             "settings": settings}, tool="job", options=sorted(options))
        from hydralysis.preparation import cancel, status
        job_id = str(args.get("id") or "")
        action = args.get("action", "status")
        if action == "cancel":
            if not job_id:
                raise ValueError("job id is required for cancellation")
            if job_id.startswith("export-"):
                from hydralysis.exporting import cancel as cancel_export
                return json.dumps(cancel_export(settings, job_id, str(args.get("owner") or "")), indent=2)
            if job_id.startswith("overlay-"):
                from hydralysis.overlayjobs import cancel as cancel_overlay
                return json.dumps(cancel_overlay(settings, job_id, str(args.get("owner") or "")), indent=2)
            return json.dumps(cancel(settings, job_id, str(args.get("owner") or "")), indent=2)
        if action != "status":
            raise ValueError("job action must be status or cancel")
        if not job_id:
            from hydralysis.backends import read_json
            from hydralysis.exporting import status as export_status
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
            from hydralysis.overlayjobs import status as overlay_status
            overlays = sorted((Path(settings["root"]) / "overlay-jobs").glob("overlay-*/job.json"),
                              key=lambda item: item.stat().st_mtime_ns, reverse=True)[:limit]
            records.extend(overlay_status(settings, item.parent.name) for item in overlays)
            records.sort(key=lambda item: item.get("created_at", item.get("started_at", 0)), reverse=True)
            fields = ("id", "job_id", "kind", "component", "state", "stage", "target", "game", "script", "owner",
                      "created_at", "started_at", "elapsed_s", "duration_s", "completed", "failed", "complete", "log_path")
            return json.dumps({"jobs": [{key: item[key] for key in fields if key in item} for item in records[:limit]],
                               "detail": "Pass an id to job status for bounded logs and full metadata."}, indent=2)
        if job_id.startswith("export-"):
            from hydralysis.exporting import status as export_status
            return json.dumps(export_status(settings, job_id), indent=2)
        if job_id.startswith("overlay-"):
            from hydralysis.overlayjobs import status as overlay_status
            return json.dumps(overlay_status(settings, job_id), indent=2)
        if job_id.startswith("job-"):
            import re
            if not re.fullmatch(r"job-[0-9a-f]{12}", job_id):
                raise ValueError("invalid script job id")
            from hydralysis.backends import read_json
            record = read_json(Path(settings["root"]) / "jobs" / (job_id + ".json"))
            if not record:
                raise ValueError("no script job %s" % job_id)
            return json.dumps(record, indent=2)
        return json.dumps(status(settings, job_id, int(args.get("limit", 20))), indent=2)
    if args.get("action") == "setup":
        from hydralysis.preparation import start_install
        return json.dumps(start_install(settings, "runtime"), indent=2)
    from hydralysis.runtime import runtime
    return runtime(str(args.get("action") or ""), args.get("options") or {}, settings)


def _options_bag(args: dict) -> dict:
    """The tool's free-form `options` object ({} when absent); anything else is refused."""
    options = args.get("options")
    if options is None:
        return {}
    if not isinstance(options, dict):
        raise ValueError("options must be an object")
    return options


def _backend_action(action: str, options: dict, args: dict) -> str:
    """doctor and backups: validated here, then handed to the registered handler (backups.py, doctor.py)."""
    if action == "backups":
        op = options.get("op", "list")
        if op not in ("list", "verify", "remove"):
            raise ValueError("backups options.op must be list, verify or remove")
        return dispatch("backups", "backend action=backups is not implemented in this release; no backup was listed or verified",
                        {"tool": "backend", "action": action, "options": options, "args": args, "settings": None},
                        tool="backend", action=action, op=op)
    return dispatch("doctor", "backend action=doctor is not implemented in this release; use backend status and inspect",
                    {"tool": "backend", "action": action, "options": options, "args": args, "settings": None},
                    tool="backend", action=action)


def _script_options(options) -> str:
    """ghidra_run options.{isolation, readonly}: validated, then not_available until the engine capability exists.

    Empty or absent options run the script exactly as before. Options are never silently ignored: a
    request for private isolation or a read-only run must not turn into a different mode."""
    if options is None:
        return ""
    if not isinstance(options, dict):
        raise ValueError("options must be an object")
    if not options:
        return ""
    isolation = options.get("isolation")
    if isolation is not None and isolation not in ("private", "shared", "exclusive"):
        raise ValueError("ghidra_run options.isolation must be private, shared or exclusive")
    if "readonly" in options and not isinstance(options["readonly"], bool):
        raise ValueError("ghidra_run options.readonly must be a boolean")
    return dispatch("scriptIsolation", "ghidra_run options are not implemented in this release; the script was not run. "
                    "Call ghidra_run without options for today's contained mode",
                    {"tool": "ghidra_run", "action": "run", "options": options, "args": {}, "settings": None},
                    tool="ghidra_run", options=sorted(options))


def _live(result: dict, args: dict, image: Image) -> None:
    """With a runtime session: each row's live bytes, and who patched them if they differ."""
    from hydralysis.runtime import RuntimeRunner
    module = Path(str(args["exe"])).name
    rows = [{"name": row["name"], "module": module, "rva": row["rva"].split(":", 1)[1],
             "size": max(1, min(64, len(row["actual"].split())))} for row in result["rows"]]
    live = RuntimeRunner(load()).call("patches", {"session": str(args["session"]), "rows": rows,
                                                  "sha256": image.fingerprint()["sha256"]})
    for row, observed in zip(result["rows"], live["rows"]):
        row["live_bytes"] = observed["live_bytes"]
        row["live_patched"] = observed["patched"]
        if observed.get("patch"):
            row["live_patch"] = observed["patch"]
    result["summary"]["live_patched"] = live["patched"]
    result["live_provenance"] = live["provenance"]


def _image(args: dict) -> Image:
    exe = args.get("exe") or os_exe()
    if not exe:
        raise ValueError("exe is required")
    path = Path(str(exe))
    if not path.is_file():
        raise ValueError("exe not found: %s" % path)
    return Image(path)


def os_exe() -> str:
    from hydralysis import compat
    return compat.env("EXE", "")


def _addr(image: Image, args: dict) -> int:
    if "address" not in args:
        raise ValueError("address is required")
    text = str(args["address"]).strip()
    if text.startswith(("name:", "hash:")):
        from hydralysis.address_maps import resolve
        image._address_resolution = resolve(_settings(), image.fingerprint()["sha256"], text)
        return int(image._address_resolution["rva"], 16)
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
    from hydralysis.backends import resolved
    return resolved(load())
