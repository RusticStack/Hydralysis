"""Operation details are retrieved on demand instead of bloating MCP schemas."""


def operation_help(component: str = "analysis") -> dict:
    if component == "runtime":
        return {
            "setup": "backend action=install component=runtime returns a job id; poll job status",
            "runtime_actions": {
                "processes": {"limit": "1..200"},
                "spawn": {"exe": "absolute owned executable", "sha256": "required full SHA-256 of exe", "argv": "optional argument array",
                          "cwd": "optional absolute working directory (games resolve data relative to it)",
                          "env": "optional {name: value} added to the caller's environment"},
                "attach": {"pid": "explicit process id", "exe": "expected executable path", "sha256": "required full SHA-256 of exe"},
                "status": {"session": "returned session id", "after": "event cursor", "limit": "bounded event count"},
                "modules": {"session": "id", "limit": "bounded rows"},
                "threads": {"session": "id", "limit": "bounded rows"},
                "read": {"session": "id", "module": "exact loaded module name with rva, OR address for absolute heap/stack", "rva": "module-relative hex offset", "address": "absolute readable target address; mutually exclusive with module/rva", "size": "1..4096 bytes"},
                "observe/break": {"session": "id", "module": "exact loaded module", "rva": "offset", "sha256": "module file build hash", "expect": "exact live bytes before installing a probe", "limit": "event count"},
                "continue": {"session": "id", "hook_id": "optional breakpoint id"},
                "unload": {"session": "id", "hook_id": "probe id"},
                "resume/detach": {"session": "id"},
            },
            "semantics": "Breakpoints capture observed registers, arguments and stack context; bounded automatic release prevents abandoned pauses. Detach removes instrumentation. CPU single-step is not supplied by this instrumentation backend.",
            "trust": "Every built-in probe requires module build identity and matching live bytes. Unrestricted injected scripts are not exposed because they could bypass that gate. No remote target or other MCP server is implied.",
        }
    return {
        "setup": "backend inspect discovers existing engines; backend install starts a private, verified portable installation job",
        "prepare": "exe, optional target; explicit initial import/analysis only. Returns a durable job; duplicate builds reuse one result. Planning performs no import.",
        "jobs": "job status with id returns stage, elapsed time and bounded progress log; job cancel requests owned-process cleanup",
        "queries": "ghidra_query uses configured or prepared target, numeric VA or rva:/va:, action, limit/cursor/contains/timeout_s and options",
        "prologue": "Single address/expect or checks[{address,expect,name?}], 1..200 rows, one PE open/hash. CLI --checks-file accepts canonical rows or legacy offset/prologue/names with explicit --offset-kind.",
        "actions": {
            "decompile/function/functions/xrefs": "read-only analysed results with bounded continuation",
            "types": "paged types, optional contains and cursor",
            "type": {"path": "exact database category path, or use address for typed data"},
            "data": {"table": "optional bool: bounded pointer candidates at address; inferred vtables require further evidence"},
            "scan": {"end": "optional inclusive numeric VA", "mnemonic": "literal substring", "operand": "literal substring; decoded listing, at most 2000 instructions/page; use next_cursor"},
            "variables": "recovered local/parameter types for address's function",
            "dossier": "bounded function picture with references/callers/callees",
            "blocks": "basic blocks and their observed static edges",
            "pcode": {"nodes": "1..200; stable op/varnode IDs seed a trace"},
            "trace": {"seed": "op/varnode id from pcode", "direction": "backward or forward", "depth": "1..12", "nodes": "1..200", "functions": "1..4"},
            "type_edit": {
                "kind": "struct/signature/variable/apply/rename/comment/function_create/function_body/function_delete/batch", "source": "required supporting evidence",
                "struct": "path,size,fields[{offset,type,name,length?}]", "signature": "prototype",
                "variable": "variable,type,name?", "apply": "type", "rename": "name", "comment": "comment",
                "function_create/function_body": "expect=exact entry bytes, ranges=[{start,end}] numeric inclusive VAs; optional name",
                "function_delete": "expect=exact entry bytes; explicit entry VA",
                "batch": "source plus edits=[{address,options}] OR file=JSON array path, 1..200 nonbatch children, atomic rollback; source inherited if absent. File snapshot max256KiB is embedded and hashed for replay.",
            },
            "export": {"mode": "decompile/functions/types", "limit": "maximum records, default100000", "contains": "optional function/type filter", "timeout_s": "per-query deadline 1..300", "resume": "existing export job id; source/options identity must match"},
        },
        "type_persistence": "Edits are full-build-hash-bound overlays replayed only in worker memory. The canonical project is not saved or mutated.",
        "flow_limits": "Recovered high-pcode dependencies and direct-call bindings are evidence, not proof of runtime reachability, complete aliasing, or indirect targets.",
    }
