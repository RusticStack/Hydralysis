"""Load and validate a trace profile (TOML, `tomllib`).

A profile is refused as a whole with every problem listed, never half-loaded. The content hash of the manifest and of
every file it names (query modules) is computed here and recorded in the trace session, so a session says exactly which
profile it ran under.
"""

from __future__ import annotations

import hashlib
import json
import re
import tomllib
from pathlib import Path

CORE_KINDS = (
    "core.session.start", "core.session.end", "core.process.start", "core.process.exit", "core.module.load",
    "core.module.unload", "core.thread.start", "core.thread.exit", "core.function.enter", "core.function.exit",
    "core.resource.open", "core.resource.close", "core.resource.read", "core.resource.write", "core.resource.missing",
    "core.object.create", "core.object.destroy", "core.state.read", "core.state.write", "core.sync.wait",
    "core.sync.signal", "core.error", "core.marker", "core.capture.source", "core.capture.gap")
DOMAINS = ("app", "game", "service", "driver", "other")
HOSTS = ("windows-x64",)
FAULT_POLICIES = ("tolerant", "fatal", "freezes")
VALUE_TYPES = ("u8", "u16", "u32", "u64", "i32", "i64", "bool", "string", "key", "hex", "va", "bytes")
CODEC_BASES = ("fnv1", "fnv1a", "crc", "murmur3_32", "layout")
ROLE_RESOLVERS = ("thread_start_rva", "thread_name", "pool", "function")
BUILTIN_RESOLVERS = ("profile_module", "profile_object_offset", "path", "handle", "address", "payload_field")
STORE_KINDS = ("file", "registry", "directory")
GROUP_KEYS = ("kind", "resource.key", "function", "state.key", "process_id", "process_gen", "thread_id", "thread_role",
              "module", "frame", "phase", "source_id")
ALIGN_KEYS = ("phase", "frame_offset", "operation", "role", "resource.key", "function")
MAX_HOOKS, MAX_KINDS, MAX_PROLOGUE = 512, 256, 64

BASELINE = Path(__file__).with_name("baseline_fixtures.toml")

_ID = re.compile(r"^[a-z][a-z0-9_-]{0,63}$")
_PROFILE_ID = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,63}/[0-9]{1,6}$")
_KIND = re.compile(r"^(?!core\.)[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,63}(?:\.[a-z][a-z0-9_]{0,63}){0,3}$")
_SHA = re.compile(r"^[0-9a-f]{64}$")
_MODULE = re.compile(r"^[A-Za-z0-9_.+ -]{1,128}$")
_FIELD = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


class ProfileError(ValueError):
    """A profile that cannot be loaded; `errors` lists every reason."""

    def __init__(self, errors: list[str], code: str = "profile_invalid"):
        super().__init__("profile refused: " + "; ".join(errors[:6]) + ("; ..." if len(errors) > 6 else ""))
        self.errors = list(errors)
        self.code = code

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), "errors": self.errors}


class Profile:
    """A validated profile: `data` is the normalised manifest, `files` the SHA-256 of every file it depends on."""

    def __init__(self, data: dict, files: dict[str, str], directory: Path | None):
        self.data = data
        self.files = dict(sorted(files.items()))
        self.directory = directory
        self.id = data["profile"]["id"]
        canonical = json.dumps({"manifest": data, "files": self.files}, sort_keys=True, separators=(",", ":"))
        self.sha256 = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def hook(self, hook_id: str) -> dict | None:
        return next((hook for hook in self.data["hooks"] if hook["id"] == hook_id), None)

    def kind_names(self) -> list[str]:
        return [kind["name"] for kind in self.data["event_kinds"]]

    def builds(self) -> list[str]:
        return [build["image_sha256"] for build in self.data["target"]["builds"]]

    def session_record(self) -> dict:
        """What a trace session records about its profile (TRACE-1 section 6; plan decision 9)."""
        return {"id": self.id, "sha256": self.sha256, "files": self.files, "fixtures_only": self.data["target"]["fixtures_only"],
                "builds": self.builds(), "host": self.data["host"]}


class _Errors(list):
    def add(self, where: str, message: str) -> None:
        self.append("%s: %s" % (where, message))


def _table(value, where: str, errors: _Errors, allowed: set[str], required: set[str] = frozenset()) -> dict:
    if not isinstance(value, dict):
        errors.add(where, "must be a table")
        return {}
    for key in sorted(set(value) - allowed):
        errors.add(where, "unknown key %r" % key)
    for key in sorted(required - set(value)):
        errors.add(where, "missing %r" % key)
    return value


def _rows(data: dict, key: str, errors: _Errors, limit: int) -> list:
    rows = data.get(key, [])
    if not isinstance(rows, list):
        errors.add(key, "must be an array of tables ([[%s]])" % key)
        return []
    if len(rows) > limit:
        errors.add(key, "at most %d entries" % limit)
        return rows[:limit]
    return rows


def _ident(value, where: str, errors: _Errors, pattern=_ID) -> str:
    if not isinstance(value, str) or not pattern.match(value):
        errors.add(where, "%r is not a valid name" % (value,))
        return ""
    return value


def _prologues(value, where: str, errors: _Errors) -> list[str]:
    """One or a few accepted prologues: hex bytes with ?? wildcards, at least one concrete byte."""
    from hydralysis.prologue import parse_expect
    items = value if isinstance(value, list) else [value]
    if not 1 <= len(items) <= 16:
        errors.add(where, "give 1..16 accepted prologues")
        return []
    out = []
    for item in items:
        try:
            parsed = parse_expect(item)
        except ValueError as exc:
            errors.add(where, str(exc))
            continue
        if len(parsed) > MAX_PROLOGUE:
            errors.add(where, "a prologue is at most %d bytes" % MAX_PROLOGUE)
            continue
        out.append(" ".join("??" if byte is None else "%02X" % byte for byte in parsed))
    return out


def _hex_int(value, where: str, errors: _Errors) -> int | None:
    try:
        if isinstance(value, bool):
            raise ValueError
        number = value if isinstance(value, int) else int(str(value).removeprefix("rva:"), 0)
        if number < 0 or number >= 1 << 32:
            raise ValueError
        return number
    except ValueError:
        errors.add(where, "must be a 32-bit hexadecimal RVA such as 0x1a2b0")
        return None


def _validate(data: dict, directory: Path | None, files: dict[str, str], errors: _Errors) -> dict:
    if not isinstance(data, dict):
        raise ProfileError(["the manifest is not a table"])
    top = {"profile", "target", "host", "hooks", "event_kinds", "identity", "resolvers", "codecs", "roles", "phases",
           "diff", "stores", "queries", "bindings"}
    for key in sorted(set(data) - top):
        errors.add("manifest", "unknown section %r" % key)

    meta = _table(data.get("profile"), "profile", errors, {"id", "domain", "description"}, {"id"})
    profile_id = meta.get("id", "")
    if not isinstance(profile_id, str) or not _PROFILE_ID.match(profile_id):
        errors.add("profile.id", "must look like name/1 (lowercase, digits, . _ -, then /version)")
    domain = meta.get("domain", "other")
    if domain not in DOMAINS:
        errors.add("profile.domain", "must be one of %s" % ", ".join(DOMAINS))
    description = str(meta.get("description", ""))[:2000]

    target = _table(data.get("target"), "target", errors, {"bitness", "modules", "builds", "fixtures_only"}, {"bitness", "modules"})
    if target.get("bitness") not in (32, 64):
        errors.add("target.bitness", "must be 32 or 64")
    modules = target.get("modules", [])
    if not isinstance(modules, list) or not 1 <= len(modules) <= 32 or not all(isinstance(m, str) and _MODULE.match(m) for m in modules):
        errors.add("target.modules", "needs 1..32 module names")
        modules = []
    fixtures_only = target.get("fixtures_only", False)
    if not isinstance(fixtures_only, bool):
        errors.add("target.fixtures_only", "must be true or false")
        fixtures_only = False
    builds = []
    for index, row in enumerate(_rows(target, "builds", errors, 256)):
        row = _table(row, "target.builds[%d]" % index, errors, {"module", "image_sha256", "label"}, {"image_sha256"})
        digest = row.get("image_sha256", "")
        if not isinstance(digest, str) or not _SHA.match(digest):
            errors.add("target.builds[%d].image_sha256" % index, "must be 64 lowercase hex digits")
            continue
        module = row.get("module", modules[0] if modules else "")
        if modules and module not in modules:
            errors.add("target.builds[%d].module" % index, "%r is not in target.modules" % (module,))
        builds.append({"module": module, "image_sha256": digest, "label": str(row.get("label", ""))[:128]})
    if not builds and not fixtures_only:
        errors.add("target.builds", "a profile is build-bound: list at least one image_sha256 "
                                    "(only a fixtures_only profile may omit them)")
    if len({b["image_sha256"] for b in builds}) != len(builds):
        errors.add("target.builds", "duplicate image_sha256")

    host = _table(data.get("host", {}), "host", errors, {"os", "fault_policy", "record_handler_chain", "allow_debugger"})
    if host.get("os", "windows-x64") not in HOSTS:
        errors.add("host.os", "only windows-x64 is supported in this release")
    default_fault = host.get("fault_policy", "tolerant")
    if default_fault not in FAULT_POLICIES:
        errors.add("host.fault_policy", "must be one of %s" % ", ".join(FAULT_POLICIES))
        default_fault = "tolerant"
    host_out = {"os": "windows-x64", "fault_policy": default_fault,
                "record_handler_chain": bool(host.get("record_handler_chain", True)),
                "allow_debugger": bool(host.get("allow_debugger", True))}

    # event kinds first: hooks refer to them
    kinds, kind_names = [], set(CORE_KINDS)
    for index, row in enumerate(_rows(data, "event_kinds", errors, MAX_KINDS)):
        where = "event_kinds[%d]" % index
        row = _table(row, where, errors, {"name", "extends", "payload", "description"}, {"name", "extends"})
        name = row.get("name", "")
        if not isinstance(name, str) or not _KIND.match(name):
            errors.add(where + ".name", "must be <namespace>.<name> in lowercase and not in core.*")
            continue
        if name in kind_names:
            errors.add(where + ".name", "%s is declared twice" % name)
        if row.get("extends") not in CORE_KINDS:
            errors.add(where + ".extends", "must be a core kind")
        payload = {}
        for field, kind in _table(row.get("payload", {}), where + ".payload", errors, set(row.get("payload", {}) or {})).items():
            if not isinstance(field, str) or not _FIELD.match(field):
                errors.add(where + ".payload", "field name %r is not valid" % (field,))
                continue
            base = kind[:-1] if isinstance(kind, str) and kind.endswith("?") else kind
            if base not in VALUE_TYPES:
                errors.add(where + ".payload." + field, "type must be one of %s (a trailing ? makes it optional)" % ", ".join(VALUE_TYPES))
                continue
            payload[field] = kind
        kind_names.add(name)
        kinds.append({"name": name, "extends": row.get("extends"), "payload": dict(sorted(payload.items())),
                      "description": str(row.get("description", ""))[:500]})

    hooks, hook_ids = [], set()
    for index, row in enumerate(_rows(data, "hooks", errors, MAX_HOOKS)):
        where = "hooks[%d]" % index
        row = _table(row, where, errors, {"id", "event", "module", "required", "symbol", "rva", "signature", "prologue",
                                          "prologue_offset", "fault", "capture", "note", "nargs", "with_leave", "buf", "stack", "const"}, {"id", "event", "prologue"})
        hook_id = _ident(row.get("id"), where + ".id", errors)
        if hook_id in hook_ids:
            errors.add(where + ".id", "%s is declared twice" % hook_id)
        hook_ids.add(hook_id)
        if row.get("event") not in kind_names:
            errors.add(where + ".event", "%r is neither a core kind nor a kind this profile declares" % (row.get("event"),))
        module = row.get("module", modules[0] if modules else "")
        if not isinstance(module, str) or not _MODULE.match(module):
            errors.add(where + ".module", "needs a module name")
        locators = [key for key in ("symbol", "rva", "signature") if key in row]
        if len(locators) != 1:
            errors.add(where, "give exactly one of symbol, rva or signature (found %s)" % (", ".join(locators) or "none"))
        entry = {"id": hook_id, "event": row.get("event"), "module": module, "required": True,
                 "prologue": _prologues(row.get("prologue"), where + ".prologue", errors),
                 "prologue_offset": 0, "fault": row.get("fault", default_fault), "capture": [], "note": str(row.get("note", ""))[:500],
                 "nargs": 0, "with_leave": False, "buf": None, "stack": 1, "fields": [], "const": {}}
        constants = row.get("const", {})
        if not isinstance(constants, dict) or len(constants) > 8 or not all(_FIELD.match(str(k)) and (isinstance(v, (bool, int)) or (isinstance(v, str) and len(v) <= 64)) for k, v in constants.items()):
            errors.add(where + ".const", "is a table of at most 8 constants (names like capture fields; values true/false, an integer or a short string) added to every event of the hook")
        else:
            entry["const"] = dict(sorted(constants.items()))
        if not isinstance(row.get("required", True), bool):
            errors.add(where + ".required", "must be true or false")
        else:
            entry["required"] = row.get("required", True)
        if entry["fault"] not in FAULT_POLICIES:
            errors.add(where + ".fault", "must be one of %s" % ", ".join(FAULT_POLICIES))
        if "symbol" in row:
            if not isinstance(row["symbol"], str) or not re.match(r"^[A-Za-z_][A-Za-z0-9_@?$.]{0,255}$", row["symbol"]):
                errors.add(where + ".symbol", "must be an exported symbol name")
            entry["symbol"] = row["symbol"]
        if "rva" in row:
            entry["rva"] = _hex_int(row["rva"], where + ".rva", errors)
            if not builds:
                errors.add(where + ".rva", "a verified RVA is build-bound: the profile must list target.builds")
        if "signature" in row:
            try:
                from hydralysis.prologue import parse_expect
                parse_expect(row["signature"])
            except ValueError as exc:
                errors.add(where + ".signature", str(exc))
            entry["signature"] = row["signature"]
        if "prologue_offset" in row:
            offset = row["prologue_offset"]
            if isinstance(offset, bool) or not isinstance(offset, int) or not 0 <= offset <= 4096:
                errors.add(where + ".prologue_offset", "must be 0..4096")
            else:
                entry["prologue_offset"] = offset
        if "nargs" in row:
            if isinstance(row["nargs"], bool) or not isinstance(row["nargs"], int) or not 0 <= row["nargs"] <= 8:
                errors.add(where + ".nargs", "must be 0..8")
            else:
                entry["nargs"] = row["nargs"]
        if "with_leave" in row:
            if not isinstance(row["with_leave"], bool):
                errors.add(where + ".with_leave", "must be true or false (true also records the return value and the time spent)")
            else:
                entry["with_leave"] = row["with_leave"]
        if "stack" in row:
            if isinstance(row["stack"], bool) or not isinstance(row["stack"], int) or not 1 <= row["stack"] <= 16:
                errors.add(where + ".stack", "call-stack depth is 1..16 (1: the return address only)")
            else:
                entry["stack"] = row["stack"]
        if "buf" in row:
            buf = _table(row["buf"], where + ".buf", errors, {"arg", "len_arg", "wide", "cstr", "fixed", "max"}, {"arg"})
            bad = [k for k in ("arg", "len_arg", "fixed", "max") if k in buf and (isinstance(buf[k], bool) or not isinstance(buf[k], int))]
            if bad or not 0 <= buf.get("arg", -1) < 8 or not 0 <= buf.get("len_arg", 0) < 8 or not 0 <= buf.get("max", 64) <= 256                     or not 0 <= buf.get("fixed", 0) <= 256 or not isinstance(buf.get("wide", False), bool) or not isinstance(buf.get("cstr", False), bool):
                errors.add(where + ".buf", "arg and len_arg are argument indexes 0..7, max and fixed are at most 256, wide is true or false")
            else:
                entry["buf"] = {"arg": buf["arg"], "len_arg": buf.get("len_arg"), "wide": bool(buf.get("wide", False)), "cstr": bool(buf.get("cstr", False)),
                                "fixed": buf.get("fixed", 0), "max": buf.get("max", 64)}
        for item in row.get("capture", []) if isinstance(row.get("capture", []), list) else [None]:
            name, _, kind = str(item).partition(":")
            kind, _, source = kind.partition("@")
            if not _FIELD.match(name) or kind.rstrip("?") not in VALUE_TYPES or source not in ("", "ret", *map(str, range(8))):
                errors.add(where + ".capture", "entries look like name:u64 or name:u64@2 (argument 2) or name:u32@ret (types: %s)"
                           % ", ".join(VALUE_TYPES))
            else:
                position = len(entry["capture"])
                entry["capture"].append(str(item))
                entry["fields"].append({"name": name, "type": kind.rstrip("?"), "source": source or str(position)})
        if "nargs" not in row:
            entry["nargs"] = max([int(f["source"]) + 1 for f in entry["fields"] if f["source"] != "ret"]
                                 + ([entry["buf"]["arg"] + 1] if entry["buf"] else []) + [0])
        if any(f["source"] == "ret" for f in entry["fields"]):
            entry["with_leave"] = True      # the return value only exists once the call is done
        if modules and isinstance(module, str) and module not in modules and module != "*":
            errors.add(where + ".module", "%r is not in target.modules" % module)
        hooks.append(entry)

    resolvers, resolver_ids = [], set(BUILTIN_RESOLVERS)
    for index, row in enumerate(_rows(data, "resolvers", errors, 128)):
        where = "resolvers[%d]" % index
        row = _table(row, where, errors, {"id", "kind", "from", "normalize"}, {"id", "kind", "from"})
        rid = _ident(row.get("id"), where + ".id", errors)
        if row.get("kind") not in ("resource", "state", "object"):
            errors.add(where + ".kind", "must be resource, state or object")
        if not isinstance(row.get("from"), str) or not re.match(r"^payload\.[a-z][a-z0-9_]*(\+payload\.[a-z][a-z0-9_]*)*$", row.get("from", "")):
            errors.add(where + ".from", "must name payload fields, such as payload.path or payload.object+payload.offset")
        if row.get("normalize", "none") not in ("none", "lower", "basename", "lower-basename"):
            errors.add(where + ".normalize", "must be none, lower, basename or lower-basename")
        if rid in resolver_ids:
            errors.add(where + ".id", "%s is declared twice or is a built-in" % rid)
        resolver_ids.add(rid)
        resolvers.append({"id": rid, "kind": row.get("kind"), "from": row.get("from"), "normalize": row.get("normalize", "none")})
    identity = _table(data.get("identity", {}), "identity", errors, {"resource", "state", "object"})
    for key, value in identity.items():
        if value not in resolver_ids:
            errors.add("identity." + key, "%r is not a built-in or declared resolver" % (value,))

    codecs, codec_ids = [], set()
    from hydralysis import trace_hashes
    registry = trace_hashes.Registry()
    for index, row in enumerate(_rows(data, "codecs", errors, 128)):
        where = "codecs[%d]" % index
        row = _table(row, where, errors, {"id", "base", "bits", "params", "fold", "encoding", "applies_to", "vectors", "fields",
                                          "image_sha256", "schema_sha256", "struct"}, {"id", "base"})
        cid = _ident(row.get("id"), where + ".id", errors, re.compile(r"^[a-z][a-z0-9_.-]{0,63}$"))
        if cid in codec_ids:
            errors.add(where + ".id", "%s is declared twice" % cid)
        codec_ids.add(cid)
        if row.get("base") not in CODEC_BASES:
            errors.add(where + ".base", "must be one of %s" % ", ".join(CODEC_BASES))
            continue
        applies = row.get("applies_to", [])
        for target_ref in applies if isinstance(applies, list) else [applies]:
            kind, _, field = str(target_ref).partition(".payload.")
            if kind not in kind_names or not field:
                errors.add(where + ".applies_to", "%r must look like <kind>.payload.<field> for a known kind" % (target_ref,))
        entry = {"id": cid, "base": row["base"], "applies_to": list(applies) if isinstance(applies, list) else [applies]}
        if row["base"] == "layout":
            fields = []
            for fidx, item in enumerate(row.get("fields", []) if isinstance(row.get("fields", []), list) else []):
                item = _table(item, "%s.fields[%d]" % (where, fidx), errors, {"name", "offset", "type", "size"}, {"name", "offset", "type"})
                if item.get("type") not in VALUE_TYPES:
                    errors.add("%s.fields[%d].type" % (where, fidx), "must be one of %s" % ", ".join(VALUE_TYPES))
                if isinstance(item.get("offset"), bool) or not isinstance(item.get("offset"), int) or item["offset"] < 0:
                    errors.add("%s.fields[%d].offset" % (where, fidx), "must be a non-negative integer")
                fields.append({"name": item.get("name"), "offset": item.get("offset"), "type": item.get("type"), "size": item.get("size")})
            if not fields:
                errors.add(where + ".fields", "a layout codec lists its fields")
            digest = row.get("image_sha256", "")
            if digest and not (isinstance(digest, str) and _SHA.match(digest)):
                errors.add(where + ".image_sha256", "must be 64 lowercase hex digits")
            entry.update(fields=fields, image_sha256=digest, struct=str(row.get("struct", "")) or None,
                         schema_sha256=hashlib.sha256(json.dumps(fields, sort_keys=True).encode()).hexdigest())
        else:
            try:
                registry.add_codec({"id": cid, "base": row["base"], "bits": row.get("bits"), "params": row.get("params"),
                                    "fold": row.get("fold", "none"), "encoding": row.get("encoding", "utf-8"),
                                    "vectors": row.get("vectors")})
            except (trace_hashes.HashError, KeyError, TypeError, ValueError) as exc:
                errors.add(where, str(exc))
            entry.update(bits=row.get("bits"), params=row.get("params") or {}, fold=row.get("fold", "none"),
                         encoding=row.get("encoding", "utf-8"), vectors=row.get("vectors") or [])
        codecs.append(entry)

    roles = []
    for index, row in enumerate(_rows(data, "roles", errors, 64)):
        where = "roles[%d]" % index
        row = _table(row, where, errors, {"id", "resolve", "value"}, {"id", "resolve", "value"})
        rid = _ident(row.get("id"), where + ".id", errors)
        if row.get("resolve") not in ROLE_RESOLVERS:
            errors.add(where + ".resolve", "must be one of %s" % ", ".join(ROLE_RESOLVERS))
        elif row["resolve"] == "function" and row.get("value") not in hook_ids:
            errors.add(where + ".value", "a function role names a hook id (the thread that ran it)")
        elif row["resolve"] == "thread_start_rva":
            _hex_int(row.get("value"), where + ".value", errors)
        roles.append({"id": rid, "resolve": row.get("resolve"), "value": row.get("value")})

    phases, phase_ids = [], set()
    for index, row in enumerate(_rows(data, "phases", errors, 64)):
        where = "phases[%d]" % index
        row = _table(row, where, errors, {"id", "kind", "open", "close", "parent"}, {"id", "kind", "open", "close"})
        pid = _ident(row.get("id"), where + ".id", errors)
        if row.get("kind") not in ("frame", "stage"):
            errors.add(where + ".kind", "must be frame or stage")
        for edge in ("open", "close"):
            if row.get(edge) not in hook_ids and row.get(edge) not in kind_names:
                errors.add("%s.%s" % (where, edge), "%r is not a hook id or a known event kind" % (row.get(edge),))
        if row.get("kind") == "stage" and row.get("parent") not in phase_ids:
            errors.add(where + ".parent", "a stage names the frame phase it sits in (declare the frame first)")
        phase_ids.add(pid)
        phases.append({"id": pid, "kind": row.get("kind"), "open": row.get("open"), "close": row.get("close"), "parent": row.get("parent")})

    diff = _table(data.get("diff", {}), "diff", errors, {"group_by", "align"})
    group_by = diff.get("group_by", ["kind", "resource.key", "function"])

    def group_key_ok(key) -> bool:
        if key in GROUP_KEYS:
            return True
        field = key.removeprefix("payload.") if isinstance(key, str) and key.startswith("payload.") else None
        return bool(field and _FIELD.match(field))
    if not isinstance(group_by, list) or not group_by or not all(group_key_ok(k) for k in group_by):
        errors.add("diff.group_by", "keys are %s or payload.<field>" % ", ".join(GROUP_KEYS))
        group_by = ["kind"]
    align = diff.get("align", [])
    if not isinstance(align, list) or any(a not in ALIGN_KEYS for a in align):
        errors.add("diff.align", "keys are %s" % ", ".join(ALIGN_KEYS))
        align = []
    if ("phase" in align or "frame_offset" in align) and not phases:
        errors.add("diff.align", "aligning by phase needs [[phases]] markers; a missing marker is `unknown`, not a match")

    stores = []
    for index, row in enumerate(_rows(data, "stores", errors, 64)):
        where = "stores[%d]" % index
        row = _table(row, where, errors, {"id", "kind", "path", "note"}, {"id", "kind", "path"})
        if row.get("kind") not in STORE_KINDS:
            errors.add(where + ".kind", "must be one of %s" % ", ".join(STORE_KINDS))
        if not isinstance(row.get("path"), str) or not row["path"].strip() or len(row["path"]) > 1024 or "\0" in row["path"]:
            errors.add(where + ".path", "needs a path or key")
        stores.append({"id": _ident(row.get("id"), where + ".id", errors), "kind": row.get("kind"), "path": row.get("path"),
                       "note": str(row.get("note", ""))[:500]})

    queries = []
    for index, row in enumerate(_rows(data, "queries", errors, 128)):
        where = "queries[%d]" % index
        row = _table(row, where, errors, {"id", "kinds", "group_by", "filter", "limit", "module", "sha256", "description"}, {"id"})
        qid = _ident(row.get("id"), where + ".id", errors, re.compile(r"^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*){0,4}$"))
        entry = {"id": qid, "description": str(row.get("description", ""))[:500]}
        if "module" in row:
            module_path = row["module"]
            digest = row.get("sha256", "")
            if directory is None:
                errors.add(where + ".module", "a Python query module needs a profile loaded from a file (it is a sibling file)")
            elif not isinstance(module_path, str) or not module_path.endswith(".py"):
                errors.add(where + ".module", "must be a relative .py path")
            elif not isinstance(digest, str) or not _SHA.match(digest):
                errors.add(where + ".sha256", "a module is pinned by its SHA-256")
            else:
                full = (directory / module_path).resolve()
                try:
                    full.relative_to(directory.resolve())
                except ValueError:
                    errors.add(where + ".module", "must stay inside the profile folder")
                else:
                    if not full.is_file():
                        errors.add(where + ".module", "%s does not exist" % module_path)
                    else:
                        actual = hashlib.sha256(full.read_bytes()).hexdigest()
                        if actual != digest:
                            errors.add(where + ".sha256", "the module hashes to %s, not the pinned %s" % (actual, digest))
                        files[module_path.replace("\\", "/")] = actual
                        entry.update(module=module_path.replace("\\", "/"), sha256=digest)
        else:
            qkinds = row.get("kinds", [])
            if not isinstance(qkinds, list) or not qkinds or any(k not in kind_names for k in qkinds):
                errors.add(where + ".kinds", "lists known event kinds")
            qgroup = row.get("group_by", [])
            if not isinstance(qgroup, list) or not qgroup or not all(group_key_ok(k) for k in qgroup):
                errors.add(where + ".group_by", "keys are %s or payload.<field>" % ", ".join(GROUP_KEYS))
            qfilter = row.get("filter", {})
            if not isinstance(qfilter, dict) or len(qfilter) > 16 or not all(isinstance(v, (str, int, bool)) for v in qfilter.values()):
                errors.add(where + ".filter", "equality terms only, up to 16")
            limit = row.get("limit", 50)
            if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 200:
                errors.add(where + ".limit", "must be 1..200")
            entry.update(kinds=qkinds, group_by=qgroup, filter=qfilter, limit=limit)
        queries.append(entry)
    if len({q["id"] for q in queries}) != len(queries):
        errors.add("queries", "duplicate id")

    bindings = []
    for index, row in enumerate(_rows(data, "bindings", errors, 32)):
        where = "bindings[%d]" % index
        row = _table(row, where, errors, {"id", "kind", "table_rva", "stride", "name_offset", "fn_offset", "count", "argc_offset",
                                          "argc_size", "name_arg", "fn_arg", "argc_arg", "register"}, {"id", "kind"})
        entry = {"id": _ident(row.get("id"), where + ".id", errors), "kind": row.get("kind")}

        def small(key, minimum=0, maximum=1 << 20, required=False):
            value = row.get(key)
            if value is None:
                if required:
                    errors.add(where + "." + key, "is required for kind %s" % row.get("kind"))
                return None
            if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
                errors.add(where + "." + key, "must be an integer %d..%d" % (minimum, maximum))
                return None
            return value
        if row.get("kind") == "table":
            rva = _hex_int(row.get("table_rva"), where + ".table_rva", errors) if "table_rva" in row else None
            if rva is None and "table_rva" not in row:
                errors.add(where + ".table_rva", "is required for kind table")
            entry.update(table_rva=rva, stride=small("stride", 4, 4096, True), name_offset=small("name_offset", 0, 4096, True),
                         fn_offset=small("fn_offset", 0, 4096, True), count=small("count", 1, 4096),
                         argc_offset=small("argc_offset", 0, 4096), argc_size=small("argc_size", 1, 8) or 4)
        elif row.get("kind") == "call":
            register = row.get("register")
            if register not in hook_ids:
                errors.add(where + ".register", "names the hook id of the registration function")
            entry.update(register=register, name_arg=small("name_arg", 0, 15, True), fn_arg=small("fn_arg", 0, 15, True),
                         argc_arg=small("argc_arg", 0, 15))
        else:
            errors.add(where + ".kind", "must be table or call")
        bindings.append(entry)
    if len({b["id"] for b in bindings}) != len(bindings):
        errors.add("bindings", "duplicate id")

    return {"profile": {"id": profile_id, "domain": domain, "description": description},
            "target": {"bitness": target.get("bitness"), "modules": modules, "builds": builds, "fixtures_only": fixtures_only},
            "host": host_out, "hooks": hooks, "event_kinds": kinds,
            "identity": {k: identity[k] for k in sorted(identity)}, "resolvers": resolvers, "codecs": codecs, "roles": roles,
            "phases": phases, "diff": {"group_by": group_by, "align": align}, "stores": stores, "queries": queries,
            "bindings": bindings}


def load_text(text: str, *, directory: Path | None = None, manifest_name: str = "profile.toml") -> Profile:
    """Parse and validate a manifest. DIRECTORY is where its sibling query modules live (none: modules are refused)."""
    raw = text.encode("utf-8") if isinstance(text, str) else bytes(text)
    if len(raw) > 512 * 1024:
        raise ProfileError(["the manifest is larger than 512 KiB"])
    try:
        data = tomllib.loads(raw.decode("utf-8"))
    except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
        raise ProfileError(["not valid TOML: %s" % exc], "profile_unreadable") from exc
    files = {manifest_name: hashlib.sha256(raw).hexdigest()}
    errors = _Errors()
    normalised = _validate(data, directory, files, errors)
    if errors:
        raise ProfileError(list(errors))
    return Profile(normalised, files, directory)


def load_file(path: str | Path) -> Profile:
    path = Path(path)
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ProfileError(["cannot read %s: %s" % (path, exc)], "profile_unreadable") from exc
    return load_text(raw, directory=path.parent, manifest_name=path.name)


def load_baseline() -> Profile:
    """The fixtures-only baseline profile that ships with Hydralysis."""
    return load_file(BASELINE)
