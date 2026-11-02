"""A new build: what does it invalidate? (spec 15.10)

* **Corpus diff** (`diff_corpora`): two type corpora (docs/type-corpus.md; for example reflection dumps of build A and
  build B) yield added, removed, moved, resized, retyped and renamed fields, enum members that changed, and functions that
  moved, appeared or disappeared. Records are matched by name and, for what is left over, by the `hash` field when the
  target's dump provides one (a renamed record keeps its hash).
* **Invalidation report** (`invalidation_report`): every dependent that cites build A (evidence claims, overlay edits,
  address-map rows, hook-table rows, profile probes, codec layouts, assertions) gets a status for build B:

  `carried`    identical bytes or layout, proven (the function's bytes were compared, or the type/field did not change)
  `candidate`  matched, but it needs independent evidence in build B (a moved function, a changed prologue, or bytes that
               were not available to compare)
  `moved`      the layout changed; the report lists the dependents that rest on it
  `unplaced`   the thing is not in build B (removed, or it cannot be matched)

  **Nothing is promoted automatically.** The report is the work list; `promoted` is always 0.

A function is never `carried` without bytes: without a reader for both builds the best status is `candidate`.
"""

from __future__ import annotations

import json
from pathlib import Path

PRIORITY = {"carried": 0, "candidate": 1, "moved": 2, "unplaced": 3}
TYPE_KINDS = ("struct", "union", "enum", "typedef", "function_type")
POLICY = "Nothing is promoted to build B automatically; this report is the work list."


class CorpusError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def load_corpus(source) -> dict:
    """A corpus from a path to a JSONL file, or from an iterable of record dicts."""
    if isinstance(source, (str, Path)):
        text = Path(source).read_text("utf-8")
        records = []
        for number, line in enumerate(text.splitlines(), 1):
            if line.strip():
                try:
                    records.append(json.loads(line))
                except ValueError as exc:
                    raise CorpusError("corpus_invalid", "%s line %d is not JSON: %s" % (source, number, exc)) from exc
    else:
        records = list(source)
    types, functions = {}, {}
    for record in records:
        if not isinstance(record, dict) or "kind" not in record:
            raise CorpusError("corpus_invalid", "a corpus record is an object with a kind")
        if record["kind"] in TYPE_KINDS:
            types[record["name"]] = record
        elif record["kind"] == "function":
            key = record.get("name") or record.get("address")
            functions[key] = record
        elif record["kind"] == "vtable":
            types.setdefault("vtable:" + record["class"], record)
    return {"types": types, "functions": functions}


def _fields(record: dict) -> dict:
    return {field["name"]: field for field in record.get("fields") or [] if isinstance(field, dict) and "name" in field}


def _members(record: dict) -> dict:
    return {member[0]: member[1] for member in record.get("members") or [] if isinstance(member, (list, tuple)) and len(member) >= 2}


def _view(field: dict | None) -> dict | None:
    return None if field is None else {"offset": field.get("offset"), "type": field.get("type"), "size": field.get("size")}


def diff_corpora(a: dict, b: dict) -> dict:
    """What changed between corpus A and corpus B (both from `load_corpus`)."""
    types_a, types_b = a["types"], b["types"]
    removed = sorted(set(types_a) - set(types_b))
    added = sorted(set(types_b) - set(types_a))
    renamed = []
    by_hash_b = {record["hash"]: name for name, record in types_b.items() if name in added and record.get("hash") is not None}
    for name in list(removed):
        digest = types_a[name].get("hash")
        if digest is not None and digest in by_hash_b:
            renamed.append({"from": name, "to": by_hash_b[digest], "basis": "hash %s" % digest})
            removed.remove(name)
            added.remove(by_hash_b[digest])
    pairs = [(name, name) for name in sorted(set(types_a) & set(types_b))] + [(r["from"], r["to"]) for r in renamed]

    field_changes, enum_changes, struct_changes = [], [], []
    for name_a, name_b in pairs:
        ra, rb = types_a[name_a], types_b[name_b]
        label = name_b
        if ra.get("kind") == "enum" or rb.get("kind") == "enum":
            ma, mb = _members(ra), _members(rb)
            for member in sorted(set(ma) | set(mb)):
                if member not in mb:
                    enum_changes.append({"type": label, "member": member, "change": "removed", "a": ma[member], "b": None})
                elif member not in ma:
                    enum_changes.append({"type": label, "member": member, "change": "added", "a": None, "b": mb[member]})
                elif ma[member] != mb[member]:
                    enum_changes.append({"type": label, "member": member, "change": "value_changed", "a": ma[member], "b": mb[member]})
            continue
        fa, fb = _fields(ra), _fields(rb)
        if ra.get("size") != rb.get("size"):
            struct_changes.append({"type": label, "change": "resized", "a": ra.get("size"), "b": rb.get("size")})
        for field in sorted(set(fa) | set(fb), key=lambda n: ((fb.get(n) or fa.get(n)).get("offset") or 0, n)):
            old, new = fa.get(field), fb.get(field)
            if new is None:
                field_changes.append({"type": label, "field": field, "change": "removed", "a": _view(old), "b": None})
            elif old is None:
                field_changes.append({"type": label, "field": field, "change": "added", "a": None, "b": _view(new)})
            else:
                kinds = [kind for kind, differs in (("moved", old.get("offset") != new.get("offset")),
                                                     ("retyped", old.get("type") != new.get("type")),
                                                     ("resized", old.get("size") != new.get("size"))) if differs]
                if kinds:
                    field_changes.append({"type": label, "field": field, "change": "+".join(kinds), "a": _view(old), "b": _view(new)})

    fa_all, fb_all = a["functions"], b["functions"]
    f_removed = sorted(set(fa_all) - set(fb_all))
    f_added = sorted(set(fb_all) - set(fa_all))
    moved = [{"name": name, "a": fa_all[name].get("address"), "b": fb_all[name].get("address")}
             for name in sorted(set(fa_all) & set(fb_all)) if fa_all[name].get("address") != fb_all[name].get("address")]
    retyped = [{"name": name, "a": fa_all[name].get("signature"), "b": fb_all[name].get("signature")}
               for name in sorted(set(fa_all) & set(fb_all)) if fa_all[name].get("signature") != fb_all[name].get("signature")]
    return {"types": {"added": added, "removed": removed, "renamed": renamed, "resized": struct_changes},
            "fields": field_changes, "enum_members": enum_changes,
            "functions": {"added": f_added, "removed": f_removed, "moved": moved, "retyped": retyped},
            "counts": {"types_added": len(added), "types_removed": len(removed), "types_renamed": len(renamed),
                       "field_changes": len(field_changes), "enum_changes": len(enum_changes), "functions_added": len(f_added),
                       "functions_removed": len(f_removed), "functions_moved": len(moved)}}


# ---- dependents ------------------------------------------------------------------------------------------------

def dependents_from_claims(rows: list[dict]) -> list[dict]:
    """Evidence claims (decoded rows of the ledger) as dependents: each cites a function by address, name and prologue."""
    return [{"id": row.get("evidence_id") or str(row.get("id")), "kind": "evidence",
             "refs": [{"function": row.get("name"), "rva": row.get("address") or None, "prologue": row.get("prologue") or None}]}
            for row in rows]


def dependents_from_address_map(entries: list[dict]) -> list[dict]:
    return [{"id": "address-map:%s" % (entry.get("name") or entry.get("hash")), "kind": "address_map",
             "refs": [{"function": entry.get("name") or None, "rva": entry.get("rva")}]} for entry in entries]


def dependents_from_profile(profile) -> list[dict]:
    """A profile's hook-table rows and layout codecs. A layout codec with `struct` rests on that struct's fields."""
    items = []
    for hook in profile.data["hooks"]:
        ref = {"function": hook.get("symbol"), "rva": ("%#x" % hook["rva"]) if "rva" in hook else None,
               "prologue": hook["prologue"][0] if hook["prologue"] else None}
        items.append({"id": "hook:%s" % hook["id"], "kind": "hook", "refs": [ref]})
    for codec in profile.data["codecs"]:
        if codec["base"] == "layout" and codec.get("struct"):
            items.append({"id": "codec:%s" % codec["id"], "kind": "codec",
                          "refs": [{"type": codec["struct"], "field": field["name"], "offset": field["offset"]} for field in codec["fields"]]})
    return items


def position_independent_reader(image):
    """A bytes reader for `invalidation_report(readers=...)` that compares code, not placement: the displacement of every
    RIP-relative operand and the target of every relative call or jump are zeroed, so the same function placed at another
    address (against data placed elsewhere too) reads the same. Anything else, including an immediate or a stack offset, is
    kept: a changed constant is a changed function. x64 images only (capstone decides what an instruction is)."""
    from hydralysis.pe import capstone

    def read(rva: int, size: int):
        try:
            raw = image.read_rva(rva, size + 16)
        except ValueError:
            try:
                raw = image.read_rva(rva, size)
            except ValueError:
                return None
        cs = capstone()
        decoder = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        decoder.detail = True
        out = bytearray(raw)
        for insn in decoder.disasm(raw, image.base + rva):
            if insn.disp_size == 4 and any(op.type == cs.x86.X86_OP_MEM and op.mem.base == cs.x86.X86_REG_RIP for op in insn.operands):
                start = insn.address - (image.base + rva) + insn.disp_offset
                out[start:start + 4] = bytes(4)
            elif insn.imm_size == 4 and insn.group(cs.CS_GRP_JUMP) or insn.imm_size == 4 and insn.group(cs.CS_GRP_CALL):
                start = insn.address - (image.base + rva) + insn.imm_offset
                out[start:start + 4] = bytes(4)
        return bytes(out[:size])
    return read


# ---- the report ------------------------------------------------------------------------------------------------

def _function_status(ref: dict, diff: dict, a: dict, b: dict, readers) -> tuple[str, str]:
    name = ref.get("function")
    if not name and ref.get("rva"):
        wanted = int(str(ref["rva"]).removeprefix("rva:"), 16)
        name = next((n for n, rec in a["functions"].items()
                     if rec.get("address") is not None and _address(rec["address"]) == wanted), None)
    if not name:
        return "unplaced", "no function name to match in build B"
    if name in diff["functions"]["removed"]:
        return "unplaced", "%s is not in build B" % name
    if name not in b["functions"]:
        return "unplaced", "%s cannot be matched in build B" % name
    moved = next((m for m in diff["functions"]["moved"] if m["name"] == name), None)
    if moved:
        length = _compare_length(ref, a["functions"].get(name))
        if not ref.get("rva") and readers is not None:      # cited by name: only the code matters, not where it sits
            old, new = readers[0](_address(moved["a"]), length), readers[1](_address(moved["b"]), length)
            if old is not None and new is not None and old == new:
                return "carried", "identical bytes (%d) at its new address %s (was %s); cited by name, not by address" % (
                    length, moved["b"], moved["a"])
        return "candidate", "%s moved from %s to %s; its bytes and callers need independent evidence" % (name, moved["a"], moved["b"])
    retyped = next((m for m in diff["functions"]["retyped"] if m["name"] == name), None)
    if retyped:
        return "candidate", "%s changed signature (%s -> %s)" % (name, retyped["a"], retyped["b"])
    address = _address(b["functions"][name].get("address"))
    if readers is None or address is None:
        return "candidate", "%s matches by name and address, but no bytes of both builds were given to compare" % name
    length = _compare_length(ref, a["functions"].get(name))
    old = readers[0](_address(a["functions"][name].get("address")), length) if name in a["functions"] else None
    new = readers[1](address, length)
    if old is not None and new is not None and old == new:
        return "carried", "identical bytes (%d) at the same address" % length
    return "candidate", "%s keeps its address but its bytes differ or could not be read" % name


def _compare_length(ref: dict, record: dict | None) -> int:
    """How many bytes of a function to compare: all of it when the corpus knows its `size` (at most 4096), else the prologue
    the reference carries, else 16."""
    if record and isinstance(record.get("size"), int) and record["size"] > 0:
        return min(record["size"], 4096)
    return max(8, len(str(ref["prologue"]).split())) if ref.get("prologue") else 16


def _address(value) -> int | None:
    if value is None:
        return None
    try:
        return int(str(value).removeprefix("rva:").removeprefix("va:"), 0)
    except ValueError:
        return None


def _type_status(ref: dict, diff: dict, b: dict) -> tuple[str, str]:
    name = ref["type"]
    renamed_to = next((r["to"] for r in diff["types"]["renamed"] if r["from"] == name), None)
    if name in diff["types"]["removed"] or (renamed_to is None and name not in b["types"]):
        return "unplaced", "type %s is not in build B" % name
    renamed = next((r for r in diff["types"]["renamed"] if r["from"] == name), None)
    label = renamed["to"] if renamed else name
    if ref.get("field"):
        change = next((c for c in diff["fields"] if c["type"] == label and c["field"] == ref["field"]), None)
        if change is None:
            return ("candidate", "type %s was renamed to %s (%s); the field is unchanged" % (name, label, renamed["basis"])) if renamed \
                else ("carried", "field %s.%s has the same offset, type and size" % (name, ref["field"]))
        if change["change"] == "removed":
            return "unplaced", "field %s.%s is not in build B" % (name, ref["field"])
        if change["change"] == "added":
            return "carried", "field present in both"
        return "moved", "field %s.%s: %s (%s -> %s)" % (name, ref["field"], change["change"], change["a"], change["b"])
    touched = [c for c in diff["fields"] if c["type"] == label] + [c for c in diff["types"]["resized"] if c["type"] == label]
    if touched:
        return "moved", "type %s changed: %d field/size change(s)" % (name, len(touched))
    return ("candidate", "type %s was renamed to %s (%s)" % (name, label, renamed["basis"])) if renamed else ("carried", "type unchanged")


def _enum_status(ref: dict, diff: dict) -> tuple[str, str]:
    name = ref["enum"]
    if name in diff["types"]["removed"]:
        return "unplaced", "enum %s is not in build B" % name
    changes = [c for c in diff["enum_members"] if c["type"] == name and (not ref.get("member") or c["member"] == ref["member"])]
    if any(c["change"] == "removed" for c in changes):
        return "unplaced", "enum member removed"
    if any(c["change"] == "value_changed" for c in changes):
        return "moved", "enum member value changed"
    return "carried", "enum unchanged"


def invalidation_report(a: dict, b: dict, dependents: list[dict], *, diff: dict | None = None, readers=None,
                        build_a: str = "", build_b: str = "") -> dict:
    """The status of every dependent for build B. READERS is (read_a, read_b), each `f(address, size) -> bytes | None`,
    used to prove a function carried; without them a function is at best a `candidate`."""
    diff = diff or diff_corpora(a, b)
    items = []
    for dependent in dependents:
        worst, reasons = "carried", []
        for ref in dependent["refs"]:
            if ref.get("type"):
                status, why = _type_status(ref, diff, b)
            elif ref.get("enum"):
                status, why = _enum_status(ref, diff)
            else:
                status, why = _function_status(ref, diff, a, b, readers)
            if PRIORITY[status] > PRIORITY[worst]:
                worst = status
            if status != "carried" or not reasons:
                reasons.append({"status": status, "why": why})
        items.append({"id": dependent["id"], "kind": dependent["kind"], "status": worst,
                      "reasons": [r for r in reasons if r["status"] == worst][:3]})
    items.sort(key=lambda item: (-PRIORITY[item["status"]], item["kind"], item["id"]))
    counts = {status: sum(1 for item in items if item["status"] == status) for status in PRIORITY}
    moved_layouts = {}
    for dependent in dependents:
        for ref in dependent["refs"]:
            if ref.get("type"):
                status, why = _type_status(ref, diff, b)
                if status == "moved":
                    moved_layouts.setdefault(why, []).append(dependent["id"])
    return {"build_a": build_a, "build_b": build_b, "counts": counts, "items": items,
            "moved_layouts": [{"change": change, "dependents": sorted(set(ids))} for change, ids in sorted(moved_layouts.items())],
            "diff": diff["counts"], "promoted": 0, "policy": POLICY}
