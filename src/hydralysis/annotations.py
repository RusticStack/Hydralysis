"""Annotation bundles: a view's cited records, exported and imported (PROTOCOL-3.md 4.9).

A bundle is one JSON file (`*.hydralysis-annot.json`) that carries records and their subject record
(`effects`), bound to a program build by its SHA-256 and to a point in time by `base` and `store`; its own
`bundle_sha256` covers the canonical JSON of everything else. It holds no game-derived bytes (a bulk import is a
hash of its input, never the input), no absolute path and no personal data.

`export_bundle` is read-only. `import_bundle` is a dry run unless `apply` is true: it checks the bundle's hash,
the program's SHA-256 (and language and compiler where both sides report them), probes every record's `before`
against the target view's program and reports what drifted; with `apply` it adds the records to a NAMED view as
pending proposals (`imported_from`), through the same engine transaction, locks, rebase and caps as an edit. It never
writes a generation. Cross-build address mapping stays in crossbuild.py.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from pathlib import Path

from hydralysis import durable, hydra, revisions, targets, workcopy
from hydralysis.analysis import MAX_OVERLAYS, _edit
from hydralysis.paths import root_path

FORMAT = "hydralysis-annotations/1"
SUFFIX = ".hydralysis-annot.json"
MAX_BUNDLE_BYTES = 64 * 1024 * 1024
# Options that name a file of the machine the record was made on: never exported.
_LOCAL_PATHS = frozenset(("input_file", "corpus_input", "corpus_file", "archive_file", "report_file"))
_STATES = ("pending", "committed", "all")


def bundle_hash(bundle: dict) -> str:
    """sha256 of the canonical JSON (sorted keys, minimal separators) of the bundle without its hash field."""
    return hashlib.sha256(durable.canonical({key: value for key, value in bundle.items() if key != "bundle_sha256"})).hexdigest()


def _scrub(options: dict) -> dict:
    """Options without the paths of the author's machine (a batch's children too)."""
    clean = {key: value for key, value in options.items() if key not in _LOCAL_PATHS}
    if isinstance(clean.get("edits"), list):
        clean["edits"] = [{**item, "options": _scrub(item["options"])} if isinstance(item.get("options"), dict) else item
                          for item in clean["edits"]]
    return clean


def _author(by) -> dict | None:
    """Who made the record: client and harness names only, and nothing that looks like a path."""
    if not isinstance(by, dict):
        return None
    return {key: by[key] for key in ("client", "harness")
            if isinstance(by.get(key), str) and "\\" not in by[key] and "/" not in by[key] and ":\\" not in by[key]}


def _va(address: str) -> int | None:
    try:
        return int(address.removeprefix("0x"), 16) if address else None
    except ValueError:
        return None


# --------------------------------------------------------------------------- export

def _archive_path(settings: dict, selected: dict, cid: str) -> Path:
    return root_path(settings) / "overlays" / "archive" / selected["key"] / (cid + ".records.json")


def archived_records(settings: dict, selected: dict, store: dict) -> list[dict]:
    """Records of earlier commits, read on demand from their archives (4.2); each archive is verified.

    A missing or mis-sealed archive, or one that does not match its entry's `ids_sha256`, refuses with
    `archive_unreadable`: an export never silently leaves records out.
    """
    found: list[dict] = []
    for entry in store.get("archived") or []:
        path = _archive_path(settings, selected, entry["cid"])
        try:
            record = durable.read_sealed(path, default=None, max_bytes=workcopy.MAX_HISTORY_BYTES + 4096)
        except durable.StoreCorrupt as error:
            raise ValueError("archive_unreadable: %s" % error) from error
        if record is None or not isinstance(record.get("records"), list):
            raise ValueError("archive_unreadable: %s is missing or holds no records" % path)
        items, previous = [], 0
        for position, item in enumerate(record["records"]):
            items.append(workcopy._clean_record(item, position, previous))
            previous = items[-1]["seq"]
        if workcopy._digest_of(sorted(item["id"] for item in items)) != entry.get("ids_sha256"):
            raise ValueError("archive_unreadable: %s does not match its ids_sha256" % path)
        found.extend(items)
    return found


def build_bundle(store: dict, selected: dict, program: dict, base: dict, *, ids=None, authors=None, since=None,
                 until=None, state: str = "all", archived: list[dict] | None = None) -> dict:
    """The bundle of the selected records of STORE. Pure: no engine, no file."""
    if state not in _STATES:
        raise ValueError("state must be pending, committed or all")
    wanted_ids = set(ids) if ids else None
    wanted_authors = set(authors) if authors else None
    committed = workcopy.committed_ids(store)
    rows = [(edit, True) for edit in archived or []] + [(edit, edit["id"] in committed) for edit in store["edits"]]
    image_base = _va(program.get("image_base") or "")
    records = []
    for edit, is_committed in sorted(rows, key=lambda row: row[0]["seq"]):
        if state != "all" and (state == "committed") != is_committed:
            continue
        if wanted_ids is not None and edit["id"] not in wanted_ids:
            continue
        if since is not None and edit["seq"] <= since or until is not None and edit["seq"] > until:
            continue
        who = _author(edit.get("by")) or {}
        if wanted_authors is not None and not wanted_authors & {who.get("client"), who.get("harness")}:
            continue
        va = _va(edit["address"])
        options = _scrub(edit["options"])
        records.append({"id": edit["id"], "address": edit["address"], "va": va,
                        "rva": va - image_base if va is not None and image_base is not None else None,
                        "kind": edit["options"].get("kind"), "options": options, "source": edit["options"].get("source"),
                        "by": who or None, "at": edit.get("at"), "effects": edit["effects"], "committed": is_committed,
                        **({"before_unknown": True} if edit.get("before_unknown") else {})})
    bundle = {"format": FORMAT, "program": program, "base": base,
              "store": {"view": selected.get("view", "shared"), "revision": store["revision"],
                        "ids_sha256": workcopy._digest_of([edit["id"] for edit in store["edits"]])},
              "records": records}
    return {**bundle, "bundle_sha256": bundle_hash(bundle)}


def program_info(engine: hydra.Engine, opened: dict, selected: dict) -> tuple[dict, dict]:
    """(the program block of a bundle, the engine's raw `info`), as far as the engine reports it (None where it does not)."""
    try:
        info = engine.call("info", program=opened["key"])
    except hydra.EngineError:
        info = {}
    return {"sha256": selected["sha256"], "language": info.get("language"), "compiler": info.get("compiler"),
            "image_base": opened.get("image_base") or info.get("imageBase"), "name": selected["program"]}, info


def export_bundle(settings: dict, target: str, *, view: str = "", ids=None, authors=None, since=None, until=None,
                  state: str = "all", path: str | Path | None = None, engine: hydra.Engine | None = None) -> dict:
    """Read-only: the selected records of a view as a bundle (written to PATH when given, else returned)."""
    from hydralysis import query
    selected = workcopy.with_view(targets.resolve(settings, target), view)
    engine = engine or hydra.Engine(settings)
    opened = query.open_program(engine, selected["gpr"], selected["program"], selected["sha256"])
    program, info = program_info(engine, opened, selected)
    store = workcopy.load_store(settings, selected)
    base_block = store.get("base") or workcopy.DEFAULT_BASE
    base = {"lineage": base_block.get("lineage", ""), "generation": base_block.get("generation", 0),
            "master_revision": opened.get("project_revision"), "engine": workcopy.engine_release(engine),
            "dbVersions": info.get("dbVersions")}
    bundle = build_bundle(store, selected, program, base, ids=ids, authors=authors, since=since, until=until, state=state,
                          archived=archived_records(settings, selected, store) if state != "pending" else None)
    result = {"ok": True, "records": len(bundle["records"]), "bundle_sha256": bundle["bundle_sha256"],
              "view": selected["view"], "view_revision": store["revision"],
              "committed": sum(1 for record in bundle["records"] if record["committed"])}
    if path is None:
        return {**result, "bundle": bundle}
    destination = Path(path)
    if not destination.name.endswith(SUFFIX):
        destination = destination.with_name(destination.name + SUFFIX)
    destination.parent.mkdir(parents=True, exist_ok=True)
    durable.atomic_write(destination, json.dumps(bundle, indent=2, ensure_ascii=False).encode("utf-8"))
    return {**result, "path": str(destination)}


# --------------------------------------------------------------------------- import

def load_bundle(source) -> dict:
    """A bundle from a path (bounded read) or an already parsed dict."""
    if isinstance(source, dict):
        return source
    path = Path(source)
    if path.stat().st_size > MAX_BUNDLE_BYTES:
        raise ValueError("bundle exceeds %d MiB" % (MAX_BUNDLE_BYTES >> 20))
    value = json.loads(path.read_bytes().decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("a bundle is a JSON object")
    return value


def _first_effects(records: list[dict]) -> list[tuple[str, str, str, dict]]:
    """(subject, field, before, record) of the first effect of each (subject, field) across the records, in order.

    Later effects on the same pair rest on the earlier ones (their `before` is the earlier `after`): only the first is
    comparable with the target as it is now.
    """
    seen, found = set(), []
    for record in records:
        for effect in record.get("effects") or []:
            pair = (effect["subject"], effect["field"])
            if pair in seen:
                continue
            seen.add(pair)
            if effect["before"] is not None:
                found.append((*pair, effect["before"], record))
    return found


def _chain_breaks(records: list[dict]) -> list[dict]:
    """Inside the bundle, a later effect whose `before` is not the earlier effect's `after` (a record is missing)."""
    last, breaks = {}, []
    for record in records:
        for effect in record.get("effects") or []:
            pair = (effect["subject"], effect["field"])
            if pair in last and effect["before"] is not None and effect["before"] != last[pair]:
                breaks.append({"id": record["id"], "subject": pair[0], "field": pair[1], "before": effect["before"],
                               "previous_after": last[pair]})
            last[pair] = effect["after"]
    return breaks


def import_bundle(settings: dict, target: str, bundle, *, view: str = "", apply: bool = False,
                  expect_revision: int | None = None, allow_unverified_before: bool = False,
                  engine: hydra.Engine | None = None, timeout_s: int = 300) -> dict:
    """Dry-run (default) or apply a bundle to VIEW of TARGET. See the module text."""
    from hydralysis import query
    selected = workcopy.with_view(targets.resolve(settings, target), view)
    if apply and selected["view"] == "shared":
        raise ValueError("import_bundle applies to a named view: pass view (records arrive as proposals, never in shared)")
    bundle = load_bundle(bundle)
    problems: list[str] = []
    if bundle.get("format") != FORMAT:
        problems.append("format: %r is not %s" % (bundle.get("format"), FORMAT))
    hash_ok = bundle.get("bundle_sha256") == bundle_hash(bundle)
    if not hash_ok:
        problems.append("bundle_sha256 does not match the bundle's content")
    program = bundle.get("program") if isinstance(bundle.get("program"), dict) else {}
    sha_ok = str(program.get("sha256", "")).lower() == selected["sha256"]
    if not sha_ok:
        problems.append("program sha256 %s is not the target build %s" % (program.get("sha256"), selected["sha256"]))
    raw = bundle.get("records")
    if not isinstance(raw, list) or len(raw) > MAX_OVERLAYS:
        raise ValueError("a bundle holds at most %d records" % MAX_OVERLAYS)
    engine = engine or hydra.Engine(settings)
    opened = query.open_program(engine, selected["gpr"], selected["program"], selected["sha256"])
    mine, mine_info = program_info(engine, opened, selected)
    mismatched = {name: {"bundle": program.get(name), "target": mine[name]} for name in ("language", "compiler")
                  if program.get(name) and mine[name] and program.get(name) != mine[name]}
    for name, pair in mismatched.items():
        problems.append("%s differs: bundle %s, target %s" % (name, pair["bundle"], pair["target"]))

    store = workcopy.load_store(settings, selected)
    known = {edit["id"] for edit in store["edits"]}
    imported = {((edit.get("imported_from") or {}).get("bundle_sha256"), (edit.get("imported_from") or {}).get("id"))
                for edit in store["edits"]}
    records, invalid, present, missing = [], [], [], []
    for item in raw:
        ident = item.get("id") if isinstance(item, dict) else None
        try:
            if not isinstance(item, dict) or "options" not in item:
                raise ValueError("a record needs id, address and options")
            clean = _edit({"id": ident, "address": item.get("address", ""), "options": item["options"]})
            effects = revisions.clean_effects(item.get("effects"))
        except (ValueError, TypeError) as error:
            invalid.append({"id": ident, "error": str(error)})
            continue
        if ident in known or (bundle.get("bundle_sha256"), ident) in imported:
            present.append(ident)
            continue
        kind = clean["options"]["kind"]
        if kind == "import_types" and not workcopy.corpus_path(settings, clean["options"]["corpus_sha256"]).is_file():
            missing.append({"id": ident, "needs": "corpus sha256 " + clean["options"]["corpus_sha256"]})
        if kind == "import_archive" and not workcopy.archive_path(settings, clean["options"]["archive_sha256"]).is_file():
            missing.append({"id": ident, "needs": "type archive sha256 " + clean["options"]["archive_sha256"]})
        records.append({**clean, "effects": effects, "before_unknown": effects is None or bool(item.get("before_unknown"))})
    if invalid:
        problems.append("%d record(s) are not valid overlay records" % len(invalid))
    if missing:
        problems.append("%d bulk record(s) need an input this root does not hold" % len(missing))

    drift, breaks = [], []
    if hash_ok and sha_ok and records:
        breaks = _chain_breaks(records)
        wanted = _first_effects(records)
        if wanted:
            program_now = query.QueryRunner(settings, engine).program_for(selected)
            values = workcopy.probe(engine, program_now, [(subject, field) for subject, field, _, _ in wanted], timeout_s)
            for subject, field, before, record in wanted:
                found = values.get((subject, field))
                if found is not None and found != before:
                    drift.append({"id": record["id"], "subject": subject, "field": field, "expected": before, "found": found})
    unverified = [record["id"] for record in records if record["effects"] is None]
    result = {"ok": not problems, "dry_run": not apply, "view": selected["view"], "view_revision": store["revision"],
              "bundle": {"sha256": bundle.get("bundle_sha256"), "hash_ok": hash_ok, "records": len(raw),
                         "program_sha256_ok": sha_ok, "mismatched": mismatched},
              "base": {"bundle": bundle.get("base"), "target": {"master_revision": opened.get("project_revision"),
                                                                "engine": workcopy.engine_release(engine)},
                       "same_master": isinstance(bundle.get("base"), dict)
                       and bundle["base"].get("master_revision") == opened.get("project_revision")},
              "would_add": [record["id"] for record in records], "already_present": present, "unverified": unverified,
              "base_drift": drift, "chain_breaks": breaks, "missing_inputs": missing, "invalid": invalid,
              "problems": problems}
    if not apply:
        return result
    if problems:
        raise ValueError("bundle refused, nothing added: " + "; ".join(problems))
    if unverified and not allow_unverified_before:
        raise ValueError("%d record(s) carry no effects (before unknown); pass allow_unverified_before to add them anyway"
                         % len(unverified))
    if not records:
        return {**result, "applied": False, "added": []}
    by_id = {item["id"]: item for item in raw if isinstance(item, dict)}
    proposals = [{"id": uuid.uuid4().hex, "source_id": record["id"], "address": record["address"], "options": record["options"],
                  "source_by": _author(by_id[record["id"]].get("by")), "source_at": by_id[record["id"]].get("at")}
                 for record in records]
    added = workcopy.add_proposals(settings, engine, selected, proposals, expect_revision, timeout_s,
                                   {"bundle_sha256": bundle["bundle_sha256"], "view": (bundle.get("store") or {}).get("view")})
    return {**result, "dry_run": False, "applied": True, **{key: added[key] for key in ("added", "revision", "view_revision",
                                                                                          "rebased")}}
