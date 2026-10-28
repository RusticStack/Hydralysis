"""A claim is a row: target, build, address, prologue, and the line that proves it (evidence v2).

A row without a note and a source is refused. The Ghidra project is a cache;
this ledger is the record that survives a project refresh, and the backbone an
engine map can be generated from: claims carry a subsystem, the client and
harness that made them, and a newer claim can supersede an older one (a 2.5
re-derivation replacing a 2.31 fact) without deleting it.

Evidence v2 (PROTOCOL-3.md Z9, audit C1-25, C1-42, C2-25 to C2-28) adds, in place and additively:

* a content-addressed `evidence_id` = `ev_` + SHA-256 of the canonical JSON of the claim's semantic content (the
  fields below, never the local integer id, the time, the writer, the provenance or the supersession back link).
  Two sessions that state the same claim get the same id; a row whose stored id no longer matches its content is
  refused on read (`EvidenceIntegrityError`).
* a coverage object (`complete` | `partial` | `unknown`) and a closed catalog of limitation codes stored with the
  row. A claim that does not say how much it covers is `unknown`; nothing that a bound cut short may say `complete`.
* `confidence`, `authority`, `parameters` (for example the generated probe's `script_sha256`), `subject_sha256`,
  `from_capture` and `evidence_links` (the id of the claim it supersedes).
* `provenance` (view, sequence, generation): stored and exported, but not part of the identity.

Legacy rows are backfilled on the first open by any writer, under one lock; a legacy row gets the same defaults a
new row without coverage gets, so its id equals the id of the same claim stated again today.

Several harnesses write at once: the database runs in WAL mode with a busy
timeout, so a writer waits for another instead of failing.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

MODEL = "hydralysis.evidence/2"
SCHEMA = """
CREATE TABLE IF NOT EXISTS claims (
    id INTEGER PRIMARY KEY,
    game TEXT NOT NULL,
    build TEXT NOT NULL,
    kind TEXT NOT NULL,
    name TEXT NOT NULL,
    address TEXT NOT NULL DEFAULT '',
    prologue TEXT NOT NULL DEFAULT '',
    note TEXT NOT NULL,
    source TEXT NOT NULL,
    created TEXT NOT NULL
);
"""
# Columns added after the first release; existing ledgers are upgraded in place.
COLUMNS = {"subsystem": "TEXT NOT NULL DEFAULT ''", "client": "TEXT NOT NULL DEFAULT ''",
           "harness": "TEXT NOT NULL DEFAULT ''", "supersedes": "INTEGER", "superseded_by": "INTEGER",
           # evidence v2
           "evidence_id": "TEXT", "coverage": "TEXT NOT NULL DEFAULT ''", "limitations": "TEXT NOT NULL DEFAULT ''",
           "parameters": "TEXT NOT NULL DEFAULT ''", "confidence": "TEXT NOT NULL DEFAULT ''",
           "authority": "TEXT NOT NULL DEFAULT ''", "subject_sha256": "TEXT NOT NULL DEFAULT ''",
           "from_capture": "TEXT NOT NULL DEFAULT ''", "evidence_links": "TEXT NOT NULL DEFAULT ''",
           "provenance": "TEXT NOT NULL DEFAULT ''"}
LEGACY_FIELDS = ("id", "game", "build", "kind", "name", "address", "prologue", "note", "source", "created",
                 "subsystem", "client", "harness", "supersedes", "superseded_by")
FIELDS = LEGACY_FIELDS + ("evidence_id", "coverage", "limitations", "parameters", "confidence", "authority",
                          "subject_sha256", "from_capture", "evidence_links", "provenance")
BUSY_TIMEOUT_MS = 15000

CONFIDENCES = ("observed", "derived", "inferred")
AUTHORITIES = ("shipped-artifact", "controlled-replay", "historical-reference", "external-service",
               "analyst-inference")
# A claim written by a person or an agent with a cited source is an inference until a replay says otherwise.
DEFAULT_CONFIDENCE = "inferred"
DEFAULT_AUTHORITY = "analyst-inference"
COVERAGE_STATES = ("complete", "partial", "unknown")
NOT_REPORTED = "coverage_not_reported"

# The closed catalog of limitation codes: (does it bound what the claim covers, what it means). A code that bounds
# coverage can never sit beside `complete`. A caller with a code of its own writes it as `<namespace>:<code>`.
LIMITATIONS = {
    "coverage_unknown": (True, "The writer did not say how much of the subject this claim covers."),
    "event_ring_overflow": (True, "The event ring keeps at most 1,000 events and 256 KiB; evicted events cannot be "
                                  "recovered (dropped_events counts them)."),
    "hit_limit_reached": (True, "A probe stops recording at its hit limit (1 to 200); later hits are not recorded."),
    "payload_clipped": (True, "An oversized payload was clipped; only a prefix was captured."),
    "sampled": (True, "The probe reported a rate, minimum and maximum per window, not every call."),
    "indirect_calls_unresolved": (True, "Calls through a register or a table were not resolved; the callers and "
                                        "callees listed are those direct references."),
    "analysis_incomplete": (True, "Analysis of the subject had not finished when this was read."),
    "static_only": (False, "Static analysis only: no process ran, so runtime behavior is not covered."),
    "module_file_hash_only": (False, "The check covers the module's backing file SHA-256 and the live bytes of the "
                                     "selected site, not the complete relocated image."),
    "calling_convention_unproven": (False, "A verified site does not prove a calling convention or that the "
                                           "function is semantically the intended one."),
    "single_run": (False, "One run of one scenario; other inputs or timing may behave differently."),
    "fixture_only": (False, "Observed on a synthetic fixture, not on the game."),
    "volatile_state": (False, "The value depends on process state that changes from run to run."),
}
_CODE = re.compile(r"^(?:[a-z][a-z0-9_.-]{0,31}:)?[a-z][a-z0-9_]{0,63}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_EVIDENCE_ID = re.compile(r"^ev_[0-9a-f]{64}$")
_CAPTURE_ID = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,79}$")
_SAFE_INT = 2 ** 53 - 1

# The REA reference (f196ebf, src/domain/evidence.ts) record fields and where each lives here. A field with no
# column is a documented gap, not a silent omission: tests/test_evidence_parity.py reads the reference and fails on
# a field that is in neither table.
REA_FIELD_MAP = {
    "evidence_id": "evidence_id",
    "subject": "subject_sha256",
    "provider": "client,harness",
    "analysis_profile": "build",
    "predicate_type": "kind",
    "parameters": "parameters",
    "normalized_result": "name,address,prologue,note",
    "confidence": "confidence",
    "authority": "authority",
    "limitations": "limitations",
    "relationship_coverage": "coverage",
    "locations": "address",
    "evidence_links": "evidence_links",
}
REA_FIELD_GAPS = {
    "operation": "not modeled: `source` names how the claim was obtained and `kind` what it is",
    "raw_result": "deliberately absent: a claim carries no payload bytes; a bounded capture travels in captures/",
    "environment": "not part of the identity: a bundle records the exporting environment in environment.json",
    "caller_input_path": "not applicable: a claim has no caller path",
}


class EvidenceIntegrityError(ValueError):
    """A stored row or a bundle record whose content no longer matches its evidence_id."""

    def __init__(self, message: str, *, code: str = "evidence_mismatch", evidence_id: str = "", row_id: int | None = None):
        super().__init__(message)
        self.code = code
        self.evidence_id = evidence_id
        self.row_id = row_id


# ---- canonical form and identity ------------------------------------------------------------------------------

def _utf16_key(text: str) -> bytes:
    return text.encode("utf-16-be", "surrogatepass")


def _emit(value, out: list) -> None:
    if value is None:
        out.append("null")
    elif value is True:
        out.append("true")
    elif value is False:
        out.append("false")
    elif isinstance(value, int):
        if abs(value) > _SAFE_INT:
            raise ValueError("an integer beyond 2**53-1 cannot be committed to an evidence id; write it as a string")
        out.append(str(value))
    elif isinstance(value, float):
        raise ValueError("a float cannot be committed to an evidence id (its text differs between implementations); "
                         "write it as an integer or a string")
    elif isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise ValueError("canonical form refuses an unpaired surrogate: %s" % exc) from exc
        out.append(json.dumps(value, ensure_ascii=False))
    elif isinstance(value, (list, tuple)):
        out.append("[")
        for index, item in enumerate(value):
            if index:
                out.append(",")
            _emit(item, out)
        out.append("]")
    elif isinstance(value, dict):
        out.append("{")
        for index, key in enumerate(sorted(value, key=lambda item: _utf16_key(item) if isinstance(item, str) else b"")):
            if not isinstance(key, str):
                raise ValueError("a canonical object has string keys only")
            if index:
                out.append(",")
            out.append(json.dumps(key, ensure_ascii=False) + ":")
            _emit(value[key], out)
        out.append("}")
    else:
        raise ValueError("a %s cannot be committed to an evidence id" % type(value).__name__)


def canonical_json(value) -> str:
    """RFC 8785 style canonical JSON: keys in UTF-16 order, no spaces; floats and unsafe integers are refused."""
    out: list[str] = []
    _emit(value, out)
    return "".join(out)


def canonical_digest(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def compute_evidence_id(content: dict) -> str:
    return "ev_" + canonical_digest(content)


def is_evidence_id(value) -> bool:
    return isinstance(value, str) and bool(_EVIDENCE_ID.match(value))


# ---- coverage and limitations ---------------------------------------------------------------------------------

def check_limitation_code(code) -> str:
    if not isinstance(code, str) or not _CODE.match(code):
        raise ValueError("limitation code %r is not a lowercase identifier (optionally `namespace:code`)" % (code,))
    if ":" not in code and code not in LIMITATIONS:
        raise ValueError("unknown limitation code %r; use one of %s, or write your own as `namespace:code`"
                         % (code, ", ".join(sorted(LIMITATIONS))))
    return code


def bounds_coverage(code: str) -> bool:
    """True when the code says the claim covers less than the whole subject (a namespaced code is assumed to)."""
    entry = LIMITATIONS.get(code)
    return True if entry is None else entry[0]


def normalize_coverage(value=None) -> dict:
    """The Coverage object: complete, partial (with limitation codes) or unknown (with a reason)."""
    if value is None:
        return {"status": "unknown", "reason": NOT_REPORTED}
    if isinstance(value, str):
        value = {"status": value}
    if not isinstance(value, dict):
        raise ValueError("coverage must be an object with a status")
    status = value.get("status")
    if status not in COVERAGE_STATES:
        raise ValueError("coverage.status must be one of %s" % ", ".join(COVERAGE_STATES))
    extra = set(value) - {"status", "limitations", "reason", "diagnostics"}
    if extra:
        raise ValueError("coverage has no field %s" % ", ".join(sorted(extra)))
    result: dict = {"status": status}
    if status == "partial":
        codes = value.get("limitations")
        if not isinstance(codes, (list, tuple)) or not codes:
            raise ValueError("partial coverage lists at least one limitation code")
        result["limitations"] = sorted({check_limitation_code(code) for code in codes})
    elif status == "unknown":
        reason = value.get("reason") or NOT_REPORTED
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("unknown coverage needs a reason")
        result["reason"] = reason
    else:
        if value.get("limitations") or value.get("reason"):
            raise ValueError("complete coverage carries no limitations or reason")
    diagnostics = value.get("diagnostics")
    if diagnostics:
        if not isinstance(diagnostics, (list, tuple)) or not all(isinstance(item, str) and item for item in diagnostics):
            raise ValueError("coverage.diagnostics is a list of non-empty strings")
        result["diagnostics"] = list(diagnostics)
    return result


def derived_limitations(coverage: dict) -> list[str]:
    if coverage["status"] == "partial":
        return list(coverage["limitations"])
    if coverage["status"] == "unknown":
        return ["coverage_unknown"]
    return []


def merge_limitations(coverage: dict, limitations=()) -> list[str]:
    """The sorted, unique codes of a row: those it states plus those its coverage implies. Complete means complete."""
    if isinstance(limitations, str):
        limitations = [limitations]
    codes = {check_limitation_code(code) for code in limitations} | set(derived_limitations(coverage))
    if coverage["status"] == "complete":
        bounding = sorted(code for code in codes if bounds_coverage(code))
        if bounding:
            raise ValueError("coverage is complete but the claim states %s, which bounds what it covers; "
                             "say partial" % ", ".join(bounding))
    return sorted(codes)


# ---- the content that an evidence id commits ------------------------------------------------------------------

def build_content(*, game: str, build: str, kind: str, name: str, note: str, source: str, address: str = "",
                  prologue: str = "", subsystem: str = "", parameters: dict | None = None,
                  confidence: str = DEFAULT_CONFIDENCE, authority: str = DEFAULT_AUTHORITY, coverage=None,
                  limitations=(), subject_sha256: str = "", from_capture: str = "", evidence_links=()) -> dict:
    """The validated semantic content of one claim; `compute_evidence_id` hashes exactly this."""
    for field, value in (("game", game), ("build", build), ("kind", kind), ("name", name), ("note", note),
                         ("source", source)):
        if not str(value).strip():
            raise ValueError("%s is required; a claim without evidence is not stored" % field)
    if confidence not in CONFIDENCES:
        raise ValueError("confidence must be one of %s" % ", ".join(CONFIDENCES))
    if authority not in AUTHORITIES:
        raise ValueError("authority must be one of %s" % ", ".join(AUTHORITIES))
    if parameters is None:
        parameters = {}
    if not isinstance(parameters, dict):
        raise ValueError("parameters must be a JSON object")
    if subject_sha256 and not _HEX64.match(str(subject_sha256)):
        raise ValueError("subject_sha256 must be 64 lowercase hex digits")
    if from_capture and not _CAPTURE_ID.match(str(from_capture)):
        raise ValueError("from_capture must be a capture id (letters, digits, `_`, `.`, `-`, at most 80)")
    links = sorted({str(link) for link in evidence_links})
    for link in links:
        if not is_evidence_id(link):
            raise ValueError("evidence_links holds ev_ ids; %r is not one" % link)
    status = normalize_coverage(coverage)
    content = {
        "model": MODEL,
        "subject": {"sha256": subject_sha256} if subject_sha256 else None,
        "game": str(game), "build": str(build), "kind": str(kind), "name": str(name), "address": str(address),
        "prologue": str(prologue), "subsystem": str(subsystem), "note": str(note), "source": str(source),
        "parameters": parameters, "confidence": confidence, "authority": authority,
        "coverage": status, "limitations": merge_limitations(status, limitations),
        "from_capture": str(from_capture) if from_capture else None,
        "evidence_links": links,
    }
    canonical_json(content)  # refuses a float, an unsafe integer or an unpaired surrogate before anything is stored
    return content


CONTENT_KEYS = tuple(build_content(game="g", build="b", kind="k", name="n", note="n", source="s"))


def _loads(text: str, default):
    return json.loads(text) if text else default


def content_of_row(row) -> dict:
    """The semantic content of a stored row, decoded without re-validating it (so a damaged row stays visible)."""
    return {
        "model": MODEL,
        "subject": {"sha256": row["subject_sha256"]} if row["subject_sha256"] else None,
        "game": row["game"], "build": row["build"], "kind": row["kind"], "name": row["name"],
        "address": row["address"], "prologue": row["prologue"], "subsystem": row["subsystem"],
        "note": row["note"], "source": row["source"],
        "parameters": _loads(row["parameters"], {}),
        "confidence": row["confidence"] or DEFAULT_CONFIDENCE, "authority": row["authority"] or DEFAULT_AUTHORITY,
        "coverage": _loads(row["coverage"], None) or normalize_coverage(None),
        "limitations": _loads(row["limitations"], None) if row["limitations"] else ["coverage_unknown"],
        "from_capture": row["from_capture"] or None,
        "evidence_links": _loads(row["evidence_links"], []),
    }


def verify_content(content: dict, evidence_id: str) -> None:
    if not is_evidence_id(evidence_id):
        raise EvidenceIntegrityError("%r is not an evidence id" % (evidence_id,), code="evidence_id_malformed",
                                     evidence_id=str(evidence_id))
    try:
        actual = compute_evidence_id(content)
    except ValueError as exc:
        raise EvidenceIntegrityError("evidence %s has content that cannot be committed: %s" % (evidence_id, exc),
                                     evidence_id=evidence_id) from exc
    if actual != evidence_id:
        raise EvidenceIntegrityError("evidence %s does not match its content (the content hashes to %s)"
                                     % (evidence_id, actual), evidence_id=evidence_id)


_STRING_FIELDS = ("game", "build", "kind", "name", "address", "prologue", "subsystem", "note", "source", "confidence",
                  "authority")


def check_content(content, evidence_id: str) -> None:
    """Strictly validate content that arrives from outside (a bundle): the claim rules, exact types, then the id.

    The content is rebuilt with `build_content` from its own fields; the rebuilt content must equal the stated one
    and hash to `evidence_id`. A hash-consistent record that breaks a rule (complete coverage beside a bounding
    limitation, an unknown enum, an integer where a string belongs) is refused.
    """
    def bad(message: str):
        return EvidenceIntegrityError("evidence %s has content the evidence model refuses: %s" % (evidence_id, message),
                                      code="evidence_content_invalid", evidence_id=str(evidence_id))

    if not isinstance(content, dict) or set(content) != set(CONTENT_KEYS):
        raise bad("its fields are not those of the evidence model")
    if content["model"] != MODEL:
        raise bad("model is %r, not %r" % (content["model"], MODEL))
    for field in _STRING_FIELDS:
        if not isinstance(content[field], str):
            raise bad("%s must be a string, not a %s" % (field, type(content[field]).__name__))
    subject = content["subject"]
    if subject is not None and not (isinstance(subject, dict) and set(subject) == {"sha256"}
                                    and isinstance(subject["sha256"], str)):
        raise bad("subject must be null or {sha256}")
    if content["from_capture"] is not None and not isinstance(content["from_capture"], str):
        raise bad("from_capture must be a string or null")
    if not isinstance(content["parameters"], dict):
        raise bad("parameters must be an object")
    if not isinstance(content["coverage"], dict):
        raise bad("coverage must be an object")
    for field in ("limitations", "evidence_links"):
        value = content[field]
        if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
            raise bad("%s must be a list of strings" % field)
    try:
        rebuilt = build_content(
            **{field: content[field] for field in _STRING_FIELDS if field not in ("confidence", "authority")},
            parameters=content["parameters"], confidence=content["confidence"], authority=content["authority"],
            coverage=content["coverage"], limitations=content["limitations"],
            subject_sha256=(subject or {}).get("sha256", ""), from_capture=content["from_capture"] or "",
            evidence_links=content["evidence_links"])
        same = canonical_json(rebuilt) == canonical_json(content)
    except ValueError as exc:
        raise bad(str(exc)) from exc
    if not same:
        raise bad("it is not in the normal form the model writes (sorted unique codes and links, no empty "
                  "subject or from_capture)")
    verify_content(content, evidence_id)


def check_meta(meta) -> dict:
    """A record's volatile meta, validated: an object whose provenance, when present, is an object."""
    if meta is None:
        return {}
    if not isinstance(meta, dict):
        raise EvidenceIntegrityError("meta must be an object", code="bundle_meta_invalid")
    for field in ("created", "client", "harness"):
        if field in meta and not isinstance(meta[field], str):
            raise EvidenceIntegrityError("meta.%s must be a string" % field, code="bundle_meta_invalid")
    try:
        _provenance(meta.get("provenance"))
    except ValueError as exc:
        raise EvidenceIntegrityError("meta.provenance: %s" % exc, code="bundle_meta_invalid") from exc
    return meta


# ---- the database ---------------------------------------------------------------------------------------------

def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path, timeout=BUSY_TIMEOUT_MS / 1000)
    db.row_factory = sqlite3.Row
    db.execute("PRAGMA busy_timeout = %d" % BUSY_TIMEOUT_MS)
    db.execute("PRAGMA journal_mode = WAL")
    db.executescript(SCHEMA)
    present = {row["name"] for row in db.execute("PRAGMA table_info(claims)")}
    if set(COLUMNS) - present:
        # Writers that open an old ledger at once upgrade it one at a time.
        db.execute("BEGIN IMMEDIATE")
        present = {row["name"] for row in db.execute("PRAGMA table_info(claims)")}
        for column, declaration in COLUMNS.items():
            if column not in present:
                db.execute("ALTER TABLE claims ADD COLUMN %s %s" % (column, declaration))
        db.execute("COMMIT")
    db.execute("CREATE INDEX IF NOT EXISTS claims_lookup ON claims (game, subsystem, build, address)")
    db.execute("CREATE INDEX IF NOT EXISTS claims_evidence_id ON claims (evidence_id)")
    db.commit()
    _backfill(db)
    return db


def _backfill(db: sqlite3.Connection) -> None:
    """Give every row without an id its v2 fields and its id. Cheap when there is nothing to do."""
    if db.execute("SELECT 1 FROM claims WHERE evidence_id IS NULL OR evidence_id = '' LIMIT 1").fetchone() is None:
        return
    db.execute("BEGIN IMMEDIATE")
    try:
        # Another writer may have finished while this one waited for the lock.
        rows = db.execute("SELECT * FROM claims WHERE evidence_id IS NULL OR evidence_id = '' ORDER BY id").fetchall()
        for row in rows:
            coverage = _loads(row["coverage"], None) or normalize_coverage(None)
            limitations = _loads(row["limitations"], None) or merge_limitations(coverage)
            links = _loads(row["evidence_links"], None)
            if links is None:
                links = []
                if row["supersedes"] is not None:
                    old = db.execute("SELECT evidence_id FROM claims WHERE id = ?", (row["supersedes"],)).fetchone()
                    if old is not None and old["evidence_id"]:
                        links = [old["evidence_id"]]
            fields = {"coverage": json.dumps(coverage, sort_keys=True), "limitations": json.dumps(limitations),
                      "parameters": row["parameters"] or "{}", "confidence": row["confidence"] or DEFAULT_CONFIDENCE,
                      "authority": row["authority"] or DEFAULT_AUTHORITY, "evidence_links": json.dumps(links),
                      "provenance": row["provenance"] or "{}"}
            filled = {key: row[key] for key in row.keys()} | fields
            content = content_of_row(filled)
            db.execute("UPDATE claims SET coverage=?, limitations=?, parameters=?, confidence=?, authority=?, "
                       "evidence_links=?, provenance=?, evidence_id=? WHERE id=?",
                       (*(fields[key] for key in ("coverage", "limitations", "parameters", "confidence", "authority",
                                                  "evidence_links", "provenance")),
                        compute_evidence_id(content), row["id"]))
        db.execute("COMMIT")
    except BaseException:
        db.execute("ROLLBACK")
        raise


def _who() -> tuple[str, str]:
    from hydralysis.hydra import identity
    who = identity()
    return who["client"], who["harness"]


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _provenance(value) -> dict:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError("provenance is an object such as {view, sequence, generation}")
    canonical_json(value)
    return value


def _insert(db: sqlite3.Connection, content: dict, evidence_id: str, *, created: str, client: str, harness: str,
            provenance: dict, supersedes: int | None) -> int:
    cursor = db.execute(
        """
        INSERT INTO claims (game, build, kind, name, address, prologue, note, source, created, subsystem, client,
                            harness, supersedes, evidence_id, coverage, limitations, parameters, confidence,
                            authority, subject_sha256, from_capture, evidence_links, provenance)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (content["game"], content["build"], content["kind"], content["name"], content["address"],
         content["prologue"], content["note"], content["source"], created, content["subsystem"], client, harness,
         supersedes, evidence_id, json.dumps(content["coverage"], sort_keys=True), json.dumps(content["limitations"]),
         json.dumps(content["parameters"], sort_keys=True), content["confidence"], content["authority"],
         (content["subject"] or {}).get("sha256", ""), content["from_capture"] or "",
         json.dumps(content["evidence_links"]), json.dumps(provenance, sort_keys=True)))
    return cursor.lastrowid


def add_claim(
    path: Path,
    *,
    game: str,
    build: str,
    kind: str,
    name: str,
    note: str,
    source: str,
    address: str = "",
    prologue: str = "",
    subsystem: str = "",
    supersedes: int | None = None,
    coverage=None,
    limitations=(),
    parameters: dict | None = None,
    confidence: str = DEFAULT_CONFIDENCE,
    authority: str = DEFAULT_AUTHORITY,
    subject_sha256: str = "",
    from_capture: str = "",
    provenance: dict | None = None,
) -> str:
    fields = dict(game=game, build=build, kind=kind, name=name, note=note, source=source, address=address,
                  prologue=prologue, subsystem=subsystem, parameters=parameters, confidence=confidence,
                  authority=authority, coverage=coverage, limitations=limitations, subject_sha256=subject_sha256,
                  from_capture=from_capture)
    build_content(**fields)  # refuse a bad claim before a database is opened
    provenance = _provenance(provenance)
    client, harness = _who()
    db = connect(path)
    try:
        db.execute("BEGIN IMMEDIATE")  # one transaction: the check, the new claim and the old one's link land together
        try:
            links: list[str] = []
            if supersedes is not None:
                old = db.execute("SELECT id, superseded_by, evidence_id FROM claims WHERE id = ?",
                                 (int(supersedes),)).fetchone()
                if old is None:
                    raise ValueError("no claim %s to supersede" % supersedes)
                links = [old["evidence_id"]]
            content = build_content(**fields, evidence_links=links)
            evidence_id = compute_evidence_id(content)
            same = db.execute("SELECT id FROM claims WHERE evidence_id = ? ORDER BY id LIMIT 1", (evidence_id,)).fetchone()
            if same is not None:  # restating a stored claim is a no-op even when its predecessor is already superseded
                db.execute("COMMIT")
                return "claim %s already stored %s %s %s evidence_id=%s" % (same["id"], game, kind, name, evidence_id)
            if supersedes is not None and old["superseded_by"] is not None:
                raise ValueError("claim %s is already superseded by claim %s" % (supersedes, old["superseded_by"]))
            row_id = _insert(db, content, evidence_id, created=_now(), client=client, harness=harness,
                             provenance=provenance, supersedes=int(supersedes) if supersedes is not None else None)
            if supersedes is not None:
                db.execute("UPDATE claims SET superseded_by = ? WHERE id = ?", (row_id, int(supersedes)))
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    finally:
        db.close()
    return "claim %s stored %s %s %s%s evidence_id=%s" % (row_id, game, kind, name,
                                                         " (supersedes %s)" % supersedes if supersedes else "", evidence_id)


def decode_row(row) -> dict:
    """A stored row as a dictionary with the JSON columns decoded."""
    result = {key: row[key] for key in FIELDS}
    for key, default in (("coverage", None), ("limitations", None), ("parameters", {}), ("evidence_links", []),
                         ("provenance", {})):
        try:
            result[key] = _loads(result[key], default)
        except ValueError:
            result[key] = {"unreadable": result[key]}
    result["from_capture"] = result["from_capture"] or None
    result["subject_sha256"] = result["subject_sha256"] or None
    return result


def verify_row(row) -> None:
    """Recompute the id of a stored row and refuse it when it does not match."""
    try:
        content = content_of_row(row)
    except (ValueError, TypeError, KeyError) as exc:
        raise EvidenceIntegrityError("claim %s has a damaged evidence field (%s)" % (row["id"], exc),
                                     code="evidence_unreadable", evidence_id=row["evidence_id"] or "",
                                     row_id=row["id"]) from exc
    try:
        verify_content(content, row["evidence_id"] or "")
    except EvidenceIntegrityError as exc:
        exc.row_id = row["id"]
        raise EvidenceIntegrityError("claim %s: %s" % (row["id"], exc), code=exc.code, evidence_id=exc.evidence_id,
                                     row_id=row["id"]) from exc


def _select(path: Path, game: str = "", subsystem: str = "", address: str = "", build: str = "",
            include_superseded: bool = False, limit: int = 50, evidence_id: str = "") -> list:
    if not path.is_file():
        return []
    clauses, args = [], []
    for column, value in (("game", game), ("subsystem", subsystem), ("address", address), ("build", build),
                          ("evidence_id", evidence_id)):
        if value:
            clauses.append("%s = ?" % column)
            args.append(value)
    if not include_superseded:
        clauses.append("superseded_by IS NULL")
    sql = "SELECT %s FROM claims" % ", ".join(FIELDS)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    db = connect(path)
    try:
        return db.execute(sql, args).fetchall()  # one statement: a consistent snapshot of the selection
    finally:
        db.close()


def query(path: Path, game: str = "", subsystem: str = "", address: str = "", build: str = "",
          include_superseded: bool = False, limit: int = 50, verify: bool | str = True, evidence_id: str = "") -> list[dict]:
    """Rows newest first. Each is verified against its evidence_id; `verify="mark"` flags instead of raising."""
    result = []
    for row in _select(path, game, subsystem, address, build, include_superseded, limit, evidence_id):
        item = decode_row(row)
        if verify:
            try:
                verify_row(row)
            except EvidenceIntegrityError:
                if verify != "mark":
                    raise
                item["integrity"] = "mismatch"
        result.append(item)
    return result


def get_claim(path: Path, evidence_id: str) -> dict | None:
    """The oldest row with this evidence id, verified, or None."""
    rows = query(path, evidence_id=evidence_id, include_superseded=True, limit=1_000_000)
    return rows[-1] if rows else None


def verify_ledger(path: Path) -> dict:
    """Recompute every id; the result lists each row that does not match instead of stopping at the first."""
    if not path.is_file():
        return {"checked": 0, "failed": []}
    db = connect(path)
    try:
        rows = db.execute("SELECT %s FROM claims ORDER BY id" % ", ".join(FIELDS)).fetchall()
    finally:
        db.close()
    failed = []
    for row in rows:
        try:
            verify_row(row)
        except EvidenceIntegrityError as exc:
            failed.append({"id": row["id"], "evidence_id": row["evidence_id"], "code": exc.code, "message": str(exc)})
    return {"checked": len(rows), "failed": failed}


def records_for_bundle(path: Path, game: str = "", subsystem: str = "", build: str = "") -> list[dict]:
    """Every row of the selection (superseded ones too) as {evidence_id, content, meta}, verified, sorted by id."""
    result = {}
    for row in reversed(_select(path, game, subsystem, build=build, include_superseded=True, limit=1_000_000)):
        verify_row(row)
        meta = {"created": row["created"], "client": row["client"], "harness": row["harness"],
                "provenance": _loads(row["provenance"], {})}
        # The same claim stated twice (a legacy ledger) is one record; the earliest statement is its meta.
        result.setdefault(row["evidence_id"], {"evidence_id": row["evidence_id"], "content": content_of_row(row),
                                               "meta": meta})
    return [result[key] for key in sorted(result)]


def import_records(path: Path, records: list[dict]) -> dict:
    """Store verified bundle records. Idempotent: a record whose id is present is skipped. All or nothing."""
    by_id = {}
    for record in records:
        check_content(record["content"], record["evidence_id"])  # nothing reaches the ledger unvalidated
        check_meta(record.get("meta"))
        by_id[record["evidence_id"]] = record
    db = connect(path)
    summary = {"added": 0, "already_present": 0, "history_diverged": 0, "dangling_links": 0}
    try:
        db.execute("BEGIN IMMEDIATE")
        try:
            local: dict[str, int] = {}
            pending = sorted(by_id)
            while pending:
                deferred = []
                for evidence_id in pending:
                    record = by_id[evidence_id]
                    links = record["content"]["evidence_links"]
                    # A record whose superseded claim is in this bundle waits until that claim is stored.
                    if any(link in by_id and link not in local for link in links):
                        deferred.append(evidence_id)
                        continue
                    present = db.execute("SELECT id FROM claims WHERE evidence_id = ? ORDER BY id LIMIT 1",
                                         (evidence_id,)).fetchone()
                    if present is not None:
                        local[evidence_id] = present["id"]
                        summary["already_present"] += 1
                        continue
                    old_id = None
                    for link in links:
                        if link in local:
                            old_id = local[link]
                        else:
                            old = db.execute("SELECT id FROM claims WHERE evidence_id = ? ORDER BY id LIMIT 1",
                                             (link,)).fetchone()
                            if old is None:
                                summary["dangling_links"] += 1
                            else:
                                old_id = old["id"]
                    meta = record.get("meta") or {}
                    row_id = _insert(db, record["content"], evidence_id, created=str(meta.get("created") or _now()),
                                     client=str(meta.get("client") or ""), harness=str(meta.get("harness") or ""),
                                     provenance=_provenance(meta.get("provenance")), supersedes=old_id)
                    local[evidence_id] = row_id
                    summary["added"] += 1
                    if old_id is not None:
                        taken = db.execute("SELECT superseded_by FROM claims WHERE id = ?", (old_id,)).fetchone()
                        if taken is not None and taken["superseded_by"] is None:
                            db.execute("UPDATE claims SET superseded_by = ? WHERE id = ?", (row_id, old_id))
                        elif taken is not None and taken["superseded_by"] != row_id:
                            summary["history_diverged"] += 1
                if len(deferred) == len(pending):
                    raise EvidenceIntegrityError("evidence_links form a cycle", code="evidence_link_cycle")
                pending = deferred
            db.execute("COMMIT")
        except BaseException:
            db.execute("ROLLBACK")
            raise
    finally:
        db.close()
    return summary


def list_claims(path: Path, game: str = "", limit: int = 50, **filters) -> str:
    rows = query(path, game, limit=limit, verify="mark", **filters)
    if not rows:
        return "no claims yet"
    lines = []
    for row in rows:
        coverage = row["coverage"] or {}
        extra = "".join([" subsystem=%s" % row["subsystem"] if row["subsystem"] else "",
                         " supersedes=#%s" % row["supersedes"] if row["supersedes"] else "",
                         " SUPERSEDED by #%s" % row["superseded_by"] if row["superseded_by"] else "",
                         " by=%s/%s" % (row["client"], row["harness"]) if row["client"] else "",
                         " coverage=%s" % coverage.get("status", "?"),
                         " limitations=%s" % ",".join(row["limitations"]) if row["limitations"] else "",
                         " INTEGRITY FAILED: the row does not match its evidence_id" if row.get("integrity") else ""])
        lines.append("#%s %s %s %s %s addr=%s prologue=%s%s" % (row["id"], row["game"], row["build"], row["kind"],
                                                                row["name"], row["address"], row["prologue"], extra))
        lines.append("  evidence_id: %s" % row["evidence_id"])
        lines.append("  note: %s" % row["note"])
        lines.append("  source: %s" % row["source"])
    return "\n".join(lines)


def export(path: Path, out: Path, game: str = "", subsystem: str = "") -> dict:
    """One subsystem's claims as Markdown (current first, superseded after) plus JSONL."""
    rows = query(path, game, subsystem, include_superseded=True, limit=1_000_000)
    current = [row for row in rows if row["superseded_by"] is None]
    old = [row for row in rows if row["superseded_by"] is not None]
    out.parent.mkdir(parents=True, exist_ok=True)
    title = "%s%s" % (subsystem or "all subsystems", " (%s)" % game if game else "")
    lines = ["# Evidence: %s" % title, "", "Generated from the Hydralysis evidence ledger; every row cites its source.", "",
             "| # | build | kind | name | address | note | source | by | coverage | evidence_id |",
             "|---|---|---|---|---|---|---|---|---|---|"]
    cell = lambda value: str(value or "").replace("|", "\\|").replace("\n", " ")
    for row in sorted(current, key=lambda item: (item["address"], item["id"])):
        lines.append("| %s | %s |" % (" | ".join(cell(row[key]) for key in
                                               ("id", "build", "kind", "name", "address", "note", "source", "harness")),
                                      " | ".join((cell((row["coverage"] or {}).get("status")), cell(row["evidence_id"])))))
    if old:
        lines += ["", "## Superseded", "", "| # | build | name | address | superseded by |", "|---|---|---|---|---|"]
        for row in old:
            lines.append("| %s | %s | %s | %s | #%s |" % tuple(cell(row[key]) for key in ("id", "build", "name", "address", "superseded_by")))
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    jsonl = out.with_suffix(".jsonl")
    with jsonl.open("w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row) + "\n")
    return {"markdown": str(out), "jsonl": str(jsonl), "current": len(current), "superseded": len(old)}
