"""A claim is a row: target, build, address, prologue, and the line that proves it.

A row without a note and a source is refused. The Ghidra project is a cache;
this ledger is the record that survives a project refresh, and the backbone an
engine map can be generated from: claims carry a subsystem, the client and
harness that made them, and a newer claim can supersede an older one (a 2.5
re-derivation replacing a 2.31 fact) without deleting it.

Several harnesses write at once: the database runs in WAL mode with a busy
timeout, so a writer waits for another instead of failing.
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

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
           "harness": "TEXT NOT NULL DEFAULT ''", "supersedes": "INTEGER", "superseded_by": "INTEGER"}
FIELDS = ("id", "game", "build", "kind", "name", "address", "prologue", "note", "source", "created",
          "subsystem", "client", "harness", "supersedes", "superseded_by")
BUSY_TIMEOUT_MS = 15000


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
    db.commit()
    return db


def _who() -> tuple[str, str]:
    from rusticre.hydra import identity
    who = identity()
    return who["client"], who["harness"]


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
) -> str:
    for field, value in (
        ("game", game),
        ("build", build),
        ("kind", kind),
        ("name", name),
        ("note", note),
        ("source", source),
    ):
        if not str(value).strip():
            raise ValueError("%s is required; a claim without evidence is not stored" % field)
    created = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    client, harness = _who()
    db = connect(path)
    try:
        with db:  # one transaction: the new claim and the old one's link land together
            if supersedes is not None:
                old = db.execute("SELECT id, superseded_by FROM claims WHERE id = ?", (int(supersedes),)).fetchone()
                if old is None:
                    raise ValueError("no claim %s to supersede" % supersedes)
                if old["superseded_by"] is not None:
                    raise ValueError("claim %s is already superseded by claim %s" % (supersedes, old["superseded_by"]))
            cursor = db.execute(
                """
                INSERT INTO claims (game, build, kind, name, address, prologue, note, source, created,
                                    subsystem, client, harness, supersedes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (game, build, kind, name, address, prologue, note, source, created, subsystem, client, harness,
                 int(supersedes) if supersedes is not None else None),
            )
            row_id = cursor.lastrowid
            if supersedes is not None:
                db.execute("UPDATE claims SET superseded_by = ? WHERE id = ?", (row_id, int(supersedes)))
    finally:
        db.close()
    return "claim %s stored %s %s %s%s" % (row_id, game, kind, name, " (supersedes %s)" % supersedes if supersedes else "")


def query(path: Path, game: str = "", subsystem: str = "", address: str = "", build: str = "",
          include_superseded: bool = False, limit: int = 50) -> list[dict]:
    if not path.is_file():
        return []
    clauses, args = [], []
    for column, value in (("game", game), ("subsystem", subsystem), ("address", address), ("build", build)):
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
        return [dict(row) for row in db.execute(sql, args).fetchall()]
    finally:
        db.close()


def list_claims(path: Path, game: str = "", limit: int = 50, **filters) -> str:
    rows = query(path, game, limit=limit, **filters)
    if not rows:
        return "no claims yet"
    lines = []
    for row in rows:
        extra = "".join([" subsystem=%s" % row["subsystem"] if row["subsystem"] else "",
                         " supersedes=#%s" % row["supersedes"] if row["supersedes"] else "",
                         " SUPERSEDED by #%s" % row["superseded_by"] if row["superseded_by"] else "",
                         " by=%s/%s" % (row["client"], row["harness"]) if row["client"] else ""])
        lines.append("#%s %s %s %s %s addr=%s prologue=%s%s" % (row["id"], row["game"], row["build"], row["kind"],
                                                                row["name"], row["address"], row["prologue"], extra))
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
    lines = ["# Evidence: %s" % title, "", "Generated from the RusticRE evidence ledger; every row cites its source.", "",
             "| # | build | kind | name | address | note | source | by |", "|---|---|---|---|---|---|---|---|"]
    cell = lambda value: str(value or "").replace("|", "\\|").replace("\n", " ")
    for row in sorted(current, key=lambda item: (item["address"], item["id"])):
        lines.append("| %s | %s | %s | %s | %s | %s | %s | %s |" % tuple(cell(row[key]) for key in
                     ("id", "build", "kind", "name", "address", "note", "source", "harness")))
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
