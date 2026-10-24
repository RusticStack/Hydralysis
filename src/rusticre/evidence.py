"""A claim is a row: game, build, address, prologue, and the log line that proves it.

A row without a note and a source is refused. The Ghidra project is a cache.
This database is the record that survives a project refresh.
"""

from __future__ import annotations

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


def connect(path: Path) -> sqlite3.Connection:
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(path)
    db.row_factory = sqlite3.Row
    db.executescript(SCHEMA)
    return db


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
    db = connect(path)
    try:
        cursor = db.execute(
            """
            INSERT INTO claims (game, build, kind, name, address, prologue, note, source, created)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (game, build, kind, name, address, prologue, note, source, created),
        )
        row_id = cursor.lastrowid
        db.commit()
    finally:
        db.close()
    return "claim %s stored %s %s %s" % (row_id, game, kind, name)


def list_claims(path: Path, game: str = "", limit: int = 50) -> str:
    if not path.is_file():
        return "no claims yet"
    query = "SELECT id, game, build, kind, name, address, prologue, note, source, created FROM claims"
    args: list[object] = []
    if game:
        query += " WHERE game = ?"
        args.append(game)
    query += " ORDER BY id DESC LIMIT ?"
    args.append(int(limit))
    db = connect(path)
    try:
        rows = db.execute(query, args).fetchall()
    finally:
        db.close()
    if not rows:
        return "no claims yet"
    lines = []
    for row in rows:
        lines.append(
            "#%s %s %s %s %s addr=%s prologue=%s"
            % (row["id"], row["game"], row["build"], row["kind"], row["name"], row["address"], row["prologue"])
        )
        lines.append("  note: %s" % row["note"])
        lines.append("  source: %s" % row["source"])
    return "\n".join(lines)
