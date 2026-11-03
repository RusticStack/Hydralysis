"""Differential driver for the Rust evidence port (rust/crates/hy-store/tests/diff_python.rs).

  gen_evidence.py gen   OUT CLAIMS.json   build py.db, py-bundle/, py.md, py.jsonl, py-list.txt in OUT
  gen_evidence.py check OUT               read rust.db and rust-bundle/ in OUT with the Python implementation
Time, writer and python version are pinned so the output bytes are comparable.
"""

import json
import platform
import sys
from pathlib import Path

from hydralysis import evidence, evidence_bundle

NOW = "2026-01-01T00:00:00Z"
evidence._now = lambda: NOW
evidence._who = lambda: ("rusticre:1", "diff-harness")
platform.python_version = lambda: "3.15.0"

PIN = {"format": "hydralysis.trace-pin/1", "trace_id": "s1", "session": "s1", "revision": 5, "interpretation_revision": None,
       "events": ["e1", "e2"], "artifacts": [{"id": "a", "sha256": "ef" * 32, "range": [0, 16], "authorized": True}],
       "reproducible": True, "cannot_reproduce": []}
CAPTURE = {"capture_id": "cap_one", "events": [{"seq": 1, "rva": "0x2e3270", "args_hex": "00ff10"}], "dropped_events": 0}


def seed(out: Path) -> None:
    (out / "captures").mkdir(parents=True, exist_ok=True)
    (out / "traces").mkdir(parents=True, exist_ok=True)
    (out / "captures" / "cap_one.json").write_text(json.dumps(CAPTURE), encoding="utf-8")
    (out / "traces" / "s1.json").write_text(json.dumps(PIN), encoding="utf-8")


def gen(out: Path, spec: Path) -> None:
    seed(out)
    db = out / "py.db"
    messages = []
    for claim in json.loads(spec.read_text(encoding="utf-8")):
        messages.append(evidence.add_claim(db, **claim))
    messages.append(evidence.add_claim(db, **json.loads(spec.read_text(encoding="utf-8"))[0]))  # restated: already stored
    (out / "py-messages.txt").write_text("\n".join(messages), encoding="utf-8", newline="\n")
    result = evidence_bundle.export_bundle(db, out / "py-bundle", captures_dir=out / "captures", traces_dir=out / "traces")
    (out / "py-export.json").write_text(json.dumps(result), encoding="utf-8")
    evidence.export(db, out / "py.md", "cp", "")
    (out / "py-list.txt").write_text(evidence.list_claims(db, "cp", include_superseded=True), encoding="utf-8", newline="\n")
    (out / "py-verify.json").write_text(json.dumps(evidence_bundle.verify_bundle(out / "py-bundle")), encoding="utf-8")


def check(out: Path) -> None:
    db = out / "rust.db"
    rows = evidence.query(db, include_superseded=True, limit=1_000_000)
    report = {
        "rows": rows,
        "ledger": evidence.verify_ledger(db),
        "bundle": evidence_bundle.verify_bundle(out / "rust-bundle"),
        "compare": evidence_bundle.compare_bundles(out / "py-bundle", out / "rust-bundle"),
        "list": evidence.list_claims(db, "cp", include_superseded=True),
    }
    (out / "py-check.json").write_text(json.dumps(report), encoding="utf-8")


if __name__ == "__main__":
    mode, folder = sys.argv[1], Path(sys.argv[2])
    if mode == "gen":
        gen(folder, Path(sys.argv[3]))
    else:
        check(folder)
