"""Differential helper: runs one hydralysis (Python) storage operation and prints its JSON result.

usage: diff.py <src> <op> <json-args>
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, sys.argv[1])
op = sys.argv[2]
args = json.loads(Path(sys.argv[3][1:]).read_text(encoding="utf-8")) if sys.argv[3].startswith("@") else json.loads(sys.argv[3])

from hydralysis import backups, lineage, runtime_events  # noqa: E402

if op == "tree_files":
    out = lineage.tree_files(Path(args["folder"]))
elif op == "tree_hash":
    out = lineage.tree_hash(Path(args["folder"]))
elif op == "write_manifest":
    out = lineage.write_manifest(Path(args["folder"]), args["body"])
elif op == "verify_manifest":
    out = lineage.verify_manifest(Path(args["folder"]))
elif op == "canonical_hex":
    out = lineage.canonical(args["value"]).hex()
elif op == "history":
    out = lineage.history(args["settings"], args["lid"])
elif op == "head":
    out = lineage.head(args["settings"], args["lid"])
elif op == "append":
    out = lineage.append_current(args["settings"], args["lid"], args["record"])
elif op == "ensure":
    out = lineage.ensure(args["settings"], args["target"])
elif op == "backup_verify":
    out = backups.verify(Path(args["folder"]))
elif op == "listing":
    out = backups.listing(args["settings"], args["lid"], args.get("verify_all", False))
elif op == "events_verify":
    out = runtime_events.verify_log(Path(args["dir"]), args["session"])
elif op == "events_write":
    log = runtime_events.EventLog(Path(args["dir"]), args["session"])
    for index in range(args["count"]):
        message = {"type": "send", "payload": {"event": "enter", "hit": index, "text": "café \U0001F600", "f": 0.5 * index}}
        log.count_message("hook", message, False)
        log.record("hook", message)
    log.marker("capture_start", {"capture": "c1"})
    log.close()
    out = {"head": log.head, "counters": log.counters_copy()}
elif op == "record_hash":
    out = runtime_events.record_hash(args["record"])
elif op == "frame_hex":
    out = runtime_events._frame(args["record"]).hex()
elif op == "canonical_many":
    out = [lineage.canonical(v).hex() for v in args["values"]]
elif op == "frame_many":
    out = [runtime_events._frame(v).hex() for v in args["values"]]
elif op == "hash_many":
    out = [runtime_events.record_hash(v) for v in args["values"]]
elif op == "policy":
    out = backups.policy(args["settings"])
else:
    raise SystemExit("unknown op " + op)
sys.stdout.write(json.dumps(out, ensure_ascii=True) + chr(10))
