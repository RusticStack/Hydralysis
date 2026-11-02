"""Report builders over trace data (spec 15.3 and 15.4): did my write survive, and was my hook bypassed.

Both work on a page of event rows that `trace query` returned; they hold no store and call no engine. An event row is
the TRACE-1 event as the engine serves it, read through `normalize_event`:

    event_id, kind, seq, frame, phase, role, thread_gen, function (symbolized, or None), stack (symbolized function names,
    innermost first), va, ours (the write came from our own instrumentation), payload

Ordering is the hard part. `seq` is the collector's ingestion ordinal, not execution order, so two events are only
ordered when they share a thread generation (their `seq` order is then the thread's own order) or when the profile's
phases order them. Anything else is *not established* and the verdict says `unknown` with that reason; the report never
guesses an order.

Verdicts and sets are integers; ratios are parts per million, so the reply is byte-identical across runs.
"""

from __future__ import annotations

SURVIVED = "survived"
OVERWRITTEN = "overwritten"
READ_BEFORE_WRITE = "consumer read before write"
UNKNOWN = "unknown"


def normalize_event(row: dict) -> dict:
    """The fields the reports read, from an engine event row (TRACE-1 section 5 plus the ingest-added `static`)."""
    static = row.get("static") or {}
    payload = row.get("payload") or {}
    stack = row.get("stack")
    if stack is None:
        stack = static.get("stack") or []
    return {"event_id": row.get("event_id"), "kind": row.get("kind"), "seq": row.get("seq"), "frame": row.get("frame"),
            "phase": row.get("phase"), "role": row.get("role") or row.get("thread_role"),
            "thread_gen": row.get("thread_gen"), "function": row.get("function") or static.get("function"),
            "stack": list(stack), "va": row.get("va"), "ours": bool(row.get("ours", payload.get("ours", False))),
            "payload": payload}


def _ppm(part: int, whole: int) -> int | None:
    return None if not whole else part * 1_000_000 // whole


def _before(a: dict, b: dict, phase_order: dict) -> bool | None:
    """True/False when A is established to come before B, None when the order is not established."""
    if a["frame"] != b["frame"]:
        return None
    pa, pb = phase_order.get(a["phase"]), phase_order.get(b["phase"])
    if pa is not None and pb is not None and pa != pb:
        return pa < pb
    if a["thread_gen"] is not None and a["thread_gen"] == b["thread_gen"] and a["seq"] is not None and b["seq"] is not None:
        return a["seq"] < b["seq"]
    return None


def _site(event: dict) -> str:
    return event["function"] or ("va:%#x" % event["va"] if event["va"] is not None else "unresolved")


def write_survival(events: list[dict], *, field: str, consumer: str, phases: list[str] | None = None,
                   gaps: list[dict] | None = None, representatives: int = 3) -> dict:
    """15.3: for FIELD (a state key) and CONSUMER (the function whose read of the field matters), per frame:

    the ordered writes (site, role, phase, ours?), the value the consumer read and which write produced it, and a
    verdict: `survived`, `overwritten` (naming the site), `consumer read before write`, or `unknown` with its reason.
    A frame that overlaps a capture gap (`gaps` is a list of {frame} or {first_frame, last_frame}) is `unknown`
    because a missing write cannot be excluded."""
    rows = [normalize_event(event) for event in events]
    order = {name: index for index, name in enumerate(phases or [])}
    gap_frames, gap_ranges = set(), []
    for gap in gaps or []:
        if "frame" in gap:
            gap_frames.add(gap["frame"])
        elif "first_frame" in gap:
            gap_ranges.append((gap["first_frame"], gap.get("last_frame", gap["first_frame"])))

    def gapped(frame) -> bool:
        return frame in gap_frames or any(lo <= frame <= hi for lo, hi in gap_ranges if isinstance(frame, int))

    writes: dict = {}
    reads: dict = {}
    for row in rows:
        key = row["payload"].get("state_key", row["payload"].get("key"))
        if key != field or row["frame"] is None:
            continue
        if row["kind"] == "core.state.write":
            writes.setdefault(row["frame"], []).append(row)
        elif row["kind"] == "core.state.read" and row["function"] == consumer:
            reads.setdefault(row["frame"], []).append(row)

    frames, overwriters = [], {}
    verdicts = {SURVIVED: 0, OVERWRITTEN: 0, READ_BEFORE_WRITE: 0, UNKNOWN: 0}
    for frame in sorted(set(writes) | set(reads), key=lambda f: (str(type(f)), f)):
        frame_writes = sorted(writes.get(frame, []), key=lambda w: (order.get(w["phase"], 10 ** 6), w["seq"] if w["seq"] is not None else 0))
        entry = {"frame": frame, "writes": [{"event_id": w["event_id"], "site": _site(w), "role": w["role"], "phase": w["phase"],
                                              "ours": w["ours"], "value": w["payload"].get("value")} for w in frame_writes]}
        frame_reads = reads.get(frame, [])
        ours = [w for w in frame_writes if w["ours"]]
        verdict, reason, produced_by, culprit = UNKNOWN, None, None, None
        if not frame_reads:
            reason = "no consumer read observed in this frame"
        elif gapped(frame):
            reason = "the frame overlaps a capture gap"
        elif not ours:
            reason = "none of our writes was observed in this frame"
        else:
            read = frame_reads[0]
            entry["read"] = {"event_id": read["event_id"], "site": _site(read), "phase": read["phase"], "value": read["payload"].get("value")}
            relations = [(_before(w, read, order), w) for w in frame_writes]
            if any(before is None for before, _ in relations):
                unordered = next(w for before, w in relations if before is None)
                reason = "order not established between %s and the consumer's read" % unordered["event_id"]
            else:
                prior = [w for before, w in relations if before]
                if not prior or not any(w["ours"] for w in prior):
                    verdict = READ_BEFORE_WRITE
                else:
                    produced = max(prior, key=lambda w: (order.get(w["phase"], 10 ** 6), w["seq"] if w["seq"] is not None else 0))
                    rivals = [w for w in prior if w is not produced and _before(w, produced, order) is None]
                    if rivals:
                        reason = "order not established between writes %s and %s" % (produced["event_id"], rivals[0]["event_id"])
                    else:
                        produced_by = produced["event_id"]
                        if produced["ours"]:
                            verdict = SURVIVED
                        else:
                            verdict, culprit = OVERWRITTEN, _site(produced)
        entry["verdict"] = verdict
        if reason:
            entry["reason"] = reason
        if produced_by:
            entry["produced_by"] = produced_by
        if culprit:
            entry["overwritten_by"] = culprit
            overwriters[culprit] = overwriters.get(culprit, 0) + 1
        verdicts[verdict] += 1
        frames.append(entry)

    total = len(frames)
    top = sorted(overwriters.items(), key=lambda item: (-item[1], item[0]))
    sentence = None
    if verdicts[OVERWRITTEN]:
        site, count = top[0]
        sentence = ("%d of %d frames overwritten%s" % (verdicts[OVERWRITTEN], total, " by one site" if len(top) == 1 else
                                                         ", %d of them by %s" % (count, site)))
    sample = {verdict: [f["frame"] for f in frames if f["verdict"] == verdict][:representatives] for verdict in verdicts}
    return {"field": field, "consumer": consumer, "frames": total, "verdicts": verdicts,
            "ratios_ppm": {verdict: _ppm(count, total) for verdict, count in verdicts.items()},
            "overwriters": [{"site": site, "frames": count} for site, count in top], "summary": sentence,
            "representatives": sample, "per_frame": frames,
            "claim": "may_not_be_complete" if verdicts[UNKNOWN] else "all_frames_decided"}


def observed_edges(events: list[dict], *, static_candidates: dict | None = None, frames_per_edge: int = 5) -> dict:
    """15.4: observed indirect-call edges as cited `observed-call` relations, apart from static candidates.

    An event `app.*` / `core.function.enter` with payload {site, target, receiver_class?, slot?} is an observed edge.
    Edges are aggregated by (site, target, class). Static candidates ({site: [targets]}, from `vcalls`) that were never
    observed stay `may call`: this function never says `does not call`."""
    edges: dict = {}
    for event in map(normalize_event, events):
        payload = event["payload"]
        if "site" not in payload or "target" not in payload:
            continue
        key = (payload["site"], payload["target"], payload.get("receiver_class"))
        edge = edges.setdefault(key, {"relation": "observed-call", "status": "supported", "site": payload["site"],
                                      "target": payload["target"], "receiver_class": payload.get("receiver_class"),
                                      "slot": payload.get("slot"), "count": 0, "frames": [], "events": []})
        edge["count"] += 1
        if event["frame"] is not None and event["frame"] not in edge["frames"] and len(edge["frames"]) < frames_per_edge:
            edge["frames"].append(event["frame"])
        if event["event_id"] and len(edge["events"]) < 3:
            edge["events"].append(event["event_id"])
    observed = [edges[key] for key in sorted(edges, key=lambda k: (str(k[0]), str(k[1]), str(k[2])))]
    seen = {(edge["site"], edge["target"]) for edge in observed}
    unobserved = [{"site": site, "target": target, "status": "may call", "basis": "static candidate (vcalls); never observed"}
                  for site, targets in sorted((static_candidates or {}).items(), key=lambda item: str(item[0]))
                  for target in sorted(targets, key=str) if (site, target) not in seen]
    return {"observed": observed, "unobserved_candidates": unobserved,
            "note": "an unobserved slot is `may call`, never `does not call`"}


def hook_bypass(events: list[dict], *, hook: str, field: str, siblings: list[str] | None = None,
                observed: list[dict] | None = None, per_class: int = 5) -> dict:
    """15.4: writes of FIELD that did not pass through HOOK, with the observed call path and why.

    A write passed through the hook when HOOK is on its symbolized stack (or is its function). Otherwise its class is
    `sibling-overload` (its function is one of SIBLINGS: the overloads of the hooked function), `different-slot` (it was
    reached through an observed indirect edge whose target is its function), `inlined-copy` (the hook is not on the
    stack but the write sits inside a function that calls it nowhere: the code was copied, recorded from the address) or
    `unexplained`. Each bypass cites the event, the path and the receiver class when an edge named one."""
    siblings = set(siblings or [])
    targets = {}
    for edge in observed or []:
        targets.setdefault(edge.get("target"), edge)
    passed, bypasses, total = 0, [], 0
    by_class: dict = {}
    for event in map(normalize_event, events):
        key = event["payload"].get("state_key", event["payload"].get("key"))
        if event["kind"] != "core.state.write" or key != field:
            continue
        total += 1
        path = [event["function"]] if event["function"] else []
        path += [name for name in event["stack"] if name != event["function"]]
        if hook in path:
            passed += 1
            continue
        edge = targets.get(event["function"])
        if event["function"] in siblings:
            kind = "sibling-overload"
        elif edge is not None:
            kind = "different-slot"
        elif event["function"] is None and event["va"] is not None:
            kind = "inlined-copy"
        else:
            kind = "unexplained"
        entry = {"class": kind, "event_id": event["event_id"], "frame": event["frame"], "site": _site(event), "path": path,
                 "receiver_class": (edge or {}).get("receiver_class"), "via": (edge or {}).get("site")}
        by_class[kind] = by_class.get(kind, 0) + 1
        if sum(1 for b in bypasses if b["class"] == kind) < per_class:
            bypasses.append(entry)
    return {"hook": hook, "field": field, "writes_observed": total, "through_hook": passed, "bypassed": total - passed,
            "ratios_ppm": {"bypassed": _ppm(total - passed, total)}, "by_class": dict(sorted(by_class.items())),
            "bypasses": bypasses,
            "verdict": "hook_bypassed" if total - passed else ("hook_covers_observed_writes" if total else "no_writes_observed"),
            "caveat": "only the instrumented sites and the observed intervals are covered; a write that was not observed is not "
                      "evidence that the hook sees every write"}


def discovery_report(*, exercised: list[dict], candidates: list[dict], observation_gaps: list[dict]) -> dict:
    """M4: separate what the run exercised, the static candidates it never exercised and where observation was missing.

    The three lists are never merged: an unobserved candidate is not a negative, and a gap is not an absence."""
    exercised_keys = {item.get("key") for item in exercised}
    unobserved = [item for item in candidates if item.get("key") not in exercised_keys]
    return {"exercised_behavior": {"count": len(exercised), "items": exercised},
            "unobserved_candidates": {"count": len(unobserved), "items": unobserved,
                                      "meaning": "static candidates with no observed execution in the observed intervals"},
            "observation_gaps": {"count": len(observation_gaps), "items": observation_gaps,
                                 "meaning": "intervals or sites where nothing could be observed; absence there proves nothing"}}
