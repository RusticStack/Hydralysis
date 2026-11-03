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
                 "receiver_class": (edge or {}).get("receiver_class"), "via": (edge or {}).get("site"),
                 "reached_through": "indirect call at %s (slot %s)" % (edge["site"], edge.get("slot")) if edge else None}
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


# ---- 14.4: who writes this field? -----------------------------------------------------------------------------------------

def _entry(value) -> int | None:
    if isinstance(value, int):
        return value
    try:
        return int(str(value), 16)
    except (TypeError, ValueError):
        return None


def field_writers(static_sites: list[dict], events: list[dict], *, object_addr: int, offset: int, size: int,
                  names: dict | None = None, escape_kind: str = "app.escape", write_kinds=("core.state.write",),
                  per_site: int = 3) -> dict:
    """14.4: the writers of one field of one object, as three answers that are never merged.

    STATIC_SITES are the static candidates (`writes` rows: {function: entry address, site, instruction?}); NAMES maps a
    function entry address to its name so a candidate can be matched with an observed site. EVENTS are trace rows. An event
    of a kind in WRITE_KINDS with payload {object, offset?, size?} (default offset 0, the span the write covers) writes the
    selected bytes when [object+offset, +size) overlaps [OBJECT_ADDR+OFFSET, +SIZE); an event of ESCAPE_KIND with payload
    {object, offset, callee} says a pointer into the selected bytes was passed to code that is not instrumented.

    * `observed`  - a site whose write was seen: count, objects, events; `static_candidate` says whether the static scan
                    listed it (a site it did not list is a writer no scan of the field would have found);
    * `may_access` - a static candidate with no observation in the observed intervals. It may run later, or never;
    * `unresolved` - a pointer to the field reached uninstrumented code: the write is neither confirmed nor excluded.

    The reply never presents the static scan as a complete inventory."""
    names = {_entry(address): name for address, name in (names or {}).items()}
    lo, hi = object_addr + offset, object_addr + offset + size
    by_function: dict = {}
    for row in static_sites:
        entry = _entry(row.get("function"))
        by_function.setdefault(entry, {"function": names.get(entry) or row.get("function_name") or row.get("function"),
                                       "entry": row.get("function"), "sites": []})["sites"].append(
            {"site": row.get("site"), "instruction": row.get("instruction")})
    candidate_names = {value["function"] for value in by_function.values()}
    observed: dict = {}
    escapes: dict = {}
    for event in map(normalize_event, events):
        payload = event["payload"]
        base = payload.get("object")
        if not isinstance(base, int):
            continue
        start = base + int(payload.get("offset", 0))
        name = event["function"] or payload.get("site") or "unresolved"
        if event["kind"] in write_kinds:
            if start < hi and start + int(payload.get("size", size)) > lo:
                entry = observed.setdefault(name, {"site": name, "count": 0, "objects": set(), "frames": [],
                                                   "events": [], "static_candidate": name in candidate_names})
                entry["count"] += 1
                entry["objects"].add(base)
                if event["frame"] is not None and len(entry["frames"]) < per_site * 2 and event["frame"] not in entry["frames"]:
                    entry["frames"].append(event["frame"])
                if event["event_id"] and len(entry["events"]) < per_site:
                    entry["events"].append(event["event_id"])
        elif event["kind"] == escape_kind and lo <= start < hi:
            entry = escapes.setdefault(name, {"site": name, "callee": payload.get("callee"), "count": 0, "events": []})
            entry["count"] += 1
            if event["event_id"] and len(entry["events"]) < per_site:
                entry["events"].append(event["event_id"])
    observed_rows = []
    for name in sorted(observed):
        row = observed[name]
        row["objects"] = sorted(row["objects"])
        row["status"] = "observed"
        row["on_selected_object"] = object_addr in row["objects"]
        if not row["static_candidate"]:
            row["note"] = "not among the static candidates: no scan of this field would have listed it"
        observed_rows.append(row)
    seen = {row["site"] for row in observed_rows}
    may = [{"site": value["function"], "status": "may access", "static_sites": value["sites"],
            "basis": "static candidate (a store at offset %#x); never observed in the observed intervals" % offset}
           for value in sorted(by_function.values(), key=lambda v: str(v["function"])) if value["function"] not in seen]
    unresolved = [{"site": name, "status": "unresolved", "callee": row["callee"], "count": row["count"], "events": row["events"],
                   "stopped_by": "alias: a pointer into the field is passed to %s, which is not instrumented; whether it writes "
                                 "the field is neither observed nor excluded" % (row["callee"] or "an uninstrumented callee")}
                  for name, row in sorted(escapes.items())]
    return {"field": {"object": object_addr, "offset": offset, "size": size}, "observed": observed_rows, "may_access": may,
            "unresolved": unresolved, "static_inventory_complete": False,
            "claim": "three distinct answers: observed writers, static candidates never seen to run, and aliases that stop the analysis; "
                     "none of them is a complete writer inventory"}


# ---- adapters: trace rows -> the events the reports read ---------------------------------------------------------------------

def from_engine_rows(rows: list[dict], *, names: dict | None = None, symbols: dict | None = None) -> list[dict]:
    """Engine query rows ({event_id, kind, seq, payload, process_gen, thread_gen, ...}, payload JSON text or object) as report
    events. The producer-stamped `frame`, `phase`, `role` and `ours` of the payload become the event's own; the site is the
    hook's id (payload.site) unless a symbolized function is known for the seq (SYMBOLS: seq -> {function, stack}); NAMES
    maps a `FUN_<hex address>` name to the program's own name for that address."""
    import json
    names = {int(str(k), 16) if not isinstance(k, int) else k: v for k, v in (names or {}).items()}

    def rename(name):
        if isinstance(name, str) and name.startswith("FUN_"):
            try:
                return names.get(int(name[4:], 16), name)
            except ValueError:
                return name
        return name
    out = []
    for row in rows:
        payload = row.get("payload")
        payload = json.loads(payload) if isinstance(payload, str) else dict(payload or {})
        known = (symbols or {}).get(row.get("seq")) or {}
        out.append({"event_id": row.get("event_id"), "kind": row.get("kind"), "seq": row.get("seq"), "frame": payload.get("frame"),
                    "phase": payload.get("phase"), "role": payload.get("role"),
                    "thread_gen": (row.get("process_gen"), row.get("thread_gen")) if row.get("thread_gen") is not None else None,
                    "function": rename(known.get("function")) or payload.get("site"),
                    "stack": [rename(n) for n in known.get("stack") or [] if n], "va": row.get("va"),
                    "ours": bool(payload.get("ours", False)), "payload": payload,
                    "rva": int(str(payload["rva"]), 0) if payload.get("rva") is not None else None})
    return out


def edges_from_dispatch(events: list[dict], dispatch_sites: dict, *, receiver_class=None, ignore=(), candidates: dict | None = None) -> list[dict]:
    """15.4: observed indirect-call edges from instrumented dispatch sites.

    DISPATCH_SITES maps a site (the hook id of a function that makes an indirect call) to {slot}; a dispatch event carries
    payload.receiver (the object the call goes through). The target is the very next instrumented event of the same thread
    (events of IGNORE are skipped); if that is itself a dispatch event there is no observed target. Several source functions
    can share one site (identical code is folded), so when CANDIDATES ({site: [targets]}) is given the next event only counts
    when it is one of the site's candidates. This is an observation of order on one thread, not of the jump itself, and each
    edge says so. RECEIVER_CLASS(receiver) names the class from the object's vtable pointer where that is known, else None."""
    rows = [normalize_event(e) for e in events]
    by_thread: dict = {}
    for row in sorted(rows, key=lambda r: r["seq"] if r["seq"] is not None else 0):
        if row["function"] not in ignore:
            by_thread.setdefault(row["thread_gen"], []).append(row)
    out = []
    for thread in by_thread.values():
        for index, row in enumerate(thread[:-1]):
            site = row["function"]
            if site not in dispatch_sites:
                continue
            target = thread[index + 1]
            if target["function"] in dispatch_sites or (candidates and target["function"] not in (candidates.get(site) or ())):
                continue
            receiver = row["payload"].get("receiver")
            out.append({"event_id": row["event_id"], "kind": "core.function.enter", "seq": row["seq"], "frame": row["frame"],
                        "payload": {"site": site, "target": target["function"], "slot": dispatch_sites[site].get("slot"),
                                    "receiver_class": receiver_class(receiver) if receiver_class and receiver is not None else None,
                                    "basis": "next instrumented event on the same thread after the dispatch (%s)" % target["event_id"]}})
    return out


# ---- optional Rust implementation (HYDRALYSIS_IMPL=rust) ------------------------------------------------------------
# crates/hy-trace (bound in native/src/trace/reports.rs). The functions above stay the specification: the Rust ones give the
# same answers for the event shapes the producers emit and raise `TraceFallback` for any other, which runs the Python.

from hydralysis import trace_native  # noqa: E402

_write_survival_py, _observed_edges_py, _hook_bypass_py = write_survival, observed_edges, hook_bypass
_discovery_report_py, _field_writers_py = discovery_report, field_writers
_from_engine_rows_py, _edges_from_dispatch_py = from_engine_rows, edges_from_dispatch


def _native(name):
    """(routine, the exceptions that mean "run the Python") for the Rust twin NAME, or (None, ())."""
    routine = trace_native.function(name)
    if routine is None:
        return None, ()
    return routine, (trace_native.native().TraceFallback, OverflowError)


def _is_int(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def write_survival(events: list[dict], *, field: str, consumer: str, phases: list[str] | None = None,
                   gaps: list[dict] | None = None, representatives: int = 3) -> dict:
    routine, errors = _native("reports_write_survival")
    if routine is not None and isinstance(field, str) and isinstance(consumer, str) and _is_int(representatives):
        try:
            return routine(events, field, consumer, phases, gaps, representatives)
        except errors:
            pass
    return _write_survival_py(events, field=field, consumer=consumer, phases=phases, gaps=gaps, representatives=representatives)


def observed_edges(events: list[dict], *, static_candidates: dict | None = None, frames_per_edge: int = 5) -> dict:
    routine, errors = _native("reports_observed_edges")
    if routine is not None and _is_int(frames_per_edge):
        try:
            return routine(events, static_candidates, frames_per_edge)
        except errors:
            pass
    return _observed_edges_py(events, static_candidates=static_candidates, frames_per_edge=frames_per_edge)


def hook_bypass(events: list[dict], *, hook: str, field: str, siblings: list[str] | None = None,
                observed: list[dict] | None = None, per_class: int = 5) -> dict:
    routine, errors = _native("reports_hook_bypass")
    if routine is not None and isinstance(hook, str) and isinstance(field, str) and _is_int(per_class):
        try:
            return routine(events, hook, field, siblings, observed, per_class)
        except errors:
            pass
    return _hook_bypass_py(events, hook=hook, field=field, siblings=siblings, observed=observed, per_class=per_class)


def discovery_report(*, exercised: list[dict], candidates: list[dict], observation_gaps: list[dict]) -> dict:
    routine, errors = _native("reports_discovery")
    if routine is not None:
        try:
            return routine(exercised, candidates, observation_gaps)
        except errors:
            pass
    return _discovery_report_py(exercised=exercised, candidates=candidates, observation_gaps=observation_gaps)


def field_writers(static_sites: list[dict], events: list[dict], *, object_addr: int, offset: int, size: int,
                  names: dict | None = None, escape_kind: str = "app.escape", write_kinds=("core.state.write",),
                  per_site: int = 3) -> dict:
    routine, errors = _native("reports_field_writers")
    if routine is not None and all(_is_int(v) for v in (object_addr, offset, size, per_site)) and isinstance(escape_kind, str) \
            and isinstance(write_kinds, (list, tuple)):
        try:
            return routine(static_sites, events, object_addr, offset, size, names, escape_kind, write_kinds, per_site)
        except errors:
            pass
    return _field_writers_py(static_sites, events, object_addr=object_addr, offset=offset, size=size, names=names,
                             escape_kind=escape_kind, write_kinds=write_kinds, per_site=per_site)


def from_engine_rows(rows: list[dict], *, names: dict | None = None, symbols: dict | None = None) -> list[dict]:
    routine, errors = _native("reports_from_engine_rows")
    if routine is not None:
        try:
            return routine(rows, names, symbols)
        except errors:
            pass
    return _from_engine_rows_py(rows, names=names, symbols=symbols)


def edges_from_dispatch(events: list[dict], dispatch_sites: dict, *, receiver_class=None, ignore=(),
                        candidates: dict | None = None) -> list[dict]:
    routine, errors = _native("reports_edges_from_dispatch")
    if routine is not None and isinstance(ignore, (list, tuple)):
        try:
            return routine(events, dispatch_sites, receiver_class, ignore, candidates)
        except errors:
            pass
    return _edges_from_dispatch_py(events, dispatch_sites, receiver_class=receiver_class, ignore=ignore, candidates=candidates)
