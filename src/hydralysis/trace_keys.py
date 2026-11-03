"""Frame, phase and thread role as first-class keys of an event (spec 15.2).

A profile declares **role resolvers** (`[[roles]]`: "the thread that ran hook X") and **phase markers** (`[[phases]]`: the
hooks that open and close a frame and each named stage within it). `annotate` stamps every profile event with

    payload.frame   the frame number (the hook's own `frame` argument, else the thread's current frame marker)
    payload.phase   the stage the event ran in
    payload.role    the thread's role

and, for each key it cannot resolve, `payload.unresolved[<key>] = <reason>`. The keys come from observations, never from
timestamps: a thread's own events are in the thread's own order, and a stage marker is an event of that thread. The
engine's checks (`only_on_role`, `write_precedes_read_in_frame`, ...) read these payload fields; an event whose key is
unresolved is `unknown` to them, never a pass.

A **missing marker** is not papered over: if a frame shows stage markers k and j but the profile declares stages between
them that never opened, the events between k and j are `unresolved: missing-marker:<stages>` and not attributed to k.

Role resolvers:

    function         the thread that ran hook X (always available)
    thread_start_rva the thread whose `core.thread.start` event carries `payload.start_rva` equal to the resolver's value
    thread_name      the thread whose `core.thread.start` (or `core.marker` thread-name) event carries `payload.name` equal to it
    pool             not evaluated by any producer; refused

A resolver whose evidence is absent from the events is **refused explicitly**, never silently skipped: the report lists it
under `refused_resolvers` with the reason (for example "no core.thread.start event carries start_rva"), and every event
that no resolver matched says why in `payload.unresolved.role`. `annotate(..., strict=True)` raises `RoleResolverRefused`
instead of returning, for a caller that must not proceed on a partial answer.
"""

from __future__ import annotations

import os

try:  # optional Rust twin of `annotate` (native/src/trace/keys.rs); HYDRALYSIS_NATIVE=0 or a missing wheel uses the Python below
    from hydralysis_native import annotate_events as _annotate_events  # type: ignore[import-not-found]
except ImportError:
    _annotate_events = None


class RoleResolverRefused(ValueError):
    """A role resolver of the profile cannot be evaluated from these events."""

    def __init__(self, refused: dict):
        super().__init__("role resolvers refused: " + "; ".join("%s: %s" % item for item in sorted(refused.items())))
        self.refused = refused


def _norm_rva(value) -> str | None:
    try:
        return hex(int(str(value), 0))
    except (TypeError, ValueError):
        return None


def _thread(event: dict):
    return (event.get("process_id"), event.get("thread_id"))


def _hook(event: dict):
    payload = event.get("payload") or {}
    return payload.get("hook")


def _matches(index: int, phase: dict, event: dict) -> bool:
    """A stage marker is its open hook; when the hook reports a `stage` number it must be this stage's (1-based) position."""
    if _hook(event) != phase["open"]:
        return False
    number = (event.get("payload") or {}).get("stage")
    return number is None or number == index + 1


def annotate(events: list[dict], profile, *, strict: bool = False) -> tuple[list[dict], dict]:
    """(events with frame/phase/role stamped, a report of what was and was not resolved). EVENTS are not modified.

    The native twin gives the same answer; whatever it does not understand (an event or profile of an unexpected shape) it
    refuses and this function then runs the Python below, which answers or raises exactly as it always did."""
    if _annotate_events is not None and type(events) is list and os.environ.get("HYDRALYSIS_NATIVE", "1") != "0":
        try:
            data = profile.data
            out, report = _annotate_events(events, list(data.get("roles", [])), list(data.get("phases", [])), strict, _norm_rva)
        except Exception:  # noqa: BLE001 - the Python implementation is the specification and the fallback
            pass
        else:
            if out is None:
                raise RoleResolverRefused(report["refused_resolvers"])
            return out, report
    return annotate_python(events, profile, strict=strict)


def annotate_python(events: list[dict], profile, *, strict: bool = False) -> tuple[list[dict], dict]:
    """`annotate` in Python (the specification the native twin is tested against)."""
    data = profile.data
    roles = data.get("roles", [])
    phases = data.get("phases", [])
    frame_phases = [p for p in phases if p["kind"] == "frame"]
    stages = [p for p in phases if p["kind"] == "stage"]
    stage_ids = [p["id"] for p in stages]
    # evidence for the resolvers that look at how a thread started
    starts: dict = {}
    for event in events:
        if event.get("kind") in ("core.thread.start", "core.marker"):
            payload = event.get("payload") or {}
            seen = starts.setdefault(_thread(event), {"rva": set(), "name": set()})
            if payload.get("start_rva") is not None and _norm_rva(payload["start_rva"]) is not None:
                seen["rva"].add(_norm_rva(payload["start_rva"]))
            if isinstance(payload.get("name"), str) and (event.get("kind") == "core.thread.start" or payload.get("thread_name")):
                seen["name"].add(payload["name"])
    refused: dict = {}
    for role in roles:
        kind = role["resolve"]
        if kind == "pool":
            refused[role["id"]] = "the pool resolver is not evaluated by any producer"
        elif kind == "thread_start_rva" and not any(v["rva"] for v in starts.values()):
            refused[role["id"]] = "no core.thread.start event carries payload.start_rva"
        elif kind == "thread_name" and not any(v["name"] for v in starts.values()):
            refused[role["id"]] = "no core.thread.start event carries payload.name"
    if strict and refused:
        raise RoleResolverRefused(refused)
    unsupported = sorted({r["resolve"] for r in roles if r["id"] in refused})

    # ---- roles: the threads that ran the resolver's hook ---------------------------------------------------------------
    ran: dict = {}
    for event in events:
        hook = _hook(event)
        if hook is not None:
            ran.setdefault(_thread(event), set()).add(hook)
    thread_role: dict = {}
    for thread, hooks in ran.items():
        found = sorted(r["id"] for r in roles if r["resolve"] == "function" and r["value"] in hooks)
        thread_role[thread] = found
    for thread, seen in starts.items():
        extra = sorted(r["id"] for r in roles if (r["resolve"] == "thread_start_rva" and _norm_rva(r["value"]) in seen["rva"])
                       or (r["resolve"] == "thread_name" and r["value"] in seen["name"]))
        thread_role[thread] = sorted(set(thread_role.get(thread, [])) | set(extra))
    # ---- frames and stages, per thread, in the thread's own order -------------------------------------------------------
    by_thread: dict = {}
    for index, event in enumerate(events):
        if _hook(event) is not None:
            by_thread.setdefault(_thread(event), []).append(index)
    stamp: dict = {}          # index -> (frame, phase, unresolved)
    for thread, indexes in by_thread.items():
        frame = None
        seen: list = []       # (stage index, event index) of the markers in this frame
        run: list = []        # event indexes of the current frame, in order
        frame_closed = True

        def settle(frame_number, items, markers):
            """Attribute phases of one frame's events from the markers it showed."""
            positions = {event_index: pos for pos, (_k, event_index) in enumerate(markers)}
            for event_index in items:
                unresolved = {}
                phase = None
                if not stages:
                    unresolved["phase"] = "the profile declares no stage markers"
                elif not markers:
                    unresolved["phase"] = "thread-has-no-stage-marker"
                else:
                    before = [(k, i) for k, i in markers if i <= event_index]
                    after = [(k, i) for k, i in markers if i > event_index]
                    prev_k = before[-1][0] if before else None
                    next_k = after[0][0] if after else None
                    lo = -1 if prev_k is None else prev_k
                    hi = len(stage_ids) if next_k is None else next_k
                    # stages declared between the neighbouring markers that never opened
                    gone = [stage_ids[j] for j in range(lo + 1, hi) if j not in {k for k, _i in markers}]
                    if prev_k is None:
                        unresolved["phase"] = ("missing-marker:" + ",".join(gone)) if gone and next_k is not None else "before-first-stage-marker"
                    elif next_k is not None and gone:
                        unresolved["phase"] = "missing-marker:" + ",".join(gone)
                    else:
                        phase = stage_ids[prev_k]
                if event_index in positions:
                    phase = stage_ids[markers[positions[event_index]][0]]
                    unresolved.pop("phase", None)
                stamp[event_index] = (frame_number, phase, unresolved)

        for index in indexes:
            event = events[index]
            payload = event.get("payload") or {}
            opener = next((p for p in frame_phases if _hook(event) == p["open"]), None)
            closer = next((p for p in frame_phases if _hook(event) == p["close"] and p["close"] != p["open"]), None)
            stage_hit = next((j for j, p in enumerate(stages) if _matches(j, p, event)), None)
            if opener is not None:
                if run:
                    settle(frame, run, seen)
                frame = payload.get("frame")
                frame_closed = False
                seen, run = [], []
            if stage_hit is not None:
                seen.append((stage_hit, index))
            if frame is not None and not frame_closed:
                run.append(index)
            else:
                stamp[index] = (payload.get("frame"), None, {"frame": "outside-frame" if frame_closed and frame_phases else "thread-has-no-frame-marker",
                                                              "phase": "outside-frame"})
            if closer is not None:
                settle(frame, run, seen)
                run, seen, frame_closed = [], [], True
        if run:
            settle(frame, run, seen)

    counts = {"events": 0, "frame": 0, "phase": 0, "role": 0}
    out = []
    for index, event in enumerate(events):
        if _hook(event) is None:
            out.append(event)
            continue
        payload = dict(event.get("payload") or {})
        frame, phase, unresolved = stamp.get(index, (None, None, {}))
        counts["events"] += 1
        unresolved = dict(unresolved)
        if isinstance(payload.get("frame"), int):
            frame = payload["frame"]                      # the hook observed its own frame argument
            unresolved.pop("frame", None)
        if frame is not None:
            payload["frame"] = frame
            counts["frame"] += 1
        elif "frame" not in unresolved:
            unresolved["frame"] = "no frame marker on this thread"
        if phase is not None:
            payload["phase"] = phase
            counts["phase"] += 1
        elif "phase" not in unresolved:
            unresolved["phase"] = "thread-has-no-stage-marker"
        found = thread_role.get(_thread(event), [])
        if len(found) == 1:
            payload["role"] = found[0]
            counts["role"] += 1
        elif len(found) > 1:
            unresolved["role"] = "ambiguous: " + ",".join(found)
        else:
            unresolved["role"] = ("no role resolver matched this thread (unsupported resolvers: %s)" % ", ".join(unsupported)
                                  if unsupported else "no role resolver matched this thread")
        if unresolved:
            payload["unresolved"] = unresolved
        out.append({**event, "payload": payload})
    return out, {"counts": counts, "unsupported_role_resolvers": unsupported, "refused_resolvers": refused,
                 "roles": {"%s/%s" % thread: roles for thread, roles in sorted(thread_role.items(), key=lambda kv: str(kv[0]))}}
