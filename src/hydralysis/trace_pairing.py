"""Pairing an owner session with a replica session: correlation, clock calibration, three-valued results.

Two sessions record on different clocks. Shared markers (events both sides emit, matched by a correlation key)
give pairs ``(t_owner, t_replica)``; a least-squares line ``t_owner = a + b * t_replica`` maps one clock to the
other, with the residual spread as uncertainty. Every comparison answers ``true``, ``false`` or ``unknown``: when the
clocks cannot be calibrated, or an outage covers the point, the answer is ``unknown`` and never a guess.
"""
from __future__ import annotations

from dataclasses import dataclass

TRUE, FALSE, UNKNOWN = "true", "false", "unknown"
MIN_MARKERS = 3
MIN_DRIFT_SPAN_NS = 1_000_000_000   # markers closer together than this cannot tell a drift from noise


@dataclass(frozen=True)
class Calibration:
    ok: bool
    offset_ns: float = 0.0
    drift: float = 1.0           # replica ns to owner ns
    uncertainty_ns: float = 0.0  # max abs residual
    markers: int = 0
    reason: str = ""
    drift_estimated: bool = True  # False: the markers span too little time, drift is assumed to be 1

    def to_owner(self, t_replica: float) -> float:
        return self.offset_ns + self.drift * t_replica


def correlate(owner_events: list[dict], replica_events: list[dict], key=lambda e: (e.get("payload") or {}).get("marker")) -> list[tuple[dict, dict]]:
    """Pairs of events with the same non-empty correlation key; a key seen more than once on either side is ambiguous
    and left out."""
    def index(events):
        out: dict = {}
        for e in events:
            k = key(e)
            if k is not None:
                out.setdefault(k, []).append(e)
        return out

    o, r = index(owner_events), index(replica_events)
    return [(o[k][0], r[k][0]) for k in o if k in r and len(o[k]) == 1 and len(r[k]) == 1]


def calibrate(pairs: list[tuple[dict, dict]], min_drift_span_ns: float = MIN_DRIFT_SPAN_NS) -> Calibration:
    pts = [(float(r["t_mono_ns"]), float(o["t_mono_ns"])) for o, r in pairs if "t_mono_ns" in o and "t_mono_ns" in r]
    if len(pts) < MIN_MARKERS:
        return Calibration(False, markers=len(pts), reason=f"need {MIN_MARKERS} shared markers, have {len(pts)}")
    n = len(pts)
    if max(x for x, _ in pts) - min(x for x, _ in pts) < min_drift_span_ns:
        # A drift cannot be told from noise over a short span: assume the clocks run at one rate, say so, and let the
        # offset spread carry the uncertainty.
        offsets = sorted(y - x for x, y in pts)
        offset = offsets[n // 2]
        return Calibration(True, offset, 1.0, max(abs(o - offset) for o in offsets), n, "drift not estimable from markers "
                           "spanning %d ns; assumed 1" % int(max(x for x, _ in pts) - min(x for x, _ in pts)), False)
    mx, my = sum(x for x, _ in pts) / n, sum(y for _, y in pts) / n
    sxx = sum((x - mx) ** 2 for x, _ in pts)
    if sxx == 0:
        return Calibration(False, markers=n, reason="markers do not span any time")
    b = sum((x - mx) * (y - my) for x, y in pts) / sxx
    a = my - b * mx
    spread = max(abs(y - (a + b * x)) for x, y in pts)
    return Calibration(True, a, b, spread, n, "", True)


@dataclass(frozen=True)
class Outage:
    start_ns: float  # owner clock
    end_ns: float


def ordered_before(cal: Calibration, t_owner: float, t_replica: float, outages: list[Outage] | None = None) -> str:
    """Did the owner event happen before the replica event? ``unknown`` if uncalibrated, within uncertainty, or in an outage."""
    if not cal.ok:
        return UNKNOWN
    mapped = cal.to_owner(t_replica)
    for o in outages or []:
        if o.start_ns <= t_owner <= o.end_ns or o.start_ns <= mapped <= o.end_ns:
            return UNKNOWN
    gap = mapped - t_owner
    if abs(gap) <= cal.uncertainty_ns:
        return UNKNOWN
    return TRUE if gap > 0 else FALSE


def both_observed(owner_has: bool | None, replica_has: bool | None) -> str:
    """Three-valued AND of 'this side observed the event'; ``None`` means the side could not say (outage, refusal)."""
    if owner_has is False or replica_has is False:
        return FALSE
    if owner_has is None or replica_has is None:
        return UNKNOWN
    return TRUE


def pair(owner_events: list[dict], replica_events: list[dict], outages: list[Outage] | None = None,
         key=lambda e: (e.get("payload") or {}).get("marker")) -> dict:
    pairs = correlate(owner_events, replica_events, key)
    cal = calibrate(pairs)
    return {"roles": {"owner": "authoritative order", "replica": "mapped onto the owner clock"},
            "calibration": cal, "pairs": len(pairs), "outages": len(outages or []),
            "usable": cal.ok}


# ---- the report of a pairing (spec 15.5) ----------------------------------------------------------------------------------

DEFAULT_SPEC = {"owner_sync": "app.sync", "replica_sync": "app.sync_recv", "sync_key": "n", "truth": "app.truth",
                "mirror": "app.mirror", "extrapolated": "app.extrapolated", "create": "app.create", "key": "obj", "seq": "seq",
                "value": "value", "gap_factor": 5, "min_gap_ns": 200_000_000, "max_error": None,
                "latency_allowance_ns": 20_000_000}


def _quantile(sorted_values: list[float], q: float) -> float:
    return sorted_values[min(len(sorted_values) - 1, int(q * len(sorted_values)))]


def _p(event: dict, name: str):
    return (event.get("payload") or {}).get(name)


def pair_report(owner_events: list[dict], replica_events: list[dict], spec: dict | None = None) -> dict:
    """Owner and replica sessions captured at the same time, compared per correlated object (spec 15.5).

    Events are `{event_id, kind, t_mono_ns, payload}`. The clock relation comes from the shared sync markers
    (`spec.owner_sync` / `spec.replica_sync`, matched by `payload[sync_key]`) and is reported with its uncertainty. For each
    object (`payload[key]`) with truth events on the owner (`spec.truth`) and mirror events on the replica (`spec.mirror`) in
    the same schema (`seq`, `value`): the lag of every reflected value, the value error over time, divergence intervals (when
    `max_error` is given), the replica's extrapolated frames, and objects present on one side only. Every owner value gets one
    of three answers: `reflected`, `not_reflected` (the replica was reporting and did not mirror it) or `unknown` (the replica
    stopped reporting over the interval that would have shown it, or its observation ended before it): silence is never
    agreement."""
    spec = {**DEFAULT_SPEC, **(spec or {})}
    key, seq_name, value_name = spec["key"], spec["seq"], spec["value"]
    syncs_o = [e for e in owner_events if e.get("kind") == spec["owner_sync"]]
    syncs_r = [e for e in replica_events if e.get("kind") == spec["replica_sync"]]
    cal = calibrate(correlate(syncs_o, syncs_r, lambda e: _p(e, spec["sync_key"])))
    out: dict = {"mode": "pair", "roles": {"owner": "authoritative order", "replica": "mapped onto the owner clock"},
                 "calibration": {"ok": cal.ok, "markers": cal.markers, "offset_ns": int(cal.offset_ns), "drift": cal.drift,
                                 "drift_estimated": cal.drift_estimated, "uncertainty_ns": int(cal.uncertainty_ns) + int(spec["latency_allowance_ns"]),
                                 "spread_ns": int(cal.uncertainty_ns),
                                 "units": "ns (monotonic clock of each side)", "reason": cal.reason}}
    if not cal.ok:
        out.update(usable=False, objects={}, note="the clocks could not be calibrated (%s): nothing is compared, every answer is "
                   "unknown" % cal.reason)
        return out
    truths = [e for e in owner_events if e.get("kind") == spec["truth"]]
    creates = [e for e in owner_events if e.get("kind") == spec["create"]]
    mirrors = [e for e in replica_events if e.get("kind") == spec["mirror"]]
    extrapolated = [e for e in replica_events if e.get("kind") == spec["extrapolated"]]

    def mapped(event: dict) -> float:
        return cal.to_owner(float(event["t_mono_ns"]))

    objects: dict = {}
    on_owner = {str(_p(e, key)) for e in truths + creates}
    on_replica = {str(_p(e, key)) for e in mirrors + extrapolated}
    for obj in sorted(on_owner | on_replica, key=lambda v: (len(v), v)):
        entry: dict = {"present_on": [side for side, there in (("owner", obj in on_owner), ("replica", obj in on_replica)) if there]}
        if obj not in on_replica:
            entry["status"] = "owner_only"
            first = next((e for e in creates + truths if str(_p(e, key)) == obj), None)
            entry["first_event"] = first["event_id"] if first else None
            objects[obj] = entry
            continue
        if obj not in on_owner:
            entry["status"] = "replica_only"
            objects[obj] = entry
            continue
        own = sorted((e for e in truths if str(_p(e, key)) == obj), key=lambda e: e["t_mono_ns"])
        rep = sorted((e for e in mirrors if str(_p(e, key)) == obj), key=lambda e: e["t_mono_ns"])
        mirrored: dict = {}
        for e in rep:
            mirrored.setdefault(_p(e, seq_name), e)
        # outages: the replica stopped reporting for longer than it ever does
        times = [mapped(e) for e in rep]
        spacing = sorted(b - a for a, b in zip(times, times[1:]))
        median = spacing[len(spacing) // 2] if spacing else 0.0
        threshold = max(float(spec["min_gap_ns"]), float(spec["gap_factor"]) * median)
        outages = [{"start_owner_ns": int(a), "end_owner_ns": int(b), "silent_ns": int(b - a), "from_event": ra["event_id"],
                    "to_event": rb["event_id"]} for a, b, ra, rb in zip(times, times[1:], rep, rep[1:]) if b - a > threshold]
        lags = sorted(mapped(mirrored[_p(e, seq_name)]) - float(e["t_mono_ns"]) for e in own if _p(e, seq_name) in mirrored)
        typical = _quantile(lags, 0.5) if lags else 0.0
        results = {"reflected": 0, "not_reflected": 0, "unknown": 0}
        unknown_events, not_reflected_events = [], []
        for e in own:
            if _p(e, seq_name) in mirrored:
                results["reflected"] += 1
                continue
            expected = float(e["t_mono_ns"]) + typical
            inside = any(o["start_owner_ns"] <= expected <= o["end_owner_ns"] for o in outages)
            beyond = not times or expected > times[-1]
            if inside or beyond:
                results["unknown"] += 1
                unknown_events.append(e["event_id"])
            else:
                results["not_reflected"] += 1
                not_reflected_events.append(e["event_id"])
        owner_values = [(float(e["t_mono_ns"]), _p(e, value_name)) for e in own]
        errors = []
        for e in rep:
            now = mapped(e)
            known = [v for t, v in owner_values if t <= now]
            mirrored_value = _p(e, value_name)
            if known and isinstance(known[-1], (int, float)) and isinstance(mirrored_value, (int, float)):
                errors.append((now, known[-1] - mirrored_value, e["event_id"]))
        entry.update(
            status="paired", truth_events=len(own), mirror_events=len(rep), answers=results,
            lag_ns={"count": len(lags), "min": int(lags[0]), "p50": int(typical), "p95": int(_quantile(lags, 0.95)),
                    "max": int(lags[-1])} if lags else None,
            delay_estimate_ns=int(_quantile(lags, 0.05)) if lags else None,
            delay_estimate_basis="the floor (5th percentile) of the lag distribution: scheduling slop only adds to a delay", delay_uncertainty_ns=int(cal.uncertainty_ns) + int(spec["latency_allowance_ns"]),
            delay_uncertainty_basis="offset spread over the sync markers plus an allowance for the one-way transport latency "
                                    "the markers cannot separate from the clock offset",
            outages=[{**o, "answer": "unknown", "meaning": "the replica reported nothing here; that is not agreement"}
                     for o in outages],
            unknown_events=unknown_events[:20], unknown_total=len(unknown_events),
            not_reflected_events=not_reflected_events[:20], not_reflected_total=len(not_reflected_events))
        if errors:
            magnitudes = [abs(v) for _, v, _ in errors]
            entry["value_error"] = {"max_abs": max(magnitudes), "mean_abs": sum(magnitudes) // len(magnitudes),
                                    "samples": len(errors),
                                    "meaning": "the owner's latest value at the mirror's mapped time minus the mirror's value"}
            if spec.get("max_error") is not None:
                runs: list = []
                current = None
                for t, v, event_id in errors:
                    bad = abs(v) > spec["max_error"]
                    if bad and current is None:
                        current = {"start_owner_ns": int(t), "first_event": event_id, "samples": 0}
                    if bad:
                        current.update(end_owner_ns=int(t), last_event=event_id)
                        current["samples"] += 1
                    elif current is not None:
                        runs.append(current)
                        current = None
                if current is not None:
                    runs.append(current)
                entry["divergence_intervals"] = runs
        objects[obj] = entry
    out.update(usable=True, objects=objects,
               extrapolated={"count": len(extrapolated), "events": [e["event_id"] for e in extrapolated[:10]],
                             "meaning": "ticks where the replica showed a value it extrapolated, without owner data"},
               owner_only=[o for o, v in objects.items() if v.get("status") == "owner_only"],
               replica_only=[o for o, v in objects.items() if v.get("status") == "replica_only"],
               note="three-valued per owner value: reflected, not_reflected, unknown; a silent replica is never agreement")
    return out
