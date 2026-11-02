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


@dataclass(frozen=True)
class Calibration:
    ok: bool
    offset_ns: float = 0.0
    drift: float = 1.0           # replica ns to owner ns
    uncertainty_ns: float = 0.0  # max abs residual
    markers: int = 0
    reason: str = ""

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


def calibrate(pairs: list[tuple[dict, dict]]) -> Calibration:
    pts = [(float(r["t_mono_ns"]), float(o["t_mono_ns"])) for o, r in pairs if "t_mono_ns" in o and "t_mono_ns" in r]
    if len(pts) < MIN_MARKERS:
        return Calibration(False, markers=len(pts), reason=f"need {MIN_MARKERS} shared markers, have {len(pts)}")
    n = len(pts)
    mx, my = sum(x for x, _ in pts) / n, sum(y for _, y in pts) / n
    sxx = sum((x - mx) ** 2 for x, _ in pts)
    if sxx == 0:
        return Calibration(False, markers=n, reason="markers do not span any time")
    b = sum((x - mx) * (y - my) for x, y in pts) / sxx
    a = my - b * mx
    spread = max(abs(y - (a + b * x)) for x, y in pts)
    return Calibration(True, a, b, spread, n)


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
