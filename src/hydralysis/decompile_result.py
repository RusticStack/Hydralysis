"""Partial decompile results: carry the engine's `fragments`, `truncated`, `bytes_emitted` and `reason` through.

An engine that stops a decompile at a size bound (`max_result_mb`, or its own cap) or finds that part of a function is
not code replies with

    {"truncated": true, "bytes_emitted": 1048576, "reason": "max_result_mb",
     "fragments": [{"start": "0x140001000", "end": "0x140001040", "class": "code"}, {... "class": "data"}, ...]}

`fragments` partition the function body by what the bytes are (`code`, `data` or `unknown`; a jump table or a
literal pool is data, not instructions). Such a reply is a PARTIAL result, not a failure: it says what was decoded and
why it stops. This module validates those fields, summarises them, and turns them into the evidence `coverage` object
so a claim built from a partial decompile says `partial` with a limitation code instead of passing for complete.
Replies from an engine that does not send the fields are unchanged.
"""

from __future__ import annotations

import json

CLASSES = ("code", "data", "unknown")
MAX_FRAGMENTS = 4096
LIMIT_TRUNCATED = "decompile_truncated"
LIMIT_NON_CODE = "non_code_fragments"
LIMIT_BUDGET = "decompile_budget_limited"   # the engine's adaptive budget (the caller named no cap) stopped the answer
LIMIT_PAGED = "decompile_paged"             # this is one page of the text; next_offset says where the rest starts


def _address(value):
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if value >= 0 else None
    try:
        number = int(str(value), 0)
    except (TypeError, ValueError):
        return None
    return number if number >= 0 else None


def fragments(value) -> tuple[list[dict], str]:
    """(well-formed fragments in the engine's order, "" or why some were dropped). Start and end are kept as sent."""
    if value is None:
        return [], ""
    if not isinstance(value, list):
        return [], "fragments is not a list"
    kept, bad = [], 0
    for item in value[:MAX_FRAGMENTS]:
        start = _address(item.get("start")) if isinstance(item, dict) else None
        end = _address(item.get("end")) if isinstance(item, dict) else None
        if start is None or end is None or end < start or item.get("class") not in CLASSES:
            bad += 1
            continue
        row = {"start": item["start"], "end": item["end"], "class": item["class"]}
        if isinstance(item.get("decompiled"), bool):
            row["decompiled"] = item["decompiled"]
        kept.append(row)
    note = []
    if bad:
        note.append("%d malformed fragment(s) dropped" % bad)
    if len(value) > MAX_FRAGMENTS:
        note.append("only the first %d fragments are kept" % MAX_FRAGMENTS)
    return kept, "; ".join(note)


def summarize(reply: dict) -> dict:
    """What the engine said about completeness: `partial`, `reason`, `bytes_emitted` and the fragment byte totals.

    Empty when the reply carries none of the fields (an engine without them) and is not truncated, so old replies stay as they were."""
    if not isinstance(reply, dict):
        return {}
    # `truncated: false` alone is what an engine without the new fields always said: nothing to add then.
    if not (reply.get("truncated") is True or any(name in reply for name in ("fragments", "bytes_emitted", "reason", "cut", "budget", "next_offset", "partial"))):
        return {}
    kept, note = fragments(reply.get("fragments"))
    # The engine's own `partial` (a body in several pieces, some of it not code) is a partial result even when nothing was cut off.
    out: dict = {"partial": reply.get("truncated") is True or reply.get("partial") is True}
    if isinstance(reply.get("reason"), str) and reply["reason"]:
        out["reason"] = reply["reason"][:200]
    emitted = reply.get("bytes_emitted")
    if isinstance(emitted, int) and not isinstance(emitted, bool) and emitted >= 0:
        out["bytes_emitted"] = emitted
    if isinstance(reply.get("cut"), dict):
        out["cut"] = {key: reply["cut"][key] for key in ("kind", "response_bytes_read", "c_recovered", "c_chars", "c_lines", "c_returned_chars")
                      if key in reply["cut"]}
    if isinstance(reply.get("budget"), dict):
        out["budget"] = {key: reply["budget"][key] for key in ("mode", "bytes", "mb", "in_flight") if key in reply["budget"]}
    for name in ("offset", "next_offset"):
        value = reply.get(name)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
            out[name] = value
    if "next_offset" in out:
        out["partial"] = True
    if "fragments" in reply:
        totals = {name: 0 for name in CLASSES}
        for item in kept:
            totals[item["class"]] += _address(item["end"]) - _address(item["start"])
        out["fragment_bytes"] = totals
        out["fragment_count"] = len(kept)
        if note:
            out["fragments_note"] = note
    return out


def annotate(reply: dict) -> dict:
    """Add `decompile` (the summary) to a decompile reply that carries the new fields; the fields themselves stay."""
    summary = summarize(reply)
    if summary:
        reply["decompile"] = summary
    return reply


def limitations(reply: dict) -> list[str]:
    summary = summarize(reply)
    codes = []
    if reply.get("truncated") is True:
        # A cut by the engine's own adaptive budget (the caller set no cap) is budget-limited; by a cap the caller set, truncated.
        auto = (reply.get("budget") or {}).get("mode") == "auto" if isinstance(reply.get("budget"), dict) else False
        codes.append(LIMIT_BUDGET if auto else LIMIT_TRUNCATED)
    if isinstance(summary.get("next_offset"), int):
        codes.append(LIMIT_PAGED)
    if (summary.get("fragment_bytes") or {}).get("data") or (summary.get("fragment_bytes") or {}).get("unknown"):
        codes.append(LIMIT_NON_CODE)
    return codes


def _coverage_codes(reply: dict) -> list[str]:
    codes = limitations(reply)
    if reply.get("truncated") is True:
        codes = [code for code in codes if code != LIMIT_NON_CODE]   # a cut-off reply is named for the cut, as before
    return codes or [LIMIT_NON_CODE]


def coverage(reply: dict) -> dict:
    """The evidence coverage for a claim read from this decompile: `partial` when it stopped, else complete.

    A reply without the engine's fields says `unknown`: there is nothing to base completeness on."""
    summary = summarize(reply)
    if not summary:
        return {"status": "unknown", "reason": "the decompile reply carries no truncated/fragments fields"}
    if summary["partial"]:
        # A cut-off reply says so; one that only has pieces of data in its body (nothing cut) says that.
        return {"status": "partial", "limitations": _coverage_codes(reply)}
    return {"status": "complete"}


def merge(response: dict, reply: dict) -> dict:
    """RESPONSE (RusticQuery's answer) with the engine's `decompile` REPLY folded in.

    The engine's `partial`, `reason`, `fragments`, `bytes_emitted` and `truncated` win. A reply that did not complete because of
    the size bound is a partial result without text (`ok` false, `truncated` true: `from_error` turns it into one). When
    RusticQuery failed and the engine decompiled, the engine's text and signature stand in for it."""
    if not isinstance(reply, dict):
        return response
    carried = {name: reply[name] for name in ("partial", "reason", "fragments", "bytes_emitted", "cut", "budget", "offset", "next_offset")
               if name in reply}
    if reply.get("completed") is False and reply.get("truncated") is True:
        keep = {name: response[name] for name in ("id", "program", "sha256", "image_base", "address_kind", "overlay_state", "engine", "function")
                if name in response}
        text = {name: reply[name] for name in ("c", "signature", "chars") if name in reply}
        return {**keep, "ok": False, "truncated": True, "error": reply.get("error", "decompile stopped at the size bound"), **text, **carried}
    if reply.get("completed") is not True or not isinstance(reply.get("c"), str):
        return response
    merged = dict(response)
    if response.get("ok") is False:
        merged = {name: response[name] for name in ("id", "program", "sha256", "image_base", "address_kind", "overlay_state", "engine")
                  if name in response}
        merged.update(ok=True, c=reply["c"], function={"address": reply.get("entry"), "name": reply.get("name"),
                                                       "signature": reply.get("signature")})
        merged["total_characters"] = reply.get("chars", len(reply["c"]))
        merged["max_characters"] = len(reply["c"])
    merged.update(carried)
    if "offset" in reply:
        # A page of the text: the engine's page replaces the script's whole (clipped) text.
        merged.update(c=reply["c"], total_characters=reply.get("chars", len(reply["c"])), max_characters=len(reply["c"]))
    clipped = bool(response.get("truncated") if response.get("ok") is not False else False) and "offset" not in reply
    merged["truncated"] = clipped or reply.get("truncated") is True
    return merged


def from_error(message: str) -> dict | None:
    """The reply behind a RuntimeError message when it is a partial decompile (truncated with text, bytes or fragments)."""
    try:
        reply = json.loads(message)
    except (TypeError, ValueError):
        return None
    if (not isinstance(reply, dict) or reply.get("truncated") is not True
            or not (isinstance(reply.get("c"), str) or reply.get("fragments") or "bytes_emitted" in reply or "cut" in reply)):
        return None
    return reply
