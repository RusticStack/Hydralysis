"""Verify a profile's hooks against the exact builds it is bound to (plan decision 9; spec 5.1).

Reuses `prologue` and the signature scan of `sigscan`. A hook is *verified* only when its image is a listed build of the
right bitness, its locator resolves to one site, and the bytes there equal the profile's exact prologue. Otherwise it is
*refused*, never guessed:

* a `required` hook that is refused refuses the dependent capability (`require` raises `HookRefused`);
* an `optional` hook that is refused is recorded as a coverage limitation with the code `optional-hook-refused`, so a
  session that ran without it never looks the same as one that ran with it.
"""

from __future__ import annotations

import re
from pathlib import Path

from hydralysis.prologue import find_pattern, matches, parse_expect

REASONS = ("module-unknown", "build-not-listed", "bitness-mismatch", "symbol-not-found", "signature-not-found",
           "signature-ambiguous", "outside-image", "prologue-mismatch")


class HookRefused(RuntimeError):
    """A required hook did not verify; the session or capability it belongs to is refused."""

    code = "required_hook_refused"

    def __init__(self, refusals: list[dict]):
        super().__init__("required hook(s) refused: " + ", ".join("%s (%s)" % (r["hook"], r["reason"]) for r in refusals))
        self.refusals = refusals

    def payload(self) -> dict:
        return {"error": self.code, "message": str(self), "refusals": self.refusals}


_MAP_LINE = re.compile(r"^\s*[0-9a-f]{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8,16})\s+(f\s)?", re.I)


def _map_rva(image, symbol: str) -> int | None:
    """The RVA of SYMBOL in the linker map (`<image stem>.map`) beside the image. Only a fixtures-only profile may use
    this: the fixtures are built without a PDB and their map is the ground truth for their internal functions. A shipped
    program has no map, so a real profile names an export, a signature or a build-bound RVA instead."""
    path = getattr(image, "path", None)
    if path is None:
        return None
    candidate = Path(path).with_suffix(".map")
    try:
        text = candidate.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    base = int(getattr(getattr(image.pe, "OPTIONAL_HEADER", None), "ImageBase", 0) or 0)
    for line in text.splitlines():
        match = _MAP_LINE.match(line)
        if match and match.group(3) and match.group(1).lstrip("_") == symbol:
            return int(match.group(2), 16) - base
    return None


def _export_rva(image, symbol: str, fixtures_only: bool = False) -> int | None:
    custom = getattr(image, "export_rva", None)
    if callable(custom):
        return custom(symbol)
    from hydralysis.pe import pefile
    image.pe.parse_data_directories(directories=[pefile().DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_EXPORT"]])
    directory = getattr(image.pe, "DIRECTORY_ENTRY_EXPORT", None)
    for item in getattr(directory, "symbols", ()) or ():
        if item.name and item.name.decode("utf-8", "replace") == symbol:
            return int(item.address)
    return _map_rva(image, symbol) if fixtures_only else None


def _signature_hits(image, signature: str) -> list[int]:
    pattern = parse_expect(signature)
    hits: list[int] = []
    for section in image._executable():
        raw = image.data[section.PointerToRawData: section.PointerToRawData + section.SizeOfRawData]
        hits += [section.VirtualAddress + offset for offset in find_pattern(raw, pattern, 3 - len(hits))]
        if len(hits) > 1:
            break
    return hits


def _check_hook(hook: dict, image, build_ok: bool, fixtures_only: bool = False) -> tuple[int | None, str, dict]:
    """(rva, reason, detail): reason is "" when the hook verified."""
    if "rva" in hook and not build_ok:
        return None, "build-not-listed", {}
    if "symbol" in hook:
        rva = _export_rva(image, hook["symbol"], fixtures_only)
        if rva is None:
            return None, "symbol-not-found", {}
    elif "signature" in hook:
        hits = _signature_hits(image, hook["signature"])
        if not hits:
            return None, "signature-not-found", {}
        if len(hits) > 1:
            return None, "signature-ambiguous", {"hits": ["rva:%#x" % hit for hit in hits]}
        rva = hits[0]
    else:
        rva = hook["rva"]
    site = rva + hook["prologue_offset"]
    patterns = [parse_expect(text) for text in hook["prologue"]]
    need = max(len(pattern) for pattern in patterns)
    if image.rva_to_offset(site) is None or need > image._available(site):
        return rva, "outside-image", {}
    actual = image.read_rva(site, need)
    for index, pattern in enumerate(patterns):
        if matches(actual, pattern):
            return rva, "", {"matched_alternative": index}
    return rva, "prologue-mismatch", {"actual": " ".join("%02X" % byte for byte in actual)}


def verify_profile(profile, images: dict) -> dict:
    """Check every hook. IMAGES maps a module name (case-insensitive) to its `pe.Image`.

    A fixtures-only profile holds one section per fixture program: a hook whose module was not supplied is
    `not-applicable` (neither verified nor refused). Any other profile refuses it as `module-unknown`.

    The result is data: `ok` (no required hook refused), per-hook `status`, `refusals` (required), `limitations`
    (optional, as coverage limitation records) and the ids of the `enabled` hooks. Nothing is modified."""
    by_name = {str(name).lower(): image for name, image in images.items()}
    listed = {(build["module"].lower(), build["image_sha256"]) for build in profile.data["target"]["builds"]}
    bits = profile.data["target"]["bitness"]
    fixtures_only = bool(profile.data["target"].get("fixtures_only"))
    module_state: dict[str, dict] = {}
    for module in {hook["module"].lower() for hook in profile.data["hooks"]}:
        image = by_name.get(module)
        if image is None:
            module_state[module] = {"reason": "module-unknown"}
            continue
        digest = image.fingerprint()["sha256"]
        state = {"image": image, "sha256": digest, "build_ok": (module, digest) in listed}
        if getattr(image, "bits", bits) != bits:
            state["reason"] = "bitness-mismatch"
        elif listed and not state["build_ok"]:
            state["reason"] = "build-not-listed"
        module_state[module] = state

    rows, refusals, limitations, enabled = [], [], [], []
    for hook in profile.data["hooks"]:
        state = module_state[hook["module"].lower()]
        row = {"hook": hook["id"], "event": hook["event"], "module": hook["module"], "required": hook["required"],
               "fault": hook["fault"]}
        if fixtures_only and state.get("reason") == "module-unknown":
            # the fixtures profile is the union of one section per fixture program; a run supplies the images it uses
            rows.append({**row, "status": "not-applicable", "reason": "module-not-supplied"})
            continue
        if "reason" in state:
            reason, rva, detail = state["reason"], None, {}
        else:
            rva, reason, detail = _check_hook(hook, state["image"], state["build_ok"], fixtures_only)
        if reason:
            row.update(status="refused", reason=reason, **detail)
            entry = {"hook": hook["id"], "event": hook["event"], "reason": reason, "required": hook["required"]}
            if hook["required"]:
                refusals.append(entry)
            else:
                limitations.append({"code": "optional-hook-refused", "hook": hook["id"], "event": hook["event"],
                                    "reason": reason})
        else:
            row.update(status="verified", rva="rva:%#x" % rva, image_sha256=state["sha256"], **detail)
            enabled.append(hook["id"])
        rows.append(row)
    return {"profile": profile.id, "profile_sha256": profile.sha256, "ok": not refusals, "hooks": rows,
            "enabled": enabled, "refusals": refusals, "limitations": limitations,
            "counts": {"verified": len(enabled), "refused_required": len(refusals), "refused_optional": len(limitations)}}


def require(result: dict) -> dict:
    """RESULT when every required hook verified; otherwise raise `HookRefused` naming each refusal."""
    if not result["ok"]:
        raise HookRefused(result["refusals"])
    return result
