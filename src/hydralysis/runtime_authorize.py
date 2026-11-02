"""Owner-authorized runtime memory mode (issue #7): the allow-list, its range check and the per-build stamp.

`write` and `watch` are FIXTURE-ONLY by default (see runtime_memory). An owner who runs an application they are entitled
to instrument may add an entry to the local setting `runtime_authorized_targets`. No other input turns it on: the
caller's options, the target file and the target itself cannot. An entry names

    {"sha256": "<64 hex, the exact build>",
     "actions": ["write", "watch"],            # which of the two this build may use
     "max_size": 8,                            # bytes per write / per watch, 1..64 (a watch is also capped at 8)
     "ranges": [{"module": "Game.exe", "rva_start": "0x1F0000", "rva_end": "0x1F4000"},
                {"va_start": "0x7FF600000000", "va_end": "0x7FF600001000"}],   # bounded, each at most 1 MiB
     "note": "why"}

Everything else of the safety contract is unchanged: compare-and-swap write with a reason, the undo log with DIVERGED,
executable ranges refused, disarm with debug-register readback before detach. A watch additionally needs a per-build
stamp, `<root>/watch-stamps/authorized/<sha256>.json`, written by `tools/watch_conformance.py --bind-build <exe>` after
the conformance matrix passed for that build's architecture and the pinned Frida.
"""

from __future__ import annotations

import re
import struct

MAX_RANGE = 1 << 20
MAX_SIZE = 64
MAX_WATCH_SIZE = 8
ACTIONS = ("write", "watch")
STAMP_VERSION = 1
SHA = re.compile(r"[0-9a-f]{64}")
MACHINES = {0x8664: "x64", 0x14C: "x86"}


class AuthorizationRefused(PermissionError):
    """A refusal with a machine-readable `code` and the `detail` that explains it. str() is `[code] detail`."""

    def __init__(self, code: str, detail: str):
        super().__init__("[%s] %s" % (code, detail))
        self.code, self.detail = code, detail


def _num(value, what: str) -> int:
    try:
        number = int(str(value), 0)
    except (TypeError, ValueError):
        raise ValueError("%s is not a number: %r" % (what, value)) from None
    if number < 0:
        raise ValueError("%s is negative" % what)
    return number


def normalize(entry) -> dict:
    """One validated entry, with its ranges as integers. Raises ValueError saying what is wrong."""
    if not isinstance(entry, dict):
        raise ValueError("an authorization is an object")
    sha = str(entry.get("sha256") or "").lower()
    if not SHA.fullmatch(sha):
        raise ValueError("sha256 must be 64 hex characters (the exact build)")
    actions = entry.get("actions")
    if not isinstance(actions, list) or not actions or any(a not in ACTIONS for a in actions):
        raise ValueError("actions must be a non-empty list of write and/or watch")
    size = entry.get("max_size")
    if isinstance(size, bool) or not isinstance(size, int) or not 1 <= size <= MAX_SIZE:
        raise ValueError("max_size must be an integer 1..%d" % MAX_SIZE)
    ranges = entry.get("ranges")
    if not isinstance(ranges, list) or not ranges:
        raise ValueError("ranges must declare at least one bounded range")
    out = []
    for item in ranges:
        if not isinstance(item, dict):
            raise ValueError("a range is an object")
        if "module" in item:
            module = str(item["module"]).strip()
            if not module or "va_start" in item:
                raise ValueError("a range is module+rva_start+rva_end or va_start+va_end")
            start, end = _num(item.get("rva_start"), "rva_start"), _num(item.get("rva_end"), "rva_end")
            kind = {"module": module.lower()}
        else:
            start, end = _num(item.get("va_start"), "va_start"), _num(item.get("va_end"), "va_end")
            kind = {"module": None}
        if not 0 < end - start <= MAX_RANGE:
            raise ValueError("a range must be 1..%d bytes (start < end)" % MAX_RANGE)
        out.append({**kind, "start": start, "end": end})
    return {"sha256": sha, "actions": sorted(set(actions)), "max_size": size, "ranges": out,
            "note": str(entry.get("note") or "")[:200]}


def lookup(settings: dict, digest: str) -> tuple[dict | None, str]:
    """(normalized entry, "") for the build, or (None, why). Invalid entries for this build are reported, never trusted."""
    listed = settings.get("runtime_authorized_targets")
    if not listed:
        return None, "the setting runtime_authorized_targets is empty or missing"
    if not isinstance(listed, list):
        return None, "runtime_authorized_targets must be a list"
    problem = ""
    for item in listed:
        if not isinstance(item, dict) or str(item.get("sha256") or "").lower() != digest or not digest:
            continue
        try:
            return normalize(item), ""
        except ValueError as exc:
            problem = "the entry for this build is invalid: %s" % exc
    return None, problem or "this build's SHA-256 is not in runtime_authorized_targets"


def check(auth: dict, action: str, address: int, size: int, module: dict | None) -> None:
    """Refuse (AuthorizationRefused) unless the action, size and the whole span are inside a declared range."""
    if action not in auth["actions"]:
        raise AuthorizationRefused("action_not_authorized", "%s is not in this build's authorized actions %s"
                                   % (action, auth["actions"]))
    cap = min(auth["max_size"], MAX_WATCH_SIZE) if action == "watch" else auth["max_size"]
    if size > cap:
        raise AuthorizationRefused("size_exceeds_authorization", "%d bytes exceeds the authorized %d for %s"
                                   % (size, cap, action))
    name = str((module or {}).get("name") or "").lower()
    base = None
    if module and module.get("base") is not None:
        try:
            base = int(str(module["base"]), 0)
        except ValueError:
            base = None
    for rng in auth["ranges"]:
        if rng["module"] is None:
            lo, hi = rng["start"], rng["end"]
        elif name == rng["module"] and base is not None:
            lo, hi = base + rng["start"], base + rng["end"]
        else:
            continue
        if lo <= address and address + size <= hi:
            return
    raise AuthorizationRefused("outside_authorized_range", "span %#x+%d is not inside any declared range of this build"
                               % (address, size))


def pe_arch(path: str) -> str:
    """'x64', 'x86' or '' from the PE header of the file."""
    try:
        with open(path, "rb") as handle:
            head = handle.read(4096)
        offset = struct.unpack_from("<I", head, 0x3C)[0]
        if head[:2] != b"MZ" or head[offset:offset + 4] != b"PE\0\0":
            return ""
        return MACHINES.get(struct.unpack_from("<H", head, offset + 4)[0], "")
    except (OSError, struct.error):
        return ""


def valid_stamp(stamp, digest: str, arch: str, frida: str, iterations: int) -> bool:
    return (isinstance(stamp, dict) and stamp.get("result") == "pass" and stamp.get("target_sha256") == digest
            and stamp.get("arch") == arch and stamp.get("frida") == frida and int(stamp.get("iterations", 0)) >= iterations)
