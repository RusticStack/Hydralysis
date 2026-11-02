"""From a verified profile to the probe specs the runtime worker arms (`capture start` with `trace.probes`).

Verification (`verify_profile`) proved each hook against the image bytes; this turns the *verified* hooks, and only
those, into plain data: the module, the site (located RVA plus the prologue offset), the build hash, the exact bytes
to expect, how many arguments to record, the buffer to read, how deep a call stack to unwind and which event the
record becomes. The worker repeats the byte check against the live module before it attaches anything, so a profile
cannot arm a probe on a module it was not verified against.
"""

from __future__ import annotations

from hydralysis.prologue import parse_expect


def host_fault_policy(profile, enabled_hooks: list[dict]) -> str:
    """The most restrictive policy among the enabled hooks and the host default (freezes > fatal > tolerant)."""
    order = {"tolerant": 0, "fatal": 1, "freezes": 2}
    chosen = profile.data["host"]["fault_policy"]
    for hook in enabled_hooks:
        if order[hook["fault"]] > order[chosen]:
            chosen = hook["fault"]
    return chosen


def probe_specs(profile, verification: dict) -> list[dict]:
    """One spec per verified hook, in profile order."""
    rows = {row["hook"]: row for row in verification["hooks"] if row.get("status") == "verified"}
    specs = []
    for hook in profile.data["hooks"]:
        row = rows.get(hook["id"])
        if row is None:
            continue
        site = int(str(row["rva"]).removeprefix("rva:"), 16) + hook["prologue_offset"]
        longest = max(len(parse_expect(text)) for text in hook["prologue"])
        spec = {"name": hook["id"], "hook": hook["id"], "event": hook["event"], "module": hook["module"],
                "rva": hex(site), "sha256": row["image_sha256"], "expect_len": max(8, min(64, longest)),
                "nargs": hook["nargs"], "with_leave": hook["with_leave"], "stack": hook["stack"], "required": hook["required"],
                "fields": [dict(field) for field in hook["fields"]], "const": dict(hook.get("const") or {})}
        if hook["buf"]:
            buf = hook["buf"]
            spec["buf"] = {"ptr_arg": buf["arg"], "len_arg": buf["len_arg"], "wide": buf["wide"], "fixed": buf["fixed"],
                           "max": buf["max"]}
        specs.append(spec)
    return specs
