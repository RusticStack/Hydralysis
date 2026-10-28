"""Run the verification checks against the prepared fixtures (docs/verification-fixtures.md).

usage: python tests/fixtures/verify_fixtures.py <fixtures out dir> [check ...]
Each check prints PASS/FAIL with its evidence; the exit status is the number of failures.
HYDRALYSIS_CONFIG selects the data root the fixtures were prepared in (prepare_fixtures.py).
"""

from __future__ import annotations

import json
import re as _re
import struct
import sys
from pathlib import Path

from hydralysis.client import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_fixtures import target_name  # noqa: E402

re = Client()
# The engine's exact refusal texts (hydra-2 engine, measured): an unknown action, a name outside every map, a map of another build.
UNKNOWN_ACTION = "unknown saved-analysis query action"
REFUSAL_TEXT = {"unknown name": "no address map entry for name:not_in_any_map", "other build": "address map build SHA-256 mismatch"}
ARCHES = ("x64", "x86")


MANIFEST: dict = {}


def load(out_dir: str) -> dict:
    MANIFEST.update(json.loads((Path(out_dir) / "manifest.json").read_text()))
    MANIFEST_DIR[:] = [out_dir]
    return MANIFEST


def target(arch: str, exe: str) -> str:
    return target_name(arch + "/" + exe, MANIFEST[arch + "/" + exe])


def last_load(name: str, address: str) -> str:
    operations = re.query(name, "pcode", address, nodes=200)["operations"]
    loads = [op for op in operations if op["opcode"] == "LOAD"]
    return loads[-1]["id"]


def check_value_flow(manifest: dict) -> list[str]:
    """Item 3: fx_read's value traced back through fx_relay -> fx_store is the constant 0x2A."""
    failures = []
    for arch in ARCHES:
        name, functions = target(arch, "flow_fixture.exe"), manifest[arch + "/flow_fixture.exe"]["functions"]
        trace = re.query(name, "trace", functions["fx_read"], timeout_s=120, seed=last_load(name, functions["fx_read"]),
                         direction="backward", depth=12, functions=4, callers=2, brief=True)
        values = [c for c in trace["constants"] if c.get("role") == "value"]
        found = [c["value"] for c in values]
        via = [hop.get("via") for hop in values[0]["path_to_seed"]] if values else []
        ok = found == ["0x2a"] and "field_store" in via
        print("%s value_flow %s: value constants %s via %s" % ("PASS" if ok else "FAIL", arch, found, via))
        if not ok:
            failures.append("value_flow " + arch)
    return failures


class Running:
    """A fixture process under a Hydralysis runtime session; stopped through its stop file."""

    def __init__(self, arch: str, exe: str, extra_argv=()):
        build = MANIFEST[arch + "/" + exe]
        self.build, self.stop_file, self.detached = build, Path(build["path"]).with_suffix(".stop"), False
        self.stop_file.unlink(missing_ok=True)
        started = re.runtime("spawn", exe=build["path"], sha256=build["sha256"], argv=[str(self.stop_file), *extra_argv],
                             cwd=str(Path(build["path"]).parent))
        self.session, self.owner = started["session"], started["owner"]
        re.runtime("resume", session=self.session, owner=self.owner)
        modules = re.runtime("modules", session=self.session, limit=50)
        main = next(m for m in modules["modules"] if m["name"].lower() == Path(build["path"]).name.lower())
        self.delta = int(main["base"], 16) - int(build["image_base"], 16)

    def live(self, name: str) -> int:
        """A global's address in the running process (the map's VA moved by the load base)."""
        return int(self.build["globals"][name], 16) + self.delta

    def call(self, action: str, **options):
        return re.runtime(action, session=self.session, owner=self.owner, **options)

    def __enter__(self):
        return self

    def detach(self):
        """Detach now (the program keeps running); __exit__ then only stops it."""
        result = re.runtime("detach", session=self.session, owner=self.owner)
        self.detached = True
        return result

    def __exit__(self, *exc):
        if not self.detached:
            try:
                re.runtime("detach", session=self.session, owner=self.owner)
            except Exception as error:  # still report the check
                print("  detach:", error)
        self.stop_file.write_text("stop")


def check_writers(manifest: dict) -> list[str]:
    """Item 13: of the static store sites at Config.limit's offset, the live ones writing g_config
    are exactly those of fx_store, fx_reset and fx_clamp (x86 folds fx_pair into fx_store)."""
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        name, functions = target(arch, "flow_fixture.exe"), build["functions"]
        names = {}
        for function, address in functions.items():
            names.setdefault(int(address, 16), []).append(function)
        rows = re.query(name, "writes", limit=32, timeout_s=120, offset="0x4")["writes"]
        expected = {"fx_store", "fx_reset", "fx_clamp"}
        with Running(arch, "flow_fixture.exe") as running:
            answer = running.call("writers", target=name, rows=rows, object=hex(running.live("g_config")), offset="0x4",
                                  size=4, window_s=3)
        writers = set()
        for site in answer["writers"]:
            writers.update(names.get(int(site["site"], 16) - 0, []) or names.get(_entry(name, site["site"]), [site["site"]]))
        refused = [s for s in answer["sites"] if not s.get("probed")]
        shared = [s for s in answer["writers"] if s.get("other_objects")]
        ok = expected <= writers and not (writers - expected - {"fx_pair"})
        print("%s writers %s: %s; %d of %d sites probed; sites that also wrote other objects: %s"
              % ("PASS" if ok else "FAIL", arch, sorted(writers), len(answer["sites"]) - len(refused), len(answer["sites"]),
                 [(s["site"], s["other_objects"]) for s in shared]))
        for site in refused[:3]:
            print("   not probed", site["site"], site["reason"][:120])
        if not ok:
            failures.append("writers " + arch)
    return failures


def _entry(name: str, site: str) -> int:
    function = re.try_query(name, "function", site)
    return int(function["function"]["address"], 16) if function else 0


def check_hooked(manifest: dict) -> list[str]:
    """Item 4: fx_hooked is detoured live (to fx_detour) by the fixture itself. patches flags it,
    names the detour, and leaves unpatched functions clean (relocated 32-bit code included);
    the static tools read the file's original bytes; a probe with accept_patch works past it."""
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        exe, functions, base = build["path"], build["functions"], int(build["image_base"], 16)
        rva = {name: int(address, 16) - base for name, address in functions.items()}
        original = re.read(exe, "rva:%#x" % rva["fx_hooked"], 16)
        static = re.check_prologues(exe, [{"name": "fx_hooked", "address": "rva:%#x" % rva["fx_hooked"],
                                           "expect": original.hex(" ").upper()}], sha256=build["sha256"])
        scanned = re.sigscan(exe, original[:12].hex(" ").upper())
        with Running(arch, "flow_fixture.exe") as running:
            rows = [{"module": Path(exe).name, "rva": hex(rva[name]), "name": name, "size": 16}
                    for name in ("fx_hooked", "fx_detour", "fx_flow", "fx_tick")]
            live = running.call("patches", rows=rows, sha256=build["sha256"])
            flagged = {row["name"]: row for row in live["rows"]}
            detour = (flagged["fx_hooked"].get("patch") or {}).get("detour")
            probe = running.call("observe", module=Path(exe).name, rva=hex(rva["fx_hooked"]), sha256=build["sha256"],
                                 expect=original[:8].hex(" ").upper(), accept_patch=True, limit=3,
                                 capture=[{"arg": 0, "as": "u32", "label": "value"}] if arch == "x64" else
                                 [{"arg": 0, "as": "u32", "label": "value"}])
            import time
            time.sleep(1)
            events = running.call("status", limit=20)["events"]
            entered = [e for e in events if ((e.get("message") or {}).get("payload") or {}).get("event") == "enter"]
        detour_at = int(detour, 16) - running.delta if detour else 0
        ok = (flagged["fx_hooked"]["patched"] and detour_at == int(functions["fx_detour"], 16)
              and not any(flagged[name]["patched"] for name in ("fx_detour", "fx_flow", "fx_tick"))
              and static["matched"] and "rva:%#x" % rva["fx_hooked"] in scanned and probe.get("past_patch") and entered)
        print("%s hooked %s: patched %s detour %s (fx_detour %s), clean %s, static prologue %s, sigscan finds it %s, "
              "probe past the detour %s with %d calls"
              % ("PASS" if ok else "FAIL", arch, flagged["fx_hooked"]["patched"], hex(detour_at), functions["fx_detour"],
                 [name for name in ("fx_detour", "fx_flow", "fx_tick") if not flagged[name]["patched"]], static["matched"],
                 "rva:%#x" % rva["fx_hooked"] in scanned, bool(probe.get("past_patch")), len(entered)))
        if not ok:
            failures.append("hooked " + arch)
    return failures


IDENTICAL = {"df_parse", "df_checksum", "df_format", "df_scale", "df_lookup", "df_walk", "df_render", "df_mix"}
CHANGED = {"df_limit", "df_banner"}


def check_diff(manifest: dict) -> list[str]:
    """Items 2 and 7: build 1 -> build 2 places every df_ function with the right status
    (identical code same/moved, df_limit and df_banner changed, df_added new, df_removed
    gone), and build 1's prologue table, re-addressed, lands on the right functions."""
    import time
    failures = []
    for arch in ARCHES:
        one, two = manifest[arch + "/diff1.exe"], manifest[arch + "/diff2.exe"]
        base = int(one["image_base"], 16)
        names_one = {int(a, 16) - base: n for n, a in one["functions"].items()}
        names_two = {int(a, 16) - base: n for n, a in two["functions"].items()}
        table = Path(one["path"]).with_suffix(".checks.json")
        table.write_text(json.dumps({"checks": [
            {"name": name, "address": "rva:%#x" % (int(address, 16) - base),
             "expect": re.read(one["path"], "rva:%#x" % (int(address, 16) - base), 12).hex(" ").upper()}
            for name, address in sorted(one["functions"].items())]}))
        job = re.query(target(arch, "diff2.exe"), "diff", timeout_s=120, against=target(arch, "diff1.exe"), checks=str(table))
        while True:
            status = re.call("job", id=job["id"])
            if status["state"] not in ("queued", "running"):
                break
            time.sleep(1)
        summary = status["result"] if "result" in status else status
        found, wrong = {}, []
        with open(summary["files"]["diff"], encoding="utf-8") as handle:
            for line in handle:
                row = json.loads(line)
                source = int(row["source"].removeprefix("rva:"), 16) if "source" in row else None
                destination = int(row["destination"].removeprefix("rva:"), 16) if "destination" in row else None
                name = names_one.get(source) or names_two.get(destination)
                if name:
                    found[name] = (row["status"], names_two.get(destination) if destination is not None else None)
        for name in IDENTICAL | CHANGED | {"df_removed", "df_added"}:
            want = ("same", "moved") if name in IDENTICAL else ("changed",) if name in CHANGED else \
                ("gone",) if name == "df_removed" else ("new",)
            got = found.get(name)
            partner_ok = name in ("df_removed", "df_added") or (got and got[1] == name)
            if not got or got[0] not in want or not partner_ok:
                wrong.append("%s: %s" % (name, got))
        moved_table = json.loads(Path(summary["checks"]["file"]).read_text())
        transferred = moved_table["candidates"]
        misplaced = [row["name"] for row in transferred if
                     names_two.get(int(row["address"].removeprefix("rva:"), 16)) != row["name"]]
        unplaced = sorted(row.get("name", str(row)) if isinstance(row, dict) else str(row) for row in moved_table["unplaced"])
        ok = (not wrong and not misplaced and unplaced == ["df_removed"] and moved_table["review_required"]
              and all(row["review_required"] and "expect" not in row for row in transferred))
        print("%s diff %s: %d matched, same %s moved %s changed %s new %s gone %s; wrong %s; table: %d placed, misplaced %s, unplaced %s"
              % ("PASS" if ok else "FAIL", arch, summary["matched"], summary.get("same", 0), summary.get("moved", 0),
                 summary.get("changed", 0), summary.get("new", 0), summary.get("gone", 0), wrong, len(transferred),
                 misplaced, unplaced))
        if not ok:
            failures.append("diff " + arch)
    return failures


def check_vcalls(manifest: dict) -> list[str]:
    """Item 10: calls through Shape slot 1 (sides). vtables names Square::vftable for
    Square::sides; vcalls with that vtable names the implementation; the call through
    g_square verifies with receiver_global, the one through fx_make_shape's result with
    receiver_from, and the folded fx_sides_of/fx_gadget_run tail call is listed with its
    receiver a parameter (its callers decide the class), verified by neither."""
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/vcall_fixture.exe"]
        name, functions, data = target(arch, "vcall_fixture.exe"), build["functions"], build["globals"]
        slot = "0x8" if arch == "x64" else "0x4"
        owner = {}
        for function, address in functions.items():
            owner.setdefault(int(address, 16), function)
        tables = re.query(name, "vtables", functions["Square::sides"])["vtables"]
        in_square = any(int(t["table"], 16) == int(data["Square::vftable"], 16) and t["offset"] == slot for t in tables)
        implementation = re.query(name, "vcalls", limit=50, timeout_s=300, offset=slot,
                                  vtable=data["Square::vftable"]).get("implementation", {})
        target_ok = int(implementation.get("target") or "0", 16) == int(functions["Square::sides"], 16)

        def sites(**verify):
            rows = re.query(name, "vcalls", limit=50, timeout_s=300, offset=slot, **verify)["callers"]
            return [r for r in rows if r.get("function") and int(r["function"], 16) in owner]

        by_global = {owner[int(r["function"], 16)] for r in sites(receiver_global=data["g_square"]) if r.get("verified")}
        by_maker = {owner[int(r["function"], 16)] for r in sites(receiver_from=functions["fx_make_shape"]) if r.get("verified")}
        listed = sites()
        folded = [r for r in listed if owner[int(r["function"], 16)] in ("fx_sides_of", "fx_gadget_run")]
        tail = bool(folded) and all(r.get("receiver_parameter") == 0 for r in folded)
        ok = in_square and target_ok and by_global == {"fx_sides_global"} and by_maker == {"fx_sides_made"} and tail
        print("%s vcalls %s: Square::sides in Square::vftable at %s %s; implementation %s; receiver_global verifies %s; "
              "receiver_from verifies %s; sites %s; folded tail call with parameter receiver %s"
              % ("PASS" if ok else "FAIL", arch, slot, in_square, target_ok, sorted(by_global), sorted(by_maker),
                 sorted({owner[int(r["function"], 16)] + (" (tail)" if r.get("tail_call") else "") for r in listed}), tail))
        if not ok:
            failures.append("vcalls " + arch)
    return failures


def check_sample(manifest: dict) -> list[str]:
    """Item 12: fx_tick(Config *, float dt) runs once per ~50 ms frame with dt in
    {0.25, 0.375, 0.5, 0.625}. A sampled probe on dt (xmm1 on x64, stack argument 1 on x86)
    reports the rate and exactly that range, one summary per window, not an event per call."""
    import time
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        base = int(build["image_base"], 16)
        rva = int(build["functions"]["fx_tick"], 16) - base
        capture = {"reg": "xmm1", "as": "f32", "label": "dt"} if arch == "x64" else {"arg": 1, "as": "f32", "label": "dt"}
        with Running(arch, "flow_fixture.exe") as running:
            probe = running.call("observe", module=Path(build["path"]).name, rva=hex(rva), sha256=build["sha256"],
                                 expect=re.read(build["path"], "rva:%#x" % rva, 8).hex(" ").upper(), limit=10,
                                 capture=[capture], sample={"window_s": 3, "capture": 0})
            time.sleep(10)
            events = [((e.get("message") or {}).get("payload") or {}) for e in running.call("status", limit=200)["events"]]
            running.call("unload", hook_id=probe["hook_id"])
        samples = [e for e in events if e.get("event") == "sample"]
        calls = [e for e in events if e.get("event") == "enter"]
        full = [x for x in samples if x.get("count")]
        ok = (len(samples) >= 2 and not calls and all(12 <= x["rate"] <= 21 for x in full)
              and all(abs(x["min"] - 0.25) < 1e-6 and abs(x["max"] - 0.625) < 1e-6 for x in full))
        print("%s sample %s: %d summaries, %d per-call events; %s"
              % ("PASS" if ok else "FAIL", arch, len(samples), len(calls),
                 [(round(x["rate"], 1), x["min"], x["max"]) for x in samples]))
        if not ok:
            failures.append("sample " + arch)
    return failures


def _payloads(running: "Running", kind: str | None = None, after: int = 0) -> list[dict]:
    """The probe payloads in the session's event ring (at most 200 per call), optionally of one event kind."""
    events = running.call("status", limit=200, after=after)["events"]
    payloads = [(e.get("message") or {}).get("payload") or {} for e in events]
    return [p for p in payloads if isinstance(p, dict) and (kind is None or p.get("event") == kind)]


def _wait(condition, seconds: float):
    import time
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        found = condition()
        if found:
            return found
        time.sleep(0.1)
    return condition()


def _file_head(build: dict, rva: int, size: int = 8) -> str:
    return re.read(build["path"], "rva:%#x" % rva, size).hex(" ").upper()


def check_break_continue(manifest: dict) -> list[str]:
    """The runtime smoke's steps, committed (C1-24, C2-18). runtime_fixture's rustic_transform(Sample *, int delta)
    runs every 50 ms and logs a line per step. A breakpoint on it stops the program (the log stops), the Sample
    behind argument 0 is read through its absolute address (armor 7, health = the step number), `continue` lets it
    run, the probe is inert after its one hit, `unload` leaves the file's bytes in place (patches: none) and a
    detach leaves the program running."""
    import time
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/runtime_fixture.exe"]
        name, base = Path(build["path"]).name, int(build["image_base"], 16)
        rva = int(build["functions"]["rustic_transform"], 16) - base
        log = Path(build["path"]).with_suffix(".log")
        log.unlink(missing_ok=True)

        def steps() -> int:
            return len(log.read_text().splitlines()) if log.exists() else 0

        with Running(arch, "runtime_fixture.exe", extra_argv=[str(log)]) as running:
            _wait(lambda: steps() >= 3, 10)
            probe = running.call("break", module=name, rva=hex(rva), sha256=build["sha256"], expect=_file_head(build, rva),
                                 limit=1, capture=[{"arg": 0, "as": "hex", "size": 8, "label": "sample"},
                                                   {"arg": 1, "as": "i32", "label": "delta"}])
            hit = _wait(lambda: next(iter(_payloads(running, "break")), None), 10) or {}
            decoded = hit.get("decoded") or [{}, {}]
            time.sleep(0.5)
            stopped_at = steps()
            time.sleep(1.0)
            stalled = steps() == stopped_at
            paused = probe["hook_id"] in running.call("status", limit=1)["paused_hooks"]
            raw = bytes.fromhex(str(decoded[0].get("value") or "00" * 8))
            health, armor = struct.unpack("<ii", raw)
            absolute = bytes.fromhex(running.call("read", address=decoded[0].get("pointer") or "0x1", size=8)["bytes"].replace(" ", ""))
            running.call("continue", hook_id=probe["hook_id"])
            resumed = _wait(lambda: steps() >= stopped_at + 10, 5)
            released = not running.call("status", limit=1)["paused_hooks"]
            breaks = len(_payloads(running, "break"))
            running.call("unload", hook_id=probe["hook_id"])
            row = running.call("patches", sha256=build["sha256"], rows=[{"module": name, "rva": hex(rva), "size": 8, "name": "rustic_transform"}])["rows"][0]
            running.detach()
            after = steps()
            alive = _wait(lambda: steps() >= after + 10, 5)
        ok = (hit.get("event") == "break" and decoded[1].get("value") == 3 and stalled and paused and armor == 7
              and health == stopped_at % 90 and absolute == raw and resumed and released and breaks == 1
              and not row["patched"] and alive)
        print("%s break_continue %s: broke at step %d (health %d armor %d delta %s), stalled %s, paused %s, absolute read same %s, "
              "continued %s, released %s, break events %d, patched after unload %s, running after detach %s"
              % ("PASS" if ok else "FAIL", arch, stopped_at, health, armor, decoded[1].get("value"), stalled, paused,
                 absolute == raw, bool(resumed), released, breaks, row["patched"], bool(alive)))
        if not ok:
            failures.append("break_continue " + arch)
    return failures


def check_export_hook(manifest: dict) -> list[str]:
    """Z10: flow_fixture exports fx_exported(int), called once per frame with the frame number. A probe named by
    export (no RVA, no expect) resolves the name in the module FILE's export table, lands on the linker map's
    address for it, and sees consecutive frame numbers. A name the table lacks (fx_hooked is not exported) and an
    RVA that is not the export's are refused."""
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        name, base = Path(build["path"]).name, int(build["image_base"], 16)
        rva = int(build["functions"]["fx_exported"], 16) - base
        with Running(arch, "flow_fixture.exe") as running:
            refusals = {}
            for label, options in (("not exported", {"export": "fx_hooked"}), ("wrong rva", {"export": "fx_exported", "rva": hex(rva + 16)})):
                try:
                    running.call("observe", module=name, sha256=build["sha256"], **options)
                    refusals[label] = "ACCEPTED"
                except Exception as error:
                    refusals[label] = str(error)
            probe = running.call("observe", module=name, export="fx_exported", sha256=build["sha256"], limit=6,
                                 capture=[{"arg": 0, "as": "i32", "label": "frame"}])
            enters = _wait(lambda: (lambda rows: rows if len(rows) >= 3 else None)(_payloads(running, "enter")), 10) or []
            running.call("unload", hook_id=probe["hook_id"])
        frames = [e["decoded"][0]["value"] for e in enters if e.get("decoded")]
        addresses = {e.get("address") for e in enters}
        ok = (probe["rva"] == hex(rva) and probe["export"]["name"] == "fx_exported" and probe["expect_source"] == "file"
              and addresses == {hex(int(build["functions"]["fx_exported"], 16) + running.delta)}
              and len(frames) >= 3 and all(b > a for a, b in zip(frames, frames[1:]))
              and "no export fx_hooked" in refusals["not exported"] and "is at rva" in refusals["wrong rva"])
        print("%s export_hook %s: fx_exported rva %s (map %s), expect from %s, frames %s, refused: %s"
              % ("PASS" if ok else "FAIL", arch, probe["rva"], hex(rva), probe["expect_source"], frames[:6],
                 {k: v[:70] for k, v in refusals.items()}))
        if not ok:
            failures.append("export_hook " + arch)
    return failures


def check_capture(manifest: dict) -> list[str]:
    """Z10: capture windows on a live program. fx_exported fires about 20 times a second. A window with a probe
    limited to 8 records exactly 8 events while the probe's own counter says many more fired: partial,
    hit_limit_reached. A short window with room to spare records every call its probe counted: complete. The
    durable log of each verifies and returns its events."""
    import time
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        name = Path(build["path"]).name
        frame = [{"arg": 0, "as": "i32", "label": "frame"}]
        with Running(arch, "flow_fixture.exe") as running:
            windows = []
            for label, limit, seconds in (("limited", 8, 3.0), ("roomy", 200, 1.5)):
                started = running.call("capture", op="start", name=label)
                probe = running.call("observe", module=name, export="fx_exported", sha256=build["sha256"], limit=limit, capture=frame)
                time.sleep(seconds)
                closed = running.call("capture", op="stop")
                running.call("unload", hook_id=probe["hook_id"])
                windows.append((started, closed))
            (_, limited), (_, roomy) = windows
            verified = [running.call("capture", op="verify", capture=c["capture"]) for _, c in windows]
            page = running.call("capture", op="read", capture=limited["capture"], limit=200)
        a, b = limited["hooks"][0], roomy["hooks"][0]
        enters = [e for e in page["events"] if ((e["message"].get("payload") or {}).get("event")) == "enter"]
        ok = (limited["coverage"] == {"status": "partial", "limitations": ["hit_limit_reached"]}
              and a["recorded"] == 8 and a["seen"] > 20 and a["lost"] == a["seen"] - 8 and len(enters) == 8
              and roomy["coverage"]["status"] == "complete" and 10 <= b["seen"] < 200 and b["recorded"] == b["seen"]
              and all(v["ok"] for v in verified) and roomy["evidence"]["from_capture"] == roomy["capture"]
              and roomy["evidence"]["subject_sha256"] == build["sha256"])
        print("%s capture %s: limited window saw %s recorded %s lost %s (%s); roomy window saw %s recorded %s (%s); log verifies %s"
              % ("PASS" if ok else "FAIL", arch, a["seen"], a["recorded"], a["lost"], limited["coverage"]["status"],
                 b["seen"], b["recorded"], roomy["coverage"]["status"], [v["ok"] for v in verified]))
        if not ok:
            failures.append("capture " + arch)
    return failures


def check_snapshot(manifest: dict) -> list[str]:
    """Z10: snapshots of a live program and their comparison. g_config (mode 2, limit 0..100, a growing speed)
    read through an inline layout in two snapshots 1.5 s apart: mode unchanged, speed increased, limit in range,
    the main module's file hash the build's. A snapshot of a second run of the program (another process, another
    session) compares equal to the first outside the region, with the default volatile masks only."""
    import time
    failures = []
    layout = [{"name": "mode", "offset": 0, "type": "i32"}, {"name": "limit", "offset": 4, "type": "i32"},
              {"name": "speed", "offset": 8, "type": "f32"}]
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        name = Path(build["path"]).name

        def take(running):
            return running.call("snapshot", name="g_config", regions=[{"name": "config", "address": hex(running.live("g_config")),
                                                                      "size": 12, "layout": layout}])

        with Running(arch, "flow_fixture.exe") as first:
            time.sleep(0.5)
            one = take(first)
            time.sleep(1.5)
            two = take(first)
            within = first.call("compare", a=one["snapshot"], b=two["snapshot"], predicates=[
                {"path": "regions/config/fields/mode/value", "op": "unchanged"},
                {"path": "regions/config/fields/speed/value", "op": "increased"},
                {"path": "regions/config/fields/limit/value", "op": "between", "value": [0, 100]},
                {"path": "modules/%s/file_sha256" % name.lower(), "op": "eq", "value": build["sha256"]}])
        with Running(arch, "flow_fixture.exe") as second:
            time.sleep(0.5)
            three = take(second)
            across = second.call("compare", other_session=first.session, a=three["snapshot"], b=one["snapshot"], mask=["regions/*"])
        main = next(m for m in one["modules"] if m["name"].lower() == name.lower())
        ok = (within["ok"] and not within["equal"] and across["equal"] and main["file_sha256"] == build["sha256"]
              and one["regions_complete"] and one["modules_complete"] and one["target"]["exe_sha256"] == build["sha256"]
              and one["target"]["pid"] != three["target"]["pid"])
        print("%s snapshot %s: predicates %s; across two runs equal %s (%d differences, %d masked, first %s)"
              % ("PASS" if ok else "FAIL", arch, [(p["path"].rsplit("/", 2)[-2], p["ok"]) for p in within["predicates"]],
                 across["equal"], across["difference_count"], across["masked_differences"],
                 [d["path"] for d in across["differences"][:3]]))
        if not ok:
            failures.append("snapshot " + arch)
    return failures


class McpClient:
    """The real stdio MCP server (hydralysis mcp), driven as an agent's client would."""

    def __init__(self):
        import os
        import subprocess
        self.process = subprocess.Popen([sys.executable, "-m", "hydralysis", "mcp"], stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, env=dict(os.environ),
                                        text=True, encoding="utf-8")
        self.next = 0
        self.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                    "clientInfo": {"name": "verify_fixtures", "version": "1"}})
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}) + "\n")
        self.process.stdin.flush()

    def request(self, method: str, params: dict) -> dict:
        self.next += 1
        self.process.stdin.write(json.dumps({"jsonrpc": "2.0", "id": self.next, "method": method, "params": params}) + "\n")
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                raise RuntimeError("the MCP server closed its output")
            message = json.loads(line)
            if message.get("id") == self.next:
                return message

    def tool(self, name: str, **arguments):
        answer = self.request("tools/call", {"name": name, "arguments": arguments})
        result = answer.get("result") or {}
        text = "".join(part.get("text", "") for part in result.get("content", []))
        if result.get("isError") or "error" in answer:
            raise RuntimeError("%s failed over MCP: %s" % (name, text or answer.get("error")))
        return json.loads(text) if text.lstrip()[:1] in "{[" else text

    def close(self):
        self.process.stdin.close()
        self.process.wait(timeout=30)


def check_mcp_typed_read(manifest: dict) -> list[str]:
    """Items 5 and 14 over the MCP transport: import a type for Config into the fixture's
    analysis, spawn the fixture, and read g_config through that type. The program keeps
    mode == 2, limit in 0..100 and a growing speed."""
    import time
    failures = []
    corpus = Path(manifest["x64/flow_fixture.exe"]["path"]).parent.parent / "config-corpus.jsonl"
    corpus.write_text(json.dumps({"kind": "struct", "name": "Config", "size": 12, "fields": [
        {"name": "mode", "offset": 0, "type": "int32"}, {"name": "limit", "offset": 4, "type": "int32"},
        {"name": "speed", "offset": 8, "type": "float"}]}) + "\n", encoding="utf-8")
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        name = target(arch, "flow_fixture.exe")
        mcp = McpClient()
        try:
            job = mcp.tool("ghidra_query", target=name, action="type_edit", timeout_s=120,
                           options={"kind": "import_types", "corpus": str(corpus), "category": "/fixture",
                                    "source": "flow_fixture.c struct Config"})
            while job.get("state") in ("queued", "running"):
                time.sleep(1)
                job = mcp.tool("job", id=job["id"])
            stop = Path(build["path"]).with_suffix(".stop")
            stop.unlink(missing_ok=True)
            started = mcp.tool("runtime", action="spawn", options={"exe": build["path"], "sha256": build["sha256"],
                                                                   "argv": [str(stop)], "cwd": str(Path(build["path"]).parent)})
            session, owner = started["session"], started["owner"]
            mcp.tool("runtime", action="resume", options={"session": session, "owner": owner})
            modules = mcp.tool("runtime", action="modules", options={"session": session, "limit": 50})["modules"]
            main = next(m for m in modules if m["name"].lower() == Path(build["path"]).name.lower())
            address = int(build["globals"]["g_config"], 16) - int(build["image_base"], 16) + int(main["base"], 16)
            reads, sources = [], []
            for _ in range(2):
                time.sleep(1)
                answer = mcp.tool("runtime", action="read", options={"session": session, "address": hex(address), "type": "Config",
                                                                     "target": name})
                reads.append({f["name"]: f.get("value") for f in answer["fields"]})
                sources.append(answer.get("layout_source") or {})
            status = mcp.tool("ghidra_query", target=name, action="status")
            mcp.tool("runtime", action="detach", options={"session": session, "owner": owner})
            stop.write_text("stop")
        finally:
            mcp.close()
        # The read names the view and the revision its layout came from: the revision the engine reports for that view.
        sourced = all(isinstance(s.get("revision"), int) and s["revision"] == status.get("view_revision")
                      and s.get("view") == "shared" and s.get("target") == name for s in sources)
        ok = (job.get("state") == "done" and all(r["mode"] == 2 and 0 <= r["limit"] <= 100 for r in reads)
              and reads[1]["speed"] > reads[0]["speed"] > 0 and sourced)
        print("%s mcp_typed_read %s: import %s; reads %s; layout from %s (status view_revision %s)"
              % ("PASS" if ok else "FAIL", arch, job.get("state"), reads, sources[-1], status.get("view_revision")))
        if not ok:
            failures.append("mcp_typed_read " + arch)
    return failures


def check_ledger(manifest: dict) -> list[str]:
    """Item 9: a claim derived on build 1 (df_limit's threshold, from its decompile) is
    superseded by its re-derivation on build 2 (found through the diff), and the subsystem
    export lists the build 2 claim with its source and the build 1 claim as superseded."""
    import re as regex
    import time
    failures = []
    arch = "x64"
    one, two = manifest[arch + "/diff1.exe"], manifest[arch + "/diff2.exe"]
    database = Path(one["path"]).parent.parent / "ledger-check.db"
    database.unlink(missing_ok=True)
    out = database.with_suffix(".md")

    def threshold(name, address):
        code = re.query(name, "decompile", address)["c"]
        line = next(text.strip() for text in code.splitlines() if "if (" in text and "<" in text)
        return int(regex.findall(r"0x[0-9a-f]+|\b\d+\b", line)[0], 0), line

    first = one["functions"]["df_limit"]
    old_value, old_line = threshold(target(arch, "diff1.exe"), first)
    stored = re.call("evidence_add", db=str(database), target="diff-fixture", build=one["sha256"][:16], kind="constant",
                     name="df_limit threshold", note="clamps to %d" % old_value, address="va:" + first,
                     source="decompile %s: %s" % (first, old_line), subsystem="limits")
    old_id = int(regex.search(r"claim (\d+)", stored).group(1))
    job = re.query(target(arch, "diff2.exe"), "diff", timeout_s=120, against=target(arch, "diff1.exe"))
    while True:
        status = re.call("job", id=job["id"])
        if status["state"] not in ("queued", "running"):
            break
        time.sleep(1)
    source_rva = "0x%x" % (int(first, 16) - int(one["image_base"], 16))
    with open(status["result"]["files"]["diff"], encoding="utf-8") as handle:
        moved = next(json.loads(line) for line in handle if json.loads(line).get("source") == source_rva)
    second = "0x%x" % (int(moved["destination"], 16) + int(two["image_base"], 16))
    new_value, new_line = threshold(target(arch, "diff2.exe"), second)
    re.call("evidence_add", db=str(database), target="diff-fixture", build=two["sha256"][:16], kind="constant",
            name="df_limit threshold", note="clamps to %d" % new_value, address="va:" + second,
            source="decompile %s: %s (diff %s, %s)" % (second, new_line, moved["status"], moved["method"]),
            subsystem="limits", supersedes=old_id)
    exported = re.call("evidence_list", db=str(database), target="diff-fixture", subsystem="limits", export=str(out))
    text = out.read_text(encoding="utf-8")
    current, superseded = text.split("## Superseded")
    ok = (old_value == 100 and new_value == 250 and exported["current"] == 1 and exported["superseded"] == 1
          and "clamps to 250" in current and new_line in current and "#%d" % (old_id + 1) in superseded
          and second == two["functions"]["df_limit"])
    print("%s ledger %s: %d -> %d at %s (map %s); export current %d, superseded %d"
          % ("PASS" if ok else "FAIL", arch, old_value, new_value, second, two["functions"]["df_limit"],
             exported["current"], exported["superseded"]))
    if not ok:
        failures.append("ledger " + arch)
    return failures


# --- Surface parity (Z8): metadata, listing, read-memory, call graph and name to address, each against the
# --- linker map of the MSVC fixtures (x86 and x64). Ground truth is the map, the C sources and the PE headers
# --- parsed here with struct, never an answer of the tool under test. Rows of docs/tool-mapping.md.

EXES = ("flow_fixture.exe", "vcall_fixture.exe", "diff1.exe", "diff2.exe")
# Functions the saved analysis does not list: fx_detour is only ever reached through a stored pointer
# (install_detour), so no call or entry-point seed leads to it. A documented gap of list_functions.
UNLISTED = {"flow_fixture.exe": {"fx_detour"}}
# Direct calls made by the fixtures' own functions, from the C sources (caller -> callees).
EDGES = {
    "flow_fixture.exe": {"fx_flow": {"fx_relay", "fx_read"}, "fx_relay": {"fx_store"}},
    "vcall_fixture.exe": {"fx_sides_global": {"Square::sides"}, "fx_sides_made": {"fx_make_shape"}},
    "diff1.exe": {},
    "diff2.exe": {"df_added": {"df_banner", "df_mix", "df_walk"}, "df_banner": {"df_limit"}},
}
# String literals of diff_fixture.c per build.
LITERALS = {"diff1.exe": ("alpha", "beta", "gamma", "delta", "value=%d units", "diff fixture build one"),
            "diff2.exe": ("alpha", "beta", "gamma", "delta", "value=%d units", "diff fixture build two")}
# What flow_fixture.c calls in kernel32 (a subset of the map's import table).
SOME_IMPORTS = {"flow_fixture.exe": {"Sleep", "GetFileAttributesA", "VirtualProtect", "FlushInstructionCache", "GetCurrentProcess"}}
MANIFEST_DIR: list[str] = []


def _build(manifest: dict, arch: str, exe: str) -> dict:
    return manifest[arch + "/" + exe]


def _pages(name: str, size: int = 100) -> list[dict]:
    """Every function of the saved analysis, by cursor pages."""
    found, cursor = [], ""
    while True:
        page = re.query(name, "functions", limit=size, **({"cursor": cursor} if cursor else {}))
        found += page["functions"]
        if not page["truncated"]:
            return found
        cursor = page["next_cursor"]


def _body(function: dict) -> tuple[int, int]:
    first, last = function["body"][0].strip("[]").split(",")
    return int(first, 16), int(last, 16)


def _unique(functions: dict) -> dict[int, list[str]]:
    """Map function VAs; identical-code folding gives one address several names."""
    by_address: dict[int, list[str]] = {}
    for function, address in functions.items():
        by_address.setdefault(int(address, 16), []).append(function)
    return by_address


def _sections(path: str) -> list[dict]:
    """PE section table parsed straight from the file (no Hydralysis code)."""
    data = Path(path).read_bytes()
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    count, optional = struct.unpack_from("<H", data, pe + 6)[0], struct.unpack_from("<H", data, pe + 20)[0]
    first, rows = pe + 24 + optional, []
    for index in range(count):
        raw = data[first + 40 * index: first + 40 * index + 40]
        name = raw[:8].rstrip(b"\0").decode("ascii")
        vsize, rva, rawsize, rawptr = struct.unpack_from("<IIII", raw, 8)
        rows.append({"name": name, "rva": rva, "vsize": vsize, "raw_size": rawsize, "raw_ptr": rawptr})
    return rows


def _file_bytes(path: str, rva: int, size: int) -> bytes:
    """Bytes of the file at an RVA: the section's file bytes, zero filled past its raw data (what the loader maps)."""
    data = Path(path).read_bytes()
    for section in _sections(path):
        if section["rva"] <= rva < section["rva"] + max(section["vsize"], section["raw_size"]):
            start = rva - section["rva"]
            raw = data[section["raw_ptr"]: section["raw_ptr"] + section["raw_size"]][start: start + size]
            return raw + b"\0" * (size - len(raw))
    raise ValueError("rva %#x is outside every section" % rva)


def _map_imports(build: dict) -> set[tuple[str, str, int]]:
    """(module, name, IAT rva) of every import, from the linker map's __imp_ rows."""
    base, found = int(build["image_base"], 16), set()
    for line in Path(build["path"]).with_suffix(".map").read_text(errors="replace").splitlines():
        match = _re.fullmatch(r"\s*\d{4}:[0-9a-f]{8}\s+__imp_(\S+)\s+([0-9a-f]{8,16})\s+(\S+):(\S+)", line, flags=_re.I)
        if match:
            name = match.group(1)
            name = _re.sub(r"@\d+$", "", name[1:] if name.startswith("_") and base < 0x100000000 else name)
            found.add((match.group(4).lower(), name, int(match.group(2), 16) - base))
    return found


def _tool_rows(text: str) -> list[list[str]]:
    return [line.split() for line in text.splitlines() if line.startswith("rva:")]


def _check(label: str, ok: bool, detail: str, failures: list[str]) -> None:
    print("%s %s: %s" % ("PASS" if ok else "FAIL", label, detail))
    if not ok:
        failures.append(label)


def check_listing(manifest: dict) -> list[str]:
    """Rows get_program_info, list_functions, list_methods, search_functions_by_name, list_segments, list_imports,
    list_exports, list_data_items and list_strings (docs/tool-mapping.md)."""
    failures: list[str] = []
    for arch in ARCHES:
        for exe in EXES:
            build, name = _build(manifest, arch, exe), target(arch, exe)
            label, base = "%s %s" % (arch, exe), int(build["image_base"], 16)
            # get_program_info: the identity from the PE header and from the saved analysis agree with the build.
            header = re.call("fingerprint", exe=build["path"])
            answer = re.query(name, "functions", limit=1)
            bits = 64 if arch == "x64" else 32
            ok = (build["sha256"] in header and ("image_base %s" % build["image_base"]) in header and "bits %d" % bits in header
                  and answer["sha256"] == build["sha256"] and int(answer["image_base"], 16) == base)
            _check("metadata " + label, ok, "sha256 %s base %s bits %d" % (build["sha256"][:12], build["image_base"], bits), failures)
            # list_functions: paged listing equals one big page, has no duplicates, and lists the map's functions.
            listed = _pages(name)
            single = _pages(name, 200)
            addresses = [int(f["address"], 16) for f in listed]
            unique = _unique(build["functions"])
            missing = {n for a, names in unique.items() if a not in set(addresses) for n in names}
            ok = (len(addresses) == len(set(addresses))
                  and addresses == [int(f["address"], 16) for f in single]
                  and missing == UNLISTED.get(exe, set()))
            _check("functions " + label, ok, "%d listed over %d pages of 100 (the same over pages of 200); map functions not listed %s (expected %s)"
                   % (len(addresses), -(-len(addresses) // 100), sorted(missing), sorted(UNLISTED.get(exe, set()))), failures)
            # list_methods / bounds: every listed map function starts at the map address and ends before the next map entry.
            by = {int(f["address"], 16): f for f in listed}
            entries, bad = sorted(unique), []
            for position, address in enumerate(entries):
                if address in by:
                    start, end = _body(by[address])
                    following = entries[position + 1] if position + 1 < len(entries) else None
                    if start != address or (following is not None and end >= following):
                        bad.append((hex(address), hex(end)))
            _check("bounds " + label, not bad, "%d map functions with exact entry and no body over the next entry; bad %s" % (len(entries), bad), failures)
            # search_functions_by_name: contains matches the analysis name; without symbols that is FUN_<address>.
            sample = next(a for a in entries if a in by)
            wanted = by[sample]["name"]
            hits = re.query(name, "functions", contains=wanted, limit=100)["functions"]
            mapped = next(iter(unique[sample]))
            nothing = re.query(name, "functions", contains=mapped, limit=100)
            ok = (wanted == "FUN_%08x" % sample and [int(h["address"], 16) for h in hits] == [sample]
                  and not nothing["functions"] and nothing["scanned"] >= len(listed))
            _check("search " + label, ok, "contains %s -> %s; contains %s (a map name) -> %d (no symbols in a stripped build)"
                   % (wanted, [h["address"] for h in hits], mapped, len(nothing["functions"])), failures)
            # list_segments: the section table agrees with the PE headers (not Ghidra memory blocks).
            table = re.call("fingerprint", exe=build["path"], detail="sections")
            tool = {row[0]: row for row in (line.split() for line in table.splitlines() if line.startswith("."))}
            expected = _sections(build["path"])
            ok = len(tool) == len(expected) and all(
                s["name"] in tool and ("rva=%#x" % s["rva"]) in tool[s["name"]] and ("vsize=%#x" % s["vsize"]) in tool[s["name"]]
                and ("raw=%#x" % s["raw_size"]) in tool[s["name"]] for s in expected)
            _check("segments " + label, ok, "%d sections %s" % (len(expected), [s["name"] for s in expected]), failures)
            # list_imports: the import table equals the linker map's __imp_ rows (module, name, IAT rva).
            truth = _map_imports(build)
            rows = _tool_rows(re.call("imports", exe=build["path"], limit=200))
            got = {(row[1].lower(), row[2], int(row[0][4:], 16)) for row in rows}
            ok = got == truth and SOME_IMPORTS.get(exe, set()) <= {item[1] for item in got}
            _check("imports " + label, ok, "%d imports, map %d, only-tool %s, only-map %s"
                   % (len(got), len(truth), sorted(got - truth)[:3], sorted(truth - got)[:3]), failures)
            # list_exports: an executable without an export table answers an empty list.
            exports = re.call("fingerprint", exe=build["path"], detail="exports")
            _check("exports " + label, "(no exports)" in exports and not _tool_rows(exports), "empty export table", failures)
            # list_strings: the source literals are found, and the bytes at the address are the literal.
            if exe in LITERALS:
                missing_strings = []
                for literal in LITERALS[exe]:
                    found = _tool_rows(re.call("strings", exe=build["path"], pattern="^%s$" % _re.escape(literal), limit=10))
                    where = [int(row[0][4:], 16) for row in found if " ".join(row[2:]) == literal]
                    if not where or _file_bytes(build["path"], where[0], len(literal)) != literal.encode():
                        missing_strings.append(literal)
                other = LITERALS["diff2.exe" if exe == "diff1.exe" else "diff1.exe"][-1]
                absent = not _tool_rows(re.call("strings", exe=build["path"], pattern=_re.escape(other), limit=10))
                _check("strings " + label, not missing_strings and absent,
                       "%d literals found at their bytes, other build's literal absent: %s; missing %s"
                       % (len(LITERALS[exe]), absent, missing_strings), failures)
        # list_data_items: no enumeration; per address, and RTTI names the vftables like the map does.
        build, name = _build(manifest, arch, "vcall_fixture.exe"), target(arch, "vcall_fixture.exe")
        wrong = []
        for symbol in ("Square::vftable", "Triangle::vftable", "Gadget::vftable", "Shape::vftable"):
            data = re.query(name, "data", build["globals"][symbol])
            label_names = [item["name"] for item in data["labels"]]
            if symbol not in label_names:
                wrong.append((symbol, label_names))
        slots = []
        for klass in ("Square", "Triangle"):
            data = re.query(name, "data", build["globals"][klass + "::vftable"])
            values = [int(c["value"], 16) for c in data["data"]["components"]]
            slots.append(values[:2] == [int(build["functions"][klass + "::area"], 16), int(build["functions"][klass + "::sides"], 16)])
        _check("data %s vcall_fixture.exe" % arch, not wrong and all(slots),
               "vftable labels equal the map names (bad %s); area and sides slots of Square and Triangle match the map" % wrong, failures)
    return failures


def _owner(entries: dict[int, list[str]], listed: list[dict], site: int) -> tuple:
    for function in listed:
        start, end = _body(function)
        if start <= site <= end:
            return tuple(entries.get(start, ()))
    return ()


def check_callgraph(manifest: dict) -> list[str]:
    """Rows get_function_by_address, get_function_calls, get_xrefs_to, get_xrefs_from and get_function_xrefs."""
    failures: list[str] = []
    for arch in ARCHES:
        for exe in EXES:
            build, name = _build(manifest, arch, exe), target(arch, exe)
            label, base = "%s %s" % (arch, exe), int(build["image_base"], 16)
            unique, listed = _unique(build["functions"]), _pages(name)
            listed_at = {int(f["address"], 16): f for f in listed}
            known = sorted(a for a in unique if a in listed_at)
            expected = {int(build["functions"][caller], 16): {int(build["functions"][c], 16) for c in callees}
                        for caller, callees in EDGES[exe].items()}
            bad_calls, bad_refs, bad_pe, extra, computed, tail = [], [], [], 0, 0, 0
            for address in known:
                dossier = re.query(name, "dossier", hex(address))
                found = {int(edge["to"], 16) for edge in dossier["callees"] if int(edge["to"], 16) in unique}
                if found != expected.get(address, set()):
                    bad_calls.append((hex(address), sorted(hex(x) for x in found), sorted(hex(x) for x in expected.get(address, set()))))
                start, end = _body(listed_at[address])
                if any(not start <= int(edge["from"], 16) <= end for edge in dossier["callees"]):
                    bad_calls.append((hex(address), "a callee site outside the body"))
                # get_xrefs_to: the references action and the dossier's callers are the same call sites, and every
                # expected caller appears as a site inside that caller's body.
                references = re.query(name, "xrefs", hex(address))["references"]
                sites = {int(r["from"], 16) for r in references}
                calls = {int(r["from"], 16) for r in dossier["callers"]}
                # xrefs also lists data references (vtable slots, unwind tables); every other reference is not a call.
                others = {int(r["from"], 16): r["type"] for r in references if int(r["from"], 16) not in calls}
                owners = {_owner(unique, listed, s) for s in calls}
                wanted = {tuple(unique[c]) for c, callees in expected.items() if address in callees}
                if not calls <= sites or any("CALL" in kind for kind in others.values()) or not wanted <= owners:
                    bad_refs.append((hex(address), sorted(hex(s) for s in calls - sites)[:3], sorted(wanted - owners)))
                # The PE-only callers tool lists the direct call sites (E8/E9 bytes reaching the entry); a computed
                # call that the analysis resolved (a virtual call through a known vtable) is not decodable there.
                direct = {s for s in calls if _file_bytes(build["path"], s - base, 1) in (b"\xe8", b"\xe9")}
                pe_sites = {base + int(row[0][4:], 16) for row in _tool_rows(re.call("callers", exe=build["path"], address="va:" + hex(address)))}
                computed += len(calls - direct)
                if not direct <= pe_sites:
                    bad_pe.append((hex(address), sorted(hex(s) for s in direct - pe_sites)[:3]))
                # The PE-only callees tool: the calls inside the body include the analysis' direct calls; sites past
                # the body (leaf functions have no pdata record, so decoding runs on) are counted, not failed.
                pe_calls = [(base + int(row[0][4:], 16), base + int(row[2][4:], 16)) for row in
                            _tool_rows(re.call("callees", exe=build["path"], address="va:" + hex(address)))]
                inside = {(s, t) for s, t in pe_calls if start <= s <= end}
                extra += len(pe_calls) - len(inside)
                truth_calls = {(int(e["from"], 16), int(e["to"], 16)) for e in dossier["callees"]
                               if _file_bytes(build["path"], int(e["from"], 16) - base, 1) == b"\xe8"}
                tail += sum(1 for e in dossier["callees"] if _file_bytes(build["path"], int(e["from"], 16) - base, 1) != b"\xe8")
                if not truth_calls <= inside:
                    bad_pe.append((hex(address), "callees", sorted(hex(s) for s, _ in truth_calls - inside)[:3]))
            _check("callees " + label, not bad_calls, "%d functions, edges from the sources %s; mismatches %s"
                   % (len(known), {sorted(unique[c])[0]: len(v) for c, v in expected.items()}, bad_calls[:3]), failures)
            _check("xrefs_to " + label, not bad_refs, "callers equal the xref sites and cover the expected callers; mismatches %s" % bad_refs[:3], failures)
            _check("pe_callgraph " + label, not bad_pe,
                   "PE callers/callees contain every direct E8/E9 edge of the analysis; %d computed call(s) and %d tail jump(s) are only in the analysis, "
                   "the callees tool decoded %d site(s) past leaf functions; mismatches %s"
                   % (computed, tail, extra, bad_pe[:3]), failures)
            # get_function_by_address: any address inside a body answers the same function.
            odd = []
            for address in known:
                start, end = _body(listed_at[address])
                inner = re.query(name, "function", hex(end))["function"]
                if int(inner["address"], 16) != start:
                    odd.append((hex(end), inner["address"]))
            _check("function_by_address " + label, not odd, "%d map functions answered from their last byte; mismatches %s" % (len(known), odd[:3]), failures)
    return failures


def _write_map(manifest: dict, arch: str, exe: str, out_dir: Path, extra: list | None = None, digest: str = "") -> Path:
    build = _build(manifest, arch, exe)
    base = int(build["image_base"], 16)
    entries = [{"name": n, "rva": "0x%x" % (int(a, 16) - base)} for n, a in build["functions"].items()]
    path = out_dir / ("namemap-%s-%s%s.json" % (arch, exe, "-" + digest[:6] if digest else ""))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"sha256": digest or build["sha256"],
                                "source": "linker map %s, function rows (Z8 parity)" % Path(build["path"]).with_suffix(".map").name,
                                "entries": entries + (extra or [])}))
    return path


def check_namemap(manifest: dict) -> list[str]:
    """Rows decompile_function (by name), decompile_function_by_address and read_memory, with the cited address map as the name source."""
    failures: list[str] = []
    out_dir = Path(MANIFEST_DIR[0]) / "namemap"
    for arch in ARCHES:
        for exe in EXES:
            build, name = _build(manifest, arch, exe), target(arch, exe)
            label, base = "%s %s" % (arch, exe), int(build["image_base"], 16)
            listed = {int(f["address"], 16) for f in _pages(name)}
            re.query(name, "address_map", path=str(_write_map(manifest, arch, exe, out_dir)))
            wrong, undone = [], []
            for symbol, address in build["functions"].items():
                where = int(address, 16)
                if where in listed:
                    answer = re.query(name, "function", "name:" + symbol)
                    resolved = answer.get("address_resolution", {})
                    if int(answer["function"]["address"], 16) != where or int(resolved.get("rva", "0"), 16) != where - base:
                        wrong.append((symbol, answer["function"]["address"], resolved.get("rva")))
                else:
                    undone.append(symbol)
                # read_memory: the bytes behind a name are the file's bytes at the mapped address.
                text = re.call("bytes", exe=build["path"], address="name:" + symbol, size=16)
                read = bytes.fromhex(next(line for line in text.splitlines() if not line.startswith("#")).replace(" ", ""))
                if read != _file_bytes(build["path"], where - base, 16):
                    wrong.append((symbol, "bytes", read.hex()))
                # The saved analysis' own instruction bytes (Ghidra memory) equal those file bytes too.
                if where in listed:
                    scanned = re.query(name, "scan", hex(where), limit=2)["instructions"]
                    memory = b"".join(bytes.fromhex(i["bytes"].replace(" ", "")) for i in scanned)
                    if memory != _file_bytes(build["path"], where - base, len(memory)):
                        wrong.append((symbol, "ghidra memory", memory.hex()))
            _check("namemap " + label, not wrong,
                   "%d names resolved to the map address, %d unlisted name(s) %s read through the map; mismatches %s"
                   % (len(build["functions"]) - len(undone), len(undone), undone, wrong[:3]), failures)
        build, name = _build(manifest, arch, "flow_fixture.exe"), target(arch, "flow_fixture.exe")
        # decompile_function by name: the same function the address form decompiles.
        by_name = re.query(name, "decompile", "name:fx_read")
        by_address = re.query(name, "decompile", build["functions"]["fx_read"])
        ok = by_name["function"] == by_address["function"] and by_name["c"] == by_address["c"] and "return" in by_name["c"]
        _check("decompile_by_name %s" % arch, ok, "name:fx_read decompiles to %s as the address form" % by_name["function"]["address"], failures)
        # Negative rows: an unknown name, a map for another build and two maps that disagree are refused.
        refusals = []
        for what, call in (
            ("unknown name", lambda: re.query(name, "function", "name:not_in_any_map")),
            ("other build", lambda: re.query(name, "address_map", path=str(_write_map(
                manifest, arch, "flow_fixture.exe", out_dir, digest=_build(manifest, arch, "diff1.exe")["sha256"])))),
        ):
            try:
                call()
                refusals.append(what + " accepted")
            except Exception as error:  # the client raises the engine's refusal
                if REFUSAL_TEXT[what] not in str(error):
                    refusals.append("%s: unexpected %s" % (what, str(error)[:160]))
        for variant, rva in (("a", 0x1000), ("b", 0x1010)):
            path = out_dir / ("conflict-%s-%s.json" % (arch, variant))
            path.write_text(json.dumps({"sha256": build["sha256"], "source": "Z8 conflict probe " + variant,
                                        "entries": [{"name": "z8_conflict", "rva": "0x%x" % rva}]}))
            re.query(name, "address_map", path=str(path))
            path.unlink()  # the rows are loaded; do not leave the probe files in the fixtures dir
        try:
            re.query(name, "function", "name:z8_conflict")
            refusals.append("conflicting rows resolved")
        except Exception as error:
            if "ambiguous" not in str(error).lower():
                refusals.append("conflict: unexpected %s" % str(error)[:160])
        _check("namemap_refusals %s" % arch, not refusals,
               "unknown name, another build's map and conflicting rows are refused; problems %s" % refusals, failures)
        # read_memory / list_segments / list_classes gap: ghidra_query has no such action.
        gaps = []
        for action in ("memory", "read_memory", "segments", "classes", "namespaces"):
            try:
                re.query(name, action, build["functions"]["fx_read"])
                gaps.append(action + " exists")
            except Exception as error:
                # Only the engine's explicit unknown-action refusal proves the action does not exist;
                # any other failure (daemon, permission, module load) is a real error, not a "no match".
                if UNKNOWN_ACTION not in str(error):
                    gaps.append("%s: unexpected error %s" % (action, str(error)[:160]))
        _check("documented_gaps %s" % arch, not gaps,
               "no ghidra_query action for memory, segments, classes or namespaces (the tool-mapping gaps); found or unexpected %s" % gaps, failures)
    return failures


def check_scenario(manifest: dict) -> list[str]:
    """Z11: the runtime scenario of the old toolchain, game-free, on flow_fixture.exe (tools/scenarios/kotor_vfs_lookup.py).
    The fixture's folder is the install (hashed before and after, never run); a copy of it is the profile that is
    spawned paused. Twelve steps, run twice, the second bundle compared with the first. fx_exported is probed with a
    limit of 8 and fires about 20 times a second, so the window ends partial with hit_limit_reached, by design. The
    writers step needs the prepared analysis target (prepare_fixtures.py); without it the step is a skip that this
    line says, and the run is judged on the other eleven."""
    import shutil
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools" / "scenarios"))
    import kotor_vfs_lookup as scenario
    from hydralysis import evidence_bundle
    failures = []
    for arch in ARCHES:
        build = manifest[arch + "/flow_fixture.exe"]
        install = Path(build["path"]).parent
        work = Path(MANIFEST_DIR[0]) / "_scenario" / arch
        shutil.rmtree(work, ignore_errors=True)
        profile = work / "profile"
        shutil.copytree(install, profile, ignore=shutil.ignore_patterns("*.stop", "*.log"))
        spec = scenario.fixture_spec(manifest, arch, str(work / "flow.stop"))
        spec["writers"]["target"] = target(arch, "flow_fixture.exe")
        try:
            re.query(spec["writers"]["target"], "writes", limit=1, timeout_s=120, offset="0x4")
            engine = ""
        except Exception as error:  # no prepared analysis: the writers step is a skip, said below
            spec["writers"] = None
            spec["allowed_skips"]["writers"] = "no analysis engine target (%s)" % str(error)[:80]
            engine = "writers skipped: " + spec["allowed_skips"]["writers"]
        result = scenario.run_scenario(spec, re, profile, work / "out", install, twice=True, log=lambda line: print("   " + line))
        runs = result["runs"]
        events = []
        for run in runs:
            bundle = evidence_bundle.load_bundle(Path(run["bundle"])) if run["bundle"] else {"records": []}
            hook = [r for r in bundle["records"] if r["content"]["name"].startswith(spec["name"] + ":0x")]
            events.append(hook[0]["content"]["parameters"]["first_events"] if hook else None)
        consecutive = all(e and all(b == a + 1 for a, b in zip(e, e[1:])) for e in events)
        ok = result["ok"] and consecutive and events[0] == events[1]
        print("%s scenario %s: pass sequence %s (skipped %s), coverage %s %s, silent drops %s, install tree unchanged %s, "
              "first frames %s, bundles %s%s" % ("PASS" if ok else "FAIL", arch, len(runs[0]["pass_sequence"]), sorted(runs[0]["skipped"]),
                                                  (runs[0]["coverage"] or {}).get("status"), runs[0]["limitations"],
                                                  [r["silent_drops"] for r in runs], [r["install_tree"]["unchanged"] for r in runs], events,
                                                  (result["compare"] or {}).get("status"), ("; " + engine) if engine else ""))
        if not ok:
            for run in runs:
                for row in run["steps"]:
                    if row["status"] not in ("pass", "skipped"):
                        print("   %s %s: %s" % (row["step"], row["status"], str(row["detail"])[:300]))
            failures.append("scenario " + arch)
    return failures


CHECKS = {"value_flow": check_value_flow, "writers": check_writers, "hooked": check_hooked, "diff": check_diff,
          "vcalls": check_vcalls, "sample": check_sample, "mcp_typed_read": check_mcp_typed_read, "ledger": check_ledger,
          "listing": check_listing, "callgraph": check_callgraph, "namemap": check_namemap,
          "break_continue": check_break_continue, "export_hook": check_export_hook, "capture": check_capture,
          "snapshot": check_snapshot, "scenario": check_scenario}


def main(argv: list[str]) -> int:
    manifest = load(argv[0])
    selected = argv[1:] or list(CHECKS)
    failures = []
    for name in selected:
        failures += CHECKS[name](manifest)
    print("%d check(s) failed: %s" % (len(failures), failures) if failures else "all checks passed")
    return len(failures)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
