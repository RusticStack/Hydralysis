"""Run the verification checks against the prepared fixtures (docs/verification-fixtures.md).

usage: python tests/fixtures/verify_fixtures.py <fixtures out dir> [check ...]
Each check prints PASS/FAIL with its evidence; the exit status is the number of failures.
RUSTICRE_CONFIG selects the data root the fixtures were prepared in (prepare_fixtures.py).
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

from rusticre.client import Client

sys.path.insert(0, str(Path(__file__).resolve().parent))
from prepare_fixtures import target_name  # noqa: E402

re = Client()
ARCHES = ("x64", "x86")


MANIFEST: dict = {}


def load(out_dir: str) -> dict:
    MANIFEST.update(json.loads((Path(out_dir) / "manifest.json").read_text()))
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
    """A fixture process under a RusticRE runtime session; stopped through its stop file."""

    def __init__(self, arch: str, exe: str):
        build = MANIFEST[arch + "/" + exe]
        self.build, self.stop_file = build, Path(build["path"]).with_suffix(".stop")
        self.stop_file.unlink(missing_ok=True)
        started = re.runtime("spawn", exe=build["path"], sha256=build["sha256"], argv=[str(self.stop_file)],
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

    def __exit__(self, *exc):
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
        transferred = moved_table["checks"]
        misplaced = [row["name"] for row in transferred if
                     names_two.get(int(row["address"].removeprefix("rva:"), 16)) != row["name"]]
        unplaced = sorted(row.get("name", str(row)) if isinstance(row, dict) else str(row) for row in moved_table["unplaced"])
        ok = not wrong and not misplaced and unplaced == ["df_removed"]
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


class McpClient:
    """The real stdio MCP server (rusticre mcp), driven as an agent's client would."""

    def __init__(self):
        import os
        import subprocess
        self.process = subprocess.Popen([sys.executable, "-m", "rusticre", "mcp"], stdin=subprocess.PIPE,
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
            reads = []
            for _ in range(2):
                time.sleep(1)
                reads.append({f["name"]: f.get("value") for f in mcp.tool(
                    "runtime", action="read", options={"session": session, "address": hex(address), "type": "Config",
                                                       "target": name})["fields"]})
            mcp.tool("runtime", action="detach", options={"session": session, "owner": owner})
            stop.write_text("stop")
        finally:
            mcp.close()
        ok = (job.get("state") == "done" and all(r["mode"] == 2 and 0 <= r["limit"] <= 100 for r in reads)
              and reads[1]["speed"] > reads[0]["speed"] > 0)
        print("%s mcp_typed_read %s: import %s; reads %s" % ("PASS" if ok else "FAIL", arch, job.get("state"), reads))
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


CHECKS = {"value_flow": check_value_flow, "writers": check_writers, "hooked": check_hooked, "diff": check_diff,
          "vcalls": check_vcalls, "sample": check_sample, "mcp_typed_read": check_mcp_typed_read, "ledger": check_ledger}


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
