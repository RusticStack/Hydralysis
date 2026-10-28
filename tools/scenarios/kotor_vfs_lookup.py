"""The runtime scenario of the old toolchain, end to end, through Hydralysis (Z11, audit C2-29).

Twelve steps, always in this order:

  1 verify_sites   the hook sites' prologues, read from the profile copy's file (static; nothing runs yet)
  2 spawn          the profile copy's executable, paused, SHA-256 checked
  3 observe        probes at module+RVA sites, each checked against the file's bytes
  4 export_hooks   probes by export name (CreateFileW/CreateFileA for the game), resolved from the module file
  5 capture        a capture window opens while the program is still paused (spec `capture_first`: before the first
                   probe, for a binding whose probes fire when installed or a program that is already running)
  6 resume         the program runs; the window closes when enough events are in or the time is up
  7 typed_read     a typed read of a live structure, compared with the expected values
  8 snapshot       a snapshot of modules and regions
  9 writers        who writes a field (needs the analysis engine; an explicit skip without it)
 10 detach         probes unloaded, `patches` shows no difference in the file, detach leaves the program alive
 11 evidence_add   one claim per observation into a fresh ledger, coverage and limitations from the capture
 12 bundle_export  the ledger as an evidence bundle, verified

`--twice` runs the scenario two times (a fresh ledger and bundle each) and compares the bundles: the second must
have no non-volatile difference. The claims carry what repeats from run to run (first events, coverage, limits);
what differs by nature (capture id, session, times) goes in the volatile `provenance`.

The game is only ever run from a PROFILE COPY (`--profile`). `--install` is the original; its tree hash is taken
before and after and must not change. A live run on the game is the owner's decision (profile copy only); the
default game spec (`--spec kotor`) lists no addresses it could not prove, so it needs the owner's site file.

    python tools/scenarios/kotor_vfs_lookup.py --profile <dir> [--install <dir>] [--spec kotor|<file.json>] [--twice]

Exit status 0 only when every step ran as the spec's recorded pass sequence says, no hook dropped events without a
stated limitation, the install tree hash is unchanged, and (with --twice) the second bundle compares equal.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
import time
from pathlib import Path

STEPS = ("verify_sites", "spawn", "observe", "export_hooks", "capture", "resume", "typed_read", "snapshot",
         "writers", "detach", "evidence_add", "bundle_export")
# A limitation that states a drop: a hook that lost events is explained by one of these.
EXPLAINS_LOSS = ("hit_limit_reached", "runtime:events_missing", "payload_clipped", "runtime:event_log_full",
                 "runtime:event_log_write_failed", "event_ring_overflow")


class Skip(Exception):
    """A step that does not apply to this spec; the reason is part of the record."""


def tree_hash(root: Path) -> str:
    """One hash for a folder: the sorted relative paths, sizes and file SHA-256 (links are not followed)."""
    root = Path(root)
    lines = []
    for folder, dirs, files in os.walk(root, followlinks=False):
        dirs.sort()
        for name in sorted(files):
            path = Path(folder) / name
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1 << 20), b""):
                    digest.update(chunk)
            lines.append("%s\0%d\0%s" % (path.relative_to(root).as_posix(), path.stat().st_size, digest.hexdigest()))
    return hashlib.sha256("\n".join(lines).encode()).hexdigest()


def file_sha256(path: Path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def _inside(path: Path, folder: Path) -> bool:
    try:
        Path(path).resolve().relative_to(Path(folder).resolve())
        return True
    except ValueError:
        return False


def kotor_spec() -> dict:
    """The game's scenario outline. Export hooks need no address; the module sites need the owner's verified table
    (a site file via --spec), because no address is written here that this repository could not prove."""
    return {"name": "kotor_vfs_lookup", "game": "kotor", "exe": "swkotor.exe", "fixture": False, "sha256": "",
            "argv": [], "sites": [], "observe": [],
            "exports": [{"module": "kernel32.dll", "export": "CreateFileW", "sha256": "auto", "limit": 200,
                         "capture": [{"arg": 0, "as": "utf16", "size": 520, "label": "path"}]},
                        {"module": "kernel32.dll", "export": "CreateFileA", "sha256": "auto", "limit": 200,
                         "capture": [{"arg": 0, "as": "utf8", "size": 260, "label": "path"}]}],
            "run": {"min_events": 50, "timeout_s": 60, "record_first": 5},
            "typed_read": None, "snapshot": {"regions": []}, "writers": None,
            "allowed_skips": {"verify_sites": "no site table given", "observe": "no module+rva probes in the spec",
                              "typed_read": "no structure given", "writers": "no analysis engine target given"},
            "owner_decision": "N4: a live game run, profile copy only"}


def load_spec(value: str) -> dict:
    if value == "kotor":
        return kotor_spec()
    spec = json.loads(Path(value).read_text(encoding="utf-8"))
    if not isinstance(spec, dict) or not spec.get("exe"):
        raise ValueError("a spec is a JSON object with at least `exe`")
    return spec


def fixture_spec(manifest: dict, arch: str, stop_file: str) -> dict:
    """The game-free analogue: flow_fixture.exe from the fixtures manifest (tests/fixtures/build_fixtures.py).
    fx_exported(int frame) runs about 20 times a second; g_config is {mode 2, limit 0..100, growing speed}."""
    build = manifest[arch + "/flow_fixture.exe"]
    base = int(build["image_base"], 16)
    entry = int(build["functions"]["fx_exported"], 16) - base
    from hydralysis.pe import Image
    prologue = Image(Path(build["path"])).read_rva(entry, 8)
    expect = " ".join("%02X" % byte for byte in prologue)
    config = int(build["globals"]["g_config"], 16) - base
    frame = [{"arg": 0, "as": "i32", "label": "frame"}]
    return {"name": "flow_fixture_" + arch, "game": "fixture", "exe": Path(build["path"]).name, "fixture": True,
            "sha256": build["sha256"], "argv": [stop_file], "stop_file": stop_file,
            "sites": [{"name": "fx_exported", "address": "rva:%#x" % entry, "expect": expect}],
            "observe": [{"module": Path(build["path"]).name, "rva": hex(entry), "sha256": build["sha256"], "expect": expect,
                         "limit": 8, "capture": frame}],
            "exports": [],
            "run": {"min_events": 12, "timeout_s": 20, "record_first": 3, "limit_reached": True},
            "typed_read": {"module": Path(build["path"]).name, "rva": hex(config), "size": 12,
                           "layout": [{"name": "mode", "offset": 0, "type": "i32"}, {"name": "limit", "offset": 4, "type": "i32"},
                                      {"name": "speed", "offset": 8, "type": "f32"}],
                           "expect": {"mode": 2}, "between": {"limit": [0, 100]}},
            "snapshot": {"regions": [{"name": "config", "module": Path(build["path"]).name, "rva": hex(config), "size": 4,
                                      "layout": [{"name": "mode", "offset": 0, "type": "i32"}]}]},   # mode only: limit and speed move
            "writers": {"target": "", "module": Path(build["path"]).name, "object_rva": hex(config), "offset": "0x4",
                        "size": 4, "window_s": 3, "min_writers": 3},
            "allowed_skips": {"export_hooks": "flow_fixture's probe is placed by RVA; export hooks have their own check"}}


class Scenario:
    """One run. `client` has `.runtime(action, **options)`, `.check_prologues(exe, rows, sha256=)` and, for the
    writers step, `.query(target, action, address, **options)`."""

    def __init__(self, spec: dict, client, profile: Path, out: Path, install: Path | None = None, log=print):
        self.spec, self.client, self.profile, self.out, self.install = spec, client, Path(profile), Path(out), install
        self.log = log
        self.steps: list[dict] = []
        self.session = self.owner = None
        self.hooks: list[dict] = []
        self.exe = self.profile / spec["exe"]
        self.digest = ""
        self.closed: dict = {}
        self.first_events: dict[str, list] = {}
        self.read_values: dict = {}
        self.detached = False
        self.target: dict = {}
        self.facts: dict = {}

    # ---- plumbing --------------------------------------------------------------------------------------------
    def rt(self, action: str, **options):
        if self.session:
            options = {"session": self.session, "owner": self.owner, **options}
        return self.client.runtime(action, **options)

    def run(self) -> dict:
        self.out.mkdir(parents=True, exist_ok=True)
        before = after = None
        if self.install is not None:
            before = tree_hash(self.install)
        failed = False
        try:
            self._guard()
            for name in STEPS:
                if failed and name != "detach":
                    self.steps.append({"step": name, "status": "not_run", "detail": "an earlier step failed"})
                    continue
                if failed and name == "detach" and not self.session:
                    self.steps.append({"step": name, "status": "not_run", "detail": "no session was started"})
                    continue
                started = time.monotonic()
                try:
                    detail = getattr(self, "step_" + name)()
                    row = {"step": name, "status": "pass", "detail": detail}
                except Skip as skip:
                    row = {"step": name, "status": "skipped", "detail": str(skip)}
                except Exception as error:  # the record says what failed; the run ends cleanly below
                    row = {"step": name, "status": "fail", "detail": "%s: %s" % (type(error).__name__, str(error)[:600])}
                    failed = True
                row["seconds"] = round(time.monotonic() - started, 2)
                self.steps.append(row)
                self.log("%-13s %s  %s" % (name, row["status"].upper(), json.dumps(row["detail"], default=str)[:300]))
        finally:
            self._cleanup()
            if self.install is not None:
                after = tree_hash(self.install)
        return self._result(before, after)

    def _guard(self) -> None:
        if self.install is not None and (_inside(self.profile, self.install) or _inside(self.install, self.profile)):
            raise ValueError("the profile copy must be a separate folder from the install; the install is never run")
        if not self.exe.is_file():
            raise FileNotFoundError("the profile copy has no %s" % self.spec["exe"])
        self.digest = file_sha256(self.exe)
        if self.spec.get("sha256") and self.spec["sha256"] != self.digest:
            raise ValueError("the profile's %s has SHA-256 %s, the spec says %s" % (self.spec["exe"], self.digest, self.spec["sha256"]))

    def _cleanup(self) -> None:
        if self.session and not self.detached:
            try:
                self.rt("detach")
                self.detached = True
            except Exception as error:
                self.log("cleanup detach: %s" % str(error)[:200])
        stop = self.spec.get("stop_file")
        if stop:
            Path(stop).write_text("stop")

    # ---- the twelve steps ------------------------------------------------------------------------------------
    def step_verify_sites(self):
        rows = self.spec.get("sites") or []
        if not rows:
            raise Skip(self.spec.get("allowed_skips", {}).get("verify_sites", "the spec lists no sites"))
        answer = self.client.check_prologues(str(self.exe), rows, sha256=self.digest)
        if not answer.get("matched"):
            raise RuntimeError("prologue mismatch at %s" % [r for r in answer.get("rows", []) if not r.get("matched", True)][:3])
        return {"sites": len(rows), "matched": answer["summary"]["matched"]}

    def step_spawn(self):
        stop = self.spec.get("stop_file")
        if stop:
            Path(stop).unlink(missing_ok=True)
        started = self.client.runtime("spawn", exe=str(self.exe), sha256=self.digest, argv=list(self.spec.get("argv") or []),
                                      cwd=str(self.profile))
        self.session, self.owner = started["session"], started["owner"]
        if started.get("state") != "spawn_paused":
            raise RuntimeError("the program is not paused after spawn: state %s" % started.get("state"))
        self.target = {"pid": started.get("pid")}
        return {"state": started["state"], "arch": started.get("arch")}

    def _modules(self) -> list[dict]:
        return self.rt("modules", limit=200)["modules"]

    def _module_sha(self, hook: dict) -> str:
        wanted = hook.get("sha256") or "auto"
        if wanted != "auto":
            return wanted
        name = str(hook["module"]).lower()
        for module in self._modules():
            if module["name"].lower() == name or str(module["path"]).lower().endswith("\\" + name):
                return file_sha256(Path(module["path"]))
        raise RuntimeError("module %s is not loaded yet, so its file hash is unknown" % hook["module"])

    def _open_window(self) -> dict:
        if not self.facts.get("capture"):
            started = self.rt("capture", op="start", name=self.spec["name"])
            self.facts["capture"] = started["capture"]
        return self.facts["capture"]

    def _install(self, kind: str, hook: dict) -> dict:
        if self.spec.get("capture_first"):
            self._open_window()
        options = {"module": hook["module"], "sha256": self._module_sha(hook), "limit": int(hook.get("limit", 20))}
        for key in ("rva", "export", "expect"):
            if hook.get(key):
                options[key] = hook[key]
        if hook.get("capture"):
            options["capture"] = hook["capture"]
        probe = self.rt("observe", **options)
        if not probe.get("verified"):
            raise RuntimeError("probe not verified: %s" % probe)
        row = {"kind": kind, "hook_id": probe["hook_id"], "module": hook["module"], "rva": probe["rva"],
               "export": (probe.get("export") or {}).get("name"), "limit": options["limit"],
               "label": hook.get("export") or probe["rva"]}
        self.hooks.append(row)
        return row

    def step_observe(self):
        rows = self.spec.get("observe") or []
        if not rows:
            raise Skip(self.spec.get("allowed_skips", {}).get("observe", "no module+rva probes in the spec"))
        return [self._install("rva", hook)["label"] for hook in rows]

    def step_export_hooks(self):
        rows = self.spec.get("exports") or []
        if not rows:
            raise Skip(self.spec.get("allowed_skips", {}).get("export_hooks", "no export probes in the spec"))
        return [self._install("export", hook)["label"] for hook in rows]

    def step_capture(self):
        if not self.hooks:
            raise RuntimeError("no probe is installed, so a window would cover nothing")
        opened_early = bool(self.facts.get("capture"))
        capture = self._open_window()
        return {"capture": capture[:16] + "..", "probes": len(self.hooks), "opened_before_the_probes": opened_early}

    def step_resume(self):
        run = self.spec.get("run") or {}
        resumed = self.rt("resume")
        deadline = time.monotonic() + float(run.get("timeout_s", 30))
        want = int(run.get("min_events", 1))
        seen = {}
        while time.monotonic() < deadline:
            report = self.rt("capture", op="counters")["hooks"]
            seen = {h["hook_id"]: (report.get(h["hook_id"]) or {}).get("seen") or 0 for h in self.hooks}
            if sum(seen.values()) >= want:
                break
            time.sleep(0.2)
        closed = self.rt("capture", op="stop")
        self.closed = closed
        verified = self.rt("capture", op="verify", capture=closed["capture"])
        if not verified.get("ok"):
            raise RuntimeError("the capture's log does not verify: %s" % verified.get("first_bad"))
        record_first = int(run.get("record_first", 3))
        page = self.rt("capture", op="read", capture=closed["capture"], limit=200)
        by_hook: dict[str, list] = {}
        for event in page["events"]:
            payload = event["message"].get("payload") or {}
            if payload.get("event") in ("enter", "break"):
                by_hook.setdefault(payload.get("hook_id"), []).append(self._decoded(payload))
        self.first_events = {h["hook_id"]: by_hook.get(h["hook_id"], [])[:record_first] for h in self.hooks}
        return {"state": resumed.get("state"), "seen": seen, "coverage": closed["coverage"]["status"],
                "limitations": closed["limitations"], "log_verifies": True}

    @staticmethod
    def _decoded(payload: dict):
        values = [item.get("value") for item in (payload.get("decoded") or []) if isinstance(item, dict)]
        if not values:
            values = [item.get("hex") for item in (payload.get("captures") or []) if isinstance(item, dict)]
        return values[0] if len(values) == 1 else values

    def step_typed_read(self):
        spec = self.spec.get("typed_read")
        if not spec:
            raise Skip(self.spec.get("allowed_skips", {}).get("typed_read", "no structure given"))
        options = {key: spec[key] for key in ("module", "rva", "address", "size", "layout") if key in spec}
        if "module" in options:
            options["sha256"] = self._module_sha(spec)
        read = self.rt("read", **options)
        values = {field["name"]: field.get("value") for field in read["fields"]}
        wrong = {k: (values.get(k), v) for k, v in (spec.get("expect") or {}).items() if values.get(k) != v}
        for key, (low, high) in (spec.get("between") or {}).items():
            if not isinstance(values.get(key), (int, float)) or not low <= values[key] <= high:
                wrong[key] = (values.get(key), [low, high])
        if wrong:
            raise RuntimeError("typed read differs from what was expected (got, wanted): %s" % wrong)
        self.read_values = {k: values[k] for k in (spec.get("expect") or {})}
        return values

    def step_snapshot(self):
        options = dict(self.spec.get("snapshot") or {})
        regions = []
        for region in options.get("regions") or []:
            region = dict(region)
            if "module" in region:
                region["sha256"] = self._module_sha(region)
            regions.append(region)
        taken = self.rt("snapshot", name=self.spec["name"], regions=regions)
        main = next((m for m in taken["modules"] if m.get("file_sha256") == self.digest), None)
        if main is None:
            raise RuntimeError("no module of the snapshot carries the executable's file hash")
        if not all(r.get("ok") for r in taken["regions"]):
            raise RuntimeError("a region could not be read: %s" % [r for r in taken["regions"] if not r.get("ok")])
        again = self.rt("snapshot", name=self.spec["name"], regions=regions)
        compared = self.rt("compare", a=taken["snapshot"], b=again["snapshot"])
        if not compared["equal"]:
            raise RuntimeError("two snapshots of the same moment differ outside the default masks: %s" % compared["differences"][:3])
        self.facts["snapshot"] = {"main_module": main["name"], "modules_complete": taken.get("modules_complete")}
        return {"modules": len(taken["modules"]), "regions": len(taken["regions"]), "compare_equal": True}

    def step_writers(self):
        spec = self.spec.get("writers")
        query = getattr(self.client, "query", None)
        if not spec or not spec.get("target") or query is None:
            raise Skip(self.spec.get("allowed_skips", {}).get("writers", "no analysis engine target; the writers step needs one"))
        base = next(int(m["base"], 16) for m in self._modules() if m["name"].lower() == spec["module"].lower())
        rows = query(spec["target"], "writes", limit=32, timeout_s=120, offset=spec["offset"])["writes"]
        answer = self.rt("writers", target=spec["target"], rows=rows, object=hex(base + int(spec["object_rva"], 0)),
                         offset=spec["offset"], size=spec["size"], window_s=spec["window_s"])
        writers = answer["writers"]
        if len(writers) < int(spec.get("min_writers", 1)):
            raise RuntimeError("%d writer site(s) found, at least %s expected" % (len(writers), spec.get("min_writers", 1)))
        self.facts["writers"] = {"count": len(writers), "sites": [w["site"] for w in writers],
                                 "not_probed": [s["site"] for s in answer["sites"] if not s.get("probed")]}
        return {"writers": len(writers), "sites_probed": sum(1 for s in answer["sites"] if s.get("probed"))}

    def step_detach(self):
        probes = [h["hook_id"] for h in self.hooks]
        for hook_id in probes:
            self.rt("unload", hook_id=hook_id)
        status = self.rt("status", limit=1)
        self.target = {"pid": status.get("pid"), "created_ms": status.get("target_created_ms")}
        # the sites of the probes, unless the spec names the ones to compare with the file (a probe may sit where the
        # file has no section bytes to compare, which the fake binding's header probe does)
        rows = [{"module": h["module"], "rva": h["rva"], "size": 8, "name": h["label"], "sha256": self._module_sha(h)}
                for h in self.hooks] if not self.spec.get("patch_sites") else                [{"size": 8, "sha256": self.digest, **row} for row in self.spec["patch_sites"]]
        patches = self.rt("patches", rows=rows) if rows else {"patched": 0, "checked": 0}
        if patches["patched"]:
            raise RuntimeError("%d probe site(s) still differ from the file after unload" % patches["patched"])
        self.rt("detach")
        self.detached = True
        from hydralysis import proc
        alive = bool(self.target["pid"] and self.target["created_ms"] and proc.identity(int(self.target["pid"]), int(self.target["created_ms"])))
        if not alive:
            raise RuntimeError("the program is not running after detach")
        return {"unloaded": len(probes), "patched_after_unload": patches["patched"], "sites_checked": patches["checked"],
                "target_alive_after_detach": True}

    # ---- evidence and bundle ---------------------------------------------------------------------------------
    def _claims(self) -> list[dict]:
        spec, closed = self.spec, self.closed
        limitations = sorted(set(closed["limitations"]) | ({"fixture_only"} if spec.get("fixture") else set()))
        rows = {h["hook_id"]: h for h in closed["hooks"]}
        base = dict(game=spec["game"], build=self.digest[:16], subject_sha256=self.digest,
                    confidence="observed", authority="controlled-replay")
        claims = []
        for hook in self.hooks:
            row = rows[hook["hook_id"]]
            first = self.first_events.get(hook["hook_id"], [])
            claims.append({**base, "kind": "runtime_hook", "name": "%s:%s" % (spec["name"], hook["label"]),
                           "address": hook["rva"], "subsystem": "runtime",
                           "note": "probe on %s %s; the first %d recorded argument values are listed in parameters"
                                   % (hook["module"], hook["label"], len(first)),
                           "source": "runtime capture of a spawned, paused program (kotor_vfs_lookup scenario)",
                           "coverage": closed["coverage"], "limitations": limitations,
                           "parameters": {"hook": {k: hook[k] for k in ("kind", "module", "rva", "export", "limit")},
                                          "first_events": first, "events_recorded_at_most_limit": row["recorded"] <= hook["limit"]}})
        if self.read_values:
            claims.append({**base, "kind": "runtime_read", "name": "%s:typed_read" % spec["name"], "subsystem": "runtime",
                           "address": spec["typed_read"].get("rva", ""),
                           "note": "typed read of a live structure at one moment; stable fields only",
                           "source": "runtime read through a layout", "coverage": {"status": "unknown", "reason": "one read at one moment"},
                           "limitations": sorted(set(limitations) | {"coverage_unknown"}),
                           "parameters": {"fields": self.read_values}})
        if "writers" in self.facts:
            claims.append({**base, "kind": "runtime_writers", "name": "%s:writers" % spec["name"], "subsystem": "runtime",
                           "note": "store sites that wrote the field during the window", "source": "runtime writers action",
                           "coverage": {"status": "unknown", "reason": "only the sites the static analysis listed were probed"},
                           "limitations": sorted(set(limitations) | {"coverage_unknown"}),
                           "parameters": {"writer_count": self.facts["writers"]["count"]}})
        return claims

    def step_evidence_add(self):
        from hydralysis import evidence
        if not self.closed:
            raise RuntimeError("there is no closed capture to take claims from")
        self.ledger = self.out / "ledger.sqlite"
        if self.ledger.exists():
            raise RuntimeError("%s exists; each run needs a fresh ledger" % self.ledger)
        provenance = {"capture": self.closed["capture"], "session": self.session, "scenario": self.spec["name"]}
        stored = [evidence.add_claim(self.ledger, provenance=provenance, **claim) for claim in self._claims()]
        ids = [text.rsplit("evidence_id=", 1)[1] for text in stored]
        self.facts["evidence_ids"] = ids
        return {"claims": len(ids)}

    def step_bundle_export(self):
        from hydralysis import evidence_bundle as bundles
        self.bundle = self.out / "bundle"
        exported = bundles.export_bundle(self.ledger, self.bundle, game=self.spec["game"])
        verified = bundles.verify_bundle(self.bundle)
        if verified.get("status") not in (None, "ok", "verified") and not verified.get("ok", True):
            raise RuntimeError("bundle does not verify: %s" % verified)
        self.facts["bundle_id"] = exported["bundle_id"]
        return {"bundle_id": exported["bundle_id"], "records": exported["records"], "verify": verified.get("status", verified.get("ok"))}

    # ---- the verdict -----------------------------------------------------------------------------------------
    def silent_drops(self) -> list[str]:
        """Hooks that lost events (or could not count) with no limitation that says so."""
        problems = []
        limitations = set(self.closed.get("limitations") or [])
        for row in self.closed.get("hooks") or []:
            if row.get("lost") is None:
                if "runtime:counters_unavailable" not in limitations:
                    problems.append("%s: no counters and no limitation" % row.get("hook_id"))
            elif row["lost"] and not (limitations & set(EXPLAINS_LOSS)):
                problems.append("%s lost %d event(s) with no limitation" % (row["hook_id"], row["lost"]))
        return problems

    def _result(self, before, after) -> dict:
        allowed = dict(self.spec.get("allowed_skips") or {})
        expected = list(self.spec.get("expected_pass_sequence") or [s for s in STEPS if s not in allowed])
        got = [row["step"] for row in self.steps if row["status"] == "pass"]
        drops = self.silent_drops()
        unexpected_skips = [row["step"] for row in self.steps if row["status"] == "skipped" and row["step"] not in allowed]
        limit_ok = True
        if (self.spec.get("run") or {}).get("limit_reached") and self.closed:
            limit_ok = "hit_limit_reached" in (self.closed.get("limitations") or [])
        install = {"checked": before is not None, "before": before, "after": after, "unchanged": before == after}
        ok = (got == expected and not drops and not unexpected_skips and install["unchanged"] and limit_ok)
        return {"scenario": self.spec["name"], "ok": ok, "steps": self.steps, "pass_sequence": got,
                "expected_pass_sequence": expected, "skipped": {r["step"]: r["detail"] for r in self.steps if r["status"] == "skipped"},
                "silent_drops": drops, "install_tree": install, "limit_as_designed": limit_ok,
                "bundle": str(getattr(self, "bundle", "")) or None, "bundle_id": self.facts.get("bundle_id"),
                "coverage": self.closed.get("coverage"), "limitations": self.closed.get("limitations"),
                "capture": self.closed.get("capture"), "session": self.session}


def run_scenario(spec: dict, client, profile: Path, out: Path, install: Path | None = None, twice: bool = False,
                 log=print) -> dict:
    """One run, or two with a bundle comparison. Returns {ok, runs, compare}."""
    out = Path(out)
    runs = [Scenario(spec, client, profile, out / ("run%d" % (i + 1) if twice else "run1"), install, log).run()
            for i in range(2 if twice else 1)]
    result = {"ok": all(r["ok"] for r in runs), "runs": runs, "compare": None}
    if twice and all(r["bundle"] for r in runs):
        from hydralysis import evidence_bundle as bundles
        compared = bundles.compare_bundles(Path(runs[0]["bundle"]), Path(runs[1]["bundle"]))
        result["compare"] = compared
        if compared["status"] != "equal" or compared["changes"]:
            result["ok"] = False
    elif twice:
        result["ok"] = False
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--profile", required=True, help="a COPY of the game folder; this is what is spawned")
    parser.add_argument("--install", help="the original folder; hashed before and after, never run")
    parser.add_argument("--spec", default="kotor", help="`kotor` or a JSON spec file")
    parser.add_argument("--out", help="where ledgers and bundles go (default: a new folder next to the profile)")
    parser.add_argument("--twice", action="store_true", help="run two times and compare the bundles")
    parser.add_argument("--config", help="a Hydralysis config file")
    options = parser.parse_args(argv)
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "src"))
    from hydralysis.client import Client
    spec = load_spec(options.spec)
    profile = Path(options.profile).resolve()
    out = Path(options.out) if options.out else profile.parent / (profile.name + "-scenario-" + time.strftime("%Y%m%d-%H%M%S"))
    result = run_scenario(spec, Client(options.config), profile, out, Path(options.install).resolve() if options.install else None,
                          options.twice)
    print(json.dumps({"ok": result["ok"], "pass_sequence": [r["pass_sequence"] for r in result["runs"]],
                      "skipped": [r["skipped"] for r in result["runs"]], "silent_drops": [r["silent_drops"] for r in result["runs"]],
                      "install_tree": [r["install_tree"]["unchanged"] for r in result["runs"]],
                      "compare": result["compare"] and {"status": result["compare"]["status"], "changes": result["compare"]["changes"]}},
                     indent=2, default=str))
    return 0 if result["ok"] else 1


if __name__ == "__main__":
    sys.exit(main())
