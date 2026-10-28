"""Bounded, address-based queries on saved analysis, through Hydra Engine.

The analysed project opens in place through the engine's read-only view: no lock,
no copy, nothing written. Every Hydralysis process on the root shares one daemon,
so the program and its decompilers stay warm across harnesses. Each query is one
contained run of RusticQuery.java, which the engine rolls back, so a query can
never change what another client reads. Targets with cited overlays are answered
from their working copy (see workcopy.py).
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from pathlib import Path

from hydralysis import hydra, lineage, targets, viewgov, views, workcopy
from hydralysis.analysis import ADVANCED_ACTIONS, BULK_KINDS, validate_options

ACTIONS = {"decompile", "function", "functions", "xrefs", "status", "stop"} | ADVANCED_ACTIONS
ADDRESS_ACTIONS = {"decompile", "function", "xrefs", "variables", "dossier", "blocks", "pcode", "trace", "data", "scan", "vtables"}
_ADDRESS = re.compile(r"(?:(?:rva|va):)?(?:0x)?[0-9a-fA-F]+")
MAX_CHARS = 16_000_000
# A background save of a large working copy holds its program for up to a few minutes;
# requests wait for it rather than fail.
BUSY_WAIT_MS = 180_000

# Program keys per (root, project, program) for this process. The daemon may
# restart; a stale key is reopened once.
_keys: dict[tuple, dict] = {}
_keys_guard = threading.Lock()
# Lineages whose orphaned views this process has already listed in a reply (`adoptable`, once per lineage, 4.10).
_announced: set[str] = set()
# origin key -> (lineage id or None, when it was looked up): a lineage found stays found, "none" is asked again after a few seconds.
_lineage_ids: dict[str, tuple[str | None, float]] = {}
_NO_LINEAGE_S = 5.0
# Edits that make no new record: a view is not created, and its record is not made, by these.
_NO_NEW_RECORDS = ("revert", "commit", "commit_revert", "commit_abort", "publish", "rebase")


def _public(value):
    """Engine credentials never enter MCP/status/export output."""
    if isinstance(value, dict):
        return {key: _public(item) for key, item in value.items() if key not in ("ipc", "token", "secret")}
    if isinstance(value, list):
        return [_public(item) for item in value]
    return value


def open_program(engine: hydra.Engine, gpr: str, program: str, sha256: str, *, writable: bool = False,
                 upgrade: bool = False, refresh: bool = False, share: bool = True, backup: str | None = None) -> dict:
    """Join (or open) one program and check the build before anything is answered from it.

    `share=False` opens a writable program for its caller alone (a commit's candidate); `backup` is the verified
    backup an upgrading writable open names on an engine with the upgrade gate."""
    cache_key = (engine.key, str(Path(gpr)).lower(), program, writable)
    with _keys_guard:
        known = _keys.get(cache_key)
    if known and not refresh:
        return known
    opened = engine.call("open_project", path=gpr, writable=writable, wait=BUSY_WAIT_MS)
    fields = {"path": program, "project": opened["id"]}
    if writable:
        fields.update(writable=True, share=share, upgrade=upgrade)
        if backup:
            fields["backup"] = backup
    info = engine.call("open_program", wait=BUSY_WAIT_MS, **fields)
    if str(info.get("sha256", "")).lower() != sha256:
        raise ValueError("%s in %s reports SHA-256 %s, not the target build %s; nothing was answered"
                         % (program, opened.get("gpr", gpr), info.get("sha256"), sha256))
    result = {"key": info["key"], "project": opened["id"], "gpr": opened.get("gpr", gpr), "revision": info.get("revision"),
              "project_revision": opened.get("revision"), "image_base": info.get("imageBase"),
              "functions": info.get("functions"), "analyzed": info.get("analyzed"), "mode": info.get("mode")}
    with _keys_guard:
        _keys[cache_key] = result
    return result


def forget(engine: hydra.Engine) -> None:
    with _keys_guard:
        for key in [key for key in _keys if key[0] == engine.key]:
            _keys.pop(key, None)


def run_script(engine: hydra.Engine, program: dict, request: dict, timeout_s: int, request_dir: Path | None = None,
               wait_ms: int = 0) -> tuple[dict, dict]:
    """One RusticQuery run. Large requests travel as a file, not a command argument."""
    body = json.dumps(request, ensure_ascii=False)
    argument = body
    path = None
    if len(body) > 256 * 1024:
        if request_dir is None:
            raise ValueError("request too large to send inline")
        request_dir.mkdir(parents=True, exist_ok=True)
        path = request_dir / ("request-%s.json" % uuid.uuid4().hex)
        path.write_text(body, encoding="utf-8")
        argument = "@" + str(path)
    try:
        result = engine.call("script", script="RusticQuery.java", program=program["key"], args=[argument],
                             maxChars=MAX_CHARS, timeout=timeout_s + 5, wait=wait_ms or BUSY_WAIT_MS)
    finally:
        if path is not None:
            path.unlink(missing_ok=True)
    lines = [line for line in str(result.get("output", "")).splitlines() if line.startswith("{")]
    if not lines or result.get("truncated"):
        raise RuntimeError("RusticQuery returned no complete answer (truncated=%s): %s"
                           % (result.get("truncated"), str(result.get("output", ""))[-2000:]))
    return json.loads(lines[-1]), result


class QueryRunner:
    def __init__(self, settings: dict, engine: hydra.Engine | None = None):
        self.settings = settings
        self.engine = engine or hydra.Engine(settings)
        self.requests = Path(settings["root"]) / "hydra" / "requests"

    def target(self, name: str) -> dict:
        return targets.resolve(self.settings, name)

    def program_for(self, target: dict, *, for_overlays: bool = True) -> dict:
        """The master's read-only view, or the working copy that holds the view's overlays (never for a master read)."""
        if for_overlays and not target.get("master_read") and workcopy.has_overlays(self.settings, target):
            return workcopy.reader(self.settings, self.engine, target)
        return open_program(self.engine, target["gpr"], target["program"], target["sha256"])

    # --- identity, routing, the governor (Y5: D43, D59, 4.10) -----------------------------------------------------------

    def _release(self, entry) -> None:
        """The governor's callback: close this process's programs of one view (discard, keep the folder)."""
        workcopy.release(self.engine, self.settings, entry.target)

    def _route(self, base: dict, who: dict, explicit: str, scope: str, action: str) -> tuple[dict, str]:
        """Which store a call reads or writes. `master` (a sealed-master read), `agent` (the caller's own view),
        `shared` (the collaboration view) or `named` (an explicit `options.view`)."""
        writes = action == "type_edit"
        if scope == "master" and writes:
            raise ValueError("options.scope 'master' reads the sealed master; an edit always goes to a view")
        if explicit == "master":
            raise ValueError("view 'master' is reserved: it labels reads of the sealed master")
        if explicit:
            selected = workcopy.with_view(base, explicit)
            mode = "shared" if selected["view"] == "shared" else "named"
        elif who["shared"]:
            selected, mode = workcopy.with_view(base, "shared"), "shared"
        else:
            selected, mode = workcopy.with_view(base, who["name"]), "agent"
            if not writes and not workcopy.view_exists(self.settings, selected):
                return workcopy.master_target(base), "master"
        if scope == "master" and not writes:
            return workcopy.master_target(base), "master"
        return selected, mode

    def _register(self, base_name: str, selected: dict, who: dict, mode: str) -> dict:
        """The first edit of an agent creates its view: the lineage (generation 0 is the adopted master, never written), then
        the view's record with the agent id, the boot id, the pid and the lease. Idempotent; a later call only refreshes."""
        if mode != "agent":
            return selected
        link = selected.get("lineage")
        lineage_id = link["id"] if link else views.ensure_lineage(self.settings, selected)["id"]
        if not link:
            selected = workcopy.with_view(self.target(base_name), selected["view"])
        views.claim(self.settings, selected, who, lineage_id, self._lease())
        return selected

    def _lineage_id(self, selected: dict) -> str | None:
        """The lineage that holds the view records of this target: the resolved one, else the one created for its origin key
        (a target defined only by configuration has no registry row, so it resolves without a lineage but can still have one)."""
        link = selected.get("lineage")
        if link:
            return link["id"]
        origin = selected.get("origin_key") or selected["key"]
        with _keys_guard:
            known, stamp = _lineage_ids.get(origin, (None, 0.0))
        if known is None and time.monotonic() - stamp > _NO_LINEAGE_S:
            known = lineage.find(self.settings, origin)
            with _keys_guard:
                _lineage_ids[origin] = (known, time.monotonic())
        return known

    def _lease(self) -> float:
        value = self.settings.get("viewLeaseS", self.settings.get("view_lease_s"))
        return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value >= 5 else views.LEASE_S

    def _touch(self, selected: dict, who: dict, mode: str) -> None:
        """A read of an agent's existing view keeps its lease (never creates a record)."""
        lineage_id = self._lineage_id(selected) if mode == "agent" else None
        if lineage_id:
            views.claim(self.settings, selected, who, lineage_id, self._lease(), create=False)

    def _frame(self, selected: dict, mode: str, who: dict) -> dict:
        """What every reply says about where it came from (4.10): `view`, `agent`, `base` and, when behind, `stale`."""
        link = selected.get("lineage")
        head = {"lineage": link["id"], "generation": link["generation"]} if link else None
        frame = {"view": selected["view"], "agent": who["agent"]}
        if mode == "master":
            return {**frame, "base": head}
        try:
            store = workcopy.load_store(self.settings, selected)
        except (ValueError, OSError):
            return {**frame, "base": head}
        base = store.get("base")
        frame["base"] = base
        if workcopy.stale_reason(store, selected):
            frame["stale"] = {"base": (base or {}).get("generation", 0), "head": link["generation"],
                              "behind": link["generation"] - (base or {}).get("generation", 0)}
        return frame

    def _stamp(self, payload: dict, ctx: dict) -> dict:
        """Add the frame (without overwriting what the reply already says) and the one-time `view_rebuilt`."""
        for key, value in self._frame(ctx["selected"], ctx["mode"], ctx["who"]).items():
            payload.setdefault(key, value)
        pin = ctx.get("pin")
        if pin is not None and pin.rebuilt and "view_rebuilt" not in payload:
            payload["view_rebuilt"] = {"replayed": ctx["trace"].get("replayed", 0),
                                       "ms": round((time.monotonic() - pin.started) * 1000)}
        return payload

    def _announce(self, response: str, base: dict, who: dict) -> str:
        """The first reply of a default-id process on a lineage names the orphaned views of the same agent that hold pending
        records (`adoptable`, 4.10 b); `options.as:"<old id>"` re-attaches. Later replies stay as they are."""
        lineage_id = self._lineage_id(base)
        if not lineage_id or who["kind"] != "default":
            return response
        with _keys_guard:
            first = lineage_id not in _announced
            _announced.add(lineage_id)
        if not first:
            return response
        orphans = views.adoptable(self.settings, base, lineage_id)
        if not orphans:
            return response
        try:
            decoded = json.loads(response)
        except ValueError:
            return response
        if not isinstance(decoded, dict):
            return response
        decoded["adoptable"] = orphans
        decoded["adoptable_note"] = ("these views of an earlier process of the same agent still hold pending records; "
                                     "pass options.as with one of the listed agent ids to adopt it, or set HYDRALYSIS_AGENT_ID "
                                     "so a restarted server keeps its id")
        return json.dumps(decoded, ensure_ascii=False)

    def _housekeeping(self, base: dict) -> None:
        """Before a call: close the views that have been idle past `viewIdleEvictS`, and now and then delete the folders of
        views nobody holds that were idle for `viewIdleDeleteS`. Failures here never fail the call."""
        try:
            viewgov.GOVERNOR.sweep(self.settings, self._release)
            lineage_id = self._lineage_id(base)
            if lineage_id and viewgov.GOVERNOR.due_for_delete_sweep(lineage_id):
                viewgov.delete_idle_folders(self.settings, base, lineage_id, self.engine)
        except Exception:  # noqa: BLE001
            pass

    def _structured(self, error: hydra.EngineError, call: dict) -> RuntimeError:
        """Map the engine's refusals that have a ready answer to a `next` call (4.11): the payload keeps everything the
        engine said and adds `next`, so the caller can act without reading prose."""
        payload = json.loads(str(error))
        reason = str(payload.get("reason") or error.details.get("reason") or "")
        payload["error"] = error.code
        if error.code == "busy":
            payload["reason"] = reason or "busy"
            payload.setdefault("retryAfterMs", error.retry_after_ms or 2000)
            payload.setdefault("next", {"tool": "ghidra_query", "after_ms": payload["retryAfterMs"], "arguments": call})
        elif error.code == "sealed":
            payload.setdefault("next", {"tool": "ghidra_query", "action": "status", "options": {"show": "lineage"}})
        elif error.code == "corrupt_newest":
            payload.setdefault("next", {"tool": "backend", "action": "doctor"})
        return RuntimeError(json.dumps(payload, ensure_ascii=False))

    def query(self, target: str, action: str = "decompile", address: str = "",
              limit: int = 40, cursor: str = "", contains: str = "", timeout_s: int = 30,
              options: dict | None = None) -> str:
        """One query. The view is `options.view` when named, else the caller's own: `options.as`, else the process default
        `<client name>@<boot id>`. A caller without a view reads the sealed master; its first edit creates the view."""
        call = {"target": target, "action": action, "address": address, "limit": limit, "cursor": cursor, "contains": contains,
                "timeout_s": timeout_s, **({"options": options} if options else {})}
        for attempt in (0, 1):
            try:
                return self._query(target, action, address, limit, cursor, contains, timeout_s, options)
            except hydra.EngineError as error:
                if (attempt == 0 and error.code == "busy" and str(error.details.get("reason")) == "capacity"
                        and viewgov.GOVERNOR.evict_lru(self._release)):
                    continue  # the engine refused a view for capacity: an idle one of ours was closed, so try once more
                if error.code in ("busy", "sealed", "corrupt_newest"):
                    raise self._structured(error, call) from error
                raise
            except viewgov.Capacity as error:
                raise RuntimeError(json.dumps({"error": "busy", "reason": "capacity", "message": str(error),
                                               "retryAfterMs": error.retry_after_ms,
                                               "next": {"tool": "ghidra_query", "after_ms": error.retry_after_ms,
                                                        "arguments": call}})) from error
        raise RuntimeError("unreachable")

    def _query(self, target: str, action: str, address: str, limit: int, cursor: str, contains: str, timeout_s: int,
               options: dict | None) -> str:
        if action not in ACTIONS:
            raise ValueError("unknown saved-analysis query action; use backend help")
        if options is not None and not isinstance(options, dict):
            raise ValueError("options must be an object")
        options = dict(options or {})
        explicit = options.pop("view", "")
        scope, follow = options.pop("scope", ""), options.pop("follow", "")
        if scope not in ("", "master", "view"):
            raise ValueError("options.scope must be 'master' (the sealed master) or 'view' (the caller's view, the default)")
        if follow not in ("", "head"):
            raise ValueError("options.follow must be 'head'")
        who = views.identify(options)
        base = self.target(target)
        self._housekeeping(base)
        selected, mode = self._route(base, who, explicit, scope, action)
        guarded = views.ViewError
        if mode == "master":
            ctx = {"selected": selected, "mode": mode, "who": who, "trace": {}}
            return self._announce(self._run(target, selected, ctx, action, address, limit, cursor, contains, timeout_s, options,
                                            follow), base, who)
        try:
            if action == "type_edit" and options.get("kind") not in _NO_NEW_RECORDS:
                selected = self._register(target, selected, who, mode)
            else:
                self._touch(selected, who, mode)
        except guarded as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        with viewgov.GOVERNOR.hold(selected, self.settings, self._release) as pin:
            ctx = {"selected": selected, "mode": mode, "who": who, "pin": pin, "trace": {}}
            try:
                pin.update(len(workcopy.pending_of(workcopy.load_store(self.settings, selected))))
            except (ValueError, OSError):
                pass
            try:
                response = self._run(target, selected, ctx, action, address, limit, cursor, contains, timeout_s, options, follow)
            finally:
                try:  # the keep-warm rule counts the records the view holds now, edits included
                    pin.update(len(workcopy.pending_of(workcopy.load_store(self.settings, selected))))
                except (ValueError, OSError, RuntimeError):
                    pass
        return self._announce(response, base, who)

    def _auto_rebase(self, selected: dict, expect, timeout_s: int) -> tuple[dict | None, int | None]:
        """A view that is behind the head and holds records is rebased first, clean-only (4.10): when a record would conflict
        nothing changes, and the edit that follows is refused with `stale_view` naming the editors. Returns the rebase result
        and the revision the caller's edit should now name."""
        store = workcopy.load_store(self.settings, selected)
        if not workcopy.stale_reason(store, selected):
            return None, expect
        try:
            result = views.rebase(self.settings, self.engine, selected, {"kind": "rebase", "expect_revision": store["revision"]},
                                  timeout_s)
        except (views.ViewError, RuntimeError):
            return None, expect
        if not result.get("ok") or not result.get("rebased"):
            return None, expect
        # The caller read the revision before the rebase and nothing else has moved the view: its edit follows the rebase.
        return result, (result["revision"] if expect == store["revision"] else expect)

    def _run(self, target: str, selected: dict, ctx: dict, action: str, address: str, limit: int, cursor: str, contains: str,
             timeout_s: int, options: dict, follow: str) -> str:
        view, mode = selected["view"], ctx["mode"]
        if action == "type_edit" and options.get("kind") in ("commit", "commit_revert", "commit_abort"):
            return self._commit(target, options, selected, timeout_s)
        if action == "type_edit" and options.get("kind") in ("publish", "merge", "rebase"):
            return self._views(target, options, selected, timeout_s)
        if action == "status" and options.get("show") == "views":
            return json.dumps(_public(views.views_status(self.settings, selected, self._lineage_id(selected), ctx["who"])),
                              ensure_ascii=False)
        if action == "status" and options.get("show") in ("queue", "publish"):
            return json.dumps(_public(self.queue(selected, options.get("csid"))), ensure_ascii=False)
        if action == "status" and options.get("show") == "lineage":
            return json.dumps(_public({"target": {key: selected[key] for key in ("name", "program", "sha256", "view")},
                                       **lineage.status(self.settings, selected)}), ensure_ascii=False)
        supplied_options = options
        options = validate_options(action, supplied_options)
        # Batch/corpus normalization constructs a new dict; retain the already
        # validated revision for the eventual write, including durable jobs.
        if action == "type_edit" and "expect_revision" in supplied_options:
            options["expect_revision"] = supplied_options["expect_revision"]
        if not 1 <= limit <= 200 or not 1 <= timeout_s <= 300:
            raise ValueError("limit must be 1..200; timeout_s must be 1..300")
        requires_address = action in ADDRESS_ACTIONS
        requires_address |= action == "type_edit" and options.get("kind") not in ("struct", "batch", "revert", "import_types", "import_archive")
        if requires_address and not address:
            raise ValueError("address is required (a VA such as 0x140001000, or rva:0x1000)")
        if action == "type" and not (address or options.get("path")):
            raise ValueError("type requires options.path or a typed-data address")
        if address and not _ADDRESS.fullmatch(address):
            raise ValueError("use a numeric VA or an rva:/va: prefix, not a symbol name")
        if cursor and not re.fullmatch(r"(?:0x)?[0-9a-fA-F]+", cursor):
            raise ValueError("use a numeric VA or hexadecimal row cursor, not a symbol name")
        if mode != "master" and action != "stop":
            workcopy.heal(self.settings, selected)  # settle a commit that died between its CURRENT.log line and its store write
            if follow == "head" and action != "type_edit":
                followed = self._auto_rebase(selected, None, timeout_s)[0]
                ctx["followed"] = bool(followed) or not workcopy.stale_reason(workcopy.load_store(self.settings, selected), selected)
        if action == "type_edit":
            # Every mutation, on the shared view and on named views, names the revision it read.
            workcopy.require_revision(self.settings, selected, options.get("expect_revision"), "type_edit")
        if action == "status":
            return json.dumps(_public(self._stamp(self.status(selected, options, limit, ctx), ctx)), ensure_ascii=False)
        if action == "stop":
            # As for a named view: the caller's own view is released and the master stays open for the others; a caller with
            # no view of its own releases the master (and the shared view's copy), which is all it uses.
            released = self.stop({**selected, "view": "shared"} if mode == "master" else selected)
            viewgov.GOVERNOR.forget(selected["key"])
            return json.dumps(released)
        if action == "type_edit" and options.get("kind") == "revert":
            return json.dumps(self._stamp({**workcopy.revert(self.settings, selected, options["ids"], options.get("expect_revision"),
                                                             bool(options.get("cascade", False))), "view": view}, ctx))
        if action == "diff":
            from hydralysis import overlayjobs
            self.target(options["against"])
            return json.dumps(overlayjobs.start(self.settings, selected["name"], "diff", "", options, view=view), ensure_ascii=False)
        if action == "type_edit" and options.get("kind") in BULK_KINDS:
            from hydralysis import overlayjobs
            job = overlayjobs.start(self.settings, selected["name"], "edit", address, options, view=view)
            # The job applies the edit later, under the revision it was started with; report the revision seen now.
            return json.dumps(self._stamp({**job, "view_revision": workcopy.load_store(self.settings, selected)["revision"]}, ctx),
                              ensure_ascii=False)
        if action == "type_edit":
            if address.startswith(("rva:", "va:")):
                # Overlay records hold plain VAs, so replay never depends on how an edit was typed.
                image = open_program(self.engine, selected["gpr"], selected["program"], selected["sha256"])["image_base"]
                value = int(address.split(":", 1)[1].removeprefix("0x"), 16)
                address = hex(int(image, 16) + value if address.startswith("rva:") else value)
            rebased, options["expect_revision"] = self._auto_rebase(selected, options.get("expect_revision"), timeout_s)
            edited = workcopy.edit(self.settings, self.engine, selected, address, options, timeout_s)
            if rebased:
                edited["auto_rebased"] = {key: rebased.get(key) for key in ("outcome", "from_generation", "to_generation", "kept",
                                                                             "dropped_in_master")}
            return json.dumps(_public(self._stamp({**edited, "view": view}, ctx)), ensure_ascii=False)
        request = {"id": uuid.uuid4().hex, "action": action, "address": address, "limit": limit, "cursor": cursor,
                   "contains": contains, "timeout_s": timeout_s, "options": options, "expected_sha256": selected["sha256"]}
        started = time.monotonic()
        response = self._ask(selected, request, timeout_s, ctx["trace"])
        response.update(target=selected["name"], view=view, query_s=round(time.monotonic() - started, 3))
        if not response.get("ok"):
            raise RuntimeError(json.dumps(_public(response), ensure_ascii=False))
        if ctx.get("followed") is False:
            response["follow"] = {"followed": False, "reason": "the view holds records the head would conflict with; rebase it"}
        return json.dumps(_public(self._stamp(response, ctx)), ensure_ascii=False)

    def _commit(self, target: str, options: dict, selected: dict, timeout_s: int) -> str:
        """`type_edit kind=commit|commit_revert|commit_abort`: a commit is a job; a dry run and a revert answer at once."""
        from hydralysis import commits, locks, overlayjobs
        view = selected["view"]
        try:
            clean = commits.validate(options)
            if clean["kind"] == "commit_revert":
                return json.dumps({**commits.revert(self.settings, selected, clean, self.engine), "view": view})
            if clean["kind"] == "commit_abort":
                return json.dumps({**commits.request_abort(self.settings, selected, clean["cid"]), "view": view})
            if clean.get("dry_run"):
                return json.dumps({**commits.run_commit(self.settings, selected, clean, self.engine, timeout_s), "view": view})
            # Everything that can be refused before a worker is started is refused here: it creates nothing.
            commits.preconditions(self.settings, selected, clean, self.engine)
            commits._plan_confirmation(clean)
            link = selected.get("lineage")
            if link and locks.held(str(lineage.commit_lock_path(self.settings, link["id"]))):
                raise commits.CommitError("commit_busy", "another commit holds this lineage's commit lock; retry when it finishes",
                                          retryAfterMs=5000)
            clean["cid"] = clean.get("cid") or commits.new_cid()
            job = overlayjobs.start(self.settings, selected["name"], "commit", "", clean, view=view)
        except commits.CommitError as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        except lineage.LineageError as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        return json.dumps({**job, "cid": clean["cid"], "view": view, "view_revision": workcopy.load_store(self.settings, selected)["revision"]},
                          ensure_ascii=False)

    def _views(self, target: str, options: dict, selected: dict, timeout_s: int) -> str:
        """`type_edit kind=rebase|merge|publish` (4.7, 4.8, 4.10). Rebase and the merge of a view into another answer at once;
        a publish to the master seals a changeset and answers with a job and its position in the queue."""
        from hydralysis import commits, overlayjobs
        view = selected["view"]
        try:
            clean = views.validate(options)
            if clean["kind"] == "rebase":
                return json.dumps(_public(views.rebase(self.settings, self.engine, selected, clean, timeout_s)), ensure_ascii=False)
            if clean["kind"] == "merge" or clean.get("to"):
                other = workcopy.with_view(self.target(target), clean["from"] if clean["kind"] == "merge" else clean["to"])
                source, destination = (other, selected) if clean["kind"] == "merge" else (selected, other)
                return json.dumps(_public(views.merge(self.settings, self.engine, source, destination, clean, timeout_s)), ensure_ascii=False)
            sealed = views.seal_changeset(self.settings, selected, clean)
            if sealed.get("state") == "done":  # the same records were decided while this call was being made
                return json.dumps({**sealed, "view": view}, ensure_ascii=False)
            job = overlayjobs.start(self.settings, selected["name"], "publish", "", {"csid": sealed["csid"], "lineage": sealed["lineage"]},
                                    view=view)
        except (views.ViewError, commits.CommitError) as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        except lineage.LineageError as error:
            raise RuntimeError(json.dumps(error.payload())) from error
        return json.dumps({**job, "csid": sealed["csid"], "reused": sealed["reused"], "view": view,
                           "publish_pending": {key: sealed.get(key) for key in ("state", "csid", "position", "etaMs", "leader")},
                           "position": sealed.get("position"), "etaMs": sealed.get("etaMs"),
                           "view_revision": workcopy.load_store(self.settings, selected)["revision"]}, ensure_ascii=False)

    def queue(self, selected: dict, csid: str | None = None) -> dict:
        """`status show=queue`: the publish queue of the target's lineage."""
        from hydralysis import views
        link = selected.get("lineage")
        if not link:
            return {"target": {key: selected[key] for key in ("name", "view")}, "lineage": None,
                    "queue": {"length": 0, "leader": False, "changesets": []},
                    "note": "no publish has been made on this target; there is no queue"}
        return {"target": {key: selected[key] for key in ("name", "view")}, **views.queue_status(self.settings, link["id"], csid)}

    def _ask(self, selected: dict, request: dict, timeout_s: int, trace: dict | None = None) -> dict:
        expected_state = None if selected.get("master_read") else workcopy.expected_state(self.settings, selected)
        for attempt in (0, 1):
            program = self.program_for(selected)
            try:
                response, raw = run_script(self.engine, program, request, timeout_s, self.requests)
            except hydra.EngineError as error:
                if attempt == 0 and error.code in ("no_program", "not_found", "no_project", "closed"):
                    forget(self.engine)
                    continue
                raise
            state = response.get("overlay_state") or ""
            if expected_state is not None and state != expected_state:
                if attempt == 0:
                    # The working copy does not hold the store's state (a daemon restart lost
                    # unsaved changes, or another process is mid-edit): replay from the store.
                    stored = workcopy.load_store(self.settings, selected)
                    if workcopy.heavy(stored):
                        workcopy.rebuilding(self.settings, selected)
                    if trace is not None:
                        trace["replayed"] = len(workcopy.pending_of(stored))
                    workcopy.repair(self.settings, self.engine, selected)
                    forget(self.engine)
                    continue
                raise RuntimeError("working copy answers with overlay state %r, expected %r; refused rather than "
                                   "answer from the wrong overlay version" % (state, expected_state))
            response["engine"] = {"program": program["key"], "mode": raw.get("mode"), "script_s": raw.get("seconds")}
            if expected_state is not None:
                response["overlays"] = json.loads(expected_state) if expected_state else None
            return response
        raise RuntimeError("program could not be reopened")

    def status(self, selected: dict, options: dict | None = None, limit: int = 40, ctx: dict | None = None) -> dict:
        options = options or {}
        master = selected.get("master_read")
        target = {key: selected[key] for key in ("name", "program", "sha256", "view")}
        if options.get("show") == "changes":
            # What changed in this view: its records with their subject record (effects) and commit state.
            if master:
                return {"target": target, "view_revision": 0, "since": options.get("since", 0), "state": options.get("state", "all"),
                        "changes": [], "truncated": False, "archived_commits": 0,
                        "note": "this agent has no view yet: it reads the sealed master, which has no unpublished records"}
            return {"target": target, **workcopy.changes(self.settings, selected, options.get("since", 0), options.get("state", "all"), limit)}
        hello = self.engine.hello()
        info = {key: hello.get(key) for key in ("protocol", "hydraVersion", "ghidraVersion", "installId", "pid", "startedAt")}
        who = (ctx or {}).get("who") or {}
        session = {"boot_id": views.BOOT_ID, "agent": who.get("agent"), "agent_kind": who.get("kind"), "agent_name": views.agent_name()}
        if master:
            overlays = {"revision": 0, "view_revision": 0, "edits": 0, "pending": 0, "committed": 0, "latest_editor": None,
                        "reverted": 0, "working_copy": None, "working_state": None, "in_sync": True, "last_sync": None, "recent": []}
            return {"engine": info, "target": {**{key: selected[key] for key in ("name", "gpr", "program", "sha256")}, "view": "master"},
                    "view_revision": 0, "overlays": overlays, "identity": hydra.identity(), "session": session,
                    "note": "this agent has no view yet; it reads the sealed master and its first edit creates its view "
                            "(expect_revision 0)"}
        overlays = workcopy.summary(self.settings, selected)
        return {"engine": info, "target": {key: selected[key] for key in ("name", "gpr", "program", "sha256", "view")},
                "view_revision": overlays["view_revision"], "overlays": overlays, "identity": hydra.identity(), "session": session}

    def stop(self, selected: dict) -> dict:
        """Release this process's use of the target's programs; the shared daemon keeps serving others."""
        released = []
        failed = []
        master = str(Path(selected["gpr"])).lower()
        working = workcopy._directory(self.settings, selected).resolve()
        # Every generation of the lineage is released too (the head, the older ones the target resolved to, the shared bases).
        roots = [working, workcopy.bases_root(self.settings, selected).resolve()]
        if selected.get("lineage"):
            roots.append(lineage.lineage_dir(self.settings, selected["lineage"]["id"]).resolve())
        adopted = str(Path(selected.get("adopted_gpr") or selected["gpr"])).lower()

        def belongs(key):
            if key[0] != self.engine.key or key[2].lstrip("/") != selected["program"].lstrip("/"):
                return False
            if key[1] in (master, adopted) and selected.get("view", "shared") == "shared":
                return True
            return any(Path(key[1]).resolve().is_relative_to(root) for root in roots)

        with _keys_guard:
            entries = [(key, value) for key, value in _keys.items() if belongs(key)]
        # Several cache entries can refer to one daemon program.
        groups = {}
        for key, value in entries:
            groups.setdefault(value["key"], []).append((key, value))
        for program, group in groups.items():
            try:
                self.engine.call("close_program", program=program)
            except hydra.EngineError as exc:
                failed.append({"program": program, "error": str(exc)})
                continue
            released.append(program)
            with _keys_guard:
                for key, value in group:
                    if _keys.get(key) is value:
                        _keys.pop(key, None)
        return {"ok": not failed, "released": released, "failed": failed,
                "note": "the shared engine keeps warm programs for keepWarm seconds"}
