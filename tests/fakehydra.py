"""An in-process stand-in for Hydra Engine's daemon, for unit tests.

It models what RusticRE relies on, not Ghidra: projects opened by path, programs
with a SHA-256 and an overlay marker, contained (rolled back) versus owner script
runs, forks that copy a project's state, saves, and shared-mode changes that stay
in the daemon after their writer disconnects. RusticQuery requests are answered
with small canned results; apply_overlays records renames so reads can see them.
"""

from __future__ import annotations

import copy
import json
import threading
from pathlib import Path

from rusticre.hydra import EngineError


class Daemon:
    def __init__(self):
        self.projects: dict[str, dict] = {}   # normalized gpr -> project
        self.ids = 0
        self.calls: list[tuple[str, str, dict]] = []
        self.lock = threading.RLock()
        self.fail_next: dict[str, EngineError] = {}

    def add_project(self, gpr: Path, programs: dict[str, dict]) -> dict:
        gpr.parent.mkdir(parents=True, exist_ok=True)
        gpr.write_text("project", encoding="utf-8")
        (gpr.parent / (gpr.stem + ".rep")).mkdir(exist_ok=True)
        project = {"gpr": str(gpr), "revision": "rev-1", "programs": {}}
        for path, info in programs.items():
            project["programs"][path] = {"sha256": info["sha256"], "analyzed": info.get("analyzed", True),
                                         "functions": info.get("functions", 2), "imageBase": "0x140000000",
                                         "saved": {"marker": "", "names": {}}, "live": None, "writers": set()}
        self.projects[self._norm(gpr)] = project
        return project

    @staticmethod
    def _norm(path) -> str:
        path = Path(path)
        if path.suffix != ".gpr":
            found = sorted(path.glob("*.gpr")) or sorted(path.glob("*/*.gpr"))
            if len(found) == 1:
                path = found[0]
        return str(path.resolve()).lower()

    def project_by_id(self, ident: str) -> dict:
        for project in self.projects.values():
            if project.get("id") == ident:
                return project
        raise EngineError("no_project", "no project " + ident)


DAEMON = Daemon()


def reset() -> Daemon:
    global DAEMON
    DAEMON = Daemon()
    return DAEMON


class FakeEngine:
    """The interface RusticRE uses from hydra.Engine."""

    def __init__(self, settings: dict, role: str = "reader"):
        self.settings = settings
        self.role = role
        self.key = "fake|" + role
        self.daemon = DAEMON
        self.writable: set[str] = set()  # program keys this connection may write

    # --- connection -------------------------------------------------------------------------
    def reset(self):
        # Like the real daemon: committed changes in shared mode stay, the writer leaves.
        for key in self.writable:
            program = self._program(key)
            program["writers"].discard(self.role)
        self.writable.clear()

    def hello(self):
        return {"protocol": 2, "hydraVersion": "12.3-hydra.2", "ghidraVersion": "12.3", "installId": "fake"}

    def stop(self, force=False):
        return {"stopped": True}

    def on_event(self, callback):
        self.callback = callback

    # --- helpers ---------------------------------------------------------------------------
    def _program(self, key: str) -> dict:
        ident, path = key.split(":", 1)
        return self.daemon.project_by_id(ident)["programs"][path]

    def _view(self, program: dict) -> dict:
        return program["live"] if program["live"] is not None else program["saved"]

    # --- commands --------------------------------------------------------------------------
    def call(self, command: str, raw: bool = False, **fields):
        with self.daemon.lock:
            self.daemon.calls.append((self.role, command, fields))
            failure = self.daemon.fail_next.pop(command, None)
            if failure:
                raise failure
            return getattr(self, "_" + command)(**fields)

    def _open_project(self, path, writable=False, **_):
        norm = self.daemon._norm(path)
        if norm not in self.daemon.projects:
            raise EngineError("not_found", "no project at %s" % path)
        project = self.daemon.projects[norm]
        if "id" not in project:
            self.daemon.ids += 1
            project["id"] = "p%d" % self.daemon.ids
        return {"id": project["id"], "gpr": project["gpr"], "revision": project["revision"], "writable": writable}

    def _list(self, project, sha256=None, **_):
        entries = []
        for path, program in self.daemon.project_by_id(project)["programs"].items():
            if sha256 and program["sha256"] != sha256:
                continue
            entries.append({"path": path, "name": path.lstrip("/"), "program": True, "sha256": program["sha256"],
                            "format": "Portable Executable (PE)", "language": "x86:LE:64:default"})
        return {"entries": entries}

    def _open_program(self, path, project, writable=False, share=False, upgrade=False, **_):
        programs = self.daemon.project_by_id(project)["programs"]
        program = programs.get(path) or programs.get("/" + path.lstrip("/"))
        if program is None:
            raise EngineError("not_found", "no program " + path)
        key = "%s:%s" % (project, "/" + path.lstrip("/"))
        if writable:
            program["writers"].add(self.role)
            self.writable.add(key)
            if program["live"] is None:
                program["live"] = copy.deepcopy(program["saved"])
        return {"key": key, "sha256": program["sha256"], "analyzed": program["analyzed"], "functions": program["functions"],
                "imageBase": program["imageBase"], "mode": "shared" if writable else "read_only", "revision": "r"}

    def _info(self, program, **_):
        entry = self._program(program)
        return {"key": program, "sha256": entry["sha256"], "analyzed": entry["analyzed"],
                "changed": entry["live"] is not None and entry["live"] != entry["saved"]}

    def _save(self, program, **_):
        entry = self._program(program)
        if entry["live"] is not None:
            entry["saved"] = copy.deepcopy(entry["live"])
        return {"revision": "saved"}

    def _close_project(self, project, discard=False, **_):
        for key in [key for key in self.writable if key.startswith(project + ":")]:
            self._program(key)["writers"].discard(self.role)
            self.writable.discard(key)
        return {"closed": True}

    def _close_program(self, program, **_):
        self.writable.discard(program)
        return {"closed": True}

    def _fork_project(self, project, path, writable=True, mode="auto", **_):
        source = (self.daemon.project_by_id(project) if not Path(project).suffix and not Path(project).exists()
                  else self.daemon.projects[self.daemon._norm(project)])
        destination = Path(path)
        name = Path(source["gpr"]).stem
        gpr = destination / (name + ".gpr")
        programs = {item: {"sha256": entry["sha256"]} for item, entry in source["programs"].items()}
        fork = self.daemon.add_project(gpr, programs)
        for item, entry in source["programs"].items():
            fork["programs"][item]["saved"] = copy.deepcopy(entry["saved"])
        opened = self._open_project(str(gpr), writable=True)
        return {"project": opened["id"], "gpr": str(gpr), "method": "clone", "cloned": True, "bytes": 1, "copyMs": 1}

    def _status(self, **_):
        return {"projects": [{"gpr": item["gpr"], "id": item.get("id")} for item in self.daemon.projects.values()
                             if item.get("id")], "programs": [], "clients": []}

    def _refresh(self, project, **_):
        return {"refreshed": False}

    def _cancel(self, target=None, **_):
        return {"cancelled": True}

    def _script(self, script, program=None, args=(), **_):
        if script != "RusticQuery.java":
            return {"output": "user script ran\n", "mode": "contained", "truncated": False}
        body = args[0]
        if body.startswith("@"):
            body = Path(body[1:]).read_text(encoding="utf-8")
        request = json.loads(body)
        entry = self._program(program)
        owner = program in self.writable
        view = self._view(entry) if owner or entry["live"] is not None else entry["saved"]
        out = {"id": request["id"], "ok": True, "sha256": entry["sha256"], "image_base": entry["imageBase"],
               "address_kind": "VA", "overlay_state": view["marker"]}
        action = request["action"]
        if request.get("expected_sha256") and request["expected_sha256"] != entry["sha256"]:
            out.update(ok=False, error="program SHA-256 differs", recoverable=False)
        elif action == "apply_overlays":
            if not owner:
                out.update(ok=False, error="not a writer")
            else:
                batch = json.loads(Path(request["edits_file"]).read_text(encoding="utf-8"))
                staged = copy.deepcopy(view)
                for edit in batch["edits"]:
                    options = edit["options"]
                    if options.get("name") == "FAIL":
                        out.update(ok=False, error="java.lang.IllegalArgumentException: overlay record refused",
                                   recoverable=True)
                        break
                    if options.get("kind") == "rename":
                        staged["names"][edit["address"]] = options["name"]
                else:
                    staged["marker"] = json.dumps(batch["state"], separators=(",", ":"))
                    entry["live"] = staged
                    out["overlay_state"] = staged["marker"]
        elif action == "decompile":
            address = request["address"]
            name = view["names"].get(address, "FUN_" + address.removeprefix("0x"))
            out.update(function={"address": address, "name": name}, c="void %s(void) {}\n" % name)
        elif action == "overlay_state":
            pass
        elif action == "functions":
            out.update(functions=[{"address": "0x140001000", "name": "first"}], truncated=False)
        else:
            out.update(result=action)
        return {"output": json.dumps(out) + "\n", "mode": "owner" if owner else "contained", "truncated": False,
                "seconds": 0.001}
