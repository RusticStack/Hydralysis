"""`backend action=doctor`: a read-only report of everything that can hurt a session (PROTOCOL-3.md 7.1, package Y4b).

The doctor never starts a JVM or a daemon and never changes a file. It reads the endpoint file and the launcher
registry, joins the daemon with `Daemon.attach()` (connect without start) only when the instance lock is held, and
calls `hello`, `health`/`ping` and `status` once. It never runs `java -version`: the JDK is read from the `release`
file of its home. Findings are `{id, level, what, why, fix}`; `fix` is a ready tool call or command. Default output is
findings only; `options.verbose` adds the sections, `options.sections` limits them.

Registered in `api.HANDLER_MODULES` as `doctor`; the CLI reaches the same handler (`cli.py`).
"""

from __future__ import annotations

import json
import os
import re
import shutil
import time
from pathlib import Path

from hydralysis import backups, hydra, lineage, paths

CAPABILITY = "doctor"
REQUIRED_JDK = 25
TMP_AGE_S = 300            # a `*.tmp` younger than this may belong to a live writer
GENERATION_WARN = 20       # generations of one lineage kept on disk before the doctor suggests retention
GENERATION_WARN_BYTES = 50 * 1024 ** 3
SECTIONS = ("root", "engine", "jdk", "filesystem", "daemon", "other_daemons", "lanes", "lineage", "backups", "stores",
            "clients", "launch", "tmp", "connections")


def finding(id: str, level: str, what: str, why: str, fix: str) -> dict:
    return {"id": id, "level": level, "what": what, "why": why, "fix": fix}


def _ok(id: str, what: str) -> dict:
    return finding(id, "ok", what, "", "")


class Report:
    def __init__(self):
        self.sections: dict[str, dict] = {}

    def add(self, name: str, data: dict, *findings: dict) -> None:
        self.sections[name] = {"data": data, "findings": list(findings) or [_ok(name, "no problem found")]}

    def findings(self) -> list[dict]:
        return [item for section in self.sections.values() for item in section["findings"] if item["level"] != "ok"]


# ---- sections ------------------------------------------------------------------------------------------------------

def _root(settings: dict, report: Report) -> None:
    from hydralysis import config
    root = paths.root_path(settings)
    try:
        source = paths.root_source(config.read_settings())
    except Exception:
        source = None
    found = []
    if not root.is_dir():
        found.append(finding("root_missing", "warn", "the data root %s does not exist yet" % root,
                             "nothing has been created there; the first write will create it", "none needed, or set HYDRALYSIS_ROOT"))
    if source == "legacy":
        found.append(finding("legacy_root", "info", "the RusticRE-named data root %s is in use" % root, "nothing was moved",
                             "python -m hydralysis.environment init"))
    report.add("root", {"root": str(root), "source": source}, *found)


def _engine_dir(settings: dict) -> Path | None:
    return Path(settings["hydra_dir"]) if settings.get("hydra_dir") else None


def _engine(settings: dict, hello: dict | None, report: Report) -> None:
    directory = _engine_dir(settings)
    release = None
    if directory is not None:
        try:
            release = hydra.engine_release(directory)
        except Exception:
            release = None
    data = {"dir": str(directory) if directory else None, "pinned": hydra.RELEASE, "release": release,
            "protocol": {"min": hydra.PROTOCOL_MIN, "max": hydra.PROTOCOL}}
    found = []
    if hello:
        for key in ("paths", "platform", "analysisIdentity", "decompilerHash", "protocol", "hydraVersion"):
            if key in hello:
                data[key] = hello[key]
        if isinstance(hello.get("analysisIdentity"), dict):
            data["decompilerHash"] = data.get("decompilerHash") or hello["analysisIdentity"].get("decompilerHash")
    if directory is None:
        found.append(finding("engine_not_configured", "warn", "no Hydra engine is configured", "every engine tool will fail",
                             "backend action=install"))
    elif release is None:
        found.append(finding("engine_unreadable", "warn", "no Hydra release can be read from %s" % directory,
                             "the install may be incomplete", "backend action=inspect"))
    elif release != hydra.RELEASE and not settings.get("hydra_allow_unpinned"):
        found.append(finding("engine_not_pinned", "warn", "the engine is %s, the pinned release is %s" % (release, hydra.RELEASE),
                             "a pinned client refuses another release", "backend action=install"))
    version = hello.get("hydraVersion") if hello else release
    match = re.search(r"hydra\.(\d+)", version or "")
    if match and int(match.group(1)) < 4:
        found.append(finding("engine_older_than_hydra4", "warn", "the engine %s predates hydra.4" % version,
                             "hydra.4 carries the integrity packages (E8, E2a): the durable journal, repairs and candidate checks; "
                             "auto-restart stays off without them", "backend action=install"))
    report.add("engine", data, *found)


def _jdk(settings: dict, report: Report) -> None:
    """The JDK, read from files only (running java would add a java.exe to the process list)."""
    home = settings.get("java_home") or os.environ.get("JAVA_HOME")
    if not home:
        java = shutil.which("java")
        home = str(Path(java).resolve().parent.parent) if java else None
    version = None
    if home:
        try:
            for line in (Path(home) / "release").read_text(encoding="utf-8", errors="replace").splitlines():
                if line.startswith("JAVA_VERSION="):
                    version = line.split("=", 1)[1].strip().strip('"')
        except OSError:
            pass
    data = {"home": home, "version": version, "required": REQUIRED_JDK}
    found = []
    if not home:
        found.append(finding("jdk_missing", "warn", "no JDK found (JAVA_HOME unset, no java on PATH)", "the daemon needs JDK %d" % REQUIRED_JDK,
                             "install a JDK %d and set JAVA_HOME" % REQUIRED_JDK))
    elif version is None:
        found.append(finding("jdk_unreadable", "info", "no version in %s/release" % home, "the version could not be checked without running java",
                             "set JAVA_HOME to a JDK %d" % REQUIRED_JDK))
    else:
        major = re.match(r"(\d+)", version)
        if major and int(major.group(1)) < REQUIRED_JDK:
            found.append(finding("jdk_too_old", "error", "JDK %s at %s, the engine needs %d" % (version, home, REQUIRED_JDK),
                                 "the daemon will not start", "point JAVA_HOME at a JDK %d" % REQUIRED_JDK))
    report.add("jdk", data, *found)


def _filesystem(settings: dict, report: Report, volume_probe=None) -> None:
    root = paths.root_path(settings)
    state = hydra.state_dir(settings)
    system = paths.system_drive()
    places = {"root": root, "state": state}
    try:
        for lineage_id in _lineage_ids(settings):
            top = lineage.head(settings, lineage_id)
            places["generation:" + lineage_id] = lineage.project_folder_of(top["gpr"])
            break
    except Exception:
        pass
    data, found = {}, []
    for name, place in places.items():
        info = paths.volume_info(place, volume_probe)
        data[name] = {"path": str(place), **info}
        if system and info["drive"] == system:
            found.append(finding("fs_%s_on_system_drive" % name.split(":")[0], "warn", "%s %s is on the system drive %s" % (name, place, system),
                                 "forks, generations and logs grow without bound and compete with Windows for space",
                                 "set HYDRALYSIS_ROOT (or generations_root) to another drive"))
        if info["fs"] and info["cow"] is False:
            found.append(finding("fs_%s_not_cow" % name.split(":")[0], "warn", "%s %s is on %s, which cannot clone blocks" % (name, place, info["fs"]),
                                 "a fork or a base copy duplicates every byte of the project instead of sharing it",
                                 "put it on ReFS (Dev Drive), APFS, btrfs or xfs"))
    report.add("filesystem", data, *found)


def _read_json(path: Path) -> dict:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, ValueError):
        return {}


def _instances(state: Path) -> list[str]:
    names = []
    for item in sorted(state.glob("*.json")) if state.is_dir() else ():
        if item.name.endswith((".launch.json", ".supervisor.json")) or item.name == "supervisor.json":
            continue
        if (state / (item.stem + ".lock")).exists():
            names.append(item.stem)
    return names


def _daemon(settings: dict, report: Report) -> dict | None:
    """Joins the daemon only when its instance lock is held. Returns {hello, health, status} or None."""
    state = hydra.state_dir(settings)
    data = {"instance": hydra.INSTANCE, "state": str(state), "attached": False}
    found, joined = [], None
    try:
        module = hydra.load_client(settings["hydra_client"], bool(settings.get("hydra_allow_unpinned")))
        daemon = module.Daemon(str(_engine_dir(settings)), str(state), hydra.INSTANCE)
    except Exception as exc:
        data["client_error"] = str(exc)
        found.append(finding("client_unavailable", "warn", "the engine client library cannot be loaded: %s" % exc,
                             "the daemon cannot be inspected", "backend action=inspect"))
        report.add("daemon", data, *found)
        return None
    endpoint = daemon.read_endpoint()
    alive = daemon.jvm_alive()
    data.update(endpoint=endpoint and {k: endpoint.get(k) for k in ("pid", "port", "install", "ghidra", "protocol") if k in endpoint},
                lock_held=alive)
    if not alive:
        data["daemon"] = "not_running"
        if endpoint:
            found.append(finding("daemon_stale_endpoint", "info", "an endpoint file names pid %s but no process holds the lock" % endpoint.get("pid"),
                                 "a killed daemon leaves it behind; the next start replaces it", "none needed"))
    else:
        try:
            session = daemon.attach(client="hydralysis-doctor", harness="doctor")
        except Exception as exc:
            code = getattr(exc, "code", None) or type(exc).__name__
            data["daemon"] = "no_answer"
            found.append(finding("daemon_no_answer", "error", "a JVM holds the instance lock but did not answer hello (%s)" % code,
                                 "it is wedged or still starting", "wait, then backend action=stop with force"))
        else:
            data["attached"] = True
            joined = {"hello": dict(getattr(session, "hello", {}) or {}), "health": None, "status": None}
            try:
                for command, key in (("health", "health"), ("status", "status")):
                    try:
                        joined[key] = session.call(command)
                    except Exception as exc:
                        if getattr(exc, "code", "") not in ("unknown_command", "not_supported", "unknown_action"):
                            raise
                if joined["health"] is None:
                    session.call("ping")
                    joined["health"] = {"state": "ok", "via": "ping"}
            except Exception as exc:
                found.append(finding("daemon_call_failed", "warn", "the daemon joined but a read-only call failed: %s" % exc,
                                     "it may be busy or wedged", "backend action=status"))
            finally:
                try:
                    session.close()
                except Exception:
                    pass
            data["daemon"] = "running"
            data["health"] = joined["health"]
            health = joined["health"] or {}
            if health.get("state") == "suspect":
                found.append(finding("daemon_suspect", "error", "health.state is suspect", "the scheduler may be wedged",
                                     "backend action=stop force=true"))
            if health.get("schedulerLockOk") is False:
                found.append(finding("daemon_scheduler_lock", "error", "schedulerLockOk is false", "requests may not be scheduled",
                                     "backend action=stop force=true"))
            memory = (joined["status"] or {}).get("memory") or health.get("memory")
            if memory:
                data["memory"] = memory
    supervisor = _read_json(state / "supervisor.json")
    if supervisor:
        events = supervisor.get("events") or []
        data["restart_history"] = events[-10:]
        if any(item.get("event") == "daemon_unhealthy" or item.get("code") == "daemon_unhealthy" for item in events if isinstance(item, dict)):
            found.append(finding("daemon_unhealthy", "error", "the supervisor gave up restarting the daemon", "the restart budget (3 per 10 minutes) is used",
                                 "backend action=stop force=true, then retry"))
    report.add("daemon", data, *found)
    report.daemon_handle = (module, daemon)
    return joined


def _other_daemons(settings: dict, report: Report) -> None:
    state = hydra.state_dir(settings)
    handle = getattr(report, "daemon_handle", None)
    others, found = [], []
    for name in _instances(state):
        if name == hydra.INSTANCE or handle is None:
            continue
        module = handle[0]
        try:
            other = module.Daemon(str(_engine_dir(settings)), str(state), name)
            if other.jvm_alive():
                endpoint = other.read_endpoint() or {}
                others.append({"instance": name, "pid": endpoint.get("pid"), "install": endpoint.get("install")})
        except Exception:
            continue
    if others:
        found.append(finding("other_daemons", "info", "%d other daemon(s) run in %s: %s" % (len(others), state, ", ".join(item["instance"] for item in others)),
                             "each holds memory and its own project locks", "python ghidra_session.py --state %s --instance <name> stop" % state))
    report.add("other_daemons", {"instances": others}, *found)


def _lanes(joined: dict | None, report: Report) -> None:
    status = (joined or {}).get("status") or {}
    health = (joined or {}).get("health") or {}
    lanes = health.get("lanes") or status.get("lanes") or {}
    found = []
    rows = lanes.items() if isinstance(lanes, dict) else enumerate(lanes if isinstance(lanes, list) else [])
    for name, lane in rows:
        if not isinstance(lane, dict):
            continue
        if lane.get("starving") or lane.get("starved"):
            found.append(finding("lane_starving", "warn", "lane %s is starving" % name, "its requests wait behind long ones",
                                 "wait for the running jobs or backend action=status"))
        if lane.get("abandonedHolders") or lane.get("abandoned"):
            found.append(finding("lane_abandoned_holder", "warn", "lane %s has an abandoned holder" % name,
                                 "a client left while holding a lock; the program stays locked until it is released", "backend action=status"))
    report.add("lanes", {"lanes": lanes}, *found)


def _lineage_ids(settings: dict) -> list[str]:
    root = lineage.lineages_root(settings)
    ids = []
    for folder in sorted(root.iterdir()) if root.is_dir() else ():
        try:
            lineage.lineage_dir(settings, folder.name)
        except ValueError:
            continue
        if (folder / "lineage.json").is_file() or (folder / "CURRENT.log").is_file():
            ids.append(folder.name)
    return ids


def _dir_size(folder: Path) -> int:
    total = 0
    for current, _, names in os.walk(folder):
        for name in names:
            try:
                total += os.path.getsize(os.path.join(current, name))
            except OSError:
                pass
    return total


def _lineages(settings: dict, report: Report) -> None:
    rows, found = [], []
    for lineage_id in _lineage_ids(settings):
        row = {"lineage": lineage_id}
        folder = lineage.lineage_dir(settings, lineage_id)
        try:
            top = lineage.head(settings, lineage_id)
            row.update(generation=top["gen"], torn_tail=top["torn_tail"], corrupt=top["corrupt"])
            if top["torn_tail"]:
                found.append(finding("lineage_torn_tail", "warn", "%s: CURRENT.log has a torn tail" % lineage_id,
                                     "a writer died mid-append; readers see the last whole line", "ghidra_commit (the next owner repairs it under the lock)"))
            if top["corrupt"]:
                found.append(finding("lineage_gap", "error", "%s: CURRENT.log is corrupt in the middle" % lineage_id,
                                     "commits and reverts are refused until the owner repairs it", "inspect %s" % (folder / "CURRENT.log")))
        except lineage.LineageError as error:
            row["error"] = error.code
            found.append(finding("lineage_unreadable", "error", "%s: %s" % (lineage_id, error), "no head can be resolved", "inspect %s" % folder))
        except Exception as error:
            row["error"] = str(error)
        try:
            tampered = lineage.tampered(settings, lineage_id)
            if tampered:
                row["tampered"] = tampered
                found.append(finding("lineage_tampered", "error", "%s: generation(s) %s changed after publication" % (lineage_id, [t["generation"] for t in tampered]),
                                     "a process wrote into a published generation (4.7)", "do not use those generations; restore from a backup: backend action=backups"))
        except Exception:
            pass
        commits = folder / "commits"
        unfinished = []
        for path in sorted(commits.glob("*.intent.log")) if commits.is_dir() else ():
            try:
                records = hydra_records(path)
            except Exception:
                continue
            if records and not any(item.get("state") in ("done", "published", "aborted", "complete") or item.get("event") in ("done", "published", "aborted") for item in records):
                unfinished.append(path.name[:-len(".intent.log")])
        if unfinished:
            row["unfinished_candidates"] = unfinished
            found.append(finding("lineage_unfinished_candidates", "warn", "%s: %d commit(s) did not finish: %s" % (lineage_id, len(unfinished), ", ".join(unfinished[:5])),
                                 "a candidate is left over from a crash; the intent log decides replay or discard", "ghidra_commit action=recover"))
        gen = folder / "gen"
        generations = [item for item in gen.iterdir() if item.name.isdigit()] if gen.is_dir() else []
        row["generations_on_disk"] = len(generations)
        retained = int(settings.get("generation_warn", GENERATION_WARN))
        if len(generations) > retained:
            size = _dir_size(gen)
            row["generations_bytes"] = size
            found.append(finding("generation_retention", "warn", "%s: %d generations are kept on disk (%.1f GB)" % (lineage_id, len(generations), size / 1024 ** 3),
                                 "nothing removes old generations by itself; each one costs a full copy on a file system without block cloning",
                                 "backend action=backups options={\"op\":\"remove\",\"lineage\":\"%s\"} (a dry run lists what would go)" % lineage_id))
        elif len(generations) > 1 and _dir_size(gen) > int(settings.get("generation_warn_bytes", GENERATION_WARN_BYTES)):
            found.append(finding("generation_retention_size", "warn", "%s: the generations take more than %d GB" % (lineage_id, GENERATION_WARN_BYTES // 1024 ** 3),
                                 "nothing removes old generations by itself", "backend action=backups options={\"op\":\"remove\",\"lineage\":\"%s\"}" % lineage_id))
        rows.append(row)
    report.add("lineage", {"lineages": rows}, *found)


def hydra_records(path: Path) -> list:
    from hydralysis import durable
    return durable.AppendLog(path).scan().records


def _backups(settings: dict, report: Report) -> None:
    rows, found = [], []
    try:
        policy = backups.policy(settings)
    except ValueError as exc:
        report.add("backups", {}, finding("backups_policy_invalid", "error", "backup policy: %s" % exc, "backups cannot be made", "fix backup_roots"))
        return
    for lineage_id in _lineage_ids(settings):
        try:
            listing = backups.listing(settings, lineage_id, verify_all=False)
        except Exception as exc:
            found.append(finding("backups_unreadable", "warn", "%s: %s" % (lineage_id, exc), "the backup list cannot be read", "backend action=backups"))
            continue
        items = listing["backups"]
        legacy = [item["id"] for item in items if not item["sealed"]]
        row = {"lineage": lineage_id, "count": len(items), "independent_verified": listing["independent_verified"],
               "last": max((item.get("createdAt") or "" for item in items), default=None), "legacy_unsealed": legacy,
               "invisible": len(listing["invisible"]), "missing": listing["logged_but_missing"]}
        rows.append(row)
        if not items:
            found.append(finding("backups_none", "warn", "%s: no backup exists" % lineage_id, "a bad commit or a damaged generation has no restore source",
                                 "ghidra_commit makes one; see backend action=backups"))
        elif not listing["independent_verified"]:
            found.append(finding("backups_none_independent", "info", "%s: no independent verified backup (all share blocks with their source)" % lineage_id,
                                 "a block-cloned backup does not survive damage to the shared blocks", "set a second backup root: backup_roots"))
        if legacy:
            found.append(finding("backups_legacy", "info", "%s: %d backup(s) not sealed (made by an older release)" % (lineage_id, len(legacy)),
                                 "they are protected by client discipline only", "backend action=backups options={\"op\":\"verify\",\"lineage\":\"%s\"}" % lineage_id))
        if listing["logged_but_missing"]:
            found.append(finding("backups_missing", "warn", "%s: %d logged backup(s) are gone" % (lineage_id, len(listing["logged_but_missing"])),
                                 "backups.log names folders that no longer exist", "backend action=backups options={\"op\":\"list\",\"lineage\":\"%s\"}" % lineage_id))
        if listing["invisible"]:
            found.append(finding("backups_invisible", "info", "%s: %d folder(s) under the backup roots have no valid backup.json" % (lineage_id, len(listing["invisible"])),
                                 "they are never used as a source", "remove them by hand after checking"))
    report.add("backups", {"lineages": rows, "roots": [item["path"] for item in policy["roots"]], "one_way": "backups are never restored automatically"}, *found)


def _count_key(value, key: str) -> int:
    if isinstance(value, dict):
        return (1 if value.get(key) else 0) + sum(_count_key(item, key) for item in value.values())
    if isinstance(value, list):
        return sum(_count_key(item, key) for item in value)
    return 0


def _stores(settings: dict, report: Report) -> None:
    rows, found = [], []
    for lineage_id in _lineage_ids(settings):
        folder = lineage.lineage_dir(settings, lineage_id) / "views"
        stale = unknown = total = 0
        for path in sorted(folder.glob("*.json")) if folder.is_dir() else ():
            record = _read_json(path)
            if not record:
                continue
            total += 1
            stale += 1 if record.get("stale") else 0
            unknown += _count_key(record, "before_unknown")
        rows.append({"lineage": lineage_id, "views": total, "stale": stale, "before_unknown": unknown})
        if stale:
            found.append(finding("stores_stale_views", "warn", "%s: %d stale view(s)" % (lineage_id, stale), "a newer generation exists; the view's base is behind",
                                 "ghidra_query action=status options={\"show\":\"views\"}, then rebase"))
        if unknown:
            found.append(finding("stores_before_unknown", "info", "%s: %d record(s) with before_unknown" % (lineage_id, unknown),
                                 "they predate their subject record and cannot be drift-checked; a commit needs confirmation", "review them before a commit"))
    report.add("stores", {"lineages": rows}, *found)


def _clients(joined: dict | None, report: Report) -> None:
    status = (joined or {}).get("status") or {}
    by_protocol: dict[str, int] = {}
    for item in status.get("clients") or []:
        if isinstance(item, dict):
            key = str(item.get("protocol", "unknown"))
            by_protocol[key] = by_protocol.get(key, 0) + 1
    found = []
    old = [key for key in by_protocol if key.isdigit() and int(key) < hydra.PROTOCOL]
    if old:
        found.append(finding("clients_old_protocol", "info", "clients on protocol %s share this daemon" % ", ".join(sorted(old)),
                             "they lack the features of protocol %d (deadlines, lane hints)" % hydra.PROTOCOL, "update those harnesses"))
    report.add("clients", {"by_protocol": by_protocol}, *found)


def _launch(settings: dict, report: Report, joined: dict | None) -> None:
    state = hydra.state_dir(settings)
    launch = _read_json(state / (hydra.INSTANCE + ".launch.json"))
    health = (joined or {}).get("health") or {}
    survival = launch.get("survival")
    job = health.get("processJob") or launch.get("processJob") or (survival.get("processJob") if isinstance(survival, dict) else None)
    found = []
    text = json.dumps(survival) if survival is not None else ""
    if launch.get("daemon_dies_with_harness") or "dies_with_harness" in text:
        found.append(finding("daemon_dies_with_harness", "warn", "the daemon dies with the harness that started it",
                             "closing that harness stops the daemon for every other agent", "start it detached: backend action=install, then restart"))
    if isinstance(job, dict) and (job.get("killOnClose") or job.get("kill_on_close")):
        found.append(finding("daemon_in_kill_on_close_job", "warn", "the daemon runs inside a kill-on-close job object (D65)",
                             "its parent's exit ends it and every other agent's session", "start the harness outside a kill-on-close job, or use a detached start"))
    report.add("launch", {"spawn": launch.get("spawn"), "survival": survival, "processJob": job}, *found)


def _tmp(settings: dict, report: Report) -> None:
    """Leftover `*.tmp` of killed writers: reported, offered for removal, never deleted (D28)."""
    now = time.time()
    roots = [paths.root_path(settings)]
    old = []
    for base in roots:
        for current, dirs, names in os.walk(base):
            dirs[:] = [d for d in dirs if d not in ("project", "gen", ".git")]
            for name in names:
                if name.endswith(".tmp"):
                    path = Path(current) / name
                    try:
                        if now - path.stat().st_mtime > TMP_AGE_S:
                            old.append(str(path))
                    except OSError:
                        pass
    found = []
    if old:
        found.append(finding("tmp_leftovers", "warn", "%d leftover .tmp file(s), e.g. %s" % (len(old), old[0]),
                             "a writer was killed between write and rename; nothing sweeps them", "delete after checking: %s" % " ".join('"%s"' % p for p in old[:3])))
    report.add("tmp", {"count": len(old), "files": old[:50]}, *found)


def _connections(report: Report) -> None:
    snap = hydra.REGISTRY.snapshot()
    ab = snap["abandoned"]
    found = []
    if ab["user"] >= ab["userCap"]:
        found.append(finding("abandoned_user_cap", "error", "%d abandoned user calls (cap %d)" % (ab["user"], ab["userCap"]),
                             "the next user call fails before anything is sent (abandoned_cap)", "wait for the daemon to answer, or backend action=stop"))
    elif ab["user"]:
        found.append(finding("abandoned_user_calls", "warn", "%d abandoned user call(s) of %d" % (ab["user"], ab["userCap"]),
                             "each holds a connection until the daemon answers", "backend action=status"))
    if ab["probe"]:
        found.append(finding("abandoned_probes", "warn" if ab["probe"] < ab["probeCap"] else "error",
                             "%d abandoned supervisor probe(s) of %d" % (ab["probe"], ab["probeCap"]),
                             "the daemon did not answer probes in time", "backend action=status"))
    report.add("connections", snap, *found)


# ---- entry points --------------------------------------------------------------------------------------------------

def diagnose(settings: dict, sections=None, volume_probe=None) -> Report:
    """Runs the checks. Reads files, and joins a daemon that already runs; starts nothing, writes nothing."""
    report = Report()
    wanted = set(sections or SECTIONS)
    steps = []

    def run(name, function, *args):
        if name in wanted:
            try:
                function(*args)
            except Exception as exc:
                report.add(name, {"error": str(exc)}, finding(name + "_failed", "warn", "the %s check failed: %s: %s" % (name, type(exc).__name__, exc),
                                                              "the doctor itself could not finish this section", "report this with the doctor output"))
    joined = None
    try:
        joined = _daemon(settings, report) if "daemon" in wanted or "other_daemons" in wanted or "engine" in wanted else None
    except Exception as exc:
        report.add("daemon", {"error": str(exc)}, finding("daemon_failed", "warn", "the daemon check failed: %s" % exc, "", "backend action=status"))
    hello = (joined or {}).get("hello")
    run("root", _root, settings, report)
    run("engine", _engine, settings, hello, report)
    run("jdk", _jdk, settings, report)
    run("filesystem", _filesystem, settings, report, volume_probe)
    run("other_daemons", _other_daemons, settings, report)
    run("lanes", _lanes, joined, report)
    run("lineage", _lineages, settings, report)
    run("backups", _backups, settings, report)
    run("stores", _stores, settings, report)
    run("clients", _clients, joined, report)
    run("launch", _launch, settings, report, joined)
    run("tmp", _tmp, settings, report)
    run("connections", _connections, report)
    for name in list(report.sections):
        if name not in wanted:
            del report.sections[name]
    report.sections = {name: report.sections[name] for name in SECTIONS if name in report.sections}
    return report


def handle(capability: str, request: dict) -> str:
    from hydralysis import api
    options = request.get("options") or {}
    settings = request.get("settings") or api._settings()
    sections = options.get("sections")
    if sections is not None:
        if not isinstance(sections, list) or not all(isinstance(item, str) for item in sections):
            raise ValueError("doctor options.sections must be a list of section names")
        unknown = [item for item in sections if item not in SECTIONS]
        if unknown:
            raise ValueError("unknown doctor section(s) %s; known: %s" % (unknown, ", ".join(SECTIONS)))
    report = diagnose(settings, sections)
    findings = report.findings()
    out = {"findings": findings, "summary": {"errors": sum(f["level"] == "error" for f in findings),
                                            "warnings": sum(f["level"] == "warn" for f in findings),
                                            "info": sum(f["level"] == "info" for f in findings)}}
    if options.get("verbose"):
        out["sections"] = {name: section["data"] for name, section in report.sections.items()}
    return json.dumps(out, indent=2, default=str)
