"""Where a launch runs: one report of the data root, the configuration, the engine and the file system.

PROTOCOL-3.md package Z3. Every harness launch reports the same root, engine release and configuration, whatever
directory it starts in, and none of it starts a JVM. Four surfaces share `describe()`:

* the launch banner (`banner()`), on stderr when the MCP server starts and in the `initialize` metadata;
* `backend action=status`, which joins a running daemon and never starts one (api.py hands it to `handle`);
* `python -m hydralysis.environment init` (writes the per-user configuration that pins the root);
* `python -m hydralysis.environment doctor` (an early, read-only slice of `backend action=doctor`).

Findings use the doctor's shape `{id, level, what, why, fix}`.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from hydralysis import __version__, compat, config, paths

CAPABILITY = "environment"


def _finding(id: str, level: str, what: str, why: str, fix: str) -> dict:
    return {"id": id, "level": level, "what": what, "why": why, "fix": fix}


def _engine(settings: dict) -> dict:
    """The first engine install that names a release (its own jar tells); nothing is launched."""
    from hydralysis import backends, hydra
    try:
        candidates = backends._engine_candidates(settings, Path(settings["root"]), {})
    except Exception:
        candidates = [settings.get("hydra_dir")]
    first = None
    for candidate in candidates:
        if not candidate:
            continue
        directory = Path(candidate)
        first = first or str(directory)
        try:
            release = hydra.engine_release(directory)
        except Exception:
            release = None
        if release:
            return {"dir": str(directory), "release": release}
    return {"dir": first, "release": None}


def describe(volume_probe=None, platform: str = sys.platform, environ=os.environ) -> dict:
    """Root, configuration, engine and file system, with the warnings they raise. Never raises, never starts a JVM."""
    report = {"version": __version__, "root": None, "root_source": None, "config": None, "config_source": "none",
              "engine_release": None, "engine_dir": None, "filesystem": {"fs": None, "cow": None, "drive": None},
              "warnings": [], "error": None}
    warnings = report["warnings"]
    try:
        path, source = config.config_source()
        report["config"], report["config_source"] = (str(path) if path else None), source
        raw = config.read_settings()
        report["root_source"] = paths.root_source(raw, environ=environ)
        settings = config.load()
    except (ValueError, OSError) as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
        warnings.append(_finding("config_invalid", "error", "the configuration cannot be used: %s" % exc,
                                 "no tool can resolve a data root from it", "fix or remove %s, or set HYDRALYSIS_CONFIG" %
                                 (report["config"] or "the configuration file")))
        return report
    root = Path(settings["root"])
    report["root"] = str(root)
    engine = _engine(settings)
    report["engine_release"], report["engine_dir"] = engine["release"], engine["dir"]
    report["filesystem"] = paths.volume_info(root, volume_probe)
    if report["root_source"] == "legacy":
        warnings.append(_finding("legacy_root", "info", "the RusticRE-named data root %s is in use" % root,
                                 "it was found because no Hydralysis root exists; nothing was moved",
                                 "run `python -m hydralysis.environment init` to pin it, or move the folder yourself"))
    if report["config_source"] == "none" and report["root_source"] != "env":
        warnings.append(_finding("root_unpinned", "info", "no configuration file pins the root",
                                 "the root follows the per-user default and the environment of each launch",
                                 "run `python -m hydralysis.environment init`"))
    system = paths.system_drive(platform, environ)
    if system and report["filesystem"]["drive"] == system:
        warnings.append(_finding("root_on_system_drive", "warn", "the data root %s is on the system drive %s" % (root, system),
                                 "projects, forks and logs grow without bound and compete with Windows for space",
                                 "set HYDRALYSIS_ROOT or `root` in the configuration to another drive"))
    if report["filesystem"]["fs"] and report["filesystem"]["cow"] is False:
        warnings.append(_finding("root_not_cow", "warn", "the data root is on %s, which cannot clone blocks" % report["filesystem"]["fs"],
                                 "a fork or a base copy duplicates every byte instead of sharing it",
                                 "put the root on ReFS (a Dev Drive), APFS, btrfs or xfs"))
    if report["filesystem"]["fs"] is None:
        warnings.append(_finding("root_fs_unknown", "info", "the file system under %s could not be read" % root,
                                 "the system-drive and copy-on-write checks were skipped", "none needed unless a fork is slow"))
    if not engine["dir"]:
        warnings.append(_finding("engine_not_configured", "warn", "no Hydra engine is configured or installed",
                                 "analysis and every engine tool will fail until one is found",
                                 "run `backend action=install`, or set `hydra_dir`"))
    elif engine["release"] is None:
        warnings.append(_finding("engine_unreadable", "warn", "no Hydra release could be read from %s" % engine["dir"],
                                 "the install may be incomplete", "run `backend action=inspect`"))
    stray = config.ignored_cwd_config()
    if stray is not None and (report["config"] is None or Path(report["config"]) != stray):
        warnings.append(_finding("config_in_cwd_ignored", "warn", "%s exists in the working directory and is not read" % stray,
                                 "a configuration that depends on the working directory gives each harness a different root",
                                 "move it to %s or point HYDRALYSIS_CONFIG at it" % config.user_config_dir()))
    return report


def banner(report: dict | None = None) -> str:
    """One line: root and its source, configuration and its source, engine release, file system."""
    report = report if report is not None else describe()
    fs = report["filesystem"]
    fs_text = "unknown" if not fs["fs"] else "%s%s" % (fs["fs"], "" if fs["cow"] is None else (" (copy-on-write)" if fs["cow"] else " (no copy-on-write)"))
    return ("hydralysis %s | root=%s (source: %s) | config=%s (source: %s) | engine=%s | filesystem=%s | warnings=%d"
            % (report["version"], report["root"] or "unresolved", report["root_source"] or "unknown",
               report["config"] or "none", report["config_source"], report["engine_release"] or "none", fs_text,
               len([item for item in report["warnings"] if item["level"] != "info"])))


def announce(report: dict | None = None, stream=None) -> dict:
    """Write the banner and every warning to stderr; return the report. Never raises."""
    stream = stream if stream is not None else sys.stderr
    try:
        report = report if report is not None else describe()
        lines = [banner(report)]
        lines += ["hydralysis: %s: %s (%s)" % (item["level"], item["what"], item["fix"])
                  for item in report["warnings"] if item["level"] != "info"]
        stream.write("\n".join(lines) + "\n")
        stream.flush()
    except Exception:
        pass
    return report or {}


# ---- backend action=status (registered in api.HANDLER_MODULES; api.py routes `status` here) ----------

def handle(capability: str, request: dict) -> str:
    """`backend action=status`: the running daemon's summary plus the environment, never starting a daemon."""
    if request.get("action") != "status":
        raise ValueError("the environment capability answers backend action=status only")
    return json.dumps(daemon_status(), indent=2, default=str)


def daemon_status() -> dict:
    from hydralysis import api, hydra
    summary: dict = {}
    reason = None
    try:
        engine = hydra.Engine(api._settings(), start=False)
        status = engine.call("status")
        keep = ("protocol", "hydraVersion", "ghidraVersion", "installId", "pid", "startedAt", "memory", "youAre")
        summary = {key: status.get(key) for key in keep if key in status}
        summary["daemon"] = "running"
        summary["projects"] = [{key: item.get(key) for key in ("id", "name", "gpr", "writable", "revision", "stale", "users")}
                               for item in status.get("projects", [])][:20]
        summary["programs"] = [{key: item.get(key) for key in ("key", "mode", "owner", "users", "busy")}
                               for item in status.get("programs", [])][:40]
        summary["clients"] = [{key: item.get(key) for key in ("id", "name", "harness")}
                              for item in status.get("clients", [])][:40]
        summary["imports"] = status.get("imports")
    except (RuntimeError, ValueError, OSError) as exc:
        # No daemon, or no engine installed: a result, not an error. Nothing was started.
        reason = str(exc)
        summary = {"daemon": "not_running", "reason": reason, "started": False}
    summary["catalog"] = api.catalog()
    summary["environment"] = describe()
    return summary


# ---- python -m hydralysis.environment ----------------------------------------------------------------

def init(root: str | None = None, config_file: str | None = None, force: bool = False) -> dict:
    """Pin the data root in the per-user configuration and create the folder. Keeps an existing file unless `force`."""
    found, _ = config.config_source()
    target = Path(config_file) if config_file else (found or config.user_config_dir() / compat.PRIMARY_CONFIG)
    existing = {}
    if target.is_file():
        if not force:
            return {"written": False, "config": str(target), "reason": "exists; use --force to replace it",
                    "environment": describe()}
        try:
            existing = json.loads(target.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            existing = {}
        if not isinstance(existing, dict):
            existing = {}
    chosen = root or existing.get("root") or compat.env("ROOT") or str(paths.default_root())
    resolved = paths.root_path({**existing, "root": chosen})  # rejects dot-prefixed and forbidden locations
    resolved.mkdir(parents=True, exist_ok=True)
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(target.name + ".tmp")
    temporary.write_text(json.dumps({**existing, "root": str(resolved)}, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)
    return {"written": True, "config": str(target), "root": str(resolved), "environment": describe()}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m hydralysis.environment",
                                     description="Report or pin where Hydralysis runs. Starts no JVM.")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("describe", help="print the environment report (default)")
    sub.add_parser("banner", help="print the one-line launch banner")
    sub.add_parser("doctor", help="print the environment findings; exit 1 on an error finding")
    init_parser = sub.add_parser("init", help="write the per-user configuration that pins the data root")
    init_parser.add_argument("--root", help="data root to pin (default: the current resolution)")
    init_parser.add_argument("--config", help="configuration file to write (default: the per-user file)")
    init_parser.add_argument("--force", action="store_true", help="replace an existing configuration file")
    args = parser.parse_args(argv)
    command = args.command or "describe"
    if command == "init":
        try:
            result = init(args.root, args.config, args.force)
        except (ValueError, OSError) as exc:
            print("hydralysis init: %s" % exc, file=sys.stderr)
            return 2
        print(json.dumps(result, indent=2))
        return 0
    report = describe()
    if command == "banner":
        print(banner(report))
        return 0
    if command == "doctor":
        print(json.dumps({"findings": report["warnings"], "banner": banner(report)}, indent=2))
        return 1 if any(item["level"] == "error" for item in report["warnings"]) else 0
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
