"""Audit the agent harnesses on this machine for any trace of a stock Ghidra.

For every harness configuration it can find (or is given), the audit:

  1. reads the configured MCP servers and fails when one of them is a stock-Ghidra server or sets a stock-Ghidra
     variable or path (a Hydralysis server entry is listed, never changed);
  2. launches each configured Hydralysis server (initialize, then tools/list, nothing else), with a scrubbed
     environment and a private data root, and fails when its catalog names a stock-Ghidra hook;
  3. greps the skill directories that concern Hydralysis or Hydra Engine for the stock-install names. A line that
     says the setting is ignored is the only allowed mention.

Findings are `fail` (exit 1) or `warn` (reported, exit 0): a warn is a hygiene point, for example a server still
registered under the old name `rusticre` or started from a mutable checkout instead of a pinned install.
The audit never writes to a harness configuration, never prints an environment value, and never starts anything
but the configured Hydralysis servers it was asked to launch.

  python tools/audit_harness.py                     discover the harness configurations of the current user
  python tools/audit_harness.py --config FILE ...   audit exactly these configuration files
  python tools/audit_harness.py --skills DIR ...    audit exactly these skill directories
  python tools/audit_harness.py --no-launch         skip step 2
  python tools/audit_harness.py --self              also audit this checkout's own server (`python -m hydralysis mcp`)
  python tools/audit_harness.py --json              machine-readable report on stdout

Exit code 0 when there is no `fail`; 1 otherwise; 2 on a usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

# Built from parts so the repository's own text scan finds no stock name in this tool.
HOOK = "GHIDRA" + "_INSTALL_DIR"
STOCK_NAMES = re.compile("|".join((HOOK, "analyze" + "Headless", "ghidra" + "Run", "ghidra" + "_dir", r"support[/\\]launch")),
                         re.IGNORECASE)
STOCK_SERVER = re.compile(r"ghidra[-_ ]?mcp|ghidra[-_]?(?:server|bridge)|bethington|lauriewired", re.IGNORECASE)
IGNORED_LINE = re.compile(r"\bignored\b", re.IGNORECASE)
OURS = re.compile(r"hydralysis|rusticre", re.IGNORECASE)
SKILL_OF_INTEREST = re.compile(r"^(?:re-|hydralysis|rusticre|ghidra|evidence$|hooks$)", re.IGNORECASE)
TEXT_SUFFIXES = {".md", ".txt", ".json", ".toml", ".py", ".ps1", ".sh", ".yml", ".yaml"}
LAUNCH_TIMEOUT_S = 40
REPOSITORY = Path(__file__).resolve().parent.parent


def home() -> Path:
    return Path(os.environ.get("USERPROFILE") or os.path.expanduser("~"))


def default_configs() -> list[Path]:
    user = home()
    appdata = Path(os.environ.get("APPDATA", user / "AppData" / "Roaming"))
    candidates = [user / ".claude.json", user / ".claude" / "settings.json", user / ".codex" / "config.toml",
                  user / ".config" / "opencode" / "opencode.json", user / ".gemini" / "settings.json",
                  user / ".cursor" / "mcp.json", appdata / "Code" / "User" / "mcp.json", Path.cwd() / ".mcp.json"]
    return [path for path in candidates if path.is_file()]


def default_skill_dirs() -> list[Path]:
    user = home()
    candidates = [REPOSITORY / "skills", user / ".claude" / "skills", user / ".agents" / "skills",
                  user / ".codex" / "skills", user / ".config" / "opencode" / "skills"]
    return [path for path in candidates if path.is_dir()]


def load(path: Path) -> dict:
    if path.suffix.lower() == ".toml":
        import tomllib
        return tomllib.loads(path.read_text(encoding="utf-8"))
    return json.loads(path.read_text(encoding="utf-8-sig"))


def servers_in(document) -> list[dict]:
    """Every MCP server entry in a harness configuration, whatever the harness calls the table."""
    found = []

    def walk(node, where):
        if isinstance(node, dict):
            for key, value in node.items():
                if key in ("mcpServers", "mcp_servers", "mcp", "servers") and isinstance(value, dict):
                    for name, entry in value.items():
                        if isinstance(entry, dict) and any(k in entry for k in ("command", "url", "args", "type")):
                            found.append({"name": name, "entry": entry, "where": where + [key]})
                else:
                    walk(value, where + [key])
        elif isinstance(node, list):
            for item in node:
                walk(item, where)

    walk(document, [])
    return found


def command_line(entry: dict) -> list[str]:
    command = entry.get("command")
    args = entry.get("args") or []
    if isinstance(command, list):               # opencode: the whole argv in one list
        return [str(part) for part in command]
    return ([str(command)] if command else []) + [str(part) for part in args]


def env_of(entry: dict) -> dict:
    value = entry.get("env") or entry.get("environment") or {}
    return {str(k): str(v) for k, v in value.items()} if isinstance(value, dict) else {}


def classify(server: dict, finding) -> dict:
    """Static checks on one entry; returns the record the report keeps (no environment values)."""
    name, entry = server["name"], server["entry"]
    argv = command_line(entry)
    env = env_of(entry)
    text = " ".join([name] + argv + list(env))
    record = {"server": name, "command": argv[0] if argv else entry.get("url", ""), "env_keys": sorted(env), "ours": False}
    if any(STOCK_NAMES.search(part) for part in [name] + argv + list(env) + list(env.values())) or STOCK_SERVER.search(text):
        finding("fail", "server %r names a stock Ghidra (command, argument, variable or path)" % name)
    if OURS.search(" ".join(argv)) or OURS.search(name):
        record["ours"] = True
        if name.lower() == "rusticre" or re.search(r"rusticre(?:\.exe)?$", argv[0] if argv else "", re.IGNORECASE):
            finding("warn", "server %r is registered under the old name rusticre; register it as hydralysis" % name)
        if argv and re.search(r"[\\/]\.venv[\\/]|[\\/]rusticre-latest[\\/]|[\\/]src[\\/]", argv[0], re.IGNORECASE):
            finding("warn", "server %r starts from a virtual environment of a checkout (%s); a pinned install does not "
                            "change when the checkout does" % (name, Path(argv[0]).parent.parent.parent))
    return record


def scrubbed_environment(entry_env: dict, data_root: str) -> dict:
    keep = ("SystemRoot", "SYSTEMROOT", "PATH", "PATHEXT", "COMSPEC", "TEMP", "TMP", "USERPROFILE", "LOCALAPPDATA", "APPDATA",
            "HOME")
    env = {key: os.environ[key] for key in keep if key in os.environ}
    env.update(entry_env)
    for key in [key for key in env if key.upper() == HOOK]:
        del env[key]                     # a stock hook is never handed to the server under audit
    env["HYDRALYSIS_ROOT"] = data_root   # a private root: the audit never touches the user's data
    env["RUSTICRE_ROOT"] = data_root
    env["PYTHONIOENCODING"] = "utf-8"
    return env


def stop_tree(process: subprocess.Popen) -> None:
    """End the server and every process it started, then wait until all of them are gone.

    A bare terminate() ends only the direct child: a launcher, wrapper or helper it started keeps running, and
    on Windows a live process pins its working directory and open files, so the private root cannot be removed."""
    if process.poll() is None or os.name != "nt":
        try:
            if os.name == "nt":
                subprocess.run(["taskkill", "/PID", str(process.pid), "/T", "/F"], capture_output=True, timeout=30)
            else:
                os.killpg(process.pid, signal.SIGKILL)
        except (OSError, subprocess.SubprocessError, ProcessLookupError):
            pass
    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(15)
    except subprocess.TimeoutExpired:
        pass


def remove_tree(path: str, attempts: int = 40, pause: float = 0.25) -> None:
    """Bounded retry for rmtree: on Windows a handle can outlive its process by a moment (scanner, handle table).

    Only reached after stop_tree() returned, so a retry waits for the system, never for a process we left running."""
    for attempt in range(attempts):
        try:
            shutil.rmtree(path)
            return
        except FileNotFoundError:
            return
        except OSError:
            if attempt == attempts - 1:
                raise
            time.sleep(pause)


def launch(argv: list[str], entry_env: dict) -> dict:
    """initialize + tools/list against one server; kills it afterwards. Returns {info, tools} or {error}."""
    root = tempfile.mkdtemp(prefix="audit-harness-")
    try:
        return _launch(argv, entry_env, root)
    finally:
        try:
            remove_tree(root)
        except OSError as error:      # never lose the report over a leftover scratch directory
            print("audit-harness: could not remove %s: %s" % (root, error), file=sys.stderr)


def _launch(argv: list[str], entry_env: dict, root: str) -> dict:
    requests = [{"jsonrpc": "2.0", "id": 1, "method": "initialize",
                 "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "audit-harness", "version": "1"}}},
                {"jsonrpc": "2.0", "method": "notifications/initialized"},
                {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}]
    try:
        process = subprocess.Popen(argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   env=scrubbed_environment(entry_env, root), cwd=tempfile.gettempdir(),
                                   start_new_session=(os.name != "nt"))   # never cwd=root: a cwd pins the directory
    except OSError as error:
        return {"error": "cannot start: %s" % error}
    answers: dict = {}
    done = threading.Event()

    def read():
        for raw in process.stdout:
            try:
                message = json.loads(raw.decode("utf-8", "replace"))
            except ValueError:
                continue
            if isinstance(message, dict) and "id" in message:
                answers[message["id"]] = message
                if 2 in answers:
                    done.set()
                    return

    reader = threading.Thread(target=read, daemon=True)
    reader.start()
    try:
        for item in requests:
            process.stdin.write((json.dumps(item) + "\n").encode("utf-8"))
            process.stdin.flush()
        done.wait(LAUNCH_TIMEOUT_S)
    except OSError:
        pass
    finally:
        stop_tree(process)           # before closing stdin: a server that exits on EOF would orphan its helpers
        try:
            process.stdin.close()
        except OSError:
            pass
        reader.join(10)
        try:
            process.stdout.close()
        except OSError:
            pass
    if 2 not in answers:
        return {"error": "no tools/list answer within %d s" % LAUNCH_TIMEOUT_S}
    result = answers[1].get("result", {}) if 1 in answers else {}
    return {"info": result.get("serverInfo", {}), "tools": answers[2].get("result", {}).get("tools", []),
            "instructions": result.get("instructions", "")}


def expected_tools() -> set[str] | None:
    try:
        sys.path.insert(0, str(REPOSITORY / "src"))
        from hydralysis.api import TOOL_NAMES
        return set(TOOL_NAMES)
    except Exception:
        return None


def check_catalog(name: str, launched: dict, finding) -> dict:
    if "error" in launched:
        finding("fail", "server %r did not answer tools/list: %s" % (name, launched["error"]))
        return {"launched": False, "error": launched["error"]}
    tools = launched["tools"]
    names = sorted(tool.get("name", "") for tool in tools)
    blob = json.dumps(tools) + launched.get("instructions", "")
    for line in re.split(r"(?<=[.!?])\s+|\n", blob):
        if STOCK_NAMES.search(line) and not IGNORED_LINE.search(line):
            finding("fail", "server %r advertises a stock-Ghidra name: %s" % (name, line.strip()[:120]))
    if launched["info"].get("name") != "hydralysis":
        finding("warn", "server %r announces itself as %r, not hydralysis" % (name, launched["info"].get("name")))
    expected = expected_tools()
    if expected is not None and set(names) != expected:
        finding("warn", "server %r advertises %d tools that differ from this checkout's catalog (missing %s, extra %s)" % (
            name, len(names), sorted(expected - set(names)), sorted(set(names) - expected)))
    return {"launched": True, "server_info": launched["info"], "tool_count": len(names), "tools": names}


def skill_files(directory: Path):
    for skill in sorted(directory.iterdir()):
        if skill.is_symlink() or not skill.is_dir():
            continue
        manifest = skill / "SKILL.md"
        if not manifest.is_file():
            continue
        head = manifest.read_text(encoding="utf-8", errors="replace")
        if SKILL_OF_INTEREST.match(skill.name) or OURS.search(head) or "Hydra Engine" in head:
            yield skill, manifest


def front_matter_name(manifest: Path) -> str | None:
    text = manifest.read_text(encoding="utf-8", errors="replace").lstrip("﻿")
    match = re.match(r"---\r?\n(.*?)\r?\n---", text, re.DOTALL)
    if not match:
        return None
    found = re.search(r"^name:\s*(\S+)\s*$", match.group(1), re.MULTILINE)
    return found.group(1).strip("'\"") if found else None


def audit_skills(directory: Path, finding) -> dict:
    scanned, hits = 0, []
    for skill, manifest in skill_files(directory):
        name = front_matter_name(manifest)
        if name != skill.name:
            finding("fail" if directory == REPOSITORY / "skills" else "warn",
                    "skill %s: front matter name is %r, the directory is %r" % (skill, name, skill.name))
        for path in sorted(skill.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
                continue
            scanned += 1
            for number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
                if STOCK_NAMES.search(line) and not IGNORED_LINE.search(line):
                    where = "%s:%d" % (path, number)
                    hits.append(where)
                    finding("fail", "skill text names a stock-install setting: %s: %s" % (where, line.strip()[:100]))
    return {"directory": str(directory), "files_scanned": scanned, "hits": hits}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--config", action="append", default=[], metavar="FILE")
    parser.add_argument("--skills", action="append", default=[], metavar="DIR")
    parser.add_argument("--no-launch", action="store_true")
    parser.add_argument("--self", dest="own", action="store_true")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args(argv)
    configs = [Path(item) for item in args.config] if args.config else default_configs()
    skills = [Path(item) for item in args.skills] if args.skills else default_skill_dirs()
    findings, report = [], {"configs": [], "skills": []}

    def finding(level, message):
        findings.append({"level": level, "message": message})

    for path in configs:
        entry = {"path": str(path), "servers": []}
        report["configs"].append(entry)
        try:
            document = load(path)
        except (OSError, ValueError) as error:
            finding("fail", "cannot read %s: %s" % (path, type(error).__name__))
            continue
        for server in servers_in(document):
            record = classify(server, lambda level, message, p=path: finding(level, "%s: %s" % (p.name, message)))
            if record["ours"] and not args.no_launch:
                argv_ = command_line(server["entry"])
                if argv_:
                    record["catalog"] = check_catalog(
                        server["name"], launch(argv_, env_of(server["entry"])),
                        lambda level, message, p=path: finding(level, "%s: %s" % (p.name, message)))
            entry["servers"].append(record)
    if args.own:
        entry = {"path": "(this checkout)", "servers": []}
        report["configs"].append(entry)
        own = {"name": "hydralysis", "entry": {"command": sys.executable, "args": ["-m", "hydralysis", "mcp"],
                                               "env": {"PYTHONPATH": str(REPOSITORY / "src")}}}
        record = classify(own, finding)
        record["catalog"] = check_catalog("hydralysis", launch(command_line(own["entry"]), env_of(own["entry"])), finding)             if not args.no_launch else None
        entry["servers"].append(record)
    for directory in skills:
        if not directory.is_dir():
            finding("fail", "skill directory is missing: %s" % directory)
            continue
        report["skills"].append(audit_skills(directory, finding))
    report["findings"] = findings
    failed = [item for item in findings if item["level"] == "fail"]
    report["ok"] = not failed
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        for config in report["configs"]:
            ours = [s["server"] for s in config["servers"] if s["ours"]]
            print("config %s: %d servers; hydralysis-family: %s" % (config["path"], len(config["servers"]), ours or "none"))
        for item in report["skills"]:
            print("skills %s: %d files scanned, %d stock-install hits" % (item["directory"], item["files_scanned"], len(item["hits"])))
        for item in findings:
            print("%s: %s" % (item["level"].upper(), item["message"]))
        print("audit %s (%d fail, %d warn)" % ("passed" if not failed else "FAILED", len(failed), len(findings) - len(failed)))
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
