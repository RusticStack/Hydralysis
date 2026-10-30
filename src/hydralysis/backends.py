"""Discover or privately install the engines Hydralysis uses, never their MCPs.

Analysis runs on Hydra Engine (pinned release, see hydra.py) with a full JDK.
A stock Ghidra install is never a candidate: it is not probed, opened or used,
and the old stock-Ghidra settings are ignored with a notice (see `_ignored`).
"""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import threading
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path

from hydralysis import compat, durable, hydra
from hydralysis.locks import LaneLock
from hydralysis.paths import root_path

# Official release-asset digests. No executable installer, PATH edits,
# administrator operation, upstream bridge or upstream MCP package.
ASSETS = {
    "jdk": {
        "url": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip",
        "sha256": "00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283",
        "size": 141167264,
    },
}


def read_json(path: Path) -> dict:
    """A JSON object record. Sealed files are verified and unsealed; a bad file falls back to its `.bak`.

    A file that was never written reads as {}. A file that exists but has no valid version
    raises durable.StoreCorrupt (a ValueError, code store_corrupt); it never reads as empty.
    """
    return durable.read_sealed(Path(path), default={})


def write_json(path: Path, value: dict) -> None:
    """Record-bearing write: sealed, previous version kept as `.bak`, atomic and fsynced (durable.py)."""
    durable.write_sealed(Path(path), value)


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _properties(path: Path) -> dict:
    result = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                key, value = line.split("=", 1)
                result[key.strip()] = value.strip().strip('"')
    return result


def _children(root: Path, pattern: str) -> list[Path]:
    return sorted(root.glob(pattern), reverse=True) if root.is_dir() else []


def _native_compatible(path: Path) -> bool:
    """Read executable headers, not directory names, before reporting ready."""
    if not path.is_file():
        return False
    with path.open("rb") as handle:
        header = handle.read(64)
        if os.name == "nt":
            if len(header) < 64 or header[:2] != b"MZ":
                return False
            handle.seek(int.from_bytes(header[60:64], "little"))
            signature = handle.read(6)
            return signature[:4] == b"PE\0\0" and signature[4:6] == b"\x64\x86"
        if header[:4] == b"\xcf\xfa\xed\xfe":
            return True  # Mach-O 64-bit
        return len(header) >= 20 and header[:5] == b"\x7fELF\x02"


def _engine_candidates(settings: dict, root: Path, saved: dict) -> list:
    candidates = [settings.get("hydra_dir"), compat.env("HYDRA_DIR"), saved.get("hydra_dir")]
    candidates += _children(root / "backends", "hydra-[0-9]*")
    return candidates


def _ignored(settings: dict) -> list[dict]:
    """Stock-Ghidra settings a user may still have. They are never read for discovery.

    This is the only place that names them, so the user is told they have no effect.
    """
    notices = []
    for setting, source, present in (("ghidra_dir", "config", settings.get("ghidra_dir")),
                                     ("GHIDRA_INSTALL_DIR", "environment", os.environ.get("GHIDRA_INSTALL_DIR"))):
        if present:
            notices.append({"setting": setting, "source": source,
                            "notice": "%s (%s) is ignored: Hydralysis runs Hydra Engine only and never uses a stock Ghidra; "
                                      "use hydra_dir or HYDRALYSIS_HYDRA_DIR to point at an engine" % (setting, source)})
    return notices


def _client_candidates(settings: dict, root: Path, saved: dict, engine: str | None) -> list:
    candidates = [settings.get("hydra_client"), saved.get("hydra_client"),
                  root / "backends" / ("hydra-client-" + hydra.RELEASE) / "ghidra_session.py"]
    if engine and settings.get("hydra_allow_unpinned"):
        candidates.append(Path(engine) / hydra.SESSION_MODULE / "support" / "ghidra_session.py")
    return candidates


def inspect(settings: dict) -> dict:
    root = root_path(settings)
    saved = read_json(root / "backend.json")
    allow = bool(settings.get("hydra_allow_unpinned"))
    engine, checks, seen = None, [], set()
    for candidate in _engine_candidates(settings, root, saved):
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        if path in seen:
            continue
        seen.add(path)
        report = hydra.inspect_engine(path, allow)
        if report["ready"]:
            engine = report
            break
        checks.append(report)
    client = None
    for candidate in _client_candidates(settings, root, saved, engine["path"] if engine else None):
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        try:
            hydra.load_client(path, allow)
        except (ValueError, OSError) as exc:
            checks.append({"component": "client", "path": str(path), "ready": False, "reason": str(exc)})
            continue
        client = {"path": str(path), "release": hydra.RELEASE}
        break
    java_candidates = [settings.get("java_home"), os.environ.get("JAVA_HOME"), saved.get("java_home")]
    java_candidates += _children(root / "backends", "jdk*")
    javac = shutil.which("javac.exe" if os.name == "nt" else "javac")
    if javac:
        java_candidates.append(Path(javac).resolve().parent.parent)
    if os.name == "nt":
        java_candidates += _children(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Eclipse Adoptium", "jdk*")
    java = None
    minimum = engine["java_min"] if engine else 25
    maximum = engine["java_max"] if engine else None
    for candidate in java_candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        release = _properties(path / "release")
        match = re.match(r"(\d+)", release.get("JAVA_VERSION", ""))
        major = int(match.group(1)) if match else 0
        extension = ".exe" if os.name == "nt" else ""
        if _native_compatible(path / "bin" / ("java" + extension)) and _native_compatible(path / "bin" / ("javac" + extension)) \
                and major >= minimum and (maximum is None or major <= maximum):
            java = {"path": str(path), "version": release.get("JAVA_VERSION"), "major": major}
            break
        checks.append({"component": "jdk", "path": str(path), "ready": False,
                       "reason": "full JDK missing or outside the engine's Java bounds (%s+)" % minimum})
    return {"root": str(root), "ready": bool(engine and client and java), "engine": engine, "client": client, "jdk": java,
            "checks": checks[:12], "ignored": _ignored(settings), "pinned_release": hydra.RELEASE, "protocol": hydra.PROTOCOL,
            "portable_install_supported": os.name == "nt" and platform.machine().lower() in ("amd64", "x86_64")}


# settings (as JSON) -> (stamp, report, resolved settings) of the last ready inspection; see `_stamp`.
_RESOLVED: dict[str, tuple] = {}
_RESOLVED_GUARD = threading.Lock()
RACY_NS = 2_000_000_000
# What a candidate is judged by: an engine's properties, jar and decompiler folder, a JDK's release file and tools, a client file.
_STAMPED = (Path(), Path("Ghidra", "application.properties"), hydra.SESSION_MODULE / "lib" / "HeadlessSession.jar",
            Path("Ghidra", "Features", "Decompiler", "os"), Path("release"), Path("bin", "java.exe" if os.name == "nt" else "java"),
            Path("bin", "javac.exe" if os.name == "nt" else "javac"))


def _stamp(settings: dict, report: dict | None = None):
    """(mtime_ns, size) of everything an inspection read: the saved backend record, the backends folder, the environment it
    looked at and, with REPORT, every candidate it judged (the ones chosen and the ones that failed). None when the report
    left failures out, so it cannot be told what to watch."""
    root = root_path(settings)
    paths = [root / "backend.json", root / "backend.json.bak", root / "backends"]
    if report is not None:
        if len(report.get("checks", [])) >= 12:
            return None
        chosen = [report[name]["path"] for name in ("engine", "client", "jdk")]
        paths += [Path(item) / part for item in chosen + [check["path"] for check in report.get("checks", [])] for part in _STAMPED]
    stamps = []
    for path in paths:
        try:
            found = os.stat(path)
            stamps.append((found.st_mtime_ns, found.st_size))
        except OSError:
            stamps.append(None)
    names = ("HYDRALYSIS_HYDRA_DIR", "RUSTICRE_HYDRA_DIR", "JAVA_HOME", "PATH", "ProgramFiles")
    return tuple(stamps) + tuple(os.environ.get(name) for name in names)


def resolved(settings: dict) -> dict:
    """Settings with verified engine paths, or a clear error. Never installs.

    A ready answer is kept while nothing it was judged by changed (`_stamp`); a failed one is always inspected again."""
    memo = json.dumps(settings, sort_keys=True, default=str)
    with _RESOLVED_GUARD:
        known = _RESOLVED.get(memo)
    if known is not None and _stamp(settings, known[1]) == known[0]:
        return {**known[2]}
    started = time.time_ns()
    report = inspect(settings)
    if not report["ready"]:
        missing = [name for name in ("engine", "client", "jdk") if not report[name]]
        raise ValueError("analysis engine unavailable (%s missing); run backend inspect, then backend install. "
                         "Queries never install or import implicitly. Details: %s" % (", ".join(missing), json.dumps(report)))
    answer = {**settings, "root": report["root"], "hydra_dir": report["engine"]["path"],
              "hydra_client": report["client"]["path"], "java_home": report["jdk"]["path"]}
    stamp = _stamp(settings, report)
    # A file changed within RACY_NS of the inspection may have changed after it was read (racy git): not kept.
    if stamp is not None and all(item[0] < started - RACY_NS for item in stamp if isinstance(item, tuple)):
        with _RESOLVED_GUARD:
            _RESOLVED[memo] = (stamp, report, answer)
    return {**answer}


def _download(asset: dict, directory: Path, cancelled=lambda: False) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    filename = asset["url"].rsplit("/", 1)[-1]
    archive = directory / filename
    if archive.exists():
        if sha256(archive) != asset["sha256"]:
            raise ValueError("cached backend archive failed SHA256; preserved for inspection: %s" % archive)
        return archive
    partial = archive.with_name(archive.name + "." + uuid.uuid4().hex[:8] + ".part")
    started = time.monotonic()
    digest = hashlib.sha256()
    total = 0
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "Hydralysis backend setup"})
    with urllib.request.urlopen(request, timeout=30) as response, partial.open("xb") as output:
        while True:
            if cancelled():
                raise InterruptedError("backend download cancelled; partial archive retained")
            if time.monotonic() - started > 1800:
                raise TimeoutError("backend download exceeded 1800 seconds")
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > asset["size"]:
                raise ValueError("backend archive exceeds pinned release size")
            output.write(block)
            digest.update(block)
    if total != asset["size"] or digest.hexdigest() != asset["sha256"]:
        raise ValueError("downloaded backend archive failed size/SHA256 verification: %s" % partial)
    partial.replace(archive)
    return archive


def _extract(archive: Path, directory: Path, cancelled=lambda: False) -> Path:
    temporary = directory / ("unpack-" + uuid.uuid4().hex)
    temporary.mkdir(parents=True)
    with zipfile.ZipFile(archive) as package:
        members = package.infolist()
        if sum(item.file_size for item in members) > 8 * 1024**3:
            raise ValueError("backend archive uncompressed size exceeds 8 GiB")
        for item in members:
            target = (temporary / item.filename).resolve()
            if not target.is_relative_to(temporary.resolve()) or "\\" in item.filename or ":" in item.filename or stat.S_ISLNK(item.external_attr >> 16):
                raise ValueError("unsafe backend archive member: %s" % item.filename)
        roots = {Path(item.filename).parts[0] for item in members if Path(item.filename).parts}
        if len(roots) != 1:
            raise ValueError("backend archive must have exactly one root directory")
        for item in members:
            if cancelled():
                raise InterruptedError("backend extraction cancelled; partial directory retained")
            package.extract(item, temporary)
    extracted = temporary / roots.pop()
    destination = directory / extracted.name
    if destination.exists():
        raise ValueError("refusing to replace existing backend directory: %s" % destination)
    extracted.rename(destination)
    temporary.rmdir()
    return destination


def ensure(settings: dict, install: bool = False, cancelled=lambda: False) -> dict:
    report = inspect(settings)
    root = Path(report["root"])
    root.mkdir(parents=True, exist_ok=True)
    lock = LaneLock(str(root / ".backend.lock"))
    # Workers that start together (several agents preparing at once) must not fail each other: wait a bounded time for
    # the holder, then read the state again, because the holder may have finished the install.
    deadline = time.monotonic() + 30
    while not lock.acquire():
        if cancelled():
            raise InterruptedError("backend setup cancelled")
        if time.monotonic() > deadline:
            raise ValueError("backend setup is already running")
        time.sleep(0.05)
    try:
        report = inspect(settings)
        if not report["ready"]:
            if not install:
                raise ValueError("Hydra Engine %s, its client and a full JDK 25+ are required; run backend install"
                                 % hydra.RELEASE)
            if not report["portable_install_supported"]:
                raise ValueError("portable installation supports Windows x64 (the only released Hydra build); "
                                 "configure hydra_dir, hydra_client and java_home on this host")
            if not (report["engine"] and report["client"]):
                if cancelled():
                    raise InterruptedError("backend setup cancelled")
                settings = {**settings, **hydra.install(settings, _download, _extract, cancelled)}
                report = inspect(settings)
            if not report["jdk"]:
                if cancelled():
                    raise InterruptedError("backend setup cancelled")
                archive = _download(ASSETS["jdk"], root / "downloads", cancelled)
                settings = {**settings, "java_home": str(_extract(archive, root / "backends", cancelled))}
                report = inspect(settings)
            if not report["ready"]:
                raise ValueError("installed backends did not satisfy validation: %s" % report)
        result = {**settings, "root": str(root), "hydra_dir": report["engine"]["path"],
                  "hydra_client": report["client"]["path"], "java_home": report["jdk"]["path"]}
        write_json(root / "backend.json", {key: result[key] for key in ("hydra_dir", "hydra_client", "java_home")})
        return result
    finally:
        lock.release()
