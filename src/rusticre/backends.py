"""Discover or privately install the engines RusticRE uses, never their MCPs."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import re
import shutil
import stat
import time
import urllib.request
import uuid
import zipfile
from pathlib import Path

from rusticre.ghidra import LaneLock, headless_path
from rusticre.localio import read_text as local_read_text
from rusticre.paths import root_path

SUPPORTED_GHIDRA_VERSION = "12.1.4"

# Official release-asset digests, observed 2026-10-24. No executable installer,
# PATH edits, administrator operation, upstream bridge or upstream MCP package.
ASSETS = {
    "ghidra": {
        "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip",
        "sha256": "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
        "size": 569649598,
    },
    "jdk": {
        "url": "https://github.com/adoptium/temurin25-binaries/releases/download/jdk-25.0.4.1%2B1/OpenJDK25U-jdk_x64_windows_hotspot_25.0.4.1_1.zip",
        "sha256": "00c847d804f4a78e9f04f2683faf14fed898535b177b7fc704486cb0284e9283",
        "size": 141167264,
    },
}


def read_json(path: Path) -> dict:
    try:
        value = json.loads(local_read_text(path))
    except FileNotFoundError:
        return {}
    if not isinstance(value, dict):
        raise ValueError("expected a JSON object in %s" % path)
    return value


def write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + "." + uuid.uuid4().hex + ".tmp")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    temporary.replace(path)


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
        return len(header) >= 20 and header[:5] == b"\x7fELF\x02" and header[18:20] == b"\x3e\x00"


def inspect(settings: dict) -> dict:
    root = root_path(settings)
    saved = read_json(root / "backend.json")
    ghidra_candidates = [settings.get("ghidra_dir"), os.environ.get("GHIDRA_INSTALL_DIR"), saved.get("ghidra_dir")]
    ghidra_candidates += _children(root / "backends", "ghidra_*")
    launcher = shutil.which("analyzeHeadless.bat" if os.name == "nt" else "analyzeHeadless")
    if launcher:
        ghidra_candidates.append(Path(launcher).resolve().parent.parent)
    ghidra = None
    checks = []
    for candidate in ghidra_candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        props = _properties(path / "Ghidra" / "application.properties")
        version = props.get("application.version")
        if version and version != SUPPORTED_GHIDRA_VERSION:
            checks.append({"component": "ghidra", "path": str(path), "version": version, "ready": False,
                           "reason": "unsupported Ghidra %s; this RusticRE build requires %s" % (version, SUPPORTED_GHIDRA_VERSION)})
            continue
        native = path / "Ghidra" / "Features" / "Decompiler" / "os" / ("win_x86_64" if os.name == "nt" else "linux_x86_64") / ("decompile.exe" if os.name == "nt" else "decompile")
        if Path(headless_path(str(path))).is_file() and _native_compatible(native) and props.get("application.version"):
            ghidra = {"path": str(path), "version": props["application.version"], "java_min": int(props.get("application.java.min") or 21),
                      "java_max": int(props["application.java.max"]) if props.get("application.java.max") else None}
            break
        checks.append({"component": "ghidra", "path": str(path), "ready": False, "reason": "launcher, native decompiler or application properties missing"})
    java_candidates = [settings.get("java_home"), os.environ.get("JAVA_HOME"), saved.get("java_home")]
    java_candidates += _children(root / "backends", "jdk*")
    javac = shutil.which("javac.exe" if os.name == "nt" else "javac")
    if javac:
        java_candidates.append(Path(javac).resolve().parent.parent)
    if os.name == "nt":
        java_candidates += _children(Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Eclipse Adoptium", "jdk*")
    java = None
    minimum = ghidra["java_min"] if ghidra else 21
    maximum = ghidra["java_max"] if ghidra else None
    for candidate in java_candidates:
        if not candidate:
            continue
        path = Path(candidate).expanduser().resolve()
        release = _properties(path / "release")
        match = re.match(r"(\d+)", release.get("JAVA_VERSION", ""))
        major = int(match.group(1)) if match else 0
        extension = ".exe" if os.name == "nt" else ""
        if _native_compatible(path / "bin" / ("java" + extension)) and _native_compatible(path / "bin" / ("javac" + extension)) and major >= minimum and (maximum is None or major <= maximum):
            java = {"path": str(path), "version": release.get("JAVA_VERSION"), "major": major}
            break
        checks.append({"component": "jdk", "path": str(path), "ready": False, "reason": "full JDK missing or outside installation's Java bounds"})
    return {"root": str(root), "ready": bool(ghidra and java), "ghidra": ghidra, "jdk": java, "checks": checks,
            "supported_ghidra_version": SUPPORTED_GHIDRA_VERSION,
            "portable_install_supported": os.name == "nt" and platform.machine().lower() in ("amd64", "x86_64")}


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
    request = urllib.request.Request(asset["url"], headers={"User-Agent": "RusticRE backend setup"})
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
    return destination


def ensure(settings: dict, install: bool = False, cancelled=lambda: False) -> dict:
    report = inspect(settings)
    root = Path(report["root"])
    root.mkdir(parents=True, exist_ok=True)
    lock = LaneLock(str(root / ".backend.lock"))
    if not lock.acquire():
        raise ValueError("backend setup is already running")
    try:
        if not report["ready"]:
            if not install:
                raise ValueError("Ghidra and a compatible full JDK are required; run backend install or prepare with install enabled")
            if not report["portable_install_supported"]:
                raise ValueError("portable backend installation currently supports Windows x64; configure existing Ghidra/JDK paths on this host")
            for component, key in (("ghidra", "ghidra_dir"), ("jdk", "java_home")):
                if report[component]:
                    continue
                if cancelled():
                    raise InterruptedError("backend setup cancelled")
                archive = _download(ASSETS[component], root / "downloads", cancelled)
                path = _extract(archive, root / "backends", cancelled)
                settings = {**settings, key: str(path)}
                report = inspect(settings)
            if not report["ready"]:
                raise ValueError("installed backends did not satisfy validation: %s" % report)
        result = {**settings, "root": str(root), "ghidra_dir": report["ghidra"]["path"], "java_home": report["jdk"]["path"]}
        write_json(root / "backend.json", {key: result[key] for key in ("ghidra_dir", "java_home")})
        return result
    finally:
        lock.release()
