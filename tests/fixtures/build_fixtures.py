"""Build the verification fixtures with MSVC for x64 and x86 (docs/verification-fixtures.md).

usage: python tests/fixtures/build_fixtures.py <out dir> [--arch x64|x86] [--only NAME[,NAME...]]

No PDB is written, so analysis sees what it sees in a shipped program, and builds are
reproducible (/Brepro), so a rebuild keeps the prepared targets valid. Each build's
linker map (/MAP) is the ground truth for function addresses. Writes <out>/<arch>/*.exe,
*.map and manifest.json (sha256 and map addresses of every fx_/df_/rustic_ function).

The semantic-trace fixtures (TRACE_BUILDS, docs/trace-fixtures.md; expected answers in expected/<name>.json) are built
the same way for both architectures but listed in trace_manifest.json, not manifest.json, so prepare_fixtures.py does not
import their DLLs and helpers as analysis targets. --only takes names of TRACE_GROUPS or output file names.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILDS = [("flow_fixture.exe", "flow_fixture.c", []), ("vcall_fixture.exe", "vcall_fixture.cpp", ["/EHsc", "/GR"]),
          ("diff1.exe", "diff_fixture.c", []), ("diff2.exe", "diff_fixture.c", ["/DV2"]),
          # the runtime smoke's program: exported rustic_transform/rustic_entry over a Sample, a stop file and a log file
          ("runtime_fixture.exe", "runtime_fixture.c", [])]
# The semantic-trace fixtures (12.3-hydra.6): (output, source, extra cl flags). A *.dll output is built with /LD.
TRACE_BUILDS = [
    ("trace_app.exe", "trace_app.c", []),
    ("trace_plugin_1.dll", "trace_plugin.c", ["/DPLUGIN_ID=1"]),
    ("trace_plugin_2.dll", "trace_plugin.c", ["/DPLUGIN_ID=2"]),
    ("interleave.exe", "interleave.c", []),
    ("interleave_mod.dll", "interleave_mod.c", []),
    ("layouts.exe", "layouts.c", []),
    ("frameloop.exe", "frameloop.c", []),
    ("veh_freeze.exe", "veh_freeze.c", []),
    ("replica_a.exe", "replica_a.c", []),
    ("replica_b.exe", "replica_b.c", []),
    ("fnv_names.exe", "fnv_names.c", []),
    ("minivm.exe", "minivm.c", []),
    ("persist.exe", "persist.c", []),
    ("deadlock.exe", "deadlock.c", []),
    ("ioctl_client.exe", "ioctl_client.c", []),
]
# Fixture name (the expected/<name>.json file) -> the outputs it needs. vcall_fixture and diff_fixture are the extended
# existing fixtures, built into manifest.json.
TRACE_GROUPS = {
    "trace_app": ["trace_app.exe", "trace_plugin_1.dll", "trace_plugin_2.dll"],
    "interleave": ["interleave.exe", "interleave_mod.dll"],
    "layouts": ["layouts.exe"], "frameloop": ["frameloop.exe"], "veh_freeze": ["veh_freeze.exe"],
    "replica": ["replica_a.exe", "replica_b.exe"], "fnv_names": ["fnv_names.exe"], "minivm": ["minivm.exe"],
    "persist": ["persist.exe"], "deadlock": ["deadlock.exe"], "ioctl_client": ["ioctl_client.exe"],
    "vcall_fixture": ["vcall_fixture.exe"], "diff_fixture": ["diff1.exe", "diff2.exe"],
}
ARCHES = (("x64", "x64"), ("x86", "x86"))
SYMBOL = re.compile(r"^\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8,16})\s+(f\s)?", re.I)


def vcvars() -> Path:
    vswhere = Path("C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe")
    found = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires",
                            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, check=True).stdout.strip()
    if not found:
        raise SystemExit("no MSVC build tools found (vswhere)")
    return Path(found) / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"


def msvc_available() -> bool:
    """True when vswhere finds the x86/x64 C++ tools (what the smoke tests need before they may skip)."""
    try:
        vcvars()
    except (SystemExit, OSError, subprocess.CalledProcessError):
        return False
    return True


def symbols(map_path: Path) -> tuple[dict, dict]:
    """fx_/df_/rustic_ function and g_ data VAs from a linker map (C names carry a leading underscore on x86)."""
    functions, data = {}, {}
    for line in map_path.read_text(errors="replace").splitlines():
        match = SYMBOL.match(line)
        if match:
            name = match.group(1).lstrip("_")
            if name.startswith(("fx_", "df_", "rustic_")):
                name = re.sub(r"@\d+$", "", name)  # x86 stdcall decoration (thread and handler callbacks)
            if match.group(3) and name.startswith(("fx_", "df_", "rustic_")):
                functions[name] = "0x%x" % int(match.group(2), 16)
            elif not match.group(3) and name.startswith("g_"):
                data[name] = "0x%x" % int(match.group(2), 16)
            mangled = re.fullmatch(r"\?(g_\w+)@@3.*", match.group(1))
            if mangled and not match.group(3):
                data[mangled.group(1)] = "0x%x" % int(match.group(2), 16)
            cpp = re.fullmatch(r"\?\?_7(\w+)@@6B@", match.group(1))
            method = re.fullmatch(r"\?(\w+)@(\w+)@@U.*", match.group(1))
            direct = re.fullmatch(r"\?(\w+)@(\w+)@@Q.*", match.group(1))
            if cpp:
                data[cpp.group(1) + "::vftable"] = "0x%x" % int(match.group(2), 16)
            elif method and match.group(3):
                functions[method.group(2) + "::" + method.group(1)] = "0x%x" % int(match.group(2), 16)
            elif direct and match.group(3):  # a non-virtual member (an overload called directly): Class::name!direct
                functions[direct.group(2) + "::" + direct.group(1) + "!direct"] = "0x%x" % int(match.group(2), 16)
    return functions, data


def compile_line(exe: str, source: str, extra: list[str], target: Path) -> str:
    flags = ["/LD"] if exe.endswith(".dll") else []
    stem = exe.rsplit(".", 1)[0]
    return ('cl /nologo /Brepro /O2 /GS- /MT %s "%s" /Fe:"%s" /Fo:"%s\\%s.obj" '
            '/link /Brepro /INCREMENTAL:NO /MAP:"%s" /DEBUG:NONE'
            % (" ".join(flags + extra), HERE / source, target / exe, target, stem, target / (stem + ".map")))


def build(root: Path, builds: list, arches=ARCHES) -> dict:
    """Build the (output, source, flags) rows for each (arch, host) and return their manifest.

    One vcvars call and one batch file per architecture; the first failing compile stops the batch and is reported."""
    script = vcvars()
    manifest = {}
    for arch, host in arches:
        target = root / arch
        target.mkdir(parents=True, exist_ok=True)
        lines = ["@echo off", 'call "%s" %s >nul' % (script, host), "if errorlevel 1 exit /b 90"]
        for exe, source, extra in builds:
            lines += ["echo BUILD %s" % exe, compile_line(exe, source, extra, target), "if errorlevel 1 exit /b 91"]
        batch = target / ("build_%d.bat" % abs(hash(tuple(row[0] for row in builds))))
        batch.write_text("\r\n".join(lines) + "\r\n")
        result = subprocess.run(["cmd", "/c", str(batch)], capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL, cwd=target)
        batch.unlink(missing_ok=True)
        if result.returncode:
            print(result.stdout[-3000:], result.stderr[-3000:])
            raise SystemExit("build for %s failed (exit %d)" % (arch, result.returncode))
        for exe, _source, _extra in builds:
            path = target / exe
            functions, data = symbols(target / (exe.rsplit(".", 1)[0] + ".map"))
            manifest["%s/%s" % (arch, exe)] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                               "image_base": "0x%x" % (0x140000000 if arch == "x64" else 0x400000),
                                               "functions": functions, "globals": data}
            print(arch, exe, len(functions), "functions in the map")
    return manifest


def select(names: list[str] | None, table: list) -> list:
    """The rows of `table` that an --only list asks for (group names expand to their outputs); every row when None."""
    if not names:
        return table
    wanted = set()
    for name in names:
        wanted.update(TRACE_GROUPS.get(name, [name]))
    return [row for row in table if row[0] in wanted]


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("out_dir")
    parser.add_argument("--arch", choices=["x64", "x86"])
    parser.add_argument("--only", help="comma-separated fixture names or outputs")
    arguments = parser.parse_args(argv)
    root = Path(arguments.out_dir).resolve()
    arches = tuple(a for a in ARCHES if not arguments.arch or a[0] == arguments.arch)
    only = arguments.only.split(",") if arguments.only else None
    classic, trace = select(only, BUILDS), select(only, TRACE_BUILDS)
    root.mkdir(parents=True, exist_ok=True)
    if classic:
        (root / "manifest.json").write_text(json.dumps(build(root, classic, arches), indent=1))
    if trace:
        (root / "trace_manifest.json").write_text(json.dumps(build(root, trace, arches), indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
