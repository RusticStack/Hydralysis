"""Build the verification fixtures with MSVC for x64 and x86 (docs/verification-fixtures.md).

usage: python tests/fixtures/build_fixtures.py <out dir>

No PDB is written, so analysis sees what it sees in a shipped program, and builds are
reproducible (/Brepro), so a rebuild keeps the prepared targets valid. Each build's
linker map (/MAP) is the ground truth for function addresses. Writes <out>/<arch>/*.exe,
*.map and manifest.json (sha256 and map addresses of every fx_/df_ function).
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
BUILDS = [("flow_fixture.exe", "flow_fixture.c", []), ("vcall_fixture.exe", "vcall_fixture.cpp", ["/EHsc", "/GR"]),
          ("diff1.exe", "diff_fixture.c", []), ("diff2.exe", "diff_fixture.c", ["/DV2"])]
SYMBOL = re.compile(r"^\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8,16})\s+(f\s)?", re.I)


def vcvars() -> Path:
    vswhere = Path("C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe")
    found = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires",
                            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, check=True).stdout.strip()
    if not found:
        raise SystemExit("no MSVC build tools found (vswhere)")
    return Path(found) / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"


def symbols(map_path: Path) -> tuple[dict, dict]:
    """fx_/df_ function and g_ data VAs from a linker map (C names carry a leading underscore on x86)."""
    functions, data = {}, {}
    for line in map_path.read_text(errors="replace").splitlines():
        match = SYMBOL.match(line)
        if match:
            name = match.group(1).lstrip("_")
            if match.group(3) and name.startswith(("fx_", "df_")):
                functions[name] = "0x%x" % int(match.group(2), 16)
            elif not match.group(3) and name.startswith("g_"):
                data[name] = "0x%x" % int(match.group(2), 16)
            mangled = re.fullmatch(r"\?(g_\w+)@@3.*", match.group(1))
            if mangled and not match.group(3):
                data[mangled.group(1)] = "0x%x" % int(match.group(2), 16)
            cpp = re.fullmatch(r"\?\?_7(\w+)@@6B@", match.group(1))
            method = re.fullmatch(r"\?(\w+)@(\w+)@@U.*", match.group(1))
            if cpp:
                data[cpp.group(1) + "::vftable"] = "0x%x" % int(match.group(2), 16)
            elif method and match.group(3):
                functions[method.group(2) + "::" + method.group(1)] = "0x%x" % int(match.group(2), 16)
    return functions, data


def main(out_dir: str) -> int:
    root = Path(out_dir).resolve()
    script = vcvars()
    manifest = {}
    for arch, host in (("x64", "x64"), ("x86", "x86")):
        target = root / arch
        target.mkdir(parents=True, exist_ok=True)
        for exe, source, extra in BUILDS:
            command = ('"%s" %s >nul && cl /nologo /Brepro /O2 /GS- /MT %s "%s" /Fe:"%s" /Fo:"%s\\\\" '
                       '/link /Brepro /INCREMENTAL:NO /MAP:"%s" /DEBUG:NONE'
                       % (script, host, " ".join(extra), HERE / source, target / exe, target, target / exe.replace(".exe", ".map")))
            result = subprocess.run(command, shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=target)
            if result.returncode:
                print(result.stdout[-3000:], result.stderr[-3000:])
                raise SystemExit("build of %s for %s failed" % (exe, arch))
            path = target / exe
            functions, data = symbols(target / exe.replace(".exe", ".map"))
            manifest["%s/%s" % (arch, exe)] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                               "image_base": "0x%x" % (0x140000000 if arch == "x64" else 0x400000),
                                               "functions": functions, "globals": data}
            print(arch, exe, len(manifest["%s/%s" % (arch, exe)]["functions"]), "functions in the map")
    (root / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
