"""Build the verification fixtures with MSVC for x64 and x86 (docs/verification-fixtures.md).

usage: python tests/fixtures/build_fixtures.py <out dir>

No PDB is written, so analysis sees what it sees in a shipped program; each build's
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
SYMBOL = re.compile(r"^\s*\d{4}:[0-9a-f]{8}\s+(\S+)\s+([0-9a-f]{8,16})\s+f\s", re.I)


def vcvars() -> Path:
    vswhere = Path("C:/Program Files (x86)/Microsoft Visual Studio/Installer/vswhere.exe")
    found = subprocess.run([str(vswhere), "-latest", "-products", "*", "-requires",
                            "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
                           capture_output=True, text=True, stdin=subprocess.DEVNULL, check=True).stdout.strip()
    if not found:
        raise SystemExit("no MSVC build tools found (vswhere)")
    return Path(found) / "VC" / "Auxiliary" / "Build" / "vcvarsall.bat"


def functions(map_path: Path) -> dict:
    """fx_/df_ function VAs from a linker map (C names may carry a leading underscore on x86)."""
    out = {}
    for line in map_path.read_text(errors="replace").splitlines():
        match = SYMBOL.match(line)
        if match:
            name = match.group(1).lstrip("_")
            if name.startswith(("fx_", "df_")):
                out[name] = "0x%x" % int(match.group(2), 16)
    return out


def main(out_dir: str) -> int:
    root = Path(out_dir).resolve()
    script = vcvars()
    manifest = {}
    for arch, host in (("x64", "x64"), ("x86", "x86")):
        target = root / arch
        target.mkdir(parents=True, exist_ok=True)
        for exe, source, extra in BUILDS:
            command = ('"%s" %s >nul && cl /nologo /O2 /GS- /MT %s "%s" /Fe:"%s" /Fo:"%s\\\\" '
                       '/link /INCREMENTAL:NO /MAP:"%s" /DEBUG:NONE'
                       % (script, host, " ".join(extra), HERE / source, target / exe, target, target / exe.replace(".exe", ".map")))
            result = subprocess.run(command, shell=True, capture_output=True, text=True, stdin=subprocess.DEVNULL, cwd=target)
            if result.returncode:
                print(result.stdout[-3000:], result.stderr[-3000:])
                raise SystemExit("build of %s for %s failed" % (exe, arch))
            path = target / exe
            manifest["%s/%s" % (arch, exe)] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
                                               "functions": functions(target / exe.replace(".exe", ".map"))}
            print(arch, exe, len(manifest["%s/%s" % (arch, exe)]["functions"]), "functions in the map")
    (root / "manifest.json").write_text(json.dumps(manifest, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
