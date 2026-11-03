"""Build the native MCP host and place it where `hydralysis mcp` finds it (src/hydralysis/bin/).

    python tools/build_mcp_host.py [--target-dir DIR] [--offline] [--no-install]

Requires a Rust toolchain. The binary is not committed: build it before `pip install .` / building the wheel (the wheel
ships src/hydralysis/bin/* as package data), or point HYDRALYSIS_MCP_BIN at the built file. Without it `hydralysis mcp`
runs the Python server, as before. Also regenerates native/hydralysis-mcp/catalog.json first so the host cannot ship a
stale catalog.
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CRATE = ROOT / "native" / "hydralysis-mcp"


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--target-dir", help="CARGO_TARGET_DIR (default: the crate's target/)")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--no-install", action="store_true", help="build only; do not copy into src/hydralysis/bin")
    args = parser.parse_args(argv)
    subprocess.run([sys.executable, str(ROOT / "tools" / "gen_mcp_catalog.py")], check=True)
    env = dict(os.environ)
    if args.target_dir:
        env["CARGO_TARGET_DIR"] = args.target_dir
    command = ["cargo", "build", "--release", "--manifest-path", str(CRATE / "Cargo.toml")]
    if args.offline:
        command.append("--offline")
    subprocess.run(command, check=True, env=env)
    target = Path(env.get("CARGO_TARGET_DIR") or CRATE / "target")
    name = "hydralysis-mcp.exe" if os.name == "nt" else "hydralysis-mcp"
    built = target / "release" / name
    if not built.is_file():
        print("build finished but %s is missing" % built, file=sys.stderr)
        return 1
    if args.no_install:
        print(built)
        return 0
    destination = ROOT / "src" / "hydralysis" / "bin"
    destination.mkdir(exist_ok=True)
    shutil.copy2(built, destination / name)
    print(destination / name)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
