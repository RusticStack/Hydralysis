"""Start the native MCP host (`hydralysis-mcp`) when it is installed, else the Python server.

`hydralysis mcp` calls `run_native()` first. The native host answers the same stdio MCP with a few megabytes resident
instead of a Python interpreter; the tools it does not port run in a short-lived `python -m hydralysis.worker`
(see native/hydralysis-mcp and docs/clients.md).

HYDRALYSIS_MCP selects the server: `python` always uses the Python server, `native` requires the binary (exit 2 when it
is missing), anything else (the default) uses the binary when one is found and the Python server otherwise.
HYDRALYSIS_MCP_BIN names the binary explicitly. This module imports only the standard library and `proc`, so
`python -m hydralysis.mcp_launch` is a lean launcher: it holds a Python process of a few megabytes, not the server.
"""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path

from . import proc

BINARY = "hydralysis-mcp.exe" if os.name == "nt" else "hydralysis-mcp"


def mode(environ=None) -> str:
    environ = os.environ if environ is None else environ
    value = (environ.get("HYDRALYSIS_MCP") or environ.get("RUSTICRE_MCP") or "").strip().lower()
    return value if value in ("python", "native") else "auto"


def find_binary(environ=None) -> str | None:
    """The native host: HYDRALYSIS_MCP_BIN, the package's bin/ folder, the interpreter's Scripts/bin folder, then PATH."""
    environ = os.environ if environ is None else environ
    explicit = environ.get("HYDRALYSIS_MCP_BIN")
    if explicit:
        return explicit if Path(explicit).is_file() else None
    for folder in (Path(__file__).resolve().parent / "bin", Path(sys.executable).resolve().parent):
        candidate = folder / BINARY
        if candidate.is_file():
            return str(candidate)
    return shutil.which("hydralysis-mcp")


def run_native(environ=None) -> int | None:
    """Run the native host to its end and return its exit code; `None` when the Python server should run instead."""
    environ = dict(os.environ if environ is None else environ)
    chosen = mode(environ)
    if chosen == "python":
        return None
    binary = find_binary(environ)
    if binary is None:
        if chosen == "native":
            print("hydralysis: HYDRALYSIS_MCP=native but hydralysis-mcp was not found "
                  "(build it with tools/build_mcp_host.py or set HYDRALYSIS_MCP_BIN)", file=sys.stderr)
            return 2
        return None
    environ.setdefault("HYDRALYSIS_PYTHON", sys.executable)
    try:
        child = proc.popen_host([binary], env=environ)
    except OSError as exc:
        if chosen == "native":
            print("hydralysis: cannot start %s: %s" % (binary, exc), file=sys.stderr)
            return 2
        print("hydralysis: cannot start %s (%s); using the Python server" % (binary, exc), file=sys.stderr)
        return None
    try:
        return child.wait()
    except KeyboardInterrupt:
        child.terminate()
        return child.wait()


def main() -> int:
    code = run_native()
    if code is not None:
        return code
    from hydralysis.cli import main as cli_main
    return cli_main(["mcp"])


if __name__ == "__main__":
    sys.exit(main())
