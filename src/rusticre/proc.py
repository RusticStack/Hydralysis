"""Child processes never inherit the server's stdin.

Under the stdio MCP server the main thread holds a pending read on stdin. On
Windows a child that inherits that pipe blocks during its own start-up until the
read completes, so every runtime probe hung until its timeout over MCP while the
CLI answered at once. Every child RusticRE starts goes through these helpers.
"""

from __future__ import annotations

import os
import subprocess

def _defaults(kwargs: dict) -> dict:
    if "stdin" in kwargs or "input" in kwargs:
        if kwargs.get("stdin") not in (None, subprocess.DEVNULL) or "input" in kwargs:
            raise ValueError("RusticRE children never read the server's stdin")
    kwargs["stdin"] = subprocess.DEVNULL
    if os.name == "nt" and "creationflags" not in kwargs:
        kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW
    return kwargs


def run(command, **kwargs) -> subprocess.CompletedProcess:
    return subprocess.run(command, **_defaults(kwargs))


def popen(command, **kwargs) -> subprocess.Popen:
    return subprocess.Popen(command, **_defaults(kwargs))
