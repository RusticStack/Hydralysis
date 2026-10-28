"""An in-process runtime worker on the fake frida binding, for the capture and snapshot unit tests.

The fake binding stands in for the device, the session and the scripts; the worker code under test is the real
`RuntimeAgent`. The target is this Python process, attached by its own executable (the fake reads that file for
module bytes), so no process is started and nothing is injected.
"""

from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
from pathlib import Path

_FAKE = Path(__file__).resolve().parent / "frida" / "__init__.py"


def load_fake():
    """The fake binding as a module of its own (the real `frida`, if installed, is left alone)."""
    name = "hydralysis_fake_frida"
    if name not in sys.modules:
        spec = importlib.util.spec_from_file_location(name, _FAKE)
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return sys.modules[name]


def attached_agent(directory, **log_options):
    """(agent, exe, sha256, head5): an agent attached to this process through the fake, its log options overridden."""
    from hydralysis.runtime_events import EventLog
    from hydralysis.runtime_worker import RuntimeAgent, _process_path
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    exe = _process_path(os.getpid())
    data = Path(exe).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    agent = RuntimeAgent(directory, load_fake().get_local_device())
    if log_options:
        agent.log = EventLog(directory, directory.name, **log_options)
    agent.startup({"action": "attach", "exe": exe, "sha256": digest, "pid": os.getpid(), "argv": []})
    return agent, exe, digest, " ".join("%02X" % byte for byte in data[:5])
