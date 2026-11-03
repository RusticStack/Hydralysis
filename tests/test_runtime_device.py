"""Which device the runtime layer gets: the selection rule in runtime_device.

The rule: `HYDRALYSIS_IMPL=rust` selects the Rust device, unless a Frida stand-in is configured (a `frida` package that
declares HYDRALYSIS_STAND_IN, as tests/fakefrida does); then the Frida-shaped device serves it. The choice is made once per
process, so every case runs in a fresh interpreter.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from support import REPOSITORY

FAKE_SITE = REPOSITORY / "tests" / "fakefrida"
PROBE = (
    "from hydralysis.runtime_device import implementation, stand_in_configured, get_local_device;"
    "device = get_local_device() if implementation() == 'frida' else None;"
    "print(implementation(), stand_in_configured(), type(device).__module__ if device is not None else '-')"
)


def selected(impl: str | None, *paths: Path) -> tuple[str, bool, str]:
    env = {key: value for key, value in os.environ.items() if key not in ("HYDRALYSIS_IMPL", "PYTHONPATH")}
    if impl is not None:
        env["HYDRALYSIS_IMPL"] = impl
    env["PYTHONPATH"] = os.pathsep.join(str(path) for path in (REPOSITORY / "src", *paths))
    done = subprocess.run([sys.executable, "-c", PROBE], env=env, capture_output=True, text=True, timeout=60, check=False)
    if done.returncode:
        raise AssertionError(done.stderr[-2000:])
    chosen, stand_in, module = done.stdout.split()
    return chosen, stand_in == "True", module


class Selection(unittest.TestCase):
    def test_a_configured_stand_in_keeps_the_frida_device_under_rust(self):
        self.assertEqual(selected("rust", FAKE_SITE), ("frida", True, "frida"))

    def test_the_rust_device_is_chosen_when_no_stand_in_is_configured(self):
        with tempfile.TemporaryDirectory() as folder:
            # A frida that does not declare itself a stand-in is the real binding as far as the rule goes.
            real = Path(folder) / "frida"
            real.mkdir()
            (real / "__init__.py").write_text("__version__ = '17.24.3'\n")
            self.assertEqual(selected("rust", Path(folder)), ("rust", False, "-"))
        self.assertEqual(selected("rust")[0:2], ("rust", False))

    def test_without_the_variable_a_stand_in_and_frida_both_mean_frida(self):
        self.assertEqual(selected(None, FAKE_SITE), ("frida", True, "frida"))
        self.assertEqual(selected("", FAKE_SITE)[0], "frida")
        self.assertEqual(selected(None)[0], "frida")

    def test_the_stand_in_is_the_fake_binding(self):
        text = (FAKE_SITE / "frida" / "__init__.py").read_text()
        self.assertIn("HYDRALYSIS_STAND_IN = True", text)


if __name__ == "__main__":
    unittest.main()
