"""The trace profile SDK (WS-F): a TOML loader and validator, build-bound hook verification and query modules.

See docs/trace-profiles.md. A profile is data: it names what to hook, what the events mean and how runs are compared,
and it is bound to exact builds. No target-specific profile ships with Hydralysis; `baseline_fixtures.toml` is for the
test fixtures only.
"""

from hydralysis.profiles.loader import (BASELINE, CORE_KINDS, Profile, ProfileError, load_file, load_text,
                                        load_baseline)
from hydralysis.profiles.verify import HookRefused, require, verify_profile
from hydralysis.profiles.queries import QueryModuleError, compile_query, run_module

__all__ = ["BASELINE", "CORE_KINDS", "HookRefused", "Profile", "ProfileError", "QueryModuleError", "compile_query",
           "load_baseline", "load_file", "load_text", "require", "run_module", "verify_profile"]
