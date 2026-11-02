"""Client facade: the same scripted dispatch through the Python Client and the Rust one (HYDRALYSIS_IMPL switch).

Both the answers (or exception type, message, structured result and __cause__ text) and the exact calls the dispatch
saw (tool, argument order, dropped None arguments) must agree.
"""

import json
import os
import unittest
from unittest.mock import patch

from hydralysis.client import Client, RusticError

try:
    import hydralysis_native
    HAVE_NATIVE = hasattr(hydralysis_native, "NativeClient")
except ImportError:
    HAVE_NATIVE = False

HEADER = "# exe x.exe size 3 tds 0x0 sha256 " + "a" * 64


def make_dispatch(script, log):
    def dispatch(tool, args):
        log.append((tool, json.dumps(args)))
        answer = script(tool, args)
        if isinstance(answer, BaseException):
            raise answer
        return answer
    return dispatch


def table_script(mismatch_from=None):
    def script(tool, args):
        if tool == "prologue":
            rows = args["checks"]
            result = {"fingerprint": {"sha256": "a" * 64}, "rows": [{"match": True} for _ in rows],
                      "summary": {"checked": len(rows), "matched": len(rows), "failed": 0}, "matched": True}
            if mismatch_from is not None and args["checks"][0].get("name") == mismatch_from:
                result["rows"][0]["match"] = False
                result["summary"].update(matched=len(rows) - 1, failed=1)
                result["matched"] = False
                return RuntimeError("PROLOGUE TABLE MISMATCH\n" + json.dumps(result))
            return json.dumps(result)
        return RuntimeError("boom")
    return script


SCRIPTS = {
    "fingerprint": lambda tool, args: HEADER + "\n" + json.dumps({"sha256": "a" * 64, "bits": 64}),
    "bytes": lambda tool, args: HEADER + "\n" + "55 8b ec" if args.get("size") == 3 else ValueError("size must be positive"),
    "ghidra_query": lambda tool, args: json.dumps({"ok": True, "echo": args}),
}


def run(impl, build, script):
    log = []
    with patch.dict(os.environ, {"HYDRALYSIS_IMPL": impl}), patch("hydralysis.client.api.call", make_dispatch(script, log)):
        client = Client()
        try:
            value = build(client)
            status = ("ok", value)
        except RusticError as error:
            status = ("RusticError", str(error), error.result, type(error.__cause__).__name__, str(error.__cause__))
        except Exception as error:  # noqa: BLE001
            status = (type(error).__name__, str(error))
    return status, log


@unittest.skipUnless(HAVE_NATIVE, "native module not built")
class ClientParity(unittest.TestCase):
    def same(self, build, script):
        python = run("python", build, script)
        rust = run("rust", build, script)
        self.assertEqual(python, rust)
        return python

    def test_static_helpers(self):
        self.same(lambda c: c.fingerprint("x.exe"), SCRIPTS["fingerprint"])
        self.same(lambda c: c.read("x.exe", "rva:0x1000", 3), SCRIPTS["bytes"])
        self.same(lambda c: c.read("x.exe", "rva:0x1000", 0), SCRIPTS["bytes"])
        self.same(lambda c: c.fingerprint("x.exe"), lambda t, a: "no json here")
        self.same(lambda c: c.read("x.exe", "rva:0x1", 3), lambda t, a: "one line")
        self.same(lambda c: c.read("x.exe", "rva:0x1", 3), lambda t, a: "h\nzz")
        self.same(lambda c: (c.disasm("x", "rva:1"), c.inspect("x", "rva:1"), c.sigscan("x", "55 ??", 5)), lambda t, a: "text " + t)

    def test_call_drops_none_and_parses_json(self):
        self.same(lambda c: c.call("anything", exe="x", gone=None, n=3), lambda t, a: json.dumps({"a": [1, 2]}))
        self.same(lambda c: c.call("anything"), lambda t, a: " [1, 2]")
        self.same(lambda c: c.call("anything"), lambda t, a: "{not json")
        self.same(lambda c: c.call("anything"), lambda t, a: "plain")

    def test_refusals(self):
        refusal = json.dumps({"ok": False, "error_kind": "not_found", "error": "none"})
        for error in (RuntimeError(refusal), ValueError("bad"), OSError("disk"), KeyError("k"), RuntimeError("[1]")):
            self.same(lambda c: c.call("t", a=1), lambda t, a, e=error: e)
            self.same(lambda c: c.query("t", "function", "0x1"), lambda t, a, e=error: e)
            self.same(lambda c: c.try_query("t", "function", "0x1"), lambda t, a, e=error: e)
        timeout = RuntimeError(json.dumps({"ok": False, "error_kind": "timeout"}))
        self.same(lambda c: c.try_query("t", "decompile", "0x1"), lambda t, a: timeout)
        self.same(lambda c: c.call("t"), lambda t, a: TypeError("not caught"))

    def test_query_lifts_top_level_options_in_order(self):
        for action in ("function", "export"):
            self.same(lambda c: c.query("t", action, "0x1", contains="x", cursor="c", limit=5, timeout_s=9, mode="decompile"), SCRIPTS["ghidra_query"])
            self.same(lambda c: c.query("t", action, "0x1"), SCRIPTS["ghidra_query"])
            self.same(lambda c: c.query("t", action, timeout_s=3), SCRIPTS["ghidra_query"])
        self.same(lambda c: c.runtime("status", pid=4), lambda t, a: json.dumps({"ok": True}))
        self.same(lambda c: c.evidence(kind="claim", limit=3), lambda t, a: "[]")

    def test_prologue_table_paging(self):
        rows = [{"name": "r%d" % i, "address": "rva:0x1000", "expect": "55"} for i in range(450)]
        self.same(lambda c: c.check_prologues("x.exe", rows), table_script())
        self.same(lambda c: c.check_prologues("x.exe", rows, sha256="0" * 64), table_script())
        self.same(lambda c: c.check_prologues("x.exe", rows), table_script(mismatch_from="r200"))
        self.same(lambda c: c.check_prologues("x.exe", rows[:5]), table_script(mismatch_from="r0"))
        self.same(lambda c: c.check_prologues("x.exe", []), table_script())
        self.same(lambda c: c.check_prologues("x.exe", rows[:3]), lambda t, a: ValueError("SHA-256 mismatch"))


if __name__ == "__main__":
    unittest.main()
