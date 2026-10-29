"""tools/bump_hydra.py (PROTOCOL-3.md section 5, R1): the edit set, the anchors, the refusals.

The Hydralysis files the script edits are copied from this tree into a sandbox, so the anchors are checked against the
real text; the release archives are small synthetic ones (a client zip with the stamps, an engine zip holding a jar with
hydra.properties). The site files are synthetic copies of the lines the script edits.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "tools" / "bump_hydra.py"
SPEC = importlib.util.spec_from_file_location("bump_hydra_under_test", SCRIPT)
bump = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(bump)

RELEASE = "12.3-hydra.9"
CLIENT_PY = 'PROTOCOL = 3\nPROTOCOL_MIN = 2\nCLIENT_VERSION = "1.7.0"\nHYDRA_RELEASE = "%s"\n'

SITE_FILES = {
    "src/lib/site.ts": 'export const site = {\n  name: "Hydra Engine",\n  release: "12.3-hydra.2",\n  ghidra: "12.3 DEV",\n};\n',
    "src/docs/pages/installation.ts": ("Get-FileHash hydra-engine-12.3-hydra.2-win_x86_64.zip\n"
                                       "Expand-Archive hydra-engine-12.3-hydra.2-win_x86_64.zip C:\\\\tools\n"
                                       "p: A version is `-hydra.` and a counter: `12.3-hydra.2` is the second release.\n"),
    "src/docs/pages/clients.ts": ' "hydraVersion": "12.3-hydra.2", "ghidraVersion": "12.3", "installId": "..."\n',
    "src/docs/pages/mcp-server.ts": "`backend install` fetches the pinned Hydra Engine release (12.3-hydra.2: the engine and its client) and a JDK\n",
    "src/routes/changelog.tsx": 'id: "12.3-hydra.2",\n',
}


def make_client(path, release=RELEASE, text=CLIENT_PY):
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("hydra-client-%s/ghidra_session.py" % release, text % release if "%s" in text else text)


def make_engine(path, stamp):
    jar = io.BytesIO()
    with zipfile.ZipFile(jar, "w") as j:
        j.writestr("hydra.properties", "# stamped\nhydra.version=%s\n" % (stamp or ""))
    with zipfile.ZipFile(path, "w") as z:
        z.writestr("ghidra_12.3_DEV/Ghidra/Features/HeadlessSession/lib/HeadlessSession.jar", jar.getvalue())


class Sandbox(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="bump-test-", dir=tempfile.gettempdir()))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.tree = self.tmp / "tree"
        # the edited files and the historical ones, as they are in this tree
        for rel in bump.EDIT_SET + bump.HISTORICAL + ("tests/test_backends.py", "tests/test_query.py"):
            (self.tree / rel).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / rel, self.tree / rel)
        self.site = self.tmp / "site"
        for rel, text in SITE_FILES.items():
            (self.site / rel).parent.mkdir(parents=True, exist_ok=True)
            (self.site / rel).write_text(text, encoding="utf-8", newline="")
        self.dist = self.tmp / "dist"
        self.dist.mkdir()
        self.engine = self.dist / bump.ENGINE_ASSET.format(release=RELEASE)
        self.client = self.dist / bump.CLIENT_ASSET.format(release=RELEASE)
        make_engine(self.engine, RELEASE)
        make_client(self.client)

    def sums(self, **override):
        lines = []
        for path in (self.engine, self.client):
            digest = override.get(path.name) or hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append("%s *%s" % (digest, path.name))
        (self.dist / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def snapshot(self, base):
        return {p.relative_to(base).as_posix(): p.read_bytes() for p in sorted(base.rglob("*")) if p.is_file()}

    def run_bump(self, *extra, release=RELEASE, site=False):
        args = ["--release", release, "--dist", str(self.dist), "--root", str(self.tree), "--observed", "2026-11-01", *extra]
        if site:
            args += ["--site-root", str(self.site)]
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            return bump.main(args)


class EditSet(Sandbox):
    def test_the_edit_set_is_exactly_the_declared_files(self):
        before = self.snapshot(self.tree)
        self.sums()
        self.assertEqual(self.run_bump("--write"), 0)
        after = self.snapshot(self.tree)
        changed = {rel for rel in after if after[rel] != before[rel]}
        self.assertEqual(changed, set(bump.EDIT_SET))
        for rel in bump.HISTORICAL + ("tests/test_backends.py", "tests/test_query.py"):
            self.assertEqual(after[rel], before[rel], rel + " is frozen or historical and must not change")

    def test_the_site_edit_set_is_exactly_the_declared_files(self):
        before = self.snapshot(self.site)
        self.assertEqual(self.run_bump("--write", site=True), 0)
        after = self.snapshot(self.site)
        changed = {rel for rel in after if after[rel] != before[rel]}
        self.assertEqual(changed, set(bump.SITE_EDIT_SET))
        self.assertEqual(after["src/routes/changelog.tsx"], before["src/routes/changelog.tsx"])
        text = (self.site / "src/docs/pages/installation.ts").read_text(encoding="utf-8")
        self.assertIn("`12.3-hydra.2` is the second release", text, "the explanation example is history, not a pin")
        self.assertEqual(text.count(RELEASE), 2)

    def test_values_written_into_hydra_py(self):
        self.sums()
        self.assertEqual(self.run_bump("--write"), 0)
        text = (self.tree / bump.HYDRA_PY).read_text(encoding="utf-8")
        self.assertIn('RELEASE = "%s"' % RELEASE, text)
        self.assertIn("PROTOCOL = 3\n", text)
        self.assertIn('CLIENT_VERSION = "1.7.0"', text)
        self.assertIn("observed 2026-11-01", text)
        for path, key in ((self.engine, "engine"), (self.client, "client")):
            data = path.read_bytes()
            self.assertIn('"sha256": "%s", "size": %d' % (hashlib.sha256(data).hexdigest(), len(data)), text, key)
        namespace = {}
        exec(compile(text[text.index("RELEASE = "):text.index("SESSION_MODULE")], "hydra-slice", "exec"), {"Path": Path}, namespace)
        self.assertEqual(namespace["ASSETS"]["engine"]["url"].rsplit("/", 1)[1], self.engine.name)
        self.assertEqual(namespace["ASSETS"]["client"]["size"], len(self.client.read_bytes()))

    def test_pin_sentences_and_fake_constants(self):
        self.sums()
        self.assertEqual(self.run_bump("--write"), 0)
        for rel in (bump.README, bump.THIRD_PARTY, bump.UPSTREAM_SETUP):
            self.assertIn(RELEASE, (self.tree / rel).read_text(encoding="utf-8"), rel)
        fake = (self.tree / bump.FAKE).read_text(encoding="utf-8")
        self.assertIn('"hydraVersion": "%s"' % RELEASE, fake)
        self.assertEqual(fake.count('"protocol": 3, **'), 2)

    def test_second_run_changes_nothing(self):
        self.sums()
        self.assertEqual(self.run_bump("--write"), 0)
        once = self.snapshot(self.tree)
        self.assertEqual(self.run_bump("--write"), 0)
        self.assertEqual(self.snapshot(self.tree), once)
        self.assertEqual(self.run_bump("--check"), 0)

    def test_default_run_shows_and_does_not_write(self):
        before = self.snapshot(self.tree)
        self.assertEqual(self.run_bump(), 0)
        self.assertEqual(self.snapshot(self.tree), before)
        self.assertEqual(self.run_bump("--check"), 1, "--check fails while an edit is pending")

    def test_crlf_files_stay_crlf(self):
        path = self.tree / bump.THIRD_PARTY
        path.write_bytes(path.read_bytes().replace(b"\r\n", b"\n").replace(b"\n", b"\r\n"))
        self.assertEqual(self.run_bump("--write"), 0)
        data = path.read_bytes()
        self.assertEqual(data.count(b"\n"), data.count(b"\r\n"))
        self.assertIn(RELEASE.encode(), data)


class Refusals(Sandbox):
    def refused(self, *extra, release=RELEASE, site=False):
        before = self.snapshot(self.tree)
        self.assertEqual(self.run_bump("--write", *extra, release=release, site=site), 2)
        self.assertEqual(self.snapshot(self.tree), before, "a refusal writes nothing")

    def test_malformed_release(self):
        for bad in ("hydra.4", "12.3-hydra", "12.3-hydra.x", "v12.3-hydra.4", "12.3-hydra.4 "):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(bump.main(["--release", bad, "--dist", str(self.dist), "--root", str(self.tree)]), 2, bad)

    def test_engine_without_the_stamp_is_refused(self):
        make_engine(self.engine, "")
        self.refused()

    def test_engine_with_another_stamp_is_refused(self):
        make_engine(self.engine, "12.3-hydra.dev")
        self.refused()

    def test_unstamped_engine_only_with_the_explicit_switch(self):
        make_engine(self.engine, "")
        self.assertEqual(self.run_bump("--write", "--allow-unstamped-engine"), 0)

    def test_client_with_another_release_is_refused(self):
        make_client(self.client, text=CLIENT_PY.replace("%s", "12.3-hydra.1"))
        self.refused()

    def test_client_without_stamps_is_refused(self):
        with zipfile.ZipFile(self.client, "w") as z:
            z.writestr("hydra-client-%s/ghidra_session.py" % RELEASE, "PROTOCOL = 3\n")
        self.refused()

    def test_checksum_mismatch_is_refused(self):
        self.sums(**{self.client.name: "0" * 64})
        self.refused()

    def test_archive_missing_from_the_checksum_file_is_refused(self):
        (self.dist / "SHA256SUMS").write_text("%s *other.zip\n" % ("1" * 64), encoding="utf-8")
        self.refused()

    def test_missing_archive_is_refused(self):
        self.client.unlink()
        self.refused()

    def test_a_moved_anchor_stops_the_run_and_writes_nothing(self):
        path = self.tree / bump.THIRD_PARTY
        path.write_text(path.read_text(encoding="utf-8").replace("the pinned headless release (", "the headless release ("), encoding="utf-8", newline="")
        self.refused()

    def test_an_extra_literal_on_an_anchor_line_stops_the_run(self):
        path = self.tree / bump.FAKE
        text = path.read_text(encoding="utf-8")
        path.write_text(text + '\nX = {"hydraVersion": "12.3-hydra.2"}\n', encoding="utf-8", newline="")
        self.refused()

    def test_site_anchor_moved(self):
        (self.site / "src/lib/site.ts").write_text("export const site = {};\n", encoding="utf-8")
        site_before = self.snapshot(self.site)
        self.refused(site=True)
        self.assertEqual(self.snapshot(self.site), site_before)


class SiteProtocolConstant(Sandbox):
    def test_a_protocol_constant_in_site_ts_follows_the_pin(self):
        path = self.site / "src/lib/site.ts"
        path.write_text(path.read_text(encoding="utf-8").replace('  ghidra:', '  protocol: 2,\n  ghidra:'), encoding="utf-8", newline="")
        self.assertEqual(self.run_bump("--write", site=True), 0)
        self.assertIn("protocol: 3,", path.read_text(encoding="utf-8"))


class RealTree(unittest.TestCase):
    def test_every_anchor_matches_the_real_files(self):
        """A dry run on this tree must find every anchor once (the script is run against the real files by Y4a)."""
        tmp = Path(tempfile.mkdtemp(prefix="bump-real-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        make_engine(tmp / bump.ENGINE_ASSET.format(release=RELEASE), RELEASE)
        make_client(tmp / bump.CLIENT_ASSET.format(release=RELEASE))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = bump.main(["--release", RELEASE, "--dist", str(tmp), "--root", str(ROOT)])
        self.assertEqual(code, 0)
        report = json.loads(out.getvalue())
        self.assertFalse(report["written"])
        names = {Path(p).relative_to(ROOT).as_posix() for p in report["changed"]}
        self.assertEqual(names, set(bump.EDIT_SET))


if __name__ == "__main__":
    unittest.main()
