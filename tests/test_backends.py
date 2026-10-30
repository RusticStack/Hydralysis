import hashlib
import io
import json
import os
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from hydralysis import backends, hydra

from support import workdir


class BackendSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = workdir()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def installed(self, release=hydra.RELEASE, client_release=hydra.RELEASE):
        engine, java = self.root / "hydra-engine", self.root / "existing-jdk"
        native = engine / "Ghidra/Features/Decompiler/os" / ("win_x86_64" if os.name == "nt" else "linux_x86_64") / ("decompile.exe" if os.name == "nt" else "decompile")
        native.parent.mkdir(parents=True)
        if os.name == "nt":
            executable = b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0\x64\x86"
        else:
            executable = b"\x7fELF\x02" + b"\0" * 13 + b"\x3e\x00" + b"\0" * 44
        native.write_bytes(executable)
        (engine / "Ghidra/application.properties").write_text("application.version=12.3\napplication.java.min=25\n")
        lib = engine / "Ghidra/Features/HeadlessSession/lib"
        lib.mkdir(parents=True)
        if release:
            with zipfile.ZipFile(lib / "HeadlessSession.jar", "w") as jar:
                jar.writestr("hydra.properties", "hydra.version=%s\n" % release)
        client = self.root / "client" / "ghidra_session.py"
        client.parent.mkdir()
        client.write_text('PROTOCOL = %d\nCLIENT_VERSION = "%s"\nHYDRA_RELEASE = "%s"\n' % (hydra.PROTOCOL, hydra.CLIENT_VERSION, client_release))
        (java / "bin").mkdir(parents=True)
        extension = ".exe" if os.name == "nt" else ""
        for name in ("java", "javac"):
            (java / "bin" / (name + extension)).write_bytes(executable)
        (java / "release").write_text('JAVA_VERSION="25.0.4.1"\n')
        return {"root": str(self.root / "data"), "hydra_dir": str(engine), "hydra_client": str(client), "java_home": str(java)}

    def inspect(self, settings):
        with patch.dict(os.environ, {}, clear=True), patch("hydralysis.backends._children", return_value=[]), \
                patch("hydralysis.backends.shutil.which", return_value=None):
            return backends.inspect(settings)

    def test_reuses_existing_backend_without_download_or_machine_environment_change(self):
        settings = self.installed()
        before = dict(os.environ)
        with patch("hydralysis.backends._download") as download:
            observed = backends.ensure(settings, install=True)
        download.assert_not_called()
        self.assertEqual(observed["hydra_dir"], str(Path(settings["hydra_dir"]).resolve()))
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(backends.read_json(Path(settings["root"]) / "backend.json")["java_home"], str(Path(settings["java_home"]).resolve()))

    def test_stock_ghidra_given_as_the_engine_is_rejected(self):
        report = self.inspect(self.installed(release=None))
        self.assertFalse(report["ready"])
        self.assertIsNone(report["engine"])
        self.assertTrue(any("stock Ghidra" in item.get("reason", "") for item in report["checks"]))

    def scrubbed_inspect(self, settings, **environment):
        """Real discovery with no ambient environment: only PATH (emptied) and what the test sets."""
        with patch.dict(os.environ, {"PATH": "", **environment}, clear=True), patch("hydralysis.backends._children", return_value=[]):
            return backends.inspect(settings)

    def test_stock_ghidra_settings_are_ignored_and_change_nothing(self):
        settings = self.installed()
        bogus = str(self.root / "no-such-ghidra")
        baseline = self.scrubbed_inspect(settings)
        self.assertTrue(baseline["ready"], baseline)
        self.assertEqual(baseline["ignored"], [])
        observed = self.scrubbed_inspect({**settings, "ghidra_dir": bogus}, GHIDRA_INSTALL_DIR=bogus)
        self.assertEqual({key: value for key, value in observed.items() if key != "ignored"},
                         {key: value for key, value in baseline.items() if key != "ignored"})
        self.assertEqual(sorted(item["setting"] for item in observed["ignored"]), ["GHIDRA_INSTALL_DIR", "ghidra_dir"])
        for item in observed["ignored"]:
            self.assertIn("is ignored", item["notice"])
        self.assertNotIn(bogus, json.dumps(observed["checks"]))

    def test_a_valid_engine_named_only_by_stock_ghidra_settings_is_never_discovered(self):
        settings = self.installed()
        engine = settings.pop("hydra_dir")
        report = self.scrubbed_inspect(settings, GHIDRA_INSTALL_DIR=engine)
        self.assertIsNone(report["engine"])
        self.assertFalse(report["ready"])
        report = self.scrubbed_inspect({**settings, "ghidra_dir": engine})
        self.assertIsNone(report["engine"])
        self.assertEqual([item["setting"] for item in report["ignored"]], ["ghidra_dir"])
        self.assertEqual(report["checks"], [])

    def test_unpinned_hydra_release_is_refused_unless_allowed(self):
        settings = self.installed(release="12.4-hydra.1", client_release="12.4-hydra.1")
        report = self.inspect(settings)
        self.assertFalse(report["ready"])
        self.assertTrue(any("pins %s" % hydra.RELEASE in item.get("reason", "") for item in report["checks"]))
        self.assertTrue(self.inspect({**settings, "hydra_allow_unpinned": True})["engine"]["ready"])

    def test_client_of_another_release_is_refused(self):
        report = self.inspect(self.installed(client_release="dev"))
        self.assertIsNone(report["client"])
        self.assertTrue(any(item.get("component") == "client" for item in report["checks"]))

    def test_resolved_names_what_is_missing_and_never_installs(self):
        settings = self.installed()
        settings["java_home"] = str(self.root / "missing-jdk")
        with patch.dict(os.environ, {}, clear=True), patch("hydralysis.backends._children", return_value=[]), \
                patch("hydralysis.backends.shutil.which", return_value=None), patch("hydralysis.backends._download") as download:
            with self.assertRaisesRegex(ValueError, "jdk missing"):
                backends.resolved(settings)
        download.assert_not_called()

    def test_resolved_is_kept_while_nothing_it_was_judged_by_changes(self):
        settings = self.installed()
        old = os.stat(self.root).st_mtime - 3600
        for path in [self.root, *self.root.rglob("*")]:
            os.utime(path, (old, old))
        with patch.dict(os.environ, {}, clear=True), patch("hydralysis.backends._children", return_value=[]),                 patch("hydralysis.backends.shutil.which", return_value=None), patch.dict(backends._RESOLVED, clear=True),                 patch("hydralysis.backends.inspect", wraps=backends.inspect) as inspect:
            first = backends.resolved(settings)
            self.assertEqual(backends.resolved(settings), first)
            self.assertEqual(inspect.call_count, 1)
            client = Path(settings["hydra_client"])
            os.utime(client, (old + 60, old + 60))
            self.assertEqual(backends.resolved(settings), first)
            self.assertEqual(inspect.call_count, 2, "a changed client file is judged again")
            native = next((Path(settings["hydra_dir"]) / "Ghidra/Features/Decompiler/os").glob("*/decompile*"))
            native.write_bytes(native.read_bytes() + b"\0")
            os.utime(native, (old + 60, old + 60))
            os.utime(native.parent, (old, old))
            self.assertEqual(backends.resolved(settings), first)
            self.assertEqual(inspect.call_count, 3, "a replaced decompiler is judged again")
            (Path(settings["java_home"]) / "release").write_text('JAVA_VERSION="17.0.1"\n')
            with self.assertRaisesRegex(ValueError, "jdk missing"):
                backends.resolved(settings)

    def test_install_is_required_when_discovery_is_not_ready(self):
        report = {"ready": False, "root": str(self.root), "portable_install_supported": True}
        with patch("hydralysis.backends.inspect", return_value=report), patch("hydralysis.backends._download") as download:
            with self.assertRaisesRegex(ValueError, "required"):
                backends.ensure({"root": str(self.root)})
        download.assert_not_called()

    def test_directory_names_do_not_prove_native_backend_architecture(self):
        native = self.root / "decompile.exe"
        native.write_bytes(b"MZ" + b"\0" * 200)
        self.assertFalse(backends._native_compatible(native))

    def test_download_checks_digest_before_archive_can_be_used(self):
        body = b"not a matching backend archive"
        asset = {"url": "https://example.invalid/backend.zip", "size": len(body), "sha256": "0" * 64}
        with patch("hydralysis.backends.urllib.request.urlopen", return_value=io.BytesIO(body)):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                backends._download(asset, self.root)
        self.assertFalse((self.root / "backend.zip").exists())
        self.assertTrue(list(self.root.glob("*.part")))

    def test_verified_download_is_cached_without_second_network_request(self):
        body = b"verified official asset fixture"
        asset = {"url": "https://example.invalid/backend.zip", "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        with patch("hydralysis.backends.urllib.request.urlopen", return_value=io.BytesIO(body)) as request:
            path = backends._download(asset, self.root)
            self.assertEqual(backends._download(asset, self.root), path)
        self.assertEqual(request.call_count, 1)

    def test_zip_traversal_and_symlinks_are_refused_before_extraction(self):
        for name in ("../escaped", "C:/escaped", "root\\..\\..\\escaped"):
            with self.subTest(name=name):
                archive = self.root / "bad.zip"
                with zipfile.ZipFile(archive, "w") as package:
                    package.writestr(name, b"untrusted")
                with self.assertRaisesRegex(ValueError, "unsafe"):
                    backends._extract(archive, self.root / "install")
        archive = self.root / "symlink.zip"
        with zipfile.ZipFile(archive, "w") as package:
            member = zipfile.ZipInfo("root/link")
            member.external_attr = 0o120777 << 16
            package.writestr(member, "outside")
        with self.assertRaisesRegex(ValueError, "unsafe"):
            backends._extract(archive, self.root / "install")

    def test_extract_never_replaces_an_existing_installation(self):
        archive = self.root / "good.zip"
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("jdk-fixture/release", "valid fixture")
        destination = self.root / "install"
        result = backends._extract(archive, destination)
        (result / "owner-note").write_text("keep")
        with self.assertRaisesRegex(ValueError, "refusing to replace"):
            backends._extract(archive, destination)
        self.assertEqual((result / "owner-note").read_text(), "keep")


if __name__ == "__main__":
    unittest.main()
