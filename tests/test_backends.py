import hashlib
import io
import os
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from rusticre import backends


class BackendSetupTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def installed(self):
        ghidra, java = self.root / "existing-ghidra", self.root / "existing-jdk"
        launcher = Path(backends.headless_path(str(ghidra)))
        launcher.parent.mkdir(parents=True)
        launcher.write_text("existing launcher")
        native = ghidra / "Ghidra/Features/Decompiler/os" / ("win_x86_64" if os.name == "nt" else "linux_x86_64") / ("decompile.exe" if os.name == "nt" else "decompile")
        native.parent.mkdir(parents=True)
        if os.name == "nt":
            executable = b"MZ" + b"\0" * 58 + (64).to_bytes(4, "little") + b"PE\0\0\x64\x86"
        else:
            executable = b"\x7fELF\x02" + b"\0" * 13 + b"\x3e\x00" + b"\0" * 44
        native.write_bytes(executable)
        (ghidra / "Ghidra/application.properties").write_text("application.version=12.1.4\napplication.java.min=21\napplication.java.max=25\n")
        (java / "bin").mkdir(parents=True)
        extension = ".exe" if os.name == "nt" else ""
        for name in ("java", "javac"):
            (java / "bin" / (name + extension)).write_bytes(executable)
        (java / "release").write_text('JAVA_VERSION="25.0.4.1"\n')
        return {"root": str(self.root / "data"), "ghidra_dir": str(ghidra), "java_home": str(java)}

    def test_reuses_existing_backend_without_download_or_machine_environment_change(self):
        settings = self.installed()
        before = dict(os.environ)
        with patch("rusticre.backends._download") as download:
            observed = backends.ensure(settings, install=True)
        download.assert_not_called()
        self.assertEqual(observed["ghidra_dir"], settings["ghidra_dir"])
        self.assertEqual(dict(os.environ), before)
        self.assertEqual(backends.read_json(Path(settings["root"]) / "backend.json")["java_home"], settings["java_home"])

    def test_install_is_required_when_discovery_is_not_ready(self):
        report = {"ready": False, "root": str(self.root), "portable_install_supported": True}
        with patch("rusticre.backends.inspect", return_value=report), patch("rusticre.backends._download") as download:
            with self.assertRaisesRegex(ValueError, "required"):
                backends.ensure({"root": str(self.root)})
        download.assert_not_called()

    def test_directory_names_do_not_prove_native_backend_architecture(self):
        native = self.root / "decompile.exe"
        native.write_bytes(b"MZ" + b"\0" * 200)
        self.assertFalse(backends._native_compatible(native))

    def test_unknown_ghidra_release_is_not_admitted_by_valid_paths(self):
        settings = self.installed()
        properties = Path(settings["ghidra_dir"]) / "Ghidra/application.properties"
        properties.write_text("application.version=12.2\napplication.java.min=21\napplication.java.max=25\n")
        with patch.dict(os.environ, {}, clear=True), patch("rusticre.backends._children", return_value=[]), patch("rusticre.backends.shutil.which", return_value=None):
            report = backends.inspect(settings)
        self.assertFalse(report["ready"])
        self.assertIsNone(report["ghidra"])
        self.assertTrue(any("unsupported Ghidra 12.2" in item["reason"] for item in report["checks"]))

    def test_download_checks_digest_before_archive_can_be_used(self):
        body = b"not a matching backend archive"
        asset = {"url": "https://example.invalid/backend.zip", "size": len(body), "sha256": "0" * 64}
        with patch("rusticre.backends.urllib.request.urlopen", return_value=io.BytesIO(body)):
            with self.assertRaisesRegex(ValueError, "SHA256"):
                backends._download(asset, self.root)
        self.assertFalse((self.root / "backend.zip").exists())
        self.assertTrue(list(self.root.glob("*.part")))

    def test_verified_download_is_cached_without_second_network_request(self):
        body = b"verified official asset fixture"
        asset = {"url": "https://example.invalid/backend.zip", "size": len(body), "sha256": hashlib.sha256(body).hexdigest()}
        with patch("rusticre.backends.urllib.request.urlopen", return_value=io.BytesIO(body)) as request:
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
