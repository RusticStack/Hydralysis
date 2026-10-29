"""Release preparation (Z14): version consistency, the changelog, the policy text and the release workflow.

Text checks only: nothing here tags, builds or publishes.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

import hydralysis
from hydralysis import hydra

ROOT = Path(__file__).resolve().parent.parent


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


class VersionTests(unittest.TestCase):
    def test_pyproject_and_package_agree(self):
        match = re.search(r'^version = "([^"]+)"', read("pyproject.toml"), re.M)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), hydralysis.__version__)

    def test_changelog_names_the_version_family(self):
        family = ".".join(hydralysis.__version__.split(".")[:2])
        self.assertIn("(%s.0" % family, read("CHANGELOG.md"))


class ChangelogTests(unittest.TestCase):
    def test_carries_the_050_note(self):
        text = read("CHANGELOG.md")
        for needle in ("`saved`", "`overlay_save_debounce_s`", "`.sync.lock`", "`options.as`", "hydra.4"):
            self.assertIn(needle, text)

    def test_states_the_limits(self):
        text = read("CHANGELOG.md")
        for needle in ("Windows x64", "ReFS", "one-way upgrade", "restart"):
            self.assertIn(needle, text)

    def test_no_strong_claims_or_gui(self):
        for rel in ("CHANGELOG.md", "docs/versioning.md"):
            text = read(rel).lower()
            for banned in ("never corrupt", "never block", "any number of", " gui"):
                self.assertNotIn(banned, text, rel)


class VersioningTests(unittest.TestCase):
    def test_policy_sections(self):
        text = read("docs/versioning.md")
        for needle in ("What a version means", "Which release pins which engine", "Rolling back a pin",
                       "Upgrade and backup policy", "bump_hydra.py", "confirm_one_way_upgrade", "private"):
            self.assertIn(needle, text)

    def test_current_pin_is_in_the_table(self):
        self.assertIn(hydra.RELEASE, read("docs/versioning.md"))


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.text = read(".github/workflows/release.yml")

    def test_triggers_are_dispatch_and_tag_only(self):
        self.assertIn("workflow_dispatch:", self.text)
        self.assertIn('tags: ["v*"]', self.text)
        self.assertNotIn("pull_request", self.text)

    def test_builds_both_and_checksums(self):
        self.assertIn("--sdist --wheel", self.text)
        self.assertIn("SHA256SUMS", self.text)
        self.assertIn("upload-artifact", self.text)

    def test_release_is_a_draft_on_tags_only(self):
        self.assertIn("--draft", self.text)
        self.assertIn("github.ref_type == 'tag'", self.text)
        self.assertNotIn("--latest", self.text)
        self.assertNotIn("gh repo edit", self.text)
        self.assertNotIn("visibility", self.text)

    def test_actions_are_pinned_by_sha(self):
        for line in self.text.splitlines():
            m = re.match(r"\s*- uses: (\S+)", line)
            if m:
                self.assertRegex(m.group(1), r"@[0-9a-f]{40}$", line)

    def test_checks_the_installed_wheel(self):
        self.assertIn("backend inspect", self.text)
        self.assertIn("__version__", self.text)


if __name__ == "__main__":
    unittest.main()
