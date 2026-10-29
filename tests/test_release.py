"""Release preparation (Z14): version consistency, the changelog, the policy text and the release workflow.

Text checks only: nothing here tags, builds or publishes, and the workflow itself was never run. The workflow
checks parse release.yml into its steps (no YAML dependency) and assert on the commands a step really runs: a
command that is commented out, moved to another step, guarded by `if:`, allowed to fail or reordered fails them.
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


def workflow_steps(text: str) -> list[dict]:
    """The steps of release.yml's single job: name, uses, if, shell, continue-on-error, with, and run lines.

    Enough YAML for this file: a step starts with `- ` at the steps' indent; `run: |` collects the deeper lines.
    """
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip() == "steps:")
    steps: list[dict] = []
    item_indent = None
    i = start + 1
    while i < len(lines):
        line = lines[i]
        if not line.strip():
            i += 1
            continue
        indent = len(line) - len(line.lstrip())
        if item_indent is None:
            item_indent = indent
        if indent < item_indent:
            break
        if indent == item_indent:
            if not line.lstrip().startswith("- "):
                break
            steps.append({"run": [], "with": {}})
            body = line.lstrip()[2:]
            key_indent = indent + 2
        else:
            body = line.strip()
        key, _, value = body.partition(":")
        key, value = key.strip(), value.strip()
        step = steps[-1]
        if indent > key_indent and step.get("_in") == "with":
            step["with"][key] = value
        elif key == "run" and value in ("|", "|-", ">"):
            i += 1
            while i < len(lines) and (not lines[i].strip() or len(lines[i]) - len(lines[i].lstrip()) > key_indent):
                step["run"].append(lines[i].strip())
                i += 1
            continue
        elif key == "run":
            step["run"].append(value)
        elif key == "with":
            step["_in"] = "with"
        else:
            step[key] = re.sub(r"\s+#.*$", "", value)
            step["_in"] = key
        i += 1
    return steps


def live(run: list[str]) -> list[str]:
    """The lines a shell executes: no blank lines, no comments."""
    return [line for line in run if line and not line.startswith("#")]


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

    def step(self, name_prefix: str) -> tuple[int, dict]:
        steps = workflow_steps(self.text)
        found = [(i, st) for i, st in enumerate(steps) if st.get("name", "").startswith(name_prefix)]
        self.assertEqual(len(found), 1, name_prefix)
        return found[0]

    def assert_unconditional(self, step: dict) -> None:
        self.assertNotIn("if", step, step.get("name"))
        self.assertNotIn("continue-on-error", step, step.get("name"))
        for line in live(step["run"]):
            self.assertNotRegex(line, r"\|\|\s*(true|:)(\s|$)|set \+e", line)

    def test_no_step_may_fail_silently(self):
        self.assertNotIn("continue-on-error", self.text)

    def test_builds_both_and_checksums(self):
        build_i, build = self.step("Build sdist and wheel")
        self.assert_unconditional(build)
        self.assertIn("python -m build --sdist --wheel --outdir dist", live(build["run"]))
        sums_i, sums = self.step("SHA256SUMS")
        self.assert_unconditional(sums)
        self.assertEqual(sums.get("shell"), "bash")  # bash -eo pipefail: a failing line fails the step
        self.assertEqual(live(sums["run"])[:2], ["cd dist", "sha256sum *.whl *.tar.gz > SHA256SUMS"])
        steps = workflow_steps(self.text)
        upload = [(i, st) for i, st in enumerate(steps) if st.get("uses", "").startswith("actions/upload-artifact@")]
        self.assertEqual(len(upload), 1)
        upload_i, upload_step = upload[0]
        self.assertNotIn("if", upload_step)
        self.assertEqual(upload_step["with"].get("path"), "dist/*")
        self.assertEqual(upload_step["with"].get("if-no-files-found"), "error")
        verify_i, _ = self.step("Verify the wheel in a fresh environment")
        self.assertLess(build_i, sums_i)
        self.assertLess(sums_i, upload_i)
        self.assertLess(verify_i, upload_i)  # nothing is attached before the wheel was checked

    def test_runs_unit_tests_and_installs_the_wheel(self):
        unit_i, unit = self.step("Unit tests")
        self.assert_unconditional(unit)
        self.assertEqual(live(unit["run"]), ["python -m unittest discover -s tests"])
        build_i, _ = self.step("Build sdist and wheel")
        self.assertLess(unit_i, build_i)

    def test_tag_must_equal_version(self):
        self.assertIn('"${GITHUB_REF_NAME}" != "v${version}"', self.text)

    def test_release_is_a_draft_on_tags_only(self):
        self.assertIn("--draft", self.text)
        self.assertIn("github.ref_type == 'tag'", self.text)
        self.assertNotIn("--latest", self.text)
        self.assertNotIn("gh repo edit", self.text)
        self.assertNotIn("visibility", self.text)

    def test_actions_are_pinned_by_sha(self):
        for line in self.text.splitlines():
            m = re.match(r"\s*(?:- )?uses:\s+(\S+)", line)
            if m:
                self.assertRegex(m.group(1), r"@[0-9a-f]{40}$", line)

    def test_runs_unit_tests_and_installs_the_wheel(self):
        self.assertIn("python -m unittest discover -s tests", self.text)
        self.assertIn("pip install dist/*.whl", self.text)

    def test_checks_the_installed_wheel(self):
        # Z14 acceptance: in a fresh environment the installed wheel reports the tag version and backend inspect
        # reports ready. The tag step is the one that fails on a tag other than v<version> and exports VERSION.
        tag_i, tag = self.step("Tag matches the package version")
        self.assert_unconditional(tag)
        self.assertEqual(tag.get("shell"), "bash")
        tag_lines = live(tag["run"])
        self.assertTrue(any('"${GITHUB_REF_NAME}" != "v${version}"' in line for line in tag_lines))
        self.assertIn('echo "VERSION=$version" >> "$GITHUB_ENV"', tag_lines)
        build_i, _ = self.step("Build sdist and wheel")
        verify_i, verify = self.step("Verify the wheel in a fresh environment")
        self.assert_unconditional(verify)
        self.assertEqual(verify.get("shell"), "bash")
        self.assertLess(tag_i, verify_i)
        self.assertLess(build_i, verify_i)
        fresh = '"$RUNNER_TEMP/fresh/Scripts/'
        lines = live(verify["run"])
        expected = [
            ('python -m venv "$RUNNER_TEMP/fresh"',),
            (fresh + 'python.exe" -m pip install dist/*.whl',),
            (fresh + 'python.exe" -c', "os.environ['VERSION']", "assert hydralysis.__version__ == v"),
            (fresh + 'hydralysis.exe" backend inspect',),
            (fresh + 'python.exe" -c', "json.load(open('inspect.json'))", "assert r.get('ready') is True"),
        ]
        at = -1
        for parts in expected:
            hits = [n for n, line in enumerate(lines) if line.startswith(parts[0]) and all(p in line for p in parts[1:])]
            self.assertTrue(hits, parts)
            self.assertGreater(hits[0], at, parts)  # in this order
            at = hits[0]
        # The inspect report the ready check reads is the one this step just wrote.
        self.assertTrue(any("backend inspect" in line and "inspect.json" in line for line in lines))

if __name__ == "__main__":
    unittest.main()
