# Continuous integration

One workflow, `.github/workflows/tests.yml`, runs on every pull request, on demand (`gh workflow run
tests.yml`) and from `release.yml` on every release (`workflow_call`). It does not run on pushes to `main`:
main is tested locally before a push. Everything runs on GitHub-hosted `windows-latest`, because Hydralysis
targets Windows PEs and the engine ships as a Windows build. There are two jobs.

## What runs where

| Job | Runs | Needs | Does not need |
| --- | --- | --- | --- |
| `unit` (Python 3.13, 3.14, 3.15) | `python -m unittest discover -s tests`: the whole unit suite, the synthetic golden-harness tests (`tests/test_golden.py`) and the no-stock-Ghidra source scan (`tests/test_no_stock_ghidra.py`) | Python and `pip install -e .` | an engine, a JDK, game data |
| `engine` (Python 3.13) | `tests/test_engine_integration.py` against the real pinned Hydra release: prepare, query, overlays, revert, adopt, archive import, bulk export, and the mandatory `expect_revision` rules; then `tests/test_concurrency.py` (the Z1 concurrency guard, whose engine-backed cases are skipped without an engine); then `tests/test_engine_nostock.py` and `tools/audit_harness.py --self` (below) | JDK 25 (Temurin, `actions/setup-java`), the pinned engine and client archives | game data, a stock Ghidra |

The integration tests analyse a small PE that every Windows host has (`whoami.exe`, or the file named by
`HYDRALYSIS_INTEGRATION_BINARY`). Each run uses its own private data root and daemon and stops it at the end.

### The pinned release is read, not copied

`src/hydralysis/hydra.py` (`RELEASE`, `ASSETS`) is the only place that names the Hydra release, its asset URLs,
SHA-256 values and sizes. The workflow never repeats them. `.github/scripts/ci_engine.py` reads them from that
module:

1. `pins` writes the release and the two SHA-256 values to the step outputs.
2. `actions/cache` keeps `hydra-root/downloads` (the ~380 MB engine zip and the small client zip) under the key
   `hydra-archives-<engine sha>-<client sha>`. Bumping the pin in `hydra.py` changes the key, so the old archive is
   never reused.
3. `install` calls the product's own installer (`hydra.install` with the verified downloader). A cache hit is
   re-hashed against the pin before use. A cold download is checked for size and SHA-256 before it is renamed into
   place. The script then hashes both archives a second time and fails on any mismatch. It exports
   `HYDRALYSIS_INTEGRATION_ENGINE` and `HYDRALYSIS_INTEGRATION_CLIENT` for the test step.
4. The test step also sets `HYDRALYSIS_INTEGRATION_JAVA` (the setup-java JDK) and `HYDRALYSIS_TEST_ROOT`.

To upgrade the engine: change `RELEASE` and `ASSETS` in `hydra.py`. CI follows.

### The hermetic check: no stock Ghidra

Hydralysis never uses a stock Ghidra. CI proves it in three places:

- `unit` and `engine` set the stock-Ghidra environment hook to an empty value at job level, and
  `ci_engine.py hermetic` fails if the hook is set, or if a stock launcher is on `PATH`.
- `engine` then runs `ci_engine.py hermetic <root> --java <jdk>`: with a deliberately bogus stock hook set in
  that process, discovery must still select the pinned Hydra engine, must report the hook as ignored, and must not
  have probed the bogus path.
- `tests/test_no_stock_ghidra.py` (in `unit`) scans the shipped source, skills, documentation and tools for the
  stock hooks.

- `tests/test_engine_nostock.py` (in `engine`) proves it end to end. One sequential class scrubs `os.environ` and
  `PATH` itself, plants a decoy stock install (a directory named by the stock hook variable and first on `PATH`, whose
  launchers would write a marker if anything ran them) and then drives the public tool dispatch: `backend inspect`
  (not ready, the decoy reported as ignored), `backend install` (a job that unpacks the pinned release from archives
  it re-hashes), `backend inspect` (ready), `prepare` (a job), `prepare` with `adopt`, `ghidra_query` on both
  targets and a small `ghidra_run` script. A process audit then requires every process of the run to be Hydra Engine
  under the private root, none to name a stock launcher or the decoy, the decoy tree to be byte-identical and its
  marker never written. The archives come from `HYDRALYSIS_NOSTOCK_ARCHIVES`, else from the `downloads` folder beside
  the engine in `HYDRALYSIS_INTEGRATION_ENGINE` (where `ci_engine.py install` leaves them); nothing is downloaded, and
  without them the class is skipped.
- `tools/audit_harness.py` audits the agent harnesses: it reads each harness configuration it finds (or is given),
  launches each configured Hydralysis server for `initialize` and `tools/list` only, and searches the skill
  directories about Hydralysis for the stock-install names (a line that says the setting is ignored is allowed). A
  stock server or name is a failure (exit 1); an old server name or a server started from a mutable checkout is a
  warning. `AuditHarnessTool` in the same test file shows it fails on planted input. On a hosted runner there is no
  harness configuration, so CI runs it with `--self` (this checkout's own server) and the repository's skills; the
  audit of a developer machine is a local step (`python tools/audit_harness.py`).

The CI helper script lives under `.github/`, outside the scanned roots, because it has to name the hook it forbids.

## Limits

- **Not yet run on GitHub Actions.** The workflow was validated for YAML syntax and its commands were run
  by hand against the same pinned release (download with `gh release download`, SHA-256 check, `ci_engine.py`,
  the integration tests). It has not run on GitHub Actions. The first hosted run may still find a problem that
  only the hosted image shows, for example a different default shell quoting or Temurin 25 availability in
  `setup-java`.
- **ReFS-only claims cannot be validated here.** Hosted runners use NTFS. Anything that depends on ReFS
  (Dev Drive behaviour, block cloning, the speed of a project copy on a ReFS volume) is not checked by this CI and
  must not be claimed from a green run. Those claims stay local, measured on the Dev Drive, and are labelled as such.
- **The options-parity test is not run in CI.** `tests/test_engine_options.py` is the only engine test that fails
  on the old `RusticQuery` options, and it needs MSVC-built fixtures (`HYDRALYSIS_INTEGRATION_FIXTURES`). The
  hosted job runs `test_engine_integration.py` only, so a regression of that fix is caught locally, not by a green run.
- **No game data.** CI never sees a game binary, a decompile of one, or a golden baseline. The golden harness
  (`docs/golden-harness.md`) runs in CI only through its synthetic unit tests. Capturing and diffing real baselines
  stays a local step.
- **Cold-cache cost.** The first run after a pin change downloads ~380 MB. Later runs restore it from the cache
  (GitHub evicts caches that go unused for 7 days, which only costs a re-download).
- **Third-party actions** are pinned by full commit SHA, each read with
  `gh api repos/<owner>/<repo>/git/ref/tags/<tag>` and named in a comment in the workflow
  (checkout v4.4.0, setup-python v5.6.0, setup-java v4.9.1, cache v4.3.0). Update them deliberately and
  re-verify the SHA the same way.
